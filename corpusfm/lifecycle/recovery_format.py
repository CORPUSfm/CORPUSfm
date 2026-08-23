"""The CORPUSfm Recovery File envelope (`.cfmrecovery`) — packet 1246-02, deliverable 2.

One password-protected authenticated file carrying **only** the Corpus Key and the corpus identity
it belongs to. Never the database, never the automation password, never the Machine Key, never PKI
or user secrets. It is reusable and creating another does not revoke it.

**Construction, and why each piece is what it is.**

- **Argon2id** (`cryptography.hazmat.primitives.kdf.argon2`, available on the pinned
  `cryptography==49.0.0` used by both platform locks). The file sits in an administrator's backup,
  so the threat is a fully OFFLINE attack on a human-chosen passphrase — a memory-hard KDF is the
  only thing standing between that passphrase and the corpus. Parameters follow RFC 9106's second
  recommended option, scaled to m=128 MiB / t=3 / p=4, and they live in the header so a later
  version can raise them without orphaning existing files.
- **AES-256-GCM** with a fresh random 96-bit nonce. One key, one message, one file: each file
  derives a fresh key from a fresh 128-bit salt, so a repeated (key, nonce) pair is a birthday
  coincidence across two independent random draws — negligible, not impossible, and stated that way
  rather than as "cannot happen".
- **The whole header is authenticated as associated data.** The corpus ID, the created stamp and
  every KDF/cipher parameter are therefore tamper-evident even though they are readable: change any
  of them and the open fails, rather than silently deriving a different key or advertising the file
  as belonging to a corpus it does not.

**Everything the header can say is bounded BEFORE any key is derived** (Codex design review,
finding 4; extended to the free-text fields and the whole document after the diff review found the
claim was broader than the code). A recovery file is untrusted input: it arrives from a backup, an email, a USB stick. So
duplicate JSON members are rejected outright, unknown fields are rejected, every type is exact,
salt and nonce lengths are exact, and the Argon2 cost parameters must fall inside a supported band.
Without that, opening a hostile file is a denial of service (a header asking for 64 GiB of Argon2
memory) before authentication can possibly fail.

**Encodings are pinned, not implied** (finding 5). A Fernet key is ALREADY url-safe base64 ASCII of
32 raw bytes, so it is carried verbatim as that ASCII string — encoding it again would be a second
representation of the same thing, and two representations is how a round-trip silently changes a
key. The passphrase is NFC-normalized then UTF-8 encoded, so the same typed passphrase opens the
file on a Mac and on Windows.
"""

from __future__ import annotations

import base64
import json
import os
import unicodedata
from typing import Any, Mapping

from .errors import RecordInvalid, LifecycleError

FORMAT = "cfmrecovery"
FORMAT_VERSION = 1
KEY_FORMAT_VERSION = 1
RECOVERY_SUFFIX = ".cfmrecovery"

KDF_NAME = "argon2id"
CIPHER_NAME = "aes-256-gcm"

# RFC 9106 second recommended option, scaled up. Measured 0.135 s at 64 MiB on the build machine;
# 128 MiB is the shipped cost. A lifecycle operation is serialized behind the lifecycle lock, so
# there is no concurrent-derivation memory multiplier to budget for.
DEFAULT_MEMORY_KIB = 128 * 1024
DEFAULT_ITERATIONS = 3
DEFAULT_LANES = 4

DERIVED_KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
FERNET_KEY_RAW_LEN = 32

# Pre-authentication bounds. The floor keeps a hostile file from proposing a trivially crackable
# cost and calling itself a CORPUSfm recovery file; the ceiling keeps one from exhausting the box.
MIN_MEMORY_KIB = 32 * 1024
MAX_MEMORY_KIB = 1024 * 1024
MIN_ITERATIONS = 1
MAX_ITERATIONS = 16
MIN_LANES = 1
MAX_LANES = 16

# The passphrase is the whole strength of the file against an offline attack.
MIN_PASSPHRASE_LEN = 12

# Size bounds on the attacker-controlled parts. "Every header value is bounded" was not true of the
# free-text fields or the document as a whole when it was first written; an unbounded corpus_id or a
# gigabyte of base64 is a resource problem the same way an outsized KDF cost is, and it arrives the
# same way — in a file somebody hands you.
MAX_ID_LEN = 200
MAX_STAMP_LEN = 64
MAX_CIPHERTEXT_B64_LEN = 8192
MAX_DOCUMENT_BYTES = 64 * 1024

_HEADER_FIELDS = {"format", "format_version", "corpus_id", "created_utc", "kdf", "cipher"}
_KDF_FIELDS = {"name", "memory_kib", "iterations", "lanes", "salt"}
_CIPHER_FIELDS = {"name", "nonce"}
_DOC_FIELDS = {"header", "ciphertext"}
_PAYLOAD_FIELDS = {"corpus_key", "corpus_id", "key_format_version"}


class RecoveryFileInvalid(RecordInvalid):
    """The file is not a readable, well-formed, in-bounds CORPUSfm Recovery File."""


class RecoveryPasswordWrong(LifecycleError):
    """Authentication failed. Distinct from `RecoveryFileInvalid`: the file is well-formed."""


class RecoveryKdfUnavailable(LifecycleError):
    """Argon2id is not available from the installed cryptography/OpenSSL build.

    Raised rather than falling back to a weaker KDF. A silent downgrade would produce a file that
    looks identical to a strong one and is not, which is worse than refusing to create it.
    """


class PassphraseTooShort(LifecycleError):
    """Below the enforced floor."""


def normalize_passphrase(password: str) -> bytes:
    """NFC-normalize then UTF-8 encode. One representation, so one typed passphrase opens the file
    regardless of which platform's input method composed the characters."""
    if not isinstance(password, str):
        raise PassphraseTooShort("a recovery passphrase is required")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def assert_passphrase_acceptable(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSPHRASE_LEN:
        raise PassphraseTooShort(
            f"the recovery passphrase must be at least {MIN_PASSPHRASE_LEN} characters — it is the "
            "only thing protecting the Corpus Key in this file against an offline attack"
        )


def _no_duplicate_pairs(pairs):
    """`json.loads` keeps the LAST duplicate member silently. A file carrying two `corpus_id`
    members would then authenticate under one value and be read under the other."""
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise RecoveryFileInvalid(f"duplicate field {key!r} in the recovery file")
        seen[key] = value
    return seen


def _exact_fields(obj: Any, allowed: set[str], where: str) -> Mapping[str, Any]:
    if not isinstance(obj, dict):
        raise RecoveryFileInvalid(f"{where} is not an object")
    missing = sorted(allowed - set(obj))
    unknown = sorted(set(obj) - allowed)
    if missing:
        raise RecoveryFileInvalid(f"{where} is missing {missing}")
    if unknown:
        raise RecoveryFileInvalid(f"{where} carries unknown field(s) {unknown}")
    return obj


def _b64_exact(value: Any, length: int, where: str) -> bytes:
    if not isinstance(value, str):
        raise RecoveryFileInvalid(f"{where} is not a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RecoveryFileInvalid(f"{where} is not valid base64: {exc}") from exc
    if len(raw) != length:
        raise RecoveryFileInvalid(f"{where} must be {length} bytes, got {len(raw)}")
    return raw


def _bounded_int(value: Any, lo: int, hi: int, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RecoveryFileInvalid(f"{where} is not an integer")
    if not (lo <= value <= hi):
        raise RecoveryFileInvalid(f"{where} is out of the supported range [{lo}, {hi}]: {value}")
    return value


def _nonempty_str(value: Any, where: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RecoveryFileInvalid(f"{where} is missing or not a non-empty string")
    if len(value) > max_len:
        raise RecoveryFileInvalid(f"{where} is longer than the supported {max_len} characters")
    return value


def canonical_header_bytes(header: Mapping[str, Any]) -> bytes:
    """The exact bytes authenticated as associated data.

    Recomputed from the PARSED header on open rather than stored separately, which is safe only
    because every header value is a string or a bounded int — types whose JSON serialization is
    deterministic under fixed options.
    """
    return json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _derive(password: str, salt: bytes, *, memory_kib: int, iterations: int, lanes: int) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except Exception as exc:  # pragma: no cover - import shape is stable on the pinned version
        raise RecoveryKdfUnavailable(f"Argon2id is not available: {exc}") from exc
    try:
        return Argon2id(
            salt=salt, length=DERIVED_KEY_LEN,
            iterations=iterations, lanes=lanes, memory_cost=memory_kib,
        ).derive(normalize_passphrase(password))
    except (RecoveryFileInvalid, PassphraseTooShort):
        raise
    except Exception as exc:
        from cryptography.exceptions import UnsupportedAlgorithm
        if isinstance(exc, UnsupportedAlgorithm):
            raise RecoveryKdfUnavailable(
                "this build of OpenSSL does not support Argon2id, so a Recovery File cannot be "
                "created or opened here"
            ) from exc
        raise


def _assert_fernet_key_shape(value: Any, where: str) -> str:
    """A Fernet key is url-safe base64 of exactly 32 raw bytes, carried verbatim as that string."""
    if not isinstance(value, str):
        raise RecoveryFileInvalid(f"{where} is not a string")
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
    except Exception as exc:
        raise RecoveryFileInvalid(f"{where} is not url-safe base64: {exc}") from exc
    if len(raw) != FERNET_KEY_RAW_LEN:
        raise RecoveryFileInvalid(
            f"{where} decodes to {len(raw)} bytes, expected {FERNET_KEY_RAW_LEN}"
        )
    return value


def build_recovery_file(
    *,
    corpus_key: bytes | str,
    corpus_id: str,
    password: str,
    created_utc: str,
    memory_kib: int = DEFAULT_MEMORY_KIB,
    iterations: int = DEFAULT_ITERATIONS,
    lanes: int = DEFAULT_LANES,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Produce the complete `.cfmrecovery` bytes.

    `salt`/`nonce` are injectable ONLY so known-answer vectors can be deterministic; production
    callers pass neither and get fresh random values.
    """
    assert_passphrase_acceptable(password)
    key_str = corpus_key.decode("ascii") if isinstance(corpus_key, bytes) else str(corpus_key)
    _assert_fernet_key_shape(key_str, "the Corpus Key")
    _nonempty_str(corpus_id, "corpus_id", max_len=MAX_ID_LEN)
    _nonempty_str(created_utc, "created_utc", max_len=MAX_STAMP_LEN)
    _bounded_int(memory_kib, MIN_MEMORY_KIB, MAX_MEMORY_KIB, "kdf.memory_kib")
    _bounded_int(iterations, MIN_ITERATIONS, MAX_ITERATIONS, "kdf.iterations")
    _bounded_int(lanes, MIN_LANES, MAX_LANES, "kdf.lanes")

    salt = salt if salt is not None else os.urandom(SALT_LEN)
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN:
        raise RecoveryFileInvalid("salt/nonce length is wrong")

    header = {
        "format": FORMAT,
        "format_version": FORMAT_VERSION,
        "corpus_id": corpus_id,
        "created_utc": created_utc,
        "kdf": {
            "name": KDF_NAME,
            "memory_kib": memory_kib,
            "iterations": iterations,
            "lanes": lanes,
            "salt": base64.b64encode(salt).decode("ascii"),
        },
        "cipher": {"name": CIPHER_NAME, "nonce": base64.b64encode(nonce).decode("ascii")},
    }
    payload = json.dumps(
        {"corpus_key": key_str, "corpus_id": corpus_id, "key_format_version": KEY_FORMAT_VERSION},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    derived = _derive(password, salt, memory_kib=memory_kib, iterations=iterations, lanes=lanes)
    ciphertext = AESGCM(derived).encrypt(nonce, payload, canonical_header_bytes(header))
    document = {"header": header, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def read_recovery_file_bytes(path) -> bytes:
    """Read a candidate Recovery File without letting it choose how much memory to use.

    The size fence used to run *after* `read()` had already pulled the whole file into memory, so a
    hostile multi-gigabyte file consumed it all before the advertised pre-authentication check could
    refuse. The fence has to come first, and it has to be enforced on the bytes actually read —
    a `stat()` on the path can be true when it is taken and false a moment later.

    So: open ONCE, `fstat` that descriptor rather than the name, and read at most one byte past the
    limit from the same descriptor. A file swapped underneath after the open is not the file being
    read; a file that lied about its size is caught by the short read.
    """
    import os

    fd = os.open(str(path), os.O_RDONLY)
    try:
        stat = os.fstat(fd)
        if stat.st_size > MAX_DOCUMENT_BYTES:
            raise RecoveryFileInvalid(
                f"this file is {stat.st_size} bytes; a Recovery File is at most "
                f"{MAX_DOCUMENT_BYTES}. Refusing to read it."
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1                                     # ownership moved to the file object
            payload = handle.read(MAX_DOCUMENT_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(payload) > MAX_DOCUMENT_BYTES:
        raise RecoveryFileInvalid(
            "this file is larger than a Recovery File; refusing to parse it")
    return payload


def read_header(raw: bytes | str) -> Mapping[str, Any]:
    """Parse and fully validate the non-secret header WITHOUT deriving a key.

    This is the inspectable half: which corpus the file claims, when it was made, and what it will
    cost to open — knowable before anyone types a passphrase.
    """
    # Size FIRST, on the raw bytes, before any decode. Decoding a gigabyte to discover it is a
    # gigabyte has already spent the memory the fence exists to protect.
    if isinstance(raw, bytes):
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise RecoveryFileInvalid(
                "this file is larger than a Recovery File; refusing to parse it")
        text = raw.decode("utf-8")
    else:
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise RecoveryFileInvalid(
                "this file is larger than a Recovery File; refusing to parse it")
        text = raw
    try:
        document = json.loads(text, object_pairs_hook=_no_duplicate_pairs)
    except RecoveryFileInvalid:
        raise
    except Exception as exc:
        raise RecoveryFileInvalid(f"not a readable recovery file: {exc}") from exc

    _exact_fields(document, _DOC_FIELDS, "the recovery file")
    header = _exact_fields(document["header"], _HEADER_FIELDS, "the recovery file header")

    if header["format"] != FORMAT:
        raise RecoveryFileInvalid(
            f"not a CORPUSfm Recovery File (format {header['format']!r})"
        )
    if header["format_version"] != FORMAT_VERSION:
        raise RecoveryFileInvalid(
            f"unsupported Recovery File version {header['format_version']!r}; this CORPUSfm reads "
            f"version {FORMAT_VERSION}"
        )
    _nonempty_str(header["corpus_id"], "header.corpus_id", max_len=MAX_ID_LEN)
    _nonempty_str(header["created_utc"], "header.created_utc", max_len=MAX_STAMP_LEN)

    kdf = _exact_fields(header["kdf"], _KDF_FIELDS, "the recovery file kdf block")
    if kdf["name"] != KDF_NAME:
        raise RecoveryFileInvalid(f"unsupported key-derivation function {kdf['name']!r}")
    _bounded_int(kdf["memory_kib"], MIN_MEMORY_KIB, MAX_MEMORY_KIB, "kdf.memory_kib")
    _bounded_int(kdf["iterations"], MIN_ITERATIONS, MAX_ITERATIONS, "kdf.iterations")
    _bounded_int(kdf["lanes"], MIN_LANES, MAX_LANES, "kdf.lanes")
    _b64_exact(kdf["salt"], SALT_LEN, "kdf.salt")

    cipher = _exact_fields(header["cipher"], _CIPHER_FIELDS, "the recovery file cipher block")
    if cipher["name"] != CIPHER_NAME:
        raise RecoveryFileInvalid(f"unsupported cipher {cipher['name']!r}")
    _b64_exact(cipher["nonce"], NONCE_LEN, "cipher.nonce")

    if not isinstance(document["ciphertext"], str) or not document["ciphertext"]:
        raise RecoveryFileInvalid("the recovery file carries no ciphertext")
    if len(document["ciphertext"]) > MAX_CIPHERTEXT_B64_LEN:
        raise RecoveryFileInvalid("the recovery file's ciphertext is larger than this format holds")
    return header


def open_recovery_file(raw: bytes | str, password: str) -> dict:
    """Authenticate and decrypt. Returns `{corpus_key, corpus_id, key_format_version}`.

    Raises `RecoveryFileInvalid` for a malformed or out-of-bounds file and
    `RecoveryPasswordWrong` for a well-formed file that does not authenticate — which is also what
    a tampered header or ciphertext produces, because with AEAD those are the same event.
    """
    header = read_header(raw)
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    document = json.loads(text, object_pairs_hook=_no_duplicate_pairs)

    salt = base64.b64decode(header["kdf"]["salt"], validate=True)
    nonce = base64.b64decode(header["cipher"]["nonce"], validate=True)
    try:
        ciphertext = base64.b64decode(document["ciphertext"], validate=True)
    except Exception as exc:
        raise RecoveryFileInvalid(f"ciphertext is not valid base64: {exc}") from exc

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    derived = _derive(
        password, salt,
        memory_kib=header["kdf"]["memory_kib"],
        iterations=header["kdf"]["iterations"],
        lanes=header["kdf"]["lanes"],
    )
    try:
        payload = AESGCM(derived).decrypt(nonce, ciphertext, canonical_header_bytes(header))
    except Exception as exc:
        raise RecoveryPasswordWrong(
            "the Recovery File did not open — either the passphrase is wrong or the file has been "
            "altered since it was created"
        ) from exc

    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_no_duplicate_pairs)
    except RecoveryFileInvalid:
        raise
    except Exception as exc:
        raise RecoveryFileInvalid(f"the recovery payload is unreadable: {exc}") from exc

    _exact_fields(data, _PAYLOAD_FIELDS, "the recovery payload")
    if data["key_format_version"] != KEY_FORMAT_VERSION:
        raise RecoveryFileInvalid(
            f"unsupported key format version {data['key_format_version']!r}"
        )
    _assert_fernet_key_shape(data["corpus_key"], "the recovered Corpus Key")
    # The authenticated header and the sealed payload must name the same corpus. They cannot
    # disagree without the AEAD failing first, so this is a construction check, not a trust check.
    if data["corpus_id"] != header["corpus_id"]:
        raise RecoveryFileInvalid("the recovery file's header and payload name different corpora")
    return dict(data)
