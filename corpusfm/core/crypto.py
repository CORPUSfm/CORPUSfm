"""Compression and encryption for archive snapshots.

Key resolution order (first match wins):
  1. CORPUSFM_ENCRYPTION_KEY env var — for server/container deployments
  2. ~/.corpusfm/corpus.key           — auto-generated on first save

On-disk format: Fernet(gzip(json_utf8_bytes))
  - gzip level 6: 5-10x compression on JSON (100 MB → 10-20 MB)
  - Fernet: AES-128-CBC + HMAC-SHA256 (authenticated encryption)

The key is a URL-safe base64-encoded 32-byte value produced by Fernet.generate_key().
To export the key for use as an env var:
    cat ~/.corpusfm/corpus.key
"""
from __future__ import annotations

import base64
import gzip
import os
from pathlib import Path
from typing import Optional

# ── Two keys, never crossed (packet 1246-02 names; the split itself is packet 1007) ────────────
# CORPUS KEY — belongs to the CORPUS, not to this machine. Encrypts every DB container blob
#   (ArtifactData/SourceXML/NameMapData/SummariesData, JOB.CredentialData, the USER secret
#   container, the SETTING AiKeys container) + the short config secrets (fm_password,
#   server_configs). It is PORTABLE: a Recovery File carries it, and only it, to another machine.
#   Lives in `corpus.key`.
# MACHINE KEY — belongs to THIS installation and never leaves it. Encrypts the FMS Admin PKI
#   private key and anything else scoped to the box. Never exported, never carried by a Recovery
#   File, never swapped by an adoption.
# The one overloaded key was the bug: a machine-scoped secret encrypted under the portable key is
# orphaned the moment that key moves. Splitting them fixes it.
# **These are FUNCTIONS, not constants (packet 1246-03-01).** They used to be three module-level
# `Path.home()` expressions evaluated at import, which meant the location was frozen before the
# process could learn where this installation actually keeps its secrets — and, worse, that the very
# operation that MOVES the key directory would still be reading the old one. `secrets_dir()` answers
# from the published installation record and refuses when there is none, so there is exactly one
# installed answer and no home-directory fallback. The cached key BYTES below are a SECOND,
# independent cache of the same stale answer, which is why `reset_key_cache()` exists and why
# `app_paths.reset_cache()` calls it: clearing the path cache alone would leave a process holding
# keys it read from the directory it no longer uses.
def _key_dir() -> Path:
    from corpusfm.lifecycle import app_paths
    return app_paths.secrets_dir()


# In-process redirection seam, HONOURED ONLY IN DEVELOPMENT.
#
# **This was an unfenced alternate authority and the review caught it.** The argument for leaving it
# open was that no environment variable or argv reaches it, so it is "the same class as the
# development layout" — and that was wrong in the one way that matters: the development layout has to
# be *selected*, and this did not. Anything that could set the module attribute redirected a
# published installation's key: a planted file would have been accepted as the irreplaceable Corpus
# Key, and a regenerated Machine Key would have been written outside the published secrets directory.
# Worse, every test in this packet set both to `None`, so the escape was invisible to its own suite.
#
# Now both resolve the installation FIRST and are consulted only when that answer is DEVELOPMENT.
_CORPUS_KEY_FILE: Optional[Path] = None
_MACHINE_KEY_FILE: Optional[Path] = None


def _development_key_seam(reader, name: str) -> Optional[Path]:
    """`reader` is a CALLABLE, and that is the whole correction.

    The first version took the seam's *value* as an argument, so the module attribute was evaluated
    at the call site — before this function was entered and therefore before the installation
    resolved. Published still ignored it, but an indeterminate installation had its override
    consulted before it refused, which is exactly the ordering the ruling forbids. A callable is the
    only shape that cannot be evaluated early by accident.
    """
    from corpusfm.lifecycle import app_paths

    seam = app_paths.development_override(name, reader, what="the key file location")
    return Path(seam) if seam else None


#: The file NAMES, separate from where they are resolved. Lifecycle work that must write a key into
#: an explicitly named installation (recovery adoption, the conversion) needs the name without the
#: ambient directory — and taking the name from here keeps one spelling instead of two.
CORPUS_KEY_FILENAME = "corpus.key"
MACHINE_KEY_FILENAME = "machine.key"


def _corpus_seam() -> Optional[Path]:
    """Read the seam attribute. A NAMED function, not a lambda, so a test can observe *when* it runs.

    A lambda would be equally lazy and completely unobservable: with the attribute captured inside
    an anonymous closure, no test could tell the lazy version from the eager one, and the mutation
    that reintroduces eager evaluation would survive. Naming the read is what makes the ordering an
    asserted property rather than a reviewed one.
    """
    return _CORPUS_KEY_FILE


def _machine_seam() -> Optional[Path]:
    return _MACHINE_KEY_FILE


def corpus_key_file() -> Path:
    seam = _development_key_seam(_corpus_seam, "crypto._CORPUS_KEY_FILE")
    return seam if seam else _key_dir() / CORPUS_KEY_FILENAME


def machine_key_file() -> Path:
    seam = _development_key_seam(_machine_seam, "crypto._MACHINE_KEY_FILE")
    return seam if seam else _key_dir() / MACHINE_KEY_FILENAME


_ENV_VAR = "CORPUSFM_ENCRYPTION_KEY"   # Corpus Key only; the Machine Key has no env override

# TRANSITIONAL — part of the private conversion bridge, and it is RETAINED UNTIL THE DEVELOPER
# EXPLICITLY AUTHORIZES ITS REMOVAL (ruling 2026-08-03). Deliberately not "removed by packet 1246-10",
# which is what this comment used to promise: there is no scheduled removal and no trigger to infer,
# so naming a packet here would date the code against a decision nobody has taken. Installations made
# before the 1246-02 naming hold their keys under the old names; reading them is a one-way bridge for
# the single bounded conversion, NOT a compatibility promise — nothing writes these names, and the
# conversion removes the old files on the box it converts. The paths are derived from the CURRENT
# file's own name rather than being separate constants, so redirecting the key location (a test
# fixture, or the conversion moving the directory) moves the transitional lookup with it — a fixed
# second constant would silently read the real machine's key out from under a redirected one.
_TRANSITIONAL_CORPUS_NAME = "secret.key"
_TRANSITIONAL_MACHINE_NAME = "server.key"

_cached_corpus_key: Optional[bytes] = None
_cached_machine_key: Optional[bytes] = None


def _transitional_path(primary: Path, legacy_name: str) -> Path:
    """TRANSITIONAL (1246-02): the pre-rename location beside `primary`.

    Retained until the developer explicitly authorizes removal — no scheduled date, no trigger."""
    return Path(primary).with_name(legacy_name)


def _read_existing(primary: Path) -> Optional[bytes]:
    """The key bytes from the CURRENT location, or None.

    It used to fall back to the pre-1246-02 name. Removed under the developer's ruling of
    2026-08-03: *"ordinary runtime" includes development runtime* — no normal runtime path, published
    or indeterminate or explicitly-selected development, may read `secret.key` or `server.key`. Only
    `read_transitional_key()` may, and only when something calls it on purpose.
    """
    return primary.read_bytes().strip() if primary.exists() else None


def _published() -> bool:
    from corpusfm.lifecycle import app_paths

    return app_paths.is_published()


def get_corpus_key() -> bytes:
    """Resolve the Corpus Key for this installation.

    **On a published installation there is exactly one answer: the installed `corpus.key`**
    (packet 1246-03-01). No environment variable stands in for it, no old filename rescues it, and a
    missing one is a refusal naming the recovery action — never a fresh key.

    **This is the ONE irreplaceable secret, and the asymmetry is deliberate** (developer ruling,
    2026-08-03): the durable recovery boundary is the storage database plus the Corpus Key that
    interprets its protected values, or a Recovery File that restores that key. The Machine Key, the
    session secret, locks and caches are replaceable scaffolding and are recreated. This one is not,
    because a generated replacement produces a *working* installation that cannot read a single
    protected value, and says nothing.

    Development keeps the env override and first-run generation, because there is no installer there
    to have provisioned anything — but it does **not** keep the old-name lookup. A development tree
    holding only `secret.key` generates a fresh current-format key rather than adopting the old one
    (developer ruling, 2026-08-03: implicit adoption of a transitional name is the "forgiving
    migration" this project rejected, and it hides a box the conversion has not run on).
    """
    global _cached_corpus_key
    if _cached_corpus_key is not None:
        return _cached_corpus_key

    from corpusfm.lifecycle import app_paths

    env_val = app_paths.development_override(
        _ENV_VAR, lambda: os.environ.get(_ENV_VAR, "").strip(), what="the Corpus Key")
    if env_val:
        _cached_corpus_key = env_val.encode() if isinstance(env_val, str) else env_val
        return _cached_corpus_key

    primary = corpus_key_file()
    if _published():
        app_paths.assert_corpus_key_present(primary)
        _cached_corpus_key = primary.read_bytes().strip()
        return _cached_corpus_key

    existing = _read_existing(primary)
    if existing:
        _cached_corpus_key = existing
        return _cached_corpus_key

    # Auto-generate and persist — DEVELOPMENT ONLY. The Corpus Key is the crown jewel (it decrypts
    # every corpus blob + the per-job FM credential + the encrypted fm_password), so write it 0600 AT
    # CREATION under a 0700 parent — no chmod-after-write window.
    _cached_corpus_key = _generate_key_file(primary)
    return _cached_corpus_key


def get_machine_key() -> bytes:
    """Resolve the Machine Key. There is NO env override at all — a machine-scoped key must always
    be the on-disk file for this installation, so a portable value can never stand in for it.

    **REPLACEABLE (developer ruling, 2026-08-03).** The Machine Key protects box-local material —
    the FMS Admin PKI private key above all — that its owning packets recreate. So a missing one is
    regenerated at the authoritative published path rather than refused. Only the **Corpus Key** is
    irreplaceable, because only it interprets protected values in the durable storage database.

    What is *not* forgiven in ANY state: an old filename. Published, indeterminate and explicitly
    selected development alike read `machine.key` or write a new one; none falls back to
    `server.key`, because a box holding only the old name is one the conversion has not run on, and
    coming up on it quietly would hide exactly that.
    """
    global _cached_machine_key
    if _cached_machine_key is not None:
        return _cached_machine_key

    primary = machine_key_file()
    if primary.exists():
        _cached_machine_key = primary.read_bytes().strip()
        return _cached_machine_key

    _cached_machine_key = _generate_key_file(primary)
    return _cached_machine_key


def read_transitional_key(primary: Path, legacy_name: str) -> Optional[bytes]:
    """Read a pre-1246-02 key by its OLD name — for the private conversion bridge only.

    The bridge (1246-10) must be able to read `secret.key` / `server.key` explicitly, because that is
    what the two development boxes hold. **Ordinary published runtime must not**, which is why this
    is a separate, named entry point rather than a fallback inside `get_corpus_key`: a conversion
    asking for an old name is doing its job; a running service reaching for one is rescuing an
    installation whose real key is missing, and that is exactly the silent-wrong-key failure the
    published path now refuses.
    """
    legacy = _transitional_path(primary, legacy_name)
    return legacy.read_bytes().strip() if legacy.exists() else None


def _generate_key_file(path: Path) -> bytes:
    from cryptography.fernet import Fernet
    from corpusfm.core import secure_fs
    key = Fernet.generate_key()
    secure_fs.write_bytes_private(path, key)
    return key


def _clear_key_cache() -> None:
    """Reset both cached keys (used by tests to swap keys between runs, and after a key migration
    or adoption writes a new file)."""
    global _cached_corpus_key, _cached_machine_key
    _cached_corpus_key = None
    _cached_machine_key = None


#: The public name, and the reason it matters (packet 1246-03-01): the key BYTES are a SECOND cache
#: of the same answer as the resolved secrets directory. Clearing the paths while these survive is
#: worse than clearing neither — everything still decrypts, from the wrong installation. Registering
#: it with `app_paths` is what ties the two together; there is deliberately only one implementation,
#: because a second function doing the same thing is how one of them stops being called.
reset_key_cache = _clear_key_cache


def _register_with_app_paths() -> None:
    from corpusfm.lifecycle import app_paths

    app_paths.register_cache_reset(reset_key_cache)


_register_with_app_paths()


def key_source() -> str:
    """Human-readable description of where the active Corpus Key came from.

    Must describe what `get_corpus_key()` would ACTUALLY do, not what it once did. It previously
    reported the env var and the old filename unconditionally, so a published box with neither in
    effect would have been told its key came from a place the resolver now refuses to look — a
    diagnostic that lies is worse than none, because it sends the administrator to the wrong file.
    """
    published = _published()
    if os.environ.get(_ENV_VAR, "").strip() and not published:
        return f"env var `{_ENV_VAR}`"
    current = corpus_key_file()
    if current.exists():
        return f"`{current}`"
    if published:
        return f"`{current}` (MISSING — the installer provisions it; the service will not create one)"
    return f"`{current}` (will be created on first save)"


# ── Corpus-scoped crypto — the default; every corpus-owned DB container blob + config secret ──
def encrypt_corpus(plaintext: bytes) -> bytes:
    from cryptography.fernet import Fernet
    return Fernet(get_corpus_key()).encrypt(plaintext)


def decrypt_corpus(ciphertext: bytes) -> bytes:
    from cryptography.fernet import Fernet
    return Fernet(get_corpus_key()).decrypt(ciphertext)


# encrypt()/decrypt() remain the corpus-scoped primitives (aliases) — the default scope for every
# corpus-owned caller (encode_blob, encrypt_secret, the storage backends). The classification guard
# (tests/test_crypto_key_split.py) pins that the ONLY machine-scoped caller uses the _machine forms.
encrypt = encrypt_corpus
decrypt = decrypt_corpus


# ── Machine-scoped crypto — box-local secrets that never travel (the FMS PKI key) ──
def encrypt_machine(plaintext: bytes) -> bytes:
    from cryptography.fernet import Fernet
    return Fernet(get_machine_key()).encrypt(plaintext)


def decrypt_machine(ciphertext: bytes) -> bytes:
    from cryptography.fernet import Fernet
    return Fernet(get_machine_key()).decrypt(ciphertext)


# ── Signed download URLs (packet 1166 A3-auth) ──────────────────────────────────────
# A stateless, expiring signature so the AI can `curl` a stored container's bytes from its own machine
# WITHOUT handling a standing credential (a bearer on a command line lands in shell history + the
# transcript). Signed under the MACHINE key — box-local, never exported, never carried by a Recovery
# File — so a signed URL is valid ONLY on the box that minted it; a rebuilt box (new Machine Key)
# invalidates all prior URLs (correct and free). This is DELIBERATELY separate from the in-process
# apply plan-tokens: the download hits the WEB app (a different process than the MCP session), so an
# in-process token store cannot be shared — verification must come from the URL + the Machine Key
# alone (the load-bearing choice).
#
# `container` is the SOLE selector bound into the signature — there is NO `form` in the canonical string.
# Two addressing schemes for the same bytes would make the canonical string ambiguous (a URL could verify
# under one canonicalization and 404 under another), so the signed path uses `container=` only; the legacy
# `form=raw|artifact` stays on the session/bearer path.
def sign_download(uuid: str, container: str, exp: int) -> str:
    """HMAC-SHA256 over (uuid · container · exp), newline-joined, keyed by the Machine Key. Returns
    a hex digest."""
    import hashlib
    import hmac
    canonical = "\n".join([str(uuid), str(container), str(int(exp))]).encode("utf-8")
    return hmac.new(get_machine_key(), canonical, hashlib.sha256).hexdigest()


def verify_download(uuid: str, container: str, exp, sig: str) -> bool:
    """Constant-time verify of a sign_download signature AND its expiry (``exp`` is a unix second).
    False on a tampered / re-pointed (different uuid or container) / expired signature, or one minted
    under a different Machine Key (box-specificity). Replayable until ``exp`` — statelessness precludes
    single-use without a store; acceptable for a read of already-entitled data (the VISIBLE_TYPES fence
    runs AFTER this in the route, so a valid signature to a non-visible record is still refused)."""
    import hmac
    import time
    try:
        if int(exp) <= int(time.time()):
            return False
    except (TypeError, ValueError):
        return False
    expected = sign_download(uuid, container, int(exp))
    return hmac.compare_digest(expected, str(sig or ""))


def compress(data: bytes) -> bytes:
    return gzip.compress(data, compresslevel=6)


def decompress(data: bytes) -> bytes:
    return gzip.decompress(data)


# ── String-secret encryption (config credentials) ──────────────────────────────
# Short credentials kept in YAML config files (server_configs.yaml, install.yaml)
# are Fernet-encrypted with an "enc:" marker so a read can tell an encrypted value
# from a legacy plaintext one and migrate it transparently. In-memory values are
# always plaintext — only the on-disk form changes. One implementation, shared by
# every config store (don't reimplement the scheme).
_SECRET_PREFIX = "enc:"


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a short string secret for at-rest storage. Empty stays empty (no marker)."""
    if not plaintext:
        return ""
    return _SECRET_PREFIX + base64.b64encode(encrypt(plaintext.encode("utf-8"))).decode("ascii")


def decrypt_secret(stored: str) -> str:
    """Decrypt an at-rest secret. Legacy plaintext (no marker) is returned as-is; an
    unreadable token (e.g. wrong key) yields "" rather than raising, so a single bad
    value never crashes a whole config load."""
    if not stored:
        return ""
    s = str(stored)
    if not s.startswith(_SECRET_PREFIX):
        return s  # legacy plaintext
    try:
        return decrypt(base64.b64decode(s[len(_SECRET_PREFIX):])).decode("utf-8")
    except Exception:
        return ""


def is_legacy_plaintext_secret(stored) -> bool:
    """True if a stored value is a non-empty secret not yet encrypted at rest."""
    return bool(stored) and not str(stored).startswith(_SECRET_PREFIX)


# ── Container-blob encoding (encrypt_blobs setting) ────────────────────────────────
# Container blobs (ArtifactData / SourceXML / NameMapData / deliverable XML) are stored as
# either ``gzip(payload)`` (plaintext) or ``Fernet(gzip(payload))`` (encrypted), per the
# encrypt_blobs setting (default off). The two forms coexist — decode_blob auto-detects on
# READ, so a setting flip / in-flight bulk conversion never breaks reads.
#
# Detection: a gzip header (0x1f 0x8b) marks a plaintext blob. A Fernet token is URL-safe
# base64 of ≥73 bytes (version+ts+iv+ct+hmac) → ≥100 chars, always starting "gA". Anything
# else — most importantly FM's 1-byte stub for an *empty* container — is NEITHER, and must
# be left alone (decrypting it raises InvalidToken; it carries no payload).
_GZIP_MAGIC = b"\x1f\x8b"
_FERNET_MIN = 60   # real Fernet tokens are ~100 bytes; safely above any empty-container stub


def _is_fernet(raw: bytes) -> bool:
    return len(raw) >= _FERNET_MIN and raw[:2] != _GZIP_MAGIC and raw[:2] == b"gA"


def blob_is_encrypted(raw: bytes) -> bool:
    """True only if the blob is a real Fernet token (encrypted). Plaintext gzip, empty, and
    placeholder/stub containers → False. Drives the bulk re-encode's skip logic."""
    return bool(raw) and _is_fernet(raw)


def is_real_blob(raw: bytes) -> bool:
    """True if the blob carries a real payload — gzip (plaintext) or a Fernet token (encrypted).
    Empty/absent and tiny placeholder-stub containers are NOT real and are skipped by re-encode."""
    return bool(raw) and (raw[:2] == _GZIP_MAGIC or _is_fernet(raw))


def encode_blob(payload: bytes, *, encrypt_on: bool) -> bytes:
    """Encode an (already-gzip) container payload for storage: Fernet-encrypted when
    ``encrypt_on``, otherwise stored as-is (plaintext gzip)."""
    return encrypt(payload) if encrypt_on else payload


def decode_blob(raw: bytes) -> bytes:
    """Return the gzip payload from a stored container blob, decrypting only if it is a real
    Fernet token. Plaintext (gzip) and non-payload stubs pass through untouched (never decrypt
    a stub → no InvalidToken)."""
    if not raw:
        return raw
    return decrypt(raw) if _is_fernet(raw) else raw
