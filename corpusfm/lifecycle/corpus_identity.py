"""Corpus identity — the check that says *this key belongs to this corpus* (packet 1246-02).

An empty corpus has nothing to decrypt, so "does this key work?" cannot be answered by reading
data. Without an answer, adopting a Recovery File into a fresh installation is a guess that only
becomes visible as a failure much later, once data exists and is unreadable.

So a corpus permanently records two things:

- **`corpus_id`** — an opaque UUID. Non-secret: it names the corpus, it opens nothing.
- **`canary`** — the corpus ID sealed under the Corpus Key.

Verification decrypts the canary and checks the ID inside equals the ID stored beside it. A key that
merely decrypts *something* is not enough; it must decrypt to **this** corpus's identity. That is
what makes "wrong corpus" a refusal rather than a silent mis-adoption.

**Where it lives, and why there.** The shipped FileMaker file is frozen — no new table, no new
field. The SETTING singleton is an ordinary record and its JSON-of-record is ordinary non-secret
metadata, which is exactly what this is: an opaque ID and a piece of authenticated ciphertext.
It is deliberately NOT a wrapped key and NOT a transport envelope; nothing here can be turned back
into a Corpus Key by anyone who does not already hold one.

**Establishment is idempotent and one-way.** Creating it twice is a no-op; finding a *different*
established ID refuses, because that means the key and the corpus have been paired wrongly and the
right response is to stop, not to overwrite the corpus's name.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from .errors import LifecycleError, RecordInvalid, RecordMissing

SETTING_KEY = "corpus_identity"
IDENTITY_VERSION = 1

_FIELDS = {"version", "corpus_id", "canary", "established_utc"}


class CorpusIdentityConflict(LifecycleError):
    """An identity is already established and it is not the one being written."""


class CorpusKeyDoesNotOpenThisCorpus(LifecycleError):
    """The candidate key failed the canary check for this corpus."""


def new_corpus_id() -> str:
    return str(uuid.uuid4())


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_canary(corpus_key: bytes | str, corpus_id: str) -> str:
    """Seal the corpus ID under the Corpus Key. The token is ciphertext, never a key."""
    from cryptography.fernet import Fernet
    key = corpus_key if isinstance(corpus_key, bytes) else str(corpus_key).encode("ascii")
    payload = json.dumps(
        {"corpus_id": corpus_id, "v": IDENTITY_VERSION},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return Fernet(key).encrypt(payload).decode("ascii")


def record_for(corpus_key: bytes | str, corpus_id: str, *, established_utc: str | None = None) -> dict:
    return {
        "version": IDENTITY_VERSION,
        "corpus_id": corpus_id,
        "canary": build_canary(corpus_key, corpus_id),
        "established_utc": established_utc or _now_utc(),
    }


def validate_record(record: Any) -> Mapping[str, Any]:
    if not isinstance(record, Mapping):
        raise RecordInvalid("the corpus identity record is not an object")
    missing = sorted(_FIELDS - set(record))
    unknown = sorted(set(record) - _FIELDS)
    if missing:
        raise RecordInvalid(f"the corpus identity record is missing {missing}")
    if unknown:
        raise RecordInvalid(f"the corpus identity record carries unknown field(s) {unknown}")
    if record["version"] != IDENTITY_VERSION:
        raise RecordInvalid(f"unsupported corpus identity version {record['version']!r}")
    for field in ("corpus_id", "canary", "established_utc"):
        if not isinstance(record[field], str) or not record[field].strip():
            raise RecordInvalid(f"corpus identity {field} is missing or not a non-empty string")
    return record


def key_opens(record: Mapping[str, Any], corpus_key: bytes | str) -> bool:
    """True iff `corpus_key` decrypts the canary AND the sealed ID matches the stored one."""
    from cryptography.fernet import Fernet
    validate_record(record)
    key = corpus_key if isinstance(corpus_key, bytes) else str(corpus_key).encode("ascii")
    try:
        plain = Fernet(key).decrypt(record["canary"].encode("ascii"))
        sealed = json.loads(plain.decode("utf-8"))
    except Exception:
        return False
    return (
        isinstance(sealed, dict)
        and sealed.get("corpus_id") == record["corpus_id"]
        and sealed.get("v") == IDENTITY_VERSION
    )


def assert_key_opens(record: Mapping[str, Any], corpus_key: bytes | str) -> None:
    if not key_opens(record, corpus_key):
        raise CorpusKeyDoesNotOpenThisCorpus(
            f"this key does not open corpus {record.get('corpus_id', '?')} — it is a key for a "
            "different corpus, or the identity record has been altered"
        )


# ── Storage-side access ─────────────────────────────────────────────────────────────
# Kept behind two tiny functions so the primitive above stays pure and testable without a backend,
# and so the storage shape is stated in exactly one place.

def read_identity(backend) -> Optional[Mapping[str, Any]]:
    """The established identity, or None when this corpus has none yet."""
    try:
        settings = backend.load_fm_settings()
    except Exception as exc:
        raise RecordInvalid(f"could not read corpus settings: {exc}") from exc
    record = (settings or {}).get(SETTING_KEY)
    if not record:
        return None
    return validate_record(record)


def require_identity(backend) -> Mapping[str, Any]:
    record = read_identity(backend)
    if record is None:
        raise RecordMissing(
            "this corpus has no established identity — it predates the identity record and must be "
            "migrated by the elevated installer before a Recovery File can be created for it"
        )
    return record


def establish_identity(backend, corpus_key: bytes | str, *, corpus_id: str | None = None) -> Mapping[str, Any]:
    """Create the identity if absent, verify it if present. Idempotent; conflict refuses.

    Returns the established record. A present record that the key opens is returned unchanged —
    re-establishment never rewrites a corpus's name, because a rewrite is exactly how a corpus would
    silently acquire the identity of the box that last touched it.
    """
    existing = read_identity(backend)
    if existing is not None:
        if corpus_id is not None and existing["corpus_id"] != corpus_id:
            raise CorpusIdentityConflict(
                f"this corpus is already established as {existing['corpus_id']}, not {corpus_id}; "
                "refusing to rename an established corpus"
            )
        assert_key_opens(existing, corpus_key)
        return existing

    record = record_for(corpus_key, corpus_id or new_corpus_id())
    backend.save_fm_settings({SETTING_KEY: record})
    written = read_identity(backend)
    if written is None:
        raise RecordMissing("the corpus identity was written but could not be read back")
    if written["corpus_id"] != record["corpus_id"]:
        raise CorpusIdentityConflict(
            f"wrote corpus identity {record['corpus_id']} but read back {written['corpus_id']}"
        )
    assert_key_opens(written, corpus_key)
    return written
