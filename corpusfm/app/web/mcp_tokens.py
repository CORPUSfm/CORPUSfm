"""Many named per-user MCP tokens — backed by the MCPTOKEN table (packet 1029).

A user can mint MANY named tokens (one per app: "laptop-claude", "work-cursor", …), all listed on the
MCP page and each independently deletable. This supersedes the single-token-on-USER model (packet
1007's ``USER.TokenId``/``HasToken``/``token_secret_hash``): tokens now live in their own table so a
person can connect several apps, and deleting one never disturbs the others. There is NO rotate —
delete the old, mint a new.

Every token authenticates as its OWNER with the OWNER'S CURRENT gates (resolved live from the USER
record at auth time — a gate change propagates to all of that user's tokens at once). No per-token
gate scoping.

Storage (logical ``MCPTOKEN`` → ``TABLE10``): the token shape is ``<token_id>.<secret>``; ``token_id``
is a non-secret indexed slot (ONE direct resolve per request), ``Owner`` is an indexed slot (ONE "list
my tokens"), and only the ``secret``'s SHA-256 hash rides the Corpus-Key-encrypted ``SecretData``
container — never ``JSONOfRecord`` (the table-wide secret fence). Name + created ride jor.
"""

from __future__ import annotations

import hashlib
import hmac
import json as _json
import logging
import secrets
import uuid as _uuidlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("corpusfm.mcp_tokens")

_TBL = "MCPTOKEN"
_NAME_MAX = 60


@dataclass
class TokenMeta:
    """Non-secret view of one token (for the list). The secret is never here — shown once at mint."""
    id: str            # the engine record key (uuid) — delete addresses this
    name: str
    token_id: str      # the non-secret lookup half (shown as a short prefix for disambiguation)
    created_at: str
    owner: str


def _engine(backend=None):
    try:
        if backend is None:
            from corpusfm.storage import get_backend
            backend = get_backend()
        return getattr(backend, "engine", None)
    except Exception:
        return None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _norm(s: str) -> str:
    return (s or "").strip().lower()


def _meta_from_row(row) -> TokenMeta:
    j = row.jor
    return TokenMeta(
        id=row.key,
        name=str(j.get("Name", "")),
        token_id=str(j.get("TokenId", "")),
        created_at=str(j.get("CreatedAt", "")),
        owner=str(j.get("Owner", "")),
    )


# ── SecretData container (Corpus-Key-encrypted; never jor) ─────────────────────────

def _save_hash(engine, key: str, token_secret_hash: str) -> None:
    from corpusfm.core.crypto import compress, encode_blob
    blob = encode_blob(
        compress(_json.dumps({"token_secret_hash": token_secret_hash}).encode("utf-8")),
        encrypt_on=True)   # ALWAYS Corpus-Key-encrypted (the secret fence)
    engine.blob_put(_TBL, key, "SecretData", blob)


def _load_hash(engine, key: str) -> str:
    from corpusfm.core.crypto import decode_blob, decompress
    try:
        raw = engine.blob_get(_TBL, key, "SecretData")
        if not raw:
            return ""
        return str(_json.loads(decompress(decode_blob(raw)).decode("utf-8")).get("token_secret_hash", ""))
    except Exception:
        log.debug("mcp_tokens: hash load failed for %s", key, exc_info=True)
        return ""


# ── reads ─────────────────────────────────────────────────────────────────────

def list_for(uid: str, *, backend=None) -> list[TokenMeta]:
    """This user's tokens, newest-first. NON-secret view (no container read). An unavailable store
    reads as an empty list here (fail-closed); use :func:`list_for_or_none` when the caller must tell
    an outage apart from "no tokens"."""
    return list_for_or_none(uid, backend=backend) or []


def list_for_or_none(uid: str, *, backend=None) -> Optional[list[TokenMeta]]:
    """Like :func:`list_for`, but ``None`` when the store is UNAVAILABLE (packet 1182), so the account
    surface can tell an outage from a user who simply holds no tokens. The ``[]``-on-failure contract of
    ``list_for`` stays as it is — the auth/mint paths depend on it."""
    e = _engine(backend)
    if e is None:
        return None
    if not uid:
        return []
    try:
        rows = e.get_many(_TBL, "Owner", [uid])
    except Exception:
        log.debug("mcp_tokens: list_for_or_none failed", exc_info=True)
        return None
    metas = [_meta_from_row(r) for r in rows]
    metas.sort(key=lambda m: m.created_at, reverse=True)
    return metas


def owner_ids_with_tokens(*, backend=None) -> set[str]:
    """Set of user ids that hold at least one token (one query — for the admin users list)."""
    e = _engine(backend)
    if e is None:
        return set()
    try:
        return {str(r.jor.get("Owner", "")) for r in e.list_all(_TBL) if r.jor.get("Owner")}
    except Exception:
        return set()


# ── writes ────────────────────────────────────────────────────────────────────

def mint(uid: str, name: str, *, backend=None) -> str:
    """Mint a new named token for a user; return the RAW ``<token_id>.<secret>`` ONCE.

    Raises ValueError on a blank/too-long/duplicate name (per user), or when the user does not exist.
    Only the secret's hash is stored (in the container); the raw is never persisted."""
    e = _engine(backend)
    if e is None:
        raise RuntimeError("no storage engine — the token store needs the database")
    from corpusfm.app.web import users as _us
    if _us.get_user_by_id(uid, backend=backend) is None:
        raise ValueError("User not found.")
    label = (name or "").strip()
    if not label:
        raise ValueError("A token name is required.")
    if len(label) > _NAME_MAX:
        raise ValueError(f"Name must be {_NAME_MAX} characters or fewer.")
    if any(_norm(m.name) == _norm(label) for m in list_for(uid, backend=backend)):
        raise ValueError(f"You already have a token named '{label}'.")

    token_id = secrets.token_hex(8)          # non-secret, indexed (lowercase hex)
    secret = secrets.token_urlsafe(32)
    key = str(_uuidlib.uuid4())
    e.create(_TBL, key, {
        "Name": label,
        "Owner": uid,
        "TokenId": token_id,
        "CreatedAt": _now(),
    })
    # If the secret-hash write fails, delete the row rather than leave a phantom (a row with no
    # SecretData is fail-closed — resolve returns None — but would clutter the user's list). packet 1000 P2.
    try:
        _save_hash(e, key, _hash_token(secret))
    except Exception:
        try:
            e.delete(_TBL, key)
        except Exception:
            log.debug("mcp_tokens: mint rollback delete failed for %s", key, exc_info=True)
        raise
    return f"{token_id}.{secret}"


def delete_all_for(uid: str, *, backend=None) -> int:
    """Delete ALL of a user's tokens — called when the user is deleted (no orphan rows / lingering
    secret hashes). An orphan token can't authenticate anyway (resolve fails closed when the owner is
    gone), so this is hygiene. Returns the count removed."""
    e = _engine(backend)
    if e is None or not uid:
        return 0
    n = 0
    for m in list_for(uid, backend=backend):
        try:
            e.delete(_TBL, m.id)
            n += 1
        except Exception:
            log.debug("mcp_tokens: delete_all_for %s failed on %s", uid, m.id, exc_info=True)
    return n


def delete(uid: str, record_key: str, *, backend=None) -> bool:
    """Delete one of THIS user's tokens (ownership-checked). True if a row was deleted."""
    e = _engine(backend)
    if e is None or not record_key:
        return False
    try:
        rows = e.get_by_keys(_TBL, [record_key])
    except Exception:
        return False
    if not rows or str(rows[0].jor.get("Owner", "")) != uid:
        return False           # not found, or not the caller's token
    e.delete(_TBL, record_key)
    return True


# ── resolve (the MCP verifier path) ───────────────────────────────────────────

def resolve(token: str, *, backend=None):
    """Return the active OWNER (a users.User with their current gates) for a bearer token, or None.

    ONE indexed lookup by the non-secret ``token_id``, then a constant-time hash compare of the
    secret against the container, then the owner is loaded live (so gates are always current)."""
    if not token or "." not in token:
        return None
    token_id, secret = token.split(".", 1)
    if not token_id or not secret:
        return None
    e = _engine(backend)
    if e is None:
        return None
    try:
        r = e.get_one(_TBL, TokenId=_norm(token_id))
    except Exception:
        return None
    if r is None:
        return None
    stored = _load_hash(e, r.key)
    if not stored or not hmac.compare_digest(stored, _hash_token(secret)):
        return None
    from corpusfm.app.web import users as _us
    owner = _us.get_user_by_id(str(r.jor.get("Owner", "")), backend=backend)
    if owner is None or not owner.active:
        return None
    return owner
