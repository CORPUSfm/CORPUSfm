"""Read/write the external-auth secrets — in the SETTING ``OidcSecret`` container (packet 1065).

The OIDC ``client_secret`` and (Ph3) the LDAP bind password are APP-scoped secrets (they belong to the
corpus), so they live in the storage DB's SETTING singleton ``OidcSecret`` container, Corpus-Key-encrypted
— so they TRAVEL with the corpus and a stolen ``.fmp12`` without the Corpus Key can't read
them. Per the universal rule, the secret rides a container blob, never SETTING's ``JSONOfRecord`` (the
non-secret OIDC/LDAP config — issuer, client_id, redirect_uri, scopes, group→gate map — lives in the
AppConfig JSON blob; only the secret half is here).

Settings never round-trips a secret's value to the browser (present/absent only), mirroring ``ai_env``.
"""

from __future__ import annotations

import json as _json
import logging

OIDC_CLIENT_SECRET = "oidc_client_secret"
LDAP_BIND_PASSWORD = "ldap_bind_password"

log = logging.getLogger("corpusfm.oidc_secrets")


def _backend():
    try:
        from corpusfm.storage import get_backend
        return get_backend()
    except Exception:
        return None


def read_oidc_env() -> dict:
    """The decrypted external-auth secrets dict from the SETTING ``OidcSecret`` container ({} if
    unset/unreadable)."""
    be = _backend()
    if be is None or not hasattr(be, "read_oidc_secret"):
        return {}
    try:
        raw = be.read_oidc_secret()
        if not raw:
            return {}
        from corpusfm.core.crypto import decode_blob, decompress
        return _json.loads(decompress(decode_blob(raw)).decode("utf-8"))
    except Exception:
        log.debug("oidc_secrets: read failed", exc_info=True)
        return {}


def write_oidc_env(updates: dict) -> bool:
    """Merge updates into the OidcSecret container (preserving other keys), Corpus-Key-encrypted. A value of
    "" drops the key; an emptied dict clears the container."""
    be = _backend()
    if be is None or not hasattr(be, "write_oidc_secret"):
        return False
    try:
        cur = read_oidc_env()
        for k, v in updates.items():
            v = str(v)
            if v:
                cur[k] = v
            else:
                cur.pop(k, None)
        if not cur:
            if hasattr(be, "clear_oidc_secret"):
                be.clear_oidc_secret()
            return True
        from corpusfm.core.crypto import compress, encode_blob
        blob = encode_blob(compress(_json.dumps(cur, ensure_ascii=False).encode("utf-8")),
                           encrypt_on=True)   # ALWAYS Corpus-Key-encrypted — these are secrets
        be.write_oidc_secret(blob)
        return True
    except Exception:
        log.debug("oidc_secrets: write failed", exc_info=True)
        return False


def read_client_secret() -> str:
    """The plaintext OIDC client_secret, or "" if unset/unreadable."""
    return read_oidc_env().get(OIDC_CLIENT_SECRET, "")


def set_client_secret(secret: str) -> bool:
    """Store (or, with "", clear) the OIDC client_secret."""
    return write_oidc_env({OIDC_CLIENT_SECRET: (secret or "").strip()})


def has_client_secret() -> bool:
    return bool(read_client_secret())


def read_ldap_bind_password() -> str:
    """The plaintext LDAP bind password (Ph3), or "" if unset/unreadable."""
    return read_oidc_env().get(LDAP_BIND_PASSWORD, "")


def set_ldap_bind_password(secret: str) -> bool:
    return write_oidc_env({LDAP_BIND_PASSWORD: (secret or "").strip()})


def has_ldap_bind_password() -> bool:
    return bool(read_ldap_bind_password())
