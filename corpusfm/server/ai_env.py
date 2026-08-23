"""Read/write the AI provider API key — in the SETTING ``AiKeys`` container (packet 1007).

The AI provider key is an APP-scoped secret (it belongs to the corpus), so it lives in the storage
DB's SETTING singleton ``AiKeys`` container, Corpus-Key-encrypted — so it TRAVELS with the migrated
corpus (the old ``.ai_env`` disk file did not) and a stolen ``.fmp12`` without the Corpus Key can't read
it. Per the universal rule, the secret rides a container blob, never SETTING's ``JSONOfRecord``.

Settings never round-trips the value to the browser (present/absent only). The public surface is the
same three functions as before — ``read_ai_key`` / ``set_ai_key`` / ``has_ai_key`` — so callers are
unchanged; only the storage moved off disk into the DB.
"""

from __future__ import annotations

import json as _json
import logging

# The chat (summaries) and embedding (search) endpoints hold INDEPENDENT keys (packet 1151) — the two
# endpoints are fully decoupled (own type, own key), even when identically configured. The legacy
# single key stays as a back-compat BRIDGE: an empty per-endpoint slot falls back to it, so an existing
# openai_compat install keeps working after the split; new configs set the per-endpoint keys explicitly.
AI_KEY_VAR = "CORPUSFM_AI_API_KEY"                 # legacy shared key (read-fallback only)
AI_KEY_VARS = {
    "chat":  "CORPUSFM_AI_CHAT_KEY",
    "embed": "CORPUSFM_AI_EMBED_KEY",
}

log = logging.getLogger("corpusfm.ai_env")


def _backend():
    try:
        from corpusfm.storage import get_backend
        return get_backend()
    except Exception:
        return None


def read_ai_env() -> dict:
    """The decrypted AI-secrets dict from the SETTING ``AiKeys`` container ({} if unset/unreadable)."""
    be = _backend()
    if be is None or not hasattr(be, "read_ai_keys"):
        return {}
    try:
        raw = be.read_ai_keys()
        if not raw:
            return {}
        from corpusfm.core.crypto import decode_blob, decompress
        return _json.loads(decompress(decode_blob(raw)).decode("utf-8"))
    except Exception:
        log.debug("ai_env: read failed", exc_info=True)
        return {}


def write_ai_env(updates: dict) -> bool:
    """Merge updates into the AiKeys container (preserving other keys), Corpus-Key-encrypted. A value of ""
    drops the key; an emptied dict clears the container."""
    be = _backend()
    if be is None or not hasattr(be, "write_ai_keys"):
        return False
    try:
        cur = read_ai_env()
        for k, v in updates.items():
            v = str(v)
            if v:
                cur[k] = v
            else:
                cur.pop(k, None)
        if not cur:
            be.clear_ai_keys()
            return True
        from corpusfm.core.crypto import compress, encode_blob
        blob = encode_blob(compress(_json.dumps(cur, ensure_ascii=False).encode("utf-8")),
                           encrypt_on=True)   # ALWAYS Corpus-Key-encrypted — an API key is a secret
        be.write_ai_keys(blob)
        return True
    except Exception:
        log.debug("ai_env: write failed", exc_info=True)
        return False


def read_ai_key(kind: str = "chat") -> str:
    """The plaintext AI key for `kind` ∈ {"chat","embed"}, or "" if unset/unreadable.

    An empty per-endpoint slot falls back to the legacy shared key (packet 1151 bridge)."""
    env = read_ai_env()
    var = AI_KEY_VARS.get(kind, AI_KEY_VAR)
    return env.get(var, "") or env.get(AI_KEY_VAR, "")


def set_ai_key(key: str, kind: str = "chat") -> bool:
    """Store (or, with an empty string, clear) the AI key for `kind` in the SETTING AiKeys container."""
    var = AI_KEY_VARS.get(kind, AI_KEY_VAR)
    return write_ai_env({var: (key or "").strip()})


def has_ai_key(kind: str = "chat") -> bool:
    """True when a non-empty AI key is stored for `kind` (honoring the legacy bridge)."""
    return bool(read_ai_key(kind))
