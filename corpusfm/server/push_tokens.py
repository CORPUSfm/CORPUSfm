"""One-time bearer tokens for the fms_push channel (packet 1015).

A remote FMS box pushes its DDR to ``POST /api/upload`` with a Bearer token. That token is
minted **per run** by the job runner when it fires the ``PostToServer`` trigger, and it keys
directly to the pending QUEUE record for that run. The runner hands FileMaker the RAW token
(as the ``password`` script parameter); only its **hash** is persisted (on the QUEUE record's
``PushTokenHash`` slot). When FM posts back, ``/api/upload`` hashes the presented token and
resolves the waiting record — so the raw token never sits at rest anywhere, and a captured
token is useless after its one-time use (the record advances off the ``upload`` step).

This is the whole security model for the inbound push path: *a known (hashable-to-a-waiting-
record) token or the call is rejected*. High entropy (256 bits) makes the raw token
unguessable; sha256 makes the stored hash a safe, non-reversible lookup key.
"""

from __future__ import annotations

import hashlib
import secrets

# 32 bytes → 256 bits of entropy, url-safe (survives an HTTP header / script parameter intact).
_TOKEN_NBYTES = 32


def mint_push_token() -> tuple[str, str]:
    """Return ``(raw, hash)``: a fresh one-time push token and its lookup hash.

    The RAW is handed to FileMaker (the Bearer it will send back) and never stored; the HASH is
    persisted on the pending QUEUE record so the push can be resolved without the raw at rest.
    """
    raw = secrets.token_urlsafe(_TOKEN_NBYTES)
    return raw, hash_push_token(raw)


def hash_push_token(raw: str) -> str:
    """The stored/lookup form of a push token — sha256 hex of the raw. Stable + non-reversible,
    so it is safe to hold in an indexed slot (``QUEUE.PushTokenHash``). Empty in → empty out."""
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
