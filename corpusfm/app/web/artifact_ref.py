"""Web-edge artifact address resolution (packet 085 U3f).

The routes address artifacts by their canonical record UUID. A request ref is EITHER a UUID
(passed straight through — the downstream record read is the existence check, so the hot detail
path keeps its single read) OR a human alias (PrimaryName / FileName / tag) resolved here to a
UUID. An alias that matches nothing → 404; an alias that matches several → 409 with the
candidate list (never a guess). ``FileName/Timestamp`` rel_paths are not accepted.
"""
from __future__ import annotations

from fastapi.responses import JSONResponse


def resolve_ref(backend, ref: str) -> "tuple[str, JSONResponse | None]":
    """(uuid, error). ``uuid`` is the record UUID to address the backend with (empty on error);
    ``error`` is a JSONResponse to return as-is (404 not found / 409 ambiguous+candidates) or None.

    A bare UUID is trusted verbatim (no extra read); an alias is resolved via storage.resolve."""
    from corpusfm.storage import resolve as _resolve
    ref = (ref or "").strip()
    if _resolve.is_uuid(ref):
        return ref, None
    r = _resolve.resolve(backend, ref)
    if r.found:
        return r.uuid, None
    if r.ambiguous:
        return "", JSONResponse(
            {"ok": False, "ambiguous": True, "candidates": r.candidates,
             "error": "Ambiguous artifact name — more than one match; specify which."},
            status_code=409)
    return "", JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
