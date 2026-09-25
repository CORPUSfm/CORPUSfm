"""Import API — QUEUE workspace records (packet 086).

The client DRIVES the import: for each file it POSTs the raw bytes to ``/api/import/source``, a thin
no-parse endpoint that enqueues a ``[upload, ingest]`` QUEUE record (``queue_handlers.enqueue_import``:
create the record, store the source bytes — the client-performed ``upload`` step — then advance
``upload``→``ingest``) and pokes the ingest worker. FM creds never reach the browser; the loop is
per-file and interruptible (the pop-over just stops POSTing). The per-type FIFO ingest worker stores
each record into a fresh STORAGE record; a failed record parks durably (``IsFailed``) for Restart/Delete.
The Queue page reads the QUEUE workspace (``queue_handlers.workspace_view`` — one row per record, packet 1018).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import (
    current_user, require_auth, require_auth_or_mcp_token_gate,
)

# NB: no router-level require_auth. `/import/source` accepts an MCP BEARER (packet 1167 B1) — a
# bearer-only caller has no session, so a router-level require_auth would 401 it before the route's
# own dependency runs. Each route declares its own auth: /import/source = session-or-bearer + gate;
# the owner-or-admin controls below stay session-only.
router = APIRouter()


def _actor(request: Request) -> "tuple[str, bool]":
    """(username, is_admin) for the caller — the SESSION user, else the MCP bearer owner stashed by
    require_auth_or_mcp_token_gate (packet 1167 B-owner), else "local". Attributing to the real bearer
    user is load-bearing: cancel/restart/clear are owner-or-admin, so a bearer import stamped "local"
    would silently prevent that user from cancelling their own import in the multi-user case."""
    u = current_user(request)
    if u is None:
        u = getattr(request.state, "mcp_owner", None)     # bearer path (import/source only)
    return (getattr(u, "username", None) or "local", bool(getattr(u, "is_admin", False)))


@router.post("/import/source",
             dependencies=[Depends(require_auth_or_mcp_token_gate("library_mcp"))])
async def import_source(request: Request,
                        file: UploadFile = File(...),
                        name: str = Form(""),
                        locale: str = Form(""),
                        summarize: bool = Form(False),
                        index: bool = Form(False)) -> JSONResponse:
    """Durably stage one import file's raw source bytes as a QUEUE [upload, ingest] record (no parse
    here) + poke the ingest worker. Same 1 GB cap as the upload path; the source blob is compressed +
    encoded per encrypt_blobs. Returns {ok, id, filename}. The client calls this once per file,
    interruptibly."""
    from corpusfm.app.web.routes.api.upload import _reject_if_oversized, _read_capped, _offload
    from corpusfm.server import queue_handlers, queue_workers
    from corpusfm.storage import get_backend
    from corpusfm.storage.queue_record import INGEST

    _reject_if_oversized(request)
    raw = await _read_capped(file)
    actor, _ = _actor(request)
    filename = file.filename or "import"
    try:
        # enqueue_import creates the [upload, ingest] QUEUE record, stores the source (the client-performed
        # upload), and advances upload→ingest — a blocking FM POST + blob write. Offload it off the event
        # loop (bounded by the shared ingest limiter), same as /api/upload; inline it would freeze the
        # loop for the whole store (packet 061 #3).
        queue_id = await _offload(
            queue_handlers.enqueue_import, get_backend(), raw,
            filename=filename, name=name, locale=locale,
            summarize=summarize, index=index, owner=actor,
        )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("import/source: enqueue_import failed", exc_info=True)
        return JSONResponse({"ok": False, "error": f"Could not stage the import: {exc}"}, status_code=502)
    queue_workers.poke(INGEST)   # wake the ingest worker now (discovery would find it later — a bare wake signal)
    return JSONResponse({"ok": True, "id": queue_id, "filename": filename})


@router.post("/import/poke", dependencies=[Depends(require_auth)])
async def poke_import(request: Request) -> JSONResponse:
    """The client's end-of-run poke (belt-and-suspenders — the per-file POSTs already poke)."""
    from corpusfm.server import queue_workers
    from corpusfm.storage.queue_record import INGEST
    queue_workers.poke(INGEST)
    return JSONResponse({"ok": True})


@router.post("/import/cancel", dependencies=[Depends(require_auth)])
async def cancel_import(request: Request) -> JSONResponse:
    """Cancel a still-queued import by its record UUID (in the body — it may carry a slash, so it rides
    the body). Owner-or-admin; the record being landed right now is refused (409)."""
    from corpusfm.server import queue_handlers
    from corpusfm.storage import get_backend
    body = await request.json()
    queue_id = body.get("id") if isinstance(body, dict) else None
    if not isinstance(queue_id, str) or not queue_id:
        return JSONResponse({"ok": False, "message": "No import id provided."}, status_code=400)
    actor, is_admin = _actor(request)
    # cancel_record does BLOCKING FM reads + a delete; offload it off the event loop (packet 078).
    ok, code, msg = await run_in_threadpool(
        queue_handlers.cancel_record, get_backend(), queue_id, actor, is_admin)
    return JSONResponse({"ok": ok, "message": msg}, status_code=code)


@router.post("/import/clear-failed", dependencies=[Depends(require_auth)])
async def clear_failed_imports(request: Request) -> JSONResponse:
    from corpusfm.server import queue_handlers
    from corpusfm.storage import get_backend
    actor, is_admin = _actor(request)
    n = await run_in_threadpool(queue_handlers.clear_failed_records, get_backend(), actor, is_admin)
    return JSONResponse({"ok": True, "cleared": n})
