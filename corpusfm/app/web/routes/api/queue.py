"""Server queue API (packet 052 / packet 086 unified workspace).

The shared, system-wide view of background work (imports + enrichment) + owner-or-admin controls.
Viewing is open to any authenticated user (transparency — summaries take 10–30 min, this is how you
see what's holding up the show); cancel/restart/clear are owner-or-admin. Everything is now ONE QUEUE
workspace (packet 086): imports (upload/land steps) and enrichment (summarize/index steps) are records
on the same queue, drained by per-type FIFO workers.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import current_user, require_auth
from corpusfm.app.web.deps import get_ctx
from corpusfm.runtime import AppContext

router = APIRouter(dependencies=[Depends(require_auth)])


def _actor(request: Request) -> tuple[str, bool]:
    u = current_user(request)
    return (getattr(u, "username", None) or "local",
            bool(getattr(u, "is_admin", False)))


@router.get("/queue")
def get_queue(request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    """The shared, record-centric queue view (packet 1018) + the caller's identity so the UI can show
    cancel/restart only where allowed. `records` is EVERY live QUEUE record as one row carrying its whole
    step pipeline + current step + status — the one QUEUE workspace (packet 086), not sliced by kind.

    SYNC `def` on purpose (packet 061): `workspace_view` does BLOCKING FM OData reads, and this route is
    polled ~every 1.5s during activity — an `async def` would run them on the event loop, so a
    slow/blipping FMS would freeze the whole app. FastAPI runs a sync route in the threadpool, keeping the
    loop free.

    ``activity`` + ``generation`` + ``activity_sources`` (packet 1136 Stage 1) are ADDITIVE: the unified
    activity feed — durable rows normalized to the activity-record contract PLUS the ephemeral generation
    tasks, under a per-process generation token (restart-eviction vs unknown-expired) and per-source
    observation-validity flags (``activity_sources.{durable,ephemeral}.ok`` — a failed read is
    distinguishable from an empty one). ``records`` stays the durable-only Queue-page view UNCHANGED; no
    consumer of ``activity`` exists yet (Stage 2).

    ONE backend, from the composed context (packet 1361-01). This route resolved its own through the
    global `get_backend()`, which on a published installation builds a fresh FileMakerODataBackend
    and pays a TLS handshake — on the second-most-frequent recurring path in the product (every 1-5s
    during activity, every 30s idle, from every open tab), and alongside the retained backend the
    auth layer had already resolved for the very same request."""
    from corpusfm.server import activity_feed
    actor, is_admin = _actor(request)
    be = ctx.storage()
    feed = activity_feed.build_feed(be)
    sources = feed["sources"]
    # Derive the Queue view AND the failed badge from the SINGLE durable read `build_feed` already did
    # (packet 1160) — the old route read `workspace_view` a SECOND time plus a separate `failed_count`
    # query per ~1s poll, tripling the durable round-trips into an FMS that a running acquire is already
    # saturating. `durable_rows` is the raw workspace_view output, and is `[]` exactly when
    # `sources.durable.ok` is False — so this preserves the packet-1000 per-source degradation (serve
    # empty durable records + `durable.ok=false`, retain last-known client-side, keep the healthy
    # ephemeral half updating), with no unguarded re-read that could 500 the route.
    records = feed.get("durable_rows", [])
    failed = sum(1 for r in records if r.get("status") == "failed")
    return JSONResponse({"ok": True, "me": actor, "is_admin": is_admin,
                         "records": records, "failed_count": failed,
                         "activity": feed["records"], "generation": feed["generation"],
                         "activity_sources": sources})


# cancel/restart/clear are SYNC `def` on purpose (packet 078): they do BLOCKING FM OData reads + writes.
# An `async def` would run them on the event loop, so a slow/blipping FMS while a user clicks would
# freeze the whole app. FastAPI runs a sync route in the threadpool, keeping the loop free.

@router.post("/queue/{job_id}/cancel")
def cancel_job(job_id: str, request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    from corpusfm.server import queue_handlers
    actor, is_admin = _actor(request)
    ok, code, msg = queue_handlers.cancel_record(ctx.storage(), job_id, actor, is_admin)
    return JSONResponse({"ok": ok, "message": msg}, status_code=code)


@router.post("/queue/{job_id}/restart")
def restart_job(job_id: str, request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    from corpusfm.server import queue_handlers
    actor, is_admin = _actor(request)
    ok, code, msg = queue_handlers.restart_record(ctx.storage(), job_id, actor, is_admin)
    return JSONResponse({"ok": ok, "message": msg}, status_code=code)


@router.post("/queue/clear-failed")
def clear_failed(request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    from corpusfm.server import queue_handlers
    actor, is_admin = _actor(request)
    n = queue_handlers.clear_failed_records(ctx.storage(), actor, is_admin)
    return JSONResponse({"ok": True, "cleared": n})
