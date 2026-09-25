"""JSON API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth
from corpusfm.app.web.deps import get_ctx
from corpusfm.runtime import AppContext

router = APIRouter()


@router.get("/health")
async def health() -> JSONResponse:
    """Lightweight LOCAL liveness/readiness probe. The one endpoint reachable while paused.

    ``ok`` is process liveness, exactly as the launcher has always read it. ``database_ready`` is the
    single local fact added by packet 1361-01, round 3: it is the in-memory gate state — no database
    read, no catalog read, no diagnostics — and it exists so the paused waiting page can reload
    itself the moment recovery succeeds.

    ``state`` and ``phase`` are the DIAGNOSTIC reason a paused process gives for itself (round 7):
    `initializing`, `unavailable` or `intervention`. They change what a person is TOLD and nothing
    else — `database_ready` is the only fact any consumer branches on, and it is False for all three.
    Every value here is read from process memory.

    **While the process is paused this route is not reached at all**: the pause boundary answers the
    liveness path itself, because the deployment gate sits inside it and would redirect an
    un-migrated box's poll to `/needs-upgrade`. This is the READY answer.
    """
    from corpusfm.server import availability
    return JSONResponse({"ok": True, "database_ready": availability.is_open(),
                         "state": "ready" if availability.is_open() else "paused",
                         "phase": availability.phase()})


@router.get("/status/notifications", dependencies=[Depends(require_auth)])
def notifications_status(request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    """Polling endpoint for browser notifications (30-second visible-tab interval).

    Returns the latest job timestamp+status and active alert count so the
    client can detect changes and fire a browser Notification without SSE.

    **It is NOT exempt from the pause boundary** (packet 1361-01, round 3). It reads ALERT and JOB,
    from every open tab on a repeating clock — a database operation which is
    precisely what a paused process may not perform. Its `except` made that worse rather than safer:
    a failed read became a zeroed result indistinguishable from "no alerts, no runs". While paused it
    never executes; the middleware answers with the standard unavailable body.

    SYNC `def` on purpose (the packet-061/078 invariant): the jobs read blocks on FM OData and
    this is polled by every authed tab — an `async def` would run it on the event loop.
    Audit #4: one JOBS read serves every job's (cfg, state) — the old per-job `read_state`
    re-fetched the record `list_jobs` had just parsed (N+1: 10 jobs = 11 round-trips per poll).

    ONE backend serves BOTH reads (packet 1361-01). Each read used to resolve its own through the
    global `get_backend()`, which on a published installation builds a fresh backend and pays a TLS
    handshake — twice, on a route every open tab polls repeatedly.

    And both reads are STRICT. The `except` that used to wrap this returned zeros, which the browser
    cannot tell from "no alerts, no runs": a storage outage was published to every tab as good news.
    A typed read failure now returns the same degraded 503 + `X-CORPUSfm-Storage` the auth layer
    uses, so the SPA enters the offline behaviour it already has.
    """
    from corpusfm.server.jobs.store import JobsStoreUnavailable, list_jobs_with_state
    from corpusfm.server.monitor.alerts import load_alert_history
    from corpusfm.storage.repos import AlertReadUnavailable, JobReadUnavailable

    backend = ctx.storage()

    try:
        recent = load_alert_history(limit=50, strict=True, backend=backend)
        jobs = list_jobs_with_state(strict=True, backend=backend)
    except (AlertReadUnavailable, JobReadUnavailable, JobsStoreUnavailable) as exc:
        # A TYPED read failure: the authority could not be read. Anything else propagates — a
        # programming or contract error published as "no alerts" is the fabricated-zero this
        # correction removes, and it would arrive on a ten-second clock.
        raise HTTPException(status_code=503, detail="storage temporarily unavailable",
                            headers={"X-CORPUSfm-Storage": "unavailable"}) from exc

    alert_count = len(recent)
    newest_alert = recent[0].message if recent else ""

    latest_ts, latest_name, latest_status = "", "", ""
    for cfg, st in jobs:
        if st.last_run_ts and st.last_run_ts > latest_ts:
            latest_ts = st.last_run_ts
            latest_name = cfg.name
            latest_status = st.last_status or ""

    return JSONResponse({
        "alert_count": alert_count,
        "newest_alert": newest_alert,
        "latest_job_ts": latest_ts,
        "latest_job_name": latest_name,
        "latest_job_status": latest_status,
    })
