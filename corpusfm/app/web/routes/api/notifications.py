"""JSON API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/health")
async def health() -> JSONResponse:
    """Lightweight readiness probe used by the launcher."""
    return JSONResponse({"ok": True})


@router.get("/status/notifications", dependencies=[Depends(require_auth)])
def notifications_status(request: Request) -> JSONResponse:
    """Polling endpoint for browser notifications (10-second interval).

    Returns the latest job timestamp+status and active alert count so the
    client can detect changes and fire a browser Notification without SSE.

    SYNC `def` on purpose (the packet-061/078 invariant): the jobs read blocks on FM OData and
    this is polled every 10s by every authed tab — an `async def` would run it on the event loop.
    Audit #4: one JOBS read serves every job's (cfg, state) — the old per-job `read_state`
    re-fetched the record `list_jobs` had just parsed (N+1: 10 jobs = 11 round-trips per poll).
    """
    try:
        from corpusfm.server.monitor.alerts import load_alert_history
        from corpusfm.server.jobs.store import list_jobs_with_state, default_jobs_dir

        recent = load_alert_history(limit=50)
        alert_count = len(recent)
        newest_alert = recent[0].message if recent else ""

        latest_ts, latest_name, latest_status = "", "", ""
        for cfg, s in list_jobs_with_state(default_jobs_dir()):
            if s.last_run_ts and s.last_run_ts > latest_ts:
                latest_ts = s.last_run_ts
                latest_name = cfg.name
                latest_status = s.last_status or ""

        return JSONResponse({
            "alert_count": alert_count,
            "newest_alert": newest_alert,
            "latest_job_ts": latest_ts,
            "latest_job_name": latest_name,
            "latest_job_status": latest_status,
        })
    except Exception:
        return JSONResponse({"alert_count": 0, "newest_alert": "", "latest_job_ts": "",
                             "latest_job_name": "", "latest_job_status": ""})
