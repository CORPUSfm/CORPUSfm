"""Monitor / alerts API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/monitor/status", dependencies=[Depends(require_auth)])
async def monitor_status() -> JSONResponse:
    try:
        from corpusfm.server.monitor.alerts import check_conditions
        from corpusfm.server.monitor.config import load_monitor_config

        from corpusfm.storage import get_backend
        from corpusfm.runtime import build_context

        backend = get_backend()
        config = load_monitor_config()
        firing = check_conditions(backend.archive_dir, config)

        scheduler_status = ""
        if build_context().is_server:   # via the runtime layer (S9)
            try:
                from corpusfm.server.scheduler import scheduler_is_running, read_scheduler_status
                if scheduler_is_running():
                    info = read_scheduler_status()
                    ts = (info.get("ts", "") or "")[:19].replace("T", " ")
                    state = (info.get("status") or "")
                    if state == "paused":
                        # Alive, and firing nothing: CORPUSfm cannot read the database, so the
                        # clock evaluates nothing at all (packet 1361-01). Its own word, not
                        # "running".
                        scheduler_status = f"Scheduler paused — storage unreachable — {ts} UTC"
                    else:
                        scheduler_status = f"Scheduler running — {ts} UTC"
                else:
                    scheduler_status = "Scheduler not running"
            except Exception:
                pass

        return JSONResponse({
            "alert_count": len(firing),
            "active_alerts": [
                {
                    "condition": a.condition,
                    # The suppression KEY (packet 1372-02, R4). The Acknowledge button sends this
                    # back; `job_name` beside it is the label the operator reads. Sending only the
                    # name wrote `job_failed:<name>` while the evaluator read `job_failed:<uuid>`,
                    # so the alert kept firing while the operator believed it was muted.
                    "job_uuid":  a.job_uuid or "",
                    "job_name":  a.job_name or "",
                    "message":   a.message,
                    "severity":  a.severity,
                }
                for a in firing
            ],
            "scheduler_status": scheduler_status,
        })
    except Exception as exc:
        return JSONResponse({"alert_count": 0, "active_alerts": [], "scheduler_status": "",
                             "error": str(exc)})


@router.get("/monitor/alerts", dependencies=[Depends(require_auth)])
async def alert_history() -> JSONResponse:
    try:
        from corpusfm.server.monitor.alerts import load_alert_history
        recent = load_alert_history(limit=50)
        return JSONResponse({
            "alerts": [
                {
                    "ts":        e.ts.replace("T", " ")[:19] + " UTC",
                    "severity":  e.severity,
                    "condition": e.condition,
                    "job_name":  e.job_name or "—",
                    "message":   e.message,
                }
                for e in recent
            ]
        })
    except Exception as exc:
        return JSONResponse({"alerts": [], "error": str(exc)})


@router.get("/monitor/job-health", dependencies=[Depends(require_auth)])
async def job_health() -> JSONResponse:
    try:
        from corpusfm.server.monitor.history import get_job_health
        from corpusfm.server.monitor.config import load_monitor_config
        rows = get_job_health(load_monitor_config())
        return JSONResponse({
            "rows": [
                {
                    # Identity first: the Monitoring table keys its rows on this. Keying on `name`
                    # threw `Duplicate key on x-for` the moment two jobs shared a display name, which
                    # is ordinary now (found by the packet 1364 L1 gate on u-test-private).
                    "uuid":        r.uuid,
                    "name":        r.name,
                    "source_type": r.source_type,
                    "schedule":    r.schedule or "—",
                    "last_run":    r.last_run_ts.replace("T", " ")[:19] + " UTC" if r.last_run_ts else "—",
                    "status":      (r.last_status or "—") + (" ⚠ overdue" if r.overdue else ""),
                }
                for r in rows
            ]
        })
    except Exception as exc:
        return JSONResponse({"rows": [], "error": str(exc)})


@router.post("/monitor/suppress", dependencies=[Depends(require_auth)])
async def suppress_alert(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        from corpusfm.server.monitor.alerts import suppress_alert as _suppress
        from corpusfm.server.monitor.config import load_monitor_config
        config = load_monitor_config()
        # Suppress by UUID. `job_name` is accepted only as the fallback key for an alert that has
        # no job at all (a corpus-wide condition), where the name IS the whole scope.
        _suppress(body["condition"], None, config.suppress_hours,
                  job_uuid=(body.get("job_uuid") or "").strip() or None)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/overview", dependencies=[Depends(require_auth)])
async def overview() -> JSONResponse:
    """Aggregate the last 10 activities per group for the Recent activity pop-over.

    Read-only: each group is isolated so one failing source never blanks the page.
    """
    out: dict = {
        "imports": [], "merges": [], "patches": [],
        "explores": [], "diffs": [], "runs": [],
        "total_artifacts": 0, "errors": [],
    }

    # Artifacts → imports / merges / patches (newest-first, capped at 10 each)
    try:
        from corpusfm.storage import get_backend
        backend = get_backend()

        def _fmt(fm_file, meta) -> dict:
            return {
                "fm_file":       fm_file,
                "timestamp":     meta.timestamp,
                "uuid":          meta.uuid,        # canonical record address (packet 085 U3f)
                "origin":        meta.origin,
                "is_addon":      meta.is_addon,
                                "has_icon":      getattr(meta, "has_icon", False),
                "gap_issues":    meta.gap_issues,
                "is_schema":     getattr(meta, "is_schema", False),
                "artifact_type": getattr(meta, "artifact_type", ""),
                "root_uuid":     meta.root_uuid or "",
            }

        # DB-side path (packet 013 fix #3): the FM backend returns each bucket via bounded reads on
        # the indexed Type/Origin/ArtifactTimestamp slots ($filter + $orderby + $top + $count),
        # instead of scanning + sorting every artifact in Python. LocalBackend (no method) keeps the
        # simple full-scan fallback below.
        done = False
        if hasattr(backend, "recent_artifact_buckets"):
            try:
                b = backend.recent_artifact_buckets(limit=10)
                out["total_artifacts"] = int(b.get("total", 0))
                out["imports"] = [_fmt(m.file_name, m) for m in b.get("imports", [])]
                out["merges"]  = [_fmt(m.file_name, m) for m in b.get("merges", [])]
                out["patches"] = [_fmt(m.file_name, m) for m in b.get("patches", [])]
                done = True
            except Exception:
                done = False

        if not done:
            # Ordinary artifact discovery: the persistent catalog, not a STORAGE enumeration on an
            # overview poll (packet 1361-01, ruling 9). Its records already arrive newest-first, and
            # a catalog that could not be read yields nothing rather than a false empty overview.
            from corpusfm.server import catalog
            _view = catalog.view(backend)
            all_metas = [] if _view.failed else [r["meta"] for r in _view.records]
            out["total_artifacts"] = len(all_metas)
            out["imports"], out["merges"], out["patches"] = [], [], []
            for meta in all_metas:
                fm_file = meta.file_name
                atype = getattr(meta, "artifact_type", "")
                if atype == "MergedXML":
                    bucket = out["merges"]
                elif atype == "PatchXML" or meta.origin == "Patch (ISV)":
                    bucket = out["patches"]
                else:
                    bucket = out["imports"]
                if len(bucket) < 10:
                    bucket.append(_fmt(fm_file, meta))
    except Exception as exc:
        out["errors"].append(f"artifacts: {exc}")

    # Explores
    try:
        from corpusfm.app.explore_history import load_explore_history
        out["explores"] = [e.to_dict() for e in load_explore_history(limit=10)]
    except Exception as exc:
        out["errors"].append(f"explores: {exc}")

    # Diffs
    try:
        from corpusfm.app.diff_history import (
            load_diff_history, existing_artifact_paths, entry_artifacts_exist,
        )
        from corpusfm.storage import get_backend
        backend = get_backend()
        entries = load_diff_history(limit=10)
        existing = existing_artifact_paths(
            backend,
            candidates={e.artifact_a for e in entries} | {e.artifact_b for e in entries})
        out["diffs"] = [
            {
                "artifact_a": e.artifact_a, "artifact_b": e.artifact_b,
                "label_a": e.label_a, "label_b": e.label_b,
                "ts_display": e.ts.replace("T", " ")[:16] + " UTC",
                "exists": entry_artifacts_exist(e, backend, existing),
            }
            for e in entries
        ]
    except Exception as exc:
        out["errors"].append(f"diffs: {exc}")

    # Job runs
    try:
        from corpusfm.server.history import list_all_runs
        from corpusfm.storage import get_backend
        backend = get_backend()
        all_runs = []
        # Runs, not live configs (packet 1149) — and each run's OWN frozen label. Iterating configs
        # hid a deleted job's runs entirely; borrowing cfg.name made history re-label itself.
        for run in list_all_runs(backend, limit=200):
            detail = f"{run.duration_s}s · {run.trigger}"
            if run.error:
                detail += f" · {run.error[:60]}"
            all_runs.append({
                "job_name": run.job_name or "—", "ts": run.ts,
                "ts_display": run.ts.replace("T", " ")[:16] + " UTC",
                "status": run.status, "detail": detail,
            })
        all_runs.sort(key=lambda x: x["ts"], reverse=True)
        out["runs"] = all_runs[:10]
    except Exception as exc:
        out["errors"].append(f"runs: {exc}")

    return JSONResponse(out)
