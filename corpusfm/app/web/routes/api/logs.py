"""Logs API — GET /api/logs (+ apply-metrics and action-history readers)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


# Synchronous on purpose (packet 1344): this is disk I/O, and FastAPI runs a `def` endpoint in its
# threadpool. As `async def` it read megabytes on the web event loop.
@router.get("/logs", dependencies=[Depends(require_auth)])
def get_logs(lines: int = 100, level: str = "ALL") -> JSONResponse:
    """The newest `lines` matching `level`, across the whole rotation family (packet 1344).

    Was: the current file only, a whole-file read to return a tail, and a level filter that tested
    whether the level word appeared anywhere in the line. The response shape is unchanged, so the
    Logs page needs no change.
    """
    try:
        from datetime import datetime, timezone

        from corpusfm.app.web import log_reader
        from corpusfm.logging_config import log_path as _log_path, rotation_family

        canonical = _log_path()
        members = rotation_family()

        try:
            display, read_members, failures = log_reader.read_tail(members, lines=lines, level=level)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        except log_reader.LogReadError as exc:
            # Every member failed. That is an error, NOT `exists: false` — claiming the log is empty
            # when it could not be read would be the same class of lie as flagging a file missing on
            # a failed scan.
            return JSONResponse({"error": str(exc)}, status_code=500)

        if not read_members:
            return JSONResponse({"lines": [], "exists": False})

        # `path`/`size_kb`/`modified` describe the CANONICAL current file; when it is absent mid-
        # rotation, the newest readable member supplies size/modified so readable history is not
        # hidden, while the path stays canonical.
        stat_source = canonical if canonical.exists() else read_members[0]
        stat = stat_source.stat()
        return JSONResponse({
            "exists": True,
            "lines": display,
            "size_kb": round(stat.st_size / 1024, 1),
            # UTC ISO (packet 1005) — the browser localizes for display (see logs.html).
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
            "path": str(canonical),
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/logs/apply-metrics", dependencies=[Depends(require_auth)])
async def get_apply_metrics(recent: int = 20) -> JSONResponse:
    """Apply-loop thermometer: per-step timing + failure histogram across runs.

    Aggregates apply_metrics.jsonl (coherence / validate / close / apply / swap /
    reopen / verify steps) so the heavy parts of the generate->apply->verify loop
    are visible before anyone optimizes them. Empty when no runs have accumulated.
    """
    try:
        from corpusfm.storage import get_backend
        from corpusfm.server.apply_metrics import (
            metrics_log_path, read_apply_metrics, summarize_apply_metrics,
        )

        archive_dir = getattr(get_backend(), "archive_dir", None)
        if archive_dir is None:
            return JSONResponse({"available": False, "summary": summarize_apply_metrics([]), "recent": []})

        entries = read_apply_metrics(metrics_log_path(archive_dir))
        return JSONResponse({
            "available": True,
            "summary": summarize_apply_metrics(entries),
            "recent": entries[:max(0, recent)],
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/logs/action-history", dependencies=[Depends(require_auth)])
async def get_action_history(limit: int = 200) -> JSONResponse:
    """Artifact-linked tool-action audit trail, newest-first (unified-artifacts §7).

    Distinct from the operational apply-metrics/discovery logs: this is "doing things
    with tools against artifacts is recorded." Each entry links back to its artifact(s).
    """
    try:
        from corpusfm.storage import get_backend
        from corpusfm.server.history import list_history
        backend = get_backend()
        entries = list_history(backend, limit=max(0, limit))
        return JSONResponse({"entries": entries})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)
