"""Logs API — GET /api/logs, POST /api/logs/open-viewer"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/logs", dependencies=[Depends(require_auth)])
async def get_logs(lines: int = 100, level: str = "ALL") -> JSONResponse:
    try:
        from corpusfm.logging_config import log_path as _log_path
        from datetime import datetime, timezone

        log_file = _log_path()
        if not log_file.exists():
            return JSONResponse({"lines": [], "exists": False})

        stat = log_file.stat()
        all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()

        if level != "ALL":
            all_lines = [l for l in all_lines if level in l]

        display = all_lines[-lines:]
        return JSONResponse({
            "exists": True,
            "lines": display,
            "size_kb": round(stat.st_size / 1024, 1),
            # UTC ISO (packet 1005) — the browser localizes for display (see logs.html).
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
            "path": str(log_file),
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


@router.post("/logs/open-viewer", dependencies=[Depends(require_auth)])
async def open_log_viewer() -> JSONResponse:
    try:
        import subprocess
        import sys
        from corpusfm.logging_config import log_path as _log_path
        log_file = _log_path()
        if not log_file.exists():
            return JSONResponse({"ok": False, "error": "Log file not found."})
        if sys.platform == "darwin":
            subprocess.Popen(["open", str(log_file)])
        elif sys.platform == "win32":
            subprocess.Popen(["notepad", str(log_file)])
        else:
            subprocess.Popen(["xdg-open", str(log_file)])
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
