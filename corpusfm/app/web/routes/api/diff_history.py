"""API routes for Diff History."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/diff-history", dependencies=[Depends(require_auth)])
async def list_history() -> JSONResponse:
    """Groom the history against existing artifacts, then return survivors.

    Opening Diff History reconciles the trail: records whose artifacts were
    pruned are dropped (their Re-run would 404 anyway), so the list only shows
    re-runnable comparisons.
    """
    from corpusfm.app.diff_history import groom_diff_history
    result = groom_diff_history()
    return JSONResponse({
        "entries": [e.to_dict() for e in result["entries"]],
        "removed": result["removed"],
    })


@router.delete("/diff-history/{history_id}", dependencies=[Depends(require_auth)])
async def delete_entry(history_id: str) -> JSONResponse:
    from corpusfm.app.diff_history import delete_diff_history_entry
    ok = delete_diff_history_entry(history_id)
    return JSONResponse({"ok": ok})
