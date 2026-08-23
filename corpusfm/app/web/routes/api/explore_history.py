"""API routes for Explorer history."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/explore-history", dependencies=[Depends(require_auth)])
async def list_history() -> JSONResponse:
    """Groom the history against existing artifacts, then return survivors (newest first).

    Opening the Explorer Tool reconciles the trail: records whose artifacts were pruned are
    dropped (their re-open would fail anyway), so the list only shows re-openable sessions.
    """
    from corpusfm.app.explore_history import groom_explore_history
    result = groom_explore_history()
    return JSONResponse({
        "entries": [e.to_dict() for e in result["entries"]],
        "removed": result["removed"],
    })


@router.delete("/explore-history/{history_id}", dependencies=[Depends(require_auth)])
async def delete_entry(history_id: str) -> JSONResponse:
    from corpusfm.app.explore_history import delete_explore_history_entry
    ok = delete_explore_history_entry(history_id)
    return JSONResponse({"ok": ok})
