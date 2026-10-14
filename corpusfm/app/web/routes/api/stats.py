"""System → Stats read API (packet 1409): any authenticated user, read-only, aggregates only.

Accepts exactly a named ``range`` (``1h`` | ``24h`` | ``7d``) and an optional ``end`` (UTC ISO-8601 or
epoch milliseconds). The resolution follows from the range; a caller cannot choose it, nor ask for a
window wider than a named range. Windows are clamped to the seven-day retention.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()

_ALLOWED_PARAMS = {"range", "end"}


def _parse_end(raw: str) -> int:
    """UTC minute for ``end``: epoch milliseconds, or an ISO-8601 instant that states its offset."""
    s = raw.strip()
    if s.isdigit():
        return int(s) // 60000
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("end must state its UTC offset")
    return int(dt.astimezone(timezone.utc).timestamp() // 60)


@router.get("/stats", dependencies=[Depends(require_auth)])
def get_stats(request: Request) -> JSONResponse:
    from corpusfm.server import metrics, stats_view
    params = request.query_params
    extra = sorted(set(params.keys()) - _ALLOWED_PARAMS)
    if extra:
        return JSONResponse({"ok": False, "error": "unsupported parameter",
                             "allowed": sorted(_ALLOWED_PARAMS)}, status_code=400)
    range_name = params.get("range", "1h")
    if range_name not in stats_view.RANGES:
        return JSONResponse({"ok": False, "error": "unsupported range",
                             "ranges": list(stats_view.RANGES)}, status_code=400)
    end_minute = None
    if params.get("end"):
        try:
            end_minute = _parse_end(params["end"])
        except (ValueError, OverflowError):
            return JSONResponse({"ok": False, "error": "end must be UTC ISO-8601 or epoch milliseconds"},
                                status_code=400)
    try:
        body = stats_view.build(metrics.service(), range_name, end_minute)
    except Exception:                                       # noqa: BLE001 — history unavailable, honestly
        return JSONResponse({"ok": False, "error": "statistics are unavailable"}, status_code=503)
    return JSONResponse(body, headers={"Cache-Control": "no-store"})
