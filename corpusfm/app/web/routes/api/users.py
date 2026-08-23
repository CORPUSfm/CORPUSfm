"""Admin user management (Settings → Access). Every route requires the 'settings' gate (= Admin).

Manages the multi-user gate store: create, set gates, reset password, activate/deactivate, delete,
rotate a user's MCP token. The store enforces the guards (no self-delete, no removing the last admin)
— those surface here as 400s. Own-password self-service is at System → Your account, not here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth, require_gate, current_user
from corpusfm.app.web import users as us
from corpusfm.server import audit

router = APIRouter()
_ADMIN = [Depends(require_auth), Depends(require_gate("settings"))]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _actor(request: Request) -> str:
    me = current_user(request)
    return me.username if me else "admin"


def _row(u, has_token: bool = False) -> dict:
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name or u.username,
        "gates": sorted(u.gates), "active": u.active, "is_admin": u.is_admin,
        "has_mcp_token": has_token,
    }


@router.get("/users", dependencies=_ADMIN)
async def list_users(request: Request) -> JSONResponse:
    from corpusfm.app.web import mcp_tokens
    me = current_user(request)
    owners = mcp_tokens.owner_ids_with_tokens()   # who holds ≥1 MCP token (one query)
    return JSONResponse({
        "users": [_row(u, u.id in owners) for u in us.load_users()],
        "gates": list(us.GATES),
        "me": (me.id if me else None),
    })


@router.post("/users", dependencies=_ADMIN)
async def create_user(request: Request) -> JSONResponse:
    body = await request.json()
    if len(body.get("password", "")) < 8:
        return JSONResponse({"ok": False, "error": "Password must be at least 8 characters."}, status_code=400)
    me = current_user(request)
    try:
        u = us.create_user(
            body.get("username", ""), body.get("password", ""),
            set(body.get("gates") or []),
            display_name=body.get("display_name", ""),
            created_by=(me.username if me else "admin"), now=_now(),
        )
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    audit.record(audit.USER_CREATED, actor=_actor(request), target=u.username,
                 meta={"gates": sorted(u.gates)})
    return JSONResponse({"ok": True, "user": _row(u)})


@router.patch("/users/{uid}/gates", dependencies=_ADMIN)
async def set_gates(uid: str, request: Request) -> JSONResponse:
    body = await request.json()
    try:
        us.update_user_gates(uid, set(body.get("gates") or []))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    u = us.get_user_by_id(uid)
    audit.record(audit.USER_GATES_CHANGED, actor=_actor(request),
                 target=(u.username if u else uid), meta={"gates": sorted(u.gates) if u else []})
    return JSONResponse({"ok": True, "user": _row(u)})


@router.post("/users/{uid}/password", dependencies=_ADMIN)
async def reset_password(uid: str, request: Request) -> JSONResponse:
    me = current_user(request)
    if me and me.id == uid:
        return JSONResponse({"ok": False, "error": "Use the account page to change your own password."},
                            status_code=400)
    body = await request.json()
    if len(body.get("password", "")) < 8:
        return JSONResponse({"ok": False, "error": "Password must be at least 8 characters."}, status_code=400)
    try:
        us.set_user_password(uid, body.get("password", ""))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    u = us.get_user_by_id(uid)
    audit.record(audit.USER_PASSWORD_RESET, actor=_actor(request),
                 target=(u.username if u else uid))
    return JSONResponse({"ok": True})


@router.post("/users/{uid}/active", dependencies=_ADMIN)
async def set_active(uid: str, request: Request) -> JSONResponse:
    body = await request.json()
    active = bool(body.get("active", True))
    me = current_user(request)
    if me and me.id == uid and not active:
        return JSONResponse({"ok": False, "error": "You can't deactivate your own account."},
                            status_code=400)
    try:
        us.set_user_active(uid, active)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    u = us.get_user_by_id(uid)
    audit.record(audit.USER_ACTIVE_CHANGED, actor=_actor(request),
                 target=(u.username if u else uid), meta={"active": active})
    return JSONResponse({"ok": True, "user": _row(u)})


@router.delete("/users/{uid}", dependencies=_ADMIN)
async def delete_user(uid: str, request: Request) -> JSONResponse:
    me = current_user(request)
    target = us.get_user_by_id(uid)
    target_name = target.username if target else uid
    try:
        us.delete_user(uid, acting_user_id=(me.id if me else ""))
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    audit.record(audit.USER_DELETED, actor=_actor(request), target=target_name)
    return JSONResponse({"ok": True})

# Admin per-user token minting was retired with the move to many self-service tokens (packet 1029) —
# each user manages their own tokens at Library → MCP. No admin mint/rotate route.
