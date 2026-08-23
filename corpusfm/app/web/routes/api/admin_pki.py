"""Read-only Settings view and live test of the installation-owned Admin API identity."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import actor_from_request, require_auth, require_gate
from corpusfm.server import audit, fms_admin_pki as pki
from corpusfm.server.admin_api_identity import admin_api_identity
from corpusfm.server.fms_transport import colocated

router = APIRouter(dependencies=[Depends(require_auth), Depends(require_gate("settings"))])


def _public_status() -> dict:
    identity = admin_api_identity()
    cfg = identity.config or {}
    return {
        "state": identity.state,
        "available": identity.available,
        "reason": identity.reason,
        "remedy": identity.remedy,
        "name": cfg.get("name", "") if identity.available else "",
        "host": cfg.get("host", "") if identity.available else "",
    }


@router.get("/admin-identity/status")
async def status() -> JSONResponse:
    return JSONResponse(_public_status())


@router.post("/admin-identity/test")
async def test(request: Request) -> JSONResponse:
    identity = admin_api_identity()
    if not identity.available:
        return JSONResponse({"ok": False, **_public_status()}, status_code=409)
    cfg = identity.config or {}
    token = None
    verify_ssl = False
    try:
        verify_ssl = colocated().verify_ssl
        token = pki.authenticate(cfg["host"], cfg["name"], cfg["private_pem"], verify_ssl=verify_ssl)
        dbs = pki.list_databases(cfg["host"], token, verify_ssl=verify_ssl)
        audit.record(audit.PKI_CHANGED, actor=actor_from_request(request),
                     target=cfg.get("name", ""), meta={"op": "test-installed"})
        return JSONResponse({"ok": True, "database_count": len(dbs)})
    except Exception as exc:
        audit.record(audit.PKI_CHANGED, actor=actor_from_request(request),
                     target=cfg.get("name", ""), outcome="error", meta={"op": "test-installed"})
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    finally:
        if token:
            pki.logout(cfg["host"], token, verify_ssl=verify_ssl)
