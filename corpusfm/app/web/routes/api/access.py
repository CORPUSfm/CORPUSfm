"""External-auth (OIDC/LDAP) configuration API — Settings → Access (packet 1065). Admin-gated.

Reads/writes the NON-secret external-auth config in AppConfig.external_auth; the OIDC client_secret and
LDAP bind password go to the Corpus-Key-encrypted SETTING.OidcSecret container (never round-tripped to the
browser — present/absent only). MFA is delegated to the IdP; there is no 2FA config here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth, require_gate, current_user
from corpusfm.app.web.users import GATES

router = APIRouter()

_ADMIN = [Depends(require_auth), Depends(require_gate("settings"))]

_OIDC_STR_KEYS = ("issuer", "client_id", "redirect_uri", "scopes", "groups_claim")
_LDAP_STR_KEYS = ("server_uri", "base_dn", "bind_dn", "user_filter", "group_attr", "user_dn_template")


def _clean_map(raw) -> dict:
    """IdP group value → sorted list of valid gates. Drops unknown gates + empty groups."""
    out: dict = {}
    if isinstance(raw, dict):
        for grp, gates in raw.items():
            g = str(grp).strip()
            if not g:
                continue
            vals = sorted({x for x in (gates or []) if x in GATES})
            if vals:
                out[g] = vals
    return out


@router.get("/settings/external-auth", dependencies=_ADMIN)
async def get_external_auth(request: Request) -> JSONResponse:
    from corpusfm.app.web.settings_authority import load_settings_authority
    from corpusfm.server.oidc_secrets import has_client_secret, has_ldap_bind_password
    from corpusfm.app.web.ldap_auth import ldap3_available
    # Packet 1396: read strictly. A permissive read during an FM outage returned blank oidc/ldap, the
    # browser rendered them as an editable form, and a later save of an UNRELATED slice (the group→gate
    # map) then posted those blanks back — wiping the configured providers. The POST gate cannot catch
    # that, because the destructive payload was built from the outage-time load. So refuse the READ too.
    cfg, _unavail = load_settings_authority()
    if _unavail is not None:
        return _unavail
    ea = dict(cfg.external_auth or {})
    oidc = dict(ea.get("oidc") or {})
    ldap = dict(ea.get("ldap") or {})
    return JSONResponse({
        "gates": list(GATES),
        "oidc": {"enabled": bool(oidc.get("enabled")),
                 **{k: str(oidc.get(k, "")) for k in _OIDC_STR_KEYS}},
        "ldap": {"enabled": bool(ldap.get("enabled")),
                 **{k: str(ldap.get(k, "")) for k in _LDAP_STR_KEYS}},
        "group_gate_map": _clean_map(ea.get("group_gate_map")),
        "has_client_secret": bool(has_client_secret()),
        "has_ldap_bind_password": bool(has_ldap_bind_password()),
        "ldap3_available": bool(ldap3_available()),
    })


@router.post("/settings/external-auth", dependencies=_ADMIN)
async def save_external_auth(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        from corpusfm.app.app_config import save_app_config
        from corpusfm.app.web.settings_authority import load_settings_authority
        from corpusfm.server import oidc_secrets, audit

        # Packet 1396: require a good authoritative read before writing external-auth config OR its
        # secrets — a transient FM outage must not replace a configured identity provider (or its
        # group→gate map and browser-lifetime neighbours) with blanks, then pair stale secrets to it.
        cfg, _unavail = load_settings_authority()
        if _unavail is not None:
            return _unavail
        ea = dict(cfg.external_auth or {})

        oidc_in = dict(body.get("oidc") or {})
        ea["oidc"] = {"enabled": bool(oidc_in.get("enabled")),
                      **{k: str(oidc_in.get(k, "")).strip() for k in _OIDC_STR_KEYS}}
        ldap_in = dict(body.get("ldap") or {})
        ea["ldap"] = {"enabled": bool(ldap_in.get("enabled")),
                      **{k: str(ldap_in.get(k, "")).strip() for k in _LDAP_STR_KEYS}}
        if "group_gate_map" in body:
            ea["group_gate_map"] = _clean_map(body.get("group_gate_map"))

        cfg.external_auth = ea
        # NON-secret only. Packet 1190-02: an exception here is no longer read as proof that nothing
        # was stored. If the config DID land and we skipped the secret writes below, the box would be
        # left advertising a configured identity provider paired with stale or missing credentials —
        # sign-in broken, and nothing on screen saying so.
        from corpusfm.app.app_config import ConfigWriteIndeterminate, ConfigWriteNotCommitted
        try:
            save_app_config(cfg)
        except ConfigWriteNotCommitted as exc:
            # PROVEN unstored: the previous configuration is intact, so writing the new secrets would
            # pair them with it. Leave both halves alone and let the admin resubmit unchanged.
            return JSONResponse(
                {"ok": False,
                 "error": f"The sign-in settings were not saved and nothing was changed — your "
                          f"existing configuration and credentials are untouched. Try again. ({exc})"},
                status_code=503)
        except ConfigWriteIndeterminate as exc:
            # Dispatched, outcome unknown. The secrets are deliberately NOT written: pairing new
            # credentials with a configuration that may not have landed is the worse of the two
            # mismatches, and it is the irreversible one.
            return JSONResponse(
                {"ok": False, "recovery_required": True,
                 "error": f"CORPUSfm could not confirm whether the sign-in settings were saved, so "
                          f"the client secret and bind password were NOT changed. Reload this page "
                          f"to see what is stored, then save again. ({exc})"},
                status_code=503)

        # Secrets: present-and-set → store; present-and-empty → clear; absent → leave unchanged.
        # Packet 1190-02: these setters SWALLOW every storage failure and return False. Ignoring the
        # return reported {"ok": true} while the just-saved provider configuration stayed paired with a
        # stale or missing credential — the exact broken state reconciling the config write above
        # exists to prevent, arriving through the other half of the same operation.
        unwritten = []
        if "client_secret" in body:
            if not oidc_secrets.set_client_secret(str(body.get("client_secret") or "")):
                unwritten.append("client secret")
        if "ldap_bind_password" in body:
            if not oidc_secrets.set_ldap_bind_password(str(body.get("ldap_bind_password") or "")):
                unwritten.append("LDAP bind password")

        # Audited BEFORE the failure branch below, and deliberately: the configuration write is what
        # this event records, and it is confirmed committed by the time we get here. Gating the audit
        # on the SECRET writes would leave a real, admin-visible change to the sign-in configuration
        # with no trail whenever a container write failed.
        me = current_user(request)
        audit.record(audit.EXTERNAL_AUTH_CONFIG_CHANGED, actor=(me.username if me else "admin"),
                     meta={"oidc_enabled": ea["oidc"]["enabled"], "ldap_enabled": ea["ldap"]["enabled"]})

        if unwritten:
            # The configuration DID land — say so, and name what did not, rather than a bare failure
            # that invites the admin to assume the whole save was discarded.
            return JSONResponse(
                {"ok": False, "recovery_required": True,
                 "error": "The sign-in settings were saved, but the "
                          + " and the ".join(unwritten)
                          + " could not be stored — CORPUSfm storage is unreachable or busy. Sign-in "
                            "through this provider will fail until you enter it again."},
                status_code=503)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
