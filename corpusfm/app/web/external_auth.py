"""External-auth shared core (packet 1065) — the IdP-agnostic half of OIDC + AD/LDAP.

Authentication (WHO) delegates to the IdP; authorization (WHAT) stays CORPUSfm's five gates. This module
owns the parts both providers share: the **group/claim → gate mapping** (Ph2 authorization parity), the
**JIT resolve/create** of an external user, and **session establishment**. The provider-specific flow
lives in ``oidc.py`` (auth-code) and ``ldap_auth.py`` (bind). MFA is the IdP's job — CORPUSfm builds no
2FA (parity with FMS). Local username/password is always retained as a per-user option + break-glass.
"""

from __future__ import annotations

import re
import time as _time
from typing import Optional

from corpusfm.app.web.users import GATES


# ── config accessors (non-secret; from AppConfig.external_auth) ────────────────

def _external_auth_cfg() -> dict:
    from corpusfm.app.app_config import load_app_config
    try:
        return dict(load_app_config().external_auth or {})
    except Exception:
        return {}


def oidc_settings() -> dict:
    return dict(_external_auth_cfg().get("oidc") or {})


def ldap_settings() -> dict:
    return dict(_external_auth_cfg().get("ldap") or {})


def group_gate_map() -> dict:
    """IdP group/claim value → list of gates. E.g. {"CORPUSfm-Admins": ["settings"]}."""
    return dict(_external_auth_cfg().get("group_gate_map") or {})


def oidc_enabled() -> bool:
    """OIDC is usable: enabled + issuer + client_id configured AND a client_secret stored."""
    c = oidc_settings()
    if not (c.get("enabled") and c.get("issuer") and c.get("client_id")):
        return False
    try:
        from corpusfm.server.oidc_secrets import has_client_secret
        return has_client_secret()
    except Exception:
        return False


def ldap_enabled() -> bool:
    c = ldap_settings()
    return bool(c.get("enabled") and c.get("server_uri") and c.get("base_dn"))


# ── group → gate mapping (Ph2) ────────────────────────────────────────────────

def map_groups_to_gates(groups) -> set:
    """Union of the gates every one of the user's IdP groups maps to. No matching group → empty set →
    no access (the zero-access default). Case-insensitive group match; gates filtered to the real five."""
    mp = group_gate_map()
    have = {str(g).strip().lower() for g in (groups or []) if str(g).strip()}
    out: set = set()
    for grp, gates in mp.items():
        if str(grp).strip().lower() in have:
            out |= {g for g in (gates or []) if g in GATES}
    return out


# ── JIT resolve/create + session ──────────────────────────────────────────────

def _derive_username(preferred: str, external_id: str) -> str:
    """A stable, storeable username from IdP claims — sanitized to the create rules (alnum + _ . - @)."""
    base = (preferred or external_id or "").strip()
    base = re.sub(r"[^A-Za-z0-9_.\-@]", "", base) or "sso-user"
    return base[:64]


def resolve_external_user(*, external_id: str, preferred_username: str, display_name: str,
                          auth_method: str, groups, backend=None):
    """Find (by external_id) or JIT-create the external user, then set their effective gates from the
    group→gate mapping (authoritative + refreshed each login). Returns the (fresh) User or None on
    failure. New users are created with ZERO gates first, so a race/JIT never briefly over-grants."""
    from corpusfm.app.web import users as users_store
    xid = (external_id or "").strip()
    if not xid:
        return None
    gates = map_groups_to_gates(groups)
    u = users_store.get_user_by_external_id(xid, auth_method=auth_method, backend=backend)
    if u is None:
        uname = _unique_username(_derive_username(preferred_username, xid), backend=backend)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()   # UTC, server-stamped (packet 1005)
        try:
            u = users_store.create_external_user(
                uname, auth_method=auth_method, external_id=xid, gates=(),
                display_name=display_name or uname, created_by=f"{auth_method}:jit", now=now,
                backend=backend)
        except Exception:
            return None
        from corpusfm.server import audit as _a
        _audit(_a.USER_JIT_CREATED, u.username, {"auth_method": auth_method})
    # Gates flow from IdP groups every login (add AND remove) — the FMS re-evaluate-on-connect model.
    try:
        users_store.apply_sso_gates(u.id, gates, backend=backend)
    except Exception:
        pass
    return users_store.get_user_by_id(u.id, backend=backend) or u


def _unique_username(base: str, *, backend=None) -> str:
    """base if free, else base-2, base-3, … so a JIT create never collides with an existing account."""
    from corpusfm.app.web import users as users_store
    if users_store.get_user(base, backend=backend) is None:
        return base
    for n in range(2, 1000):
        cand = f"{base}-{n}"
        if users_store.get_user(cand, backend=backend) is None:
            return cand
    return f"{base}-{int(_time.time())}"


def establish_session(request, user, *, auth_method: str) -> None:
    """Set the same signed-session keys the local /login POST sets (packet 1030 sliding + absolute cap)."""
    now = int(_time.time())
    request.session["user_id"] = user.id
    request.session["issued_at"] = now
    request.session["seen"] = now
    # One post-login opportunity to offer the waiting-update prompt (packet 1341). Consumed by the
    # first authenticated shell load whether it shows or suppresses, so the prompt cannot reappear
    # by navigating; the next REAL sign-in creates a new one.
    request.session["update_prompt_opportunity"] = True
    from corpusfm.server import audit as _a
    _audit(_a.AUTH_SSO_LOGIN, user.username, {"auth_method": auth_method})


def _audit(action: str, actor: str, meta: dict) -> None:
    try:
        from corpusfm.server import audit
        audit.record(action, actor=actor, meta=meta)
    except Exception:
        pass
