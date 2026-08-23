"""AD/LDAP bind auth (packet 1065 Ph3) — strict FMS parity for orgs on Active Directory / LDAP.

Authenticate by an LDAP **bind** with the entered username/password, read the user's **group
memberships**, and feed them through the SAME group→gate mapping OIDC uses (``external_auth``). Heavier +
org-specific (domain reachability, filters) → this is the completeness path; OIDC covers the modern
majority. ``ldap3`` is imported LAZILY, so a box without it simply reports LDAP unavailable rather than
failing import — and the dependency-lock addition is revalidation-gated.

The ldap3 work is one seam — ``_ldap_authenticate(cfg, username, password)`` — so the resolve/gate/session
logic is unit-testable without a live directory (monkeypatch the seam).
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from corpusfm.app.web import external_auth

log = logging.getLogger("corpusfm.ldap")

# ldap3 is synchronous, so every directory connection gets fixed network bounds.
# connect_timeout limits socket establishment; receive_timeout limits blocking LDAP
# operations such as bind and search. These are operational safety limits, not settings.
LDAP_CONNECT_TIMEOUT_S = 10
LDAP_RECEIVE_TIMEOUT_S = 30


def ldap3_available() -> bool:
    try:
        import ldap3  # noqa: F401
        return True
    except Exception:
        return False


def _ldap_authenticate(cfg: dict, username: str, password: str) -> Optional[Tuple[str, str, list]]:
    """Bind as the user + read their groups. Returns (external_id, display_name, groups) on success, or
    None on any failure (bad creds, unreachable, misconfig). Never raises. The lazy-imported ldap3 seam.

    Model: if a service ``bind_dn`` + bind password are configured, bind as the service to SEARCH for the
    user's DN (+ group_attr), then REBIND as that DN with the entered password to prove identity. With no
    service account, bind directly using ``user_dn_template`` (e.g. ``uid={username},ou=people,{base}``)."""
    if not password:                                 # never allow an anonymous/unauthenticated bind
        return None
    try:
        import ldap3
    except Exception:
        log.warning("ldap: ldap3 not installed — LDAP auth unavailable")
        return None
    try:
        server_uri = str(cfg.get("server_uri", ""))
        if server_uri and not server_uri.lower().startswith("ldaps://"):
            # Not a hard fail: AD commonly uses ldap://389 with Kerberos sign/seal. But a plain
            # ldap:// with simple bind sends the bind + user password in cleartext — surface it.
            log.warning("ldap: server_uri is not ldaps:// — bind credentials may travel unencrypted; "
                        "prefer ldaps:// (see Settings docs)")
        server = ldap3.Server(
            server_uri, get_info=ldap3.NONE, connect_timeout=LDAP_CONNECT_TIMEOUT_S,
        )
        base_dn = str(cfg.get("base_dn", ""))
        user_filter = str(cfg.get("user_filter") or "(uid={username})")
        group_attr = str(cfg.get("group_attr") or "memberOf")
        bind_dn = str(cfg.get("bind_dn", "")).strip()
        user_dn = ""
        display = username
        groups: list = []

        if bind_dn:
            from corpusfm.server.oidc_secrets import read_ldap_bind_password
            svc = ldap3.Connection(server, user=bind_dn, password=read_ldap_bind_password(),
                                   auto_bind=True, receive_timeout=LDAP_RECEIVE_TIMEOUT_S)
            flt = user_filter.replace("{username}", ldap3.utils.conv.escape_filter_chars(username))
            svc.search(base_dn, flt, attributes=[group_attr, "cn", "displayName"])
            if not svc.entries:
                return None
            entry = svc.entries[0]
            user_dn = str(entry.entry_dn)
            display = _first_attr(entry, "displayName") or _first_attr(entry, "cn") or username
            groups = _attr_list(entry, group_attr)
            svc.unbind()
            # Prove identity: rebind as the located user DN with the entered password.
            user_conn = ldap3.Connection(
                server, user=user_dn, password=password,
                receive_timeout=LDAP_RECEIVE_TIMEOUT_S,
            )
            if not user_conn.bind():
                return None
            user_conn.unbind()
        else:
            tmpl = str(cfg.get("user_dn_template") or "").strip()
            if not tmpl:
                return None
            # Escape the untrusted username before it enters a DN (escape_dn_chars) or a search
            # filter (escape_filter_chars) — the service-bind path already does; without it a crafted
            # username (e.g. `*)(uid=admin)`) could inject the group filter and read another entry's
            # groups → gate escalation (packet 1000 P1).
            safe_dn_user = ldap3.utils.conv.escape_dn_chars(username)
            safe_flt_user = ldap3.utils.conv.escape_filter_chars(username)
            user_dn = tmpl.replace("{username}", safe_dn_user).replace("{base}", base_dn)
            user_conn = ldap3.Connection(
                server, user=user_dn, password=password,
                receive_timeout=LDAP_RECEIVE_TIMEOUT_S,
            )
            if not user_conn.bind():
                return None
            user_conn.search(base_dn, user_filter.replace("{username}", safe_flt_user),
                             attributes=[group_attr, "cn", "displayName"])
            if user_conn.entries:
                entry = user_conn.entries[0]
                display = _first_attr(entry, "displayName") or _first_attr(entry, "cn") or username
                groups = _attr_list(entry, group_attr)
            user_conn.unbind()
        return (user_dn or username, display, groups)
    except Exception as exc:
        log.warning("ldap: authenticate failed: %s", exc)
        return None


def _first_attr(entry, name: str) -> str:
    try:
        v = entry[name].value
        if isinstance(v, (list, tuple)):
            return str(v[0]) if v else ""
        return str(v) if v else ""
    except Exception:
        return ""


def _attr_list(entry, name: str) -> list:
    try:
        v = entry[name].value
        if v is None:
            return []
        return [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]
    except Exception:
        return []


def ldap_login(username: str, password: str, *, backend=None):
    """Authenticate a user against LDAP and resolve/JIT the CORPUSfm account. Returns the User or None.
    Called from the /login POST as a fallback when no local password matches and LDAP is enabled."""
    if not external_auth.ldap_enabled():
        return None
    cfg = external_auth.ldap_settings()
    res = _ldap_authenticate(cfg, username, password)
    if res is None:
        return None
    external_id, display, groups = res
    return external_auth.resolve_external_user(
        external_id=external_id, preferred_username=username, display_name=display,
        auth_method="ldap", groups=groups, backend=backend)
