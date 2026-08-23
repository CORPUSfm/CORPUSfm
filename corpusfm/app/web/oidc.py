"""OIDC auth-code flow (packet 1065 Ph1) — the modern-IdP half of FMS-parity external auth.

A generic **custom OIDC** client (one config covers Google / Microsoft / Okta / Amazon — all OIDC). The
flow: ``/auth/oidc/login`` → redirect to the IdP with **state + nonce + PKCE** (authlib stores them in the
signed session); ``/auth/oidc/callback`` → authlib validates the ID token (**JWKS signature, issuer,
audience, expiry, nonce**), then we resolve/JIT the user, apply group→gate mapping, and establish the
existing signed session. Fail-closed: an IdP/JWKS error surfaces a login error but **local login still
works** (break-glass). Authlib is a maintained library and is already in the box constraints lock.

The ID-token validation + token exchange is a single seam — ``_fetch_userinfo(request)`` — so the JIT /
gate / session logic around it is unit-testable without a live IdP (monkeypatch the seam; the HTTP/JWT
validation itself is authlib's job).
"""

from __future__ import annotations

import logging
from typing import Optional

from corpusfm.app.web import external_auth

log = logging.getLogger("corpusfm.oidc")

_REGISTERED_NAME = "cfm_oidc"


def _build_client():
    """A fresh authlib Starlette OAuth client from current config. Rebuilt per request so a config
    change takes effect with no restart. Raises if authlib is unavailable (deps not installed)."""
    from authlib.integrations.starlette_client import OAuth
    from corpusfm.server.oidc_secrets import read_client_secret
    c = external_auth.oidc_settings()
    issuer = str(c.get("issuer", "")).rstrip("/")
    oauth = OAuth()
    oauth.register(
        name=_REGISTERED_NAME,
        client_id=str(c.get("client_id", "")),
        client_secret=read_client_secret(),
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs={"scope": str(c.get("scopes") or "openid email profile"),
                       "code_challenge_method": "S256"},   # PKCE
    )
    return oauth.create_client(_REGISTERED_NAME)


def _redirect_uri(request) -> str:
    """The configured redirect_uri (must match the IdP app registration), else derive it from this
    request behind the reverse proxy."""
    c = external_auth.oidc_settings()
    uri = str(c.get("redirect_uri", "")).strip()
    if uri:
        return uri
    from corpusfm.app.web.deployment import prefixed
    base = str(request.base_url).rstrip("/")
    return base + prefixed(request, "/auth/oidc/callback")


async def login_redirect(request):
    """Begin the auth-code flow: 302 to the IdP with state+nonce+PKCE (stored in the session)."""
    client = _build_client()
    return await client.authorize_redirect(request, _redirect_uri(request))


async def _fetch_userinfo(request) -> dict:
    """Exchange the code and return VALIDATED ID-token claims. authlib validates signature (JWKS),
    issuer, audience, expiry, and nonce inside authorize_access_token. The single mockable seam."""
    client = _build_client()
    token = await client.authorize_access_token(request)   # validates the id_token
    return dict(token.get("userinfo") or {})


def _extract_groups(claims: dict):
    c = external_auth.oidc_settings()
    key = str(c.get("groups_claim") or "groups")
    val = claims.get(key)
    if isinstance(val, str):
        return [g for g in val.replace(",", " ").split() if g]
    if isinstance(val, (list, tuple)):
        return [str(g) for g in val]
    return []


async def handle_callback(request):
    """Complete the flow. Returns (user, None) on success or (None, error_message) on failure — the
    route establishes the session on success or re-renders login with the error (local login intact)."""
    try:
        claims = await _fetch_userinfo(request)
    except Exception as exc:                       # IdP/JWKS/token error → fail-closed to local login
        log.warning("oidc: callback failed: %s", exc)
        return None, "SSO sign-in failed. Try again, or sign in with a local account."
    sub = str(claims.get("sub") or "").strip()
    email = str(claims.get("email") or "").strip()
    external_id = sub or email
    if not external_id:
        return None, "SSO sign-in failed: the identity provider returned no subject or email."
    preferred = (str(claims.get("preferred_username") or "").strip()
                 or (email.split("@")[0] if email else "") or sub)
    display = str(claims.get("name") or "").strip() or preferred
    user = external_auth.resolve_external_user(
        external_id=external_id, preferred_username=preferred, display_name=display,
        auth_method="oidc", groups=_extract_groups(claims))
    if user is None:
        return None, "SSO sign-in failed: could not provision the account."
    external_auth.establish_session(request, user, auth_method="oidc")
    return user, None
