"""Authentication for CORPUSfm web UI.

Standalone mode: no auth — all requests pass through.
Server mode:     per-user login (the USER storage table, PBKDF2-SHA256 password hashes held in a
                 Corpus-Key-encrypted container — packet 1007); every protected route checks the session
                 cookie via require_auth(). Direct URL parameter attacks are blocked at the route
                 level, not just the login page.

Session signing: itsdangerous via Starlette SessionMiddleware; secret from
                 CORPUSFM_SESSION_SECRET env var or ~/.corpusfm/session_secret (auto-generated).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse

from corpusfm.config import is_server_mode


def _enforces(request: Request) -> bool:
    """Whether this request must enforce auth/gates, from the composed AuthPolicy on the app
    (packet 006, S3). Falls back to is_server_mode() when no AppContext is on app.state — a bare
    test app or a non-app request — so behaviour is identical to the prior direct checks."""
    try:
        return bool(request.app.state.ctx.auth_policy.enforces)
    except Exception:
        return is_server_mode()


# ── Session secret ─────────────────────────────────────────────────────────────

def _session_secret() -> str:
    """Resolve the session secret from THIS installation's secrets directory.

    **Called lazily, never at import (packet 1246-03-01).** This module used to end with
    `SESSION_SECRET: str = _session_secret()`, evaluated the moment anything imported `auth` — which
    was harmless while the answer was `Path.home()`, because `HOME` is always defined, and became a
    defect the instant the answer came from an installation record: import order decided whether the
    process could resolve at all, and any later publication left the frozen value behind. It is the
    same import-time freeze the key constants had, in a module nobody thought of as a path consumer.
    """
    from corpusfm.lifecycle import app_paths

    # DEVELOPMENT ONLY (packet 1246-03-01). On a published installation the signing secret is the
    # installed file and nothing else: an environment variable that could replace it is a way to
    # mint valid sessions for this box from outside its own record.
    env = app_paths.development_override(
        "CORPUSFM_SESSION_SECRET",
        lambda: os.environ.get("CORPUSFM_SESSION_SECRET", "").strip(),
        what="the web session signing secret")
    if env:
        return env

    # REPLACEABLE (developer ruling, 2026-08-03). A regenerated signing secret costs every live
    # session a re-login and nothing else — no stored value becomes unreadable. So it is recreated at
    # the authoritative published path rather than refused. Only the Corpus Key is irreplaceable.
    key_file = app_paths.secrets_dir() / "session_secret"
    if key_file.exists():
        return key_file.read_text().strip()
    secret = secrets.token_hex(32)
    from corpusfm.core.secure_fs import write_text_private
    write_text_private(key_file, secret)
    return secret


def session_secret() -> str:
    """The signing secret, resolved on first use and cached for the process.

    `reset_session_secret()` drops it, and `app_paths.reset_cache()` calls that — the cache must not
    outlive the paths it was derived from.
    """
    global _cached_session_secret
    if _cached_session_secret is None:
        _cached_session_secret = _session_secret()
    return _cached_session_secret


def reset_session_secret() -> None:
    global _cached_session_secret
    _cached_session_secret = None


_cached_session_secret: str | None = None


def _register_with_app_paths() -> None:
    from corpusfm.lifecycle import app_paths

    app_paths.register_cache_reset(reset_session_secret)


_register_with_app_paths()


# ── Session lifetime (sliding with an absolute cap — packet 1030) ───────────────
# The web session is a signed cookie. It SLIDES on activity (idle-only timeout) but can never
# outlive the absolute cap from login. Keep these here so the SessionMiddleware max_age and the
# slide logic below can't drift (a config guard asserts they match).

SESSION_IDLE_TIMEOUT = 12 * 3600            # 43200 — SessionMiddleware max_age + the sliding window
SESSION_ABSOLUTE_MAX = 7 * 24 * 3600        # 604800 — hard ceiling from login, even for active use
SESSION_REFRESH_AFTER = SESSION_IDLE_TIMEOUT // 2   # 21600 (6h) — only re-stamp past this boundary


def _slide_session(request: Request) -> bool:
    """Enforce the absolute cap + rolling refresh on an already-authenticated request. Returns False
    when the session has exceeded the absolute ceiling (caller should treat it as unauthenticated).

    The trick: WRITING to the session flips Starlette's `session.modified`, so it re-signs the cookie
    with a fresh timestamp — restarting the 12h idle clock. We only write once activity crosses the
    6h refresh boundary, so we don't emit a Set-Cookie on every response."""
    if "session" not in request.scope:          # bare test app / no SessionMiddleware
        return True
    s = request.session
    now = int(time.time())
    if "issued_at" not in s:
        s["issued_at"] = now                    # anchor an in-flight (pre-1030) / anchor-less session on
                                                # first sight — a WRITE, so the cap actually persists and
                                                # engages. Without this the cap read defaults to `now`
                                                # every request → `now - now` never trips → uncapped.
    if now - int(s["issued_at"]) > SESSION_ABSOLUTE_MAX:
        s.clear()                               # → this request 401s → base.html sends them to /login
        return False
    if now - int(s.get("seen", 0)) > SESSION_REFRESH_AFTER:
        s["seen"] = now                         # WRITE → session.modified → Starlette re-signs the cookie
    return True


# ── Password helpers ───────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"{salt}:{dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, dk_hex = stored_hash.split(":", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk.hex(), dk_hex)


# ── Auth dependency ────────────────────────────────────────────────────────────

def current_user(request: Request):
    """Resolve the logged-in user from the session, or None (also None in standalone mode)."""
    if not _enforces(request):
        return None
    # No SessionMiddleware in scope (a bare test app / non-session context) → touching
    # request.session would raise. Mirror require_gate's guard and treat it as no user.
    if "session" not in request.scope:
        return None
    uid = request.session.get("user_id")
    if not uid:
        return None
    from corpusfm.app.web.users import get_user_by_id
    u = get_user_by_id(uid)
    return u if (u and u.active) else None


def actor_from_request(request: Request) -> str:
    """Best-available actor name for the security audit ledger: the authenticated user, or
    a stable fallback ("admin") when no session user can be resolved (admin-gated route)."""
    u = current_user(request)
    return u.username if u else "admin"


def _auth_redirect(request: Request, status: int, detail: str, location: str):
    from corpusfm.app.web.deployment import route_path, prefixed
    if route_path(request).startswith("/api/"):
        raise HTTPException(status_code=status, detail=detail)
    raise HTTPException(status_code=302, headers={"location": prefixed(request, location)})


def _storage_down_for_session(request: Request) -> bool:
    """True when the session NAMES a user but the USER store can't be read (storage outage) — as
    opposed to no session or a genuinely deleted user (packet 1067). Distinguishes a degraded backend
    from an expired session so an outage returns a 503 the SPA can pause on, instead of a 401 that
    redirect-churns every poller to /login."""
    if "session" not in request.scope:
        return False
    uid = request.session.get("user_id")
    if not uid:
        return False
    from corpusfm.app.web.users import get_user_by_id, UserStoreUnavailable
    try:
        get_user_by_id(uid, raise_on_error=True)
    except UserStoreUnavailable:
        return True
    except Exception:
        return False
    return False


def require_auth(request: Request) -> None:
    """FastAPI dependency. Logged-in (any active user) required in server mode."""
    if not _enforces(request):
        return
    if current_user(request) is not None and _slide_session(request):
        return
    # A storage OUTAGE on an authenticated session is degraded, not expired: for an in-page /api/*
    # poller, return 503 + a header the SPA reads to pause + show the connectivity toast, rather than a
    # 401 that drives the redirect-churn peg (packet 1067). Page routes still fall through to the login
    # redirect (rendering /login needs no DB, and it unloads the churning SPA).
    from corpusfm.app.web.deployment import route_path
    if route_path(request).startswith("/api/") and _storage_down_for_session(request):
        raise HTTPException(status_code=503, detail="storage temporarily unavailable",
                            headers={"X-CORPUSfm-Storage": "unavailable"})
    _auth_redirect(request, 401, "Authentication required", "/login")


def require_auth_or_mcp_token_gate(gate: str):
    """Dependency factory: like require_auth, but ALSO accepts a valid MCP per-user bearer token
    (the same credential used for MCP tools) AND enforces `gate` for whichever credential resolves.
    For READ-ONLY routes an agent legitimately reaches — e.g. downloading a stored deliverable's
    bytes it can already read over MCP (`get_deliverable`).

    The gate is the load-bearing half: the token/session must carry `gate`, so this grants nothing
    the caller couldn't already read over MCP under that same gate. The router-level `require_gate`
    is a no-op for a bearer-only caller (no session user), so WITHOUT this check a token missing the
    gate would still download — defeating per-user gate scoping (packet 1000 P1). Session path first."""
    def _dep(request: Request) -> None:
        if not _enforces(request):
            return
        u = current_user(request)
        if u is not None and _slide_session(request):
            if not u.has_gate(gate):
                _auth_redirect(request, 403, f"Access denied (requires {gate})", "/docs")
            return
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:]:
            from corpusfm.app.web import mcp_tokens
            owner = mcp_tokens.resolve(auth_header[7:])
            if owner is not None:
                if not owner.has_gate(gate):
                    raise HTTPException(status_code=403, detail=f"Access denied (requires {gate})")
                # Surface the resolved token owner to the route so a WRITE route can attribute the
                # record to the REAL user, not "local" (packet 1167 B-owner). A read route ignores it.
                # Without this the owner is discarded and a bearer import would stamp owner="local",
                # silently breaking owner-or-admin cancel/restart in the multi-user case.
                request.state.mcp_owner = owner
                return
        _auth_redirect(request, 401, "Authentication required", "/login")
    return _dep


# The library download routes read stored artifacts/deliverables — the library_mcp read surface.
require_auth_or_mcp_token = require_auth_or_mcp_token_gate("library_mcp")


def require_gate(gate: str):
    """Dependency factory: enforce `gate` for the resolved user. PAIR it with require_auth, which
    enforces login — this is soft on a missing user (defers to require_auth) so that a logged-in
    user lacking the gate is bounced to Documentation (page) / 403 (api), while not double-handling
    the not-logged-in case. 'settings' = Admin."""
    def _dep(request: Request) -> None:
        if not _enforces(request):
            return
        # No session in scope → no authenticated-user context (a bare test app with no
        # SessionMiddleware). Defer to require_auth rather than touching request.session
        # (which would raise). The real app always has the middleware.
        if "session" not in request.scope:
            return
        u = current_user(request)
        if u is not None and not u.has_gate(gate):
            _auth_redirect(request, 403, f"Access denied (requires {gate})", "/docs")
    return _dep


def require_any_gate(*gates: str):
    """Like require_gate, but passes when the user holds ANY of `gates`. For surfaces reachable
    from more than one role (e.g. the vector index, managed from both the Library page and the
    admin Settings tab). Soft on a missing user — pair with require_auth."""
    def _dep(request: Request) -> None:
        if not _enforces(request):
            return
        if "session" not in request.scope:
            return
        u = current_user(request)
        if u is not None and not any(u.has_gate(g) for g in gates):
            _auth_redirect(request, 403,
                           f"Access denied (requires one of: {', '.join(gates)})", "/docs")
    return _dep


def is_authenticated(request: Request) -> bool:
    if not _enforces(request):
        return True
    return current_user(request) is not None


_LOOPBACK = frozenset({"127.0.0.1", "::1"})


def _normalize_ip(value: str) -> str:
    """A canonical IP string, or "" when the value isn't an IP. Strips brackets/zone via ipaddress."""
    import ipaddress
    v = (value or "").strip().strip("[]")
    if not v:
        return ""
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return ""


def trustworthy_client_ip(request: Request) -> "str | None":
    """The client IP we can TRUST for the bearer-push path (packet 1015), or None → fail-closed.

    The app listens on loopback behind FMS's reverse proxy, so the trust model is:
    - a genuine loopback PEER with no forwarding header = the co-located LOCAL push → the loopback IP;
    - a loopback peer WITH an ``X-Forwarded-For`` the trusted proxy appended = a proxied client; the
      REAL client is the RIGHTMOST XFF entry (a client-stuffed XFF sits to its LEFT and is never
      trusted — we take only the hop the proxy itself added);
    - a non-loopback direct peer (no proxy in front) = that peer IS the client.
    None when no usable IP can be derived (a malformed/absent value on the proxied path) → the caller
    fails closed. "Unknown origin" must NEVER read as "local". **Installer dependency:** the proxy
    (nginx / IIS-ARR) MUST forward a trustworthy client IP — this is part of the security control."""
    peer = _normalize_ip(getattr(getattr(request, "client", None), "host", "") or "")
    xff = request.headers.get("x-forwarded-for", "") or ""
    if peer in _LOOPBACK:
        if xff.strip():
            return _normalize_ip(xff.split(",")[-1]) or None
        return peer                                   # genuine local co-located push
    return peer or None


def require_upload_auth(request: Request) -> "str | None":
    """FastAPI dependency for /api/upload.

    Two callers, two shapes:
    - a valid session cookie (browser/API import) → returns ``None`` (the handler ingests inline);
    - an ``Authorization: Bearer <one-time push token>`` (packet 1015 fms_push) → returns the PENDING
      push QUEUE record's id (the handler stages the posted bytes into it + advances upload→land).

    The bearer path is the ONLY unattended push. Its whole model: **a token that hashes to a WAITING
    push record, from a TRUSTWORTHY origin, or the call is rejected**. We IP-gate BEFORE the token
    probe (an origin we can't trust never touches the token store) and resolve the one-time token by
    HASH against the QUEUE — so a used/expired/unknown token resolves nothing (401). Raises 401/403 if
    neither shape is valid in server mode."""
    if not _enforces(request):
        return None
    # A browser session authenticates the same way as require_auth. Importing is a LIBRARY WRITE, not a
    # bare logged-in capability, so a session uploader must additionally hold the library_mcp gate.
    u = current_user(request)
    if u is not None:
        if not u.has_gate("library_mcp"):
            raise HTTPException(status_code=403, detail="Access denied (requires library_mcp)")
        return None
    # Bearer push (fms_push). Token first (cheap reject on a non-bearer), then fail-closed IP trust
    # BEFORE the token store is touched.
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer ") or not auth_header[7:]:
        raise HTTPException(status_code=401, detail="Authentication required")
    token = auth_header[7:]
    client_ip = trustworthy_client_ip(request)
    if client_ip is None:
        raise HTTPException(status_code=403, detail="Push origin could not be verified.")
    try:
        from corpusfm.server.push_tokens import hash_push_token
        from corpusfm.storage import get_backend
        from corpusfm.storage.repos import queue_repo
        repo = queue_repo(get_backend())
        row = repo.find_pending_push(hash_push_token(token)) if repo is not None else None
    except Exception:
        row = None
    if row is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    # The one-time token (single-use, keyed to this exact pending run) is the isolation; the
    # trustworthy-origin check above is structural proxy trust. No per-server source-IP policy.
    return row.key
