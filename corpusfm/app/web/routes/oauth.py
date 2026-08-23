"""OAuth authorization + consent, the in-app half (packet 1179, Stage C).

The in-app half of the authorization-code flow. The FastMCP ``/authorize`` endpoint (under the ``/mcp``
mount) validates the request, creates a server-held authorization TRANSACTION, and redirects the browser
here. This module then integrates with the EXISTING signed browser session:

  GET  /oauth/authorize?txn=<handle>
    → validate the server-held transaction (opaque, short expiry, single use);
    → if unauthenticated: stash the txn handle in the signed session and redirect to the EXISTING
      /login (NO arbitrary external ``next`` — the txn IS the resume state); local + LDAP + OIDC login
      all resume the same way (the session cookie carries the handle across the round-trip);
    → if authenticated: bind the owner to the transaction, then show a CSRF-protected consent page with
      the client identity and the user's LIVE gates (silent re-consent only when an unchanged grant
      already exists — authentication alone never grants all tools).

  POST /oauth/consent  (approve | deny)
    → synchronizer-token CSRF check; the transaction must belong to the logged-in user (wrong user
      cannot consume another's transaction); approve consumes the transaction, records the consent grant
      and mints a single-use authorization code in ONE cross-process critical section (so an approval in
      flight cannot straddle a user's Disconnect), then redirects to the client's loopback redirect_uri
      with ``code``+``state``; deny returns a standards-correct ``error=access_denied``.

There is no switch in front of this flow (packet 1220): OAuth sign-in is available whenever the box has
a usable MCP address, which is also the only address a client can have reached to get here. Manual named
tokens and break-glass are never touched by this flow.
"""

from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from corpusfm.config import is_server_mode
from corpusfm.app.web.auth import current_user
from corpusfm.app.web.deployment import prefixed
from corpusfm.app.web import oauth_store

router = APIRouter()

_SESSION_TXN_KEY = "oauth_pending_txn"     # a pending authorization txn handle, resumed after login
_SESSION_CSRF_KEY = "oauth_consent_csrf"   # synchronizer CSRF token for the consent form


def _which_box() -> dict:
    """The install this consent is FOR: the address the running process is actually serving, plus the
    stored one when a saved change has not taken effect yet.

    Never raises and never guesses. A box that cannot state its own address renders the screen without
    the line rather than with a made-up one — the constraint is that display must never diverge from what
    is enforced, and silence satisfies it where a guess does not."""
    try:
        from corpusfm.mcp.server import serving_base
        live = serving_base() or ""
    except Exception:
        live = ""
    try:
        from corpusfm.app.web.deployment import external_base_url
        stored = external_base_url() or ""
    except Exception:
        stored = ""
    return {"box_address": live, "box_address_pending": stored if stored and stored != live else ""}


def _templates():
    from corpusfm.app.web.routes.pages import templates
    return templates


def _prefix(request: Request) -> str:
    return request.scope.get("root_path", "") or ""


def _error_page(request: Request, status: int, message: str) -> HTMLResponse:
    ctx = {"url_prefix": _prefix(request), "message": message}
    return _templates().TemplateResponse(request, "oauth_error.html", ctx, status_code=status)


def _client_redirect(redirect_uri: str, **params) -> str:
    """Append OAuth response params to the client's registered redirect_uri, preserving any query."""
    parsed = urlparse(redirect_uri)
    q = parse_qsl(parsed.query)
    q += [(k, v) for k, v in params.items() if v is not None]
    return urlunparse(parsed._replace(query=urlencode(q)))


def _consent_csp(redirect_uri: str) -> str:
    """The consent page's OWN Content-Security-Policy: the app-wide one plus THIS transaction's
    callback origin in ``form-action``.

    WITHOUT THIS, BROWSER OAUTH CANNOT COMPLETE AT ALL — measured 2026-07-29 on a real client, not
    reasoned about. The app-wide header is ``form-action 'self'``, and a browser enforces
    ``form-action`` against the **redirect that follows a form submission**, not just the form's own
    action. So: Approve POSTs same-origin (allowed) → the server approves, mints the code and answers
    302 to ``http://localhost:<port>/callback?code=…`` → the browser refuses that hop and **silently
    cancels the navigation**. The page does not move, nothing is shown, and the code is stranded while
    the client waits forever. Reproduced in Chromium: the POST reaches the server, the callback is never
    hit, and the console logs the ``form-action 'self'`` violation.

    The second symptom follows from the first and is what makes it look like a UI bug rather than a
    dead flow: the CSRF token is single-use, so clicking Approve again answers *"Your session could not
    be verified"*. Every MCP client is affected, because they all use a loopback ``redirect_uri`` that
    is by definition not ``'self'``.

    Scoped to the ONE origin this transaction will actually redirect to — taken from the stored
    transaction, never from user input — so the directive keeps doing its job for anything else. A
    non-http(s) or unparseable value contributes nothing rather than widening the policy.
    """
    origin = ""
    try:
        p = urlparse(redirect_uri or "")
        if p.scheme in ("http", "https") and p.netloc:
            origin = f"{p.scheme}://{p.netloc}"
    except Exception:
        origin = ""
    form_action = "'self'" + (f" {origin}" if origin else "")
    return f"frame-ancestors 'none'; base-uri 'self'; form-action {form_action}"


def oauth_resume_target(request: Request):
    """If a browser-OAuth authorization is pending in the session, return the in-app resume path and
    CLEAR it; else None. Called by the login handlers after a successful sign-in (local/LDAP/OIDC).
    The txn handle is server-held state in the signed session — never an attacker-controllable URL."""
    try:
        handle = request.session.pop(_SESSION_TXN_KEY, None)
    except Exception:
        handle = None
    if not handle:
        return None
    return prefixed(request, "/oauth/authorize?txn=" + handle)


@router.get("/oauth/authorize", response_class=HTMLResponse)
async def oauth_authorize(request: Request, txn: str = ""):
    if not is_server_mode():
        return RedirectResponse(prefixed(request, "/"), status_code=302)
    rec = oauth_store.get_txn(txn)
    if rec is None:
        return _error_page(request, 400, "This sign-in link has expired or was already used. Start the "
                                         "connection again from your MCP client.")
    u = current_user(request)
    if u is None:
        # Resume after login via the server-held transaction — NO external next URL.
        request.session[_SESSION_TXN_KEY] = txn
        return RedirectResponse(prefixed(request, "/login"), status_code=302)

    # Bind the freshly-authenticated owner to this transaction — FIRST-BIND-ONLY, serialized. Fail
    # closed if the binding cannot be recorded (never proceed to consent on an unbindable transaction).
    if not oauth_store.bind_txn_subject(txn, u.id):
        return _error_page(request, 403, "This sign-in could not be linked to your account. Start the "
                                         "connection again from your MCP client.")
    # The EFFECTIVE GRANT is the intersection of what the client requested (empty = all) and the user's
    # current gates — exactly what the consent page shows and the code/token is bound to.
    grant = _effective_grant(rec.get("Scopes"), u.gates)
    existing = oauth_store.get_consent(u.id, rec.get("ClientId"), rec.get("Resource"))
    if existing and set(grant).issubset(set(existing.get("Scopes") or [])):
        # Already consented AND the grant is within the prior ceiling (no new gate to approve) → silent.
        # This read is OUTSIDE the critical section, so it is only a candidate decision: the completion
        # re-checks the grant under the lock and returns None if a Disconnect won the race, at which
        # point the reconnection has to be approved visibly like any other new grant.
        done = _finish_approve(request, txn, u, grant, silent=True)
        if done is not None:
            return done

    csrf = secrets.token_urlsafe(32)
    request.session[_SESSION_CSRF_KEY] = csrf
    client = oauth_store.get_client(rec.get("ClientId")) or {}
    ctx = {
        "url_prefix": _prefix(request),
        "username": u.display_name or u.username,
        "client_name": (client.get("client_name") or "").strip(),
        "client_id": rec.get("ClientId", ""),
        "gates": grant,               # display EXACTLY the effective grant (review §3)
        "txn": txn,
        "csrf": csrf,
        # WHICH BOX (packet 1222). The screen named the product, so a person with two installs saw the
        # same page from both with nothing on it that differed. It names the address instead — the value
        # that is distinct per install within a network, and the audience this very grant will be bound
        # to.
        #
        # LIVE, not stored. `serving_base()` is what this process advertises; the stored address may be
        # newer and not yet served, because an admin can save one and answer "No" to the restart. Showing
        # the stored value would tell a person they are approving a connection to an audience the box is
        # not serving — and the approval would then fail at the client's own `resource` check with
        # nothing on screen explaining it.
        **_which_box(),
    }
    resp = _templates().TemplateResponse(request, "oauth_consent.html", ctx)
    # Set BEFORE the security-headers middleware, which uses setdefault and so leaves this alone. The
    # header has to be on the page that CONTAINS the form — `form-action` is a property of the document
    # doing the submitting, not of the response that redirects.
    resp.headers["Content-Security-Policy"] = _consent_csp(rec.get("RedirectUri", ""))
    return resp


@router.post("/oauth/consent", response_class=HTMLResponse)
async def oauth_consent(request: Request, txn: str = Form(""), csrf: str = Form(""),
                        decision: str = Form("")):
    if not is_server_mode():
        return RedirectResponse(prefixed(request, "/"), status_code=302)
    u = current_user(request)
    if u is None:
        # Session expired mid-consent — re-authenticate (the txn, if still live, resumes).
        request.session[_SESSION_TXN_KEY] = txn
        return RedirectResponse(prefixed(request, "/login"), status_code=302)
    # Synchronizer-token CSRF (the consent form is exempt from the SPA double-submit header check).
    sess_csrf = request.session.get(_SESSION_CSRF_KEY, "")
    if not sess_csrf or not csrf or not hmac.compare_digest(sess_csrf, csrf):
        return _error_page(request, 403, "Your session could not be verified. Start the connection "
                                         "again from your MCP client.")
    request.session.pop(_SESSION_CSRF_KEY, None)

    rec = oauth_store.get_txn(txn)
    if rec is None:
        return _error_page(request, 400, "This authorization has expired or was already used.")
    # Wrong user cannot consume another user's transaction.
    if rec.get("Subject") != u.id:
        return _error_page(request, 403, "This authorization does not belong to your account.")

    if (decision or "").lower() != "approve":
        # DENY: consume the transaction FIRST and confirm THIS caller consumed it before redirecting —
        # never signal a denial for a transaction that was already used/expired (fail closed).
        denied = oauth_store.consume_txn(txn)
        if denied is None:
            return _error_page(request, 400, "This authorization has expired or was already used.")
        return RedirectResponse(
            _client_redirect(denied.get("RedirectUri", ""), error="access_denied", state=denied.get("State")),
            status_code=302)
    return _finish_approve(request, txn, u, _effective_grant(rec.get("Scopes"), u.gates))


def _effective_grant(requested, user_gates):
    """The gates actually granted: (requested ∩ user_gates) when the client requested a specific set,
    else the user's current gates. Never broadens beyond either bound."""
    gates = set(user_gates or [])
    req = set(requested or [])
    return sorted(gates & req) if req else sorted(gates)


def _finish_approve(request: Request, txn: str, u, grant, *, silent: bool = False):
    """Complete an approval and redirect to the client with the code.

    Transaction consume, live-grant check, consent persistence and code mint all happen in ONE
    cross-process critical section (``oauth_store.approve_authorization``) — the same authority a user
    Disconnect holds. Four separately locked steps left a window in which a Disconnect could land after
    the transaction was consumed, delete the consent, report success, and then be silently undone by this
    function re-creating the grant and minting a code for it.

    ``silent`` marks the no-consent-page path. There the grant must STILL exist inside the section; if a
    Disconnect removed it, this returns ``None`` (consuming nothing) and the caller shows the consent
    page — a disconnected connection can only come back through visible consent."""
    status, res = oauth_store.approve_authorization(
        txn, subject=u.id, scopes=grant, require_existing_consent=silent)
    if status == oauth_store.APPROVE_CONSENT_REQUIRED:
        return None                        # silent path only — caller falls through to visible consent
    if status == oauth_store.APPROVE_TXN_GONE:
        return _error_page(request, 400, "This authorization has expired or was already used.")
    if status != oauth_store.APPROVE_OK or not res:
        # Nothing was issued: fail closed rather than redirect on an unrecorded grant.
        return _error_page(request, 500, "Could not record your approval. Please try again.")
    return RedirectResponse(
        _client_redirect(res.get("redirect_uri", ""), code=res.get("code"), state=res.get("state")),
        status_code=302)
