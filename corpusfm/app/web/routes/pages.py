"""HTML page routes."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from corpusfm.config import is_server_mode
from corpusfm.app.web.auth import (
    is_authenticated, require_auth, require_gate, current_user,
)
from corpusfm.app.web import users as users_store
from corpusfm.app.web.deployment import prefixed, route_path, is_migrated

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

import time as _time

router = APIRouter()

# Unique token per server process — used to invalidate patch workspace session on restart
_BOOT_TS = str(int(_time.time()))

_STATIC_DIR = Path(__file__).parent.parent / "static"


def _css_version() -> str:
    """Return the newest CSS/kit-asset mtime as a cache-bust token.

    Covers style.css plus the re-platform kit (kit.css/kit.js) so a change to
    any of them busts the browser cache.
    """
    newest = 0.0
    for name in ("style.css", "kit.css", "kit.js"):
        try:
            newest = max(newest, (_STATIC_DIR / name).stat().st_mtime)
        except OSError:
            pass
    return str(int(newest)) if newest else "1"


def _max_upload_label() -> str:
    """Human label for the hard upload ceiling, derived from the single source of truth."""
    from corpusfm.app.web.routes.api.upload import MAX_UPLOAD_BYTES
    gb = MAX_UPLOAD_BYTES / (1024 * 1024 * 1024)
    return f"{gb:g} GB"


def _ctx(request: Request, **kwargs) -> dict:
    """Base template context injected into every page.

    Starlette 1.0.0 passes request as the first positional arg to TemplateResponse;
    the context dict must NOT include 'request'.
    """
    import corpusfm
    from corpusfm.config import is_server_mode as _srv
    from corpusfm.app.app_config import load_app_config
    from corpusfm.app.web.routes.api.settings import _upgrade_command
    _u = current_user(request)
    return {
        "mode": "server" if _srv() else "local",
        "authenticated": is_authenticated(request),
        # The logged-in user (server mode); None in standalone. Drives nav visibility + display.
        "current_user": ({
            "username": _u.username,
            "display_name": _u.display_name or _u.username,
            "gates": sorted(_u.gates),
            "is_admin": _u.is_admin,
        } if _u else None),
        # Standalone (no auth) reaches everything; server mode gates by the user's gates.
        "all_access": (not _srv()),
        "css_v": _css_version(),
        # Server default for the Documentation drawer side ("right"|"left"); a
        # per-device flip overrides via localStorage (see base.html).
        # Personal pref (per-user) overrides the app default; a per-device localStorage flip
        # overrides both (see base.html).
        "docs_drawer_side": (_u.prefs.get("docs_drawer_side") if _u else None) or load_app_config().docs_drawer_side,
        # URL prefix when mounted behind a reverse proxy under a sub-path (root_path,
        # set by uvicorn --root-path; e.g. "/corpusfm"). "" at root (local/dev) → every
        # template URL stays exactly as before. Templates prepend {{ url_prefix }} to
        # static/nav/download links; JS reads window.CFM_PREFIX (see base.html).
        "url_prefix": request.scope.get("root_path", "") or "",
        # route (root_path stripped) for nav active-state checks — request.url.path
        # includes the prefix under the reverse proxy, so compare against this.
        "route_path": route_path(request),
        # Current app version (0.{rev-count}) — base.html gates the "Update available" badge on
        # latest > current so a stale localStorage cache can't flag an already-applied/older build.
        "version": corpusfm.__version__,
        # Server OS — drives the platform-correct admin-CLI hint on the no-users login page
        # (Windows ships no `corpusfm` on PATH; the bundled-Python module form is the working command).
        "is_windows": (os.name == "nt"),
        # The exact, INSTALL-ROOT-CORRECT command to create the first admin, resolved server-side from
        # the running interpreter (sys.executable) — so a custom Windows -InstallRoot (e.g. D:\Apps\...)
        # is honored instead of a hard-coded C:\CORPUSfm. Linux uses the `corpusfm` shim.
        "admin_cli": (
            "corpusfm users create <name> --admin" if os.name != "nt"
            else f"{__import__('sys').executable} -m corpusfm.server.cli users create <name> --admin"
        ),
        # True when the session + CSRF cookies are Secure (migrated server install). A browser on
        # plain http silently DROPS a Secure cookie, so a login over http succeeds then bounces
        # straight back ("correct account, no advance"). The login page reads this to show an
        # https hint when it's reached over http — the cookie policy itself is unchanged.
        "secure_cookies": is_migrated(),
        # Hard, fixed upload ceiling (NOT a setting) surfaced read-only on Settings → Storage. The
        # value is the single source of truth in upload.MAX_UPLOAD_BYTES.
        "max_upload_label": _max_upload_label(),
        # Platform-correct, copy-pasteable installer command for the gate pages (build-mismatch /
        # needs-upgrade) — Linux sudo install.sh vs Windows elevated install.ps1.
        "upgrade_command": _upgrade_command(),
        **kwargs,
    }


# ── Login / logout (server mode) ───────────────────────────────────────────────

def _sso_enabled() -> bool:
    """OIDC configured → render the SSO button on the login screen (packet 1065). Never raises."""
    try:
        from corpusfm.app.web.external_auth import oidc_enabled
        return oidc_enabled()
    except Exception:
        return False


def _user_store_state() -> str:
    """"empty" · "populated" · "unreadable". The login page must never report an empty user store it
    could not read (packet 1201): "no users configured" is a definite claim about durable data, and the
    remedy it prints — the on-box CLI — writes to the very table that just failed to read. An outage
    says so instead."""
    try:
        return "populated" if users_store.users_exist(raise_on_error=True) else "empty"
    except users_store.UserStoreUnavailable:
        return "unreadable"


@router.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    if not is_server_mode() or is_authenticated(request):
        return RedirectResponse(prefixed(request, "/"), status_code=302)
    state = _user_store_state()
    error = "SSO sign-in failed. Sign in with a local account, or try again." \
        if request.query_params.get("sso_error") else None
    return templates.TemplateResponse(
        request, "login.html",
        _ctx(request, no_users=(state == "empty"), store_unavailable=(state == "unreadable"),
             error=error, sso_enabled=_sso_enabled()),
        status_code=503 if state == "unreadable" else 200)


@router.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(""), password: str = Form(...)):
    if not is_server_mode():
        return RedirectResponse(prefixed(request, "/"), status_code=302)

    # No users configured: do NOT mint an admin from an anonymous browser POST. The old "first-run"
    # behavior let whoever reached the login page first silently become full admin — too magical for
    # a server install. The first admin is an INSTALLER product; on a box that somehow has none, the
    # on-box `corpusfm users create <name> --admin` makes one. Render the locked "no users configured"
    # state and create nothing. (The legacy single-password migration was deleted — packet 082.)
    # An UNREADABLE store is neither of those states and must not borrow either one's copy.
    state = _user_store_state()
    if state != "populated":
        return templates.TemplateResponse(
            request, "login.html",
            _ctx(request, no_users=(state == "empty"), store_unavailable=(state == "unreadable"),
                 error=None, sso_enabled=_sso_enabled()),
            status_code=503 if state == "unreadable" else 200)

    # Brute-force throttle (packet 1175): the ONE choke-point covers BOTH the local-password and the LDAP
    # bind below (both run inside this POST). Evaluate BEFORE touching the password hash / LDAP bind, so a
    # blocked identity/source never even reaches the expensive verify (design §12 DoS mitigation). The
    # source is the trustworthy proxy-attributed client IP; a missing one still throttles by identity.
    from corpusfm.app.web import login_throttle
    from corpusfm.app.web.auth import trustworthy_client_ip
    source = trustworthy_client_ip(request)
    decision = login_throttle.evaluate(username, source)
    if decision.blocked:
        return templates.TemplateResponse(
            request, "login.html",
            _ctx(request, no_users=False,
                 error=f"Too many failed sign-in attempts. Try again in about {decision.retry_after} seconds.",
                 sso_enabled=_sso_enabled()),
            status_code=429,
        )

    # Local password first (also the mandatory break-glass). If it doesn't match, try LDAP bind (Ph3) —
    # a directory user authenticates on the SAME form. OIDC uses the separate SSO button, not this POST.
    u = users_store.verify_login(username, password)
    via = "password"
    if u is None:
        try:
            from corpusfm.app.web import ldap_auth
            # ldap3 is synchronous. Keep its complete bind/search/JIT attempt off the
            # async request loop so an unavailable directory cannot stall other users.
            lu = await run_in_threadpool(ldap_auth.ldap_login, username, password)
        except Exception:
            lu = None
        if lu is not None:
            u, via = lu, "ldap"
    if u is not None:
        login_throttle.note_success(username, source)   # clear this identity's failures on a real login
        if via == "ldap":
            from corpusfm.app.web.external_auth import establish_session
            establish_session(request, u, auth_method="ldap")
        else:
            request.session["user_id"] = u.id
            now = int(_time.time())
            request.session["issued_at"] = now   # absolute cap anchor — NEVER updated after login
            request.session["seen"] = now        # sliding marker — bumped on activity (packet 1030)
        # Packet 1179: resume a pending browser-OAuth authorization by its server-held transaction —
        # never an arbitrary external next URL. None for an ordinary sign-in → land on the app root.
        from corpusfm.app.web.routes.oauth import oauth_resume_target
        return RedirectResponse(oauth_resume_target(request) or prefixed(request, "/"), status_code=302)

    login_throttle.note_failure(username, source)       # count this failure against identity + source
    return templates.TemplateResponse(
        request, "login.html",
        _ctx(request, no_users=False, error="Incorrect username or password.", sso_enabled=_sso_enabled())
    )


# ── OIDC SSO (packet 1065) — public routes, they ESTABLISH the session ──────────

@router.get("/auth/oidc/login")
async def oidc_login(request: Request):
    if not is_server_mode():
        return RedirectResponse(prefixed(request, "/"), status_code=302)
    from corpusfm.app.web import external_auth
    if not external_auth.oidc_enabled():
        return RedirectResponse(prefixed(request, "/login"), status_code=302)
    from corpusfm.app.web import oidc as oidc_flow
    try:
        return await oidc_flow.login_redirect(request)
    except Exception:
        return RedirectResponse(prefixed(request, "/login?sso_error=1"), status_code=302)


@router.get("/auth/oidc/callback")
async def oidc_callback(request: Request):
    if not is_server_mode():
        return RedirectResponse(prefixed(request, "/"), status_code=302)
    from corpusfm.app.web import oidc as oidc_flow
    user, err = await oidc_flow.handle_callback(request)
    if user is not None:
        # Packet 1179: OIDC resume is safe here — the pending authorization is a server-held txn handle
        # carried in the signed session (it survives the IdP round-trip), independent of OIDC's own
        # state/nonce/PKCE, which are untouched. No arbitrary next URL is introduced.
        from corpusfm.app.web.routes.oauth import oauth_resume_target
        return RedirectResponse(oauth_resume_target(request) or prefixed(request, "/"), status_code=302)
    state = _user_store_state()
    return templates.TemplateResponse(
        request, "login.html",
        _ctx(request, no_users=(state == "empty"), store_unavailable=(state == "unreadable"),
             error=err or "SSO sign-in failed.", sso_enabled=_sso_enabled()))


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(prefixed(request, "/login" if is_server_mode() else "/"), status_code=302)


# ── Your account (System group — universal self-service) ───────────────────────
@router.get("/account", response_class=HTMLResponse)
async def account_get(request: Request, _=Depends(require_auth)):
    from corpusfm.app.app_config import load_app_config
    from corpusfm.app.web.landing import accessible_pages
    cfg = load_app_config()
    u = current_user(request)
    if u is not None:
        p = u.prefs
    else:
        from corpusfm.app.web.appearance_preferences import load as load_appearance_preferences
        p = load_appearance_preferences()
    from corpusfm.extensions.export.syntax_palettes import (
        catalog, catalog_css, highlighter_source, resolve_selection,
    )
    syntax_selection = resolve_selection(p)
    acct_prefs = {
        "landing_page": p.get("landing_page") or cfg.landing_page,
        "docs_drawer_side": p.get("docs_drawer_side") or cfg.docs_drawer_side,
        "addon_locale": p.get("addon_locale", ""),   # "" = system default (no per-user override)
        "calculation_palette": syntax_selection.calculation,
        "script_palette": syntax_selection.script,
    }
    # The dropdown offers only pages this user can actually reach (standalone = everything).
    has_gate = (u.has_gate if u else (lambda g: True))
    return templates.TemplateResponse(request, "account.html", _ctx(
        request, acct_prefs=acct_prefs, landing_pages=accessible_pages(has_gate),
        syntax_palettes=catalog(), syntax_palette_css=catalog_css(),
        syntax_highlighter_js=highlighter_source()))


@router.post("/api/account/prefs")
async def account_prefs(request: Request, _=Depends(require_auth)):
    """Save the current user's personal prefs, or standalone's local appearance prefs."""
    if not is_server_mode():
        body = await request.json()
        from corpusfm.app.web.appearance_preferences import save
        try:
            saved = save(body)
        except OSError as exc:
            return JSONResponse({"ok": False, "error": f"Could not save appearance preferences: {exc}"},
                                status_code=500)
        return JSONResponse({"ok": True, "preferences": saved})
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    body = await request.json()
    users_store.set_user_prefs(u.id, body)
    return JSONResponse({"ok": True})


@router.post("/api/account/password")
async def account_password(request: Request, _=Depends(require_auth)):
    if not is_server_mode():
        return JSONResponse({"ok": False, "error": "Not available on the local path — this needs a co-located FileMaker Server."}, status_code=400)
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    body = await request.json()
    if not u.is_local:
        return JSONResponse({"ok": False, "error": f"{u.auth_method.upper()} accounts change their "
                                                   "password with the identity provider."},
                            status_code=400)
    # verify_user_password reads the hash from the SecretData container. Do NOT reintroduce a
    # comparison against a hash off `u` — current_user() never loads it (see the User dataclass).
    if not users_store.verify_user_password(u.id, body.get("current", "")):
        return JSONResponse({"ok": False, "error": "Current password is incorrect."}, status_code=400)
    new_pw = body.get("new", "")
    if len(new_pw) < 8:
        return JSONResponse({"ok": False, "error": "New password must be at least 8 characters."}, status_code=400)
    users_store.set_user_password(u.id, new_pw)
    return JSONResponse({"ok": True})


# ── MCP access (Library group — per-user connection self-service) ───────────────
@router.get("/mcp-access", response_class=HTMLResponse,
            dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def mcp_access(request: Request):
    # The page fetches everything from /api/account/mcp-connections — no server-rendered flag.
    return templates.TemplateResponse(request, "mcp_access.html", _ctx(request))


@router.get("/api/account/mcp-connections")
async def account_mcp_connections(request: Request, _=Depends(require_auth),
                                  __=Depends(require_gate("library_mcp"))):
    """The current user's unified, non-secret MCP access view (packet 1182): browser connections
    (one per consent grant) + manual tokens. Mutations stay explicit per credential type."""
    from corpusfm.app.web import mcp_connections
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    return JSONResponse({"ok": True, **mcp_connections.account_mcp_view(u.id)})


@router.delete("/api/account/mcp-connections/{connection_id}")
async def account_disconnect_mcp_connection(connection_id: str, request: Request,
                                            _=Depends(require_auth),
                                            __=Depends(require_gate("library_mcp"))):
    """Disconnect ONE of the current user's browser connections. The subject is taken from the signed-in
    session ONLY — never from the request — and ownership is re-checked inside the store."""
    from corpusfm.app.web import oauth_store
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    try:
        res = oauth_store.disconnect(u.id, connection_id)
    except oauth_store.OAuthStoreUnavailable:
        # Honest failure: nothing was half-done (the store mutation is serialized and ordered so a
        # failure never leaves a live token behind a removed grant).
        return JSONResponse({"ok": False, "error": "The connection could not be disconnected right now. "
                                                   "Try again in a moment."}, status_code=503)
    if res is None:
        return JSONResponse({"ok": False, "error": "That connection no longer exists."}, status_code=404)
    from corpusfm.server import audit
    audit.record(audit.MCP_BROWSER_CONNECTION_DISCONNECTED, actor=u.username,
                 target=str(res.get("client_id", ""))[:64],
                 meta={"op": "disconnect", "resource": res.get("resource", ""),
                       "tokens_revoked": res.get("tokens_revoked", 0)})
    return JSONResponse({"ok": True, "client_id_prefix": str(res.get("client_id", ""))[:8],
                         "tokens_revoked": res.get("tokens_revoked", 0)})


@router.post("/api/account/mcp-tokens")
async def account_mint_mcp_token(request: Request, _=Depends(require_auth),
                                 __=Depends(require_gate("library_mcp"))):
    """Mint a new NAMED token for the current user — self-service. Returns the raw token ONCE."""
    from corpusfm.app.web import mcp_tokens
    if not is_server_mode():
        return JSONResponse({"ok": False, "error": "Not available on the local path — this needs a co-located FileMaker Server."}, status_code=400)
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    body = await request.json()
    try:
        raw = mcp_tokens.mint(u.id, str(body.get("name", "")))
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    return JSONResponse({"ok": True, "token": raw})


@router.delete("/api/account/mcp-tokens/{record_key}")
async def account_delete_mcp_token(record_key: str, request: Request, _=Depends(require_auth),
                                   __=Depends(require_gate("library_mcp"))):
    """Delete one of the current user's tokens (ownership-checked). Takes effect immediately."""
    from corpusfm.app.web import mcp_tokens
    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    ok = mcp_tokens.delete(u.id, record_key)
    return JSONResponse({"ok": ok}, status_code=(200 if ok else 404))


# ── Pages ──────────────────────────────────────────────────────────────────────

@router.get("/", dependencies=[Depends(require_auth)])
async def home(request: Request):
    # `/` lands on the configured page — Artifacts (default) or Monitoring — IF the user holds its
    # gate; otherwise Documentation (ungated, the safe universal landing — e.g. a new user with no
    # gates yet). The wordmark links here; the nav alert dot carries health everywhere.
    from corpusfm.app.app_config import load_app_config
    from corpusfm.app.web.landing import landing_target
    u = current_user(request)
    key = (u.prefs.get("landing_page") if u else None) or load_app_config().landing_page
    # Standalone (no user) reaches everything; server mode gates by the user's gates. An
    # inaccessible/unknown choice falls back to Documentation (ungated, the safe landing).
    has_gate = (u.has_gate if u else (lambda g: True))
    target = landing_target(key, has_gate) or "/docs"
    return RedirectResponse(url=prefixed(request, target), status_code=307)


@router.get("/artifacts", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def artifacts(request: Request):
    from corpusfm.app.app_config import load_app_config, system_locale_code
    from corpusfm.server.ai.vector_index import embedding_ready
    from corpusfm.server.ai import summary_provider_ready
    cfg = load_app_config()
    u = current_user(request)
    pref_loc = (u.prefs.get("addon_locale") if u else "") or cfg.preferred_addon_locale or system_locale_code()
    return templates.TemplateResponse(request, "artifacts.html", _ctx(
        request,
        has_embedding_provider=embedding_ready(cfg),
        has_summary_provider=summary_provider_ready(cfg),
        preferred_locale=pref_loc))


@router.get("/monitoring", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("automation"))])
async def monitoring(request: Request):
    return templates.TemplateResponse(request, "monitoring.html", _ctx(request))


@router.get("/jobs", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("automation"))])
async def jobs(request: Request):
    # packet 1153: the AI-enrichment switches (Summarize / Index) only render when their capability is
    # configured — a toggle for work that can never run is noise. Capability is a slow-moving install fact.
    from corpusfm.server import enrichment
    return templates.TemplateResponse(request, "jobs.html", _ctx(
        request,
        summarize_capable=enrichment.provider_ready(),
        index_capable=enrichment.embedder_ready(),
    ))


@router.get("/runs", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("automation"))])
async def runs(request: Request):
    return templates.TemplateResponse(request, "runs.html", _ctx(request))


@router.get("/queue", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def queue(request: Request):
    # The shared enrichment-queue view (packet 052) — any authenticated user can see what's running
    # system-wide; cancel/restart inside are owner-or-admin (enforced by /api/queue).
    return templates.TemplateResponse(request, "queue.html", _ctx(request))


# Job editing now lives in each file's pop-over on the Jobs page (no deep-link).
@router.get("/jobs/edit", dependencies=[Depends(require_auth), Depends(require_gate("automation"))])
async def jobs_edit_redirect(request: Request, name: str | None = None):
    return RedirectResponse(url=prefixed(request, "/jobs"), status_code=307)


@router.get("/settings", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("settings"))])
async def settings(request: Request):
    return templates.TemplateResponse(request, "settings.html", _ctx(request))


@router.get("/build-mismatch", response_class=HTMLResponse)
async def build_mismatch_page(request: Request):
    # The "fresh install required" gate. Reachable while locked (allowlisted);
    # self-dismisses once the DB schema matches this build (after a fresh install).
    # Pass the live/target builds + direction so the page gives ACCURATE guidance: 085 is
    # fresh-install-only (no in-place migration), and an older-app-over-newer-DB rollback needs
    # the CODE upgraded, not the DB touched.
    live_build = target_build = ""
    db_newer = False
    try:
        from corpusfm.storage import storage_migration as sm, get_backend
        target_build = sm.expected_build()
        live_build = str(get_backend().load_fm_build()).strip()

        def _n(b):
            try:
                return int(str(b).strip().lstrip("."))
            except Exception:
                return -1
        db_newer = _n(live_build) >= 0 and _n(live_build) > _n(target_build)
    except Exception:
        pass
    return templates.TemplateResponse(
        request, "build_mismatch.html",
        _ctx(request, live_build=live_build, target_build=target_build, db_newer=db_newer))


@router.get("/needs-upgrade", response_class=HTMLResponse)
async def needs_upgrade_page(request: Request):
    # The "run the installer to finish migrating behind the FMS web server" gate.
    # Reachable while locked (allowlisted); self-dismisses once the install.yaml
    # web_prefix marker is present (after a re-run of install.sh applies the proxy).
    return templates.TemplateResponse(request, "needs_upgrade.html", _ctx(request))


@router.get("/converting", response_class=HTMLResponse)
async def converting_page(request: Request):
    # Full-screen "re-encoding blobs" waiting room. The global blob-encryption lock holds
    # everyone here (allowlisted in the deployment gate); the page polls the status endpoint
    # and redirects back to /settings#storage once the conversion finishes.
    return templates.TemplateResponse(request, "converting.html", _ctx(request))


@router.get("/reload", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def reload_page(request: Request):
    # Dedicated full-screen "the app is restarting" waiting room for standalone
    # updates: it applies the update (the server self-relaunches), then shows a
    # single Reload button to reconnect to the freshly-launched process.
    return templates.TemplateResponse(request, "reload.html", _ctx(request))


@router.get("/logs", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("settings"))])
async def logs(request: Request):
    return templates.TemplateResponse(request, "logs.html", _ctx(request))


# ── Transformations (Diff / Explorer / Ingestion / ISV / Merge) ──────────────────
# Actions over the artifact catalog. Ingestion is the import front door (Drop → Triage
# → Commit); the others are launched from a Catalog selection (CLAUDE-UX §4/§5).
# Import is now an Artifacts pop-over (one import surface — no separate page). The old
# /ingestion front doors redirect to the catalog. The standalone Schema Inspector page was
# retired: gap analysis is surfaced per-artifact on the Health tab and resolved by an agent
# over MCP (get_schema_gaps / try_schema_yaml); the `corpusfm gap-analyze` CLI also remains.
@router.get("/ingestion", dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
@router.get("/ingestion/inspect", dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def ingestion(request: Request):
    return RedirectResponse(url=prefixed(request, "/artifacts"), status_code=307)


# View tools (Explore/Diff) have no page — they're launched from a Catalog selection to a
# result tab (CLAUDE-UX §5/§6). The old paths redirect to the Catalog.
@router.get("/explorer", dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
@router.get("/diff", dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def view_tool_redirect(request: Request):
    return RedirectResponse(url=prefixed(request, "/artifacts"), status_code=307)


# Merge is a direct Catalog action now (no page; CLAUDE-UX §5/§6) — old path → Catalog.
@router.get("/merge", dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def merge_redirect(request: Request):
    return RedirectResponse(url=prefixed(request, "/artifacts"), status_code=307)


@router.get("/isv", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("patching"))])
async def isv_tool(request: Request):
    return templates.TemplateResponse(request, "patch_isv.html", {**_ctx(request), "boot_ts": _BOOT_TS})


# ── Readiness — capability + tier report (drives UI gating + status surface) ─────
@router.get("/api/readiness", dependencies=[Depends(require_auth)])
async def api_readiness(request: Request):
    """The readiness report (tiers + per-capability status). Cheap (TTL-cached); pass
    ?force=1 to bypass the cache. Login is Tier-0 so this is reachable even when Tier 1 is down."""
    from corpusfm.server import readiness
    force = request.query_params.get("force") in ("1", "true", "yes")
    return JSONResponse(readiness.report(force=force))


# ── Documentation (System) — bundled markdown, version-locked to the app ─────────
def _doc_gates(request: Request):
    """The gate set the current viewer holds, for per-article gate filtering. None in
    standalone (all-access — no per-user gates); the user's gates in server mode; an empty
    set for an unresolved session (gated articles hidden)."""
    from corpusfm.config import is_server_mode as _srv
    if not _srv():
        return None
    u = current_user(request)
    return set(u.gates) if u else set()


@router.get("/api/docs", dependencies=[Depends(require_auth)])
async def api_docs(request: Request):
    """All published doc articles (slug/title/rendered html) — feeds the global doc drawer.
    Gate-filtered to the viewer (an admin-gated dev article never reaches a non-admin)."""
    from corpusfm.app.web.docs_render import list_docs, render_doc
    prefix = request.scope.get("root_path", "") or ""
    arts = []
    for m in list_docs(gates=_doc_gates(request)):
        title, html = render_doc(m.slug)
        if html:
            html = html.replace('href="/', f'href="{prefix}/')   # prefix internal links for the proxy
            arts.append({"slug": m.slug, "title": m.title, "section": m.section, "html": html})
    return JSONResponse({"articles": arts})


@router.get("/docs", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
@router.get("/docs/{slug}", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def documentation(request: Request, slug: str = ""):
    from corpusfm.app.web.docs_render import list_docs, render_doc, group_by_section
    articles = list_docs(gates=_doc_gates(request))
    allowed = {a.slug for a in articles}
    current = slug if slug in allowed else (articles[0].slug if articles else "")
    title, html = (render_doc(current) if current else (None, None))
    if html is None and articles:        # unknown/ungranted slug → fall back to the first article
        current = articles[0].slug
        title, html = render_doc(current)
    prefix = request.scope.get("root_path", "") or ""
    if html:                              # reverse-proxy sub-path: prefix internal links
        html = html.replace('href="/', f'href="{prefix}/')
    groups = [{"section": s, "links": [{"slug": a.slug, "title": a.title} for a in items]}
              for s, items in group_by_section(articles)]
    return templates.TemplateResponse(request, "docs.html", {
        **_ctx(request),
        "doc_groups": groups,
        "doc_current": current,
        "doc_title": title,
        "doc_html": html or "",
        "has_docs": bool(articles),
    })


# Legacy /upload → the catalog (import is now the Artifacts pop-over; one import surface).
@router.get("/upload", dependencies=[Depends(require_auth)])
async def upload_legacy_redirect(request: Request):
    return RedirectResponse(url=prefixed(request, "/artifacts"), status_code=307)


# Indexed page retired — its controls moved onto the Artifacts page (Index All in the
# header; per-artifact index/remove in the detail Pop-over). Old path → Catalog.
@router.get("/indexed", dependencies=[Depends(require_auth)])
async def indexed_redirect(request: Request):
    return RedirectResponse(url=prefixed(request, "/artifacts"), status_code=307)


@router.get("/files", dependencies=[Depends(require_auth), Depends(require_gate("automation"))])
async def files_redirect(request: Request):
    # Files + Jobs consolidated into one file-centric Jobs page.
    return RedirectResponse(url=prefixed(request, "/jobs"), status_code=307)


@router.get("/tags", response_class=HTMLResponse, dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def tags_page(request: Request):
    return templates.TemplateResponse(request, "tags.html", _ctx(request))


@router.get("/about", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
async def about(request: Request):
    import sys
    import corpusfm
    from corpusfm.updater import RELEASES_PAGE_URL
    from corpusfm.server import update_notice
    py = sys.version_info
    return templates.TemplateResponse(request, "about.html", _ctx(
        request,
        version=corpusfm.__version__,
        python_version=f"{py.major}.{py.minor}.{py.micro}",
        releases_url=RELEASES_PAGE_URL,
        update_notice=(update_notice.about_notice() or {}).get("text", ""),
    ))
