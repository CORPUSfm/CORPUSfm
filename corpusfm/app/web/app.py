"""CORPUSfm FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from corpusfm.app.web.auth import session_secret, SESSION_IDLE_TIMEOUT
from corpusfm.app.web.routes.pages import router as pages_router
from corpusfm.app.web.routes.api import router as api_router
from corpusfm.app.web.routes.oauth import router as oauth_router

_STATIC_DIR = Path(__file__).parent / "static"
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class _ExactMcpPathIsNotARedirect:
    """Serve the canonical `…/mcp` without Starlette's mount redirect (packet 1329).

    Root-path aware: behind the FMS proxy (and under `--root-path`) the scope path carries the mount
    prefix, so the comparison is made on the ROUTED path — the same distinction `deployment.route_path`
    draws for the deployment gate. Everything but that one exact path passes through untouched."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            root = scope.get("root_path") or ""
            path = scope.get("path") or ""
            routed = path[len(root):] if root and path.startswith(root) else path
            if routed == "/mcp":
                scope = dict(scope, path=f"{root}/mcp/", raw_path=f"{root}/mcp/".encode())
        await self.app(scope, receive, send)


def _build_mcp_app():
    """The folded-in MCP as a mountable ASGI app — stateless streamable-HTTP — or None.

    Mounted at /mcp → served behind the FMS proxy at /corpusfm/mcp. Stateless (json_response)
    ⇒ no in-memory session, so it's multi-worker-safe and proxies as plain request/response
    (no SSE buffering to configure).

    FAIL-CLOSED in server mode, and the guarantee MOVED (packet 1258). It used to be *not mounted
    without a token*: no server-wide credential existed to hold, so the absence of one meant no
    endpoint. With MCP access now user-account-centric, the endpoint always mounts on a deployed box
    and REFUSES — `_build_auth()` returns a verifier unconditionally in server mode, and every request
    without a credential belonging to a named user gets 401. There is no state in which /corpusfm/mcp
    answers an anonymous caller. A from-source dev run (LocalBackend, loopback) is the one
    unauthenticated path, exactly as before.

    ONE DECISION SITE, and it stays that way. Status surfaces that each re-derived the mount from the
    mode plus a token found in `.mcp_env` or the environment disagreed with the real mount in BOTH
    directions; this function is the only place the decision is made, so it is the only place that
    states it.
    """
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware
    from corpusfm.server import mcp_status
    from corpusfm.mcp.server import mcp as _mcp
    # CORS for BROWSER-ORIGIN MCP clients (packet 1327). VS Code's Copilot Agent Host (the client
    # Copilot chat calls tools through) and MCP Inspector-in-a-browser use the renderer's fetch, so a
    # preflight on /mcp/ must answer and the 401 must EXPOSE WWW-Authenticate or discovery can never
    # start — measured 2026-08-23: OPTIONS /mcp/ was 405 and the Agent Host's Sign In did nothing.
    # Node/Rust clients (Claude Code, Codex, VS Code core) never noticed because they enforce no CORS.
    # `*` without credentials exposes nothing new: every call still needs a bearer or OAuth token.
    # The proxy include must stop FMS's nginx stacking its own ACAO on top (proxy half, same packet).
    cors = Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept",
                       "Mcp-Protocol-Version", "Mcp-Session-Id", "Last-Event-ID"],
        expose_headers=["Mcp-Session-Id", "WWW-Authenticate"],
        max_age=600,
    )
    app = _mcp.http_app(path="/", stateless_http=True, json_response=True, middleware=[cors])
    from corpusfm.mcp.server import point_challenge_at_canonical_resource
    point_challenge_at_canonical_resource(app)
    mcp_status.record_mounted(_mcp)
    return app


def _enforce_single_worker() -> None:
    """Refuse a multi-worker launch (packet 063). The QUEUE workers drain their type FIFO in-process;
    a second worker would fork the queue — two worker sets racing the same records, double AI spend.
    Reads WEB_CONCURRENCY (the gunicorn/uvicorn standard). A manual multi-PROCESS
    launch (a second bare `python -m …`) isn't caught here — a PID/advisory lock would; left as a
    documented follow-up. Raises RuntimeError so a misconfigured launch dies loudly at startup."""
    import os
    from corpusfm.server import queue_workers
    try:
        workers = int(os.environ.get("WEB_CONCURRENCY", "1") or "1")
    except ValueError:
        workers = 1
    queue_workers.assert_single_worker(workers)


def _make_lifespan(mcp_app):
    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        from corpusfm.logging_config import setup_logging
        setup_logging()
        # Publish the informational post-update notice off the startup path. This never opens storage,
        # resets the index, or enqueues derived work; real migrations receive their own lifecycle.
        try:
            import threading
            from corpusfm.server import update_notice

            def _run_update_flow():
                try:
                    result = update_notice.run_update_flow()
                    if not result.get("ok"):
                        import logging
                        logging.getLogger(__name__).warning(
                            "post-update notice was not published: %s", result.get("error"))
                except Exception:
                    import logging
                    logging.getLogger(__name__).warning("post-update notice failed", exc_info=True)
            threading.Thread(target=_run_update_flow, name="cfm-update-notice", daemon=True).start()
        except Exception:
            import logging
            logging.getLogger(__name__).warning("post-update notice skipped", exc_info=True)
        # Build-mismatch gate: detect once at startup whether the live DB schema is older
        # than this build expects. If so, lock the UI to /build-mismatch. Fail-open.
        try:
            from corpusfm.storage import get_backend, storage_migration
            storage_migration.refresh_gate(get_backend())
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup build-mismatch check skipped", exc_info=True)
        # Publish-integrity heal (077-E, release-gating invariant): reap aged staged-store
        # crash residue + any catalog-visible row whose ArtifactData blob is missing (poison
        # rows from pre-invariant code). Bounded reads; in a daemon thread; never fails startup.
        try:
            import threading

            def _heal_publish():
                try:
                    from corpusfm.storage import get_backend
                    from corpusfm.storage.artifact_store import heal_publish_integrity
                    heal_publish_integrity(get_backend())
                except Exception:
                    import logging
                    logging.getLogger(__name__).debug("startup publish-integrity heal skipped",
                                                      exc_info=True)
            threading.Thread(target=_heal_publish, daemon=True).start()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup publish-integrity heal skipped", exc_info=True)
        # Promote any pre-1219 per-job callback onto its SERVER record. Idempotent, bounded, and
        # LOGGED rather than silent: a conflict (the server already carries a different callback) is
        # reported and left alone, because resolving it invisibly is the one outcome the migration
        # exists to prevent. Never fails startup.
        try:
            import threading

            def _migrate_callbacks():
                try:
                    from corpusfm.server.remote_servers import migrate_job_callbacks_to_servers
                    promoted, conflicts = migrate_job_callbacks_to_servers()
                    import logging
                    log = logging.getLogger(__name__)
                    if promoted:
                        log.info("packet 1219: promoted %d job callback(s) onto their server records",
                                 promoted)
                    for job, value, why in conflicts:
                        log.warning("packet 1219: job %r kept a callback %r that was NOT promoted (%s) "
                                    "— set it on the server under Settings if it is still wanted",
                                    job, value, why)
                except Exception:
                    import logging
                    logging.getLogger(__name__).debug("startup callback migration skipped", exc_info=True)
            threading.Thread(target=_migrate_callbacks, daemon=True).start()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup callback migration skipped", exc_info=True)
        # Sweep orphaned Explorer/Diff preview temp dirs: the task→path map is in-memory, so every
        # /tmp/corpusfm_{explorer,diff}_* from before this process is now unreachable. Clears the
        # accumulated backlog on every boot. Never fails startup.
        try:
            from corpusfm.app.web._temp_cleanup import sweep_preview_temp
            sweep_preview_temp()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup preview-temp sweep skipped", exc_info=True)
        # Clear the reabsorb staging dir: tokens are request-scoped, so every staged .artifact from
        # before this process is orphaned once we restart. Never fails startup.
        try:
            from corpusfm.app.web import _reabsorb_staging
            _reabsorb_staging.sweep()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup reabsorb-staging sweep skipped", exc_info=True)
        # Pre-warm the index-membership cache off the request path: the first list_indexed()
        # scan is ~1.2s on a real index, so warm it in a daemon thread at boot rather than
        # making the first Artifacts click pay for it. Never fails startup.
        try:
            import threading
            from corpusfm.app.web.routes.api.library import _indexed_keys
            threading.Thread(target=_indexed_keys, daemon=True).start()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup index-cache prewarm skipped", exc_info=True)
        # Warm the readiness report in a daemon thread. Storage repair belongs to the installer;
        # web startup observes the published state and never mutates it.
        try:
            import threading

            def _diagnose():
                # Assert the FM-side index-projection contract BEFORE any record is written: read the
                # SETTING JSONOfRecord and, if it's missing/empty, write the full default template; else
                # ensure only the Calculations map matches the code (settings left alone), updating it if
                # drifted. Whenever the map is written, run the file-wide refresh script (waited on). The
                # app no longer writes slot fields — the CF derives them, so a missing map = empty slots.
                # Server-mode only; never fails startup.
                try:
                    from corpusfm.config import is_server_mode
                    if is_server_mode():
                        from corpusfm.storage import projections, get_backend
                        _be = get_backend()
                        projections.assert_projection(_be)
                        # Fence (packet 085 §8): a secret must never sit in the SETTING blob —
                        # strip any legacy AI key a hand-copied config may have carried.
                        projections.assert_no_setting_secrets(_be)
                except Exception:
                    import logging
                    logging.getLogger(__name__).debug("startup projection-assert skipped", exc_info=True)
                # Seed the default example artifacts (CORPUSfm's own DB + addon schemas) so a fresh
                # catalog always has something for MCP/testing/demo. Only fills an EMPTY catalog +
                # self-healing. Server-mode only, so the LocalBackend test/dev path (and e2e catalogs)
                # aren't seeded. Runs AFTER the projection assert so seeded rows project on create.
                try:
                    from corpusfm.config import is_server_mode
                    if is_server_mode():
                        from corpusfm.server.seed_artifact import seed_default_artifacts
                        from corpusfm.storage import get_backend
                        seed_default_artifacts(get_backend())
                except Exception:
                    import logging
                    logging.getLogger(__name__).debug("startup seed-artifact skipped", exc_info=True)
                try:
                    from corpusfm.server import readiness
                    readiness.invalidate()
                    readiness.report(force=True)
                except Exception:
                    import logging
                    logging.getLogger(__name__).debug("startup readiness warm skipped", exc_info=True)

            threading.Thread(target=_diagnose, daemon=True).start()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup diagnose thread skipped", exc_info=True)
        # Refuse a multi-worker launch (packet 063) — DELIBERATELY outside the try/except below so it
        # dies LOUDLY. Both background queues keep running-state in-process; a second worker would fork
        # the queue (two drainers, split state, double AI spend).
        _enforce_single_worker()
        # Start the QUEUE workspace workers (packet 086): register the producer step handlers, then
        # start the per-type FIFO workers + the upload watchdog. They scan the QUEUE for work orphaned
        # by a crash/restart and drain it; a bare poke wakes the relevant worker on each new record.
        # Never fails startup (a scan hiccup must not block boot).
        try:
            from corpusfm.server import queue_handlers, queue_workers
            queue_handlers.register_all()
            queue_workers.start_all()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("startup queue workers skipped", exc_info=True)
        # Scheduled refusal-only update observation (packet 1281): ONE box-wide clock so the
        # passive browser polls (packet 1251, D2) have fresh refs to classify. Starts only on a
        # published installation — start_if_published gates on app_paths.is_published() itself,
        # because update_service.check()'s development route fetches directly. Never fails startup.
        _update_observer = None
        try:
            from corpusfm.server.update_observer import start_if_published
            _update_observer = start_if_published()
        except Exception:
            import logging
            logging.getLogger(__name__).debug("scheduled update observation skipped", exc_info=True)
        # The mounted MCP app runs its OWN lifespan (the streamable-HTTP session manager); enter
        # it within ours, or its task group is never initialized ("Task group is not initialized").
        try:
            if mcp_app is not None:
                async with mcp_app.lifespan(app):
                    yield
            else:
                yield
        finally:
            # Shutdown prevents any LATER cycle; it does not join an observation already handed to
            # the privileged one-shot (packet 1281 route step 6).
            if _update_observer is not None:
                _update_observer.stop()
    return _lifespan


_GATE_ALLOW = (
    "/build-mismatch", "/needs-upgrade", "/static", "/login", "/logout", "/favicon",
    "/auth/oidc",   # SSO login/callback establish the session — reachable like /login (packet 1065)
    # Reachable while a blob-encryption conversion holds the global lock:
    "/converting", "/api/settings/storage/blob-encryption/status",
    # The folded-in MCP — gated by fastmcp's own bearer token, not the web session/redirects:
    "/mcp",
    # NOTE: the RFC 9728 protected-resource metadata path (packet 1175) is deliberately NOT here — a
    # startswith() prefix entry would also exempt neighbors/descendants. It is exempted by EXACT match
    # in _deployment_gate, from the actual registered route paths (see create_app).
)


def create_app() -> FastAPI:
    from corpusfm.app.web.deployment import is_migrated

    # ZERO CONFIG, AND EARLY ENOUGH TO MATTER: a box that has not been told its own external address
    # takes one it detects (packet 1219 ruling) — and it must do so BEFORE the MCP application is
    # constructed, because building it imports `corpusfm.mcp.server`, which resolves the address it
    # will advertise ONCE, at module scope (`SERVING_BASE`). Packet 1219 moved this out of the first
    # request and into the lifespan for exactly that reason; the lifespan still runs AFTER this line,
    # so a first boot asserted the address and then served discovery-less MCP until someone restarted
    # the service. Measured on a fresh Linux install (packet 1250): the address never arrived at all
    # because of the compose defect, so this half was never exercised.
    #
    # Synchronous and ahead of the mount, so a fresh published installation serves OAuth discovery on
    # its FIRST boot with no operator input. Never fails app construction: a box with no usable
    # address is a supported state (bearer MCP still works), which is what the resolver reports.
    try:
        from corpusfm.app.web.deployment import assert_external_base_at_startup
        assert_external_base_at_startup()
    except Exception:
        import logging
        logging.getLogger(__name__).debug("startup address assertion skipped", exc_info=True)

    # The status belongs to the application about to be composed, so any record left by a PREVIOUS
    # composition in this process is cleared first and the fresh one is hung on the app itself. One
    # process composes one app in production; a test session composes many, and a module-global that
    # outlived its app reported another application's mount (caught by test_mcp_info_route in a full
    # run, passing in isolation — the order-dependent shape this repo treats as a hidden guard).
    from corpusfm.server import mcp_status as _mcp_status

    _mcp_status.begin_composition()
    mcp_app = _build_mcp_app()
    application = FastAPI(
        title="CORPUSfm", docs_url=None, redoc_url=None, lifespan=_make_lifespan(mcp_app)
    )

    application.state.mcp_runtime = _mcp_status.runtime_status()

    # The composition edge (packet 006): build the runtime graph ONCE here and hang it on
    # app.state. Surfaces read it via the get_ctx dependency instead of importing the resolvers
    # ad hoc. Transitional facade — behaviour-identical to the current per-call discovery.
    from corpusfm.runtime import build_context
    application.state.ctx = build_context()

    application.add_middleware(
        SessionMiddleware,
        secret_key=session_secret(),
        session_cookie="corpusfm_session",
        same_site="lax",
        max_age=SESSION_IDLE_TIMEOUT,  # 12h idle window; slides on activity, capped absolutely (packet 1030)
        # Secure cookie once served over HTTPS via the FMS reverse proxy. Off at root /
        # un-migrated (plain HTTP) so the cookie still works there. Evaluated at startup.
        https_only=is_migrated(),
    )

    # Host allow-list (defence against Host-header spoofing / cache poisoning). CONFIG-DRIVEN so it
    # can never lock out a box by guessing the wrong public hostname: only active when
    # CORPUSFM_ALLOWED_HOSTS is set (comma-separated, e.g. "fms-host.example.com"); loopback is
    # always allowed so the box's own health checks + the deploy smoke test work. Unset → not added
    # (nginx already fronts the only public path). The installer can set it to the FMS hostname.
    import os as _os
    _hosts = [h.strip() for h in _os.environ.get("CORPUSFM_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if _hosts:
        for _h in ("localhost", "127.0.0.1"):
            if _h not in _hosts:
                _hosts.append(_h)
        application.add_middleware(TrustedHostMiddleware, allowed_hosts=_hosts)

    # ── CSRF (double-submit cookie) ──────────────────────────────────────────────
    # SameSite=Lax on the session cookie already blocks cross-site cookie-bearing POSTs; this is the
    # belt-and-suspenders. A readable `corpusfm_csrf` cookie is issued on responses; the SPA's global
    # fetch wrapper echoes it as an X-CSRF-Token header on same-origin mutating requests, and we
    # require the two to match. ONLY cookie-authenticated browser requests are checked — Bearer
    # (MCP / upload token) is token-auth, the /login POST establishes the session, and the /mcp mount
    # has its own bearer gate; all exempt. Inert outside server mode (the dev/test path).
    from corpusfm.config import is_server_mode as _is_server_mode
    _CSRF_EXEMPT = ("/login", "/logout", "/mcp", "/static", "/favicon")
    # EXACT-match exemptions (packet 1179 review §5): ONLY the server-rendered consent FORM POST is
    # exempt from the SPA double-submit HEADER check (it has no fetch wrapper to echo the header); it
    # carries its OWN mandatory, single-use, session-bound synchronizer CSRF token instead
    # (routes/oauth.py). Any OTHER mutating /oauth/* path (a neighbour, a future route) is NOT exempt and
    # still receives the global double-submit protection.
    _CSRF_EXEMPT_EXACT = frozenset({"/oauth/consent"})
    # Cookie-security is FROZEN at boot (packet 073-A, decision a): migration REQUIRES A RESTART.
    # https_only / _csrf_secure are set here from is_migrated() and never recomputed per-request, so
    # a mid-migration flip (which the per-request _deployment_gate would see) can't leave the two
    # disagreeing — the operator restarts as part of migrating. Do NOT move these to per-request.
    _csrf_secure = is_migrated()

    @application.middleware("http")
    async def _csrf(request, call_next):
        import hmac as _hmac
        import secrets as _secrets
        from starlette.responses import JSONResponse as _JSON
        if _is_server_mode() and request.method not in ("GET", "HEAD", "OPTIONS", "TRACE"):
            # Use the ROOT-PATH-STRIPPED route, not request.url.path: behind the FMS proxy with
            # --root-path /corpusfm the raw path is "/corpusfm/login", which fails to match the
            # exempt "/login" prefix → the login POST was wrongly CSRF-checked and 403'd remotely
            # (it worked on loopback, where there's no prefix). route_path() normalizes both.
            from corpusfm.app.web.deployment import route_path
            path = route_path(request)
            bearer = request.headers.get("authorization", "").startswith("Bearer ")
            exempt = bearer or (path in _CSRF_EXEMPT_EXACT) or any(path.startswith(p) for p in _CSRF_EXEMPT)
            # Packet 073-A: require the double-submit token for EVERY mutating, non-exempt, non-bearer
            # request — NOT only when a session cookie is present. The old cookie-presence gate meant
            # that on a migrated box reached over plain HTTP (Secure cookie dropped) the CSRF check
            # evaporated along with auth; enforcement must not depend on the cookie surviving. A
            # request without a session is unauthenticated anyway (require_auth 401s it) — failing it
            # closed here is strictly safer. Browsers always carry the readable corpusfm_csrf cookie
            # (set on every response) + echo it as X-CSRF-Token; token auth uses the exempt Bearer path.
            if not exempt:
                ck = request.cookies.get("corpusfm_csrf", "")
                hd = request.headers.get("x-csrf-token", "")
                if not ck or not hd or not _hmac.compare_digest(ck, hd):
                    return _JSON({"detail": "CSRF token missing or invalid"}, status_code=403)
        resp = await call_next(request)
        if "corpusfm_csrf" not in request.cookies:
            resp.set_cookie("corpusfm_csrf", _secrets.token_urlsafe(32),
                            samesite="lax", secure=_csrf_secure, httponly=False, path="/")
        return resp

    @application.middleware("http")
    async def _security_headers(request, call_next):
        # Baseline browser-side hardening on every response. Deliberately NO restrictive
        # script-src/style-src CSP: the app runs Alpine (eval-based) and serves self-contained
        # Explorer/Diff HTML previews with inline scripts/styles — a strict CSP would break them.
        # We DO set frame-ancestors (clickjacking), nosniff (MIME confusion), and a referrer policy.
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault(
            "Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        return resp

    application.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    _well_known_exact: set = set()
    if mcp_app is not None:
        application.mount("/mcp", mcp_app)
        # `/mcp` answers DIRECTLY (packet 1329). Starlette's Mount 307s the no-slash form to `/mcp/`;
        # the canonical address we publish is now the no-slash one, and a client that POSTs to it should
        # not depend on following a redirect. `/mcp/` is unchanged.
        application.add_middleware(_ExactMcpPathIsNotARedirect)
        # RFC 9728 discovery (packet 1175): serve the protected-resource metadata at the HOST ROOT
        # (/.well-known/oauth-protected-resource/corpusfm/mcp), where the 401 WWW-Authenticate
        # challenge points. The mounted /mcp app's own copy lives under the prefix and is unreachable
        # there; these top-level routes are what the FMS-safe host-root proxy rule forwards. Empty
        # (no-op) when MCP auth is not configured OR discovery is disabled (no canonical base).
        from corpusfm.mcp.server import resource_metadata_routes, authorization_server_metadata_routes
        # Packet 1175: RFC 9728 protected-resource metadata. Packet 1179: when browser OAuth is enabled,
        # ALSO the RFC 8414 authorization-server metadata (both at the host root; the AS list is [] when
        # OAuth is off, so this is a no-op on a default install).
        _wk_routes = list(resource_metadata_routes()) + list(authorization_server_metadata_routes())
        application.router.routes.extend(_wk_routes)
        # Exact paths (canonical + no-slash alias) for the deployment-gate exemption below — an exact
        # set, never a prefix, so a neighbor (.../mcpX) or descendant (.../mcp/evil) is NOT exempted.
        _well_known_exact = {getattr(r, "path", "") for r in _wk_routes if getattr(r, "path", "")}

    @application.middleware("http")
    async def _deployment_gate(request, call_next):
        # Two locks, fail-open (never break a working box):
        #  1) DB schema older than this build  → /build-mismatch
        #  2) server install not behind the FMS reverse proxy yet → /needs-upgrade
        # We support only the co-located proxy deployment, so an un-migrated server box is
        # directed to run the installer rather than running a second (direct/root) version.
        try:
            from corpusfm.app.web.deployment import route_path, prefixed, needs_proxy_migration
            path = route_path(request)   # root_path-stripped, so allowlist matches behind the proxy
            # Prefix allow-list for app surfaces + an EXACT-match set for the RFC 9728 metadata path
            # (packet 1175) so only the canonical path + its trailing-slash alias are exempt — never a
            # neighbor or descendant.
            allowed = (path in _well_known_exact) or any(path.startswith(p) for p in _GATE_ALLOW)
            if not allowed:
                from starlette.responses import RedirectResponse
                from corpusfm.app.web import blob_conversion
                # A bulk blob re-encode holds a global lock — everyone waits at /converting.
                if blob_conversion.is_running():
                    return RedirectResponse(prefixed(request, "/converting"), status_code=302)
                from corpusfm.storage import storage_migration
                if storage_migration.gate_active():
                    return RedirectResponse(prefixed(request, "/build-mismatch"), status_code=302)
                if needs_proxy_migration():
                    return RedirectResponse(prefixed(request, "/needs-upgrade"), status_code=302)
        except Exception:
            pass
        return await call_next(request)

    application.include_router(pages_router)
    application.include_router(oauth_router)   # packet 1179 — browser OAuth authorize + consent
    application.include_router(api_router, prefix="/api")

    _require_session_middleware(application)
    return application


def _require_session_middleware(application) -> None:
    """Fail-loud invariant (packet 073-B): auth + every gate rely on SessionMiddleware populating
    request.scope["session"]; the gate deps SOFT-PASS when it's absent (deliberate for bare test
    apps). If enforcement is on (server mode) but the middleware is somehow not installed — a future
    refactor removing/misordering it — gates would silently open. Assert at boot instead, so that
    mistake dies here rather than shipping a wide-open app."""
    from corpusfm.config import is_server_mode
    if is_server_mode() and not any(
        m.cls is SessionMiddleware for m in application.user_middleware
    ):
        raise AssertionError(
            "SessionMiddleware must be installed in server mode — auth and all gates depend on it; "
            "without it every gate soft-passes (fail-open)."
        )


app = create_app()
