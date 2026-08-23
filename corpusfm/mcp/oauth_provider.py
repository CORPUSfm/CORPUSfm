"""CORPUSfm OAuth Authorization Server provider (packet 1179).

A FastMCP ``OAuthProvider`` subclass implementing the nine SDK persistence/lifecycle hooks over the
shared, Corpus-Key-encrypted :mod:`corpusfm.app.web.oauth_store` (logical ``OAUTH`` → ``TABLE11``). Composed
under ``MultiAuth(server=CfmOAuthProvider, verifiers=[_CfmTokenVerifier])`` so the existing manual
NAMED per-user tokens keep working unchanged (Stage-A finding: MultiAuth tries the server first, then
the verifier; shape-dispatch keeps each store single-touch). The old installer/env break-glass token
is RETIRED — packet 1258; developer ruling 2026-08-20, no real use case — the wide credential is a
named admin user's token now.

Stage-A proved (locked fastmcp 3.4.2 / mcp 1.28.0) that the framework itself enforces PKCE-S256, exact
redirect match, code/token expiry, and required scopes, and maps invalid_grant→401. This provider owns
what the framework does NOT: authorization-code SINGLE USE, the DCR loopback fence (public PKCE clients,
exact loopback redirect URIs only), RESOURCE/AUDIENCE binding to the canonical MCP resource, and
OWNER-FRESH resolution on every request (so a deactivation or a live gate change takes effect
immediately). There is no server-wide switch to check: OAuth sign-in is available whenever this box has
a usable MCP address (packet 1220).

Packet 1183 adds the ROTATING REFRESH rail. The access credential ROTATES every 8 hours, silently, and
nobody signs in because of it; the connection outlives each one because the client exchanges a refresh
credential that is consumed and replaced on every use. The framework's refresh handling is thin by design — it checks the client binding,
an expiry it was given, and that requested scopes are a subset of the ones we advertised, then hands the
whole decision to :meth:`CfmOAuthProvider.exchange_refresh_token`. Everything that matters (rotation,
reuse detection, both lifetime boundaries, and the live consent/gate re-check) therefore lives in
:mod:`corpusfm.app.web.oauth_store`, under the same critical section as the code exchange and Disconnect.

The AUDIENCE on a token request is ours to check twice over. mcp 1.28.0 parses the RFC
8707 ``resource`` form field on BOTH grants and then drops it: no provider hook is given the value and
``RefreshToken`` has no resource field, so comparing our own canonical resource with itself would make an
explicitly WRONG resource indistinguishable from a correct or omitted one. :class:`_TokenResourcePublisher`
recovers the submitted value at the one place it still exists — the ``/token`` route, before the
framework's own handler runs — and publishes it to the hooks, which refuse an explicit mismatch with
invalid_grant before anything is consumed, minted or revoked. The stored resource on the code row / family
row remains the authority for what a credential is bound to.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from typing import Optional
from urllib.parse import urlparse

from fastmcp.server.auth.auth import OAuthProvider
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams,
                                      AuthorizeError, RefreshToken, RegistrationError, TokenError)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.routing import Route

from corpusfm.app.web import oauth_store

log = logging.getLogger("corpusfm.oauth_provider")


# The loopback hosts accepted as a DCR redirect. `localhost` is included (case-insensitively — urlparse
# already lowercases the host) alongside the IP literals: real MCP clients (e.g. Claude Code 2.1.219)
# construct `http://localhost:<ephemeral-port>/callback`, which the OAuth 2.1 / MCP authorization spec
# permits as a loopback redirect. Membership is EXACT — `localhost.evil` / `localhost.example` are a
# different host and rejected; only these three literal hosts pass.
_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


def _is_loopback_redirect(uri: str) -> bool:
    """Exact loopback rule (controlling conclusion #7): http/https on 127.0.0.1, [::1], or localhost ONLY
    — no wildcard, no foreign host, no non-loopback http, no userinfo, no fragment. Host matching is
    EXACT + case-insensitive (a `localhost` suffix like `localhost.evil` is a different host → rejected).
    Ports/paths are free (a native MCP client picks an ephemeral loopback port). HTTPS loopback is also
    accepted (some clients use it). Exact registered-URI matching at authorize/token is unchanged — this
    only decides which redirect URIs DCR will register."""
    try:
        p = urlparse(uri)
    except Exception:
        return False
    if p.username or p.password or p.fragment or "*" in (uri or ""):
        return False
    host = (p.hostname or "").lower()
    if host not in _LOOPBACK_HOSTS:
        return False
    if p.scheme not in ("http", "https"):
        return False
    return True


# ── the RFC 8707 resource indicator submitted on THIS token request ───────────
# None means "not submitted" (the indicator is optional, and `authorize` already bound the grant to this
# server's resource). A string is what the client explicitly asked for, and an explicit mismatch is
# refused. The default is None so a hook invoked outside an HTTP token request — a direct call in a test
# or CLI path — behaves exactly as it did before, rather than reading a value left behind by someone
# else's request.
_SUBMITTED_TOKEN_RESOURCE: ContextVar[Optional[str]] = ContextVar("cfm_oauth_token_resource", default=None)

# OAuth token forms carry short codes, verifiers, client ids and resource URLs. 64 KiB leaves ample
# protocol headroom while preventing the anonymous wrapper + framework parser from buffering an
# attacker-controlled body without bound. This is deliberately endpoint-local, not a web-wide policy.
TOKEN_REQUEST_MAX_BYTES = 64 * 1024


def _replaying(messages, receive):
    """A ``receive`` that hands back the ASGI messages we already read, byte for byte and in order, then
    falls through to the live channel. Nothing is synthesized, so the framework's own handler sees exactly
    the request body that arrived."""
    queue = list(messages)

    async def _receive():
        return queue.pop(0) if queue else await receive()
    return _receive


async def _peek_resource(scope, receive) -> Optional[str]:
    """The ``resource`` form field this token request actually submitted, or None when absent, blank or
    unreadable. Parsed with Starlette's own form parser, so an unusual-but-valid encoding reads the same
    here as it does one layer down in the framework's handler."""
    from starlette.requests import Request
    try:
        form = await Request(scope, receive=receive).form()
    except Exception:
        log.debug("oauth_provider: token form not readable for the resource indicator", exc_info=True)
        return None
    raw = form.get("resource")
    try:
        await form.close()
    except Exception:
        pass
    return raw.strip() if isinstance(raw, str) and raw.strip() else None


class _TokenResourcePublisher:
    """ASGI wrapper over the framework's OWN ``/token`` app, so the provider hooks can see the audience the
    client asked for. This is NOT a second token endpoint: client authentication, PKCE, code/refresh
    expiry, scope narrowing, error mapping and the response all stay the framework's. We read one form
    field, publish it, and hand the request on with its body intact.

    A class rather than a closure because Starlette dispatches on ``inspect.isfunction`` — a function
    endpoint would be wrapped as a request handler, and this has to remain a raw ASGI app (which is what
    the framework's own CORS-wrapped token route is)."""

    def __init__(self, inner):
        self._inner = inner

    @staticmethod
    async def _too_large(send) -> None:
        body = (b'{"error":"invalid_request","error_description":'
                b'"Token request body exceeds 65536 bytes."}')
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") != "POST":
            await self._inner(scope, receive, send)       # a CORS preflight carries no form
            return
        # The whole accepted body is held so it can be replayed intact. Count the actual streamed bytes,
        # not Content-Length (optional and untrusted), and fail closed before parsing or delegation. A
        # padded form therefore cannot bypass the resource check by making this wrapper stop inspecting.
        captured = []
        total = 0
        while True:
            msg = await receive()
            captured.append(msg)
            if msg.get("type") == "http.request":
                total += len(msg.get("body", b""))
                if total > TOKEN_REQUEST_MAX_BYTES:
                    await self._too_large(send)
                    return
            if msg.get("type") != "http.request" or not msg.get("more_body"):
                break
        submitted = await _peek_resource(scope, _replaying(captured, receive))
        token = _SUBMITTED_TOKEN_RESOURCE.set(submitted)
        try:
            await self._inner(scope, _replaying(captured, receive), send)
        finally:
            _SUBMITTED_TOKEN_RESOURCE.reset(token)


def _unknown_client_page(client_id: str, web_prefix: str) -> bytes:
    """The human page for an ``/authorize`` request whose ``client_id`` this server does not know
    (packet 1325 F1). Measured 2026-08-23: Claude Code reused a registration saved before fms-dev was
    reinstalled, the framework answered raw JSON in the developer's browser, and the CLI sat waiting. The
    refusal is unchanged — same 400, nothing registered, nothing redirected — only its FORM is readable
    by the person who can actually fix it. Every interpolated value is escaped; the client id is
    client-supplied text."""
    import html
    raw = client_id or ""
    cid = html.escape(raw[:120]) + ("…" if len(raw) > 120 else "")
    home = html.escape(f"{web_prefix}/mcp-access")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CORPUSfm — sign-in can't continue</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
 body{{margin:0;background:#0f1115;color:#e6e8ee;font:15px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif}}
 main{{max-width:44rem;margin:8vh auto;padding:0 1.5rem}} h1{{font-size:1.25rem;margin:0 0 .75rem}}
 code{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em;background:#1b1f29;padding:.1em .35em;border-radius:4px}}
 p,li{{color:#c3c8d4}} ol{{padding-left:1.25rem}} a{{color:#8ab4ff}}
</style></head><body><main>
<h1>This client's sign-in can't continue</h1>
<p>CORPUSfm no longer knows the registration this client is using (client id <code>{cid}</code>).
That happens when a client saved its registration for this server before the server was reinstalled or
its MCP address changed. Nothing was registered, authorized or redirected.</p>
<ol>
 <li>In the client, clear its saved sign-in for <em>this</em> server — for Claude Code:
   <code>claude mcp logout &lt;name&gt;</code>; for Codex: <code>codex mcp logout &lt;name&gt;</code>;
   other clients: remove and re-add the server.</li>
 <li>Sign in again. The client re-registers automatically and your browser returns to the usual approval page.</li>
</ol>
<p>The address to use, and your connections, are under <a href="{home}">Library → MCP</a>.</p>
</main></body></html>"""


class _UnknownClientPage:
    """ASGI wrapper over the framework's OWN ``/authorize`` app. Intercepts exactly one case — a request
    whose ``client_id`` names no registered client — and answers it with the human page above at the
    same 400 the framework would return. Everything else (missing client_id, redirect/PKCE/scope
    validation, the transaction, the consent redirect) is the framework's, untouched. Only GET and POST
    are inspected; a CORS preflight passes straight through."""

    def __init__(self, inner, web_prefix: str):
        # The framework registers /authorize as a plain request handler (`AuthorizationHandler.handle`),
        # not an ASGI app; Starlette's Route would wrap it with request_response, so this wrapper does
        # the same — exactly Starlette's own test (function or bound method → request handler).
        import inspect
        from starlette.routing import request_response
        self._inner = request_response(inner) if (inspect.isfunction(inner) or inspect.ismethod(inner)) else inner
        self._web_prefix = (web_prefix or "").rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("method") not in ("GET", "POST"):
            await self._inner(scope, receive, send)
            return
        client_id = ""
        captured = []
        if scope.get("method") == "GET":
            from urllib.parse import parse_qs
            client_id = (parse_qs((scope.get("query_string") or b"").decode("latin-1")).get("client_id") or [""])[0]
        else:
            total = 0
            while True:
                msg = await receive()
                captured.append(msg)
                if msg.get("type") == "http.request":
                    total += len(msg.get("body", b""))
                    if total > TOKEN_REQUEST_MAX_BYTES:
                        break                                  # let the framework deal with it
                if msg.get("type") != "http.request" or not msg.get("more_body"):
                    break
            try:
                from starlette.requests import Request
                form = await Request(scope, receive=_replaying(captured, receive)).form()
                raw = form.get("client_id")
                client_id = raw if isinstance(raw, str) else ""
                await form.close()
            except Exception:
                client_id = ""
        if client_id and oauth_store.get_client(client_id) is None:
            body = _unknown_client_page(client_id, self._web_prefix).encode("utf-8")
            await send({"type": "http.response.start", "status": 400, "headers": [
                (b"content-type", b"text/html; charset=utf-8"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"cache-control", b"no-store"),
                (b"content-security-policy", b"default-src 'none'; style-src 'unsafe-inline'"),
                (b"x-content-type-options", b"nosniff"),
            ]})
            await send({"type": "http.response.body", "body": body})
            return
        await self._inner(scope, _replaying(captured, receive) if captured else receive, send)


class CfmOAuthProvider(OAuthProvider):
    """The nine hooks over :mod:`oauth_store`. ``canonical_mcp_url`` is the audience-bound resource
    (e.g. ``https://box/corpusfm/mcp``); ``web_prefix`` is the reverse-proxy mount (e.g. ``/corpusfm``)
    used to build the in-app consent redirect (never an arbitrary external ``next``)."""

    def __init__(self, canonical_mcp_url: str, web_prefix: str):
        self._canonical = canonical_mcp_url.rstrip("/")
        self._web_prefix = (web_prefix or "").rstrip("/")
        super().__init__(
            base_url=self._canonical,          # operational endpoints resolve under the /mcp mount
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                # Advertised scopes = the CORPUSfm gate vocabulary; the actual grant is the user's LIVE
                # gates, resolved at verify time (authentication alone never grants all tools).
                valid_scopes=list(_GATE_VOCAB()),
            ),
            revocation_options=RevocationOptions(enabled=True),
        )

    # ── routes ────────────────────────────────────────────────────────────────
    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """The framework's routes, with the ``/token`` app wrapped so the submitted resource indicator
        reaches the hooks. Every other route — including the framework's own token handler inside this
        one — is used unchanged."""
        routes = super().get_routes(mcp_path)
        wrapped: list[Route] = []
        for r in routes:
            if isinstance(r, Route) and r.path == "/token" and "POST" in (r.methods or ()):
                wrapped.append(Route(path=r.path, methods=["POST", "OPTIONS"],
                                     endpoint=_TokenResourcePublisher(r.endpoint)))
            elif isinstance(r, Route) and r.path == "/authorize":
                wrapped.append(Route(path=r.path, methods=list(r.methods or ["GET", "POST", "OPTIONS"]),
                                     endpoint=_UnknownClientPage(r.endpoint, self._web_prefix)))
            elif isinstance(r, Route) and r.path == "/.well-known/oauth-authorization-server":
                wrapped.append(Route(path=r.path, methods=["GET", "OPTIONS"],
                                     endpoint=self._public_client_metadata_endpoint()))
            else:
                wrapped.append(r)
        return wrapped

    def _public_client_metadata_endpoint(self):
        """The AS metadata document with ``token_endpoint_auth_methods_supported`` stating what
        :meth:`register_client` actually admits — ``none`` (public PKCE clients) — instead of the
        framework's secret-based default. A metadata-following client that registered with
        ``client_secret_basic`` was refused by our own DCR (measured 2026-08-22, packet 1324 S1); the
        document must not point clients at a method the registration endpoint rejects. Built from the
        same inputs the framework passes, so every other field is identical; the framework's
        path-aware aliases reuse this endpoint because they are derived from this route."""
        from mcp.server.auth.handlers.metadata import MetadataHandler
        from mcp.server.auth.routes import build_metadata, cors_middleware
        md = build_metadata(
            issuer_url=self.base_url,
            service_documentation_url=self.service_documentation_url,
            client_registration_options=self.client_registration_options,
            revocation_options=self.revocation_options,
        )
        md.token_endpoint_auth_methods_supported = ["none"]
        if md.revocation_endpoint_auth_methods_supported:
            md.revocation_endpoint_auth_methods_supported = ["none"]
        return cors_middleware(MetadataHandler(md).handle, ["GET", "OPTIONS"])

    def _resource_indicator_mismatch(self) -> bool:
        """True when THIS token request explicitly named an audience that is not ours.

        An omitted indicator is not a mismatch — RFC 8707 makes it optional, and `authorize` already bound
        the transaction to this server's canonical resource. An explicitly WRONG one is refused before any
        code is consumed, any credential minted, or any family touched: a request that was never entitled
        to this audience must not be able to spend a legitimate credential or trip reuse detection."""
        submitted = _SUBMITTED_TOKEN_RESOURCE.get()
        return submitted is not None and submitted.rstrip("/") != self._canonical

    # ── clients (DCR) ─────────────────────────────────────────────────────────
    async def get_client(self, client_id: str):
        rec = oauth_store.get_client(client_id)
        if not rec:
            return None
        try:
            return OAuthClientInformationFull(**rec)
        except Exception:
            log.debug("oauth_provider: stored client record invalid for %s", client_id, exc_info=True)
            return None

    async def register_client(self, client_info: OAuthClientInformationFull):
        # Public PKCE clients only.
        if client_info.token_endpoint_auth_method not in (None, "none"):
            raise RegistrationError(error="invalid_client_metadata",
                                    error_description="only public PKCE clients are supported")
        # Exact supported contract, nothing more (review §3). The FastMCP 3.4.2 DCR handler already
        # MANDATES grant_types ⊇ {authorization_code, refresh_token} and response_types ∋ code; we
        # tighten that to the EXACT sets supported and reject anything else (implicit, client_credentials,
        # a `token` response type, …). Both advertised grants are now genuinely served (packet 1183): the
        # authorization_code grant creates the connection, the refresh_token grant rotates it. The
        # framework refuses a grant the client did not advertise, so this set is also what gates refresh.
        # Effective contract: public + authorization_code + refresh_token + response_type=code, PKCE-S256.
        grants = set(client_info.grant_types or [])
        if grants - {"authorization_code", "refresh_token"} or "authorization_code" not in grants:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="only the authorization_code grant is supported")
        if list(client_info.response_types or []) != ["code"]:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="only the 'code' response type is supported")
        # Exact loopback redirect URIs only — registered as the loopback SUBSET of what was asked
        # (packet 1325 R2). Real native clients send a mixed list: VS Code 1.134.0 registers
        # ["https://insiders.vscode.dev/redirect", "https://vscode.dev/redirect", "http://127.0.0.1/",
        # "http://127.0.0.1:<port>/"], so all-or-nothing refused a desktop client that would only ever
        # use its loopback entry. RFC 7591 lets the server replace requested metadata and return what
        # it registered; the stored record and the 201 carry only this subset, so a hosted callback is
        # never registered and exact matching at authorize/token still sees loopback URIs only. The
        # rule is metadata-based — it never keys on a claimed client name or version.
        uris = list(client_info.redirect_uris or [])
        if not uris:
            raise RegistrationError(error="invalid_redirect_uri", error_description="a redirect_uri is required")
        loopback = [u for u in uris if _is_loopback_redirect(str(u))]
        if not loopback:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="redirect_uri must be an exact loopback URI "
                                  "(127.0.0.1, [::1], or localhost)")
        client_info.redirect_uris = loopback
        client_info.token_endpoint_auth_method = "none"
        # Registered SCOPE (packet 1325, Cursor gate 2026-08-23). The framework refuses any /authorize
        # scope the client did not DECLARE at registration, and a client that registers with no `scope`
        # is allowed none at all — Cursor registers without one, then asks for our advertised scopes, and
        # bounced back with `invalid_scope: Client was not registered with scope automation`. Claude
        # Code, Codex and VS Code send our scopes in DCR, so they never met this. RFC 7591 lets the server
        # set or replace requested metadata and return it: a client that declared scopes keeps exactly
        # those (the framework already refused anything outside our vocabulary before this hook ran, so
        # a declaration is always a subset of ours and a deliberate narrowing stays narrow); a client that
        # declared NONE is registered for our whole vocabulary. Nothing widens — the GRANT is the user's
        # live gates at consent, never the registered list.
        vocab = list(_GATE_VOCAB())
        declared = [x for x in (client_info.scope or "").split() if x in vocab]
        client_info.scope = " ".join(declared or vocab)
        from corpusfm.app.web import oauth_registration_guard
        try:
            oauth_registration_guard.admit()
        except oauth_registration_guard.RegistrationRateExceeded as exc:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="client registration rate exceeded; retry later",
            ) from exc
        except oauth_registration_guard.RegistrationAdmissionUnavailable as exc:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="client registration is temporarily unavailable",
            ) from exc
        if not oauth_store.save_client(client_info.model_dump(mode="json")):
            raise RegistrationError(error="invalid_client_metadata", error_description="storage unavailable")
        maintenance = oauth_store.cleanup_abandoned_clients()
        if not maintenance.get("ok"):
            log.warning("oauth_provider: abandoned-client cleanup failed: %s",
                        maintenance.get("error") or "unknown failure")

    # ── authorize → server-held transaction → in-app consent ──────────────────
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        # Audience fence (RFC 8707): a stated resource must equal our canonical MCP resource.
        if params.resource is not None and params.resource.rstrip("/") != self._canonical:
            raise AuthorizeError(error="invalid_target",
                                 error_description="resource does not match this MCP server")
        handle = oauth_store.create_txn(
            client_id=client.client_id,
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            scopes=list(params.scopes or []),
            resource=self._canonical,
            state=params.state,
        )
        if not handle:
            raise AuthorizeError(error="server_error", error_description="could not start authorization")
        # Redirect to the in-app consent gate (root-relative; the proxy prefix is applied by the browser
        # against the box host). NEVER an arbitrary external next URL — the txn IS the resume state.
        return f"{self._web_prefix}/oauth/authorize?txn={handle}"

    # ── code exchange ─────────────────────────────────────────────────────────
    async def load_authorization_code(self, client, authorization_code: str):
        rec = oauth_store.load_code(authorization_code)
        if not rec or rec.get("ClientId") != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=list(rec.get("Scopes") or []),
            expires_at=float(rec.get("ExpiresAt", 0)),
            client_id=rec.get("ClientId"),
            code_challenge=rec.get("CodeChallenge", ""),
            redirect_uri=rec.get("RedirectUri", ""),
            redirect_uri_provided_explicitly=bool(rec.get("RedirectUriProvidedExplicitly")),
            resource=rec.get("Resource"),
            subject=rec.get("Subject"),
        )

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        if self._resource_indicator_mismatch():
            # Refused BEFORE the consume, like the store's own wrong-audience refusal: a request naming
            # another audience must not burn this user's single-use code.
            raise TokenError(error="invalid_grant",
                             error_description="resource does not match this MCP server")
        subject = authorization_code.subject or ""
        if _live_gates(subject) is None:
            raise TokenError(error="invalid_grant", error_description="account is not active")
        # SINGLE USE + LIVE GRANT, in ONE critical section — the framework does NOT invalidate the code,
        # and consume-then-mint as two steps left a window where a user Disconnect between them would
        # report success and still see a token appear (packet 1182). Two simultaneous exchanges of one
        # code → at most one winner → at most one token; an exchange that arrives after Disconnect finds
        # no consent grant and mints nothing.
        # The audience passed is what this server EXPECTS, not what it mints from: the store matches it
        # against the code's own stored resource and binds the token to that row's value.
        # The same section also replaces any prior refresh family for this connection and creates the
        # new one, so a second browser authorization never leaves an older family or token usable.
        # The AUTHENTICATED client id goes with it (review round 3). The framework resolved this client
        # and matched it against the code BEFORE the lock, which left client identity as the last part of
        # the grant decided by a pre-lock read: the store re-checks it — and re-resolves the registration
        # itself — against the freshly loaded code row, consuming nothing on any mismatch.
        minted = oauth_store.exchange_code_for_token(authorization_code.code,
                                                     expected_client_id=client.client_id,
                                                     expected_resource=self._canonical)
        if minted is None:
            raise TokenError(error="invalid_grant", error_description="authorization code is no longer valid")
        token, expires_at, code_record, refresh = minted
        # The token is bound to the CONSENTED CEILING (the code's scopes), never re-broadened to the
        # user's full live gates. Effective scope is (ceiling ∩ live gates), computed fresh at verify.
        ceiling = sorted(set(code_record.get("Scopes") or []))
        import time as _t
        # Advertise the effective grant at issuance (ceiling ∩ live) — never broadening the request.
        effective = sorted(set(ceiling) & set(_live_gates(subject) or []))
        return OAuthToken(access_token=token, token_type="Bearer",
                          expires_in=max(1, int(expires_at - _t.time())),
                          scope=" ".join(effective), refresh_token=refresh)

    # ── refresh (rotating; packet 1183) ───────────────────────────────────────
    async def load_refresh_token(self, client, refresh_token: str):
        """VERIFY the presented credential and describe it — no decision, no mutation.

        A SPENT generation deliberately still resolves here. Returning None for one would make the
        framework answer "refresh token does not exist" and the replay would never reach the code that
        can recognise it, so a stolen retired credential would look like an unrelated unknown token. The
        rotation decision — including reuse detection — happens in :meth:`exchange_refresh_token`.

        ``scopes`` is the family's consented CEILING: the framework refuses any requested scope outside
        it with invalid_scope, so refresh can never widen a grant. ``expires_at`` is this connection's
        effective boundary; the store re-enforces both boundaries authoritatively under the lock."""
        if self._resource_indicator_mismatch():
            return None                                  # wrong audience asked for → no store read at all
        rec = oauth_store.load_refresh_credential(refresh_token)
        if rec is None:
            return None
        row, family = rec["refresh"], rec["family"]
        if str(row.get("ClientId") or "") != client.client_id:
            return None                                  # another client's lineage — never loadable here
        if (str(family.get("Resource") or "")).rstrip("/") != self._canonical:
            return None                                  # audience-bound, like the access token
        # The due date comes back WITH the record: the store computed it under the one policy read it
        # already took for this request, so describing the credential costs no second read and has no
        # second chance to fail (packet 1189, review round 2).
        due = int(rec.get("reauthorization_due_at") or 0)
        if due <= 0:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=str(row.get("ClientId") or ""),
            scopes=sorted(set(family.get("ScopeCeiling") or [])),
            expires_at=due,
            subject=str(row.get("Subject") or ""))

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        """Rotate: consume the presented credential, mint a NEW access token and a NEW refresh
        credential. Every failure is one invalid_grant with no sensitive detail — the client learns that
        it must sign in through the browser again, never why."""
        if self._resource_indicator_mismatch():
            # Before rotation, so a wrong-audience request neither spends the presented generation nor
            # reaches the reuse-detection path that revokes a family.
            raise TokenError(error="invalid_grant",
                             error_description="resource does not match this MCP server")
        status, payload = oauth_store.rotate_refresh(
            getattr(refresh_token, "token", refresh_token),
            expected_client_id=client.client_id, expected_resource=self._canonical,
            requested_scopes=list(scopes or []))
        if status != oauth_store.REFRESH_OK or not payload:
            raise TokenError(error="invalid_grant",
                             error_description="refresh token is no longer valid")
        import time as _t
        # No refresh-token expiry rides the wire: OAuthToken (mcp 1.28.0) has no standard field for one,
        # and inventing a non-standard claim would tell a client something it cannot act on. The
        # server-side inactivity/absolute policy is unaffected — both are enforced from stored state on
        # every rotation.
        return OAuthToken(access_token=payload["access_token"], token_type="Bearer",
                          expires_in=max(1, int(payload["expires_at"] - _t.time())),
                          scope=" ".join(payload.get("effective_scopes") or []),
                          refresh_token=payload["refresh_token"])

    # ── access-token verify (owner resolved FRESH every request) ──────────────
    async def load_access_token(self, token: str):
        # Shape-dispatch: a non-OAuth-prefixed token returns None WITHOUT any OAuth-store read, so a
        # dotted manual token never fans out through here (it is resolved by _CfmTokenVerifier instead).
        # The store's own validation also re-reads the token's refresh FAMILY, so a revoked connection
        # and a tightened lifetime policy both deny an already-issued token here, not just at the next
        # rotation (review round 2).
        rec = oauth_store.load_token(token)
        if rec is None:
            return None
        if (rec.get("Resource") or "").rstrip("/") != self._canonical:
            return None                                  # audience-bound
        subject = rec.get("Subject") or ""
        live = _live_gates(subject)                      # LIVE gates; deactivation → None
        if live is None:
            return None
        # Effective scope = the consented CEILING ∩ the owner's CURRENT gates. Gate REMOVAL takes effect
        # immediately (drops from live → drops from effective); a newly-ADDED gate is NOT in the ceiling,
        # so this client never receives it until a fresh consent records a new ceiling (review §3).
        ceiling = set(rec.get("Scopes") or [])
        effective = sorted(ceiling & set(live))
        username = _username_for(subject)
        return AccessToken(
            token=token,
            client_id=rec.get("ClientId") or "",         # the REGISTERED OAuth client id (attribution)
            scopes=effective, expires_at=int(rec.get("ExpiresAt", 0)),
            resource=self._canonical, subject=subject,   # subject = the CORPUSfm user id
            claims={"user": username} if username else None)   # claims.user = the CORPUSfm username

    async def revoke_token(self, token):
        """RFC 7009 revocation, shape-dispatched. The framework resolves the presented credential as
        either an access token or a refresh token and hands us whichever matched; revoking a REFRESH
        credential retires the whole family (it is the connection's authorization, not one disposable
        token), which is also what the SDK asks implementations to do."""
        val = getattr(token, "token", token)
        if isinstance(val, str) and val.startswith(oauth_store.REFRESH_TOKEN_PREFIX):
            oauth_store.revoke_refresh_credential(val)
            return
        oauth_store.revoke_token(val)


# ── owner resolution (live) ───────────────────────────────────────────────────

def _GATE_VOCAB():
    from corpusfm.app.web.users import GATES
    return GATES


def _live_gates(subject: str):
    """The owner's CURRENT gates (sorted list), or None when the account is missing/inactive. One
    implementation, shared with the store's own under-the-lock re-check (packet 1183)."""
    return oauth_store._owner_gates(subject)


def _username_for(subject: str):
    try:
        from corpusfm.app.web import users as _us
        u = _us.get_user_by_id(subject)
        return u.username if u else None
    except Exception:
        return None
