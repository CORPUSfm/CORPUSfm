"""corpusfm MCP server — mode-aware tool registration.

App mode (77 tools — the non-server code path; co-located server is the only real deployment):
  list_artifacts      — list stored artifacts in the archive (optional tag filter)
  get_artifact_types  — the artifact TYPES the catalog holds and what each one supports
  delete_source       — delete an artifact's retained source XML to reclaim storage
  get_object          — ONE object's header + uses/used-by + full rendered body (single-object retrieval)
  get_object_evidence — neutral, query-time evidence for one object or an artifact's attention candidates
  get_change_impact_evidence — neutral change-impact evidence for one object: DEPENDENTS in / DEPENDENCIES out, per-edge observed-vs-inferred provenance (never a verdict)
  get_artifact_attention_signals — artifact-WIDE neutral triage scan: what deserves a look first, each ranked by its own number (never a verdict)

  the 5 perspective LENSES (read-only, neutral, no verdict — MCP is their home; the human-UI overlays were removed):
  get_workflows       — what a user can DO and the data each action touches
  get_security_reach  — what each privilege set can reach + the accounts assigned to it
  get_data_model      — the real table-to-table model under the TableOccurrence graph (+ a mermaid erDiagram)
  get_ai_usage        — which FileMaker native-AI capabilities the solution uses, by script
  get_workflow_deltas — how each workflow's observed blast radius changed between two artifacts
  find_external_references — what one file references in its siblings (cross-file)
  reconstruct_external_interface — rebuild a missing file's external interface from siblings
  emit_reconstruction_stub — render a missing file's reconstruction as a buildable schema stub (plan/OData DDL)
  suggest_external_field_names — naming evidence for a missing file's id-only fields (context-mined candidates)
  get_patch_authoring_guide — the full patch-authoring guide (action grammar + construction templates + limits)
  get_ai_build_guide  — the END-TO-END build-loop orchestration guide (goal -> applied change)
  get_step_exemplar   — real, verified step sequences from the corpus, volatile bits as placeholders
  check_patch         — statically verify a patch (coherence + simulate) BEFORE save/apply
  verify_patch_applied — confirm a patch did exactly what it intended AFTER apply (before vs after)
  dry_run_patch       — apply a patch to a COPY of a live DB + verify (production untouched)
  plan_apply          — step 1/2: predict a production apply's blast radius + issue a token
  apply_patch         — step 2/2: execute a planned apply (token-gated, reversible, backed up)
  compare             — diff two archive artifacts, return summary
  render_section      — human-readable content of one section from an artifact
  get_raw_xml         — raw XML for a named item (AI inspection; supplemental sources via source_catalog)
  get_script_steps    — a script's steps in FM order: index/id/name/enabled + rendered + (opt) raw step XML
  list_registrations  — list git export registrations
  export_to_git       — export an artifact to a named registration
  semantic_search     — natural language search over indexed items (scope to one record with ref=)
  get_index_status    — is one artifact in the search index + how many docs (the `indexed` badge over MCP)
  get_server_info     — CORPUSfm version / mode / tool count / FM support / index-configured
  temporal_diff       — compare schema changes over a time window
  get_schema_context  — compact ID-explicit schema context for AI write-path
  get_patch_capabilities — FMUpgradeTool do's/don'ts (capability ledger)
  reimport_after_patch — re-import FM file after patch apply (co-located only)
  generate_patch      — generate FMUpgradeToolPatch XML from two artifacts
  save_ai_patch       — store AI-generated patch XML as a PatchXML catalog artifact
  save_clip           — store a FileMaker FMObjectList clip as an fmClip catalog artifact
  save_fmscript       — save a single FileMaker script as an fmScript artifact
  save_fmcalc         — save a single FileMaker calculation as an fmCalc artifact
  validate_clip       — pre-paste check for a clip: well-formed/kind, block balance, calc parse, and reference resolution against a target file (the silent-<…Missing> guard)
  patch_clip          — deterministic structured edits on an existing clip (set_enabled/delete/replace_calc/insert/move by index/name/banner/var/calc); re-validated after
  get_deliverable     — fetch a STORED deliverable's content by ref (fmClip/PatchXML/fmScript/fmCalc — the read side; schema loaders can't read a deliverable blob)
  export_object_clip  — export ONE schema script as a paste-ready FileMaker clip. CURRENT runtime is fenced to round-trip-verified step types and refuses unsupported step ids; that fixture fence is regression evidence, not the permission model (see the fmClip product model in CLAUDE.md, packet 1086)
  export_field_clip   — export a base table's FIELD DEFINITIONS as a paste-ready XMFD clip. CURRENT runtime is fenced to round-trip-verified field shapes and refuses uncaptured ones (all class-1/capturable); that fixture fence is regression evidence, not the permission model (fmClip product model, CLAUDE.md, packet 1086)
  create_script_acceptance_batch — generate + store an isolated pasteable clip per requested SaveAsXML script as a paste-acceptance BATCH (preflight-all; deterministic FileMaker-safe names; structured acceptance metadata). The human pastes them into one disposable file and exports SaveAsXML
  evaluate_acceptance_return — correlate a returned SaveAsXML to a batch by EXACT generated script name and record a conservative per-case observation (shape-match / shape-changed / not-found / paste-rejected / evaluation-incomplete); shape match is NOT behavioral verification
  compile_script_clip — compile a structured, AI-authored FLAT script AST into a paste-ready FileMaker clip, resolving field/layout/current-file-script NAMES against a target artifact and lowering to DDR steps for the SAME fenced emitter (no second emitter); unresolved/ambiguous references withhold the whole script; limitations in result metadata, never the clip XML
  get_fmclip_compiler_guide — the authoring guide for compile_script_clip (AST schema, MVP vocabulary, the reference-resolution rule, result vocabulary, and the four metadata buckets); read before compiling
  detect_clip_variations — triage a script/artifact against the LIVE clip-emitter fence: covered / new-variation / unsupported / ddr-gap, with the shortfall reported as capture TELEMETRY (informational, not a work order) (read-only)
  import_artifact     — ingest an in-context export (SaveAsXML/Addon/clip) through the ingest queue; returns a queue id (poll get_queue). Bulk/large files: POST to /api/import/source instead
  download_container_data — get signed, expiring local-download URLs for retained container contents (raw XML / parsed artifact / summaries / addon name-map) of one record or many; curl them from your machine, each row saying whether it lands zipped (read-only)
  set_artifact_memory — set the agent-authored memory note on an artifact
  index_artifact      — enqueue an index job for an artifact (semantic-search vectors; via the queue)
  deindex_artifact    — remove an artifact's file from the search index (immediate; inverse of index_artifact)
  summarize_artifact  — enqueue a summarize job for an artifact (chat-model enrichment; summarize-later)
  get_queue           — the server enrichment queue: running + pending + failed (what's holding up the show)
  generate_db_file    — materialize a working .fmp12 from a full SaveAsXML (FMUpgradeTool 2026, co-located)
  plan_promote_generated_db / execute_promote_generated_db — two-step promote of a generated .fmp12 into CORPUSfm's VERIFIED patch compartment (single-use token; the source is either already in the compartment or in the `_generated/` quarantine; never the live FMS Databases folder; storage-DB-guarded; no-replace)
  get_schema_gaps     — an artifact's ACTIONABLE schema gaps (unknown step IDs / ref types / sections) + the YAML to extend
  try_schema_yaml     — dry-run a candidate mappings/structure YAML overlay vs the artifact (resolve/clobber safeguard; never writes shipped YAML)

  the 4 STABLE update-control-plane tools (packet 1124 — permanent short names, a compatibility promise; the update rendezvous does NOT depend on discovering a newly-named status tool after each release):
  server_capabilities — read-only rendezvous: running version/build/head + mode, control-plane revision, whether the four update tools are registered, MCP/FastMCP version + list-changed-notification support (fact, not a client-refresh promise), and the VS Code recovery order. No tool dump / secrets / paths / tokens
  update_check        — explicit read-only observation through the shared Settings-updater authority (asks the fixed elevated one-shot to refresh refs with an impossible consent; the service performs no git operation): the exact current/target head + version, head_build_version + stamp_repair (OBSERVED ONLY — a stale runtime build stamp on a current checkout; there is no in-app repair, an installer run rewrites it), behind count, privacy-safe classification booleans, apply_allowed, and the installer handoff when elevated work is required
  update_apply        — mutating wrapper: requires expected_head from update_check as a refusal-only consent pin, then TRIGGERS the fixed elevated one-shot, which resolves origin/main itself and refuses target_changed / unclean_tree / origin_mismatch / not_fast_forward / needs_installer / import_probe_failed. The service performs no git operation. Drops the MCP connection — reconnect + update_status
  update_status       — read-only durable status/reconciliation: reads the request record and lazily promotes restart_scheduled → restarted once the running version matches the applied update (mismatch is a named non-success, never a silent one)
  fms_list_databases  — list hosted DBs + status (Admin API via PKI; `fms_api` gate)
  fms_list_clients    — list connected clients (`fms_api` gate)
  fms_list_schedules  — list FMS schedules (`fms_api` gate)
  plan_fms_control_database / execute_fms_control_database — two-step open/close/pause/resume/flush (NOT the storage DB)
  plan_fms_disconnect_client / execute_fms_disconnect_client — two-step disconnect a client by id
  plan_fms_message_clients / execute_fms_message_clients — two-step message one client or ALL

The 9 fms_* tools are broad FileMaker Server control via the Admin API v2 (PKI — no admin
password held), behind THREE rails: the per-user `fms_api` gate; the server-wide
enable_fms_admin_mcp_tools switch (default off — hidden from tools/list + refused when off); and
plan_*→execute_* two-step for every mutating op. Server-process restarts are deliberately excluded
(the Admin API has no restart endpoint; that stays a CLI/installer concern).

Server mode adds 7 more tools (84 total; registered only in server mode):
  list_jobs           — list jobs (name, uuid, owner file, schedule, last run) — filterable by file
  run_job             — trigger a named job (pulls fresh XML from FMS); returns run_id
  get_job_run         — exact per-run status/outcome by run_id (active queue → HISTORY, no "latest")
  get_job_history     — run history for a named job
  get_health          — current health status: firing alerts + job health
  list_alerts         — recent alert history
  acknowledge_alert   — suppress a named alert condition for N hours

fmClip generation — epoch orientation (packet 1086, ratified 2026-07-16): the governing model for
export_object_clip / export_field_clip / patch_clip / validate_clip / detect_clip_variations lives in
CLAUDE.md ("fmClip generation — product model"). Fixture coverage is regression evidence, NOT the
universal permission to emit; a missing pair is not by itself grounds to refuse. The ratified direction
is generate-the-best-supported-result-and-disclose-limits, with a five-state result vocabulary
(generated_verified / generated_static_valid / generated_experimental / refused_known_hazard /
observed_filemaker_failure) and an inline developer-feedback report. THAT DIRECTION IS NOT SHIPPED: the
current runtime still enforces the old fail-closed fixture gates (these tools refuse an uncaptured shape
today) and returns no structured result states. Do not describe the future behavior as implemented; the
plumbing lands in packet 1087+.

Start: python -m corpusfm.mcp
"""

from __future__ import annotations

import math
import os
import re
import secrets
import time
from corpusfm.core import safe_xml as _ET
from pathlib import Path
from threading import Lock
from typing import Optional

from fastmcp import FastMCP

from corpusfm.runtime import build_context
from corpusfm.core.git_formatter import export_artifact_to_registration, list_registrations as _list_regs
from corpusfm.storage import get_backend
from corpusfm.artifact import Artifact
from corpusfm.core.comparator import compare_artifacts as _compare_artifacts
from corpusfm.core.renderer import format_report
from corpusfm.server import audit

# MCP composition edge (packet 006, S5): resolve the runtime mode ONCE through the shared runtime
# layer, instead of three separate is_server_mode() calls at import. The mode decides the 6
# server-only tools (jobs / alerts / health), so it must be evaluated before they register — the
# `mcp` object stays import-time global (a build_mcp(ctx) factory is a larger future slice). This
# removes MCP's direct dependency on config.is_server_mode and the duplicate discovery paths.
_SERVER_MODE = build_context().is_server

if _SERVER_MODE:
    from corpusfm.server.monitor.alerts import (
        check_conditions, load_alert_history, suppress_alert,
    )
    from corpusfm.server.monitor.config import load_monitor_config
    from corpusfm.server.monitor.history import get_job_health
    from corpusfm.server.jobs.history import default_history_dir, list_runs_for
    from corpusfm.server.jobs.state import read_state
    from corpusfm.server.jobs.store import default_jobs_dir, list_jobs as _list_jobs, load_job as _load_job

def _canonical_public_base_url() -> "Optional[str]":
    """The canonical HTTPS base of the SUPPORTED CORPUSfm deployment to advertise in RFC 9728 / RFC 8414
    metadata, or ``None`` when none is safely configured (→ discovery disabled; the raw bearer MCP still
    works). Packet 1180: MCP holds NO independent environment/persisted precedence — it consumes the ONE
    shared **External CORPUSfm address** resolver (``deployment.external_base()``), whose value already
    identifies the real deployment (https, non-loopback host, path == ``web_prefix()``) and whose
    authoritative-invalid override disables discovery without falling through. ``""`` (no usable
    address) maps to ``None`` to preserve this function's contract."""
    try:
        from corpusfm.app.web.deployment import external_base
        return external_base().value or None
    except Exception:
        return None


def _build_auth():
    """Auth for the folded-in MCP — unconditional in server mode, absent outside it.

    **The MODE is the whole condition (packet 1258).** A deployed box always authenticates: every
    request must carry `Authorization: Bearer <token>`, and a token resolves to a NAMED user carrying
    that user's live gates as scopes. There is no server-wide token, no break-glass, and therefore no
    credential that is not a person's — so a gate change lands on the next call and a departure is a
    deletion. Those scopes are enforced downstream by the _TOOL_GATES map + the middleware below: each
    request's gates decide which tools it both SEES (tools/list is filtered) and may CALL.

    Outside server mode → None → unauthenticated (loopback / SSH-tunnel / unit tests), which is the
    from-source development path and nothing that is ever served publicly.

    This replaced a token-present test. That test also decided whether the app mounted /mcp at all, so
    an absent token meant no MCP rather than a refused one; the fail-closed property now rests on the
    verifier refusing, and its proof is that a server-mode app with an empty environment still answers
    401. **Storage is the single authority for identity:** with the backend unreachable nothing
    authenticates, which is the intended behavior (owner ruling, packet 1258) — recovery is admin +
    CLI on the box, never a credential kept outside the store.

    With a canonical external HTTPS base configured, the verifier is composed into the OAuth
    ``MultiAuth`` (packet 1179), which serves BOTH discovery documents — RFC 9728 protected-resource
    metadata and the authorization-server metadata — plus a discovery-correct 401. With NO canonical
    base we must NOT advertise a misleading (loopback / plain-HTTP) resource — so we keep the RAW
    verifier: bearer authentication is unchanged, discovery is simply OFF until an address is set, and
    we log a clear one-line warning.

    The address IS the whole condition for DISCOVERY (packet 1220). The bearer-only
    ``RemoteAuthProvider`` composition that used to sit between these two cases existed to serve
    resource metadata while OAuth was switched off; with no switch there is nothing between them, and
    MultiAuth already serves that document."""
    # Read the mode LIVE rather than reusing the import-time `_SERVER_MODE`: this function is called
    # again whenever `mcp.auth` is rebuilt (the hermetic test fixture does exactly that), and a frozen
    # copy would answer for the mode at import instead of the mode being asked about.
    from corpusfm.config import is_server_mode
    if not is_server_mode():
        return None
    verifier = _CfmTokenVerifier()
    base = _canonical_public_base_url()
    if not base:
        import logging
        logging.getLogger(__name__).warning(
            "MCP RFC 9728 discovery DISABLED: this box has no MCP address — set it in Settings -> MCP "
            "to https://<host>/corpusfm. The bearer MCP still works; resource-metadata discovery stays "
            "off until an address is set (a loopback/plain-HTTP base is never advertised)."
        )
        return verifier
    # Packet 1179: mount the full OAuth authorization server composed with the existing bearer verifier
    # via MultiAuth. There is no switch in front of it (packet 1220) — a usable MCP address is the whole
    # condition, which is why this sits below the `if not base` return above. Manual per-user tokens
    # are unaffected: MultiAuth tries the OAuth server first, then the verifier.
    return _build_oauth_multiauth(verifier, base)


def _build_oauth_multiauth(verifier, base: str):
    """MultiAuth(server=CfmOAuthProvider, verifiers=[verifier]) — the OAuth AS + the bearer rails.

    base_url = ``<base>/mcp`` so operational endpoints (/authorize,/token,/register,/revoke) resolve
    UNDER the existing ``/mcp`` mount (Stage-A topology proof); only the host-root metadata docs are
    hoisted by ``resource_metadata_routes()`` + ``authorization_server_metadata_routes()``."""
    from fastmcp.server.auth.auth import MultiAuth
    from corpusfm.mcp.oauth_provider import CfmOAuthProvider
    try:
        from corpusfm.app.web.deployment import web_prefix
        prefix = web_prefix()
    except Exception:
        prefix = ""
    provider = CfmOAuthProvider(canonical_mcp_url=base + "/mcp", web_prefix=prefix)
    return MultiAuth(server=provider, verifiers=[verifier])


def _build_cfm_verifier_class():
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
    from fastmcp.server.auth import AccessToken

    class _CfmTokenVerifier(StaticTokenVerifier):
        def __init__(self):
            # EMPTY static map, and nothing is ever added to it: every credential this verifier
            # accepts belongs to a named user and is resolved live per request, so a gate change or a
            # deletion takes effect on the next call with no reload. There is no server-wide token
            # (packet 1258) — MCP access is user-account-centric.
            super().__init__(tokens={})

        async def verify_token(self, token: str):
            # Per-user token → that user's gates (resolved live from the users store, which is the
            # storage backend: with storage down NOTHING authenticates, which is the intended
            # behavior, not a gap to soften. Recovery is admin + CLI on the box.)
            try:
                from corpusfm.app.web import users as _us
                u = _us.resolve_mcp_token(token)
            except Exception:
                u = None
            if u is None:
                return None
            return AccessToken(token=token, client_id="cfm:" + u.username,
                               scopes=sorted(u.gates), claims={"user": u.username})

    return _CfmTokenVerifier


_CfmTokenVerifier = _build_cfm_verifier_class()


# The address THIS PROCESS is actually serving, captured at the moment the auth stack is built. It is a
# module global rather than a re-read because that is the honest answer: the stack is composed once at
# import, so a later change to the stored address does not move what this process advertises. Settings
# compares the two to say "saved, takes effect at the next restart" instead of showing one identity while
# serving another (packet 1219 Half B).
SERVING_BASE: str = _canonical_public_base_url() or ""

mcp = FastMCP("corpusfm", auth=_build_auth())


def serving_base() -> str:
    """The MCP address this running process advertises, or "" when it has none. Never re-resolved."""
    return SERVING_BASE


def _host_root_well_known_routes():
    """Raw host-root discovery routes from whichever auth provider is configured (mcp_path='/' mirrors
    http_app(path='/')). MultiAuth/OAuthProvider (packet 1179) → the OAuth AS metadata (RFC 8414
    path-aware) + OIDC aliases + the protected-resource route. Returns [] for a genuine no-metadata
    state (no token / no MCP address, so discovery is disabled). A construction failure while a provider
    IS configured is a real misconfiguration — logged and re-raised (never silently swallowed while the
    401 advertises it)."""
    from fastmcp.server.auth.auth import MultiAuth, OAuthProvider
    auth = getattr(mcp, "auth", None)
    try:
        if isinstance(auth, (MultiAuth, OAuthProvider)):
            return list(auth.get_well_known_routes(mcp_path="/"))
    except Exception:
        import logging
        logging.getLogger(__name__).error(
            "MCP host-root well-known route construction FAILED while an auth provider is configured — "
            "the 401 challenge would advertise discovery that is not served. Refusing to hide it.",
            exc_info=True,
        )
        raise
    # None → no token (no auth); a raw _CfmTokenVerifier → discovery disabled (no canonical base).
    return []


def _with_no_slash_aliases(routes):
    """Emit each route plus a no-slash alias for any trailing-slash path, so a client that drops the
    slash is served directly rather than via a redirect."""
    from starlette.routing import Route
    out = list(routes)
    for r in routes:
        path = getattr(r, "path", "") or ""
        endpoint = getattr(r, "endpoint", None)
        methods = list(getattr(r, "methods", None) or ["GET"])
        if path.endswith("/") and endpoint is not None:
            out.append(Route(path.rstrip("/"), endpoint, methods=methods))
    return out


def resource_metadata_routes():
    """The host-root RFC 9728 protected-resource route(s) the PARENT ASGI app must serve at the box
    root (outside ``/corpusfm/``), so a compliant MCP client can discover how to authenticate. RFC 9728
    §3.1 fixes the metadata document at the HOST ROOT regardless of the resource path; the FMS-safe
    host-root proxy rule (the Linux nginx include line / the Windows 1177 exact-match routes) forwards
    ``/.well-known/oauth-protected-resource/corpusfm/mcp`` to this app. Emits BOTH the canonical
    trailing-slash form (matching the 401 ``resource_metadata`` URL) and a no-slash alias."""
    prot = [r for r in _host_root_well_known_routes()
            if str(getattr(r, "path", "")).startswith("/.well-known/oauth-protected-resource")]
    return _no_slash_resource_aliases(prot)


def _provider():
    """The OAuth provider itself — MultiAuth carries it as ``.server`` (and the base class declares an
    empty ``_resource_url``, so attribute presence proves nothing)."""
    auth = getattr(mcp, "auth", None)
    while getattr(auth, "server", None) is not None:
        auth = auth.server
    return auth


def point_challenge_at_canonical_resource(mcp_app) -> None:
    """Make the 401 challenge name the NO-SLASH protected-resource document (packet 1329).

    The canonical MCP URL is ``…/corpusfm/mcp`` — the form the MCP spec prefers ("SHOULD consistently use
    the form without the trailing slash"), the form this server's audience has always been stored in
    (``CfmOAuthProvider._canonical``), and the only form a strictly-matching client accepts: Cursor
    compares the POINTED document's ``resource`` to its own canonicalized URL and refuses at CONNECT
    otherwise (measured on devservice 2026-08-23, twice; a local rig with this change connected Cursor,
    Claude Code and VS Code). The framework derives the pointer from the mount path (``/``), which yields
    the trailing-slash form, so it is retargeted here — rather than re-basing the provider, whose
    ``base_url`` the audience of every live grant derives from.

    BOTH documents stay served, each stating its own resource (:func:`_no_slash_resource_aliases`): VS
    Code, when the pointed document does not match its configured URL, falls back to the document derived
    from its own path — measured connecting on both forms — so the trailing-slash alias is load-bearing.
    """
    provider = _provider()
    canonical = str(getattr(provider, "_canonical", "") or "")
    if not canonical:
        return
    try:
        from mcp.server.auth.routes import build_resource_metadata_url
        from pydantic import AnyHttpUrl
        target = str(build_resource_metadata_url(AnyHttpUrl(canonical)))
    except Exception:
        import logging
        logging.getLogger(__name__).debug("challenge retarget: metadata URL not derivable", exc_info=True)
        return
    retargeted = 0
    for route in getattr(mcp_app, "routes", ()):
        endpoint = getattr(route, "app", None) or getattr(route, "endpoint", None)
        if hasattr(endpoint, "resource_metadata_url"):
            endpoint.resource_metadata_url = target
            retargeted += 1
    if not retargeted:
        # Loud, not silent: a framework upgrade that renames the attribute would otherwise quietly
        # restore the trailing-slash pointer and strict clients would refuse at connect again.
        import logging
        logging.getLogger(__name__).warning(
            "MCP 401 challenge could not be pointed at %s (no resource_metadata_url on any route) — "
            "clients that match the resource strictly will refuse.", target)


def _no_slash_resource_aliases(routes):
    """The no-slash alias of each protected-resource route states the resource in ITS OWN form
    (packet 1325, Cursor gate 2026-08-23). RFC 9728 derives the metadata URL from the resource by path
    insertion, so a client that asks at ``…/oauth-protected-resource/corpusfm/mcp`` is asking about the
    resource ``…/corpusfm/mcp`` — and Cursor, which canonicalizes its server URL without a trailing slash
    and compares the document's ``resource`` strictly, refused the token exchange when the alias
    answered ``…/mcp/``: *"Protected resource …/mcp/ does not match expected …/mcp (or origin)"*. Claude
    Code strips the slash before comparing and VS Code accepts the slash form, so the trailing-slash
    document (the one the 401 points at) is unchanged. Same authorization server, same scopes; the
    audience check already ignores the slash. Falls back to a plain alias if the provider cannot say
    its own facts — serving the old document beats serving nothing."""
    from starlette.routing import Route
    out = list(routes)
    auth = _provider()
    for r in routes:
        path = getattr(r, "path", "") or ""
        endpoint = getattr(r, "endpoint", None)
        methods = list(getattr(r, "methods", None) or ["GET"])
        if not (path.endswith("/") and endpoint is not None):
            continue
        alias = None
        try:
            from mcp.server.auth.routes import create_protected_resource_routes
            resource = str(getattr(auth, "_resource_url", "") or "").rstrip("/")
            issuer = getattr(auth, "issuer_url", None)
            opts = getattr(auth, "client_registration_options", None)
            scopes = list(getattr(opts, "valid_scopes", None) or []) or None
            if resource and issuer is not None:
                built = create_protected_resource_routes(
                    resource_url=resource, authorization_servers=[issuer], scopes_supported=scopes)
                alias = next((b for b in built if getattr(b, "path", "") == path.rstrip("/")), None)
        except Exception:
            import logging
            logging.getLogger(__name__).debug("no-slash resource alias fell back to the slash document", exc_info=True)
        out.append(alias or Route(path.rstrip("/"), endpoint, methods=methods))
    return out


def authorization_server_metadata_routes():
    """The host-root RFC 8414 authorization-server metadata route(s) — served whenever the OAuth
    provider is configured (packet 1179). Stage-A proved the exact forms for issuer ``<base>/corpusfm/mcp``:
    ``/.well-known/oauth-authorization-server/corpusfm/mcp`` plus the OIDC aliases
    ``/.well-known/openid-configuration/corpusfm/mcp`` and ``/.well-known/openid-configuration``. [] when
    there is no provider at all (raw verifier / no auth), which after packet 1220 means only "no usable
    MCP address" or "no token". These are hoisted to the parent app root + added to the deployment-gate exemption as
    an EXACT set (never a broad ``/.well-known/`` allow)."""
    asr = [r for r in _host_root_well_known_routes()
           if str(getattr(r, "path", "")).startswith(("/.well-known/oauth-authorization-server",
                                                       "/.well-known/openid-configuration"))]
    return _with_no_slash_aliases(asr)


# ── Per-tool gate enforcement ────────────────────────────────────────────────────
# A per-user token carries that user's gates as scopes; there is no other kind (packet 1258). Every
# tool's required gate is declared in the _TOOL_GATES map below — the SINGLE enforcement point.
# The middleware enforces it at call time AND filters it out of tools/list, so ALL tools (read,
# authoring, patch, FMS, automation) are gated CENTRALLY via the map (packet 073-F: the former
# per-tool inline _require_gate() duplicates were removed — two mechanisms that could silently
# disagree became one source of truth). CAVEAT: a DIRECT tool.fn() call (in-process test/CLI code)
# bypasses the middleware, so it is UNGATED — that is a trusted, non-network path, not an attacker
# surface. The FMS second rail (_require_fms_admin_enabled) IS still called inline in each fms_*
# tool, so the server-wide switch holds even on a direct call. Unauthenticated mode (no env token →
# loopback/dev) has no token → no per-tool gating (the network is the boundary).

def _current_access_token():
    try:
        from fastmcp.server.dependencies import get_access_token
        return get_access_token()
    except Exception:
        return None


def _require_gate(gate: str) -> None:
    at = _current_access_token()
    if at is not None and gate not in (getattr(at, "scopes", None) or []):
        from fastmcp.exceptions import ToolError
        raise ToolError(f"Access denied: your CORPUSfm MCP token lacks the '{gate}' gate.")


def _mcp_actor() -> str:
    """Best-available actor for the security audit ledger from the MCP caller's token: the per-user
    token's username, else its client_id, else 'unknown' (unauthenticated loopback/dev)."""
    at = _current_access_token()
    if at is None:
        return "unknown"
    claims = getattr(at, "claims", None) or {}
    return claims.get("user") or getattr(at, "client_id", None) or "unknown"


# ── Tool → gate map (single source of truth) ─────────────────────────────────────
# Every registered tool declares the gate it needs here. Two consumers read it: the
# middleware below ENFORCES the gate at call time (no tool carries an inline gate check any
# more — packet 073-F) and FILTERS tools/list so an agent never sees a tool its token can't
# use. A conformance test asserts every registered tool appears here (a new ungated tool fails
# CI) and that the middleware enforces each entry.
_TOOL_GATES: dict = {
    # library_mcp — schema/context read + patch *authoring* (no production write)
    "list_artifacts": "library_mcp",
    "get_object_evidence": "library_mcp",
    "get_change_impact_evidence": "library_mcp",
    "get_artifact_attention_signals": "library_mcp",
    "get_workflows": "library_mcp",
    "get_security_reach": "library_mcp",
    "get_data_model": "library_mcp",
    "get_ai_usage": "library_mcp",
    "get_workflow_deltas": "library_mcp",
    "find_external_references": "library_mcp",
    "reconstruct_external_interface": "library_mcp",
    "emit_reconstruction_stub": "library_mcp",
    "suggest_external_field_names": "library_mcp",
    "get_patch_authoring_guide": "library_mcp",
    "get_ai_build_guide": "library_mcp",
    "get_step_exemplar": "library_mcp",
    "check_patch": "library_mcp",
    "verify_patch_applied": "library_mcp",
    "compare": "library_mcp",
    "render_section": "library_mcp",
    "get_raw_xml": "library_mcp",
    "get_object": "library_mcp",
    "get_script_steps": "library_mcp",
    "summarize_artifact": "library_mcp",
    "get_queue": "library_mcp",
    "list_registrations": "library_mcp",
    "export_to_git": "library_mcp",
    "semantic_search": "library_mcp",
    "get_index_status": "library_mcp",
    "get_server_info": "library_mcp",
    "temporal_diff": "library_mcp",
    "get_schema_context": "library_mcp",
    "get_patch_capabilities": "library_mcp",
    "get_artifact_types": "library_mcp",
    "get_schema_gaps": "library_mcp",
    "try_schema_yaml": "library_mcp",
    "generate_patch": "library_mcp",
    "index_artifact": "library_mcp",
    "deindex_artifact": "library_mcp",
    "save_ai_patch": "library_mcp",
    "save_clip": "library_mcp",
    "validate_clip": "library_mcp",
    "patch_clip": "library_mcp",
    "get_deliverable": "library_mcp",
    "export_object_clip": "library_mcp",
    "export_field_clip": "library_mcp",
    "create_script_acceptance_batch": "library_mcp",
    "evaluate_acceptance_return": "library_mcp",
    "compile_script_clip": "library_mcp",
    "get_fmclip_compiler_guide": "library_mcp",
    "detect_clip_variations": "library_mcp",
    "save_fmscript": "library_mcp",
    "save_fmcalc": "library_mcp",
    "import_artifact": "library_mcp",
    "download_container_data": "library_mcp",
    "set_artifact_memory": "library_mcp",
    "delete_source": "library_mcp",
    # update control plane (packet 1124) — the four stable self-update tools. server_capabilities is a
    # value-free read-only rendezvous (library_mcp); the check/apply/status trio drive the update and are
    # `settings`-gated, matching the Settings → Updates authority they share.
    "server_capabilities": "library_mcp",
    "update_check": "settings",
    "update_apply": "settings",
    "update_status": "settings",
    # patching — apply / materialize against production
    "dry_run_patch": "patching",
    "plan_apply": "patching",
    "apply_patch": "patching",
    "generate_db_file": "patching",
    "plan_promote_generated_db": "patching",
    "execute_promote_generated_db": "patching",
    "reimport_after_patch": "patching",
    # fms_api — broad FileMaker Server control (also behind the enable_fms_admin_mcp_tools switch)
    "fms_list_databases": "fms_api",
    "fms_list_clients": "fms_api",
    "fms_list_schedules": "fms_api",
    "plan_fms_control_database": "fms_api",
    "execute_fms_control_database": "fms_api",
    "plan_fms_disconnect_client": "fms_api",
    "execute_fms_disconnect_client": "fms_api",
    "plan_fms_message_clients": "fms_api",
    "execute_fms_message_clients": "fms_api",
    # automation — jobs / monitoring (server mode only)
    "list_jobs": "automation",
    "run_job": "automation",
    "get_job_run": "automation",
    "get_job_history": "automation",
    "get_health": "automation",
    "list_alerts": "automation",
    "acknowledge_alert": "automation",
}

# The broad FMS-admin surface, gated a SECOND time by the server-wide enable_fms_admin_mcp_tools
# switch (default off): hidden from tools/list and refused at call time unless an admin enables it.
_FMS_TOOLS = frozenset({
    "fms_list_databases", "fms_list_clients", "fms_list_schedules",
    "plan_fms_control_database", "execute_fms_control_database",
    "plan_fms_disconnect_client", "execute_fms_disconnect_client",
    "plan_fms_message_clients", "execute_fms_message_clients",
})


def _fms_admin_mcp_enabled() -> bool:
    """Is the broad FMS-admin MCP surface switched on? Fail-closed on any config error."""
    try:
        from corpusfm.app.app_config import load_app_config
        return bool(load_app_config().enable_fms_admin_mcp_tools)
    except Exception:
        return False


def _require_fms_admin_enabled() -> None:
    if not _fms_admin_mcp_enabled():
        from fastmcp.exceptions import ToolError
        raise ToolError("FMS admin tools are disabled on this server "
                        "(enable_fms_admin_mcp_tools is off — an admin can enable it in Settings).")


# The patch/apply MUTATOR surface, gated a SECOND time by the server-wide enable_patching_mcp_tools
# switch (default off): hidden from tools/list and refused at call time unless an admin enables it.
# Derived from _TOOL_GATES (not a hand-curated literal) so it is EXACTLY the `patching`-gated set and
# a future `patching` tool is covered automatically — no drift (packet 1059).
_PATCHING_TOOLS = frozenset(n for n, g in _TOOL_GATES.items() if g == "patching")


def _patching_mcp_enabled() -> bool:
    """Is the MCP patch/apply mutator surface switched on? Fail-closed on any config error."""
    try:
        from corpusfm.app.app_config import load_app_config
        return bool(load_app_config().enable_patching_mcp_tools)
    except Exception:
        return False


def _require_patching_enabled() -> None:
    if not _patching_mcp_enabled():
        from fastmcp.exceptions import ToolError
        raise ToolError("MCP patch/apply tools are disabled on this server "
                        "(enable_patching_mcp_tools is off — an admin can enable it in Settings).")


def _build_gate_middleware():
    from fastmcp.server.middleware import Middleware

    class _GateMiddleware(Middleware):
        """Reflects the user's gates into the tool surface: hides tools their token can't use
        (and the FMS surface when the server switch is off), and enforces the same at call time."""

        async def on_list_tools(self, context, call_next):
            tools = await call_next(context)
            at = _current_access_token()
            scopes = None if at is None else set(getattr(at, "scopes", None) or [])
            fms_on = _fms_admin_mcp_enabled()
            patching_on = _patching_mcp_enabled()
            visible = []
            for tool in tools:
                name = getattr(tool, "name", None)
                if name in _FMS_TOOLS and not fms_on:
                    continue
                if name in _PATCHING_TOOLS and not patching_on:
                    continue
                gate = _TOOL_GATES.get(name)
                if gate is not None and scopes is not None and gate not in scopes:
                    continue
                visible.append(tool)
            return visible

        async def on_call_tool(self, context, call_next):
            name = getattr(context.message, "name", None)
            if name in _FMS_TOOLS:
                _require_fms_admin_enabled()
            if name in _PATCHING_TOOLS:
                _require_patching_enabled()
            gate = _TOOL_GATES.get(name)
            if gate is not None:
                _require_gate(gate)
            return await call_next(context)

    return _GateMiddleware()


# The cap that actually rejects a tool result is the CLIENT's, and it is measured in TOKENS (Claude
# Code default 25_000, env MAX_MCP_OUTPUT_TOKENS). Our bounds must therefore be token-aware, NOT byte-
# aware: CORPUSfm's densest output — DDR / clip XML studded with hex hashes + UUIDs — tokenizes at
# ≈2.6 chars/token (measured), far worse than the ~4 a char budget assumes, so a 65k-char result blew
# the client cap while sitting under a 160k-byte backstop (packet 1152). We estimate tokens from bytes
# with a conservative worst-case ratio (no tokenizer dependency — `tokenizers` is only transitive) and
# derive every byte/char bound from a token budget set BELOW the client cap (margin for the footer, the
# client's own accounting, and FastMCP's structured_content duplicate).
_CHARS_PER_TOKEN_WORST = 2.5   # ≈2.6 measured on hash-dense XML; 2.5 = margin. Conservative on purpose:
                               # prose (~4 c/tok) is over-counted, so it truncates early (safe), never late.
_RESULT_TOKEN_BUDGET = max(1, int(os.environ.get("CORPUSFM_MCP_MAX_RESULT_TOKENS", "") or 20_000))


def _estimate_tokens(text: str) -> int:
    """Conservative token estimate: ceil(utf-8 bytes / worst-case chars-per-token). Over-counts prose;
    tuned so hash-dense XML never under-counts (the failure that blew the client cap)."""
    return math.ceil(len(text.encode("utf-8")) / _CHARS_PER_TOKEN_WORST)


# Per-tool char default (render_section / get_object / get_script_steps / get_step_exemplar). Kept below
# the global backstop's byte size so the per-tool marker (which points to a narrower tool) fires FIRST.
_DEFAULT_MAX_CHARS = 40_000

# Global response-size backstop — the catch-all so a future un-capped tool (or one whose per-tool bound
# is mis-set) still can't blow the client's TOKEN cap. Derived from the token budget: bytes ≤ budget ×
# worst-case chars/token ⟺ estimated tokens ≤ budget, so byte-truncating at this ceiling is token-safe
# even for the densest XML. (≈50 KB at a 20k-token budget — well under the 160 KB it replaced.)
_RESPONSE_BYTE_CEILING = int(_RESULT_TOKEN_BUDGET * _CHARS_PER_TOKEN_WORST)

# Per-section name cap the MCP `compare` tool passes into the shared format_report (which
# stays default-uncapped for the HTML Diff / git-export / compare CLI). Mirrors temporal_diff.
_COMPARE_SECTION_CAP = 25


def _truncate_text_to_bytes(text: str, ceiling: int) -> tuple[str, bool]:
    """Truncate `text` so its UTF-8 size (plus footer) stays under `ceiling`. Returns
    (text, truncated?). Sizes the already-known string — no double serialization."""
    raw = text.encode("utf-8")
    if len(raw) <= ceiling:
        return text, False
    footer = (
        f"\n\n[response truncated to stay under the ~{_RESULT_TOKEN_BUDGET}-token MCP result budget — "
        f"narrow your query, e.g. with a focus/limit arg or a more specific tool]"
    )
    budget = max(0, ceiling - len(footer.encode("utf-8")))
    kept = raw[:budget].decode("utf-8", "ignore")
    return kept + footer, True


def _guard_faithful_size(text: str, *, what: str, alt: str) -> str:
    """Byte-faithful / structured results must NOT be byte-truncated — a mid-blob cut corrupts a clip,
    patch, or trailing JSON into something that looks complete. So when such a result would exceed the
    token budget, REFUSE with a size + a pointer to another way to fetch it, rather than let the backstop
    corrupt it. Within budget → returned unchanged. (packet 1152)"""
    if _estimate_tokens(text) <= _RESULT_TOKEN_BUDGET:
        return text
    nbytes = len(text.encode("utf-8"))
    return (f"[{what} is {nbytes} bytes (~{_estimate_tokens(text)} tokens) — over the ~"
            f"{_RESULT_TOKEN_BUDGET}-token MCP result budget, and truncating it would corrupt it. {alt}]")


def _echo_xml_lines(label: str, xml: str, echo_full: bool, preview: int = 1_500) -> list:
    """Trailer for the save_* echoes: the caller already holds the full XML it passed in, so
    by default return a size + a bounded preview (not the whole blob); echo_full=True returns
    the full XML for copying."""
    size = len(xml.encode("utf-8"))
    if echo_full:
        return [f"--- {label} ({size} bytes) ---", xml]
    head = xml[:preview]
    suffix = (f"\n… [preview — {size} bytes total; re-call with echo_xml=True for the full XML]"
              if len(xml) > preview else "")
    return [f"--- {label} (preview; {size} bytes total) ---", head + suffix]


def _build_response_size_middleware():
    from fastmcp.server.middleware import Middleware

    class _ResponseSizeMiddleware(Middleware):
        """Backstop only: truncate any tool result whose serialized text exceeds
        `_RESPONSE_BYTE_CEILING`, appending a standard footer. A within-budget result is
        returned byte-identical (untouched)."""

        async def on_call_tool(self, context, call_next):
            result = await call_next(context)
            blocks = getattr(result, "content", None) or []
            if len(blocks) != 1:
                return result
            block = blocks[0]
            text = getattr(block, "text", None)
            if not isinstance(text, str):
                return result
            new_text, truncated = _truncate_text_to_bytes(text, _RESPONSE_BYTE_CEILING)
            if not truncated:
                return result
            block.text = new_text
            sc = getattr(result, "structured_content", None)
            if isinstance(sc, dict) and isinstance(sc.get("result"), str):
                sc["result"] = new_text
            return result

    return _ResponseSizeMiddleware()


mcp.add_middleware(_build_gate_middleware())
mcp.add_middleware(_build_response_size_middleware())


# ── Path helpers ───────────────────────────────────────────────────────────────


def _bust_catalog_snapshot() -> None:
    """Bust the catalog tag/lineage snapshot after an MCP-side artifact store (audit #2) —
    the new row shows on the next catalog read, not after the TTL. Best-effort."""
    try:
        from corpusfm.server.tags_store import invalidate_record_views
        invalidate_record_views()
    except Exception:
        pass


def _artifact_uuid(ref: str, archive_dir: Optional[Path] = None) -> str:
    """Resolve an MCP artifact ref to its canonical record UUID (packet 085 U3f). ``ref`` is a
    record UUID or a human alias (PrimaryName / FileName / tag). Ambiguity raises with the
    candidate UUIDs (never a guess); an empty ref passes through. The rest of the MCP surface then
    addresses the backend by UUID."""
    if not ref:
        return ref
    from corpusfm.storage import resolve as _resolve
    r = _resolve.resolve(get_backend(archive_dir), ref)
    if r.ambiguous:
        raise ValueError(
            f"{ref!r} matches multiple artifacts — address by record UUID. Candidates: "
            + ", ".join(f"{c['uuid']} ({c.get('primary_name') or c.get('file_name')})"
                        for c in r.candidates))
    return r.uuid or ref


def _load_artifact(path_str: str, archive_dir: Optional[Path] = None) -> Artifact:
    """Load an Artifact by record UUID / human alias, or an absolute filesystem path.

    An absolute path loads artifact.json.gz directly (dev harness). Otherwise the ref is resolved
    to a record UUID (packet 085 U3f) and loaded via the active StorageBackend, which works for
    BOTH the local archive and the FileMaker OData backend (artifacts live in container fields).
    """
    p = Path(path_str)
    if p.is_absolute():
        snap_dir = p.parent if p.is_file() else p
        art_gz = snap_dir / "artifact.json.gz"
        if not art_gz.exists():
            raise FileNotFoundError(
                f"No artifact found at {snap_dir} (expected artifact.json.gz). "
                "Re-ingest this snapshot to generate an artifact."
            )
        return Artifact.load_gz(art_gz)
    backend = get_backend(archive_dir)
    uuid = _artifact_uuid(path_str, archive_dir)
    try:
        return backend.load_artifact(uuid)
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise FileNotFoundError(
            f"No artifact found at {path_str!r}: {exc}. "
            "Re-import this snapshot to generate an artifact."
        )


# ── Archive tools ──────────────────────────────────────────────────────────────

def _latest_per_file(backend) -> list:
    """The newest ArtifactMeta per FM file (file-less deliverables excluded) — for corpus /
    cross-file SCANNING that wants one representative snapshot per file. (Packet 1026 retired the
    old `_group_by_file` display helper; the user-facing `list_artifacts` is now record-centric.)"""
    latest: dict = {}
    for m in backend.iter_artifact_metas():
        if not m.file_name:
            continue
        cur = latest.get(m.file_name)
        if cur is None or m.timestamp > cur.timestamp:
            latest[m.file_name] = m
    return list(latest.values())


@mcp.tool()
def list_artifacts(archive_dir: str = None, type: str = None, tag: str = None,
                   file: str = None, name: str = None, origin: str = None,
                   job_uuid: str = None, latest_only: bool = False, sort: str = "recent",
                   limit: int = 50, offset: int = 0) -> str:
    """Query the artifact catalog — a FLAT, record-centric list (one row per stored artifact).

    Every artifact is a record with a Type; the deliverable types (fmClip / fmCalc / fmScript /
    PatchXML) belong to NO FM file, so this lists RECORDS, not files. Each row carries the fields you
    address other tools with (name · type · timestamp · file · origin · tags · uuid). Default sort is
    most-recent-first, so `list_artifacts(limit=1)` is "the last thing added".

    Filters (optional, AND-combined):
      type:        one artifact type or a comma list — SaveAsXML, AddonXML, MergedXML, fmClip,
                   PatchXML, fmScript, fmCalc. e.g. type="fmClip,PatchXML".
      tag:         case-insensitive; only records carrying this user tag.
      file:        exact FM file name (with/without .fmp12) — e.g. all snapshots of one file.
      name:        case-insensitive substring on the artifact name.
      origin:      WebUI · Job · MCP · Merge · Patch (ISV) · Reabsorb · Seed (· Import = legacy).
      job_uuid:    artifacts PRODUCED BY one job (from list_jobs). Lineage is the job uuid alone —
                   a shared file name never joins two jobs' outputs, so this is not the same as
                   `file`.
      latest_only: keep only the latest snapshot per lineage (drops superseded versions).
    sort:  "recent" (default, newest first) · "name" (A→Z) · "type" (by type, then recent).
    limit/offset: pagination (default limit 50, capped at 100 to keep the result token-safe). The output
                  discloses the total matched + how many are withheld; advance offset / narrow with a
                  filter to see more.
    """
    from corpusfm.core.filenames import ensure_fmp12
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    metas = list(backend.iter_artifact_metas())
    if not metas:
        return "Archive is empty."
    try:
        from corpusfm.server.tags import load_tags
        tags_map = load_tags()
    except Exception:
        tags_map = {}

    types = {t.strip() for t in (type or "").split(",") if t.strip()}
    if types:
        metas = [m for m in metas if m.artifact_type in types]
    want_tag = (tag or "").strip().lower()
    if want_tag:
        metas = [m for m in metas if want_tag in {t.lower() for t in tags_map.get(m.uuid, [])}]
    if file and file.strip():
        want_file = ensure_fmp12(file.strip()).lower()
        metas = [m for m in metas if ensure_fmp12(m.file_name).lower() == want_file]
    if name and name.strip():
        want_name = name.strip().lower()
        metas = [m for m in metas if want_name in (m.name or "").lower()]
    if origin and origin.strip():
        want_origin = origin.strip().lower()
        metas = [m for m in metas if (m.origin or "").lower() == want_origin]
    if job_uuid and job_uuid.strip():
        want_job = job_uuid.strip()
        metas = [m for m in metas if (getattr(m, "job_uuid", "") or "") == want_job]
    if latest_only:
        # Authoritative IsLatest lives on the STORAGE record (not ArtifactMeta) — read it from the
        # lineage view. Best-effort: an untracked/older DB (uuid absent) defaults to keep, so the
        # filter degrades to a no-op rather than hiding everything.
        try:
            from corpusfm.server import tags_store
            _uv, recs = tags_store.record_views_cached(backend)
            latest = {r.get("uuid"): bool(r.get("is_latest", False)) for r in recs if r.get("uuid")}
            metas = [m for m in metas if latest.get(m.uuid, True)]
        except Exception:
            pass

    if not metas:
        return "No artifacts match the given filters."

    if sort == "name":
        metas.sort(key=lambda m: (m.name or "").lower())
    elif sort == "type":
        metas.sort(key=lambda m: (m.artifact_type, _neg_ts(m.timestamp)))
    else:  # recent (default)
        metas.sort(key=lambda m: m.timestamp, reverse=True)

    total = len(metas)
    try:
        # Upper-clamp the page (packet 1152): the result carries a text bullet AND a JSON item (two hex
        # UUIDs) per row, so an unbounded limit can push the trailing STRUCTURED JSON past the token
        # budget where the backstop would byte-truncate it into unparseable JSON. 100 keeps the whole
        # result token-safe; the "…more" pointer + offset paginate the rest.
        limit = max(1, min(100, int(limit)))
        offset = max(0, int(offset))
    except Exception:
        limit, offset = 50, 0
    page = metas[offset:offset + limit]

    lines = [f"{total} artifact(s) matched" + (f" (showing {offset + 1}–{offset + len(page)})"
                                               if total > len(page) else "") + ":", ""]
    for m in page:
        # A deliverable's file_name is a name-slug, not a real FM file — show — so it doesn't read
        # as belonging to a file (only schema types SaveAsXML/AddonXML/MergedXML have a real file).
        file_part = m.file_name if (m.file_name and m.is_schema) else "—"
        fm_ver = f"  [{m.fm_version}]" if m.fm_version else ""
        row_tags = sorted(tags_map.get(m.uuid, []))
        tag_part = f"   tags: {', '.join(row_tags)}" if row_tags else ""
        lines.append(f"{m.name}  ·  {m.artifact_type}  ·  {m.timestamp}  ·  {file_part}"
                     f"  ·  {m.origin}{fm_ver}{tag_part}")
        lines.append(f"    uuid: {m.uuid}")
    if offset + len(page) < total:
        lines += ["", f"… {total - offset - len(page)} more — raise limit or advance offset "
                      f"(offset={offset + len(page)}), or narrow with a filter."]

    # Canonical structured data alongside the human text — agents read fields, never scrape bullets.
    import json as _json
    items = [{
        "uuid": m.uuid, "ref": m.uuid, "primary_name": m.name,
        "type": m.artifact_type, "origin": m.origin, "timestamp": m.timestamp,
        "file": (m.file_name if (m.file_name and m.is_schema) else None),
        "fm_version": (m.fm_version or None),
        "tags": sorted(tags_map.get(m.uuid, [])),
    } for m in page]
    payload = {"total": total, "offset": offset, "limit": limit,
               "returned": len(page), "withheld": max(0, total - offset - len(page)),
               "items": items}
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---",
              _json.dumps(payload, ensure_ascii=False)]
    return "\n".join(lines).rstrip()


def _neg_ts(ts: str) -> str:
    """Sort key that inverts a compact timestamp string for descending order within an ascending
    primary sort (each char complemented against '~' so newer sorts first)."""
    return "".join(chr(0x7E - ord(c)) if 0x20 <= ord(c) <= 0x7E else c for c in (ts or ""))


@mcp.tool()
def get_object_evidence(artifact_path: str, object_id_or_name: str = None,
                        section: str = None, limit: int = 20, archive_dir: str = None) -> str:
    """Neutral, query-time EVIDENCE about FM schema objects — counts and examples, never a verdict.

    Two modes:
      • object_id_or_name given → evidence for that one object (matched by item_id, then exact name,
        then case-insensitive name; `section` scopes/disambiguates same-named objects across catalogs).
      • object_id_or_name omitted → the artifact's top attention CANDIDATES by a triage score
        (inbound + outbound reference activity + a dead-end flag + neutral name tokens).

    Reports only what the artifact already carries: cross-reference counts (by edge type), the
    reachability/dead-end flag, inbound/outbound example edges, and name-attention tokens
    (temp/old/copy/test/z_…). It does NOT decide importance, intent, or whether anything is unused,
    obsolete, or safe to remove — a misleading FM name doesn't reveal intent, so the conclusion is
    the human's. Nothing is written back to the artifact. `attention_score` is for triage only, not
    business importance. `limit` clamps to 1–50.
    """
    from corpusfm.core import evidence as ev
    limit = max(1, min(50, int(limit)))
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    if object_id_or_name and object_id_or_name.strip():
        item = ev.find_artifact_item(art, object_id_or_name, section=section)
        if item is None:
            scope = f" in section {section!r}" if section else ""
            return (f"No object matched {object_id_or_name!r}{scope} in {artifact_path}. "
                    f"Call without object_id_or_name to list attention candidates.")
        return ev.format_object_markdown(artifact_path, ev.object_evidence(art, item, limit=limit))
    cands = ev.artifact_attention_candidates(art, limit=limit, section=section)
    return ev.format_candidates_markdown(artifact_path, cands)


@mcp.tool()
def get_change_impact_evidence(artifact_path: str, object_id_or_name: str,
                               section: str = None, limit: int = 20,
                               archive_dir: str = None) -> str:
    """Neutral CHANGE-IMPACT evidence for one FM object: "if I change/rename/remove this, what
    appears to depend on it?" — the SAME observed cross-reference edges, seen through a blast-radius
    lens. Never a verdict.

    Reports, for the object (a field / script / table / layout / value list / custom function /
    table occurrence, matched by item_id → exact name → case-insensitive; `section` disambiguates):
      • DEPENDENTS (inbound) — objects that reference it, so they're affected if it changes — with
        counts by edge type, by source section, and by CHANNEL (direct / trigger / button / sql /
        dynamic), plus example edges;
      • DEPENDENCIES (outbound) — what the object itself relies on (affected if THOSE change);
      • a per-edge PROVENANCE label — observed (the schema records the reference) vs inferred
        (heuristic: ExecuteSQL parsing or dynamic 'Perform Script by Name' dispatch).

    It does NOT decide whether a change is safe, breaking, or complete: dynamic dispatch, plug-ins,
    external/Data-API callers, and runtime-computed calculations can reference an object without a
    recorded edge, so a zero count is "no observed dependents", never "unused / safe to delete".
    Confirm impact with the human. Query-time only; nothing is written back. `limit` clamps to 1–50.
    """
    from corpusfm.core import evidence as ev
    limit = max(1, min(50, int(limit)))
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    if not (object_id_or_name and object_id_or_name.strip()):
        return "object_id_or_name is required — name the field/script/table/layout/etc. to assess."
    item = ev.find_artifact_item(art, object_id_or_name, section=section)
    if item is None:
        scope = f" in section {section!r}" if section else ""
        return (f"No object matched {object_id_or_name!r}{scope} in {artifact_path}. "
                f"Use get_object_evidence (no object) to list objects, or pass `section`.")
    return ev.format_change_impact_markdown(
        artifact_path, ev.change_impact_evidence(art, item, limit=limit))


@mcp.tool()
def get_artifact_attention_signals(artifact_path: str, section: str = None,
                                   limit: int = 10, archive_dir: str = None) -> str:
    """Neutral ARTIFACT-LEVEL triage: which parts of a file deserve a human/AI look first? A SCAN,
    never a verdict — the artifact-wide companion to get_object_evidence / get_change_impact_evidence.

    Groups objects under a small set of neutral signal kinds, each derived purely from the evidence
    the artifact already carries and each pointing back to concrete objects + their numbers:
      • high_reference_count — the most-connected objects (inbound + outbound xref degree);
      • no_observed_dependents — zero inbound xrefs (orphan CANDIDATES — dynamic dispatch / plug-ins /
        external/Data-API callers leave no edge, so it is a prompt to check, not a conclusion);
      • name_attention_token — names carrying a neutral token (temp/old/test/backup/copy/z_/zz);
      • duplicate_looking_name — 2+ objects in a section whose names match after trimming a copy/
        number suffix;
      • sigil_named_with_dependencies — a z_/zz 'park at the bottom' name that still has outbound deps.

    Within each kind, entries are ranked by the NUMBER that defines the kind (degree, token count,
    group size) — NOT by any inferred meaning. It does not call an object important, unused, obsolete,
    or safe to remove; the conclusion is the human's. `section` restricts the scan; `limit` (1–50)
    caps EACH kind's list. Query-time only; nothing is written back.
    """
    from corpusfm.core import evidence as ev
    limit = max(1, min(50, int(limit)))
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    result = ev.artifact_attention_signals(art, limit=limit, section=section)
    return ev.format_attention_signals_markdown(artifact_path, result)


# ── Perspective tools (compressed AI-oriented lenses over one artifact) ────────
# These wrap the deterministic builders that the removed human-UI overlays used (inbox
# packet 002): MCP is now the home for the compressed perspectives. All are read-only,
# query-time, neutral (no verdicts), and write nothing back to the artifact.

@mcp.tool()
def get_workflows(artifact_path: str, entry: str = None, limit: int = 20,
                  archive_dir: str = None) -> str:
    """The WORKFLOWS lens: what a user can DO and the data each action touches. Traces each
    user-invocable entry script (button / layout trigger / external call) through its call
    tree and reports, per workflow, the fields it writes/reads, the scripts it calls, the
    SQL tables it hits (outside the relationship graph), the conditions it branches on, the
    navigation triggers it fires, and where it lands — plus a flag for runtime-computed
    targets that leave no recorded edge. Each workflow carries its entry script's stable
    `item_id` so you can drill into get_object_evidence / get_change_impact_evidence.

    Two modes:
      • `entry` omitted → the richest-first slice of all workflows, compact; the output states
        "showing X of Y" so truncation is explicit. `limit` (1–200, default 20) caps how many —
        large solutions have hundreds of entry points, so raise it deliberately.
      • `entry` given → ONE workflow by entry-script name (exact match first, then an unambiguous
        case-insensitive match), rendered in full (richer member lists, still bounded with inline
        `… (+N)`). No match → a not-found note with up to 5 close names; multiple case-insensitive
        matches → an ambiguity list to re-call with the exact name.

    All observed from the xref graph; facts, never a verdict. Query-time only; nothing is written
    back; no raw XML or rendered script bodies are returned.
    """
    from corpusfm.core.workflows import extract_workflows
    from corpusfm.mcp import perspectives
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)

    if entry and entry.strip():
        q = entry.strip()
        report = extract_workflows(art)                       # all, to find the named one
        wfs = report.workflows
        exact = [w for w in wfs if w.entry_name == q]
        if exact:
            return perspectives.format_one_workflow_md(artifact_path, exact[0])
        ci = [w for w in wfs if w.entry_name.lower() == q.lower()]
        if len(ci) == 1:
            return perspectives.format_one_workflow_md(artifact_path, ci[0])
        if len(ci) > 1:
            return perspectives.format_workflow_ambiguous_md(artifact_path, q, ci)
        cand = [w.entry_name for w in wfs if q.lower() in w.entry_name.lower()][:5]
        return perspectives.format_workflow_not_found_md(artifact_path, q, cand)

    limit = max(1, min(200, int(limit)))
    report = extract_workflows(art, max_workflows=limit)
    return perspectives.format_workflows_md(artifact_path, report, limit=limit)


@mcp.tool()
def get_security_reach(artifact_path: str, archive_dir: str = None) -> str:
    """The SECURITY lens: what each privilege set can reach. Regroups the PrivilegeAccess /
    AccountPrivilege edges into, per privilege set, the layouts / scripts / value lists /
    tables it can access (write-tables flagged) and the accounts assigned to it.

    Observed from the schema; not a verdict on whether the access is correct or safe. Addon
    exports omit security catalogs by design, so this can legitimately be empty. Query-time
    only; nothing is written back.
    """
    from corpusfm.extensions.export.explorer import _build_security_from_artifact
    from corpusfm.mcp import perspectives
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    return perspectives.format_security_md(artifact_path, _build_security_from_artifact(art))


@mcp.tool()
def get_data_model(artifact_path: str, archive_dir: str = None) -> str:
    """The STRUCTURE lens: the real table-to-table data model under the TableOccurrence graph
    (TOs collapsed to their base tables), with cardinalities, plus a mermaid `erDiagram` of
    the same model. Deterministic facts by rule, not inferred purpose.

    Query-time only; nothing is written back.
    """
    from corpusfm.core.structure_intent import structure_intent_dict
    from corpusfm.mcp import perspectives
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    return perspectives.format_data_model_md(artifact_path, structure_intent_dict(art))


@mcp.tool()
def get_ai_usage(artifact_path: str, archive_dir: str = None) -> str:
    """The AI-USAGE lens: which FileMaker native-AI capabilities the solution uses, by script
    (configuration / ML / embeddings / semantic find / RAG / generation / NL-query / image),
    plus AI-related calc functions and any configured providers/accounts/models found as
    literals. Steps are the source of truth — AI accounts/models are runtime config, not
    schema. Facts, not a verdict. Query-time only; nothing is written back.
    """
    from corpusfm.core.ai_usage import analyze_ai_usage, CAPABILITY_LABELS
    from corpusfm.mcp import perspectives
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    return perspectives.format_ai_usage_md(artifact_path, analyze_ai_usage(art).to_dict(),
                                           CAPABILITY_LABELS)


@mcp.tool()
def get_workflow_deltas(artifact_path_a: str, artifact_path_b: str, limit: int = 100,
                        archive_dir: str = None) -> str:
    """The WORKFLOW-DELTA lens: how each workflow's observed blast radius changed between two
    artifacts (matched by entry script) — new / removed / changed entry points, and per
    workflow the added/removed writes, reads, calls, conditions, triggers, SQL tables, and
    landing layouts. Facts from the xref graph, not a verdict. The output states the total
    changed count and "showing X"; `limit` (1–500, default 100) caps how many are listed.
    Query-time only; nothing is written back. (For schema-level added/removed/changed items
    over a job's history, use temporal_diff instead.)
    """
    from corpusfm.extensions.export.diff import _workflow_deltas
    from corpusfm.mcp import perspectives
    limit = max(1, min(500, int(limit)))
    adir = Path(archive_dir) if archive_dir else None
    art_a = _load_artifact(artifact_path_a, adir)
    art_b = _load_artifact(artifact_path_b, adir)
    return perspectives.format_workflow_deltas_md(
        artifact_path_a, artifact_path_b, _workflow_deltas(art_a, art_b), limit=limit)


# ── Cross-file tools ─────────────────────────────────────────────────────────

@mcp.tool()
def find_external_references(artifact_path: str, archive_dir: str = None) -> str:
    """List every reference a FM file makes INTO its sibling files.

    Reads one artifact and reports its external data sources (which sibling files it opens)
    plus, grouped by target file: the external tables it borrows, the fields it uses from
    them, and the cross-file scripts it calls. This is the per-file half of cross-file
    reconstruction — run it on each sibling, or use reconstruct_external_interface to
    aggregate automatically. Deterministic; no fabrication.
    """
    from corpusfm.core.crossfile import extract_external_references, render_reference_set
    art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    return render_reference_set(extract_external_references(art))


@mcp.tool()
def reconstruct_external_interface(target_file: str, sibling_paths: list = None,
                                   archive_dir: str = None) -> str:
    """Reconstruct a MISSING file's external INTERFACE from its siblings' references to it.

    Given the name of a file that is gone/unavailable (target_file, the FM file name — NOT a
    path), aggregate every external reference to it across its sibling files into a skeleton:
    the tables it must expose, the fields each table must carry (with a confidence-scored
    inferred type and whether it's a relationship key), and the scripts it must publish.

    sibling_paths: explicit artifact paths ("File/timestamp") to aggregate. If omitted, the
    siblings are AUTO-DISCOVERED — the newest artifact of every other file that actually
    references target_file (the intrinsic connector: files declare cross-refs via external
    data sources, so no tag/label is needed).

    Coverage is the UNION of what siblings ask of the target; it grows with more siblings and
    is the recoverable EXTERNAL surface only. Everything no sibling references is reported as
    a blind spot, never fabricated.
    """
    from corpusfm.core.crossfile import reconstruct_interface, render_interface
    artifacts = _gather_siblings(target_file, sibling_paths, archive_dir)
    if isinstance(artifacts, str):
        return artifacts
    return render_interface(reconstruct_interface(target_file, artifacts))


def _gather_siblings(target_file: str, sibling_paths, archive_dir):
    """Resolve the sibling artifacts for a reconstruction, or return an error string.

    Explicit sibling_paths are loaded as given; otherwise auto-discover the newest artifact
    of every other stored file that references target_file via its external data sources.
    """
    from corpusfm.core.crossfile import extract_external_references
    from corpusfm.core.filenames import ensure_fmp12
    adir = Path(archive_dir) if archive_dir else None
    if sibling_paths:
        return [_load_artifact(p, adir) for p in sibling_paths]
    backend = get_backend(adir)
    artifacts = []
    # Match on the canonical (suffixed) file form so a bare target name unifies with the
    # suffixed target_files() the extractor reports (the project file-name standard).
    tgt = ensure_fmp12(target_file.strip().lower())
    for m in _latest_per_file(backend):   # cross-file name match (parked, Tier D) — one snapshot per file
        if ensure_fmp12(m.file_name.strip().lower()) == tgt:
            continue
        try:
            art = backend.load_artifact(m.uuid)   # UUID-addressed (packet 085 U3f)
        except Exception:
            continue
        if tgt in {ensure_fmp12(t.lower()) for t in extract_external_references(art).target_files()}:
            artifacts.append(art)
    if not artifacts:
        return (f"No stored file references {target_file!r} via an external data source. "
                "Ingest its sibling files first, or pass sibling_paths explicitly.")
    return artifacts


@mcp.tool()
def emit_reconstruction_stub(target_file: str, fmt: str = "plan",
                             sibling_paths: list = None, archive_dir: str = None,
                             max_bytes: int = None) -> str:
    """Emit a BUILDABLE schema stub for a missing file (reconstruct, then render to build).

    Runs the same reconstruction as reconstruct_external_interface, then projects it onto a
    creatable schema: each recovered base table with its NAMED fields (the recovered keys +
    any calc-named fields, typed where inferred). Id-only fields (referenced by internal id
    with no recoverable name) are reported as a count to add by hand — never fabricated.

    fmt:
      "plan" (default) — human-readable creation plan with origins/confidence/keys, the
                          id-only field counts, and the blind spots.
      "ddl"            — a JSON array of FileMaker_Tables create bodies, ready to POST to
                          /fmi/odata/v4/<NewFile>/FileMaker_Tables on a blank hosted file.
      "both"           — the plan followed by the DDL.
      "saveasxml"      — a COMPLETE FMSaveAsXML carrying the recovered tables + NAMED fields,
                          ready to feed straight into generate_db_file(source_xml=...) to
                          MATERIALIZE a hostable .fmp12 (FMUpgradeTool 2026 --generateDBFile,
                          no FileMaker Pro). The origination path for a missing file.

    This is a scaffold, not an auto-relink: cross-file refs were stored by internal id with
    blank names, so recreate the schema from this stub and repair the siblings' relationships
    using the recovered KEY names.

    max_bytes: optional cap on the emitted text (default None = uncapped; the saveasxml/both
    forms feed generate_db_file, so they are uncapped by default — the global response-size
    backstop is the ultimate ceiling). Set it to bound an oversized stub with a marker.
    """
    from corpusfm.core.crossfile import (
        reconstruct_interface, build_schema_stub, render_stub_plan, render_stub_ddl,
        render_stub_saveasxml,
    )
    artifacts = _gather_siblings(target_file, sibling_paths, archive_dir)
    if isinstance(artifacts, str):
        return artifacts
    stub = build_schema_stub(reconstruct_interface(target_file, artifacts))
    fmt = (fmt or "plan").strip().lower()
    if fmt == "ddl":
        out = render_stub_ddl(stub)
    elif fmt == "saveasxml":
        out = render_stub_saveasxml(stub)
    elif fmt == "both":
        out = (render_stub_plan(stub)
               + "\n\n--- OData DDL (FileMaker_Tables create bodies) ---\n"
               + render_stub_ddl(stub))
    else:
        out = render_stub_plan(stub)
    if max_bytes is not None:
        raw = out.encode("utf-8")
        if len(raw) > max_bytes:
            out = raw[:max_bytes].decode("utf-8", "ignore") + (
                f"\n… [truncated at {max_bytes} bytes of {len(raw)} — raise max_bytes "
                f"or fetch a narrower fmt]")
    return out


@mcp.tool()
def suggest_external_field_names(target_file: str, sibling_paths: list = None,
                                 archive_dir: str = None) -> str:
    """Surface NAMING EVIDENCE for a missing file's id-only fields — for YOU to name them.

    Cross-file field references are stored by internal id with a BLANK name, so reconstruction
    cannot READ the names of most fields. This tool mines the surrounding context in the
    siblings for naming SIGNALS — text labels placed beside the field on a sibling's layout,
    the local key a relationship joins it to, and any name a calculation spelled out — and
    lists, per id-only field, the candidate names with a confidence and the evidence behind
    each.

    These are deterministic CANDIDATES, not assertions. Use them to PROPOSE a final name per
    field (you are the model in the loop — subscription-via-MCP), weighing the evidence and the
    table's recovered fields + domain. Never invent a name with no signal: a field with no
    candidate is reported as such and left for the developer. Keep your suggestions clearly
    marked as suggestions for the developer to accept or reject.
    """
    from corpusfm.core.crossfile import reconstruct_interface
    artifacts = _gather_siblings(target_file, sibling_paths, archive_dir)
    if isinstance(artifacts, str):
        return artifacts
    iface = reconstruct_interface(target_file, artifacts)
    lines = [
        f"NAMING EVIDENCE for id-only fields of: {target_file}",
        f"(from {len(iface.contributing_files)} sibling(s): {', '.join(sorted(iface.contributing_files)) or '(none)'})",
        "",
        "Each field below is referenced cross-file by internal id only. Candidates are mined",
        "from context (layout captions, join partners, calc text). Propose a final name from",
        "the evidence; leave fields with no signal for the developer. Do not fabricate.",
        "",
    ]
    any_field = False
    for t in iface.tables:
        idonly = [f for f in t.fields
                  if (not f.name) or f.name.startswith("field #") or f.name == "(unnamed field)"]
        if not idonly:
            continue
        any_field = True
        lines.append(f"TABLE {t.name}{' [name inferred from TO]' if t.name_is_inferred else ''}:")
        for f in idonly:
            key = " ★KEY" if f.used_as_key else ""
            lines.append(f"  field id {f.field_id}{key}  (type guess: {f.inferred_type}, conf {f.confidence:.2f})")
            if f.candidate_names:
                for c in f.candidate_names:
                    lines.append(f"      candidate: {c.name}  (conf {c.confidence:.2f}, {c.source}: {c.evidence})")
            else:
                lines.append("      (no naming signal — name by hand)")
        lines.append("")
    if not any_field:
        lines.append("All referenced fields already carry a recovered or inferred name — nothing to deduce.")
    return "\n".join(lines).rstrip()


# ── Patch verification tools (static pre-flight — no FM, no FMUpgradeTool) ──────

@mcp.tool()
def check_patch(patch_xml: str, artifact_path: str, mode: str = "simulate",
                archive_dir: str = None) -> str:
    """Statically verify an FMUpgradeToolPatch against the artifact it targets.

    Run this on a patch YOU composed (or generated) BEFORE saving or applying it — it catches
    the gap a structurally-valid patch can still have: it doesn't hang together against the
    real schema. Pure schema-graph analysis; no FileMaker, no FMUpgradeTool, nothing touched.

    mode:
      "simulate" (default) — the full dry-run: intra-patch coherence (dangling refs, a field
                  referenced through a TO it isn't on, ordering) PLUS delete-impact (surviving,
                  unchanged schema that still references something the patch deletes, found via
                  the xref graph), hostability (a field type-change FM couldn't host), and the
                  resulting per-section counts + signed deltas.
      "coherence" — the cheaper intra-patch pass only (fast; no delete-impact / hostability).

    Returns a verdict (consistent / would-host) and every finding with its severity and the
    capability-ledger rule it enforces. Fix the errors, then save_ai_patch / apply.
    """
    from corpusfm.extensions.export.patch_coherence import check_patch_coherence
    from corpusfm.extensions.export.patch_simulate import simulate_apply
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    def _findings(items) -> list:
        out = []
        for f in items:
            d = f.to_dict() if hasattr(f, "to_dict") else f
            ref = d.get("reference") or d.get("via") or ""
            who = d.get("referrer") or d.get("object") or ""
            tail = f"  [{d['ledger_id']}]" if d.get("ledger_id") else ""
            loc = f" ({who}{' → ' + ref if ref else ''})" if who or ref else ""
            out.append(f"  [{d['severity']}] {d['kind']}: {d['message']}{loc}{tail}")
        return out

    mode = (mode or "simulate").strip().lower()
    if mode == "coherence":
        r = check_patch_coherence(patch_xml, art)
        head = (f"PATCH COHERENCE — {'COHERENT' if r.is_coherent else 'INCOHERENT'} "
                f"({len(r.errors)} error(s), {len(r.warnings)} warning(s); "
                f"{r.resolved_references}/{r.checked_references} refs resolved)")
        body = _findings(r.errors) + _findings(r.warnings) or ["  (no findings)"]
        return "\n".join([head, ""] + body)

    r = simulate_apply(patch_xml, art)
    # is_consistent folds in the coherence sub-report (intra-patch refs); surface those
    # findings too, else a coherence-only failure shows consistent=False with no reason.
    coh = (r.coherence or {}).get("findings", [])
    coh_err = [f for f in coh if f.get("severity") == "error"]
    coh_warn = [f for f in coh if f.get("severity") == "warning"]
    head = (f"PATCH SIMULATION — consistent={r.is_consistent}  would_host={r.would_host}  "
            f"({len(r.errors) + len(coh_err)} error(s), {len(r.warnings) + len(coh_warn)} warning(s))")
    lines = [head, ""]
    lines += (_findings(coh_err) + _findings(r.errors)
              + _findings(coh_warn) + _findings(r.warnings)) or ["  (no findings)"]
    if r.deltas:
        lines.append("")
        lines.append("Resulting section deltas: " +
                     ", ".join(f"{k} {v:+d}" for k, v in sorted(r.deltas.items())))
    return "\n".join(lines)


@mcp.tool()
def verify_patch_applied(patch_xml: str, before_artifact: str, after_artifact: str,
                         archive_dir: str = None) -> str:
    """Confirm a patch did EXACTLY what it intended — the post-apply 'verify' rung.

    After you apply a patch and re-import the target (reimport_after_patch), call this with
    the artifact from BEFORE the apply and the one from AFTER. It cross-references the patch's
    intent against the real before→after diff and reports each change as:
      confirmed  — an intended change that landed,
      missing    — an intended change that did NOT land (an apply failure),
      unexpected — a real change the patch never asked for (collateral).
    Verdicts: applied_cleanly (nothing missing) and exact (nothing missing AND no collateral).

    Pairs with check_patch (the pre-apply static gate): check before, verify after.
    """
    from corpusfm.extensions.export.patch_verify import verify_applied_patch
    adir = Path(archive_dir) if archive_dir else None
    try:
        before = _load_artifact(before_artifact, adir)
        after = _load_artifact(after_artifact, adir)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    r = verify_applied_patch(patch_xml, before, after)
    audit.record(audit.PATCH_VERIFY, actor=_mcp_actor(),
                 target=getattr(after.identity, "file_name", ""),
                 outcome="ok" if r.applied_cleanly else "error", meta={"via": "mcp"})
    head = (f"PATCH VERIFY — applied_cleanly={r.applied_cleanly}  exact={r.exact}  "
            f"({len(r.confirmed)} confirmed, {len(r.missing)} missing, {len(r.unexpected)} unexpected)")
    lines = [head, ""]
    for label, items in (("CONFIRMED", r.confirmed), ("MISSING (apply failures)", r.missing),
                         ("UNEXPECTED (collateral)", r.unexpected)):
        if items:
            lines.append(f"{label}:")
            for f in items:
                d = f.to_dict()
                loc = f"{d['section']}/{d['name']}" if d.get("name") else d.get("section", "")
                act = f"{d['action']} " if d.get("action") else ""
                lines.append(f"  {act}{loc}: {d['message']}")
    return "\n".join(lines)


def _safe_db_name(xml: bytes) -> str:
    """Derive a safe filename stem from a SaveAsXML's File= attribute (.fmp12-stripped,
    sanitized), defaulting to 'Generated'. Sniffs UTF-8 and UTF-16 heads."""
    head = xml[:4000].decode("utf-8", "ignore") + " " + xml[:4000].decode("utf-16", "ignore")
    m = re.search(r'File="([^"]+)"', head)
    raw = (m.group(1) if m else "Generated").rsplit(".fmp12", 1)[0]
    return (re.sub(r"[^A-Za-z0-9_.-]", "_", raw) or "Generated")[:60]


@mcp.tool()
def generate_db_file(source_xml: str = "", artifact_path: str = "",
                     verify_hosts: bool = False, archive_dir: str = None) -> str:
    """Materialize a working FileMaker .fmp12 from a COMPLETE SaveAsXML export, via FMUpgradeTool
    2026's --generateDBFile (co-located FM Server 2026 only).

    This is the file-MATERIALIZATION primitive for origination/reconstruction: assemble or
    reconstruct a full <FMSaveAsXML> schema, then turn it into a real, openable database file
    WITHOUT FileMaker Pro. Source is either inline `source_xml` (the assembled SaveAsXML) or the
    stored raw XML of `artifact_path` (only present if the artifact was imported with
    keep_source_xml). --generateDBFile consumes a FULL SaveAsXML, NOT a patch — for incremental
    edits to an existing file, use the patch tools instead.

    With verify_hosts=True the generated file is hosted on FMS through the sandbox slot to confirm
    it opens cleanly (production is never touched; costs an Admin API session). Returns the
    server-side path of the generated .fmp12 — retrieve it and open/host it from there.
    """
    from corpusfm.server.patch_apply import find_tool, generate_db_file as _gen

    tool = find_tool()
    if tool is None:
        return "ERROR: FMUpgradeTool not found on this machine (co-located FM Server 2026 only)."

    xml = source_xml.encode("utf-8") if source_xml.strip() else None
    if xml is None and artifact_path:
        try:
            backend = get_backend()
            xml = backend.load_raw_xml(_artifact_uuid(artifact_path))
        except Exception as exc:
            return f"ERROR loading raw XML for '{artifact_path}': {exc}"
        if xml is None:
            return (f"ERROR: no stored raw XML for '{artifact_path}' — re-import it with "
                    "keep_source_xml, or pass the schema as source_xml.")
    if not xml:
        return ("ERROR: provide source_xml (an assembled SaveAsXML) or an artifact_path whose "
                "raw XML was kept.")
    head = xml[:2000]
    if b"FMSaveAsXML" not in head and b"F\x00M\x00S\x00a\x00v\x00e" not in head:
        return ("ERROR: source does not look like an FMSaveAsXML export. --generateDBFile needs a "
                "complete SaveAsXML, not a patch, addon, or clip.")

    import datetime as _dt
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d_%H%M%S")   # UTC (packet 1005)
    name = _safe_db_name(xml)

    # The storage database is never a materialization target — same guard every apply/promote path
    # carries (packet 1000 P1; matches is_storage_database enforcement elsewhere).
    from corpusfm.install import is_storage_database
    if is_storage_database(name):
        return f"ERROR: '{name}' is the CORPUSfm storage database — refusing to generate over it."

    # With a VERIFIED patch compartment, materialize the .fmp12 straight INTO it as <name>.fmp12 at
    # the folder root — FMS hosts it in place, no quarantine-then-move. Host-in-place must never
    # clobber a currently-hosted DB. Without one, materialize into the <archive>/_generated/
    # QUARANTINE, which is never a compartment, never establishes any manifest flag, and is never a
    # patch/apply target: materializing is permitted precisely because it changes nothing FMS sees.
    from corpusfm.server import db_helper
    host_root = db_helper.hosting_dir()
    if host_root:
        hosted = _hosted_db_names()
        # Fail CLOSED: if we cannot enumerate hosted DBs (Admin API down / PKI not registered),
        # refuse rather than risk writing over a live hosted database (packet 1000 P1). The
        # quarantine path stays available by omitting the hosting folder.
        if hosted is None:
            return ("ERROR: cannot verify which databases are currently hosted (FMS Admin API "
                    "unreachable or PKI not registered) — refusing host-in-place generation to "
                    "avoid clobbering a live database. Enable the Admin API and retry.")
        if name.lower() in hosted:
            return (f"ERROR: a database named '{name}' is already hosted — regenerate under a "
                    "different File= name so host-in-place does not clobber a live database.")
        out_dir = Path(host_root)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            return f"ERROR: cannot create the patch compartment folder '{out_dir}': {exc}"
        src_xml = out_dir / f"{name}.xml"
    else:
        base = Path(archive_dir) if archive_dir else getattr(backend, "archive_dir", None)
        if base is None:
            return "ERROR: no archive_dir available to write the generated file."
        out_dir = Path(base) / "_generated" / f"{stamp}_{name}"
        out_dir.mkdir(parents=True, exist_ok=True)
        src_xml = out_dir / f"{name}.xml"
    src_xml.write_bytes(xml)

    ok, log = _gen(tool, src_xml)
    fmp12 = src_xml.with_suffix(".fmp12")
    if not ok or not fmp12.exists():
        if host_root:
            src_xml.unlink(missing_ok=True)   # leave the shared compartment clean on failure
        return f"GENERATE FAILED (production untouched):\n{log}"

    # generate_db_file is a transform, not artifact-activity history (085 U3c) — it rides the
    # security audit ledger, not HISTORY.

    if host_root:
        db_helper.force_hostable_mode(fmp12)   # 664 g+w so fmserver can host R/W (UMASK TRAP, 1061)
        src_xml.unlink(missing_ok=True)        # the .xml is spent; keep the FMS-scanned folder clean

    # MATERIALIZE is inert — FMS neither knows nor serves the file. HOST is what a verified
    # compartment buys. Without one, the result says QUARANTINED, in the result itself and not in a
    # log, and patch/apply, sandbox dry-run, host verification, promotion (plan AND execute) and
    # global patch access all remain disabled for this installation.
    where = ("verified patch compartment (hosts in place)" if host_root
             else "QUARANTINE (_generated/) — materialized, NOT hosted")
    lines = [f"GENERATED: {fmp12}  ({fmp12.stat().st_size:,} bytes)  → {where}",
             f"from a {len(xml):,}-byte SaveAsXML via FMUpgradeTool --generateDBFile."]
    if not host_root:
        lines.append(
            "QUARANTINED: this installation has no VERIFIED patch compartment, so the file is inert "
            "— FileMaker Server neither knows nor serves it. Hosting, patching/applying, the sandbox "
            "dry-run, host verification and promotion are all disabled until the compartment is "
            "provisioned and proven.")
    if verify_hosts:
        from corpusfm.server.dry_run import verify_db_file_hosts
        hosts, hlog = verify_db_file_hosts(fmp12)
        lines.append(f"Hosts cleanly on FMS: {hosts}  ({hlog})")
    lines.append("\nRetrieve the .fmp12 from the path above (server-side) and open it in "
                 "FileMaker Pro or host it on FMS.")
    return "\n".join(lines)


# ── Plan-token infrastructure (shared by patch apply + the FMS mutators) ──────────
# A plan_*/execute_* token is the STRUCTURAL human-in-the-loop gate. Each token is:
# high-entropy (token_hex(16) = 128-bit), single-use, kind-isolated, TTL-bounded, and bound to
# its CREATOR — execute refuses a token issued to a different MCP client. (Unauthenticated
# loopback/dev has no client identity, so creator-binding is a no-op there, matching the rest of
# the auth model.) The TTL also bounds leakage.
#
# DEPLOYMENT CAVEAT — plan records live IN-PROCESS (the module-global dicts below). That is a
# feature for safety (a restart invalidates every pending plan, so no stale production action
# survives a deploy), but it ASSUMES A SINGLE WEB WORKER: the deployed unit runs one uvicorn
# process (`-m corpusfm.app.web` calls uvicorn.run with no `workers=`), so a plan and its execute
# always land on the same process. If this is ever scaled to multiple workers, plan/execute would
# need sticky routing or a shared plan store (e.g. Redis) — otherwise execute can miss a plan that
# was created on a different worker.
_PLAN_TTL_SECONDS = 600  # 10 min: a human reviews the plan, then executes


def _file_digest(path: "Path") -> str:
    """SHA-256 of a file, streamed. A plan records it so `execute` can prove the source is still the
    exact file the human reviewed — a size check alone cannot."""
    import hashlib
    h = hashlib.sha256()
    with open(str(path), "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _new_plan(payload: dict) -> tuple:
    """Mint a (token, record) pair: a 128-bit token + the payload stamped with creator + birth."""
    at = _current_access_token()
    record = {**payload,
              "_creator": None if at is None else getattr(at, "client_id", None),
              "_created": time.monotonic()}
    return secrets.token_hex(16), record


def _plan_rejection(plan: dict) -> Optional[str]:
    """None if this caller may execute the plan; else a short reason. Expired plans should be
    dropped; a creator mismatch must NOT drop the plan (leave it for the rightful caller)."""
    if time.monotonic() - plan.get("_created", 0.0) > _PLAN_TTL_SECONDS:
        return "expired"
    at = _current_access_token()
    caller = None if at is None else getattr(at, "client_id", None)
    creator = plan.get("_creator")
    if creator is not None and caller != creator:
        return "issued to a different user"
    return None


# ── Patch apply tools (co-located: need FMUpgradeTool + the scoped DB helper) ──
#
# A one-call production apply is deliberately impossible. plan_apply predicts the blast
# radius and mints a single-use token; apply_patch(token) executes. The token is the
# STRUCTURAL human-in-the-loop gate (review the plan, then apply) — not a convention the
# agent might skip. The apply itself is reversible (the live DB is backed up before the one
# swap, and restored if it fails) and runs a sandbox dry-run pre-flight first.

_APPLY_PLANS: dict = {}            # token -> plan dict (in-process, single MCP session)
_APPLY_PLANS_LOCK = Lock()


def _coerce_patch(patch_xml: str) -> str:
    """Reduce AI-fenced output to the bare <FMUpgradeToolPatch> (no-op for clean ISV XML)."""
    try:
        from corpusfm.server.ai.patch_ai import extract_ai_patch_xml
        return extract_ai_patch_xml(patch_xml)
    except Exception:
        return patch_xml


@mcp.tool()
def dry_run_patch(patch_xml: str, database_name: str, before_artifact: str,
                  archive_dir: str = None) -> str:
    """Apply a patch to a COPY of a live database and verify it — production never touched.

    The real-apply verification rung (between check_patch's static prediction and a true
    production apply): the scoped helper copies the live DB out, FMUpgradeTool patches the
    copy, it is materialized through the sandbox slot, and the result is verified against the
    patch's intent. before_artifact = the target's current artifact (the pre-apply baseline).
    Runs against the configured (co-located) FileMaker server. Needs FMUpgradeTool + the scoped
    DB helper on this machine (co-located install).
    """
    from corpusfm.install import is_storage_database
    if is_storage_database(database_name):
        return (f"ERROR: '{database_name}' is CORPUSfm's storage backend database — "
                "patch tools cannot target it. Read-only jobs are allowed.")
    from corpusfm.server import db_helper
    ok, reason = db_helper.check_apply_target(database_name)
    if not ok:
        return f"ERROR: {reason}"
    from corpusfm.app.web.routes.api.patch_ops import (
        _run_sandbox, _find_tool, _metrics_path, _target_access,
    )
    from corpusfm.server.fms_transport import colocated
    tool = _find_tool()
    if tool is None:
        return "ERROR: FMUpgradeTool not found on this machine."
    try:
        transport = colocated()
        access = _target_access({}, database_name=database_name, before_path=before_artifact)
    except Exception as exc:
        return f"ERROR: installed FileMaker transport is unavailable: {exc}"
    if not access.account:
        return ("ERROR: this target needs file credentials. Continue in the authenticated Patch UI; "
                "raw target or EAR passwords are never MCP arguments.")
    try:
        before = _load_artifact(before_artifact, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading before artifact: {exc}"
    report, log = _run_sandbox(tool, database_name, _coerce_patch(patch_xml), before,
                               transport, access, _metrics_path())
    if report is None:
        audit.record(audit.PATCH_DRY_RUN, actor=_mcp_actor(), target=database_name,
                     outcome="error", meta={"op": "sandbox", "via": "mcp"})
        return f"DRY-RUN FAILED (production untouched):\n{log}"
    r = report.to_dict()
    audit.record(audit.PATCH_DRY_RUN, actor=_mcp_actor(), target=database_name, outcome="ok",
                 meta={"op": "sandbox", "via": "mcp", "applied_cleanly": bool(r["applied_cleanly"])})
    return (f"DRY-RUN on a copy of '{database_name}' — applied_cleanly={r['applied_cleanly']} "
            f"exact={r['exact']} ({r['confirmed_count']} confirmed, {r['missing_count']} missing, "
            f"{r['unexpected_count']} unexpected). Production NOT touched.\n\n{log}")


@mcp.tool()
def plan_apply(patch_xml: str, database_name: str, before_artifact: str,
               archive_dir: str = None) -> str:
    """STEP 1 of 2 — predict a production apply's blast radius and issue a confirmation token.

    Touches NOTHING. Returns the predicted change-set (consistent? would-host? section deltas;
    any surviving schema orphaned by a delete) plus a one-time token. A human reviews this,
    THEN you call apply_patch(token) to execute. There is no one-call apply — the token is the
    gate. The eventual apply is reversible (the live DB is backed up before the one swap).
    """
    from corpusfm.install import is_storage_database
    if is_storage_database(database_name):
        return (f"ERROR: '{database_name}' is CORPUSfm's storage backend database — "
                "patch tools cannot target it. Read-only jobs are allowed.")
    from corpusfm.server import db_helper
    target_ok, target_reason = db_helper.check_apply_target(database_name)
    if not target_ok:
        return f"ERROR: {target_reason}"
    from corpusfm.extensions.export.patch_simulate import simulate_apply
    patch_xml = _coerce_patch(patch_xml)
    try:
        before = _load_artifact(before_artifact, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading before artifact: {exc}"
    sim = simulate_apply(patch_xml, before)
    token, record = _new_plan({"patch_xml": patch_xml, "database_name": database_name,
                               "before_artifact": before_artifact, "archive_dir": archive_dir})
    with _APPLY_PLANS_LOCK:
        _APPLY_PLANS[token] = record
    audit.record(audit.PATCH_APPLY, actor=_mcp_actor(), target=database_name, outcome="ok",
                 meta={"op": "plan", "via": "mcp", "consistent": bool(sim.is_consistent)})
    lines = [f"APPLY PLAN — database '{database_name}'  |  consistent={sim.is_consistent}  "
             f"would_host={sim.would_host}  ({len(sim.errors)} error(s), {len(sim.warnings)} warning(s))", ""]
    lines.append(f"  target   : {database_name}  (authorized for apply)")
    lines.append(f"  patch    : {len(patch_xml)} bytes of FMUpgradeToolPatch XML; "
                 f"baseline artifact = {before_artifact}")
    for f in sim.errors + sim.warnings:
        d = f.to_dict()
        lines.append(f"  [{d['severity']}] {d['kind']}: {d['message']}")
    if sim.deltas:
        lines.append("Resulting section deltas: " +
                     ", ".join(f"{k} {v:+d}" for k, v in sorted(sim.deltas.items())))
    lines += ["",
              "Apply behavior — the live DB is CLOSED (clients disconnected) for the swap window, "
              "backed up to its exact pre-patch bytes, patched on a copy, then the copy is swapped "
              "in atomically and the DB is REOPENED. If any step fails the backup is restored and the "
              "DB is always reopened — production is never left offline or half-patched.",
              "Production is NOT yet touched. After a human reviews this plan, EXECUTE with:",
              f"    apply_patch('{token}')"]
    if not sim.is_consistent:
        lines.append("⚠ INCONSISTENT simulation — fix the patch before applying (apply will abort).")
    return "\n".join(lines)


@mcp.tool()
def apply_patch(plan_token: str) -> str:
    """STEP 2 of 2 — EXECUTE a planned apply (PRODUCTION-IMPACTING). Requires a plan_apply token.

    Refuses without a valid, unused token (there is no one-call apply). Runs a sandbox dry-run
    pre-flight and applies for real ONLY if it applies cleanly, via the reversible helper-swap
    (the live DB is backed up first and restored if the swap fails; it is always reopened).
    Only call this after a human has reviewed the plan_apply blast radius.
    """
    with _APPLY_PLANS_LOCK:
        plan = _APPLY_PLANS.get(plan_token)
        if plan is None:
            return ("ERROR: unknown or already-used plan token. Call plan_apply first, have a human "
                    "review the predicted change-set, then apply_patch(its token).")
        reason = _plan_rejection(plan)
        if reason == "expired":
            _APPLY_PLANS.pop(plan_token, None)
            return ("ERROR: this plan token has EXPIRED (plans last "
                    f"{_PLAN_TTL_SECONDS // 60} min) — re-run plan_apply and review the new plan.")
        if reason is not None:
            return f"ERROR: plan token rejected — {reason}. Have the original requester apply it."
        _APPLY_PLANS.pop(plan_token, None)   # valid → consume (single-use)
    from corpusfm.app.web.routes.api.patch_ops import (
        _run_production_apply, _find_tool, _metrics_path, _target_access,
    )
    from corpusfm.server.fms_transport import colocated
    tool = _find_tool()
    if tool is None:
        return "ERROR: FMUpgradeTool not found on this machine."
    try:
        transport = colocated()
        access = _target_access({}, database_name=plan["database_name"],
                                before_path=plan["before_artifact"])
    except Exception as exc:
        return f"ERROR: installed FileMaker transport is unavailable: {exc}"
    if not access.account:
        return ("ERROR: this target needs file credentials. Continue in the authenticated Patch UI; "
                "raw target or EAR passwords are never MCP arguments.")
    try:
        before = _load_artifact(plan["before_artifact"],
                                Path(plan["archive_dir"]) if plan["archive_dir"] else None)
    except Exception:
        before = None
    ok, log, mode = _run_production_apply(
        tool, plan["database_name"], plan["patch_xml"], before, transport, access,
        _metrics_path(), skip_dry_run=False)
    # apply is a mutating op, not artifact-activity history (085 U3c) — audited below, not HISTORY.
    audit.record(audit.PATCH_APPLY, actor=_mcp_actor(), target=plan["database_name"],
                 outcome="ok" if ok else "error", meta={"op": "execute", "via": "mcp", "path": mode})
    head = (f"APPLY {'SUCCEEDED' if ok else 'FAILED'} — database '{plan['database_name']}' "
            f"(mode={mode}). The live DB was backed up before the swap; "
            f"{'changes are live' if ok else 'production was restored / never modified'}.")
    return head + "\n\n" + log


# ── Promote a generated .fmp12 into the live FMS Databases folder (opt-in, two-step) ──
# generate_db_file QUARANTINES its output under <archive>/_generated/ (never auto-exposed — an
# unvetted materialized file must not appear in production). This is the opt-in bridge for a remote
# agent with no shell on the box: plan → (human review) → execute places the file into the FMS
# Databases folder. Guarded exactly like apply: single-use plan token + the storage-DB guard, plus
# it only accepts a path WE generated (under _generated/) and refuses clobbering an already-hosted DB.
_PROMOTE_PLANS: dict = {}
_PROMOTE_PLANS_LOCK = Lock()


def _hosted_db_names() -> "set[str] | None":
    """Best-effort lower-cased set of hosted DB filenames (sans .fmp12), or None if unreachable."""
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
        ok, _code, body = pki.admin_api_request(
            cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/databases", verify_ssl=verify)
        if not ok:
            return None
        return {str(d.get("filename", "")).lower().rsplit(".fmp12", 1)[0]
                for d in (body.get("response") or {}).get("databases") or []}
    except Exception:
        return None


@mcp.tool()
def plan_promote_generated_db(generated_path: str, open_after: bool = True,
                              archive_dir: str = None) -> str:
    """STEP 1 of 2 — plan promoting a generate_db_file output into CORPUSfm's VERIFIED patch
    compartment.

    **Two dispositions, one destination.** Either the file already resides canonically inside the
    verified compartment (**no move** — revalidate and optionally open), or it resides canonically
    inside the ``<archive>/_generated/`` quarantine and is **published** into the compartment under
    its database basename. **There is no third disposition: no promotion targets the main FMS
    Databases directory, on any layout, under any setting.** That route existed and is removed —
    it was a privileged write into FileMaker's own directory authorized by nothing but the source
    not being somewhere else.

    Touches NOTHING; mints a single-use token a human reviews before
    execute_promote_generated_db(token). Refuses CORPUSfm's own storage DB, a source in neither
    place, a name that collides with an already-hosted DB, and a quarantine source when this
    installation has no verified compartment to publish into.
    """
    from corpusfm.install import is_storage_database
    from corpusfm.server import db_helper
    base = Path(archive_dir) if archive_dir else getattr(get_backend(), "archive_dir", None)
    p = Path(generated_path)
    gen_root = (Path(base) / "_generated") if base else None

    try:
        authority = db_helper.load_published_patch_authority()
    except db_helper.PatchAuthorityError as exc:
        authority = None
        authority_error = str(exc)

    def _under(root) -> bool:
        try:
            return root is not None and Path(root).resolve() in p.resolve().parents
        except Exception:
            return False

    in_compartment = authority is not None and _under(authority.patch_hosting_dir)
    from_quarantine = _under(gen_root)
    if not (in_compartment or from_quarantine):
        return ("ERROR: promote only accepts a generate_db_file output — either already inside "
                "CORPUSfm's verified patch compartment (hosts in place) or under "
                "<archive>/_generated/ (published into the compartment). Generate the file first, "
                "then promote its returned path.")
    if p.suffix.lower() != ".fmp12" or not p.exists():
        return f"ERROR: '{generated_path}' is not an existing .fmp12."
    if authority is None:
        return (f"ERROR: this installation has no VERIFIED patch compartment to promote into — "
                f"{authority_error} The file stays quarantined and inert.")

    db_name = p.stem
    if is_storage_database(db_name):
        return f"ERROR: '{db_name}' is CORPUSfm's storage backend database — refused."
    hosted = _hosted_db_names()
    if hosted is not None and db_name.lower() in hosted:
        return (f"ERROR: a database named '{db_name}' is already hosted — promote must not clobber a "
                "live database. Regenerate under a different File= name, or close the existing one first.")

    kind = "in_compartment" if in_compartment else "quarantine"
    source = p.resolve()
    destination = source if in_compartment else (authority.patch_hosting_dir / f"{db_name}.fmp12")
    try:
        stat = source.stat()
        digest = _file_digest(source)
    except Exception as exc:
        return f"ERROR: '{generated_path}' could not be read ({exc})."
    if kind == "quarantine" and (destination.exists() or destination.is_symlink()):
        return (f"ERROR: '{destination}' already exists. Publication never replaces an existing "
                "destination; nothing was changed.")

    token, record = _new_plan({
        "path": str(source), "db_name": db_name, "open_after": bool(open_after),
        "kind": kind, "destination": str(destination),
        "source_digest": digest, "source_size": stat.st_size,
        "installation_id": authority.installation_id,
        "manifest_generation": authority.generation,
        "compartment": str(authority.patch_hosting_dir),
        "hosted_name_absent": hosted is not None,
    })
    with _PROMOTE_PLANS_LOCK:
        _PROMOTE_PLANS[token] = record
    audit.record(audit.PATCH_APPLY, actor=_mcp_actor(), target=db_name,
                 meta={"op": "plan_promote", "via": "mcp", "open_after": bool(open_after),
                       "kind": kind})
    disposition = ("hosts IN PLACE inside the verified patch compartment (no file move)"
                   if kind == "in_compartment"
                   else "PUBLISHES the quarantined file into the verified patch compartment "
                        "(atomic, never replacing an existing destination)")
    return (f"PROMOTE PLAN — {disposition} (nothing done yet)\n"
            f"  file       : {source.name}  ({stat.st_size:,} bytes)\n"
            f"  db name    : {db_name}  (not a hosted DB{'' if hosted is not None else '; hosted list unverified'})\n"
            f"  compartment: {authority.patch_hosting_dir}\n"
            f"  destination: {destination}\n"
            f"  open after : {bool(open_after)}\n\n"
            "This exposes an FMUpgradeTool-materialized file as a real hosted database — review it first.\n"
            f"    execute_promote_generated_db('{token}')")


@mcp.tool()
def execute_promote_generated_db(plan_token: str) -> str:
    """STEP 2 of 2 — EXECUTE a planned promote into CORPUSfm's verified patch compartment (and host
    it if planned). Refuses without a valid, unused plan_promote_generated_db token.

    Every fact the plan recorded is rechecked here before the token is consumed — a token minted
    under one state must not execute under another. A compartment that MOVED while remaining
    ``verified`` fails here, and the plan-time no-clobber check is repeated rather than assumed.
    """
    with _PROMOTE_PLANS_LOCK:
        plan = _PROMOTE_PLANS.get(plan_token)
        if plan is None:
            return ("ERROR: unknown or already-used plan token. Call plan_promote_generated_db first, "
                    "have a human review it, then execute_promote_generated_db(its token).")
        reason = _plan_rejection(plan)
        if reason == "expired":
            _PROMOTE_PLANS.pop(plan_token, None)
            return ("ERROR: this plan token has EXPIRED (plans last "
                    f"{_PLAN_TTL_SECONDS // 60} min) — re-run plan_promote_generated_db.")
        if reason is not None:
            return f"ERROR: plan token rejected — {reason}. Have the original requester execute it."

        from corpusfm.server import db_helper
        recheck = _recheck_promote_plan(plan)
        if recheck is not None:
            return f"ERROR: {recheck} Nothing was changed; the plan token is preserved."
        _PROMOTE_PLANS.pop(plan_token, None)           # every recheck passed → consume (single-use)

    p = Path(plan["path"])
    if plan["kind"] == "in_compartment":
        # The file already lives in the verified compartment, so there is NO move — just make sure
        # it is group-writable (664, idempotent) and let the open below host it.
        db_helper.force_hostable_mode(p)
        lines = [f"HOST-IN-PLACE: '{plan['db_name']}.fmp12' already resides in the verified patch "
                 f"compartment {plan['compartment']} (no file move)."]
    else:
        ok, msg = db_helper.publish_into_compartment(p, plan["db_name"])
        if not ok:
            audit.record(audit.PATCH_APPLY, actor=_mcp_actor(), target=plan["db_name"],
                         outcome="error", meta={"op": "execute_promote", "via": "mcp"})
            return f"PROMOTE FAILED (nothing hosted): {msg}"
        lines = [f"PUBLISHED: '{plan['db_name']}.fmp12' published into the verified patch "
                 f"compartment {plan['compartment']}."]

    opened = True
    if plan.get("open_after"):
        from corpusfm.server.patch_apply import open_database
        opened, msg2 = open_database(plan["db_name"])
        lines.append(f"Host (open): {'ok' if opened else 'FAILED'} — {msg2}")

    # The quarantine source is preserved until publication AND any requested open have succeeded.
    # An undeletable source is safe residue reported as such — never data loss, and never a failure
    # of the promotion that already succeeded.
    if plan["kind"] == "quarantine" and opened:
        try:
            p.unlink()
        except Exception as exc:
            lines.append(f"Safe residue: the quarantined source at {p} could not be removed ({exc}). "
                         "The promotion completed; delete it at your convenience.")
    audit.record(audit.PATCH_APPLY, actor=_mcp_actor(), target=plan["db_name"],
                 outcome="ok", meta={"op": "execute_promote", "via": "mcp"})
    return "\n".join(lines)


def _recheck_promote_plan(plan: dict) -> "str | None":
    """Every plan-time fact, rechecked BEFORE the token is consumed. None when all of them hold."""
    from corpusfm.install import is_storage_database
    from corpusfm.server import db_helper

    try:
        authority = db_helper.load_published_patch_authority()
    except db_helper.PatchAuthorityError as exc:
        return f"the patch compartment is no longer verified — {exc}"
    if authority.installation_id != plan["installation_id"]:
        return "this is not the installation the plan was made against."
    if authority.generation != plan["manifest_generation"]:
        return "the installation manifest moved after the plan was made."
    if str(authority.patch_hosting_dir) != plan["compartment"]:
        return ("the patch compartment moved after the plan was made (it is still verified, but it "
                "is a different directory).")

    src = Path(plan["path"])
    try:
        if not src.is_file():
            return "the source file no longer exists."
        if src.stat().st_size != plan["source_size"]:
            return "the source file's size changed after the plan was made."
        if _file_digest(src) != plan["source_digest"]:
            return "the source file's content changed after the plan was made."
    except Exception as exc:
        return f"the source file could not be re-read ({exc})."

    if plan["kind"] == "quarantine":
        dest = Path(plan["destination"])
        if dest.is_symlink():
            return "the destination is a symlink; publication refuses to follow it."
        if dest.exists():
            return "the destination appeared after the plan was made; publication never replaces it."

    hosted = _hosted_db_names()
    if hosted is None:
        return ("the hosted-database list is unreachable, so the no-clobber check cannot be "
                "repeated at execute time.")
    if plan["db_name"].lower() in hosted:
        return f"'{plan['db_name']}' became a hosted database after the plan was made."

    try:
        if is_storage_database(plan["db_name"]):
            return f"'{plan['db_name']}' is CORPUSfm's storage backend database."
    except Exception as exc:
        return f"could not determine whether '{plan['db_name']}' is the storage database ({exc})."
    return None


# ── Broad FMS control (Admin API via PKI) ───────────────────────────────────────
# These drive the FileMaker Server Admin API v2 through the stored PKI key — NO admin
# password held. They cover databases / clients / schedules: everything beyond patching.
# Server-process RESTARTS are deliberately NOT here (the API has no restart endpoint;
# that stays a CLI/installer concern).
#
# This is the sharpest surface on the bus, so it carries THREE rails: (1) the per-user
# `fms_api` gate; (2) the server-wide enable_fms_admin_mcp_tools switch (default off — when
# off these tools are hidden from tools/list and refused at call time); and (3) every MUTATING
# op is two-step plan_*→execute_*, mirroring patch apply: the plan touches nothing, predicts
# the blast radius, and mints a single-use token that execute consumes. A one-call mutation is
# deliberately impossible. DB-mutating ops also refuse CORPUSfm's own storage DB.

_FMS_PLANS: dict = {}            # token -> plan dict (in-process, single MCP session)
_FMS_PLANS_LOCK = Lock()


def _store_fms_plan(kind: str, **params) -> str:
    token, record = _new_plan({"kind": kind, **params})
    with _FMS_PLANS_LOCK:
        _FMS_PLANS[token] = record
    return token


def _take_fms_plan(token: str, kind: str):
    """Pop a single-use plan, but only if it matches the expected kind AND is still valid for this
    caller (not expired, not issued to a different client). Expired plans are dropped; a creator
    mismatch leaves the plan in place for the rightful caller."""
    with _FMS_PLANS_LOCK:
        plan = _FMS_PLANS.get(token)
        if plan is None or plan.get("kind") != kind:
            return None
        reason = _plan_rejection(plan)
        if reason == "expired":
            _FMS_PLANS.pop(token, None)
            return None
        if reason is not None:
            return None
        return _FMS_PLANS.pop(token, None)


def _fms_admin_pki_ctx():
    """Resolve (key_cfg, verify_ssl) for Admin API calls, or raise RuntimeError."""
    from corpusfm.server.admin_api_identity import admin_api_identity
    from corpusfm.server.fms_transport import colocated
    identity = admin_api_identity()
    cfg = identity.config
    if not cfg:
        # The resolver's own reason, not a generic "configure it": on a published installation the
        # identity is established at install time, so "absent", "unreadable" and "disagrees" send an
        # administrator to three different actions (packet 1247).
        raise RuntimeError(
            f"The FileMaker Server Admin API identity is unavailable: {identity.reason}. "
            f"{identity.remedy}".strip())
    return cfg, colocated().verify_ssl


@mcp.tool()
def fms_list_databases() -> str:
    """List databases hosted on the FileMaker Server with their status (read-only).

    Uses the Admin API via PKI (no password). Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    ok, code, body = pki.admin_api_request(
        cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/databases", verify_ssl=verify)
    if not ok:
        return f"ERROR (HTTP {code}): {body.get('messages')}"
    dbs = (body.get("response") or {}).get("databases") or []
    if not dbs:
        return "No databases are hosted."
    lines = [f"{len(dbs)} database(s) on {cfg['host']}:"]
    for d in dbs:
        lines.append(f"  [{d.get('id')}] {d.get('filename','?')} — {d.get('status','?')} "
                     f"({d.get('clients', 0)} clients)")
    return "\n".join(lines)


@mcp.tool()
def plan_fms_control_database(database_name: str, action: str, force: bool = False) -> str:
    """STEP 1 of 2 — plan a hosted-DB control op (open|close|pause|resume|flush) and issue a token.

    Touches NOTHING. Validates the action, refuses CORPUSfm's own storage DB, reports the DB's
    CURRENT status, and returns a one-time token. A human reviews the blast radius, THEN calls
    execute_fms_control_database(token). There is no one-call control — the token is the gate.
    Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    from corpusfm.install import is_storage_database
    if is_storage_database(database_name):
        return (f"ERROR: '{database_name}' is CORPUSfm's storage backend database — "
                "it must not be opened/closed/paused by these tools.")
    status_map = {"open": "OPENED", "close": "CLOSED", "pause": "PAUSED",
                  "resume": "RESUMED", "flush": "FLUSHED"}
    act = action.strip().lower()
    status = status_map.get(act)
    if status is None:
        return f"ERROR: action must be one of {', '.join(sorted(status_map))}."
    current = "?"
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
        ok, _code, body = pki.admin_api_request(
            cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/databases", verify_ssl=verify)
        if ok:
            want = database_name.lower()
            for d in (body.get("response") or {}).get("databases") or []:
                fn = str(d.get("filename", "")).lower()
                if fn == want or fn == want + ".fmp12":
                    current = d.get("status", "?")
                    break
    except Exception:
        pass
    token = _store_fms_plan("control_database", database_name=database_name,
                            action=act, status=status, force=force)
    audit.record(audit.FMS_PLAN, actor=_mcp_actor(), target=database_name,
                 meta={"op": "control_database", "action": act, "force": bool(force)})
    impact = " (disconnects connected clients first)" if (status == "CLOSED" and force) else ""
    return ("FMS CONTROL PLAN — PRODUCTION-IMPACTING (nothing changed yet)\n"
            f"  database : {database_name}\n"
            f"  current  : {current}\n"
            f"  action   : {act} → {status}{impact}\n\n"
            "After a human reviews this, EXECUTE with:\n"
            f"    execute_fms_control_database('{token}')")


@mcp.tool()
def execute_fms_control_database(plan_token: str) -> str:
    """STEP 2 of 2 — EXECUTE a planned hosted-DB control op (PRODUCTION-IMPACTING).

    Refuses without a valid, unused plan_fms_control_database token. Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    plan = _take_fms_plan(plan_token, "control_database")
    if plan is None:
        return ("ERROR: unknown, expired, already-used, or wrong-user plan token. Call plan_fms_control_database first, "
                "have a human review the plan, then execute_fms_control_database(its token).")
    from corpusfm.install import is_storage_database
    if is_storage_database(plan["database_name"]):
        return f"ERROR: '{plan['database_name']}' is CORPUSfm's storage backend database — refused."
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    ok, msg = pki.set_database_status(
        cfg["host"], cfg["name"], cfg["private_pem"], plan["database_name"], plan["status"],
        force=bool(plan.get("force")), verify_ssl=verify)
    audit.record(audit.FMS_EXECUTE, actor=_mcp_actor(), target=plan["database_name"],
                 outcome="ok" if ok else "error",
                 meta={"op": "control_database", "action": plan["action"], "status": plan["status"]})
    return (f"{'OK' if ok else 'FAILED'}: {plan['action']} '{plan['database_name']}' "
            f"(status→{plan['status']}). {msg}")


@mcp.tool()
def fms_list_clients() -> str:
    """List clients connected to the FileMaker Server (read-only).

    Admin API via PKI (no password). Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    ok, code, body = pki.admin_api_request(
        cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/clients", verify_ssl=verify)
    if not ok:
        return f"ERROR (HTTP {code}): {body.get('messages')}"
    clients = (body.get("response") or {}).get("clients") or []
    if not clients:
        return "No clients are connected."
    lines = [f"{len(clients)} connected client(s):"]
    for c in clients:
        lines.append(f"  [{c.get('id')}] {c.get('userName','?')} @ {c.get('computerName','?')} "
                     f"— {c.get('status','?')} ({c.get('appVersion','?')})")
    return "\n".join(lines)


@mcp.tool()
def plan_fms_disconnect_client(client_id: str, message: str = "", grace_seconds: int = 90) -> str:
    """STEP 1 of 2 — plan disconnecting a client and issue a token (PRODUCTION-IMPACTING on execute).

    Touches NOTHING. Identifies who the client is (best effort) and returns a one-time token. A
    human reviews it, THEN calls execute_fms_disconnect_client(token). Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    cid = str(client_id).strip()
    if not cid:
        return "ERROR: client_id is required."
    who = "?"
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
        ok, _code, body = pki.admin_api_request(
            cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/clients", verify_ssl=verify)
        if ok:
            for c in (body.get("response") or {}).get("clients") or []:
                if str(c.get("id")) == cid:
                    who = f"{c.get('userName','?')} @ {c.get('computerName','?')}"
                    break
    except Exception:
        pass
    token = _store_fms_plan("disconnect_client", client_id=cid,
                            message=message, grace_seconds=int(grace_seconds))
    audit.record(audit.FMS_PLAN, actor=_mcp_actor(), target=f"client:{cid}",
                 meta={"op": "disconnect_client", "grace_seconds": int(grace_seconds)})
    return ("FMS DISCONNECT PLAN — PRODUCTION-IMPACTING (nothing changed yet)\n"
            f"  client   : [{cid}] {who}\n"
            f"  grace    : {int(grace_seconds)}s\n"
            f"  message  : {message.strip() or '(none)'}\n\n"
            "After a human reviews this, EXECUTE with:\n"
            f"    execute_fms_disconnect_client('{token}')")


@mcp.tool()
def execute_fms_disconnect_client(plan_token: str) -> str:
    """STEP 2 of 2 — EXECUTE a planned client disconnect (PRODUCTION-IMPACTING).

    Refuses without a valid, unused plan_fms_disconnect_client token. Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    plan = _take_fms_plan(plan_token, "disconnect_client")
    if plan is None:
        return ("ERROR: unknown, expired, already-used, or wrong-user plan token. Call plan_fms_disconnect_client first, "
                "have a human review the plan, then execute_fms_disconnect_client(its token).")
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    params = {"graceTime": int(plan["grace_seconds"])}
    if plan["message"].strip():
        params["messageText"] = plan["message"].strip()
    ok, code, body = pki.admin_api_request(
        cfg["host"], cfg["name"], cfg["private_pem"], "DELETE",
        f"/clients/{plan['client_id']}", params=params, verify_ssl=verify)
    audit.record(audit.FMS_EXECUTE, actor=_mcp_actor(), target=f"client:{plan['client_id']}",
                 outcome="ok" if ok else "error", meta={"op": "disconnect_client"})
    return (f"{'OK' if ok else 'FAILED'} (HTTP {code}): disconnect client {plan['client_id']}. "
            f"{body.get('messages')}")


@mcp.tool()
def plan_fms_message_clients(message: str, client_id: str = "") -> str:
    """STEP 1 of 2 — plan messaging one client or ALL connected clients, and issue a token.

    Touches NOTHING. Resolves the target set (broadcast-to-ALL is flagged with its count) and
    returns a one-time token. A human reviews it, THEN calls execute_fms_message_clients(token).
    Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    if not message.strip():
        return "ERROR: message text is required."
    broadcast = not client_id.strip()
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    if broadcast:
        ok, code, body = pki.admin_api_request(
            cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/clients", verify_ssl=verify)
        if not ok:
            return f"ERROR listing clients (HTTP {code}): {body.get('messages')}"
        targets = [str(c.get("id")) for c in (body.get("response") or {}).get("clients") or []]
    else:
        targets = [client_id.strip()]
    if not targets:
        return "No clients to message."
    token = _store_fms_plan("message_clients", message=message.strip(),
                            targets=targets, broadcast=broadcast)
    audit.record(audit.FMS_PLAN, actor=_mcp_actor(),
                 target=("broadcast" if broadcast else f"client:{targets[0]}"),
                 meta={"op": "message_clients", "broadcast": broadcast, "count": len(targets)})
    scope = (f"ALL {len(targets)} connected client(s) — BROADCAST" if broadcast
             else f"client {targets[0]}")
    return ("FMS MESSAGE PLAN (nothing sent yet)\n"
            f"  scope    : {scope}\n"
            f"  message  : {message.strip()}\n\n"
            "After a human reviews this, EXECUTE with:\n"
            f"    execute_fms_message_clients('{token}')")


@mcp.tool()
def execute_fms_message_clients(plan_token: str) -> str:
    """STEP 2 of 2 — EXECUTE a planned client message (broadcast or single).

    Refuses without a valid, unused plan_fms_message_clients token. Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    plan = _take_fms_plan(plan_token, "message_clients")
    if plan is None:
        return ("ERROR: unknown, expired, already-used, or wrong-user plan token. Call plan_fms_message_clients first, "
                "have a human review the plan, then execute_fms_message_clients(its token).")
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    targets = plan["targets"]
    msg = plan["message"]
    sent, failed = 0, 0
    for cid in targets:
        ok, _code, _body = pki.admin_api_request(
            cfg["host"], cfg["name"], cfg["private_pem"], "POST",
            f"/clients/{cid}/message", json_body={"messageText": msg}, verify_ssl=verify)
        sent += 1 if ok else 0
        failed += 0 if ok else 1
    audit.record(audit.FMS_EXECUTE, actor=_mcp_actor(),
                 target=("broadcast" if plan.get("broadcast") else f"client:{targets[0]}"),
                 outcome="ok" if failed == 0 else "error",
                 meta={"op": "message_clients", "sent": sent, "failed": failed})
    return f"Messaged {sent}/{len(targets)} client(s)" + (f" ({failed} failed)." if failed else ".")


@mcp.tool()
def fms_list_schedules() -> str:
    """List the FileMaker Server schedules (read-only).

    Admin API via PKI (no password). Requires the `fms_api` gate.
    """
    _require_fms_admin_enabled()
    from corpusfm.server import fms_admin_pki as pki
    try:
        cfg, verify = _fms_admin_pki_ctx()
    except Exception as exc:
        return f"ERROR: {exc}"
    ok, code, body = pki.admin_api_request(
        cfg["host"], cfg["name"], cfg["private_pem"], "GET", "/schedules", verify_ssl=verify)
    if not ok:
        return f"ERROR (HTTP {code}): {body.get('messages')}"
    scheds = (body.get("response") or {}).get("schedules") or []
    if not scheds:
        return "No schedules are configured."
    lines = [f"{len(scheds)} schedule(s):"]
    for s in scheds:
        lines.append(f"  [{s.get('id')}] {s.get('name','?')} — type {s.get('taskType','?')}, "
                     f"{'enabled' if s.get('enabled') else 'disabled'}")
    return "\n".join(lines)


# ── Job tools (server mode only) ───────────────────────────────────────────────

if _SERVER_MODE:
    @mcp.tool()
    def list_jobs(jobs_dir: str = None, database: str = None) -> str:
        """List configured jobs so you can pick the one that OWNS a hosted file, then run it.

        Each valid job reports: name, stable job UUID, owner file, source type, schedule, and last-run
        status/time — enough to choose a job by the file it refreshes. Invalid job records stay VISIBLE
        with a bounded error (never silently hidden). Pass ``database`` to filter to the job(s) that own
        that file (the ``.fmp12`` suffix is optional — matched canonically). Never exposes credentials;
        never auto-creates a job. Jobs are the authority for source method, credentials, scheduling, and
        owner file — this only helps you find and start the right one."""
        from corpusfm.core.filenames import ensure_fmp12
        jdir = Path(jobs_dir) if jobs_dir else default_jobs_dir()
        pairs = _list_jobs(jdir)
        want = ensure_fmp12(database.strip()) if (database and database.strip()) else ""
        valid = invalid = 0
        lines = []
        for cfg, err in pairs:
            if err:
                invalid += 1
                if not want:                 # a file-filtered listing can't match an unparseable record
                    lines.append(f"  [INVALID] {err}")
                continue
            owner = ensure_fmp12(cfg.file) if getattr(cfg, "file", "") else ""
            if want and owner != want:
                continue
            valid += 1
            state = read_state(cfg.name, jdir)
            src_type = cfg.source.type if cfg.source else "?"
            schedule = ""
            if cfg.triggers:
                # The human sentence, not the stored shape — an agent reading this should see what
                # the user sees (packet 1185).
                from corpusfm.server.jobs import schedule as _sched
                said = [_sched.summary(s) for s in
                        (t.resolved_schedule() for t in cfg.triggers) if s is not None]
                if said:
                    schedule = f"  schedule={said[0]}"
            status = ""
            if state.last_run_ts:
                status = f"  last={state.last_run_ts} ({state.last_status or '?'})"
                if state.last_error:
                    status += f"  error={state.last_error[:60]}"
            lines.append(
                f"  {cfg.name}  uuid={getattr(cfg, 'id', '') or '(unassigned)'}  "
                f"file={owner or '(none)'}  source={src_type}{schedule}{status}")
        if not lines:
            # Secret-free diagnostic: distinguish an empty store from a filtered miss / all-invalid.
            if want:
                return (f"No job owns '{want}'. The job store held {len(pairs)} record(s) "
                        f"({invalid} invalid). Jobs are file-centric — one job owns one hosted file.")
            if not pairs:
                return "No jobs configured — the job store contained zero valid and zero invalid records."
            return f"No valid jobs — the job store held {invalid} invalid record(s) only."
        header = f"Jobs owning '{want}':" if want else "Jobs:"
        return header + "\n" + "\n".join(lines)

    @mcp.tool()
    def run_job(
        job_name: str,
        jobs_dir: str = None,
        archive_dir: str = None,
    ) -> str:
        """Trigger a named job to pull fresh XML from the configured FMS source and store it.

        Enqueues the run on the server's QUEUE workspace (the single pull worker executes it) and
        returns immediately with BOTH the queue record id (the operational address while the run is
        active) and a durable run_id. Resolve the exact outcome with get_job_run(run_id) — it works
        whether the run is still queued/running OR already finished (a fast pull deletes its queue row
        on success before you could poll, but the run_id still resolves its result and artifact).
        """
        from corpusfm.server import queue_handlers
        from corpusfm.server.jobs.store import load_job, default_jobs_dir
        from corpusfm.storage import get_backend
        jdir = Path(jobs_dir) if jobs_dir else default_jobs_dir()
        adir = Path(archive_dir) if archive_dir else None
        try:
            cfg = load_job(job_name, jdir)
        except Exception as exc:
            return f"ERROR: no such job '{job_name}': {exc}"
        qid, run_id = queue_handlers.enqueue_job_run(
            get_backend(adir), job_name=job_name, job_uuid=getattr(cfg, "id", "") or "",
            file_name=getattr(cfg, "file", "") or "", trigger="manual")
        return (
            f"Enqueued run for job '{job_name}'.\n  run_id:       {run_id}\n"
            f"  Queue record: {qid}\n"
            "\nResolve the outcome with get_job_run(run_id) — it returns the exact status + produced "
            "artifact whether the run is still active or already finished. (get_queue is the whole "
            "workspace; get_job_history is this job's chronological history — neither is per-run exact.)"
        )

    @mcp.tool()
    def get_job_run(run_id: str, archive_dir: str = None) -> str:
        """Resolve the EXACT outcome of one run started by run_job, by its run_id.

        Spans the run's whole lifecycle: while it is queued/running/failed this reads the live QUEUE
        row; after a successful pull deletes that row it reads the HISTORY Type=Run record keyed by the
        SAME run_id. An unknown run_id is an honest not-found — never 'the latest run'. This is the
        reliable correlation path: a fast pull can finish and delete its queue row before your first
        poll, yet get_job_run still returns its success and produced-artifact UUID."""
        from corpusfm.server import queue_handlers, queue_workers as W
        from corpusfm.server.history import get_run_record
        from corpusfm.storage import get_backend, queue_record as Q
        if not (run_id or "").strip():
            return "ERROR: run_id is required."
        rid = run_id.strip()
        be = get_backend(Path(archive_dir) if archive_dir else None)

        # 1) Active phase — the run's queue row still exists (keyed in its payload by run_id).
        row = queue_handlers.find_run_in_queue(be, rid)
        if row is not None:
            j = row.jor
            p = j.get("Payload", {}) or {}
            if Q.is_failed(j):
                st = "failed"
            elif row.key in W.current_ids():
                st = "running"
            else:
                st = "queued"
            lines = [f"Run {rid} — {st}",
                     f"  job:          {p.get('job_name', '') or '(unknown)'}",
                     f"  current step: {j.get('Type', '')}",
                     f"  queue record: {row.key}"]
            if j.get("UUIDJob"):
                lines.append(f"  job_uuid:     {j.get('UUIDJob')}")
            if j.get("UUIDStorage"):
                lines.append(f"  artifact:     {j.get('UUIDStorage')}")
            if st == "failed" and j.get("Outcome"):
                lines.append(f"  error:        {j.get('Outcome')}")
            return "\n".join(lines)

        # 2) Terminal phase — the queue row is gone (success) or was a recorded error: HISTORY by run_id.
        rec = get_run_record(be, rid)
        if rec is not None:
            lines = [f"Run {rid} — {rec.status or '(unknown)'}",
                     f"  trigger:    {rec.trigger}",
                     f"  finished:   {rec.ts}",
                     f"  duration_s: {rec.duration_s}"]
            if rec.job_uuid:
                lines.append(f"  job_uuid:   {rec.job_uuid}")
            if rec.archive_path:
                lines.append(f"  artifact:   {rec.archive_path}")
            if rec.error:
                lines.append(f"  error:      {rec.error}")
            if rec.git_commits:
                lines.append(f"  git:        {', '.join(str(c) for c in rec.git_commits)}")
            return "\n".join(lines)

        return (f"No run found for run_id '{rid}'. It is not active on the queue and has no history "
                "row — check the id, or the run never started.")

    @mcp.tool()
    def get_job_history(
        job_name: str,
        limit: int = 10,
        history_dir: str = None,
    ) -> str:
        """Return the most recent run records for a named job (newest first).

        Backend-aware: reads HISTORY Type="Run" rows (source of truth) on the FM backend,
        the local JSONL on LocalBackend. The run-record fields are unchanged either way."""
        hdir = Path(history_dir) if history_dir else default_history_dir()
        from corpusfm.storage import get_backend
        _job_uuid = ""
        try:
            _job_uuid = getattr(_load_job(job_name, default_jobs_dir()), "id", "") or ""
        except Exception:
            pass
        runs = list_runs_for(job_name, hdir, limit=limit, backend=get_backend(), job_uuid=_job_uuid)
        if not runs:
            return f"No history for job '{job_name}'."
        lines = [f"History for job '{job_name}' (last {len(runs)} runs):"]
        for r in runs:
            line = f"  {r.ts}  {r.status}  {r.duration_s}s  trigger={r.trigger}"
            if r.archive_path:
                line += f"  archive={r.archive_path}"
            if r.error:
                line += f"  error={r.error[:80]}"
            lines.append(line)
        return "\n".join(lines)


# ── Diff tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def compare(
    artifact_a: str,
    artifact_b: str,
    label_a: str = None,
    label_b: str = None,
) -> str:
    """Compare two archive artifacts and return a plain-text diff summary.

    artifact_a / artifact_b: archive-relative path (e.g. "MyDatabase/2025-01-01_120000")
    or absolute path to an artifact directory.

    Returns a report listing added/removed/changed items per section. Each list is capped
    at the first 25 names with a "…N more" marker so a huge diff can't blow the context (the
    counts stay exact); for the full per-item list use the HTML Diff export or the compare CLI.
    Exit note: if no differences, says so explicitly.
    """
    try:
        art_a = _load_artifact(artifact_a)
        art_b = _load_artifact(artifact_b)
    except Exception as exc:
        return f"ERROR loading artifacts: {exc}"

    label_a_str = label_a or art_a.identity.file_name
    label_b_str = label_b or art_b.identity.file_name
    cr = _compare_artifacts(art_a, art_b)
    if cr.total_real == 0:
        return (
            f"No differences between:\n"
            f"  A: {label_a_str}\n"
            f"  B: {label_b_str}"
        )
    return format_report(cr, section_cap=_COMPARE_SECTION_CAP)


@mcp.tool()
def render_section(
    artifact_path: str,
    section_key: str,
    names_only: bool = False,
    max_chars: int = _DEFAULT_MAX_CHARS,
) -> str:
    """Return human-readable content for all items in one section of an artifact.

    artifact_path: archive-relative or absolute path (same format as compare).
    section_key: catalog key, e.g. ScriptCatalog, CustomFunctionsCatalog,
                 BaseTableCatalog, LayoutCatalog, ValueListCatalog,
                 RelationshipCatalog, BaseDirectoryCatalog.
    names_only:  return just the item names + sizes (a manifest), no bodies — use this
                 first on a large section (e.g. a ScriptCatalog with asset scripts that
                 embed JS libraries), then pull specifics via get_schema_context(focus=
                 [name]) / get_raw_xml.
    max_chars:   cap total output (default 60000). Bodies fill until the budget, then
                 remaining items are listed as omitted; a single oversized item is
                 truncated with a pointer to get_raw_xml. Prevents a multi-MB section
                 from blowing the token ceiling.

    Returns one text block per item, separated by dashes.
    """
    try:
        artifact = _load_artifact(artifact_path)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    in_section = [item for item in artifact.items.values() if item.section == section_key]
    if not in_section:
        known = sorted({item.section for item in artifact.items.values()})
        return (
            f"Section '{section_key}' not found or empty.\n"
            f"Available sections: {', '.join(known) or '(none)'}"
        )
    return _render_section_body(
        section_key, artifact_path, in_section,
        names_only=names_only, max_chars=max_chars,
    )


def _render_section_body(section_key, artifact_label, in_section, *,
                         names_only=False, max_chars=_DEFAULT_MAX_CHARS):
    """Pure, bounded rendering of a section's items (folders excluded).

    Output is capped at `max_chars`: bodies fill greedily, then the rest are listed as
    omitted; a single oversized item is truncated with a pointer to get_raw_xml.
    """
    items = [it for it in in_section if not getattr(it, "is_folder", False)]
    if not items:
        return (f"Section: {section_key}  (only folders, no rendered items)\n"
                f"Artifact: {artifact_label}")

    if names_only:
        lines = [
            f"Section: {section_key}  ({len(items)} items — names only)",
            f"Artifact: {artifact_label}",
            "",
        ]
        for item in sorted(items, key=lambda i: i.name.lower()):
            lines.append(f"  {item.name}  ({len(item.rendered_text or '')} chars)")
        lines.append("")
        lines.append("Pull a specific item with get_schema_context(focus=[name]) or "
                     "get_raw_xml; drop names_only (or raise max_chars) for the bodies.")
        return "\n".join(lines)

    blocks, used, omitted = [], 0, []
    for idx, item in enumerate(items):
        body = item.rendered_text or "(no rendered content)"
        block = f"--- {item.name} ---\n{body}"
        if blocks and used + len(block) > max_chars:
            omitted = [it.name for it in items[idx:]]
            break
        if len(block) > max_chars:
            block = block[:max_chars] + (
                f"\n… [truncated at {max_chars} chars — use get_raw_xml for the full "
                f"'{item.name}']")
        blocks.append(block)
        used += len(block)

    header = f"Section: {section_key}  ({len(items)} items)\nArtifact: {artifact_label}\n"
    out = header + "\n\n".join(blocks)
    if omitted:
        out += (
            "\n\n--- TRUNCATED ---\n"
            f"{len(omitted)} of {len(items)} items omitted to stay under {max_chars} chars. "
            f"Omitted: {', '.join(omitted)}\n"
            "Re-call with names_only=True for the full list, raise max_chars, or fetch a "
            "specific item via get_schema_context(focus=[name]) / get_raw_xml."
        )
    return out


@mcp.tool()
def get_raw_xml(
    artifact_path: str,
    section_key: str,
    item_name: str,
    archive_dir: str = None,
    source_catalog: str = None,
    max_bytes: int = 48_000,
) -> str:
    """Return the raw FM XML string for a named item in a section.

    Useful for AI inspection of element structure or attribute details.

    item_name is matched flexibly: by the item's display name, its FM UUID, or the
    name/id attribute on the stored XML root. This lets you look up an external table
    occurrence by its NUMERIC name (e.g. '432') or any object by id/UUID — which the
    display-name path alone could not resolve.

    RelationshipCatalog is special: a relationship has no name, only a numeric id, so
    item_name ALSO resolves by a participating table-occurrence name or a predicate
    field name it joins on (e.g. 'SalesOrderProducts' or '_ID_PurchaseOrder'). If the
    name matches several relationships, a disambiguation list of ids + join summaries is
    returned; the not-found list shows each relationship's human join string.

    source_catalog: a script (and a few other types) carries MORE than one XML source.
    By default this returns the PRIMARY source (e.g. a script's ScriptCatalog shell —
    id/name/UUID/Options, NOT the steps). Pass source_catalog to fetch a supplemental
    source by its catalog name; if the requested catalog is absent, the available
    catalogs for the matched item are listed. The ordered script steps (Sort Records
    fields/order, Perform Script params, Set Variable calcs) live in 'StepsForScripts' —
    e.g.

        get_raw_xml(artifact_path=..., section_key="ScriptCatalog",
                    item_name="SITC2Acu -- Assemble Data",
                    source_catalog="StepsForScripts")

    For a per-step structured view of a script, prefer get_script_steps.

    max_bytes: cap the returned XML (default 48000 — token-safe for hash-dense XML). A larger blob —
    typically a script's whole un-split 'StepsForScripts' source — is truncated with a marker pointing
    to get_script_steps (which IS bounded and gives a per-step view).
    """
    try:
        artifact = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    def _bounded(xml: str) -> str:
        raw = xml.encode("utf-8")
        if max_bytes is None or len(raw) <= max_bytes:
            return xml
        kept = raw[:max_bytes].decode("utf-8", "ignore")
        return kept + (
            f"\n<!-- … truncated at {max_bytes} bytes of {len(raw)} — for a bounded per-step "
            f"view use get_script_steps; raise max_bytes for more raw XML -->"
        )

    want = str(item_name).strip()

    def _xml_ids(item) -> tuple:
        """(name_attr, id_attr) from the stored XML root, or ('', '')."""
        if not item.xml_sources:
            return ("", "")
        try:
            root = _ET.fromstring(item.xml_sources[0].xml)
        except _ET.ParseError:
            return ("", "")
        return (root.get("name", ""), root.get("id", ""))

    def _matches(item) -> bool:
        if item.section != section_key or item.is_folder:
            return False
        if item.name == want or (item.fm_uuid and item.fm_uuid == want):
            return True
        xname, xid = _xml_ids(item)
        return want in (xname, xid)

    def _rel_tokens(item) -> set:
        """Lowercased matchable tokens for a RelationshipCatalog item: each participating
        table-occurrence name, each predicate field name, and each TO::field pair. A
        relationship has no name attribute (only a numeric id), so this lets one be found
        by a TO or field it joins on — the name a caller actually knows."""
        toks: set = set()
        if not item.xml_sources:
            return toks
        try:
            root = _ET.fromstring(item.xml_sources[0].xml)
        except _ET.ParseError:
            return toks
        for tag in ("LeftTable", "RightTable"):
            ref = root.find(f"./{tag}/TableOccurrenceReference")
            if ref is not None and ref.get("name"):
                toks.add(ref.get("name").lower())
        for fr in root.findall(".//JoinPredicate//FieldReference"):
            fn = fr.get("name") or ""
            if fn:
                toks.add(fn.lower())
            tor = fr.find("TableOccurrenceReference")
            tname = tor.get("name") if tor is not None else ""
            if tname:
                toks.add(tname.lower())
                if fn:
                    toks.add(f"{tname}::{fn}".lower())
        return toks

    def _rel_summary(item) -> str:
        try:
            from corpusfm.core.rendering.section_renderer import render_relationship
            return render_relationship(item.name, item.xml_sources[0].xml).summary
        except Exception:
            return item.name

    matches = [item for item in artifact.items.values() if _matches(item)]
    item = matches[0] if matches else None

    # Relationships carry no name — only a numeric id — so an exact match often misses.
    # Fall back to resolving by a participating TO name / predicate field the caller knows.
    if item is None and section_key == "RelationshipCatalog":
        wl = want.lower()
        fuzzy = [
            it for it in artifact.items.values()
            if it.section == section_key and not it.is_folder and wl in _rel_tokens(it)
        ]
        if len(fuzzy) == 1:
            item = fuzzy[0]
        elif len(fuzzy) > 1:
            lines = [f"  {it.name}: {_rel_summary(it)}" for it in fuzzy[:30]]
            more = "" if len(fuzzy) <= 30 else f"\n  … {len(fuzzy) - 30} more"
            return (
                f"'{item_name}' matches {len(fuzzy)} relationships in '{section_key}'. "
                f"Re-call get_raw_xml with the id (leftmost value below):\n"
                + "\n".join(lines) + more
            )

    if item is None:
        catalog = [
            item for item in artifact.items.values()
            if item.section == section_key and not item.is_folder
        ]
        if section_key == "RelationshipCatalog":
            available = [f"{item.name}: {_rel_summary(item)}" for item in catalog[:20]]
            return (
                f"ERROR: item '{item_name}' not found in section '{section_key}'.\n"
                f"Relationships have no name — address one by its numeric id, or by a "
                f"table-occurrence or field name it joins on. Available (first 20):\n  "
                + "\n  ".join(available)
            )
        available = [item.name for item in catalog][:20]
        # also surface XML name/id so a numeric/id lookup can be retried correctly
        id_hints = []
        for item in catalog[:20]:
            xname, xid = _xml_ids(item)
            if xid and xid != item.name:
                id_hints.append(f"{item.name or xname or '?'}(id={xid})")
        hint = f"\nWith ids: {id_hints}" if id_hints else ""
        return (
            f"ERROR: item '{item_name}' not found in section '{section_key}'.\n"
            f"Available (first 20): {available}{hint}"
        )
    if not item.xml_sources:
        return "(no XML source stored for this item)"
    if source_catalog:
        src = next((s for s in item.xml_sources if s.catalog == source_catalog), None)
        if src is None:
            available = [s.catalog for s in item.xml_sources]
            return (
                f"ERROR: no XML source with catalog '{source_catalog}' on item "
                f"'{item.name}'. Available sources: {', '.join(available)}"
            )
        return _bounded(src.xml)
    return _bounded(item.xml_sources[0].xml)


@mcp.tool()
def get_object(artifact_path: str, name_or_id: str, section: str = None,
               archive_dir: str = None, max_chars: int = _DEFAULT_MAX_CHARS) -> str:
    """Return ONE object's full rendered body + its cross-reference summary — the single-object
    primitive between get_object_evidence (counts only, no body) and get_schema_context
    (whole graph-expanded neighborhoods).

    Use this when you know the object you want and need its actual content (a script's steps, a
    field's calculation, a custom function's formula, a value list's definition) without pulling
    a neighborhood. It is the body that get_object_evidence omits and that get_schema_context's
    focus mode points you to for a 1-hop neighbor.

    name_or_id: matched by exact item_id → exact name → case-insensitive name. `section` scopes
                the match (and disambiguates the same name across catalogs). If nothing matches,
                returns near-miss candidate names; if a name is ambiguous across sections, lists
                the sections to re-call with `section`.

    Returns: a header (name / id / section), a compact xref summary (uses / used by, capped), then
    `--- <name> ---` and the object's full rendered_text. A very large body is truncated at
    max_chars with a pointer to get_raw_xml.
    """
    from corpusfm.core import evidence as ev
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    item = ev.find_artifact_item(art, name_or_id, section=section)
    if item is None:
        q = (name_or_id or "").strip()
        if not section:
            same = sorted({it.section for it in art.items.values()
                           if (it.name or "").lower() == q.lower()})
            if same:
                return (f"{name_or_id!r} matches objects in multiple sections: "
                        f"{', '.join(same)}. Re-call with section=<one of these>.")
        ql = q.lower()
        pool = [it for it in art.items.values()
                if (not section or it.section == section) and not it.is_folder]
        near = sorted({it.name for it in pool if ql and ql in (it.name or "").lower()})
        if not near:
            near = sorted({it.name for it in pool})[:20]
        scope = f" in section {section!r}" if section else ""
        return (f"No object matched {name_or_id!r}{scope} in {artifact_path}.\n"
                f"Candidates: {', '.join(near[:20]) or '(none)'}")

    def _names(records, *, inbound: bool) -> list:
        out: list = []
        for r in records:
            n = (r.from_name or r.from_id) if inbound else (r.to_name or r.to)
            if n and n not in out:
                out.append(n)
        return out

    uses = _names(art.xrefs_from(item.item_id), inbound=False)
    used_by = _names(art.xrefs_to(item.item_id), inbound=True)
    _CAP = 24
    iid = item.attributes.get("id", "?")
    lines = [f"name: {item.name}  id={iid}  item_id={item.item_id}  section: {item.section}"]
    if uses:
        more = f", +{len(uses) - _CAP} more" if len(uses) > _CAP else ""
        lines.append(f"uses ({len(uses)}): {', '.join(uses[:_CAP])}{more}")
    if used_by:
        more = f", +{len(used_by) - _CAP} more" if len(used_by) > _CAP else ""
        lines.append(f"used by ({len(used_by)}): {', '.join(used_by[:_CAP])}{more}")
    lines.append("")
    body = item.rendered_text or "(no rendered content)"
    block = f"--- {item.name} ---\n{body}"
    if len(block) > max_chars:
        block = block[:max_chars] + (
            f"\n… [truncated at {max_chars} chars — use get_raw_xml for the full "
            f"'{item.name}']")
    lines.append(block)
    return "\n".join(lines)


@mcp.tool()
def get_script_steps(artifact_path: str, script: str, archive_dir: str = None,
                     step_filter: str = None, include_xml: bool = False,
                     max_chars: int = _DEFAULT_MAX_CHARS) -> str:
    """Return a script's steps IN FILEMAKER ORDER with per-step detail — the step-level
    primitive beneath get_object (which gives the rendered script as one body) and
    get_raw_xml(source_catalog='StepsForScripts') (which gives the whole un-split XML blob).

    Use this when rendered script text hides behavior — e.g. `Sort Records [ With dialog: Off ]`
    shows no sort fields/order; the fields live in the step's raw XML. Each step block carries:
    its 1-based index (cite it as "step N"), step id, step name, enabled/disabled state, the
    rendered text, and — only when include_xml=True — that step's bounded raw XML.

    script: matched with the same friendly semantics as get_object, scoped to ScriptCatalog.
            On no match, near-name candidates are returned.
    step_filter: case-insensitive substring; a step is kept if it matches by step name,
                 rendered text, or (when present) its raw XML. e.g. step_filter="Sort Records".
    max_chars: output is filled in order up to this bound; omitted trailing steps are noted.
    """
    from corpusfm.core import evidence as ev
    from corpusfm.extensions.export.explorer import _render_script_steps
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    item = ev.find_artifact_item(art, script, section="ScriptCatalog")
    if item is None:
        q = (script or "").strip().lower()
        pool = [it for it in art.items.values()
                if it.section == "ScriptCatalog" and not it.is_folder]
        near = sorted({it.name for it in pool if q and q in (it.name or "").lower()})
        if not near:
            near = sorted({it.name for it in pool})[:20]
        return (f"No script matched {script!r} in ScriptCatalog of {artifact_path}.\n"
                f"Candidates: {', '.join(near[:20]) or '(none)'}")

    step_src = next((s for s in (item.xml_sources or [])
                     if s.catalog == "StepsForScripts"), None)
    if step_src is None:
        available = [s.catalog for s in (item.xml_sources or [])]
        return (f"Script '{item.name}' has no 'StepsForScripts' XML source (no steps stored).\n"
                f"Available sources: {', '.join(available) or '(none)'}")

    schema_ver = art.provenance.catalog_version
    steps, _ = _render_script_steps(step_src.xml, schema_ver)

    raw_steps: list[str] = []
    try:
        root = _ET.fromstring(step_src.xml)
        raw_steps = [_ET.tostring(s, encoding="unicode") for s in root.iter("Step")]
    except _ET.ParseError:
        raw_steps = []

    flt = (step_filter or "").strip().lower()
    iid = item.attributes.get("id", "?")
    kept: list[str] = []
    matched = 0
    for i, st in enumerate(steps):
        raw = raw_steps[i] if i < len(raw_steps) else ""
        name = st.get("step_name", "")
        rendered = st.get("full_text") or st.get("one_line") or ""
        if flt and flt not in name.lower() and flt not in rendered.lower() \
                and flt not in raw.lower():
            continue
        matched += 1
        state = "disabled" if st.get("disabled") else "enabled"
        sid = st.get("step_id", "?")
        lines = [f"[step {i + 1}] id={sid}  name={name or '(unnamed)'}  {state}"]
        if rendered:
            lines.append(f"  {rendered}")
        if include_xml and raw:
            lines.append("  raw XML:")
            lines.append("\n".join("    " + ln for ln in raw.splitlines()))
        kept.append("\n".join(lines))

    filt_note = f"  filter={step_filter!r} → {matched} match(es)" if flt else ""
    header = (f"Script: {item.name}  id={iid}  section: ScriptCatalog\n"
              f"{len(steps)} step(s) total{filt_note}\n")

    out_blocks: list[str] = []
    used = len(header)
    omitted = 0
    for block in kept:
        if used + len(block) + 2 > max_chars:
            if out_blocks:
                omitted = len(kept) - len(out_blocks)
                break
            # A lone first block that alone exceeds max_chars: truncate it (like get_object /
            # render_section) instead of emitting the whole thing — the old `and out_blocks` guard let
            # an oversized step's raw XML through untruncated, which overshot the bound (packet 1152).
            avail = max(0, max_chars - used - 2)
            block = block[:avail] + (
                f"\n… [step truncated at {max_chars} chars — use get_raw_xml for the full step XML]")
            out_blocks.append(block)
            omitted = len(kept) - 1
            break
        out_blocks.append(block)
        used += len(block) + 2

    out = header + "\n\n".join(out_blocks) if out_blocks else \
        header + ("(no steps matched the filter)" if flt else "(no steps)")
    if omitted:
        out += (f"\n\n--- TRUNCATED ---\n{omitted} step(s) omitted to stay under "
                f"{max_chars} chars. Raise max_chars or narrow step_filter.")
    return out


# ── Schema-gap resolution (forward-compat mappings/structure YAML) ──────────────

def _find_step_xml(artifact, step_id) -> str:
    """The raw <Step id=N> element from the artifact's stored XML sources, or ''."""
    needle = f'id="{step_id}"'
    for item in artifact.items.values():
        for src in (item.xml_sources or []):
            xml = getattr(src, "xml", "")
            if needle not in xml or "<Step" not in xml:
                continue
            try:
                root = _ET.fromstring(xml)
            except _ET.ParseError:
                continue
            for step in root.iter("Step"):
                if step.get("id") == str(step_id):
                    return _ET.tostring(step, encoding="unicode")
    return ""


@mcp.tool()
def get_schema_gaps(artifact_path: str, archive_dir: str = None) -> str:
    """Report an artifact's ACTIONABLE schema gaps — FM vocabulary PRESENT in the XML that the
    shipped mappings.yaml / structure_catalog.yaml / rendering.yaml don't handle yet: unknown
    script-step IDs, unknown reference types, unknown catalog sections. (Catalog sections a
    file simply doesn't use are NOT gaps — there is nothing to map.)

    For each gap it names the YAML file to extend, and for unknown step IDs includes the raw
    <Step> XML so you can author the entry. To VALIDATE a proposed adjustment without touching
    the shipped files, pass it to try_schema_yaml — it overlays your candidate in memory and
    re-checks this artifact. A human commits the validated YAML.
    """
    try:
        artifact = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"
    prof = getattr(artifact, "completeness_profile", None)
    if prof is None:
        return "No completeness profile on this artifact."
    g = prof.actionable_gaps()
    ver = getattr(getattr(artifact, "provenance", None), "catalog_version", "") or "?"
    if g["issues"] == 0:
        return (f"No actionable gaps (schema {ver}). Catalog sections this file doesn't use "
                "are not gaps.")
    lines = [f"ACTIONABLE SCHEMA GAPS — schema {ver} — {g['issues']} issue(s)", ""]
    if g["step_ids"]:
        lines.append("Unknown step IDs — extend structure_catalog.yaml (script_steps: name / "
                     f"param_types / block_role) and rendering.yaml (step xpaths): {g['step_ids']}")
        for sid in g["step_ids"]:
            raw = _find_step_xml(artifact, sid)
            if raw:
                lines.append(f"  sample <Step id={sid}>:\n{raw}")
    if g["reference_types"]:
        lines.append("Unknown reference types — extend mappings.yaml (reference_types list): "
                     f"{g['reference_types']}")
    if g["sections"]:
        lines.append(f"Unknown catalog sections — extend mappings.yaml: {g['sections']}")
    lines += ["", "Next: author the additions, then call try_schema_yaml(artifact_path, "
              "structure_yaml=…, mappings_yaml=…) to dry-run them against THIS artifact. Never "
              "edit the shipped YAML directly — iterate until clean, then a human commits it."]
    return "\n".join(lines)


@mcp.tool()
def try_schema_yaml(artifact_path: str, mappings_yaml: str = "", structure_yaml: str = "",
                    archive_dir: str = None) -> str:
    """Breakage-safeguard DRY-RUN for an agent-proposed schema-YAML adjustment. Overlays your
    candidate mappings.yaml / structure_catalog.yaml additions ON TOP of the shipped config IN
    MEMORY (the shipped files are NEVER written) and re-analyzes this artifact's source XML.
    Reports which previously-unknown step IDs / reference types / sections now resolve, plus any
    keys the candidate would CLOBBER (replace existing config — the breakage signal).

    Pass YAML fragments — e.g. structure_yaml='script_steps:\\n  99001:\\n    name: Future Step'.
    Validates against the artifact's STORED gaps (no source-XML retention needed). Iterate until
    the gap resolves with zero clobbers, then hand the validated YAML to a human to commit.
    """
    if not mappings_yaml and not structure_yaml:
        return "ERROR: provide mappings_yaml and/or structure_yaml (the candidate additions)."
    try:
        artifact = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"
    prof = getattr(artifact, "completeness_profile", None)
    if prof is None:
        return "ERROR: artifact has no completeness profile."
    version = getattr(getattr(artifact, "provenance", None), "catalog_version", "") or ""
    from corpusfm.tools.yaml_tryout import try_candidate_against_gaps
    r = try_candidate_against_gaps(
        version,
        unknown_steps=list(getattr(prof, "unknown_step_ids", []) or []),
        unknown_refs=list(getattr(prof, "unknown_reference_types", []) or []),
        mappings=mappings_yaml or None, structure=structure_yaml or None)
    out = [f"TRY SCHEMA YAML — schema {r['schema_version'] or '?'}",
           f"applied cleanly: {r['ok']}" + (f" | resolves all gaps: {r['resolved_all']}"
                                            if r['resolved_all'] is not None else "")]
    if r["errors"]:
        out.append("ERRORS: " + " | ".join(r["errors"]))
    if r["clobbered"]:
        out.append("⚠ WOULD CLOBBER existing config (do NOT commit — additions only): "
                   + " | ".join(r["clobbered"]))
    if r["structure"]:
        out.append(f"structure: resolved step IDs {r['structure']['steps_resolved']}; "
                   f"still unknown {r['structure']['steps_still_unknown']}")
    if r["mappings"]:
        m = r["mappings"]
        out.append(f"mappings: ref types resolved {m['ref_types_resolved']} (still "
                   f"{m['ref_types_still_unknown']}); sections resolved {m['sections_resolved']} "
                   f"(still {m['sections_still_unknown']})")
    return "\n".join(out)


# ── Git export tools ───────────────────────────────────────────────────────────

@mcp.tool()
def list_registrations() -> str:
    """List all configured git export registrations."""
    regs = _list_regs()
    if not regs:
        return "No registrations configured."
    lines = ["Registrations:"]
    for r in regs:
        modes = ", ".join(r.modes) if r.modes else "(none)"
        lines.append(f"  {r.name}  repo={r.repo}  branch={r.branch}  modes={modes}")
    return "\n".join(lines)


# ── Monitor tools (server mode only) ──────────────────────────────────────────

if _SERVER_MODE:
    @mcp.tool()
    def get_health(
        jobs_dir: str = None,
        archive_dir: str = None,
        history_dir: str = None,
    ) -> str:
        """Return current health status: firing alerts + job health summary.

        Use this before running a job or after an unexpected result to check
        whether any known problems exist.
        """
        jdir = Path(jobs_dir) if jobs_dir else default_jobs_dir()
        adir = Path(archive_dir) if archive_dir else get_backend().archive_dir
        hdir = Path(history_dir) if history_dir else default_history_dir()
        config = load_monitor_config()

        firing = check_conditions(jdir, hdir, adir, config)
        health = get_job_health(jdir, config)

        lines = []
        if not firing:
            lines.append("Alerts: all clear")
        else:
            lines.append(f"Alerts: {len(firing)} active")
            for a in firing:
                lines.append(f"  [{a.severity}] {a.condition}: {a.message}")

        lines.append("")
        lines.append("Job health:")
        if not health:
            lines.append("  (no jobs)")
        else:
            for r in health:
                overdue = "  OVERDUE" if r.overdue else ""
                status = r.last_status or "never run"
                ts = r.last_run_ts.replace("T", " ")[:16] if r.last_run_ts else "—"
                lines.append(f"  {r.name}  {status}  {ts}{overdue}")

        return "\n".join(lines)

    @mcp.tool()
    def list_alerts(
        limit: int = 20,
    ) -> str:
        """Return recent alert history, newest first."""
        events = load_alert_history(limit=limit)
        if not events:
            return "No alerts recorded."
        lines = [f"Recent alerts ({len(events)}):"]
        for e in events:
            ts = e.ts.replace("T", " ")[:19]
            job = f"  job={e.job_name}" if e.job_name else ""
            lines.append(f"  {ts}  [{e.severity}] {e.condition}{job}: {e.message}")
        return "\n".join(lines)

    @mcp.tool()
    def acknowledge_alert(
        condition: str,
        job_name: str = None,
        hours: int = None,
    ) -> str:
        """Suppress a named alert condition for N hours (default: from monitor config).

        condition: one of job_failed, job_overdue, zero_diff_suspicion,
                   scheduler_stopped, disk_low
        job_name: required for job-specific conditions (job_failed, job_overdue, zero_diff_suspicion)
        hours: override the default suppress window from config
        """
        config = load_monitor_config()
        h = hours if hours is not None else config.suppress_hours
        suppress_alert(condition, job_name or None, h)
        job_part = f" for job '{job_name}'" if job_name else ""
        return f"Alert '{condition}'{job_part} suppressed for {h} hours."


@mcp.tool()
def export_to_git(
    artifact_path: str,
    registration: str,
) -> str:
    """Export an artifact to a named git registration.

    Loads the artifact, renders it as structured/rendered text files,
    and commits to the registration's git repo.

    Returns the commit SHA if changes were made, or 'no changes' if nothing changed.
    """
    try:
        artifact = _load_artifact(artifact_path)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    try:
        er = export_artifact_to_registration(artifact, registration)
    except Exception as exc:
        return f"ERROR during export: {exc}"

    if er.commit_sha:
        return (
            f"Exported to registration '{registration}'.\n"
            f"Commit: {er.commit_sha}\n"
            f"Files written: {er.files_written}\n"
            f"Files deleted: {er.files_deleted}"
        )
    return f"No changes — registration '{registration}' is already up to date."


# ── Semantic search (vector index) ────────────────────────────────────────────

@mcp.tool()
def index_artifact(
    artifact_path: str,
    replace_existing: bool = True,
    archive_dir: str = None,
) -> str:
    """Enqueue an INDEX job for an artifact — the semantic-search substrate.

    Indexing is what enables semantic_search and MCP retrieval; it embeds each object's deterministic
    rendered text and needs NO AI summaries (packet 1006). Enrichment runs on the server's single FIFO
    queue (one job at a time; minutes for big files), so this ENQUEUES and returns a job id + position
    rather than blocking. Poll get_queue for status, then semantic_search once it's done. Re-running
    refreshes the raw layer in place.

    artifact_path:    archive-relative or absolute path (same format as get_schema_context).
    replace_existing: kept for compatibility; the queue upserts per item (re-indexing overwrites).
    archive_dir:      override archive directory (optional).
    """
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index

    adir = Path(archive_dir) if archive_dir else None
    from corpusfm.storage import get_backend
    try:
        uuid = _artifact_uuid(artifact_path, adir)
    except Exception as exc:
        return f"ERROR: {exc}"
    # Validate the record exists + is indexable via its META (not _load_artifact — a DELIVERABLE has
    # no parsed Artifact; packet 1035 indexes fmClip/fmScript/fmCalc via their text). PatchXML has no
    # searchable content.
    meta = get_backend(adir).get_artifact_meta(uuid)
    if meta is None:
        return f"ERROR: no artifact found for {artifact_path!r}. Re-import this snapshot."
    atype = getattr(meta, "artifact_type", "")
    if not (getattr(meta, "is_schema", False) or atype in ("fmClip", "fmScript", "fmCalc")):
        return (f"{atype or 'This record'} is not indexable — only schema artifacts and "
                "fmClip/fmScript/fmCalc deliverables can be added to the search index.")
    if get_vector_index(load_app_config()) is None:
        return (
            "Vector index is not configured. "
            "Set an OpenAI-compatible embedding endpoint in Settings → Integrations."
        )

    from corpusfm.server import queue_handlers
    from corpusfm.storage.queue_record import INDEX
    qid = queue_handlers.enqueue_enrichment_steps(get_backend(), uuid, [INDEX], owner=_mcp_actor())
    if not qid:
        return f"An index job for {uuid} is already queued or running. Use get_queue to check status."
    return (
        f"Enqueued index job for {uuid}.\n  Queue record: {qid}\n"
        "\nUse get_queue to check status; semantic_search once it finishes."
    )


@mcp.tool()
def deindex_artifact(
    artifact_path: str,
    archive_dir: str = None,
) -> str:
    """Remove ONE artifact from the semantic-search index — the per-artifact inverse of index_artifact.

    Keyed by the artifact's record uuid, so sibling versions + any same-named file are untouched (the
    index is per-artifact, independent). Unlike indexing, de-index is sub-second, so it runs IMMEDIATELY
    (not via the queue) and returns the count of vectors removed. After this the artifact no longer appears
    in semantic_search until re-indexed.

    artifact_path: archive-relative or absolute path (same format as index_artifact).
    archive_dir:   override archive directory (optional).
    """
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index

    adir = Path(archive_dir) if archive_dir else None
    try:
        _load_artifact(artifact_path, adir)   # validate it exists before acting
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"
    idx = get_vector_index(load_app_config())
    if idx is None:
        return (
            "Vector index is not configured. "
            "Set an OpenAI-compatible embedding endpoint in Settings → Integrations."
        )
    from corpusfm.storage import get_backend
    uuid = _artifact_uuid(artifact_path, adir)
    meta = get_backend().get_artifact_meta(uuid) if uuid else None
    if meta is None or not meta.file_name:
        return f"ERROR: could not resolve the FM file for artifact {artifact_path}."
    removed = idx.delete_artifact(uuid)
    return f"De-indexed {meta.file_name} — removed {removed} vector(s) from the search index."


@mcp.tool()
def summarize_artifact(
    artifact_path: str,
    replace_existing: bool = False,
    archive_dir: str = None,
) -> str:
    """Enqueue a SUMMARIZE job (AI one-line summaries) for an artifact — the chat-model enrichment.

    Summaries are OPTIONAL descriptive enrichment — they do NOT enable search; indexing does (packet
    1006). semantic_search works on an indexed artifact whether or not it has summaries. The way to
    summarize LATER (import is fast, no inline AI). One chat call per object (minutes on large files),
    so this ENQUEUES on the server's FIFO queue and returns a job id + position rather than blocking.
    Writes the summaries.json sidecar that git export and MCP read. If an embedder is configured, an
    additive summary-layer index step is enqueued when summaries finish — it enriches the index as an
    extra layer and NEVER re-indexes or stales the raw search substrate. Poll get_queue for status.

    Needs an AI summary (chat) provider in Settings → Integrations — independent of the embedder.
    replace_existing: kept for compatibility; a summarize job always (re)writes the sidecar.
    """
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai import summary_provider_ready

    adir = Path(archive_dir) if archive_dir else None
    try:
        _load_artifact(artifact_path, adir)   # validate it exists before enqueuing
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"
    if not summary_provider_ready(load_app_config()):
        return (
            "No AI summary (chat) provider configured. "
            "Set a chat model in Settings → Integrations → AI summaries."
        )

    from corpusfm.server import queue_handlers
    from corpusfm.storage import get_backend
    from corpusfm.storage.queue_record import SUMMARIZE
    uuid = _artifact_uuid(artifact_path, adir)
    qid = queue_handlers.enqueue_enrichment_steps(get_backend(), uuid, [SUMMARIZE], owner=_mcp_actor())
    if not qid:
        return f"A summarize job for {uuid} is already queued or running. Use get_queue to check status."
    return (
        f"Enqueued summarize job for {uuid}.\n  Queue record: {qid}\n"
        "\nUse get_queue to check status."
    )


@mcp.tool()
def get_queue() -> str:
    """Show the server enrichment queue — the system-wide view of background AI/index work.

    Summaries take minutes, and the queue runs one job at a time, so this is how you see what's
    running and what's holding up the line: the RUNNING job (kind + live progress), the QUEUED
    line in order, and any FAILED jobs (with their error). Owner is attributed per job.
    """
    from corpusfm.server import queue_handlers
    from corpusfm.storage import get_backend
    be = get_backend()
    recs = queue_handlers.workspace_view(be)
    running = [r for r in recs if r["status"] == "running"]
    queued  = [r for r in recs if r["status"] == "queued"]
    failed  = [r for r in recs if r["status"] == "failed"]

    def _elapsed(ts: str) -> str:
        # How long a RUNNING job has been going (packet 1036) — best-effort; "" on any parse issue so
        # the queue view never breaks. Answers slow-vs-stuck without a progress %.
        from datetime import datetime, timezone
        s = (ts or "").strip()
        if not s:
            return ""
        dt = None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%d_%H%M%S_%f", "%Y-%m-%d_%H%M%S"):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return ""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        secs = int((datetime.now(timezone.utc) - dt).total_seconds())
        if secs < 0:
            return ""
        human = f"{secs}s" if secs < 60 else (f"{secs // 60}m{secs % 60:02d}s" if secs < 3600
                                              else f"{secs // 3600}h{(secs % 3600) // 60:02d}m")
        return f"  · running {human}"

    def _line(r: dict) -> str:
        trail = " > ".join(("[" + s + "]" if s == r["current"] else s) for s in (r.get("steps") or []))
        tgt = (r.get("target") or "").strip()
        kind = " + ".join(r.get("kinds") or []) or "queued"
        return (f"{kind}{(' — ' + tgt) if tgt else ''} · {trail or r.get('current','')} "
                f"[owner {r.get('owner')}] id={r.get('id')}")

    lines: list[str] = []
    lines.append(f"RUNNING ({len(running)}):" if running else "RUNNING: (idle)")
    for r in running:
        lines.append("  " + _line(r) + _elapsed(r.get("created_at")))
    lines.append(f"QUEUED ({len(queued)}):")
    for i, r in enumerate(queued, 1):
        lines.append(f"  {i}. " + _line(r))
    if failed:
        lines.append(f"FAILED ({len(failed)}):")
        for r in failed:
            lines.append("  " + _line(r) + f" — {(r.get('error') or '')[:140]}")
    return "\n".join(lines)


@mcp.tool()
def semantic_search(
    query: str,
    top_k: int = 5,
    file_name: str = None,
    ref: str = None,
    archive_dir: str = None,
) -> str:
    """Search all indexed items (schema objects AND indexed deliverables) using a natural language query.

    Returns the top matching items (scripts, CFs, tables, layouts, indexed clips, etc.) from any indexed
    snapshot. Embeddings are generated via the configured OpenAI-compatible endpoint (Settings → Integrations).

    Args:
        query:     Natural language description (e.g. "script that sends email notifications")
        top_k:     Number of results to return (default 5, max 20)
        file_name: Limit results to a specific FM file name (optional)
        ref:       Scope the search to ONE record — its record UUID / primary name / any resolvable
                   ref (packet 1036). Use it to confirm/inspect what a SINGLE artifact contributed to
                   the index (e.g. a stored clip whose content otherwise clusters with a schema copy).

    Returns a ranked list with file, section, item name, the evidence layer (object_raw =
    deterministic rendered text; object_summary = an optional AI-summary layer), and the indexed
    snippet. Search works from the raw layer alone — no summaries required; when a summary layer
    exists it can additionally match and is labelled as such.
    """
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index

    app_cfg = load_app_config()
    index = get_vector_index(app_cfg)
    if index is None:
        return (
            "Vector index is not configured. "
            "Set an OpenAI-compatible embedding endpoint in Settings → Integrations, "
            "or set the AI_SUMMARY_API_KEY / OPENAI_API_KEY environment variable."
        )

    count = index.count()
    if count == 0:
        return (
            "Vector index is empty. Import with indexing enabled, run a job with index_on_ingest, "
            "or call index_artifact(artifact_path) to index a specific artifact — no summaries needed."
        )

    scope_uuid = None
    if ref:
        try:
            scope_uuid = _artifact_uuid(ref, Path(archive_dir) if archive_dir else None)
        except Exception as exc:
            return f"ERROR resolving ref: {exc}"

    top_k = max(1, min(top_k, 20))
    try:
        results = index.search(query, top_k=top_k, file_name=file_name or None, uuid=scope_uuid)
    except Exception as exc:
        return f"ERROR searching index: {exc}"

    if not results:
        return "No results found."

    out = [f"Top {len(results)} result(s) for: {query!r}\n"]
    for i, r in enumerate(results, 1):
        dist = f"{r['distance']:.3f}" if r.get("distance") is not None else "?"
        layer = r.get("layer") or "object_raw"
        out.append(
            f"{i}. [{r['folder_name']}] {r['item_name']}\n"
            f"   File: {r['file_name']}  Snapshot: {r['timestamp']}  Distance: {dist}  Layer: {layer}\n"
            f"   {r['document'][:120]}{'...' if len(r['document']) > 120 else ''}"
        )
    return "\n".join(out)


@mcp.tool()
def get_index_status(ref: str, archive_dir: str = None) -> str:
    """Is one artifact in the semantic-search index, and how many docs? (packet 1036)

    The catalog's `indexed` badge over MCP: resolve ref (record UUID / primary name / any resolvable
    ref) and report its indexed doc counts by layer (raw = the search substrate; summary = the optional
    AI layer). Use it to confirm index_artifact actually wrote docs without inferring from search rank.
    """
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index
    from corpusfm.storage import get_backend
    adir = Path(archive_dir) if archive_dir else None
    try:
        uuid = _artifact_uuid(ref, adir)
    except Exception as exc:
        return f"ERROR: {exc}"
    meta = get_backend(adir).get_artifact_meta(uuid)
    if meta is None:
        return f"ERROR: no artifact found for {ref!r}."
    index = get_vector_index(load_app_config())
    if index is None:
        return "Vector index is not configured (Settings → Integrations)."
    st = index.index_status(uuid)
    name = getattr(meta, "name", "") or getattr(meta, "file_name", "") or uuid
    atype = getattr(meta, "artifact_type", "")
    indexable = getattr(meta, "is_schema", False) or atype in ("fmClip", "fmScript", "fmCalc")
    if st["total"] == 0:
        tail = " Index it with index_artifact." if indexable else " This type is not indexable."
        return f"{name} ({atype}) — NOT indexed (0 docs).{tail}\n  uuid: {uuid}"
    return (f"{name} ({atype}) — INDEXED.\n"
            f"  uuid:                        {uuid}\n"
            f"  raw docs (search substrate): {st['raw']}\n"
            f"  summary docs (AI layer):     {st['summary']}\n"
            f"  total:                       {st['total']}")


@mcp.tool()
def get_server_info() -> str:
    """Version + capability info about this CORPUSfm server (packet 1036).

    Reports the running CORPUSfm version (0.<git-commit-count>), the deployment mode, how many MCP
    tools this server exposes, the supported FileMaker version window, and whether the semantic-search
    index is configured. Use it to confirm exactly which build you are talking to.
    """
    from corpusfm import __version__
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index
    try:
        n_tools = len(_TOOL_GATES)
    except Exception:
        n_tools = "?"
    try:
        idx_on = get_vector_index(load_app_config()) is not None
    except Exception:
        idx_on = False
    return "\n".join([
        f"CORPUSfm {__version__}",
        f"  mode:         {'co-located server' if _SERVER_MODE else 'local (dev/test)'}",
        f"  MCP tools:    {n_tools} (co-located; fewer register in local mode)",
        "  FM support:   FM 21+ (schema 2.2.0.0–2.3.0.0; FM 2026 first-class)",
        f"  search index: {'configured' if idx_on else 'not configured'}",
    ])


# ── Temporal diff ─────────────────────────────────────────────────────────────

@mcp.tool()
def temporal_diff(
    job_name: str,
    days: int = 30,
    since: str = None,
    archive_dir: str = None,
    history_dir: str = None,
) -> str:
    """Compare what changed in an FM file between two points in time.

    Finds the oldest and most recent successful job runs within the time window,
    loads both artifacts, and returns a structured diff summary.

    Args:
        job_name:    Name of the job whose history to query
        days:        Look back this many days (default 30). Ignored if 'since' is set.
        since:       ISO date or datetime string for start of window (e.g. "2026-01-01")
        archive_dir: Override archive directory (optional)
        history_dir: Override history directory (optional)

    Returns a section-by-section summary of added/removed/changed items.
    """
    from datetime import datetime, timezone, timedelta
    from corpusfm.server.jobs.history import list_runs_for, default_history_dir
    from corpusfm.server.jobs.store import default_jobs_dir, load_job as _load_job
    from corpusfm.storage import get_backend

    hdir = Path(history_dir) if history_dir else default_history_dir()
    adir = Path(archive_dir) if archive_dir else None

    _job_uuid = ""
    try:
        _job_uuid = getattr(_load_job(job_name, default_jobs_dir()), "id", "") or ""
    except Exception:
        pass
    runs = list_runs_for(job_name, hdir, limit=500, backend=get_backend(), job_uuid=_job_uuid)
    ok_runs = [r for r in runs if r.status == "ok" and r.archive_path]

    if not ok_runs:
        return f"No successful runs found for job '{job_name}'."

    now = datetime.now(timezone.utc)
    if since:
        try:
            cutoff = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        except ValueError:
            return f"ERROR: 'since' value {since!r} is not a valid ISO date/datetime."
    else:
        cutoff = now - timedelta(days=days)

    in_window = [r for r in ok_runs if r.ts >= cutoff.isoformat(timespec="seconds")]

    if len(in_window) < 2:
        oldest_ts = ok_runs[-1].ts if ok_runs else "?"
        return (
            f"Not enough artifacts in the window for job '{job_name}'.\n"
            f"Window start: {cutoff.date()}. Oldest available run: {oldest_ts}.\n"
            f"Widen the window (increase 'days' or set an earlier 'since') to include more history."
        )

    newest_run = in_window[0]
    oldest_run = in_window[-1]

    def _load(run):
        # Backend-agnostic: run.archive_path is the artifact rel_path, loaded via
        # the active StorageBackend (works for the local archive AND the FM OData
        # backend, where artifacts live in container fields, not on local disk).
        return _load_artifact(run.archive_path, adir)

    try:
        art_old = _load(oldest_run)
        art_new = _load(newest_run)
    except Exception as exc:
        return f"ERROR loading artifacts: {exc}"

    try:
        cr = _compare_artifacts(art_old, art_new)
    except Exception as exc:
        return f"ERROR comparing artifacts: {exc}"

    if cr.total_real == 0:
        return (
            f"No changes in '{job_name}' between {oldest_run.ts[:10]} and {newest_run.ts[:10]}."
        )

    result_lines = [
        f"Changes in '{job_name}' between {oldest_run.ts[:10]} and {newest_run.ts[:10]}",
        f"Total changes: {cr.total_real}",
        "",
    ]

    def _section_lines(label, sr):
        if sr.total == 0:
            return []
        out = [f"{label}:  +{len(sr.added)} added  -{len(sr.removed)} removed  ~{len(sr.changed)} changed"]
        if sr.added:
            out.append(f"  Added:   {', '.join(sr.added[:10])}{'...' if len(sr.added) > 10 else ''}")
        if sr.removed:
            out.append(f"  Removed: {', '.join(sr.removed[:10])}{'...' if len(sr.removed) > 10 else ''}")
        if sr.changed:
            out.append(f"  Changed: {', '.join(sr.changed[:10])}{'...' if len(sr.changed) > 10 else ''}")
        return out

    for section_key, sr in cr.sections.items():
        result_lines.extend(_section_lines(section_key, sr))
    for table_name, sr in cr.fields.items():
        if sr.total:
            result_lines.extend(_section_lines(f"Fields [{table_name}]", sr))

    return "\n".join(result_lines)


# ── Schema context ─────────────────────────────────────────────────────────────

@mcp.tool()
def get_schema_context(
    artifact_path: str,
    connected_paths: list = None,
    archive_dir: str = None,
    focus: list = None,
    focus_neighbor_bodies: bool = False,
    max_chars: int = None,
) -> str:
    """Return a compact, ID-explicit schema context for AI write-path use.

    Provides all FM object names + internal IDs needed to generate valid
    fmClip XML targeting this specific FM file: table occurrences, base
    tables + fields, scripts, layouts, value lists, custom functions, and
    external data sources.

    artifact_path:   archive-relative or absolute artifact path.
    connected_paths: additional artifact paths for connected files (optional).
    archive_dir:     override archive directory (optional).
    focus:           optional list of object names/ids to deep-dive. Each seed is
                     graph-expanded one hop through the cross-reference map and a
                     FOCUS DETAIL section renders each object's signature (header +
                     uses/used-by). By default the full BODY (script step bodies,
                     field/CF/value-list bodies, layout objects) renders for the
                     SEEDS only; the 1-hop NEIGHBORS show signature plus a pointer
                     to fetch their body (a hub seed can have dozens of neighbors,
                     and dumping every body blows the token ceiling). The rest of
                     the context stays a bounded symbol table. Seed from
                     semantic_search results.
    focus_neighbor_bodies: when True, also render the full body of every 1-hop
                     neighbor, not just the seeds. Default False.
    max_chars:       optional running budget on the FOCUS DETAIL body emission.
                     Seed bodies are emitted first; once the accumulated body
                     output would exceed max_chars, remaining bodies are dropped
                     and their items listed by name with a get_object pointer.
                     None = no cap. Use it to keep a wide neighborhood inside a
                     token ceiling. Per-object lines/signatures are unaffected.
    """
    adir = Path(archive_dir) if archive_dir else None
    try:
        artifact = _load_artifact(artifact_path, adir)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    out = [_build_schema_context(
        artifact, artifact_path, focus=focus,
        focus_neighbor_bodies=focus_neighbor_bodies, max_chars=max_chars)]

    if connected_paths:
        for cp in connected_paths:
            try:
                cp_art = _load_artifact(cp, adir)
                out.append("")
                out.append(f"=== Connected: {cp} ===")
                out.append(_build_schema_context(cp_art, cp))
            except Exception as exc:
                out.append(f"\n[connected: {cp}]  ERROR: {exc}")

    return "\n".join(out)


def _build_schema_context(artifact, label: str = "", *, focus: list = None,
                          focus_neighbor_bodies: bool = False, max_chars: int = None) -> str:
    from corpusfm.server.ai.schema_context import build_schema_context
    return build_schema_context(
        artifact, label, focus=focus,
        focus_neighbor_bodies=focus_neighbor_bodies, max_chars=max_chars)


# ── FMUpgradeTool capability ledger ───────────────────────────────────────────

@mcp.tool()
def get_patch_authoring_guide() -> str:
    """The full FMUpgradeToolPatch AUTHORING guide — for composing a patch yourself.

    CORPUSfm has no in-app AI patch generator; interactive authoring is YOUR job over MCP.
    This returns the complete authoring guidance: the three action types (AddAction /
    ReplaceAction / DeleteAction) with XML examples, the CONSTRUCTION grammar for building
    fields, table occurrences + relationships, and layouts with buttons, and the
    capability-ledger limits — the same guidance the removed in-app harness used.

    Typical loop: get_schema_context (the target) → get_patch_authoring_guide (how) →
    compose the FMUpgradeToolPatch XML → check_patch (verify) → save_ai_patch (store).
    """
    from corpusfm.server.ai.patch_ai import _SYSTEM_PROMPT
    return _SYSTEM_PROMPT


@mcp.tool()
def get_ai_build_guide() -> str:
    """The END-TO-END orchestration guide for building a feature into a FileMaker file.

    One level up from get_patch_authoring_guide (the patch XML grammar): this is the
    GOAL -> verified, applied change loop — discover (get_schema_context / semantic_search)
    -> ground (get_patch_capabilities / get_patch_authoring_guide / get_step_exemplar) ->
    author -> check_patch -> save_ai_patch -> dry_run_patch -> apply_patch ->
    reimport_after_patch -> verify_patch_applied / compare. Start here when you have a goal
    but don't yet know which tools to drive in what order.
    """
    from corpusfm.server.ai.patch_ai import _AI_BUILD_GUIDE
    return _AI_BUILD_GUIDE


@mcp.tool()
def get_step_exemplar(
    query: str,
    tag: str = None,
    limit: int = 3,
    artifact_path: str = None,
    archive_dir: str = None,
    max_chars: int = _DEFAULT_MAX_CHARS,
    compact: bool = False,
) -> str:
    """Return real, VERIFIED-WORKING step sequences from the corpus as adapt-ready templates.

    Authoring needs OBJECT/STEP-level grounding — get_patch_capabilities warns "do not
    hand-invent a step's parameter XML", and semantic_search finds FILES. This finds
    SCRIPTS whose steps match `query` (e.g. "open card window", "loop over JSON array") and
    returns their real step sequence with the volatile bits (field / script / layout refs,
    literals) replaced by typed {placeholders}, plus the source artifact + object.

    query:         what the steps should do (matched against script name, summary, body).
    tag:           optional — restrict to files carrying this tag (e.g. "seed", "pattern").
    artifact_path: optional — search just this one artifact instead of the whole corpus.
    limit:         max exemplars to return (default 3).
    max_chars:     cap total output (default 60000). Exemplars fill greedily; the rest are
                   listed by name with a pointer to narrower retrieval — a whole-script
                   exemplar's sanitized XML is large, so an uncapped multi-match could
                   otherwise overrun the caller's tool-output budget.
    compact:       readable step shapes only — drop the (large) sanitized step-XML block.
                   Use when you want step *shapes*, not whole scripts.

    Complements get_patch_authoring_guide (grammar) and the STRUCTURE CATALOG block in
    get_schema_context (per-step-id templates).
    """
    from corpusfm.server.ai.exemplars import find_step_exemplars, render_exemplars
    adir = Path(archive_dir) if archive_dir else None

    items = []
    if artifact_path:
        scope = f"artifact {artifact_path}"
        try:
            art = _load_artifact(artifact_path, adir)
        except Exception as exc:
            return f"ERROR loading artifact: {exc}"
        items = [(artifact_path, it) for it in art.items.values()]
    else:
        backend = get_backend(adir)
        latest_metas = _latest_per_file(backend)
        if not latest_metas:
            return "Archive is empty."
        want = (tag or "").strip().lower()
        scope = f'tag="{tag}"' if want else "all files"
        try:
            from corpusfm.server.tags import load_tags
            tags_map = load_tags()
        except Exception:
            tags_map = {}
        MAX_SCAN = 60
        scanned = 0
        capped = False
        for latest in sorted(latest_metas, key=lambda m: m.file_name):
            if want and want not in {t.lower() for t in tags_map.get(latest.uuid, [])}:
                continue
            if not getattr(latest, "is_schema", True):
                continue
            if scanned >= MAX_SCAN:
                capped = True
                break
            scanned += 1
            try:
                art = backend.load_artifact(latest.uuid)   # UUID-addressed (packet 085 U3f)
            except Exception:
                continue
            items.extend((file_name, it) for it in art.items.values())
        if capped:
            scope += f" (scanned first {MAX_SCAN} files; narrow with a tag for full coverage)"

    exemplars = find_step_exemplars(items, query, limit=limit)
    return render_exemplars(exemplars, query, scope, max_chars=max_chars, compact=compact)


@mcp.tool()
def get_patch_capabilities() -> str:
    """What an FMUpgradeToolPatch CAN and CANNOT do — verified live, version-tagged.

    Call this BEFORE composing a patch (generate_patch / save_ai_patch) so the
    patch respects FMUpgradeTool's real, tested behavior and limits — e.g. you
    cannot insert a script into a folder that already exists in the target file;
    a new folder needs its open AND close markers in document order. Behavior is
    tool-version-specific; each claim is tagged with the build it was verified on,
    and OPEN QUESTIONS are not yet verified — do not rely on them.
    """
    from corpusfm.extensions.export.capabilities import (
        load_capabilities, render_capability_guidance,
    )
    led = load_capabilities()
    lines = [render_capability_guidance(led), "", "VERIFICATION:"]
    for e in led.entries:
        ver = f" (tool {e.tool_version})" if e.tool_version else ""
        lines.append(f"  [{e.status}/{e.verified_via or '—'}] {e.title}{ver}")
    if led.open_questions:
        lines.append("")
        lines.append("OPEN QUESTIONS (not yet verified — do not rely on):")
        for q in led.open_questions:
            lines.append(f"  - {q.question}")
    return "\n".join(lines)


@mcp.tool()
def get_artifact_types() -> str:
    """The artifact TYPES the catalog holds and what each one supports (packet 033).

    Call this to learn which kinds of FileMaker things CORPUSfm can store and how each behaves —
    so an agent knows, e.g., that a SaveAsXML schema artifact supports Explorer/Diff/xref while an
    fmscript / fmcalc / fmclip is a low-fidelity text/clip tenant it can store + retrieve but not
    run schema lenses on. Capabilities: download, view, index (semantic search), explorer,
    diff (same-type-only), merge, xref, git_export, patch_ops, mcp_save. Download is universal.
    """
    from corpusfm.artifact.capabilities import capability_matrix
    notes = {
        "SaveAsXML": "full FileMaker schema export — the gold-standard analysis artifact",
        "AddonXML": "an FM add-on package; merges with a SaveAsXML into a MergedXML",
        "MergedXML": "SaveAsXML + AddonXML resolved together — richest schema view",
        "PatchXML": "an FMUpgradeToolPatch deliverable (validate/encrypt/apply via patch_ops)",
        "fmClip": "an fmClip — a copy/paste FMObjectList clip (one or more objects)",
        "fmScript": "a single FileMaker script as fmscript.org text (store/view/export)",
        "fmCalc": "a single FileMaker calculation as FM calc-expression text (store/view/export)",
    }
    lines = ["ARTIFACT TYPES — what each can do (download is universal):", ""]
    for t, caps in capability_matrix().items():
        lines.append(f"  {t}: {', '.join(caps)}")
        if t in notes:
            lines.append(f"      {notes[t]}")
    lines += ["", "Unknown types fall back to {download} only; reabsorb rejects what it can't "
              "understand. diff is same-type-only; merge is schema-types-only (not already-merged)."]
    return "\n".join(lines)


# ── Re-import after patch ─────────────────────────────────────────────────────

@mcp.tool()
def reimport_after_patch(
    database: str,
    job_uuid: str,
    archive_dir: str = None,
) -> str:
    """Post-patch VERIFY: re-import a FM file's schema right after you applied a patch to it.

    This is the *verify* leg of the generate → apply → verify loop — NOT the general artifact-refresh
    interface. For a normal, scheduled, or manual pull of a hosted file, use a configured **Job**
    (list_jobs → run_job → get_job_run): a Job owns the source method, credentials, schedule, and
    owner file. Reach for this tool only to confirm that a patch you just applied produced a healthy,
    parseable file, when standing up a Job for an arbitrary just-patched database would be overkill.

    It calls CFM.TOOLS.ExportSchemaXML.SaveToDocumentsFolder on the target database (on the co-located
    FileMaker server) via OData, reads the exported XML from the local filesystem, and lands it as a
    new artifact — returning an artifact SUMMARY (identity/metrics), never raw XML.

    QUEUE policy (packet 1058 P1): CORPUSfm routes normal ingestion through the QUEUE workspace. This
    helper is a deliberate, NARROW **synchronous exception** — the verify step must return the new
    artifact identity in-line, and verifying an arbitrary just-patched file must not require a
    pre-configured Job or a queue round-trip. To avoid a *competing* ingestion pipeline it does NOT
    hand-roll its own ingest+store: the landing reuses the shared 077-E path
    (`ingest_import_bytes` → the same parse → store → discovery-log every import/pull/push lands
    through). The only inline-vs-queue divergence is that this path is synchronous by design.

    Requires:
    - CORPUSfm and FileMaker Server running on the same machine
    - The SaveToDocumentsFolder script enabled in the CORPUSfm addon on the target
      database (it is the default-enabled script — no configuration needed
      unless it was manually disabled)

    Returns a summary including the new artifact's uuid, which can be used
    as the new baseline for subsequent patch generation.
    """
    import time as _time
    from corpusfm.server.jobs.store import find_job_by_id, get_job_credential
    from corpusfm.server.fms_transport import colocated
    from corpusfm.server.fms_client import pull_fms_save_to_documents, FMSError
    from corpusfm.storage import get_backend
    from corpusfm.server.apply_metrics import metrics_log_path, record_step

    job = find_job_by_id(job_uuid)
    if job is None or (getattr(job.source, "server_ref", None) or "local") != "local":
        return "ERROR: job_uuid does not identify a current co-located tracked-file job."
    if (job.file or "").removesuffix(".fmp12").casefold() != database.removesuffix(".fmp12").casefold():
        return "ERROR: job_uuid does not own the requested FileMaker database."
    credential = get_job_credential(job.name)
    if not credential or not credential.get("account") or not credential.get("password"):
        return "ERROR: the target Job has no usable file credential."
    try:
        transport = colocated()
    except Exception as exc:
        return f"ERROR: installed FileMaker transport is unavailable: {exc}"
    credentials = {"username": credential["account"], "password": credential["password"]}
    backend = get_backend(Path(archive_dir) if archive_dir else None)

    label = database.removesuffix(".fmp12")

    # Verify step of the generate->apply->verify loop: the re-export + re-ingest
    # that confirms the patch produced a healthy, parseable file. Instrumented so
    # the thermometer captures the verify cost alongside apply.
    _adir = getattr(backend, "archive_dir", None)
    _metrics = metrics_log_path(_adir) if _adir is not None else None
    _t0 = _time.perf_counter()

    def _rec(ok: bool, output: str = "") -> None:
        record_step("verify", _time.perf_counter() - _t0, ok,
                    database=label, output=output, metrics_path=_metrics)

    try:
        xml_bytes = pull_fms_save_to_documents(
            transport.host, database, credentials, verify_ssl=transport.verify_ssl
        )
    except FMSError as exc:
        _rec(False, str(exc))
        return (
            f"ERROR: Could not run SaveToDocumentsFolder on '{database}': {exc}\n\n"
            "Ensure the CORPUSfm addon is installed in the target database and "
            "the SaveToDocumentsFolder script is enabled."
        )
    except FileNotFoundError as exc:
        _rec(False, str(exc))
        return (
            f"ERROR: {exc}\n\n"
            "This operation requires CORPUSfm to be running on the same machine "
            "as FileMaker Server."
        )

    # Land via the SHARED 077-E path (parse → store → discovery-log), not a hand-rolled ingest+store —
    # the same landing every import/pull/push uses; keep_source_xml is honored inside it. Synchronous by
    # design (the documented narrow verify exception). The land routes by filename extension, and a
    # re-exported schema is SaveAsXML, so the name must end in .xml.
    from corpusfm.app.web._import_ingest import ingest_import_bytes
    try:
        outcome = ingest_import_bytes(xml_bytes, f"{label}.xml", backend=backend)
    except Exception as exc:
        _rec(False, str(exc))
        return f"ERROR: Ingestion failed for '{database}': {exc}"
    if not outcome.ok:
        _rec(False, outcome.error or "ingest failed")
        return (f"ERROR: Ingestion failed for '{database}': "
                f"{outcome.error or 'the re-exported schema could not be parsed.'}")
    _bust_catalog_snapshot()
    artifact, meta = outcome.artifact, outcome.meta

    _rec(True)

    lines = [
        f"Re-import complete: {label}",
        f"  uuid:       {meta.uuid}",
        f"  timestamp:  {meta.timestamp}",
        f"  fm_version: {artifact.identity.fm_version}",
        f"  root_uuid:  {artifact.identity.root_uuid}",
        f"  sections:   {len(artifact.sections)}",
        f"  items:      {len(artifact.items)}",
        "",
        "This artifact is now available as a new baseline for patch generation.",
    ]
    return "\n".join(lines)


# ── Patch generation ───────────────────────────────────────────────────────────

@mcp.tool()
def generate_patch(
    artifact_a: str,
    artifact_b: str,
    inject_export_script: bool = False,
    archive_dir: str = None,
    include_xml: bool = False,
) -> str:
    """Generate an FMUpgradeToolPatch XML from two CORPUSfm artifacts.

    artifact_a is the baseline (currently deployed). artifact_b is the new
    version. Returns a coverage report; by default the patch XML itself is NOT
    inlined (it can be megabytes) — its size is reported and you save it with
    save_ai_patch(artifact_path, patch_xml, description), which stores it as a
    first-class PatchXML catalog record. Pass include_xml=True to also inline the
    full patch XML in the response.

    inject_export_script — when True and artifact_b lacks the CORPUSfm export
    script, adds CFM.TOOLS.ExportSchemaXML.SaveToDocumentsFolder to the patch so
    the patched file can export its schema for CORPUSfm to read. Disabled by
    default — read the CORPUSfm Addon documentation before enabling.

    include_xml — inline the full patch XML in the response (default False: report
    coverage + size + the save_ai_patch pointer instead).
    """
    from corpusfm.storage import get_backend
    from corpusfm.extensions.export.patch_build import generate_patch as _gen

    adir = Path(archive_dir) if archive_dir else None
    art_a = _load_artifact(artifact_a, adir)
    art_b = _load_artifact(artifact_b, adir)

    notice_lines: list[str] = []
    if not art_b.has_corpusfm_export:
        if inject_export_script:
            notice_lines.append(
                "NOTE: artifact_b does not have the CORPUSfm export script. "
                "It has been added to this patch (inject_export_script=True)."
            )
        else:
            notice_lines.append(
                "NOTE: artifact_b does not have the CORPUSfm export script. "
                "Pass inject_export_script=True to include it so the patched file "
                "can push its schema back to CORPUSfm."
            )

    patch_xml, coverage = _gen(art_a, art_b, inject_export_script=inject_export_script)
    cr = coverage.to_dict()

    lines: list[str] = []
    if notice_lines:
        lines += notice_lines + [""]

    lines += [
        f"Patch version: {cr.get('fm_version', '?')}",
        f"Version mismatch: {cr.get('version_mismatch', False)}",
        f"Patchable: {coverage.patchable_count}  "
        f"Not patchable: {coverage.not_patchable_count}  "
        f"Total: {len(cr.get('entries', []))}",
        "",
        "--- Coverage ---",
    ]
    for entry in cr.get("entries", []):
        status = entry.get("status", "?")
        reason = f" ({entry['reason']})" if entry.get("reason") else ""
        lines.append(
            f"  [{status}] {entry.get('section','?')} / {entry.get('name','?')} "
            f"— {entry.get('action','?')}{reason}"
        )

    patch_bytes = len(patch_xml.encode("utf-8"))
    if include_xml:
        lines += [
            "",
            f"--- Patch XML ({patch_bytes} bytes) ---",
            patch_xml,
        ]
    else:
        lines += [
            "",
            f"--- Patch XML: {patch_bytes} bytes (not inlined) ---",
            "Save it to the catalog with save_ai_patch(artifact_path, patch_xml, description), "
            "or re-call with include_xml=True to inline the full XML here.",
        ]
    return "\n".join(lines)


# ── AI patch storage ───────────────────────────────────────────────────────────

@mcp.tool()
def save_ai_patch(
    artifact_path: str,
    patch_xml: str,
    description: str,
    archive_dir: str = None,
    echo_xml: bool = False,
) -> str:
    """Save AI-generated FMUpgradeToolPatch XML as a PatchXML artifact in the catalog.

    Use this tool when you have composed patch XML containing AddAction elements for a
    target FM file. The patch becomes ONE first-class catalog record (type=PatchXML,
    origin=MCP) — it appears on the Artifacts page like any other artifact; its actions
    (download / validate / encrypt / apply) live in the artifact detail drawer.

    Workflow:
      1. Call get_schema_context(artifact_path) to understand the schema.
      2. Compose FMUpgradeToolPatch XML with AddAction elements using IDs from
         the schema context.
      3. Call save_ai_patch(artifact_path, patch_xml, description) to store it.
      4. The returned rel_path identifies the new catalog record.

    By default the result reports the saved record + a SHORT PREVIEW of the validated patch
    XML (you already hold the full XML you passed in). Pass echo_xml=True to echo the full
    validated XML back for copying.

    artifact_path: archive-relative path to the context artifact (used to name the record).
    patch_xml:     FMUpgradeToolPatch XML string (must have <FMUpgradeToolPatch> root).
    description:   Natural-language description of what the patch adds (stored as name).
    archive_dir:   Override archive directory (optional).
    echo_xml:      echo the full validated XML (default False: a bounded preview only).
    """
    from corpusfm.server.ai.patch_ai import extract_ai_patch_xml, coverage_from_ai_patch
    from corpusfm.server import queue_handlers

    try:
        patch_xml = extract_ai_patch_xml(patch_xml)
    except ValueError as exc:
        return f"ERROR: Invalid patch XML — {exc}"

    backend = get_backend(Path(archive_dir) if archive_dir else None)

    artifact_label = artifact_path
    source_uuid = ""
    try:
        source_uuid = _artifact_uuid(artifact_path)
        meta = backend.get_artifact_meta(source_uuid) if source_uuid else None
        if meta and getattr(meta, "name", ""):
            artifact_label = meta.name
    except Exception:
        pass

    coverage = coverage_from_ai_patch(patch_xml)
    name = (description[:80] + "…") if len(description) > 80 else (description or f"Patch for {artifact_label}")

    # packet 086: save THROUGH the queue (the land worker does store_deliverable + the HISTORY patch
    # event + catalog bust) and wait for it — nothing competes with the queue.
    res = queue_handlers.enqueue_deliverable_and_wait(
        backend, patch_xml.encode("utf-8"), artifact_type="PatchXML", origin="MCP",
        owner=_mcp_actor(),
        name=name, description=description, source_uuid=source_uuid or "")
    if res["status"] == "failed":
        return f"ERROR saving patch: {res['error']}"

    lines = [
        "AI patch saved as a PatchXML artifact in the catalog."
        + (" (still processing — it will appear shortly)" if res["status"] == "timeout" else ""),
        f"  uuid:        {res['uuid']}",
        f"  context:     {artifact_label}",
        f"  actions:     {len(coverage)}",
        f"  description: {description[:120]}",
        "",
        "It now appears on the Artifacts page (filter PatchXML); download / validate / encrypt /",
        "apply live in its detail drawer. To re-import after applying: reimport_after_patch(database).",
        "",
    ]
    lines += _echo_xml_lines("VALIDATED PATCH XML", patch_xml, echo_xml)
    return "\n".join(lines)


@mcp.tool()
def save_clip(
    clip_xml: str = None,
    description: str = "",
    artifact_path: str = None,
    archive_dir: str = None,
    echo_xml: bool = False,
    clip_path: str = None,
) -> str:
    """Save a FileMaker FMObjectList clip (script steps, fields, etc.) as a catalog artifact.

    Use this when you have composed a FileMaker clipboard snippet — an
    <fmxmlsnippet type="FMObjectList"> carrying script steps, fields, layouts, scripts, etc.
    The clip becomes ONE first-class catalog record (type=fmClip, origin=MCP); a
    developer can open it on the Artifacts page, copy it to the clipboard, and paste it into
    FileMaker (script steps need FM's clipboard flavor — convert the copied text with the MBS
    plugin or FmClipTools first).

    The result reports the detected FM clipboard class, a ready MBS paste snippet, and a
    SHORT PREVIEW of the validated clip XML (you already hold the full clip you passed in).
    Pass echo_xml=True to echo the full validated XML back for copying.

    clip_xml:      the <fmxmlsnippet type="FMObjectList">…</fmxmlsnippet> snippet (markdown
                   fences / surrounding prose are tolerated and stripped).
    clip_path:     alternative to clip_xml — a filesystem path to read the clip from, so a large
                   (~tens of KB) snippet need not be shipped inline through the model (packet 1024).
    description:   what the clip contains (stored as the name).
    artifact_path: optional archive-relative path to a context artifact (used for the name).
    archive_dir:   override archive directory (optional).
    echo_xml:      echo the full validated XML (default False: a bounded preview only).
    """
    from corpusfm.ingestion.clip import extract_clip_xml, classify_clip

    raw, err = _read_clip_input(clip_xml, clip_path)
    if err:
        return f"ERROR: {err}"
    try:
        clip_xml = extract_clip_xml(raw)
    except ValueError as exc:
        return f"ERROR: Invalid clip XML — {exc}"

    backend = get_backend(Path(archive_dir) if archive_dir else None)

    name = (description[:80] + "…") if len(description) > 80 else (description or "clip")

    from corpusfm.server import queue_handlers
    res = queue_handlers.enqueue_deliverable_and_wait(
        backend, clip_xml.encode("utf-8"), artifact_type="fmClip", origin="MCP",
        owner=_mcp_actor(),
        name=name, description=description)
    if res["status"] == "failed":
        return f"ERROR saving clip: {res['error']}"

    info = classify_clip(clip_xml)
    fm_class = (info or {}).get("fm_class") or "XMSS"
    lines = [
        "Clip saved as an fmClip artifact in the catalog."
        + (" (still processing — it will appear shortly)" if res["status"] == "timeout" else ""),
        f"  uuid:        {res['uuid']}",
        f"  description: {description[:120]}",
    ]
    if info:
        lines.append(f"  kind:        {info['kind']} (FM class {info['fm_class'] or '?'})")
    lines += [
        "",
        "It now appears on the Artifacts page (filter fmClip). Paste into FileMaker via the",
        "MBS plugin (copy the XML below, then run, then paste):",
        '  Set Variable [ $xml ; MBS("Clipboard.GetText") ]',
        f'  Set Variable [ $r ; MBS("Clipboard.SetFileMakerData"; "{fm_class}"; $xml) ]',
        "",
    ]
    lines += _echo_xml_lines("VALIDATED CLIP XML", clip_xml, echo_xml)
    return "\n".join(lines)


def _load_deliverable_text(ref: str, archive_dir: "str | None",
                           require_type: "str | None" = None) -> tuple:
    """Resolve a STORED deliverable (fmClip / PatchXML / fmScript / fmCalc) by ref → (text, atype,
    error). ref is a record UUID / primary name / any resolvable alias. require_type pins the
    expected artifact_type (a clear error otherwise); None accepts any deliverable type."""
    from corpusfm.artifact.capabilities import DELIVERABLE_TYPES
    ad = Path(archive_dir) if archive_dir else None
    try:
        uuid = _artifact_uuid(ref, ad)
    except Exception as exc:
        return "", "", f"could not resolve {ref!r}: {exc}"
    backend = get_backend(ad)
    meta = backend.get_artifact_meta(uuid)
    atype = getattr(meta, "artifact_type", "") if meta else ""
    descr = (f"a {atype} record" if atype else "not a stored record")
    if require_type and atype != require_type:
        return "", atype, f"{ref!r} is {descr} — expected a {require_type}."
    if atype not in DELIVERABLE_TYPES:
        return "", atype, (f"{ref!r} is {descr} — not a deliverable "
                           "(fmClip / PatchXML / fmScript / fmCalc).")
    data = backend.load_deliverable_xml(uuid)
    if not data:
        return "", atype, f"no stored content for {ref!r} (uuid {uuid})."
    return data.decode("utf-8", "replace"), atype, ""


def _read_clip_input(clip_xml: "str | None", clip_path: "str | None",
                     clip_ref: "str | None" = None, archive_dir: "str | None" = None) -> tuple:
    """Resolve a clip's text from EXACTLY ONE of: inline clip_xml, a filesystem clip_path, or
    clip_ref (a STORED fmClip catalog record — its record UUID / primary name / any resolvable
    alias). Returns (text, error) — error is a message string when the input is unusable."""
    given = [bool((clip_xml or "").strip()), bool(clip_path), bool(clip_ref)]
    if sum(given) > 1:
        return "", "pass exactly one of clip_xml, clip_path, or clip_ref."
    if clip_ref:
        text, atype, err = _load_deliverable_text(clip_ref, archive_dir, require_type="fmClip")
        if err:
            hint = "" if atype == "fmClip" else " The clip tools operate on fmClip records (store one with save_clip)."
            return "", err + hint
        return text, ""
    if clip_path:
        try:
            return Path(clip_path).read_text(encoding="utf-8"), ""
        except Exception as exc:
            return "", f"could not read clip_path — {exc}"
    if not (clip_xml or "").strip():
        return "", "provide clip_xml (the snippet), clip_path (a file), or clip_ref (a stored fmClip)."
    return clip_xml, ""


@mcp.tool()
def validate_clip(
    clip_xml: str = None,
    clip_path: str = None,
    target_artifact: str = None,
    archive_dir: str = None,
    clip_ref: str = None,
) -> str:
    """Validate a FileMaker clipboard clip BEFORE pasting — the pre-paste safety check.

    FileMaker's worst failure is SILENT: on paste it blanks references it can't resolve
    (<Field Missing>, <Table Missing>, an unresolved script/layout) instead of erroring. This
    runs the validation ladder — well-formed XML, FMObjectList kind/class, If/Loop block balance,
    calc parse, and (the moat) REFERENCE RESOLUTION against a target file's index — so you learn
    which references would paste unresolved while you can still fix them.

    EPOCH (packet 1086): passing these checks is the `generated_static_valid` state — static validity
    only. It does NOT prove FileMaker paste acceptance or runtime behavior; a real paste failure is an
    `observed_filemaker_failure` worth a developer report. See CLAUDE.md "fmClip generation — product
    model" for the ratified result vocabulary (contract; structured representation lands in packet 1087+).

    clip_xml:        the <fmxmlsnippet type="FMObjectList"> snippet (fences/prose tolerated).
    clip_path:       alternative to clip_xml — read the clip from this file (so a large snippet
                     need not be shipped inline through the model).
    clip_ref:        alternative to clip_xml/clip_path — a STORED fmClip catalog record (its
                     record UUID / primary name / any resolvable ref). Fetches the stored clip
                     XML so you can validate a clip already in the catalog without re-supplying it.
    target_artifact: the file the clip is destined for (archive ref / UUID / alias). When given,
                     every Script/Field/Layout/Table/ValueList/CustomFunction reference is checked
                     against that file's objects; omit it to just list the references + structure.
    archive_dir:     override archive directory (optional).
    """
    from corpusfm.core.clip_validate import validate_clip as _validate, TargetIndex

    raw, err = _read_clip_input(clip_xml, clip_path, clip_ref, archive_dir)
    if err:
        return f"ERROR: {err}"

    target = None
    target_note = "no target file given — references are LISTED, not resolved."
    if target_artifact:
        try:
            art = _load_artifact(target_artifact, Path(archive_dir) if archive_dir else None)
            target = TargetIndex.from_artifact(art)
            target_note = f"resolved against: {target_artifact}"
        except Exception as exc:
            return f"ERROR loading target_artifact: {exc}"

    res = _validate(raw, target)
    if not res.well_formed:
        return f"NOT well-formed XML — {res.error}"

    ok = (res.schema_ok and res.blocks_balanced and not res.unresolved
          and not res.unverifiable and not res.calc_errors)
    # packet 1079 — what we do NOT recognise in this clip. Surfaced here because this is where someone
    # decides whether to paste or patch it: a clip carrying an unrecognised step/value is a correctness
    # risk the moment it's edited, and an incoming clip is the only place FMXML drift is observable.
    # Advisory ONLY — it never changes PASS/ISSUES, because "we've never seen this" is not "it's wrong".
    from corpusfm.core.clip_gap import analyze_clip as _clip_gap
    _gap = _clip_gap(raw)
    lines = [
        f"Clip validation — {'PASS' if ok else 'ISSUES FOUND'}",
        f"  kind:            {res.kind or '?'} (FM class {res.fm_class or '?'})",
        f"  well-formed XML: yes",
        f"  FMObjectList:    {'yes' if res.schema_ok else 'NO — wrong root/type'}",
        f"  block balance:   {'balanced' if res.blocks_balanced else 'UNBALANCED'}",
        f"  FM form:         {_gap.inferred_fm_form or 'n/a'} — a clip declares no version; this is "
        "inferred from content",
    ]
    if _gap.unknown_step_ids or _gap.unknown_enum_values or _gap.unknown_elements or _gap.failed:
        lines.append("  ⚠ UNRECOGNISED CONTENT — this clip carries things we have no evidence for.")
        lines.append("    Not necessarily wrong: FileMaker made it. But we cannot vouch for what an")
        lines.append("    edit would do to these, and export_object_clip would refuse to emit them.")
        for u in _gap.unknown_step_ids:
            lines.append(f"      ✗ unknown step id: {u} — not in FileMaker 2026's catalog, so this "
                         "clip likely came from a NEWER FileMaker")
        for u in _gap.unknown_enum_values:
            lines.append(f"      ? {u}")
        for u in _gap.unknown_elements:
            lines.append(f"      ? unknown element: {u}")
        if _gap.failed:
            lines.append(f"      ! gap analysis INCOMPLETE ({', '.join(_gap.failed)}) — the list above "
                         "is not trustworthy as complete")
    for e in res.block_errors:
        lines.append(f"      ✗ {e}")
    lines.append(f"  references:      {len(res.references)}  ({target_note})")
    if target is not None:
        unresolved = res.unresolved
        unverifiable = res.unverifiable
        if unresolved:
            lines.append(f"      ⚠ {len(unresolved)} would PASTE UNRESOLVED (silent <… Missing> on paste):")
            for u in unresolved[:40]:
                # a field-def calc ref resolves at FIELD level (TO::field); a step ref at TO level
                if u["kind"] == "Field" and u["origin"] == "def_calc":
                    where = f" (field on TO '{u['table']}')"
                elif u["kind"] == "Field":
                    where = f" on TO '{u['table']}'"
                else:
                    where = ""
                lines.append(f"        - {u['kind']}: {u['name'] or u['table']}{where}  [{u['origin']}]")
            if len(unresolved) > 40:
                lines.append(f"        … +{len(unresolved) - 40} more")
        elif not unverifiable:
            lines.append("      ✓ all references resolve in the target file")
        # Field references we can't confirm — the target holds no field evidence for their table
        # (external / incomplete). Reported so an incomplete target never reads as 'fully resolved'.
        if unverifiable:
            lines.append(f"      ? {len(unverifiable)} field reference(s) UNVERIFIABLE "
                         "(target has no field evidence for their table — cannot confirm):")
            for u in unverifiable[:40]:
                lines.append(f"        - {u['name']} on TO '{u['table']}'  [{u['origin']}]")
        # Intentional FM constructs — shown so they're visible, but NOT a paste risk (packet 1043).
        intentional = res.intentional
        if intentional:
            nvar = sum(1 for r in intentional if r["status"] == "variable")
            nph = len(intentional) - nvar
            bits = ([f"{nvar} $variable target(s)"] if nvar else []) + \
                   ([f"{nph} placeholder(s) (<unknown>/<Current Table>)"] if nph else [])
            lines.append(f"      · {' + '.join(bits)} — intentional, not a paste risk")
    if res.calc_errors:
        lines.append(f"  calc parse:      {len(res.calc_errors)} calc(s) did not parse:")
        for c in res.calc_errors[:10]:
            lines.append(f"        - {c['error']}  «{c['calc']}»")
    else:
        lines.append("  calc parse:      all calcs parse")
    return "\n".join(lines)


@mcp.tool()
def patch_clip(
    ops: list,
    clip_xml: str = None,
    clip_path: str = None,
    target_artifact: str = None,
    archive_dir: str = None,
    echo_xml: bool = True,
    clip_ref: str = None,
    save_description: str = None,
) -> str:
    """Apply deterministic structured edits to an EXISTING FileMaker clipboard clip — the safe,
    reviewable way to fix a script you already hold as a clip (no hand-editing 200 steps of XML).

    This is the clip-in → clip-out patch path: the clip is already the paste dialect, so edits are a
    structural transform (no DDR transpile). After applying, the result is re-validated (block balance
    + reference resolution when target_artifact is given) and each op is echoed as a concise
    before/after review so a logically wrong (but still valid) edit is visible.

    EPOCH (packet 1086 — existing fmClip → modified fmClip contract, CLAUDE.md "fmClip generation —
    product model"): the supplied clip is the RICHER source. Preserve all XML except the parts
    intentionally changed — unknown, latent, machine-specific, and uninterpreted content is preserved,
    never reconstructed from schema. This is the direction where a captured pair was never the permission
    model to begin with.

    ops:             a list of edit ops, applied in order. Each is a dict:
      {"op":"set_enabled","selector":{…},"enabled":true|false}
      {"op":"delete","selector":{…}}
      {"op":"replace_calc","selector":{…},"calc":"<new calc text>"}          # whole calc
      {"op":"replace_calc_text","selector":{…},"find":"<exact old>","replace":"<exact new>",
       "expected_matches":1}     # EXACT-fragment edit inside the selected calc; fail-closed if the
                                 # fragment count ≠ expected_matches (a positive int, or "all")
      {"op":"insert","steps_xml":"<Step …>…","at":{"after"|"before":{…}} | {"end":true}}
      {"op":"move","selector":{…},"dest":{"after"|"before":{…}} | {"end":true}}
    Any op may also carry "expected_matches" to assert its SELECTOR match count fail-closed before
    mutating (omit for legacy first-match behavior).
    selector:        {"by":"index|name|banner|var|calc","value":…,"all":false}
                     index=position · name=step name · banner=comment-step text contains · var=Set
                     Variable Name equals · calc=calc text contains. all=true selects every match.
    clip_xml/clip_path: the clip inline, or a file path to read it from (large clips need not go inline).
    clip_ref:        alternative to clip_xml/clip_path — a STORED fmClip catalog record (record UUID
                     / primary name / any resolvable ref); patches a clip already in the catalog.
    target_artifact: optional — re-resolve references against this file after patching.
    save_description: when given, PATCH-AND-SAVE — persist the validated result as ONE NEW immutable
                     fmClip catalog record (never overwriting the source) and return its UUID, so a
                     large clip need not round-trip back through the model for a separate save_clip.
                     Saves nothing if any op failed or block balance is broken (atomic). Lineage to
                     the source clip (clip_ref) is recorded on the new record.
    echo_xml:        echo the full patched clip (default True — you need it to paste; set False with
                     save_description to keep the large XML out of the response).
    """
    from corpusfm.core.clip_patch import apply_clip_patch
    from corpusfm.core.clip_validate import validate_clip as _validate, TargetIndex

    raw, err = _read_clip_input(clip_xml, clip_path, clip_ref, archive_dir)
    if err:
        return f"ERROR: {err}"
    if not isinstance(ops, list) or not ops:
        return "ERROR: ops must be a non-empty list of edit operations."

    try:
        new_xml, report = apply_clip_patch(raw, ops)
    except Exception as exc:
        return f"ERROR applying patch: {exc}"

    target = None
    if target_artifact:
        try:
            art = _load_artifact(target_artifact, Path(archive_dir) if archive_dir else None)
            target = TargetIndex.from_artifact(art)
        except Exception as exc:
            return f"ERROR loading target_artifact: {exc}"

    res = _validate(new_xml, target)
    lines = [
        f"Clip patched — {len(report['applied'])} op(s) applied, {len(report['failed'])} failed.",
    ]

    def _bounded(s: str, n: int = 400) -> str:
        s = s or ""
        return s if len(s) <= n else s[:n] + f" …[+{len(s) - n} chars]"

    # Per-op deterministic review — makes a valid-but-wrong edit visible (never a semantic verdict).
    for e in report.get("ops", []):
        mark = "✓" if e["status"] == "applied" else "✗"
        where = ""
        if e.get("matched"):
            labels = e.get("labels") or []
            lab = f" — {labels[0]}" if labels else ""
            where = f" · step index {e['matched'][0]}{lab}" if len(e["matched"]) == 1 \
                else f" · {len(e['matched'])} steps {e['matched']}"
        head = f"  {mark} [{e['n']}] {e['op']} {e.get('selector')}{where}"
        if e.get("replacements") is not None:
            head += f" · {e['replacements']} replacement(s)"
        lines.append(head)
        if e["status"] == "failed":
            lines.append(f"        error: {e['error']}")
        elif e.get("before") is not None and e.get("after") is not None \
                and e["before"] != e["after"]:
            lines.append(f"        before: {_bounded(e['before'])}")
            lines.append(f"        after:  {_bounded(e['after'])}")

    lines += [
        "",
        f"Re-validation: block balance {'OK' if res.blocks_balanced else 'UNBALANCED'}"
        + ("" if target is None else f"; {len(res.unresolved)} unresolved reference(s)"),
    ]
    for e in res.block_errors[:10]:
        lines.append(f"    ✗ {e}")
    if target is not None:
        for u in res.unresolved[:20]:
            where = f" on TO '{u['table']}'" if u["kind"] == "Field" else ""
            lines.append(f"    ⚠ unresolved {u['kind']}: {u['name'] or u['table']}{where}")

    # Patch-and-save (atomic): persist a NEW immutable fmClip only when the patch is clean.
    if save_description is not None:
        lines.append("")
        if report["failed"]:
            lines.append("NOT SAVED — one or more ops failed; fix the ops and retry (atomic: no write).")
        elif not res.blocks_balanced:
            lines.append("NOT SAVED — patched clip has unbalanced If/Loop blocks (atomic: no write).")
        else:
            try:
                from corpusfm.ingestion.clip import extract_clip_xml
                clean = extract_clip_xml(new_xml)
                backend = get_backend(Path(archive_dir) if archive_dir else None)
                src_uuid = ""
                if clip_ref:
                    try:
                        src_uuid = _artifact_uuid(clip_ref, Path(archive_dir) if archive_dir else None)
                    except Exception:
                        src_uuid = ""
                desc = save_description or "patched clip"
                nm = (desc[:80] + "…") if len(desc) > 80 else (desc or "patched clip")
                mem = f"derived via patch_clip from {clip_ref}" if clip_ref else ""
                if target_artifact:
                    mem = (mem + f"; validated against {target_artifact}").lstrip("; ")
                from corpusfm.server import queue_handlers
                sv = queue_handlers.enqueue_deliverable_and_wait(
                    backend, clean.encode("utf-8"), artifact_type="fmClip", origin="MCP",
                    owner=_mcp_actor(),
                    name=nm, description=desc, memory=mem, source_uuid=src_uuid)
                if sv["status"] == "failed":
                    lines.append(f"SAVE FAILED — {sv['error']} (patch was valid; nothing persisted).")
                else:
                    lines.append("SAVED — new immutable fmClip artifact (source clip untouched)"
                                 + (" (still processing — appears shortly)"
                                    if sv["status"] == "timeout" else "") + ".")
                    lines.append(f"  saved uuid:  {sv['uuid']}")
                    if src_uuid:
                        lines.append(f"  lineage:     derived from {src_uuid}")
            except Exception as exc:
                lines.append(f"SAVE FAILED — {exc} (patch was valid; nothing persisted).")

    lines.append("")
    # An oversized full-clip echo would be corrupted by the byte backstop; refuse it with a pointer
    # instead (the patched clip is saved when save_as is set; else re-run with echo_xml + a smaller
    # clip, or fetch the saved artifact). packet 1152.
    if echo_xml and _estimate_tokens(new_xml) > _RESULT_TOKEN_BUDGET:
        lines.append(f"  [patched clip is {len(new_xml.encode('utf-8'))} bytes "
                     f"(~{_estimate_tokens(new_xml)} tokens) — over the ~{_RESULT_TOKEN_BUDGET}-token MCP "
                     f"result budget, and truncating it would corrupt it. Save it (save_as / save_description) "
                     f"and fetch it with get_deliverable(raw=True) or the HTTP download instead.]")
    else:
        lines += _echo_xml_lines("PATCHED CLIP XML", new_xml, echo_xml)
    return "\n".join(lines)


@mcp.tool()
def get_deliverable(ref: str, archive_dir: str = None, echo_xml: bool = True,
                    raw: bool = False, summary: bool = False, max_chars: int = 0) -> str:
    """Retrieve a STORED deliverable's content by ref — the read side for the catalog's non-schema
    records (fmClip / PatchXML / fmScript / fmCalc). save_* stores; validate_clip / patch_clip act on
    a clip; this one FETCHES any of them.

    A deliverable is a stored blob, NOT a parsed schema artifact, so the schema loaders
    (get_object / get_script_steps / get_raw_xml) can't read it — that's the gap this fills. It
    resolves ref (record UUID / primary name / any resolvable alias), reports the type, and echoes the
    stored content (plus the FM clipboard class + a ready MBS paste snippet for an fmClip).

    ref:         the stored deliverable record — record UUID, primary name, or any resolvable ref.
    echo_xml:    include the full content (default True — you need it to paste / patch); False
                 returns a bounded preview.
    raw:         return ONLY the exact stored content — no `<type> — <ref>` header, no MBS snippet,
                 no `--- CLIP XML ---` framing — so it can be sliced/saved byte-faithfully (e.g. a
                 test fixture). Overrides echo_xml/summary. (For a clip too large to ship inline, use
                 the HTTP download `GET /api/artifact-download/{ref}?form=raw` instead — packet 1043.)
    summary:     for an fmClip, report WHAT IT COVERS without the body — kind, total steps, block
                 balance, sha256, and a step-id inventory (id · name · count). Cheap triage; lets you
                 learn a clip's step coverage without pulling the whole XML.
    max_chars:   bound the echoed body (default 0 = unbounded). Applies to the framed body and to
                 `raw` (a bounded raw is marked truncated — do NOT use it as faithful bytes).
    archive_dir: override archive directory (optional).
    """
    import hashlib
    text, atype, err = _load_deliverable_text(ref, archive_dir)
    if err:
        return f"ERROR: {err}"

    if raw:
        if max_chars and len(text) > max_chars:
            return text[:max_chars] + f"\n<!-- TRUNCATED at {max_chars} chars; NOT faithful bytes. " \
                                      f"Use ?form=raw over HTTP for the full clip. -->"
        # raw=True is a byte-faithful contract — never let the backstop corrupt it (packet 1152).
        return _guard_faithful_size(
            text, what=f"{atype} {ref} (raw)",
            alt=f"Fetch it byte-faithfully over HTTP: GET /api/artifact-download/{ref}?form=raw.")

    if summary:
        return "\n".join(_deliverable_summary_lines(text, atype, ref))

    lines = [f"{atype} — {ref}"]
    label = {"fmClip": "CLIP XML", "PatchXML": "PATCH XML",
             "fmScript": "SCRIPT", "fmCalc": "CALC"}.get(atype, "CONTENT")
    size = len(text.encode("utf-8"))
    lines.append(f"  bytes:    {size}  sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}…")
    if atype == "fmClip":
        from corpusfm.ingestion.clip import classify_clip
        info = classify_clip(text) or {}
        fm_class = info.get("fm_class") or "XMSS"
        lines.append(f"  kind:     {info.get('kind') or '?'} (FM class {info.get('fm_class') or '?'})")
        lines += [
            "",
            "Paste into FileMaker via the MBS plugin (copy the XML below, then run, then paste):",
            '  Set Variable [ $xml ; MBS("Clipboard.GetText") ]',
            f'  Set Variable [ $r ; MBS("Clipboard.SetFileMakerData"; "{fm_class}"; $xml) ]',
        ]
    lines.append("")
    body = text if not (max_chars and len(text) > max_chars) else \
        text[:max_chars] + f"\n… [bounded at {max_chars} chars; re-call with a larger max_chars, " \
                           f"raw=True, or the HTTP download for the rest]"
    # An oversized full-XML echo would be byte-truncated (→ invalid clip/patch) by the backstop; refuse
    # the body with pointers instead, keeping the useful header/paste-snippet above (packet 1152).
    if echo_xml and _estimate_tokens(body) > _RESULT_TOKEN_BUDGET:
        lines.append(f"  [content is {len(body.encode('utf-8'))} bytes (~{_estimate_tokens(body)} tokens) "
                     f"— over the ~{_RESULT_TOKEN_BUDGET}-token MCP result budget; truncating it would "
                     f"corrupt it. Use summary=True for a step inventory, or fetch the full clip over "
                     f"HTTP: GET /api/artifact-download/{ref}?form=raw]")
    else:
        lines += _echo_xml_lines(label, body, echo_xml)
    return "\n".join(lines)


def _deliverable_summary_lines(text: str, atype: str, ref: str) -> list:
    """Cheap 'what does this deliverable cover?' triage without echoing the body (packet 1043).
    For an fmClip: kind + total steps + block balance + a step-id inventory. Other types: type + size."""
    import hashlib
    from collections import Counter
    size = len(text.encode("utf-8"))
    out = [f"{atype} — {ref}",
           f"  bytes:    {size}  sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}…"]
    if atype != "fmClip":
        return out + ["  (summary is step-level for fmClip only; use raw=True / echo_xml for the body)"]
    from corpusfm.ingestion.clip import classify_clip
    info = classify_clip(text) or {}
    out.append(f"  kind:     {info.get('kind') or '?'} (FM class {info.get('fm_class') or '?'})")
    try:
        root = _ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    except Exception as exc:
        return out + [f"  (could not parse steps: {exc})"]
    steps = [s for s in root.iter("Step") if s.get("id") is not None]
    if not steps:
        return out + ["  (no script steps — not a steps clip)"]
    names, counts = {}, Counter()
    depth_if = depth_loop = min_if = min_loop = 0
    for s in steps:
        try:
            sid = int(s.get("id"))
        except (TypeError, ValueError):
            continue
        counts[sid] += 1
        names[sid] = s.get("name") or ""
        if sid == 68:                                                # If (opener)
            depth_if += 1
        elif sid == 71:                                              # Loop (opener)
            depth_loop += 1
        elif sid == 70:                                              # End If
            depth_if -= 1; min_if = min(min_if, depth_if)
        elif sid == 73:                                              # End Loop
            depth_loop -= 1; min_loop = min(min_loop, depth_loop)
    balanced = (depth_if == 0 and depth_loop == 0 and min_if >= 0 and min_loop >= 0)
    out.append(f"  steps:    {len(steps)} total · {len(counts)} distinct step ids · "
               f"blocks {'balanced' if balanced else 'UNBALANCED'}")
    out.append("  step-id inventory (id · name · count):")
    for sid in sorted(counts):
        out.append(f"    {sid:>4}  {names[sid]:<34} x{counts[sid]}")
    return out


def _coverage_pct(covered: int, total: int) -> float:
    """Coverage %, floored — NEVER rounds an incomplete set up to 100 (nor a non-empty one down to 0).

    A plain round() reports 6108/6127 as "100%", which reads as "exports whole" while 19 steps refuse.
    The whole point of surfacing a denominator is to make incompleteness obvious, so the number must not
    be able to claim completeness the fence doesn't have.
    """
    if not total or covered <= 0:
        return 0.0
    if covered >= total:
        return 100.0                                     # the ONLY way to reach 100
    return min(math.floor(1000.0 * covered / total) / 10.0, 99.9)   # 99.69 → 99.6, never 100


def _fmt_pct(covered: int, total: int) -> str:
    pct = _coverage_pct(covered, total)
    if pct == 100.0:
        return "100%"
    if covered and pct == 0.0:
        return "<0.1%"
    return f"{pct:g}%"


def _emitted_step_ids(clip_xml: str) -> set:
    """The step ids actually present in an emitted clip (packet 1077 — which version-sensitive types a
    given clip really contains). Read from the emitted XML, not the DDR, so it reflects what shipped."""
    from corpusfm.core import safe_xml as _sx
    from corpusfm.ingestion.clip import _strip_xml_decl as _strip
    try:
        return {int(s.get("id")) for s in _sx.fromstring(_strip(clip_xml)).iter("Step")
                if (s.get("id") or "").isdigit()}
    except Exception:
        return set()


@mcp.tool()
def export_object_clip(artifact_path: str, object_name_or_id: str, section: str = "ScriptCatalog",
                       archive_dir: str = None, save_description: str = None,
                       echo_xml: bool = False, as_steps: bool = False,
                       strict: bool = False) -> str:
    """Export ONE parsed schema SCRIPT as a paste-ready FileMaker clipboard clip (FMObjectList).

    Derives a real clipboard clip from a stored SaveAsXML script's steps — the write-path counterpart
    to get_script_steps. The DDR and clipboard step dialects differ completely, so this is a per-step
    transform, not a copy.

    PERMISSION MODEL (fmClip epoch): one live assessment per step (`clip_emit.step_generation_assessment`).
    A step EMITS when it is a byte-verified shape (`generated_verified`), a registered source-incomplete
    shape (`generated_static_valid`; see below), or a shape a migrated CAPABILITY RULE fully accounts for
    though its exact pair is uncaptured (`generated_experimental` — static-valid, NOT FileMaker-verified).
    CAPABILITY VALIDATES BEFORE EVIDENCE: the rule checks the actual source tree first, so a malformed shape
    whose signature collides with a verified one is refused, not handed a verified verdict. Reference names/
    ids, calc/path/URL TEXT, and message/credential content are CONTENT (never in a reason string);
    destination/payload kind, option modes, enums, named-Boolean values, and anchor/repetition presence are
    SHAPE — every value authority an EXPLICIT map, never a raw pass-through. An unmapped enum, a configured
    export/save variant, or any OTHER unseen option shape REFUSES by a named reason
    (`capability_unaccounted_shape` or a feature-specific code); structural validity alone cannot prove a
    step's options survived conversion, so nothing is emitted best-effort, and any refused step withholds the
    WHOLE requested script (a step is never omitted). This is NOT universal FileMaker step/option coverage.

    The migrated capability set, its per-id families, and the byte-verified fence ARE THE CODE —
    `clip_emit._STEP_CAPABILITY_RULES` (the capability predicates) and `VERIFIED_STEP_IDS` (`set()`-equal to
    it), with the emitter count + per-shape table in docs/clip-emit-coverage.md (both guarded). This docstring
    deliberately does NOT restate the per-packet migration history or a hardcoded id count — that was drift
    surface (it carried a stale "190" after the fence moved to 192).

    SOURCE-INCOMPLETE GENERATION IS THE DEFAULT (packet 1089). A shape registered as source-incomplete —
    today, populated Print Setup (step 42), a CLASS-2 shape where the clip carries printer geometry +
    PlatformData the DDR provably never held — now EMITS its schema-held minimum by default, with the
    limitations in the RESULT METADATA (never in the clip XML). Result metadata splits each affected step's
    target facts THREE ways: `emitted_from_source`, `source_held_unimplemented` (source has it, the emitter
    does not yet map it — e.g. Print Setup's paper size — a capture does NOT fix it, code does), and
    `source_absent_for_target` (the source never held it — no capture, no emitter, ever). No printer
    geometry or PlatformData is invented; absent facts stay UNSET. `strict=True` restores verified-only
    behaviour and refuses source-incomplete shapes — the refusal says the strictness was caller-selected.

    TARGET VERSION (packet 1077): every clip emitted is **FM2026-form** — `<DisableStepCollapsed>` is an
    FM2026 clipboard addition present on every step, so the target is a property of the emitter, not of
    the script. There is no FM2025 output mode and no target_version parameter. Whether FM2025 accepts an
    FM2026-form clip is UNTESTED (hence `fm2025_compatible: null`, not false). 19 step types serialise
    differently between the versions; a clip containing any of them is reported in
    `version_sensitive_steps` with the exact delta — e.g. 212, where FM2025 expects the typo
    `SetLLMAccout` and we emit FM2026's corrected `SetLLMAccount`.

    artifact_path:    the stored SaveAsXML artifact (archive ref / UUID / alias).
    object_name_or_id: the script, matched with get_object's friendly semantics (scoped to ScriptCatalog).
    section:          only 'ScriptCatalog' is supported (scripts); stated honestly.
    save_description: when given, store the emitted clip as a new fmClip catalog record (lineage to the
                     source artifact) and return its UUID.
    echo_xml:         echo the full clip XML (default False: a bounded preview).
    as_steps:         packet 1043 §6 — clip FLAVOR. False (default) emits a whole-script clip (XMSC:
                     paste into the Scripts list). True emits a bare STEPS clip (XMSS: paste INTO an
                     already-open script at the cursor). Same verified steps + same fence; the two are
                     NOT interchangeable at paste time — pick by where the user will paste.
    strict:           packet 1089/1091 — request VERIFIED-ONLY output. Default False: registered
                     source-incomplete shapes (populated Print Setup) AND capability-experimental shapes (a
                     migrated id whose exact pair is uncaptured — ids 9/10) both generate, with the
                     limitations disclosed in the structured block (`source_incomplete` / `experimental`,
                     the completeness axes, `filemaker_equivalent`/`result_state`). Set True for verified-
                     only — a source-incomplete or experimental step then withholds the clip, and the
                     refusal says the strictness was caller-selected (NOT the product default). Either way,
                     an unsupported step TYPE or a `capability_unaccounted_shape` still withholds the whole
                     script.
    """
    from corpusfm.core import evidence as ev
    from corpusfm.core import clip_catalog as _clip_catalog
    from corpusfm.core.clip_emit import (emit_script_clip, scan_source_incomplete, scan_step_assessments,
                                         ClipEmitContext, VERIFIED_STEP_IDS, CLIP_TARGET_VERSION)
    from corpusfm.core.crossfile import build_external_data_source_index
    if section != "ScriptCatalog":
        return (f"ERROR: export_object_clip supports section='ScriptCatalog' (scripts) only — "
                f"got {section!r}. Other object types are not yet round-trip-verified.")
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    # packet 1118 — the explicit clip-emission context, built ONCE from the loaded artifact, so assessment,
    # atomicity, and reporting share ONE external-data-source resolution. It resolves a step's external
    # DataSourceReference against THIS artifact's ExternalDataSourceCatalog for privacy-safe reporting only;
    # every external form still refuses (external_file_reference_unsupported) and withholds the whole clip.
    _ctx = ClipEmitContext(external_data_sources=build_external_data_source_index(art))

    item = ev.find_artifact_item(art, object_name_or_id, section="ScriptCatalog")
    if item is None or item.is_folder:
        pool = [it for it in art.items.values() if it.section == "ScriptCatalog" and not it.is_folder]
        q = (object_name_or_id or "").strip().lower()
        near = sorted({it.name for it in pool if q and q in (it.name or "").lower()}) \
            or sorted({it.name for it in pool})[:20]
        return (f"No script matched {object_name_or_id!r} in ScriptCatalog of {artifact_path}.\n"
                f"Candidates: {', '.join(near[:20]) or '(none)'}")

    step_src = next((s for s in (item.xml_sources or []) if s.catalog == "StepsForScripts"), None)
    if step_src is None:
        return f"Script '{item.name}' has no 'StepsForScripts' XML source (no steps stored)."

    clip_xml, unsupported = emit_script_clip(
        step_src.xml, script_name=item.name, script_id=item.attributes.get("id", ""),
        include_in_menu=item.attributes.get("includeInMenu", "False"),
        flavor="xmss" if as_steps else "xmsc",
        strict=strict, context=_ctx)
    # Per-step verdicts (packet 1091) — one structured assessment each, the same authority the emitter used.
    # Lets the result report every step's permission/evidence/reason without re-deriving it, and separates
    # capability from evidence (a migrated capability-complete-but-uncaptured step emits EXPERIMENTALLY).
    # The SAME _ctx as emission → assessment/atomicity/report agree on every external resolution (pkt 1118).
    _assessed = scan_step_assessments(step_src.xml, strict=strict, context=_ctx,
                                      flavor="xmss" if as_steps else "xmsc")   # pkt 1123: match emit flavor
    # Privacy-safe external-file resolutions (packet 1118) — now permission-bearing (packet 1119): a resolved
    # unique FileMaker one-path sibling EMITS its external branch; a multi-path / non-FileMaker / ambiguous /
    # unresolved form still refuses. Each row carries the emission state alongside the resolution (status/alias/
    # id/source-type/path-count — never a raw path).
    _ext_refs = [{"id": r["id"], "name": r["name"], "emitted": r["permission"] == "emit",
                  "result_state": r["result_state"], **r["external_resolution"]}
                 for r in _assessed if r.get("external_resolution")]
    _experimental = [a for a in _assessed if a["evidence"] == "experimental" and not a["blocked"]]
    # The source-incomplete steps present in this script. Computed ALWAYS, not only when emitted: when the
    # clip carries them these are what made it source-incomplete, and under strict (where they refuse) these
    # tell the caller that retrying/capturing is pointless. Either way the caller gets the reason.
    _si_all = scan_source_incomplete(step_src.xml)
    _si = [] if strict else _si_all

    # Total DDR step count → an honest coverage ratio. This bridge is intentionally PARTIAL (it emits
    # only round-trip-verified shapes); surfacing supported/total makes the incompleteness obvious to a
    # human AND to an MCP agent, rather than a bare "N unsupported" with no denominator.
    from corpusfm.core import safe_xml as _sx
    from corpusfm.ingestion.clip import _strip_xml_decl as _sx_strip
    try:
        _blob = step_src.xml.decode("utf-8", "replace") if isinstance(step_src.xml, bytes) else step_src.xml
        _total_steps = len(list(_sx.fromstring(_sx_strip(_blob)).iter("Step")))
    except Exception:
        _total_steps = len(unsupported) + clip_xml.count("<Step ")

    if unsupported:
        by_type: dict = {}
        for u in unsupported:
            key = (u["id"], u["name"], u.get("reason", "unsupported step type"))
            by_type[key] = by_type.get(key, 0) + 1
        _supported = max(_total_steps - len(unsupported), 0)
        _pct = _coverage_pct(_supported, _total_steps)
        # Experimental steps blocked ONLY by strict (packet 1091) — distinct from a genuine capability gap.
        _exp_blocked = [a for a in _assessed if a["evidence"] == "experimental" and a["blocked"]]
        lines = [
            f"REFUSED — '{item.name}': {len(unsupported)} of {_total_steps} step(s) are outside what the "
            "emitter can generate → no clip emitted (fail-closed).",
            f"COVERAGE: {_supported}/{_total_steps} steps ({_fmt_pct(_supported, _total_steps)}) "
            "would emit. This bridge is",
            "INTENTIONALLY PARTIAL — a step emits only when it is a byte-verified shape, a migrated "
            "capability-complete shape, or a registered source-incomplete shape; every OTHER unseen option "
            "shape is refused",
            "rather than risk a silent lossy paste. Gaps are expected by design, not a bug; a clean "
            "refusal is the honest outcome.",
            "The fence is per step type AND per option shape: a structurally valid clip cannot prove a",
            "step's option flags survived conversion, so a step whose grammar the emitter does not account "
            "for (capability_unaccounted_shape) is never exported.",
            "",
            "Unsupported (id · name · reason · count):",
        ]
        for (sid, nm, reason), ct in sorted(by_type.items(), key=lambda kv: -kv[1]):
            lines.append(f"  id {sid} · {nm or '?'} · {reason} · x{ct}")
        if _exp_blocked and strict:
            # These are capability-complete and would emit by DEFAULT (experimentally). They refused ONLY
            # because you asked for strict/verified-only output — not a capability gap and not a capture.
            lines += ["",
                      f"NOTE — {len({a['id'] for a in _exp_blocked})} of the above are "
                      "EXPERIMENTAL-CAPABLE shapes (a migrated id whose exact pair is uncaptured), refused",
                      "ONLY because you set strict=True. Drop strict to generate them experimentally "
                      "(static-valid, correct by construction, NOT FileMaker-verified)."]
        if _si_all and strict:
            # These refused ONLY because the caller asked for strict/verified-only output. By DEFAULT
            # (packet 1089) they GENERATE their schema-held minimum. Class 2 is "never, from this surface":
            # the DDR never held the missing geometry, so no capture makes them byte-exact — the point is
            # to drop strict, not to capture.
            lines += ["",
                      f"NOTE — {len({u['id'] for u in _si_all})} of the above are CLASS-2 "
                      "(source-completeness) shapes, refused ONLY because you asked for strict/verified-",
                      "only output. They are not a coverage gap: the DDR never held the missing printer",
                      "geometry, so no capture makes them byte-exact. DROP strict=True to generate their",
                      "schema-held minimum as a clearly-labelled source-incomplete clip — that is the",
                      "outcome available for them, and it is the default."]
        lines += ["", f"Verified step ids: {sorted(int(x) for x in VERIFIED_STEP_IDS)}."]
        # Machine-readable block — so an MCP agent parses the incompleteness unambiguously, never
        # mistaking a refusal for a transient error or a partial clip for a complete one.
        import json as _json
        _exp_ids = {str(a["id"]) for a in _exp_blocked}

        def _gap_class(sid):
            # None = a strict-only block (experimental-capable), NOT a coverage gap. class 2 = "never, from
            # this surface". class 1 = a genuine unaccounted-capability shape. An agent must tell them apart
            # WITHOUT parsing prose, or it will keep asking for a capture that cannot help.
            if str(sid) in _exp_ids:
                return None
            return 2 if any(str(u["id"]) == str(sid) for u in _si_all) else 1
        _struct = {
            "result": "refused", "bridge": "partial-by-design", "clip_emitted": False,
            "result_state": "refused_known_hazard", "script": item.name, "total_steps": _total_steps,
            "supported_steps": _supported, "unsupported_steps": len(unsupported), "coverage_pct": _pct,
            "strict": strict,
            "unsupported": [{"id": int(sid) if str(sid).isdigit() else sid, "name": nm,
                             "reason": reason, "count": ct,
                             "gap_class": _gap_class(sid),
                             "blocked_by_strict": str(sid) in _exp_ids
                             or (strict and any(str(u["id"]) == str(sid) for u in _si_all))}
                            for (sid, nm, reason), ct in sorted(by_type.items(), key=lambda kv: -kv[1])],
            "class2_steps": [{"id": u["id"], "name": u["name"],
                              "source_absent_for_target": u["source_absent_for_target"],
                              "source_held_unimplemented": u.get("source_held_unimplemented", []),
                              "why": " ".join(str(u["why"]).split())} for u in _si_all],
            "experimental_blocked_by_strict": [{"id": a["id"], "name": a["name"]} for a in _exp_blocked],
            "source_incomplete_available": bool(_si_all),
            # packet 1118/1119 — external-file references resolved against the artifact catalog. A resolved
            # unique FileMaker one-path sibling EMITS its external branch (packet 1119); an external step in
            # THIS refused struct is one that could NOT emit — multi-path, non-FileMaker, ambiguous/unresolved,
            # a malformed grammar, or an uncaptured populated-parameter form — and it withholds the whole clip
            # like any refusal. Resolution alone is never permission; a raw path never appears.
            **({"external_references": _ext_refs,
                "external_note": "External-file references were resolved against this artifact's "
                                 "ExternalDataSourceCatalog (status/alias/id/source-type/path-count — never a "
                                 "raw path). A unique FileMaker single-path sibling emits its external branch "
                                 "(packet 1119); the references here could not — multi-path, non-FileMaker, "
                                 "unresolved/ambiguous, or an unimplemented external shape — so the whole clip "
                                 "is withheld. resolved_unverified is not permission."} if _ext_refs else {}),
            "note": "A script is refused WHOLE if any step is refused (fail-closed atomicity). A "
                    "capability_unaccounted_shape (gap_class 1) is a real gap — an emitter exists but no "
                    "capability rule accounts for that option shape; migrating the id's grammar (or a "
                    "captured pair) fixes it, retrying blindly does not."
                    + ("" if not (_exp_blocked and strict) else
                       " The blocked_by_strict experimental-capable steps (gap_class null) are DIFFERENT: "
                       "capability-complete, they emit by DEFAULT (experimentally) and refused ONLY because "
                       "strict=True — drop strict to generate them.")
                    + ("" if not (_si_all and strict) else
                       " The gap_class=2 entries refused ONLY because you set strict=True. By default "
                       "(packet 1089) they GENERATE their schema-held minimum — the DDR never held the "
                       "missing geometry, so a capture cannot make them byte-exact; drop strict=True to get "
                       "the source-incomplete clip."),
        }
        lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]
        return "\n".join(lines)

    from corpusfm.core.clip_validate import validate_clip as _validate, TargetIndex
    res = _validate(clip_xml, TargetIndex.from_artifact(art))
    n_steps = clip_xml.count("<Step ")

    # STATIC VALIDATION (packet 1089): block balance is the structural check. A block-unbalanced clip is a
    # generation FAILURE — it is NOT labelled generated_static_valid, is never saved, and returns a
    # concrete failure + developer feedback. Static validity still could not prove FileMaker paste
    # acceptance; a failure here is a structural one, upstream of that.
    if not res.blocks_balanced:
        import json as _json
        fb = _developer_feedback(
            recommended=True, category="generation_failure", direction="schema->new_clip",
            tool="export_object_clip",
            context={"artifact_path": artifact_path, "object": item.name, "as_steps": as_steps},
            observations=["the emitted clip failed static validation: script blocks are unbalanced"],
            inferences=["an emitter defect or an unbalanced source script; the clip is NOT presented as "
                        "valid and was NOT saved"],
            needed=["confirm whether the source script itself is unbalanced, or report the emitter defect"])
        _struct = {
            "result": "failed", "result_state": None, "clip_emitted": False, "script": item.name,
            "static_validation": {
                "state": None, "valid": False, "blocks_balanced": False,
                "note": "Script blocks are unbalanced — a static-validation FAILURE. Not saved and NOT "
                        "labelled generated_static_valid. Static validity still would not prove FileMaker "
                        "paste acceptance; this failure is structural, upstream of that."},
            "developer_feedback": fb,
            "note": "REFUSED — the emitted clip did not pass static validation (script blocks unbalanced). "
                    "No clip is presented as valid and nothing was saved.",
        }
        return "\n".join([
            f"REFUSED — '{item.name}': the emitted clip failed static validation (script blocks "
            "unbalanced) → not presented as valid, not saved.",
            "", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)])

    flavor = ("XMSS (bare steps — paste INTO an open script)" if as_steps
              else "XMSC (whole script — paste into the Scripts list)")
    # packet 1077 — the emitted clip's TARGET FM VERSION, stated rather than implied. Which
    # version-sensitive ids this particular script actually contains is the useful part: every clip is
    # FM2026-form (we emit <DisableStepCollapsed> universally), but these are the ids whose PAYLOAD also
    # differs, so a wrong-version paste would land differently — not just carry a spare element.
    _cat = _clip_catalog.load_catalog()
    _vs_here = sorted({int(sid) for sid in _emitted_step_ids(clip_xml) if sid in _cat.version_sensitive})
    # With a class-2 or experimental step in the clip, "all verified types" / "every step is
    # round-trip-verified" would be FALSE — the reassuring-but-wrong string this whole packet exists to
    # prevent. n_verified = the byte-captured steps; the rest are experimental or source-incomplete.
    _exp_n = len(_experimental)
    _n_verified = n_steps - len(_si) - _exp_n
    if _si:
        _headline = (f"⚠ Exported '{item.name}' → FileMaker clip [{flavor}]: {n_steps} step(s) — "
                     f"**SOURCE-INCOMPLETE** (class 2): {len(_si)} step(s) are knowingly LOSSY."
                     + (f" ({_exp_n} experimental.)" if _exp_n else ""))
        _cov_tail = (f"— {_n_verified} verified, {_exp_n} experimental, {len(_si)} SOURCE-INCOMPLETE "
                     "(emitted from the DDR-held part only; see below).")
    elif _exp_n:
        _headline = (f"⚠ Exported '{item.name}' → FileMaker clip [{flavor}]: {n_steps} step(s) — "
                     f"**EXPERIMENTAL**: {_exp_n} step(s) are capability-complete but UNCAPTURED.")
        _cov_tail = (f"— {_n_verified} verified, {_exp_n} experimental "
                     "(capability-complete, static-valid, NOT FileMaker-verified; see below).")
    else:
        _headline = (f"Exported '{item.name}' → FileMaker clip [{flavor}]: {n_steps} step(s), "
                     "all verified types.")
        _cov_tail = ("— every step is a round-trip-verified shape "
                     "(this bridge refuses whole if any step is refused).")
    lines = [
        _headline,
        f"  COVERAGE: {n_steps}/{_total_steps} steps ({_fmt_pct(n_steps, _total_steps)}) {_cov_tail}",
        f"  TARGET VERSION: {CLIP_TARGET_VERSION}-form clip. This emitter targets "
        f"{CLIP_TARGET_VERSION} only — there is no FM2025 output mode, and whether FileMaker 2025 "
        "accepts an FM2026-form clip is UNTESTED. Paste into FM2026.",
        f"  block balance {'OK' if res.blocks_balanced else 'UNBALANCED'}; "
        f"{len(res.unresolved)} unresolved reference(s) against the source artifact.",
    ]
    if _si:
        lines += ["",
                  "  SOURCE-INCOMPLETE — generated by default (packet 1089), NOT a full FileMaker",
                  "  reproduction. Each affected step's target facts split THREE ways: emitted from the",
                  "  source; held by the source but not yet mapped by this emitter (fix = code, not a",
                  "  capture); and absent from the source projection entirely (no capture, no emitter,",
                  "  ever — left UNSET, never defaulted, and never invented). FileMaker supplies its own",
                  "  on paste; whether it accepts the clip is UNTESTED. Do not present this as equivalent",
                  "  to the source step. The user may finish FileMaker-specific configuration after paste."]
        for u in _si:
            lines.append(f"    ⚠ step {u['index'] + 1} · id {u['id']} · {u['name']}")
            lines.append(f"        emitted from source        : {', '.join(u['emitted_from_source'])}")
            lines.append(f"        source-held, unimplemented : "
                         f"{', '.join(u.get('source_held_unimplemented') or ['(none)'])}")
            lines.append(f"        source-absent (class 2)    : {', '.join(u['source_absent_for_target'])}")
            lines.append(f"        why                        : {' '.join(str(u['why']).split())}")
        lines.append("")
    if _experimental:
        lines += ["",
                  f"  EXPERIMENTAL ({_exp_n}) — a migrated step id whose exact (DDR, clip) pair is",
                  "  UNCAPTURED, but whose whole option grammar the emitter accounts for (packet 1091). The",
                  "  clip is generated (correct by construction, static-valid) but NOT FileMaker-verified.",
                  "  If you paste it, a FileMaker paste/behaviour result is worth reporting."]
        for a in _experimental:
            lines.append(f"    ⚠ step {a['index'] + 1} · id {a['id']} · {a['name']} · {a['reason_code']}")
        lines.append("")
    _ext_emitted = [r for r in _ext_refs if r.get("emitted")]
    if _ext_emitted:
        lines += ["",
                  f"  EXTERNAL-FILE ({len(_ext_emitted)}) — step(s) that open/call a sibling file. Each "
                  "resolved to a UNIQUE FileMaker single-path sibling in this artifact's catalog, so its "
                  "external clip branch was emitted (packet 1119). Only the alias/id/source-type/path-count "
                  "is reported — never a raw path."]
        for r in _ext_emitted:
            lines.append(f"    · id {r['id']} · alias {r.get('alias') or '?'} · {r.get('ds_type') or '?'} · "
                         f"{r.get('result_state')}")
        lines.append("")
    if _vs_here:
        lines.append(f"    ⚠ {len(_vs_here)} step type(s) here serialise DIFFERENTLY in FM2025 — "
                     f"ids {_vs_here}. Emitted FM2026-form:")
        for sid in _vs_here[:8]:
            v = _cat.version_sensitive[sid]
            why = v.get("delta") or f"{v.get('name')} does not exist in FM2025."
            lines.append(f"      id {sid} · {v.get('name')} · {' '.join(str(why).split())}")
    for u in res.unresolved[:15]:
        where = f" on TO '{u['table']}'" if u["kind"] == "Field" else ""
        lines.append(f"    ⚠ unresolved {u['kind']}: {u['name'] or u['table']}{where}")

    saved_uuid = None
    if save_description is not None:
        # The clip is block-balanced here (an unbalanced one returned a failure above). Save is authorized
        # by the explicit save_description; a source-incomplete clip carries a concise provenance marker so
        # the saved artifact is never later mistaken for a full FileMaker projection (packet 1089). This is
        # artifact truthfulness within the requested save — NOT persistence of the developer report.
        try:
            backend = get_backend(Path(archive_dir) if archive_dir else None)
            try:
                src_uuid = _artifact_uuid(artifact_path, Path(archive_dir) if archive_dir else None)
            except Exception:
                src_uuid = ""
            desc = save_description or f"clip: {item.name}"
            nm = (desc[:80] + "…") if len(desc) > 80 else desc
            _mem = f"exported via export_object_clip from {artifact_path}::{item.name}"
            if _si:
                _mem += ("  [SOURCE-INCOMPLETE: generated schema-held minimum for "
                         f"{len(_si)} step(s) (ids {sorted({u['id'] for u in _si})}); "
                         "printer geometry/PlatformData absent from the DDR — NOT a full FileMaker clip]")
            if _experimental:
                _mem += ("  [EXPERIMENTAL: capability-complete but UNCAPTURED for "
                         f"{_exp_n} step(s) (ids {sorted({a['id'] for a in _experimental})}); "
                         "static-valid, correct by construction, NOT FileMaker-verified]")
            from corpusfm.server import queue_handlers
            sv = queue_handlers.enqueue_deliverable_and_wait(
                backend, clip_xml.encode("utf-8"), artifact_type="fmClip", origin="MCP",
                owner=_mcp_actor(),
                name=nm, description=desc, memory=_mem, source_uuid=src_uuid)
            if sv["status"] == "failed":
                lines.append(f"SAVE FAILED — {sv['error']} (clip was valid; nothing persisted).")
            else:
                saved_uuid = sv["uuid"]
                lines.append(f"SAVED — new fmClip artifact  uuid: {sv['uuid']}"
                             + ("  [source-incomplete provenance recorded]" if _si else "")
                             + ("  [experimental provenance recorded]" if _experimental else "")
                             + (f"  (lineage: from {src_uuid})" if src_uuid else ""))
        except Exception as exc:
            lines.append(f"SAVE FAILED — {exc} (clip was valid; nothing persisted).")

    # A SUCCESSFUL export had no structured block at all — only the refusal path did — so an agent could
    # read the coverage ratio but had to parse prose for everything else, and the target version had
    # nowhere machine-readable to live. Same convention as the refusal block above (packet 1077).
    import json as _json
    # packet 1089 — completeness is THREE independent axes, none collapsed into one scalar:
    #   transform_complete_for_source — did the transform reproduce everything the SOURCE held? False when
    #     any emitted step has a source_held_unimplemented fact (Print Setup's paper size).
    #   source_complete_for_target    — did the source hold everything the TARGET clip needs? False when a
    #     source-incomplete step is present (its source_absent facts).
    #   filemaker_equivalent          — is this a reproduction of FileMaker's full clip projection? False
    #     for any source-incomplete clip; it is a useful reconstruction, not the machine state.
    _transform_complete = not any(u.get("source_held_unimplemented") for u in _si)
    _fm_equivalent = not _si
    # result_state (packet-1087 vocabulary; packet 1091 adds the experimental axis). Precedence — the
    # WEAKEST claim wins the scalar, and BOTH axes are always reported in the struct so neither is erased:
    #   source-incomplete present → generated_static_valid (knowingly lossy, class-2);
    #   else experimental present  → generated_experimental (capability-complete, uncaptured);
    #   else                       → generated_verified.
    if _si:
        _result_state = "generated_static_valid"
    elif _experimental:
        _result_state = "generated_experimental"
    else:
        _result_state = "generated_verified"
    _static_validation = {
        "state": "generated_static_valid", "valid": True, "blocks_balanced": True,
        "checks": "FM2026-form envelope + block balance + reference resolution against the source artifact",
        "unresolved_references": len(res.unresolved),
        "note": "Static/structural validity only. This is NOT proof that FileMaker accepts the paste or "
                "that the pasted steps behave correctly; a real paste failure would be an "
                "observed_filemaker_failure worth a developer report.",
    }
    # Recommend ONE consolidated report when the clip carries a source-incomplete OR an experimental step
    # (packet 1091). A fully verified clip stays silent — a clean success is not turned into an incident.
    _fb_evidence = {}
    if _si:
        _fb_evidence["source_incomplete_steps"] = [
            {"id": u["id"], "name": u["name"],
             "emitted_from_source": u["emitted_from_source"],
             "source_held_unimplemented": u.get("source_held_unimplemented", []),
             "source_absent_for_target": u["source_absent_for_target"]} for u in _si]
    if _experimental:
        _fb_evidence["experimental_steps"] = [
            {"id": a["id"], "name": a["name"], "reason_code": a["reason_code"]} for a in _experimental]
    _fb_obs, _fb_inf, _fb_need = [], [], []
    if _si:
        _fb_obs.append(f"generated a source-incomplete clip for {len(_si)} step(s); the schema-held "
                       "minimum was emitted, no machine state invented")
        _fb_inf.append("source_held_unimplemented facts are fixable in code (a capture does NOT fix them); "
                       "source_absent_for_target facts are unrecoverable from any DDR")
        _fb_need.append("a FileMaker paste/behavior result for the source-incomplete step(s) — the user "
                        "may finish FileMaker-specific configuration (e.g. printer/paper) after paste; "
                        "report a paste failure as observed_filemaker_failure, or the paper-size "
                        "implementation gap as avoidable friction")
    if _experimental:
        _fb_obs.append(f"generated {_exp_n} EXPERIMENTAL step(s) (ids "
                       f"{sorted({a['id'] for a in _experimental})}): capability-complete but no committed "
                       "(DDR, clip) pair; emitted correct-by-construction, static-valid")
        _fb_inf.append("experimental steps are NOT a capture prerequisite — the emitter already accounts "
                       "for their grammar; capturing a pair would only promote them to generated_verified")
        _fb_need.append("if the user pastes this clip, a FileMaker paste/behaviour observation for the "
                        "experimental step(s) — a success promotes them to verified, a failure is an "
                        "observed_filemaker_failure worth a regression")
    _feedback = _developer_feedback(
        recommended=bool(_si or _experimental), category="gap_analysis_finding",
        direction="schema->new_clip", tool="export_object_clip",
        context={"artifact_path": artifact_path, "object": item.name, "as_steps": as_steps},
        source_artifact=artifact_path, generated_artifact=saved_uuid,
        static_validation={"blocks_balanced": True, "unresolved_references": len(res.unresolved)},
        evidence=(_fb_evidence or None),
        observations=_fb_obs, inferences=_fb_inf, needed=_fb_need)
    _struct = {
        "result": "exported", "result_state": _result_state, "clip_emitted": True, "script": item.name,
        "flavor": "XMSS" if as_steps else "XMSC",
        "clip_target_version": CLIP_TARGET_VERSION,
        "fm2025_compatible": None,          # UNTESTED — deliberately not False, and never True
        # packet 1076/1089 — a source-incomplete clip must be machine-detectable, not just prose-flagged.
        "source_incomplete": bool(_si),
        "source_complete": not _si,
        "gap_class": 2 if _si else None,
        # packet 1089 — three explicit completeness axes; `faithful` retained as a compat ALIAS of
        # filemaker_equivalent (the script tool's long-standing meaning: equal to FileMaker's full clip
        # projection). Do not read it as the field tool's transform-completeness sense.
        "transform_complete_for_source": _transform_complete,
        "source_complete_for_target": not _si,
        "filemaker_equivalent": _fm_equivalent,
        "faithful": _fm_equivalent,
        "static_validation": _static_validation,
        "developer_feedback": _feedback,
        "source_incomplete_steps": [
            {"index": u["index"], "id": u["id"], "name": u["name"],
             "emitted_from_source": u["emitted_from_source"],
             "source_held_unimplemented": u.get("source_held_unimplemented", []),
             "source_absent_for_target": u["source_absent_for_target"],
             "why": " ".join(str(u["why"]).split()),
             "paste_untested": u.get("paste_untested", True)} for u in _si],
        # packet 1091 — the experimental axis, reported ALONGSIDE source_incomplete (neither erases the
        # other). `experimental` is capability-complete-but-uncaptured: emitted, static-valid, NOT verified.
        "experimental": bool(_experimental),
        "experimental_steps": [
            {"index": a["index"], "id": a["id"], "name": a["name"], "evidence": a["evidence"],
             "result_state": a["result_state"], "reason_code": a["reason_code"]} for a in _experimental],
        # per-step verdicts (packet 1091 §C): one compact assessment per step so an agent reads the
        # permission/evidence of the whole script without re-deriving it. Verified steps stay tiny (no
        # signature/detail); non-verified carry the diagnostic shape + reason.
        "steps": [
            {"index": a["index"], "id": a["id"], "name": a["name"], "evidence": a["evidence"],
             "result_state": a["result_state"], "reason_code": a["reason_code"],
             **({} if a["evidence"] == "verified"
                else {"detail": a["detail"], "signature": a.get("signature")})}
            for a in _assessed],
        "verified_steps": _n_verified,
        # packet 1119 — external-file references (present only when a step opens/calls a sibling). An
        # `emitted` row resolved to a unique FileMaker single-path sibling and its external branch is in this
        # clip; the alias/id/source-type/path-count is reported, never a raw path.
        **({"external_references": _ext_refs} if _ext_refs else {}),
        "total_steps": _total_steps, "supported_steps": n_steps,
        "coverage_pct": _coverage_pct(n_steps, _total_steps),
        "blocks_balanced": res.blocks_balanced, "unresolved_refs": len(res.unresolved),
        "version_sensitive_steps": [
            {"id": sid, "name": _cat.version_sensitive[sid].get("name"),
             "kind": _cat.version_sensitive[sid].get("kind"),
             "delta": " ".join(str(_cat.version_sensitive[sid].get("delta") or "").split()) or None}
            for sid in _vs_here],
        "note": f"This clip is {CLIP_TARGET_VERSION}-form. EVERY clip this tool emits is — "
                "<DisableStepCollapsed> is an FM2026 clipboard addition emitted on every step — so the "
                "target is a property of the emitter, not of this script. `version_sensitive_steps` "
                "lists the ids whose PAYLOAD also differs in FM2025. There is no FM2025 output mode; "
                "FM2025 acceptance is untested, hence fm2025_compatible=null, not false."
                + ("" if not _si else
                   " SOURCE-INCOMPLETE (generated by default, packet 1089): this clip is NOT equivalent to "
                   "FileMaker's full projection. Per affected step, `emitted_from_source` is what the DDR "
                   "gave, `source_held_unimplemented` is what the DDR holds but this emitter does not yet "
                   "map (fixable in code — a capture does NOT help), and `source_absent_for_target` is "
                   "machine state the DDR never carried (class 2 — no capture, no emitter, ever). Treat "
                   "the absent facts as UNSET, not defaulted; static_validation is structural only and is "
                   "NOT FileMaker paste acceptance.")
                + ("" if not _experimental else
                   " EXPERIMENTAL (packet 1091): `experimental_steps` are a migrated id whose exact (DDR, "
                   "clip) pair is UNCAPTURED but whose whole option grammar the emitter accounts for — "
                   "emitted correct-by-construction and static-valid, but NOT FileMaker-verified. This is "
                   "NOT a capture prerequisite (the grammar is already accounted for); a real paste result "
                   "would promote them to generated_verified or report an observed_filemaker_failure."),
    }
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]

    lines.append("")
    lines += _echo_xml_lines("CLIP XML", clip_xml, echo_xml)
    return "\n".join(lines)


def _table_fields(art, table_name: str):
    """(table, [(item, <Field> elem)]) for one base table's FieldsForTables items, in DDR order.

    Fields are stored one item per field, named 'TABLE::Field'. Resolution is case-insensitive on the
    table half so a caller can name the table the way FileMaker shows it."""
    from corpusfm.core import safe_xml as _sx
    want = (table_name or "").strip().lower()
    out, resolved = [], None
    for it in art.items.values():
        if it.section != "FieldsForTables" or "::" not in (it.name or ""):
            continue
        tbl, _, _fld = (it.name or "").partition("::")
        if tbl.lower() != want:
            continue
        resolved = tbl
        src = next((s for s in (it.xml_sources or []) if s.catalog == "FieldsForTables"), None)
        if src is None:
            continue
        blob = src.xml.decode("utf-8", "replace") if isinstance(src.xml, bytes) else src.xml
        try:
            out.append((it, _sx.fromstring(blob)))
        except Exception:
            continue
    # DDR order, not alphabetical: a pasted field list should read the way the table does.
    out.sort(key=lambda p: int(p[1].get("id") or 0))
    return resolved, out


def _developer_feedback(*, recommended: bool, category: str, direction: str, tool: str,
                        context: dict, intent: str = None, source_artifact: str = None,
                        generated_artifact: str = None, evidence=None, static_validation=None,
                        observations=None, inferences=None, needed=None, reproduction=None) -> dict:
    """The bounded inline developer-feedback object (packet 1087, fmClip epoch — CLAUDE.md "fmClip
    generation — product model").

    DATA ONLY — building this NEVER posts, writes, or persists anything. It hands the AI enough bounded
    context to prepare ONE consolidated, portable report for the CORPUSfm developer via an authorized
    channel, then return to the user's task. The default (and, in this packet, only) sink is the inline
    tool result. Kept small on purpose: no whole-artifact echoes, no secrets, and a verified clean success
    is not turned into an incident report. Shared so later packets reuse one formatter instead of divergent
    per-tool report prose; wired here only where the serial-experimental result and its field-export
    failures need it."""
    fb = {
        "reporting_recommended": recommended,
        # generation_failure | paste_behavior_failure | workflow_friction | unsupported_case |
        # gap_analysis_finding
        "category": category,
        "direction": direction,     # schema->new_clip | existing_clip->modified_clip
        "tool": tool,
        "context": context,         # sanitized arguments/context only
        "observations": observations or [],     # stated separately from inferences
        "inferences": inferences or [],
        "needed_from_filemaker_or_user": needed or [],
        "reproduction": reproduction or [],
        "no_write_performed": ("No external post, repository write, artifact-memory write, or other "
                               "durable/external sink occurred. Reporting is an escape valve for "
                               "uncertainty, not a prerequisite."),
    }
    if intent:
        fb["intent"] = intent
    if source_artifact:
        fb["source_artifact"] = source_artifact
    if generated_artifact:
        fb["generated_artifact"] = generated_artifact
    if evidence is not None:
        fb["evidence"] = evidence
    if static_validation is not None:
        fb["static_validation"] = static_validation
    fb["instruction"] = (
        "Prepare ONE consolidated, portable report for the CORPUSfm developer via an authorized channel "
        "available to you (default sink: relay THIS inline result). Consolidate related findings, do not "
        "file duplicates or start a capture campaign, label inference vs observation, then return to the "
        "user's task." if recommended else "No report needed; return to the user's task.")
    return fb


@mcp.tool()
def export_field_clip(artifact_path: str, table_name: str, field_names: str = None,
                      archive_dir: str = None, save_description: str = None,
                      echo_xml: bool = False) -> str:
    """Export a base table's FIELD DEFINITIONS as a paste-ready FileMaker clip (XMFD).

    The field counterpart to export_object_clip: derives a real clipboard clip from a stored SaveAsXML's
    field definitions — "paste into Manage Database → Fields". The DDR and XMFD dialects differ
    completely (the DDR says fieldtype/datatype/comment="", the clip says fieldType/dataType/<Comment/>,
    and two facts are stated in OPPOSITE polarity), so this is a per-field transform, never a copy.

    PERMISSION IS CAPABILITY, not fixture membership (packet 1088 — the shipped runtime). A field emits
    when the current transform ACCOUNTS FOR every source feature it carries: a captured shape emits
    generated_verified, a capability-complete but UNCAPTURED shape emits generated_experimental, and only a
    field with an unmapped value or an unaccounted child/attr REFUSES (refused_known_hazard) — named by its
    concrete capability gap, never merely "no captured pair". The fence (_VERIFIED_FIELD_SIGS) is the
    EVIDENCE index (verified vs experimental), not the permission gate.

    STILL ALL-OR-NOTHING per request. Verified + experimental fields emit ONE complete clip with per-field
    evidence in the result metadata (never inside the clip XML); if any field is incapable, NO clip is
    emitted and the refusal names every blocking field and its capability reason. A partial field clip
    pastes cleanly, looks right, and the fields you didn't get are simply ABSENT — that silent loss is the
    whole reason the whole-clip invariant exists (packet 1086).

    EPOCH (packet 1086): the fixture fence is REGRESSION EVIDENCE, not the universal permission model
    (CLAUDE.md, "fmClip generation — product model"). Packet 1088 makes that concrete for fields: a shape
    with no captured pair but a fully-implemented transform now GENERATES (experimentally) instead of
    refusing; refusal is reserved for a real capability gap.

    ONE TABLE PER CLIP, and this is FileMaker's rule rather than ours: a Manage-Database→Fields copy is
    always from a single table's field list, and a field's (id, name) is NOT unique across tables — so a
    mixed-table clip has no coherent paste target.

    SCOPE — a REFUSAL names a CONCRETE capability gap (an unmapped value or an unaccounted child/attr),
    class 1 ("not yet", a coverage gap), fixed by IMPLEMENTING that mapping in the transform, not by a
    capture alone. There is no allow_source_incomplete hatch because a field refusal is never class-2.

    ONE SOURCE-COMPLETENESS RESIDUE, and it does not refuse (found 2026-07-15; this docstring previously
    claimed "no class-2 gap exists here", which was WRONG). FileMaker retains RETAINED-BUT-INACTIVE
    configuration in a field's options — a value left in the *unchecked* Data box when the field is set to
    Calculated instead — and the clip carries it; the DDR projects only the ACTIVE mode and drops it. One
    real field's clip holds a constant that appears ZERO times in the whole 39 MB DDR, and it meets the
    Print Setup proof standard: two fields with byte-identical DDR auto-enter shapes produce DIFFERENT
    clips. The fence CANNOT catch it — the signature is derived from the DDR, and the DDR holds no signal
    to derive from — so it is STATED rather than refused (`constant_data_may_be_incomplete`).

    Calibrate it correctly, because the first version of this disclosure did not: it is a POSSIBILITY for
    every Calculated-auto-enter field (77 of 442 in a real file) and is a DETECTED loss on two of them.
    BEHAVIOURAL IMPACT IS NONE — the value is inactive by definition. So `faithful` stays True (the
    transform reproduces everything the DDR holds) and `source_complete` carries the caveat: fidelity is
    projection↔projection, and it is the INPUT that may be short, not the transform. Marking every clip
    "unfaithful" for this would train a reader to ignore the flag — which is how a real disclosure dies.

    Everything else a field clip carries IS in the DDR.

    artifact_path: the stored SaveAsXML artifact (archive ref / UUID / alias).
    table_name:    the BASE TABLE whose fields to export (case-insensitive).
    field_names:   comma-separated subset; omit for the whole table. Because the fence is
                   all-or-nothing, naming the covered subset is how you get a clip out of a table that
                   refuses as a whole — the refusal lists exactly which fields to drop.
    save_description: when given, store the emitted clip as a new fmClip catalog record (lineage to the
                   source artifact) and return its UUID.
    echo_xml:      echo the full clip XML (default False: a bounded preview).
    """
    import json as _json
    from corpusfm.core.field_emit import (XMFD_CLASS, emit_field_clip, field_generation_assessment,
                                          _INDEX_LANGUAGE)
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    resolved, pairs = _table_fields(art, table_name)
    if not pairs:
        tables = sorted({(it.name or "").partition("::")[0]
                         for it in art.items.values() if it.section == "FieldsForTables"
                         and "::" in (it.name or "")})
        q = (table_name or "").strip().lower()
        near = [t for t in tables if q and q in t.lower()] or tables
        return (f"No base table matched {table_name!r} in {artifact_path}.\n"
                f"Candidates: {', '.join(near[:25]) or '(none)'}")

    total_in_table = len(pairs)
    if field_names:
        # Keep what the caller actually typed: matching is case-insensitive, but an error that echoes
        # back a lower-cased name they never wrote reads like a different field.
        want = {n.strip().lower(): n.strip() for n in field_names.split(",") if n.strip()}
        chosen = [(it, f) for it, f in pairs if (f.get("name") or "").lower() in want]
        found = {(f.get("name") or "").lower() for _, f in chosen}
        if missing := [want[k] for k in want if k not in found]:
            return (f"No field named {', '.join(repr(m) for m in missing)} in "
                    f"{resolved}. Fields: {', '.join(f.get('name') for _, f in pairs[:40])}")
        pairs = chosen

    # packet-1088 epoch: one structured assessment per field — verified / experimental / refused. Verified
    # AND experimental both EMIT (a captured shape vs a capability-complete uncaptured one); only a REFUSED
    # field withholds the clip, and it refuses for a CONCRETE capability reason (an unmapped value or an
    # unaccounted child/attr), never merely "no captured pair". unsupported_field_reason would lump
    # experimental in with refused, so classify on the assessment's PERMISSION instead.
    assessed = [(it, f, field_generation_assessment(f)) for it, f in pairs]
    refused = [(f.get("name"), a) for _it, f, a in assessed if a.permission == "refuse"]
    experimental = [(f.get("name"), a.detail) for _it, f, a in assessed if a.evidence == "experimental"]
    requested = len(pairs)
    supported = requested - len(refused)   # verified + experimental both emit

    if refused:
        # Group by CAPABILITY REASON, not by field: fields blocked by the same unimplemented mapping /
        # unaccounted child are one gap, not N problems. The reason NAMES the hazard (packet 1088) — a
        # missing capture is never itself the hazard.
        by_reason: dict = {}
        for nm, a in refused:
            by_reason.setdefault((a.reason_code, a.detail), []).append(nm)
        ok_names = [f.get("name") for _it, f, a in assessed if a.permission != "refuse"]
        # packet 1090 — the unknown-index-language refusal states a NARROWER truth than the generic
        # "implement, then capture": this axis is demonstrated non-identity (Unicode → Unicode_Raw), so an
        # unmapped name is a materially-misleading-output hazard, and the fix is a DEVELOPER MAPPING
        # DECISION — never a user capture task.
        _idx_lang_names = sorted({f.find("Storage/LanguageReference").get("name")
                                  for _it, f, a in assessed
                                  if a.reason_code == "unmapped_index_language"
                                  and f.find("Storage/LanguageReference") is not None})
        _other_codes = sorted({c for c, _d in by_reason} - {"unmapped_index_language"})
        lines = [
            f"REFUSED — {resolved}: {len(refused)} of {requested} requested field(s) carry a source "
            "feature the current transform does not account for → no clip emitted.",
            "The whole-table request cannot be satisfied while these fields are incapable, and a table "
            "clip must NEVER omit fields (packet 1086 invariant) — so nothing is emitted rather than a "
            "clip missing fields.",
            f"COVERAGE: {supported}/{requested} field(s) ({_fmt_pct(supported, requested)}) would emit "
            "(verified + experimental).",
            "",
            f"Blocking capability gaps ({len(by_reason)}), each with the fields that hit it:",
        ]
        for (code, detail), names in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"  · x{len(names)}  [{code}]  {', '.join(names[:6])}"
                         + (f" … +{len(names) - 6} more" if len(names) > 6 else ""))
            lines.append(f"        {detail}")
        if experimental:
            lines += ["",
                      f"({len(experimental)} requested field(s) would emit as generated_experimental, but "
                      "the clip is still withheld — it cannot be complete.)"]
        if _other_codes:
            lines += [
                "",
                "Each gap names a CONCRETE unimplemented mapping or known hazard — NOT merely 'no captured "
                "pair'. Fixing it means IMPLEMENTING that mapping in the transform (then capturing a pair "
                "to verify it), not just copying a clip. Do not retry this table until the named gap is "
                "built.",
            ]
        if _idx_lang_names:
            lines += [
                "",
                f"INDEX LANGUAGE: {_idx_lang_names} is not in the explicit clip map {sorted(_INDEX_LANGUAGE)}. "
                "This axis is DEMONSTRATED NON-IDENTITY (Unicode → Unicode_Raw), so an unmapped name cannot "
                "be assumed verbatim — a blind pass-through could paste cleanly while SILENTLY changing "
                "indexing. This is the RATIFIED policy (packet 1090): a known misleading-output hazard, NOT "
                "a missing pair. The fix is a DEVELOPER MAPPING DECISION backed by real FileMaker behaviour "
                "— NOT a capture, and not your task as the user.",
            ]
        if ok_names:
            lines += ["",
                      f"`supported_field_names` holds the {len(ok_names)} field(s) that WOULD emit. Asking "
                      "for that subset yields a DIFFERENT, partial deliverable — it does NOT satisfy this "
                      "complete-table request. Do not present it as though it did."]
        _observations = [f"{len(by_reason)} distinct capability gap(s) block {len(refused)} requested "
                         "field(s) — each a source feature the transform does not account for"]
        _inferences, _needed = [], []
        _evidence = {"capability_gaps": [{"reason_code": code, "reason": detail, "fields": names}
                                         for (code, detail), names in by_reason.items()]}
        if _other_codes:
            _inferences.append("the non-index-language gap(s) are fixable by implementing the named "
                               "mapping/structure in the field transform, then capturing a pair to verify "
                               "it — not by capture alone")
            _needed += [f"implement the transform mapping for: {code}" for code in _other_codes]
        if _idx_lang_names:
            _observations.append(
                f"the whole field-clip request was withheld and NO field was omitted; the index-language "
                f"block is {_idx_lang_names}, absent from the explicit map {sorted(_INDEX_LANGUAGE)}")
            _inferences.append(
                "INDEX-LANGUAGE HAZARD (labelled separately): blind pass-through of an unmapped index "
                "language is UNSAFE — this axis has a proven remap (Unicode → Unicode_Raw), so an unmapped "
                "name could paste cleanly while silently changing indexing behaviour. A materially-"
                "misleading-output hazard, not a missing-pair gap; NO capture makes an unmapped language "
                "safe")
            _needed.append(
                f"a DEVELOPER MAPPING DECISION for index language(s) {_idx_lang_names}, backed by real "
                f"FileMaker behaviour or another authoritative basis (mapped today: {sorted(_INDEX_LANGUAGE)}) "
                "— this is the CORPUSfm developer's decision, NOT a capture task for the current user")
            _evidence["index_language_hazard"] = {
                "source_languages": _idx_lang_names, "mapped_names": sorted(_INDEX_LANGUAGE),
                "axis_non_identity": True}
        fb = _developer_feedback(
            recommended=True, category="unsupported_case", direction="schema->new_clip",
            tool="export_field_clip",
            context={"artifact_path": artifact_path, "table_name": resolved, "field_names": field_names},
            evidence=_evidence, observations=_observations, inferences=_inferences, needed=_needed)
        _struct = {
            "result": "refused", "result_state": "refused_known_hazard", "clip_emitted": False,
            "clip_class": XMFD_CLASS, "table": resolved,
            "fields_in_table": total_in_table, "requested_fields": requested,
            "supported_fields": supported, "unsupported_fields": len(refused),
            "experimental_fields": len(experimental),
            "coverage_pct": _coverage_pct(supported, requested),
            # Each refusal names a concrete capability gap (packet 1088). gap_class stays 1 (a COVERAGE
            # gap — fixable by building), but the fix is IMPLEMENTING the named mapping, not a capture.
            # This is a claim about refusals only; the tool's one class-2 residue (the inactive auto-enter
            # constant) never refuses, because the DDR holds no signal to refuse on — see
            # constant_data_may_be_incomplete on the exported path.
            "unsupported": [{"fields": names, "reason_code": code, "reason": detail,
                             "count": len(names), "gap_class": 1}
                            for (code, detail), names in
                            sorted(by_reason.items(), key=lambda kv: -len(kv[1]))],
            "supported_field_names": ok_names,
            "developer_feedback": fb,
            "note": "REFUSED because one or more requested fields carry a source feature the transform "
                    "does not account for (result_state refused_known_hazard). Each blocking field names a "
                    "CONCRETE capability gap — an unmapped value or an unaccounted child/attr — via "
                    "reason_code; missing capture alone is NEVER the hazard. Every REFUSAL is class 1 (a "
                    "coverage gap, fixable by building), but the fix is IMPLEMENTING the named mapping in "
                    "the transform, then capturing a pair to verify it — not a capture by itself. (That is "
                    "a claim about refusals only — the tool carries one class-2 residue, the inactive "
                    "auto-enter constant, which never refuses because the DDR holds no signal to refuse "
                    "on; it is disclosed on the exported path.) Do NOT present a subset of "
                    "`supported_field_names` as satisfying the whole-table request — that is a different, "
                    "partial deliverable. Capability-complete but uncaptured fields already emit "
                    "experimentally; only genuinely unaccounted features refuse.",
        }
        lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]
        return "\n".join(lines)

    clip_xml = emit_field_clip([f for _, f in pairs])
    if clip_xml is None:                       # belt-and-braces: the fence already cleared every field
        return (f"REFUSED — {resolved}: emit_field_clip declined despite every field passing the shape "
                "fence. This is a bug, not a coverage gap; please report it.")

    # A byte-exact field is not the same as a field that PASTES correctly: a summary field references
    # another field by id+name, and an auto-enter calc references a TO — neither travels in the clip. If
    # the target lacks them FileMaker resolves them to <…Missing>, silently. Validate for the same reason
    # export_object_clip does; the fence proves the transform, this proves the references.
    from corpusfm.core.clip_validate import validate_clip as _validate, TargetIndex
    res = _validate(clip_xml, TargetIndex.from_artifact(art))

    # packet 1087: per-field evidence, and the overall state. Every field here is verified OR
    # serial-experimental (a refused field would have withheld the clip above). The clip XML is clean
    # FileMaker XML — all evidence/status lives OUT here in the result metadata, never inside the clip.
    field_evidence = [
        {"name": f.get("name"), "evidence": a.evidence,
         "detail": (a.detail if a.evidence == "experimental" else None)}
        for _it, f, a in assessed]
    result_state = "generated_experimental" if experimental else "generated_verified"

    lines = [
        f"Exported {resolved} → FileMaker field clip [{XMFD_CLASS} — paste into Manage Database → "
        f"Fields]: {requested} field(s) "
        + (f"({supported - len(experimental)} verified, {len(experimental)} experimental)."
           if experimental else "all verified shapes."),
        f"  COVERAGE: {requested}/{total_in_table} of the table's fields "
        f"({_fmt_pct(requested, total_in_table)}).",
        "  TARGET: paste into the Fields tab of a base table. The clip carries no table identity of its "
        "own — FileMaker applies it to whichever table you have open, so open the intended one.",
        f"  {len(res.unresolved)} unresolved reference(s) against the source artifact.",
    ]
    if experimental:
        lines.append(
            f"  ⚠ EXPERIMENTAL ({len(experimental)}): {', '.join(nm for nm, _ in experimental[:8])}"
            + (f" +{len(experimental) - 8} more" if len(experimental) > 8 else "")
            + " — capability-complete but UNCAPTURED: every source feature is accounted for by the "
            "transform, so emission is correct by construction, but this exact (DDR field, XMFD clip) "
            "shape was never captured. Static-valid, NOT proof of FileMaker acceptance.")
    if requested < total_in_table:
        lines.append(f"  ⚠ SUBSET — {total_in_table - requested} of {resolved}'s {total_in_table} "
                     "field(s) were not requested. This clip is complete for what you asked for, NOT "
                     "for the table.")
    # The class-2 residue (2026-07-15). It cannot be fenced — the signature comes from the DDR and the DDR
    # holds no signal — so disclosure is the ONLY honest handling. Computed for every emitted clip.
    _cd_risk = [f.get("name") for _, f in pairs
                if (f.find("AutoEnter") is not None
                    and f.find("AutoEnter").get("type") == "Calculated"
                    and f.find("AutoEnter/ConstantData") is None)]
    for u in res.unresolved[:15]:
        where = f" on TO '{u['table']}'" if u["kind"] == "Field" and u.get("table") else ""
        lines.append(f"    ⚠ unresolved {u['kind']}: {u['name'] or u['table']}{where}")
    if res.unresolved:
        lines.append("      (a reference the clip names but does not carry — FileMaker resolves it "
                     "against the table you paste INTO, silently, so confirm the target has it.)")
    if _cd_risk:
        lines.append(
            f"  NOTE — source-completeness: {len(_cd_risk)} Calculated-auto-enter field(s) emit an empty "
            "<ConstantData/>. FileMaker retains RETAINED-BUT-INACTIVE config there (a value left in the "
            "unchecked Data box); the DDR projects only the active mode, so if one existed it is not "
            "recoverable. Behavioural impact: none — the value is inactive by definition. The clip is "
            "faithful to everything the DDR holds; it is the DDR that may be incomplete.")

    saved_uuid = None
    if save_description is not None:
        try:
            backend = get_backend(Path(archive_dir) if archive_dir else None)
            try:
                src_uuid = _artifact_uuid(artifact_path, Path(archive_dir) if archive_dir else None)
            except Exception:
                src_uuid = ""
            desc = save_description or f"field clip: {resolved}"
            nm = (desc[:80] + "…") if len(desc) > 80 else desc
            from corpusfm.server import queue_handlers
            sv = queue_handlers.enqueue_deliverable_and_wait(
                backend, clip_xml.encode("utf-8"), artifact_type="fmClip", origin="MCP",
                owner=_mcp_actor(),
                name=nm, description=desc,
                memory=f"exported via export_field_clip from {artifact_path}::{resolved}",
                source_uuid=src_uuid)
            if sv["status"] == "failed":
                lines.append(f"SAVE FAILED — {sv['error']} (clip was valid; nothing persisted).")
            else:
                saved_uuid = sv["uuid"]
                lines.append(f"SAVED — new fmClip artifact  uuid: {sv['uuid']}"
                             + (f"  (lineage: from {src_uuid})" if src_uuid else ""))
        except Exception as exc:
            lines.append(f"SAVE FAILED — {exc} (clip was valid; nothing persisted).")

    # Static validity is its OWN axis, reported separately and NEVER as FileMaker acceptance (packet 1087).
    static_validation = {
        "state": "generated_static_valid", "valid": True,
        "checks": "well-formed XMFD envelope + reference resolution against the source artifact",
        "unresolved_references": len(res.unresolved),
        "note": "Static/structural validity only. This is NOT proof that FileMaker accepts the paste or "
                "that the pasted fields behave correctly; a real paste failure would be an "
                "observed_filemaker_failure worth a developer report.",
    }
    feedback = _developer_feedback(
        recommended=bool(experimental), category="gap_analysis_finding",
        direction="schema->new_clip", tool="export_field_clip",
        context={"artifact_path": artifact_path, "table_name": resolved, "field_names": field_names},
        source_artifact=artifact_path, generated_artifact=saved_uuid,
        evidence=({"experimental_fields": [{"name": nm, "detail": d} for nm, d in experimental]}
                  if experimental else None),
        static_validation={"unresolved_references": len(res.unresolved)},
        observations=([f"{len(experimental)} field(s) emitted experimentally: capability-complete but the "
                       "exact shape is uncaptured"] if experimental else []),
        inferences=(["emission is correct by construction (every source feature is accounted for by the "
                     "transform), but this exact (DDR field, XMFD clip) shape was never captured"]
                    if experimental else []),
        needed=(["a real FileMaker paste result for the experimental field(s) — a success converts the "
                 "shape into a captured regression pair; a failure is an observed_filemaker_failure"]
                if experimental else []))

    _struct = {
        "result": "exported", "result_state": result_state, "clip_emitted": True,
        "clip_class": XMFD_CLASS, "table": resolved,
        "fields_in_table": total_in_table, "requested_fields": requested,
        "supported_fields": supported, "experimental_fields": len(experimental),
        "coverage_pct": _coverage_pct(requested, total_in_table),
        "complete_table": requested == total_in_table,
        # packet 1087: per-field evidence (verified vs serial-experimental). The clip XML carries only
        # legitimate FileMaker XML; every status/uncertainty lives HERE, outside the clip.
        "fields": field_evidence,
        "static_validation": static_validation,
        "developer_feedback": feedback,
        # FAITHFUL vs SOURCE-COMPLETE are different axes, and collapsing them was a real mis-calibration:
        # `faithful:false` fired on 77 of 442 real fields for a 1-in-77 occurrence — i.e. on essentially
        # every real field clip — which trains a reader to ignore the flag. It is the Projections
        # Principle's first consequence: fidelity is projection↔projection. Our TRANSFORM reproduces
        # everything the DDR holds (faithful), while our INPUT may not hold everything FileMaker would
        # emit (source_complete). Both are stated, neither is inflated.
        "faithful": True,
        "source_complete": not _cd_risk,
        "gap_class": 2 if _cd_risk else None,
        "source_incomplete": False,     # export_object_clip's sense: a KNOWN-lossy shape, opted into.
        "constant_data_may_be_incomplete": _cd_risk,
        "constant_data_note": (
            "RETAINED-BUT-INACTIVE configuration, not live data. FileMaker keeps a value left in the "
            "unchecked Data box; the DDR projects only the ACTIVE auto-enter mode and drops it (proof: "
            "one field's clip holds a constant absent from the whole 39 MB DDR). The DDR gives no signal, "
            "so this cannot be fenced or detected — only stated. NO capture fixes it. BEHAVIOURAL IMPACT: "
            "NONE — the value is inactive by definition; it would only ever be seen by someone switching "
            "that field's auto-enter back to Data. This is a possibility for every listed field, not a "
            "detected loss on any of them." if _cd_risk else None),
        "unresolved_refs": len(res.unresolved),
        "unresolved": [{"kind": u["kind"], "name": u["name"], "table": u.get("table")}
                       for u in res.unresolved[:25]],
        "field_names": [f.get("name") for _, f in pairs],
        "paste_target": "Manage Database → Fields (the clip carries no table identity; FileMaker applies "
                        "it to the open table)",
        "note": (
            ("Every field in this clip is a round-trip-verified shape — its transform reproduces a real "
             "captured FileMaker clip byte-exact."
             if not experimental else
             f"{supported - len(experimental)} field(s) are round-trip-verified; {len(experimental)} "
             "emitted as generated_experimental (capability-complete but the exact shape is uncaptured — "
             "correct by construction, but never captured). See `fields` for per-field evidence and "
             "`static_validation` for the static-only check.")
            + " Fidelity here is projection↔projection: it matches what FileMaker's own DDR and clipboard "
            "projections do, which is narrower than 'correct against the .fmp12'. static_validation is "
            "structural only and is NOT FileMaker paste acceptance."
            + ("" if requested == total_in_table else
               " SUBSET: this clip is complete for the requested fields, NOT for the table.")),
    }
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]
    lines.append("")
    lines += _echo_xml_lines("CLIP XML", clip_xml, echo_xml)
    return "\n".join(lines)


def _parse_script_list(s: str) -> "list[str]":
    """A caller's script list: a JSON array, else one name/id per LINE (a comma fallback would split a FileMaker
    name that legally contains a comma). Blank entries dropped."""
    s = (s or "").strip()
    if not s:
        return []
    if s.startswith("["):
        import json as _json
        try:
            v = _json.loads(s)
            if isinstance(v, list):
                return [str(x).strip() for x in v if str(x).strip()]
        except Exception:
            pass
    return [ln.strip() for ln in s.splitlines() if ln.strip()]


@mcp.tool()
def create_script_acceptance_batch(artifact_path: str, script_names: str, batch_label: str,
                                   archive_dir: str = None, strict: bool = False) -> str:
    """Create a paste-acceptance BATCH: generate an isolated, pasteable clip for each of several stored
    SaveAsXML scripts so a developer can paste them into ONE disposable FileMaker file, export it as SaveAsXML,
    and have CORPUSfm correlate the returned scripts back to these cases (see evaluate_acceptance_return).

    artifact_path : a stored SaveAsXML artifact (uuid / name / abs path).
    script_names  : the scripts to batch — a JSON array OR one script name/id per line (caller order kept).
    batch_label   : a short safe label (1-60 chars of letters/digits/space/_/-; it is echoed — no private text).
    strict        : as in export_object_clip — verified-only; an experimental/source-incomplete case then
                    REFUSES and the whole batch refuses (nothing is stored).

    Calling this tool IS the persistence authorization. It PREFLIGHTS the entire batch first: any script that
    refuses, is ambiguous, duplicated, or unsafe refuses the WHOLE request with a per-case reason — no partial
    batch. On success each case is stored as a SEPARATE ordinary fmClip with a deterministic FileMaker-safe name
    `CFM_ACCEPT_<token>_<NNN>` (only the top-level Script object is renamed; no step/content is changed) and a
    structured acceptance-case record (source lineage, generation state, expected step-shape sequence,
    acceptance_state=awaiting_paste). Returns a bounded manifest — it does not echo the clips. `returned_shape_
    match` later proves paste + schema-shape survival, NOT runtime behavior."""
    import json as _json
    from corpusfm.server import acceptance_ops
    requested = _parse_script_list(script_names)
    if not requested:
        return "ERROR: script_names is empty — pass a JSON array or one script name/id per line."
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"
    try:
        art_uuid = _artifact_uuid(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception:
        art_uuid = ""
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    res = acceptance_ops.create_batch(backend, art, art_uuid, requested, label=batch_label, strict=strict)
    if res.get("stored"):
        _bust_catalog_snapshot()
    if not res.get("ok"):
        head = (f"REFUSED — acceptance batch not created ({res.get('error')}): {res.get('detail')}"
                if not res.get("partial") else
                f"PARTIAL — {len(res.get('stored', []))} case(s) stored then a storage failure occurred; "
                "the batch is INCOMPLETE (no atomic rollback).")
        return "\n".join([head, "", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(res)])
    lines = [f"Created acceptance batch {res['batch_id']} ({res['label']!r}) — {len(res['stored'])} case(s), "
             f"strict={strict}. Paste each into ONE disposable FileMaker file, export SaveAsXML, upload it, then "
             "call evaluate_acceptance_return.",
             "", "Cases (case · name · artifact · source script · generation state · steps):"]
    for c in res["stored"]:
        lines.append(f"  {c['case_id']} · {c['case_name']} · {c['artifact_uuid']} · {c['source_script']} · "
                     f"{c['generation_state']} · {c['step_count']} steps")
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(res)]
    return "\n".join(lines)


@mcp.tool()
def evaluate_acceptance_return(batch_id: str, returned_artifact_path: str, rejected_case_ids: str = None,
                               archive_dir: str = None, override: bool = False) -> str:
    """Correlate a returned SaveAsXML (the file the developer pasted the batch cases into, then exported +
    uploaded) to an acceptance batch, and record a CONSERVATIVE observation per case.

    batch_id              : the batch id from create_script_acceptance_batch.
    returned_artifact_path: the stored SaveAsXML the developer uploaded after pasting.
    rejected_case_ids     : optional comma-separated case ids the user OBSERVED FileMaker reject at paste time.
    override              : re-evaluate cases already scored against a DIFFERENT returned artifact (keeps a
                            bounded prior-observation history); re-evaluating the SAME return is idempotent.

    The batch is loaded ONLY from structured case metadata (never a description/memory string). Matching is by
    EXACT generated script name — no substring/case-fold/ordinal fallback. Each case is classified:
    returned_shape_match (name found + ordered step shapes match) / returned_shape_changed (found, shape differs,
    with a bounded structural diff) / not_found_in_return / paste_rejected (explicit) / evaluation_incomplete.
    A found-but-changed script is NEVER normalized to success, and shape match is NOT behavioral verification.
    This never mutates an emitter fence or promotes evidence."""
    import json as _json
    from corpusfm.server import acceptance_ops
    rejected = set()
    for tok in (rejected_case_ids or "").replace(" ", "").split(","):
        if tok:
            try:
                rejected.add(int(tok))
            except ValueError:
                return f"ERROR: rejected_case_ids must be comma-separated integers — got {tok!r}."
    try:
        returned = _load_artifact(returned_artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading returned artifact: {exc}"
    try:
        returned_uuid = _artifact_uuid(returned_artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception:
        returned_uuid = ""
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    res = acceptance_ops.evaluate_return(backend, batch_id, returned, returned_uuid,
                                         rejected_ids=rejected, override=override)
    if res.get("cases"):
        _bust_catalog_snapshot()
    if not res.get("ok"):
        return "\n".join([f"REFUSED — {res.get('error')}: {res.get('detail')}",
                          "", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(res)])
    lines = [f"Evaluated batch {res['batch_id']} against returned {returned_uuid} — "
             + ", ".join(f"{k}: {v}" for k, v in sorted(res["counts"].items())) + ".",
             res["disclaimer"], ""]
    if res.get("needs_override"):
        lines.append(f"NOTE — cases {sorted(res['needs_override'])} were already scored against a different "
                     "return; pass override=True to re-evaluate them.")
    lines.append("Cases (case · name · observation · diff positions):")
    for c in res["cases"]:
        extra = f" · {c['skipped']}" if c.get("skipped") else f" · {c.get('diff_count', 0)} diffs"
        lines.append(f"  {c['case_id']} · {c['case_name']} · {c['state']}{extra}")
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(res)]
    return "\n".join(lines)


@mcp.tool()
def compile_script_clip(target_artifact_path: str, ast: str, script_name: str, as_steps: bool = False,
                        save_description: str = None, acceptance_label: str = None, echo_xml: bool = False,
                        strict: bool = False, archive_dir: str = None) -> str:
    """Compile a STRUCTURED, AI-authored script (a flat AST) into a paste-ready FileMaker clip, resolving
    names against a selected target artifact (packet 1131). This is NOT a second emitter: it lowers the AST
    to DDR `<Step>` XML — the exact SaveAsXML step dialect — and hands that to the SAME fenced emitter
    export_object_clip uses. Everything downstream (permission, the verified/experimental line, static
    validity, whole-script atomicity) is reused unchanged. Call get_fmclip_compiler_guide first for the AST
    schema, the MVP vocabulary, the reference-resolution rules, and the four metadata buckets.

    target_artifact_path : the stored SaveAsXML whose catalogs resolve field/layout/script NAMES (uuid/name/
                           abs path). Nothing on the server is mutated by resolution.
    ast          : the flat ordered step list — a JSON object {"steps":[...]} or a bare JSON array. Each step
                   names a canonical MVP id and carries names (not ids) for references; the resolver fills ids.
    script_name  : the name of the script the clip creates.
    as_steps     : XMSS (bare steps to paste INTO an open script) vs XMSC (a whole-script object). Default XMSC.
    save_description : set → persist the compiled clip as a stored fmClip deliverable (the persistence IS the
                   authorization, like the other save-* tools). Unset → transient result.
    acceptance_label : set → also register the compiled clip + its lowered DDR sequence as a strict=False
                   paste-acceptance case through the shared acceptance authority (packet 1121/1131), so a
                   developer can paste it and evaluate_acceptance_return can correlate the return. 1-60 safe
                   chars; echoed.
    echo_xml     : echo the full clip XML (default False — a bounded preview + metadata).
    strict       : verified-only; a capability-experimental shape then REFUSES and the whole script is withheld.

    THE ② RULE (reference resolution). For every explicitly requested reference (field/table occurrence,
    layout, current-file script): unresolved OR ambiguous → the WHOLE script is WITHHELD (refused_*, naming
    the reference); a requested reference is NEVER silently omitted or substituted. A uniquely resolved
    reference is COMPLETE — it appears in `resolved_references`, never in `manual_actions`. Limitations live
    in this result's metadata, NEVER in the clip XML. A clip that pastes is not a behavioral-equivalence claim
    — FileMaker remains the final contextual editor and manual post-paste editing is an expected workflow."""
    import json as _json
    from corpusfm.core import clip_compile as _cc
    from corpusfm.server import acceptance_ops
    from corpusfm.core.clip_emit import ClipEmitContext
    from corpusfm.core.crossfile import build_external_data_source_index
    try:
        parsed = _json.loads(ast) if isinstance(ast, str) else ast
    except Exception as exc:
        return f"ERROR: `ast` is not valid JSON ({exc}) — pass a JSON object {{\"steps\":[...]}} or a JSON array."
    try:
        art = _load_artifact(target_artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading target artifact: {exc}"
    ctx = ClipEmitContext(external_data_sources=build_external_data_source_index(art))
    res = _cc.compile_script(art, parsed, script_name=script_name, flavor="xmss" if as_steps else "xmsc",
                             strict=strict, context=ctx)
    if not res.ok:
        _struct = {"result": "refused", "result_state": res.result_state, "clip_emitted": False,
                   "script_name": script_name,
                   "refusal": {"code": res.refusal_code, "detail": res.refusal_detail,
                               "step_index": res.refusal_index},
                   "resolved_references": res.resolved_references,
                   "note": "A structured-script compile is WHOLE-SCRIPT atomic — an unsupported step, an "
                           "unbalanced block, an unresolved/ambiguous reference, or a strict refusal withholds "
                           "the entire script. Nothing is silently omitted or substituted. Fix the named "
                           "step/reference and recompile."}
        return "\n".join([f"REFUSED — '{script_name}' not compiled ({res.refusal_code}): {res.refusal_detail}"
                          + (f" [step index {res.refusal_index}]" if res.refusal_index is not None else ""),
                          "", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)])

    lines = [f"Compiled '{script_name}' → FileMaker clip "
             f"[{'XMSS (bare steps)' if as_steps else 'XMSC (whole script)'}]: {res.step_count} step(s), "
             f"result_state={res.result_state}.",
             f"  resolved references: {len(res.resolved_references)} "
             f"(all COMPLETE — resolution is not manual work).",
             f"  experimental steps: {len(res.experimental_steps)}  ·  source-incomplete: "
             f"{len(res.source_incomplete_steps)}  ·  manual actions: {len(res.manual_actions)}."]
    for r in res.resolved_references:
        lines.append(f"    ✓ {r['kind']}: {r.get('requested')} → "
                     f"{r.get('resolved_name') or r.get('resolved_field_name')} "
                     f"(id {r.get('resolved_id') or r.get('resolved_field_id')})")
    if res.experimental_steps:
        lines += ["", f"  EXPERIMENTAL ({len(res.experimental_steps)}) — a migrated id whose exact (DDR, clip) "
                  "pair is UNCAPTURED but whose grammar the emitter accounts for: generated (static-valid, "
                  "correct by construction), NOT FileMaker-verified. A paste/behaviour result is worth reporting."]
        for a in res.experimental_steps:
            lines.append(f"    ⚠ step {a['index'] + 1} · id {a['id']} · {a['name']}")
    if res.result_state == "generated_verified":
        lines.append("  every step is a byte-verified shape (this compiler withholds whole if any step refuses).")

    saved_uuid = None
    if save_description is not None:
        try:
            backend = get_backend(Path(archive_dir) if archive_dir else None)
            try:
                src_uuid = _artifact_uuid(target_artifact_path, Path(archive_dir) if archive_dir else None)
            except Exception:
                src_uuid = ""
            desc = save_description or f"compiled clip: {script_name}"
            nm = (desc[:80] + "…") if len(desc) > 80 else desc
            _mem = f"compiled via compile_script_clip against {target_artifact_path} (state {res.result_state})"
            from corpusfm.server import queue_handlers
            sv = queue_handlers.enqueue_deliverable_and_wait(
                backend, res.clip.encode("utf-8"), artifact_type="fmClip", origin="MCP",
                owner=_mcp_actor(),
                name=nm, description=desc, memory=_mem, source_uuid=src_uuid)
            if sv["status"] == "failed":
                lines.append(f"SAVE FAILED — {sv['error']} (clip was valid; nothing persisted).")
            else:
                saved_uuid = sv["uuid"]
                lines.append(f"SAVED — new fmClip artifact  uuid: {sv['uuid']}"
                             + (f"  (lineage: from {src_uuid})" if src_uuid else ""))
            _bust_catalog_snapshot()
        except Exception as exc:
            lines.append(f"SAVE FAILED — {exc} (clip was valid; nothing persisted).")

    acceptance = None
    if acceptance_label is not None:
        backend = get_backend(Path(archive_dir) if archive_dir else None)
        acceptance = acceptance_ops.register_compiler_case(
            backend, clip_xml=res.clip, ddr_steps_blob=res.ddr_blob, script_name=script_name,
            label=acceptance_label, gen_state=res.result_state)
        if acceptance.get("ok"):
            _bust_catalog_snapshot()
            c = acceptance["stored"][0]
            lines.append(f"ACCEPTANCE — registered case {c['case_name']} in batch {acceptance['batch_id']} "
                         f"(uuid {c['artifact_uuid']}). Paste it into a disposable file, export SaveAsXML, then "
                         "call evaluate_acceptance_return; a shape match is NOT behavioral verification.")
        else:
            lines.append(f"ACCEPTANCE NOT REGISTERED — {acceptance.get('error')}: {acceptance.get('detail')} "
                         "(the clip is still valid above).")

    if echo_xml:
        lines += ["", "--- CLIP XML ---", res.clip]
    else:
        lines += ["", f"  (clip is {len(res.clip)} chars; pass echo_xml=true for the full XML)"]

    _struct = {"result": "compiled", "result_state": res.result_state, "clip_emitted": True,
               "script_name": script_name, "step_count": res.step_count, "as_steps": as_steps,
               "strict": strict, "saved_uuid": saved_uuid,
               "metadata": {"resolved_references": res.resolved_references,
                            "experimental_steps": res.experimental_steps,
                            "source_incomplete_steps": res.source_incomplete_steps,
                            "manual_actions": res.manual_actions},
               "acceptance": acceptance,
               "note": "result_state is the WEAKEST-claim scalar. No state implies FileMaker paste acceptance "
                       "unless FileMaker actually supplied that observation. Limitations are HERE, never in the "
                       "clip XML; a uniquely resolved reference is complete, never a manual action."}
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]
    return "\n".join(lines)


@mcp.tool()
def get_fmclip_compiler_guide() -> str:
    """The authoring guide for compile_script_clip (packet 1131) — how an AI composes a structured script AST
    the compiler lowers into a FileMaker clip. Analogue of get_patch_authoring_guide. Read this before
    calling compile_script_clip."""
    import json as _json
    from corpusfm.core import clip_compile as _cc
    schema = _json.dumps(_cc.ast_json_schema(), indent=2)
    vocab = ", ".join(f"{n} ({i})" for n, i in sorted(_cc.MVP_STEP_IDS.items(), key=lambda kv: int(kv[1])))
    return f"""CORPUSfm — structured-script → fmClip compiler (compile_script_clip), MVP guide.

WHAT IT IS. You author a FLAT, ORDERED list of step objects (an AST). The compiler resolves the NAMES you
write (fields, layouts, current-file scripts) to ids against a selected target artifact, lowers each step to
the DDR `<Step>` a real SaveAsXML export would contain, and hands that to the existing, fenced clip emitter.
It is NOT a second emitter and never re-implements step grammar. The result is a legitimate, useful FileMaker
STARTING POINT — FileMaker remains the final contextual editor, and manual post-paste editing is expected,
not a defect.

MVP VOCABULARY (every id is a verified emitter; anything else refuses the whole script):
  {vocab}

FLAT CONTROL FLOW — no nested blocks. Express structure with explicit sequential steps: If / Else If / Else /
End If, and Loop / Exit Loop If / End Loop. The compiler validates block balance over the flat list BEFORE
lowering; an unbalanced list refuses.

REFERENCES (the ② rule — STRICT):
  • Set Field       → "field": "TableOccurrence::Field"  (resolved against TableOccurrenceCatalog + the TO's
                       base table's FieldsForTables).
  • Perform Script  → "script": "<current-file script name>"  (From-list; ScriptCatalog).
  • Go to Layout    → "destination": {{"mode": "layout", "layout": "<name>"}}  (LayoutCatalog).
  • Show Custom Dialog input → per slot {{"field": "TO::Field"}} OR {{"variable": "$var"}}.
  An UNRESOLVED or AMBIGUOUS name WITHHOLDS THE WHOLE SCRIPT. A requested reference is never silently omitted
  or substituted. A uniquely resolved reference is COMPLETE (it appears in resolved_references, never in
  manual_actions). Go to Layout "mode": "original" is a CHOSEN portable shape (no reference) and emits.

STEP FIELDS (calculations are FileMaker calc TEXT, exactly as typed in the FM calc box):
  If / Else If / Exit Loop If : "calc"     (condition)
  Exit Script                 : "calc"     (optional result)
  Set Variable                : "name" ($var), "value" (calc), "repetition" (optional, default "1")
  Set Field                   : "field", "value" (calc), "repetition" (optional)
  Perform Script              : "script", "parameter" (optional calc)
  Go to Layout                : "destination" {{mode: original|name_by_calc|number_by_calc|layout, +calc/layout}},
                                "animation" (optional; a PROVEN FileMaker spelling, else refuses)
  Show Custom Dialog          : "title" (opt calc), "message" (calc), "buttons" [{{label, commit}} × up to 3],
                                "inputs" [{{variable|field, password?, label?}}]
  Comment                     : "text"
  Loop                        : "flush" (optional: Always|Defer|Minimum)

RESULT VOCABULARY (weakest-claim wins; NO state implies FileMaker paste acceptance):
  generated_verified — every step is a byte-verified shape.
  generated_experimental — a step is capability-complete but its exact pair is uncaptured (static-valid,
     correct by construction, NOT FileMaker-verified).
  generated_static_valid — a registered source-incomplete step (none arise from the MVP vocabulary today).
  refused_known_hazard — an unsupported step / unbalanced block / unresolved-or-ambiguous reference / strict
     refusal; the WHOLE script is withheld, naming the offending step or reference.

FOUR METADATA BUCKETS (limitations live HERE, never in the clip XML):
  resolved_references  — each requested name uniquely resolved; COMPLETE, not a manual-edit list.
  experimental_steps   — capable-but-uncaptured shapes emitted experimentally.
  source_incomplete_steps — registered source-incomplete shapes (schema-held minimum emitted).
  manual_actions       — only GENUINE remaining FileMaker work (empty for the MVP vocabulary).

PERSISTENCE. Set save_description to store the clip as an fmClip deliverable (that IS the authorization). Set
acceptance_label to also register it as a paste-acceptance case (then paste + call evaluate_acceptance_return;
a returned_shape_match is a schema-shape match, NOT behavioral verification).

AST JSON SCHEMA:
{schema}

EXAMPLE:
{{"steps": [
  {{"step": "Comment", "text": "Guard the parameter"}},
  {{"step": "If", "calc": "IsEmpty ( Get ( ScriptParameter ) )"}},
  {{"step": "Show Custom Dialog", "message": "\\"Missing parameter\\"",
    "buttons": [{{"label": "OK", "commit": true}}]}},
  {{"step": "Exit Script", "calc": "0"}},
  {{"step": "End If"}},
  {{"step": "Set Variable", "name": "$id", "value": "Get ( ScriptParameter )"}},
  {{"step": "Go to Layout", "destination": {{"mode": "layout", "layout": "Detail"}}}},
  {{"step": "Perform Script", "script": "Commit Changes"}}
]}}
"""


@mcp.tool()
def detect_clip_variations(artifact_path: str, object_name_or_id: str = None,
                           section: str = "ScriptCatalog", archive_dir: str = None,
                           limit: int = 25) -> str:
    """Triage a stored SaveAsXML's script steps against the clip-emitter fence — what would export today,
    and where the current fixture coverage falls short.

    The read-only companion to export_object_clip: that tool refuses a script whole if any step is refused;
    this one says WHY, across one script or a whole artifact, ranked by how often each shape actually occurs
    in this corpus. Evidence, not guesswork — nothing is emitted or mutated.

    EPOCH FRAMING (packet 1086): this output is capture TELEMETRY — informational, not a work order. A
    shortfall here does not by itself create a capture campaign, a user prerequisite, or a refusal; it
    tells you where the emitter is coverage-thin. The governing generation model is in CLAUDE.md ("fmClip
    generation — product model"); fixture coverage is regression evidence, not the permission system.

    Each step is classified into exactly one kind (packet 1091 reads the LIVE step assessment):
      covered            — the emitter reproduces this step's shape byte-exact; it would export today.
      experimental-capable — a MIGRATED step id in a capability-complete but UNCAPTURED shape. It EMITS
                           today (experimentally) — NOT a capture owed; a capture would only promote it.
      new-variation      — a VERIFIED step id in an UNACCOUNTED option shape (grammar not yet migrated). A
                           capability migration (or a captured pair) unblocks it.
      unsupported        — no emitter for this step id at all. A capture unblocks a new emitter.
      ddr-gap       — CLASS 2 (source-completeness): the clip needs data the DDR projection never held
                      (e.g. Print PlatformData geometry). NO capture fixes this — it is a policy
                      decision (emit the schema-held minimum + mask, or refuse). Do NOT request a
                      capture for a ddr-gap.

    The covered/unverified decision reads the LIVE emitter fence (VERIFIED_STEP_IDS + _VERIFIED_SIGS via
    _unsupported_reason), never a hand-maintained mirror — so this can never drift from what the emitter
    actually reproduces. The ddr-gap layer comes from the declarative catalog (clip_catalog.yaml),
    grounded in our own committed (DDR, clip) pairs.

    artifact_path:     the stored SaveAsXML artifact (archive ref / UUID / alias).
    object_name_or_id: ONE script to scan (get_object's friendly matching). Omit to scan EVERY script in
                       the artifact — the corpus-wide "what should we capture next?" view.
    section:           only 'ScriptCatalog' is supported (scripts); stated honestly.
    limit:             max backlog groups listed (default 25); the structured block reports the total.
    """
    import json as _json

    from corpusfm.core import clip_catalog as cc
    from corpusfm.core import evidence as ev

    if section != "ScriptCatalog":
        return (f"ERROR: detect_clip_variations supports section='ScriptCatalog' (scripts) only — "
                f"got {section!r}. Other object types have no clip emitter to triage against.")
    try:
        art = _load_artifact(artifact_path, Path(archive_dir) if archive_dir else None)
    except Exception as exc:
        return f"ERROR loading artifact: {exc}"

    catalog = cc.load_catalog()
    if object_name_or_id:
        item = ev.find_artifact_item(art, object_name_or_id, section="ScriptCatalog")
        if item is None or item.is_folder:
            pool = [it for it in art.items.values()
                    if it.section == "ScriptCatalog" and not it.is_folder]
            q = (object_name_or_id or "").strip().lower()
            near = sorted({it.name for it in pool if q and q in (it.name or "").lower()}) \
                or sorted({it.name for it in pool})[:20]
            return (f"No script matched {object_name_or_id!r} in ScriptCatalog of {artifact_path}.\n"
                    f"Candidates: {', '.join(near[:20]) or '(none)'}")
        src = next((s for s in (item.xml_sources or []) if s.catalog == "StepsForScripts"), None)
        if src is None:
            return f"Script '{item.name}' has no 'StepsForScripts' XML source (no steps stored)."
        rep = cc.detect_variations(src.xml, catalog)
        scope = f"script '{item.name}'"
    else:
        rep = cc.scan_artifact(art, catalog)
        scope = "every script in the artifact"

    total, covered = rep["total_steps"], rep["covered"]
    if not total:
        return f"No script steps found in {scope} of {artifact_path} — nothing to triage."
    pct = _coverage_pct(covered, total)
    counts = rep["counts"]
    backlog = rep["backlog"]

    needs_capture = [g for g in backlog if g["kind"] in cc.NEEDS_CAPTURE]
    gaps = [g for g in backlog if g["kind"] == cc.DDR_GAP]
    blocked_steps = sum(g["count"] for g in needs_capture)

    _experimental_n = rep.get("experimental", 0)
    _exp_tail = (f" (incl. {_experimental_n} experimental-capable — emit today, NOT captures owed)"
                 if _experimental_n else "")
    lines = [
        f"Clip-emitter triage — {scope} of {artifact_path}",
        f"  COVERAGE: {covered}/{total} steps ({_fmt_pct(covered, total)}) would export today{_exp_tail}.",
        f"  kinds: " + " · ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "",
    ]
    if not needs_capture and not gaps:
        lines.append(f"{scope} exports whole — no captures owed"
                     + (f" ({_experimental_n} step(s) emit experimentally, capability-complete but "
                        "uncaptured; a paste result would promote them)." if _experimental_n
                        else " (every step is a byte-verified shape)."))
    # packet 1080 §3 — two groups with DIFFERENT asks. The old single "NEEDS CAPTURE — capture the top
    # rows first" banner was false for every one of them: we hold a committed clip for all 217 canonical
    # step types, so the blocker is CODE. Telling someone to re-capture bytes already in the repo is
    # worse than stale, it is actively misleading — the same defect as the CAPTURE-BACKLOG §③ drift.
    code_blocked = [g for g in needs_capture if (g.get("evidence") or {}).get("held")]
    capture_owed = [g for g in needs_capture if not (g.get("evidence") or {}).get("held")]

    # `limit` caps the WHOLE listing (its documented contract), not each group — otherwise splitting the
    # backlog in two would quietly double what a given limit prints. The budget is spent on NEEDS A
    # CAPTURE first: that is the group that asks a human to go do something, it is usually the short one,
    # and it must never be the part that gets chopped. Any drop is disclosed — never a silent cap.
    budget = [limit]

    def _rows(groups):
        out, shown = [], groups[:budget[0]]
        budget[0] -= len(shown)
        for g in shown:
            raw = (g.get("example") or {}).get("shape") or []
            shape = f"[{', '.join(map(str, raw))}]" if raw else "(bare — no parameters)"
            out.append(f"    id {g['id']} · {g.get('name') or '?'} · {g['kind']} · "
                       f"x{g['count']} · {shape}")
            ev = g.get("evidence") or {}
            if ev.get("held"):
                out.append(f"        held: {ev['shapes']} captured clip shape(s) in "
                           f"{', '.join(ev['fixtures'])} ({', '.join(ev['scopes'])})")
            if g.get("note"):
                out.append(f"        note: {g['note']}")
        if len(groups) > len(shown):
            out.append(f"    … {len(groups) - len(shown)} more (raise limit to see them)")
        return out

    if capture_owed:
        lines += [
            f"NEEDS A CAPTURE — {len(capture_owed)} distinct shape(s) blocking "
            f"{sum(g['count'] for g in capture_owed)} step(s), ranked by occurrences in this corpus.",
            "We hold NO captured clip for these step ids. Each needs ONE real (DDR, clip) pair; capture "
            "the top rows first — they unblock the most.",
            "",
            "  (id · name · kind · occurrences · unverified shape)",
        ] + _rows(capture_owed) + [""]
    if code_blocked:
        lines += [
            f"NEEDS AN EMITTER — {len(code_blocked)} distinct shape(s) blocking "
            f"{sum(g['count'] for g in code_blocked)} step(s), ranked by occurrences in this corpus.",
            "⚠ DO NOT CAPTURE THESE. We already hold a real FileMaker clip for each of these step ids "
            "(committed under tests/fixtures/clip_emit/). The blocker is code, not evidence — "
            "writing the emitter is the work.",
            "Caveat, stated honestly: this is id-level. The fence is per-SHAPE, so a step id we hold a "
            "BASE clip for may still lack YOUR configured shape. Check the named fixture before "
            "concluding a capture is owed.",
            "",
            "  (id · name · kind · occurrences · unverified shape)",
        ] + _rows(code_blocked)
    if gaps:
        lines += [
            "",
            f"DDR-GAPS (class 2 — NOT capturable; {len(gaps)} shape(s)). The DDR projection never held "
            "what the clip needs here,",
            "so no capture and no emitter recovers it. These need a policy decision (emit the "
            "schema-held minimum + mask, or refuse) — do not request a capture.",
            "",
        ]
        for g in gaps[:limit]:
            gap = g.get("gap") or {}
            lines.append(f"    id {g['id']} · {g.get('name') or '?'} · x{g['count']}")
            lines.append(f"        gap: {gap.get('gap') or 'source-incomplete'}")
            if gap.get("decision"):
                lines.append(f"        decision: {gap['decision']}")

    _struct = {
        "result": "triage", "scope": scope, "artifact": artifact_path,
        "total_steps": total, "covered_steps": covered, "coverage_pct": pct,
        # packet 1091 — covered_steps = would export today = verified + experimental-capable; the split is
        # here so an agent never reads an experimental-capable shape as a capture owed.
        "verified_steps": rep.get("verified", covered), "experimental_capable_steps": _experimental_n,
        "counts": counts,
        "needs_capture": [
            {"id": g["id"], "name": g.get("name"), "kind": g["kind"], "occurrences": g["count"],
             "shape": (g.get("example") or {}).get("shape"), "note": g.get("note"),
             # packet 1080 §3 — what we ALREADY hold, so an agent reading only this block cannot
             # conclude "go capture it" for bytes already committed.
             "blocker": "code" if (g.get("evidence") or {}).get("held") else "evidence",
             "clip_evidence": g.get("evidence")}
            for g in needs_capture],
        "capture_really_needed": rep.get("capture_really_needed", []),
        "code_blocked": rep.get("code_blocked", []),
        "ddr_gaps": [
            {"id": g["id"], "name": g.get("name"), "occurrences": g["count"], "gap": g.get("gap")}
            for g in gaps],
        "note": "kinds read the LIVE step assessment (packet 1091). 'experimental-capable' EMITS today "
                "(capability-complete, uncaptured) — it is NOT in needs_capture and is NOT a capture owed. "
                "A 'ddr-gap' is class-2 source-incompleteness — never request a capture for one. A "
                "'new-variation' is a verified step id in an UNACCOUNTED option shape (its grammar is not "
                "yet migrated). ⚠ Read `blocker` before asking anyone to "
                "capture anything: blocker='code' means we ALREADY hold a real clip for that step id "
                "(see clip_evidence.fixtures) and the work is writing the emitter — do NOT request a "
                "capture. Only blocker='evidence' is a genuine capture ask. `clip_evidence` is "
                "id-level, not per-shape: a base clip may not cover a configured shape.",
    }
    lines += ["", "--- STRUCTURED (machine-readable JSON) ---", _json.dumps(_struct)]
    return "\n".join(lines)


def _save_text_deliverable(text: str, name: str, artifact_type: str, kind: str,
                           archive_dir: str, context: str, tool: str) -> str:
    """Shared body for save_fmscript / save_fmcalc — store a single text object as a
    low-fidelity catalog artifact via store_deliverable (no schema parse)."""
    text = (text or "").strip()
    if not text:
        return f"ERROR: empty {kind} — nothing to save."
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    nm = (name or "").strip() or kind
    nm = (nm[:80] + "…") if len(nm) > 80 else nm
    from corpusfm.server import queue_handlers
    res = queue_handlers.enqueue_deliverable_and_wait(
        backend, text.encode("utf-8"), artifact_type=artifact_type, origin="MCP",
        owner=_mcp_actor(),
        name=nm, description=f"{kind}: {nm}")
    if res["status"] == "failed":
        return f"ERROR saving {kind}: {res['error']}"
    return "\n".join([
        f"{kind} saved as a {artifact_type} artifact in the catalog."
        + (" (still processing — it will appear shortly)" if res["status"] == "timeout" else ""),
        f"  uuid: {res['uuid']}",
        f"  name:     {nm}",
        "",
        f"It appears on the Artifacts page (type {artifact_type}); a developer can open, copy, and",
        f"save it as a .{artifact_type} file. This is a low-fidelity text tenant — store/view/export",
        "only, no Explorer/Diff/xref (see get_artifact_types).",
    ])


@mcp.tool()
def save_fmscript(
    script_text: str,
    name: str = "",
    artifact_path: str = None,
    archive_dir: str = None,
) -> str:
    """Save a single FileMaker script as an fmScript artifact (packet 033).

    fmScript is a plain-text representation of ONE FileMaker script (the fmscript.org grammar).
    Use this when you've composed/translated a script as text and want it kept in the catalog as
    a durable, downloadable artifact. It becomes one first-class record (type=fmScript, origin=MCP)
    — store + view + export only (a low-fidelity text tenant; no Explorer/Diff/xref). For a
    multi-object, paste-into-FileMaker clip use save_clip instead.

    script_text:   the fmscript text (one script).
    name:          a short name for the artifact (defaults to "fmScript").
    artifact_path: optional context artifact (archive-relative) for the action log.
    """
    return _save_text_deliverable(script_text, name, "fmScript", "fmScript",
                                  archive_dir, artifact_path, "save_fmscript")


@mcp.tool()
def save_fmcalc(
    calc_text: str,
    name: str = "",
    artifact_path: str = None,
    archive_dir: str = None,
) -> str:
    """Save a single FileMaker calculation as an fmCalc artifact (packet 033).

    fmCalc is the raw FileMaker calc-expression text for ONE calculation (FM's own calc language
    is the format — no invented grammar). Use this to keep a composed/extracted calc in the
    catalog as a durable, downloadable artifact (type=fmCalc, origin=MCP) — store + view + export
    only (low-fidelity text tenant; no Explorer/Diff/xref).

    calc_text:     the FileMaker calculation expression text.
    name:          a short name for the artifact (defaults to "fmCalc").
    artifact_path: optional context artifact (archive-relative) for the action log.
    """
    return _save_text_deliverable(calc_text, name, "fmCalc", "fmCalc",
                                  archive_dir, artifact_path, "save_fmcalc")


# The largest inline source_xml import_artifact accepts. This transport is for IN-CONTEXT generated
# XML (the reconstruct flow); a large real DDR (~26 MB) belongs on the HTTP import endpoint, which is
# the only path with the 1 GB cap and off-context byte transfer. This soft cap is transport hygiene —
# the parse is worker-serialized regardless, so the queue is never the concern (packet 1167 B2).
_IMPORT_ARTIFACT_INLINE_CAP = 4 * 1024 * 1024


@mcp.tool()
def import_artifact(
    source_xml: str,
    name: str = "",
    locale: str = "",
    summarize: bool = False,
    index: bool = False,
) -> str:
    """Ingest a complete FileMaker export you already hold in context (SaveAsXML, Addon, or clip XML)
    and store it as a real catalog artifact — THROUGH the server's ingest queue.

    Use this for in-context, AI-generated/reconstructed XML (e.g. a reconstructed <FMSaveAsXML>): the
    worker auto-detects the type and parses it through the full pipeline (items, xref, dead-ends), so
    Explorer / Diff / get_schema_context all work on the result. NOT for patches or clips as
    deliverables (use save_ai_patch / save_clip) and NOT for materializing a .fmp12 (use
    generate_db_file).

    This does NOT block on the parse: it stages the source, enqueues a [upload, ingest] record, and
    returns a queue id immediately. Poll get_queue to watch it land (the artifact appears in the catalog
    once ingest completes). The record is owned by YOUR user (cancel/restart from the queue) and stamped
    origin="MCP".

    For files on disk or BULK import, do NOT pass bytes here — POST each file to the HTTP endpoint and
    poll:  curl -F file=@f.xml -H "Authorization: Bearer $CFM_TOKEN" <server>/api/import/source  (that
    path carries the 1 GB cap and moves bytes off-context); then poll get_queue. This tool is for a
    single, small, in-context export.

    source_xml: the complete export XML string (FMSaveAsXML / FMAdd_on / fmxmlsnippet clip).
    name:       display name for the record (defaults to the export's own name).
    locale:     addon locale hint (addon imports only).
    summarize:  also enqueue AI summaries after landing (needs a summary provider).
    index:      also enqueue vector indexing after landing (needs an embedder).
    """
    xml_bytes = source_xml.encode("utf-8")
    if len(xml_bytes) > _IMPORT_ARTIFACT_INLINE_CAP:
        mb = _IMPORT_ARTIFACT_INLINE_CAP // (1024 * 1024)
        return (f"ERROR: source_xml is {len(xml_bytes) // (1024 * 1024)} MB, over the {mb} MB inline "
                "limit for this tool. For large/bulk files POST to the HTTP endpoint instead:\n"
                "  curl -F file=@f.xml -H \"Authorization: Bearer $CFM_TOKEN\" "
                "<server>/api/import/source\nthen poll get_queue. (That path has the 1 GB cap and moves "
                "bytes off-context; this inline tool is for a single small in-context export.)")

    from corpusfm.server import queue_handlers, queue_workers
    from corpusfm.storage.queue_record import INGEST
    backend = get_backend()
    try:
        qid = queue_handlers.enqueue_import(
            backend, xml_bytes, filename=(name or "import") + ".xml",
            name=(name or "").strip(), locale=locale or "",
            summarize=bool(summarize), index=bool(index),
            owner=_mcp_actor(), origin="MCP",
        )
    except Exception as exc:
        return f"ERROR: could not stage the import — {exc}"
    queue_workers.poke(INGEST)
    return (
        "Import staged on the ingest queue.\n"
        f"  queue record: {qid}\n"
        f"  owner:        {_mcp_actor()}\n"
        "\nThe worker auto-detects SaveAsXML / Addon / clip and lands it in the catalog. "
        "Poll get_queue to watch it complete."
    )


# Short TTL for a signed download URL — a bulk `curl` loop finishes well within it; leakage is bounded
# (packet 1166 A3-auth). A signed URL is REPLAYABLE until exp (statelessness precludes single-use without
# a store) — acceptable for a read of data the caller is already entitled to.
_DOWNLOAD_URL_TTL_SECONDS = 600


@mcp.tool()
def download_container_data(
    refs: list = None,
    containers: list = None,
    type: str = "",
    file: str = "",
    all: bool = False,
) -> str:
    """Get LOCAL-DOWNLOAD URLs for the retained contents of catalog records — the raw source XML, the
    parsed artifact, AI summaries, or the addon name-map — for one record or many.

    The MCP server runs ON the box; the corpus files live on YOUR machine — so this tool cannot land a
    file for you. Instead it returns a manifest of **signed, expiring GET URLs** you `curl` locally,
    wherever you want the bytes. **No artifact bytes pass through this result.** Each URL is signed with
    the box's server key and carries NO credential — you curl it with no header and no body:
        curl -O -J "<signed_url>"
    URLs expire in ~10 minutes (mint fresh by calling again); they are valid only on the box that minted
    them. The library_mcp gate is checked HERE, at mint time — the download itself verifies only the
    signature + expiry + that the record is a visible catalog artifact.

    Select records by `refs` (UUIDs or human aliases) OR a filter: `all=true` (every visible record),
    `type=` (e.g. SaveAsXML / fmClip), `file=` (exact FM file name). `containers` chooses which blobs
    (default ["SourceXML","ArtifactData"]); opt into "SummariesData" / "NameMapData" / "icon" explicitly.
    ArtifactData is the deliverable file for a deliverable, the parsed artifact.json for a schema record.

    To evacuate ALL retained raw XML: download_container_data(all=true, containers=["SourceXML"]) then
    curl each returned URL. An absent slot (a non-addon record has no name-map; a Seed record retains no
    source) is reported skipped-with-reason — never an error.
    """
    import json as _json
    import time as _time
    from corpusfm.app.web import container_download as _cd
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.app.web.deployment import external_base_url
    from corpusfm.core import crypto
    from corpusfm.core.filenames import ensure_fmp12

    backend = get_backend()
    want = [c for c in (containers or list(_cd.DEFAULT_CONTAINERS)) if c in _cd.CONTAINER_NAMES]
    if not want:
        return "ERROR: no valid containers requested. One of: " + ", ".join(_cd.CONTAINER_NAMES)

    # Resolve the selection → [(uuid, meta)]. refs win; else a filter over the visible catalog.
    selected: list = []
    skipped_refs: list = []
    if refs:
        for ref in refs:
            uuid, err = resolve_ref(backend, ref)
            if err is not None:
                skipped_refs.append({"ref": ref, "reason": "not found"})
                continue
            selected.append((uuid, backend.get_artifact_meta(uuid)))
    elif all or type or file:
        want_file = ensure_fmp12(file).lower() if file else ""
        for m in backend.iter_artifact_metas():
            if type and getattr(m, "artifact_type", "") != type:
                continue
            if want_file and (getattr(m, "file_name", "") or "").lower() != want_file:
                continue
            selected.append((m.uuid, m))
    else:
        return ("ERROR: specify records — pass refs=[...] OR a filter (all=true, or type=, or file=).")

    # Build the download base from the ONE authoritative External CORPUSfm address (packet 1180
    # correction): externally-usable URLs ALWAYS resolve through the shared resolver — never from the
    # incoming MCP request Host (a spoofable, per-request value that could yield an off-box http:// or a
    # host CORPUSfm never verified) and never a loopback base. The shared address is https, non-loopback,
    # and path-matched to web_prefix by construction, so it is the only value safe to hand another
    # machine. When none is configured we return an honest, actionable error rather than a URL a remote
    # caller cannot trust or reach.
    base = (external_base_url() or "").rstrip("/")
    if not base:
        return ("ERROR: this box has no MCP address, so no externally-usable download URL can be built. "
                "Set Settings -> MCP (the HTTPS base another machine uses to reach this box, including "
                "its web prefix), then re-call this tool.")
    exp = int(_time.time()) + _DOWNLOAD_URL_TTL_SECONDS
    rows: list = []
    total_bytes = 0
    for uuid, meta in selected:
        if not _cd.is_visible(meta):
            skipped_refs.append({"ref": uuid, "reason": "not a visible catalog record"})
            continue
        for c in want:
            if not _cd.present(meta, c):
                rows.append({"uuid": uuid, "name": getattr(meta, "name", ""),
                             "artifact_type": getattr(meta, "artifact_type", ""), "container": c,
                             "present": False, "skipped": _cd.absent_reason(c)})
                continue
            sig = crypto.sign_download(uuid, c, exp)
            size = int(getattr(meta, "xml_bytes", 0) or 0) if c == "SourceXML" else None
            if size:
                total_bytes += size
            rows.append({"uuid": uuid, "name": getattr(meta, "name", ""),
                         "artifact_type": getattr(meta, "artifact_type", ""), "container": c,
                         "present": True, "bytes": size,
                         # Some containers arrive ZIPPED (packet 1226) — `bytes` is the payload's own
                         # size, not the download's. Say so, or the caller unpacks nothing and reports
                         # a corrupt file. `is_zipped` is the SHARED rule the HTTP route uses; never
                         # restate the condition here, or the two can drift apart.
                         "delivered_as": "zip" if _cd.is_zipped(c, meta) else "raw",
                         "signed_url": f"{base}/api/artifact-download/{uuid}?container={c}&exp={exp}&sig={sig}"})

    n_urls = sum(1 for r in rows if r.get("present"))
    if not rows:
        return "No matching records. (Nothing selected, or the filter matched nothing.)"
    out = {
        "count_records": len(selected),
        "count_urls": n_urls,
        "source_xml_bytes_total": total_bytes,
        "url_ttl_seconds": _DOWNLOAD_URL_TTL_SECONDS,
        "how_to": ("curl -O -J each signed_url (no header, no body); URLs expire in ~10 min. "
                   "Rows with delivered_as=zip arrive compressed — unzip to get the single file "
                   "inside; `bytes` is that file's size, not the download's."),
        "rows": rows,
        "skipped": skipped_refs,
    }
    return _json.dumps(out, ensure_ascii=False, indent=2)


@mcp.tool()
def set_artifact_memory(artifact_path: str, memory: str, archive_dir: str = None) -> str:
    """Set the agent-authored MEMORY note on an artifact (your durable notes about it).

    `memory` is a searchable, agent-owned field on the artifact record — distinct from the
    human-authored `description`. Use it to leave context for your future self or other
    agents (what this file is, decisions made, gotchas). Overwrites any prior memory.

    artifact_path: archive-relative path to the artifact.
    memory:        the note text to store (replaces existing memory).
    archive_dir:   override archive directory (optional).
    """
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    try:
        uuid = _artifact_uuid(artifact_path, Path(archive_dir) if archive_dir else None)
    except ValueError as exc:
        return f"ERROR: {exc}"
    if not uuid or backend.get_artifact_meta(uuid) is None:
        return f"ERROR: no artifact found at {artifact_path!r}."
    try:
        backend.update_record(uuid, {"memory": memory})
    except Exception as exc:
        return f"ERROR: could not set memory — {exc}"
    _bust_catalog_snapshot()   # memory shows on the snapshot-served catalog card
    # set_memory is a metadata mutation, not artifact-activity history (085 U3c) — not a HISTORY event.
    return f"Memory set on {artifact_path} ({len(memory)} chars)."


@mcp.tool()
def delete_source(artifact_path: str, archive_dir: str = None) -> str:
    """Delete an artifact's retained source XML to reclaim storage (packet 059).

    CORPUSfm keeps the original FM source XML (gzip-compressed) with each artifact by default — the
    archived original for git export / download / audit. This drops it. The analyzed artifact (Explorer,
    Diff, xref, summaries, search index) is UNTOUCHED and keeps working; only the raw original is removed.
    Irreversible — there is no re-derivation or re-download recovery.

    artifact_path: archive-relative path to the artifact.
    archive_dir:   override archive directory (optional).
    """
    backend = get_backend(Path(archive_dir) if archive_dir else None)
    try:
        uuid = _artifact_uuid(artifact_path, Path(archive_dir) if archive_dir else None)
    except ValueError as exc:
        return f"ERROR: {exc}"
    meta = backend.get_artifact_meta(uuid) if uuid else None
    if meta is None:
        return f"ERROR: no artifact found at {artifact_path!r}."
    if not getattr(meta, "has_source", False):
        return f"No source XML stored for {artifact_path} — nothing to delete."
    try:
        removed = backend.delete_source(uuid)
    except Exception as exc:
        return f"ERROR: could not delete source — {exc}"
    if removed:
        _bust_catalog_snapshot()   # has_source rides the snapshot-served catalog rows
    # delete_source is a mutation, not artifact-activity history (085 U3c) — not a HISTORY event.
    return (f"Deleted the source XML for {artifact_path} (the analyzed artifact is kept)."
            if removed else f"No source XML was present for {artifact_path}.")


# ── Update control plane (packet 1124) ────────────────────────────────────────────
# Four permanent, short-named tools that let an authorized agent inspect, authorize, and verify one
# exact code-only origin/main self-update through the SAME tested Settings updater authority
# (corpusfm.server.update_service). They do not create a second git updater, grant root, run the
# installer, choose a branch/server, or make updates automatic. The names/schemas are a compatibility
# promise (guarded); a self-update terminates the serving connection, so the stable names + the
# reconnect/status handshake — not a live notification — are the primary update rendezvous.

def _list_changed_declared():
    """Best-effort: does THIS server declare the tools/list_changed notification capability? Returns a
    bool, or None when it cannot be determined. A FACT about the server declaration — NOT a promise the
    client will refresh (a process replacement drops the live connection the notification rides)."""
    try:
        srv = getattr(mcp, "_mcp_server", None)
        if srv is None:
            return None
        caps = srv.get_capabilities(srv.notification_options, {})
        return bool(getattr(getattr(caps, "tools", None), "listChanged", False))
    except Exception:
        return None


def _mcp_protocol_versions() -> dict:
    """Best-effort MCP/FastMCP version facts (never raises; missing → None)."""
    out = {"fastmcp_version": None, "mcp_protocol_version": None}
    try:
        import fastmcp as _fm
        out["fastmcp_version"] = getattr(_fm, "__version__", None)
    except Exception:
        pass
    try:
        from mcp import types as _mt
        out["mcp_protocol_version"] = getattr(_mt, "LATEST_PROTOCOL_VERSION", None)
    except Exception:
        pass
    return out


@mcp.tool()
def server_capabilities() -> str:
    """Read-only update rendezvous: confirm exactly which build you are talking to and how to recover the
    MCP client after a self-update restart (packet 1124). Gate: library_mcp.

    Returns (JSON): the running CORPUSfm version/build/head + deployment mode; the control-plane
    revision; whether the four stable update tools are registered in THIS process; the MCP protocol /
    FastMCP version if safely available; whether tools/list_changed notification support is DECLARED
    (a fact about the server — NOT a promise the client will auto-refresh); and the one-line VS Code
    recovery order. It deliberately returns NO tool inventory, secrets, filesystem paths, token state,
    environment, or generic invocation surface — use the normal tools/list for the tool set."""
    import json as _json
    from corpusfm import __version__
    from corpusfm.server import update_service

    head = None
    try:
        from corpusfm import updater
        head = update_service._rev_parse(updater._repo_root(), "HEAD")
    except Exception:
        head = None

    registered = {n: callable(globals().get(n)) for n in update_service.STABLE_TOOL_NAMES}
    versions = _mcp_protocol_versions()
    return _json.dumps({
        "product": "CORPUSfm",
        "version": __version__,
        "build": str(__version__).rsplit(".", 1)[-1],
        "head": head,
        "mode": "server" if _SERVER_MODE else "local",
        "control_plane_revision": update_service.CONTROL_PLANE_REVISION,
        "update_tools_registered": registered,
        "all_update_tools_registered": all(registered.values()),
        "mcp_protocol_version": versions["mcp_protocol_version"],
        "fastmcp_version": versions["fastmcp_version"],
        "tools_list_changed_declared": _list_changed_declared(),
        "vscode_recovery_order": [
            "MCP: List Servers → reconnect/restart this server",
            "MCP: Reset Cached Tools (only if definitions remain stale)",
            "Reload the VS Code window (fallback only)",
        ],
        "note": ("A server self-update restarts the MCP-serving process and DROPS this connection. "
                 "After it, reconnect and issue a fresh tools/list. notifications/tools/list_changed "
                 "helps only where the live connection survives — a process replacement is not that "
                 "case. The four stable tool names mean the update rendezvous does not depend on "
                 "discovering a newly-named status tool after a release."),
    }, indent=2)


@mcp.tool()
def update_check() -> str:
    """Inspect the pending origin/main update as an EXACT, immutable target before authorizing it
    (packet 1124). Read-only wrapper over the shared Settings-updater authority. Gate: settings.

    This is an EXPLICIT check, so it asks the fixed privileged updater for a fresh refusal-only
    observation — an impossible all-zero consent that cannot authorize a checkout — and then reads
    only the refs that operation left behind. The service performs no git fetch itself and never
    writes `.git`. The returned `observation` field reports which kind of look produced the result
    (`observed` fresh, `classified` from refs already on disk, `direct` on a development tree).

    Returns (JSON): current running version + head; the fetched origin/main target version + head;
    the head_build_version (the git-derived build for the exact HEAD, independent of the runtime
    stamp) and stamp_repair (true when the checkout is CURRENT but the runtime build stamp is stale —
    a fetch/reset deploy that advanced git without re-stamping. REPORTED ONLY: there is no in-app
    repair for it, and an installer run rewrites the stamp); the behind count and update_available;
    the privacy-safe classification (schema_change / installer_change + platform reasons — raw git
    tails withheld); apply_allowed (this read-only view's opinion that an update is worth authorizing
    — not permission: the elevated operation re-decides every gate itself); the canonical operator
    command when the installer is required; and the control-plane revision. Pass the returned target_head to update_apply verbatim —
    that exact head is the authorization."""
    import json as _json
    from corpusfm.server import update_service
    # refresh=True: this tool IS the explicit action (packet 1251, developer ruling D2). The shared
    # authority defaults to passive so the all-users sidebar poll cannot start a root one-shot per
    # browser — and the first version of this change left that default here, so an agent asking to
    # check for updates silently got whatever refs were last on disk while the docstring promised a
    # fetched target. The `observation` field in the result says which one a caller received.
    res = update_service.check(refresh=True)
    return _json.dumps(res.to_public_dict(), indent=2)


@mcp.tool()
def update_apply(expected_head: str) -> str:
    """Authorize and apply ONE exact, already-inspected code-only origin/main update, then schedule the
    supervised restart (packet 1124). Mutating wrapper over the shared authority. Gate: settings.

    expected_head — the exact origin/main head from update_check. THE SERVICE DOES NOT UPDATE
    ANYTHING (packet 1246-03): it triggers one fixed elevated operation that takes no arguments, and
    that operation resolves origin/main for itself. `expected_head` is a refusal-only consent
    precondition — it cannot name a ref, cannot reach an older commit, and cannot make an otherwise
    ineligible update eligible. There is NO branch/repo/server/host/force/reset/command/installer
    argument, and none can be added: the elevated side accepts none.

    Refusals come from two places and are reported identically. Here: installation_state_unclear /
    not_a_published_installation / update_in_progress / consent_required / invalid_expected_head /
    privileged_updater_unavailable / outcome_authority_unproven / request_not_written /
    trigger_failed / update_execution_timeout / no_matching_outcome. From the elevated operation's
    own outcome record, passed through verbatim: origin_mismatch, unclean_tree, not_fast_forward,
    needs_installer, target_changed, import_probe_failed and the rest.

    On success it returns the request id, old/applied head + version, restart_scheduled, and the
    reconnect/status instruction, THEN restarts shortly after this result flushes. The restart drops
    this MCP connection: reconnect the client and call update_status(request_id) to confirm which
    update landed. Returns JSON."""
    import json as _json
    from corpusfm.server import update_service
    r = update_service.apply(expected_head=expected_head, actor=_mcp_actor())
    out = {
        "ok": r.ok,
        "reason_code": r.reason_code,
        "request_id": r.request_id or None,
        "old_head": r.old_head,
        "old_version": r.old_version,
        "applied_head": r.applied_head,
        "target_version": r.target_version,
        "restart_scheduled": r.restart_scheduled,
        "restart_mode": r.restart_mode,
        "stamp_repair": r.stamp_repair,
        "message": r.message,
    }
    if r.reason_code in ("needs_installer", "import_probe_failed"):
        out["operator_command"] = r.operator_command
        out["schema_change"] = r.schema_change
        out["installer_change"] = r.installer_change
        out["rolled_back"] = r.rolled_back
    if r.ok:
        out["next"] = ("The server is restarting. Reconnect this MCP client (VS Code: MCP: List "
                       "Servers), then call update_status(request_id) to confirm the running head "
                       "matches the applied update.")
    return _json.dumps(out, indent=2)


@mcp.tool()
def update_status(request_id: str = "") -> str:
    """Confirm which update actually landed after the restart (packet 1124). Read-only durable
    status/reconciliation wrapper over the shared authority. Gate: settings.

    request_id — empty returns the latest recorded attempt; an explicit id that does not match the most
    recent attempt refuses clearly (only the latest is retained). It lazily reconciles a scheduled
    restart: once the running process's version matches the applied update the state becomes
    `restarted`; a genuine mismatch becomes a named non-success state (never a silent success). Status
    reads never fetch, pull, restart, or mutate the repository. Same-request polling is idempotent.
    Returns JSON: {ok, reason_code, record?}."""
    import json as _json
    from corpusfm.server import update_service
    s = update_service.status(request_id or "")
    return _json.dumps({
        "ok": s.ok,
        "reason_code": s.reason_code,
        "message": s.message,
        "record": s.record,
    }, indent=2)
