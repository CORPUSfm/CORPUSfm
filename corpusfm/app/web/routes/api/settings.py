"""Settings API — archive, git registrations, notifications, preferences, server controls."""

from __future__ import annotations

import os
import sys
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import require_auth, require_gate

router = APIRouter()

# Settings routes are admin-only: pair require_auth with the `settings` gate so a non-admin
# logged-in user can't drive them directly. The TWO read-only exceptions reachable by any
# authed user keep require_auth alone: GET /settings/check-update (the all-users sidebar update
# notice polls it) and GET /settings/mcp-info (status the Library → MCP page reads; value-free).
_ADMIN = [Depends(require_auth), Depends(require_gate("settings"))]


def _installed_filemaker_projection() -> dict:
    """Bounded, secret-free view of the installation-owned FileMaker backend."""
    from corpusfm.lifecycle import runtime_storage

    published = runtime_storage.published_installation()
    if published is None:
        return {"state": "unpublished", "managed_by": "none",
                "reason": "This checkout has no published installation."}
    block = getattr(published, "storage", None)
    if block is None or not getattr(block, "initialized", False):
        return {"state": "not_composed", "managed_by": "installation",
                "reason": "This installation has not composed its storage corpus yet."}
    try:
        resolved = runtime_storage.resolve()
        return {
            "state": "active", "managed_by": "installation", "host": resolved.host,
            "database": resolved.database_name, "account": resolved.account,
            "access_available": True, "verify_ssl": resolved.verify_ssl,
        }
    except Exception as exc:
        return {"state": "unavailable", "managed_by": "installation",
                "database": str(getattr(block, "database_name", "") or ""),
                "access_available": False, "reason": str(exc)[:500]}


def _lifetime_choices() -> list:
    """The OAuth connection lifetime ladder as ``[{id, label}]`` — the complete supported set, served
    from the policy module so a label can never advertise a duration the server does not enforce."""
    try:
        from corpusfm.app.web.oauth_policy import POLICIES, POLICY_LABELS
        return [{"id": pid, "label": POLICY_LABELS[pid]} for pid in POLICIES]
    except Exception:
        return []


def _persisted_public_base() -> str:
    from corpusfm.install import read_install_config
    try:
        return str(read_install_config().get("public_base_url", "") or "")
    except Exception:
        return ""


@router.get("/settings/data", dependencies=_ADMIN)
async def settings_data(request: Request) -> JSONResponse:
    try:
        from corpusfm.storage import get_backend
        from corpusfm.storage.local import load_settings
        from corpusfm.server.monitor.config import load_monitor_config
        from corpusfm.app.app_config import load_app_config
        from corpusfm.core.git_formatter import list_registrations, resolve_local_path
        from corpusfm.config import is_server_mode
        from corpusfm.core.crypto import key_source
        from corpusfm.install import read_install_config
        from corpusfm.server import ai_env

        from corpusfm.server import remote_servers as _rs

        settings = load_settings()
        fm_config = _installed_filemaker_projection()
        # A broken published storage authority is itself a Settings state, not a reason for this
        # route to fail before the administrator can see it.
        try:
            backend = get_backend()
            archive_dir = str(getattr(backend, 'archive_dir', ''))
        except Exception:
            archive_dir = ""
        cfg = load_monitor_config()
        app_cfg = load_app_config()
        regs = list_registrations()
        try:
            servers = _rs.list_servers()
        except Exception:
            # Remote-server records live in the corpus. If corpus access is unavailable, preserve
            # the installed-backend diagnosis above rather than collapsing the whole page to 500.
            servers = []
        email = cfg.email or {}

        install_cfg = read_install_config()
        storage_backend = "fm_odata" if fm_config["state"] == "active" else fm_config["state"]

        # The MCP address (packet 1180, scoped to MCP by 1219): the one value this box asserts as its
        # own. Resolve through the shared resolver (which also runs the one-time
        # legacy-key→public_base_url migration), and offer the request-derived candidate as a one-click
        # suggestion. Read the persisted value AFTER external_base() so a just-migrated key shows
        # correctly. No secret is involved.
        external_address = _external_address_projection(request)
        return JSONResponse({
            "archive_dir": archive_dir,
            "key_source": key_source(),
            "storage_backend": storage_backend,
            "fm_config": fm_config,
            "external_address": external_address,
            "monitor": {
                "suppress_hours": cfg.suppress_hours,
                "overdue_grace_minutes": cfg.overdue_grace_minutes,
                "disk_min_gb": cfg.disk_min_gb,
                "webhook_url": cfg.webhook_url or "",
                "smtp_host": email.get("smtp_host", ""),
                "smtp_port": int(email.get("smtp_port", 587)),
                "smtp_user": email.get("username", ""),
                # Write-only secret (packet 1009/S1-E): expose only whether a password is set, never
                # the value. The client leaves the field blank to keep the stored one.
                "smtp_pass_set": bool(email.get("password", "")),
                "smtp_from": email.get("from_addr", ""),
                "smtp_to": ", ".join(email.get("to_addrs", [])),
            },
            "prefs": {
                "keep_source_xml": app_cfg.keep_source_xml,
                "encrypt_blobs": app_cfg.encrypt_blobs,
                "enable_fms_admin_mcp_tools": app_cfg.enable_fms_admin_mcp_tools,
                "enable_patching_mcp_tools": app_cfg.enable_patching_mcp_tools,
                # Packet 1183 — the OAuth connection lifetime ladder + its exact supported choices, so
                # the selector can never offer a duration the server does not enforce.
                "browser_connection_lifetime": app_cfg.browser_connection_lifetime,
                "browser_connection_lifetime_choices": _lifetime_choices(),
                "restrict_apply_to_compartment": app_cfg.restrict_apply_to_compartment,
                "ui_locale": app_cfg.ui_locale,
                # landing_page / docs_drawer_side / preferred_addon_locale are PER-USER now (Your account).
                "ai_summary_provider": app_cfg.ai_summary_provider,
                "ai_summary_model": app_cfg.ai_summary_model,
                "ai_summary_base_url": app_cfg.ai_summary_base_url,
                "ai_summary_api_version": app_cfg.ai_summary_api_version,
                "ai_summary_max_content_chars": app_cfg.ai_summary_max_content_chars,
                "ai_summary_include_xref": app_cfg.ai_summary_include_xref,
                "ai_summary_api_key_set": ai_env.has_ai_key("chat"),
                "ai_embedding_provider": app_cfg.ai_embedding_provider,
                "ai_embedding_model": app_cfg.ai_embedding_model,
                "ai_embedding_base_url": app_cfg.ai_embedding_base_url,
                "ai_embedding_api_version": app_cfg.ai_embedding_api_version,
                "ai_embedding_batch_size": app_cfg.ai_embedding_batch_size,
                "ai_embedding_api_key_set": ai_env.has_ai_key("embed"),
                "ai_embedding_verified": app_cfg.ai_embedding_verified,
                "ai_summary_verified": app_cfg.ai_summary_verified,
            },
            "registrations": [
                {
                    "name": r.name,
                    "cred_type": r.cred_type,
                    "repo": r.repo,
                    "repo_locked": r.cred_type == "deploy_key",  # D-Key repo is fixed downstream
                    "branch": r.branch,
                    "username": r.username,
                    "secret_set": bool(r.token_enc or r.ssh_key_enc),
                    "ssh_pubkey": r.ssh_pubkey,
                    "modes": r.modes,
                    "show_hidden": r.show_hidden,
                    "group": r.group or "",
                    "local_path": str(resolve_local_path(r)),
                }
                for r in regs
            ],
            "remote_servers": [
                {
                    "name": s.name,
                    "host": s.host,
                    "account": s.account,   # the fmsadmin Admin-API account
                    # Write-only secret: expose only whether set (blank field on edit keeps it).
                    "password_set": bool(s.password),
                    "verify_ssl": bool(s.verify_ssl),
                    "callback_url": s.callback_url or "",
                }
                for s in servers
            ],
            "is_server_mode": is_server_mode(),
        })
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/settings/archive-info", dependencies=_ADMIN)
async def archive_info() -> JSONResponse:
    try:
        from corpusfm.storage import get_backend
        from corpusfm.server import catalog
        backend = get_backend()
        # Counts are ordinary artifact discovery, so they come from the persistent catalog rather
        # than a STORAGE enumeration per settings page load (packet 1361-01, ruling 9). The
        # filesystem size below is still measured from the filesystem, which is the only authority
        # for it.
        _view = catalog.view(backend)
        if _view.failed:
            return JSONResponse({"exists": True, "catalog_failed": True, "unavailable": True,
                                 "reason": "storage"})
        _metas = [r["meta"] for r in _view.records]

        # FM backend: no filesystem — return snapshot counts only
        if not hasattr(backend, 'archive_dir'):
            metas = _metas
            snap_count = len(metas)
            fm_files = len({m.file_name for m in metas})
            return JSONResponse({
                "exists": True,
                "fm_mode": True,
                "total_size": "FM Database",
                "fm_files": fm_files,
                "artifacts": snap_count,
                "per_file": [],
            })

        arc = backend.archive_dir
        if not arc.exists():
            return JSONResponse({"exists": False})
        all_metas = _metas
        snap_count = len(all_metas)
        # Group flat metas by file_name locally for the per-file display (no backend grouping).
        by_file: dict = {}
        for m in all_metas:
            by_file.setdefault(m.file_name, []).append(m)
        total_bytes = sum(f.stat().st_size for f in arc.rglob("*") if f.is_file())
        total_mb = total_bytes / (1024 ** 2)
        if total_mb >= 1024:
            total_str = f"{total_mb / 1024:.1f} GB"
        else:
            total_str = f"{total_mb:.0f} MB"

        per_file = []
        for fm_file, metas in sorted(by_file.items()):
            fd = arc / fm_file
            sz = sum(f.stat().st_size for f in fd.rglob("*") if f.is_file()) if fd.exists() else 0
            sz_mb = sz / (1024 ** 2)
            sz_str = f"{sz_mb / 1024:.1f} GB" if sz_mb >= 1024 else f"{sz_mb:.0f} MB"
            per_file.append({"name": fm_file, "artifacts": len(metas), "size": sz_str})

        return JSONResponse({
            "exists": True,
            "fm_mode": False,
            "total_size": total_str,
            "fm_files": len(by_file),
            "artifacts": snap_count,
            "per_file": per_file,
        })
    except Exception as exc:
        return JSONResponse({"exists": False, "error": str(exc)})


@router.post("/settings/archive", dependencies=_ADMIN)
async def save_archive(request: Request) -> JSONResponse:
    try:
        if _installed_filemaker_projection()["state"] != "unpublished":
            return JSONResponse(
                {"ok": False, "error": "Installed storage is managed by the CORPUSfm installer."},
                status_code=409,
            )
        body = await request.json()
        from corpusfm.storage.local import load_settings, save_settings
        settings = load_settings()
        settings["archive_dir"] = body["archive_dir"]
        save_settings(settings)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/settings/initial-mcp-address", dependencies=_ADMIN)
async def initial_mcp_address(request: Request) -> JSONResponse:
    """The first-sign-in MCP address prompt's state (packet 1326) — admin-only, non-secret.

    `{"show": false}` once the installation has acknowledged it, so an ordinary page load costs one
    small read and nothing renders. A narrow contract on purpose: the shell must not pull the whole
    Settings payload on every page just to learn whether to prompt."""
    from corpusfm.app.web import mcp_address_prompt as prompt

    ack = prompt.acknowledged()
    if ack is None:
        # An unreadable authority is not "unset" — never prompt from a fallback default.
        return JSONResponse({"show": False, "available": False,
                             "error": "The settings authority could not be read."})
    if ack:
        return JSONResponse({"show": False, "available": True})
    projection = _external_address_projection(request)
    credentials = prompt.box_holds_any_mcp_credential()
    return JSONResponse({
        "show": True,
        "available": True,
        "external_address": projection,
        "candidates": prompt.address_candidates(projection),
        # Tri-state, and the UI must say the unknown case out loud rather than pick a side.
        "has_credentials": (prompt.CREDENTIALS_UNKNOWN if credentials is None else bool(credentials)),
        "reauthorize_warning": prompt.reauthorize_warning(projection.get("value", ""),
                                                          credentials=credentials),
    })


@router.post("/settings/initial-mcp-address/dismiss", dependencies=_ADMIN)
async def dismiss_initial_mcp_address(request: Request) -> JSONResponse:
    """Acknowledge the prompt WITHOUT changing the address (packet 1326). A failed or indeterminate
    write is not a dismissal: the caller keeps the pop-over open and says so."""
    from corpusfm.app.web import mcp_address_prompt as prompt
    if not prompt.acknowledge():
        return JSONResponse({"ok": False,
                             "error": "Could not record that you have seen this. It will appear again."},
                            status_code=500)
    return JSONResponse({"ok": True})


def _prompt_reauthorize_warning(new_value: str) -> str:
    """The re-sign-in sentence for the address save, derived from what this box actually holds."""
    from corpusfm.app.web import mcp_address_prompt as prompt
    return prompt.reauthorize_warning(new_value, credentials=prompt.box_holds_any_mcp_credential())


def _external_address_projection(request) -> dict:
    """The MCP-address facts, computed ONCE for every surface that states them (packet 1326).

    `/api/settings/data` (the Settings island) and `/api/settings/initial-mcp-address` (the first-sign-in
    prompt) must not disagree about what this box asserts, what it is serving, whether a restart is owed
    or whether the certificate covers the served host — so the stored-vs-serving rule, the
    request-derived candidate and the certificate read live here and nowhere else.
    """
    from corpusfm.app.web.deployment import (external_base, public_callback_url_from_request,
                                             certificate_coverage)
    from corpusfm.install import read_install_config
    eb = external_base()
    persisted = (read_install_config().get("public_base_url", "") or "")
    # STORED vs SERVING (packet 1219 Half B). The auth stack is composed once at import, so a saved
    # address does not become the advertised audience until the process restarts. Showing only the
    # stored value would make Settings display one identity while discovery, the consent screen and the
    # connections page serve another — worse than being simply wrong, because nothing says so.
    try:
        from corpusfm.mcp.server import serving_base
        serving = serving_base()
    except Exception:
        serving = ""
    return {
        "value": eb.value,               # the STORED effective address ("" when none usable)
        "source": eb.source,             # persisted | none
        "error": eb.error,               # actionable message when stored-invalid / none
        "warning": eb.warning,           # migration/retired-env note
        "env_managed": eb.env_managed,   # always False; kept so the payload shape is unchanged
        "persisted": persisted,          # the stored value
        "serving": serving,              # what THIS process advertises right now
        "pending": bool(eb.value != serving),   # saved, not yet live → a restart is owed
        "detected": public_callback_url_from_request(request) or "",
        # What a verifying client will make of the served host (packet 1325 R4b). Read, not judged:
        # "checked" False means nothing is said.
        "certificate": certificate_coverage(serving or eb.value),
    }


@router.post("/settings/external-address", dependencies=_ADMIN)
async def save_external_address(request: Request) -> JSONResponse:
    """Persist the **MCP address** (install.yaml ``public_base_url``, packet 1180; scoped to MCP by 1219)
    — the HTTPS base another machine uses to reach this box, INCLUDING the deployed web prefix. A
    non-empty value must be valid for THIS deployment (https, non-loopback host, path == web_prefix;
    certificate posture is not checked); empty clears it.

    A change takes effect only at the next process start, because the OAuth issuer/resource is bound
    there. The caller decides WHEN: ``restart_now`` true schedules the supported restart immediately;
    false saves the value and leaves the running process advertising the old audience until something
    else restarts it — reported back as ``pending`` so the UI can say so rather than showing an identity
    the box is not serving. Either way the change disconnects every client once it lands, because the
    address is the audience each grant is bound to. No secret is involved."""
    try:
        body = await request.json()
        from corpusfm.app.web.deployment import external_base, _validate_external_base, external_base_url
        from corpusfm.install import set_public_base_url
        url = (body.get("public_base_url") or "").strip()   # R5: NO pre-strip of slashes — the validator
        if url:                                              # accepts 0/1 trailing slash and rejects //
            v = _validate_external_base(url)
            if not v:
                return JSONResponse(
                    {"ok": False, "error": "Not a valid MCP address for this deployment — needs an "
                     "https:// URL with a non-loopback host and a path exactly matching the web prefix "
                     "(e.g. https://your-host/corpusfm or https://192.168.1.50/corpusfm)."},
                    status_code=400)
            url = v
        prev_value = external_base_url()
        try:
            set_public_base_url(url)
        except Exception:
            # ONE write, so there is nothing to reconcile against a partner: report the failure and the
            # value that is actually stored. Packet 1220 removed the other side (browser sign-in was
            # disabled here when clearing the address left the box with no OAuth identity, which is now
            # a derived fact rather than a stored flag to keep in step).
            return JSONResponse(
                {"ok": False, "error": "Could not persist the MCP address change. The stored value is "
                 f"unchanged: '{_persisted_public_base()}'."}, status_code=500)
        new_value = external_base_url()
        try:
            from corpusfm.mcp.server import serving_base
            _serving_now = serving_base()
        except Exception:
            _serving_now = ""
        # The issuer/resource is bound at process start, so the advertised audience only follows the
        # stored address across a restart. Derived from the EFFECTIVE value, never from a stored "is OAuth
        # on" flag (packet 1220): the address is the whole condition.
        # A restart is owed whenever the effective address differs from what THIS PROCESS SERVES — not
        # merely when the stored value changed (Codex F1, packet 1326). On a box carrying a pending
        # address (saved earlier, restart never completed) re-saving that same value changed nothing
        # against the stored copy, so no restart was scheduled and the box stayed on its old identity
        # while the prompt closed. A genuine no-op — stored and serving already agree — still schedules
        # nothing.
        restart_required = (new_value != prev_value) or (new_value != _serving_now)
        # The ADMIN decides when (packet 1219 Half B). "No" is a real answer, not "later": the value is
        # saved and takes effect at the next restart, whenever that is — so the response says the change
        # is pending rather than pretending it is live.
        restart_now = bool(body.get("restart_now", True))
        restart_scheduled = False
        # ORDER IS THE POINT (packet 1326, Codex scope §3): address → mark → restart. The restart is
        # scheduled a second out, so acknowledging in a separate request would race the process going
        # down and could leave a box that answered the prompt being prompted again. A mark that did not
        # certainly commit therefore also cancels the restart — the address is stored and pending, and
        # the response says exactly that rather than pretending both halves landed.
        acknowledged = None
        if bool(body.get("acknowledge_initial_prompt")):
            from corpusfm.app.web import mcp_address_prompt as prompt
            acknowledged = prompt.acknowledge()
            if not acknowledged:
                return JSONResponse({
                    "ok": False,
                    "acknowledged": False,
                    "error": ("The address was saved" + (" and is pending a restart" if restart_required
                              else "") + ", but this box could not record that you have seen this "
                              "prompt, so no restart was scheduled and the prompt will appear again."),
                }, status_code=500)
        if restart_required and restart_now:
            from corpusfm.app.web import service_restart
            try:
                restart_scheduled = service_restart.request_service_restart()   # post-commit: never rolls back
            except Exception:
                restart_scheduled = False
        eb = external_base()
        try:
            from corpusfm.mcp.server import serving_base
            _serving = serving_base()
        except Exception:
            _serving = ""
        return JSONResponse({
            "ok": True,
            "external_address": {"value": eb.value, "source": eb.source, "error": eb.error,
                                 "warning": eb.warning, "env_managed": eb.env_managed,
                                 "persisted": url, "serving": _serving,
                                 "pending": bool(eb.value != _serving)},
            "restart_required": restart_required,
            "restart_scheduled": restart_scheduled,
            "acknowledged": acknowledged,
            # MEASURED, not assumed (packet 1326 §4): a fresh installation holds no credential, so the
            # sentence would describe a consequence that cannot occur; a box in use does, so it must.
            # An unreadable store says so conservatively rather than choosing a side.
            "reauthorize_warning": (
                _prompt_reauthorize_warning(new_value) if restart_required else ""),
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/settings/update-notice", dependencies=[Depends(require_auth)])
def get_update_notice() -> JSONResponse:
    """The post-update ACTION WARNING for THIS build if it hasn't been dismissed.

    ``{}`` when there is nothing to warn about — which is most updates. Since packet 1359 the toast is
    raised only when the crossed release window recommends re-ingestion, and it is NOT the durable
    update narrative: that stays in About and in the `corpusfm update-notice` CLI."""
    from corpusfm.server import update_notice
    return JSONResponse(update_notice.current_notice() or {})


@router.post("/settings/update-notice/dismiss", dependencies=[Depends(require_auth)])
def dismiss_update_notice() -> JSONResponse:
    """Dismiss the current build's update notice so the banner stops showing (any authenticated user)."""
    from corpusfm.server import update_notice
    try:
        update_notice.dismiss_notice()
        return JSONResponse({"ok": True})
    except update_notice.UpdateNoticeStateError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)


@router.get("/settings/check-update", dependencies=[Depends(require_auth)])
def check_update(refresh: bool = False) -> JSONResponse:
    # Sync (def) ON PURPOSE: the refresh path shells out to systemctl and waits on a root one-shot. A
    # `def` route runs in the threadpool, so a slow remote can never block the single web event loop —
    # the all-users sidebar polls this, and an event-loop block froze the whole app.
    #
    # ONE AUTHORITY (packet 1251): this used to call `updater.check_for_update()` directly, which
    # fetched from the web process into administrator-owned Git metadata — impossible on an installed
    # Linux box by design, and a second opinion from MCP's on every box. It now consumes
    # `update_service.check()`, the same function MCP `update_check` consumes.
    #
    # `refresh` is the passive/explicit split (developer ruling D2): the sidebar poll and an ordinary
    # page load omit it and get a classification of the refs already on disk; the *Check for updates*
    # button passes it and gets the privileged refusal-only observation. The response says which one
    # it is, so "up to date" is never confused with "nobody has looked lately".
    #
    # The RESPONSE SHAPE IS UNCHANGED. Every key the page and the sidebar already read keeps its name
    # and meaning; `observation` and `diverged` are additive.
    try:
        from corpusfm.server import update_service
        from corpusfm.updater import RELEASES_PAGE_URL, _repo_root

        res = update_service.check(refresh=bool(refresh))
        return JSONResponse(_update_projection(res))
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


def _update_projection(res) -> dict:
    """The ONE mapping of an update-service result to a JSON body (packet 1341).

    `/settings/check-update` and `/settings/update-prompt` both project the same result. Factored so
    they cannot disagree about `target_head`, `schema_change`, `installer_change` or the installer
    guidance — a prompt that showed a different target from the page that applies it would be worse
    than no prompt.
    """
    from corpusfm.updater import RELEASES_PAGE_URL, _repo_root
    return {
        "update_available": res.update_available,
        "latest_version": res.target_version,
        "current_version": res.current_version,
        "current_head": res.current_head,
        # The EXACT inspected target. It is what the browser must hand back as `expected_head`,
        # because the elevated updater treats that value as the administrator's consent to one
        # specific commit and refuses anything else.
        "target_head": res.target_head,
        "head_build_version": res.head_build_version,
        "stamp_repair": res.stamp_repair,
        "releases_url": RELEASES_PAGE_URL,
        "checked": res.checked,
        "error": res.error,
        "error_class": res.error_class,   # "credentials" / "network" / "" — friendly-state selector
        "error_detail": res.error_detail, # raw git tail; diagnostic only, not the primary UI message
        "source": res.source,
        "behind": res.behind,
        "schema_change": res.schema_change,
        "installer_change": res.installer_change,
        "installer_reason": res.installer_reason,
        "repo_dir": str(_repo_root()),
        # Installer ownership lives outside this checkout. This is an operator handoff,
        # never a path to retired application-side installer sources.
        "upgrade_command": _upgrade_command(),
        # Additive (packet 1251): how this result was obtained, and whether the checkout has
        # diverged from origin/main — which is a refusal, not an available update.
        "observation": res.observation,
        "diverged": res.diverged,
    }


def _upgrade_command() -> str:
    """The canonical handoff for work the code-only updater cannot perform."""
    from corpusfm.server.update_service import operator_command
    return operator_command()



@router.get("/settings/update-prompt", dependencies=_ADMIN)
def update_prompt(request: Request) -> JSONResponse:
    """Should this administrator be shown the waiting-update pop-over? (packet 1341)

    PASSIVE: it delegates to `update_service.check(refresh=False)` — the same classification of refs
    already on disk that the sidebar poll uses — and never triggers the privileged observation. The
    two-hour `UpdateObserver` clock and the explicit *Check for updates* button are untouched.

    Admin shells populate the update badge from THIS response rather than making a second check.
    """
    from corpusfm.app.web import update_prompt as policy
    from corpusfm.app.web import users as users_mod
    from corpusfm.app.web.auth import current_user
    from corpusfm.server import update_service

    # Consume the one opportunity FIRST. It is spent by this shell load whether the prompt shows,
    # suppresses, or the check itself fails — an error path that left it unconsumed handed the same
    # sign-in another chance to prompt (Codex review, 2026-08-26).
    opportunity = bool(request.session.pop("update_prompt_opportunity", False))
    try:
        res = update_service.check(refresh=False)
        projection = _update_projection(res)
    except Exception as exc:
        return JSONResponse({"show": False, "reason": "error", "error": str(exc)}, status_code=500)

    u = current_user(request)

    skipped = ""
    if u is not None:
        try:
            skipped = users_mod.skipped_update_head(u.id)
        except Exception:
            skipped = ""

    reason = policy.decide(
        is_admin=bool(u is not None and u.has_gate("settings")),
        update_available=bool(projection.get("update_available")),
        target_head=str(projection.get("target_head") or ""),
        skipped_head=skipped,
        opportunity=opportunity,
        acknowledged_1326=policy.initial_prompt_outstanding(),
        busy=policy.restart_sensitive_work(),
    )
    body = dict(projection)
    body["show"] = reason == policy.SHOW
    body["reason"] = reason
    body["installer_required"] = policy.installer_required(projection)
    return JSONResponse(body)


@router.post("/settings/update-prompt/skip", dependencies=_ADMIN)
async def skip_update_prompt(request: Request) -> JSONResponse:
    """Record that this administrator skipped THIS update (packet 1341).

    Writes only when the displayed head is still the waiting target — a moved or absent target writes
    nothing and says so, so a skip can never silence a different update. Storage uncertainty keeps the
    pop-over open with an error rather than reporting a skip it did not persist.
    """
    from corpusfm.app.web import users as users_mod
    from corpusfm.app.web.auth import current_user
    from corpusfm.server import update_service

    try:
        body = await request.json()
    except Exception:
        body = {}
    claimed = str((body or {}).get("expected_head") or "").strip()
    if not claimed:
        return JSONResponse({"ok": False, "error": "expected_head is required."}, status_code=400)

    try:
        res = update_service.check(refresh=False)          # a FRESH passive classification
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
    if not res.update_available or not res.target_head:
        return JSONResponse({"ok": False, "reason": "no_update",
                             "error": "There is no waiting update to skip."}, status_code=409)
    if res.target_head != claimed:
        return JSONResponse({"ok": False, "reason": "target_changed",
                             "error": "The waiting update changed while the prompt was open. "
                                      "Nothing was skipped."}, status_code=409)

    u = current_user(request)
    if u is None:
        return JSONResponse({"ok": False, "error": "Not authenticated."}, status_code=401)
    try:
        users_mod.set_skipped_update_head(u.id, claimed)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"The skip could not be saved: {exc}"},
                            status_code=503)
    return JSONResponse({"ok": True, "skipped_head": claimed})


@router.post("/settings/apply-update", dependencies=_ADMIN)
def apply_update(request: Request) -> JSONResponse:
    """Ask the privileged updater to advance this installation to one exact, already-inspected tip.

    THE WHOLE CONTRACT, in order:

    1. Settings calls ``/settings/check-update`` and shows the administrator what it found. That
       response carries ``target_head`` — the exact commit the check resolved.
    2. The browser hands that same value back here as ``expected_head``. It is not optional: the
       shared authority refuses ``consent_required`` without it, so a request that omits it cannot
       apply anything.
    3. This route delegates to ``update_service.apply`` and does nothing else. **It runs no git,
       forks no process, pulls nothing, rolls nothing back and repairs nothing.**
    4. That authority writes a fixed three-field request — ``trigger_id`` for correlation,
       ``expected_head`` for refusal-only consent, and ``actor`` for the audit trail — to a
       root-owned inbox, and starts one fixed elevated operation that takes no arguments. None of
       those fields selects a ref, path, helper, executable or operation.
    5. The privileged updater independently resolves and verifies ``origin/main`` for itself. It
       decides eligibility on the tip IT resolved: origin identity, a clean deployed tree, a
       fast-forward, and a code-only change class.
    6. ``expected_head`` is **refusal-only consent**. It is compared to that independently resolved
       tip and can produce exactly one outcome — a refusal. It cannot name a ref, cannot reach an
       older commit, and cannot make an otherwise ineligible update eligible.
    7. The result comes back through the authoritative outcome channel: a record written by root in
       a directory the service may read and may not write. This route reports what that record says
       and never re-derives it.

    A stale runtime build stamp (``stamp_repair`` in the check response) is an **observation**. There
    is no in-app repair for it and no control that offers one; re-running the installer on the server
    rewrites the stamp.

    Sync (def) ON PURPOSE — the delegation blocks while the elevated operation runs, and the
    threadpool keeps that off the single web event loop. It has no ``await`` (the restart is a
    daemon thread), so the conversion is safe. The response keys and status codes are a
    compatibility surface and are mapped from the shared ``ApplyResult``.
    """
    from corpusfm.server import update_service
    from corpusfm.app.web.auth import actor_from_request
    actor = actor_from_request(request)
    # The exact-head pin (query param) is the administrator's CONSENT to a specific origin/main tip,
    # and it is refusal-only: the elevated one-shot resolves origin/main itself and refuses if the
    # resolved tip differs. This route performs no update (packet 1246-03-03); it triggers the fixed
    # elevated operation and reports what root recorded.
    expected_head = (request.query_params.get("expected_head") or "").strip() or None
    # Work-in-flight preflight (packet 1341), immediately before delegation. This is the packet's
    # required CLICK-TIME recheck, not a new apply mechanism and not a queue drain: work that starts
    # after this instant is outside the exclusion contract. The exact-head consent pin below remains
    # the authority on the target race.
    from corpusfm.app.web import update_prompt as _policy
    _busy = _policy.restart_sensitive_work()
    if _busy is None or _busy:
        return JSONResponse(
            {"ok": False, "reason": "work_in_flight",
             "error": ("A queue worker is holding a record right now, so a restart would interrupt it. "
                       "Try again in a moment." if _busy else
                       "Whether work is in flight could not be determined, so the update was not "
                       "started.")}, status_code=409)
    try:
        r = update_service.apply(expected_head=expected_head, actor=actor)
        if r.ok:
            return JSONResponse({
                "ok": True, "output": r.pull_output, "restarting": True, "mode": r.restart_mode,
                "stamp_repair": r.stamp_repair,
            })
        body: dict = {"ok": False, "error": r.message, "reason_code": r.reason_code}
        if r.reason_code == "needs_installer":
            body.update({"schema_change": r.schema_change, "installer_change": r.installer_change,
                         "installer_reason": r.installer_reason,
                         "upgrade_command": r.operator_command})
        elif r.reason_code == "import_probe_failed":
            body.update({"rolled_back": True, "installer_change": True,
                         "upgrade_command": r.operator_command})
        return JSONResponse(body, status_code=r.http_status)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/git/add", dependencies=_ADMIN)
async def git_add(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        from corpusfm.core.crypto import encrypt_secret
        from corpusfm.core.git_formatter import (
            RegistrationConfig, add_registration, get_registration,
        )
        name = body["name"].strip()
        cred_type = body.get("cred_type", "pat").strip() or "pat"
        # Preserve an existing secret when the form leaves it blank (edit without re-entry).
        prior = None
        try:
            prior = get_registration(name)
        except Exception:
            prior = None
        token_enc = prior.token_enc if prior else ""
        ssh_key_enc = prior.ssh_key_enc if prior else ""
        if cred_type == "pat":
            new_token = (body.get("token") or "").strip()
            if new_token:
                token_enc = encrypt_secret(new_token)
            ssh_key_enc = ""  # switching to PAT drops any stale key
        else:
            new_key = (body.get("ssh_key") or "").strip()
            if new_key:
                ssh_key_enc = encrypt_secret(new_key)
            token_enc = ""
        cfg = RegistrationConfig(
            name=name,
            cred_type=cred_type,
            repo=body.get("repo", "").strip(),
            branch=body.get("branch", "main").strip() or "main",
            username=body.get("username", "").strip(),
            token_enc=token_enc,
            ssh_key_enc=ssh_key_enc,
            ssh_pubkey=body.get("ssh_pubkey", "").strip(),
            modes=body.get("modes") or ["structured", "rendered"],
            show_hidden=bool(body.get("show_hidden", True)),
            group=body.get("group", "").strip() or None,
        )
        add_registration(cfg, overwrite=True)
        return JSONResponse({"ok": True})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/git/generate-deploy-key", dependencies=_ADMIN)
async def git_generate_deploy_key(request: Request) -> JSONResponse:
    """Generate an ed25519 deploy-key credential server-side and persist it. The private key is
    stored encrypted and never returned; only the public key (to paste as the repo's deploy key,
    with write access) is sent back. Mirrors the FMS PKI keygen pattern."""
    import dataclasses
    try:
        body = await request.json()
        from corpusfm.core.crypto import encrypt_secret
        from corpusfm.core.git_formatter import (
            RegistrationConfig, add_registration, get_registration,
            generate_ssh_keypair, is_valid_registration_name,
        )
        name = (body.get("name") or "").strip()
        repo = (body.get("repo") or "").strip()
        if not is_valid_registration_name(name):
            return JSONResponse({"ok": False, "error": (
                "Credential name may only contain letters, digits, dot, dash, and underscore "
                "(no slashes or spaces)."
            )}, status_code=400)
        if not repo:
            return JSONResponse({"ok": False, "error": "A deploy key needs its bound repo URL."},
                                status_code=400)
        priv, pub = generate_ssh_keypair(comment=f"corpusfm-{name}")
        try:
            prior = get_registration(name)
        except Exception:
            prior = None
        if prior is not None:
            cfg = dataclasses.replace(prior, cred_type="deploy_key", repo=repo,
                                      ssh_key_enc=encrypt_secret(priv), ssh_pubkey=pub, token_enc="")
        else:
            cfg = RegistrationConfig(name=name, cred_type="deploy_key", repo=repo,
                                     ssh_key_enc=encrypt_secret(priv), ssh_pubkey=pub)
        add_registration(cfg, overwrite=True)
        return JSONResponse({"ok": True, "ssh_pubkey": pub})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/settings/git/{name}", dependencies=_ADMIN)
async def git_remove(name: str) -> JSONResponse:
    try:
        from corpusfm.core.git_formatter import remove_registration
        remove_registration(name)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/git/{name}/verify", dependencies=_ADMIN)
async def git_verify(name: str, request: Request) -> JSONResponse:
    """Prove the credential reaches a repo (auth'd ls-remote)."""
    try:
        from corpusfm.core.git_formatter import get_registration, verify_registration
        body = await request.json() if await request.body() else {}
        repo = (body or {}).get("repo", "")
        # verify_registration shells out to `git ls-remote` (up to a 30s timeout) — offload it off the
        # event loop (packet 078) so a slow/unreachable remote can't freeze the whole app.
        def _verify():
            return verify_registration(get_registration(name), repo)
        ok, msg = await run_in_threadpool(_verify)
        return JSONResponse({"ok": ok, "msg": msg})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/git/{name}/push", dependencies=_ADMIN)
def git_push(name: str) -> JSONResponse:
    # SYNC `def` (packet 078): push_registration shells out to `git push` (up to a 60s timeout). A sync
    # route runs in the threadpool, so a slow/unreachable remote can't block the event loop.
    try:
        from corpusfm.core.git_formatter import (
            get_registration, push_registration, resolve_local_path, effective_repo,
        )
        reg = get_registration(name)
        local = resolve_local_path(reg, effective_repo(reg))
        ok, msg = push_registration(reg, local)
        return JSONResponse({"ok": ok, "msg": msg} if ok
                            else {"ok": False, "error": msg}, status_code=200 if ok else 500)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


# ── Remote FMS servers (packet 1015) — GITREG-parity CRUD + per-server Test ──────

@router.post("/settings/servers/add", dependencies=_ADMIN)
async def server_add(request: Request) -> JSONResponse:
    """Create or update a remote FMS server (packet 1015 redesign; verify-on-save, packet 1016): FOUR
    fields — name · host · account · password — where account/password are the fmsadmin Admin-API
    credential (used only to LIST the server's hosted files). No OData, no PKI. The password is
    write-only: a blank field on edit keeps the stored one (add_server merges).

    Save VERIFIES before it persists — the effective credential must reach the Admin API and enumerate
    hosted files, or nothing is stored (a remote server that can't list files is useless to the Jobs
    page). Verification runs against the *merged* credential, so a blank password on edit re-uses the
    stored one for the check, exactly as add_server would persist it."""
    try:
        from corpusfm.server import remote_servers as rs
        body = await request.json()
        cfg = rs.RemoteServer(
            name=(body.get("name") or "").strip(),
            host=(body.get("host") or "").strip(),
            account=(body.get("account") or "").strip(),
            password=(body.get("password") or "").strip(),
            verify_ssl=bool(body.get("verify_ssl", False)),
            callback_url=(body.get("callback_url") or "").strip(),
        )
        if not rs.is_valid_server_name(cfg.name):
            return JSONResponse(
                {"ok": False, "error": "Server name may only contain letters, digits, dot, dash, and "
                 "underscore (no slashes or spaces)."}, status_code=400)
        if cfg.callback_url:
            # A remote peer POSTs a live one-time token over this, so it must be reachable FROM THAT
            # PEER — a loopback address is rejected here rather than at the next run (packet 1055/1219).
            from corpusfm.app.web.deployment import validate_callback_url
            try:
                cfg.callback_url = validate_callback_url(cfg.callback_url, require_public=True)
            except ValueError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        eff = rs.RemoteServer(name=cfg.name, host=cfg.host, account=cfg.account, password=cfg.password,
                              verify_ssl=cfg.verify_ssl, callback_url=cfg.callback_url)
        if not eff.password:
            try:
                eff.password = rs.get_server(cfg.name).password
            except KeyError:
                pass
        ok, msg, _dbs = await run_in_threadpool(rs.verify_server, eff)
        if not ok:
            return JSONResponse({"ok": False, "error": msg}, status_code=400)
        rs.add_server(cfg, overwrite=True)
        return JSONResponse({"ok": True})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/settings/servers/{name}", dependencies=_ADMIN)
async def server_remove(name: str) -> JSONResponse:
    try:
        from corpusfm.server import remote_servers as rs
        rs.remove_server(name)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/notifications", dependencies=_ADMIN)
async def save_notifications(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        from corpusfm.server.monitor.config import (
            MonitorConfig, save_monitor_config, load_monitor_config,
        )
        email = None
        if body.get("smtp_host", "").strip():
            to_list = [a.strip() for a in body.get("smtp_to", "").split(",") if a.strip()]
            # Write-only secret (packet 1009/S1-E): a blank posted password PRESERVES the stored one
            # (the GET only ever exposed `smtp_pass_set`, never the value) — only a newly typed
            # password overwrites it.
            posted_pass = body.get("smtp_pass", "")
            password = posted_pass if posted_pass else ((load_monitor_config().email or {}).get("password", ""))
            email = {
                "smtp_host": body["smtp_host"].strip(),
                "smtp_port": int(body.get("smtp_port", 587)),
                "username": body.get("smtp_user", "").strip(),
                "password": password,
                "from_addr": body.get("smtp_from", "").strip() or body.get("smtp_user", "").strip(),
                "to_addrs": to_list,
            }
        cfg = MonitorConfig(
            suppress_hours=int(body.get("suppress_hours", 4)),
            overdue_grace_minutes=int(body.get("overdue_grace_minutes", 15)),
            disk_min_gb=float(body.get("disk_min_gb", 1.0)),
            webhook_url=body.get("webhook_url", "").strip() or None,
            email=email,
        )
        save_monitor_config(cfg)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/preferences", dependencies=_ADMIN)
async def save_preferences(request: Request) -> JSONResponse:
    # ONE-SIDED since packet 1220. The two-sided address/flag transaction here existed for the combined
    # "enable browser sign-in using <detected address>" action; with no switch to enable there is no
    # second side, and this route writes app-config only.
    try:
        body = await request.json()
        from corpusfm.app.app_config import load_app_config, save_app_config, FM_ADDON_LOCALES
        cfg = load_app_config()
        # Personal prefs (landing_page / docs_drawer_side / preferred_addon_locale) moved to the
        # per-user store (Your account). This route now carries only the app-wide content settings.
        cfg.keep_source_xml = bool(body.get("keep_source_xml", cfg.keep_source_xml))
        fms_admin_change = None
        if "enable_fms_admin_mcp_tools" in body:
            new_val = bool(body["enable_fms_admin_mcp_tools"])
            if new_val != cfg.enable_fms_admin_mcp_tools:
                fms_admin_change = new_val
            cfg.enable_fms_admin_mcp_tools = new_val
        patching_change = None
        if "enable_patching_mcp_tools" in body:
            new_val = bool(body["enable_patching_mcp_tools"])
            if new_val != cfg.enable_patching_mcp_tools:
                patching_change = new_val
            cfg.enable_patching_mcp_tools = new_val
        lifetime_change = None
        if "browser_connection_lifetime" in body:
            # Packet 1183: how long an OAUTH CONNECTION lasts — one of exactly three policies, never a
            # free-form duration. Validated through the same settings boundary as everything else
            # (app_config normalizes), and read dynamically at authorization/refresh, so this one needs
            # NO service restart and must never claim one.
            from corpusfm.app.web.oauth_policy import normalize_policy_id
            new_val = normalize_policy_id(body["browser_connection_lifetime"])
            if new_val != cfg.browser_connection_lifetime:
                lifetime_change = new_val
            cfg.browser_connection_lifetime = new_val
        compartment_change = None
        if "restrict_apply_to_compartment" in body:
            new_val = bool(body["restrict_apply_to_compartment"])
            if new_val != cfg.restrict_apply_to_compartment:
                compartment_change = new_val
            cfg.restrict_apply_to_compartment = new_val
        if "ui_locale" in body:
            loc = str(body["ui_locale"]).strip().lower()
            cfg.ui_locale = loc if loc in FM_ADDON_LOCALES else ""
        save_app_config(cfg)
        # ── POST-COMMIT bookkeeping: the settings are already persisted, so an audit-write failure must
        # NOT be reported as a generic ok:false suggesting nothing applied. It is surfaced HONESTLY as a
        # warning while the committed change is preserved and reported. ──
        post_commit_warning = ""
        if (fms_admin_change is not None or patching_change is not None
                or compartment_change is not None or lifetime_change is not None):
            try:
                from corpusfm.server import audit
                from corpusfm.app.web.auth import current_user
                me = current_user(request)
                actor = me.username if me else "admin"
                if fms_admin_change is not None:
                    audit.record(audit.FMS_ADMIN_MCP_TOGGLED, actor=actor,
                                 meta={"enabled": fms_admin_change})
                if patching_change is not None:
                    audit.record(audit.PATCHING_MCP_TOGGLED, actor=actor,
                                 meta={"enabled": patching_change})
                if compartment_change is not None:
                    audit.record(audit.COMPARTMENT_RESTRICTION_TOGGLED, actor=actor,
                                 meta={"restricted": compartment_change})
                if lifetime_change is not None:
                    audit.record(audit.BROWSER_LIFETIME_CHANGED, actor=actor,
                                 meta={"policy": lifetime_change})
            except Exception:
                post_commit_warning = ((post_commit_warning + " ") if post_commit_warning else "") + (
                    "The change was saved, but the audit log entry could not be written.")
        return JSONResponse({"ok": True, "warning": post_commit_warning})
    except Exception as exc:
        # Packet 1190-02: an INDETERMINATE write is unknown, not failed, and must never be reported as
        # "nothing was saved" — the administrator is told to look at what is actually stored instead.
        from corpusfm.app.app_config import ConfigWriteIndeterminate
        if isinstance(exc, ConfigWriteIndeterminate):
            return JSONResponse(
                {"ok": False, "recovery_required": True,
                 "error": "CORPUSfm could not confirm whether these preferences were saved. Reload "
                 f"Settings to see what is stored, then set anything that is not what you intend. "
                 f"({exc})"}, status_code=503)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/storage/blob-encryption", dependencies=_ADMIN)
async def set_blob_encryption(request: Request) -> JSONResponse:
    """Set the encrypt_blobs setting and launch the global bulk re-encode.

    Re-encodes every stored container blob to the new form; while it runs the whole app
    is locked to /converting (see the deployment gate). Single-flight — a conversion
    already in progress is rejected.
    """
    try:
        body = await request.json()
        enabled = bool(body.get("enabled", False))
        from corpusfm.app.web import blob_conversion
        if blob_conversion.is_running():
            return JSONResponse(
                {"ok": False, "started": False, "error": "conversion already running"},
                status_code=409,
            )
        from corpusfm.app.app_config import (load_app_config, save_app_config,
                                             ConfigWriteIndeterminate, ConfigWriteNotCommitted)
        from corpusfm.storage import get_backend
        cfg = load_app_config()
        cfg.encrypt_blobs = enabled
        try:
            save_app_config(cfg)
        except ConfigWriteNotCommitted as exc:
            # PROVEN nothing was stored: the setting is unchanged, so the blobs must stay as they are.
            # Starting the conversion here would re-encode every blob to match a setting that does not
            # exist. Safe to retry exactly as submitted.
            return JSONResponse(
                {"ok": False, "started": False,
                 "error": f"The encryption setting was not saved, and no blobs were changed. "
                          f"Try again. ({exc})"},
                status_code=503)
        except ConfigWriteIndeterminate as exc:
            # The save was dispatched and its outcome is unknown, so the stored setting may or may not
            # say `enabled`. Running the bulk conversion on a guess is the one thing that must not
            # happen — it rewrites every stored blob. Report the real state instead (packet 1190-02).
            return JSONResponse(
                {"ok": False, "started": False, "recovery_required": True,
                 "error": f"CORPUSfm could not confirm whether the encryption setting was saved, so "
                          f"no blobs were converted. Reload Settings to see the stored value, then "
                          f"set it again if it is not what you chose. ({exc})"},
                status_code=503)
        started = blob_conversion.start(get_backend(), enabled)
        if not started:
            # The single-flight check above and this launch are separate steps with a network
            # round-trip between them, so another request can start a conversion in the gap —
            # possibly toward the OPPOSITE setting. `ok: true, started: false` reported that as
            # success (packet 1208): the setting was saved, no conversion ran for it, and the
            # blobs were left converging on someone else's value with nothing said.
            return JSONResponse(
                {"ok": False, "started": False,
                 "error": "The encryption setting was saved, but another conversion started first, "
                          "so no blobs were converted for it. Wait for that conversion to finish, "
                          "then set the encryption setting again."},
                status_code=409)
        return JSONResponse({"ok": True, "started": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "started": False, "error": str(exc)}, status_code=500)


@router.get("/settings/storage/blob-encryption/status", dependencies=_ADMIN)
async def blob_encryption_status() -> JSONResponse:
    """Live conversion progress {running, done, total, pct, error}. Reachable while the
    global lock holds (allowlisted in the deployment gate) so /converting can poll it."""
    from corpusfm.app.web import blob_conversion
    return JSONResponse(blob_conversion.state())


@router.post("/settings/ai-summary", dependencies=_ADMIN)
async def save_ai_summary_config(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        from corpusfm.app.app_config import load_app_config, save_app_config
        from corpusfm.server import ai_env
        cfg = load_app_config()
        # Capture the summary fingerprint BEFORE overwriting, to invalidate the chat verified flag
        # if any of provider/model/base-url/key changes (packet 033, #13). The key lives in the
        # SETTING.AiKeys DB container now (packet 1007) — read it into the fingerprint so a key change
        # still clears the flag.
        # packet 1151: chat + embedding hold INDEPENDENT keys/providers; fingerprint each with its own
        # key so a change to one clears only its own verified flag.
        _old_chat_key = ai_env.read_ai_key("chat")
        _old_embed_key = ai_env.read_ai_key("embed")
        _old_summary = (cfg.ai_summary_provider, cfg.ai_summary_model,
                        cfg.ai_summary_base_url, cfg.ai_summary_api_version, _old_chat_key)
        _old_embed = (cfg.ai_embedding_provider, cfg.ai_embedding_model,
                      cfg.ai_embedding_base_url, cfg.ai_embedding_api_version, _old_embed_key)
        provider = str(body.get("ai_summary_provider", "")).strip()
        if provider not in ("anthropic", "openai_compat", "azure_openai", ""):
            return JSONResponse({"ok": False, "error": f"Unknown provider: {provider!r}"}, status_code=400)
        embed_provider = str(body.get("ai_embedding_provider", "")).strip()
        if embed_provider not in ("openai_compat", "azure_openai", ""):
            return JSONResponse({"ok": False, "error": f"Unknown embedding provider: {embed_provider!r}"},
                                status_code=400)
        cfg.ai_summary_provider = provider
        cfg.ai_summary_model = str(body.get("ai_summary_model", "")).strip()
        cfg.ai_summary_api_version = str(body.get("ai_summary_api_version", "")).strip()
        new_summary_base = str(body.get("ai_summary_base_url", "")).strip()
        cfg.ai_embedding_provider = embed_provider
        new_embed_model = str(body.get("ai_embedding_model", "")).strip()
        new_embed_base = str(body.get("ai_embedding_base_url", "")).strip()
        new_embed_apiver = str(body.get("ai_embedding_api_version", "")).strip()
        cfg.ai_summary_base_url = new_summary_base
        cfg.ai_embedding_model = new_embed_model
        cfg.ai_embedding_base_url = new_embed_base
        cfg.ai_embedding_api_version = new_embed_apiver
        # (packet 1161) Embedding batch size — 0 = Auto; clamp an explicit value to [1, 2048]. Chunking
        # only (never changes a vector), so it is deliberately NOT part of the _old_embed change-tuple
        # that clears ai_embedding_verified below.
        if "ai_embedding_batch_size" in body:
            try:
                cfg.ai_embedding_batch_size = min(2048, max(0, int(body.get("ai_embedding_batch_size") or 0)))
            except (TypeError, ValueError):
                pass
        # (packet 053) summarization knobs — input budget (0 = never chunk) + optional xref-in-prompt.
        if "ai_summary_max_content_chars" in body:
            try:
                cfg.ai_summary_max_content_chars = max(0, int(body.get("ai_summary_max_content_chars") or 0))
            except (TypeError, ValueError):
                pass
        if "ai_summary_include_xref" in body:
            cfg.ai_summary_include_xref = bool(body.get("ai_summary_include_xref"))
        # API keys: a newly-entered value is written to the Corpus-Key-encrypted SETTING.AiKeys container
        # (packet 1007 — never to jor/slots); an explicit clear empties that slot; a blank field leaves
        # the stored key untouched. Chat and embed are independent (packet 1151). Never round-tripped.
        new_chat_key = str(body.get("ai_summary_api_key", "")).strip()
        if body.get("ai_summary_api_key_clear"):
            ai_env.set_ai_key("", "chat")
        elif new_chat_key:
            ai_env.set_ai_key(new_chat_key, "chat")
        new_embed_key = str(body.get("ai_embedding_api_key", "")).strip()
        if body.get("ai_embedding_api_key_clear"):
            ai_env.set_ai_key("", "embed")
        elif new_embed_key:
            ai_env.set_ai_key(new_embed_key, "embed")
        cur_chat_key = ai_env.read_ai_key("chat")
        cur_embed_key = ai_env.read_ai_key("embed")
        # Any chat provider/model/base-url/api-version/key change invalidates the prior chat test.
        if _old_summary != (cfg.ai_summary_provider, cfg.ai_summary_model,
                            cfg.ai_summary_base_url, cfg.ai_summary_api_version, cur_chat_key):
            cfg.ai_summary_verified = False
        # Any embedding provider/model/base-url/api-version/key change invalidates the prior embed test.
        if _old_embed != (cfg.ai_embedding_provider, cfg.ai_embedding_model,
                          cfg.ai_embedding_base_url, cfg.ai_embedding_api_version, cur_embed_key):
            cfg.ai_embedding_verified = False
        save_app_config(cfg)
        return JSONResponse({"ok": True, "embedding_verified": cfg.ai_embedding_verified,
                             "summary_verified": cfg.ai_summary_verified,
                             "api_key_set": bool(cur_chat_key),
                             "embedding_api_key_set": bool(cur_embed_key)})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/test-embedding", dependencies=_ADMIN)
async def test_embedding(request: Request) -> JSONResponse:
    """Live /embeddings round-trip. Persists ai_embedding_verified on success so
    the index features unlock only after a real working endpoint is proven."""
    try:
        body = await request.json()
        from corpusfm.app.app_config import load_app_config, save_app_config
        from corpusfm.server.ai.vector_index import test_embedding_endpoint
        from corpusfm.server import ai_env
        cfg = load_app_config()
        # Test the values currently in the form (may be unsaved), falling back to the saved values,
        # exactly as get_vector_index resolves them. Chat-base fallback only when NOT azure (decoupled).
        embed_provider = str(body.get("ai_embedding_provider", "")).strip() or cfg.ai_embedding_provider
        base_url = (str(body.get("ai_embedding_base_url", "")).strip()
                    or (cfg.ai_summary_base_url if embed_provider != "azure_openai" else "") or "")
        model = str(body.get("ai_embedding_model", "")).strip() or cfg.ai_embedding_model
        api_version = str(body.get("ai_embedding_api_version", "")).strip() or cfg.ai_embedding_api_version
        # UI-settable EMBED key first (SETTING.AiKeys container; env fallback inside the helper; a
        # just-typed unsaved key wins) — mirrors get_vector_index so the test uses the real key.
        typed_key = str(body.get("ai_embedding_api_key", "")).strip()
        ui_key = typed_key or ai_env.read_ai_key("embed")
        # Live network round-trip — offload off the event loop (packet 078).
        result = await run_in_threadpool(
            test_embedding_endpoint, base_url, model, ui_key, 20, embed_provider, api_version)
        if result.get("ok"):
            # Persist the proven provider/endpoint/model/api-version + the verified flag (test = verify).
            cfg.ai_embedding_provider = embed_provider
            cfg.ai_embedding_base_url = str(body.get("ai_embedding_base_url", "")).strip()
            cfg.ai_embedding_model = str(body.get("ai_embedding_model", "")).strip()
            cfg.ai_embedding_api_version = api_version
            cfg.ai_embedding_verified = True
            save_app_config(cfg)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/test-summary", dependencies=_ADMIN)
async def test_summary(request: Request) -> JSONResponse:
    """Live chat round-trip proving the AI summary (chat) provider works — the
    counterpart to test-embedding for the summaries side."""
    try:
        body = await request.json()
        from corpusfm.app.app_config import load_app_config, save_app_config
        from corpusfm.server.ai import test_summary_endpoint
        from corpusfm.server import ai_env
        cfg = load_app_config()
        # Test the values currently in the form (may be unsaved), falling back to saved.
        provider = str(body.get("ai_summary_provider", "")).strip() or cfg.ai_summary_provider
        model = str(body.get("ai_summary_model", "")).strip() or cfg.ai_summary_model
        base_url = str(body.get("ai_summary_base_url", "")).strip() or cfg.ai_summary_base_url
        api_version = str(body.get("ai_summary_api_version", "")).strip() or cfg.ai_summary_api_version
        # A just-typed (unsaved) key wins; else the stored chat key (env fallback in the helper).
        typed_key = str(body.get("ai_summary_api_key", "")).strip()
        ui_key = typed_key or ai_env.read_ai_key("chat")
        # Live network round-trip — offload off the event loop (packet 078). Positional args match
        # test_summary_endpoint(provider_name, model, base_url, api_key, api_version).
        result = await run_in_threadpool(
            test_summary_endpoint, provider, model, base_url, ui_key, api_version)
        if result.get("ok"):
            # Persist the proven provider/model/base/api-version + the verified flag (test = verify) —
            # mirrors test-embedding (packet 033, #13).
            cfg.ai_summary_provider = provider
            cfg.ai_summary_model = model
            if base_url:
                cfg.ai_summary_base_url = base_url
            cfg.ai_summary_api_version = api_version
            cfg.ai_summary_verified = True
            save_app_config(cfg)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/settings/list-embedding-models", dependencies=_ADMIN)
async def list_embedding_models(request: Request) -> JSONResponse:
    """Server-side GET {base_url}/models so the user picks from what the reachable
    endpoint actually serves. The model is user-specific (whatever they installed);
    the URL is stable. In server mode the endpoint lives on the CORPUSfm box, so
    this discovery must run server-side — same path as test-embedding."""
    try:
        body = await request.json()
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server.ai.vector_index import list_endpoint_models
        from corpusfm.server import ai_env
        cfg = load_app_config()
        # Generic discovery: an explicit base_url (the chat-provider field) wins;
        # else the embedding field; else the saved summary URL. Both AI sections
        # (chat model + embeddings) call this — the endpoint is provider-neutral.
        base_url = (str(body.get("base_url", "")).strip()
                    or str(body.get("ai_embedding_base_url", "")).strip()
                    or cfg.ai_summary_base_url or "")
        # Azure lists deployments in the portal, not via /models — the helper returns a not-supported
        # result so the UI hides the button; pass whichever section's provider the caller sent.
        provider = (str(body.get("provider", "")).strip()
                    or str(body.get("ai_embedding_provider", "")).strip()
                    or str(body.get("ai_summary_provider", "")).strip() or "openai_compat")
        ui_key = ai_env.read_ai_key("embed") if body.get("ai_embedding_provider") else ai_env.read_ai_key("chat")
        result = list_endpoint_models(base_url, api_key=ui_key, provider=provider)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/settings/server-info", dependencies=_ADMIN)
async def server_info() -> JSONResponse:
    import time
    import corpusfm
    from corpusfm.config import is_server_mode
    py = sys.version_info
    info = {
        "corpusfm_version": corpusfm.__version__,
        "python_version": f"{py.major}.{py.minor}.{py.micro}",
        "mode": "server" if is_server_mode() else "local",
        "uptime": "",
    }
    try:
        import psutil
        uptime_s = int(time.time() - psutil.Process(os.getpid()).create_time())
        d, r = divmod(uptime_s, 86400)
        h, r = divmod(r, 3600)
        m = r // 60
        info["uptime"] = (
            f"{d}d {h}h {m}m" if d else
            f"{h}h {m}m" if h else
            f"{m}m"
        )
    except Exception:
        pass
    return JSONResponse(info)


@router.get("/settings/health", dependencies=_ADMIN)
async def settings_health(request: Request) -> JSONResponse:
    """Read-only install capability + readiness surface for Settings → Health. One structured
    payload (environment facts + capability rows with fix-tab hints); never raises."""
    force = request.query_params.get("force") in ("1", "true", "yes")
    try:
        from corpusfm.server import health
        return JSONResponse(health.report(force=force))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/settings/mcp-info", dependencies=[Depends(require_auth)])
async def mcp_info(request: Request) -> JSONResponse:
    """Live MCP connect details for the folded-in endpoint.

    The MCP is served by the web app itself at <prefix>/mcp (stateless streamable-HTTP) — behind
    the FMS reverse proxy that's https://<fms-host>/corpusfm/mcp. No separate port or service.
    In server mode it always mounts and always AUTHENTICATES: every credential belongs to a named
    user, so an anonymous caller gets 401 (packet 1258 — there is no server-wide token to report on).
    A from-source dev run (LocalBackend, loopback) mounts it unauthenticated."""
    from corpusfm.config import is_server_mode

    server = is_server_mode()

    # Endpoint = this app's public base + url-prefix + /mcp — the CANONICAL no-slash form (packet
    # 1329). The old comment here said the trailing slash was REQUIRED because `/mcp` 307-redirected
    # to an unprefixed Location that escaped the proxy; that redirect is gone (`app._ExactMcpPathIsNotARedirect`
    # serves the exact path directly), and the slash form keeps working. Build it from the
    # BROWSER-FACING request, honouring the reverse proxy: X-Forwarded-Host + X-Forwarded-Proto
    # (when the edge sets them) take precedence over the upstream Host — IIS ARR rewrites the
    # upstream Host to the loopback (which is why this once showed http://127.0.0.1:8533/...). The
    # UI additionally prefers window.location.origin for display (always the user's real URL); this
    # server value is the authoritative fallback for non-browser JSON consumers.
    prefix = request.scope.get("root_path", "") or ""
    fwd_host = (request.headers.get("x-forwarded-host") or "").split(",")[0].strip()
    host = fwd_host or request.headers.get("host") or request.url.netloc
    fwd_proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    scheme = fwd_proto or request.url.scheme
    endpoint = f"{scheme}://{host}{prefix}/mcp"

    # THE MOUNT IS REPORTED, NOT MIRRORED (packet 1248). This recomputed `_build_mcp_app`'s rule
    # from `is_server_mode()` and a token read from `.mcp_env` or the environment — a second copy of
    # a decision, and it disagreed with the real one whenever the token lived only in `.mcp_env`:
    # nothing mounts in that state, and this said it had. `enforced` is the composed instance's own
    # auth, so it answers the question the transport answers. `token_set` stays a CONFIGURATION fact
    # (it drives the Settings "Set / Not set" badge) and is deliberately not a mount claim.
    # THE APP SERVING THIS REQUEST, and nothing else. `create_app` hangs its own snapshot here. A
    # router mounted on a bare app (tests, embedding) composed no MCP, so it falls back to the
    # documented rule — deliberately NOT to the process-wide record, which would describe a
    # DIFFERENT application's mount. That fallback was the first version of this line and a full-suite
    # run caught it: the route reported another test's composition and passed in isolation.
    status = getattr(request.app.state, "mcp_runtime", None)
    # The mount is unconditional now, so the documented-rule fallback is simply True; `enforced`
    # follows the mode, because server mode is exactly the condition under which `_build_auth`
    # returns a verifier. Both still PREFER the composed application's own record when it is known.
    mounted = status.mounted if (status is not None and status.known) else True

    # Personal connect lines are built per-user from a freshly minted token (Library → MCP); this
    # route reports service status only and has no credential to disclose.
    return JSONResponse({
        "server_mode": server,
        "transport": "http",
        "endpoint": endpoint,
        "mounted": mounted,
        # Whether the mounted endpoint actually requires a bearer, from the composed application
        # rather than from configuration.
        "enforced": (status.enforced if (status is not None and status.known) else server),
        "runtime_status_known": bool(status is not None and status.known),
    })


@router.post("/settings/reload", dependencies=_ADMIN)
async def reload_server() -> JSONResponse:
    try:
        import signal
        os.kill(os.getpid(), signal.SIGTERM)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
