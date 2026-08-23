"""Session-scoped patch operations — validate / encrypt / apply.

These act on the patch XML held in the active Patch (ISV) or Patch (AI)
generation session, NOT on a saved library entry. They are part of the
patch-making process and live in the generate UIs until the user abandons
the patch, starts a new one, or starts a new session. The Patches Library is
the end of the line: once a patch is archived there, the only action is download.

All three require FMUpgradeTool (and fmsadmin, for apply) on the same machine —
i.e. a co-located server install.

POST /api/patch-ops/coherence { patch_xml, artifact_path }            -> intra-patch pre-flight
POST /api/patch-ops/simulate  { patch_xml, artifact_path }            -> simulated apply (dry-run)
POST /api/patch-ops/verify    { patch_xml, before_path, after_path }  -> post-apply verify
POST /api/patch-ops/validate  { patch_xml, src_path }
POST /api/patch-ops/encrypt   { patch_xml, key }                      -> encrypted download
POST /api/patch-ops/apply     { patch_xml, database_name }
GET  /api/patch-ops/tool-status

The static gates need no FMUpgradeTool / FileMaker. The verification ladder, cheapest first:
- /coherence checks references WITHIN the patch (dangling, field-on-occurrence, ordering).
- /simulate models the schema the patch would PRODUCE — delete-impact (does the EXISTING
  schema still reference a deleted object?), hostability, resulting object-count delta.
- /verify confirms, after a (sandbox) apply, that the patch's intended changes actually
  landed and nothing else changed — the "confirm" that closes the predict→apply→verify loop.
- /dry-run-verify is the co-located in-app sandbox: patch a COPY of a live DB (via
  FMUpgradeTool), materialize it through the ONE sandbox file inside the verified patch
  compartment, and verify — production untouched. Needs a VERIFIED patch compartment
  holding that sandbox; an absent sandbox refuses rather than being re-created elsewhere.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import require_auth, require_gate, actor_from_request
from corpusfm.server import audit

# Every patch op (validate / encrypt / dry-run / apply / …) requires the `patching` gate, not just
# a login — enforced at the router level so a privileged endpoint can't be reached directly by a
# logged-in user without the gate. (Per-route require_auth is kept for explicitness.)
router = APIRouter(dependencies=[Depends(require_gate("patching"))])

# Serialize sandbox dry-runs: each does PKI close+open (2 Admin API auths) and reuses
# the single sandbox file the verified compartment records. FMS caps concurrent Admin API
# sessions (error 956), so concurrent dry-runs would both exhaust the pool and collide.
_dry_run_lock = threading.Lock()


@dataclass(frozen=True)
class TargetAccess:
    """One operation's target-file authority; secret fields are never serialized or logged."""
    account: str = ""
    password: str = ""
    ear_password: str = ""
    source: str = "transient"


def _target_access(body: dict, *, database_name: str = "", before_path: str = "") -> TargetAccess:
    """Resolve transient input or the exact Job that produced the reviewed baseline artifact."""
    account = str(body.get("file_account") or "").strip()
    password = str(body.get("file_password") or "")
    ear = str(body.get("ear_password") or "")
    if account or password:
        if not account or not password:
            raise ValueError("target-file account and password must be supplied together")
        return TargetAccess(account, password, ear, "transient")

    if before_path:
        try:
            from corpusfm.storage import get_backend
            from corpusfm.server.jobs.store import find_job_by_id, get_job_credential

            meta = get_backend().get_artifact_meta(before_path)
            job_id = (getattr(meta, "job_uuid", "") or "") if meta else ""
            job = find_job_by_id(job_id) if job_id else None
            expected = (database_name or "").removesuffix(".fmp12").casefold()
            actual = (getattr(job, "file", "") or "").removesuffix(".fmp12").casefold() if job else ""
            local = not job or (getattr(job.source, "server_ref", None) or "local") == "local"
            cred = get_job_credential(job.name) if job and local and expected and actual == expected else None
            if cred and cred.get("account") and cred.get("password"):
                return TargetAccess(str(cred["account"]), str(cred["password"]), ear, "job")
        except Exception:
            pass
    return TargetAccess(ear_password=ear, source="transient")


def _is_windows() -> bool:
    return os.name == "nt"


def _refuse_storage_db(database_name: str, key: str = "error") -> JSONResponse | None:
    """403 if the target is CORPUSfm's own storage backend database — patch tools must
    never address it. Read-only jobs are allowed (they don't come through here)."""
    from corpusfm.install import is_storage_database
    if is_storage_database(database_name):
        msg = (f"'{database_name}' is CORPUSfm's storage backend database and cannot be a "
               "patch/apply target. Read-only jobs against it are allowed.")
        return JSONResponse({"ok": False, key: msg}, status_code=403)
    return None


def _refuse_unauthorized_target(database_name: str, key: str = "error") -> JSONResponse | None:
    """403 if the apply-target policy refuses this DB, unified across platforms. The verified
    compartment is the prerequisite: with no verified compartment nothing passes, whatever the
    preference says. With the restriction ON (default) only a file hosted from that compartment
    passes; anything from the default Databases dir is refused, and an unlocatable target fails
    closed. With it OFF, any non-storage DB passes WITHIN that already-authorized world. Storage-DB
    refusal is handled by _refuse_storage_db (call it first for its dedicated message); this catches
    the compartment case before anything is closed."""
    from corpusfm.server import db_helper
    ok, reason = db_helper.check_apply_target(database_name)
    if not ok:
        return JSONResponse({"ok": False, key: reason}, status_code=403)
    return None


def _tier_gate(*, tier: int = 0, capability: str = "") -> JSONResponse | None:
    """Return a structured 'unavailable' response (HTTP 200, ok:False) when the required tier or
    capability isn't established — so a privileged op degrades to a notice, never a 500. Pass
    `tier=2` (apply/dry-run) or `capability="upgrade_tool"` (validate/encrypt)."""
    from corpusfm.server import readiness
    g = readiness.require_tier(tier) if tier else readiness.require_capability(capability)
    if g is None:
        return None
    return JSONResponse(
        {"ok": False, "available": False, "tier": g.get("tier", tier),
         "error": g.get("reason", "capability unavailable"), "how": g.get("how", "")},
        status_code=200,
    )


def _write_temp_patch(patch_xml: str) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        path = Path(tmp.name)
    path.write_text(patch_xml, encoding="utf-8")
    return path


def _metrics_path() -> Path | None:
    """Resolve the apply-loop metrics log under the backend archive dir, or None.

    The thermometer (apply_metrics.jsonl) accumulates per-step timings + failure
    modes across the whole generate->coherence->validate->apply->verify loop so
    the heavy apply cost can be measured before it is optimized. Best-effort.
    """
    try:
        from corpusfm.storage import get_backend
        from corpusfm.server.apply_metrics import metrics_log_path
        archive_dir = get_backend().archive_dir
        return metrics_log_path(archive_dir) if archive_dir is not None else None
    except Exception:
        return None


def _find_tool():
    from corpusfm.server.patch_apply import find_tool
    from corpusfm.app.app_config import load_app_config
    try:
        cfg = load_app_config()
        override = getattr(cfg, "fmupgrade_tool_path", None) or None
    except Exception:
        # Detection is a capability probe. An uncomposed installation has no preference store,
        # but should still produce the ordinary unavailable result rather than a traceback.
        override = None
    return find_tool(override)


@router.get("/patch-ops/tool-status", dependencies=[Depends(require_auth)])
async def get_tool_status() -> JSONResponse:
    """Return FMUpgradeTool + fmsadmin detection status, plus whether the verified compartment
    holds its sandbox (sandbox dry-run availability)."""
    from corpusfm.server.patch_apply import tool_status
    from corpusfm.server import db_helper
    from corpusfm.app.app_config import load_app_config
    cfg = load_app_config()
    override = getattr(cfg, "fmupgrade_tool_path", None) or None
    status = tool_status(override)
    try:
        db_helper.sandbox_file_path()
        status["sandbox_available"] = True
    except db_helper.PatchAuthorityError:
        status["sandbox_available"] = False
    return JSONResponse(status)


@router.post("/patch-ops/coherence", dependencies=[Depends(require_auth)])
async def check_coherence(request: Request) -> JSONResponse:
    """Static intra-patch coherence pre-flight against the target artifact.

    Body: { "patch_xml": "...", "artifact_path": "<rel_path of the base artifact>" }
    Returns the CoherenceReport dict. No FMUpgradeTool / FileMaker needed.
    """
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    artifact_path = (body.get("artifact_path") or "").strip()
    if not patch_xml:
        return JSONResponse({"ok": False, "error": "patch_xml is required"}, status_code=400)
    if not artifact_path:
        return JSONResponse({"ok": False, "error": "artifact_path is required"}, status_code=400)

    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.extensions.export.patch_coherence import check_patch_coherence
    from corpusfm.server.apply_metrics import record_step

    backend = get_backend()
    uuid, err = resolve_ref(backend, artifact_path)
    if err is not None:
        return err
    try:
        artifact = backend.load_artifact(uuid)
    except FileNotFoundError:
        return JSONResponse(
            {"ok": False, "error": "Target artifact not found — re-ingest the file first."},
            status_code=404,
        )

    t0 = time.perf_counter()
    report = check_patch_coherence(patch_xml, artifact)
    record_step(
        "coherence", time.perf_counter() - t0, report.is_coherent,
        database=getattr(artifact.identity, "file_name", ""),
        output="incoherent" if not report.is_coherent else "",
        metrics_path=_metrics_path(),
    )
    return JSONResponse({"ok": True, "report": report.to_dict()})


@router.post("/patch-ops/simulate", dependencies=[Depends(require_auth)])
async def simulate_patch(request: Request) -> JSONResponse:
    """Simulated apply — a schema-graph dry-run of the patch against the target.

    Body: { "patch_xml": "...", "artifact_path": "<rel_path of the base artifact>" }
    Returns the SimulationReport dict (consistency + hostability + delete-impact +
    resulting object-count delta). No FMUpgradeTool / FileMaker needed — the cheap
    proxy for a real close→patch→swap→reopen apply.
    """
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    artifact_path = (body.get("artifact_path") or "").strip()
    if not patch_xml:
        return JSONResponse({"ok": False, "error": "patch_xml is required"}, status_code=400)
    if not artifact_path:
        return JSONResponse({"ok": False, "error": "artifact_path is required"}, status_code=400)

    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.extensions.export.patch_simulate import simulate_apply
    from corpusfm.server.apply_metrics import record_step

    backend = get_backend()
    uuid, err = resolve_ref(backend, artifact_path)
    if err is not None:
        return err
    try:
        artifact = backend.load_artifact(uuid)
    except FileNotFoundError:
        return JSONResponse(
            {"ok": False, "error": "Target artifact not found — re-ingest the file first."},
            status_code=404,
        )

    t0 = time.perf_counter()
    report = simulate_apply(patch_xml, artifact)
    record_step(
        "simulate", time.perf_counter() - t0, report.is_consistent and report.would_host,
        database=getattr(artifact.identity, "file_name", ""),
        output="" if (report.is_consistent and report.would_host) else "patch_invalid",
        metrics_path=_metrics_path(),
    )
    return JSONResponse({"ok": True, "report": report.to_dict()})


@router.post("/patch-ops/verify", dependencies=[Depends(require_auth)])
async def verify_patch(request: Request) -> JSONResponse:
    """Targeted post-apply verification — did the patch do exactly what it intended?

    Body: { "patch_xml": "...", "before_path": "<rel_path>", "after_path": "<rel_path>" }
    where after_path is the artifact re-imported AFTER applying the patch (e.g. via
    reimport_after_patch / a sandbox dry-run). Returns the VerifyReport dict: confirmed /
    missing (apply failures) / unexpected (collateral). No FMUpgradeTool / FileMaker.
    """
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    before_path = (body.get("before_path") or "").strip()
    after_path = (body.get("after_path") or "").strip()
    if not patch_xml or not before_path or not after_path:
        return JSONResponse(
            {"ok": False, "error": "patch_xml, before_path and after_path are required"},
            status_code=400,
        )

    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.extensions.export.patch_verify import verify_applied_patch
    from corpusfm.server.apply_metrics import record_step

    backend = get_backend()
    before_uuid, err = resolve_ref(backend, before_path)
    if err is not None:
        return err
    after_uuid, err = resolve_ref(backend, after_path)
    if err is not None:
        return err
    try:
        before = backend.load_artifact(before_uuid)
        after = backend.load_artifact(after_uuid)
    except FileNotFoundError:
        return JSONResponse(
            {"ok": False, "error": "before or after artifact not found."}, status_code=404)

    t0 = time.perf_counter()
    report = verify_applied_patch(patch_xml, before, after)
    record_step(
        "verify", time.perf_counter() - t0, report.applied_cleanly,
        database=getattr(after.identity, "file_name", ""),
        output="" if report.applied_cleanly else "patch_invalid",
        metrics_path=_metrics_path(),
    )
    audit.record(audit.PATCH_VERIFY, actor=actor_from_request(request),
                 target=getattr(after.identity, "file_name", ""),
                 outcome="ok" if report.applied_cleanly else "error")
    return JSONResponse({"ok": True, "report": report.to_dict()})


def _run_sandbox(tool, database_name, patch_xml, before, transport, access, metrics_path):
    """Blocking sandbox dry-run+verify, serialized so concurrent runs can't exhaust
    the Admin API session pool or collide on the shared sandbox slot."""
    from corpusfm.server.dry_run import sandbox_dry_run_verify
    with _dry_run_lock:
        return sandbox_dry_run_verify(
            tool, database_name, patch_xml, before,
            host=transport.host,
            credentials={"username": access.account, "password": access.password},
            verify_ssl=transport.verify_ssl,
            ear_password=access.ear_password,
            metrics_path=metrics_path,
        )


@router.post("/patch-ops/dry-run-verify", dependencies=[Depends(require_auth)])
async def dry_run_verify(request: Request) -> JSONResponse:
    """In-app sandbox apply: patch a COPY of a live DB and verify intent, production
    untouched. Needs a VERIFIED patch compartment holding its one sandbox file.

    Body: { "patch_xml", "before_path", "database_name" }
    Returns the VerifyReport dict (confirmed / missing / unexpected).
    """
    gate = _tier_gate(tier=2)
    if gate:
        return gate
    # The sandbox dry-run materializes the patched copy through the compartment sandbox + an OData
    # export — a Linux-only provisioned path. On Windows there is no sandbox slot; the reversible
    # apply route (backup → swap → inspect → restore) is the supported path instead.
    if _is_windows():
        return JSONResponse(
            {"ok": False, "error": "Sandbox dry-run-verify is not available on Windows (it needs "
             "the Linux-provisioned compartment sandbox + OData materialize). Use the apply "
             "route — on Windows it is reversible via backup/restore."},
            status_code=400)
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    before_path = (body.get("before_path") or "").strip()
    database_name = (body.get("database_name") or "").strip()
    if not patch_xml or not before_path or not database_name:
        return JSONResponse(
            {"ok": False, "error": "patch_xml, before_path and database_name are required"},
            status_code=400)
    refusal = _refuse_storage_db(database_name) or _refuse_unauthorized_target(database_name)
    if refusal:
        return refusal

    # Accept AI-fenced output too — reduce to the bare <FMUpgradeToolPatch> (no-op for
    # already-clean ISV XML).
    try:
        from corpusfm.server.ai.patch_ai import extract_ai_patch_xml
        patch_xml = extract_ai_patch_xml(patch_xml)
    except Exception:
        pass

    from corpusfm.server import db_helper
    try:
        db_helper.sandbox_file_path()
    except db_helper.PatchAuthorityError as exc:
        return JSONResponse(
            {"ok": False, "error": f"Sandbox apply is not available on this server: {exc}"},
            status_code=400)

    from corpusfm.storage import get_backend
    from corpusfm.server.fms_transport import colocated
    tool = _find_tool()
    if tool is None:
        return JSONResponse({"ok": False, "error": "FMUpgradeTool not found"}, status_code=400)
    try:
        transport = colocated()
        access = _target_access(body, database_name=database_name, before_path=before_path)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"Installed FileMaker transport unavailable: {exc}"},
                            status_code=409)
    if not access.account:
        return JSONResponse({"ok": False, "error": "Target-file account and password are required."},
                            status_code=400)
    from corpusfm.app.web.artifact_ref import resolve_ref
    _be = get_backend()
    before_uuid, err = resolve_ref(_be, before_path)
    if err is not None:
        return err
    try:
        before = _be.load_artifact(before_uuid)
    except FileNotFoundError:
        return JSONResponse({"ok": False, "error": "before artifact not found."}, status_code=404)

    report, log = await run_in_threadpool(
        _run_sandbox, tool, database_name, patch_xml, before, transport, access, _metrics_path())
    if report is None:
        audit.record(audit.PATCH_DRY_RUN, actor=actor_from_request(request),
                     target=database_name, outcome="error", meta={"op": "sandbox"})
        return JSONResponse({"ok": False, "error": log}, status_code=500)
    report_dict = report.to_dict()
    audit.record(audit.PATCH_DRY_RUN, actor=actor_from_request(request),
                 target=database_name, outcome="ok",
                 meta={"op": "sandbox", "applied_cleanly": bool(report_dict.get("applied_cleanly"))})
    return JSONResponse({"ok": True, "report": report_dict, "log": log,
                         "access_source": access.source})


@router.post("/patch-ops/validate", dependencies=[Depends(require_auth)])
async def validate_patch(request: Request) -> JSONResponse:
    """Run --validatePatch against a local FM file.

    Body: { "patch_xml": "...", "src_path": "/path/to/file.fmp12" }
    The account/password a password-protected source file needs (else 212) come from the
    configured FileMaker server.
    """
    gate = _tier_gate(capability="upgrade_tool")
    if gate:
        return gate
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    src_path = (body.get("src_path") or "").strip()
    if not patch_xml:
        return JSONResponse({"ok": False, "output": "patch_xml is required"}, status_code=400)
    if not src_path:
        return JSONResponse({"ok": False, "output": "src_path is required"}, status_code=400)

    from corpusfm.server.patch_apply import validate_patch as _validate
    from corpusfm.server.apply_metrics import record_step
    tool = _find_tool()
    if tool is None:
        return JSONResponse({"ok": False, "output": "FMUpgradeTool not found"}, status_code=400)

    database_name = (body.get("database_name") or Path(src_path).stem).strip()
    before_path = (body.get("before_path") or "").strip()
    try:
        access = _target_access(body, database_name=database_name, before_path=before_path)
    except ValueError as exc:
        return JSONResponse({"ok": False, "output": str(exc)}, status_code=400)
    if not access.account:
        return JSONResponse(
            {"ok": False, "output": "Target-file account and password are required."}, status_code=400)

    tmp_patch = _write_temp_patch(patch_xml)
    t0 = time.perf_counter()
    try:
        ok, output = _validate(tool, tmp_patch, Path(src_path), access.account, access.password,
                               access.ear_password)
    finally:
        tmp_patch.unlink(missing_ok=True)

    record_step("validate", time.perf_counter() - t0, ok,
                database=Path(src_path).stem, output=output, metrics_path=_metrics_path())
    audit.record(audit.PATCH_DRY_RUN, actor=actor_from_request(request),
                 target=Path(src_path).stem, outcome="ok" if ok else "error",
                 meta={"op": "validate"})
    return JSONResponse({"ok": ok, "output": output, "access_source": access.source})


@router.post("/patch-ops/encrypt", dependencies=[Depends(require_auth)])
async def encrypt_patch(request: Request) -> Response:
    """Encrypt a patch and return the encrypted XML as a download.

    Body: { "patch_xml": "...", "key": "passphrase" }
    """
    gate = _tier_gate(capability="upgrade_tool")
    if gate:
        return gate
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    key = (body.get("key") or "").strip()
    if not patch_xml:
        return JSONResponse({"ok": False, "error": "patch_xml is required"}, status_code=400)
    if not key:
        return JSONResponse({"ok": False, "error": "key is required"}, status_code=400)

    from corpusfm.server.patch_apply import encrypt_patch as _encrypt
    tool = _find_tool()
    if tool is None:
        return JSONResponse({"ok": False, "error": "FMUpgradeTool not found"}, status_code=400)

    tmp_patch = _write_temp_patch(patch_xml)
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp_out:
        tmp_enc = Path(tmp_out.name)
    try:
        ok, output = _encrypt(tool, tmp_patch, key, tmp_enc)
        if not ok:
            return JSONResponse({"ok": False, "error": output}, status_code=500)
        encrypted_bytes = tmp_enc.read_bytes()
    finally:
        tmp_patch.unlink(missing_ok=True)
        tmp_enc.unlink(missing_ok=True)

    return Response(
        content=encrypted_bytes,
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="patch-encrypted.xml"'},
    )


def _run_production_apply(tool, database_name, patch_xml, before, transport, access,
                          metrics_path, skip_dry_run):
    """Blocking production apply, serialized (shares the Admin API session pool + the
    sandbox slot with dry-runs). Safe-by-construction: it (a) runs the sandbox dry-run
    pre-flight — production untouched — and aborts unless it applies cleanly, then (b)
    applies for real through the authorized, reversible loop.

    **There is one route (packet 1246-05-02 §4.1).** This used to branch on
    ``db_helper.helper_available()`` and, when false, call ``apply_patch_with_swap`` on a
    caller-supplied ``src_path`` — a path never resolved through the compartment resolver, with no
    backup, no restore and no authority. Helper unavailability must not select a weaker route: a
    compartment target does not need the privileged mechanism at all, and an outside-compartment
    target needs it and refuses without it, before anything is closed."""
    from corpusfm.server.patch_apply import apply_patch_with_helper_swap
    from corpusfm.server.dry_run import sandbox_dry_run_verify
    with _dry_run_lock:
        # (a) Pre-flight: predict on a copy. Abort the real apply unless clean. SKIPPED on
        # Windows — the sandbox materialize is Linux-only (no compartment sandbox slot); the
        # authorized loop below is itself reversible (backup → swap → inspect → restore).
        if before is not None and not skip_dry_run and not _is_windows():
            report, dlog = sandbox_dry_run_verify(
                tool, database_name, patch_xml, before,
                host=transport.host,
                credentials={"username": access.account, "password": access.password},
                verify_ssl=transport.verify_ssl,
                ear_password=access.ear_password,
                metrics_path=metrics_path)
            if report is None:
                return False, f"Pre-flight dry-run failed; production NOT touched.\n{dlog}", "preflight"
            if not report.applied_cleanly:
                return (False,
                        "Pre-flight dry-run did NOT apply cleanly; production NOT touched. "
                        f"Missing: {report.missing}. Re-check the patch.\n{dlog}",
                        "preflight")
        # (b) Apply for real — authorized once, carried, reversible.
        tmp_patch = _write_temp_patch(patch_xml)
        try:
            ok, log = apply_patch_with_helper_swap(
                tool=tool, database_name=database_name, patch_path=tmp_patch,
                account=access.account or None, password=access.password or None,
                ear_password=access.ear_password or None, metrics_path=metrics_path)
        finally:
            tmp_patch.unlink(missing_ok=True)
        return ok, log, "authorized"


@router.post("/patch-ops/apply", dependencies=[Depends(require_auth)])
async def apply_patch(request: Request) -> JSONResponse:
    """Apply a patch to a hosted FM database, production-safe.

    The culmination of the verification ladder, and there is ONE route: a sandbox dry-run pre-flight
    (production untouched) gates a reversible, authorized real apply — mint the permit, close (PKI),
    copy out the permit's exact target as the pristine backup, complete the authority from it, patch
    a copy, revalidate, place, reopen — with no root and no admin password.

    The ``src_path`` body field and the no-helper direct-swap route it selected are GONE (packet
    1246-05-02 §4.1). That branch wrote a caller-supplied path with no backup, no restore and no
    authority; helper unavailability now selects nothing, because a compartment target needs no
    privileged mechanism at all and an outside-compartment target refuses without one before
    anything is closed.

    Body:
    {
        "patch_xml": "...",
        "database_name": "MyFile",
        "before_path": "<rel_path of the pre-apply artifact>",  // enables the pre-flight
        "skip_dry_run": false                        // escape hatch (not recommended)
    }
    The host + credentials come from the configured FileMaker server.
    Returns { "ok": bool, "log": str, "path": "authorized|preflight" }
    """
    gate = _tier_gate(tier=2)
    if gate:
        return gate
    body = await request.json()
    patch_xml = (body.get("patch_xml") or "").strip()
    database_name = (body.get("database_name") or "").strip()
    before_path = (body.get("before_path") or "").strip()
    skip_dry_run = bool(body.get("skip_dry_run"))

    if not patch_xml:
        return JSONResponse({"ok": False, "log": "patch_xml is required"}, status_code=400)
    if not database_name:
        return JSONResponse({"ok": False, "log": "database_name is required"}, status_code=400)
    refusal = (_refuse_storage_db(database_name, key="log")
               or _refuse_unauthorized_target(database_name, key="log"))
    if refusal:
        return refusal

    # Accept AI-fenced output — reduce to the bare <FMUpgradeToolPatch> (no-op for ISV).
    try:
        from corpusfm.server.ai.patch_ai import extract_ai_patch_xml
        patch_xml = extract_ai_patch_xml(patch_xml)
    except Exception:
        pass

    from corpusfm.storage import get_backend
    from corpusfm.server.fms_transport import colocated

    tool = _find_tool()
    if tool is None:
        return JSONResponse({"ok": False, "log": "FMUpgradeTool not found"}, status_code=400)

    try:
        transport = colocated()
        access = _target_access(body, database_name=database_name, before_path=before_path)
    except ValueError as exc:
        return JSONResponse({"ok": False, "log": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "log": f"Installed FileMaker transport unavailable: {exc}"},
                            status_code=409)
    if not access.account:
        return JSONResponse({"ok": False, "log": "Target-file account and password are required."},
                            status_code=400)
    before = None
    if before_path:
        try:
            before = get_backend().load_artifact(before_path)
        except FileNotFoundError:
            return JSONResponse(
                {"ok": False, "log": "before_path artifact not found — re-ingest the file, "
                                     "or omit before_path to skip the safety pre-flight."},
                status_code=404)

    ok, log, path = await run_in_threadpool(
        _run_production_apply, tool, database_name, patch_xml, before, transport, access,
        _metrics_path(), skip_dry_run)
    audit.record(audit.PATCH_APPLY, actor=actor_from_request(request), target=database_name,
                 outcome="ok" if ok else "error",
                 meta={"op": "apply", "path": path, "skip_dry_run": skip_dry_run})
    status = 200 if ok else (409 if path == "preflight" else 500)
    return JSONResponse({"ok": ok, "log": log, "path": path,
                         "access_source": access.source}, status_code=status)
