"""Sandbox dry-run orchestration — patch a copy, materialize it, verify intent.

This composes the building blocks into the production-safe end of the test-cycle:

    dry_run_apply (patch a COPY, no production swap)
      -> materialize_after (turn the patched .fmp12 into an 'after' Artifact)
      -> verify_applied_patch (confirm the patch's intent landed, flag collateral)

`materialize_after` is INJECTED because turning a patched `.fmp12` back into an
artifact is deployment-specific and side-effectful. On a co-located FMS server it
means: copy the patched file into the Databases folder under a temp name, host it
(`fmsadmin open` / Admin API), export its schema via the OData export script, ingest
the bytes, then close + remove the temp DB. That step needs filesystem access to the
FMS Databases directory (root / fmserver-owned) — so the in-app version requires the
service to run with that access; the orchestration itself is permission-agnostic.

Crucially, none of this touches the live database: the patch is applied to a copy and
the verification runs against a throwaway temp host.

Public API:
    dry_run_and_verify(tool, src_path, patch_xml, before_artifact, materialize_after,
                       *, account, password, metrics_path) -> (VerifyReport | None, log)
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact
    from corpusfm.extensions.export.patch_verify import VerifyReport

# A pre-provisioned, FMS-known database the in-app sandbox reuses. Because FMS already knows it
# (it has an id), PKI close/open work — so the unprivileged service never needs the admin password
# (which it would, to open a brand-new file). Each dry-run overwrites its file and leaves it CLOSED.
#
# **The FILE comes from the verified manifest** (``patch.sandbox_file``), never from this name and
# never from a lookup that could miss (packet 1246-05-02 §6). This constant is only the conventional
# name; ``_sandbox_target()`` resolves the real one, and refuses when the compartment cannot supply
# it. That matters because the previous code placed the sandbox through the privileged broker: if
# the sandbox file was absent — the first run after provisioning, or after a remove — the broker
# would have written ``CORPUSfm_Sandbox.fmp12`` into the MAIN FMS Databases directory. An absent
# sandbox is a refusal, never a re-creation somewhere else.
SANDBOX_DB = "CORPUSfm_Sandbox"


def _sandbox_target(sandbox_db: str = "") -> "tuple[Path, str]":
    """(the compartment's sandbox file, the FMS database name). Raises PatchAuthorityError."""
    from corpusfm.server import db_helper
    path = db_helper.sandbox_file_path()
    return path, (sandbox_db or path.stem)


def verify_db_file_hosts(
    fmp12_path: "Path",
    *,
    sandbox_db: str = "",
    admin_user: str = "",
    admin_pass: str = "",
    verify_ssl: bool = False,
) -> "tuple[bool, str]":
    """Confirm a generated .fmp12 HOSTS cleanly on FMS, without touching production: PKI-close the
    compartment's sandbox, overwrite that exact file with a direct confined atomic replacement,
    PKI-open it, confirm it reaches a running status, then close. NO OData export (a freshly
    materialized file need not carry the CORPUSfm export addon). Returns (hosts, log). Never raises.

    The replacement never uses the privileged helper: the sandbox lives inside the CORPUSfm-owned
    compartment, so the service writes it directly."""
    from corpusfm.server import db_helper, fms_admin_pki as P
    from corpusfm.server.patch_apply import open_database, close_database
    try:
        _sandbox_path, sandbox_db = _sandbox_target(sandbox_db)
    except db_helper.PatchAuthorityError as exc:
        return False, f"sandbox host check refused: {exc}"
    try:
        close_database(sandbox_db, admin_user, admin_pass)
    except Exception:
        pass
    try:
        ok, msg = db_helper.replace_sandbox_file(fmp12_path)
        if not ok:
            return False, f"sandbox place failed: {msg}"
        ok, msg = open_database(sandbox_db, admin_user, admin_pass)
        if not ok:
            return False, f"sandbox open failed: {msg}"
        from corpusfm.server.admin_api_identity import admin_api_identity

        identity = admin_api_identity()
        cfg = identity.config
        if not cfg:
            return True, f"placed + opened (no PKI to confirm running status: {identity.reason})"
        hosts = P.wait_until_status(
            cfg["host"], cfg["name"], cfg["private_pem"], sandbox_db, "OPEN", verify_ssl=verify_ssl)
        return (hosts, "hosts cleanly" if hosts
                else "placed + opened but did not reach a running status")
    except Exception as exc:
        return False, f"host check error: {exc}"
    finally:
        # Left CLOSED between runs.
        try:
            close_database(sandbox_db, admin_user, admin_pass)
        except Exception:
            pass


def dry_run_and_verify(
    tool: Path,
    src_path: Path,
    patch_xml: str,
    before_artifact: "Artifact",
    materialize_after: "Callable[[Path], Artifact]",
    *,
    account: Optional[str] = None,
    password: Optional[str] = None,
    ear_password: Optional[str] = None,
    metrics_path: Optional[Path] = None,
) -> "tuple[Optional[VerifyReport], str]":
    """Apply a patch to a sandbox copy of src, materialize the patched copy into an
    artifact, and verify it against before_artifact.

    Returns (report, log). report is None when the dry-run apply itself failed (the
    log explains). The patched copy and all temp files are always cleaned up; the live
    database is never touched.
    """
    from corpusfm.server.patch_apply import dry_run_apply
    from corpusfm.extensions.export.patch_verify import verify_applied_patch

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
        patch_path = Path(tf.name)
    patch_path.write_text(patch_xml, encoding="utf-8")

    try:
        ok, dest, log = dry_run_apply(
            tool, Path(src_path), patch_path,
            account=account, password=password, ear_password=ear_password,
            metrics_path=metrics_path,
        )
        if not ok or dest is None:
            return None, log
        try:
            after = materialize_after(dest)
        finally:
            shutil.rmtree(dest.parent, ignore_errors=True)
        report = verify_applied_patch(patch_xml, before_artifact, after)
        return report, log
    finally:
        patch_path.unlink(missing_ok=True)


def materialize_via_fms(
    dest_path: Path,
    *,
    sandbox_db: str = "",
    host: str,
    credentials: dict,
    verify_ssl: bool = True,
    admin_user: str = "",
    admin_pass: str = "",
    export_retries: int = 6,
    export_wait: float = 3.0,
) -> "Artifact":
    """Turn a patched .fmp12 into an Artifact on a co-located FMS, using the compartment's own
    sandbox — never touching the live database.

    PKI-close the sandbox -> overwrite THAT EXACT FILE with the patched copy, directly and
    atomically inside the compartment (never the privileged helper) -> PKI-open it -> export its
    schema via the OData export script -> ingest. It is left CLOSED (the next run overwrites it).
    Raises on any failure (the caller's dry_run_and_verify still cleans up the patched copy).
    """
    from corpusfm.server import db_helper
    from corpusfm.server.patch_apply import open_database, close_database
    from corpusfm.server.fms_client import pull_fms_save_to_documents, FMSError
    from corpusfm.ingestion.pipeline import ingest

    _sandbox_path, sandbox_db = _sandbox_target(sandbox_db)

    # Ensure it is closed before overwriting its file. Best-effort: between runs it is already
    # closed (close-of-closed may error harmlessly); only a real "busy with clients" close failure
    # would matter, and the sandbox has no clients.
    try:
        close_database(sandbox_db, admin_user, admin_pass)
    except Exception:
        pass
    try:
        ok, msg = db_helper.replace_sandbox_file(dest_path)
        if not ok:
            raise RuntimeError(f"sandbox place failed: {msg}")
        ok, msg = open_database(sandbox_db, admin_user, admin_pass)
        if not ok:
            raise RuntimeError(f"sandbox open failed: {msg}")
        last = ""
        for _ in range(export_retries):
            try:
                xml_bytes = pull_fms_save_to_documents(
                    host, sandbox_db, credentials, verify_ssl=verify_ssl)
                return ingest(xml_bytes, sandbox_db, source_type="dry_run", name_map={})
            except (FMSError, FileNotFoundError) as exc:
                last = str(exc)
                time.sleep(export_wait)
        raise RuntimeError(f"sandbox export failed after {export_retries} tries: {last}")
    finally:
        try:
            close_database(sandbox_db, admin_user, admin_pass)
        except Exception:
            pass


def sandbox_dry_run_verify(
    tool: Path,
    database_name: str,
    patch_xml: str,
    before_artifact: "Artifact",
    *,
    host: str,
    credentials: dict,
    verify_ssl: bool = True,
    admin_user: str = "",
    admin_pass: str = "",
    ear_password: Optional[str] = None,
    sandbox_db: str = "",
    metrics_path: Optional[Path] = None,
) -> "tuple[Optional[VerifyReport], str]":
    """In-app sandbox dry-run+verify of a patch against a live, hosted database — with
    the live database never touched.

    Copy the live DB OUT (directly for a compartment target; through the privileged mechanism only
    when the five gates authorize it), dry-run the patch on that copy, materialize the patched copy
    through the compartment's sandbox, and verify intent. Returns (VerifyReport | None, log).

    The apply-target policy is applied HERE too — a dry-run reads a live database, and the verified
    compartment prerequisite governs it exactly as it governs a real apply.
    """
    from corpusfm.server import db_helper

    ok, reason = db_helper.check_apply_target(database_name)
    if not ok:
        return None, f"Refused: {reason}"

    # /tmp/cfm* so the scoped helper accepts the copy-out destination (Windows: system temp).
    src_dir = Path(tempfile.mkdtemp(prefix="cfm_src_", dir=db_helper.staging_dir()))
    src = src_dir / "src.fmp12"
    ok, msg = db_helper.copy_out(database_name, str(src))
    if not ok:
        shutil.rmtree(src_dir, ignore_errors=True)
        return None, f"copy-out '{database_name}' failed: {msg}"

    account = credentials.get("username") or None
    password = credentials.get("password") or None
    try:
        def _materialize(dest: Path) -> "Artifact":
            return materialize_via_fms(
                dest, sandbox_db=sandbox_db, host=host, credentials=credentials,
                verify_ssl=verify_ssl, admin_user=admin_user, admin_pass=admin_pass)

        return dry_run_and_verify(
            tool, src, patch_xml, before_artifact, _materialize,
            account=account, password=password, ear_password=ear_password,
            metrics_path=metrics_path)
    finally:
        shutil.rmtree(src_dir, ignore_errors=True)
