"""FMUpgradeTool subprocess wrapper.

Handles detection, validate, apply, and encrypt operations against a local
FMUpgradeTool binary. Database close/open uses the installation-owned Admin API identity.

All functions return (success: bool, output: str).  They never raise — errors
are captured in the output string so the caller can surface them to the UI.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

# Candidate paths checked in order.  First match wins.
# Project-local dev path is checked first so tests work without FMS installed.
_TOOL_CANDIDATES: list[Path] = [
    Path(__file__).parents[2] / "fms" / "bin" / "FMUpgradeTool",
    # Linux FMS (Ubuntu) — the server deployment target.
    Path("/opt/FileMaker/FileMaker Server/Database Server/bin/FMUpgradeTool"),
    # macOS FMS.
    Path("/Library/FileMaker Server/Tools/FMUpgradeTool"),
    Path("/Library/FileMaker Server/Database Server/FMUpgradeTool"),
    Path("/Library/FileMaker Server/Database Server/bin/FMUpgradeTool"),
    # Windows FMS (Program Files; co-located Windows Server deployment).
    Path(r"C:\Program Files\FileMaker\FileMaker Server\Database Server\FMUpgradeTool.exe"),
]

_FMSADMIN_CANDIDATES: list[Path] = [
    Path("/opt/FileMaker/FileMaker Server/Database Server/bin/fmsadmin"),  # Linux FMS
    Path("/Library/FileMaker Server/Database Server/bin/fmsadmin"),        # macOS FMS
    Path("/usr/local/sbin/fmsadmin"),
    Path("/usr/bin/fmsadmin"),  # symlinked on Linux
    Path(r"C:\Program Files\FileMaker\FileMaker Server\Database Server\fmsadmin.exe"),  # Windows FMS
    Path("fmsadmin"),  # in PATH on some installs
]

_TIMEOUT = 120  # seconds


def find_tool(override: Optional[str] = None) -> Optional[Path]:
    """Return the first usable FMUpgradeTool binary path, or None."""
    if override:
        p = Path(override)
        return p if p.is_file() else None
    for candidate in _TOOL_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


def find_fmsadmin(override: Optional[str] = None) -> Optional[Path]:
    """Return the first usable fmsadmin binary path, or None."""
    if override:
        p = Path(override)
        return p if p.is_file() else None
    for candidate in _FMSADMIN_CANDIDATES:
        if candidate.is_file():
            return candidate
    # Last resort: check PATH
    import shutil
    found = shutil.which("fmsadmin")
    return Path(found) if found else None


def tool_status(override: Optional[str] = None) -> dict:
    """Return detection status for UI display."""
    tool = find_tool(override)
    pki_configured = False
    try:
        from corpusfm.server.admin_api_identity import admin_api_config
        pki_configured = admin_api_config() is not None
    except Exception:
        pass
    return {
        "tool_available": tool is not None,
        "tool_path": str(tool) if tool else None,
        "admin_pki_configured": pki_configured,
    }


_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){1,3})\b")


def tool_version(tool: Optional[Path] = None) -> str:
    """Best-effort FMUpgradeTool version string (e.g. ``26.0.1.68``), or ``""`` if undetectable.

    Runs the tool's ``--version`` with a short timeout; never raises. The major (e.g. 26) is what
    distinguishes the FM 2026 build (which carries ``--generateDBFile``) from the 22.x builds that
    do not, so callers gate the generate-db capability on ``version_major() >= 26``."""
    t = tool or find_tool()
    if t is None:
        return ""
    try:
        r = subprocess.run([str(t), "--version"], capture_output=True, text=True, timeout=10)
        out = (r.stdout + r.stderr).strip()
    except Exception:  # noqa: BLE001 — detection must never break the caller
        return ""
    m = _VERSION_RE.search(out)
    return m.group(1) if m else ""


def version_major(version: str) -> int:
    """Leading integer of a version string (``"26.0.1.68"`` → 26), or 0 if unparseable."""
    head = (version or "").split(".", 1)[0]
    return int(head) if head.isdigit() else 0


_SECRET_FLAGS = frozenset({"-p", "-src_pwd", "-src_key", "-patch_key"})


def _redact_argv(cmd: list[str]) -> str:
    """argv joined for an error message, with the value following any credential flag
    scrubbed — _run's output flows into route/MCP responses (an agent's persisted
    transcript), so it must never echo an fmsadmin/FM-account password or patch key."""
    out: list[str] = []
    hide = False
    for arg in cmd:
        out.append("****" if hide else arg)
        hide = (not hide) and arg in _SECRET_FLAGS
    return " ".join(out)


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        output = (result.stdout + result.stderr).strip()
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {_TIMEOUT}s: {_redact_argv(cmd)}"
    except FileNotFoundError:
        return False, f"Binary not found: {cmd[0]}"
    except Exception as exc:
        return False, f"Unexpected error: {exc}"


def validate_patch(
    tool: Path, patch_path: Path, src_path: Path,
    account: Optional[str] = None, password: Optional[str] = None,
    ear_password: Optional[str] = None,
) -> tuple[bool, str]:
    """Run --validatePatch and return (ok, output).

    account/password are needed for a password-protected source file — without them
    FMUpgradeTool can't open it and fails with "(212): Invalid account/password".
    """
    cmd = [
        str(tool),
        "--validatePatch",
        "-patch_path", str(patch_path),
        "-src_path", str(src_path),
    ]
    if account:
        cmd += ["-src_account", account]
    if password:
        cmd += ["-src_pwd", password]
    if ear_password:
        cmd += ["-src_key", ear_password]
    return _run(cmd)


def encrypt_patch(
    tool: Path,
    patch_path: Path,
    key: str,
    dest_path: Path,
) -> tuple[bool, str]:
    """Run --encryptPatch and return (ok, output)."""
    return _run([
        str(tool),
        "--encryptPatch",
        "-patch_path", str(patch_path),
        "-patch_key", key,
        "-dest_path", str(dest_path),
    ])


def apply_patch(
    tool: Path,
    src_path: Path,
    patch_path: Path,
    dest_path: Path,
    account: Optional[str] = None,
    password: Optional[str] = None,
    ear_password: Optional[str] = None,
) -> tuple[bool, str]:
    """Run --update and return (ok, output).

    Writes patched file to dest_path (never modifies src_path in place).
    Caller is responsible for closing the database before calling this and
    re-opening it afterward.
    """
    cmd = [
        str(tool),
        "--update",
        "-src_path", str(src_path),
        "-patch_path", str(patch_path),
        "-dest_path", str(dest_path),
        "-force",
    ]
    if account:
        cmd += ["-src_account", account]
    if password:
        cmd += ["-src_pwd", password]
    if ear_password:
        cmd += ["-src_key", ear_password]
    return _run(cmd)


def generate_db_file(
    tool: Path, src_xml_path: Path, *, force: bool = True,
) -> "tuple[bool, str]":
    """Materialize a working FileMaker .fmp12 from a COMPLETE SaveAsXML export via the 2026
    tool's --generateDBFile (absent in 22.x). The output lands BESIDE the source with the same
    stem and a .fmp12 extension (the subcommand takes no -dest_path). Returns (ok, output).

    src_xml_path must be readable by the user running the tool — FileMaker's file open is
    stricter than read(2) (a foreign-owned 644 file gives error 802), so keep the source in a
    path owned by the service user. Verified on FMUpgradeTool 26.0.1.68
    (fm2026-generate-db-file-materializes)."""
    cmd = [str(tool), "--generateDBFile", "-src_path", str(src_xml_path)]
    if force:
        cmd.append("-force")
    return _run(cmd)


def dry_run_apply(
    tool: Path,
    src_path: Path,
    patch_path: Path,
    *,
    account: Optional[str] = None,
    password: Optional[str] = None,
    ear_password: Optional[str] = None,
    metrics_path: Optional[Path] = None,
) -> "tuple[bool, Optional[Path], str]":
    """Sandbox apply — run --update against a COPY of src to a fresh dest file,
    leaving the live database completely untouched (NO close / swap / reopen).

    Returns (ok, dest_path | None, log). On success dest_path is a temp .fmp12 the
    caller owns: re-host it under a temp name, export + ingest its schema, verify
    with verify_applied_patch(), then delete dest_path.parent. On failure the temp
    output is cleaned up here and dest_path is None.

    This is the production-safe rung between simulated apply (schema-graph only) and
    a real apply_patch_with_swap (which takes the live DB offline). Instrumented as a
    ``dry_run`` apply-metrics step.
    """
    import shutil
    import tempfile
    import time

    from corpusfm.server.apply_metrics import record_step

    # Linux: under /tmp/cfm* so the scoped cfm-db-helper accepts the patched output path (its
    # external paths are confined to /tmp/cfm*). Windows: the system temp (no broker confinement).
    from corpusfm.server import db_helper
    work = Path(tempfile.mkdtemp(prefix="cfm_dryrun_", dir=db_helper.staging_dir()))
    src_copy = work / "src.fmp12"
    dest = work / "out.fmp12"
    t0 = time.monotonic()
    ok, log = False, ""
    try:
        shutil.copy2(src_path, src_copy)
        ok, log = apply_patch(tool, src_copy, patch_path, dest, account, password, ear_password)
    except Exception as exc:
        ok, log = False, f"dry-run setup failed: {exc}"
    record_step("dry_run", time.monotonic() - t0, ok and dest.exists(),
                database=Path(src_path).stem, output="" if ok else log,
                metrics_path=metrics_path)

    if ok and dest.exists():
        src_copy.unlink(missing_ok=True)  # no longer needed; keep only the patched output
        return True, dest, log
    shutil.rmtree(work, ignore_errors=True)
    return False, None, log


def _pki_db_op(database: str, status: str) -> Optional[tuple[bool, str]]:
    """Open/close a database via the Admin API using a stored PKI key.

    Returns the (ok, msg) result when a PKI key is configured, or None to signal
    the caller to fall back to fmsadmin + password. CORPUSfm supports BOTH: PKI is
    preferred (no admin password needed); fmsadmin is the fallback.
    """
    try:
        from corpusfm.server.admin_api_identity import admin_api_config
        from corpusfm.server.fms_admin_pki import close_database_pki, open_database_pki

        cfg = admin_api_config()
    except Exception:
        return None
    if not cfg:
        return None
    op = close_database_pki if status == "CLOSED" else open_database_pki
    try:
        ok, msg = op(cfg["host"], cfg["name"], cfg["private_pem"], database)
        return ok, f"PKI/{cfg['host']}: {msg}"
    except Exception as exc:
        return False, f"PKI admin-API {status.lower()} failed: {exc}"


_STORAGE_DB_REFUSAL = (
    "Refused: '{db}' is CORPUSfm's storage backend database — patch/apply/close/open "
    "tools cannot target it (it holds CORPUSfm's own data). Read-only jobs are allowed."
)


def _refuse_if_storage_db(database: str) -> Optional[tuple[bool, str]]:
    """Guard for every DB-mutating/control op: refuse CORPUSfm's own storage file."""
    try:
        from corpusfm.install import is_storage_database
        if is_storage_database(database):
            return (False, _STORAGE_DB_REFUSAL.format(db=database))
    except Exception:
        pass
    return None


def _db_op(
    database: str, status: str, admin_user: str, admin_pass: str,
    fmsadmin_path: Optional[Path],
) -> tuple[bool, str]:
    """Open/close a DB through the published PKI identity only."""
    refusal = _refuse_if_storage_db(database)
    if refusal is not None:
        return refusal
    pki = _pki_db_op(database, status)
    if pki is None:
        return False, "the published FileMaker Admin API identity is unavailable"
    return pki


def close_database(
    database: str, admin_user: str = "", admin_pass: str = "",
    fmsadmin_path: Optional[Path] = None,
) -> tuple[bool, str]:
    """Close a hosted FM database through the published PKI identity."""
    return _db_op(database, "CLOSED", admin_user, admin_pass, fmsadmin_path)


def open_database(
    database: str, admin_user: str = "", admin_pass: str = "",
    fmsadmin_path: Optional[Path] = None,
) -> tuple[bool, str]:
    """Open a hosted FM database through the published PKI identity."""
    return _db_op(database, "OPENED", admin_user, admin_pass, fmsadmin_path)


def _refuse_unless_development_layout() -> Optional[tuple[bool, str]]:
    """Structurally refuse the direct close→swap→reopen path anywhere but an explicitly selected
    development layout.

    ``apply_patch_with_swap`` replaces a CALLER-SUPPLIED path with ``tmp_path.replace(src_path)`` —
    a path never resolved through the compartment resolver, with no backup, no restore and no
    authority. It survives as an explicitly development/offline library path; its installed
    reachability is refused here rather than left to convention (packet 1246-05-02 §4.1).

    The predicate is *is a development layout selected*, not *is this published*: an INDETERMINATE
    installation is refused too. A box whose records cannot be read is not a development box, and
    "we could not tell" must never be the state in which the unauthorized write path opens."""
    from corpusfm.lifecycle.app_paths import DEVELOPMENT, resolve
    try:
        state = resolve().state
    except Exception:
        state = ""
    if state == DEVELOPMENT:
        return None
    return (False,
            "Refused: the direct close→swap→reopen path is a development/offline library path and is "
            "never a route on an installed CORPUSfm. An in-compartment target is applied through the "
            "confined compartment transaction; an outside-compartment target needs the privileged "
            "mechanism and refuses without it, before anything is closed.")


def apply_patch_with_swap(
    tool: Path,
    src_path: Path,
    patch_path: Path,
    database_name: str,
    admin_user: str = "",
    admin_pass: str = "",
    account: Optional[str] = None,
    password: Optional[str] = None,
    ear_password: Optional[str] = None,
    fmsadmin_path: Optional[Path] = None,
    metrics_path: Optional[Path] = None,
) -> tuple[bool, str]:
    """DEVELOPMENT / OFFLINE ONLY — full apply workflow: close → patch to temp → swap → reopen.

    1. Close the database via fmsadmin
    2. Apply patch to a temp file
    3. Replace src_path with the patched temp file
    4. Reopen the database via fmsadmin

    **Not an installed route.** It writes a caller-supplied path directly and keeps no restore
    point, so on a published installation it is refused outright. It is never selected by the
    privileged mechanism being unavailable — helper unavailability selects nothing.

    Returns (ok, log) where log captures timing + output from each step.

    When ``metrics_path`` is given, one structured run record (per-step seconds +
    classified failure mode) is appended to that JSONL log — the apply-loop
    thermometer. Instrumentation is best-effort and never affects the outcome.
    """
    refusal = _refuse_unless_development_layout()
    if refusal is not None:
        return refusal
    # The compartment policy is about an INSTALLED runtime and has nothing to answer on a
    # development layout; the storage refusal is orthogonal to all of that and still applies.
    refusal = _refuse_if_storage_db(database_name)
    if refusal is not None:
        return refusal

    import time
    from datetime import datetime, timezone

    from corpusfm.server.apply_metrics import (
        ApplyMetrics, StepMetric, append_apply_metrics, classify_failure,
    )

    log_lines: list[str] = []
    steps: list[StepMetric] = []
    started_at = datetime.now(timezone.utc).isoformat()
    run_start = time.monotonic()

    def _record(step: str, ok: bool, out: str, secs: float) -> None:
        kind = "" if ok else classify_failure(out)
        steps.append(StepMetric(step=step, seconds=round(secs, 3), ok=ok, failure_kind=kind))
        tag = f"{step} {secs:.2f}s" + (f" !{kind}" if kind else "")
        log_lines.append(f"[{tag}] {out}")

    def _finish(overall_ok: bool) -> tuple[bool, str]:
        if metrics_path is not None:
            append_apply_metrics(
                ApplyMetrics(
                    database=database_name,
                    started_at=started_at,
                    total_seconds=round(time.monotonic() - run_start, 3),
                    overall_ok=overall_ok,
                    steps=steps,
                ),
                Path(metrics_path),
            )
        return overall_ok, "\n".join(log_lines)

    # Step 1: close
    t = time.monotonic()
    ok, out = close_database(database_name, admin_user, admin_pass, fmsadmin_path)
    _record("close", ok, out, time.monotonic() - t)
    if not ok:
        return _finish(False)

    # Step 2: patch to temp
    suffix = src_path.suffix or ".fmp12"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        t = time.monotonic()
        ok, out = apply_patch(tool, src_path, patch_path, tmp_path, account, password, ear_password)
        _record("apply", ok, out, time.monotonic() - t)
        if not ok:
            tmp_path.unlink(missing_ok=True)
            _reopen(database_name, admin_user, admin_pass, fmsadmin_path, log_lines, steps)
            return _finish(False)

        # Step 3: swap
        t = time.monotonic()
        try:
            tmp_path.replace(src_path)
            _record("swap", True, f"replaced {src_path.name}", time.monotonic() - t)
        except OSError as exc:
            _record("swap", False, f"[swap] failed: {exc}", time.monotonic() - t)
            tmp_path.unlink(missing_ok=True)
            _reopen(database_name, admin_user, admin_pass, fmsadmin_path, log_lines, steps)
            return _finish(False)

    finally:
        tmp_path.unlink(missing_ok=True)

    # Step 4: reopen. Its outcome IS the apply's outcome (packet 1205): "the patch was written" is not
    # the postcondition the caller asked about — "the database is serving" is. The log lines and
    # ApplyMetrics still distinguish patched-but-not-reopened from not-patched, so nothing is lost by
    # reporting the honest verdict.
    reopened = _reopen(database_name, admin_user, admin_pass, fmsadmin_path, log_lines, steps)
    return _finish(reopened)


def _open_after_place(
    database: str, admin_user: str = "", admin_pass: str = "",
    *, retries: int = 3, wait: float = 5.0,
) -> tuple[bool, str]:
    """Open a database whose file was just swapped in place. FM Server needs a moment
    to re-scan the changed file before the Admin API will open it — an immediate open
    hits a transient 1709 ("invalid for the resource's current status").

    Session-frugal: each PKI open opens (and releases) one Admin API session, and the
    FMS pool is SMALL (error 956 if exhausted). So we wait BEFORE the first attempt —
    giving FM time to re-scan — which means the open usually succeeds on the first try
    (one auth), not after hammering. On 956 a longer back-off is the only thing that
    helps (the pool drains on a TTL), so don't retry-spam it."""
    import time
    last = ""
    for attempt in range(retries):
        time.sleep(wait)               # let FM re-scan the swapped file FIRST
        ok, out = open_database(database, admin_user, admin_pass)
        if ok:
            return True, f"opened after {attempt + 1} attempt(s)"
        last = out
        if "956" in out:               # session pool exhausted — spamming won't help
            time.sleep(wait * 2)
    return False, f"open still failing after {retries} tries: {last}"


def apply_patch_with_helper_swap(
    tool: Path,
    database_name: str,
    patch_path: Path,
    admin_user: str = "",
    admin_pass: str = "",
    account: Optional[str] = None,
    password: Optional[str] = None,
    ear_password: Optional[str] = None,
    metrics_path: Optional[Path] = None,
) -> tuple[bool, str]:
    """Production apply from the UNPRIVILEGED service — reversible, no root/admin password.

    The authorization is minted ONCE and CARRIED, and it is **split at the close** (packet
    1246-05-02 §3.2). Every authorization and helper prerequisite is decided before anything is
    closed; the pristine backup is deliberately NOT required before it, because that backup is both
    the restore point and the patch source, and a copy taken while FMS holds the file open is
    neither.

        mint ApplyPermit -> close (PKI) -> copy out THE PERMIT'S TARGET to a backup ->
        complete ApplyAuthority from that backup -> patch the backup copy -> record the
        proposed digest -> forward placement (revalidating five facts first) -> reopen,
        or inspect-then-restore.

    What this replaces: ``check_apply_target(db_name)`` was consulted once and then the copy-out,
    the forward swap and the restore each RE-RESOLVED from a database name, re-reading mutable
    preference and mutable compartment state — four independent resolutions of one decision, three
    of them after the database was already closed. Ambient authorization, re-derived per call, is
    what lets the answer change underneath an operation in flight.

    Rollback is an obligation, not a second authorization: it inspects the exact captured target and
    acts on what is there, and it does not re-evaluate the mutable preference. The database is
    ALWAYS reopened — production is never left offline. Returns (ok, log).
    """
    import shutil
    import tempfile
    import time
    from datetime import datetime, timezone

    from corpusfm.server import db_helper
    from corpusfm.server.apply_metrics import (
        ApplyMetrics, StepMetric, append_apply_metrics, classify_failure,
    )

    permit, refusal_reason = db_helper.mint_apply_permit(database_name)
    if permit is None:
        return (False, refusal_reason)

    log_lines: list[str] = []
    steps: list[StepMetric] = []
    started_at = datetime.now(timezone.utc).isoformat()
    run_start = time.monotonic()

    def _record(step: str, ok: bool, out: str, secs: float) -> None:
        kind = "" if ok else classify_failure(out)
        steps.append(StepMetric(step=step, seconds=round(secs, 3), ok=ok, failure_kind=kind))
        log_lines.append(f"[{step} {secs:.2f}s{(' !' + kind) if kind else ''}] {out}")

    def _finish(overall_ok: bool) -> tuple[bool, str]:
        if metrics_path is not None:
            append_apply_metrics(
                ApplyMetrics(database=database_name, started_at=started_at,
                             total_seconds=round(time.monotonic() - run_start, 3),
                             overall_ok=overall_ok, steps=steps),
                Path(metrics_path))
        return overall_ok, "\n".join(log_lines)

    def _reopen_step() -> bool:
        # After a place(), FM must re-scan the swapped file before it will open — retry.
        t = time.monotonic()
        ok, out = _open_after_place(database_name, admin_user, admin_pass)
        _record("reopen", ok, out, time.monotonic() - t)
        return ok

    # The pristine backup lives in its OWN directory, deleted only after a successful reopen. Every
    # incomplete outcome — reopen-only, restored, manual recovery — leaves it on disk, because the
    # one thing an administrator may need is the exact pre-patch bytes.
    work = Path(tempfile.mkdtemp(prefix="cfm_apply_", dir=db_helper.staging_dir()))
    backup_dir = Path(tempfile.mkdtemp(prefix="cfm_backup_", dir=db_helper.staging_dir()))
    backup = backup_dir / f"{database_name}.pre-patch.fmp12"
    dest = work / "patched.fmp12"
    applied_cleanly = False
    try:
        # 1. close (PKI) — production goes offline for the swap window only. Everything that could
        #    refuse has already refused, so reaching here means nothing is closed for nothing.
        t = time.monotonic()
        ok, out = close_database(database_name, admin_user, admin_pass)
        _record("close", ok, out, time.monotonic() - t)
        if not ok:
            return _finish(False)  # never closed → nothing changed, still hosted

        # 2. copy out THE PERMIT'S TARGET → readable backup (the restore point + patch source).
        t = time.monotonic()
        ok, out = db_helper.copy_out_for(permit, str(backup))
        _record("copy_out", ok and backup.exists(), out, time.monotonic() - t)
        if not (ok and backup.exists()):
            _reopen_step()
            return _finish(False)

        # 3. only a closed file can supply a pristine backup and the original digest.
        authority, why = db_helper.complete_apply_authority(permit, backup)
        if authority is None:
            _record("authorize", False, why, 0.0)
            _reopen_step()
            return _finish(False)

        # 4. apply the patch to a copy of the backup (backup stays pristine for restore).
        t = time.monotonic()
        ok, out = apply_patch(tool, backup, patch_path, dest, account, password, ear_password)
        _record("apply", ok and dest.exists(), out, time.monotonic() - t)
        if not (ok and dest.exists()):
            _reopen_step()                       # live file untouched (nothing placed)
            return _finish(False)

        authority, why = db_helper.with_proposed(authority, dest)
        if authority is None:
            _record("authorize", False, why, 0.0)
            _reopen_step()
            return _finish(False)

        # 5. swap — the only mutation, and it reports whether publication occurred.
        t = time.monotonic()
        outcome = db_helper.place_authorized(authority, dest)
        # The publication verdict is RECORDED, never used to decide whether to inspect: mutation is
        # not inferred from an exit code, and the inspection below is strictly safer than any
        # verdict — a "did not occur" that was wrong would otherwise skip the restore entirely.
        _record("swap", outcome.ok, f"published={outcome.published}: {outcome.output}",
                time.monotonic() - t)
        if not outcome.ok:
            # Inspect the exact captured target, then act on what is there.
            t = time.monotonic()
            restore = db_helper.restore_authorized(authority)
            _record("restore", restore.result in ("no_change", "rolled_back"),
                    f"{restore.result}: {restore.output}", time.monotonic() - t)
            log_lines.append(f"[recovery] the pristine backup is preserved at {backup}")
            _reopen_step()
            return _finish(False)

        # 6. reopen (PKI). Its outcome IS the apply's outcome.
        applied_cleanly = _reopen_step()
        return _finish(applied_cleanly)
    finally:
        db_helper.close_operation(permit.operation_id)
        shutil.rmtree(work, ignore_errors=True)
        if applied_cleanly or not backup.exists():
            shutil.rmtree(backup_dir, ignore_errors=True)


def _reopen(
    database_name: str,
    admin_user: str,
    admin_pass: str,
    fmsadmin_path: Optional[Path],
    log_lines: list[str],
    steps: Optional[list] = None,
) -> bool:
    """Reopen the database. Returns whether it actually came back (packet 1205).

    It used to return ``None``, and the direct-swap path discarded the outcome and reported the apply as
    a success — a database left OFFLINE described as applied. The helper path already treated a failed
    reopen as a failed apply, so the product disagreed with itself about the same event."""
    import time

    from corpusfm.server.apply_metrics import StepMetric, classify_failure

    t = time.monotonic()
    ok, out = open_database(database_name, admin_user, admin_pass, fmsadmin_path)
    secs = time.monotonic() - t
    kind = "" if ok else classify_failure(out)
    if steps is not None:
        steps.append(StepMetric(step="reopen", seconds=round(secs, 3), ok=ok, failure_kind=kind))
    tag = f"open {secs:.2f}s" + (f" !{kind}" if kind else "")
    log_lines.append(f"[{tag}] {out}")
    return bool(ok)
