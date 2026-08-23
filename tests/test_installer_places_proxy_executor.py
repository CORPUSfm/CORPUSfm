"""Phase 13 installs the proxy executor, or the install stops before phase 14.

**The defect, measured on fms-server 2026-08-08.** A fresh install reached generation 3 and phase 17
refused: `/opt/CORPUSfm/bin/cfm-proxy-exec.sh does not exist`. The executor ships in the payload at
`installer/linux/cfm-proxy-exec.sh` (and its Windows sibling) and **no installer step placed it** —
`grep -c cfm-proxy-exec` returned 0 for both scripts, and `git log -S` showed `install.sh` had never
referenced it. Every other file in `<InstallDir>/bin` was installed inside `if [[ -f "$UPDATER_SRC" ]]`,
so even the shape that existed was conditioned on the one-shot updater.

`proxy_transaction.executor_script` resolves `<InstallDir>/bin/cfm-proxy-exec.{sh,ps1}` and nothing
else — no source tree, no PATH, no cwd — because the file is handed root authority over FileMaker
Server's own web configuration. The resolver is right; the installers were incomplete. So these
controls are about PLACEMENT, and they are deliberately split:

* what the installer scripts DECIDE — asserted by reading them (they cannot be run off-box);
* what the resolver REQUIRES — asserted by executing the real `executor_script` against a real
  directory tree, so the two halves are pinned to one path rather than to each other's wording.

**E3.** Off box. Real Linux placement is executed against a temporary tree; the Windows DACL and the
live phase ordering remain 1246-10 live gates.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SH = ROOT / "installer" / "linux" / "install.sh"
PS1 = ROOT / "installer" / "windows" / "install.ps1"
WINDOWS_EXECUTOR = ROOT / "installer" / "windows" / "cfm-proxy-exec.ps1"

LINUX_SRC = "installer/linux/cfm-proxy-exec.sh"
WINDOWS_SRC = "installer/windows/cfm-proxy-exec.ps1"
LINUX_NAME = "cfm-proxy-exec.sh"
WINDOWS_NAME = "cfm-proxy-exec.ps1"


@pytest.fixture(scope="module")
def sh() -> str:
    return SH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ps1() -> str:
    return PS1.read_text(encoding="ascii")


def _code(text: str) -> str:
    """Executable lines only. Every rule here is also NAMED in a comment explaining the defect, and
    a scan that cannot tell the two apart reports the rationale as the violation."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


# ── the shipped sources exist and are what the classifier says they are ──────────────

def test_both_platform_executors_ship_in_the_payload():
    for rel in (LINUX_SRC, WINDOWS_SRC):
        assert (ROOT / rel).is_file(), f"{rel} is not in the payload"


def test_windows_iis_listener_identity_does_not_require_a_process_path():
    """A settled IIS front is owned by the protected ``System`` process on the real server.

    Windows exposes its process name but no executable path.  Claris nginx still requires a path
    beneath the verified FMS root; IIS attribution must therefore consume a separate name census.
    Folding both into the path-only census makes IIS permanently UNKNOWN whenever dormant nginx
    configuration is installed beside it.
    """
    code = _code(WINDOWS_EXECUTOR.read_text(encoding="ascii"))
    assert "if ($proc.ProcessName) { $ownerNames += $proc.ProcessName }" in code
    assert "if ($proc.Path) { $ownerPaths += $proc.Path }" in code
    assert "$fmsOwned = @($ownerPaths | Where-Object" in code
    assert "$iisOwned = @($ownerNames | Where-Object" in code
    assert "if ($proc -and $proc.Path)" not in code


def test_inactive_claris_validation_accepts_only_a_proven_bind_conflict():
    """With IIS active, dormant nginx necessarily loses 80/443 while ``nginx -t`` parses.

    The executor may accept that environmental failure only after an explicit syntax verdict, and
    an unrelated nginx error beside it must still make the validation fail.
    """
    code = _code(WINDOWS_EXECUTOR.read_text(encoding="ascii"))
    assert "$syntaxOk = [bool]($text -match 'syntax is ok')" in code
    assert "$bindConflict = [bool]($text -match $bindRe" in code
    assert "if ($item -match $bindRe" in code
    assert "$otherError = $true" in code
    assert "Ok = ($syntaxOk -and -not $otherError)" in code
    assert "Ok = ($code -eq 0)" not in code


def test_linux_executor_exposes_read_only_baseline_validation_and_its_exact_error():
    """Inactive Apache must be classified before publication, using the same whole-config check.

    The measured failure named an absent FileMaker ``server.pem``. Redirecting stderr to
    ``/dev/null`` converted that actionable fact into a generic installer refusal, so the executor
    now folds the validator output into its one-line JSON report.
    """
    source = (ROOT / LINUX_SRC).read_text(encoding="utf-8")
    code = _code(source)
    assert 'validate)' in code
    assert 'out="$(HTTP_ROOT="$FMS_ROOT/HTTPServer"' in code
    assert 'VALIDATION_DETAIL="$(printf' in code
    assert 'bounded 30 "$SYSTEM_APACHE"' in code
    assert '>/dev/null 2>&1' not in code


def test_linux_installer_surfaces_an_inactive_front_skip_as_a_warning():
    code = _code(SH.read_text(encoding="utf-8"))
    assert 'lc_report_inactive_proxy_skips' in code
    assert 'detail.startswith("inactive ")' in code
    assert 'lc_report_inactive_proxy_skips\n_lc_proxy_op=' in code


def test_windows_installer_does_not_call_a_mixed_proxy_rollback_unchanged():
    code = _code(PS1.read_text(encoding="ascii"))
    assert "recorded recovery may still contain independently completed work" in code
    assert "the installation is unchanged (rolled_back)" not in code


def test_the_source_destination_pairs_are_owned_by_the_private_runtime():
    """The focused package, not the application updater, owns both privileged executors."""
    packager = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")
    for rel in (LINUX_SRC, WINDOWS_SRC):
        assert rel in packager, f"{rel} is absent from the private runtime inventory"
    assert Path(LINUX_SRC).name == LINUX_NAME
    assert Path(WINDOWS_SRC).name == WINDOWS_NAME


# ── the resolver's requirement, executed ─────────────────────────────────────────────

@pytest.fixture
def unrooted(monkeypatch):
    """Double the POSIX OWNERSHIP answer, and nothing else.

    A test cannot create a root-owned file, and `proxy_transaction` already anticipates exactly this
    — `posix_executor_refusal` is a PURE predicate over a stat result precisely so the rule can be
    exercised without root. Here the rule is satisfied so that PATH RESOLUTION is what the test
    measures; the rule itself is measured directly in
    `test_the_POSIX_ownership_rule_refuses_a_non_root_or_writable_executor`.
    """
    from corpusfm.lifecycle import proxy_transaction as pt

    monkeypatch.setattr(pt, "posix_executor_refusal", lambda **kw: None)
    monkeypatch.setattr(pt, "posix_directory_refusal", lambda **kw: None)


def test_the_POSIX_ownership_rule_refuses_a_non_root_or_writable_executor():
    """The rule the fixture above satisfies, measured on its own terms — no doubles at all."""
    from corpusfm.lifecycle import proxy_transaction as pt

    assert pt.posix_executor_refusal(uid=0, mode=0o100755, executable=True, what="x") is None
    assert "root" in (pt.posix_executor_refusal(
        uid=501, mode=0o100755, executable=True, what="x") or "")
    assert "writable" in (pt.posix_executor_refusal(
        uid=0, mode=0o100775, executable=True, what="x") or "")
    assert "executable" in (pt.posix_executor_refusal(
        uid=0, mode=0o100644, executable=False, what="x") or "")


def test_the_resolver_requires_the_exact_path_the_installers_write(tmp_path, unrooted):
    """Executed against `executor_script` itself, so neither half can drift onto its own path."""
    from corpusfm.lifecycle import proxy_transaction as pt

    install_dir = tmp_path / "CORPUSfm"
    (install_dir / "bin").mkdir(parents=True)
    target = install_dir / "bin" / LINUX_NAME
    target.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    os.chmod(target, 0o755)

    resolved = pt.executor_script(is_windows=False, install_dir=install_dir)
    assert resolved == target


def test_the_resolver_requires_the_WINDOWS_path_the_windows_installer_writes(tmp_path):
    """The same rule, one name over — EXECUTED rather than read out of a docstring.

    Only the NTFS authority answer is doubled, at the injected `WindowsFileAuthorityApi` boundary
    the module already provides for this. Path selection is real.
    """
    from corpusfm.lifecycle import proxy_transaction as pt
    from corpusfm.lifecycle.protection import FileAuthority

    install_dir = tmp_path / "CORPUSfm"
    (install_dir / "bin").mkdir(parents=True)
    target = install_dir / "bin" / WINDOWS_NAME
    target.write_text("param()\n", encoding="ascii")

    class Api:
        def system_sid_text(self):
            return "S-1-5-18"

        def invoking_owner_sids(self):
            return ("S-1-5-32-544",)

        def authority_of_path(self, path):
            return FileAuthority(owner="S-1-5-32-544", trustees=("S-1-5-18",),
                                 protected=True, inherited=False)

    assert pt.executor_script(is_windows=True, install_dir=install_dir,
                              authority_api=Api()) == target
    # …and the resolver does NOT accept the Linux name on Windows.
    target.unlink()
    (install_dir / "bin" / LINUX_NAME).write_text("#!/bin/bash\n", encoding="ascii")
    with pytest.raises(pt.ExecutorUnavailable):
        pt.executor_script(is_windows=True, install_dir=install_dir, authority_api=Api())


def test_the_resolver_refuses_when_only_a_SOURCE_TREE_copy_exists(tmp_path, unrooted):
    """The exact fms-server condition: the payload has it, `<InstallDir>/bin` does not."""
    from corpusfm.lifecycle import proxy_transaction as pt

    install_dir = tmp_path / "CORPUSfm"
    (install_dir / "bin").mkdir(parents=True)
    src = install_dir / "src" / "installer" / "linux"
    src.mkdir(parents=True)
    (src / LINUX_NAME).write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    os.chmod(src / LINUX_NAME, 0o755)

    with pytest.raises(pt.ExecutorUnavailable):
        pt.executor_script(is_windows=False, install_dir=install_dir)


def test_the_resolver_names_no_fallback_at_all():
    """PATH, cwd, lib, the checkout: a published installation resolves none of them."""
    import inspect

    from corpusfm.lifecycle import proxy_transaction as pt

    # The DOCSTRING is stripped, not only the comments: it NAMES `parents[2]` while explaining why
    # that fallback was removed, and a scan that cannot tell prose from code reports the explanation
    # of a fix as the fix failing. (Made that mistake here first; it is the same class as the
    # guard-scans-its-own-rationale trap CLAUDE.md records twice.)
    src = inspect.getsource(pt.executor_script)
    body = _code(src[src.index('"""', src.index('"""') + 3) + 3:])
    for fallback in ("PATH", "getcwd", "which(", "shutil.which", "parents[2]", '"lib"', "'lib'"):
        assert fallback not in body, f"executor_script consults {fallback}"
    assert 'Path(install_dir) / "bin" / name' in body


# ── LINUX: the placement, executed ───────────────────────────────────────────────────

_SHIMS = {
    # `install -m MODE -o root -g root SRC DST` — GNU-only ownership flags. The MODE is honoured for
    # real (the group-writable control depends on it); the OWNERSHIP is accepted and not applied,
    # because a test cannot chown to root.
    "install": r"""#!/usr/bin/env python3
import os, shutil, sys
args, mode = [], 0o755
i = 1
while i < len(sys.argv):
    a = sys.argv[i]
    if a == "-m": mode = int(sys.argv[i + 1], 8); i += 2
    elif a in ("-o", "-g"): i += 2
    else: args.append(a); i += 1
shutil.copyfile(args[0], args[1]); os.chmod(args[1], mode)
""",
    # `stat -c '%U' PATH` — GNU format. The OWNER IS DOUBLED as root: see the note on `_linux_place`.
    "stat": r"""#!/usr/bin/env python3
import sys
fmt = sys.argv[2] if sys.argv[1] == "-c" else ""
print("root" if "%U" in fmt else "")
""",
    "sha256sum": r"""#!/usr/bin/env python3
import hashlib, sys
for path in sys.argv[1:]:
    print(hashlib.sha256(open(path, "rb").read()).hexdigest() + "  " + path)
""",
    # `find PATH -perm /022 -print -quit` — GNU's `/` "any of these bits" form. Real answer.
    "find": r"""#!/usr/bin/env python3
import os, stat, sys
path = sys.argv[1]
if os.stat(path).st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    print(path)
""",
}


@pytest.fixture
def coreutils(tmp_path_factory):
    """GNU `install`, `stat`, `sha256sum` and `find`, for a suite that runs on macOS.

    **Four OS primitives, doubled at their own boundary, and one of them weakens a check — said
    plainly rather than left for a reader to discover.** `stat -c '%U'` answers `root`
    unconditionally, because a test cannot create a root-owned file. So these tests measure staging,
    atomic replacement, the mode, the digest read-back and every refusal path; they do NOT measure
    the ownership assertion. That rule is measured on its own terms by
    `test_the_POSIX_ownership_rule_refuses_a_non_root_or_writable_executor`, and on a real box by the
    live gate.
    """
    shim_dir = tmp_path_factory.mktemp("coreutils")
    for name, body in _SHIMS.items():
        path = shim_dir / name
        path.write_text(body, encoding="utf-8")
        os.chmod(path, 0o755)
    return shim_dir


def _run_block(install_dir: Path, runtime_root: Path, shim_dir: Path, *, mutate=None) -> subprocess.CompletedProcess:
    """Run the installer's OWN placement lines against a temporary tree.

    Extracted from `install.sh` rather than retyped: a copy would prove a script written in this
    file, which is precisely what the fms-server defect argues against. Only `die`, `info`, `ok` and
    `$INSTALL_DIR` are supplied.
    """
    text = SH.read_text(encoding="utf-8")
    start = text.index('info "Proxy executor"')
    end = text.index("\n", text.index('ok "Proxy executor installed', start)) + 1
    block = text[start:end]
    if mutate is not None:
        block = mutate(block)
    harness = (
        "set -uo pipefail\n"
        f'export PATH="{shim_dir}:$PATH"\n'
        f'INSTALL_DIR="{install_dir}"\n'
        f'CFM_RUNTIME_ROOT="{runtime_root}"\n'
        'die() { echo "DIE: $*" >&2; exit 9; }\n'
        "info() { :; }\n"
        'ok() { echo "OK: $*"; }\n'
    )
    return subprocess.run(["bash", "-c", harness + block],
                          capture_output=True, text=True, timeout=60)


def _seed_payload(install_dir: Path) -> tuple[Path, Path]:
    runtime = install_dir.parent / "private-runtime"
    src = runtime / "installer" / "linux"
    src.mkdir(parents=True, exist_ok=True)
    shipped = src / LINUX_NAME
    shipped.write_bytes((ROOT / LINUX_SRC).read_bytes())
    return runtime, shipped


def test_LINUX_places_the_executor_at_the_exact_path_with_the_exact_bytes(tmp_path, coreutils,
                                                                          unrooted):
    from corpusfm.lifecycle import proxy_transaction as pt

    install_dir = tmp_path / "CORPUSfm"
    install_dir.mkdir()
    runtime, shipped = _seed_payload(install_dir)

    result = _run_block(install_dir, runtime, coreutils)
    assert result.returncode == 0, result.stderr

    placed = install_dir / "bin" / LINUX_NAME
    assert placed.is_file(), "the executor was not placed"
    assert placed.read_bytes() == shipped.read_bytes(), "the placed bytes are not the shipped bytes"
    assert hashlib.sha256(placed.read_bytes()).hexdigest() == \
        hashlib.sha256((ROOT / LINUX_SRC).read_bytes()).hexdigest()

    mode = stat.S_IMODE(os.stat(placed).st_mode)
    assert mode & stat.S_IXUSR, f"not executable ({mode:o})"
    assert not mode & (stat.S_IWGRP | stat.S_IWOTH), f"group/other writable ({mode:o})"
    assert not (install_dir / "bin" / (LINUX_NAME + ".tmp")).exists(), "the staging file survived"

    # And the RESOLVER accepts what was placed — the two halves meeting on one path.
    assert pt.executor_script(is_windows=False, install_dir=install_dir) == placed


def test_LINUX_a_MISSING_SOURCE_is_fatal(tmp_path, coreutils):
    install_dir = tmp_path / "CORPUSfm"
    runtime = install_dir.parent / "private-runtime"
    (runtime / "installer" / "linux").mkdir(parents=True)
    result = _run_block(install_dir, runtime, coreutils)
    assert result.returncode != 0, "a missing executor source did not stop the install"
    assert "not in this payload" in result.stderr
    assert not (install_dir / "bin" / LINUX_NAME).exists()


def test_LINUX_a_DIGEST_MISMATCH_is_fatal(tmp_path, coreutils):
    """The read-back is not decoration: corrupt the destination after the copy and it must refuse."""
    install_dir = tmp_path / "CORPUSfm"
    install_dir.mkdir()
    runtime, _ = _seed_payload(install_dir)
    result = _run_block(install_dir, runtime, coreutils, mutate=lambda b: b.replace(
        '_cfm_pe_src="$(sha256sum "$PROXY_EXEC_SRC"',
        'printf "corrupted" >> "$PROXY_EXEC_DST"\n_cfm_pe_src="$(sha256sum "$PROXY_EXEC_SRC"'))
    assert result.returncode != 0, "a corrupted destination was accepted"
    assert "does not match the shipped source" in result.stderr


def test_LINUX_a_GROUP_WRITABLE_destination_is_fatal(tmp_path, coreutils):
    install_dir = tmp_path / "CORPUSfm"
    install_dir.mkdir()
    runtime, _ = _seed_payload(install_dir)
    result = _run_block(install_dir, runtime, coreutils, mutate=lambda b: b.replace(
        "install -m 0755 -o root -g root", "install -m 0775"))
    assert result.returncode != 0, "a group-writable root-authority executor was accepted"
    assert "group- or world-writable" in result.stderr


# ── ordering, and independence from the updater ──────────────────────────────────────

def test_LINUX_installs_the_executor_BEFORE_phase_14(sh: str):
    body = _code(sh)
    placement = body.index('PROXY_EXEC_DST="$INSTALL_DIR/bin/cfm-proxy-exec.sh"')
    phase_14 = sh.index("PHASE 14 — Provider prerequisites")
    assert placement < phase_14, "the executor is placed after provider observation begins"


def test_WINDOWS_installs_the_executor_BEFORE_phase_14(ps1: str):
    placement = ps1.index("$ProxyExecDst = Join-Path $BinDir 'cfm-proxy-exec.ps1'")
    phase_14 = ps1.index("PHASE 14 - Provider prerequisites")
    assert placement < phase_14, "the executor is placed after provider observation begins"


def test_LINUX_executor_installation_is_OUTSIDE_the_updater_branch(sh: str):
    """A missing updater may disable updates; it may never suppress the executor.

    The updater branch is `if [[ -f "$UPDATER_SRC" ]] … else … fi`. The placement must sit after
    that `fi`, so it runs on both arms.
    """
    body = _code(sh)
    branch = body.index('if [[ -f "$UPDATER_SRC" ]]; then')
    closing = body.index('warn "corpusfm-update.sh not found', branch)
    closing = body.index("\nfi\n", closing)
    placement = body.index('PROXY_EXEC_SRC="$CFM_RUNTIME_ROOT/installer/linux/cfm-proxy-exec.sh"')
    assert placement > closing, (
        "the executor is installed inside the updater branch — a box with no updater source would "
        "silently get no proxy executor, which is the shape of the defect this replaces")


def test_WINDOWS_executor_installation_is_OUTSIDE_the_updater_branch(ps1: str):
    placement = ps1.index("$ProxyExecSrc = Join-Path $RuntimeRoot 'installer\\windows\\cfm-proxy-exec.ps1'")
    branch = ps1.index("if (-not (Test-Path $UpdaterSrc)) {")
    assert placement < branch, (
        "the executor is installed inside or after the updater branch; a missing updater must not "
        "suppress it")


def test_a_missing_UPDATER_does_not_suppress_LINUX_executor_installation(tmp_path, coreutils):
    """Executed: the placement block runs standalone, with no updater source anywhere."""
    install_dir = tmp_path / "CORPUSfm"
    install_dir.mkdir()
    runtime, _ = _seed_payload(install_dir)
    assert not (runtime / "installer" / "linux" / "corpusfm-update.sh").exists()
    result = _run_block(install_dir, runtime, coreutils)
    assert result.returncode == 0, result.stderr
    assert (install_dir / "bin" / LINUX_NAME).is_file()


# ── the placement is outside the checkout and outside service-writable state ─────────

def test_the_executor_is_installed_OUTSIDE_the_source_checkout_and_state_trees(sh: str, ps1: str):
    """`<InstallDir>/bin`, never `src/`, never the state, run, log or secrets directories."""
    assert '"$INSTALL_DIR/bin/cfm-proxy-exec.sh"' in sh
    assert "Join-Path $BinDir 'cfm-proxy-exec.ps1'" in ps1
    for forbidden in ("$INSTALL_DIR/src/installer/linux/cfm-proxy-exec.sh\"\nPROXY_EXEC_DST",
                      "/var/lib/corpusfm", "$CFM_STATE_DIR", "$CFM_RUN_DIR"):
        assert f'PROXY_EXEC_DST="{forbidden}' not in sh, f"the destination is {forbidden}"


def test_WINDOWS_protects_the_executor_and_grants_no_service_identity(ps1: str):
    body = _code(ps1)
    assert "icacls $ProxyExecDst /reset" in body, "the executor's ACL is never reset"
    assert "icacls $ProxyExecDst /inheritance:r /grant:r" in body, "no protected DACL is applied"
    grant = body[body.index("icacls $ProxyExecDst /inheritance:r"):]
    grant = grant[:grant.index("\n")]
    assert "$SystemSid" in grant and "$AdminsSid" in grant
    for identity in ("$WebSid", "$SchedSid", "NT SERVICE"):
        assert identity not in grant, f"the executor grants {identity} authority"
    assert "AreAccessRulesProtected" in body, "the protected DACL is never read back"


def test_WINDOWS_reads_back_the_digest(ps1: str):
    body = _code(ps1)
    assert "Get-FileHash -Algorithm SHA256 $ProxyExecSrc" in body
    assert "Get-FileHash -Algorithm SHA256 $ProxyExecDst" in body
    assert "$peSrcHash -ne $peDstHash" in body, "the two digests are never compared"


def test_WINDOWS_IIS_family_grants_and_verifies_its_pool_read_access():
    """IIS must read the isolated web.config through its own pool identity.

    On the clean IIS-only box, registering all four applications succeeded but every proxied
    request returned 500.19 / 0x80070005 because the protected installation root had no grant for
    ``IIS AppPool\\CORPUSfmProxy``. Keep the grant, effective readback, and rollback authority
    together in the lifecycle-owned executor.
    """
    body = _code(WINDOWS_EXECUTOR.read_text(encoding="utf-8"))
    assert '"IIS AppPool\\$($script:CfmPool)"' in body
    assert "Grant-CfmPoolReadAccess $a.Dir" in body
    assert "Set-Acl -LiteralPath $Path -AclObject $acl" in body
    assert 'if (-not $ok) { Fail "the read grant' in body
    assert "dir_sddl" in body
    assert "Set-CfmDirectorySddl -Path $a.dir -Sddl $a.dir_sddl" in body


def test_WINDOWS_stages_beside_the_destination_and_replaces_atomically(ps1: str):
    body = _code(ps1)
    assert "$ProxyExecTmp = $ProxyExecDst + '.tmp'" in body, "no staging beside the destination"
    assert "Move-Item -Force $ProxyExecTmp $ProxyExecDst" in body, "no atomic replacement"
    assert "Remove-Item -Force $ProxyExecTmp" in body, "a failed staging leaves its temporary behind"


# ── the omission itself, caught ──────────────────────────────────────────────────────

def test_REINTRODUCING_THE_OMISSION_IS_CAUGHT():
    """The defect was an ABSENCE, and an absence is what a guard is worst at noticing.

    It asserts the exact DESTINATION each installer writes, not merely that the name appears
    somewhere — the first version checked the latter and a mutation that redirected the destination
    to `bin/not-the-executor` SURVIVED it, because the source path line still spelled the name. The
    rule is that the installed path is the one `executor_script` resolves, so that is what is
    asserted, and it is derived from the resolver rather than retyped.
    """
    # <InstallDir>/bin/<name>, matched in each script. The tie to the RESOLVER is the test below,
    # which resolves the same path through `executor_script` itself.
    assert f'PROXY_EXEC_DST="$INSTALL_DIR/bin/{LINUX_NAME}"' in _code(SH.read_text(encoding="utf-8")), (
        f"install.sh does not install {LINUX_NAME} at $INSTALL_DIR/bin; the proxy provider refuses "
        "at phase 17 and no fresh install can complete")
    assert f"$ProxyExecDst = Join-Path $BinDir '{WINDOWS_NAME}'" in _code(PS1.read_text(encoding="ascii")), (
        f"install.ps1 does not install {WINDOWS_NAME} at $BinDir; the proxy provider refuses at "
        "phase 17 and no fresh install can complete")


def test_the_asserted_destination_IS_the_one_the_resolver_resolves(tmp_path, unrooted):
    """Ties the two statements above to the resolver, so neither can drift onto its own path."""
    from corpusfm.lifecycle import proxy_transaction as pt

    install_dir = tmp_path / "CORPUSfm"
    (install_dir / "bin").mkdir(parents=True)
    placed = install_dir / "bin" / LINUX_NAME
    placed.write_text("#!/bin/bash\n", encoding="utf-8")
    os.chmod(placed, 0o755)
    resolved = pt.executor_script(is_windows=False, install_dir=install_dir)
    assert resolved.parent.name == "bin" and resolved.name == LINUX_NAME
    assert str(resolved) == str(install_dir / "bin" / LINUX_NAME)
