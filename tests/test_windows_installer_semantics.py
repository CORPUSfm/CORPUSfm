"""Packet 1246-04-04 - the WINDOWS conversion: option surface, 21 phases, composition, definitions.

**Opens `installer/windows/install.ps1` and nothing else.** Never `install.sh`: that is 04-02's and
04-03's, and every existing installer test that could judge this conversion reads BOTH scripts in one
function (`test_installer_conformance.py`), so neither platform child can use them as a green bar.
That is what this module exists to supply.

**What it proves**, from parent 1246-04 section 4H: the ten supported option groups bind and each of
the fifteen retired spellings is a *binding error*; phases 1-21 in order; quiesce before the first
byte replacement; the provider order, generations, protocols and journal discards; definitions
installed and READ BACK before anything starts; phase 21 starting exactly that set on BOTH paths.
Plus the two Windows-specific guards - PowerShell parses, and the file is ASCII.

**Evidence class.** The parameter-binding and phase-21 controls EXECUTE PowerShell against real
`param()` binding and a real script body with stubbed service control - policy-through-doubles.
They prove what the script decides, never that a Windows box behaves. Real service registration,
DACLs, scheduled-task security, IIS and `appcmd` remain 1246-10 live gates.

**Candidate override.** `CFM_INSTALLER_PS1` points the suite at an off-tree candidate while it is
being built. Harness authority only: production never reads it, and the default is the repository
script.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from application_checkout import APPLICATION_ROOT

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO_PS1 = REPO_ROOT / "installer" / "windows" / "install.ps1"
_PWSH = __import__("shutil").which("pwsh") or __import__("shutil").which("powershell")
PS1_PATH = Path(os.environ.get("CFM_INSTALLER_PS1", REPO_PS1))
UPDATER_PS1 = REPO_ROOT / "installer" / "windows" / "corpusfm-update.ps1"

PWSH = shutil.which("pwsh") or shutil.which("powershell")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell available to execute controls")

SERVICES = ("corpusfm-web", "corpusfm-scheduler")
#: ADMIN IDENTITY FIRST (ruling 2026-08-08). The patch compartment authenticates to the FMS Admin
#: API with THIS installation's PKI identity, which the admin-identity provider publishes — so with
#: patch first, phase 15 could only ever report `api_required_unavailable`, which is what fms-server
#: measured. This list moved with `installer/linux/install.sh` and `install.ps1`; it did NOT move
#: when the installers did (commit 62309575 updated the parity suite and missed this one), so the
#: Windows half of the reorder went unguarded until the key-provisioning correction ran this suite.
PROVIDERS = ["admin_identity", "patch", "proxy", "storage"]
PROTOCOL_F = ["admin_identity", "proxy", "storage"]

#: The ten supported semantic option groups (section 4H.1). Nine are declared; `-Verbose` is the one
#: documented asymmetry - `[CmdletBinding()]` supplies it, and declaring it again is a binding error.
DECLARED = {
    "InstallDir", "PatchHostingDir", "FmsRoot",
    "ProxyPolicyAdd", "ProxyPolicyIgnore",
    "RepairStorageAccess", "ReplaceExistingInstall",
    "Silent", "Yes",
}
#: The fifteen Windows retirements (section 2.3), with no alias and no accept-and-ignore.
RETIRED = [
    "WebPort", "Prefix", "ConfigHome", "Site", "GitPat",
    "FmAdminUser", "FmAdminPass", "AdminUser", "AdminPass",
    "Ref", "NoMcp", "NoPull", "AllowDirty", "NoPki", "NoBootstrap",
]
RETIRED_SWITCHES = {"NoMcp", "NoPull", "AllowDirty", "NoPki", "NoBootstrap"}


@pytest.fixture(scope="module")
def ps1() -> str:
    return PS1_PATH.read_text(encoding="ascii")


@pytest.fixture(scope="module")
def phases(ps1: str) -> dict:
    """phase label -> its body, in file order.

    LETTERED SUB-PHASES ARE THEIR OWN BLOCKS (packet 1246-10-04). The pattern used to match only
    `PHASE <digits>`, so `PHASE 15B` and `PHASE 16B` were silently absorbed into the numeric phase
    above them — and every assertion about "phase 20" kept passing while the work it named had moved
    to 15B. A key is the int for a plain number and the string for a lettered one, so `phases[20]`
    still means phase 20 and `phases["15B"]` can be asked for by name.
    """
    marks = [(m.group(1), m.start(), m.end())
             for m in re.finditer(r"^# === PHASE (\d+[A-Z]?) - [^\n]*\n", ps1, re.M)]
    out: dict = {}
    for i, (label, _, end) in enumerate(marks):
        stop = marks[i + 1][1] if i + 1 < len(marks) else len(ps1)
        out[int(label) if label.isdigit() else label] = ps1[end:stop]
    return out


def code(body: str) -> str:
    """Executable lines only.

    A guard whose own rationale must name the thing it forbids has to exclude comments from its
    scan, or it reports its own explanation as the violation. This file's prose names every retired
    parameter and every forbidden primitive, deliberately.
    """
    out = []
    in_here = False
    for line in body.splitlines():
        if re.match(r"^\s*@['\"]\s*$", line):
            in_here = True
        elif re.match(r"^\s*['\"]@", line):
            in_here = False
            continue
        if in_here:
            continue
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def pos(ps1: str, needle: str) -> int:
    i = ps1.find(needle)
    assert i >= 0, f"not found: {needle!r}"
    return i


def param_block(ps1: str) -> str:
    m = re.search(r"(?m)^\[CmdletBinding\(\)\]\r?\nparam\(", ps1)
    assert m, "no advanced-function param block"
    return ps1[m.start():ps1.index("\n)\n", m.start()) + 3]


def help_block(ps1: str) -> str:
    return ps1[:ps1.index("#>")]


# ── the sequence itself ──────────────────────────────────────────────────────


def test_phases_are_exactly_one_to_twentyone_in_order(ps1):
    seen = [int(m.group(1)) for m in re.finditer(r"^# === PHASE (\d+) - ", ps1, re.M)]
    assert seen == list(range(1, 22)), f"phase markers: {seen}"


def test_every_phase_carries_executable_work(phases):
    """A phase marker with nothing under it is a contract that reads as implemented and is not."""
    empty = [n for n, body in phases.items() if not [l for l in code(body).splitlines() if l.strip()]]
    assert not empty, f"phases present but empty: {empty}"


# ── the option surface: ten groups, fifteen retirements ──────────────────────


def test_exactly_the_nine_target_parameters_are_declared(ps1):
    declared = set(re.findall(r"^\s*\[[\w\[\]]+\]\$(\w+)", param_block(ps1), re.M))
    assert declared == DECLARED, (
        f"missing: {sorted(DECLARED - declared)}   unexpected: {sorted(declared - DECLARED)}"
    )


def test_verbose_is_not_declared_and_is_supplied_by_cmdletbinding(ps1):
    """The one permitted divergence, and it is in the DECLARATION, not in the administrator's surface.

    `[CmdletBinding()]` already supplies `-Verbose`; a `[switch]$Verbose` beside it defines the same
    name twice, which PowerShell refuses. So the script must NOT declare it, must still document it,
    and must read it - through `$VerbosePreference`, the only thing there is to read.
    """
    assert "$Verbose" not in param_block(ps1), "-Verbose is declared beside [CmdletBinding()]"
    assert "[CmdletBinding()]" in ps1
    assert "$VerbosePreference" in code(ps1), "-Verbose is documented but never honoured"
    assert "-Verbose" in help_block(ps1), "the help text does not document -Verbose"


@needs_pwsh
@pytest.mark.parametrize("name", RETIRED)
def test_every_retired_parameter_is_a_binding_error(name, tmp_path, ps1):
    """EXECUTED. An undeclared parameter is Windows's native form of 'refused as unknown' - but the
    packet requires the executor to CONFIRM that behaviour rather than assume it, so this binds for
    real instead of reasoning about PowerShell."""
    probe = tmp_path / "probe.ps1"
    probe.write_text(param_block(ps1) + "\n'BOUND'\n")
    args = ["-" + name] if name in RETIRED_SWITCHES else ["-" + name, "x"]
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(probe)] + args,
                       capture_output=True, text=True)
    assert r.returncode != 0 and "BOUND" not in r.stdout, (
        f"-{name} still binds; it was retired with no alias and no accept-and-ignore"
    )


@needs_pwsh
@pytest.mark.parametrize("args", [
    ["-InstallDir", r"C:\X"], ["-PatchHostingDir", r"D:\H"], ["-FmsRoot", r"C:\F"],
    ["-ProxyPolicyAdd", "a,b"], ["-ProxyPolicyIgnore", "c"],
    ["-RepairStorageAccess"], ["-ReplaceExistingInstall"],
    ["-Silent"], ["-Yes"], ["-Verbose"], [],
], ids=lambda a: (a[0] if a else "<no options>"))
def test_every_supported_option_binds(args, tmp_path, ps1):
    """The OTHER half of the control above, and it is not decoration.

    A param block that refused everything would pass all fifteen refusal tests perfectly. This is
    what makes those fifteen mean something: the same probe, the same invocation, an accepting
    answer. `-Verbose` is here because it must bind despite being undeclared.
    """
    probe = tmp_path / "probe.ps1"
    probe.write_text(param_block(ps1) + "\n'BOUND'\n")
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(probe)] + args,
                       capture_output=True, text=True)
    assert "BOUND" in r.stdout, f"{args} did not bind: {r.stderr[:300]}"


@pytest.mark.parametrize("name", RETIRED)
def test_no_retired_parameter_survives_as_an_executable_consumer(name, ps1):
    """Retiring the declaration is half the job; a surviving `if ($NoMcp)` is the other half.

    Six names are deliberately EXEMPT because the retirement removed the PARAMETER, not the concept.
    `install.sh` keeps the identical variables for the identical reason: the loopback port, the URL
    prefix and the config home are implementation constants the blocks below still read; the IIS
    site is now DETECTED into a variable of the same name; the PAT is the internal embedded
    credential; and the FM/CORPUSfm administrator names are read from the approved environment.
    What is gone in every case is any way for argv to set them.
    """
    exempt = {"WebPort", "Prefix", "ConfigHome", "Site", "GitPat",
              "FmAdminUser", "FmAdminPass", "AdminUser", "AdminPass"}
    if name in exempt:
        pytest.skip(f"${name} survives as an internal value, not as a parameter (see docstring)")
    hits = [l for l in code(ps1).splitlines() if re.search(rf"\${name}\b", l)]
    assert not hits, f"${name} is retired but still read: {hits[:3]}"


@pytest.mark.parametrize("name", sorted(DECLARED))
def test_help_documents_every_supported_option(name, ps1):
    assert f"-{name}" in help_block(ps1), f"the help text does not document -{name}"


@pytest.mark.parametrize("name", RETIRED)
def test_help_identifies_every_retirement(name, ps1):
    """The help must NAME each retirement, so an administrator whose command line stops working
    learns why from the tool rather than from a diff."""
    retired_section = help_block(ps1)[help_block(ps1).index("RETIRED"):]
    assert f"-{name}" in retired_section, f"-{name} is retired but the help never says so"


def test_help_does_not_offer_a_retired_option(ps1):
    """A retirement named in the RETIRED paragraph is documentation; the same spelling in the
    OPTIONS paragraph is an offer, and an offer that no longer binds is worse than silence."""
    h = help_block(ps1)
    options = h[h.index("Options ("):h.index("RETIRED")]
    for name in RETIRED:
        assert f"-{name} " not in options and f"-{name}\n" not in options, (
            f"-{name} is still offered in the options list"
        )


def test_credentials_come_from_the_environment_not_argv(ps1):
    body = code(ps1)
    for var in ("FM_ADMIN_USER", "FM_ADMIN_PASS", "CORPUSFM_ADMIN_USER", "CORPUSFM_ADMIN_PASS"):
        assert f"$env:{var}" in body, f"{var} is not read from the environment"
    # And each is cleared from the environment the moment it is captured, so no child inherits it.
    for var in ("FM_ADMIN_PASS", "CORPUSFM_ADMIN_PASS"):
        assert re.search(rf"\$env:{var} = \$null", body), f"{var} is never cleared from the environment"


# ── quiesce, replacement, start ──────────────────────────────────────────────


def test_quiesce_precedes_the_first_replacement(ps1):
    """Phase 9 stops the services; phase 10 is the first phase that replaces an installed byte.

    Windows installs its interpreter IN PLACE - it has no staging directory - so this ordering is
    not a nicety here: a running service holds python.exe and its native extension DLLs mapped, and
    Windows refuses to overwrite a loaded binary."""
    assert pos(ps1, "# === PHASE 9 ") < pos(ps1, "# === PHASE 10 ")


def test_the_quiesce_phase_actually_stops_services(phases):
    body = code(phases[9])
    assert "Stop-Service" in body, "phase 9 stops nothing"
    for svc in ("$WebService", "$SchedService"):
        assert svc in body, f"phase 9 does not name {svc}"


def test_the_interpreter_replacement_no_longer_stops_services_itself(phases):
    """The characteristic defect this reorder removes: the stop used to live inside the
    interpreter-VERSION branch, so the same-version path replaced dependencies under a service that
    had been stopped only by a branch that was not taken."""
    assert "Stop-Service" not in code(phases[10]), (
        "phase 10 stops a service; quiesce belongs to phase 9 and nowhere else"
    )


def test_no_service_start_is_reachable_before_phase_21(ps1):
    pre = code(ps1[:pos(ps1, "# === PHASE 21 ")])
    for line in pre.splitlines():
        assert not re.search(r"\bStart-Service\b", line), f"a service start is reachable: {line.strip()}"
        assert not re.search(r"\bStart-ScheduledTask\b", line), f"a task start is reachable: {line.strip()}"
        assert not re.search(r"sc\.exe\s+start\b", line), f"a service start is reachable: {line.strip()}"
        assert not re.search(r"\$exe\s+start\b", line), f"a wrapper start is reachable: {line.strip()}"


def test_the_registration_helper_has_no_start_path_at_all(ps1):
    """Structural, not defaulted. The previous helper took a `$start` parameter defaulted to false;
    a capability that exists behind a default is a capability the next edit turns on by accident."""
    helper = ps1[pos(ps1, "function Register-CfmService"):]
    helper = helper[:helper.index("\n}\n")]
    assert "start" not in helper.replace("& $exe stop", "").replace("sc.exe stop", ""), (
        "Register-CfmService can start a service"
    )
    assert "$start" not in helper, "the start capability survives as a parameter"


def test_task_registration_is_not_task_activation(phases):
    """Registering a scheduled task does not run it - it has no trigger. The distinction matters
    because phase 13 installs a privileged task nine phases before anything may start."""
    body = code(phases[13])
    assert "Register-ScheduledTask" in body
    assert "Start-ScheduledTask" not in body


def test_phase_21_starts_exactly_what_phase_20_verified(phases):
    """Identity, not merely order: the set 21 starts is the set 20 wrote, read back and recorded."""
    assert "$VerifiedServices += $id" in code(phases["15B"]), "phase 15B never records what it verified"
    assert 'foreach ($id in $VerifiedServices)' in code(phases[21]), (
        "phase 21 does not iterate the verified set"
    )
    p20 = code(phases["15B"])
    assert p20.index("$VerifiedServices += $id") > p20.index("$VerifyPy $role"), (
        "a definition is recorded as verified before it is read back"
    )


def test_phase_21_has_no_fresh_versus_update_branch(phases):
    """An earlier design started services only on the fresh path 'because the layout cutover owns
    the restart'. The cutover is gone, and that branch left every update finished with the product
    stopped. Packet 1000-09 adds an update-only WARNING before the loop; the start itself must remain
    unconditional on both paths."""
    phase = code(phases[21])
    start = phase.index("foreach ($id in $VerifiedServices)")
    assert "$IsUpgrade" not in phase[start:], "service startup branches on fresh-versus-update"


# ── phase 21, EXECUTED - the presence of a start call is not the property ────


def phase21_body(ps1: str) -> str:
    s = ps1.index("# === PHASE 21 ")
    s = ps1.index("\n", s) + 1
    return ps1[s:ps1.index('Section "Summary"', s)]


PHASE21_HARNESS = """$SvcDir = '{d}'
$LogDir = '{d}'
$VerifiedServices = @('corpusfm-web','corpusfm-scheduler')
$IsUpgrade = ${upgrade}
function Ok($m) {{ }}
function Warn($m) {{ }}
function Die($m) {{ Write-Host ("die: " + $m); exit 1 }}
function Get-Service {{ param($Name, $ErrorAction) [pscustomobject]@{{ Status = '{status}' }} }}
function Lc-Cleanup {{ }}
{body}
"""


def run_phase21(ps1: str, tmp_path: Path, *, is_upgrade: bool, status: str = "Running",
                tag: str = "") -> tuple[int, list[str], str]:
    d = tmp_path / f"p21-{is_upgrade}-{status}{tag}"
    d.mkdir(parents=True, exist_ok=True)
    log = d / "calls.log"
    for sid in SERVICES:
        exe = d / f"{sid}.exe"
        exe.write_text(f'#!/bin/sh\necho "{sid} $1" >> "{log}"\n')
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    script = d / "p21.ps1"
    script.write_text(PHASE21_HARNESS.format(
        d=d, upgrade="true" if is_upgrade else "false", status=status, body=phase21_body(ps1)))
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(script)], capture_output=True, text=True)
    calls = log.read_text().splitlines() if log.exists() else []
    return r.returncode, calls, r.stdout + r.stderr


@needs_pwsh
@pytest.mark.parametrize("is_upgrade", [False, True], ids=["fresh", "update"])
def test_phase_21_starts_both_services_on_both_paths(ps1, tmp_path, is_upgrade):
    rc, calls, out = run_phase21(ps1, tmp_path, is_upgrade=is_upgrade)
    assert rc == 0, f"phase 21 body failed: {out}"
    for sid in SERVICES:
        assert f"{sid} start" in calls, f"{sid} NOT STARTED (is_upgrade={is_upgrade}): {calls}"


@needs_pwsh
@pytest.mark.parametrize("is_upgrade", [False, True], ids=["fresh", "update"])
def test_removing_the_start_fails_this_control_on_each_path(ps1, tmp_path, is_upgrade):
    """The control must die on the mutation it exists for, on EACH path independently. Without this
    a phase 21 that started nothing would pass the test above by never being exercised."""
    broken = ps1.replace("  & $exe start | Out-Null", "  & $exe noop | Out-Null", 1)
    assert broken != ps1, "the mutation matched nothing; this control proves nothing"
    _, calls, _ = run_phase21(broken, tmp_path, is_upgrade=is_upgrade, tag="-broken")
    assert not [c for c in calls if c.endswith(" start")], (
        "the mutation did not remove the start; this control proves nothing"
    )


@needs_pwsh
def test_a_service_that_does_not_reach_running_is_fatal(ps1, tmp_path):
    """Discriminating negative control. 'Started' is not 'starting was attempted': a definition that
    phase 20 called verified and that will not run is an install that must fail loudly, on the
    scheduler as much as on the web service."""
    rc, _, out = run_phase21(ps1, tmp_path, is_upgrade=False, status="Stopped")
    assert rc != 0, "a service that never reached Running did not fail the install"
    assert "failed to start after its definition was verified" in out


# ── phase 20: canonical definitions, installed and read back ─────────────────


def test_final_definitions_come_from_the_canonical_renderer(phases):
    # The renderer is CALLED from the two helper scripts this phase writes, so the names live inside
    # here-strings that `code()` deliberately strips. Scan the raw phase for what must be there and
    # the executable lines for what must not.
    raw, body = phases["15B"], code(phases["15B"])
    assert "winsw_service_spec" in raw and "render_winsw_service" in raw
    assert "service_definition_names_an_identity" in raw, "the identity read-back is gone"
    assert "<serviceaccount>" not in body, "a hand-written definition survives beside the canonical one"
    assert "<env name=" not in body, "a hand-written environment block survives beside the canonical one"


def test_the_definition_is_read_back_before_the_service_is_registered(phases):
    body = code(phases["15B"])
    assert body.index("$VerifyPy $role") < body.index("Register-CfmService $id"), (
        "a definition is registered before it is read back"
    )


def test_phase_20_has_no_tautological_interpreter_check_or_default_root_remedy(phases):
    """R8: renderer and installer receive the same root, so comparing their derived exe is tautology."""
    body = code(phases["15B"])
    assert "$canonicalExe" not in body
    assert "platform's default software root" not in body
    assert "Re-run without" not in body
    assert "$canonicalLogDir -ne $LogDir" in body, (
        "the installer's log directory is never checked against the published layout"
    )


def test_install_dir_is_normalized_before_any_windows_path_is_derived(ps1):
    normalize = ps1.index("$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)")
    assert normalize < ps1.index("$CurrentManifest = Join-Path $InstallDir")
    assert normalize < ps1.index("$PyDir    = Join-Path $InstallDir")
    block = ps1[normalize:ps1.index("# Series 1 is retired", normalize)]
    assert ".TrimEnd([char[]]@('\\','/'))" in block
    assert "$volumeRoot" in block, "a volume root would be collapsed to a drive-relative path"


def test_the_installer_config_home_is_the_published_windows_layout(ps1):
    """One literal, checked against the module that defines it. A ProgramData path that drifts from
    `windows_os_layout()` renders definitions naming directories the application does not use."""
    from corpusfm.lifecycle import os_layout

    # `OsLayout` builds `pathlib.Path`, so the SEPARATOR follows the machine running the test, not
    # the machine being described. Comparing rendered strings would pass on Windows and fail here for
    # a reason that has nothing to do with the property. Compare the parts.
    layout = os_layout.windows_os_layout()
    assert "$ConfigHome = 'C:\\ProgramData\\CORPUSfm'" in ps1
    def leaf(p):
        return (str(p).replace("\\", "/").rsplit("C:/ProgramData/CORPUSfm/", 1))
    for path, expected in ((layout.log_dir, "logs"), (layout.state_dir, "state"),
                           (layout.secrets_dir, "secrets"), (layout.run_dir, "run"),
                           (layout.config_dir, "config")):
        parts = leaf(path)
        assert len(parts) == 2 and parts[1] == expected, f"{path} is not <ConfigHome>/{expected}"
    for var, expected in (("$LogDir", "logs"), ("$FixedState", "state"),
                          ("$FixedSecrets", "secrets"), ("$FixedRun", "run"),
                          ("$FixedConfig", "config")):
        assert f"{var}" in ps1 and f"Join-Path $ConfigHome '{expected}'" in ps1, (
            f"{var} is not derived from $ConfigHome as '{expected}'")


def test_the_default_install_dir_is_the_canonical_windows_software_root(ps1):
    """`service_identity` derives the service command from `DEFAULT_WINDOWS_INSTALL_DIR`; the
    installed bundle has to be there or the verified definition names nothing real."""
    from corpusfm.lifecycle import os_layout

    m = re.search(r"\[string\]\$InstallDir = '([^']+)'", param_block(ps1))
    assert m, "no -InstallDir default"
    assert m.group(1) == os_layout.DEFAULT_WINDOWS_INSTALL_DIR


def test_the_canonical_windows_definitions_are_unprivileged_and_carry_no_global_token():
    """Both canonical definitions are unprivileged and carry no retired global credential."""
    from corpusfm.lifecycle import os_layout, service_identity as si

    layout = os_layout.windows_os_layout()
    for role, sid in (("web", "corpusfm-web"), ("scheduler", "corpusfm-scheduler")):
        # `install_dir` is an explicit authority now (correction E); this is the value install.ps1
        # supplies, i.e. what a stock installation chooses.
        spec = si.winsw_service_spec(role, layout, install_dir=si.DEFAULT_WINDOWS_INSTALL_DIR,
                                     service_id=sid, display_name="d",
                                     description="CORPUSfm " + role)
        text = si.render_winsw_service(spec)
        assert si.service_definition_names_an_identity(text)
        assert f"NT SERVICE\\{sid}" in text
        assert "LocalSystem" not in text
        # No PYTHONPATH, no HOME, no token: the allowlist is short and the interpreter's own `._pth`
        # carries the source path. Asserting it here keeps the installer honest about why it stopped
        # injecting them.
        assert "PYTHONPATH" not in text and "CORPUSFM_MCP_TOKEN" not in text


def test_both_stale_mcp_token_files_are_removed_before_service_registration(phases):
    body = code(phases["15B"])
    cleanup = body.index("foreach ($staleMcpEnv")
    assert "Join-Path $FixedSecrets '.mcp_env'" in body
    assert "Join-Path $InstallDir '.mcp_env'" in body
    assert "Remove-Item -LiteralPath $staleMcpEnv -Force -ErrorAction Stop" in body
    assert cleanup < body.index("Register-CfmService $id")


def test_neither_windows_definition_carries_a_global_mcp_token(phases):
    body = phases["15B"]
    assert "mcp_token_for_definition" not in body
    assert 'environment=common' in body
    assert "CORPUSFM_MCP_TOKEN" not in body

def test_the_service_identity_grants_wait_for_the_registration_that_creates_them(phases):
    """`NT SERVICE\\<id>` has no SID until the service is registered, so the grants cannot precede
    it - and the services cannot start before the grants, because ConfigHome is locked to
    SYSTEM+Administrators and they are neither. Register-all, grant, then start at 21."""
    body = code(phases["15B"])
    assert body.index("Register-CfmService $id") < body.index("$WebSid   = 'NT SERVICE\\'")


def test_the_secrets_and_outcome_directories_are_never_service_writable(phases):
    r"""A parent a service can create, delete and rename entries in defeats any per-file protection
    inside it.

    **Re-expressed 2026-08-09.** Phase 8 still creates both under the ConfigHome tree lock. The
    OUTCOME directory keeps its single `/grant:r` naming all four principals; the SECRETS directory
    is now the provider's, applied and read back by the final `provision-keys` — because a
    `/reset` then `/grant` here removed the caller's own authority before the grant could run and
    locked phase 20 out of the directory entirely. Read-and-traverse for the services in both
    cases, never Modify: Modify on a directory carries create, delete and rename.
    """
    p8, p20 = code(phases[8]), code(phases[20])
    for target in ("$FixedSecrets", "$OutcomeDir"):
        assert target in p8, f"{target} is not created under the phase 8 tree lock"

    assert "provision-keys-final" in p20, "the secrets directory has no final authority"
    from corpusfm.lifecycle.protection import DIRECTORY_AUTHORITY, DIRECTORY_TRAVERSE_READ
    assert DIRECTORY_TRAVERSE_READ & DIRECTORY_AUTHORITY == 0

    outcome = [ln for ln in p20.splitlines() if "$OutcomeDir /inheritance:r" in ln]
    assert outcome, "the outcome directory lost its protective DACL"
    grants = p20[p20.index("$OutcomeDir /inheritance:r"):][:400]
    assert "(RX)" in grants and "(M)" not in grants.split("\n")[0]

def test_foundation_publishes_at_phase_11(phases):
    body = code(phases[11])
    assert "'composition','foundation'" in body
    assert '"$CfmGeneration" -ne "1"' in body, "generation 1 is not asserted"


def test_phase_10_provisions_and_reads_back_the_installed_uninstaller(phases):
    body = code(phases[10])
    assert "$UninstallerPath = Join-Path $InstallDir 'uninstall.ps1'" in body
    assert "$UninstallerLib = Join-Path $InstallDir '_cfm_lib.ps1'" in body
    assert "Copy-Item -LiteralPath $UninstallerSource -Destination $UninstallerPath -Force" in body
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerPath" in body
    assert "Get-FileHash -Algorithm SHA256 -LiteralPath $UninstallerLib" in body


def test_phase_11_records_and_reads_back_the_installed_uninstaller(phases):
    body = code(phases[11])
    assert re.search(r"^\s*uninstaller_path\s*=\s*\$UninstallerPath$", body, re.M)
    assert "Lc-Field $out 'uninstaller_path'" in body
    assert "foundation did not read back the canonical installed uninstaller" in body


def test_the_foundation_request_carries_exactly_the_shipped_keys(phases):
    """The schema is exhaustive: no web facts, no path fields, no expected generation."""
    from corpusfm.lifecycle import cli

    body = phases[11]
    for key in cli._CO_REQUEST_KEYS["foundation"]:
        assert re.search(rf"^\s*{key}\s*=", body, re.M), f"foundation request omits {key}"
    for forbidden in ("web_prefix", "port", "secrets_dir", "config_dir"):
        assert not re.search(rf"^\s*{forbidden}\s*=", body, re.M), (
            f"foundation request carries {forbidden}"
        )


def test_the_commit_request_carries_exactly_the_shipped_keys(ps1):
    from corpusfm.lifecycle import cli

    helper = ps1[pos(ps1, "function Lc-CommitProvider"):]
    helper = helper[:helper.index("\n}\n")]
    for key in cli._CO_REQUEST_KEYS["commit-provider"]:
        assert re.search(rf"^\s*{key}\s*=", helper, re.M), f"commit request omits {key}"


@pytest.mark.parametrize("provider,phase", list(zip(PROVIDERS, (15, 16, 17, 18))))
def test_each_provider_commits_in_its_ruled_phase(provider, phase, phases):
    """15 admin_identity, 16 patch, 17 proxy, 18 storage — the dependency order, not a preference."""
    assert f"Lc-CommitProvider '{provider}'" in code(phases[phase])


def test_the_provider_order_is_admin_patch_proxy_storage(ps1):
    order = re.findall(r"Lc-CommitProvider '(\w+)'", code(ps1))
    assert order == PROVIDERS, f"provider order: {order}"


def test_generations_advance_one_per_provider(ps1):
    """foundation 1, then 2, 3, 4, 5 - enforced by the helper, which refuses anything else."""
    helper = ps1[pos(ps1, "function Lc-CommitProvider"):]
    helper = helper[:helper.index("\n}\n")]
    assert "[int]$inspectedGeneration + 1" in helper, "the commit does not require generation+1"
    assert "refusing to continue" in helper, "a wrong generation does not stop the run"


def test_patch_follows_protocol_P_and_has_no_finalize(phases):
    """Its `apply` resolves its own journal, so there is no finalize verb to call. Phase 16 now."""
    body = code(phases[16])
    assert "'patch-compartment','apply'" in body
    assert "finalize" not in body, "Protocol P has no finalize; calling one is a contract error"


@pytest.mark.parametrize("provider,phase", list(zip(PROTOCOL_F, (15, 17, 18))))
def test_each_protocol_F_provider_finalizes(provider, phase, phases):
    body = code(phases[phase])
    assert re.search(r"Lc-Run \"\w+ finalize\"", body), f"{provider} never finalizes"
    assert re.search(r"'\w[\w-]*','finalize','--request'", body), f"{provider} finalize is not a verb call"


def test_every_provider_journal_is_discarded_at_its_boundary(ps1):
    """Required, not tidy-up: storage answers foreign_open on the PRESENCE of any journal record, so
    a leftover one stops the NEXT provider before it starts."""
    helper = ps1[pos(ps1, "# Commit one provider"):pos(ps1, "function Lc-CommitProvider")]
    assert "discard" in helper.lower(), "the discard requirement is not stated where it is performed"


def test_storage_composition_ready_predicate_is_exact(phases):
    body = phases[18]
    assert "first_administrator_owed" in body, "storage's composable success predicate is not named"
    assert "incomplete_safe" in body


# ── failure, recovery and the result vocabulary ──────────────────────────────


def test_prior_operation_routing_ends_the_invocation(phases):
    """RE-EXPRESSED (packet 1246-04-04, correction C).

    The rule is unchanged - an operation in flight OWNS the box, and cleanup is never combined with
    new work. What was wrong is what the rule was tested against: this asserted the string
    `requires_recovery`, which is exactly the key `status --json` DOES NOT EMIT. The guard passed
    while the installer's match found nothing on every box - a spelling assertion reporting the
    defect as compliance.
    """
    body = code(phases[3])
    assert "requires_recovery" not in body, (
        "the dead match is back; `requires_recovery()` is an internal Journal predicate and "
        "`status --json` has never emitted a key by that name"
    )
    for state in ("open", "checkpointed", "needs_recovery", "resolved"):
        assert state in body, f"the routing does not answer for journal state {state!r}"
    assert "Die" in body, "routing does not end the invocation"


def test_the_routing_reads_only_fields_STATUS_JSON_ACTUALLY_EMITS(phases):
    """Every field phase 3 reads must be one the shipped emitter produces - measured from
    `cli._status` / `cli._journal_state`, not from a list written here."""
    import inspect

    from corpusfm.lifecycle import cli as _cli

    source = inspect.getsource(_cli._status) + inspect.getsource(_cli._journal_state)
    emitted = set(re.findall(r'\b(?:report|extra)\["(\w+)"\]', source))
    emitted |= set(re.findall(r'"(\w+)":', source))
    read = set(re.findall(r"Lc-Field \$lcState '(\w+)'", phases[3]))
    assert read, "phase 3 reads no status field at all"
    assert read <= emitted, f"phase 3 reads fields nothing emits: {sorted(read - emitted)}"


def test_the_recovery_route_NAMES_THE_SHIPPED_PROTOCOL_for_each_subsystem(phases):
    """Recovery routing is delegated to the shared application disposition boundary."""
    body = code(phases[3])
    assert "Lc-PreflightDisposition" in body
    assert "LcRecoveryCommand" in body
    assert "Lc-DiscardProvider" in body, "a resolved-but-undischarged record is not routed"


def test_every_lifecycle_exit_code_is_handled(ps1):
    from corpusfm.lifecycle import cli

    disp = ps1[pos(ps1, "function Lc-Dispatch"):]
    disp = disp[:disp.index("\n}\n")]
    for rc in sorted(set(cli._CO_EXIT_CODES.values()) | {cli._CO_BAD_REQUEST}):
        assert re.search(rf"^\s*{rc} \{{", disp, re.M), f"exit {rc} has no branch"
    assert re.search(r"^\s*default \{", disp, re.M), "an unrecognised status is unhandled"


def test_a_refused_request_is_reported_as_an_installer_defect(ps1):
    """Exit 4 means the installer built a request the build rejects - never the box's fault."""
    disp = ps1[pos(ps1, "function Lc-Dispatch"):]
    assert "installer defect" in disp[:disp.index("\n}\n")]


def test_incomplete_safe_leaves_the_box_stopped(ps1):
    disp = ps1[pos(ps1, "function Lc-Dispatch"):]
    disp = disp[:disp.index("\n}\n")]
    assert "incomplete_safe" in disp
    assert "stay STOPPED" in disp, (
        "an incomplete_safe result does not tell the administrator the box is stopped"
    )


def test_no_platform_invents_a_result_word_or_an_exit_code(ps1):
    """Section 4H.8: the six-word vocabulary and the exit map are the shipped contract."""
    from corpusfm.lifecycle import cli

    disp = ps1[pos(ps1, "function Lc-Dispatch"):]
    disp = disp[:disp.index("\n}\n")]
    words = set(re.findall(r"\(([a-z_]+)\)", disp))
    assert words <= set(cli._CO_EXIT_CODES) | {"failed_before_change"}, f"invented words: {words}"


# ── secret fencing ───────────────────────────────────────────────────────────


#: The keys a SHIPPED schema legitimately spells with a word this test otherwise bans, and what each
#: one is. Named individually — an unnamed exception would be a hole rather than a rule. Kept
#: identical in meaning to the Linux twin in `test_linux_installer_orchestration.py`.
_ALLOWED_FLAGGED_KEYS = {
    # A credential TRANSPORT, never a value: `absent` (proxy and admin-identity only), `prompt`,
    # `stdin` or `fd:<n>`, refused by the shipped parser otherwise.
    "credential_input": ("absent", "prompt", "stdin"),
    "admin_credential_input": ("prompt", "stdin"),
    "credential_transport": ("none", "prompt", "stdin", "$transport"),
    # A DIRECTORY. The path a provider reads its own material FROM is not the material.
    "secrets_dir": None,
}

_FLAGGED_WORDS = ("password", "token", "secret", "credential", "pem")


def test_no_request_object_names_a_credential(ps1):
    """A request may name an installation and an operation. It may never name a secret.

    RE-EXPRESSED (packet 1246-04-04, correction R5). This banned five substrings outright — and the
    shipped schemas THEMSELVES spell `credential_input`, `admin_credential_input` and `secrets_dir`,
    so once the requests were corrected to match the production parsers the ban forbade conformance
    with the contract it was protecting. Banning the WORD had stopped being the same thing as
    banning the SECRET.
    """
    for m in re.finditer(r"Lc-Request [^\n]*\(Lc-Json \(\[ordered\]@\{(.*?)\}\)\)", ps1, re.S):
        schema = m.group(1)
        for name, value in re.findall(r"^\s*(\w+)\s*=\s*(.+?)\s*$", schema, re.M):
            if not any(word in name.lower() for word in _FLAGGED_WORDS):
                continue
            assert name in _ALLOWED_FLAGGED_KEYS, (
                f"request schema names {name!r}, which no shipped schema defines"
            )
            allowed = _ALLOWED_FLAGGED_KEYS[name]
            if allowed is None:
                continue
            literal = value.strip().strip("'")
            assert literal in allowed or literal.startswith("fd:"), (
                f"{name} is given {value!r}, which is not a transport token"
            )
        # The whole ASSIGNMENT goes, not just the key name: `secrets_dir = $CfmSecretsDir` carries
        # the flagged word on both sides, and a variable named after the directory it holds is the
        # same legitimate thing the key is.
        residue = "\n".join(
            line for line in schema.splitlines()
            if not any(re.match(rf"^\s*{name}\s*=", line) for name in _ALLOWED_FLAGGED_KEYS))
        for word in _FLAGGED_WORDS:
            assert word not in residue.lower(), (
                f"request schema mentions {word!r} outside a shipped key: {schema[:120]}"
            )


def test_no_credential_variable_is_interpolated_into_a_request(ps1):
    """RE-EXPRESSED with the same correction. `$AdminUser` left this list because it is a NAME, not
    a secret: `storage create-first-admin` requires `admin_username`, and a schema that could not
    carry the username would be unusable. Every variable that holds a VALUE stays banned."""
    for m in re.finditer(r"Lc-Request [^\n]*\(Lc-Json \(\[ordered\]@\{(.*?)\}\)\)", ps1, re.S):
        blob = m.group(1)
        assert not re.search(r"\$(FmAdminPass|AdminPass|GitPat|Tok)\b", blob), (
            f"a credential reaches a request: {blob[:120]}"
        )


def test_request_files_are_administrator_owned_and_removed(ps1):
    helper = ps1[pos(ps1, "function Lc-Request"):]
    helper = helper[:helper.index("\n}\n")]
    assert "/inheritance:r /grant:r" in helper and "$script:SystemSid" in helper, (
        "the request directory is not protected"
    )
    assert "PowerShell.Exiting" in ps1, "request files outlive the invocation"
    assert "Lc-Cleanup" in code(phases_of(ps1)[21]), "phase 21 does not remove the request directory"


def phases_of(ps1: str) -> dict:
    marks = [(m.group(1), m.start(), m.end())
             for m in re.finditer(r"^# === PHASE (\d+[A-Z]?) - [^\n]*\n", ps1, re.M)]
    out: dict = {}
    for i, (label, _, end) in enumerate(marks):
        stop = marks[i + 1][1] if i + 1 < len(marks) else len(ps1)
        out[int(label) if label.isdigit() else label] = ps1[end:stop]
    return out


def test_the_bearer_token_is_never_printed(ps1):
    """Developer ruling 2026-07-29. `install.sh` had already refused to print it; Windows was the
    divergence, not the policy. The ENDPOINT stays - consequence 5 of the Unknowable-Install
    Principle requires the MCP address to exist where no working connection is needed."""
    # THE ARGUMENT, NOT THE LINE. `if ($Tok) { Info "..." }` tests whether a token was found and
    # prints a sentence that contains none of it; scanning the whole line reported that as a leak.
    # What must never appear is the VALUE inside what an output cmdlet is given.
    for line in code(ps1).splitlines():
        for match in re.finditer(r"\b(Write-Host|Ok|Info|Warn)\b(.*)$", line):
            assert "$Tok" not in match.group(2), \
                f"the bearer token reaches operator output: {line.strip()}"
    assert "/mcp/" in ps1, "the MCP endpoint is no longer stated in the installer output"


# ── the cutover stays gone ───────────────────────────────────────────────────


def test_no_cutover_module_or_invocation(ps1):
    for line in code(ps1).splitlines():
        assert "cutover_cli" not in line and "lifecycle.cutover" not in line, (
            f"the retired cutover survives: {line.strip()}"
        )


def test_no_phase_defers_work_to_a_cutover(ps1):
    """The prose mattered as much as the call: 'the layout cutover starts them after publication'
    was what justified never starting anything."""
    # This module's own docstring and the script's own history notes name the retired mechanism, so
    # the scan reads EXECUTABLE lines only. A guard whose rationale must name what it forbids has to
    # exclude comments, or it reports its own explanation as the violation.
    assert "layout cutover" not in code(ps1).lower(), "a phase still hands work to the retired cutover"


# ── the privileged updater ───────────────────────────────────────────────────


def test_the_updater_is_rendered_by_the_SHIPPED_RENDERER_and_not_by_this_script(phases):
    """RE-EXPRESSED (packet 1246-04-04, correction F item 8).

    The rule this defends is unchanged: every `@@...@@` the shipped updater carries must be filled,
    or the installed artifact runs a placeholder as a literal path AS SYSTEM. What changed is who
    fills them. This test used to assert nine `.Replace('@@X@@', ...)` calls - i.e. that the
    installer held a SECOND opinion about nine paths the installation record already states. It did,
    and the two opinions diverged: `update_boundary` derived the Windows interpreter as
    `venv\\Scripts\\python.exe`, which this installer never creates.

    So the assertion is now that the installer holds NO opinion: it calls
    `render_windows_updater()`, which takes nothing, derives all nine from the published record and
    refuses on any it did not fill.
    """
    body = code(phases[13])
    assert "render_windows_updater" in body, "the shipped renderer is not called"
    assert not re.search(r"Replace\('@@", body), "the installer still hand-renders placeholders"
    assert "-match '@@'" in body, "the unrendered-placeholder guard is gone"

    # …and the renderer really does account for every placeholder the shipped template carries.
    from corpusfm.lifecycle import update_boundary as _ub

    shipped = {f"@@{n}@@" for n in re.findall(r"@@(\w+)@@", UPDATER_PS1.read_text(encoding="ascii"))}
    assert shipped <= set(_ub.WINDOWS_PLACEHOLDERS), (
        f"the renderer knows nothing about {sorted(shipped - set(_ub.WINDOWS_PLACEHOLDERS))}"
    )


def test_the_administrator_owned_library_is_installed_before_the_updater_is_rendered(phases):
    """The updater loads its tree inspector and its outcome publisher from OUTSIDE the checkout -
    loading the judge from the tree being judged is how a modified helper in a modified checkout
    declares itself clean. `outcome_publisher` resolves its library as `<its own dir>\\..\\lib`, so
    bin/ and lib/ must be siblings under the install directory and neither may be the checkout."""
    body = code(phases[13])
    assert body.index("$LibPkg") < body.index("render_windows_updater")
    assert "$LibDir = Join-Path $InstallDir 'lib'" not in body, "lib is re-derived inside the phase"
    assert "corpusfm\\lifecycle" in body or "'lifecycle'" in body, (
        "the installed library is never checked for corpusfm/lifecycle"
    )
    for name in ("$Helper", "$Publisher"):
        assert re.search(rf"Copy-Item -Force [^\n]*\{re.escape(name)}", body) or \
               re.search(rf"{re.escape(name)}\s*=", body), f"{name} is never installed"


def test_the_updater_library_and_entry_points_live_outside_the_checkout(phases):
    body = code(phases[13])
    assert "$LibDir" in body and "$BinDir" in body
    # RE-EXPRESSED with the hand-rendering it used to read. The rule is the same one and it is now
    # structural rather than textual: the renderer derives HELPER / PUBLISHER / LIB_DIR from
    # `install_dir` through `bin/` and `lib/`, and its own containment check refuses anything that
    # is not beneath the install directory. There is no expression here that could name $Src.
    from corpusfm.lifecycle import update_boundary as _ub

    assert _ub.HELPER_DIRNAME != _ub.CHECKOUT_DIRNAME
    assert _ub.LIBRARY_DIRNAME != _ub.CHECKOUT_DIRNAME
    for helper in (_ub.helper_path, _ub.publisher_path, _ub.library_path):
        assert not str(helper(r"C:\CORPUSfm")).startswith(f"C:\\CORPUSfm\\{_ub.CHECKOUT_DIRNAME}\\")


def test_the_updater_script_is_not_writable_by_a_service_identity(phases):
    """RE-EXPRESSED (packet 1000-10, R10).

    This asserted `icacls $UpdaterDst /inheritance:r /grant:r` - the phase-13 grant applied directly
    to the final path. Phase 13 now grants the DACL on the STAGED render and publishes it by rename,
    so that spelling is gone while the rule is unchanged and stronger: the file the elevated task
    executes is protected BEFORE it ever appears at that path. The staged variable is read out of
    the publication statement rather than retyped, so a rename of the variable cannot silently
    retire the assertion.
    """
    p13, p20 = code(phases[13]), code(phases[20])
    staged = re.search(r"Move-Item -Force (\$\w+) \$UpdaterDst", p13)
    assert staged, "the updater is not published from a staged path"
    stage = staged.group(1)
    assert f"icacls {stage} /inheritance:r /grant:r" in p13, (
        "the staged updater receives no protective DACL")
    # The UPDATER's own two statements, not the first `/inheritance:r` in the phase: the library,
    # the entry-point directories and the proxy executor are all granted earlier, and the proxy is
    # published by its own `Move-Item` above - a positional check on the bare strings would compare
    # two unrelated statements and pass whatever this block did.
    assert p13.index(f"icacls {stage} /inheritance:r") < \
        p13.index(f"Move-Item -Force {stage} $UpdaterDst"), (
        "the DACL is applied after publication; the executed path is unprotected until it lands")
    assert "$WebSid" not in p13, "the web identity is granted before its SID exists"
    # The grant is issued through a loop over the three administrator-owned paths, so the line that
    # NAMES $UpdaterDst is the loop header and the line that grants is its body. Read the loop.
    m = re.search(r"foreach \(\$p in @\([^)]*\$UpdaterDst[^)]*\)\) \{(.*?)\n\}", p20, re.S)
    assert m, "the updater script receives no service grant at phase 20"
    grants = [l for l in m.group(1).splitlines() if "Grant-OrDie" in l]
    assert grants and all("(RX)" in l for l in grants), (
        f"the updater script is granted more than read+execute: {grants}"
    )
    assert not [l for l in grants if "$SchedSid" in l], "the scheduler was granted the update path"


# ── PowerShell integrity ─────────────────────────────────────────────────────


@needs_pwsh
def test_the_script_parses(tmp_path):
    """`bash -n`'s equivalent. A syntax error in PowerShell is not caught by reading, and this file
    is never executed by the suite - so without this the module could be green over a script that
    cannot run at all."""
    probe = tmp_path / "parse.ps1"
    probe.write_text(
        "$e = $null; $t = $null\n"
        f"[System.Management.Automation.Language.Parser]::ParseFile('{PS1_PATH}', [ref]$t, [ref]$e) | Out-Null\n"
        "if ($e) { $e | ForEach-Object { '{0}:{1} {2}' -f $_.Extent.StartLineNumber, "
        "$_.Extent.StartColumnNumber, $_.Message }; exit 1 }\n'PARSE OK'\n"
    )
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(probe)], capture_output=True, text=True)
    assert r.returncode == 0, f"install.ps1 does not parse:\n{r.stdout}{r.stderr}"


def test_the_script_is_ascii():
    """Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI, so one em dash, arrow or box-drawing
    character corrupts the parser. A non-ASCII byte in this file has failed the suite before."""
    raw = PS1_PATH.read_bytes()
    bad = [(i, b) for i, b in enumerate(raw) if b > 0x7F]
    assert not bad, f"non-ASCII byte {bad[0][1]:#x} at offset {bad[0][0]}"


def test_the_lifecycle_helpers_are_defined_before_any_phase_uses_them(ps1):
    """The reorder's characteristic failure is a block moved ahead of what produces what it reads."""
    for helper in ("function Lc-Dispatch", "function Lc-Request", "function Lc-Run",
                   "function Lc-CommitProvider", "function Register-CfmService"):
        assert pos(ps1, helper) < pos(ps1, "# === PHASE 1 "), f"{helper} is defined too late"


def test_error_action_preference_is_stop(ps1):
    assert "$ErrorActionPreference = 'Stop'" in ps1


def test_no_variable_is_read_before_it_is_assigned(ps1):
    """PowerShell has no `set -u`: an unassigned variable is $null, and $null is falsy, so a block
    that moved ahead of its producer takes the wrong branch in silence. These are the values the
    reorder actually moved."""
    for name, first_use in (
        ("$InstallationId", "Lc-CommitProvider"),
        ("$FmsBin", "# === PHASE 4 "),
        ("$Site", "# === PHASE 2 "),
        ("$VerifiedServices", "# === PHASE 21 "),
        ("$UpdaterTask", "# === PHASE 20 "),
    ):
        assign = re.search(rf"(?m)^\s*{re.escape(name)}\s*=", ps1)
        assert assign, f"{name} is never assigned"
        assert assign.start() < pos(ps1, first_use), f"{name} is read at {first_use} before assignment"


@needs_pwsh
def test_every_command_the_script_invokes_actually_resolves(tmp_path):
    r"""The defect this exists for, found by a blind reviewer and not by this module.

    A rename left one call site spelled `Lc-JsonField` while the function was defined as `Lc-Field`.
    PowerShell parses that perfectly - an undefined function is a RUNTIME error - so
    `test_the_script_parses` was green, and `…helpers_are_defined_before_any_phase_uses_them` checks
    definition POSITION, not that the name resolves at all. Under `$ErrorActionPreference = 'Stop'`
    the script would have terminated at phase 15 with a bare `CommandNotFoundException`: no `Die`, no
    transcript line, no guidance, after the box was fully mutated.

    So: walk the AST, and require every invoked command to be either defined in this file or
    resolvable in this PowerShell. The Windows-only cmdlets that cannot resolve on a POSIX host are
    listed by exact spelling - a visible allowlist, so widening it is an edit somebody can see.
    """
    windows_only = sorted({
        "Get-CimInstance", "Get-Service", "Stop-Service", "Get-NetTCPConnection", "Get-Website",
        "Get-WebApplication", "New-WebApplication", "New-WebAppPool", "Get-WebConfiguration",
        "Get-WebConfigurationProperty", "Set-WebConfigurationProperty", "Register-ScheduledTask",
        "Unregister-ScheduledTask", "New-ScheduledTaskAction", "New-ScheduledTaskPrincipal",
        "New-ScheduledTaskSettingsSet", "Expand-Archive", "Get-FileHash", "Get-Acl",
        # dot-sourced from the shipped libraries, not from this file
        "Die", "Ok", "Warn", "Info", "Hello", "Section", "Cfm-Run", "Cfm-Confirm", "Cfm-LogInit",
        "Cfm-Logline", "Lock-FileAcl", "Lock-DirTreeAcl",
        # native Windows executables, not functions
        "icacls", "sc.exe",
    })
    probe = tmp_path / "resolve.ps1"
    probe.write_text(
        "$e=$null;$t=$null\n"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{PS1_PATH}',[ref]$t,[ref]$e)\n"
        "$defined=@($ast.FindAll({param($n) $n -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst]},$true) | "
        "ForEach-Object { $_.Name })\n"
        "$called=@($ast.FindAll({param($n) $n -is "
        "[System.Management.Automation.Language.CommandAst]},$true) | "
        "ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })\n"
        "$called | Sort-Object -Unique | ForEach-Object {\n"
        "  if ($defined -contains $_) { return }\n"
        "  if (Get-Command $_ -ErrorAction SilentlyContinue) { return }\n"
        "  $_\n"
        "}\n"
    )
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(probe)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    unresolved = [n.strip() for n in r.stdout.splitlines() if n.strip()]
    leftover = sorted(set(unresolved) - set(windows_only))
    assert not leftover, f"the script calls commands that resolve nowhere: {leftover}"


@needs_pwsh
def test_that_control_would_have_caught_the_rename(tmp_path):
    """Negative control. Without it the test above is a claim, not evidence."""
    broken = tmp_path / "broken.ps1"
    broken.write_text(PS1_PATH.read_text(encoding="ascii").replace("Lc-Field $out", "Lc-JsonField $out", 1))
    probe = tmp_path / "resolve2.ps1"
    probe.write_text(
        "$e=$null;$t=$null\n"
        f"$ast=[System.Management.Automation.Language.Parser]::ParseFile('{broken}',[ref]$t,[ref]$e)\n"
        "$defined=@($ast.FindAll({param($n) $n -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst]},$true) | "
        "ForEach-Object { $_.Name })\n"
        "$called=@($ast.FindAll({param($n) $n -is "
        "[System.Management.Automation.Language.CommandAst]},$true) | "
        "ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })\n"
        "$called | Sort-Object -Unique | Where-Object { $defined -notcontains $_ -and "
        "-not (Get-Command $_ -ErrorAction SilentlyContinue) }\n"
    )
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(probe)], capture_output=True, text=True)
    assert "Lc-JsonField" in r.stdout, "the control does not detect an undefined call"


# ── the POST-START VERIFICATION, EXECUTED (1246-04-04 post-closure correction) ───
#
# The Windows Verify stage REPORTED and never REFUSED: every gate was `Ok`/`Warn`, and `$installOk`
# — one HTTP code — chose only which completion message printed. A box whose MCP answered 200
# unauthenticated, or whose storage was unreachable, still finished under a success banner. Linux
# had the mirror defect (it lost the stage entirely) and 1246-04-03 corrected it.
#
# **Presence checks are what let both survive**, so these RUN the stage under stubs: one healthy
# pass, then one failure per critical gate. Policy-through-doubles on **pwsh 7 / macOS** — Windows
# PowerShell 5.1 remains 1246-10's live gate.

def summary_body_ps(text: str) -> str:
    start = text.index('Section "Summary"')
    return text[start:text.index('Section "Next steps"', start)]


_SUMMARY_STUBS = """
$VerifiedServices = @('corpusfm-web','corpusfm-scheduler')
$WebPort = 8533; $WebPrefix = '/corpusfm'; $WebService = 'corpusfm-web'
$LogDir = '{tmp}'; $Dl = '{tmp}'; $Py = '{py}'; $Version = '0.1'
$StorageOk = $false
$CfmSvcStatus = '{svc}'; $CfmLoop = {loop}; $CfmProx = {prox}; $CfmFms = {fms}; $CfmMcp = {mcp}
$CfmStorage = '{storage}'; $CfmLogin = '{login}'
function Ok($m) {{ Write-Output ("OK: " + $m) }}
function Warn($m) {{ Write-Output ("WARN: " + $m) }}
function Info($m) {{ Write-Output ("INFO: " + $m) }}
function Section($m) {{ Write-Output ("SECTION: " + $m) }}
function Die($m) {{ Write-Output ("DIE: " + $m); exit 9 }}
function Code($u) {{ if ($u -like '*/login') {{ return $CfmLoop }} elseif ($u -like '*fmi*') {{ return $CfmFms }} else {{ return $CfmProx }} }}
function CodePost($u) {{ return $CfmMcp }}
function Get-Service {{ param($Name, $ErrorAction) return [pscustomobject]@{{ Status = $CfmSvcStatus }} }}
function Start-Sleep {{ param($Seconds) }}
"""


def run_summary_ps(tmp_path, *, tag="", svc="Running", loop=200, prox=200, fms=200, mcp=401,
                   storage="OK:7", login="1"):
    """The child `& $Py <script>` calls are answered by a stub interpreter, so the storage and
    login probes return exactly what the case under test needs."""
    stub_py = tmp_path / f"py{tag}.sh"
    stub_py.write_text("#!/bin/sh\ncase \"$1\" in\n  *_health.py) printf '%s' \"$CFM_STORAGE\" ;;\n"
                       "  *_loginstate.py) printf '%s' \"$CFM_LOGIN\" ;;\n  *) : ;;\nesac\n")
    stub_py.chmod(0o755)
    body = summary_body_ps(PS1_PATH.read_text(encoding="ascii"))
    script = tmp_path / f"summary{tag}.ps1"
    script.write_text(
        _SUMMARY_STUBS.format(tmp=tmp_path, py=stub_py, svc=svc, loop=loop, prox=prox, fms=fms,
                              mcp=mcp, storage=storage, login=login)
        + body + "\nWrite-Output 'REACHED-END'\n", encoding="utf-8")
    return subprocess.run([_PWSH, "-NoProfile", "-File", str(script)], capture_output=True,
                          text=True, env={**os.environ, "CFM_STORAGE": storage, "CFM_LOGIN": login})


@needs_pwsh
def test_the_windows_verification_PASSES_when_every_gate_is_healthy(tmp_path):
    """THE CLEAN CONTROL. Without it every refusal below is satisfied by a stage that always dies."""
    r = run_summary_ps(tmp_path)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    assert "REACHED-END" in r.stdout
    assert "OK: Post-install verification passed" in r.stdout
    for proof in ("corpusfm-web running", "corpusfm-scheduler running", "Loopback login responds",
                  "proxied /corpusfm/", "MCP fail-closed", "all four required default artifacts installed",
                  "Login user configured", "coexistence verified"):
        assert proof in r.stdout, f"the healthy run never proved: {proof}"


@needs_pwsh
@pytest.mark.parametrize("gate,kwargs,expected", [
    ("a verified service is not running", {"svc": "Stopped"}, "is NOT running"),
    ("the app does not answer on loopback", {"loop": 0}, "did NOT answer on loopback"),
    ("the proxied route does not answer", {"prox": 502}, "proxied route"),
    ("unauthenticated MCP is accepted", {"mcp": 200}, "did NOT reject unauthenticated access"),
    ("storage is unreachable", {"storage": "FAIL:OSError"}, "Storage is NOT reachable"),
    ("default artifacts are incomplete", {"storage": "MISSING:CORPUSfm_ADDON/MergedXML"},
     "Required default artifacts did not complete within 60 seconds"),
    ("no login user exists", {"login": "0"}, "No login user yet"),
])
def test_EVERY_WINDOWS_CRITICAL_GATE_INDEPENDENTLY_REFUSES(tmp_path, gate, kwargs, expected):
    """Each failure alone. A stage that only fails when several things break at once passes a box
    with exactly one thing wrong — which is the ordinary case, and was the shipped behaviour."""
    r = run_summary_ps(tmp_path, tag=gate.replace(" ", "-"), **kwargs)
    assert r.returncode == 9, f"{gate}: the install reported success anyway\n{r.stdout}"
    assert expected in r.stdout, f"{gate}: the refusal does not say why\n{r.stdout}"
    assert "DIE: Post-install verification FAILED" in r.stdout
    assert "REACHED-END" not in r.stdout, f"{gate}: Next steps was reached over a degraded install"
    assert "Post-install verification passed" not in r.stdout


@needs_pwsh
def test_EVERY_PHASE_20_VERIFIED_SERVICE_IS_RECHECKED(tmp_path):
    """Not a hard-coded pair: the stage iterates `$VerifiedServices`, the exact set phase 20 read
    back and registered, so a service added later cannot be silently unverified."""
    body = summary_body_ps(PS1_PATH.read_text(encoding="ascii"))
    assert "foreach ($id in $VerifiedServices)" in body
    r = run_summary_ps(tmp_path, tag="recheck")
    for svc in ("corpusfm-web", "corpusfm-scheduler"):
        assert f"OK: {svc} running" in r.stdout, f"{svc} was never rechecked"


@needs_pwsh
def test_the_WINDOWS_named_user_check_is_POST_INSTALL(tmp_path):
    """Phase 19's detection ran before the services existed. This asks the running installation —
    and distinguishes configured / absent / unreadable, because a storage outage is not a claim that
    no user exists (packet 1201)."""
    body = summary_body_ps(PS1_PATH.read_text(encoding="ascii"))
    assert "users_exist(raise_on_error=True)" in body
    ps1 = PS1_PATH.read_text(encoding="ascii")
    assert ps1.index("Section \"Summary\"") > ps1.index("storage create-first-admin")
    unknown = run_summary_ps(tmp_path, tag="login-unknown", login="?")
    assert unknown.returncode == 0
    assert "Could not verify the login user" in unknown.stdout
    assert "REACHED-END" in unknown.stdout


@needs_pwsh
def test_INSTALLOK_IS_NO_LONGER_THE_AUTHORITY_FOR_SUCCESS():
    """`$installOk` read one HTTP code and then chose an adjective, so a warning was always followed
    by a completion claim. Arriving past the stage IS the success condition now."""
    ps1 = PS1_PATH.read_text(encoding="ascii")
    code_only = "\n".join(l for l in ps1.splitlines() if not l.lstrip().startswith("#"))
    assert "$installOk" not in code_only, "$installOk still decides something"
    body = summary_body_ps(ps1)
    assert re.search(r"^\s*Die \"Post-install verification FAILED", body, re.M), (
        "the Windows stage cannot refuse success"
    )


# ── phase 12 and phase 20: FixedSecrets, never LegacyHome ─────────────────────────────
#
# The Windows twin of the fms-server defect (measured on Linux 2026-08-08, identical here by
# inspection): phase 12 guarded on `$LegacyHome\<key>` and downgraded a creation failure to
# "created on first use", and the phase-20 secret ACL loop protected `$LegacyHome\<key>` — a
# directory the resolver no longer uses — while reporting success.

def _uncommented(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_phase_12_does_not_detect_keys_in_LEGACY_HOME(ps1: str):
    body = _uncommented(ps1)
    for name in ("corpus.key", "secret.key", "machine.key", "server.key"):
        assert f"Join-Path $LegacyHome '{name}'" not in body, \
            f"phase 12 still detects {name} in the retired home"


def test_phase_12_has_NO_first_use_continuation(ps1: str):
    assert "created on first use" not in ps1.lower(), \
        "the warning path that let a missing key reach phase 15 is still here"


def test_phase_12_provisions_through_the_PRIVILEGED_lifecycle_operation(ps1: str):
    assert "provision-keys" in ps1, "phase 12 does not invoke the key-provisioning operation"
    # Lc-Run, not Lc-RunRaw: Lc-Run dispatches a non-zero exit into Die, which is what makes a
    # failure fatal before phase 15 rather than a warning carried past it.
    assert re.search(r"Lc-Run \"key provisioning\" @\('provision-keys','--request',\$req\)", ps1), \
        "key provisioning is not run through the dispatching runner, so a failure would not be fatal"
    assert not re.search(r"get_corpus_key\(\); get_machine_key\(\)", ps1), \
        "phase 12 still calls the runtime resolvers to CREATE the keys"


def test_the_phase_20_secret_ACL_loop_targets_FIXED_SECRETS(ps1: str):
    """**Re-expressed 2026-08-09.** The loop is retired: it hard-coded a list of secret filenames
    that never included `storage_access.json`, and re-granted each file with a `/reset` first. The
    rule it defended — the installed secrets, in the FIXED directory, are what gets protected — now
    lives in `READ_ONLY_SECRETS`, which the final `provision-keys` applies against the published
    layout's own secrets directory."""
    from corpusfm.lifecycle.protection import READ_ONLY_SECRETS

    body = _uncommented(ps1)
    assert "$roPath = Join-Path $LegacyHome $ro" not in body, \
        "the retired home, where no key lives, is protected again"
    assert "$roPath = Join-Path $FixedSecrets $ro" not in body, \
        "the hard-coded secret loop is back"
    for name in ("corpus.key", "machine.key", "session_secret", "storage_access.json"):
        assert name in READ_ONLY_SECRETS, name


def test_BOTH_installed_key_files_are_ACL_PROVEN_at_their_CURRENT_authority(ps1: str):
    """The effective-rights proof must read the files that actually exist, not the retired path."""
    body = _uncommented(ps1)
    proof = re.search(r"foreach \(\$proof in @\(\$FixedSecrets[^\n]*\n", body)
    assert proof, "the ACL proof loop was not found"
    line = proof.group(0)
    assert "corpus.key" in line and "machine.key" in line, "the proof does not name both key files"
    assert "$FixedSecrets" in line, "the proof reads a directory other than the fixed secrets one"
    assert "$LegacyHome" not in line, "the proof still reads the retired home"


def test_the_RETIRED_marker_setters_are_not_invoked(ps1: str):
    for retired in ("set-hosting-dir", "set-support-dir"):
        assert not re.search(rf"corpusfm\.server\.cli\s+{retired}", ps1), \
            f"the installer still invokes the retired {retired}"
