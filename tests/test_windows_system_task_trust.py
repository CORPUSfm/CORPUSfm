r"""Packet 1380-02 - the SYSTEM updater task's AllSigned check.

**Evidence class.** `Get-CfmSystemTaskTrustVerdict` is extracted from the shipped `install.ps1` and
EXECUTED under PowerShell 7 against injected facts. That is supporting evidence only: what SYSTEM
actually observes under AllSigned, and the Authenticode and certificate-store collection, are Gate 3
evidence on Windows PowerShell 5.1.

**The rule.** The task runs as SYSTEM, governed by MachinePolicy then LocalMachine. When that
machine-wide policy is AllSigned, or cannot be determined, the running installer's valid signer leaf
must be in LocalMachine\TrustedPublisher before phase 8's first installation mutation.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SRC = (ROOT / "installer/windows/install.ps1").read_text(encoding="ascii")
PWSH = shutil.which("pwsh") or shutil.which("powershell")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell available to execute decisions")

LEAF = "A1DEC4F631E48803458A0259F3F128542EDB5773"
OTHER = "CEE6FDC77F59D5A4F0835EC872F12B4991D26B0B"


def _extract(name: str, text: str) -> str:
    start = text.index(f"function {name}")
    depth, i = 0, text.index("{", start)
    while True:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1


def _code_only(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _verdict(machine: str, local: str, status: str = "", thumb: str = "",
             trusted: tuple[str, ...] = ()) -> dict:
    store = ", ".join("'%s'" % t for t in trusted)
    scenario = (
        f"$v = Get-CfmSystemTaskTrustVerdict -MachinePolicy '{machine}' -LocalMachine '{local}' "
        f"-SignatureStatus '{status}' -SignerThumbprint '{thumb}' -LocalMachineThumbprints @({store})\n"
        "[pscustomobject]@{ allow=$v.Allow; reason=$v.Reason; policy=$v.Policy } | ConvertTo-Json -Compress")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "scenario.ps1"
        path.write_text(_extract("Get-CfmSystemTaskTrustVerdict", INSTALL_SRC) + "\n\n" + scenario + "\n",
                        encoding="ascii")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                              capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    assert out, f"scenario produced no output.\nstderr:\n{proc.stderr}"
    return json.loads(out.splitlines()[-1])


CASES = [
    # machine-wide policy does not make AllSigned applicable: nothing is required, signed or not
    (("Undefined", "RemoteSigned", "NotSigned", "", ()), (True, "not_applicable", "RemoteSigned")),
    (("Undefined", "RemoteSigned", "Valid", LEAF, ()), (True, "not_applicable", "RemoteSigned")),
    # MachinePolicy outranks LocalMachine, in both directions
    (("RemoteSigned", "AllSigned", "NotSigned", "", ()), (True, "not_applicable", "RemoteSigned")),
    (("AllSigned", "RemoteSigned", "Valid", LEAF, (OTHER,)),
     (False, "leaf_not_in_localmachine_trustedpublisher", "AllSigned")),
    # AllSigned applies: the running installer must be validly signed by a LocalMachine-trusted leaf
    (("Undefined", "AllSigned", "NotSigned", "", ()), (False, "signature_not_valid", "AllSigned")),
    (("Undefined", "AllSigned", "HashMismatch", LEAF, (LEAF,)), (False, "signature_not_valid", "AllSigned")),
    (("Undefined", "AllSigned", "Valid", "", ()), (False, "no_signer_certificate", "AllSigned")),
    (("Undefined", "AllSigned", "Valid", LEAF, ()), (False, "leaf_not_in_localmachine_trustedpublisher",
                                                     "AllSigned")),
    (("Undefined", "AllSigned", "Valid", LEAF.lower(), (OTHER, " " + LEAF + " ")),
     (True, "trusted", "AllSigned")),
    # an undeterminable machine-wide policy fails closed, and a deployed leaf still satisfies it
    (("", "", "NotSigned", "", ()), (False, "signature_not_valid", "Indeterminate")),
    (("Undefined", "", "Valid", LEAF, (OTHER,)), (False, "leaf_not_in_localmachine_trustedpublisher",
                                                  "Indeterminate")),
    (("Undefined", "NotAPolicy", "Valid", LEAF, (LEAF,)), (True, "trusted", "Indeterminate")),
]


@needs_pwsh
@pytest.mark.parametrize("facts,expected", CASES,
                         ids=[f"{f[0] or 'unread'}-{f[1] or 'unread'}-{f[2] or 'none'}-{e[1]}" for f, e in CASES])
def test_the_system_task_verdict(facts, expected):
    v = _verdict(*facts)
    assert (v["allow"], v["reason"], v["policy"]) == expected


def test_the_check_reads_only_machine_wide_policy_and_the_localmachine_store():
    """SYSTEM's authority is machine-wide; the administrator's own scopes and stores cannot speak for it."""
    body = _code_only(_extract("Assert-CfmSystemTaskTrust", INSTALL_SRC))
    assert "Get-ExecutionPolicy -Scope MachinePolicy" in body
    assert "Get-ExecutionPolicy -Scope LocalMachine" in body
    assert "Cert:\\LocalMachine\\TrustedPublisher" in body
    for other in ("-List", "CurrentUser", "UserPolicy", "-Scope Process"):
        assert other not in body, other


def _phase8_prefix() -> str:
    """The real phase 8 text from its header through its first New-Item: the check, the replace-aside
    move and the first directory creation, exactly as shipped."""
    start = INSTALL_SRC.index("# === PHASE 8 - Establish or verify the layout")
    first_new_item = INSTALL_SRC.index("New-Item -ItemType Directory -Force -Path $InstallDir,", start)
    # Packet 1398 wraps that creation in `La-Do ... { ... }`; the slice ends where its block closes.
    end = INSTALL_SRC.index("\n", first_new_item) + 1
    if INSTALL_SRC.startswith("}\n", end):
        end += 2
    return INSTALL_SRC[start:end]


# The Windows-only facts and every mutating command are replaced by recording functions; functions
# take precedence over cmdlets of the same name, so the shipped text runs unchanged.
_PHASE8_STUBS = r"""
$script:events = New-Object System.Collections.Generic.List[string]
function Section($t) { }
function Info($m) { }
function Ok($m) { }
function Warn($m) { }
function Die($m) { $script:events.Add('DIE'); throw ('DIE: ' + $m) }
function Test-CfmInstallationAuthority { $false }
function Get-ExecutionPolicy { [CmdletBinding()] param([string]$Scope)
  if ($Scope -eq 'MachinePolicy') { $script:machinePolicy } else { $script:localMachine } }
function Get-AuthenticodeSignature { [CmdletBinding()] param([string]$LiteralPath)
  [pscustomobject]@{ Status = $script:sigStatus
    SignerCertificate = $(if ($script:sigThumb) { [pscustomobject]@{ Thumbprint = $script:sigThumb; Subject = 'CN=Test' } } else { $null }) } }
function Get-ChildItem { [CmdletBinding()] param([Parameter(Position=0)]$Path, $LiteralPath, [switch]$Force)
  if ("$Path" -like 'Cert:*') { foreach ($t in $script:trusted) { [pscustomobject]@{ Thumbprint = $t } } }
  else { 'existing-entry' } }
function Test-Path { [CmdletBinding()] param($LiteralPath, $Path, $PathType)
  ("$LiteralPath$Path" -eq $InstallDir) }
function Move-Item { [CmdletBinding()] param($LiteralPath, $Destination) $script:events.Add('Move-Item') }
function New-Item { [CmdletBinding()] param($ItemType, [switch]$Force, $Path) $script:events.Add('New-Item') }
$InstallDir = 'C:\Program Files\CORPUSfm'; $ConfigHome = 'C:\ProgramData\CORPUSfm'
$SvcDir = 'x'; $BinDir = 'x'; $LibDir = 'x'; $LogDir = 'x'; $ProxyDir = 'x'; $Dl = 'x'; $Src = 'x'
$ReplaceAsideWasDebris = $false
# Packet 1398: no attempt is active in these scenarios, so its wrapper is the real pass-through and
# beginning one records nothing the policy check could be confused with.
$script:CfmAttempt = $false
function La-BeginAttempt { }
$ReleaseLocation = 'https://example.invalid/releases'
$PSCommandPath = 'C:\pkg\install.ps1'
"""


def _run_phase8(machine: str, local: str, status: str, thumb: str, trusted: tuple[str, ...],
                replace_aside: bool) -> list[str]:
    funcs = "\n\n".join(_extract(n, INSTALL_SRC) for n in ("Get-CfmSystemTaskTrustVerdict",
                                                          "Assert-CfmSystemTaskTrust", "La-Do"))
    facts = (f"$script:machinePolicy = '{machine}'; $script:localMachine = '{local}'\n"
             f"$script:sigStatus = '{status}'; $script:sigThumb = '{thumb}'\n"
             f"$script:trusted = @({', '.join(repr(t) for t in trusted)})\n"
             f"$ReplaceAside = {'\"C:\\\\Program Files\\\\CORPUSfm.aside\"' if replace_aside else '$null'}\n")
    body = _phase8_prefix()
    scenario = (_PHASE8_STUBS + funcs + "\n" + facts +
                "try {\n" + body + "\n} catch { if (-not \"$_\".StartsWith('DIE: ')) { $script:events.Add('ERROR: ' + \"$_\") } }\n"
                "@($script:events) | ConvertTo-Json -Compress\n")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "phase8.ps1"
        path.write_text(scenario, encoding="ascii")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                              capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    assert out, f"scenario produced no output.\nstderr:\n{proc.stderr}"
    events = json.loads(out.splitlines()[-1])
    return [events] if isinstance(events, str) else list(events)


@needs_pwsh
@pytest.mark.parametrize("replace_aside", [True, False], ids=["replace-aside", "fresh-layout"])
def test_an_untrusted_allsigned_machine_refuses_before_phase_8_mutates(replace_aside):
    events = _run_phase8("Undefined", "AllSigned", "NotSigned", "", (), replace_aside)
    assert events == ["DIE"], events


@needs_pwsh
def test_an_undeterminable_machine_policy_refuses_before_phase_8_mutates():
    events = _run_phase8("", "", "Valid", LEAF, (OTHER,), True)
    assert events == ["DIE"], events


@needs_pwsh
@pytest.mark.parametrize("replace_aside,expected", [(True, ["Move-Item", "New-Item"]), (False, ["New-Item"])],
                         ids=["replace-aside", "fresh-layout"])
def test_control_remotesigned_does_not_trigger_the_check_and_phase_8_proceeds(replace_aside, expected):
    """An unsigned private package under RemoteSigned: the prerequisite does not apply."""
    assert _run_phase8("Undefined", "RemoteSigned", "NotSigned", "", (), replace_aside) == expected


@needs_pwsh
def test_a_trusted_leaf_under_allsigned_lets_phase_8_proceed():
    assert _run_phase8("AllSigned", "Undefined", "Valid", LEAF, (LEAF,), False) == ["New-Item"]


def test_the_check_is_called_once_inside_phase_8_before_phase_9():
    assert _code_only(INSTALL_SRC).count("Assert-CfmSystemTaskTrust -EntryPoint") == 1
    phase8 = INSTALL_SRC.index("# === PHASE 8 - Establish or verify the layout")
    phase9 = INSTALL_SRC.index("# === PHASE 9")
    call = INSTALL_SRC.index("Assert-CfmSystemTaskTrust -EntryPoint $PSCommandPath")
    assert phase8 < call < phase9


def test_the_refusal_names_the_remedy_and_offers_no_evasion():
    body = _extract("Assert-CfmSystemTaskTrust", INSTALL_SRC)
    refusal = body[body.index("Die ("):]
    for needed in ("Certificate thumbprint: ", "LocalMachine\\TrustedPublisher", "$ReleaseLocation",
                   "$verdict.Policy"):
        assert needed in refusal, needed
    lowered = refusal.lower()
    for evasion in ("bypass", "unblock-file", "set-executionpolicy", "import-certificate"):
        assert evasion not in lowered, evasion
