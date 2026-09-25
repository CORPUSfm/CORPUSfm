"""Packet 1380-02 — the privileged updater task must be registered with a task ACTION OBJECT.

THE DEFECT THIS EXISTS FOR, measured on w-test-private during the Gate 3 run. `install.ps1` registers
the one-shot updater inside the packet-1398 write-ahead ledger wrapper::

    La-Do 'task' 'create' $null @('\\CORPUSfm Update') {
        Register-ScheduledTask -TaskName $UpdaterTask -Action $action ...
    }

and the wrapper itself declares ``[scriptblock]$Action``. PowerShell resolves variables
case-insensitively through the dynamic scope chain, so when `La-Do` runs ``& $Action`` the block's
``$action`` binds to **La-Do's own parameter — the scriptblock** — and the real cmdlet refuses:
"Cannot convert ... ScriptBlock to Microsoft.Management.Infrastructure.CimInstance[]". The install
aborted at phase 20 with the service stopped and no updater task.

It had never been caught because `La-Do` arrived after the 0.2818 baseline installer, and packet 1398's
live gates were *interrupted* installs that stopped before phase 20 ever ran.

So this executes the REAL La-Do definition and the REAL registration snippet, lifted from the shipped
script, and asserts what `Register-ScheduledTask` actually receives. The mutation restores `$action` and
must fail — a test that cannot see the original defect would not be evidence that it is gone.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL_PS1 = ROOT / "installer" / "windows" / "install.ps1"

PWSH = shutil.which("pwsh") or shutil.which("powershell")
#: Executed under whatever PowerShell this machine has. The authoritative host is Windows PowerShell
#: 5.1 on the target; scope resolution is the same rule in both, and the static guard below runs
#: everywhere regardless.
supplementary = pytest.mark.skipif(PWSH is None, reason="no PowerShell available; static guard still runs")

LA_DO_PARAMS = ("Kind", "Intent", "Extra", "Targets", "Action")


def _text() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")


def _match_block(text: str, open_idx: int) -> int:
    """Index just past the brace-balanced block that opens at `open_idx`, ignoring quoted text."""
    depth, quote = 0, None
    for i in range(open_idx, len(text)):
        c = text[i]
        if quote:
            if c == quote:
                quote = None
            continue
        if c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise AssertionError("unbalanced block in install.ps1")


def _la_do_source(text: str) -> str:
    i = text.index("function La-Do(")
    return text[i:_match_block(text, text.index("{", i))]


def _registration_snippet(text: str) -> str:
    """The real phase-20 registration: the action/principal/settings assignments plus the whole
    try/catch that wraps the La-Do call."""
    start = text.index("New-ScheduledTaskAction")
    start = text.rindex("\n", 0, start) + 1
    try_idx = text.index("\n  try {", start)
    end = _match_block(text, text.index("{", try_idx))
    catch_idx = text.index("catch", end)
    end = _match_block(text, text.index("{", catch_idx))
    return text[start:end]


HARNESS_HEAD = r"""
$ErrorActionPreference = 'Stop'
$script:CfmAttempt = $ATTEMPT_FLAG
$script:LaSeqs = @(1)
$UpdaterTask = '\CORPUSfm Update'
$UpdaterDst  = 'C:\Program Files\CORPUSfm\bin\corpusfm-update.ps1'

function La-Step { param($Kind,$Intent,$Extra,$Targets) $script:LaSeqs = @(1) }
function La-Result { param($Seqs,$State,$Extra) [Console]::Out.WriteLine("LA_RESULT=" + $State) }

# Records go to the CONSOLE, not the success stream: the shipped call ends in `| Out-Null`,
# which would discard anything written with Write-Output.
# Stand-ins for the ScheduledTasks cmdlets, which do not exist off Windows. The real
# Register-ScheduledTask types -Action as CimInstance[] and REFUSES a ScriptBlock; this one records
# what it was handed and refuses the same way, which is the fact under test.
function New-ScheduledTaskAction { param($Execute,$Argument)
  [pscustomobject]@{ CfmKind='TaskAction'; Execute=$Execute; Argument=$Argument } }
function New-ScheduledTaskPrincipal { param($UserId,$LogonType,$RunLevel)
  [pscustomobject]@{ CfmKind='Principal'; UserId=$UserId } }
function New-ScheduledTaskSettingsSet {
  param([switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$ExecutionTimeLimit,$MultipleInstances)
  [pscustomobject]@{ CfmKind='Settings' } }
function Unregister-ScheduledTask { param($TaskName,$Confirm,$ErrorAction) }
function Die { param($m) [Console]::Out.WriteLine("DIE=" + $m); throw $m }

function Register-ScheduledTask {
  param($TaskName,$Action,$Principal,$Settings,$Description,[switch]$Force)
  $t = if ($null -eq $Action) { 'NULL' } else { $Action.GetType().Name }
  [Console]::Out.WriteLine("ACTION_TYPE=" + $t)
  if ($Action -is [scriptblock]) { throw "Register-ScheduledTask received a ScriptBlock for -Action" }
  [Console]::Out.WriteLine("ACTION_KIND=" + $Action.CfmKind)
  [Console]::Out.WriteLine("ACTION_EXECUTE=" + $Action.Execute)
  [Console]::Out.WriteLine("ACTION_ARGUMENT=" + $Action.Argument)
  [Console]::Out.WriteLine("TASK_NAME=" + $TaskName)
}
"""


def _run(tmp_path: Path, snippet: str, attempt: bool) -> str:
    text = _text()
    script = (HARNESS_HEAD.replace("$ATTEMPT_FLAG", "$true" if attempt else "$false")
              + "\n" + _la_do_source(text) + "\n" + snippet + "\n")
    p = tmp_path / f"harness_{attempt}.ps1"
    p.write_text(script, encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(p)],
                       capture_output=True, text=True, timeout=120)
    return r.stdout + r.stderr


@supplementary
@pytest.mark.parametrize("attempt", [False, True], ids=["ledger-passthrough", "ledger-active"])
def test_the_real_phase20_path_registers_a_task_action_object(tmp_path, attempt):
    """The shipped registration, executed through the real `La-Do`, in BOTH ledger modes — the
    pass-through (`& $Action` with no ledger) and the recording path. Each invokes the block inside
    La-Do's scope, which is where the shadowing happens, so both must bind the action OBJECT."""
    out = _run(tmp_path, _registration_snippet(_text()), attempt)
    assert "ACTION_TYPE=ScriptBlock" not in out, f"the scriptblock reached -Action again:\n{out}"
    assert "ACTION_KIND=TaskAction" in out, f"-Action did not receive the task action object:\n{out}"
    assert "ACTION_EXECUTE=powershell.exe" in out, out
    assert "corpusfm-update.ps1" in out, out
    assert "DIE=" not in out, f"the registration failed:\n{out}"


@supplementary
def test_restoring_the_shadowed_name_reintroduces_the_defect(tmp_path):
    """THE MUTATION. Rename the variable back to `$action` — the exact pre-correction spelling — and the
    block's reference resolves to La-Do's own `$Action` parameter instead. `Register-ScheduledTask` then
    receives a ScriptBlock and the shipped `catch` calls `Die`, which is precisely what aborted the
    install on w-test-private. If this passes, the test above is not proving anything."""
    mutated = _registration_snippet(_text()).replace("$taskAction", "$action")
    out = _run(tmp_path, mutated, attempt=False)
    assert "ACTION_TYPE=ScriptBlock" in out, f"the mutation did not reproduce the defect:\n{out}"
    assert "ACTION_KIND=TaskAction" not in out, out
    assert "DIE=" in out, f"the shipped failure path did not fire:\n{out}"


def test_no_la_do_action_block_references_a_la_do_parameter_name():
    """Static guard — runs everywhere, including where no PowerShell exists.

    Generalises the defect instead of pinning the one variable: NO block handed to `La-Do` may mention
    any of its parameter names, because PowerShell would resolve the mention to the wrapper's own
    parameter. `$Action` is the one that bit; `$Kind`/`$Intent`/`$Extra`/`$Targets` are the same hazard
    waiting for a call site to use those names.
    """
    text = _text()
    pat = re.compile(r"\$(" + "|".join(LA_DO_PARAMS) + r")\b", re.IGNORECASE)
    offenders, sites = [], 0
    for m in re.finditer(r"(?<!function )\bLa-Do\b", text):
        if text.count("function La-Do", m.start(), m.start() + 1):
            continue
        sites += 1
        brace = text.index("{", m.start())
        block = text[brace:_match_block(text, brace)]
        for hit in sorted(set(h.group(0) for h in pat.finditer(block))):
            offenders.append((text[:m.start()].count("\n") + 1, hit))
    assert sites >= 12, f"expected the known La-Do call sites, found {sites}"
    assert not offenders, (
        "a La-Do action block references one of La-Do's own parameter names; PowerShell will bind it "
        f"to the wrapper's parameter, not the caller's variable: {offenders}"
    )
