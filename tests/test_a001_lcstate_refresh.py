"""`Get-LcState -Refresh` — the explicit fresh read A001's post-recovery verification needs.

**The live failure this corrects.** `Get-LcState` memoizes on `$script:LcStateRaw` so phases 2 and 3
classify from ONE status object — a deliberate contract, because a second read between them could
route on a box that changed under the classification. A001's post-recovery check then called it
expecting current state and received the **phase-3 observation**, taken while the journal was still
`open`. Measured on w-test-private, 2026-09-03: the recovery had genuinely succeeded — journal gone,
generation 9, scheduler authority removed — and the installer aborted with *"A001 recovery ran but a
lifecycle journal is still retained"*. It failed closed, so nothing was damaged; it reported a
success as a failure and stopped the invocation with the wrong reason.

**Evidence tiers in this module.** The static assertions are AUTHORITATIVE: they read the shipped
`install.ps1`. The executable checks run under **local pwsh** and are **SUPPLEMENTARY ONLY** — the
authoritative shell for this installer is Windows PowerShell 5.1 through `powershell.exe`, which
this repository cannot run. They are marked `supplementary` and skip where pwsh is absent.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PS1_PATH = ROOT / "installer/windows/install.ps1"
PS1 = PS1_PATH.read_text(encoding="ascii")
CODE = "\n".join(l for l in PS1.splitlines() if not l.lstrip().startswith("#"))

PWSH = shutil.which("pwsh")
supplementary = pytest.mark.skipif(PWSH is None, reason="no pwsh; these are supplementary anyway")


def _fn(name: str) -> str:
    m = re.search(rf"^function {re.escape(name)}\b", CODE, re.M)
    assert m, f"{name} is not defined"
    start = m.start()
    depth, i = 0, CODE.index("{", start)
    for j in range(i, len(CODE)):
        if CODE[j] == "{":
            depth += 1
        elif CODE[j] == "}":
            depth -= 1
            if depth == 0:
                return CODE[start:j + 1]
    raise AssertionError(name)


# ── AUTHORITATIVE: the shipped source ─────────────────────────────────────────────────────────────

def test_get_lcstate_takes_an_explicit_refresh_switch():
    body = _fn("Get-LcState")
    assert "param([switch]$Refresh)" in body
    assert "if (-not $Refresh -and $null -ne $script:LcStateRaw) { return $script:LcStateRaw }" in body


def test_the_default_contract_is_preserved_and_phases_2_and_3_share_one_observation():
    """The memoization is not weakened: an ordinary call still returns the cached value, and the two
    classification phases still read the same object."""
    calls = [l.strip() for l in CODE.splitlines() if "Get-LcState" in l and "function" not in l]
    defaults = [c for c in calls if "-Refresh" not in c]
    assert any("$lcStateEarly = Get-LcState" == c for c in defaults), "phase 2 no longer shares"
    assert any("$lcState = Get-LcState" == c for c in defaults), "phase 3 no longer shares"
    # and nothing between them forces a re-read
    early = CODE.index("$lcStateEarly = Get-LcState")
    phase3 = CODE.index("$lcState = Get-LcState", early)
    assert "-Refresh" not in CODE[early:phase3]
    # The cache is assigned ONLY by its initialiser and inside `Get-LcState`. A call site that
    # reset it would defeat the shared-observation contract just as surely as a second read.
    assigns = [i for i, l in enumerate(CODE.splitlines()) if "$script:LcStateRaw =" in l]
    fn_start = CODE[:CODE.index("function Get-LcState")].count("\n")
    fn_end = fn_start + _fn("Get-LcState").count("\n")
    outside = [i for i in assigns if not (fn_start <= i <= fn_end)]
    assert len(outside) == 1, f"the cache is assigned outside Get-LcState at lines {outside}"
    assert CODE.splitlines()[outside[0]].strip() == "$script:LcStateRaw = $null", \
        "the one assignment outside the function is not the initialiser"


def test_only_a001s_post_recovery_verification_refreshes():
    refreshed = [l.strip() for l in CODE.splitlines() if "Get-LcState -Refresh" in l]
    assert refreshed == ["$after = Get-LcState -Refresh"], f"unexpected refresh sites: {refreshed}"
    body = _fn("Lc-RecoverA001Authority")
    assert "$after = Get-LcState -Refresh" in body


def test_the_refresh_stores_the_fresh_result_back_as_the_shared_observation():
    body = _fn("Get-LcState")
    assert "$script:LcStateRaw = $raw" in body
    assert body.rstrip().endswith("return $script:LcStateRaw\n}")


def test_no_second_status_reader_and_no_cache_clearing_at_the_call_site():
    """The correction is one option on the one reader — not a second path, and not a call site that
    reaches into the cache.

    Scoped to the CLASSIFICATION reader. Later phases legitimately run `status --json` of their own
    for post-install verification; those are not this contract's subject, and asserting a
    whole-file count of one was simply wrong about the script.
    """
    assert _fn("Get-LcState").count("-m corpusfm.lifecycle status --json") == 1
    body = _fn("Lc-RecoverA001Authority")
    for forbidden in ("LcStateRaw", "status --json", "Initialize-PackagedRecoveryRuntime"):
        assert forbidden not in body, f"the call site reaches past Get-LcState: {forbidden}"


def test_no_failure_path_returns_the_stale_cached_value():
    """Every exit from a refresh either dies or REPLACES the cache. None hands back the value the
    caller asked to look past."""
    body = _fn("Get-LcState")
    returns = [l.strip() for l in body.splitlines() if l.strip().startswith("return ")]
    assert set(returns) == {"return $script:LcStateRaw"}, returns
    # the two non-fatal early exits both overwrite the cache first
    assert body.count("$script:LcStateRaw = ''") == 2
    for seg in body.split("$script:LcStateRaw = ''")[1:]:
        assert seg.lstrip().startswith("\n    return $script:LcStateRaw") or \
               seg.lstrip().startswith("return $script:LcStateRaw"), \
               "a cache-clearing path does not immediately return the cleared value"


# ── SUPPLEMENTARY: executed under local pwsh, NOT the authoritative Windows PowerShell 5.1 ────────

#: In production `$Py` and `$script:Py` are the SAME script-scope variable: a real path that
#: `Test-Path` checks and `&` invokes. An earlier harness set `$script:Py` to a path and then `$Py`
#: to a function name, which silently clobbered the path — so the interpreter check failed and the
#: function took its "no application source" refusal instead of ever reading status. The shim is a
#: real executable file for exactly that reason.
HARNESS = r"""
$ErrorActionPreference = 'Stop'
$script:LcStateRaw = $null
$script:RecoverySource = $env:STUBDIR
$script:RecoveryRuntimeKind = 'installed'
$script:Py = Join-Path $env:STUBDIR 'pyshim'
$FixedState = $env:STUBDIR
$InstallerSeries = ''
$RuntimeTemp = ''
function Die($m) { throw ("DIE: " + $m) }
function Warn($m) { Write-Output ("WARN: " + $m) }
function Cfm-Logline($m) { }
function Test-CfmInstallationAuthority { return $true }
function Initialize-PackagedRecoveryRuntime { }
function New-CfmProbeFile($text) {
  $f = Join-Path $env:STUBDIR ("probe-" + [guid]::NewGuid().ToString() + ".py")
  Set-Content -LiteralPath $f -Value $text -Encoding ascii
  return $f
}
function StatusCalls { (Get-Content -LiteralPath (Join-Path $env:STUBDIR 'calls') -Raw).Trim() }
__GETLCSTATE__
__BODY__
"""

#: The interpreter stand-in. `status --json` returns the CURRENT scripted answer and records the
#: call; anything else is the strict JSON probe, which succeeds.
PYSHIM = """#!/bin/sh
case "$*" in
  *status*)
    printf x >> "$STUBDIR/calls"
    a=$(cat "$STUBDIR/answer.json")
    if [ "$a" = "FAIL" ]; then exit 1; fi
    printf '%s' "$a"; exit 0 ;;
  *) exit 0 ;;
esac
"""


def _run_ps(tmp_path, body: str, answer: str) -> tuple[int, str]:
    stub = tmp_path / "stub"
    stub.mkdir(exist_ok=True)
    shim = stub / "pyshim"
    shim.write_text(PYSHIM)
    shim.chmod(0o755)
    (stub / "calls").write_text("")
    # `Get-LcState` requires both the interpreter and the lifecycle package to exist before it will
    # run status at all; without them it takes the "no application source" refusal instead.
    #
    # BOTH SPELLINGS, and the reason is the tier label on this whole section. The production path is
    # built with `Join-Path … 'corpusfm\lifecycle\__main__.py'`, and under macOS pwsh those
    # backslashes are ORDINARY CHARACTERS rather than separators — so the same expression names a
    # nested path on Windows and a single oddly-named file here. Creating both keeps the harness
    # honest about what it is: a supplementary check on a non-authoritative shell.
    pkg = stub / "corpusfm" / "lifecycle"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__main__.py").write_text("")
    (stub / "corpusfm\\lifecycle\\__main__.py").write_text("")
    (stub / "answer.json").write_text(answer)
    src = HARNESS.replace("__GETLCSTATE__", _fn("Get-LcState")).replace("__BODY__", body)
    script = tmp_path / "t.ps1"
    script.write_text(src, encoding="utf-8")
    r = subprocess.run([PWSH, "-NoProfile", "-File", str(script)],
                       capture_output=True, text=True,
                       env={**os.environ, "STUBDIR": str(stub)})
    calls = len((stub / "calls").read_text())
    return r.returncode, (r.stdout + r.stderr).replace("__CALLS__", str(calls)) + f"\ncalls={calls}"


OPEN = '{"journal":"open","locator":"present","generation":8}'
NONE = '{"journal":"none","locator":"present","generation":9}'


@supplementary
def test_supplementary_two_default_calls_execute_status_once(tmp_path):
    rc, out = _run_ps(tmp_path, """
$a = Get-LcState
$b = Get-LcState
Write-Output ("same=" + ($a -eq $b))
""", OPEN)
    assert rc == 0, out
    assert "calls=1" in out, out
    assert "same=True" in out


@supplementary
def test_supplementary_refresh_executes_status_again_and_returns_the_changed_state(tmp_path):
    rc, out = _run_ps(tmp_path, f"""
$first = Get-LcState
Set-Content -LiteralPath (Join-Path $env:STUBDIR 'answer.json') -Value '{NONE}' -Encoding ascii
$second = Get-LcState -Refresh
Write-Output ("first_open=" + $first.Contains('"journal":"open"'))
Write-Output ("second_none=" + $second.Contains('"journal":"none"'))
Write-Output ("cache_updated=" + $script:LcStateRaw.Contains('"journal":"none"'))
""", OPEN)
    assert rc == 0, out
    assert "calls=2" in out, out
    assert "first_open=True" in out and "second_none=True" in out
    assert "cache_updated=True" in out, "the fresh result was not stored back"


@supplementary
def test_supplementary_the_cached_call_reproduces_the_live_failure(tmp_path):
    """Restoring the defect: without -Refresh the post-recovery read returns the pre-recovery answer,
    which is exactly what aborted the live invocation."""
    rc, out = _run_ps(tmp_path, f"""
$before = Get-LcState
Set-Content -LiteralPath (Join-Path $env:STUBDIR 'answer.json') -Value '{NONE}' -Encoding ascii
$after = Get-LcState
Write-Output ("after_still_open=" + $after.Contains('"journal":"open"'))
""", OPEN)
    assert rc == 0, out
    assert "calls=1" in out
    assert "after_still_open=True" in out, "the defect no longer reproduces; the control is vacuous"


@supplementary
def test_supplementary_a_failed_refresh_does_not_return_the_cached_value(tmp_path):
    """With an installation authority present an unreadable status DIES. It must not quietly hand
    back the pre-recovery answer the caller asked to look past."""
    rc, out = _run_ps(tmp_path, """
$first = Get-LcState
Set-Content -LiteralPath (Join-Path $env:STUBDIR 'answer.json') -Value 'FAIL' -Encoding ascii
try {
  $second = Get-LcState -Refresh
  Write-Output ("RETURNED=" + $second)
} catch {
  Write-Output ("THREW: " + $_.Exception.Message)
}
""", OPEN)
    assert "THREW: DIE:" in out, out
    assert "RETURNED=" not in out, "a failed refresh returned a value"
    assert '"journal":"open"' not in out.split("THREW")[-1], "the stale value leaked into the failure"
