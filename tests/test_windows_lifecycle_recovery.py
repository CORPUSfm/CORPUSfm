r"""Packet 1380-02 - Windows lifecycle recovery runs the lifecycle CLI directly.

**Evidence class.** The recovery functions are extracted from the shipped `install.ps1` and EXECUTED
under PowerShell 7 with the interpreter replaced by a recording function, so the closed family/verb
table, the argv it builds and the exit-code routing are exercised rather than grepped. This is
SUPPORTING EVIDENCE ONLY: Windows PowerShell 5.1, the real runtimes and a real interrupted operation
are Gate 3 evidence.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "installer/windows/install.ps1"
INSTALL_SRC = INSTALL.read_text(encoding="ascii")
PWSH = shutil.which("pwsh") or shutil.which("powershell")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell available to execute decisions")

OP = "22222222-2222-4222-8222-222222222222"
INST = "11111111-1111-4111-8111-111111111111"
REQUEST_PATH = r"C:\ProgramData\CORPUSfm\run\installer-recovery.json"


def _extract(name: str, text: str) -> str:
    """Lift one function out by brace balance; a test carrying its own copy would drift silently."""
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


def _ps(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


FUNCS = "\n\n".join(_extract(n, INSTALL_SRC) for n in (
    "Lc-IsOneJsonObject", "Test-CfmLifecycleRecoverySucceeded", "Invoke-CfmLifecycleRecovery",
    "Complete-CfmOwedLifecycleRecovery"))

# Die throws so an ending path is observable; the interpreter is a function that records its argv.
PRELUDE = r"""
$script:calls = @()
$script:requests = @()
$script:RecoveryRuntimeKind = 'installed'
function Die($m) { throw ('DIE: ' + $m) }
function Info($m) { }
function Lc-Request($name, $json) { $script:requests += $json; return '%s' }
function FakePy { $script:calls += ,@($args); $global:LASTEXITCODE = $script:fakeExit }
$script:Py = 'FakePy'
""" % REQUEST_PATH


def _run(scenario: str) -> dict:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "scenario.ps1"
        path.write_text(PRELUDE + "\n" + FUNCS + "\n\n" + scenario + "\n", encoding="ascii")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                              capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    assert out, f"scenario produced no output.\nstderr:\n{proc.stderr}"
    return json.loads(out.splitlines()[-1])


def _facts(family: str, verb: str, request: str | None, rc: int = 0) -> str:
    return (f"$script:LcRecoveryFamily = {_ps(family)}\n$script:LcRecoveryVerb = {_ps(verb)}\n"
            f"$script:LcRecoveryRequest = {_ps(request or '')}\n$script:LcOp = {_ps(OP)}\n"
            f"$script:fakeExit = {rc}\n")


_REPORT = ("[pscustomobject]@{ rc = $rc; died = $died; calls = @($script:calls | ForEach-Object { ,@($_) }); "
           "requests = @($script:requests) } | ConvertTo-Json -Compress -Depth 5")


def _windows_answer(provider: str) -> dict:
    from corpusfm.lifecycle.installer_disposition import classify

    return classify({
        "schema_version": 1, "phase": "preflight", "provider": None, "exit_code": None,
        "installation_id": None, "expected_generation": None, "mode": None,
        "install_dir": r"C:\Program Files\CORPUSfm", "platform": "windows", "provider_result": None,
        "journal": {"state": "needs_recovery", "operation_id": OP, "installation_id": INST,
                    "current_subsystem": {"patch": "patch_compartment", "proxy": "proxy_policy",
                                          "storage": "storage",
                                          "admin_identity": "admin_identity"}[provider]},
    })


def test_no_installer_code_installs_or_runs_the_recovery_file_script():
    """`corpusfm-recovery.ps1` creates or adopts a CORPUSfm Recovery File (1246-02); it is shipped,
    never installed or run by the installer (D-L). Comments may name it to say so."""
    code = "\n".join(l.split("#", 1)[0] for l in INSTALL_SRC.splitlines())
    assert "corpusfm-recovery.ps1" not in code


@needs_pwsh
@pytest.mark.parametrize("provider", ["patch", "proxy", "storage", "admin_identity"])
def test_the_application_disposition_runs_through_the_installer_closed_table(provider):
    """The family/verb the application returns is exactly what the installer runs, with its request."""
    answer = _windows_answer(provider)
    v = _run(_facts(answer["recovery_family"], answer["recovery_verb"], answer["recovery_request"])
             + "$died = ''\ntry { $rc = Invoke-CfmLifecycleRecovery } catch { $died = \"$_\" }\n" + _REPORT)
    assert v["died"] == ""
    assert len(v["calls"]) == 1
    argv = v["calls"][0]
    assert argv[:4] == ["-m", "corpusfm.lifecycle", answer["recovery_family"], answer["recovery_verb"]]
    if answer["recovery_request"]:
        assert argv[4:] == ["--request", REQUEST_PATH]
        assert v["requests"] == [answer["recovery_request"]]
    else:
        assert argv[4:] == ["--operation-id", OP]
        assert v["requests"] in ([], None)


@needs_pwsh
@pytest.mark.parametrize("family,verb,body", [
    ("proxy", "rollback", '{"a":1}'),
    ("patch-compartment", "abort", ""),
    ("Proxy", "abort", '{"a":1}'),
    ("script", "abort", '{"a":1}'),
    ("storage", "abort", ""),
    ("storage", "abort", '"not an object"'),
])
def test_anything_outside_the_closed_table_refuses_before_running(family, verb, body):
    v = _run(_facts(family, verb, body)
             + "$died = ''\ntry { $rc = Invoke-CfmLifecycleRecovery } catch { $died = \"$_\" }\n" + _REPORT)
    assert v["died"].startswith("DIE: ") and "journal remains untouched" in v["died"]
    assert v["calls"] in ([], None), "the interpreter ran for a pair the table does not name"


@needs_pwsh
@pytest.mark.parametrize("code,recovered", [(0, True), (2, True), (1, False), (3, False), (4, False),
                                            (5, False), (64, False)])
def test_an_owed_recovery_always_ends_the_invocation(code, recovered):
    """0 and 2 recover; everything else keeps the journal. Neither returns to later phases."""
    answer = _windows_answer("proxy")
    v = _run(_facts(answer["recovery_family"], answer["recovery_verb"], answer["recovery_request"], rc=code)
             + "$rc = $null; $died = ''\n"
             "try { Complete-CfmOwedLifecycleRecovery; $died = 'RETURNED' } catch { $died = \"$_\" }\n"
             + _REPORT)
    assert len(v["calls"]) == 1
    assert v["died"] != "RETURNED" and v["died"].startswith("DIE: ")
    if recovered:
        assert "recovery completed. Re-run" in v["died"]
    else:
        assert f"did not complete (exit {code})" in v["died"]
        assert "journal and recovery evidence remain in place" in v["died"]
        assert "Re-run this same verified" in v["died"]


def test_owed_recovery_is_routed_in_phase_3_before_any_phase_8_mutation():
    phase3 = INSTALL_SRC.index("# === PHASE 3 - Prior-operation routing")
    phase8 = INSTALL_SRC.index("# === PHASE 8 - Establish or verify the layout")
    branch = INSTALL_SRC.index("if ($LcCondition -eq 'recover_first') {", phase3)
    call = INSTALL_SRC.index("Complete-CfmOwedLifecycleRecovery", branch)
    assert phase3 < branch < call < phase8


def test_the_real_candidate_remains_installer_required():
    from corpusfm.lifecycle.update_boundary import classify

    assert classify(["corpusfm/lifecycle/installer_disposition.py"]).requires_installer
