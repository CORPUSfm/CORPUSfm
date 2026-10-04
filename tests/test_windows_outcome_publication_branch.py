"""The Windows updater's publication branch, EXECUTED: a refused publication must not finalize.

`Write-Outcome` hands the record to the installed publisher and finalizes the ACTIVE request only when
the publisher exits 0. On the public 0.3007 box the publisher exited 2, the request stayed ACTIVE and
every later check answered `update_in_progress` until the task was re-run — the designed, recoverable
result. These run the shipped function (with its own `Invoke-Fixed` / `New-ChildEnvironment`) under
PowerShell against the real publisher and the real `update_boundary`, so a later edit that finalized
regardless of the exit status, or finalized the wrong trigger, fails here.

The refusal is induced by a directory at the outcome path, which makes the publisher's rename fail on
any platform. It proves the branch, not the Windows file-sharing cause; that stays on a real box.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from corpusfm.lifecycle import update_boundary as ub
from tests import updater_installation as _ui

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "installer/windows/corpusfm-update.ps1").read_text(encoding="ascii")
PWSH = shutil.which("pwsh") or shutil.which("powershell")
pytestmark = pytest.mark.skipif(PWSH is None, reason="no PowerShell available to execute the branch")

ZERO = "0" * 40
TRIGGER = "upd_branch0000000001"
FUNCTIONS = ("New-ChildEnvironment", "Encode-WindowsArgv", "Encode-WindowsCommandLine",
             "Invoke-Fixed", "Write-Log", "Write-Outcome")


def _extract(name: str) -> str:
    start = SRC.index(f"function {name}")
    depth, i = 0, SRC.index("{", start)
    while True:
        if SRC[i] == "{":
            depth += 1
        elif SRC[i] == "}":
            depth -= 1
            if depth == 0:
                return SRC[start:i + 1]
        i += 1


def _ps(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@pytest.fixture
def box(tmp_path):
    install = tmp_path / "install"
    _ui.install_administrator_files(install)
    state = tmp_path / "state"
    (state / "update-inbox").mkdir(parents=True)
    (state / "update-outcome").mkdir(parents=True)
    (tmp_path / "temp").mkdir()
    return dict(install=install, state=state, log=tmp_path / "update.log", temp=tmp_path / "temp")


def _claim(box) -> None:
    ub.publish_request(box["state"], trigger_id=TRIGGER, expected_head=ZERO, actor="update_check")
    assert ub.claim_request(box["state"]).disposition == "run"


def _write_outcome(box, *, trigger: str = TRIGGER) -> None:
    install = box["install"]
    prelude = "\n".join([
        f"$SystemDirectory = {_ps(Path(sys.executable).parent)}",
        "$SystemRoot = '/'",
        f"$ChildTemp = {_ps(box['temp'])}",
        f"$InstallDir = {_ps(install)}",
        f"$Py = {_ps(sys.executable)}",
        f"$Publisher = {_ps(install / ub.HELPER_DIRNAME / ub.PUBLISHER_FILENAME)}",
        f"$LibDir = {_ps(install / ub.LIBRARY_DIRNAME)}",
        f"$StateDir = {_ps(box['state'])}",
        f"$LogFile = {_ps(box['log'])}",
        "$PyEnv = New-ChildEnvironment -Kind python",
        "$script:OpId = 'op-branch'",
        "$script:Started = '2026-10-04T00:00:00Z'",
        f"$script:TriggerId = {_ps(trigger)}",
        f"$script:Requested = {_ps(ZERO)}",
        "$script:Observed = ''",
        "$script:ResultHead = ''",
        "Write-Outcome 'refused' 'target_changed' 'branch test' $false",
    ])
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "scenario.ps1"
        path.write_text("\n\n".join(_extract(n) for n in FUNCTIONS) + "\n\n" + prelude + "\n",
                        encoding="ascii")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                              capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr


def _log(box) -> str:
    return box["log"].read_text(encoding="utf-8") if box["log"].exists() else ""


def test_a_refused_publication_skips_finalization(box):
    _claim(box)
    ub.outcome_path(box["state"]).mkdir()                    # the publisher's rename now fails
    _write_outcome(box)
    assert "NO OUTCOME PUBLISHED (publisher exit 2)" in _log(box)
    assert ub.active_request_path(box["state"]).exists()
    assert json.loads(ub.active_request_path(box["state"]).read_text())["trigger_id"] == TRIGGER
    resumed = ub.claim_request(box["state"])
    assert (resumed.disposition, resumed.trigger_id, resumed.resumed) == ("run", TRIGGER, True)


def test_a_successful_publication_finalizes_the_matching_request(box):
    _claim(box)
    _write_outcome(box)
    assert "NO OUTCOME PUBLISHED" not in _log(box)
    assert ub.read_outcome(box["state"]).trigger_id == TRIGGER
    assert not ub.active_request_path(box["state"]).exists()
    assert ub.claim_request(box["state"]).disposition == "no_request"


def test_a_successful_publication_never_finalizes_a_different_request(box):
    _claim(box)
    _write_outcome(box, trigger="upd_someoneelse00001")
    assert ub.read_outcome(box["state"]).trigger_id == "upd_someoneelse00001"
    assert json.loads(ub.active_request_path(box["state"]).read_text())["trigger_id"] == TRIGGER


def test_the_retry_failure_then_resume_path_converges(box):
    _claim(box)
    ub.outcome_path(box["state"]).mkdir()
    _write_outcome(box)
    assert ub.active_request_path(box["state"]).exists()
    ub.outcome_path(box["state"]).rmdir()                    # the obstruction clears; the task re-runs
    assert ub.claim_request(box["state"]).resumed is True
    _write_outcome(box)
    assert ub.read_outcome(box["state"]).trigger_id == TRIGGER
    assert not ub.active_request_path(box["state"]).exists()
