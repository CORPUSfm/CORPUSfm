r"""Packet 1380-02 - the static Windows updater derives its paths from fixed authority.

**Evidence class.** `Get-CfmUpdaterRootVerdict` and `Get-CfmUpdaterPaths` are extracted from the
shipped `corpusfm-update.ps1` and EXECUTED under PowerShell 7 against injected facts. That is
supporting evidence only: the HKLM locator read, the manifest read and a SYSTEM run are Gate 3
evidence on Windows PowerShell 5.1.

**The rule.** The installation root is the fixed locator's `install_dir`, corroborated by the manifest
it names, and the updater must be running from that root's `bin`. Every other path is fixed beneath
that root or in the fixed OS layout, and agrees with the application's own derivation.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PureWindowsPath

import pytest

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "installer/windows/corpusfm-update.ps1"
SRC = UPDATER.read_text(encoding="ascii")
PWSH = shutil.which("pwsh") or shutil.which("powershell")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell available to execute decisions")

INST = "aaaaaaaa-1111-4111-8111-bbbbbbbbbbbb"
INSTALL_DIR = r"C:\Program Files\CORPUSfm"


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


def _ps(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _run(functions: str, scenario: str) -> dict:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "scenario.ps1"
        path.write_text(functions + "\n\n" + scenario + "\n", encoding="ascii")
        proc = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                              capture_output=True, text=True, timeout=120)
    out = proc.stdout.strip()
    assert out, f"scenario produced no output.\nstderr:\n{proc.stderr}"
    return json.loads(out.splitlines()[-1])


def _root_verdict(**over) -> dict:
    facts = {"ScriptRoot": INSTALL_DIR + r"\bin", "LocatorId": INST, "ManifestId": INST,
             "LocatorInstallDir": INSTALL_DIR, "ManifestInstallDir": INSTALL_DIR}
    facts.update(over)
    args = " ".join(f"-{k} {_ps(v)}" for k, v in facts.items())
    return _run(_extract("Get-CfmUpdaterRootVerdict", SRC),
                f"$v = Get-CfmUpdaterRootVerdict {args}\n"
                "[pscustomobject]@{ allow=$v.Allow; reason=$v.Reason } | ConvertTo-Json -Compress")


@needs_pwsh
def test_an_agreeing_locator_manifest_and_location_is_accepted():
    assert _root_verdict() == {"allow": True, "reason": "ok"}
    # Windows paths compare case-insensitively; identities do not.
    assert _root_verdict(ManifestInstallDir=INSTALL_DIR.upper(),
                         ScriptRoot=INSTALL_DIR.lower() + r"\BIN") == {"allow": True, "reason": "ok"}


REFUSALS = [
    ({"LocatorId": ""}, "authority_unreadable"),
    ({"ManifestId": ""}, "authority_unreadable"),
    ({"LocatorInstallDir": "", "ManifestInstallDir": ""}, "authority_unreadable"),
    ({"ManifestId": "22222222-2222-4222-8222-222222222222"}, "locator_manifest_disagree"),
    ({"ManifestId": INST.upper()}, "locator_manifest_disagree"),
    ({"LocatorInstallDir": r"C:\CORPUSfm\..\Windows", "ManifestInstallDir": r"C:\CORPUSfm\..\Windows",
      "ScriptRoot": r"C:\CORPUSfm\..\Windows\bin"}, "install_dir_not_canonical"),
    ({"LocatorInstallDir": r"relative\CORPUSfm", "ManifestInstallDir": r"relative\CORPUSfm",
      "ScriptRoot": r"relative\CORPUSfm\bin"}, "install_dir_not_canonical"),
    ({"LocatorInstallDir": INSTALL_DIR + "\\", "ManifestInstallDir": INSTALL_DIR + "\\"},
     "install_dir_not_canonical"),
    ({"ManifestInstallDir": r"D:\Elsewhere"}, "install_dir_disagrees"),
    ({"ScriptRoot": r"C:\Users\admin\Downloads"}, "script_root_disagrees"),
    ({"ScriptRoot": INSTALL_DIR}, "script_root_disagrees"),
]


@needs_pwsh
@pytest.mark.parametrize("over,reason", REFUSALS, ids=[r for _, r in REFUSALS])
def test_every_disagreement_refuses_by_name(over, reason):
    assert _root_verdict(**over) == {"allow": False, "reason": reason}


@needs_pwsh
def test_the_fixed_paths_agree_with_the_application_derivation():
    from corpusfm.lifecycle import update_boundary as ub
    from corpusfm.lifecycle.os_layout import windows_os_layout

    def win(p) -> str:
        return str(PureWindowsPath(str(p)))

    layout = windows_os_layout()
    expected = {
        "InstallDir": INSTALL_DIR,
        "StateDir": win(layout.state_dir),
        "LogDir": win(layout.log_dir),
        "Src": win(PureWindowsPath(INSTALL_DIR) / ub.CHECKOUT_DIRNAME),
        "Py": ub._interpreter_path("windows", INSTALL_DIR),
        "Helper": win(ub.helper_path(INSTALL_DIR)),
        "Publisher": win(ub.publisher_path(INSTALL_DIR)),
        "LibDir": win(ub.library_path(INSTALL_DIR)),
        "Git": win(PureWindowsPath(INSTALL_DIR).joinpath(*ub.WINDOWS_GIT_RELATIVE.split("\\"))),
    }
    v = _run(_extract("Get-CfmUpdaterPaths", SRC),
             f"Get-CfmUpdaterPaths {_ps(INSTALL_DIR)} | ConvertTo-Json -Compress")
    assert v == expected


def test_the_updater_takes_no_input_and_refuses_before_using_a_derived_path():
    """No parameter, environment variable or data file selects a path, and nothing derived from the
    locator is used until the verdict has accepted it."""
    head = SRC[:SRC.index("$ErrorActionPreference")]
    assert "[CmdletBinding()]\nparam()" in head
    assert "ValueFromRemainingArguments" not in SRC
    code = "\n".join(line.split("#", 1)[0] for line in SRC.splitlines())
    derivation = code[code.index("$LocatorRoot = "):code.index("$UpdaterLayout = Get-CfmUpdaterPaths")]
    assert "$env:" not in derivation and "$args" not in derivation
    assert "if (-not $RootVerdict.Allow)" in derivation, "the derived root is used before it is judged"
    assert "$LocatorRoot = 'HKLM:\\SOFTWARE\\CORPUSfm\\Installation'" in derivation


def test_the_updater_carries_no_rendered_placeholder():
    assert re.findall(r"@@\w+@@", SRC) == []
