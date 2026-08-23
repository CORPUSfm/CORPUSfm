"""Output-UX parity checks for the Windows installer (Batch 1 of the foundation-completion train).

install.ps1 + _cfm_lib.ps1 gained the same model the Linux side already ships (see
test_installer_logging.py): an always-on timestamped transcript, a concise console with full
command detail captured to the log, a -Verbose console stream, and a Die that points at the log.

Two layers, mirroring test_windows_install_trust.py (static) + test_installer_logging.py (behavioral):
  - STATIC text assertions on the .ps1 files (always run; PowerShell isn't on the Linux/macOS CI host);
  - a pwsh-gated behavioral harness that actually sources the library and exercises the primitives
    (runs only where `pwsh` exists, e.g. a Windows box or a dev box with PowerShell Core).
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_LIB = _ROOT / "installer/windows/_cfm_lib.ps1"
_PS1 = (_ROOT / "installer/windows/install.ps1").read_text()
_LIBTXT = _LIB.read_text()


# -- static: library carries the logging layer --------------------------------------------------

def test_lib_defines_logging_primitives():
    for fn in ("function Cfm-Ts", "function Cfm-Logline", "function Cfm-LogInit",
               "function Cfm-Run", "function Cfm-IsVerbose"):
        assert fn in _LIBTXT, f"{fn} missing from _cfm_lib.ps1"


def test_lib_primitives_write_to_transcript():
    # every canonical primitive + the section runner must log a timestamped line
    for prim in ("function Hello", "function Info", "function Ok", "function Warn", "function Die",
                 "function Section"):
        block = _LIBTXT[_LIBTXT.index(prim): _LIBTXT.index(prim) + 260]
        assert "Cfm-Logline" in block, f"{prim} must record to the transcript"


def test_lib_die_points_at_the_log():
    block = _LIBTXT[_LIBTXT.index("function Die"): _LIBTXT.index("function Die") + 320]
    assert "full install log" in block, "Die must print the transcript path"


def test_lib_loginit_reuses_env_and_exports_it():
    # reuse $env:CFM_LOG when already set; export it for children (mirror cfm_log_init)
    assert "$env:CFM_LOG" in _LIBTXT, "CFM_LOG env must be read/exported for transcript continuity"
    assert "if ($env:CFM_LOG)" in _LIBTXT, "Cfm-Log must initialise from $env:CFM_LOG when present"


def test_cfm_run_is_dash_safe_simple_function():
    # Cfm-Run must NOT use a declared remaining-args param: a flag like `-c` would bind by prefix to
    # `-Cmd`. It uses $args (no binding) instead.
    block = _LIBTXT[_LIBTXT.index("function Cfm-Run"): _LIBTXT.index("function Cfm-Run") + 700]
    assert "ValueFromRemainingArguments" not in block, "Cfm-Run must avoid remaining-args binding (dash-flag collision)"
    assert "$args" in block, "Cfm-Run must read its command from $args"


def test_cfm_run_avoids_tee_object_stop_pitfall():
    # capturing native stderr via 2>&1 under ErrorActionPreference='Stop' turns a benign warning into
    # a terminating error; Cfm-Run must force Continue locally around the call.
    block = _LIBTXT[_LIBTXT.index("function Cfm-Run"): _LIBTXT.index("function Cfm-Run") + 900]
    assert "$ErrorActionPreference = 'Continue'" in block, "Cfm-Run must neutralise stderr-as-error during capture"
    assert "Tee-Object" not in block, "Cfm-Run must not use the Tee-Object pattern that caused the prior break"


# -- static: install.ps1 wires the layer --------------------------------------------------------

def test_install_sets_verbose_from_builtin_switch():
    assert "$VerbosePreference -ne 'SilentlyContinue'" in _PS1, "verbose must derive from the built-in -Verbose"
    assert "$script:CfmVerbose = $true" in _PS1


def test_install_opens_transcript_early():
    assert "Cfm-LogInit" in _PS1, "install.ps1 must open the transcript"
    assert 'install-" + (Get-Date).ToString(' in _PS1, "transcript filename must be timestamped"
    # opened in Self-check (after the admin check), before the heavy Progress work
    i_init = _PS1.index("Cfm-LogInit")
    i_progress = _PS1.index('Section "Progress"')
    assert i_init < i_progress, "transcript must be opened before the Progress section"


def test_install_routes_pip_through_cfm_run():
    for label in ('Cfm-Run "pip upgrade"', 'Cfm-Run "pip install (locked)"',
                  'Cfm-Run "pip install (unpinned)"', 'Cfm-Run "pip bootstrap"'):
        assert label in _PS1, f"{label} must run through Cfm-Run (transcript capture + concise console)"


def test_install_drops_inline_quiet_now_that_log_captures_detail():
    # the old console-quieting flags are gone: full detail lives in the transcript instead
    assert "pip install --quiet --upgrade pip" not in _PS1
    assert "pip install -q -r $reqFile" not in _PS1
    assert "$getpip --no-warn-script-location 2>&1 | Out-Null" not in _PS1


def test_install_prints_transcript_path_in_next_steps():
    assert "Install transcript: " in _PS1, "Next steps must surface the transcript path"


def test_install_documents_verbose_flag():
    assert "-Verbose" in _PS1, "help block must document -Verbose"


# -- behavioral: source the library and exercise it (pwsh only) ----------------------------------

pwsh = shutil.which("pwsh")
ps_gate = pytest.mark.skipif(pwsh is None, reason="pwsh not available")


def _run_ps(body: str, tmp_path: pathlib.Path) -> subprocess.CompletedProcess:
    script = f". '{_LIB}'\n{body}\n"
    f = tmp_path / "t.ps1"
    f.write_text(script)
    return subprocess.run([pwsh, "-NoProfile", "-File", str(f)], capture_output=True, text=True)


@ps_gate
def test_ps_transcript_captures_primitives_and_sections(tmp_path):
    log = tmp_path / "install.log"
    r = _run_ps(f'Cfm-LogInit "{log}"\nSection "Hello"\nInfo "narrate"\nOk "did it"\nWarn "careful"', tmp_path)
    assert r.returncode == 0, r.stderr
    body = log.read_text()
    assert "transcript opened" in body
    assert "S1  Hello" in body
    assert "narrate" in body and "did it" in body and "careful" in body


@ps_gate
def test_ps_cfm_run_concise_hides_but_logs(tmp_path):
    log = tmp_path / "install.log"
    r = _run_ps(f'Cfm-LogInit "{log}"\n$script:CfmVerbose=$false\n'
                'Cfm-Run "probe" bash -c "echo OUT_LINE; echo ERR_LINE 1>&2"', tmp_path)
    assert r.returncode == 0, r.stderr
    assert "OUT_LINE" not in r.stdout and "ERR_LINE" not in r.stdout
    body = log.read_text()
    assert "[probe]" in body and "OUT_LINE" in body and "ERR_LINE" in body


@ps_gate
def test_ps_cfm_run_verbose_shows_on_console(tmp_path):
    log = tmp_path / "install.log"
    r = _run_ps(f'Cfm-LogInit "{log}"\n$script:CfmVerbose=$true\n'
                'Cfm-Run "probe" bash -c "echo SEEN_LINE"', tmp_path)
    assert r.returncode == 0, r.stderr
    assert "SEEN_LINE" in r.stdout
    assert "SEEN_LINE" in log.read_text()


@ps_gate
def test_ps_cfm_run_propagates_exit_code(tmp_path):
    log = tmp_path / "install.log"
    r = _run_ps(f'Cfm-LogInit "{log}"\nCfm-Run "fail" bash -c "exit 7"\nWrite-Host "rc=$LASTEXITCODE"', tmp_path)
    assert r.returncode == 0, r.stderr
    assert "rc=7" in r.stdout  # the caller's NeedExit $LASTEXITCODE path sees the real failure


@ps_gate
def test_ps_die_points_at_the_log(tmp_path):
    log = tmp_path / "install.log"
    r = _run_ps(f'Cfm-LogInit "{log}"\nDie "boom"', tmp_path)
    assert r.returncode == 1
    assert "boom" in (r.stdout + r.stderr)
    assert str(log) in (r.stdout + r.stderr)
    assert "boom" in log.read_text()


@ps_gate
def test_ps_no_transcript_preserves_passthrough(tmp_path):
    r = _run_ps('Ok "plain ok"\nCfm-Run "x" bash -c "echo PASSTHROUGH"', tmp_path)
    assert r.returncode == 0, r.stderr
    assert "plain ok" in r.stdout
    assert "PASSTHROUGH" in r.stdout
