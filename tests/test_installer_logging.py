"""Functional checks for the installer's output-UX layer (Batch 4) in installer/linux/_cfm_lib.sh.

The library gained an always-on timestamped transcript + a concise/--verbose split + a die->log
pointer, WITHOUT changing the console behavior when no transcript is opened. These run a real bash
sourcing the library (skipped where bash is unavailable) and assert:
  - cfm_log_init opens a transcript that captures every primitive + section as a timestamped line;
  - cfm_run captures a command's full stdout+stderr to the log, but shows it on the console only
    under CFM_VERBOSE (concise by default);
  - die appends the log path so a failed install points the operator at the transcript;
  - with no transcript opened, primitives + cfm_run behave exactly as before (console passthrough).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_LIB = Path(__file__).resolve().parent.parent / "installer" / "linux" / "_cfm_lib.sh"
_INSTALLER = Path(__file__).resolve().parent.parent / "installer" / "linux" / "install.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _run(script: str, tmp_path: Path) -> subprocess.CompletedProcess:
    body = f"source {_LIB}\n{script}\n"
    sh = tmp_path / "t.sh"
    sh.write_text(body)
    return subprocess.run(["bash", str(sh)], capture_output=True, text=True)


def test_transcript_captures_primitives_and_sections(tmp_path):
    log = tmp_path / "install.log"
    r = _run(f'cfm_log_init "{log}"\ncfm_section "Hello"\ninfo "narrate"\nok "did it"\nwarn "careful"', tmp_path)
    assert r.returncode == 0
    body = log.read_text()
    assert "=== transcript opened" in body
    assert "=== S1  Hello ===" in body
    assert "> narrate" in body and "+ did it" in body and "! careful" in body
    # timestamped lines (YYYY-MM-DD HH:MM:SS prefix)
    assert any(line[:4].isdigit() and line[4] == "-" for line in body.splitlines() if line.strip())


def test_cfm_run_concise_hides_output_from_console_but_logs_it(tmp_path):
    log = tmp_path / "install.log"
    r = _run(f'cfm_log_init "{log}"\nCFM_VERBOSE=false\n'
             'cfm_run "probe" bash -c \'echo OUT_LINE; echo ERR_LINE >&2\'', tmp_path)
    assert r.returncode == 0
    # concise: the command's output is NOT on the console
    assert "OUT_LINE" not in r.stdout and "ERR_LINE" not in r.stdout
    # but the transcript captured both streams + the labeled command line
    body = log.read_text()
    assert "[probe]" in body and "OUT_LINE" in body and "ERR_LINE" in body


def test_cfm_run_verbose_shows_output_on_console(tmp_path):
    log = tmp_path / "install.log"
    r = _run(f'cfm_log_init "{log}"\nCFM_VERBOSE=true\n'
             'cfm_run "probe" bash -c \'echo SEEN_LINE\'', tmp_path)
    assert r.returncode == 0
    assert "SEEN_LINE" in r.stdout
    assert "SEEN_LINE" in log.read_text()


def test_cfm_run_propagates_exit_code(tmp_path):
    log = tmp_path / "install.log"
    r = _run(f'cfm_log_init "{log}"\nif cfm_run "fail" bash -c \'exit 7\'; then echo RAN_OK; else echo "rc=$?"; fi',
             tmp_path)
    assert r.returncode == 0
    assert "rc=7" in r.stdout  # the caller's `|| die` path sees the real failure


def test_die_points_at_the_log(tmp_path):
    log = tmp_path / "install.log"
    r = _run(f'cfm_log_init "{log}"\ndie "boom"', tmp_path)
    assert r.returncode == 1
    assert "boom" in r.stderr
    assert str(log) in r.stderr  # the operator is pointed at the transcript
    assert "boom" in log.read_text()


def test_no_transcript_preserves_console_passthrough(tmp_path):
    # No cfm_log_init: primitives print to console; cfm_run runs the command with output on console.
    r = _run('ok "plain ok"\ncfm_run "x" echo PASSTHROUGH', tmp_path)
    assert r.returncode == 0
    assert "plain ok" in r.stdout
    assert "PASSTHROUGH" in r.stdout  # falls back to a normal command run


def test_linux_installer_opens_capture_before_diagnostics_and_keeps_one_log():
    body = _INSTALLER.read_text(encoding="utf-8")
    setup = body.index('CFM_LOG="${CFM_LOG:-/var/log/corpusfm/install-')
    start = body.index("=== early transcript opened")
    parse = body.index("while [[ $# -gt 0 ]]")
    locations = body.index("Installation locations (resolved before acquisition)")
    clock = body.index("A bad local clock can make TLS")
    acquire = body.index("Canonical source authority")
    finish = body.index("cfm_early_log_finish\ncfm_log_init")
    assert start < parse < locations < clock
    assert start < acquire < finish
    assert setup < start
    assert 'export CFM_LOG' in body[setup:finish]


# ── Batch 6 (packet 016): noisy command paths are folded through cfm_run ──────────
# The default console is section headers + one-line outcomes; command chatter (git pull diffstat,
# projection-backfill output) goes to the transcript and only reaches the console under --verbose.

def test_no_installer_ever_prints_the_bearer_token():
    """Neither installer provisions or prints the retired server-wide MCP credential."""
    import pathlib as _p
    root = _p.Path(__file__).resolve().parents[1] / "installer"
    offenders = []

    ps1 = (root / "windows" / "install.ps1").read_text(encoding="utf-8")
    assert "CORPUSFM_MCP_TOKEN" not in ps1
    for n, ln in enumerate(ps1.splitlines(), 1):
        body = ln.lstrip()
        if body.startswith("#"):
            continue
        if ("Write-Host" in ln or any(f"{p} (" in ln or f"{p}(" in ln for p in ("Ok", "Info", "Warn", "Die"))) \
                and "$Tok" in ln:
            offenders.append(f"install.ps1:{n}")

    sh = (root / "linux" / "install.sh").read_text(encoding="utf-8")
    assert "CORPUSFM_MCP_TOKEN" not in sh
    for n, ln in enumerate(sh.splitlines(), 1):
        body = ln.lstrip()
        if body.startswith("#"):
            continue
        if ("echo" in ln or "info " in ln or "ok " in ln) and "$TOKEN" in ln:
            offenders.append(f"install.sh:{n}")

    assert not offenders, (
        "an installer prints the MCP bearer token to the console (and thus to scrollback and any "
        f"terminal capture): {offenders}")


def test_no_installer_mints_a_global_mcp_token():
    """The retired credential must not return through either platform's former mint primitive."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "installer"
    ps1 = (root / "windows" / "install.ps1").read_text(encoding="utf-8")
    sh = (root / "linux" / "install.sh").read_text(encoding="utf-8")
    assert "token_hex(24)" not in ps1
    assert "openssl rand -hex 24" not in sh


def test_installer_summaries_print_the_asserted_address_not_a_placeholder():
    """The box knows where it can be reached; the summary must say so (packet 1194 closure).

    Both installers used to print `https://<your-fms-host>/corpusfm/` — seven sites — on a box that has
    detected and persisted its own address at startup since packet 1219. Telling the operator to work
    out what the machine already knows is consequence 1 of the Unknowable-Install Principle, in our own
    output.

    The rule asserted here is that no EMITTED line carries the placeholder: it may survive only as the
    fallback value, for the honest case where the app asserted nothing. Deliberately does not pin how
    the base is read — only that output uses a variable rather than a literal."""
    import pathlib as _p
    root = _p.Path(__file__).resolve().parents[1] / "installer"
    offenders = []

    for rel, is_comment in (("windows/install.ps1", lambda l: l.lstrip().startswith("#")),
                            ("linux/install.sh", lambda l: l.lstrip().startswith("#"))):
        for n, ln in enumerate((root / rel).read_text(encoding="utf-8").splitlines(), 1):
            if "your-fms-host" not in ln or is_comment(ln):
                continue
            # The one legitimate survivor: assigning the fallback.
            if "CFM_BASE=" in ln or "$Base =" in ln:
                continue
            offenders.append(f"{rel}:{n}")

    assert not offenders, (
        "an installer prints a placeholder hostname instead of the address the box asserted: "
        f"{offenders}")
