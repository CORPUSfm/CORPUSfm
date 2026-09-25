r"""No shipped installer surface INSTRUCTS or USES an execution-policy override (1380-02 D20).

The sibling of `tests/test_no_bypass_instruction.py` in the application repository, for the half of
the thirteen-row inventory that lives here. **The rule, not the spelling** (`CLAUDE.md` § *Assert what
must be TRUE*): a guard that pins `-ExecutionPolicy Bypass` verbatim dies the moment the flag is
removed, and the property it was defending stops being checked silently.

**Why removing the flag was safe at each site, measured rather than assumed.**

* The installed launcher and the rendered updater are *local files with no Mark of the Web*, which
  RemoteSigned already permits.
* The bootstrap's delegation target is extracted with `Invoke-WebRequest -OutFile` + `Expand-Archive`,
  neither of which applies Mark of the Web (parent 1380 section 3.5, measured).
* Under AllSigned the authority is the organization's deployed publisher leaf, which the D-O preflight
  requires before the first mutation - an override would not have supplied one.

**A ban on RECOMMENDING Bypass is not a ban on prose that forbids it** (D-J), so the scan tolerates a
line that names the flag in order to rule it out.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Both spellings: the command line, and the argv-vector form used by delegation sites.
_INVOCATION = re.compile(
    r"""-ExecutionPolicy['"]?\s*,?\s*['"]?\s*(Bypass|Unrestricted)""",
    re.IGNORECASE | re.VERBOSE,
)

#: Prose that rules the flag OUT rather than recommending it.
_FORBIDS = re.compile(r"\b(do not|don't|never|no|without|forbid|refus|instead of|not use|"
                      r"would not|cannot|must not)\b", re.IGNORECASE)

#: Every shipped surface: the Windows scripts, the bootstrap, and the packager that writes
#: READ-ME-FIRST.txt (the first thing an administrator reads).
SURFACES = [
    ROOT / "installer/windows/install.ps1",
    ROOT / "installer/windows/uninstall.ps1",
    ROOT / "installer/windows/corpusfm-update.ps1",
    ROOT / "installer/bootstrap/windows/bootstrap.ps1",
    ROOT / "installer/package-installer.sh",
]

def _comment_stripped(path: Path, text: str) -> list[tuple[int, str]]:
    """Drop `#` comments so the guard cannot trip over its own rationale.

    `CLAUDE.md` records this mistake being made twice in one day. Several comments added by this
    packet name the flag in order to explain its removal; matching prose to excuse them would make
    the guard depend on how a future comment is worded. String literals are KEPT - the argv form
    lives in them.
    """
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line
        # Both file kinds use `#`. Only strip when it is not inside an obvious quoted span.
        hash_at = stripped.find("#")
        if hash_at != -1:
            before = stripped[:hash_at]
            if before.count("'") % 2 == 0 and before.count('"') % 2 == 0:
                stripped = before
        out.append((number, stripped))
    return out


def _label(path: Path) -> str:
    """Name the file for a failure message.

    `relative_to` RAISES for a path outside the repository, and the poisoned controls write to
    pytest's tmp_path. This is the SECOND time this bug was written in one session: it was fixed in
    the application repository's sibling guard and then reintroduced here by authoring this file
    fresh instead of carrying the fix across. The symptom is worse than a plain failure - the
    control crashes *before reaching the detection logic*, so the guard proves nothing while the
    suite still reports most tests passing.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return path.name


def _violations(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out = []
    for number, line in _comment_stripped(path, text):
        if _INVOCATION.search(line) and not _FORBIDS.search(line):
            out.append(f"{_label(path)}:{number}: {line.strip()[:110]}")
    return out


def test_no_shipped_installer_surface_overrides_execution_policy():
    assert SURFACES, "nothing scanned - the guard would pass vacuously"
    bad = []
    for path in SURFACES:
        bad += _violations(path)
    assert not bad, (
        "a shipped installer surface instructs or uses an execution-policy override, which D20 "
        "forbids:\n  " + "\n  ".join(bad)
    )


def test_no_installer_surface_runs_an_encoded_command():
    """Packet 1380-02 D-C retired the last `-EncodedCommand` site and its temporary allowance.

    Policy governs script FILES, not commands, so a generated program cannot be signed or refused by
    any execution policy. Lifecycle recovery is now a static file invocation; nothing may regress to
    composing a command.
    """
    bad = []
    for path in SURFACES:
        for number, code in _comment_stripped(path, path.read_text(encoding="utf-8")):
            if "-encodedcommand" in code.lower():
                bad.append(f"{_label(path)}:{number}: {code.strip()[:110]}")
    assert not bad, "an installer surface runs -EncodedCommand again:\n  " + "\n  ".join(bad)


def test_the_four_operator_instruction_sites_are_clean():
    """The rows an administrator actually reads, named individually so a regression is specific."""
    install = (ROOT / "installer/windows/install.ps1").read_text(encoding="ascii")
    uninstall = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
    packager = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")

    assert "powershell -File install.ps1 [options]" in install
    assert "powershell -File uninstall.ps1 [options]" in uninstall
    assert "powershell -File install.ps1" in packager
    assert "then run: powershell -File install.ps1 -Silent -Yes" in packager
    printed = next(l for l in install.splitlines() if "- Installer: powershell" in l)
    assert "-ExecutionPolicy" not in printed


def test_the_system_updater_task_registers_without_a_policy_override():
    """The elevated task is CORPUSfm's own invocation, so D20 binds it too."""
    install = (ROOT / "installer/windows/install.ps1").read_text(encoding="ascii")
    action = next(l for l in install.splitlines()
                  if "-Argument (" in l and "$UpdaterDst" in l)
    assert "-NonInteractive" in action and "-NoProfile" in action and "-File" in action
    assert "-ExecutionPolicy" not in action and "Bypass" not in action


def test_the_bootstrap_delegates_without_a_policy_override():
    boot = (ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_text(encoding="ascii")
    delegate = boot[boot.index("$delegate = @("):boot.index("if ($Yes) { $delegate")]
    assert "'-NoProfile'" in delegate and "'-File'" in delegate
    assert "ExecutionPolicy" not in delegate and "Bypass" not in delegate


def test_guard_says_wrong_to_a_real_override(tmp_path):
    """The poisoned half. Unconditional: a control that cannot fail is not a control."""
    cmdline = tmp_path / "a.ps1"
    cmdline.write_text("powershell -ExecutionPolicy Bypass -File install.ps1\n")
    assert _violations(cmdline), "missed the command-line spelling"

    argv = tmp_path / "b.ps1"
    argv.write_text("$d = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $p)\n")
    assert _violations(argv), "missed the argv spelling"

    unrestricted = tmp_path / "c.sh"
    unrestricted.write_text("powershell -ExecutionPolicy Unrestricted -File install.ps1\n")
    assert _violations(unrestricted), "missed Unrestricted"


def test_guard_stays_quiet_about_prose_that_forbids_the_flag(tmp_path):
    """The clean half - vacuous without it, since a guard that flags everything scores perfectly."""
    ok = tmp_path / "ok.ps1"
    ok.write_text("# NO -ExecutionPolicy Bypass (D20): the deployed leaf is the authority.\n"
                  "$d = @('-NoProfile', '-File', $p)\n")
    assert not _violations(ok), "falsely flagged a comment that FORBIDS the flag"
