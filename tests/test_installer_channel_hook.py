"""Application packet 1399: both privileged updaters observe the installer channel, safely.

What must be TRUE, on each platform:

* the observation runs AFTER the fetch has produced two validated heads and the fast-forward proof,
  and BEFORE classification, so an update that needs the installer is still observed;
* the observer and everything it imports load from the administrator-owned library, even when the
  interpreter itself puts the deployed checkout on `sys.path` (the Windows embeddable `._pth` does,
  and ignores `PYTHONPATH`; the Linux venv's `.pth` binds the checkout too);
* a run that does not complete removes the previous answer, and never fails, refuses or stops the
  update.

The loading property is proven by EXECUTING the boot line each script actually carries, under an
interpreter whose own site configuration places a decoy checkout on `sys.path`, against a copy of the
application library. A string match could not tell the difference.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
MODULE = "corpusfm.lifecycle.installer_channel_observer"
RECORD = "installer_channel.json"

LINUX = ROOT / "installer/linux/corpusfm-update.sh"
WINDOWS = ROOT / "installer/windows/corpusfm-update.ps1"
DEPLOYED, TARGET = "a" * 40, "c" * 40


def _code(path: Path) -> str:
    return "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))


def _boot(path: Path) -> str:
    pattern = r"^CHANNEL_BOOT='([^']*)'$" if path == LINUX else r"^\$ChannelBoot = '([^']*)'$"
    found = re.findall(pattern, path.read_text(encoding="utf-8"), re.M)
    assert len(found) == 1, f"{path.name} must carry exactly one channel boot line"
    return found[0]


def _application_boot() -> str:
    from corpusfm.lifecycle.installer_channel_observer import BOOT

    return BOOT


# ── placement ─────────────────────────────────────────────────────────────────────────


def _placed_correctly(code: str, fetched: str, fast_forward: str, classify: str) -> bool:
    if code.count(MODULE) != 1:
        return False
    at = code.index(MODULE)
    return code.index(fetched) < code.index(fast_forward) < at < code.index(classify)


PLACEMENTS = [
    (LINUX, "fetch --quiet origin main", "not_fast_forward", 'CHANGED="$('),
    (WINDOWS, "'fetch', '--quiet', 'origin', 'main'", "not_fast_forward", "$changed = (Invoke-Git"),
]


@pytest.mark.parametrize(("path", "fetched", "fast_forward", "classify"), PLACEMENTS)
def test_the_observation_sits_between_the_fast_forward_proof_and_classification(path, fetched, fast_forward, classify):
    assert _placed_correctly(_code(path), fetched, fast_forward, classify)


@pytest.mark.parametrize(("path", "fetched", "fast_forward", "classify"), PLACEMENTS)
def test_the_placement_rule_rejects_a_hook_moved_after_classification(path, fetched, fast_forward, classify):
    """Control: the same rule, applied to a copy with the boot line moved after classification, fails."""
    code = _code(path)
    line = next(l for l in code.splitlines() if MODULE in l)
    moved = code.replace(line, "")
    tail = moved.index(classify)
    after = moved.index("\n\n", tail)
    poisoned = moved[:after] + "\n" + line + moved[after:]
    assert not _placed_correctly(poisoned, fetched, fast_forward, classify)


@pytest.mark.parametrize("path", [LINUX, WINDOWS])
def test_each_script_carries_the_observer_s_own_boot_line(path):
    assert _boot(path) == _application_boot()


# ── loading: executed, under an interpreter that puts a decoy checkout on sys.path ────


@pytest.fixture(scope="module")
def box(tmp_path_factory):
    """An install root with a copy of the application library, a decoy checkout, and a venv whose
    site configuration binds that decoy — what `._pth` (Windows) and the `.pth` (Linux) both do."""
    root = tmp_path_factory.mktemp("box")
    install = root / "install"
    shutil.copytree(APPLICATION_ROOT / "corpusfm", install / "lib" / "corpusfm",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    decoy = root / "src" / "corpusfm" / "lifecycle"
    decoy.mkdir(parents=True)
    (decoy.parent / "__init__.py").write_text("")
    (decoy / "__init__.py").write_text("")
    (decoy / "installer_channel_observer.py").write_text(
        "import pathlib, sys\n"
        f"pathlib.Path({str(root / 'DECOY_RAN')!r}).write_text('loaded from the checkout')\n"
        "def entry(library, argv):\n    return 0\n")
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(root / "venv")], check=True)
    python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site = subprocess.run([str(python), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                          check=True, capture_output=True, text=True).stdout.strip()
    Path(site, "deployed-checkout.pth").write_text(str(root / "src") + "\n")
    return root, install, python


def _run(box, boot: str, *, extra_env=None):
    root, install, python = box
    (root / "DECOY_RAN").unlink(missing_ok=True)
    state = root / "state"
    (state / "update-outcome").mkdir(parents=True, exist_ok=True)
    record = state / "update-outcome" / RECORD
    record.write_text("{}")                          # a previous answer the run must not leave behind
    env = {"PATH": os.environ.get("PATH", "")}
    env.update(extra_env or {})
    proc = subprocess.run([str(python), "-I", "-c", boot, str(install / "lib"), str(state), str(root / "src"),
                           "git", str(install), DEPLOYED, TARGET],
                          cwd=root / "src", env=env, capture_output=True, text=True, timeout=120)
    return proc, (root / "DECOY_RAN").exists(), record.exists()


def test_the_emulated_checkout_binding_is_real(box):
    """Control: with no explicit library insert, the interpreter loads the decoy checkout."""
    boot = _application_boot().replace("sys.path.insert(0, sys.argv[1]); ", "")
    _, decoy_ran, _ = _run(box, boot)
    assert decoy_ran


def test_the_previous_pythonpath_hook_loaded_the_checkout(box):
    """Control: `PYTHONPATH=lib -m …` (the first version) is defeated by an interpreter-supplied path."""
    root, install, python = box
    (root / "DECOY_RAN").unlink(missing_ok=True)
    subprocess.run([str(python), "-I", "-m", MODULE], cwd=root / "src", capture_output=True,
                   env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(install / "lib")}, timeout=120)
    assert (root / "DECOY_RAN").exists()


@pytest.mark.parametrize("path", [LINUX, WINDOWS])
def test_each_script_s_boot_line_loads_the_protected_library(box, path):
    proc, decoy_ran, record_left = _run(box, _boot(path))
    assert not decoy_ran, "the observer was loaded from the deployed checkout"
    assert proc.returncode == 0, proc.stderr[-400:]
    # The real observer ran: it found no published installation, so it bound no operands and
    # removed the previous answer rather than leave it standing.
    assert not record_left


def test_a_library_that_is_not_the_installation_s_own_is_refused(box):
    """The observer refuses (exit 3) and removes the previous answer when it was not loaded from
    `<install_dir>/lib` — here the boot line is pointed at a second copy elsewhere."""
    root, install, _ = box
    other = root / "other-lib"
    if not other.exists():
        shutil.copytree(install / "lib", other)
    boot = _application_boot().replace("sys.path.insert(0, sys.argv[1])", f"sys.path.insert(0, {str(other)!r})")
    proc, decoy_ran, record_left = _run(box, boot)
    assert (proc.returncode, decoy_ran, record_left) == (3, False, False)


# ── failure: the previous answer is removed, the update continues ─────────────────────


def _linux_hook() -> str:
    text = LINUX.read_text(encoding="utf-8")
    start = text.index("CHANNEL_BOOT=")
    end = text.index("\nfi\n", start) + 4
    return text[start:end]


@pytest.mark.parametrize("interpreter", ["/bin/false", "/nonexistent/python"])
def test_the_linux_hook_removes_the_record_when_the_observer_does_not_complete(tmp_path, interpreter):
    (tmp_path / "update-outcome").mkdir()
    record = tmp_path / "update-outcome" / RECORD
    record.write_text('{"state": "eligible"}')
    script = (f'set -euo pipefail\nlog() {{ echo "LOG $*"; }}\nVENV_PY={interpreter}\nLIB_DIR=/x\n'
              f'STATE_DIR={tmp_path}\nSRC=/x\nGIT=/x\nINSTALL_DIR=/x\nOLD_HEAD={DEPLOYED}\n'
              f'OBSERVED={TARGET}\n' + _linux_hook() + 'echo CONTINUED\n')
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and "CONTINUED" in proc.stdout
    assert "LOG installer channel observation did not complete" in proc.stdout
    assert not record.exists()


def _ps_function(text: str, name: str) -> str:
    match = re.search(rf"^function {re.escape(name)}\b.*?^}}[ \t]*$", text, re.M | re.S)
    assert match, f"{name} is not defined at top level in {WINDOWS.name}"
    return match.group(0)


def _windows_hook_harness(tmp_path, interpreter: str, *, body: str | None = None) -> str:
    text = WINDOWS.read_text(encoding="utf-8")
    functions = "\n\n".join(_ps_function(text, name) for name in
                            ("Encode-WindowsArgv", "Encode-WindowsCommandLine", "Invoke-Fixed"))
    start = text.index("$ChannelBoot =")
    hook = body if body is not None else text[start:text.index("# CLASSIFY.", start)]
    outcome = tmp_path / "update-outcome"
    return "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "function Write-Log($msg) { Write-Output ('LOG ' + $msg) }",
        functions,
        f"$Py = '{interpreter}'",
        "$PyEnv = @{ 'PATH' = $env:PATH }",
        f"$OutcomeDir = '{outcome}'",
        f"$StateDir = '{tmp_path}'",
        "$LibDir = '/x/lib'; $Src = '/x/src'; $Git = '/x/git'; $InstallDir = '/x'",
        f"$oldHead = '{DEPLOYED}'",
        f"$script:Observed = '{TARGET}'",
        hook,
        "Write-Output 'CONTINUED'",
    ])


def _pwsh(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=120)


needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell is not installed here")


@needs_pwsh
@pytest.mark.parametrize("interpreter", ["/nonexistent/python.exe", "/usr/bin/false"])
def test_the_windows_hook_removes_the_record_when_the_observer_does_not_complete(tmp_path, interpreter):
    """EXECUTED: the script's own Invoke-Fixed and hook, with an interpreter that cannot start (Invoke-Fixed
    throws) and one that exits non-zero. Both must remove the previous record and let the run continue."""
    (tmp_path / "update-outcome").mkdir()
    record = tmp_path / "update-outcome" / RECORD
    record.write_text('{"state": "eligible"}')
    proc = _pwsh(_windows_hook_harness(tmp_path, interpreter))
    assert proc.returncode == 0 and "CONTINUED" in proc.stdout, proc.stdout + proc.stderr
    assert "LOG installer channel observation did not complete" in proc.stdout
    assert not record.exists()


@needs_pwsh
def test_control_invoke_fixed_throws_for_an_interpreter_that_cannot_start(tmp_path):
    """The premise of the correction: without the try, the launch failure escapes the hook."""
    (tmp_path / "update-outcome").mkdir()
    record = tmp_path / "update-outcome" / RECORD
    record.write_text('{"state": "eligible"}')
    unguarded = ("$channel = Invoke-Fixed -FilePath $Py -Environment $PyEnv -Arguments @('-I')\n"
                 "if ($channel.ExitCode -ne 0) { Remove-Item -LiteralPath (Join-Path $OutcomeDir "
                 "'installer_channel.json') -Force -ErrorAction SilentlyContinue }")
    proc = _pwsh(_windows_hook_harness(tmp_path, "/nonexistent/python.exe", body=unguarded))
    assert "CONTINUED" not in proc.stdout and record.exists()


def test_the_windows_hook_removes_the_record_and_cannot_stop_the_run():
    code = _code(WINDOWS)
    start = code.index("$ChannelBoot =")
    block = code[start:code.index("$changed = (Invoke-Git", start)]
    failure = block[block.index("if (-not $channelCompleted)"):]
    assert re.search(r"try \{\s*\$channel = Invoke-Fixed", block), "the launch itself must be inside the try"
    assert "Remove-Item -LiteralPath (Join-Path $OutcomeDir 'installer_channel.json')" in failure
    assert "'-I', '-c', $ChannelBoot, $LibDir" in block
    assert not re.search(r"Stop-With|\bexit\b|throw", block)


def test_the_linux_hook_cannot_stop_the_run():
    hook = "\n".join(l for l in _linux_hook().splitlines() if not l.lstrip().startswith("#"))
    assert '"$VENV_PY" -I -c "$CHANNEL_BOOT" "$LIB_DIR"' in hook
    assert not re.search(r"\bdie\b|\bexit\b", hook)
