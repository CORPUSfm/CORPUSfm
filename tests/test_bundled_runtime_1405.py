"""Packet 1405 — bundled CPython runtime identity and Windows runtime recovery.

What must be true:
  - Linux and Windows ship the SAME exact CPython, from exact checksum-pinned artifacts;
  - the Windows runtime is only "healthy" when it is the pinned version AND `python -m pip --version`
    works (a matching interpreter without pip must be replaced, never skipped);
  - everything the replacement needs from the network is fetched BEFORE the destructive wipe;
  - once a transient fault is removed, an ordinary rerun restores a working runtime;
  - the service stop and installed-runtime process termination still precede the replacement.
"""
from __future__ import annotations

import hashlib
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SH = (ROOT / "installer/linux/install.sh").read_text()
PS1 = (ROOT / "installer/windows/install.ps1").read_text()

# Independently downloaded and hashed 2026-10-10 (packet 1405); sizes in bytes.
PY_VERSION = "3.13.16"
PBS_TAG = "20261001"
LINUX = {
    "x86_64": ("b55f90dfb060e998a47e4a811dae46aaa27b923244044bbcf88de5e57a5fa4c7", 75282113),
    "aarch64": ("e662f77a0c908d8f9555af85fb7fe636a7c34b0c86adc141f0f7b571bbaea6fd", 57629364),
}
WINDOWS_SHA256 = "97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297"
WINDOWS_SIZE = 11439094


def _sh(name: str) -> str:
    m = re.search(rf'^{name}="([^"]*)"', SH, re.M)
    assert m, name
    return m.group(1)


def test_linux_runtime_identity_is_exact():
    assert _sh("PY_FULL") == PY_VERSION
    assert _sh("PY_PBS_TAG") == PBS_TAG
    for arch, (sha, _size) in LINUX.items():
        assert re.search(rf'PY_ARCH="{arch}";\s+PY_SHA256="{sha}"', SH), arch
    assert 'PY_ASSET="cpython-${PY_FULL}+${PY_PBS_TAG}-${PY_ARCH}-unknown-linux-gnu-install_only.tar.gz"' in SH


def test_windows_runtime_identity_is_exact_and_matches_linux():
    assert f"$script:PythonRuntimeVersion = '{PY_VERSION}'" in PS1
    assert f"$script:PythonRuntimeSha256 = '{WINDOWS_SHA256}'" in PS1
    assert f"$script:PythonRuntimeSize = {WINDOWS_SIZE}" in PS1
    rec = PS1[PS1.index("$script:PythonEmbedRecord = @{"):PS1.index("$script:GetPipRecord = @{")]
    assert "'https://www.python.org/ftp/python/' + $script:PythonRuntimeVersion" in rec
    assert "Size = $script:PythonRuntimeSize" in rec and "Sha256 = $script:PythonRuntimeSha256" in rec


@pytest.mark.parametrize("path", ["installer/constraints-server-py313.txt",
                                  "installer/constraints-server-win-py313.txt"])
def test_lock_headers_name_the_pinned_runtime_and_do_not_overclaim(path):
    head = (ROOT / path).read_text().split("\n\n")[0]
    assert PY_VERSION in head
    assert "OWED" in head, "a lock not yet revalidated under the pinned runtime must say so"


# -- Windows runtime health + ordering (static) ---------------------------------------------------

def _function_block() -> str:
    a = PS1.index("function Ensure-BundledPython {")
    b = PS1.index("\n}\nEnsure-BundledPython", a)
    return PS1[a:b + 2]


def _state_block() -> str:
    a = PS1.index("function Get-BundledPythonState {")
    b = PS1.index("\n}\n", a)
    return PS1[a:b + 3]


def _primitive_block() -> str:
    a = PS1.index("# >>> verified-input primitive")
    b = PS1.index("# <<< verified-input primitive")
    return PS1[a:b]


def test_windows_health_requires_working_pip_not_an_import():
    health = _state_block()
    assert '-ne $script:PythonRuntimeVersion' in health
    assert "-m pip --version" in health
    assert "import pip" not in health and "import pip" not in _function_block()
    assert "Get-BundledPythonState" in _function_block()


def test_windows_fetches_everything_before_the_destructive_wipe():
    fn = _function_block()
    wipe = fn.index("Remove-Item $PyDir")
    for needle in ("Get-VerifiedInput $script:PythonEmbedRecord", "Get-VerifiedInput $script:GetPipRecord"):
        assert fn.index(needle) < wipe, needle
    assert "Get-File" not in fn and "bootstrap.pypa.io" not in fn


def test_windows_service_stop_and_process_cleanup_precede_replacement():
    stop = PS1.index("Stop-Service $svc -Force")
    kill = PS1.index("StartsWith($PyDir.ToLower())")
    fn = PS1.index("function Ensure-BundledPython {")
    call = PS1.index("\nEnsure-BundledPython\n")
    assert stop < kill < fn < call
    assert ("ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
            in PS1[kill:kill + 200])
    code = [l for l in PS1.splitlines() if not l.lstrip().startswith("#")]
    assert sum("Remove-Item $PyDir -Recurse -Force" in l for l in code) == 1, "the wipe lives only in the function"


def test_dependency_install_follows_a_healthy_runtime():
    assert PS1.index("\nEnsure-BundledPython\n") < PS1.index('Cfm-Run "pip upgrade"')


# -- Windows runtime recovery (behavioral; pwsh only) ---------------------------------------------

pwsh = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(pwsh is None, reason="pwsh not available")

FAKE_PYTHON = r"""#!/bin/bash
D="$(dirname "$0")"
case "$1" in
  -c) case "$2" in *platform*) cat "$D/version";; *) exit 0;; esac;;
  -m) [ "$2" = pip ] || exit 0; [ -f "$D/pip.ok" ] || exit 1; echo "pip 25.0";;
  *)  [ -f "$FAULT_GETPIP_RUN" ] && exit 1; touch "$D/pip.ok";;
esac
"""

HARNESS = r"""
$ErrorActionPreference = 'Stop'
# Emulates Windows PowerShell 5.1, where a failing native command terminates under 'Stop' (packet 1407).
$PSNativeCommandUseErrorActionPreference = $true
$Root = $env:H_ROOT
$PyDir = Join-Path $Root 'python'; $Py = Join-Path $PyDir 'python.exe'
$Dl = Join-Path $Root 'dl'; $Src = Join-Path $Root 'src'
$pyVer = '3.13.16'; $script:PythonRuntimeVersion = $pyVer
$InputsDir = Join-Path $Root 'inputs'
$script:PythonEmbedRecord = @{ File = 'python-embed.zip'; Name = 'test python'; Url = 'https://test.invalid/python.zip'
  Size = [int]$env:H_ZIP_LEN; Sha256 = $env:H_SHA }
$script:GetPipRecord = @{ File = 'get-pip.py'; Name = 'test get-pip'; Url = 'https://test.invalid/get-pip.py'
  Size = [int]$env:H_GP_LEN; Sha256 = $env:H_GP_SHA }
$log = Join-Path $Root 'calls.log'
function Info($m) {}; function Ok($m) {}; function Warn($m) {}
function Die($m) { throw "DIE: $m" }
function Get-File($url, $out) {
  Add-Content $log "get $url"
  if ($env:FAULT_FETCH -and $url -like "*$($env:FAULT_FETCH)*") { throw "DIE: Download failed: $url" }
  if ($url -like '*get-pip*') { Copy-Item $env:H_GP $out -Force } else { Copy-Item $env:H_ZIP $out -Force }
}
function Expand-Archive([string]$Path, [string]$DestinationPath, [switch]$Force) {
  Add-Content $log "expand"
  New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
  Set-Content (Join-Path $DestinationPath 'python.exe') $env:H_FAKEPY -NoNewline
  chmod +x (Join-Path $DestinationPath 'python.exe')
  Set-Content (Join-Path $DestinationPath 'version') $pyVer -NoNewline
  Set-Content (Join-Path $DestinationPath 'python313._pth') 'x'
}
function Cfm-Run($what, $exe) {   # like _cfm_lib's: the command runs under a scoped 'Continue'
  $e = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try { & $exe @args | Out-Null } finally { $ErrorActionPreference = $e }
}
"""


def _run(tmp_path: pathlib.Path, *, mutate=None, env_extra=None):
    root = tmp_path
    (root / "dl").mkdir(exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    zipf = root / "fake.zip"
    zipf.write_bytes(b"fake-archive")
    fake = root / "fakepy.sh"
    fake.write_text(FAKE_PYTHON)
    gp = root / "getpip.bin"
    gp.write_bytes(b"fake-get-pip")
    fn = _primitive_block() + _state_block() + _function_block()
    if mutate:
        fn = mutate(fn)
    script = root / "h.ps1"
    script.write_text(HARNESS + "\n" + fn + "\nEnsure-BundledPython\n'DONE'\n")
    import os
    env = dict(os.environ, H_ROOT=str(root), H_ZIP=str(zipf),
               H_SHA=hashlib.sha256(b"fake-archive").hexdigest(), H_FAKEPY=FAKE_PYTHON,
               H_ZIP_LEN=str(len(b"fake-archive")), H_GP=str(gp), H_GP_LEN=str(len(b"fake-get-pip")),
               H_GP_SHA=hashlib.sha256(b"fake-get-pip").hexdigest())
    env.update(env_extra or {})
    return subprocess.run([pwsh, "-NoProfile", "-File", str(script)], capture_output=True, text=True, env=env)


def _seed(root: pathlib.Path, *, version="3.13.16", pip=True, sentinel=True):
    py = root / "python"
    (py / "Lib" / "site-packages").mkdir(parents=True, exist_ok=True)
    exe = py / "python.exe"
    exe.write_text(FAKE_PYTHON)
    exe.chmod(0o755)
    (py / "version").write_text(version)
    if pip:
        (py / "pip.ok").write_text("")
    if sentinel:
        (py / "Lib" / "site-packages" / "sentinel.txt").write_text("x")


def _calls(root):
    f = root / "calls.log"
    return f.read_text().splitlines() if f.exists() else []


@needs_pwsh
def test_healthy_runtime_is_kept_so_a_dependency_retry_needs_no_wipe(tmp_path):
    _seed(tmp_path)
    r = _run(tmp_path)
    assert r.returncode == 0 and "DONE" in r.stdout, r.stderr
    assert _calls(tmp_path) == []
    assert (tmp_path / "python/Lib/site-packages/sentinel.txt").exists()


@needs_pwsh
def test_matching_python_without_working_pip_is_replaced(tmp_path):
    _seed(tmp_path, pip=False)
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "python/pip.ok").exists()
    assert not (tmp_path / "python/Lib/site-packages/sentinel.txt").exists()


@needs_pwsh
def test_old_version_is_replaced_even_with_working_pip(tmp_path):
    _seed(tmp_path, version="3.13.14")
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "python/version").read_text() == "3.13.16"


@needs_pwsh
def test_failed_get_pip_fetch_leaves_the_old_runtime_untouched(tmp_path):
    _seed(tmp_path, pip=False)
    r = _run(tmp_path, env_extra={"FAULT_FETCH": "get-pip"})
    assert r.returncode != 0 and "Download failed" in (r.stderr + r.stdout)
    assert "expand" not in _calls(tmp_path)
    assert (tmp_path / "python/Lib/site-packages/sentinel.txt").exists()


@needs_pwsh
def test_rerun_recovers_once_a_transient_pip_bootstrap_fault_is_removed(tmp_path):
    fault = tmp_path / "fault"
    fault.write_text("")
    env = {"FAULT_GETPIP_RUN": str(fault)}
    first = _run(tmp_path, env_extra=env)
    assert first.returncode != 0 and "pip bootstrap failed" in (first.stderr + first.stdout)
    py = tmp_path / "python"
    assert (py / "python.exe").exists() and not (py / "pip.ok").exists()   # the stranded state

    still_faulty = _run(tmp_path, env_extra=env)                            # fault still active
    assert still_faulty.returncode != 0 and not (py / "pip.ok").exists()

    fault.unlink()                                                           # transient fault removed
    healed = _run(tmp_path, env_extra=env)
    assert healed.returncode == 0 and "DONE" in healed.stdout, healed.stderr
    assert (py / "pip.ok").exists()


@needs_pwsh
def test_control_the_old_import_only_health_check_strands_the_rerun(tmp_path):
    # Discriminates the test above: with the pip check removed, a rerun trusts the stranded runtime.
    fault = tmp_path / "fault"
    fault.write_text("")
    env = {"FAULT_GETPIP_RUN": str(fault)}
    _run(tmp_path, env_extra=env)
    fault.unlink()

    def old_health(fn: str) -> str:   # the import-only predicate: no pip probe
        out = fn.replace("    & $Py -m pip --version 2>$null | Out-Null\n    $rc = $LASTEXITCODE\n    $state.Ok = ($rc -eq 0)\n",
                         "    $state.Ok = $true\n")
        assert out != fn
        return out

    r = _run(tmp_path, mutate=old_health, env_extra=env)
    assert r.returncode == 0
    assert not (tmp_path / "python/pip.ok").exists(), "old predicate would have skipped the bootstrap"
