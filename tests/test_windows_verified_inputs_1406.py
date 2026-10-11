"""Packet 1406 — Windows executable inputs are exact, verified, and staged before anything changes.

What must be true:
  - get-pip.py, MinGit and WinSW (and the embeddable Python) each have ONE record of exact URL, size
    and SHA-256, and nothing is discovered through `releases/latest` or fetched from a mutable URL;
  - the installed runtime and the packaged recovery runtime share one get-pip record;
  - every byte stream is verified BEFORE extraction, execution or placement; an empty, wrong-digest
    or one-byte-mutated download is refused and leaves no consumable staged file;
  - the inputs a plan newly needs are acquired before the first service stop.
Mutation controls prove the detectors fail when verification is bypassed, moved after use, or
`releases/latest` discovery returns.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PS1 = (ROOT / "installer/windows/install.ps1").read_text()
SPEC = (ROOT / "installer/SPEC.md").read_text()

# Independently downloaded and hashed 2026-10-10 (packet 1406).
IDENTITIES = {
    "GetPipRecord": (
        "https://raw.githubusercontent.com/pypa/get-pip/af54dfe793b24685f8dc4ebba0630d9f2d77653c/public/get-pip.py",
        2230488, "fb24e693bab954209a063d90953621412ccad4a500905a726286e038f508ddf6"),
    "MinGitRecord": (
        "https://github.com/git-for-windows/git/releases/download/v2.56.0.windows.2/MinGit-2.56.0.2-64-bit.zip",
        39806486, "da35e72aa21c005a5a0d298cfbae110bc1609a815730ea0dde84b01a1b3cd3be"),
    "WinSwRecord": (
        "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW.NET461.exe",
        655872, "b5066b7bbdfba1293e5d15cda3caaea88fbeab35bd5b38c41c913d492aadfc4f"),
}


def _code(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _record(name: str) -> str:
    a = PS1.index(f"$script:{name} = @{{")
    return PS1[a:PS1.index("}", a) + 1]


def _func(text: str, name: str) -> str:
    a = re.search(rf"function {re.escape(name)}\b[^\n]*\{{\n", text).start()
    return text[a:text.index("\n}\n", a) + 3]


def _primitive(text: str = PS1) -> str:
    return text[text.index("# >>> verified-input primitive"):text.index("# <<< verified-input primitive")]


# -- static: identities ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", sorted(IDENTITIES))
def test_executable_input_identity_is_exact(name):
    url, size, sha = IDENTITIES[name]
    rec = _record(name)
    assert f"Url = '{url}'" in rec
    assert f"Size = {size}" in rec
    assert f"Sha256 = '{sha}'" in rec


def test_no_mutable_or_latest_acquisition_of_executable_inputs():
    code = _code(PS1)
    assert _latest_lookups(PS1) == []
    assert "bootstrap.pypa.io" not in code
    assert "Get-Json" not in code
    assert PS1.count("raw.githubusercontent.com/pypa/get-pip/") == 1


def _latest_lookups(text: str) -> list[str]:
    return re.findall(r"[^\n]*releases/latest[^\n]*", _code(text))


# -- static: one get-pip record, one acquisition primitive, everything staged first ---------------

def test_normal_and_recovery_runtimes_share_one_get_pip_record():
    recovery = _func(PS1, "Initialize-PackagedRecoveryRuntime")
    normal = _func(PS1, "Ensure-BundledPython")
    assert "Get-VerifiedInput $script:GetPipRecord" in recovery
    assert "Get-VerifiedInput $script:GetPipRecord" in normal
    assert "Get-VerifiedInput $script:PythonEmbedRecord" in recovery
    assert PS1.count("$script:GetPipRecord = @{") == 1


def test_only_the_primitive_downloads():
    outside = PS1.replace(_primitive(), "")
    calls = [l for l in _code(outside).splitlines() if re.search(r"\bGet-File\b", l) and "function Get-File" not in l]
    assert calls == [], calls


def _verified_before_use(fn: str) -> bool:
    """True when the function obtains its bytes through the primitive before any extraction/placement."""
    got = fn.find("Get-VerifiedInput")
    use = min([i for i in (fn.find("Expand-Archive"), fn.find("Copy-Item")) if i >= 0] or [len(fn)])
    return 0 <= got < use


def test_mingit_and_winsw_are_used_only_from_verified_staged_bytes():
    for name in ("Install-MinGit", "Install-WinSw"):
        fn = _func(PS1, name)
        assert _verified_before_use(fn), name
        assert "Get-File" not in fn and "Invoke-WebRequest" not in fn, name
    assert "$zip = Get-VerifiedInput $script:MinGitRecord" in _func(PS1, "Install-MinGit")
    assert "$src = Get-VerifiedInput $script:WinSwRecord" in _func(PS1, "Install-WinSw")


def test_primitive_promotes_a_file_only_after_verification():
    prim = _func(_primitive(), "Get-VerifiedInput")
    assert prim.index("Get-File $Record.Url $part") < prim.index("Get-InputMismatch $Record $part") \
        < prim.index("Move-Item")
    assert "$part = $dest + '.part'" in prim
    assert "Remove-Item -LiteralPath $part" in prim


def test_inputs_are_staged_before_the_first_service_stop_or_mutation():
    call = PS1.index("\nStage-VerifiedInputs\n")
    assert PS1.index("Cfm-Confirm -Prompt 'Proceed?'") < call
    assert call < PS1.index("# === PHASE 8 ") < PS1.index("Assert-CfmSystemTaskTrust -EntryPoint")
    assert call < PS1.index("Stop-Service $svc -Force")
    stage = _func(PS1, "Stage-VerifiedInputs")
    for rec in ("PythonEmbedRecord", "GetPipRecord", "MinGitRecord", "WinSwRecord"):
        assert f"$script:{rec}" in stage
    assert "Test-Path $Git" in stage and "WinSW.exe" in stage
    # inputs the installed tree already has are not re-fetched or replaced
    assert "if (Test-Path $Git) { return }" in _func(PS1, "Install-MinGit")
    assert "if (Test-Path $Winsw) { return }" in _func(PS1, "Install-WinSw")


def test_spec_requires_exact_url_and_stored_sha256():
    assert "float to GitHub-latest" not in SPEC
    for needle in ("exact record of URL", "SHA-256", "releases/latest", "Bump procedure", "independently download"):
        assert needle in SPEC, needle


# -- behavioral (pwsh): the real primitive + the real MinGit/WinSW consumers ----------------------

pwsh = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(pwsh is None, reason="pwsh not available")

GOOD = b"good-bytes-for-an-executable-input"

HARNESS = r"""
$ErrorActionPreference = 'Stop'
$Root = $env:H_ROOT
$InputsDir = Join-Path $Root 'inputs'
$InstallDir = Join-Path $Root 'install'
$Git = Join-Path $InstallDir 'git\cmd\git.exe'
$Winsw = Join-Path $Root 'services/WinSW.exe'
$log = Join-Path $Root 'calls.log'
function Die($m) { throw "DIE: $m" }
function Info($m) {}
function Get-File($url, $out) {
  Add-Content $log "get $url"
  if ($env:H_FAULT) { throw "DIE: Download failed: $url" }
  [IO.File]::WriteAllBytes($out, [IO.File]::ReadAllBytes($env:H_SERVE))
}
function Expand-Archive([string]$Path, [string]$DestinationPath, [switch]$Force) {
  $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
  Add-Content $log "expand $Path $h"
}
$script:MinGitRecord = @{ File = 'MinGit.zip'; Name = 'test MinGit'; Url = 'https://test.invalid/MinGit.zip'
  Size = [int]$env:H_SIZE; Sha256 = $env:H_SHA }
$script:WinSwRecord = @{ File = 'WinSW.exe'; Name = 'test WinSW'; Url = 'https://test.invalid/WinSW.exe'
  Size = [int]$env:H_SIZE; Sha256 = $env:H_SHA }
"""


def _fn_with_call(name: str) -> str:
    a = PS1.index(f"function {name} {{")
    return PS1[a:PS1.index(f"\n{name}\n", a) + 1]


def _harness(tmp_path, *, serve: bytes, expected: bytes = GOOD, size: int | None = None, fault=False,
             target="mingit", mutate=None, preseed: bytes | None = None, installed=False):
    root = tmp_path
    (root / "services").mkdir(exist_ok=True)
    serve_f = root / "serve.bin"
    serve_f.write_bytes(serve)
    if preseed is not None:
        (root / "inputs").mkdir(exist_ok=True)
        (root / "inputs" / ("MinGit.zip" if target == "mingit" else "WinSW.exe")).write_bytes(preseed)
    if installed:
        if target == "mingit":
            g = root / "install/git/cmd"
            g.mkdir(parents=True)
            (g / "git.exe").write_text("x")
        else:
            (root / "services/WinSW.exe").write_text("x")
    prim = _primitive()
    fn = _func(PS1, "Install-MinGit" if target == "mingit" else "Install-WinSw")
    if mutate:
        prim, fn = mutate(prim, fn)
    body = HARNESS + prim + fn + ("Install-MinGit\n" if target == "mingit" else "Install-WinSw\n") + "'DONE'\n"
    script = root / "h.ps1"
    script.write_text(body)
    env = dict(os.environ, H_ROOT=str(root), H_SERVE=str(serve_f), H_SHA=hashlib.sha256(expected).hexdigest(),
               H_SIZE=str(size if size is not None else len(expected)), H_FAULT="1" if fault else "")
    return subprocess.run([pwsh, "-NoProfile", "-File", str(script)], capture_output=True, text=True, env=env)


def _log(root):
    f = root / "calls.log"
    return f.read_text().splitlines() if f.exists() else []


def _staged(root):
    d = root / "inputs"
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def _mutated(b: bytes) -> bytes:
    return b[:-1] + bytes([b[-1] ^ 1])


TARGETS = ["mingit", "winsw"]


@needs_pwsh
@pytest.mark.parametrize("target", TARGETS)
def test_correct_bytes_pass_and_are_used_from_the_verified_staged_file(tmp_path, target):
    r = _harness(tmp_path, serve=GOOD, target=target)
    assert r.returncode == 0 and "DONE" in r.stdout, r.stderr
    if target == "mingit":
        expands = [l for l in _log(tmp_path) if l.startswith("expand")]
        assert len(expands) == 1 and hashlib.sha256(GOOD).hexdigest() in expands[0]
        assert str(tmp_path / "inputs" / "MinGit.zip") in expands[0]
    else:
        assert (tmp_path / "services/WinSW.exe").read_bytes() == GOOD
    assert _staged(tmp_path) == ["MinGit.zip" if target == "mingit" else "WinSW.exe"]


BAD = {
    "empty": dict(serve=b"", size=len(GOOD)),
    "one-byte-mutation": dict(serve=_mutated(GOOD)),
    "wrong-expected-digest": dict(serve=GOOD, expected=b"a different expected identity of x length"[:len(GOOD)].ljust(len(GOOD), b"x")),
}


@needs_pwsh
@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("case", sorted(BAD))
def test_bad_bytes_refuse_before_the_mutation_boundary_and_leave_nothing_consumable(tmp_path, target, case):
    r = _harness(tmp_path, target=target, **BAD[case])
    out = r.stderr + r.stdout
    assert r.returncode != 0 and "DIE: Refusing" in out, out
    assert "expected" in out or "empty" in out
    assert not [l for l in _log(tmp_path) if l.startswith("expand")]
    assert not (tmp_path / "services/WinSW.exe").exists()
    assert _staged(tmp_path) == [], "no consumable (or .part) file may survive a refusal"


@needs_pwsh
def test_a_tampered_staged_file_is_rehashed_at_use_and_never_consumed(tmp_path):
    r = _harness(tmp_path, serve=GOOD, fault=True, preseed=_mutated(GOOD))
    assert r.returncode != 0
    assert not [l for l in _log(tmp_path) if l.startswith("expand")]
    assert _staged(tmp_path) == []


@needs_pwsh
def test_a_tampered_staged_file_is_replaced_by_a_verified_download(tmp_path):
    r = _harness(tmp_path, serve=GOOD, preseed=_mutated(GOOD))
    assert r.returncode == 0, r.stderr
    expands = [l for l in _log(tmp_path) if l.startswith("expand")]
    assert len(expands) == 1 and hashlib.sha256(GOOD).hexdigest() in expands[0]


@needs_pwsh
@pytest.mark.parametrize("target", TARGETS)
def test_an_already_installed_tool_is_not_refetched_or_replaced(tmp_path, target):
    r = _harness(tmp_path, serve=GOOD, target=target, installed=True)
    assert r.returncode == 0, r.stderr
    assert _log(tmp_path) == []


@needs_pwsh
def test_a_transient_fetch_failure_stages_nothing_and_a_rerun_recovers(tmp_path):
    first = _harness(tmp_path, serve=GOOD, fault=True)
    assert first.returncode != 0 and _staged(tmp_path) == []
    again = _harness(tmp_path, serve=GOOD)
    assert again.returncode == 0 and "DONE" in again.stdout, again.stderr


# -- mutation controls: the detectors above must FAIL when the guarantee is broken ---------------

@needs_pwsh
def test_control_bypassed_verification_would_consume_bad_bytes(tmp_path):
    def bypass(prim, fn):
        out = prim.replace("if ($why) {", "if ($false) {")
        assert out != prim
        return out, fn
    r = _harness(tmp_path, serve=_mutated(GOOD), mutate=bypass)
    assert r.returncode == 0
    assert [l for l in _log(tmp_path) if l.startswith("expand")], "the refusal tests would have caught this"


@needs_pwsh
def test_control_a_primitive_that_trusts_staged_files_would_consume_a_tampered_one(tmp_path):
    def trust(prim, fn):
        out = prim.replace("if (-not (Get-InputMismatch $Record $dest)) { return $dest }", "return $dest")
        assert out != prim
        return out, fn
    r = _harness(tmp_path, serve=GOOD, fault=True, preseed=_mutated(GOOD), mutate=trust)
    assert r.returncode == 0
    assert [l for l in _log(tmp_path) if l.startswith("expand")]


def test_control_verification_after_use_is_detected():
    fn = _func(PS1, "Install-MinGit")
    moved = fn.replace("  $zip = Get-VerifiedInput $script:MinGitRecord $InputsDir\n", "").replace(
        "  Expand-Archive -Path $zip", "  Expand-Archive -Path $zip", 1)
    moved = moved.replace("-Force\n}", "-Force\n  $zip = Get-VerifiedInput $script:MinGitRecord $InputsDir\n}")
    assert moved != fn
    assert _verified_before_use(fn) is True
    assert _verified_before_use(moved) is False


def test_control_latest_discovery_returning_is_detected():
    assert _latest_lookups(PS1) == []
    injected = PS1 + "\n$rel = Get-Json 'https://api.github.com/repos/winsw/winsw/releases/latest'\n"
    assert _latest_lookups(injected)
    commented = PS1 + "\n# historical: releases/latest was removed\n"
    assert _latest_lookups(commented) == [], "a comment naming the removed lookup is not a lookup"
