"""The fresh-install Admin API identity observation, executed through the REAL call sites.

A fresh attempt observes the Admin API identity immediately before phase 15 mutates it, and refuses
first on a foreign same-name registration. It used to observe with `credential_input=absent`. With no
local identity yet, only the read-only authorized registry GET can tell "not installed" from
"someone else's key", so every clean FileMaker Server read `unknown` and every fresh install stopped.
That was measured on both private targets on 2026-09-29.

These tests run the installers' own bytes: the fresh-attempt block and the helper functions it calls,
cut out of `install.sh` / `install.ps1`, under bash and PowerShell. The child process is the real
`python -m corpusfm.lifecycle admin-identity observe`: real request parsing, the real framed-stdin
credential reader, the real observation and the real classifier. A `sitecustomize` on the child's
`PYTHONPATH` substitutes only external authority:
- the FileMaker Admin API (records every call, never the password);
- the reachability probe;
- the OS and lifecycle layouts (rooted in a temp directory);
- the root-owned-request stat check (a test does not run as root).

Under PowerShell the Windows-only `icacls` protection in `Lc-Request` is also substituted. **pwsh on
macOS is PowerShell 7, not Windows PowerShell 5.1**: this proves the call site's logic and credential
framing, not Windows behaviour.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from application_checkout import APPLICATION_ROOT

INSTALLER = Path(__file__).resolve().parent.parent
PASSWORD = "Fm-adm1n-Sent1nel"
#: The last installer commit carrying the `absent` fresh-attempt observation (0.2979/0.3002 sources).
#: The reproductions read its exact bytes; where that commit is not in the repository (a projection
#: with its own history) they skip rather than compare against some other tree.
PRE_CORRECTION = "c5534d2d333d16a517a2c3f98e991f9a2b1c684a"
USER = "fmadmin-test"

SHIM = r'''
import json, os, sys
if os.environ.get("CFM_T_SHIM") == "1":
    from pathlib import Path
    from corpusfm.lifecycle import cli, os_layout, layout as lifecycle_layout
    from corpusfm.lifecycle import admin_identity_store as store
    root = Path(os.environ["CFM_T_ROOT"])
    scenario = os.environ["CFM_T_SCENARIO"]
    calls = Path(os.environ["CFM_T_CALLS"])
    def note(**kw):
        with calls.open("a") as fh:
            fh.write(json.dumps(kw) + "\n")
    note(event="argv", argv=sys.argv)
    os_layout.platform_os_layout = lambda: os_layout.posix_os_layout(root)
    cli.platform_layout = lambda: lifecycle_layout.posix_layout(root)
    cli._stat_refusal = lambda st, what: None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    # A REAL key someone else registered under our name: an unparseable one would read as
    # inconclusive (unknown), which is a different, weaker path than the refuse-first one.
    FOREIGN = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key() \
        .public_bytes(serialization.Encoding.PEM,
                      serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    class Api:
        def get_public_keys(self, host, user, password):
            ok = (user == os.environ["CFM_T_USER"] and password == os.environ["CFM_T_PASSWORD"])
            note(event="get", user=user, password_matches=ok)
            if not ok:
                return False, [], "401"
            if scenario == "foreign":
                return True, [{"id": "u", "name": store.REGISTRATION_NAME, "publicKey": FOREIGN}], "OK"
            return True, [], "OK"
        def authenticate(self, *a):
            note(event="authenticate"); return False
        def __getattr__(self, name):
            def mutation(*a, **k):
                note(event="MUTATION", name=name)
                raise AssertionError("observe mutated: " + name)
            return mutation
    cli._ai_api = lambda: Api()
    cli._ai_probe = lambda: (lambda host: scenario != "unavailable")
'''


def _source(rel: str, ref: str | None) -> str:
    if ref is not None and subprocess.run(
            ["git", "-C", str(INSTALLER), "cat-file", "-e", f"{ref}^{{commit}}"],
            capture_output=True).returncode != 0:
        pytest.skip(f"pre-correction installer commit {ref[:12]} is not in this repository")
    if ref is None:
        return (INSTALLER / rel).read_text(encoding="utf-8")
    return subprocess.run(["git", "-C", str(INSTALLER), "show", f"{ref}:{rel}"],
                          check=True, capture_output=True, text=True).stdout


def _bash_function(text: str, name: str) -> str:
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines) if re.match(rf"^{re.escape(name)}\(\) *\{{", l))
    if lines[start].rstrip().endswith("}") and lines[start].count("{") == lines[start].count("}"):
        end = start
    else:
        end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
        # lc_json_field / friends are two-line bodies ending in "; }" rather than a bare brace
    return "\n".join(lines[start:end + 1])


def _bash_json_field(text: str) -> str:
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("lc_json_field() {"))
    end = next(i for i in range(start, len(lines)) if lines[i].rstrip().endswith("; }"))
    return "\n".join(lines[start:end + 1])


def _bash_attempt_block(text: str) -> str:
    lines = text.splitlines()
    anchor = next(i for i, l in enumerate(lines) if "lc_request admin_identity-reconcile" in l)
    start = next(i for i in range(anchor, len(lines)) if lines[i].startswith("if $CFM_ATTEMPT; then"))
    end = next(i for i in range(start, len(lines)) if lines[i] == "fi")
    return "\n".join(lines[start:end + 1])


def _ps_function(text: str, name: str) -> str:
    lines = text.splitlines()
    start = next(i for i, l in enumerate(lines) if re.match(rf"^function {re.escape(name)}\b", l))
    if lines[start].count("{") == lines[start].count("}") and "{" in lines[start]:
        return lines[start]
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start:end + 1])


def _ps_attempt_block(text: str) -> str:
    lines = text.splitlines()
    anchor = next(i for i, l in enumerate(lines) if "Lc-Request 'admin_identity-reconcile'" in l)
    start = next(i for i in range(anchor, len(lines)) if lines[i].startswith("if ($script:CfmAttempt) {"))
    end = next(i for i in range(start, len(lines)) if lines[i] == "}")
    return "\n".join(lines[start:end + 1])


@pytest.fixture
def box(tmp_path):
    """A fresh co-located box at the moment of phase 15: keys established, no identity anywhere."""
    from cryptography.fernet import Fernet

    root = tmp_path / "root"
    secrets = root / "var" / "lib" / "corpusfm" / "secrets"
    secrets.mkdir(parents=True)
    (secrets / "machine.key").write_bytes(Fernet.generate_key())
    fms = tmp_path / "fms"
    (fms / "Database Server").mkdir(parents=True)
    install = tmp_path / "install"
    (install / "venv" / "bin").mkdir(parents=True)
    (install / "venv" / "bin" / "python").symlink_to(sys.executable)
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text(SHIM, encoding="utf-8")
    return dict(tmp=tmp_path, root=root, secrets=secrets, fms=fms, install=install, shim=shim,
                calls=tmp_path / "calls.jsonl", log=tmp_path / "install.log",
                reqdir=tmp_path / "requests")


def _env(box, scenario, *, password=PASSWORD):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CFM_", "PYTHON"))}
    env.update(CFM_T_SHIM="1", CFM_T_ROOT=str(box["root"]), CFM_T_SCENARIO=scenario,
               CFM_T_CALLS=str(box["calls"]), CFM_T_USER=USER, CFM_T_PASSWORD=PASSWORD,
               PYTHONPATH=f"{box['shim']}{os.pathsep}{APPLICATION_ROOT}",
               PYTHONDONTWRITEBYTECODE="1", FM_ADMIN_USER=USER, FM_ADMIN_PASS=password)
    return env


def _calls(box):
    if not box["calls"].exists():
        return []
    return [json.loads(l) for l in box["calls"].read_text().splitlines()]


def _run_linux(box, scenario, *, ref=None, password=PASSWORD):
    text = _source("installer/linux/install.sh", ref)
    script = "\n".join([
        "set -euo pipefail",
        'die() { printf "DIE: %s\\n" "$1"; exit 3; }',
        'la_py() { printf "{}"; }',
        f'INSTALL_DIR="{box["install"]}"; LC_REQ_DIR="{box["reqdir"]}"; CFM_LOG="{box["log"]}"',
        f'LC_RUNTIME_PY="{sys.executable}"',
        f'INSTALLATION_ID=11111111-1111-4111-8111-111111111111; FMS_ROOT="{box["fms"]}"',
        f'CFM_SECRETS_DIR="{box["secrets"]}"; CFM_FMS_HOST=127.0.0.1; CFM_MODE=fresh_install',
        "CFM_GENERATION=1; CFM_ATTEMPT=true",
        f'CFM_LIFECYCLE=(env "PYTHONPATH={box["shim"]}{os.pathsep}{APPLICATION_ROOT}" "{sys.executable}" -m corpusfm.lifecycle)',
        _bash_function(text, "lc_request"),
        _bash_function(text, "lc_fms_transport"),
        _bash_function(text, "lc_fms_frame"),
        _bash_function(text, "lc_admin_identity_request"),
        _bash_json_field(text),
        _bash_attempt_block(text),
        'printf "PASSED_BLOCK state=%s intent=%s\\n" "$_la_state" "$LA_PROVIDER_INTENT"',
    ])
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120,
                          env=_env(box, scenario, password=password))


def _assert_no_leak(box, result):
    for request in box["reqdir"].glob("*.json"):
        body = request.read_text()
        assert PASSWORD not in body, f"the password entered {request.name}"
    for c in _calls(box):
        assert PASSWORD not in json.dumps(c), "the password reached an argv or a recorded call"
    log = box["log"].read_text() if box["log"].exists() else ""
    assert PASSWORD not in log + result.stdout + result.stderr, "the password reached a log or stream"


# ── Linux: the real install.sh bytes under bash ─────────────────────────────────────────────────

def test_LINUX_original_bytes_reproduce_the_fresh_install_refusal(box):
    """The measured defect: installer ca1a7b89/c5534d2d observes with `absent`, reads `unknown`."""
    result = _run_linux(box, "clean", ref=PRE_CORRECTION)
    assert "DIE: The Admin API identity reads 'unknown' and cannot be recorded for a fresh attempt." \
        in result.stdout, result.stdout + result.stderr
    assert not [c for c in _calls(box) if c["event"] == "get"], "the original path made no GET"


def test_LINUX_a_clean_box_is_observed_with_authority_and_proceeds(box):
    result = _run_linux(box, "clean")
    assert "PASSED_BLOCK state=not_installed intent=admin_identity_reconcile" in result.stdout, \
        result.stdout + result.stderr
    gets = [c for c in _calls(box) if c["event"] == "get"]
    assert gets == [{"event": "get", "user": USER, "password_matches": True}], _calls(box)
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    request = json.loads((box["reqdir"] / "admin_identity-observe-attempt.json").read_text())
    assert request["credential_input"] == "stdin"
    _assert_no_leak(box, result)


def test_LINUX_a_foreign_same_name_identity_still_refuses_first(box):
    result = _run_linux(box, "foreign")
    assert "DIE: REFUSE-FIRST" in result.stdout and "(remote_only)" in result.stdout, result.stdout
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    _assert_no_leak(box, result)


@pytest.mark.parametrize("scenario,password,why", [
    ("clean", "wrong-password", "rejected authentication"),
    ("unavailable", PASSWORD, "an unreachable server"),
    ("clean", "", "no credential held"),
])
def test_LINUX_an_unestablished_observation_is_never_relabelled_absent(box, scenario, password, why):
    result = _run_linux(box, scenario, password=password)
    assert "DIE: The Admin API identity reads 'unknown'" in result.stdout, \
        f"{why}: {result.stdout}{result.stderr}"
    assert "PASSED_BLOCK" not in result.stdout
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    if password:
        _assert_no_leak(box, result)


# ── Windows: the real install.ps1 bytes under PowerShell (pwsh 7 on this host) ─────────────────

_PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="pwsh not installed")


def _run_windows(box, scenario, *, ref=None, password=PASSWORD):
    text = _source("installer/windows/install.ps1", ref)
    functions = "\n".join(_ps_function(text, n) for n in (
        "Lc-Json", "Lc-AdminIdentityRequest", "Lc-FmsTransport", "Encode-WindowsArgv",
        "Encode-WindowsCommandLine", "Lc-IsOneJsonObject", "Lc-RunFramedRaw", "La-Lifecycle",
        "La-JsonObject", "La-Field"))
    script = "\n".join([
        "$ErrorActionPreference = 'Stop'",
        "function Die($m) { Write-Output ('DIE: ' + $m); exit 3 }",
        f"function Cfm-Logline($m) {{ Add-Content -LiteralPath '{box['log']}' -Value $m }}",
        # SUBSTITUTED: the Windows-only icacls protection. Everything else in Lc-Request is the same.
        f"function Lc-Request($name, $json) {{ New-Item -ItemType Directory -Force -Path '{box['reqdir']}' | Out-Null;"
        f" $f = Join-Path '{box['reqdir']}' ($name + '.json'); [IO.File]::WriteAllText($f, $json); return $f }}",
        functions,
        f"$script:Py = '{sys.executable}'",
        "$script:LcFramedTimeoutMs = 120000",
        "$script:InstallationId = '11111111-1111-4111-8111-111111111111'",
        f"$script:InstallDir = '{box['install']}'; $script:FmsBin = '{box['fms']}'",
        f"$script:CfmSecretsDir = '{box['secrets']}'; $script:CfmFmsHost = '127.0.0.1'",
        "$script:CfmMode = 'fresh_install'; $script:CfmGeneration = 1; $script:CfmAttempt = $true",
        "$script:FmAdminUser = $env:FM_ADMIN_USER; $script:FmAdminPass = $env:FM_ADMIN_PASS",
        "$FmAdminUser = $script:FmAdminUser; $FmAdminPass = $script:FmAdminPass",
        _ps_attempt_block(text),
        "Write-Output ('PASSED_BLOCK state=' + $laState + ' intent=' + $script:LaProviderIntent)",
    ])
    path = box["tmp"] / "block.ps1"
    path.write_text(script, encoding="utf-8")
    return subprocess.run([_PWSH, "-NoProfile", "-NonInteractive", "-File", str(path)],
                          capture_output=True, text=True, timeout=180,
                          env=_env(box, scenario, password=password))


@needs_pwsh
def test_WINDOWS_original_bytes_reproduce_the_fresh_install_refusal(box):
    result = _run_windows(box, "clean", ref=PRE_CORRECTION)
    assert "DIE: The Admin API identity reads 'unknown' and cannot be recorded for a fresh attempt." \
        in result.stdout, result.stdout + result.stderr
    assert not [c for c in _calls(box) if c["event"] == "get"]


@needs_pwsh
def test_WINDOWS_a_clean_box_is_observed_with_authority_and_proceeds(box):
    result = _run_windows(box, "clean")
    assert "PASSED_BLOCK state=not_installed intent=admin_identity_reconcile" in result.stdout, \
        result.stdout + result.stderr
    gets = [c for c in _calls(box) if c["event"] == "get"]
    assert gets == [{"event": "get", "user": USER, "password_matches": True}], _calls(box)
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    request = json.loads((box["reqdir"] / "admin_identity-observe-attempt.json").read_text())
    assert request["credential_input"] == "stdin"
    _assert_no_leak(box, result)


@needs_pwsh
def test_WINDOWS_a_foreign_same_name_identity_still_refuses_first(box):
    result = _run_windows(box, "foreign")
    assert "DIE: REFUSE-FIRST" in result.stdout and "(remote_only)" in result.stdout, result.stdout
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    _assert_no_leak(box, result)


@needs_pwsh
@pytest.mark.parametrize("scenario,password,why", [
    ("clean", "wrong-password", "rejected authentication"),
    ("unavailable", PASSWORD, "an unreachable server"),
    ("clean", "", "no credential held"),
])
def test_WINDOWS_an_unestablished_observation_is_never_relabelled_absent(box, scenario, password, why):
    result = _run_windows(box, scenario, password=password)
    assert "DIE: The Admin API identity reads 'unknown'" in result.stdout, \
        f"{why}: {result.stdout}{result.stderr}"
    assert "PASSED_BLOCK" not in result.stdout
    assert not [c for c in _calls(box) if c["event"] == "MUTATION"]
    if password:
        _assert_no_leak(box, result)
