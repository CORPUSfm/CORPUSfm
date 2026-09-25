"""One incoming credential frame supplies one top-level uninstall run - on both launchers.

MEASURED ON A LIVE BOX (packet 1380-04, run 35569225467, u-test-private, 2026-09-21). The Linux
launcher read the frame, validated it, ran `start` with it - and the lifecycle then answered
`credential_required` again for the PKI read-back. The launcher tried to read stdin a SECOND time:

    x the credential frame ended before its account length
         Nothing has changed.

and the box was left `incomplete_safe` with `['pki']` owed. Windows had the mirror-image defect by
inspection: it marked the frame spent after `start` and stopped at the next continuation.

The lifecycle asks per OPERATION, so a credential spent on the first call strands the second. The
developer ruling (narrowing packet 1236): after validation the launcher holds the credential for the
one approved run and reuses it for every start or resume that answers `credential_required`; each
lifecycle child still receives a freshly framed copy on stdin; the launcher reads its own stdin at
most once; and the credential is wiped when the run ends.

These tests run the SHIPPED launcher regions - including the shipped framed-invoke functions - against
a fake `corpusfm.lifecycle` module that records every frame it receives and answers from a script.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WIN = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii").replace("\r\n", "\n")
LIN = (ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8")

PWSH = shutil.which("pwsh")
supplementary = pytest.mark.skipif(PWSH is None, reason="no pwsh; WinPS 5.1 is authoritative")

USER, PASSWORD = "gate-admin", "gate-Pw!"
READ_LINE = "Read one FMS administrator credential frame from standard input."


def frame(account: str = USER, password: str = PASSWORD) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in (account.encode(), password.encode()))


def region(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


# A stand-in for `python -m corpusfm.lifecycle uninstall <verb> --request <file>`. It records the verb
# and the frame it was handed on ITS OWN stdin, then answers with the next scripted reason.
FAKE_LIFECYCLE = textwrap.dedent('''
    import json, os, struct, sys
    d = os.environ["FAKE_DIR"]
    verb = sys.argv[sys.argv.index("uninstall") + 1]
    raw = sys.stdin.buffer.read()
    fields, i = [], 0
    while i + 4 <= len(raw):
        (n,) = struct.unpack(">I", raw[i:i + 4]); fields.append(raw[i + 4:i + 4 + n].decode()); i += 4 + n
    with open(os.path.join(d, "calls"), "a") as f:
        f.write(json.dumps({"verb": verb, "fields": fields, "bytes": len(raw),
                            "env_pass": os.environ.get("FM_ADMIN_PASS", "UNSET")}) + "\\n")
    seq = open(os.path.join(d, "seq")).read().split()
    reason = seq.pop(0) if seq else "done"
    open(os.path.join(d, "seq"), "w").write(" ".join(seq))
    busy = reason == "credential_required"
    print(json.dumps({"result": "incomplete_safe" if busy else "removed",
                      "reason": reason if busy else "", "detail": "fake"}))
    sys.exit(5 if busy else 0)
''')


def fake_lifecycle(tmp_path: Path, answers: list[str]) -> Path:
    pkg = tmp_path / "fakepkg" / "corpusfm" / "lifecycle"
    pkg.mkdir(parents=True)
    (pkg.parent / "__init__.py").write_text("")
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(FAKE_LIFECYCLE)
    (tmp_path / "seq").write_text(" ".join(answers))
    (tmp_path / "calls").write_text("")
    return tmp_path / "fakepkg"


def calls(tmp_path: Path) -> list[dict]:
    return [json.loads(l) for l in (tmp_path / "calls").read_text().splitlines() if l.strip()]


def fmsadmin_stub(tmp_path: Path) -> Path:
    p = tmp_path / "fmsadmin"
    p.write_text("#!/bin/sh\nexit 0\n"); p.chmod(0o755)
    return p


# ── Windows ─────────────────────────────────────────────────────────────────────────────────────

W_READER = region(WIN, "function Lc-ReadFramedCredential($plan) {", "# THE SIX RESULT WORDS")
W_INVOKE = region(WIN, "function Encode-UninstallArg([string]$value) {", "function Lc-ReadFmsCredential($plan) {")
W_START = region(WIN, "$startTransport = 'none'; $script:LcCredentialUser = ''",
                 "if ($plan.mode -eq 'start') {")
W_DISPATCH = region(WIN, "if ($startTransport -eq 'stdin') {", "# **A pending record means")
W_LOOP = region(WIN, "$continuations = 0\nwhile ($script:LcReason -eq 'credential_required') {",
                'Section "Summary"')

W_PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$L = $env:FAKE_DIR
$script:CfmSilent = $true
$CredentialStdin = $true
function Info($m) { Add-Content -LiteralPath "$L/out" -Value ("INFO: " + $m) }
function Warn($m) { Add-Content -LiteralPath "$L/out" -Value ("WARN: " + $m) }
function Ok($m)   { Add-Content -LiteralPath "$L/out" -Value ("OK: " + $m) }
function Section($m) { }
function Cfm-Logline($m) { }
function Die($m)  { Add-Content -LiteralPath "$L/out" -Value ("DIE: " + $m); exit 9 }
function Lc-ReadFmsCredential($plan) { Add-Content -LiteralPath "$L/out" -Value "READHOST"; exit 8 }
function Lc-Invoke($verb, $t) { Add-Content -LiteralPath "$L/out" -Value ("PLAIN: $verb|$t"); $script:LcReason='' }
# The request file carries no credential; icacls is a Windows-only step, so this one helper is stubbed.
function Lc-Request($transport) { $f = "$L/request.json"; Set-Content -LiteralPath $f -Value $transport; return $f }
$script:LcPy = $env:FAKE_PY
$plan = [pscustomobject]@{ mode = $env:PLAN_MODE; fms_admin_login_required = $true
                           locations = [pscustomobject]@{ fmsadmin = $env:FAKE_FMSADMIN } }
"""


def run_win(tmp_path: Path, answers: list[str], plan_mode: str = "start", stdin: bytes = None):
    pkg = fake_lifecycle(tmp_path, answers)
    (tmp_path / "out").write_text("")
    if plan_mode == "start":
        main = W_START + W_DISPATCH
    else:
        # A recorded uninstall being resumed: no start-time read, the lifecycle asks first.
        main = ("$script:LcCredentialUser = ''; $script:LcCredentialPass = ''\n"
                "$script:CredentialFrameRead = $false\n$script:LcReason = 'credential_required'\n")
    body = (W_PRELUDE + W_READER + W_INVOKE + main + W_LOOP +
            '\nAdd-Content -LiteralPath "$L/out" -Value ("AFTER:[" + $script:LcCredentialUser + "|" + $script:LcCredentialPass + "]")\n')
    script = tmp_path / "t.ps1"; script.write_text(body, encoding="ascii")
    e = dict(os.environ, FAKE_DIR=str(tmp_path), FAKE_PY=sys.executable, PYTHONPATH=str(pkg),
             PLAN_MODE=plan_mode, FAKE_FMSADMIN=str(fmsadmin_stub(tmp_path)))
    e.pop("FM_ADMIN_USER", None); e.pop("FM_ADMIN_PASS", None)
    # cwd is the scratch directory ON PURPOSE. `python -m` puts the working directory first on
    # sys.path, so run from a tree that carries the real `corpusfm/` package (the consolidated public
    # root) the fake lifecycle on PYTHONPATH would be shadowed and the real CLI would answer instead.
    proc = subprocess.run([PWSH, "-NoProfile", "-File", str(script)],
                          input=frame() if stdin is None else stdin, capture_output=True, env=e,
                          cwd=str(tmp_path))
    return proc, (tmp_path / "out").read_text(), calls(tmp_path)


@supplementary
def test_windows_one_frame_satisfies_start_and_two_credential_continuations(tmp_path):
    proc, out, got = run_win(tmp_path, ["credential_required", "credential_required", "done"])
    assert "DIE:" not in out, out + proc.stderr.decode(errors="replace")
    assert [c["verb"] for c in got] == ["start", "resume", "resume"], got
    for c in got:                                   # a fresh, complete frame for every child
        assert c["fields"] == [USER, PASSWORD] and c["bytes"] == len(frame()), c
        assert c["env_pass"] == "UNSET", "the credential reached a child's environment"
    assert out.count(READ_LINE) == 1, "the launcher read its stdin more than once"
    assert "AFTER:[|]" in out, "the held credential was not wiped at the end of the run"


@supplementary
def test_windows_one_frame_satisfies_two_continuations_of_a_resumed_run(tmp_path):
    _, out, got = run_win(tmp_path, ["credential_required", "done"], plan_mode="resume")
    assert "DIE:" not in out, out
    assert [c["verb"] for c in got] == ["resume", "resume"], got
    assert all(c["fields"] == [USER, PASSWORD] for c in got)
    assert out.count(READ_LINE) == 1
    assert "AFTER:[|]" in out


@supplementary
def test_windows_a_lifecycle_that_never_stops_asking_is_bounded(tmp_path):
    _, out, got = run_win(tmp_path, ["credential_required"] * 20)
    assert len(got) == 1 + 8, "start plus exactly eight continuations"
    assert "continuations; stopping" in out and "AFTER:[|]" in out


def test_windows_the_run_level_finally_wipes_the_held_credential():
    """Interruption and refusal leave through the outer finally; it is where the held value dies."""
    tail = WIN[WIN.rindex("} finally {"):]
    assert "$script:LcCredentialPass = ''; $script:LcCredentialUser = ''" in tail


# ── Linux ───────────────────────────────────────────────────────────────────────────────────────

L_SETUP = region(LIN, 'LC_REQ_DIR=""\n', "# --credential-stdin is a NON-INTERACTIVE route")
L_FUNCS = region(LIN, "lc_read_framed_credential() {", "# THE SIX RESULT WORDS")
L_START = region(LIN, 'START_TRANSPORT="none"\nCREDENTIAL_FRAME_READ=false\n',
                 'if [[ "$PLAN_MODE" == "start" ]]; then\n    cfm_section "Confirm"')
L_LOOP = region(LIN, "CONTINUATIONS=0\nwhile", "# ── S6 Summary")


def run_lin(tmp_path: Path, answers: list[str], plan_mode: str = "start", stdin: bytes = None,
            extra: str = "", env_extra: dict | None = None):
    pkg = fake_lifecycle(tmp_path, answers)
    (tmp_path / "out").write_text("")
    if plan_mode == "start":
        main = L_START + 'lc_invoke "start" "$START_TRANSPORT"\n'
    else:
        main = 'CREDENTIAL_FRAME_READ=false\nLC_REASON="credential_required"\n'
    harness = f"""#!/bin/bash
set -euo pipefail
d="{tmp_path}"
info() {{ printf 'INFO: %s\\n' "$*" >> "$d/out"; }}
ok()   {{ printf 'OK: %s\\n' "$*" >> "$d/out"; }}
warn() {{ printf 'WARN: %s\\n' "$*" >> "$d/out"; }}
die()  {{ printf 'DIE: %s\\n' "$*" >> "$d/out"; exit 9; }}
cfm_section() {{ :; }}
PY="{sys.executable}"; RESULT_PY="{sys.executable}"
CFM_LIFECYCLE=("{sys.executable}" -m corpusfm.lifecycle)
CFM_LOG="$d/log"; INSTALLATION_ID="inst-1"; FORCE=false; SILENT=true; CREDENTIAL_STDIN=true
PLAN_MODE="{plan_mode}"; PLAN_NEEDS_CREDENTIAL=true; PLAN_FMSADMIN="{fmsadmin_stub(tmp_path)}"
{L_SETUP}
{L_FUNCS}
{extra}
{main}
{L_LOOP}
printf 'AFTER:[%s|%s]\\n' "${{FM_ADMIN_USER-}}" "${{FM_ADMIN_PASS-}}" >> "$d/out"
"""
    script = tmp_path / "harness.sh"; script.write_text(harness); script.chmod(0o755)
    e = dict(os.environ, FAKE_DIR=str(tmp_path), PYTHONPATH=str(pkg), TMPDIR=str(tmp_path))
    e.pop("FM_ADMIN_USER", None); e.pop("FM_ADMIN_PASS", None)
    e.update(env_extra or {})
    # cwd is the scratch directory for the same reason as run_win: never let the real package win.
    proc = subprocess.run(["/bin/bash", str(script)], input=frame() if stdin is None else stdin,
                          capture_output=True, env=e, cwd=str(tmp_path))
    return proc, (tmp_path / "out").read_text(), calls(tmp_path)


def test_linux_one_frame_satisfies_start_and_two_credential_continuations(tmp_path):
    """The live failure, reproduced and closed: start, then TWO credential_required answers."""
    proc, out, got = run_lin(tmp_path, ["credential_required", "credential_required", "done"])
    assert "DIE:" not in out, out + proc.stderr.decode(errors="replace")
    assert [c["verb"] for c in got] == ["start", "resume", "resume"], got
    for c in got:
        assert c["fields"] == [USER, PASSWORD] and c["bytes"] == len(frame()), c
        assert c["env_pass"] == "UNSET", "the credential reached a child's environment"
    assert out.count(READ_LINE) == 1, "the launcher read its stdin more than once"
    assert "AFTER:[|]" in out, "the held credential was not wiped at the end of the run"


def test_linux_one_frame_satisfies_two_continuations_of_a_resumed_run(tmp_path):
    _, out, got = run_lin(tmp_path, ["credential_required", "done"], plan_mode="resume")
    assert "DIE:" not in out, out
    assert [c["verb"] for c in got] == ["resume", "resume"], got
    assert all(c["fields"] == [USER, PASSWORD] for c in got)
    assert out.count(READ_LINE) == 1
    assert "AFTER:[|]" in out


def test_linux_a_lifecycle_that_never_stops_asking_is_bounded(tmp_path):
    _, out, got = run_lin(tmp_path, ["credential_required"] * 20)
    assert len(got) == 1 + 8, "start plus exactly eight continuations"
    assert "continuations; stopping" in out and "AFTER:[|]" in out


def test_linux_an_inherited_exported_credential_never_reaches_a_child(tmp_path):
    """Holding the credential for the whole run raises the stakes of an export attribute surviving."""
    _, out, got = run_lin(tmp_path, ["credential_required", "done"],
                          env_extra={"FM_ADMIN_USER": "inherited", "FM_ADMIN_PASS": "inherited-pw"})
    assert got and all(c["env_pass"] == "UNSET" for c in got), got
    assert all(c["fields"] == [USER, PASSWORD] for c in got), "an inherited value was used"


def test_linux_an_interrupted_run_leaves_through_the_wiping_exit_trap(tmp_path):
    """TERM mid-run must still run lc_cleanup, which is what clears the held credential."""
    probe = ('trap \'lc_cleanup; printf "TRAP:[%s|%s]\\n" "$FM_ADMIN_USER" "$FM_ADMIN_PASS" >> "$d/out"\' EXIT\n'
             'lc_invoke() { printf "INVOKE\\n" >> "$d/out"; kill -TERM $$; sleep 1; }\n')
    proc, out, _ = run_lin(tmp_path, ["done"], extra=probe)
    assert "INVOKE" in out, out
    assert "TRAP:[|]" in out, f"the EXIT trap did not run with the credential wiped:\n{out}"
    assert proc.returncode in (-15, 143), "the run was not terminated by the signal"


def test_linux_lc_cleanup_itself_wipes_the_credential():
    body = region(LIN, "lc_cleanup() {", "\n}\n")
    assert 'FM_ADMIN_PASS=""; FM_ADMIN_USER=""' in body
    assert "trap lc_cleanup EXIT" in LIN


def test_both_launchers_read_the_frame_from_at_most_two_sites_guarded_by_one_flag():
    """Start-time and first-continuation reads are alternatives, never both, on each platform."""
    assert WIN.count("$script:CredentialFrameRead = $true") == 2
    assert LIN.count("CREDENTIAL_FRAME_READ=true") == 2
    assert "CredentialFrameSpent" not in WIN and "CREDENTIAL_FRAME_SPENT" not in LIN
