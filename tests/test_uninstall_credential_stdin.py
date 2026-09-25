"""The uninstallers' non-interactive FMS credential route: one framed credential on stdin.

MEASURED ON A LIVE BOX (packet 1380-04, gate C, 2026-09-20). `uninstall.ps1 -Silent` reached a
recorded operation that needed an FMS administrator and had nowhere to get one:

    ! Uninstall stopped safely part-way (incomplete_safe). Re-run to continue.
    !   ['pki'] did not complete and remain owed;
    !   ['secrets_dir','config_dir','state_dir','install_dir'] were not attempted

An environment-variable route was written first and REJECTED BY THE PRODUCT'S OWN GUARDS: packet
1236 removed exactly that, because an exported credential is inherited by pip, git and apt-get and
is therefore not "transient" in the sense SPEC 4 promises. Six guards failed, four of them parity -
which also settled that a one-platform fix is not shippable.

So the route is a FRAME ON STDIN, the same wire shape the lifecycle component already consumes:

    [4-byte big-endian length][UTF-8 account][4-byte big-endian length][UTF-8 password]

It is inherited by nothing, appears in no argv, and is read once. These tests execute the shipped
launchers' own regions against stubs, so removing the framing, retaining a credential, or leaking
one fails by BEHAVIOUR rather than because a string moved.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WIN = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
LIN = (ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8")

PWSH = shutil.which("pwsh")
supplementary = pytest.mark.skipif(PWSH is None, reason="no pwsh; WinPS 5.1 is authoritative")

USER, PASSWORD = "gate-admin", "gate-Pw!"


def frame(account: str = USER, password: str = PASSWORD) -> bytes:
    out = b""
    for field in (account.encode(), password.encode()):
        out += struct.pack(">I", len(field)) + field
    return out


def region(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


READER = region(WIN, "function Lc-ReadFramedCredential($plan) {", "# THE SIX RESULT WORDS")
LOOP = region(WIN, "while ($script:LcReason -eq 'credential_required') {", 'Section "Summary"')
STARTPATH = region(WIN, "if ($plan.mode -eq 'start' -and $plan.fms_admin_login_required) {",
                   "if ($plan.mode -eq 'start') {")
DISPATCH = region(WIN, "if ($startTransport -eq 'stdin') {", "# **A pending record means")

STUBS = r"""
$ErrorActionPreference = 'Stop'
$L = $env:STUBDIR
$script:CfmSilent = $true
$CredentialStdin = [bool]$env:STUB_FRAMED
$script:CredentialFrameSpent = $false
$script:LcCredentialUser = ''; $script:LcCredentialPass = ''
$startTransport = 'none'
function Info($m) { Add-Content -LiteralPath "$L/out" -Value ("INFO: " + $m) }
function Warn($m) { Add-Content -LiteralPath "$L/out" -Value ("WARN: " + $m) }
function Ok($m)   { Add-Content -LiteralPath "$L/out" -Value ("OK: " + $m) }
function Section($m) { }
function Die($m)  { Add-Content -LiteralPath "$L/out" -Value ("DIE: " + $m); exit 9 }
function Read-Host { param([string]$Prompt, [switch]$AsSecureString)
  Add-Content -LiteralPath "$L/out" -Value "READHOST"; exit 8 }
function Lc-ReadFmsCredential($plan) { Read-Host 'u' }
function Lc-InvokeFramed($verb, $u, $p) {
  Add-Content -LiteralPath "$L/framed" -Value ("$verb|$u|$p"); $script:LcReason='done'; $script:LcRc=0 }
function Lc-Invoke($verb, $t) {
  Add-Content -LiteralPath "$L/plain" -Value ("$verb|$t"); $script:LcReason='done'; $script:LcRc=0 }
$plan = [pscustomobject]@{ mode='start'; fms_admin_login_required=$true
                           locations=[pscustomobject]@{ fmsadmin = "$L/fmsadmin" } }
"""


def run_win(tmp_path, body: str, stdin: bytes = b"", framed: bool = True, ok: bool = True):
    stub = tmp_path / "stub"; stub.mkdir(exist_ok=True)
    shim = stub / "fmsadmin"
    shim.write_text("#!/bin/sh\n"
                    f'printf "%s\\n" "$*" >> "{stub}/argv"\n'
                    f'printf "u=%s p=%s\\n" "${{FM_ADMIN_USER-UNSET}}" "${{FM_ADMIN_PASS-UNSET}}" >> "{stub}/childenv"\n'
                    f"exit {0 if ok else 1}\n")
    shim.chmod(0o755)
    for f in ("out", "framed", "plain", "argv", "childenv"):
        (stub / f).write_text("")
    script = tmp_path / "t.ps1"
    script.write_text(STUBS + "\n" + body, encoding="ascii")
    e = dict(os.environ); e.update({"STUBDIR": str(stub), "STUB_FRAMED": "1" if framed else ""})
    e.pop("FM_ADMIN_USER", None); e.pop("FM_ADMIN_PASS", None)
    proc = subprocess.run([PWSH, "-NoProfile", "-File", str(script)],
                          input=stdin, capture_output=True, env=e)
    rd = lambda n: (stub / n).read_text()
    return proc, rd("out"), rd("framed"), rd("argv"), rd("childenv"), rd("plain")


START = STARTPATH + DISPATCH


# ── the defect, closed ──────────────────────────────────────────────────────────────────────────

@supplementary
def test_a_framed_credential_performs_the_start_operation_without_prompting(tmp_path):
    _, out, framed, _, _, _ = run_win(tmp_path, READER + START, stdin=frame())
    assert "READHOST" not in out, out
    assert "authenticated" in out
    assert framed.strip() == f"start|{USER}|{PASSWORD}", framed


@supplementary
def test_a_framed_credential_completes_the_owed_resume(tmp_path):
    """The live box stopped in credential_required with ['pki'] owed. This is that resume."""
    body = READER + "$script:LcReason='credential_required'\n" + LOOP
    _, out, framed, _, _, _ = run_win(tmp_path, body, stdin=frame())
    assert "READHOST" not in out
    assert framed.strip() == f"resume|{USER}|{PASSWORD}", framed


@supplementary
def test_the_credential_travels_only_through_the_framed_lifecycle_call(tmp_path):
    _, _, framed, _, _, plain = run_win(tmp_path, READER + START, stdin=frame())
    assert framed.strip().endswith("|" + PASSWORD)
    assert plain.strip() == "", "a credential run used the unframed transport"


# ── framing refusals, each before any mutation ──────────────────────────────────────────────────

@supplementary
@pytest.mark.parametrize("bad,why", [
    (frame()[:-3], "truncated password"),
    (frame()[:2], "truncated length"),
    (frame() + b"x", "trailing bytes"),
    (struct.pack(">I", 0) + struct.pack(">I", 3) + b"abc", "empty account"),
    (struct.pack(">I", 3) + b"abc" + struct.pack(">I", 0), "empty password"),
    (struct.pack(">I", 99999) + b"abc", "implausible length, truncated"),
    # All 8193 bytes are present, so only the bound can refuse this one; without it the frame
    # would be accepted and a hostile length would become a real allocation.
    (struct.pack(">I", 8193) + b"a" * 8193 + struct.pack(">I", 3) + b"abc",
     "over-long account, fully supplied"),
    (struct.pack(">I", 2) + b"\xff\xfe" + struct.pack(">I", 3) + b"abc", "invalid UTF-8"),
    (b"", "no frame at all"),
])
def test_a_malformed_frame_is_refused_before_anything_is_removed(tmp_path, bad, why):
    _, out, framed, argv, _, plain = run_win(tmp_path, READER + START, stdin=bad)
    assert "DIE:" in out, f"{why}: accepted\n{out}"
    assert "Nothing has changed." in out, why
    assert framed.strip() == "" and plain.strip() == "", f"{why}: reached the component"
    assert argv.strip() == "", f"{why}: reached fmsadmin"


@supplementary
def test_invalid_credentials_fail_without_advancing_removal(tmp_path):
    _, out, framed, _, _, plain = run_win(tmp_path, READER + START, stdin=frame(), ok=False)
    assert "DIE: FM Server admin login failed. Nothing has changed." in out, out
    assert framed.strip() == "" and plain.strip() == ""


# ── the credential is not left anywhere ─────────────────────────────────────────────────────────

@supplementary
def test_the_credential_is_absent_from_the_environment_of_children(tmp_path):
    _, _, _, _, childenv, _ = run_win(tmp_path, READER + START, stdin=frame())
    assert "u=UNSET p=UNSET" in childenv, childenv
    assert PASSWORD not in childenv


@supplementary
def test_the_credential_is_absent_from_this_launchers_output_and_records(tmp_path):
    proc, out, _, _, childenv, _ = run_win(tmp_path, READER + START, stdin=frame())
    for blob in (out, proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace"),
                 childenv):
        assert PASSWORD not in blob
    assert USER in out  # the account is named on purpose; the password never is


@supplementary
def test_the_credential_is_wiped_when_the_run_ends(tmp_path):
    """RE-EXPRESSED for packet 1380-04 (was: wiped after its final framed call). The ruling that one
    frame supplies one run means the credential is deliberately HELD across start and every resume;
    what must stay true is that it does not outlive the run."""
    body = (READER + START + LOOP +
            '\nAdd-Content -LiteralPath "$L/out" -Value ("AFTER:[" + $script:LcCredentialPass + "]")\n')
    _, out, _, _, _, _ = run_win(tmp_path, body, stdin=frame())
    assert "AFTER:[]" in out, out


@supplementary
def test_the_password_reaches_only_the_existing_fmsadmin_validation(tmp_path):
    """PRE-EXISTING, OWNED FINDING - recorded, not newly accepted. The shipped validation is
    `& $fmsadmin -u <user> -p <password> list files`, so the password is in the FMSADMIN child's
    argv. The interactive path has always done this and it is unchanged by this correction. Pinned
    here so a future change that routes it elsewhere breaks a test rather than passing quietly."""
    _, _, _, argv, _, _ = run_win(tmp_path, READER + START, stdin=frame())
    assert PASSWORD in argv and "list files" in argv, argv


# ── behaviour without the option is untouched ───────────────────────────────────────────────────

@supplementary
def test_without_the_option_a_silent_run_keeps_the_resumable_stop(tmp_path):
    body = READER + "$script:LcReason='credential_required'\n" + LOOP
    _, out, framed, _, _, _ = run_win(tmp_path, body, framed=False)
    # asserted as facts, not as a wrapping: these messages are line-wrapped in the shipped script
    # and a contiguous-substring test would break the moment a word moved across the break.
    assert "never prompts" in out
    assert "recorded" in out and "resumes" in out
    assert "READHOST" not in out
    assert framed.strip() == "", "it proceeded without a credential"


@supplementary
def test_without_the_option_a_prompting_run_still_prompts(tmp_path):
    body = READER + "$script:CfmSilent = $false\nLc-ReadFmsCredential $plan\n"
    _, out, framed, _, _, _ = run_win(tmp_path, body, framed=False)
    assert "READHOST" in out, out
    assert framed.strip() == ""


# ── symmetry and the standing rules ─────────────────────────────────────────────────────────────

def test_both_launchers_implement_the_route():
    """A one-platform fix is not shippable: the parity guards require the pair to agree."""
    # The option must be DISPATCHED, not merely mentioned. Naming it only in help text would leave
    # `--credential-stdin` refused as unknown while the documentation claimed otherwise.
    assert "[switch]$CredentialStdin," in WIN
    assert "--credential-stdin) CREDENTIAL_STDIN=true" in LIN
    # ...and each platform must actually call its reader from both credential decision points.
    assert WIN.count("Lc-ReadFramedCredential $plan") == 2, "windows: start and resume"
    assert LIN.count("lc_read_framed_credential") == 3, "linux: definition, start and resume"


@supplementary
def test_the_silent_pairing_requirement_is_enforced_not_merely_documented(tmp_path):
    """Executed: the refusal must happen, not just be spelled in a message."""
    guard = region(WIN, "if ($CredentialStdin -and -not $Silent) {", "if ($retired.Count -gt 0) {")
    body = "$CredentialStdin = $true\n$Silent = $false\n" + guard
    _, out, framed, _, _, _ = run_win(tmp_path, body, framed=False)
    assert "DIE:" in out and "requires -Silent" in out, out
    assert framed.strip() == ""


def test_both_launchers_require_the_silent_mode_for_it():
    assert "-CredentialStdin requires -Silent." in WIN
    assert "--credential-stdin requires --silent." in LIN


def test_both_launchers_bound_the_field_length_and_demand_strict_utf8():
    assert "$MaxField = 4096" in WIN and "MAX = 4096" in LIN
    assert "UTF8Encoding($false, $true)" in WIN      # throwOnInvalidBytes
    assert "UnicodeDecodeError" in LIN


def test_neither_launcher_reads_an_inherited_environment_credential():
    """Packet 1236, which the first attempt at this correction violated."""
    assert "$env:FM_ADMIN_PASS" not in WIN and "$env:FM_ADMIN_USER" not in WIN
    assert "${FM_ADMIN_PASS" not in LIN


def test_the_retired_credential_options_remain_refused():
    assert "'-FmAdminUser', $FmAdminUser" in WIN and "They are gone." in WIN


def test_both_help_texts_describe_the_route_and_its_absence():
    # The Linux help is the leading comment block, which is longer than an arbitrary slice; take it
    # up to the first non-comment line rather than guessing a byte count.
    lin_help = LIN[:LIN.index("\nset -")] if "\nset -" in LIN else LIN[:6000]
    for text, opt in ((WIN[:WIN.index("#>")], "-CredentialStdin"), (lin_help, "--credential-stdin")):
        assert opt in text
        assert "big-endian" in text
        assert "incomplete_safe" in text and "resumable" in text
