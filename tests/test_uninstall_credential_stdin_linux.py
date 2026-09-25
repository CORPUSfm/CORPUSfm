"""The LINUX uninstaller's framed-credential reader, executed under a real /bin/bash.

CODEX REVIEW OF 5539770 FOUND THIS SHIPPED BROKEN, and the reproduction is the reason this file
exists rather than a parity assertion:

  1. The reader wrote `account\\0password` through command substitution. A Bash variable cannot hold
     a NUL, so the separator was silently dropped - "acct\\0secret" arrived as "acctsecret".
  2. The split expressions `${parsed%%$'\\0'*}` / `${parsed#*$'\\0'}` are a syntax error. Real bash
     answers `bad substitution: no closing "}"` and leaves BOTH variables empty, which would then be
     offered to fmsadmin as a login.

A static parity test would have said Windows and Linux both "have the route" while the Linux one
could not carry a credential at all. So every test here EXTRACTS THE SHIPPED FUNCTION and runs it
under `/bin/bash` against a real binary frame.

The transfer is now two base64 records, one per line: base64 holds no NUL, no newline and nothing
bash rewrites, so each record survives command substitution byte for byte. The record count is
proved before anything is decoded, and each record is decoded through stdin rather than argv.
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LIN = (ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8")

USER, PASSWORD = "gate-admin", "gate-Pw!"


def reader_source() -> str:
    i = LIN.index("lc_read_framed_credential() {")
    return LIN[i:LIN.index("\n}\n", i) + 3]


def frame(account: str = USER, password: str = PASSWORD) -> bytes:
    out = b""
    for field in (account.encode("utf-8"), password.encode("utf-8")):
        out += struct.pack(">I", len(field)) + field
    return out


def run(tmp_path, stdin: bytes, fmsadmin_ok: bool = True, resume: bool = False):
    """Execute the SHIPPED reader under /bin/bash with stubs, and report what it produced."""
    d = tmp_path
    for f in ("out", "argv", "childenv", "framed"):
        (d / f).write_text("")
    (d / "fmsadmin").write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$*" >> "{d}/argv"\n'
        f'printf "u=[%s] p=[%s]\\n" "${{FM_ADMIN_USER-UNSET}}" "${{FM_ADMIN_PASS-UNSET}}" >> "{d}/childenv"\n'
        f"exit {0 if fmsadmin_ok else 1}\n")
    (d / "fmsadmin").chmod(0o755)
    verb = "resume" if resume else "start"
    harness = f"""#!/bin/bash
RESULT_PY="{sys.executable}"
PLAN_FMSADMIN="{d}/fmsadmin"
info() {{ printf 'INFO: %s\\n' "$*" >> "{d}/out"; }}
ok()   {{ printf 'OK: %s\\n' "$*" >> "{d}/out"; }}
die()  {{ printf 'DIE: %s\\n' "$*" >> "{d}/out"; exit 9; }}
# The framed lifecycle call, stubbed: it records the two fields SEPARATELY, so a concatenation or a
# swap is visible rather than hidden inside one blob.
lc_invoke() {{ printf '%s|%s|%s\\n' "$1" "$FM_ADMIN_USER" "$FM_ADMIN_PASS" >> "{d}/framed"; }}
{reader_source()}
lc_read_framed_credential
lc_invoke {verb}
printf 'USER=[%s]\\nPASS=[%s]\\n' "$FM_ADMIN_USER" "$FM_ADMIN_PASS" >> "{d}/out"
"""
    script = d / "harness.sh"
    script.write_text(harness)
    script.chmod(0o755)
    e = dict(os.environ)
    e.pop("FM_ADMIN_USER", None); e.pop("FM_ADMIN_PASS", None)
    proc = subprocess.run(["/bin/bash", str(script)], input=stdin,
                          capture_output=True, env=e)
    rd = lambda n: (d / n).read_text()
    return proc, rd("out"), rd("framed"), rd("argv"), rd("childenv")


# ── the credential arrives intact ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("account,password,why", [
    (USER, PASSWORD, "ordinary"),
    ("admin", "p@ss w/ord!#$%^&*()", "spaces and shell punctuation"),
    ("ünïcøde-admin", "пароль-密码-🔐", "non-ASCII in both fields"),
    ("a", "b", "single characters"),
    ("admin", "a" * 4096, "maximum permitted length"),
    ("admin", "tab\there", "embedded tab"),
    ("admin", "quote'and\"both", "both quote kinds"),
    ("admin", "$(echo pwned)`id`${HOME}", "shell metacharacters must not be evaluated"),
])
def test_the_exact_credential_reaches_the_framed_call(tmp_path, account, password, why):
    _, out, framed, _, _ = run(tmp_path, frame(account, password))
    assert "DIE:" not in out, f"{why}: refused\n{out}"
    verb, u, p = framed.rstrip("\n").split("|", 2)
    assert u == account, f"{why}: account altered"
    assert p == password, f"{why}: password altered"


def test_start_and_resume_both_carry_the_credential(tmp_path):
    for resume in (False, True):
        sub = tmp_path / ("resume" if resume else "start"); sub.mkdir()
        _, out, framed, _, _ = run(sub, frame(), resume=resume)
        assert "DIE:" not in out, out
        verb, u, p = framed.rstrip("\n").split("|", 2)
        assert verb == ("resume" if resume else "start")
        assert (u, p) == (USER, PASSWORD)


def test_the_two_fields_are_not_concatenated_or_swapped(tmp_path):
    """The exact shape of the original defect: a dropped separator joined them into one string."""
    _, _, framed, _, _ = run(tmp_path, frame("ACCOUNT", "PASSWORD"))
    _, u, p = framed.rstrip("\n").split("|", 2)
    assert u == "ACCOUNT" and p == "PASSWORD"
    assert u != "ACCOUNTPASSWORD" and p != ""


# ── every malformed frame refused, before anything is removed ───────────────────────────────────

@pytest.mark.parametrize("bad,why", [
    (frame()[:-3], "truncated password"),
    (frame()[:2], "truncated length"),
    (frame() + b"x", "trailing bytes"),
    (struct.pack(">I", 0) + struct.pack(">I", 3) + b"abc", "empty account"),
    (struct.pack(">I", 3) + b"abc" + struct.pack(">I", 0), "empty password"),
    (struct.pack(">I", 99999) + b"abc", "implausible length, truncated"),
    (struct.pack(">I", 8193) + b"a" * 8193 + struct.pack(">I", 3) + b"abc",
     "over-long account, fully supplied"),
    (struct.pack(">I", 2) + b"\xff\xfe" + struct.pack(">I", 3) + b"abc", "invalid UTF-8"),
    (b"", "no frame at all"),
])
def test_a_malformed_frame_is_refused_before_anything_is_removed(tmp_path, bad, why):
    _, out, framed, argv, _ = run(tmp_path, bad)
    assert "DIE:" in out, f"{why}: accepted\n{out}"
    assert "Nothing has changed." in out, why
    assert framed.strip() == "", f"{why}: reached the lifecycle call"
    assert argv.strip() == "", f"{why}: reached fmsadmin"


@pytest.mark.parametrize("ch,name", [("\x00", "NUL"), ("\n", "newline"), ("\r", "carriage return")])
def test_a_credential_bash_cannot_carry_faithfully_is_refused_not_mangled(tmp_path, ch, name):
    """NUL cannot exist in a Bash variable or an argv string; a newline or CR is altered by command
    substitution. Silently changing the credential would show the operator an authentication
    failure instead of the representation problem that caused it."""
    _, out, framed, argv, _ = run(tmp_path, frame("admin", "secret" + ch + "more"))
    assert "DIE:" in out and name in out, f"{name} not named in the refusal:\n{out}"
    assert framed.strip() == "" and argv.strip() == ""


def test_invalid_credentials_fail_without_advancing_removal(tmp_path):
    _, out, framed, _, _ = run(tmp_path, frame(), fmsadmin_ok=False)
    assert "DIE: FM Server admin login failed. Nothing has changed." in out, out
    assert framed.strip() == ""


# ── the credential is not left anywhere ─────────────────────────────────────────────────────────

def test_the_credential_is_absent_from_the_environment_of_children(tmp_path):
    _, _, _, _, childenv = run(tmp_path, frame())
    assert "u=[UNSET] p=[UNSET]" in childenv, childenv
    assert PASSWORD not in childenv


def test_the_credential_is_absent_from_output_transcript_and_streams(tmp_path):
    proc, out, _, _, childenv = run(tmp_path, frame())
    for blob in (out.replace(f"PASS=[{PASSWORD}]", ""),
                 proc.stdout.decode(errors="replace"), proc.stderr.decode(errors="replace"),
                 childenv):
        assert PASSWORD not in blob
    assert USER in out  # the account is named on purpose; the password never is


def test_the_password_reaches_only_the_existing_fmsadmin_validation(tmp_path):
    """PRE-EXISTING, OWNED FINDING - recorded, not newly accepted; identical to the Windows note."""
    _, _, _, argv, _ = run(tmp_path, frame())
    assert PASSWORD in argv and "list files" in argv, argv


def test_no_base64_record_is_passed_through_argv():
    """base64 of a password is trivially reversible and argv is world-readable in ps, so the decode
    must take its input on stdin."""
    reader = reader_source()
    assert "printf '%s' \"${records[0]}\" | " in reader
    assert "sys.stdin.read()" in reader
