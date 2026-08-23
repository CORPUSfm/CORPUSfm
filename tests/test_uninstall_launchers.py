"""The two uninstall launchers, EXECUTED (packet 1246-09, stage 6).

**Static guards say what is not in these files; this one says what they do.** The stage fence proves
neither launcher can delete, plan, name a path or hold a credential. That is necessary and it is not
sufficient: a launcher whose whole job is a protocol — start with no credential, resume on a named
reason, acquire one only when the component asks by name, consume exactly one JSON object, map six
result words — has to be run to be believed.

So both real scripts are executed against a DOUBLE for `corpusfm-lifecycle`: a stand-in interpreter
that records the requests it was handed and answers with a chosen result and exit code. Nothing on
this machine is touched, no server is contacted, and no real installation is involved — the double is
the whole world outside the launcher.

**Two production choices exist to make this possible, and neither is a test hook.** The elevation
probe on each platform is an ordinary command (`id -u`, `whoami /groups`) rather than a shell builtin
or an in-process .NET API, because a check that cannot be observed from outside the process is a
check that can be executed exactly once — as root, on an elevated Windows box — which is to say
never. Both fail closed, and neither is the security boundary: the CLI judges every request on the
open descriptor and refuses one that is not privileged, so a run that got past the probe reaches
exactly one step further and stops there.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
INSTALLATION = "6f1d0d2a-2f1e-4c3b-9a77-1b2c3d4e5f60"

PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="PowerShell is not installed on this host")


def test_the_module_named_by_both_launchers_is_ACTUALLY_RUNNABLE():
    """The retired ``-m corpusfm.lifecycle.cli`` silently imported and exited 0 with no output."""
    proc = subprocess.run(
        [sys.executable, "-m", "corpusfm.lifecycle", "--help"],
        cwd=APPLICATION_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "corpusfm-lifecycle" in proc.stdout
    assert "uninstall" in proc.stdout


def test_WINDOWS_protects_the_request_file_not_only_its_parent():
    body = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
    written = "[IO.File]::WriteAllText($f,"
    protected = "& icacls $f /inheritance:r /grant:r"
    returned = "return $f"
    assert body.index(written) < body.index(protected) < body.index(returned, body.index(protected))
    assert "Could not protect the uninstall request file" in body


# ── the double ───────────────────────────────────────────────────────────────


def _double(script_calls: Path, answers: list, *, installation=INSTALLATION) -> str:
    """A stand-in for `python -m corpusfm.lifecycle`.

    It answers `status --json` with an installation id, records every `uninstall` invocation — the
    verb, and the request as it was actually written — and replies from a scripted queue, so a test
    says *the first call answers this and the second answers that* and the launcher's own protocol
    decides which calls happen at all.
    """
    return f'''#!/usr/bin/env python3
import json, os, shutil, stat, sys
CALLS = {str(script_calls)!r}
ANSWERS = json.loads({json.dumps(json.dumps(answers))})   # JSON, not a Python literal

argv = sys.argv[1:]
# **The double stands in for `-m corpusfm.lifecycle` and for nothing else.** Both launchers also
# use the shipped interpreter as a JSON reader (`python -c ...`), exactly as `install.sh` does, and a
# stand-in that swallowed those would be answering a question nobody asked.
if argv and argv[0] == "-c":
    import runpy, os
    os.execv(sys.executable, [sys.executable, *argv])

# **THE RUNTIME VERB, answered by really staging a runtime** (packet 1000-14). The double IS the
# interpreter the launcher found beside itself, so it stages itself: it copies its own file into the
# destination the launcher protected and reports that copy. Everything after this is then executed
# by a runtime OUTSIDE the installation, which is the whole point — a double that only printed a
# path would leave the join unexercised, and the join is what is being tested.
if "runtime" in argv:
    destination = argv[argv.index("--destination") + 1]
    staged_dir = os.path.join(destination, "python")
    os.makedirs(staged_dir, exist_ok=True)
    staged = os.path.join(staged_dir, "python.exe")
    shutil.copyfile(os.path.abspath(sys.argv[0]), staged)
    os.chmod(staged, os.stat(staged).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(json.dumps({{"result": "staged", "executable": staged, "root": destination}}))
    raise SystemExit(0)

if "status" in argv:
    report = {{"locator": "present", "manifest": "valid"}}
    if {installation!r}:
        report["installation_id"] = {installation!r}
    print(json.dumps(report))
    raise SystemExit(0)

if "uninstall" in argv and argv[argv.index("uninstall") + 1] == "plan":
    request = {{}}
    if "--request" in argv:
        with open(argv[argv.index("--request") + 1], encoding="utf-8") as handle:
            request = json.load(handle)
    with open(CALLS, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({{"verb": "plan", "request": request,
                                 "stdin_isatty": sys.stdin.isatty(),
                                 "invoked_as": os.path.abspath(sys.argv[0]),
                                 "cwd": os.getcwd()}}) + "\\n")
    print(json.dumps({{
        "result": "ready", "reason": "", "detail": "read-only plan",
        "mode": "start", "installation_id": {installation!r}, "force": False,
        "fms_state": "running", "fms_admin_login_required": False,
        "fms_admin_login_deferred": False, "fms_admin_login_reasons": [],
        "locations": {{"fms_root": "/opt/FileMaker/FileMaker Server",
                       "fmsadmin": "/bin/true", "install_dir": "/opt/CORPUSfm",
                       "patch_hosting_dir": "/opt/CORPUSfm-Hosted"}},
        "operations": [], "retained": []}}))
    raise SystemExit(0)

verb = argv[argv.index("uninstall") + 1] if "uninstall" in argv else "?"
request = {{}}
if "--request" in argv:
    with open(argv[argv.index("--request") + 1], encoding="utf-8") as handle:
        request = json.load(handle)

with open(CALLS, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({{"verb": verb, "request": request,
                             "stdin_isatty": sys.stdin.isatty(),
                             # WHICH RUNTIME the launcher used, and WHERE FROM. A child inherits its
                             # parent's working directory, so `cwd` is the launcher's own.
                             "invoked_as": os.path.abspath(sys.argv[0]),
                             "cwd": os.getcwd()}}) + "\\n")

mutating = [json.loads(line) for line in open(CALLS, encoding="utf-8").read().splitlines()
            if json.loads(line).get("verb") != "plan"]
index = min(len(mutating) - 1, len(ANSWERS) - 1)
answer = ANSWERS[index]
if answer.get("remove_executable"):
    os.unlink(os.path.abspath(sys.argv[0]))
sys.stdout.write(answer["raw"] if "raw" in answer else json.dumps(answer["body"]))
raise SystemExit(answer["code"])
'''


def _answer(result, *, code, reason="", detail="ok"):
    return {"body": {"result": result, "reason": reason, "detail": detail, "operation_id": "op",
                     "installation_id": INSTALLATION, "executed": [], "retained": [],
                     "skipped": [], "finalized": result == "completed", "observations": []},
            "code": code}


# ── the Linux launcher ───────────────────────────────────────────────────────


@pytest.fixture
def linux_box(tmp_path):
    """An installation tree shaped the way a real one is: the launcher lives at
    `<root>/src/installer/linux/uninstall.sh` and the interpreter beside it at `<root>/venv/bin`."""
    root = tmp_path / "opt" / "CORPUSfm"
    here = root / "src" / "installer" / "linux"
    here.mkdir(parents=True)
    (root / "venv" / "bin").mkdir(parents=True)
    for name in ("uninstall.sh", "_cfm_lib.sh"):
        shutil.copy(ROOT / "installer" / "linux" / name, here / name)
    (here / "uninstall.sh").chmod(0o755)
    return root


def run_linux(box, tmp_path, *, answers, args=(), elevated=True, stdin="", tmpdir=None,
              installation=INSTALLATION, sudo_rc=0):
    calls = tmp_path / "calls.jsonl"
    calls.write_text("", encoding="utf-8")
    (box / "venv" / "bin" / "python").write_text(
        _double(calls, answers, installation=installation), encoding="utf-8")
    (box / "venv" / "bin" / "python").chmod(0o755)

    shims = tmp_path / "shims"
    shims.mkdir(exist_ok=True)
    (shims / "id").write_text(f"#!/bin/sh\necho {0 if elevated else 1000}\n", encoding="utf-8")
    (shims / "sudo").write_text(
        f"#!/bin/sh\necho SUDO-CALLED >&2\nexit {sudo_rc}\n", encoding="utf-8")
    for name in ("id", "sudo"):
        (shims / name).chmod(0o755)

    env = dict(os.environ, PATH=f"{shims}:{os.environ['PATH']}", CFM_ASSUME_YES="true",
               CFM_UNINSTALL_LOG=str(tmp_path / "transcript.log"))
    if tmpdir is not None:
        env["TMPDIR"] = str(tmpdir)
    proc = subprocess.run(
        ["bash", str(box / "src" / "installer" / "linux" / "uninstall.sh"), *args],
        capture_output=True, text=True, env=env, input=stdin, timeout=60)
    recorded = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()
                if line and json.loads(line).get("verb") != "plan"]
    return proc, recorded


def test_LINUX_a_clean_uninstall_is_ONE_start_with_NO_CREDENTIAL(linux_box, tmp_path):
    proc, calls = run_linux(linux_box, tmp_path,
                            answers=[_answer("completed", code=0)], args=["--yes"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [call["verb"] for call in calls] == ["start"]
    assert calls[0]["request"]["credential_transport"] == "none"
    assert calls[0]["request"]["schema_version"] == 2
    assert calls[0]["request"]["installation_id"] == INSTALLATION
    assert calls[0]["request"]["force"] is False
    assert set(calls[0]["request"]) == {"schema_version", "installation_id", "actor", "force",
                                        "credential_transport"}


def test_LINUX_reads_the_terminal_result_after_the_installed_interpreter_is_removed(
        linux_box, tmp_path):
    """The lifecycle process survives its own POSIX unlink; the launcher's next parser did not."""
    answer = _answer("completed", code=0)
    answer["remove_executable"] = True
    proc, calls = run_linux(linux_box, tmp_path, answers=[answer], args=["--yes"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [call["verb"] for call in calls] == ["start"]
    assert not (linux_box / "venv" / "bin" / "python").exists()
    assert "CORPUSfm removed" in proc.stdout


def test_LINUX_uses_a_FIXED_system_result_reader_not_PATH_resolution():
    text = (ROOT / "installer" / "linux" / "uninstall.sh").read_text(encoding="utf-8")
    assert 'RESULT_PY="/usr/bin/python3"' in text
    assert 'command -v python' not in text
    assert '"$RESULT_PY" -I -c' in text


def test_LINUX_force_reaches_the_request_and_changes_nothing_else(linux_box, tmp_path):
    _proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                             args=["--force"])
    assert calls[0]["request"]["force"] is True
    assert calls[0]["request"]["credential_transport"] == "none"


def test_LINUX_a_PENDING_RECORD_makes_the_launcher_RESUME(linux_box, tmp_path):
    """It learns this from the component's own named reason, never by inspecting any state itself."""
    answers = [_answer("failed_before_change", code=1,
                       reason="pending_record_exists__resume_it_rather_than_starting_again"),
               _answer("completed", code=0)]
    proc, calls = run_linux(linux_box, tmp_path, answers=answers, args=["--yes"])
    assert [call["verb"] for call in calls] == ["start", "resume"]
    assert proc.returncode == 0


def test_LINUX_credential_NOT_NEEDED_never_asks(linux_box, tmp_path):
    proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                            args=["--yes"])
    assert len(calls) == 1 and calls[0]["request"]["credential_transport"] == "none"
    assert "FileMaker Server must be restarted" not in proc.stdout, "nobody was asked"


def test_LINUX_a_call_that_CANNOT_need_a_credential_is_given_NOTHING_TO_READ(linux_box, tmp_path):
    """**The stdin discipline, asserted rather than merely recorded.** A `none`-transport call is run
    with `< /dev/null`, so a transport bug cannot turn into a process waiting silently on a terminal;
    the `prompt` call inherits the console, because the CLI reads it. The double reports what it was
    handed, and this is the only place that answer is checked."""
    _proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                             args=["--yes"])
    assert calls[0]["stdin_isatty"] is False

    answers = [_answer("incomplete_safe", code=5, reason="credential_required"),
               _answer("completed", code=0)]
    _proc, calls = run_linux(linux_box, tmp_path, answers=answers, args=["--yes"])
    assert calls[1]["request"]["credential_transport"] == "prompt"
    # Not a terminal in a suite either — which is the point: `CredentialLease.read` refuses a prompt
    # on a stream that is not one, so an unattended run stops with a reason instead of blocking.
    assert calls[1]["stdin_isatty"] is False


def test_LINUX_credential_REQUIRED_resumes_with_the_PROMPT_transport(linux_box, tmp_path):
    """**The whole point of the two-call protocol.** The first call establishes the need — by name,
    before anything was touched — and only then does a second call let the CLI read the console."""
    answers = [_answer("incomplete_safe", code=5, reason="credential_required"),
               _answer("completed", code=0)]
    proc, calls = run_linux(linux_box, tmp_path, answers=answers, args=["--yes"])
    assert [call["verb"] for call in calls] == ["start", "resume"]
    assert calls[0]["request"]["credential_transport"] == "none"
    assert calls[1]["request"]["credential_transport"] == "prompt"
    assert proc.returncode == 0


def test_LINUX_SILENT_never_prompts_and_reports_the_named_need(linux_box, tmp_path):
    proc, calls = run_linux(linux_box, tmp_path,
                            answers=[_answer("incomplete_safe", code=5,
                                             reason="credential_required")],
                            args=["--silent"])
    assert [call["verb"] for call in calls] == ["start"], "silent made no second call"
    assert proc.returncode == 5
    assert "never prompts" in (proc.stdout + proc.stderr)


def test_LINUX_a_REJECTED_credential_is_NEVER_RETRIED(linux_box, tmp_path):
    """A credential that was supplied and refused cannot produce `credential_required` — the
    component only emits that word when no lease was available at all — so there is no loop here.
    Driven with the component answering a rejection AFTER the prompted resume."""
    answers = [_answer("incomplete_safe", code=5, reason="credential_required"),
               _answer("incomplete_safe", code=5, reason="failed_unknown",
                       detail="the FMS restart failed: 401")]
    proc, calls = run_linux(linux_box, tmp_path, answers=answers, args=["--yes"])
    assert [call["verb"] for call in calls] == ["start", "resume"]
    assert proc.returncode == 5, "it stops rather than asking again"


@pytest.mark.parametrize("result,code", [
    ("completed", 0), ("no_change", 0), ("failed_before_change", 1), ("rolled_back", 2),
    ("manual_action_required", 3), ("incomplete_safe", 5),
])
def test_LINUX_every_result_word_maps_to_its_exit_code(linux_box, tmp_path, result, code):
    proc, _calls = run_linux(linux_box, tmp_path, answers=[_answer(result, code=code)],
                             args=["--yes"])
    assert proc.returncode == code, proc.stdout + proc.stderr
    assert result in proc.stdout or result in proc.stderr


@pytest.mark.parametrize("raw", ["not json at all", '{"a":1}{"b":2}', "[1,2,3]", '"scalar"', ""])
def test_LINUX_MALFORMED_or_MULTIPLE_JSON_stops_the_run(linux_box, tmp_path, raw):
    """A second document, an array, a scalar or a truncated write is not a result, and reading it
    field-by-field is how a partial write becomes a false answer."""
    proc, _calls = run_linux(linux_box, tmp_path, answers=[{"raw": raw, "code": 0}], args=["--yes"])
    assert proc.returncode != 0
    assert "one readable JSON result" in (proc.stdout + proc.stderr)


def test_LINUX_a_NON_ELEVATED_run_re_execs_through_sudo_and_does_nothing_else(linux_box, tmp_path):
    proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                            args=["--yes"], elevated=False)
    assert calls == [], "nothing was invoked before elevation"
    assert "SUDO-CALLED" in proc.stderr


def test_LINUX_an_ELEVATION_FAILURE_stops_before_any_lifecycle_call(linux_box, tmp_path):
    """`exec sudo` replaces this process, so a sudo that refuses ends the run — and it must end it
    without having asked the component for anything."""
    proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                            args=["--yes"], elevated=False, sudo_rc=1)
    assert calls == [] and proc.returncode != 0


def test_LINUX_an_INTERRUPTED_run_RETRIES_as_a_resume(linux_box, tmp_path):
    """The crash contract, from the launcher's side: the first invocation stops part-way, and a
    rerun is told by the component that a record exists and continues it."""
    proc_one, calls_one = run_linux(linux_box, tmp_path,
                                    answers=[_answer("incomplete_safe", code=5,
                                                     reason="an_early_quiesce_target_refused")],
                                    args=["--yes"])
    assert proc_one.returncode == 5 and [c["verb"] for c in calls_one] == ["start"]

    answers = [_answer("failed_before_change", code=1,
                       reason="pending_record_exists__resume_it_rather_than_starting_again"),
               _answer("completed", code=0)]
    proc_two, calls_two = run_linux(linux_box, tmp_path, answers=answers, args=["--yes"])
    assert [c["verb"] for c in calls_two] == ["start", "resume"] and proc_two.returncode == 0


@pytest.mark.parametrize("retired", [
    "--keep-data", "--fm-admin-user", "--fm-admin-pass", "--install-root", "--config-home",
    "--no-fms", "--site", "--fms-root",
])
def test_LINUX_every_RETIRED_option_is_refused_as_unknown(linux_box, tmp_path, retired):
    proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                            args=["--yes", retired, "value"])
    assert proc.returncode != 0
    assert "Unknown option" in (proc.stdout + proc.stderr)
    assert calls == [], "a refused option never reaches the component"


def test_LINUX_the_request_material_is_CLEANED_UP(linux_box, tmp_path):
    """A request names an installation and an operation and is removed when the invocation ends —
    on the exit path AND on the failing one, because the trap fires either way.

    **The launcher prefers `/run` when it is writable**, so a test that only ever inspected the
    `TMPDIR` fallback would pass by looking at a directory the launcher never used. Both are checked,
    and the assertion is that NEITHER holds a leftover.
    """
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    def leftovers():
        found = set(scratch.glob("corpusfm-uninstall.*"))
        if Path("/run").is_dir():
            found |= set(Path("/run").glob("corpusfm-uninstall.*"))
        return found

    before = leftovers()
    proc, _calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                             args=["--yes"], tmpdir=scratch)
    assert proc.returncode == 0
    assert leftovers() == before

    proc, _calls = run_linux(linux_box, tmp_path,
                             answers=[{"raw": "not json", "code": 0}], args=["--yes"],
                             tmpdir=scratch)
    assert proc.returncode != 0
    assert leftovers() == before, "cleaned on the failing path too"


def test_LINUX_NO_INSTALLATION_RECORD_stops_without_guessing(linux_box, tmp_path):
    proc, calls = run_linux(linux_box, tmp_path, answers=[_answer("completed", code=0)],
                            args=["--yes"], installation="")
    assert proc.returncode != 0 and calls == []
    assert "No CORPUSfm installation record" in (proc.stdout + proc.stderr)


# ── the Windows launcher ─────────────────────────────────────────────────────


@pytest.fixture
def windows_box(tmp_path):
    root = tmp_path / "CORPUSfm"
    here = root / "src" / "installer" / "windows"
    here.mkdir(parents=True)
    (root / "python").mkdir(parents=True)
    for name in ("uninstall.ps1", "_cfm_lib.ps1"):
        shutil.copy(ROOT / "installer" / "windows" / name, here / name)
    return root


def run_windows(box, tmp_path, *, answers, args=(), elevated=True, probe_rc=0):
    calls = tmp_path / "calls.jsonl"
    calls.write_text("", encoding="utf-8")
    # `python.exe` is what the launcher looks for beside itself; on this host it is a POSIX script,
    # which pwsh runs happily. The launcher's own contract does not care what the interpreter is.
    interpreter = box / "python" / "python.exe"
    interpreter.write_text(_double(calls, answers), encoding="utf-8")
    interpreter.chmod(0o755)

    shims = tmp_path / "winshims"
    shims.mkdir(exist_ok=True)
    level = "S-1-16-12288" if elevated else "S-1-16-8192"
    (shims / "whoami").write_text(
        f"#!/bin/sh\necho 'Mandatory Label\\\\High Mandatory Level {level}'\nexit {probe_rc}\n",
        encoding="utf-8")
    (shims / "icacls").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for name in ("whoami", "icacls"):
        (shims / name).chmod(0o755)

    env = dict(os.environ, PATH=f"{shims}:{os.environ['PATH']}", TEMP=str(tmp_path / "temp"),
               ProgramData=str(tmp_path / "pd"), USERNAME="administrator")
    (tmp_path / "temp").mkdir(exist_ok=True)
    (tmp_path / "pd").mkdir(exist_ok=True)
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(box / "src" / "installer" / "windows" / "uninstall.ps1"),
         *args],
        capture_output=True, text=True, env=env, timeout=120)
    recorded = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()
                if line and json.loads(line).get("verb") != "plan"]
    return proc, recorded


@needs_pwsh
def test_WINDOWS_a_clean_uninstall_is_ONE_start_with_NO_CREDENTIAL(windows_box, tmp_path):
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=["-Yes"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert [call["verb"] for call in calls] == ["start"]
    assert calls[0]["request"]["credential_transport"] == "none"
    assert calls[0]["request"]["schema_version"] == 2
    assert set(calls[0]["request"]) == {"schema_version", "installation_id", "actor", "force",
                                        "credential_transport"}


# ── the ORDINARY Windows path runs from OUTSIDE the installation (packet 1000-14) ─────────────────
#
# **This is the control that showed 1000-14 was not finished.** The launcher runs the interpreter it
# finds beside itself — `<install_root>\python\python.exe` — so on Windows, where a running image
# cannot be unlinked, the executor's self-runtime guard refuses `install_dir` on EVERY ordinary
# uninstall. The guard is right; a uninstall that deterministically ends in
# `manual_action_required` is not.
#
# So the ordinary path stages the runtime out first. These assertions are about the JOIN — which
# interpreter actually executed the uninstall, where the launcher was standing while it ran, and
# whether the temporary material survived — not about the staging mechanism, which is the adapter's
# own suite.


@needs_pwsh
def test_WINDOWS_the_ORDINARY_uninstall_RUNS_FROM_OUTSIDE_the_installation(windows_box, tmp_path):
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=["-Yes"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert calls, "the uninstall was never invoked"
    install_root = str(windows_box.resolve())
    for call in calls:
        assert not call["invoked_as"].startswith(install_root + os.sep), (
            f"the uninstall ran {call['invoked_as']}, which is inside the installation it removes; "
            "on Windows that image cannot be unlinked and the removal refuses")
        assert not call["cwd"].startswith(install_root + os.sep) and call["cwd"] != install_root, (
            f"the launcher was standing in {call['cwd']} while removing {install_root}; a directory "
            "that is a live process's working directory cannot be removed on Windows")


@needs_pwsh
def test_WINDOWS_the_STAGED_RUNTIME_is_removed_when_the_run_ENDS(windows_box, tmp_path):
    """The adapter's material is short-lived: it exists for the invocation and nothing survives it.
    Asserted over the whole of `TEMP`, so a stage left behind under any name is caught."""
    proc, _calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                               args=["-Yes"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    leftovers = sorted(p.name for p in (tmp_path / "temp").iterdir())
    assert leftovers == [], f"temporary material survived the run: {leftovers}"


@needs_pwsh
def test_WINDOWS_force_reaches_the_request_and_changes_nothing_else(windows_box, tmp_path):
    _proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                               args=["-Force"])
    assert calls[0]["request"]["force"] is True
    assert calls[0]["request"]["credential_transport"] == "none"


@needs_pwsh
def test_WINDOWS_a_PENDING_RECORD_makes_the_launcher_RESUME(windows_box, tmp_path):
    answers = [_answer("failed_before_change", code=1,
                       reason="pending_record_exists__resume_it_rather_than_starting_again"),
               _answer("completed", code=0)]
    proc, calls = run_windows(windows_box, tmp_path, answers=answers, args=["-Yes"])
    assert [call["verb"] for call in calls] == ["start", "resume"] and proc.returncode == 0


@needs_pwsh
def test_WINDOWS_credential_NOT_NEEDED_never_asks(windows_box, tmp_path):
    """**On this platform that is the ordinary case, not a special one.** The IIS front publishes
    without an activation restart, so no proxy removal needs a credential — which the component
    establishes from the real mechanism, never from anything this launcher assumes."""
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=["-Yes"])
    assert len(calls) == 1 and calls[0]["request"]["credential_transport"] == "none"
    assert proc.returncode == 0


def test_WINDOWS_credential_REQUIRED_resumes_with_VISIBLE_FRAMED_CREDENTIAL():
    """PowerShell owns the visible prompt; the captured child receives only framed bytes.

    `Read-Host -AsSecureString` cannot be driven through redirected stdin on non-Windows pwsh, so
    this joins the already-executed framed-start primitive to the exact continuation branch and
    forbids the defective captured child-prompt path.
    """
    body = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
    loop = body[body.index("while ($script:LcReason -eq 'credential_required')"):]
    assert "Lc-ReadFmsCredential $plan" in loop
    assert "Lc-InvokeFramed 'resume' $script:LcCredentialUser $script:LcCredentialPass" in loop
    assert "Lc-Invoke 'resume' 'prompt'" not in body
    assert 'Read-Host "  FM Server admin account username [admin]"' in body
    assert 'Read-Host "  FM Server admin account password" -AsSecureString' in body


@needs_pwsh
def test_WINDOWS_failure_cleans_ITS_stage_and_restores_the_callers_directory(windows_box, tmp_path):
    """The post-stage lifetime is one finally block, including failures that call `Die`/`exit`.

    A Ctrl-C exercises the same PowerShell unwinding boundary on Windows; the executed failure is a
    deterministic cross-platform proof that cleanup is not merely the successful tail anymore.
    """
    proc, _calls = run_windows(windows_box, tmp_path,
                               answers=[{"raw": "not json", "code": 0}], args=["-Yes"])
    assert proc.returncode != 0
    assert list((tmp_path / "temp").glob("corpusfm-uninstall.*")) == []
    logs = list((tmp_path / "pd").glob("CORPUSfm-uninstall-*.log"))
    assert len(logs) == 1
    transcript = logs[0].read_text(encoding="utf-8")
    assert "restored working directory:" in transcript


def test_WINDOWS_stage_lifetime_has_ONE_try_finally_cleanup_boundary():
    body = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
    stage = body.index("# THE STAGED LIFETIME:")
    lifetime = body[stage:]
    assert lifetime.index("try {") < lifetime.index("Set-Location $env:TEMP")
    assert lifetime.rindex("} finally {") < lifetime.rindex("Lc-Cleanup") < lifetime.rindex("exit $script:LcRc")


@needs_pwsh
def test_WINDOWS_SILENT_never_prompts_and_reports_the_named_need(windows_box, tmp_path):
    proc, calls = run_windows(windows_box, tmp_path,
                              answers=[_answer("incomplete_safe", code=5,
                                               reason="credential_required")],
                              args=["-Silent"])
    assert [call["verb"] for call in calls] == ["start"]
    assert proc.returncode == 5


def test_WINDOWS_a_REJECTED_credential_is_NEVER_RETRIED():
    body = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="ascii")
    loop = body[body.index("while ($script:LcReason -eq 'credential_required')"):body.index(
        "$script:LcCredentialPass = ''; $script:LcCredentialUser = ''", body.index(
            "while ($script:LcReason -eq 'credential_required')"))]
    assert loop.count("Lc-InvokeFramed 'resume'") == 1
    assert "while ($script:LcReason -eq 'credential_required')" in loop
    assert "failed_unknown" not in loop, "only a fresh credential_required result may iterate"


@needs_pwsh
@pytest.mark.parametrize("result,code", [
    ("completed", 0), ("no_change", 0), ("failed_before_change", 1), ("rolled_back", 2),
    ("manual_action_required", 3), ("incomplete_safe", 5),
])
def test_WINDOWS_every_result_word_maps_to_its_exit_code(windows_box, tmp_path, result, code):
    proc, _calls = run_windows(windows_box, tmp_path, answers=[_answer(result, code=code)],
                               args=["-Yes"])
    assert proc.returncode == code, proc.stdout + proc.stderr


@needs_pwsh
@pytest.mark.parametrize("raw", ["not json at all", '{"a":1}{"b":2}', "[1,2,3]", '"scalar"', ""])
def test_WINDOWS_MALFORMED_or_MULTIPLE_JSON_stops_the_run(windows_box, tmp_path, raw):
    proc, _calls = run_windows(windows_box, tmp_path, answers=[{"raw": raw, "code": 0}],
                               args=["-Yes"])
    assert proc.returncode != 0
    assert "one readable JSON result" in (proc.stdout + proc.stderr)


@needs_pwsh
def test_WINDOWS_a_NON_ELEVATED_run_stops_before_any_lifecycle_call(windows_box, tmp_path):
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=["-Yes"], elevated=False)
    assert calls == [] and proc.returncode != 0
    assert "ELEVATED" in (proc.stdout + proc.stderr)


@needs_pwsh
def test_WINDOWS_an_UNREADABLE_elevation_probe_FAILS_CLOSED(windows_box, tmp_path):
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=["-Yes"], probe_rc=3)
    assert calls == [] and proc.returncode != 0


@needs_pwsh
def test_WINDOWS_an_INTERRUPTED_run_RETRIES_as_a_resume(windows_box, tmp_path):
    proc_one, calls_one = run_windows(windows_box, tmp_path,
                                      answers=[_answer("incomplete_safe", code=5,
                                                       reason="an_early_quiesce_target_refused")],
                                      args=["-Yes"])
    assert proc_one.returncode == 5 and [c["verb"] for c in calls_one] == ["start"]
    answers = [_answer("failed_before_change", code=1,
                       reason="pending_record_exists__resume_it_rather_than_starting_again"),
               _answer("completed", code=0)]
    proc_two, calls_two = run_windows(windows_box, tmp_path, answers=answers, args=["-Yes"])
    assert [c["verb"] for c in calls_two] == ["start", "resume"] and proc_two.returncode == 0


@needs_pwsh
@pytest.mark.parametrize("retired,value", [
    ("-KeepData", None), ("-InstallRoot", "C:\\CORPUSfm"), ("-ConfigHome", "C:\\ProgramData"),
    ("-FmAdminUser", "admin"), ("-FmAdminPass", "hunter2"), ("-Site", "FMWebSite"),
    ("-FmsRoot", "C:\\Program Files\\FileMaker"), ("-Prefix", "/corpusfm"),
])
def test_WINDOWS_every_RETIRED_option_is_refused_by_name(windows_box, tmp_path, retired, value):
    args = ["-Yes", retired] + ([value] if value is not None else [])
    proc, calls = run_windows(windows_box, tmp_path, answers=[_answer("completed", code=0)],
                              args=args)
    assert proc.returncode != 0
    assert "Unknown option" in (proc.stdout + proc.stderr)
    assert calls == [], "a refused option never reaches the component"


@needs_pwsh
def test_WINDOWS_NO_INSTALLATION_RECORD_stops_without_guessing(windows_box, tmp_path):
    interpreter = windows_box / "python" / "python.exe"
    interpreter.write_text("#!/usr/bin/env python3\nprint('{}')\n", encoding="utf-8")
    interpreter.chmod(0o755)
    shims = tmp_path / "winshims"
    shims.mkdir(exist_ok=True)
    (shims / "whoami").write_text(
        "#!/bin/sh\necho 'Mandatory Label High Mandatory Level S-1-16-12288'\nexit 0\n",
        encoding="utf-8")
    (shims / "whoami").chmod(0o755)
    (shims / "icacls").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (shims / "icacls").chmod(0o755)
    (tmp_path / "temp").mkdir(exist_ok=True)
    (tmp_path / "pd").mkdir(exist_ok=True)
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-File",
         str(windows_box / "src" / "installer" / "windows" / "uninstall.ps1"), "-Yes"],
        capture_output=True, text=True, timeout=120,
        env=dict(os.environ, PATH=f"{shims}:{os.environ['PATH']}", TEMP=str(tmp_path / "temp"),
                 ProgramData=str(tmp_path / "pd"), USERNAME="administrator"))
    assert proc.returncode != 0
    assert "No CORPUSfm installation record" in (proc.stdout + proc.stderr)


# ── the property both platforms must share ───────────────────────────────────


@needs_pwsh
def test_BOTH_LAUNCHERS_BUILD_THE_SAME_REQUEST(linux_box, windows_box, tmp_path):
    """**Parity, executed rather than compared as text.** The two scripts share nothing but a
    protocol, and the request is the whole of it — so the two must produce the same object, modulo the
    one field that names who is running it."""
    _p, linux_calls = run_linux(linux_box, tmp_path / "l", answers=[_answer("completed", code=0)],
                                args=["--yes"])
    _q, windows_calls = run_windows(windows_box, tmp_path / "w",
                                    answers=[_answer("completed", code=0)], args=["-Yes"])
    left = dict(linux_calls[0]["request"])
    right = dict(windows_calls[0]["request"])
    left.pop("actor"), right.pop("actor")
    assert left == right


@pytest.fixture(autouse=True)
def _isolated_tmp(tmp_path):
    (tmp_path / "l").mkdir(exist_ok=True)
    (tmp_path / "w").mkdir(exist_ok=True)
    yield
