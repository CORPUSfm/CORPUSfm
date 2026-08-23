"""The Linux proxy validators, against the interfaces the box actually has (E5-measured).

**The defect.** `cfm-proxy-exec.sh` validated through `$FMS_ROOT/NginxServer/nginx` and
`$FMS_ROOT/HTTPServer/bin/httpd`. Measured on fms-server 2026-08-08, **neither exists** —
`find "<FMS root>" \\( -name nginx -o -name httpd \\) -type f` returns nothing. So every validator
returned 2 (*cannot validate*), the transaction treated a correct configuration as unproven, and
phase 17 rolled back on every Linux install. Same false premise as the one `linux_active_front`
carried, one layer down.

**What was measured, and what each measurement decides:**

===============  ==========================================================================
`/usr/sbin/nginx`   `root:root 0755`, not group/other-writable, in `root:root 0755 /usr/sbin`.
                    Invoked by FMS as `-c "<root>/NginxServer/conf/fms_nginx.conf"`.
`NginxServer/`      holds `conf htdocs logs restart start stop` — and `start`/`restart`/`stop`
                    are 20-byte TIMESTAMP files, not scripts. There is no bundled nginx.
`httpdctl`          `root:root 0750`. Exposes **start|stop|restart|graceful only** — it has no
                    validation verb, so it is an ACTIVATION interface and is never run here.
                    It is what revealed the real Apache invocation.
`/usr/sbin/apache2` `root:root 0755`. FMS runs it as
                    `-k <verb> -D FILEMAKER -f "<root>/HTTPServer/conf/httpd.conf"`.
`httpd.conf`        includes `conf/extra/httpd-proxy.conf` at line 493 and dereferences
                    `${HTTP_ROOT}` and `${SERVER_NAME}`. The edited fragment is a bare
                    `ProxyPass`/`<Proxy>` set with no ServerRoot, listener or MPM — it cannot
                    stand alone, which is why the WHOLE configuration is what gets checked.
===============  ==========================================================================

**Evidence class.** The predicate and the selection are EXECUTED here, by extracting the script's own
lines and running them — the same technique the installer-placement controls use, and for the same
reason: a retyped copy would prove a script written in this file. What is **not** executed here is a
successful end-to-end validation, because the policy requires a root-owned executable at a fixed
absolute path and this suite cannot create one. That gap is reported, not papered over.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXEC = ROOT / "installer" / "linux" / "cfm-proxy-exec.sh"

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the Linux executor is a bash script")

MEASURED_NGINX = "/usr/sbin/nginx"
MEASURED_APACHE = "/usr/sbin/apache2"
#: The bound is coreutils' `timeout`, at the path it occupies on the Ubuntu LTS floor this targets.
MEASURED_TIMEOUT = "/usr/bin/timeout"
RETIRED = ("$FMS_ROOT/NginxServer/nginx", "$FMS_ROOT/HTTPServer/bin/httpd")


@pytest.fixture(scope="module")
def script() -> str:
    return EXEC.read_text(encoding="utf-8")


def _code(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _extract(text: str, start_marker: str, end_marker: str) -> str:
    start = text.index(start_marker)
    return text[start:text.index(end_marker, start)]


#: GNU `stat -c` and `find -perm /MODE`, which macOS does not have. The predicate is a LINUX
#: script and is correct as written there; these shims are the two coreutils differences, doubled at
#: their own boundary so the predicate's LOGIC is what these controls measure. Both answer truthfully
#: — unlike the installer-placement shims, nothing here is stubbed to a constant.
_SHIMS = {
    "stat": r"""#!/usr/bin/env python3
import pwd, os, sys
fmt = sys.argv[2] if sys.argv[1] == "-c" else ""
path = sys.argv[-1]
if "%U" in fmt:
    try: print(pwd.getpwuid(os.stat(path).st_uid).pw_name)
    except Exception: print("")
""",
    "find": r"""#!/usr/bin/env python3
import os, stat, sys
path = sys.argv[1]
try:
    if os.stat(path).st_mode & (stat.S_IWGRP | stat.S_IWOTH): print(path)
except OSError: pass
""",
}


def _shim_dir(tmp_factory) -> Path:
    d = tmp_factory.mktemp("coreutils")
    for name, body in _SHIMS.items():
        (d / name).write_text(body, encoding="utf-8")
        os.chmod(d / name, 0o755)
    return d


@pytest.fixture(scope="module")
def coreutils(tmp_path_factory) -> Path:
    return _shim_dir(tmp_path_factory)


def _run_predicate(candidate: Path | str, script_text: str, shim: Path) -> int:
    """Run the script's OWN `validator_usable`, extracted, against a real file."""
    body = _extract(script_text, "validator_usable() {", "\nvalidate_nginx() {")
    harness = (f'export PATH="{shim}:$PATH"\n' + "set -uo pipefail\n" + body
               + f'\nvalidator_usable "{candidate}"; echo "rc=$?"\n')
    proc = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
    return int(proc.stdout.strip().rsplit("rc=", 1)[1])


def _run_bounded(timeout_path: Path | str, script_text: str, shim: Path,
                 *, argument: str = "MARKER") -> tuple[int, str]:
    """Run the script's OWN `bounded`, extracted, with `SYSTEM_TIMEOUT` bound to a real path.

    Returns the return code and everything the run wrote, so a control can prove not just the code
    but WHETHER THE ARGUMENT RAN — which is the only way to tell a refusal from the unbounded
    fallback this replaced: both used to be "not 124", and one of them started a root-run server
    with no bound at all.
    """
    body = _extract(script_text, "validator_usable() {", "\nvalidate_nginx() {")
    harness = (f'export PATH="{shim}:$PATH"\n' + "set -uo pipefail\n"
               + f'SYSTEM_TIMEOUT="{timeout_path}"\n' + body
               + f'\nout="$(bounded 5 /bin/echo {argument} 2>&1)"; echo "rc=$?"; echo "out=$out"\n')
    proc = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
    text = proc.stdout
    return int(text.split("rc=", 1)[1].splitlines()[0]), text


# ── the retired premise is gone ──────────────────────────────────────────────────────

def test_the_RETIRED_bundled_validator_paths_are_not_resolved(script: str):
    body = _code(script)
    for retired in RETIRED:
        assert retired not in body, f"the executor still resolves {retired}, which does not exist"


def test_the_measured_system_validators_are_FIXED_ABSOLUTE_constants(script: str):
    body = _code(script)
    assert f'SYSTEM_NGINX="{MEASURED_NGINX}"' in body
    assert f'SYSTEM_APACHE="{MEASURED_APACHE}"' in body
    for constant in (MEASURED_NGINX, MEASURED_APACHE):
        assert constant.startswith("/"), "a validator path must be absolute"


# ── the BOUND is privileged authority, not a convenience ─────────────────────────────
#
# It was `command -v timeout`, with an unbounded fallback when PATH found nothing. Both halves are
# defects and they are different defects: the first lets a caller CHOOSE the program run as root
# with a server as its argument; the second removes the bound entirely, and the nginx technique's
# whole verdict is "still serving when the bound expired" — so an unbounded run of a VALID
# configuration never returns at all.


def test_the_BOUND_is_a_FIXED_ABSOLUTE_constant_like_the_validators(script: str):
    body = _code(script)
    assert f'SYSTEM_TIMEOUT="{MEASURED_TIMEOUT}"' in body, "the bound is not a fixed constant"
    assert MEASURED_TIMEOUT.startswith("/"), "the bound's path must be absolute"
    assert "TIMEOUT_BIN" not in body, "the PATH-selected bound survives under its old name"


def test_the_BOUND_is_held_to_THE_SAME_privileged_command_policy(script: str):
    """One predicate, not a second implementation that can drift away from it."""
    body = _code(_extract(script, "timeout_usable() {", "\nbounded() {"))
    assert 'validator_usable "$SYSTEM_TIMEOUT"' in body, (
        "the bound is not checked by the privileged-command predicate")


def test_BOTH_validator_paths_REFUSE_when_the_bound_is_unusable(script: str):
    """Apache's `-t` returns promptly, so its bound is not the load-bearing one — but the command
    enforcing it is still executed as root on that path, and the policy is what makes that safe."""
    for start, stop in (("validate_nginx() {", "\nvalidate_apache() {"),
                        ("validate_apache() {", "\nvalidate_now() {")):
        body = _code(_extract(script, start, stop))
        assert "if ! timeout_usable; then" in body and "return 2" in body, (
            f"{start} runs a bounded command without first checking the bound's authority")


def test_there_is_NO_UNBOUNDED_FALLBACK_in_the_source(script: str):
    body = _code(_extract(script, "bounded() {", "\nvalidate_nginx() {"))
    assert '"$SYSTEM_TIMEOUT" "$secs" "$@"' in body, "the fixed bound is not what runs the command"
    assert body.count('"$@"') == 1, "the command is invoked somewhere other than through the bound"
    assert "timeout_usable || return 2" in body, "the bound may be skipped"


def test_bounded_REFUSES_and_the_COMMAND_NEVER_RUNS_when_the_bound_fails_policy(
        script, tmp_path, coreutils):
    """THE DISCRIMINATOR between a refusal and the fallback this replaced.

    The return code alone cannot tell them apart — the old fallback returned whatever the unbounded
    command returned, which for a valid nginx configuration is *never*. So the control reads whether
    the argument RAN. Two shapes, because they failed differently: a bound that is absent, and one
    that is present but fails the privileged-command policy.
    """
    absent = tmp_path / "no-timeout-here"
    rc, text = _run_bounded(absent, script, coreutils)
    assert rc == 2, f"an absent bound did not answer cannot-validate: {text}"
    assert "MARKER" not in text, "the command ran with NO BOUND when the bound was absent"

    foreign = tmp_path / "timeout"
    foreign.write_text("#!/bin/sh\nshift\nexec \"$@\"\n", encoding="utf-8")
    foreign.chmod(0o755)
    assert os.stat(foreign).st_uid != 0, "this control needs a non-root-owned file to mean anything"
    rc, text = _run_bounded(foreign, script, coreutils)
    assert rc == 2, f"a foreign-owned bound was accepted: {text}"
    assert "MARKER" not in text, "the command ran through a bound that fails the policy"


def test_bounded_ACTUALLY_RUNS_the_fixed_bound_when_it_IS_usable(script, coreutils):
    """The accepting half. Without it, a `bounded` that refused EVERYTHING would score perfectly
    above — and would silently make every Linux install unvalidatable.

    `/bin/echo` stands in for the bound, so what it prints IS the argument vector the executor
    handed to `/usr/bin/timeout`: the seconds first, then the command. This box has no
    `/usr/bin/timeout` to run for real (macOS ships none), and that gap is reported, not papered
    over — the shipped path is proven on Linux, not here.
    """
    stand_in = "/bin/echo"
    if _run_predicate(stand_in, script, coreutils) != 0:
        pytest.skip(f"{stand_in} does not satisfy the privileged-command policy on this box")
    rc, text = _run_bounded(stand_in, script, coreutils)
    assert rc == 0, text
    assert "out=5 /bin/echo MARKER" in text, (
        f"the bound was not invoked as <bound> <seconds> <command>: {text}")


def test_HTTPDCTL_IS_NEVER_INVOKED(script: str):
    """It exposes start|stop|restart|graceful and no validation verb — running it would ACTIVATE.

    Measured from its own source on the box. It told us how FMS invokes Apache; it is not a
    validator and this executor must never restart a front.
    """
    assert "httpdctl" not in _code(script), "the executor invokes httpdctl, which only activates"


# ── the privileged-command policy, EXECUTED ──────────────────────────────────────────

def test_a_MISSING_validator_is_not_usable(script, tmp_path, coreutils):
    assert _run_predicate(tmp_path / "nothing-here", script, coreutils) == 1


def test_a_NON_EXECUTABLE_validator_is_not_usable(script, tmp_path, coreutils):
    candidate = tmp_path / "nginx"
    candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate.chmod(0o644)
    assert _run_predicate(candidate, script, coreutils) == 1


def test_a_GROUP_or_WORLD_WRITABLE_validator_is_not_usable(script, tmp_path, coreutils):
    for mode in (0o775, 0o757):
        candidate = tmp_path / f"nginx{mode:o}"
        candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        candidate.chmod(mode)
        assert _run_predicate(candidate, script, coreutils) == 1, oct(mode)


def test_a_SYMLINKED_validator_is_not_usable(script, tmp_path, coreutils):
    """A substituted validator: the name is right and the target is somebody else's."""
    real = tmp_path / "elsewhere"
    real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    real.chmod(0o755)
    link = tmp_path / "nginx"
    link.symlink_to(real)
    assert _run_predicate(link, script, coreutils) == 1


def test_a_DIRECTORY_named_like_a_validator_is_not_usable(script, tmp_path, coreutils):
    (tmp_path / "nginx").mkdir()
    assert _run_predicate(tmp_path / "nginx", script, coreutils) == 1


def test_a_FOREIGN_OWNED_validator_is_not_usable(script, tmp_path, coreutils):
    """Owned by anyone but root. Executed against a real file — this suite runs unprivileged, so
    every file it creates is already foreign-owned, which is exactly the condition under test."""
    candidate = tmp_path / "nginx"
    candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate.chmod(0o755)
    assert os.stat(candidate).st_uid != 0, "this control needs a non-root-owned file to mean anything"
    assert _run_predicate(candidate, script, coreutils) == 1


def test_the_PREDICATE_ACCEPTS_a_root_owned_non_writable_executable(script, coreutils):
    """The positive half, against a real file this box genuinely has: `/bin/sh`.

    Without it, a predicate that refused EVERYTHING would score perfectly above.
    """
    for real_root_binary in ("/bin/sh", "/bin/cat"):
        if Path(real_root_binary).is_file() and os.stat(real_root_binary).st_uid == 0:
            assert _run_predicate(real_root_binary, script, coreutils) == 0, real_root_binary
            return
    pytest.skip("no root-owned system binary available to prove the accepting half")


# ── what each validator actually checks ──────────────────────────────────────────────

def test_nginx_validates_the_EXACT_FMS_MAIN_CONFIG_already_selected(script: str):
    body = _extract(script, "validate_nginx() {", "\nvalidate_apache() {")
    assert '"$SYSTEM_NGINX" -c "$CONF"' in body, "nginx is not validated against the selected config"
    assert "$FMS_ROOT/NginxServer/conf" not in _code(body), \
        "the validator re-derives the config instead of using the one already selected from the root"


def test_nginx_keeps_the_BOUND_and_the_BIND_CONFLICT_reading(script: str):
    body = _code(_extract(script, "validate_nginx() {", "\nvalidate_apache() {"))
    assert "if ! timeout_usable; then" in body and "return 2" in body, \
        "the bound is no longer required"
    assert "bounded 8" in body, "the timed foreground start is gone"
    assert "Address already in use" in body, "the bind-conflict-is-valid reading is gone"
    assert '"$rc" -eq 124' in body, "running to the bound is no longer read as valid"


def test_apache_validates_the_WHOLE_configuration_NOT_the_edited_fragment(script: str):
    """`$CONF` for apache is the included fragment. The check must name `httpd.conf`.

    The fragment is a bare ProxyPass set — no ServerRoot, no listener, no MPM — so `-f` on it alone
    would fail for reasons unrelated to our block, and passing would prove nothing about the server
    that has to load it.
    """
    body = _extract(script, "validate_apache() {", "\nvalidate_now() {")
    assert 'main="$FMS_ROOT/HTTPServer/conf/httpd.conf"' in body, \
        "apache does not validate the FMS main configuration"
    assert '-f "$main"' in body
    assert '-f "$CONF"' not in body, "apache validates the edited fragment as if it stood alone"
    assert "-t " in body, "the syntax check is gone"


def test_apache_supplies_the_variables_the_MAIN_CONFIG_dereferences(script: str):
    """`httpd.conf` uses `ServerRoot "${HTTP_ROOT}"` and `ServerName "${SERVER_NAME}"` — measured.

    httpdctl exports both. Without them the check fails on an unset variable rather than on our edit,
    which is a false negative that looks exactly like a real syntax error.
    """
    body = _extract(script, "validate_apache() {", "\nvalidate_now() {")
    assert "HTTP_ROOT=" in body and "SERVER_NAME=" in body
    assert "-D FILEMAKER" in body, "FMS's own define is not mirrored"


def test_a_MISSING_main_apache_config_is_cannot_validate(script: str):
    body = _extract(script, "validate_apache() {", "\nvalidate_now() {")
    assert 'if [[ ! -f "$main" ]]; then' in body and "return 2" in body, \
        "a missing main configuration is not reported as cannot-validate"


def test_both_validators_answer_CANNOT_VALIDATE_as_2_not_as_failure(script: str):
    """2 and 1 mean different things: 2 is *unproven*, 1 is *proven bad*. Both restore, and the
    distinction is what the caller reports."""
    for start, stop in (("validate_nginx() {", "\nvalidate_apache() {"),
                        ("validate_apache() {", "\nvalidate_now() {")):
        body = _extract(script, start, stop)
        assert "return 2" in body, f"{start} has no cannot-validate answer"


# ── the fences that must survive ─────────────────────────────────────────────────────

def test_NO_PATH_LOOKUP_selects_ANY_command_this_runs_as_root(script: str):
    """RE-EXPRESSED (2026-08-09). The carve-out for `timeout` is gone, and it was the defect.

    This used to permit exactly one PATH lookup and say so: *"`timeout` is still located by PATH and
    is NOT a validator — the distinction is the point."* The distinction does not hold. The bound is
    the program this process EXECUTES AS ROOT, with the validator as its argument, so PATH selecting
    it is the same hazard one layer out — a caller who can prepend a directory to PATH never needs to
    touch the validator at all. The surviving rule is therefore stronger and has no exception: **no
    PATH lookup selects anything this executor runs.**
    """
    body = _code(script)
    for lookup in ("command -v nginx", "command -v apache", "command -v httpd",
                   "command -v timeout", "which nginx", "which apache", "which httpd",
                   "which timeout"):
        assert lookup not in body, f"a root-run command is resolved through {lookup}"
    assert body.count("command -v") == 0, "a PATH lookup appeared; there is no permitted one"
    # `which` is matched only in its INVOKED forms. The word itself is ordinary English and appears
    # in refusal text the executor prints ("refusing to guess which is current"), so a bare scan for
    # it reports the product's own prose as the violation — this repo's guards have made that
    # mistake three times and it is not being made a fourth.
    for invoked in ("$(which", "`which", "= which", "; which", "|| which"):
        assert invoked not in body, f"a PATH lookup appeared as {invoked}"


def test_NO_CALLER_SELECTED_validator(script: str):
    """No option, environment variable or argument may name the executable this runs as root."""
    body = _code(script)
    for injected in ("--validator", "--nginx-bin", "--apache-bin", "CFM_VALIDATOR",
                     "${VALIDATOR", "$VALIDATOR_BIN"):
        assert injected not in body, f"the validator can be selected by {injected}"


def test_the_validators_ACTIVATE_NOTHING(script: str):
    body = _code(_extract(script, "SYSTEM_NGINX=", "\nvalidate_now() {"))
    for activation in ("fmsadmin", "systemctl", "-k start", "-k stop", "-k restart",
                       "-k graceful", "-s reload", "reload", "kill "):
        assert activation not in body, f"a validator performs {activation}"


def test_no_process_supplied_text_is_SHELL_EVALUATED(script: str):
    # COMMENTS STRIPPED. The rationale above these functions quotes `nginx -t` in backticks while
    # explaining why it is not used, and a scan that cannot tell prose from code reports the
    # explanation as the violation. Third time this trap has fired in this packet.
    body = _code(_extract(script, "SYSTEM_NGINX=", "\nvalidate_now() {"))
    for evaluation in ("eval ", "$(cat", "`", "source ", ". /"):
        assert evaluation not in body, f"a validator uses {evaluation}"


def test_the_transaction_guarantees_are_untouched(script: str):
    """This correction changed WHICH binary validates. It changed nothing about the transaction."""
    body = _code(script)
    for guarantee, why in (
        ("restore_backup", "exact restoration"),
        ("cfmbak", "same-directory before-images"),
        ("validate_now; vrc=$?", "validate-after-publish ordering"),
        ("exact bytes restored and verified", "restoration read-back"),
    ):
        assert guarantee in body, f"{why} is gone"


# ── the parent directory, which the file's own mode cannot speak for ─────────────────

def _a_real_root_owned_binary():
    for candidate in ("/bin/sh", "/bin/cat", "/bin/echo"):
        path = Path(candidate)
        if path.is_file() and os.stat(path).st_uid == 0:
            return path
    return None


def test_the_PARENT_RULE_alone_refuses_an_OTHERWISE_PERFECT_validator(script, tmp_path, coreutils):
    """THE DISCRIMINATOR for the parent half, and it changes exactly one thing.

    The same root-owned, non-writable binary is addressed twice: once by its real path, once through
    a SYMLINKED directory. The file the predicate stats is the same file and passes every file-level
    check both times — `-f` follows the link, and the final component is not itself a link. Only the
    containing directory differs, so a refusal in the second case can come from nothing but the
    parent rule. Without this, the writable-parent control below would be a restatement of the file
    rule: every file this suite creates is already foreign-owned and would refuse anyway.
    """
    real = _a_real_root_owned_binary()
    if real is None:
        pytest.skip("no root-owned system binary available to discriminate the parent rule")

    assert _run_predicate(real, script, coreutils) == 0, \
        "the accepting half does not accept a root-owned binary in a root-owned directory"

    link = tmp_path / "sbin"
    link.symlink_to(real.parent)              # the ONLY difference
    assert _run_predicate(link / real.name, script, coreutils) == 1, \
        "a symlinked containing directory was accepted; the parent rule is not reached"


def _a_root_owned_but_writable_executable():
    """A REAL file that is root-owned, executable, group- or other-writable — and whose parent is
    root-owned and NOT writable, so a refusal can only be attributed to the FILE's own mode.

    Discovered rather than fabricated, because this suite cannot create a root-owned file, and a
    fabricated one would be refused by the OWNER rule before its writability was ever consulted —
    which is precisely how the corresponding mutation survived its first run.
    """
    import stat as _stat

    for root in ("/Library/ColorSync/Profiles", "/Library/Preferences", "/usr/local/bin"):
        base = Path(root)
        if not base.is_dir():
            continue
        parent = os.stat(base)
        if parent.st_uid != 0 or parent.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
            continue
        try:
            entries = list(base.iterdir())
        except OSError:
            continue
        for candidate in entries:
            try:
                info = os.stat(candidate, follow_symlinks=False)
            except OSError:
                continue
            if not _stat.S_ISREG(info.st_mode) or candidate.is_symlink():
                continue
            if info.st_uid != 0:
                continue
            if not info.st_mode & _stat.S_IXUSR:
                continue
            if info.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
                return candidate
    return None


def test_the_FILE_WRITABILITY_RULE_alone_refuses_a_root_owned_executable(script, coreutils):
    """THE DISCRIMINATOR for the file's own mode.

    Every file this suite can create is foreign-owned, so the OWNER rule refuses it first and any
    control built on one proves nothing about writability — measured: the mutation that removed this
    very check SURVIVED against such a file. This uses a real file that passes owner, type and
    executability and whose parent is clean, so writability is the only rule left to refuse it.
    """
    candidate = _a_root_owned_but_writable_executable()
    if candidate is None:
        pytest.skip("no root-owned, executable, group-writable file with a clean parent to test with")
    assert os.stat(candidate).st_uid == 0
    assert _run_predicate(candidate, script, coreutils) == 1, (
        f"{candidate} is root-owned but group- or world-writable and was accepted as a validator")


def test_a_WRITABLE_PARENT_is_refused(script, tmp_path, coreutils):
    """A binary nobody can edit, inside a directory anybody can rewrite, is not protected: they need
    not modify it, they unlink it and put their own there."""
    parent = tmp_path / "sbin"
    parent.mkdir()
    candidate = parent / "nginx"
    candidate.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    candidate.chmod(0o755)
    parent.chmod(0o777)
    assert _run_predicate(candidate, script, coreutils) == 1


def test_the_predicate_checks_BOTH_the_file_and_its_directory(script: str):
    body = _extract(script, "validator_usable() {", "\nvalidate_nginx() {")
    code = _code(body)
    assert code.count('stat -c') == 2, "the owner is not checked on both the file and its directory"
    assert code.count("-perm /022") == 2, "writability is not checked on both"
    assert '! -L "$dir"' in code and "-d \"$dir\"" in code, "the directory's own type is not checked"


# ── the TEST-ONLY materialization, guarded ───────────────────────────────────────────

def test_the_materialized_copy_replaces_EXACTLY_the_two_validators(tmp_path):
    """Rule 4's guard, exercised. The instrumented flow suite is only evidence about the shipped
    executor if the copy IS the shipped executor everywhere else."""
    from tests import proxy_exec_materialize as mz

    copy = mz.materialize(tmp_path / "e.sh", outcome=mz.VALID)
    original = mz.REAL_EXECUTOR.read_text(encoding="utf-8")
    text = copy.read_text(encoding="utf-8")

    for name in mz.REPLACEABLE:
        assert text.count(f"{name}() {{") == 1
        assert f"TEST-ONLY: deterministic" in text
    # Everything the flow depends on is verbatim.
    for verbatim in ('SYSTEM_NGINX="/usr/sbin/nginx"', 'SYSTEM_APACHE="/usr/sbin/apache2"',
                     "validator_usable() {", "restore_backup", "cfmbak"):
        assert verbatim in text, f"{verbatim} did not survive materialization"
    assert original != text


def test_the_materializer_REFUSES_a_source_it_cannot_transform_exactly_once(tmp_path):
    """The guard must fail closed, not silently do nothing."""
    from tests import proxy_exec_materialize as mz

    doubled = tmp_path / "doubled.sh"
    doubled.write_text(mz.REAL_EXECUTOR.read_text(encoding="utf-8")
                       + "\nvalidate_nginx() {\n  return 0\n}\n", encoding="utf-8")
    with pytest.raises(mz.TransformationRefused):
        mz.materialize(tmp_path / "out.sh", outcome=mz.VALID, source=doubled)

    missing = tmp_path / "missing.sh"
    missing.write_text("#!/bin/bash\necho nothing\n", encoding="utf-8")
    with pytest.raises(mz.TransformationRefused):
        mz.materialize(tmp_path / "out2.sh", outcome=mz.VALID, source=missing)


def test_the_materializer_REFUSES_an_outcome_it_does_not_define(tmp_path):
    from tests import proxy_exec_materialize as mz

    with pytest.raises(mz.TransformationRefused):
        mz.materialize(tmp_path / "out.sh", outcome="probably-fine")


def test_each_outcome_answers_its_own_return_code(tmp_path):
    from tests import proxy_exec_materialize as mz

    for outcome, rc in ((mz.VALID, 0), (mz.INVALID, 1), (mz.UNAVAILABLE, 2)):
        text = mz.materialize(tmp_path / f"{outcome}.sh", outcome=outcome).read_text(encoding="utf-8")
        body = _extract(text, "validate_nginx() {", "\nvalidate_apache() {")
        assert f"return {rc}" in body, (outcome, body)
