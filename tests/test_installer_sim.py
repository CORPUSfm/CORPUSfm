"""Installer decision-path simulations (no live host).

Runs extracted installer logic against fake commands / temp roots, plus pure-Python simulators for the
sharpest behaviors. Proves anonymous public source reconciliation and first-admin decisions without
touching FMS. Windows full-script execution needs pwsh (absent here) → the Windows credential behavior
is simulated at the logic level; see test_installer_*_credentials for the static guards.
"""
from __future__ import annotations

import os
import re

from tests.installer_sim.harness import make_fake_bin, extract_sh_func, run_bash


# ── 1. Linux anonymous public source-update flow ────────────────────────────────────────────────

_GIT_FAKE = r'''
while [ "$1" = "-c" ] || [ "$1" = "-C" ]; do shift 2; done
if [ "$1" = "remote" ] && [ "$2" = "get-url" ]; then echo "git@github.com:blconstructs/REPO.git";
elif [ "$1" = "remote" ] && [ "$2" = "set-url" ]; then echo "set-url $4" >> "$FAKE_LOG";
elif [ "$1" = "config" ] && [ "$2" = "--unset" ] && [ "$3" = "core.sshCommand" ]; then echo "unset-sshcommand" >> "$FAKE_LOG";
elif [ "$1" = "config" ] && [ "$2" = "--unset-all" ] && [ "$3" = "credential.helper" ]; then echo "unset-helper" >> "$FAKE_LOG";
fi
exit 0
'''


def test_linux_public_source_flow_endstate(tmp_path):
    install_dir = tmp_path / "opt"
    (install_dir / "src" / ".git").mkdir(parents=True)
    log = tmp_path / "fakelog"
    fb = make_fake_bin(tmp_path / "bin", {
        "sudo": '[ "$1" = "-u" ] && shift 2\nexec "$@"',   # drop "-u <user>", run the rest as us
        "chown": "exit 0",                                  # can't chown to root as the test user
        "git": _GIT_FAKE,
    })
    script = "set +e\n" + extract_sh_func("gitsu") \
        + "\n" + extract_sh_func("configure_public_source") + "\nconfigure_public_source; echo RC=$?\n"
    env = {"INSTALL_DIR": str(install_dir),
           "SERVICE_USER": os.environ.get("USER", "tester"),
           "REPO_URL": "https://github.com/CORPUSfm/CORPUSfm.git", "FAKE_LOG": str(log)}
    r = run_bash(script, env, fb)
    assert "RC=0" in r.stdout, r.stderr
    logtext = log.read_text()
    # origin normalized to plain HTTPS (the fake returns an SSH origin → must be rewritten)
    assert "set-url https://github.com/CORPUSfm/CORPUSfm.git" in logtext
    assert "set-url git@github.com" not in logtext
    assert "unset-helper" in logtext
    assert "unset-sshcommand" in logtext
    assert not (install_dir / ".git-pat").exists()
    assert not (install_dir / ".git-pat-helper").exists()
    assert not (install_dir / ".ssh" / "id_ed25519").exists()   # the PAT path generates no SSH key


# ── 1b. The extracted Linux source/PAT domain helpers (detect → build → verify) ───────────────────

def _run_func(func_names, call, env, fake_bin):
    script = "set +e\n" + "\n".join(extract_sh_func(n) for n in func_names) + "\n" + call
    return run_bash(script, env, fake_bin)


def test_source_origin_https_build_is_pure(tmp_path):
    # build (pure): SSH origin → HTTPS; empty/unreadable origin → REPO_URL fallback
    fb = make_fake_bin(tmp_path / "bin", {})
    env = {"REPO_URL": "https://github.com/blconstructs/REPO.git"}
    r1 = _run_func(["source_origin_https"], 'source_origin_https "git@github.com:blconstructs/REPO.git"; echo', env, fb)
    assert "https://github.com/blconstructs/REPO.git" in r1.stdout
    assert "git@" not in r1.stdout
    r2 = _run_func(["source_origin_https"], 'source_origin_https ""; echo', env, fb)
    assert "https://github.com/blconstructs/REPO.git" in r2.stdout   # fallback to REPO_URL


def test_detect_source_state_reads_origin_helper_sshcommand(tmp_path):
    install_dir = tmp_path / "opt"; (install_dir / "src" / ".git").mkdir(parents=True)
    git = r'''
while [ "$1" = "-c" ] || [ "$1" = "-C" ]; do shift 2; done
if [ "$1" = "remote" ] && [ "$2" = "get-url" ]; then echo "https://github.com/blconstructs/REPO.git";
elif [ "$1" = "config" ] && [ "$2" = "--get" ] && [ "$3" = "credential.helper" ]; then echo "/opt/CORPUSfm/.git-pat-helper";
elif [ "$1" = "config" ] && [ "$2" = "--get" ] && [ "$3" = "core.sshCommand" ]; then exit 1;
fi
exit 0
'''
    fb = make_fake_bin(tmp_path / "bin", {"sudo": '[ "$1" = "-u" ] && shift 2\nexec "$@"', "git": git})
    env = {"INSTALL_DIR": str(install_dir), "SERVICE_USER": os.environ.get("USER", "tester")}
    r = _run_func(["gitsu", "detect_source_state"], "detect_source_state; echo", env, fb)
    out = r.stdout.strip()
    # "origin|helper|sshCommand" — HTTPS origin, the PAT helper, and NO sshCommand (the PAT-only end-state)
    assert "https://github.com/blconstructs/REPO.git|/opt/CORPUSfm/.git-pat-helper|" in out


def test_verify_public_source_is_readonly_lsremote(tmp_path):
    install_dir = tmp_path / "opt"; (install_dir / "src" / ".git").mkdir(parents=True)
    # ls-remote exit 0 → verify passes; the fake records that ONLY a read-only ls-remote was used
    git = 'while [ "$1" = "-c" ] || [ "$1" = "-C" ]; do shift 2; done\necho "$1 $2" >> "$FAKE_LOG"\nexit 0'
    log = tmp_path / "log"
    fb = make_fake_bin(tmp_path / "bin", {"sudo": '[ "$1" = "-u" ] && shift 2\nexec "$@"', "git": git})
    env = {"INSTALL_DIR": str(install_dir), "SERVICE_USER": os.environ.get("USER", "tester"), "FAKE_LOG": str(log)}
    r = _run_func(["gitsu", "verify_public_source"], "verify_public_source; echo RC=$?", env, fb)
    assert "RC=0" in r.stdout
    assert log.read_text().strip() == "ls-remote origin"   # read-only ls-remote; no mutation


# ── 2. Windows credential-store host matching (why CRLF breaks it, LF works) ──────────────────────

def _store_matches(store_bytes: bytes, want_host: str) -> bool:
    """Model git-credential-store: read lines (split on \\n, NOT \\r\\n) and match protocol+host. A
    CRLF file leaves a trailing \\r on the host, so it never matches a clean request host."""
    for raw in store_bytes.decode("ascii").split("\n"):
        if not raw:
            continue
        m = re.match(r"https://(?:[^@/]+@)?([^/]+)$", raw)
        if m and m.group(1) == want_host:
            return True
    return False


def test_windows_installer_has_no_source_credential_store():
    entry = "https://x-access-token:THEPAT@github.com"
    assert _store_matches((entry + "\r\n").encode(), "github.com") is False   # CRLF → host "github.com\r" → miss (the pkt-018 bug)
    assert _store_matches((entry + "\n").encode(), "github.com") is True       # LF → match (the fix)
    ps = (__import__("pathlib").Path(__file__).resolve().parent.parent / "installer/windows/install.ps1").read_text()
    assert "[IO.File]::WriteAllText($credStore" not in ps
    assert "store --file=" not in ps


# ── 3. First-admin: password reaches the child via ENV, never argv (process-list safety) ──────────

def test_first_admin_password_not_on_command_line(tmp_path):
    log = tmp_path / "argv.log"
    fb = make_fake_bin(tmp_path / "bin", {"python": 'echo "$@" >> "$FAKE_LOG"\nexit 0'})
    # the installer's create form: username + password handed via env (CFM_AU/CFM_AP), not argv
    script = '''CFM_AU="admin" CFM_AP="s3cretPW123" python -c "import os; mk(os.environ['CFM_AU'], os.environ['CFM_AP'])"'''
    r = run_bash(script, {"FAKE_LOG": str(log)}, fb)
    assert r.returncode == 0
    argv = log.read_text()
    assert "s3cretPW123" not in argv          # the PASSWORD VALUE never appears on the command line
    assert "import os" in argv                 # (sanity: the fake python did capture the -c argv)


# ── 3b. First-admin build_plan: the pure create-decision (packet 028) ─────────────────────────────

def _eval_first_admin_plan(state: str, has_pass: str, pw_len: str, tmp_path) -> str:
    """Run the REAL extracted build_first_admin_plan() with the given inputs and return its token."""
    fn = extract_sh_func("build_first_admin_plan")
    r = run_bash(f'{fn}\nbuild_first_admin_plan "{state}" "{has_pass}" "{pw_len}"',
                 {}, tmp_path / "bin")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_first_admin_plan_decisions(tmp_path):
    make_fake_bin(tmp_path / "bin", {})  # no fakes needed — the function is pure
    # existing users → never overwrite
    assert _eval_first_admin_plan("1", "1", "12", tmp_path) == "preserve"
    assert _eval_first_admin_plan("1", "0", "0", tmp_path) == "preserve"
    # no users + a valid password → create the first admin
    assert _eval_first_admin_plan("0", "1", "8", tmp_path) == "create"
    # Packet 1201 — the split is on KNOWLEDGE, not on outcome. All three below fail to produce an
    # admin; only the two that KNOW the store is empty are fatal.
    # KNOWN empty + no password supplied (non-interactive) → FATAL, not a warning-and-continue
    assert _eval_first_admin_plan("0", "0", "0", tmp_path) == "fail:no-pass"
    # KNOWN empty + too-short password → FATAL; never create a weak admin, never ship an unreachable box
    assert _eval_first_admin_plan("0", "1", "7", tmp_path) == "fail:short-pass"
    # UNKNOWN (the read failed) → never blindly create, and never abort an upgrade re-run over a
    # transient outage: "we could not tell" is not "there is no admin".
    assert _eval_first_admin_plan("?", "1", "12", tmp_path) == "warn:unknown"


def test_first_admin_plan_fatal_only_when_absence_is_KNOWN(tmp_path):
    """The control for packet 1201's amendment 2. Every non-creating outcome is one of exactly two
    kinds, and an unreadable store is NEVER the fatal one — collapsing them was the whole defect."""
    make_fake_bin(tmp_path / "bin", {})
    fatal = {_eval_first_admin_plan(*a, tmp_path) for a in (("0", "0", "0"), ("0", "1", "7"))}
    assert all(t.startswith("fail:") for t in fatal), fatal
    for unreadable in ("?", "", "x"):
        tok = _eval_first_admin_plan(unreadable, "1", "12", tmp_path)
        assert not tok.startswith("fail:"), \
            f"state {unreadable!r} means the read FAILED, not that no admin exists — got {tok}"


# ── 3c. FMS discovery: storage-DB path resolution (packet 028) ────────────────────────────────────

def _resolve_db_path(db_dir, stem, tmp_path) -> str:
    fn = extract_sh_func("fms_storage_db_path")
    r = run_bash(f'{fn}\nfms_storage_db_path "{db_dir}" "{stem}"', {}, tmp_path / "bin")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_fms_storage_db_path_prefers_subfolder_then_toplevel(tmp_path):
    make_fake_bin(tmp_path / "bin", {})
    dbdir = tmp_path / "Databases"
    (dbdir / "CORPUSfm").mkdir(parents=True)
    # absent in both → empty (caller dies)
    assert _resolve_db_path(dbdir, "CORPUSfm_DB", tmp_path) == ""
    # legacy top-level only → top-level
    (dbdir / "CORPUSfm_DB.fmp12").write_text("x")
    assert _resolve_db_path(dbdir, "CORPUSfm_DB", tmp_path) == str(dbdir / "CORPUSfm_DB.fmp12")
    # CORPUSfm/ subfolder present → PREFERRED over the legacy top-level
    (dbdir / "CORPUSfm" / "CORPUSfm_DB.fmp12").write_text("x")
    assert _resolve_db_path(dbdir, "CORPUSfm_DB", tmp_path) == str(dbdir / "CORPUSfm" / "CORPUSfm_DB.fmp12")


# ── 3d. Storage bootstrap: the build_storage_plan decision table (packet 028) ─────────────────────

def _storage_plan(completed, backend_set, activate_ok, tmp_path) -> str:
    fn = extract_sh_func("build_storage_plan")
    r = run_bash(f'{fn}\nbuild_storage_plan "{completed}" "{backend_set}" "{activate_ok}"',
                 {}, tmp_path / "bin")
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_build_storage_plan_decision_table(tmp_path):
    make_fake_bin(tmp_path / "bin", {})
    # never bootstrapped → bootstrap (the activate probe is irrelevant / not run)
    assert _storage_plan("0", "0", "-", tmp_path) == "bootstrap"
    assert _storage_plan("0", "1", "-", tmp_path) == "bootstrap"
    # completed + backend already active → preserve (no probe, no mutation)
    assert _storage_plan("1", "1", "-", tmp_path) == "preserve"
    # completed, backend unset, stored credential GOOD → just activate
    assert _storage_plan("1", "0", "1", tmp_path) == "activate"
    # completed, backend unset, stored credential UNUSABLE → re-bootstrap (NEVER silent LocalBackend)
    assert _storage_plan("1", "0", "0", tmp_path) == "rebootstrap"


# ── 4. Uninstall cwd-safety: no longer a sim gap ──────────────────────────────────────────────────

def test_uninstall_cwd_safety_is_statically_guarded(tmp_path, monkeypatch):
    """RE-EXPRESSED (packet 1000-14). **The seam this test recorded is gone.**

    It used to pin `Set-Location $env:TEMP` ahead of `Remove-Tree $InstallRoot` in `uninstall.ps1`,
    and said in its own docstring that the decision "can't run here (no pwsh)" — a static stand-in
    for a behaviour nothing could exercise. The 1246 rethread moved every deletion out of both
    launchers and into the lifecycle executor, so the PowerShell anchors went with it; the protection
    did not follow, which is what packet 1000-14 found.

    It is Python now, so this runs the decision instead of describing it: a removal whose target
    holds this process's working directory steps out FIRST, and the step-out lands somewhere outside
    the target. The `windows` flavour is the case the retired guard was written for, and it needs no
    Windows box to drive. The refusal half — an executing image inside the target — belongs to the
    executor's own suite (`test_uninstall_exec.py`), which owns the record and the lock.
    """
    import os
    from pathlib import Path

    from corpusfm.lifecycle import uninstall_exec_posix as ex

    class _Fake(ex.UninstallExecutor):
        FLAVOUR = "windows"
        SELF_RUNTIME_IS_REMOVABLE = False

        def __init__(self):
            pass

    # `monkeypatch.chdir` records the real working directory NOW and restores it at teardown, so the
    # guard's own `chdir` cannot leak into the rest of the session.
    monkeypatch.chdir(tmp_path)
    doomed = Path(os.getcwd())
    conflict, stepped = _Fake()._guard_self_runtime(doomed)
    assert conflict == "", conflict
    assert stepped and "stepped out of" in stepped[0], stepped
    landed = Path(os.getcwd())
    assert not ex._inside_or_is(landed, doomed, flavour="windows"), (
        f"the step-out landed on {landed}, which the removal of {doomed} would take with it")
