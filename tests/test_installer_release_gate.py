"""Release-gate runner contract: fixed report shape + v0.1018 checks (pkt 019) AND the executed-live
runner's safety guards (pkt 030) — safe-by-default, --live gated, no tag/release, secrets redacted,
wrong-box refusal."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("rg", ROOT / "scripts/installer_release_gate.py")
rg = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(rg)
_live_spec = importlib.util.spec_from_file_location("rg_live", ROOT / "scripts/_release_gate_live.py")
rg_live = importlib.util.module_from_spec(_live_spec); _live_spec.loader.exec_module(rg_live)
LIVE_SRC = (ROOT / "scripts/_release_gate_live.py").read_text(encoding="utf-8")
RG_SRC = (ROOT / "scripts/installer_release_gate.py").read_text(encoding="utf-8")


def test_report_has_the_eleven_fixed_sections():
    assert rg.REPORT_SECTIONS[0] == "bundle built"
    assert rg.REPORT_SECTIONS[-1] == "residual risks / skips"
    for box in ("Linux", "Windows"):
        for kind in ("fresh install", "anonymous public source-update", "health", "uninstall"):
            assert f"{box} {kind} proof" in rg.REPORT_SECTIONS
    assert "release tag/publish result" in rg.REPORT_SECTIONS
    assert len(rg.REPORT_SECTIONS) == 11


def test_checks_cover_the_v01018_lessons():
    pat = " ".join(rg.PUBLIC_SOURCE_CHECKS).lower()
    for token in ("deploy-key", "arm the in-app", "https", "core.sshcommand",
                  "headless", "gcm", "wincredman", "token-in-origin", "legacy"):
        assert token.lower() in pat, token
    health = " ".join(rg.HEALTH_CHECKS).lower()
    for token in ("filemakerodatabackend", "tier 2", "first admin", "proxy", "401"):
        assert token in health, token
    clean = " ".join(rg.CLEANLINESS_CHECKS).lower()
    for token in ("install root absent", "services absent", "storage db absent", "proxy removed", "pki"):
        assert token in clean, token


def test_public_gate_version_comes_from_the_release_build_not_short_git_history():
    assert 'app_root / "release-build.txt"' in RG_SRC
    assert "the public application has no valid release-build.txt identity" in RG_SRC
    assert '"rev-list", "--count"' not in RG_SRC


# ── executed-runner safety contract (packet 030) ──────────────────────────────────

def _run(args, env_extra=None):
    import os
    env = dict(os.environ)
    # ensure no stray gate secrets leak in from the dev shell
    env.pop(rg.ENV_FM_ADMIN_PASS, None)
    env.pop(rg.ENV_CFM_ADMIN_PASS, None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(ROOT / "scripts/installer_release_gate.py"), *args],
                          capture_output=True, text=True, timeout=60, env=env)


def test_live_requires_explicit_acknowledgement():
    # --live WITHOUT --yes-mutate-boxes refuses BEFORE touching any box
    r = _run(["--live"])
    assert r.returncode == 2
    assert "REFUSED" in (r.stdout + r.stderr) and "yes-mutate-boxes" in (r.stdout + r.stderr)


def test_live_requires_env_secrets_not_argv():
    # --live --yes-mutate-boxes with NO env secrets refuses before box contact; secrets are env-only
    r = _run(["--live", "--yes-mutate-boxes"])
    assert r.returncode == 2
    assert rg.ENV_FM_ADMIN_PASS in (r.stdout + r.stderr)
    # the runner declares NO argv password options (env-only) — no leakage via ps/history
    help_txt = _run(["--help"]).stdout
    assert "--fm-admin-pass" not in help_txt and "--cfm-admin-pass" not in help_txt


def test_runner_never_tags_or_releases():
    # the live orchestration must invoke none of the release/publish/push commands — it is a GATE
    for tok in rg.FORBIDDEN_RELEASE_TOKENS:
        assert tok not in LIVE_SRC, f"live orchestration must not invoke {tok!r}"
    assert "git tag" in " ".join(rg.FORBIDDEN_RELEASE_TOKENS)
    assert "gh release" in " ".join(rg.FORBIDDEN_RELEASE_TOKENS)


def test_secrets_are_redacted_value_and_base64():
    s = rg.Secrets(["sup3r-secret-pw"])
    import base64
    b64 = base64.b64encode(b"sup3r-secret-pw").decode()
    red = s.redact(f"login as admin / sup3r-secret-pw encoded {b64} ok")
    assert "sup3r-secret-pw" not in red and b64 not in red and "***" in red


def test_wrong_box_safeguard_refuses_non_clean_boxes():
    # the orchestrator verifies each box is reachable AND clean before mutating, and won't clobber
    assert "_linux_clean" in LIVE_SRC and "_win_clean" in LIVE_SRC
    assert "won't clobber it" in LIVE_SRC
    # the clean checks gate the lanes (refusal returns before _linux_lane/_win_lane)
    assert "if not _linux_clean(" in LIVE_SRC and "if not _win_clean(" in LIVE_SRC


def test_failure_is_honest_not_false_pass():
    # a lane that raises still records uninstall-not-reached + flags the box for inspection
    assert "uninstall not reached" in LIVE_SRC.lower() or "CHECK BOX MANUALLY" in LIVE_SRC
    assert "IN AN UNCLEAR STATE" in LIVE_SRC
    # overall result requires BOTH boxes left clean
    assert "overall and lin_clean and win_clean" in LIVE_SRC


def test_plan_mode_writes_skeleton_without_box_mutation(tmp_path):
    # plan mode (no --live) populates the fixed skeleton and never imports the live orchestrator
    rep = tmp_path / "rep.md"
    rg.write_skeleton(rep, "0.test")
    body = rep.read_text()
    for s in rg.REPORT_SECTIONS:
        assert f"## {s}" in body
    assert "PLAN (no box touched)" in body


def test_live_lanes_use_verified_zips_and_current_fixed_roots():
    assert "installer-files.sha256" in LIVE_SRC
    assert "sha256sum -c" in LIVE_SRC and "Get-FileHash -Algorithm SHA256" in LIVE_SRC
    assert '"sudo /opt/CORPUSfm/uninstall.sh --yes"' in LIVE_SRC
    assert "C:\\\\Program Files\\\\CORPUSfm\\\\uninstall.ps1" in LIVE_SRC
    assert "C:\\\\Program Files\\\\CORPUSfm" in LIVE_SRC
    assert '"--install-dir /opt/CORPUSfm "' in LIVE_SRC
    assert '"--fms-root \\\"/opt/FileMaker/FileMaker Server\\\" "' in LIVE_SRC
    assert '"--patch-hosting-dir /opt/CORPUSfm-Hosted\'"' in LIVE_SRC
    assert 'str(root / "installer/linux/install.sh")' not in LIVE_SRC
    assert 'str(root / "installer/windows/install.ps1")' not in LIVE_SRC


def test_live_lanes_do_not_send_retired_credential_flags_or_passwords_on_argv():
    for retired in ("--fm-admin-pass", "--admin-pass", "-FmAdminPass", "-AdminPass"):
        assert retired not in LIVE_SRC
    assert "stdin_text=secret_input" in LIVE_SRC
    assert "stdin_text=answers" in LIVE_SRC


def test_windows_console_answers_use_carriage_return_not_unix_line_feed():
    # Windows OpenSSH -tt presents Read-Host with conhost semantics: Enter is CR.  LF merely joins
    # the next answer to the current input line, then EOF can leave the installed product in place.
    windows_lane = LIVE_SRC[LIVE_SRC.index("def _win_lane"):]
    assert 'answers = f"admin\\r{fm_pw}\\radmin\\r{fm_pw}\\r"' in windows_lane
    assert 'answers = f"admin\\n{fm_pw}\\nadmin\\n{fm_pw}\\n"' not in windows_lane


def test_windows_prompted_uninstall_uses_a_real_local_pty(monkeypatch):
    called = {}

    def fake_dialog(argv, timeout, stdin_text):
        called.update(argv=argv, timeout=timeout, stdin_text=stdin_text)
        return 0, "dialog complete"

    def pipe_must_not_run(*_args, **_kwargs):
        raise AssertionError("a pipe cannot drive Windows Read-Host")

    monkeypatch.setattr(rg_live, "_run_windows_tty_dialog", fake_dialog)
    monkeypatch.setattr(rg_live, "_run", pipe_must_not_run)

    class NoSecrets:
        @staticmethod
        def redact(value):
            return value

    answers = "admin\rpassword\radmin\rpassword\r"
    rc, out = rg_live._pssh("windows", "uninstall", NoSecrets(), timeout=321,
                            stdin_text=answers, tty=True)
    assert rc == 0 and out == "dialog complete"
    assert called["timeout"] == 321 and called["stdin_text"] == answers
    assert "-tt" in called["argv"]


def test_windows_install_call_does_not_redirect_the_script_streams():
    # PowerShell 5.1 promotes nested native stderr under a call-boundary *> redirect.  With the
    # installer's Stop policy, ordinary Git clone progress then terminates a clean first install.
    windows_lane = LIVE_SRC[LIVE_SRC.index("def _win_lane"):]
    install_call = windows_lane[windows_lane.index("inst_cmd ="):windows_lane.index("rc, irc =")]
    assert "install.ps1' -Silent -Yes; " in install_call
    assert "*> $null" not in install_call


def test_linux_health_reads_the_published_storage_authority_and_exact_service_load_states():
    linux_lane = LIVE_SRC[LIVE_SRC.index("def _linux_lane"):LIVE_SRC.index("def _win_clean")]
    assert "runtime_storage.backend()" in linux_lane
    assert "FileMakerODataBackend" in linux_lane
    assert "systemctl show -p LoadState" in linux_lane
    assert "systemctl list-units --all" not in linux_lane


def test_package_identity_binds_version_commit_zip_and_sidecar(tmp_path):
    linux = tmp_path / "linux.zip"
    windows = tmp_path / "windows.zip"
    linux.write_bytes(b"linux-package")
    windows.write_bytes(b"windows-package")
    platforms = {}
    for name, path in (("linux", linux), ("windows", windows)):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (tmp_path / f"{path.name}.sha256").write_text(f"{digest}  {path.name}\n", encoding="ascii")
        platforms[name] = {"file": path.name, "sha256": digest}
    commit = "a" * 40
    (tmp_path / "release.json").write_text(json.dumps({
        "application_version": "0.2656", "commit": commit, "platforms": platforms,
    }), encoding="utf-8")

    lin, win, (_body, ok) = rg_live._package_identity(tmp_path, "0.2656", commit)
    assert ok and lin == (linux, tmp_path / "linux.zip.sha256")
    assert win == (windows, tmp_path / "windows.zip.sha256")
    _lin, _win, (body, wrong) = rg_live._package_identity(tmp_path, "0.2656", "b" * 40)
    assert not wrong and "exact candidate commit" in body


def test_version_authority_is_the_application_not_the_installer_history():
    assert "application_identity()" in RG_SRC
    assert 'app_root / "release-build.txt"' in RG_SRC
    assert '"rev-list", "--count"' not in RG_SRC
    assert '["git", "-C", str(ROOT), "rev-list", "--count", "HEAD"]' not in RG_SRC
