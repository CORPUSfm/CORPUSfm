"""OP-031: the privileged checkout update and runtime build stamp are one transaction."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINUX = (ROOT / "installer/linux/corpusfm-update.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "installer/windows/corpusfm-update.ps1").read_text(encoding="ascii")


def test_linux_stamps_the_applied_head_before_LOADING_new_code():
    """RE-EXPRESSED for application packet 1361-01, round 3: the chain used to end at the service
    restart, and this script restarts no service now (the scheduler is retired; the web service is
    the caller waiting for the outcome). The IMPORT PROBE is the last step that trusts the new code,
    so it is the one the stamp must precede — which is what OP-031 was ever about."""
    merge = LINUX.index('merge --ff-only "$OBSERVED"')
    derive = LINUX.index('NEW_BUILD="$(read_release_build)"', merge)
    write = LINUX.index("printf '%s\\n' \"$NEW_BUILD\"", derive)
    readback = LINUX.index('!= "$NEW_BUILD"', write)
    probe = LINUX.index("import corpusfm.app.web.app", readback)

    assert merge < derive < write < readback < probe
    assert '[[ "$value" =~ ^[1-9][0-9]*$ ]]' in LINUX
    assert "rev-list --count HEAD" not in LINUX
    assert "systemctl restart" not in LINUX


def test_linux_rollback_restores_both_checkout_and_prior_stamp_state():
    preserve = LINUX.index('cp -p -- "$STAMP" "$STAMP_BACKUP"')
    merge = LINUX.index('merge --ff-only "$OBSERVED"')
    restore = LINUX[LINUX.index("restore() {"):merge]

    assert preserve < merge
    assert 'reset --hard "$OLD_HEAD"' in restore
    assert 'mv -f -- "$STAMP_STAGE" "$STAMP"' in restore
    assert 'rm -f -- "$STAMP"' in restore
    assert LINUX.count("build_stamp_failed") >= 2
    assert "build_stamp_mismatch" in LINUX


def test_windows_stamps_the_applied_head_before_LOADING_new_code():
    """The Windows twin of the Linux re-expression above (application packet 1361-01, round 3)."""
    merge = WINDOWS.index("'merge', '--ff-only', $script:Observed")
    derive = WINDOWS.index('$newBuild = Get-DeclaredReleaseBuild', merge)
    write = WINDOWS.index("Set-Content -Path $Stamp", derive)
    readback = WINDOWS.index("Get-Content $Stamp -Raw", write)
    probe = WINDOWS.index("import corpusfm.app.web.app", readback)

    assert merge < derive < write < readback < probe
    assert "$newBuild -notmatch '^[1-9][0-9]*$'" in WINDOWS
    assert "'rev-list', '--count', 'HEAD'" not in WINDOWS
    assert "Restart-Service" not in WINDOWS


def test_windows_rollback_restores_both_checkout_and_exact_prior_stamp_state():
    preserve = WINDOWS.index("[System.IO.File]::ReadAllBytes($Stamp)")
    merge = WINDOWS.index("'merge', '--ff-only', $script:Observed")
    restore = WINDOWS[WINDOWS.index("function Restore-Previous"):merge]

    assert preserve < merge
    assert "'reset', '--hard', $oldHead" in restore
    assert "[System.IO.File]::WriteAllBytes($Stamp, $oldStampBytes)" in restore
    assert "Remove-Item -Force $Stamp" in restore
    assert WINDOWS.count("build_stamp_failed") >= 2
    assert "build_stamp_mismatch" in WINDOWS


def test_both_platforms_verify_head_stamp_agreement_before_publishing_success():
    linux_final = LINUX.rindex("FINAL_BUILD=\"$(read_release_build || true)\"")
    linux_mismatch = LINUX.index("build_stamp_mismatch", linux_final)
    linux_success = LINUX.index("write_outcome completed ok", linux_mismatch)
    assert linux_final < linux_mismatch < linux_success

    windows_final = WINDOWS.rindex("$finalBuild = Get-DeclaredReleaseBuild")
    windows_mismatch = WINDOWS.index("build_stamp_mismatch", windows_final)
    windows_success = WINDOWS.index("Write-Outcome 'completed' 'ok'", windows_mismatch)
    assert windows_final < windows_mismatch < windows_success
