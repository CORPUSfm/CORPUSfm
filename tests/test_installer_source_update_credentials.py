"""The shipped application source is the anonymous public CORPUSfm repository.

Source acquisition and updates need no PAT, deploy key, credential store, or prompt. Git-export
credentials remain a separate user-configured product feature.
"""
from __future__ import annotations

from pathlib import Path

from application_checkout import APPLICATION_ROOT


ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
INSTALL_PS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")
LINUX_UPDATE = (ROOT / "installer/linux/corpusfm-update.sh").read_text(encoding="utf-8")
WINDOWS_UPDATE = (ROOT / "installer/windows/corpusfm-update.ps1").read_text(encoding="utf-8")
LINUX_BOOT = (ROOT / "installer/bootstrap/linux/bootstrap.sh").read_text(encoding="utf-8")
WINDOWS_BOOT = (ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_text(encoding="utf-8")
PACKAGER = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")
SETTINGS_HTML = (APPLICATION_ROOT / "corpusfm/app/web/templates/settings.html").read_text(encoding="utf-8")
OLD_DEV_PREFIX = "PRIVATE" + "_FILEMAKER_APP"
OLD_OWNER_PREFIX = "blconstructs/" + OLD_DEV_PREFIX


def test_all_source_authorities_name_the_one_public_repository():
    for source in (INSTALL_SH, INSTALL_PS, LINUX_UPDATE, WINDOWS_UPDATE, LINUX_BOOT, WINDOWS_BOOT):
        assert "CORPUSfm/CORPUSfm" in source
        assert OLD_DEV_PREFIX not in source
        assert OLD_OWNER_PREFIX not in source


def test_installer_package_accepts_no_github_credential():
    assert "--pat-file" not in PACKAGER
    assert "GITHUB_PAT" not in PACKAGER
    assert "embedded read-only PAT" not in PACKAGER
    assert "Authorization" not in PACKAGER


def test_linux_reconciles_to_public_https_and_removes_old_credential_artifacts():
    assert 'REPO_URL="https://github.com/CORPUSfm/CORPUSfm.git"' in INSTALL_SH
    assert "configure_public_source()" in INSTALL_SH
    assert "verify_public_source()" in INSTALL_SH
    body = INSTALL_SH.split("configure_public_source() {", 1)[1].split("\n}", 1)[0]
    assert 'remote set-url origin "$REPO_URL"' in body
    assert "--unset-all credential.helper" in body
    assert "--unset core.sshCommand" in body
    for old in (".git-pat", ".git-pat-helper", ".git-credentials"):
        assert old in body
    verify = INSTALL_SH.split("verify_public_source() {", 1)[1].split("\n}", 1)[0]
    assert "ls-remote" in verify
    assert "Authorization" not in verify and "GIT_PAT" not in verify


def test_windows_reconciles_to_public_https_without_a_credential_store():
    assert "$Repo = 'CORPUSfm/CORPUSfm'" in INSTALL_PS
    assert 'remote set-url origin "https://github.com/$Repo.git"' in INSTALL_PS
    assert "--unset-all credential.helper" in INSTALL_PS
    assert "--unset core.sshCommand" in INSTALL_PS
    assert "store --file=" not in INSTALL_PS
    assert "[IO.File]::WriteAllText($credStore" not in INSTALL_PS
    assert "GITHUB_PAT" not in INSTALL_PS


def test_privileged_updaters_require_the_public_origin_and_no_saved_source_secret():
    assert 'EXPECTED_ORIGIN="https://github.com/CORPUSfm/CORPUSfm.git"' in LINUX_UPDATE
    assert "CORPUSfm/CORPUSfm" in WINDOWS_UPDATE
    for source in (LINUX_UPDATE, WINDOWS_UPDATE):
        assert OLD_DEV_PREFIX not in source
        assert "Authorization" not in source
        assert "store --file=" not in source


def test_bootstraps_acquire_release_assets_anonymously():
    for source in (LINUX_BOOT, WINDOWS_BOOT):
        assert "api.github.com/repos/" in source
        assert "CORPUSfm/CORPUSfm" in source
        assert "browser_download_url" in source
        assert "Authorization" not in source
        assert "GITHUB_PAT" not in source


def test_durable_bootstrap_is_installed_byte_for_byte():
    assert 'install -m 0755 -o root -g root "$INSTALLER_BOOTSTRAP_STAGE" "$INSTALLER_ENTRY_POINT"' in INSTALL_SH
    block = INSTALL_PS[INSTALL_PS.index("$InstallerEntryPoint ="):]
    # The Windows half is an explicit COPY whose result is PROVED equal to the verified package
    # source, not a text round trip (packet 1380-02 Deliverable 3). This assertion has now been
    # re-expressed twice against the same property: it once pinned `[IO.File]::ReadAllText(...)`,
    # then the `$installedBytes[$i] -ne $sourceBytes[$i]` byte loop. Installer commit `a5cfbb2`
    # replaced that loop with one SHA-256 comparison of the two files, so the spelling moved again
    # while the property did not. Assert the property: copied, both sides digested, the two digests
    # actually compared, and no text round trip under a signature block.
    assert "Copy-Item -LiteralPath $InstallerBootstrapSource" in block
    assert "Get-FileHash -LiteralPath $InstallerBootstrapSource" in block
    assert "Get-FileHash -LiteralPath $InstallerEntryPoint" in block
    assert "$sourceHash -ne $installedHash" in block, "the two digests must actually be compared"
    assert "WriteAllText($InstallerBootstrapStage" not in block


def test_package_upgrade_aligns_remote_tracking_ref_with_verified_payload():
    linux_start = INSTALL_SH.index("Existing git checkout — advancing it to the selected local payload")
    linux_end = INSTALL_SH.index("chown -R root:", linux_start)
    linux = INSTALL_SH[linux_start:linux_end]
    assert 'update-ref "refs/remotes/origin/$GIT_TRACKED_BRANCH" "$_cfm_source_head"' in linux
    assert 'rev-parse "origin/$GIT_TRACKED_BRANCH"' in linux
    assert linux.index('reset -q --hard "$_cfm_source_head"') < linux.index("update-ref")

    win_start = INSTALL_PS.index("Existing checkout - advancing it to the exact external payload")
    win_end = INSTALL_PS.index("Assert-InstallerSourceAgreement $Src", win_start)
    windows = INSTALL_PS[win_start:win_end]
    assert 'update-ref ("refs/remotes/origin/" + $GitTrackedBranch) $ExternalSourceHead' in windows
    assert 'rev-parse ("origin/" + $GitTrackedBranch)' in windows
    assert windows.index("reset --hard $ExternalSourceHead") < windows.index("update-ref")


def test_git_export_deploy_key_feature_remains_separate():
    assert "Git Export Credentials" in SETTINGS_HTML
    assert "Generate deploy key" in SETTINGS_HTML
    assert "generate-deploy-key" in SETTINGS_HTML
    assert (APPLICATION_ROOT / "tests/test_git_credentials.py").exists()


def test_windows_native_captures_remain_error_action_preference_safe():
    assert INSTALL_PS.count("$ErrorActionPreference = 'Continue'") >= 2
