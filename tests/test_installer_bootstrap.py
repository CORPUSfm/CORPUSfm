"""Stable bootstrap and one-use handoff source contracts.

Direct installation remains the acceptance test. These checks guard the narrow boundary that is
easy to widen accidentally: bootstraps acquire/verify/delegate, handoffs carry no credential, and
ordinary installers retain direct execution while consuming a verified handoff when one exists.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
LINUX_BOOT = (ROOT / "installer/bootstrap/linux/bootstrap.sh").read_text()
WINDOWS_BOOT = (ROOT / "installer/bootstrap/windows/bootstrap.ps1").read_text()
LINUX_INSTALL = (ROOT / "installer/linux/install.sh").read_text()
WINDOWS_INSTALL = (ROOT / "installer/windows/install.ps1").read_text()
PACKAGER = (ROOT / "installer/package-installer.sh").read_text()
_LINUX_EXERCISE_PATH = ROOT / "installer/bridge-exercise/linux/install.sh"
_WINDOWS_EXERCISE_PATH = ROOT / "installer/bridge-exercise/windows/install.ps1"
LINUX_EXERCISE = _LINUX_EXERCISE_PATH.read_text() if _LINUX_EXERCISE_PATH.exists() else ""
WINDOWS_EXERCISE = _WINDOWS_EXERCISE_PATH.read_text() if _WINDOWS_EXERCISE_PATH.exists() else ""


def test_bootstraps_select_a_series_and_verify_an_exact_zip_before_delegation():
    assert "latest.json" in LINUX_BOOT and "release.json" in LINUX_BOOT
    assert "latest.json" in WINDOWS_BOOT and "release.json" in WINDOWS_BOOT
    assert "sha256_file \"$ZIP\"" in LINUX_BOOT
    assert "Get-FileHash -LiteralPath $zip" in WINDOWS_BOOT
    assert "cfm-verify-installer-bundle.sh" in LINUX_BOOT
    assert "cfm-verify-installer-bundle.ps1" in WINDOWS_BOOT


def test_handoff_schema_is_secret_free_on_both_platforms():
    linux_record = LINUX_BOOT[LINUX_BOOT.index('json.dump({'):LINUX_BOOT.index("chmod 600")]
    windows_record = WINDOWS_BOOT[WINDOWS_BOOT.index("[ordered]@{ schema_version=1"):
                                  WINDOWS_BOOT.index("| ConvertTo-Json")]
    for forbidden in ("password", "admin_pass", "pat", "token", "credential", "repository", "git_ref"):
        assert forbidden not in linux_record.lower()
        assert forbidden not in windows_record.lower()
    for required in ("installer_series", "installer_version", "application_version", "commit",
                     "bundle_sha256", "consent", "transcript", "nonce"):
        assert required in linux_record and required in windows_record


def test_installers_accept_only_the_environment_handoff_and_consume_it_once():
    assert "CFM_BOOTSTRAP_HANDOFF" in LINUX_INSTALL
    assert "CFM_BOOTSTRAP_HANDOFF" in WINDOWS_INSTALL
    assert 'rm -f -- "$CFM_BOOTSTRAP_HANDOFF"' in LINUX_INSTALL
    assert "Remove-Item -LiteralPath $env:CFM_BOOTSTRAP_HANDOFF -Force" in WINDOWS_INSTALL
    assert "--handoff" not in LINUX_INSTALL
    assert "Handoff" not in WINDOWS_INSTALL[WINDOWS_INSTALL.index("param("):
                                            WINDOWS_INSTALL.index("$ErrorActionPreference")]


def test_packages_carry_handoff_verifiers_and_private_bootstrap_sources():
    assert "linux/cfm-verify-bootstrap-handoff.sh" in PACKAGER
    assert "windows/cfm-verify-bootstrap-handoff.ps1" in PACKAGER
    assert '"$DISTRIBUTION_ROOT/bootstrap/bootstrap.sh"' in PACKAGER
    assert '"$DISTRIBUTION_ROOT/bootstrap/bootstrap.ps1"' in PACKAGER
    # The public ZIP still has one entry point. Bootstrap source rides inside the digest-covered
    # private runtime so installation can render a durable, protected local launcher.
    runtime = PACKAGER[PACKAGER.index('LINUX_RUNTIME='):PACKAGER.index('if [[ "$PACKAGE_KIND" == exercise ]]')]
    assert "installer/bootstrap/linux/bootstrap.sh" in runtime
    runtime = PACKAGER[PACKAGER.index('WINDOWS_RUNTIME='):PACKAGER.index('if [[ "$PACKAGE_KIND" == exercise ]]', PACKAGER.index('WINDOWS_RUNTIME='))]
    assert "installer/bootstrap/windows/bootstrap.ps1" in runtime
    linux_call = next(line for line in PACKAGER.splitlines()
                      if line.strip().startswith("build_zip linux"))
    windows_call = next(line for line in PACKAGER.splitlines()
                        if line.strip().startswith("build_zip windows"))
    assert "bootstrap/linux/bootstrap.sh" not in linux_call
    assert "bootstrap/windows/bootstrap.ps1" not in windows_call


def test_installers_publish_one_durable_protected_bootstrap_and_print_its_command():
    assert 'INSTALLER_ENTRY_POINT="$INSTALL_DIR/bin/corpusfm-installer"' in LINUX_INSTALL
    assert 'install -m 0755 -o root -g root "$INSTALLER_BOOTSTRAP_STAGE" "$INSTALLER_ENTRY_POINT"' in LINUX_INSTALL
    assert 'chmod 0700 "$INSTALLER_ENTRY_POINT"' in LINUX_INSTALL
    assert '"installer_entry_point":"%s"' in LINUX_INSTALL
    assert 'echo "  Installer: sudo $INSTALLER_ENTRY_POINT"' in LINUX_INSTALL

    assert "$InstallerEntryPoint = Join-Path $BinDir 'corpusfm-installer.ps1'" in WINDOWS_INSTALL
    assert "Assert-InstallerBootstrapAcl" in WINDOWS_INSTALL
    assert "installer_entry_point      = $InstallerEntryPoint" in WINDOWS_INSTALL
    assert "powershell -ExecutionPolicy Bypass -File '" in WINDOWS_INSTALL


def test_original_package_cleanup_is_explicit_but_never_automatic():
    assert PACKAGER.count("the installed bootstrap is the durable entry point") == 2
    for installer in (LINUX_INSTALL, WINDOWS_INSTALL):
        assert "may delete the original extracted installer package and ZIP" in installer
        assert "read-only release credential" not in installer


def test_windows_bundle_verifier_accepts_and_validates_the_packager_source_identity():
    verifier = (ROOT / "installer/windows/cfm-verify-installer-bundle.ps1").read_text()
    assert "'installer_source_commit'" in verifier
    assert "$manifest.installer_source_commit -notmatch '^[0-9a-f]{40}$'" in verifier


def test_linux_handoff_verifier_accepts_the_real_schema_including_bundle_sha256(tmp_path):
    bundle = tmp_path / "bundle"; bundle.mkdir()
    handoff = bundle / ".bootstrap-handoff.json"
    handoff.write_text(json.dumps({
        "schema_version": 1, "bootstrap_protocol": 1, "bundle_protocol": 1,
        "installer_series": "series-2", "installer_version": "0.2373",
        "application_version": "0.2373", "commit": "a" * 40, "platform": "linux",
        "entry_point": "install.sh", "bundle_sha256": "b" * 64,
        "transcript": "/var/log/corpusfm/bootstrap-install-20260812-123456.log",
        "consent": "yes", "nonce": "11111111-1111-4111-8111-111111111111",
    }, indent=2, sort_keys=True) + "\n")
    handoff.chmod(0o600)
    # macOS stat lacks GNU -c; this shim supplies only the two Linux metadata observations so the
    # production verifier itself can exercise every schema/identity rule off-box.
    shim = tmp_path / "stat"
    shim.write_text("#!/bin/sh\n[ \"$2\" = %u ] && echo 0 || echo 600\n")
    shim.chmod(0o755)
    env = dict(os.environ, PATH=str(tmp_path) + os.pathsep + os.environ["PATH"])
    result = subprocess.run(
        ["bash", str(ROOT / "installer/linux/cfm-verify-bootstrap-handoff.sh"),
         str(handoff), str(bundle)], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split("\t")[:4] == ["series-2", "0.2373", "0.2373", "a" * 40]


def test_stable_bootstraps_do_not_route_retired_series_1():
    assert '[[ "$SERIES" != series-1 ]]' in LINUX_BOOT
    assert "if schema == 1:" in LINUX_BOOT
    assert "schema-1 installations are retired and have no bootstrap route" in LINUX_BOOT
    assert "if ($Series -eq 'series-1')" in WINDOWS_BOOT
    assert "if ($manifest.schema_version -eq 1)" in WINDOWS_BOOT
    assert "schema-1 installations are retired and have no bootstrap route" in WINDOWS_BOOT


def test_linux_installer_provisions_and_exercises_service_git_trust_without_a_cli_bypass():
    assert 'git config --file "$INSTALL_DIR/.gitconfig" --replace-all safe.directory' in LINUX_INSTALL
    verify = LINUX_INSTALL[LINUX_INSTALL.index("CFM_ST_SOURCE_ORIGIN="):
                           LINUX_INSTALL.index("CFM_ST_DISCOVERY=")]
    assert 'env HOME="$INSTALL_DIR" git' in verify
    assert '-c safe.directory' not in verify
    assert 'rev-parse HEAD' in verify
    assert 'CFM_ST_GIT_TRUST_DAC' in verify


def test_linux_completion_proves_both_exact_protected_resource_paths():
    discovery = LINUX_INSTALL[LINUX_INSTALL.index("CFM_ST_DISCOVERY="):
                              LINUX_INSTALL.index("# 6. STORAGE")]
    assert '"/.well-known/oauth-protected-resource${WEB_PREFIX}/mcp"' in discovery
    assert '"/.well-known/oauth-protected-resource${WEB_PREFIX}/mcp/"' in discovery
    assert '"/.well-known/oauth-authorization-server${WEB_PREFIX}/mcp"' in discovery
    assert '"/.well-known/openid-configuration${WEB_PREFIX}/mcp"' in discovery
    assert 'oauth-authorization-server${WEB_PREFIX}/mcp/"' not in discovery
    assert 'openid-configuration${WEB_PREFIX}/mcp/"' not in discovery


def test_linux_required_credentials_are_validated_before_final_consent_and_never_prompt_later():
    confirmation = LINUX_INSTALL.index('cfm_section "Confirm"')
    fms_auth = LINUX_INSTALL.index('fmsadmin -u "$FM_ADMIN_USER" -p "$FM_ADMIN_PASS" list files')
    first_admin = LINUX_INSTALL.index('First CORPUSfm admin password (min 8 chars)')
    progress = LINUX_INSTALL.index('PHASE 8')
    assert fms_auth < confirmation and first_admin < confirmation < progress
    assert 'read -rsp "  CORPUSfm admin password' not in LINUX_INSTALL[progress:]
    assert '--silent requires FM_ADMIN_USER and FM_ADMIN_PASS' in LINUX_INSTALL


def test_linux_packaged_installer_materializes_its_exact_bundle_without_repository_download():
    start = LINUX_INSTALL.index('_package_bundle="$SCRIPT_DIR/corpusfm.bundle"')
    package_branch = LINUX_INSTALL[start:LINUX_INSTALL.index('cfm_early_log_finish', start)]
    assert 'git clone -q --no-hardlinks --branch main "$_package_bundle"' in package_branch
    assert '"$(git -C "$BOOT_CLONE/repo" rev-parse HEAD)" == "$CFM_PACKAGE_COMMIT"' in package_branch
    assert 'github.com' not in package_branch and '_boot_url' not in package_branch


def test_windows_bootstrap_reads_the_canonical_two_slot_locator_value():
    assert "-Name committed_slot" in WINDOWS_BOOT
    assert ").committed_slot" in WINDOWS_BOOT
    assert "CommittedSlot" not in WINDOWS_BOOT


def test_windows_bootstrap_refusal_reaches_its_documented_exit_code():
    function = WINDOWS_BOOT[WINDOWS_BOOT.index("function Refuse"):
                            WINDOWS_BOOT.index("if (-not ([Security.Principal")]
    assert "[Console]::Error.WriteLine" in function
    assert "exit 2" in function
    assert "Write-Error" not in function


def test_windows_bootstrap_uses_typed_consent_for_handoff_and_delegation():
    assert "[switch]$Yes" in WINDOWS_BOOT and "[switch]$Silent" in WINDOWS_BOOT
    assert "$consent = if ($Silent) { 'silent' } elseif ($Yes) { 'yes' }" in WINDOWS_BOOT
    assert "if ($Yes) { $delegate += '-Yes' }" in WINDOWS_BOOT
    assert "if ($Silent) { $delegate += '-Silent' }" in WINDOWS_BOOT


def test_windows_bootstrap_forwards_named_installer_arguments_through_a_fresh_parameter_binder():
    delegation = WINDOWS_BOOT[WINDOWS_BOOT.index("$delegate = @("):
                              WINDOWS_BOOT.index("$result = $LASTEXITCODE")]
    assert "$delegate += $InstallerArguments" in delegation
    assert "& (Join-Path $PSHOME 'powershell.exe') @delegate" in delegation
    assert "& (Join-Path $bundleDir 'install.ps1')" not in delegation


def test_linux_bootstrap_silent_consent_precedence_is_argument_order_independent():
    assert 'requested_yes=false' in LINUX_BOOT
    assert 'requested_silent=false' in LINUX_BOOT
    assert '$requested_yes && consent=yes' in LINUX_BOOT
    assert '$requested_silent && consent=silent' in LINUX_BOOT
    assert LINUX_BOOT.index('$requested_yes && consent=yes') < LINUX_BOOT.index(
        '$requested_silent && consent=silent')


def test_windows_required_credentials_are_validated_before_final_consent_and_never_prompt_later():
    confirmation = WINDOWS_INSTALL.index('Section "Confirm"')
    fms_auth = WINDOWS_INSTALL.index("list files *> $null")
    first_admin = WINDOWS_INSTALL.index('First CORPUSfm admin password (min 8 chars)')
    progress = WINDOWS_INSTALL.index('Section "Progress"')
    assert fms_auth < confirmation and first_admin < confirmation < progress
    assert 'Read-Host "  CORPUSfm admin password' not in WINDOWS_INSTALL[progress:]
    assert '-Silent requires FM_ADMIN_USER and FM_ADMIN_PASS' in WINDOWS_INSTALL


def test_windows_foreign_install_directory_is_moved_only_after_final_consent():
    confirmation = WINDOWS_INSTALL.index("Cfm-Confirm -Prompt 'Proceed?'")
    progress = WINDOWS_INSTALL.index('Section "Progress"')
    move = WINDOWS_INSTALL.index('Move-Item -LiteralPath $InstallDir -Destination $ReplaceAside')
    assert confirmation < progress < move
    settings = WINDOWS_INSTALL[WINDOWS_INSTALL.index('Section "Settings"'):confirmation]
    assert 'Move-Item -LiteralPath $InstallDir' not in settings
    assert 'The existing-install replacement facts changed after confirmation' in WINDOWS_INSTALL


def test_rerunning_an_installer_never_infers_consent_from_update_scope():
    assert 'cfm_confirm "Proceed?"' in LINUX_INSTALL
    assert 'CFM_SKIP_CONFIRM' not in LINUX_INSTALL
    assert "Cfm-Confirm -Prompt 'Proceed?'" in WINDOWS_INSTALL
    assert '$CfmSkipConfirm' not in WINDOWS_INSTALL


def test_a_bridge_names_one_exact_destination_and_never_follows_target_latest():
    for bootstrap in (LINUX_BOOT, WINDOWS_BOOT):
        assert "bridge.json" in bootstrap
        assert "target_changed" not in bootstrap
    linux_bridge = LINUX_BOOT[LINUX_BOOT.index("bridge_identity="):
                               LINUX_BOOT.index("requested_yes=false")]
    windows_bridge = WINDOWS_BOOT[WINDOWS_BOOT.index("$bundleManifest ="):
                                   WINDOWS_BOOT.index("if ($InstallerArguments")]
    assert "latest.json" not in linux_bridge
    assert "latest.json" not in windows_bridge
    for value in ("target_series", "target_version", "target_commit", "target_sha"):
        assert value in linux_bridge
    for value in ("$bridge.target.series", "$bridge.target.version", "$bridge.target.commit",
                  "$targetPlatform.sha256"):
        assert value in windows_bridge


def test_bridge_destination_is_a_non_destructive_incoming_series_entry_point():
    if not LINUX_EXERCISE or not WINDOWS_EXERCISE:
        pytest.skip("retired bridge exercise is not part of the consolidated public source")
    for exercise in (LINUX_EXERCISE, WINDOWS_EXERCISE):
        lowered = exercise.lower()
        assert "installed uninstaller" in lowered
        assert "stop before every installation" in lowered
        assert "existing installation unchanged" in lowered
        assert "git reset" not in lowered
        assert "systemctl stop" not in lowered
        assert "stop-service" not in lowered
        assert "remove-service" not in lowered
    assert "CFM_BRIDGE_FROM_SERIES" in LINUX_EXERCISE
    assert "CFM_BRIDGE_FROM_SERIES" in WINDOWS_EXERCISE


def test_packager_freezes_a_series_when_it_publishes_its_bridge():
    assert '[[ ! -e "$SERIES_DIR/bridge.json" ]]' in PACKAGER
    assert 'cp "$BRIDGE_JSON" "$SERIES_DIR/bridge.json"' in PACKAGER
    assert "bridge destination release is absent" in PACKAGER
    assert "bridge.json" in PACKAGER[PACKAGER.index("build_zip()"):
                                      PACKAGER.index("# ── Linux bundle")]
