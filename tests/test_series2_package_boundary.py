"""Series 2 packages own acquisition and their private installer runtime."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGER = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")
LINUX = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "installer/windows/install.ps1").read_text(encoding="ascii")


def test_series_2_is_the_default_release_channel():
    assert 'SERIES="${CORPUSFM_INSTALLER_SERIES:-series-2}"' in PACKAGER


def test_public_package_needs_no_repository_credential_and_uses_declared_release_identity():
    assert "--pat-file" not in PACKAGER
    assert "Authorization" not in PACKAGER
    assert ("PRIVATE" + "_FILEMAKER_APP") not in PACKAGER
    assert 'APP_MATERIALIZED/release-build.txt' in PACKAGER
    assert "selected public commit has no valid release-build.txt" in PACKAGER


def test_each_package_carries_one_digest_covered_private_runtime():
    # RE-EXPRESSED for packet 1380-04 (was: `cp "$runtime" "$stage/installer-runtime.zip"`). The
    # packager gained a signing seam and builds the nested archive after adoption, so the variable
    # changed name. The rule is unchanged: each package carries exactly ONE nested runtime archive,
    # placed at exactly that member name, and both installers read it from there.
    assert 'cp "$runtime_zip" "$stage/installer-runtime.zip"' in PACKAGER
    assert PACKAGER.count('"$stage/installer-runtime.zip"') == 1
    for required in (
        "installer/requirements-server.txt",
        "installer/linux/uninstall.sh",
        "installer/linux/cfm-proxy-exec.sh",
        "installer/windows/uninstall.ps1",
        "installer/windows/cfm-proxy-exec.ps1",
        "installer/bootstrap/linux/bootstrap.sh",
        "installer/bootstrap/windows/bootstrap.ps1",
    ):
        assert required in PACKAGER
    assert "installer-runtime.zip" in LINUX
    assert "installer-runtime.zip" in WINDOWS


def test_public_zip_has_no_uninstaller_or_series_1_adapter_entry_point():
    # RE-EXPRESSED for packet 1380-04 (was: lines beginning `build_zip `). The outer members of each
    # platform ZIP are now chosen by `stage_platform`. The rule is unchanged: neither an uninstaller
    # nor a Series 1 migration launcher is a distribution entry point.
    outer_calls = [line for line in PACKAGER.splitlines()
                   if line.strip().startswith("stage_platform ")]
    assert outer_calls
    for line in outer_calls:
        assert "uninstall" not in line
        assert "migrate-legacy" not in line


def test_linux_materializes_only_the_exact_bundled_application_commit():
    start = LINUX.index('_package_bundle="$SCRIPT_DIR/corpusfm.bundle"')
    end = LINUX.index('cfm_early_log_finish', start)
    block = LINUX[start:end]
    assert 'git clone -q --no-hardlinks --branch main "$_package_bundle"' in block
    assert 'rev-parse HEAD)" == "$CFM_PACKAGE_COMMIT"' in block
    assert "github.com" not in block
    assert "for _attempt in" not in block


def test_final_series_1_manifest_refuses_before_any_series_2_deployment():
    phrase = "Series 2 will not overwrite, upgrade, adopt or convert it"
    assert phrase in LINUX and phrase in WINDOWS

    linux_gate = LINUX.index('PREEXISTING_INSTALLER_SERIES" == series-1')
    assert linux_gate < LINUX.index('_package_bundle="$SCRIPT_DIR/corpusfm.bundle"')
    assert linux_gate < LINUX.index("apt-get update -qq")
    assert 'installer["series"]' in LINUX[LINUX.index("manifest = json.loads"):linux_gate]

    windows_gate = WINDOWS.index("$published.installer.series) -eq 'series-1'")
    assert windows_gate < WINDOWS.index(". $LibPath")
    assert windows_gate < WINDOWS.index("Prepare-ExternalSourceAdvance $Src")
    for locator_fact in ("committed_slot", "manifest_relative_path", "install_dir"):
        assert locator_fact in WINDOWS[WINDOWS.index("$PublishedLocatorRoot"):windows_gate]


def test_verified_package_recovers_a_journal_without_rebuilding_the_install_root_first():
    # RE-EXPRESSED TWICE, and the rule has never changed: the recovery source archive is produced,
    # and it is added to the nested runtime archive of each platform.
    #   * packet 1380-04 retired `RECOVERY_SOURCE_ARCHIVE=` plus `PACKAGER.count('zip -q -j "$') >= 2`,
    #     because the archive moved into the signing candidate and the per-platform assembly;
    #   * packet 1380-03 retired the `zip -q -j` spelling, because archives are now written by
    #     `zip_deterministic.py` so that repacking one frozen tree is reproducible. The recovery
    #     archive rides as a FLAT member (its basename), exactly as `zip -j` placed it.
    assert '"$CANDIDATE/payload/corpusfm-recovery-source.zip"' in PACKAGER
    flat_add = '--flat "$CANDIDATE/payload/corpusfm-recovery-source.zip"'
    assert flat_add in PACKAGER
    build = PACKAGER[PACKAGER.index("build_platform() {"):PACKAGER.index("build_platform linux")]
    assert flat_add in build, "the recovery archive must ride in the per-platform assembly"
    runtime_call = build[build.index('zip_deterministic.py" "$runtime_zip"'):]
    assert flat_add in runtime_call[:runtime_call.index("\n\n")], "it belongs to the runtime archive"
    assert "build_platform linux" in PACKAGER and "build_platform windows" in PACKAGER
    linux_runtime = LINUX[LINUX.index("prepare_package_recovery_runtime()"):
                            LINUX.index("# The release package carries", LINUX.index(
                                "prepare_package_recovery_runtime()"))]
    assert '$BOOT_CLONE/recovery-runtime' in linux_runtime
    assert 'requirements-server.txt' in linux_runtime
    assert 'constraints-server-${pytag}.txt' in linux_runtime
    assert 'corpusfm-recovery-source.zip' in linux_runtime
    assert '"$INSTALL_DIR/venv"' not in linux_runtime
    assert 'lc_resume_orphaned_uninstall' in LINUX
    assert 'uninstall resume --request' in LINUX

    windows_runtime = WINDOWS[WINDOWS.index("function Initialize-PackagedRecoveryRuntime"):
                              WINDOWS.index("function Get-Json")]
    assert "Join-Path $RuntimeTemp 'lifecycle-recovery-runtime'" in windows_runtime
    assert "installer\\requirements-server.txt" in windows_runtime
    assert "installer\\constraints-server-win-py313.txt" in windows_runtime
    assert "corpusfm-recovery-source.zip" in windows_runtime
    assert "Test-Path $script:Py" in WINDOWS
    assert 'Lc-Field $lcState \'journal_mode\'' in WINDOWS
    assert "Resume-PackagedInterruptedUninstall" in WINDOWS
    assert "@('uninstall','resume','--request',$request)" in WINDOWS

    # A surviving installed interpreter is not allowed to outrank the newer verified package.
    linux_route = LINUX[LINUX.index("CFM_JOURNAL_FILE=/var/lib/corpusfm/state"):
                         LINUX.index("if [[ ! -x \"$INSTALL_DIR/venv/bin/python\" ]]")]
    assert '[[ -e "$CFM_JOURNAL_FILE"' in linux_route
    assert "prepare_package_recovery_runtime" in linux_route
    windows_route = WINDOWS[WINDOWS.index("function Get-LcState"):
                            WINDOWS.index("function Lc-PreflightDisposition")]
    assert "Test-Path -LiteralPath $orphanJournal" in windows_route
    assert "Initialize-PackagedRecoveryRuntime" in windows_route

    # POSIX still binds its recovery command to the verified package runtime. Windows no longer
    # sends runtime paths at all (packet 1380-02): the installer runs the lifecycle CLI itself with the
    # runtime this invocation selected.
    assert "recovery_python" in LINUX and "recovery_source" in LINUX
    assert "recovery_python" not in WINDOWS and "recovery_source" not in WINDOWS
    for script in (LINUX, WINDOWS):
        assert "Restore $INSTALL_DIR/venv" not in script


def test_runtime_helpers_never_come_from_the_application_checkout():
    for source in (LINUX, WINDOWS):
        assert "src/installer/linux/uninstall.sh" not in source
        assert "src\\installer\\windows\\uninstall.ps1" not in source
    assert '"$CFM_RUNTIME_ROOT/installer/linux/uninstall.sh"' in LINUX
    assert "Join-Path $RuntimeRoot 'installer\\windows\\uninstall.ps1'" in WINDOWS


# ── the asset boundary (packet 1257) ──────────────────────────────────────────────────
#
# The 0.2438 Linux install placed the payload into `src/db` and `src/addon`, composed every
# provider, and then refused at the deployed-checkout eligibility gate with 33 "untracked content
# that is not an installer artifact" problems -- services never started. The gate is correct: the
# checkout is on the service's import path. So the assets live in a SIBLING of it.

def test_neither_installer_places_assets_inside_the_deployed_checkout():
    """The regression that cost a full install round, asserted on both scripts at once."""
    for name, text in (("linux", LINUX), ("windows", WINDOWS)):
        for forbidden in ("src/db", "src/addon", "src\\db", "src\\addon"):
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or forbidden not in line:
                    continue
                # A refusal that NAMES the forbidden location is the guard, not a violation.
                assert ("refusing" in line.lower() or "! -e" in line
                        or "Test-Path -LiteralPath $forbidden" in line
                        or "forbidden" in line), f"{name}: {stripped[:100]}"


def test_both_installers_place_the_payload_under_the_shared_assets_directory_name():
    """One directory name, spelled the same on both platforms and in the application.

    `app_paths.ASSETS_DIRNAME` is what the running service derives from the published install root;
    if either installer used a different name the seeds would be placed where nothing reads them.
    """
    from corpusfm.lifecycle import app_paths

    assert app_paths.ASSETS_DIRNAME == "assets"
    assert 'CFM_ASSETS_DIRNAME=assets' in LINUX
    assert "$script:CfmAssetsDirName = 'assets'" in WINDOWS


def test_both_installers_read_the_asset_root_back_through_the_application():
    """A readback that recomputed the path locally would agree with itself and prove nothing."""
    for name, text in (("linux", LINUX), ("windows", WINDOWS)):
        assert "app_paths; print(app_paths.assets_dir())" in text, name


def test_the_linux_installer_keeps_the_placed_assets_unwritable_by_the_service():
    """The service reads its seeds; it must never be able to rewrite what it is seeded from."""
    assert 'chown -R root:"$SERVICE_USER" "$INSTALL_DIR/$CFM_ASSETS_DIRNAME"' in LINUX
    assert 'chmod -R u=rwX,g=rX,o= "$INSTALL_DIR/$CFM_ASSETS_DIRNAME"' in LINUX


# ── the completion gate's required artifacts (packet 1257) ────────────────────────────
#
# The 0.2440 Linux install seeded all four artifacts correctly and then FAILED post-install
# verification, because the gate required the Series 1 identity `CORPUSfm_Addon` while the Series 2
# assets seed as `CORPUSfm_ADDON`. The comparison is a case-SENSITIVE tuple membership test, so it
# could never match: a false negative that reported a correct installation as degraded.
#
# Matching stays case-sensitive on purpose. A case-insensitive gate would have accepted the Series 1
# spelling too, and this gate exists precisely to notice that the shipped identity changed.

import re

REQUIRED_ARTIFACT_PAIRS = frozenset({
    ("CORPUSfm_DB", "SaveAsXML"),
    ("CORPUSfm_ADDON", "SaveAsXML"),
    ("CORPUSfm_ADDON", "AddonXML"),
    ("CORPUSfm_ADDON", "MergedXML"),
})

_PAIR = re.compile(r"\(\s*'([A-Za-z_]+)'\s*,\s*'([A-Za-z]+)'\s*\)")


def _declared_pairs(text: str) -> frozenset:
    """The pairs inside the completion gate's own `required = (...)` tuple, as written."""
    block = text[text.index("required = ("):]
    block = block[: block.index(")\n")]
    return frozenset(_PAIR.findall(block))


def test_each_installer_declares_exactly_the_four_required_artifact_pairs():
    for name, text in (("linux", LINUX), ("windows", WINDOWS)):
        assert _declared_pairs(text) == REQUIRED_ARTIFACT_PAIRS, name


def test_the_two_installers_require_THE_SAME_pairs():
    """Parity. A gate that differs by platform is a box that passes on one OS and fails on the other,
    which no per-platform test can see because each is green against its own script."""
    assert _declared_pairs(LINUX) == _declared_pairs(WINDOWS)


def test_the_retired_series_1_addon_identity_is_gone_from_both_gates():
    """The exact false negative, named. `CORPUSfm_Addon` must not appear in either gate again."""
    for name, text in (("linux", LINUX), ("windows", WINDOWS)):
        block = text[text.index("required = ("):]
        assert "CORPUSfm_Addon'" not in block[: block.index(")\n")], name


# ── package-relative resolution (packet 1257) ─────────────────────────────────────────
#
# The Windows 0.2440 install died at the asset step with "Cannot bind argument to parameter 'Path'
# because it is null": `Join-Path $ScriptDir 'corpusfm-assets.zip'`, and `$ScriptDir` was never
# defined anywhere in the script. It had never fired because no Windows box had yet installed an
# asset payload -- a whole placement step that had been packaged twice without once executing.

def test_the_windows_installer_resolves_the_asset_payload_from_PSScriptRoot():
    """Every package-relative file resolves the same way; the payload is not an exception."""
    assert "Join-Path $PSScriptRoot 'corpusfm-assets.zip'" in WINDOWS


def test_the_windows_installer_binds_no_undefined_path_variable():
    """A phantom variable in a Join-Path is a null bind, and PowerShell refuses it at runtime.

    Checked by ASSIGNMENT rather than by name: any variable the script feeds to `Join-Path` must be
    one it assigns, a parameter it declares, or an automatic. That catches the next `$ScriptDir`
    without this test having to know its name.
    """
    assigned = set(re.findall(r"^\s*\$(?:script:)?([A-Za-z_]\w*)\s*=", WINDOWS, re.M))
    # Typed parameters, both in the top-level param() block and inline in a function signature
    # (`function Foo([string]$Bar)`) -- the latter is where `$SourceRoot`/`$DeployedRoot` live.
    declared = set(re.findall(r"\[[^\]]+\]\$([A-Za-z_]\w*)", WINDOWS))
    automatic = {"PSScriptRoot", "PSCommandPath", "PWD", "HOME", "env", "_"}
    used = set(re.findall(r"Join-Path\s+\$(?:script:)?([A-Za-z_]\w*)", WINDOWS))

    unknown = sorted(used - assigned - declared - automatic)
    assert not unknown, f"Join-Path binds undefined variable(s): {unknown}"


# ── traceless-debris recovery ordering (packet 1257) ──────────────────────────────────
#
# A Windows run interrupted at the asset step left `python\` and `src\` but no venv, so
# `corpusfm-lifecycle status --json` exited 1 with no stdout. `Get-LcState` refused there, at phase
# 2, and execution never reached the `-ReplaceExistingInstall` decision that exists for exactly that
# debris -- the box could not be recovered by its own installer. Product files on disk are not an
# installation; a locator, a manifest or the legacy marker are.

def _lc_state_body() -> str:
    start = WINDOWS.index("function Get-LcState")
    return WINDOWS[start: WINDOWS.index("\nfunction ", start + 1)]


def test_one_authority_helper_answers_installed_or_not():
    """Two places ask 'is this box installed'. They must not be able to drift apart."""
    assert "function Test-CfmInstallationAuthority" in WINDOWS
    for token in ("HKLM:\\SOFTWARE\\CORPUSfm\\Installation", "install.yaml", "$CurrentManifest"):
        assert token in WINDOWS[WINDOWS.index("function Test-CfmInstallationAuthority"):][:600], token
    # Both decision sites route on it, rather than re-deriving the answer.
    assert _lc_state_body().count("Test-CfmInstallationAuthority") >= 1
    assert "$tracelessDebris = [bool]($ours -and -not $IsUpgrade -and -not (Test-CfmInstallationAuthority))" in WINDOWS


def test_an_unanswerable_interpreter_with_no_authority_is_debris_not_a_refusal():
    """Case 1: classification CONTINUES so the replacement decision downstream can be reached."""
    body = _lc_state_body()
    empty = body[body.index("if (-not ($raw.Trim()))"):]
    guarded = empty[: empty.index("Die (")]
    assert "if (-not (Test-CfmInstallationAuthority))" in guarded
    assert "$script:LcStateRaw = ''" in guarded and "return $script:LcStateRaw" in guarded


def test_an_unanswerable_interpreter_WITH_authority_is_still_fatal():
    """Case 3: an installation whose status cannot be read is never classified as absent."""
    body = _lc_state_body()
    empty = body[body.index("if (-not ($raw.Trim())):".rstrip(":")):]
    assert "produced no output" in empty, "the fatal refusal must survive"
    # The refusal is reached only when the authority check does NOT short-circuit.
    assert empty.index("if (-not (Test-CfmInstallationAuthority))") < empty.index("Die (")


def test_traceless_debris_refuses_without_the_flag_and_proceeds_with_it():
    """Case 2. Without -ReplaceExistingInstall: refuse BEFORE mutation, naming the debris.
    With it: the existing bounded move-aside path, not a new one."""
    block = WINDOWS[WINDOWS.index("$ReplaceAside = ''"):]
    block = block[: block.index("cannot account for") + 200]
    assert "if (-not $ReplaceExistingInstall)" in block
    assert "interrupted CORPUSfm installation" in block
    assert "no locator, manifest or install" in block
    assert "Nothing has been changed." in block
    # The authorized path is the pre-existing one.
    assert "$ReplaceAside = $InstallDir + '.replaced-'" in block


def test_an_installation_with_authority_is_never_moved_aside():
    """The narrowness that makes the above safe: authority present -> the unconditional refusal."""
    block = WINDOWS[WINDOWS.index("$ReplaceAside = ''"):]
    tail = block[block.index("} elseif ($ours -and -not $IsUpgrade) {"):]
    assert "no parameter converts, replaces or discards one" in tail[:600]


def test_the_pre_mutation_recheck_reobserves_the_basis_the_plan_was_authorized_on():
    """The third site that asks 'is this ours', and the one the first correction missed.

    The pre-mutation re-check refused whenever `src\\` or `services\\` existed -- re-deriving
    `-not $ours` and so contradicting a plan deliberately authorized FOR traceless debris, which is
    exactly what contains `src\\`. The box refused AFTER consent, having planned a move it would not
    perform. The re-check now re-observes the authorizing basis instead of a fixed shape.
    """
    block = WINDOWS[WINDOWS.index("if ($ReplaceAside) {"):]
    block = block[: block.index("Move-Item -LiteralPath $InstallDir")]

    assert "$ReplaceAsideWasDebris" in WINDOWS[:WINDOWS.index("if ($ReplaceAside) {")], (
        "the basis must be recorded at plan time"
    )
    assert "if ($ReplaceAsideWasDebris) { Test-CfmInstallationAuthority }" in block
    # Authority appearing during the prompt refuses on EITHER basis.
    assert block.count("Test-CfmInstallationAuthority") >= 2
    # The product-file re-check survives for the case it was written for.
    assert "(Test-Path -LiteralPath $Src) -or (Test-Path -LiteralPath $SvcDir)" in block
    # And the unconditional guards remain.
    assert "-not (Test-Path -LiteralPath $InstallDir)" in block
    assert "(Test-Path -LiteralPath $ReplaceAside)" in block
