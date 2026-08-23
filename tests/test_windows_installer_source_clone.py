"""Static guards for the Windows fresh-Source clone staging/promotion boundary (packet 1173).

Windows has no live box in CI and PowerShell isn't on the test host, so — like the other
install.ps1 trust guards (test_windows_install_trust) — these inspect the PowerShell source
structurally. They pin the packet-1173 invariants the earlier trust suite does not cover:

  * the fresh clone stays a BLOBLESS partial clone (--filter=blob:none) with the exact network
    controls, and is never re-labelled "treeless" (that word is only correct for --filter=tree:0);
  * the fresh clone lands in a dedicated installer-owned SIBLING staging dir, promoted to canonical
    $Src only on success and only after origin is normalized to the tokenless URL;
  * no fresh-clone cleanup path recursively deletes canonical $Src;
  * exhausted failure cleans staging before the terminal error, and a finally/best-effort path
    cleans staging on interruption;
  * a rerun removes stale staging before its first clone.

Each positive assertion is paired with a negative-control comment naming the regression it rejects.
"""

from __future__ import annotations

import pathlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PS1 = (_ROOT / "installer/windows/install.ps1").read_text()


def _fresh_clone_block() -> str:
    """The fresh-clone `else { ... }` arm: from the blobless-clone comment to the `& $Git -C $Src
    remote set-url` line that follows the closing brace (the shared upgrade/fresh origin reset)."""
    start = _PS1.index("# Blobless partial clone (--filter=blob:none)")
    end = _PS1.index('& $Git -C $Src remote set-url origin "https://github.com/$Repo.git"', start)
    assert start < end, "could not bound the fresh-clone block"
    return _PS1[start:end]


# ── 1. blobless filter + network controls preserved ───────────────────────────────
def test_fresh_clone_keeps_blobless_filter_and_network_controls():
    block = _fresh_clone_block()
    clone = [ln for ln in block.splitlines()
             if " clone " in ln and "$Git" in ln and "--filter=blob:none" in ln
             and not ln.strip().startswith("#")]
    assert clone, "no git clone invocation in the fresh-clone block"
    ln = clone[0]
    # negative control: the filter removed or changed to tree:0 (or shallow) fails this.
    assert "'--filter=blob:none'" in ln, "fresh clone must stay a blobless partial clone"
    # negative control (on the clone command, not the explanatory comment): the filter changed to
    # tree:0 or a shallow --depth fails here.
    assert "tree:0" not in ln, "the clone must not become the technically-treeless tree:0 filter"
    assert "--depth" not in ln, "no shallow clone (would break the rev-list version stamp)"
    assert "--progress" in ln, "fresh clone must keep visible progress"
    assert "http.postBuffer=524288000" in ln, "postBuffer control lost"
    assert "http.lowSpeedLimit=1000" in ln, "lowSpeedLimit control lost"
    assert "http.lowSpeedTime=60" in ln, "lowSpeedTime control lost"


def test_complete_checkout_seeds_the_canonical_source_without_a_new_caller_authority():
    block = _fresh_clone_block()
    assert "$SourceSeed = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\\..'))" in _PS1
    for forbidden in ("SourceSeed = $env:", "[string]$SourceSeed", "-SourceSeed"):
        assert forbidden not in _PS1
    assert "if ($hasSourceSeed) {" in block
    assert "Assert-InstallerSourceAgreement $SourceSeed" in block
    assert "Assert-CleanTree $SourceSeed" in block
    assert "rev-parse HEAD" in block and "rev-parse origin/main" in block
    assert "$seedHead -ne $seedMain" in block


def test_seed_is_independently_cloned_and_read_back_before_promotion():
    block = _fresh_clone_block()
    seed_clone = [ln for ln in block.splitlines()
                  if "$Git clone --no-hardlinks" in ln and "$SourceSeed" in ln]
    assert len(seed_clone) == 1
    assert seed_clone[0].rstrip().endswith("$SourceSeed $cloneStage")
    i_clone = block.index(seed_clone[0])
    i_readback = block.index("$stageHead = (& $Git -C $cloneStage rev-parse HEAD).Trim()", i_clone)
    i_normalize = block.index("-C $cloneStage remote set-url origin", i_readback)
    i_promote = block.index("Move-Item -LiteralPath $cloneStage -Destination $Src", i_normalize)
    assert i_clone < i_readback < i_normalize < i_promote


def test_flattened_release_keeps_the_existing_network_clone_fallback():
    block = _fresh_clone_block()
    i_seed = block.index("if ($hasSourceSeed) {")
    i_fallback = block.index("} else {", i_seed)
    i_network = block.index("clone '--filter=blob:none'", i_fallback)
    assert i_seed < i_fallback < i_network


def test_flattened_release_bundle_can_advance_an_existing_checkout_before_skew_refusal():
    start = _PS1.index("function Prepare-ExternalSourceAdvance")
    block = _PS1[start:_PS1.index("$ExpectedRemote =", start)]
    assert "$packageBundle = Join-Path $PSScriptRoot 'corpusfm.bundle'" in block
    assert "$Git clone --no-hardlinks --branch $GitTrackedBranch $packageBundle $bundleSeed" in block
    assert '& $Git -C $bundleSeed remote set-url origin "https://github.com/$Repo.git"' in block
    assert "$script:SourceSeed = $bundleSeed" in block
    assert block.index("$script:SourceSeed = $bundleSeed") < block.index(
        "Assert-InstallerSourceAgreement $SourceSeed"
    )


def test_focused_package_agreement_uses_the_manifest_application_commit_not_retired_app_scripts():
    start = _PS1.index("function Assert-InstallerSourceAgreement")
    block = _PS1[start:_PS1.index("function Prepare-ExternalSourceAdvance", start)]
    assert "if ($InstallerSeries)" in block
    assert "$sourceHead -ne $PackageCommit" in block
    assert "verified installer and application source identities agree" in block
    assert block.index("if ($InstallerSeries)") < block.index("Test-InstallerSourceAgreement $SourceRoot")


def test_interrupted_dependency_setup_is_fresh_only_without_any_installation_authority():
    """RE-EXPRESSED for packet 1257. The rule is unchanged: an interrupted dependency setup may be
    classified fresh ONLY when no installation authority exists.

    What moved is where the authorities are read. They used to be three inline `Test-Path` calls in
    `Get-LcState`; they now live in `Test-CfmInstallationAuthority`, which BOTH decision sites call
    -- the classification here and the replacement decision at `$ReplaceAside` -- so the two cannot
    drift apart. Asserting the old inlining would have pinned a structure while the rule it guarded
    got stronger.
    """
    helper = _PS1.index("function Test-CfmInstallationAuthority")
    block = _PS1[helper:_PS1.index("function Lc-ProviderRun", helper)]
    assert "corpusfm\\lifecycle\\__main__.py" in block
    # Every authority is still consulted, and all three in one place.
    assert "HKLM:\\SOFTWARE\\CORPUSfm\\Installation" in block
    assert "Test-Path $CurrentManifest" in block
    assert "install.yaml" in block
    assert "its lifecycle application source is unavailable" in block
    # The fresh classification is REACHED ONLY THROUGH the authority check, on both routes: the
    # absent interpreter and the unanswerable one.
    fresh = [i for i in range(len(block)) if block.startswith("$script:LcStateRaw = ''", i)]
    assert len(fresh) == 2, "one fresh classification per route (interpreter absent / unanswerable)"
    for at in fresh:
        assert "Test-CfmInstallationAuthority" in block[:at]


def test_dependency_only_retry_does_not_become_an_unknown_installation():
    start = _PS1.index("$ReplaceAside = ''")
    block = _PS1[start:_PS1.index("# === PHASE 5", start)]
    for name in ("bin", "downloads", "git", "lib", "proxy", "python", "services"):
        assert f"'{name}'" in block
    assert "$unexpectedResidue.Count -eq 0" in block
    assert "$populatedProductDirs.Count -eq 0" in block
    assert "-not (Test-Path $Src)" in block
    assert "Resuming installer-owned dependency preparation" in block
    assert block.index("if ($dependencyResidue)") < block.index("elseif ($existing.Count -gt 0")


def test_bundle_materialization_tolerates_native_stderr_and_judges_both_git_calls_by_exit_code():
    start = _PS1.index("function Prepare-ExternalSourceAdvance")
    block = _PS1[start:_PS1.index("$ExpectedRemote =", start)]
    # PowerShell 5.1 turns git's normal clone progress on stderr into NativeCommandError under Stop.
    # Both bundle git calls therefore run under a narrowly-scoped Continue policy, capture their
    # own exit status, and restore the installer's fail-fast policy before deciding what to do.
    assert "$bundleEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'" in block
    assert "$bundleCloneRc = $LASTEXITCODE" in block
    assert "$bundleOriginRc = $LASTEXITCODE" in block
    assert "if ($bundleCloneRc -ne 0" in block
    assert "if ($bundleOriginRc -ne 0)" in block
    assert block.count("finally { $ErrorActionPreference = $bundleEap }") == 2


# ── 2. terminology: blobless, not treeless, for blob:none ─────────────────────────
def test_no_treeless_label_for_blob_none():
    # negative control: reverting the label to "Treeless partial clone (--filter=blob:none)" fails.
    assert "treeless partial clone" not in _PS1.lower(), \
        "blob:none must not be labelled 'treeless partial clone' (that's --filter=tree:0)"
    assert "blobless partial clone" in _fresh_clone_block(), \
        "the fresh-clone comment must call blob:none a 'blobless partial clone'"


# ── 3+4. fresh clone targets the dedicated sibling staging dir, not $Src ───────────
def test_fresh_clone_targets_staging_not_src():
    block = _fresh_clone_block()
    clone = [ln for ln in block.splitlines()
             if " clone " in ln and "$Git" in ln and not ln.strip().startswith("#")][0]
    # negative control: cloning straight into $Src (`... $cloneUrl $Src`) fails this.
    assert "$cloneStage" in clone, "fresh clone must target the staging dir"
    assert clone.rstrip().split()[-1] == "$cloneStage", "clone destination must be $cloneStage, not $Src"


def test_staging_is_a_sibling_of_src_not_nested():
    # negative control: a nested path (e.g. "$Src\partial") fails this exact-sibling assertion.
    assert '$cloneStage = "$Src.clone-partial"' in _PS1, \
        "staging must be the installer-owned sibling $Src.clone-partial"
    assert '"$Src\\' not in _PS1, "staging (or any path) must not be nested under $Src\\"
    assert '"$Src/' not in _PS1, "staging must not be nested under $Src/"


# ── 5. no recursive delete of canonical $Src in the fresh-clone path ──────────────
def test_fresh_clone_never_recursively_deletes_src():
    # negative control: any `Remove-Item -Recurse -Force $Src` (the old retry cleanup) fails this.
    assert "-Recurse -Force $Src " not in _PS1, "fresh-clone cleanup must never rm -rf canonical $Src"
    assert "-Recurse -Force $Src\n" not in _PS1
    block = _fresh_clone_block()
    # every recursive delete in the block targets staging only
    for ln in block.splitlines():
        if "Remove-Item -Recurse -Force" in ln:
            assert "$cloneStage" in ln, f"recursive delete must target staging only: {ln.strip()}"


def test_existing_unrecognized_src_fails_closed_not_deleted():
    block = _fresh_clone_block()
    # negative control: auto-deleting an unexpected $Src instead of Die-ing fails this.
    assert "if (Test-Path $Src) {" in block, "must check for an unexpected existing $Src"
    assert "not a recognized CORPUSfm Git checkout" in block, "must fail closed with a recovery message"
    i_check = block.index("if (Test-Path $Src) {")
    i_die = block.index("Die", i_check)
    i_stage = block.index("$cloneStage =", i_check)
    assert i_die < i_stage, "the unexpected-$Src guard must Die before any staging work"


# ── 6. promotion only on success, after origin normalization ──────────────────────
def test_promotion_follows_origin_normalization_and_success():
    block = _fresh_clone_block()
    i_norm = block.index('& $Git -C $cloneStage remote set-url origin "https://github.com/$Repo.git"')
    i_move = block.index("Move-Item -LiteralPath $cloneStage -Destination $Src")
    i_promoted = block.index("$promoted = $true")
    # negative control: promoting before normalizing origin (i_move < i_norm) fails this.
    assert i_norm < i_move, "origin must be normalized in staging BEFORE promotion"
    assert i_move < i_promoted, "$promoted must be set only after the Move-Item promotion"
    # promotion is gated on a successful clone ($cloned) reaching this far
    assert "if (-not $cloned) {" in block and block.index("if (-not $cloned) {") < i_move, \
        "an exhausted clone must Die before promotion is reached"


# ── 6b. a failed origin normalization must not reach promotion (issue 1) ──────────
def test_staged_origin_normalization_exit_is_checked():
    block = _fresh_clone_block()
    norm = [ln for ln in block.splitlines()
            if "-C $cloneStage remote set-url origin" in ln and not ln.strip().startswith("#")]
    assert norm, "the staged tokenless origin normalization line is missing"
    # negative control: dropping the exit check (so a failed set-url could promote a token-bearing
    # origin) fails this. set-url is a native command; its nonzero exit must Die before promotion.
    assert "NeedExit $LASTEXITCODE" in norm[0], \
        "a failed staged origin normalization must be checked (NeedExit) before promotion"
    i_norm = block.index("-C $cloneStage remote set-url origin")
    i_move = block.index("Move-Item -LiteralPath $cloneStage -Destination $Src")
    assert i_norm < i_move, "the checked normalization must precede promotion"


# ── 7. exhausted failure cleans staging before the terminal error ─────────────────
def test_terminal_failure_cleans_staging_before_die():
    block = _fresh_clone_block()
    seg = block[block.index("if (-not $cloned) {"):]
    seg = seg[:seg.index("# Normalize origin")]
    assert "Remove-Item -Recurse -Force $cloneStage" in seg, "exhausted-failure path must clean staging"
    i_clean = seg.index("Remove-Item -Recurse -Force $cloneStage")
    i_die = seg.index("Die")
    # negative control: reporting failure without first removing staging fails this ordering.
    assert i_clean < i_die, "staging must be removed before the terminal failure message"
    assert "after 4 attempts" in seg, "the terminal error must name the four failed attempts"
    assert "staging checkout" in seg, "the terminal error must speak of the staging checkout, not $Src"


# ── 8. best-effort interruption cleanup via finally ───────────────────────────────
def test_finally_best_effort_staging_cleanup_exists():
    block = _fresh_clone_block()
    assert "} finally {" in block, "a finally block must give best-effort interruption cleanup"
    fin = block[block.index("} finally {"):]
    assert "-not $promoted" in fin, "finally must only clean when promotion did not happen"
    assert "Remove-Item -Recurse -Force $cloneStage" in fin, "finally must remove staging"
    assert "Remove-Item -Recurse -Force $Src" not in fin, "finally must never delete $Src"


# ── 9. a rerun removes stale staging before its first clone ───────────────────────
def test_rerun_removes_stale_staging_before_first_clone():
    block = _fresh_clone_block()
    i_loop = block.index("for ($attempt = 1;")
    body = block[i_loop:]
    i_clean = body.index("Remove-Item -Recurse -Force $cloneStage")
    i_clone = body.index("clone '--filter=blob:none'")
    # negative control: gating the pre-clone cleanup on `$attempt -gt 1` (so attempt 1 skips it) fails.
    assert i_clean < i_clone, "stale staging must be removed before the first clone in the loop"
    pre = body[:i_clean]
    assert "$attempt -gt 1" not in pre, "the pre-clone staging cleanup must not be gated on attempt > 1"
