"""THE SCHEDULER RETIREMENT ADAPTER — the durable upgrade knowledge, pinned.

The standalone `corpusfm-scheduler` service is retired (application packet 1361-01) and no installer
renders one any more. Boxes that carry it keep arriving, though, so the adapter that retires it is
**permanent installer knowledge** and these tests exist to stop a later cleanup from deleting it as
dead code.

**The defect that produced them, measured on w-test-private 2026-09-03.** Release 0.2792 unregistered
the service and then asked `icacls /remove:g` to drop its ACE by name. A Windows virtual service
account exists only while its service is registered, so the trustee no longer resolved, icacls
answered **1332** — and removed *nothing at all*, including for the trustee that still resolved. The
install aborted, and so did every rerun, because the orphaned SID it failed to remove was still in
the DACL.

The order is therefore the contract:

  0. observe it, and RESOLVE its account to a numerical SID immediately - before phase 9 quiesces
     anything and before any installed byte is replaced. Presence is only the trigger; the
     successful translation is the fact, and a failed one refuses while the box is untouched.
  1. stop it, leave it REGISTERED while its ACL work is outstanding;
  2. remove its ACL entries by that captured SID, one trustee per icacls call;
  3. read the DACLs back and compare numerical SIDs;
  4. only then unregister it and delete its definition and wrapper.

**Why SIDs and not names.** The friendly account is what LSA fails to look up, and a name lookup is
the only thing on this path that can produce 1332. `icacls` takes `*<SID>` precisely so it performs
no lookup. And removals are never batched: a batch is all-or-nothing, so one bad operand removed
NEITHER grant while the exit code blamed only the other.

Everything here is a static read of the shipped script. The live proof is the private Windows gate.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PS1_PATH = ROOT / "installer/windows/install.ps1"
INSTALL_PS = PS1_PATH.read_text(encoding="ascii")
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")


def _code_only(text: str) -> str:
    """The script with comment lines removed.

    A guard whose subject must be named in its own rationale has to exclude comments, or it reports
    the explanation as the violation — a mistake this repository has made twice.
    """
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


CODE = _code_only(INSTALL_PS)


ADAPTER_FNS = ("Resolve-CfmServiceSid", "Remove-CfmGrantBySid",
               "Get-CfmRetiredSchedulerArtifacts", "Remove-CfmRetiredSchedulerGrants",
               "Assert-CfmOneServiceAclPolicy", "Remove-CfmRetiredSchedulerService",
               "Remove-CfmRetiredSchedulerArtifacts")


def _block(marker: str) -> str:
    """One brace-matched block starting at ``marker`` (which must contain its opening brace)."""
    i = CODE.index(marker)
    depth, j = 0, CODE.index("{", i)
    for k in range(j, len(CODE)):
        if CODE[k] == "{":
            depth += 1
        elif CODE[k] == "}":
            depth -= 1
            if depth == 0:
                return CODE[i:k + 1]
    raise AssertionError(f"unbalanced braces after {marker!r}")


def _fn(name: str) -> str:
    """The body of one PowerShell function, by brace matching."""
    m = re.search(rf"^function {re.escape(name)}\b", CODE, re.M)
    assert m, f"{name} is not defined"
    start = m.start()
    depth, i = 0, CODE.index("{", start)
    for j in range(i, len(CODE)):
        if CODE[j] == "{":
            depth += 1
        elif CODE[j] == "}":
            depth -= 1
            if depth == 0:
                return CODE[start:j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


# ── the adapter is PERMANENT, even though rendering a scheduler is forbidden ──────────────────────

def test_the_retirement_adapter_survives_even_though_rendering_one_is_forbidden():
    """The two rules are not in tension and a later reader must not "simplify" one into the other.

    `test_installer_services_proxy` forbids RENDERING a scheduler service. This forbids REMOVING the
    code that retires one. An installer that renders none and retires none strands every existing
    two-service box.
    """
    for fn in ADAPTER_FNS:
        assert f"function {fn}" in CODE, f"the retirement adapter lost {fn}"
    assert "THE SCHEDULER RETIREMENT ADAPTER" in INSTALL_PS, \
        "the adapter's rationale header is gone; the next reader will delete it as dead code"
    # and the forbidden half still holds
    for forbidden in ("'web','scheduler'", '"web","scheduler"', "@('web','scheduler')"):
        assert forbidden not in CODE, "a scheduler service is being rendered again"


def test_the_adapter_takes_its_observation_once_before_anything_unregisters():
    """One observation, taken before phase 9 quiesces and long before phase 20 deletes.

    Recomputing it after deletion would make the later steps disagree with the earlier ones about
    which case this box is.
    """
    obs = CODE.index("$SchedRetiredPresent = [bool](Get-Service")
    quiesce = CODE.index("foreach ($svc in @($WebService, $SchedServiceRetired))")
    assert obs < quiesce, "the presence observation is taken after the quiesce that stops it"
    assert CODE.count("$SchedRetiredPresent = ") == 1, \
        "the presence observation is assigned more than once"


# ── ORDER: ACLs are removed and proven BEFORE the service is unregistered ─────────────────────────

def test_acl_removal_and_readback_both_precede_the_service_deletion():
    """The measured defect, asserted as an ordering property rather than as a spelling."""
    remove = CODE.index("Remove-CfmRetiredSchedulerGrants $OneServiceAclPolicyPaths")
    readback = CODE.index("Assert-CfmOneServiceAclPolicy $OneServiceAclPolicyPaths")
    delete = CODE.index("\nRemove-CfmRetiredSchedulerService\n")
    assert remove < readback < delete, (
        "the retirement steps are out of order: ACL removal and its read-back must both complete "
        "while the service is still registered")


def test_the_service_is_not_deleted_in_the_registration_phase():
    """Where 0.2792 put it. S8 registers the web service; deleting the scheduler there is what made
    the account unresolvable before phase 20's ACL work ran."""
    s8 = CODE.index("$VerifiedServices += $id")
    delete = CODE.index("\nRemove-CfmRetiredSchedulerService\n")
    grants = CODE.index("Remove-CfmRetiredSchedulerGrants $OneServiceAclPolicyPaths")
    assert s8 < grants < delete
    between = CODE[s8:grants]
    assert "sc.exe delete" not in between and "uninstall" not in between.replace(
        "Register-CfmService", ""), "something unregisters a service between S8 and the ACL work"


def test_phase_21_starts_only_what_phase_20_verified():
    """After deletion no later phase may want the retired identity."""
    delete = CODE.index("\nRemove-CfmRetiredSchedulerService\n")
    tail = CODE[delete + len("Remove-CfmRetiredSchedulerService\n"):]
    assert "$SchedRetiredAccount" not in tail, \
        "a phase after the deletion still names the retired account"
    assert "foreach ($id in $VerifiedServices)" in tail


# ── the no-service path never names or resolves the retired account ───────────────────────────────

def test_the_retired_account_is_never_named_outside_a_presence_guard():
    """`NT SERVICE\\corpusfm-scheduler` is what error 1332 keys on. Every use of it must sit behind
    the presence observation, so a fresh box never asks Windows to resolve an account that has never
    existed there."""
    uses = [l.strip() for l in CODE.splitlines() if "$SchedRetiredAccount" in l]
    # Exactly three: the definition, the ONE translation at the preflight, and that translation's
    # refusal message. Nothing else in the script may touch the friendly name.
    assert len(uses) == 3, f"the retired account is named {len(uses)} times: {uses}"
    assert uses[0] == "$SchedRetiredAccount = 'NT SERVICE\\' + $SchedServiceRetired"
    assert "NTAccount($SchedRetiredAccount)" in uses[1], "the second use is not the translation"
    assert "does not resolve to a SID" in uses[2], "the third use is not the refusal message"
    # and none of them is an icacls operand
    assert not any("icacls" in u for u in uses), "the friendly name reaches icacls"


@pytest.mark.parametrize("fn,guard", [
    ("Remove-CfmRetiredSchedulerGrants", "if (-not $script:SchedRetiredIcaclsOperand) { return }"),
    ("Remove-CfmRetiredSchedulerService", "if (-not $script:SchedRetiredSid) { return }"),
])
def test_each_mutating_step_returns_early_when_no_sid_was_captured(fn, guard):
    """Keyed on the CAPTURED SID rather than on bare presence: presence is the trigger, the
    successful translation is the fact, and these steps may only run on the fact."""
    assert guard in _fn(fn), f"{fn} acts without a captured retired SID"


def test_the_icacls_operand_is_a_sid_and_is_empty_when_there_is_no_service():
    """`*<SID>` is icacls's own "this is a SID, do not look up a name" spelling, and a name lookup is
    the only thing here that can answer 1332."""
    assert "$SchedRetiredIcaclsOperand = '*' + $SchedRetiredSid" in CODE
    assert "$SchedRetiredIcaclsOperand = ''" in CODE, \
        "the operand is not empty on the no-scheduler path"
    assert "$WebIcaclsOperand = '*' + $WebSidValue" in CODE


def test_the_authority_chain_removes_each_trustee_in_its_own_checked_call():
    """The exact line that failed, and the shape that replaces it."""
    assert "Remove-CfmGrantBySid $subject.Path $WebIcaclsOperand 'prior web service read'" in CODE
    assert "if ($SchedRetiredIcaclsOperand) {" in CODE
    for gone in ("$removeArgs = @($subject.Path, '/remove:g', $WebSid)",
                 "/remove:g $WebSid ('NT SERVICE\\' + $SchedServiceRetired)"):
        assert gone not in CODE, "a batched trustee removal is back"


# ── the forbidden shortcuts ───────────────────────────────────────────────────────────────────────

def test_no_forbidden_shortcut_is_used():
    """Each of these would "work" and each is a different way of being wrong."""
    assert "showsid" not in CODE, "the SID is being parsed out of sc.exe showsid"
    assert "S-1-5-80-" not in CODE, "a service SID is hardcoded"
    # RUNTIME TRANSLATION IS REQUIRED, NOT FORBIDDEN. An earlier version of this test banned every
    # `Translate(` on the theory that touching a SID at all was the hazard. The hazard is a NAME
    # reaching icacls; asking LSA for a live SID is the fix, so what is banned is a SID this script
    # invents (hardcoded, or parsed out of `sc showsid`), never one it is given.
    assert "Translate([System.Security.Principal.SecurityIdentifier])" in CODE
    # 1332 is never TOLERATED. It may be described in a comment - that is the incident record - but
    # no code path may branch on it or swallow it.
    assert "1332" not in CODE, "error 1332 is being tolerated somewhere in code"
    # no blanket trustee sweep: each removal carries exactly one operand
    body = _fn("Remove-CfmRetiredSchedulerGrants")
    assert "$script:SchedRetiredIcaclsOperand" in body
    for wildcard in ("PurgeAccessRules", "/remove:g *", "RemoveAccessRuleAll"):
        assert wildcard not in body, "unexplained trustees are being deleted"


def test_no_recovery_path_for_the_unpublished_failed_package():
    """0.2792 was never published. A box stranded by it is reset from its snapshot, not rescued by
    code that would then live in the installer forever."""
    adapter = "".join(_fn(f) for f in ADAPTER_FNS)
    # Scoped to the adapter on purpose: `$orphanJournal` elsewhere is unrelated lifecycle recovery,
    # and a whole-script scan would report it. The rule is about THIS mechanism.
    for phrase in ("orphan", "0.2792", "stranded", "unresolvable", "leftover"):
        assert phrase not in adapter.lower(), \
            f"a special recovery path for the failed package: {phrase!r}"


# ── strictness is preserved ───────────────────────────────────────────────────────────────────────

def test_a_failed_removal_is_a_refusal_not_a_warning():
    body = _fn("Remove-CfmGrantBySid")
    assert "if ($LASTEXITCODE -ne 0) {" in body
    assert "Die (" in body and "Warn" not in body


def test_the_readback_asserts_both_halves_and_refuses():
    """A read-back that only checks the retired trustee is gone would pass over a DACL that grants
    the web service nothing either — which is the state the failed 0.2792 run actually left."""
    body = _fn("Assert-CfmOneServiceAclPolicy")
    assert "Get-Acl" in body, "the policy is inferred from the calls issued, not read back"
    assert body.count("Die (") >= 2
    assert "still holds a grant on" in body
    assert "holds no grant on" in body
    assert "Warn" not in body


def test_the_readback_uses_the_exact_captured_sids_and_compares_numerically():
    """It must not re-resolve at read-back time. The SID was captured at the preflight precisely so
    that nothing downstream depends on the account still resolving, and comparing the SID actually
    removed against the SID actually present is what makes this a proof rather than a restatement."""
    body = _fn("Assert-CfmOneServiceAclPolicy")
    assert "$retiredSid = $script:SchedRetiredSid" in body
    assert "$webSidValue = $script:WebSidValue" in body
    assert "NTAccount(" not in body, "the read-back re-resolves an account instead of using the capture"
    assert "$sids -contains $retiredSid" in body
    assert "$sids -contains $webSidValue" in body
    # the ACL's own identities are normalised to SIDs before comparison, never compared as names
    assert "IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])" in body


def test_removal_is_never_inferred_from_an_icacls_exit_code():
    """`Remove-CfmGrantBySid` checking `$LASTEXITCODE` proves the CALL succeeded; only the read-back
    proves the ACE is gone. Both must exist, and the read-back must not be reachable-by-skipping."""
    assert "$LASTEXITCODE -ne 0" in _fn("Remove-CfmGrantBySid")
    assert "Get-Acl" in _fn("Assert-CfmOneServiceAclPolicy")


def test_the_policy_path_set_is_exactly_what_the_grant_loop_grants():
    """A hand-maintained list would drift from the grants it is supposed to mirror. Assert the two
    agree, so adding a grant without adding its removal fails here."""
    decl = re.search(r"\$OneServiceAclPolicyPaths = @\(([^)]*)\)", CODE, re.S)
    assert decl, "the policy path set is gone"
    declared = set(re.findall(r"\$\w+", decl.group(1)))
    loop = CODE.index("foreach ($sid in @($WebSid)) {")
    end = CODE.index("\n}", loop)
    granted = set(re.findall(r"Grant-OrDie \s*(\$\w+)", CODE[loop:end]))
    assert declared == granted, (
        f"the removal set and the grant set disagree: only-removed={declared - granted}, "
        f"only-granted={granted - declared}")


# ── the four scenarios the contract names ─────────────────────────────────────────────────────────

def test_scenario_fresh_install_resolves_and_removes_nothing_scheduler_shaped():
    """No service observed -> no translation, no operand, no removal, no comparison. The retired
    identity is not touched in any way on the path every fresh box takes."""
    assert "if ($SchedRetiredPresent) {" in CODE, "the preflight translation is unconditional"
    assert "if (-not $script:SchedRetiredIcaclsOperand) { return }" in _fn("Remove-CfmRetiredSchedulerGrants")
    assert "if (-not $script:SchedRetiredSid) { return }" in _fn("Remove-CfmRetiredSchedulerService")
    # the read-back's retired half is inert when nothing was captured
    assert "if ($retiredSid -and" in _fn("Assert-CfmOneServiceAclPolicy")


def test_scenario_upgrade_from_the_two_service_layout_quiesces_before_it_removes():
    """Step 1: stopped at phase 9, still registered."""
    quiesce = CODE.index("foreach ($svc in @($WebService, $SchedServiceRetired))")
    remove = CODE.index("Remove-CfmRetiredSchedulerGrants $OneServiceAclPolicyPaths")
    assert quiesce < remove
    block = CODE[quiesce:quiesce + 600]
    assert "Stop-Service" in block or "stop" in block
    assert "sc.exe delete" not in block, "phase 9 unregisters the service it is only meant to stop"


def test_scenario_completed_rerun_is_the_no_service_path():
    """A rerun after a completed retirement observes absence, captures no SID, and is byte-identically
    the fresh-install path — there is no third branch to get wrong."""
    assert "$SchedRetiredPresent = [bool](Get-Service $SchedServiceRetired" in CODE
    assert "$SchedRetiredSid = ''" in CODE and "$SchedRetiredIcaclsOperand = ''" in CODE


def test_scenario_interrupted_before_acl_completion_leaves_the_identity_available():
    """Nothing between the observation and the read-back may unregister the service."""
    obs = CODE.index("$SchedRetiredPresent = [bool](Get-Service")
    readback = CODE.index("Assert-CfmOneServiceAclPolicy $OneServiceAclPolicyPaths")
    window = CODE[obs:readback]
    assert "Remove-CfmRetiredSchedulerService" not in window
    assert f"sc.exe delete $script:SchedServiceRetired" not in window


def test_scenario_interrupted_after_acl_completion_cannot_leave_the_grant_behind():
    """Deletion is the step immediately after the read-back, and the read-back is what proves the
    grant is gone — so an interruption between them leaves a box whose next run simply repeats both.
    """
    readback = CODE.index("Assert-CfmOneServiceAclPolicy $OneServiceAclPolicyPaths")
    delete = CODE.index("\nRemove-CfmRetiredSchedulerService\n", readback)
    between = CODE[readback:delete]
    assert "Grant-OrDie" not in between, "a grant is issued between the proof and the deletion"
    assert between.count("\n") < 12, "the proof and the deletion have drifted apart"


# ── Linux has the same retirement and does NOT have the same hazard ───────────────────────────────

def test_linux_retires_the_unit_and_needs_no_trustee_dance():
    """Recorded so the asymmetry is deliberate rather than an oversight: both services ran as the one
    `corpusfm` user, so removing the unit orphans no per-service identity and no ACL entry.
    """
    assert "SCHED_SERVICE_RETIRED=corpusfm-scheduler" in INSTALL_SH
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    assert 'systemctl disable "$SCHED_SERVICE_RETIRED"' in sh
    assert 'rm -f "$_sched_unit_file"' in sh
    assert "for _role in web\n" in sh or "for _role in web;" in sh or "for _role in web " in sh


# ── THE SID PREFLIGHT (correction to 7d7eccd) ─────────────────────────────────────────────────────
#
# Presence is the trigger; the successful translation is the fact. Six properties, each named by the
# correction, each asserted on its own so a failure says which one broke.

def test_the_retired_sid_is_resolved_BEFORE_phase_9_quiesces_anything():
    """And before phase 8 creates or re-permissions a directory, and before any byte is replaced —
    so the refusal below costs the box nothing."""
    # Landmarks are CODE, not the phase banners — those are comments and `_code_only` strips them.
    resolve = CODE.index("$SchedRetiredSid = (New-Object System.Security.Principal.NTAccount")
    for landmark, label in (
        ("New-Item -ItemType Directory -Force -Path $InstallDir,$ConfigHome,", "phase 8's layout work"),
        ("Lock-DirTreeAcl $ConfigHome", "phase 8's tree lock"),
        ("foreach ($svc in @($WebService, $SchedServiceRetired))", "phase 9's quiesce loop"),
        ("Register-CfmService $id", "service registration"),
    ):
        assert resolve < CODE.index(landmark), f"the SID is resolved after {label}"


def test_a_failed_resolution_cannot_reach_the_quiesce():
    """The refusal is a `Die` inside the preflight's own catch, not a warning and not a flag someone
    downstream is trusted to read."""
    preflight = _block("if ($SchedRetiredPresent) {")
    assert "} catch {" in preflight
    assert preflight.count("Die (") >= 2, "resolution failure and an empty SID must both refuse"
    assert "Warn" not in preflight, "a failed resolution was softened into a warning"
    assert "does not resolve to a SID" in preflight
    # an empty translation result is refused too, not carried forward as ''
    assert "if (-not $SchedRetiredSid) {" in preflight


def test_no_icacls_removal_ever_carries_the_friendly_account():
    """The name is what LSA fails to look up. Every removal operand is `*<numerical SID>`."""
    for line in CODE.splitlines():
        if "/remove:g" in line:
            assert "$SchedRetiredAccount" not in line, f"a friendly name reaches icacls: {line.strip()}"
            assert "NT SERVICE" not in line, f"a friendly name reaches icacls: {line.strip()}"
    body = _fn("Remove-CfmGrantBySid")
    assert "& icacls $path '/remove:g' $sidOperand" in body


def test_every_removal_command_carries_exactly_one_trustee():
    """A batch is all-or-nothing: one unresolvable operand removed NEITHER grant and reported 1332 on
    the other's behalf. One trustee per call, one exit code per trustee."""
    body = _fn("Remove-CfmGrantBySid")
    call = [l for l in body.splitlines() if "& icacls" in l]
    assert len(call) == 1
    # exactly one operand variable after the verb
    assert call[0].strip() == "& icacls $path '/remove:g' $sidOperand 2>&1 | Out-Null"
    assert "$LASTEXITCODE -ne 0" in body, "the call's own exit code is not checked"
    # and every removal in the script goes through it
    direct = [l for l in CODE.splitlines()
              if "/remove:g" in l and "Remove-CfmGrantBySid" not in l and "function" not in l]
    assert direct == [call[0].strip()] or direct == [call[0]], \
        f"a removal bypasses the single-trustee helper: {direct}"


def test_the_no_scheduler_path_resolves_and_removes_nothing_retired():
    """The whole fresh-install and completed-rerun path, stated as one property."""
    # the translation is inside the presence branch
    resolve = CODE.index("$SchedRetiredSid = (New-Object")
    branch = CODE.rindex("if ($SchedRetiredPresent) {", 0, resolve)
    assert branch < resolve
    # and both mutating steps refuse to act without a captured value
    assert "if (-not $script:SchedRetiredIcaclsOperand) { return }" in _fn("Remove-CfmRetiredSchedulerGrants")
    assert "if (-not $script:SchedRetiredSid) { return }" in _fn("Remove-CfmRetiredSchedulerService")
    # the authority chain's retired half is conditional on the operand existing
    assert "if ($SchedRetiredIcaclsOperand) {" in CODE


def test_the_readback_compares_the_exact_captured_sid():
    """Not a re-resolution, and not a name. The value proven absent must be the value removed."""
    body = _fn("Assert-CfmOneServiceAclPolicy")
    assert "$retiredSid = $script:SchedRetiredSid" in body
    assert "$webSidValue = $script:WebSidValue" in body
    assert "NTAccount(" not in body
    assert "Resolve-CfmServiceSid" not in body
    # and the operands removed are built from those same two captures
    assert "$SchedRetiredIcaclsOperand = '*' + $SchedRetiredSid" in CODE
    assert "$WebIcaclsOperand = '*' + $WebSidValue" in CODE


# ── ACCUMULATED ADAPTERS (developer ruling, 2026-09-03) ───────────────────────────────────────────

def test_the_adapter_is_governed_by_observed_state_not_by_a_recorded_version():
    """Adapters accumulate from the first public epoch and each is governed by what it OBSERVES.

    A `0.2791 -> 0.2792` branch would be wrong for exactly the boxes that need the adapter — the ones
    whose history is not what their record claims. The predicate is `Get-Service`, and no version
    string may gate any step of the retirement.
    """
    assert "$SchedRetiredPresent = [bool](Get-Service $SchedServiceRetired" in CODE
    adapter = "".join(_fn(f) for f in ADAPTER_FNS) + _block("if ($SchedRetiredPresent) {")
    for version_ish in ("0.2791", "0.2792", "$InstallerVersion", "$InstalledVersion",
                        "installer_version", "application_version"):
        assert version_ish not in adapter, \
            f"the adapter branches on a recorded version ({version_ish}) rather than observed state"


def test_the_adapter_records_that_it_is_permanent_and_accumulated():
    """The rationale has to survive in the file, because the next reader's instinct is to delete an
    adapter no box in front of them needs."""
    for phrase in ("ACCUMULATED ADAPTERS", "RECORDED INSTALLER VERSION IS CONTEXT, NEVER AUTHORITY",
                   "PERMANENT and IDEMPOTENT", "compatibility-epoch"):
        assert phrase in INSTALL_PS, f"the accumulated-adapter ruling lost: {phrase!r}"


# ── A001 INTERRUPTION SHAPES — the final step, both platforms ─────────────────────────────────────
#
# The claim "every interruption point is rerunnable" was false at the last step on BOTH platforms,
# in the same way: the healing work was guarded by a predicate that the interruption itself makes
# false, so the next invocation skipped exactly the box that needed it.

def test_windows_separates_service_retirement_from_artifact_cleanup():
    """Two steps, two predicates. One function may not carry both."""
    svc = _fn("Remove-CfmRetiredSchedulerService")
    art = _fn("Remove-CfmRetiredSchedulerArtifacts")
    assert "if (-not $script:SchedRetiredSid) { return }" in svc
    assert "Remove-Item" not in svc, "the service step deletes files; 4b is meant to own that"
    assert "$script:SchedRetiredSid" not in art, \
        "artifact cleanup is guarded by the captured SID, so an interrupted box can never heal"
    assert "Get-CfmRetiredSchedulerArtifacts" in art


def test_windows_artifact_cleanup_runs_without_a_captured_sid():
    """THE INTERRUPTION SHAPE: service already deleted, files still there, next invocation observes
    no service and captures no SID. 4b must still run, attempt no ACL work, and invent no SID."""
    art = _fn("Remove-CfmRetiredSchedulerArtifacts")
    assert "Test-Path -LiteralPath" in art, "cleanup is not guarded by artifact presence"
    for forbidden in ("NTAccount", "Translate", "icacls", "/remove:g", "SchedRetiredAccount",
                      "Resolve-CfmServiceSid"):
        assert forbidden not in art, f"the no-SID cleanup path attempts identity work: {forbidden}"
    # and the call site is unconditional on this invocation's SID
    call = CODE.index("\nRemove-CfmRetiredSchedulerArtifacts")
    prev = CODE[CODE.rindex("\n", 0, call - 1):call]
    assert "if" not in prev, "the 4b call site is wrapped in a condition"


def test_windows_artifact_cleanup_names_exactly_two_files_and_globs_nothing():
    body = _fn("Get-CfmRetiredSchedulerArtifacts")
    assert body.count("Join-Path") == 2
    assert "'.xml'" in body and "'.exe'" in body
    for wildcard in ("*", "-Recurse", "-Include", "-Filter"):
        assert wildcard not in body, f"the artifact set is not bounded: {wildcard}"


def test_windows_absence_is_read_back_not_inferred_from_silentlycontinue():
    """`-ErrorAction SilentlyContinue` hides a locked file, so the removal's silence proves nothing."""
    art = _fn("Remove-CfmRetiredSchedulerArtifacts")
    assert "SilentlyContinue" in art          # used to ATTEMPT
    tail = art[art.index("foreach ($path in $present)"):]
    assert "$remaining" in tail and "Die (" in tail, "absence is never read back"
    assert "Test-Path -LiteralPath $_" in tail
    # the service step likewise proves absence rather than assuming the uninstall worked
    svc = _fn("Remove-CfmRetiredSchedulerService")
    assert "if (Get-Service $script:SchedServiceRetired" in svc and "Die (" in svc


def test_linux_daemon_reconciliation_is_not_gated_solely_on_the_unit_file():
    """THE INTERRUPTION SHAPE: `rm -f` landed, `daemon-reload` did not. systemd still exposes the
    unit from its in-memory generation, and a file-only predicate skips the reload forever."""
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    guard = [l for l in sh.splitlines() if l.startswith("if [[ -f \"$_sched_unit_file\"")]
    assert guard, "the retirement guard changed shape"
    assert "_sched_load_state" in guard[0], \
        "the guard is the unit file alone; a reload-only residue can never be reconciled"
    assert 'systemctl show -p LoadState --value "$SCHED_SERVICE_RETIRED"' in sh


def test_linux_verifies_both_the_file_and_systemds_view_before_reporting():
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    block = sh[sh.index('if [[ -f "$_sched_unit_file"'):sh.index('unset _sched_unit_file')]
    reload_at = block.index("systemctl daemon-reload")
    ok_at = block.index('ok "Standalone scheduler unit retired')
    assert reload_at < ok_at
    # both verifications sit between the reload and the success report
    verify = block[reload_at:ok_at]
    assert 'if [[ -f "$_sched_unit_file" ]]; then' in verify and "die " in verify
    assert 'LoadState=' in verify or "_sched_load_state" in verify
    assert verify.count("die ") >= 2, "one of the two verifications does not refuse"


def test_linux_removal_is_an_explicit_if_not_a_trailing_and_list():
    """Positional, not fatal: `set -e` exempts a failing LEFT operand of `&&`, so the `&&` form does
    not abort here — measured. The `if` is used because that exemption is positional and the residue
    path is exactly where the test is false."""
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    assert '[[ -f "$_sched_unit_file" ]] && rm -f' not in sh
    assert 'if [[ -f "$_sched_unit_file" ]]; then\n        rm -f "$_sched_unit_file"' in sh


def test_the_three_source_states_are_recorded_and_orphan_acls_are_not_repaired():
    """State (c) must stay documented and unimplemented: no code path hunts for an ACE whose
    principal this installer cannot account for."""
    for phrase in ("A REGISTERED SERVICE", "EXACT RETIRED ARTIFACTS, NO SERVICE",
                   "UNEXPLAINED ORPHAN ACL WITH NO SERVICE", "UNSUPPORTED CORRUPTION"):
        assert phrase in INSTALL_PS, f"A001's source-state vocabulary lost: {phrase!r}"
    adapter = "".join(_fn(f) for f in ADAPTER_FNS)
    for repair in ("PurgeAccessRules", "RemoveAccessRuleAll", "/remove:g *", "S-1-5-80-"):
        assert repair not in adapter, f"orphan-ACL repair was implemented: {repair}"


def test_linux_the_reload_itself_is_not_nested_under_a_file_test():
    """Control 70 came back NOT CAUGHT and this is why.

    `test_linux_daemon_reconciliation_is_not_gated_solely_on_the_unit_file` checks the OUTER guard,
    so wrapping `daemon-reload` in its own `if [[ -f $_sched_unit_file ]]` reintroduced the whole
    defect while that test stayed green: on the residue path the file is already gone, the inner test
    is false, and the reload — the only thing that can clear systemd's in-memory view — is skipped
    exactly on the box that needs it.

    Asserted by INDENTATION, which is what "nested" means in a shell block: the reconciliation must
    sit at the retirement block's own level.
    """
    lines = INSTALL_SH.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith('if [[ -f "$_sched_unit_file"'))
    end = next(i for i, l in enumerate(lines[start:], start) if l.startswith("unset _sched_unit_file"))
    body = lines[start + 1:end]

    reload_lines = [l for l in body if "systemctl daemon-reload" in l or "systemctl reset-failed" in l]
    assert reload_lines, "the reconciliation is gone"
    for l in reload_lines:
        indent = len(l) - len(l.lstrip())
        assert indent == 4, (
            f"the reconciliation is nested {indent} spaces deep, so some inner condition can skip "
            f"it: {l.strip()!r}")


def test_linux_nothing_between_the_removal_and_the_reload_can_skip_it():
    """The companion property, stated over the statements rather than the whitespace: every `if`
    opened after the removal is closed before the reload."""
    lines = INSTALL_SH.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith('if [[ -f "$_sched_unit_file"'))
    end = next(i for i, l in enumerate(lines[start:], start) if l.startswith("unset _sched_unit_file"))
    body = [l for l in lines[start + 1:end] if not l.lstrip().startswith("#")]
    reload_at = next(i for i, l in enumerate(body) if "systemctl daemon-reload" in l)
    depth = 0
    for l in body[:reload_at]:
        t = l.strip()
        if t.startswith("if "):
            depth += 1
        elif t == "fi":
            depth -= 1
    assert depth == 0, "the reload sits inside an unclosed conditional opened before it"


# ── A001 STEP 5 — AUTHORITY RETIREMENT (platform ordering) ────────────────────────────────────────
#
# PHYSICAL retirement and AUTHORITY retirement are different obligations. Steps 1-4b prove the OS no
# longer carries the service; step 5 proves the published installation record no longer claims it.
# Measured on w-test-private 2026-09-03: after a green upgrade AND a green idempotent rerun, the
# manifest still recorded `web, scheduler, updater` at generation 8.

def test_windows_calls_authority_retirement_only_after_physical_absence():
    """Ordering, asserted over the call sites rather than over a comment."""
    grants = CODE.index("Remove-CfmRetiredSchedulerGrants $OneServiceAclPolicyPaths")
    readback = CODE.index("Assert-CfmOneServiceAclPolicy $OneServiceAclPolicyPaths")
    svc = CODE.index("\nRemove-CfmRetiredSchedulerService\n")
    art = CODE.index("\nRemove-CfmRetiredSchedulerArtifacts")
    auth = CODE.index("\nLc-RetireSchedulerAuthority")
    assert grants < readback < svc < art < auth, \
        "authority retirement is not last; it must follow every physical postcondition"


def test_windows_authority_retirement_re_proves_physical_absence_itself():
    """It does not merely trust the order of two call sites: a still-registered service or a
    surviving artifact refuses, because retiring the authority then would publish a record wrong in
    the other direction."""
    body = _fn("Lc-RetireSchedulerAuthority")
    assert "Get-Service $script:SchedServiceRetired" in body and "Die (" in body
    assert "Get-CfmRetiredSchedulerArtifacts" in body
    assert body.count("Die (") >= 3, "a precondition or the refusal path is missing"


def test_windows_authority_request_names_no_role_and_binds_the_installation():
    body = _fn("Lc-RetireSchedulerAuthority")
    assert "'retire-scheduler-authority'" in body
    for bound in ("installation_id", "expected_generation", "install_dir", "actor", "schema_version"):
        assert bound in body, f"the request does not bind {bound}"
    assert "role" not in body.replace("SchedRetired", "").replace("scheduler", ""), \
        "the request selects a role"


def test_windows_updates_the_generation_from_the_committed_value():
    body = _fn("Lc-RetireSchedulerAuthority")
    assert "Lc-Field $out 'committed_generation'" in body
    assert "$script:CfmGeneration = [int]$committed" in body


def test_windows_a_failed_authority_retirement_fails_the_installer():
    """A001 must not be reported complete over a stale record."""
    body = _fn("Lc-RetireSchedulerAuthority")
    assert "Lc-Run " in body, "the call bypasses the dying runner"
    assert "Warn" not in body


def test_linux_calls_authority_retirement_only_after_the_unit_work():
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    guard = sh.index('if [[ -f "$_sched_unit_file"')
    verify = sh.index('ok "Standalone scheduler unit retired')
    auth = sh.index("\nlc_retire_scheduler_authority\n")
    assert guard < verify < auth


def test_linux_authority_retirement_is_OUTSIDE_the_os_residue_block():
    """The healing case has no OS residue at all: unit gone, LoadState absent, manifest stale. A
    call inside the block would skip exactly that installation, forever."""
    lines = INSTALL_SH.splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith('if [[ -f "$_sched_unit_file"'))
    end = next(i for i, l in enumerate(lines[start:], start) if l.startswith("unset _sched_unit_file"))
    block = "\n".join(lines[start:end])
    assert "lc_retire_scheduler_authority" not in block, \
        "the authority call sits inside the OS-residue block and cannot heal a stale manifest"
    call = next(i for i, l in enumerate(lines) if l.strip() == "lc_retire_scheduler_authority")
    assert call > end
    indent = len(lines[call]) - len(lines[call].lstrip())
    assert indent == 0, "the authority call is nested under some condition"


def test_linux_authority_retirement_re_proves_physical_absence_and_dies_on_failure():
    sh = "\n".join(l for l in INSTALL_SH.splitlines() if not l.lstrip().startswith("#"))
    body = sh[sh.index("lc_retire_scheduler_authority() {"):sh.index("\n}", sh.index("lc_retire_scheduler_authority() {"))]
    assert 'if [[ -f "$unit_file" ]]; then' in body and "die " in body
    assert 'systemctl show -p LoadState --value' in body
    assert 'lc_run "scheduler authority retirement"' in body
    assert 'CFM_GENERATION="$committed"' in body
    assert body.count("die ") >= 3


@pytest.mark.parametrize("name", ["Lc-RetireSchedulerAuthority", "lc_retire_scheduler_authority"])
def test_neither_platform_rebuilds_the_services_list(name):
    src = INSTALL_PS if name.startswith("Lc-") else INSTALL_SH
    assert name in src
    for rebuild in ("services =", "canonical_service_records", "SERVICE_ROLES"):
        assert rebuild not in src.split(name, 1)[1][:2500], \
            f"{name} appears to rebuild the services list"
