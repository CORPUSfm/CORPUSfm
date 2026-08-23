"""What may be removed, and in what order — decided, never performed (packet 1246-09, stage 2).

**A pure function of the observed facts.** No I/O, no clock, no randomness: the same facts always
produce the same plan, which is what lets the whole decision space be enumerated in a test rather
than sampled.

Three stages, deliberately separate:

1. `validate_relations` — combinations that cannot be acted on refuse by NAME, before anything is
   classified. A refusal here is a *result*, not a failure.
2. `classify` — a total function from facts to one decision per resource, each carrying the
   AUTHORITY that permits it.
3. `plan` — the ordered operations.

**The one rule the rest hangs from: `RECORDED` is the only authority that may permit a deletion.**
`FIXED` names a resource; it never permits removing one. That distinction is why an account with a
matching name survives, and why a service is removed only on the five-part conjunction.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import uninstall_inventory as inv

# ── decisions and authorities ─────────────────────────────────────────────────

REMOVE = "remove"
PRESERVE = "preserve"
DEREGISTER_ONLY = "deregister_only"
UNAVAILABLE = "unavailable"
DECISIONS = (REMOVE, PRESERVE, DEREGISTER_ONLY, UNAVAILABLE)

RECORDED = "recorded"
FIXED_PLATFORM = "fixed_platform"
OBSERVED = "observed"
INFERRED = "inferred"
#: **Not owed, because there is nothing to owe it to.** §G keeps the four FMS conditions apart and
#: says of a genuinely absent server that its work is *not applicable* — which is not the same as
#: *preserved as pending*. The distinction had no vocabulary, so an absent FileMaker Server produced
#: `UNAVAILABLE + RECORDED` for the PKI deregistration and the folder slot: durable work owed to a
#: server that does not exist and never will. Once a run retains work it also preserves the runtime
#: needed to finish it, so the uninstall could never terminate on a box with no FileMaker Server —
#: every rerun produced the identical plan for ever.
NOT_APPLICABLE = "not_applicable"

#: Resources this installation never owns, whatever any record says.
NEVER_OWNED = ("fms_backups", "fms_removed_folder", "recovery_files", "admin_patch_work",
               "unrelated_certs", "legacy_firewall_rule")

# ── refusals ──────────────────────────────────────────────────────────────────

NO_INSTALLATION_RECORD = "no_installation_record"
PENDING_WITHOUT_LOCATOR = "pending_without_locator__resume_from_pending_only"
LOCATOR_UNREADABLE = "locator_unreadable__refuse_rather_than_guess"
LOCATOR_ELSEWHERE = "locator_names_another_installation"
MANIFEST_ABSENT = "manifest_absent__no_deletion_authority"
MANIFEST_INVALID = "manifest_invalid__no_deletion_authority"
ID_MISMATCH = "installation_id_mismatch"
FOREIGN_PENDING = "foreign_pending_record"
INCOMPLETE_PATHS = "incomplete_path_authority__manual_action_required"
INCOMPLETE_PROVIDER = "incomplete_provider_authority__manual_action_required"
AMBIGUOUS_SUPPORT_DIR = "support_directory_authority_is_ambiguous"
FMS_STOPPED = "fms_installed_stopped__start_it_or_use_force"
#: §G: *a rejected credential is not absence.* The stopped server refused before destructive cleanup
#: and the rejected credential did not, so a run that could not authenticate proceeded to remove the
#: installation's own trees and reported the FMS half as merely unfinished. It is the same condition
#: — reachable server, work owed, no way to do it — and it gets the same gate (stage 5, ruling 2).
FMS_CRED_REJECTED = "fms_credential_rejected__supply_working_credentials_or_use_force"
UNCONTAINED_RC = "sandbox_rc_entry_without_recorded_compartment__invalid_containment"
#: **The recorded services do not bind, so this uninstall cannot finish — and it must not START.**
#: The classifier makes drifted units `UNAVAILABLE + RECORDED`, which is right for a record that
#: already exists: the work is owed and the runtime that would do it is preserved. It is the wrong
#: thing to BEGIN. An ordinary start would publish a pending record, open a journal and stop at the
#: quiesce, leaving durable evidence of an operation nobody can complete until the definitions are
#: what this installation recorded — an uninstall that never removes anything and never goes away.
#: Refusing here costs nothing and leaves nothing.
SERVICE_BINDING_DRIFT = "recorded_services_do_not_bind__nothing_was_started"

REFUSAL_REASONS = (NO_INSTALLATION_RECORD, PENDING_WITHOUT_LOCATOR, LOCATOR_UNREADABLE,
                   LOCATOR_ELSEWHERE, MANIFEST_ABSENT, MANIFEST_INVALID, ID_MISMATCH,
                   FOREIGN_PENDING, INCOMPLETE_PATHS, FMS_STOPPED, FMS_CRED_REJECTED,
                   UNCONTAINED_RC, SERVICE_BINDING_DRIFT, INCOMPLETE_PROVIDER,
                   AMBIGUOUS_SUPPORT_DIR)


class Refused(Exception):
    """A named, expected outcome — not an error. Carries the reason so a caller can report it."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Decision:
    decision: str
    authority: str | None
    because: str


# ── stage 1: relations ────────────────────────────────────────────────────────


def requires_fms_work(facts: dict) -> bool:
    """Work only a running FileMaker Server can complete, derived from the record.

    A foundation-only record publishes none of these providers, so it owes no FMS call.
    """
    return (facts["storage"] == inv.STORAGE_OWNED_PRESENT
            or facts["patch_slot"] == inv.PROVIDER_RECORDED
            or facts["pki_registration"] == inv.PROVIDER_RECORDED)


def validate_relations(facts: dict) -> None:
    """Refuse, by name, every combination that must not reach a classifier."""
    inv.validate_facts(facts)
    if facts["locator"] == inv.LOCATOR_ABSENT and facts["pending"] == inv.PENDING_NONE:
        raise Refused(NO_INSTALLATION_RECORD)
    if facts["locator"] == inv.LOCATOR_ABSENT and facts["pending"] == inv.PENDING_MATCHING:
        # LATE FINALIZATION, not a refusal (product ruling, §V). The locator is removed
        # PENULTIMATE and the pending record LAST, so a crash in that one-step window leaves
        # exactly this state — and it is the ordinary tail of a successful uninstall, not damage.
        # It resumes from the fixed pending path alone, which is why pending must outlive the
        # locator rather than the other way round.
        return
    if facts["locator"] == inv.LOCATOR_ABSENT:
        raise Refused(PENDING_WITHOUT_LOCATOR)      # a FOREIGN pending record with no locator
    if facts["locator"] == inv.LOCATOR_UNREADABLE:
        raise Refused(LOCATOR_UNREADABLE)
    if facts["locator"] == inv.LOCATOR_POINTS_ELSEWHERE:
        raise Refused(LOCATOR_ELSEWHERE)
    if facts["manifest"] == inv.MANIFEST_ABSENT:
        raise Refused(MANIFEST_ABSENT)
    if facts["manifest"] == inv.MANIFEST_INVALID:
        raise Refused(MANIFEST_INVALID)
    if facts["manifest"] == inv.MANIFEST_ID_MISMATCH:
        raise Refused(ID_MISMATCH)
    if facts["pending"] == inv.PENDING_FOREIGN:
        raise Refused(FOREIGN_PENDING)
    # O6. A missing exclusive-tree field is INCOMPLETE AUTHORITY, not a smaller job.
    if facts["paths"] == inv.PATHS_INCOMPLETE:
        raise Refused(INCOMPLETE_PATHS)
    if any(facts[name] == inv.PROVIDER_INCOMPLETE
           for name in ("pki_registration", "patch_slot", "proxy_family")):
        raise Refused(INCOMPLETE_PROVIDER)
    # O7 containment. The ruling makes containment part of the identifier's identity — "inside the
    # recorded patch_hosting_dir" — so an RC entry with no recorded compartment is not a usable
    # record. It is refused as a corrupt one, exactly as an invalid manifest is.
    if facts["sandrc"] == inv.SANDRC_PRESENT and facts["patchdir"] == inv.PATCHDIR_NOT_RECORDED:
        raise Refused(UNCONTAINED_RC)
    if facts["supportdir"] == inv.SUPPORTDIR_AMBIGUOUS:
        raise Refused(AMBIGUOUS_SUPPORT_DIR)
    # **THE SERVICE BINDING, and `force` has nothing to say about it.** `--force` continues past work
    # that cannot be completed *now*; it has never meant *begin an operation that cannot finish*.
    # This is deliberately unconditional, and it is deliberately in `validate_relations` rather than
    # in the driver: everything a start does that leaves a trace — the pending publication, the
    # journal, the quiesce, every FMS call and every removal — happens after this function returns,
    # so a refusal here is a result the caller reports and the box is untouched.
    if facts["svcbind"] not in (inv.SVC_BOUND, inv.SVC_ALL_ABSENT,
                                inv.SVC_BOUND_OR_ABSENT):
        raise Refused(SERVICE_BINDING_DRIFT)
    # O5. A stopped FileMaker Server with FMS work owed refuses BEFORE destructive cleanup. `force`
    # permits independent local cleanup only — and only after durable pending evidence exists.
    #
    # **Both unusable conditions refuse here, and this is the LAST thing validation does** — before
    # any pending publication, before the service quiesce, before anything destructive. A refusal
    # from this function is a result the caller reports; nothing has been written and nothing has
    # been touched.
    if requires_fms_work(facts) and not facts["force"]:
        if facts["fms"] == inv.FMS_INSTALLED_STOPPED:
            raise Refused(FMS_STOPPED)
        if facts["fms"] == inv.FMS_CRED_REJECTED:
            raise Refused(FMS_CRED_REJECTED)


# ── stage 2: classification ───────────────────────────────────────────────────


def why_fms_is_unusable(facts: dict) -> str:
    """The condition, named — never generalized into *absent* and never into *done*.

    §G keeps the four FMS conditions apart, and the reason survives into the decisions: an operator
    reading *preserved as pending* is entitled to know whether the server is stopped or whether the
    credential they supplied was refused, because those want different actions from them.
    """
    if facts["fms"] == inv.FMS_INSTALLED_STOPPED:
        return "FileMaker Server is installed and stopped"
    if facts["fms"] == inv.FMS_CRED_REJECTED:
        return "FileMaker Server refused the supplied credential; this is not absence"
    return "FileMaker Server is not usable"


def classify(facts: dict) -> dict:
    """One decision per resource, each with the authority that permits it. Total."""
    d: dict[str, Decision] = {}
    fms_usable = facts["fms"] == inv.FMS_RUNNING
    fms_absent = facts["fms"] == inv.FMS_ABSENT
    local_only = not fms_usable
    unusable = why_fms_is_unusable(facts)

    # -- storage: recorded exact paths, never a name (O1) --------------------------------
    if facts["storage"] == inv.STORAGE_NOT_OWNED:
        d["storage_db"] = Decision(UNAVAILABLE, None,
                                   "no ownership entry; an unrecorded database survives")
        d["storage_rc"] = Decision(UNAVAILABLE, None, "no ownership entry")
    elif facts["storage"] == inv.STORAGE_OWNED_ABSENT:
        d["storage_db"] = Decision(PRESERVE, RECORDED, "owned, already gone")
        d["storage_rc"] = Decision(PRESERVE, RECORDED, "owned, already gone")
    elif fms_absent:
        d["storage_db"] = Decision(REMOVE, RECORDED,
                                   "exact owned path; FMS absent, so no close is possible")
        d["storage_rc"] = Decision(REMOVE, RECORDED, "exact owned RC path")
    elif fms_usable:
        d["storage_db"] = Decision(REMOVE, RECORDED,
                                   "closed, proven unhosted, then the exact owned path removed")
        d["storage_rc"] = Decision(REMOVE, RECORDED, "exact owned RC path, after its database")
    else:
        d["storage_db"] = Decision(UNAVAILABLE, RECORDED,
                                   f"{unusable}, so the database cannot be proved unhosted; "
                                   "preserved as pending")
        d["storage_rc"] = Decision(UNAVAILABLE, RECORDED, "follows its database")

    # -- sandbox file: patch.sandbox_file, the single authority ---------------------------
    if facts["sandbox"] == inv.SANDBOX_NOT_RECORDED:
        d["sandbox"] = Decision(UNAVAILABLE, None, "not recorded")
    elif facts["sandbox"] == inv.SANDBOX_ABSENT:
        d["sandbox"] = Decision(PRESERVE, RECORDED, "recorded, already gone")
    else:
        d["sandbox"] = Decision(REMOVE, RECORDED, "patch.sandbox_file, the sole sandbox authority")

    # -- sandbox RC: one attributed ownership entry, or nothing (O7) ----------------------
    if facts["sandrc"] == inv.SANDRC_PRESENT:
        d["sandbox_rc"] = Decision(
            REMOVE, RECORDED,
            "typed shared/conditional entry, canonical path inside the recorded compartment")
    elif facts["sandrc"] == inv.SANDRC_ABSENT:
        d["sandbox_rc"] = Decision(PRESERVE, RECORDED, "recorded, already gone")
    elif facts["sandrc"] == inv.SANDRC_UNRECORDED_PRESENT:
        d["sandbox_rc"] = Decision(
            PRESERVE, None,
            "present but never attributed; a pre-existing or same-named RC is never adopted")
    else:
        d["sandbox_rc"] = Decision(PRESERVE, None,
                                   "attribution ambiguous; no entry, and the limitation is reported")

    if facts["supportdir"] == inv.SUPPORTDIR_NOT_RECORDED:
        d["support_dir"] = Decision(PRESERVE, None, "no support directory was recorded")
    elif facts["supportdir"] == inv.SUPPORTDIR_ABSENT:
        d["support_dir"] = Decision(PRESERVE, RECORDED, "recorded, already gone")
    elif facts["supportdir"] == inv.SUPPORTDIR_EMPTY:
        d["support_dir"] = Decision(REMOVE, RECORDED,
                                    "the exact recorded support directory is empty")
    else:
        d["support_dir"] = Decision(PRESERVE, RECORDED,
                                    "the support directory contains work and is retained")

    # O7's second-order rule, computed rather than assumed: an RC this installation may not remove
    # is CONTENT, so the compartment is not empty and neither it nor its slot may go.
    residue = facts["sandrc"] in (inv.SANDRC_UNRECORDED_PRESENT, inv.SANDRC_AMBIGUOUS)

    if facts["patchdir"] == inv.PATCHDIR_NOT_RECORDED:
        d["patch_dir"] = Decision(UNAVAILABLE, None, "not recorded")
        d["patch_slot"] = Decision(UNAVAILABLE, None, "no directory to deregister")
    elif facts["patchdir"] == inv.PATCHDIR_HAS_WORK or residue:
        d["patch_dir"] = Decision(
            PRESERVE, RECORDED,
            "non-empty: administrator work, or an RC path this installation may not remove")
        d["patch_slot"] = Decision(PRESERVE, RECORDED,
                                   "the slot is preserved with the directory it serves")
    else:
        d["patch_dir"] = (Decision(PRESERVE, RECORDED, "recorded, already gone")
                          if facts["patchdir"] == inv.PATCHDIR_ABSENT
                          else Decision(REMOVE, RECORDED,
                                        "exact recorded path, empty or holding only the recorded "
                                        "sandbox family removed earlier in this plan"))
        if facts["patch_slot"] == inv.PROVIDER_NOT_RECORDED:
            d["patch_slot"] = Decision(PRESERVE, None, "no folder-slot authority was published")
        elif fms_usable:
            d["patch_slot"] = Decision(DEREGISTER_ONLY, RECORDED, "exact recorded slot")
        elif fms_absent:
            d["patch_slot"] = Decision(
                PRESERVE, NOT_APPLICABLE,
                "a folder slot is held BY a FileMaker Server, and there is none on this box; the "
                "deregistration is not applicable rather than pending")
        else:
            d["patch_slot"] = Decision(UNAVAILABLE, RECORDED,
                                       f"{unusable}; preserved as pending")

    # The proxy edits are LOCAL FILES with recorded fingerprints, so their removal is local
    # too — which is why an absent FileMaker Server permits it and a merely unusable one does not
    # (an unusable one may still be serving the routing we are about to take out).
    if facts["proxy_family"] == inv.PROVIDER_NOT_RECORDED:
        d["proxy_edits"] = Decision(PRESERVE, None, "no proxy family was published")
    else:
        d["proxy_edits"] = (
            Decision(REMOVE, RECORDED, "config_location and config_fingerprint recorded")
            if fms_usable or fms_absent
            else Decision(UNAVAILABLE, RECORDED, f"{unusable}; preserved as pending"))
    if facts["pki_registration"] == inv.PROVIDER_NOT_RECORDED:
        d["pki"] = Decision(PRESERVE, None, "no PKI registration authority was published")
    elif fms_usable:
        d["pki"] = Decision(REMOVE, RECORDED,
                            "registration_name and public_fingerprint recorded")
    elif fms_absent:
        d["pki"] = Decision(
            PRESERVE, NOT_APPLICABLE,
            "a registration is held BY a FileMaker Server, and there is none on this box; the "
            "deregistration is not applicable rather than pending")
    else:
        d["pki"] = Decision(UNAVAILABLE, RECORDED,
                            f"{unusable}, and deregistration needs a running one; preserved as "
                            "pending")

    # -- services: the five-part conjunction, or OWED (O4; Codex disposition, stage 6) ----
    #
    # **A service that cannot presently be re-proved is UNFINISHED WORK, not absent work.** The three
    # non-bound results used to PRESERVE, and preserving is what made them disappear: a preserved
    # resource is owed nothing, so it builds no operation, withholds nothing through the recovery
    # closure, and never reaches the early quiesce. The run then removed `install_dir` and cleaned the
    # trees while three registered units went on pointing at what used to be there — a box with live
    # services and nothing left that knows how to stop them.
    #
    # `UNAVAILABLE` + `RECORDED` says the true thing instead: **this installation owns these units and
    # cannot act on them right now.** Every consequence follows from that one word without a special
    # case — `remaining_from_plan` builds all three typed operations into durable authority,
    # `recovery_closure` withholds the interpreter, the shim, the helpers and both cleans, `plan`
    # emits no removal, and the executor's early quiesce re-proves each conjunction and refuses before
    # issuing a single stop or delete.
    #
    # **These branches are for TOTALITY and for a record that ALREADY EXISTS, not for starting.** An
    # ordinary start never reaches them: `validate_relations` refuses a non-bound binding by name
    # before anything is published, so the state they describe is only reachable when a record was
    # published while the services bound and the definitions changed underneath it. That is external
    # interference with installed state, it is not a supported configuration, and what these branches
    # guarantee is the safe half — the work stays owed, the runtime stays, and nothing is removed.
    # **Repairing or adopting such a record is not machinery this packet has**, and nothing here
    # should be read as promising it.
    #
    # **`RECORDED` is the authority for all three, including `name_only`.** It authorizes nothing on
    # its own — no removal is emitted, and the executor re-proves the whole conjunction before it acts
    # — and what it records is the fact that MADE this work owed: the installation published these
    # service records. Answering `None` here is what let the work vanish.
    for resource in ("web_service", "scheduler_service", "updater_task"):
        if facts["svcbind"] in (inv.SVC_BOUND, inv.SVC_ALL_ABSENT,
                                inv.SVC_BOUND_OR_ABSENT):
            d[resource] = Decision(
                REMOVE, RECORDED,
                "role, name and definition path recorded; the observed service resolves to that "
                "definition; its executable is canonically beneath install_dir; identity agrees")
        elif facts["svcbind"] == inv.SVC_NAME_ONLY:
            d[resource] = Decision(
                UNAVAILABLE, RECORDED,
                "no recorded definition path binds the observed service, and a matching name is not "
                "authority; the unit stays owed until its definition is what this installation "
                "recorded")
        elif facts["svcbind"] == inv.SVC_EXECUTABLE_OUTSIDE:
            d[resource] = Decision(
                UNAVAILABLE, RECORDED,
                "the executable is not beneath the recorded install_dir — drift, so the conjunction "
                "cannot be re-proved and the unit stays owed")
        else:
            d[resource] = Decision(
                UNAVAILABLE, RECORDED,
                "the expected service identity disagrees — drift, so the conjunction cannot be "
                "re-proved and the unit stays owed")

    # -- account: an ownership entry, never a name (O3) -----------------------------------
    d["service_account"] = (
        Decision(REMOVE, RECORDED, "an ownership entry says this installation created it")
        if facts["account"] == inv.ACCOUNT_OWNED
        else Decision(PRESERVE, None, "a fixed account name never authorizes deletion"))

    # **These were unconditional, and a blind review built the counterexample by hand.** An
    # installer that supplied neither `cli_shim` nor `privilege_helpers` publishes an EMPTY
    # ownership table — `cli.py` says so in as many words — and the planner claimed `RECORDED`
    # authority to delete both anyway. The enumeration could not see it: there was no fact
    # representing whether they were recorded, so no combination could express the wrong one.
    for resource in ("cli_shim", "sudoers_helpers"):
        d[resource] = (Decision(REMOVE, RECORDED, "foundation-published ownership entry")
                       if facts["fixed_resources"] == inv.FIXED_OWNED
                       else Decision(PRESERVE, None,
                                     "nothing recorded it; an empty ownership table is not a "
                                     "licence to go looking"))

    for resource in RECURSIVE_TREES:
        d[resource] = Decision(REMOVE, RECORDED,
                               "recorded exclusive tree, holding no control-plane path")
    for resource in ("config_dir", "state_dir"):
        d[resource] = Decision(
            REMOVE, RECORDED,
            "recorded exclusive tree, CLEANED of product content — the live control-plane paths "
            "inside it are excluded, derived from paired_layouts()")
    d["run_dir"] = Decision(
        PRESERVE, RECORDED,
        "the minimal permanent lifecycle coordination footprint; the active lock lives here and is "
        "never removed or replaced while held")

    for resource in NEVER_OWNED:
        d[resource] = Decision(PRESERVE, None, "never installation-owned")

    # O5 under `--force` needs no correction pass here: every FMS-dependent branch above already
    # conditions REMOVE/DEREGISTER_ONLY on `fms_usable` or `fms_absent`, so none of them can be
    # reached when `local_only` holds. An earlier version ran a re-flip loop over those five
    # resources; enumerating the 720 relevant points showed it firing ZERO times. A correction that
    # never corrects reads like a safeguard and is not one, so it is gone and the invariant is
    # asserted in the test suite instead.
    assert not (local_only and not fms_absent) or all(
        d[r].decision not in (REMOVE, DEREGISTER_ONLY)
        for r in ("storage_db", "storage_rc", "patch_slot", "pki", "proxy_edits")
    ), "an FMS-dependent removal survived a non-running FileMaker Server"
    return d


# ── stage 3: the ordered plan ─────────────────────────────────────────────────

WRITE_PENDING = "write_pending_to_stable_config_locator_authority"
STOP_SERVICES = "stop_app_services"

#: `config_dir` and `state_dir` are CLEANED, not removed. They hold the live control plane, and a
#: recursive removal of either destroys the record the operation is still using. The exclusions are
#: derived from `paired_layouts()` by `inventory.control_plane_exclusions`, never hand-listed.
CLEAN_CONFIG = "clean:config_dir"
CLEAN_STATE = "clean:state_dir"

#: The journal is resolved and discarded under the held lock, only after every product removal and
#: every checkpoint is terminal — it is the authority that says so.
DISCARD_JOURNAL = "journal:resolve_and_discard"

REMOVE_LOCATOR = "remove:locator"
REMOVE_PENDING = "remove:pending_evidence"

#: `run_dir` and the lock inside it are the minimal PERMANENT lifecycle coordination footprint. The
#: active lock pathname is never unlinked, replaced or recursively removed — an uninstall that
#: deleted the lock it is holding has no way to serialize its own last steps, and a reinstall
#: reuses the same fixed directory.
PRESERVED_FOOTPRINT = ("run_dir",)

#: Trees still removed outright: they hold no control-plane path on either platform.
RECURSIVE_TREES = ("install_dir", "log_dir", "secrets_dir")


#: **What invoking the next run is MADE OF.** `install_dir` holds the bundled interpreter and the
#: package (`install.sh` runs `$INSTALL_DIR/venv/bin/python -m corpusfm.lifecycle.cli`), the CLI shim
#: is a wrapper that `exec`s that same interpreter, and the privilege helpers are the elevation
#: surface a shipped resume path may need. None of them is downstream of a retained operation, so
#: none is reachable through the dependency relation — they are the *invocation's* own footprint and
#: are declared as such.
#:
#: A run that retained work and removed these left a pending record on a box with nothing able to
#: read it: durable evidence, no runnable recovery, which is the RC4 this packet exists to prevent.
INVOCATION_FOOTPRINT: tuple = ("install_dir", "cli_shim", "sudoers_helpers")


def recovery_closure(decisions: dict) -> frozenset:
    """Every resource this invocation must NOT remove, because a later one still needs it.

    **Derived, never enumerated.** The seed is the invocation's own footprint plus whatever is
    already retained; the closure then follows the SAME dependency relation the pending record is
    ordered by — if `B` must run after `A`, then `A` being undone is exactly the reason `B` may not
    run now. That is what makes `secrets_dir` survive a retained PKI deregistration, `patch_dir`
    survive a retained slot, and both cleans wait for everything: not three special cases, one
    relation read in the direction that answers this question.

    Empty when nothing is retained — a complete uninstall removes its own runtime, which is the
    point of it.
    """
    from .uninstall_pending import CLEANED_RESOURCES, RESOURCE_FOLLOWS

    retained = {r for r, v in decisions.items()
                if v.decision == UNAVAILABLE and v.authority == RECORDED}
    if not retained:
        return frozenset()
    closure = set(retained) | {r for r in INVOCATION_FOOTPRINT if r in decisions}
    while True:
        grew = set()
        for resource in decisions:
            if resource in closure:
                continue
            follows = (set(decisions) - set(CLEANED_RESOURCES)
                       if resource in CLEANED_RESOURCES
                       else set(RESOURCE_FOLLOWS.get(resource, ())))
            if follows & closure:
                grew.add(resource)
        if not grew:
            return frozenset(closure)
        closure |= grew


def is_late_finalization(facts: dict) -> bool:
    """The supported tail state: pending survives, the locator is already gone."""
    return (facts["locator"] == inv.LOCATOR_ABSENT
            and facts["pending"] == inv.PENDING_MATCHING)


def plan(facts: dict, decisions: dict) -> tuple:
    """`(operations, unfinished)`.

    The pending record is written to stable fixed authority FIRST and never moves — there is no
    relocation step, by design, so there is no torn-relocation window to recover from. Pending
    evidence is removed second-last and the locator last, and only when nothing is unfinished.
    """
    if is_late_finalization(facts):
        # Everything else already happened; the record that says so is the only thing left.
        return (REMOVE_PENDING,), ()
    # **What this invocation may not touch, because a later one still needs it (ruling 4).** Every
    # emission below consults it, so a resource inside the closure is recorded as owed and simply is
    # not acted on now.
    withheld = recovery_closure(decisions)

    def owed(resource: str) -> bool:
        return resource not in withheld

    ops = [WRITE_PENDING, STOP_SERVICES]
    if facts["fms"] == inv.FMS_RUNNING:
        for resource in ("pki", "patch_slot"):
            if decisions[resource].decision in (REMOVE, DEREGISTER_ONLY) and owed(resource):
                ops.append("fms:" + resource)
        # `fms:close_storage` and `fms:verify_unhosted` are NOT separate operations any more, for
        # the same reason: they are the first two steps of `remove:storage_db`, and a step a caller
        # can skip is a step that gets skipped.
    # `storage_rc` is CLASSIFIED but not emitted as its own operation (packet 1246-09 §Y). The
    # storage removal is ATOMIC — close, prove unhosted, remove the file, then its RC paths — and
    # three externally orderable operations were how a live hosted database got deleted with no
    # proof it had ever been closed. The decision still exists because the RC's ownership is a real
    # fact; what it no longer is, is something a caller can order independently.
    for resource in ("storage_db", "sandbox", "sandbox_rc", "support_dir", "patch_dir",
                     "proxy_edits"):
        if decisions[resource].decision == REMOVE and owed(resource):
            ops.append("remove:" + resource)
    for resource in ("web_service", "scheduler_service", "updater_task", "cli_shim",
                     "sudoers_helpers", "service_account"):
        if decisions[resource].decision == REMOVE and owed(resource):
            ops.append("remove:" + resource)
    for resource in RECURSIVE_TREES:
        if decisions[resource].decision == REMOVE and owed(resource):
            ops.append("remove:" + resource)
    # CLEANED, never removed: each holds a live control-plane path.
    if decisions["state_dir"].decision == REMOVE and owed("state_dir"):
        ops.append(CLEAN_STATE)
    if decisions["config_dir"].decision == REMOVE and owed("config_dir"):
        ops.append(CLEAN_CONFIG)
    # **Unfinished is now everything still owed after this invocation** — the resources nothing can
    # do yet, AND the ones this run deliberately preserved so that the next one can run at all. Both
    # are in the pending record; both are why the locator stays.
    unfinished = tuple(r for r, v in decisions.items()
                       if (v.decision == UNAVAILABLE and v.authority == RECORDED)
                       or (r in withheld and v.decision in (REMOVE, DEREGISTER_ONLY)))
    if unfinished:
        ops.append("retain_pending_and_locator__remaining:%d" % len(unfinished))
    else:
        # THE FINALIZATION TAIL, in this order and for these reasons:
        #   journal   — resolved and discarded under the held lock, only now that every product
        #               removal and every checkpoint is terminal;
        #   locator   — PENULTIMATE;
        #   pending   — LAST, so a crash in the one-step window between them leaves a matching
        #               pending record with no locator, which resumes from the fixed pending path
        #               alone. The reverse order leaves a locator pointing at an installation that
        #               is gone, with no evidence of what remains — unresumable.
        ops.append(DISCARD_JOURNAL)
        ops.append(REMOVE_LOCATOR)
        ops.append(REMOVE_PENDING)
    return tuple(ops), unfinished


def removable_resources(decisions: dict) -> tuple:
    """Every resource the plan would delete, with its authority. Used by callers that must record
    the remaining set before the first destructive action."""
    return tuple((name, decision.authority)
                 for name, decision in sorted(decisions.items())
                 if decision.decision == REMOVE)
