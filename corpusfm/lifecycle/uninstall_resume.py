"""Driving an uninstall, and resuming one (packet 1246-09, stage 5).

**Two entry points, and the difference between them is where authority comes from.** `start` observes
the box, plans, and writes down what it is about to do. `resume` reads what was written down and does
exactly that. Neither takes a target from its caller, and `resume` never re-plans — which is not a
stylistic preference but the only thing that works:

* the ordinary tail of a *successful* uninstall has already removed `install_dir`, so the manifest is
  gone at every boundary after it. A resume that consulted the planner would refuse there, on a box
  where nothing is wrong;
* and a re-plan that ran earlier would produce a different remaining set, which `publish` refuses by
  design. There is no arrangement in which re-planning is the safe option.

So the pending record is read FIRST on a resume, and its typed operations and their durable order are
the whole of the dispatch. The journal is joined, never used to decide what to do.

**The ordering of the two durable writes is the crash contract.** The record is published *before*
`journal.begin` and before anything destructive, so a crash between them leaves a matching record and
no journal — which `resume` opens and continues. The reverse order would leave a journal describing
an operation whose remaining set nobody wrote down.

**What a caller may supply: operational collaborators, and NO facts** (corrected at stage 6). A
subprocess runner, an FMS adapter, an admin API client, a proxy engine and observation, a folder-slot
client, a credential provider — every one of them a way to reach the box, and not one of them a
statement about it.

The two observations that used to arrive from outside — whether FileMaker Server is running, and
whether the recorded services still bind — are both derived here now, from the recorded root, the
platform's fixed service names, and `canonical_service_records`. §AE.1 had already proved that a
*claimed* absence is an RC4 and made `fms_state` locally proved while still accepting the word;
`service_binding` was the same defect one field along, and its consequence was worse — no caller
could establish it at all, which is what made a thin launcher impossible. Both are gone from the
request.

A caller supplies no path, no name, no fingerprint, no root, no host and no state, and a credential
is acquired only when the operation about to run has proved it needs one.
"""

from __future__ import annotations

import dataclasses
import uuid
import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path

from . import install_attempt as ia
from . import result as R
from . import uninstall_inventory as inv
from . import uninstall_pending as pending
from . import uninstall_plan as up
from .errors import LifecycleError, RecordInvalid, RecoveryRequired
from .journal import Journal
from .layout import POSIX, WINDOWS
from .lock import LockNotHeld, require_lock
from .locator import locator_for
from .schema import (
    JOURNAL_RESOLVED,
    OWNERSHIP_KIND_PATCH_SANDBOX_RC,
    OWNERSHIP_KIND_SERVICE_ACCOUNT,
    utc_now_iso,
)

#: The journal mode. One word, from the closed vocabulary, and never a per-verb variant.
UNINSTALL_MODE = "uninstall"

# The storage component is the sole producer of these checkpoint words.  A prefix match would turn
# a corrupt or future subsystem into destructive authority before its recovery contract was known.
_RECOVERABLE_STORAGE_CHECKPOINTS = frozenset({
    "storage:template_placed",
    "storage:settings_initialized",
})

# ── named outcomes ────────────────────────────────────────────────────────────
#
# Every refusal this module can produce has a name, for the same reason the planner's do: a caller
# branches on the reason, and prose is not a branch. These are the ones the planner does not already
# supply — a planner refusal keeps its own reason.

NO_PENDING_RECORD = "no_pending_record__nothing_to_resume"
PENDING_ALREADY_EXISTS = "pending_record_exists__resume_it_rather_than_starting_again"
PENDING_UNREADABLE = "pending_record_unreadable__refuse_rather_than_overwrite"
JOURNAL_UNREADABLE = "journal_unreadable__recovery_owed_before_any_uninstall"
JOURNAL_UNRESOLVED = "journal_unresolved__an_earlier_operation_stopped_in_the_middle"
JOURNAL_FOREIGN = "journal_belongs_to_another_operation"
JOURNAL_WRONG_MODE = "journal_is_not_an_uninstall"
JOURNAL_RESOLVED_WITH_WORK = "journal_resolved_while_pending_still_owes_work__contradiction"
LOCATOR_GONE_WITH_WORK = "locator_absent_while_pending_still_owes_work__not_late_finalization"
QUIESCE_INCOMPLETE = "application_services_did_not_quiesce__nothing_destructive_attempted"
INSTALLATION_MISMATCH = "installation_id_does_not_match_this_installation"
FMS_PRESENCE_CONFLICTS = "fms_presence_evidence_conflicts__refusing_to_guess"
FMS_PRESENCE_UNREADABLE = "fms_presence_evidence_unreadable__refusing_to_guess"
SERVICE_BINDING_UNREADABLE = "service_binding_evidence_unreadable__refusing_to_guess"
COLLABORATOR_UNAVAILABLE = "an_operation_needs_a_collaborator_this_box_cannot_construct"
#: **Not a refusal — a terminal REPORT.** The invocation removed the interpreter, the launcher or an
#: elevation helper and then could not finish, so what remains is real work on a box that can no
#: longer run this program. Saying `incomplete_safe` there would promise a resume through a CLI that
#: is gone.
REINSTALL_REQUIRED = "terminal_footprint_removed__reinstall_to_finish"
REASON_UNREACHABLE = "unreachable_dispatch__no_handler_for_this_operation"

REFUSAL_REASONS: tuple = (
    NO_PENDING_RECORD, PENDING_ALREADY_EXISTS, PENDING_UNREADABLE, JOURNAL_UNREADABLE,
    JOURNAL_UNRESOLVED, JOURNAL_FOREIGN, JOURNAL_WRONG_MODE, JOURNAL_RESOLVED_WITH_WORK,
    LOCATOR_GONE_WITH_WORK, QUIESCE_INCOMPLETE, INSTALLATION_MISMATCH, COLLABORATOR_UNAVAILABLE,
    REINSTALL_REQUIRED, REASON_UNREACHABLE, FMS_PRESENCE_CONFLICTS,
    FMS_PRESENCE_UNREADABLE, SERVICE_BINDING_UNREADABLE,
)

# ── proving that FileMaker Server is genuinely absent ─────────────────────────
#
# **There is no request value left to disbelieve** (stage 6). The condition is observed here, and
# `absent` is the word that makes work DISAPPEAR — it decides that the PKI deregistration and the
# folder slot are NOT APPLICABLE and produce no operation at all, after which nothing downstream can
# re-check them, because there is no operation to carry evidence and a resume never re-plans.
#
# The storage operation was built against exactly this hazard, and its answer is the model followed
# here: `StorageOperation.fms_root` exists so the executor re-observes absence ITSELF, at the exact
# recorded path, every time. This does the same for the classification.
#
# **A conjunction, because one fact is not a proof.** A missing directory could be a mount that has
# not come up; a missing service could be a manager that is not answering. Absence is concluded only
# when the recorded root and the platform's fixed FileMaker Server service BOTH say so, and every
# disagreement — one present and one absent, a link or reparse point where the root should be, a
# root replaced between the read and the open, an unreadable root, an unreadable service manager —
# refuses by name rather than resolving to either answer.
#
# **`cred_rejected` is no longer produced by anything** (stage 6 ruling 2). No local observation can
# see an authentication refusal, so a caller was the only possible source and a caller is the one
# thing that may no longer state it. A rejected credential is now learned the only honest way: by
# attempting the authenticated work and having it refused, which retains that operation and reports
# the executor's own reason. The word survives in `inv.FMS_STATES` and in `validate_relations`
# because the planner is a total function over a closed domain with an exhaustive enumeration behind
# it — removing a domain member to match one producer's reach would narrow the proof, not the risk.

#: The platform's own FileMaker Server service. FIXED, never from a caller and never from the
#: manifest: it is the platform's name for FileMaker Server, not a fact about this installation.
POSIX_FMS_UNIT = "fmshelper.service"
WINDOWS_FMS_SERVICE = "FileMaker Server"

#: systemd and `sc` words that mean *this service is running*.
_RUNNING_WORDS = frozenset({"ACTIVE", "ACTIVATING", "RUNNING", "START_PENDING", "CONTINUE_PENDING"})


def observe_fms_presence(manifest, *, flavour: str, runner=None) -> tuple:
    """`(state, detail)` — the FMS condition from installed authority, or `(None, why not)`.

    The root comes from `manifest.paths.fms_root` and the service name from the platform. The caller
    contributes a subprocess runner and nothing else: no root, no service name, and no way to assert
    an answer.
    """
    recorded = manifest.paths.fms_root if manifest is not None else None
    if not recorded:
        return None, ("the manifest records no FileMaker Server root, so this installation never "
                      "wrote down what would have to be absent")
    return _fms_presence_from_recorded_root(recorded, flavour=flavour, runner=runner)


def _fms_presence_from_recorded_root(recorded, *, flavour: str, runner=None) -> tuple:
    """The same conjunction, from a root that is already known to be a RECORDED one.

    Split out so a resume can ask it of `StorageOperation.fms_root` — the durable record's own copy
    of the same fact — on a box where the manifest is already gone. Neither caller supplies a root of
    its own choosing: one reads the manifest, the other reads the pending record.
    """
    from . import service_control as sc
    from .uninstall_exec_posix import (
        FMS_ROOT_ABSENT,
        FMS_ROOT_PRESENT,
        _observe_recorded_fms_root,
    )

    if not recorded:
        return None, "no FileMaker Server root is recorded"
    root_state, root_detail = _observe_recorded_fms_root(recorded, flavour=flavour)
    if root_state not in (FMS_ROOT_ABSENT, FMS_ROOT_PRESENT):
        return None, f"the recorded FileMaker Server root is not observable: {root_detail}"

    if flavour == POSIX:
        registered, running, probe = sc.posix_service_run_state(POSIX_FMS_UNIT, runner=runner)
        unit = POSIX_FMS_UNIT
    else:
        registered, running, probe = sc.windows_service_run_state(WINDOWS_FMS_SERVICE,
                                                                  runner=runner)
        unit = WINDOWS_FMS_SERVICE
    if registered == sc.UNREADABLE:
        return None, (f"the service manager could not be asked about {unit}: "
                      f"{(probe.stderr or probe.stdout or '').strip()!r}")

    if root_state == FMS_ROOT_ABSENT and registered == sc.ABSENT:
        return inv.FMS_ABSENT, (f"{recorded} does not exist and the service manager does not know "
                                f"{unit}")
    if root_state == FMS_ROOT_ABSENT or registered == sc.ABSENT:
        # ONE of the two. A mount that has not come up, a manager mid-restart, a half-removed
        # FileMaker Server: every reading of this is a guess, and the one guess that would matter
        # is the one that abandons work.
        return None, (f"the recorded root is {root_state} and {unit} is {registered}; presence and "
                      "absence disagree, and neither is concluded")
    if running is None:
        return None, f"{unit} is registered and its run state could not be read"
    return ((inv.FMS_RUNNING if running.upper() in _RUNNING_WORDS else inv.FMS_INSTALLED_STOPPED),
            f"{recorded} exists and {unit} is {running}")


class ResumeRefused(LifecycleError):
    """Authority could not be established. Nothing was written and nothing was touched."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


@dataclass
class Progress:
    """Whether this invocation has made a DURABLE change yet.

    The CLI has to tell `failed_before_change` from `incomplete_safe` when an exception escapes, and
    reading the record from disk cannot answer it — on a resume a record was already there before
    anything happened. So the two events that matter are recorded as they occur, by the code that
    performs them.
    """

    published: bool = False
    checkpoints: int = 0

    @property
    def mutated(self) -> bool:
        return self.published or self.checkpoints > 0


@dataclass(frozen=True)
class Report:
    """One invocation, as a closed structure. The CLI renders it; it decides nothing."""

    result: str
    operation_id: str | None = None
    installation_id: str | None = None
    reason: str = ""
    detail: str = ""
    executed: tuple = ()
    retained: tuple = ()
    skipped: tuple = ()
    finalized: bool = False
    observations: tuple = ()
    #: Packet 1398: the discard finished its frozen plan and terminal retirement is owed OUTSIDE the
    #: lifecycle lock. Deliberately absent from `to_dict`, so the ordinary report is unchanged.
    attempt_terminal: bool = False

    def to_dict(self) -> dict:
        return {"result": self.result, "operation_id": self.operation_id,
                "installation_id": self.installation_id, "reason": self.reason,
                "detail": self.detail, "executed": list(self.executed),
                "retained": list(self.retained), "skipped": list(self.skipped),
                "finalized": self.finalized, "observations": list(self.observations)}


# ── collaborators ─────────────────────────────────────────────────────────────


@dataclass
class Collaborators:
    """Everything that touches the world outside this process, and nothing that names a target.

    Every field is a client through which a recorded operation reaches the box. **None of them is a
    fact about the box** — `fms_state` and `service_binding` were, and they are derived from
    installed evidence now, because a collaborator a caller cannot supply is an interface gap and a
    fact a caller cannot observe is a lie waiting to be told.

    **A credential is a callable**, not a value: it is invoked only when the operation about to run
    has proved it needs one, so an uninstall that never reaches an FMS restart never asks for one —
    which is §G's rule that the need is derived after observation, expressed as a shape rather than
    as a convention.
    """

    #: The bounded subprocess runner the service primitives use.
    runner: object = None
    #: `close_database` / `await_status` / `list_databases`. `None` means *no observation available*,
    #: which the executor turns into its own recorded-root check — never into permission.
    fms: object = None
    #: The FMS Admin API client, for the PKI deregistration.
    admin_api: object = None
    #: The folder-slot client, for the patch compartment.
    folders: object = None
    #: The proxy box-reader and the bounded executor.
    proxy_observe: object = None
    proxy_engine: object = None
    #: Called with no arguments, at most once, and only when a recorded operation needs it.
    credential: object = None
    #: Optional BUILDERS, called at most once each and only for the operation that needs them. The
    #: shipped CLI supplies these; a test supplies the finished object instead. Either way nothing
    #: is constructed for an operation the record does not owe, which is what keeps an uninstall
    #: with no proxy work from opening a network client or reading a credential.
    build_fms: object = None
    build_admin_api: object = None
    build_folders: object = None
    build_proxy_observe: object = None
    build_proxy_engine: object = None
    _lease: object = field(default=None, init=False, repr=False)
    _leased: bool = field(default=False, init=False, repr=False)
    _built: dict = field(default_factory=dict, init=False, repr=False)
    _failed: dict = field(default_factory=dict, init=False, repr=False)

    def lease(self):
        """The held credential, acquired on first genuine need and reused for the rest of the run.

        `_leased` rather than `self._lease is None`: a credential callable that legitimately returns
        a falsy lease would otherwise be invoked again on every operation that asked.

        **Acquisition is a lazy construction like any other, and it fails the same way.** The
        shipped closure duplicates a descriptor and reads a length-prefixed frame from it — an
        `OSError` for a descriptor that was never inherited, a `CredentialFrameRefused` for a short
        or empty one — and letting either escape aborted the whole invocation over one operation
        that should simply have stayed owed. It is caught here for the same reason a builder's is.
        """
        if not self._leased and self.credential is not None:
            self._leased = True
            try:
                self._lease = self.credential()
            except Exception as exc:                                      # noqa: BLE001
                self._lease = None
                self._record_failure("credential", exc)
        return self._lease

    def credential_failed(self) -> bool:
        """Whether a credential was CONFIGURED and could not be obtained. A transport of `none` is
        not a failure — it is an installation that never expected to need one."""
        return "credential" in self._failed

    def need(self, name: str):
        """The collaborator for THIS operation, constructed now if it has not been already.

        Returns `None` when neither a finished object nor a builder was supplied, or when the
        builder itself answers `None` — the shape `fms_folders.build_adapter` already uses for
        *authority is missing or unusable*. The caller turns that into a named refusal that retains
        the operation, rather than a traceback and an invented state.
        """
        supplied = getattr(self, name)
        if supplied is not None:
            return supplied
        if name in self._built:
            return self._built[name]
        builder = getattr(self, "build_" + name, None)
        if builder is None:
            self._built[name] = None
            return None
        try:
            built = builder()
        except Exception as exc:                                          # noqa: BLE001
            # **A builder that RAISES means the same thing as one that returns `None`**: this box
            # could not construct the collaborator. `_px_engine` raises `_PxRefused`, and the real
            # activator and executor-script helpers can raise too — and letting any of them escape
            # aborted the whole invocation over one operation that should simply have stayed owed.
            # `KeyboardInterrupt` and `SystemExit` are not ordinary exceptions and are not caught.
            self._built[name] = None
            self._record_failure(name, exc)
            return None
        self._built[name] = built
        return built

    def _record_failure(self, name: str, exc: BaseException) -> None:
        """**The ONE place a construction failure is written down**, and it records the exception
        TYPE only.

        Two sites used to build the same string independently — `lease()` and `need()` — which is
        two spellings of one contract and therefore one that drifts. It is also the text that
        reaches a report, and an exception's message carries whatever it was handed: a host, a path,
        an argv. The type says which boundary failed; the payload says things a report must not.
        """
        self._failed[name] = type(exc).__name__

    def why_unavailable(self, name: str) -> str:
        """How the construction failed, when it failed by raising. Empty when it simply answered
        `None`, which is `build_adapter`'s own way of saying *authority is missing or unusable*."""
        return self._failed.get(name, "")

    def wipe(self) -> None:
        lease = self._lease
        self._lease, self._leased = None, False
        if lease is not None and hasattr(lease, "wipe"):
            lease.wipe()


# ── observation ───────────────────────────────────────────────────────────────


def observe(layout, *, collaborators: Collaborators, force: bool,
            expected_installation_id: str | None = None) -> tuple:
    """`(facts, manifest)` — every one of them derived from installed evidence.

    **No fact comes from the caller any more** (stage 6). The locator, the manifest, path
    completeness, storage ownership, the sandbox and its RC, the compartment, the fixed resources,
    the service account, the pending record, FileMaker Server's condition and the service binding are
    all read here from what the installation wrote about itself and what the box answers about it.

    That is not fastidiousness. A fact cannot aim a deletion — the target always comes from the
    manifest and the executor re-proves it — but a fact does decide whether an operation is BUILT at
    all, and an operation that is never built is work that silently disappears.
    """
    flavour = _flavour_of(layout)
    locator_state, manifest_state, manifest = inv.observe_locator_and_manifest(
        layout, expected_installation_id=expected_installation_id)
    facts = {
        "locator": locator_state,
        "manifest": manifest_state,
        "paths": inv.observe_paths(manifest),
        "fms": _proved_fms_state(manifest, flavour=flavour, runner=collaborators.runner),
        "storage": inv.observe_storage(manifest),
        "patchdir": _observe_patch_dir(manifest),
        "sandbox": _observe_sandbox(manifest),
        "sandrc": inv.observe_sandbox_rc(manifest),
        "supportdir": inv.observe_support_dir(manifest),
        "svcbind": _proved_service_binding(manifest, flavour=flavour,
                                           runner=collaborators.runner),
        "pki_registration": _provider_record_state(
            manifest.pki.registration_name if manifest else None,
            manifest.pki.public_fingerprint if manifest else None),
        "patch_slot": _provider_record_state(
            manifest.patch.folder_slot if manifest else None,
            manifest.patch.registered if manifest else None,
            manifest.patch.verified if manifest else None),
        "proxy_family": _proxy_record_state(manifest),
        "fixed_resources": inv.observe_fixed_resources(manifest),
        "account": (inv.ACCOUNT_OWNED
                    if inv.recorded_ownership(manifest, OWNERSHIP_KIND_SERVICE_ACCOUNT)
                    else inv.ACCOUNT_NOT_OWNED),
        "pending": _observe_pending(layout, manifest),
        "force": bool(force),
    }
    inv.validate_facts(facts)
    return facts, manifest


def _provider_record_state(*values) -> str:
    """Whether one provider published all of its removal authority, none, or a torn subset."""
    present = tuple(bool(value) for value in values)
    if present and all(present):
        return inv.PROVIDER_RECORDED
    if not any(present):
        return inv.PROVIDER_NOT_RECORDED
    return inv.PROVIDER_INCOMPLETE


def _proxy_record_state(manifest) -> str:
    policy = manifest.proxy_policy if manifest else None
    if not policy:
        return inv.PROVIDER_NOT_RECORDED
    recorded = False
    for entry in policy.values():
        has_location = bool(entry.config_location)
        has_fingerprint = bool(entry.config_fingerprint)
        # Discovery records WHERE an installed proxy would be configured even when CORPUSfm did
        # not publish anything there.  A settled no-op therefore legitimately has a location and
        # no fingerprint: the latter is authority over bytes we successfully applied, and there
        # are no such bytes to remove.  This is the ordinary fresh-install shape for an available
        # but inactive optional front (Windows Claris nginx beside active IIS).  Do not turn that
        # observation into deletion authority, and do not let it poison removal of a different,
        # actually-recorded front.
        if has_location and not has_fingerprint and entry.last_result == R.NO_CHANGE:
            continue
        if has_location != has_fingerprint:
            return inv.PROVIDER_INCOMPLETE
        recorded = recorded or (has_location and has_fingerprint)
    return inv.PROVIDER_RECORDED if recorded else inv.PROVIDER_NOT_RECORDED


def _proved_fms_state(manifest, *, flavour: str, runner=None) -> str:
    """The FMS condition, OBSERVED. There is nothing to reconcile a claim against any more.

    Every outcome is the box's: `absent` only on the two-part conjunction, `running` and
    `installed_stopped` from the fixed service's run state, and every disagreement or unreadable
    piece of evidence refuses by name rather than resolving to either answer.
    """
    if manifest is None:
        # No manifest, so no recorded root to observe — and `validate_relations` has a more specific
        # refusal for that, which this must not mask. `running` is returned because it is the value
        # that makes NOTHING disappear: absence is the word that retires work, and it is never
        # produced without evidence. The fact is unused on the one path that does not refuse (late
        # finalization, which re-enters `resume` before classification).
        return inv.FMS_RUNNING
    proved, detail = observe_fms_presence(manifest, flavour=flavour, runner=runner)
    if proved is None:
        reason = (FMS_PRESENCE_CONFLICTS if "disagree" in detail else FMS_PRESENCE_UNREADABLE)
        raise ResumeRefused(reason, f"FileMaker Server's presence could not be established: "
                                    f"{detail}")
    return proved


def _proved_service_binding(manifest, *, flavour: str, runner=None) -> str:
    """Whether the recorded services still bind, OBSERVED — never asserted.

    The observer is the executors' own five-part conjunction plus the platform's fixed-argv
    registration query, so the planner and the executor cannot disagree about what binds. Evidence
    that cannot be read refuses: a preserved service is not owed work, so it withholds nothing, and a
    run that preserved three services on unreadable evidence would go on to delete the tree beneath
    them.
    """
    from .service_binding import observe_service_binding

    state, detail = observe_service_binding(manifest, flavour=flavour, runner=runner)
    if state is None:
        raise ResumeRefused(
            SERVICE_BINDING_UNREADABLE,
            f"whether this installation's recorded services still bind could not be established: "
            f"{detail}")
    return state


def _observe_patch_dir(manifest) -> str:
    hosting = manifest.paths.patch_hosting_dir if manifest else None
    if not hosting:
        return inv.PATCHDIR_NOT_RECORDED
    try:
        content = list(Path(hosting).iterdir())
    except FileNotFoundError:
        return inv.PATCHDIR_ABSENT
    except OSError:
        # Unreadable is not empty, and *empty* is what permits the compartment to go.
        return inv.PATCHDIR_HAS_WORK
    if not content:
        return inv.PATCHDIR_EMPTY

    # The compartment is normally non-empty at planning time because the sandbox and its FMS RC
    # are removed by earlier typed operations.  Treat only those recorded top-level entries as
    # removable content; one unrecorded sibling keeps the historical preserve decision.  The
    # executor checks again after the owned children are gone and removes only a directory tree
    # containing directories—never a surviving file or link.
    root = Path(hosting)
    sandbox = Path(manifest.patch.sandbox_file) if manifest.patch.sandbox_file else None
    rc_roots = tuple(
        Path(entry.identifier)
        for entry in inv.recorded_ownership(manifest, OWNERSHIP_KIND_PATCH_SANDBOX_RC)
    )

    def beneath(path: Path, parent: Path) -> bool:
        try:
            path.relative_to(parent)
        except ValueError:
            return False
        return True

    stack = list(content)
    while stack:
        child = stack.pop()
        if sandbox is not None and child == sandbox:
            continue
        # The exact RC path owns its whole tree. Its ancestors inside the compartment are only FMS
        # scaffolding; walk those so a sibling hidden under RC_Data_FMS is still detected.
        if any(child == rc_root for rc_root in rc_roots):
            continue
        if any(beneath(rc_root, child) for rc_root in rc_roots):
            try:
                observed = child.lstat()
                if _stat.S_ISLNK(observed.st_mode) or not _stat.S_ISDIR(observed.st_mode):
                    return inv.PATCHDIR_HAS_WORK
                stack.extend(child.iterdir())
            except OSError:
                return inv.PATCHDIR_HAS_WORK
            continue
        return inv.PATCHDIR_HAS_WORK
    return inv.PATCHDIR_ONLY_RECORDED


def _observe_sandbox(manifest) -> str:
    recorded = manifest.patch.sandbox_file if manifest else None
    if not recorded:
        return inv.SANDBOX_NOT_RECORDED
    return inv.SANDBOX_PRESENT if Path(recorded).exists() else inv.SANDBOX_ABSENT


def _observe_pending(layout, manifest) -> str:
    """`none` · `matching` · `foreign`, and an unreadable record REFUSES rather than reading absent."""
    try:
        record = pending.read(layout)
    except pending.PendingRecordRefused as exc:
        raise ResumeRefused(PENDING_UNREADABLE, str(exc)) from exc
    if record is None:
        return inv.PENDING_NONE
    if manifest is not None and record.installation_id.lower() != manifest.installation_id.lower():
        return inv.PENDING_FOREIGN
    return inv.PENDING_MATCHING


# ── the two entry points ──────────────────────────────────────────────────────


def preview(layout, *, collaborators: Collaborators, installation_id: str,
            force: bool = False) -> dict:
    """Return the uninstall plan without publishing or executing anything.

    A new uninstall is derived through the exact observation/classification path ``start`` uses.
    An interrupted uninstall is projected from its durable pending record instead; it is never
    replanned against a machine which it has already changed.  The result intentionally contains
    typed operations rather than prose-only promises, so launchers can show concrete paths and
    provider registrations without becoming a second planner.
    """
    attempt_payload = _attempt_preview(layout, collaborators=collaborators,
                                       installation_id=installation_id, force=force)
    if attempt_payload is not None:
        return attempt_payload
    existing = _read_pending(layout)
    if existing is not None:
        if existing.installation_id.lower() != str(installation_id).lower():
            raise ResumeRefused(
                INSTALLATION_MISMATCH,
                f"the request names installation {installation_id} and the pending record at "
                f"{pending.pending_path(layout)} belongs to {existing.installation_id}")
        operations = tuple(existing.remaining)
        return _preview_payload(
            mode="resume", installation_id=existing.installation_id, operations=operations,
            fms_state="recorded_at_start", retained=(), force=force)

    facts, manifest = observe(layout, collaborators=collaborators, force=force,
                              expected_installation_id=installation_id)
    if manifest is not None and manifest.installation_id.lower() != str(installation_id).lower():
        raise ResumeRefused(
            INSTALLATION_MISMATCH,
            f"the request names installation {installation_id} and the manifest names "
            f"{manifest.installation_id}")
    try:
        up.validate_relations(facts)
    except up.Refused as refusal:
        raise ResumeRefused(
            refusal.reason,
            f"the uninstall plan refused before anything was written: {refusal.reason}") from refusal
    decisions = up.classify(facts)
    operations = pending.remaining_from_plan(manifest, decisions, flavour=_flavour_of(layout))
    retained = tuple({"resource": name, "decision": decision.decision,
                      "because": decision.because}
                     for name, decision in sorted(decisions.items())
                     if decision.decision != up.REMOVE
                     and decision.decision != up.DEREGISTER_ONLY)
    payload = _preview_payload(
        mode="start", installation_id=manifest.installation_id, operations=operations,
        fms_state=facts["fms"], retained=retained, force=force)
    if _flavour_of(layout) == POSIX:
        import posixpath
        fmsadmin_path = posixpath.join(manifest.paths.fms_root, "Database Server", "bin",
                                       "fmsadmin")
    else:
        import ntpath
        fmsadmin_path = ntpath.join(manifest.paths.fms_root, "fmsadmin.exe")
    payload["locations"] = {
        "fms_root": manifest.paths.fms_root,
        "fmsadmin": fmsadmin_path,
        "install_dir": manifest.paths.install_dir,
        "patch_hosting_dir": manifest.paths.patch_hosting_dir,
    }
    return payload


def _preview_payload(*, mode: str, installation_id: str, operations: tuple,
                     fms_state: str, retained: tuple, force: bool) -> dict:
    """One secret-free wire projection shared by fresh and resumed plans."""
    reasons = []
    for operation in operations:
        if operation.tag == pending.OP_PKI:
            reasons.append("verify the recorded PKI registration is absent after deregistration")
        elif operation.tag == pending.OP_PROXY and operation.flavour == POSIX:
            reasons.append("restart FileMaker Server after removing its recorded proxy routing")
    reasons = tuple(dict.fromkeys(reasons))
    required_now = bool(reasons) and fms_state in (inv.FMS_RUNNING, "recorded_at_start")
    return {
        "result": "ready",
        "reason": "",
        "detail": ("an interrupted uninstall will resume from its durable record"
                   if mode == "resume" else
                   "the uninstall plan was derived without changing the installation"),
        "mode": mode,
        "installation_id": installation_id,
        "force": bool(force),
        "fms_state": fms_state,
        "fms_admin_login_required": required_now,
        "fms_admin_login_deferred": bool(reasons) and not required_now,
        "fms_admin_login_reasons": list(reasons),
        "operations": [operation.to_dict() for operation in operations],
        "retained": list(retained),
    }


def start(layout, *, lock, collaborators: Collaborators, installation_id: str,
          force: bool = False, progress: Progress | None = None) -> Report:
    """A FRESH uninstall: observe, plan, publish, open the journal, execute.

    **The operation id is generated here.** A caller that could choose it could adopt somebody
    else's record, and the whole point of the pending record is that it belongs to exactly one
    operation.

    Order, and none of it is arrangeable: this installation's two known checkpointed storage states
    may be rolled back through storage's own operation-bound abort; every other unresolved journal
    refuses; a resolved prior record is discarded; the uninstall record is published; its journal
    is opened; and only then does uninstall destruction begin.
    """
    _authority(layout, lock, "starting an uninstall")
    progress = progress if progress is not None else Progress()
    routed = _route_attempt(layout, lock=lock, collaborators=collaborators,
                            installation_id=installation_id, force=force, progress=progress)
    if routed is not None:
        return routed
    # **The flavour is DERIVED, never accepted.** A caller-supplied one that disagreed with the
    # layout published a record `_assert_platform` refuses for ever: `start` would then say
    # `PENDING_ALREADY_EXISTS` and `resume` would refuse, permanently, with no way out.
    flavour = _flavour_of(layout)
    journal = Journal(layout)

    existing = _read_pending(layout)
    if existing is not None:
        raise ResumeRefused(
            PENDING_ALREADY_EXISTS,
            f"a pending uninstall record for operation {existing.operation_id} is already at "
            f"{pending.pending_path(layout)}; it is resumed, never started over")
    prior_recovery = _recover_matching_storage_operation(
        layout, journal, lock, installation_id=installation_id)
    if prior_recovery is not None:
        if prior_recovery.result != R.ROLLED_BACK:
            finding = prior_recovery.findings[0] if prior_recovery.findings else None
            return Report(
                result=prior_recovery.result,
                operation_id=prior_recovery.operation_id,
                installation_id=installation_id,
                reason=getattr(finding, "code", "storage_recovery_refused"),
                detail=prior_recovery.next_action,
                observations=("the unfinished storage operation was retained",),
            )
    _require_journal_clear(journal, lock)

    # **THE INSTALLATION IDENTITY, load-bearing.** The caller says which installation it means, and
    # the locator is read against it: a locator naming another installation refuses by name before
    # anything is classified, which is `LOCATOR_ELSEWHERE` and is the only guard against an
    # uninstall aimed at the wrong installation on a box that has met two.
    facts, manifest = observe(layout, collaborators=collaborators, force=force,
                              expected_installation_id=installation_id)
    if manifest is not None and manifest.installation_id.lower() != str(installation_id).lower():
        raise ResumeRefused(
            INSTALLATION_MISMATCH,
            f"the request names installation {installation_id} and the manifest names "
            f"{manifest.installation_id}")
    if up.is_late_finalization(facts):
        # The locator is already gone and a matching record is still here: the ordinary tail of a
        # successful uninstall, reached from a fresh invocation. It finalizes; it does not re-plan.
        return resume(layout, lock=lock, collaborators=collaborators,
                      installation_id=installation_id, force=force, progress=progress)
    try:
        up.validate_relations(facts)
    except up.Refused as refusal:
        return Report(result=R.FAILED_BEFORE_CHANGE, reason=refusal.reason,
                      detail=f"the uninstall refused before anything was written: {refusal.reason}")

    decisions = up.classify(facts)
    remaining = pending.remaining_from_plan(manifest, decisions, flavour=flavour)
    operation_id = str(uuid.uuid4())
    record = pending.PendingRecord(
        operation_id=operation_id, installation_id=manifest.installation_id,
        manifest_generation=manifest.generation, remaining=remaining,
        created_utc=utc_now_iso(), updated_utc=utc_now_iso()).validated()

    if not record.remaining:
        # Nothing is owed. The tail still runs — the locator and the record are what remain of an
        # installation whose resources are all already gone.
        pending.publish(layout, record, lock=lock)
        progress.published = True
        journal.begin(lock=lock, operation_id=record.operation_id,
                      installation_id=record.installation_id, mode=UNINSTALL_MODE,
                      plan_digest=_plan_digest(record))
        return _finalize(layout, lock=lock, record=record, journal=journal,
                         executed=(), retained=(), skipped=())

    # THE ORDER THE CRASH CONTRACT RESTS ON: the record first, the journal second, destruction
    # third. A crash between the first two leaves a matching record and no journal, which `resume`
    # opens and continues.
    published = pending.publish(layout, record, lock=lock)
    progress.published = True
    journal.begin(lock=lock, operation_id=published.operation_id,
                  installation_id=published.installation_id, mode=UNINSTALL_MODE,
                  plan_digest=_plan_digest(published))
    return _execute(layout, lock=lock, record=published, journal=journal,
                    collaborators=collaborators, force=force, progress=progress)


def resume(layout, *, lock, collaborators: Collaborators, installation_id: str,
           force: bool = False, progress: Progress | None = None) -> Report:
    """Continue from the record, and from nothing else.

    The pending record is read first; the journal is JOINED to it, never consulted for what to do.
    An absent journal is opened for the matching operation — that is the crash between publication
    and `begin`, and it is an ordinary state rather than damage. A foreign, unreadable or
    wrong-mode journal refuses without mutating anything.
    """
    _authority(layout, lock, "resuming an uninstall")
    progress = progress if progress is not None else Progress()
    routed = _route_attempt(layout, lock=lock, collaborators=collaborators,
                            installation_id=installation_id, force=force, progress=progress)
    if routed is not None:
        return routed
    record = _read_pending(layout)
    if record is not None and record.installation_id.lower() != str(installation_id).lower():
        # **Before the journal is joined and before anything is touched.** A resume aimed at another
        # installation's record must not open a journal for it, contact anything, or run a
        # subprocess — the refusal happens on the identity alone.
        raise ResumeRefused(
            INSTALLATION_MISMATCH,
            f"the request names installation {installation_id} and the pending record at "
            f"{pending.pending_path(layout)} belongs to {record.installation_id}")
    if record is None:
        # Already finished, or never started. Both are *nothing to do*, and reporting an error for
        # the tail of a successful uninstall is how idempotence gets lost.
        return Report(result=R.NO_CHANGE, reason=NO_PENDING_RECORD,
                      detail=f"there is no pending uninstall record at "
                             f"{pending.pending_path(layout)}")
    journal = Journal(layout)
    state = _join_journal(journal, record, lock)

    if state == JOURNAL_RESOLVED:
        if record.remaining:
            raise ResumeRefused(
                JOURNAL_RESOLVED_WITH_WORK,
                f"the journal reports operation {record.operation_id} resolved while the pending "
                f"record still owes {[op.resource for op in record.remaining]}; two authorities "
                "disagree and neither is acted on")
        return _finalize(layout, lock=lock, record=record, journal=journal,
                         executed=(), retained=(), skipped=())

    if not _locator_present(layout) and record.remaining:
        raise ResumeRefused(
            LOCATOR_GONE_WITH_WORK,
            f"the locator is gone and the record still owes "
            f"{[op.resource for op in record.remaining]}; a record without a locator is accepted "
            "only as the late finalization of an uninstall that had finished its work")
    if not record.remaining:
        return _finalize(layout, lock=lock, record=record, journal=journal,
                         executed=(), retained=(), skipped=())
    return _execute(layout, lock=lock, record=record, journal=journal,
                    collaborators=collaborators, force=force, progress=progress)


# ── the install-attempt discard (packet 1398) ────────────────────────────────
#
# Reached ONLY when the protected attempt container exists. An installation that never had one takes
# every path above exactly as before. The discard reuses the typed operations, canonical order,
# checkpoints and executors; what it adds is where its authority lives (the protected container) and
# that every dispatch re-proves the pending operations against the frozen plan held there.


def attempt_protection() -> "ia.Protection":
    """Production protection: root on POSIX, administrator/SYSTEM on Windows. A suite rooted in a
    temporary directory replaces this function, as it redirects `privilege.is_elevated`."""
    return ia.Protection()


def _attempt_refused(exc) -> ResumeRefused:
    return ResumeRefused(exc.reason, exc.detail)


def _validate_attempt(authority, record) -> None:
    try:
        authority.validate(record)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc


def _classify_attempt(layout, protection):
    try:
        return ia.classify(layout, protection)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc


def attempt_finishes_outside_lock(layout) -> bool:
    """Whether an invocation must finish an attempt WITHOUT taking the lifecycle lock.

    Terminal retirement removes the directory that holds the lock, so the steps after it cannot take
    the lock again without recreating what was just retired.
    """
    try:
        return ia.classify(layout, attempt_protection()).kind in ia.OUTSIDE_LOCK
    except ia.AttemptRefused:
        return False


def _route_attempt(layout, *, lock, collaborators, installation_id, force, progress):
    protection = attempt_protection()
    state = _classify_attempt(layout, protection)
    paths = ia.attempt_paths(layout)
    if state.kind == ia.STATE_NONE:
        return None
    if state.kind == ia.STATE_LEFTOVER_EMPTY:
        ia.remove_empty_container(paths, protection)
        return None
    if state.kind == ia.STATE_STALE_COMPLETE:
        if state.record.installation_id != str(installation_id).lower():
            raise ResumeRefused(ia.REFUSE_BINDING_MISMATCH,
                                "the stale completion record belongs to another installation")
        ia.unlink_protected(paths, paths.record, protection)
        ia.remove_empty_container(paths, protection)
        return None
    if state.kind in ia.OUTSIDE_LOCK:
        raise ResumeRefused(ia.REFUSE_PHASE_INVALID,
                            f"the install attempt is at {state.kind}; it finishes outside the "
                            "lifecycle lock, so run the uninstall again")
    if force:
        raise ResumeRefused(ia.REFUSE_FORCE,
                            "a discard executes its frozen plan in order and stops at the first "
                            "refusal; --force would reorder it and is not accepted")
    try:
        ia.bind(state, layout, installation_id=installation_id)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc
    if state.kind == ia.STATE_DISCARDING:
        return _continue_attempt(layout, lock=lock, record=state.record,
                                 collaborators=collaborators, progress=progress,
                                 protection=protection)
    return _start_attempt(layout, lock=lock, state=state, collaborators=collaborators,
                          progress=progress, protection=protection)


def _selection_order(operations) -> tuple:
    """The operations in the order `_execute` will actually take them.

    **The frozen plan must be in THIS order, not merely a canonical one** (measured defect, caught by
    a mutation control). `canonical_order` may place a terminal-footprint operation ahead of an
    ordinary one when no clean is owed, while `_next_operation` always defers the footprint. A plan
    frozen canonically then fails its own head-of-suffix check on a legitimate discard, and the box
    stays stranded with nothing removed. Replaying the selector over the full set, with no refusals,
    yields an order that satisfies every `RESOURCE_FOLLOWS` edge and whose every suffix the selector
    takes head-first.
    """
    probe = dataclasses.make_dataclass("_Probe", [("remaining", tuple)])(tuple(operations))
    ordered, executed = [], set()
    while True:
        candidate = _next_operation(probe, executed=executed, blocked=set())
        if candidate is None:
            break
        ordered.append(candidate)
        executed.add(candidate.resource)
    if len(ordered) != len(operations):
        raise ResumeRefused(ia.REFUSE_PLAN_MISMATCH,
                            "the discard plan has no order in which every operation can run")
    return tuple(ordered)


def _plan_attempt(layout, *, state, collaborators):
    """`(refusal, operations, manifest_generation, decisions)` — shared by the discard and preview."""
    record = state.record
    flavour = _flavour_of(layout)
    if state.kind == ia.STATE_POST_FOUNDATION:
        facts, manifest = observe(layout, collaborators=collaborators, force=False,
                                  expected_installation_id=record.installation_id)
        try:
            up.validate_relations(facts)
        except up.Refused as refusal:
            return refusal, (), None, {}
        decisions = ia.attempt_filter(record, up.classify(facts), manifest)
        return (None, _selection_order(pending.remaining_from_plan(manifest, decisions,
                                                                  flavour=flavour)),
                manifest.generation, decisions)
    view, decisions = ia.attempt_plan(record, layout)
    return (None, _selection_order(pending.remaining_from_plan(view, decisions, flavour=flavour)),
            None, decisions)


def _abandon_foundation_journal(layout, *, lock, record, protection):
    """Write-ahead: record the abandonment, resolve and discard the bound foundation journal, record
    the result. No locator is ever written (ruling 3)."""
    journal = Journal(layout)
    current = journal.read()
    target = str(journal.path)
    entries = [e for e in record.ledger if e.kind == "journal" and e.intent == "abandon_foundation"]
    try:
        if current is not None:
            if not entries or entries[-1].state != ia.STATE_INTENDED:
                entry = ia.LedgerEntry(
                    seq=len(record.ledger) + 1, target=target, kind="journal",
                    intent="abandon_foundation",
                    prior={"mode": current.mode, "subsystem": current.current_subsystem,
                           "state": "open", "installation_id": current.installation_id},
                    state=ia.STATE_INTENDED, post=None, intent_utc=utc_now_iso(), result_utc=None)
                record = ia.write_record(
                    layout, dataclasses.replace(record, ledger=record.ledger + (entry,)),
                    protection)
            if current.state != JOURNAL_RESOLVED:
                journal.resolve(lock=lock, result=R.ROLLED_BACK)
            journal.discard(lock=lock)
        entries = [e for e in record.ledger
                   if e.kind == "journal" and e.intent == "abandon_foundation"]
        if entries and entries[-1].state == ia.STATE_INTENDED:
            done = dataclasses.replace(entries[-1], state=ia.STATE_DONE,
                                       post={"state": "discarded"}, result_utc=utc_now_iso())
            ledger = tuple(done if e.seq == done.seq else e for e in record.ledger)
            record = ia.write_record(layout, dataclasses.replace(record, ledger=ledger), protection)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc
    return record


def _start_attempt(layout, *, lock, state, collaborators, progress, protection):
    record = state.record
    if state.kind == ia.STATE_FOUNDATION_WINDOW:
        record = _abandon_foundation_journal(layout, lock=lock, record=record,
                                             protection=protection)
        state = ia.AttemptState(ia.STATE_FOUNDATION_WINDOW, record)
    if state.kind == ia.STATE_POST_FOUNDATION:
        journal = Journal(layout)
        prior_recovery = _recover_matching_storage_operation(
            layout, journal, lock, installation_id=record.installation_id)
        if prior_recovery is not None and prior_recovery.result != R.ROLLED_BACK:
            finding = prior_recovery.findings[0] if prior_recovery.findings else None
            return Report(result=prior_recovery.result,
                          operation_id=prior_recovery.operation_id,
                          installation_id=record.installation_id,
                          reason=getattr(finding, "code", "storage_recovery_refused"),
                          detail=prior_recovery.next_action,
                          observations=("the unfinished storage operation was retained",))
        _require_journal_clear(journal, lock)
    refusal, operations, generation, _decisions = _plan_attempt(
        layout, state=state, collaborators=collaborators)
    if refusal is not None:
        return Report(result=R.FAILED_BEFORE_CHANGE, reason=refusal.reason,
                      installation_id=record.installation_id,
                      detail=f"the discard refused before its plan was frozen: {refusal.reason}")
    try:
        frozen = ia.freeze_plan(record, operation_id=str(uuid.uuid4()),
                                manifest_generation=generation, operations=operations)
        record = ia.write_record(layout, frozen, protection)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc
    progress.published = True
    return _continue_attempt(layout, lock=lock, record=record, collaborators=collaborators,
                             progress=progress, protection=protection)


def _continue_attempt(layout, *, lock, record, collaborators, progress, protection):
    authority = ia.PendingAuthority(layout, record.attempt_id, record.installation_id, protection)
    journal = Journal(layout, path=authority.journal_path)
    plan = record.discard
    current = _read_pending(layout, authority)
    if current is None:
        # The crash between freezing the plan and publishing the pending record.
        current = pending.PendingRecord(
            operation_id=plan.operation_id, installation_id=record.installation_id,
            manifest_generation=plan.manifest_generation,
            remaining=tuple(pending.parse_operation(op) for op in plan.operations),
            created_utc=utc_now_iso(), updated_utc=utc_now_iso(),
            source=pending.SOURCE_INSTALL_ATTEMPT, attempt_id=record.attempt_id).validated()
        _validate_attempt(authority, current)
        try:
            current = pending.publish(layout, current, lock=lock, attempt=authority)
        except pending.PendingRecordRefused as exc:
            raise ResumeRefused(PENDING_UNREADABLE, str(exc)) from exc
        progress.published = True
    _validate_attempt(authority, current)
    state_word = _join_journal(journal, current, lock)
    if state_word == JOURNAL_RESOLVED and current.remaining:
        raise ResumeRefused(
            JOURNAL_RESOLVED_WITH_WORK,
            f"the container journal is resolved while the discard still owes "
            f"{[op.resource for op in current.remaining]}")
    if not current.remaining:
        return _finalize_attempt(layout, lock=lock, journal=journal, authority=authority,
                                 executed=(), observations=())
    return _execute(layout, lock=lock, record=current, journal=journal,
                    collaborators=collaborators, force=False, progress=progress,
                    authority=authority)


def _finalize_attempt(layout, *, lock, journal, authority, executed, observations) -> Report:
    """§6.6 steps 1, 2 and 3a — under the lock. 3b onward runs in `finish_attempt`, outside it."""
    protection = authority.protection
    on_disk = _read_pending(layout, authority)
    if on_disk is None or on_disk.remaining:
        raise ResumeRefused(JOURNAL_RESOLVED_WITH_WORK,
                            "terminal retirement requires an empty install-attempt pending record")
    _validate_attempt(authority, on_disk)
    current = journal.read()
    if current is not None and current.state != JOURNAL_RESOLVED:
        journal.resolve(lock=lock, result=R.COMPLETED)
    adapter = locator_for(layout)
    if adapter.exists():
        adapter.remove(lock=lock)
    try:
        record = ia.read_record(layout, protection)
        if record is None:
            raise ia.AttemptRefused(ia.REFUSE_PHASE_INVALID,
                                    "the attempt record vanished before terminal retirement")
        if record.phase == ia.PHASE_DISCARDING:
            candidate = dataclasses.replace(record, phase=ia.PHASE_TERMINAL_PENDING)
            ia.check_phase(candidate, pending=on_disk, journal=journal.read(),
                           locator_present=_locator_present(layout))
            ia.write_record(layout, candidate, protection)
    except ia.AttemptRefused as exc:
        raise _attempt_refused(exc) from exc
    return Report(result=R.COMPLETED, operation_id=on_disk.operation_id,
                  installation_id=on_disk.installation_id, finalized=True,
                  detail=("every operation of the frozen discard plan is complete; terminal "
                          "retirement follows outside the lifecycle lock"),
                  executed=tuple(executed), observations=tuple(observations),
                  attempt_terminal=True)


def _require_attempt_identity(record, installation_id) -> None:
    if record.installation_id != str(installation_id).lower():
        raise ResumeRefused(ia.REFUSE_BINDING_MISMATCH,
                            f"the request names {installation_id} and the attempt is "
                            f"{record.installation_id}")


def finish_attempt(layout, *, installation_id: str, os_layout=None, windows_authority=None,
                   posix_service_uid=None, retire=None) -> Report:
    """§6.6 steps 3b, 3c, 4 and 5, OUTSIDE the lifecycle lock.

    Retirement runs once per `terminal_pending` and advances to `terminal_done`; after that it is
    never run again. The record is unlinked, and only then the empty pending record, the resolved
    journal and the container go — bookkeeping that authorizes no deletion of anything else.
    """
    from .os_layout import os_layout_for_lifecycle
    from .uninstall_terminal import retire_attempt

    protection = attempt_protection()
    paths = ia.attempt_paths(layout)
    state = _classify_attempt(layout, protection)
    observations = []
    if state.kind == ia.STATE_TERMINAL_PENDING:
        _require_attempt_identity(state.record, installation_id)
        osl = os_layout if os_layout is not None else os_layout_for_lifecycle(layout)
        plan = ia.terminal_plan(state.record, osl)
        cleaner = retire if retire is not None else retire_attempt
        retired = cleaner(layout, osl, plan=plan, windows_authority=windows_authority,
                          posix_service_uid=posix_service_uid)
        observations.extend(f"retired {root}" for root in retired)
        try:
            ia.write_record(layout, dataclasses.replace(state.record,
                                                        phase=ia.PHASE_TERMINAL_DONE), protection)
        except ia.AttemptRefused as exc:
            raise _attempt_refused(exc) from exc
        state = _classify_attempt(layout, protection)
    if state.kind == ia.STATE_TERMINAL_DONE:
        _require_attempt_identity(state.record, installation_id)
        ia.unlink_protected(paths, paths.record, protection)
        state = _classify_attempt(layout, protection)
    if state.kind == ia.STATE_BOOKKEEPING:
        journal_record = state.journal
        if journal_record.installation_id != str(installation_id).lower():
            raise ResumeRefused(ia.REFUSE_BINDING_MISMATCH,
                                "the leftover discard journal belongs to another installation")
        ia.unlink_protected(paths, paths.pending, protection)
        ia.unlink_protected(paths, paths.journal, protection)
        ia.remove_empty_container(paths, protection)
        return Report(result=R.COMPLETED, operation_id=journal_record.operation_id,
                      installation_id=journal_record.installation_id, finalized=True,
                      detail=("the incomplete install attempt was discarded; logs were preserved; "
                              "run the installer again to start a fresh installation"),
                      observations=tuple(observations))
    raise ResumeRefused(ia.REFUSE_PHASE_INVALID,
                        f"no install attempt is finishing here (state {state.kind})")


def _attempt_preview(layout, *, collaborators, installation_id, force):
    protection = attempt_protection()
    state = _classify_attempt(layout, protection)
    if state.kind in (ia.STATE_NONE, ia.STATE_LEFTOVER_EMPTY, ia.STATE_STALE_COMPLETE):
        return None
    record = state.record
    if record is not None:
        _require_attempt_identity(record, installation_id)
    if state.kind in (ia.STATE_DISCARDING, ia.STATE_TERMINAL_PENDING, ia.STATE_TERMINAL_DONE,
                      ia.STATE_BOOKKEEPING):
        if state.pending is not None:
            operations = tuple(state.pending.remaining)
        elif record is not None and record.discard is not None:
            operations = tuple(pending.parse_operation(op) for op in record.discard.operations)
        else:
            operations = ()
        payload = _preview_payload(mode="attempt_resume", installation_id=str(installation_id),
                                   operations=operations, fms_state="recorded_at_start",
                                   retained=(), force=force)
    else:
        try:
            ia.bind(state, layout, installation_id=installation_id)
        except ia.AttemptRefused as exc:
            raise _attempt_refused(exc) from exc
        refusal, operations, _generation, decisions = _plan_attempt(
            layout, state=state, collaborators=collaborators)
        if refusal is not None:
            raise ResumeRefused(refusal.reason,
                                f"the discard plan refused before anything was written: "
                                f"{refusal.reason}")
        retained = tuple({"resource": name, "decision": decision.decision,
                          "because": decision.because}
                         for name, decision in sorted(decisions.items())
                         if decision.decision not in (up.REMOVE, up.DEREGISTER_ONLY))
        payload = _preview_payload(mode="attempt_start", installation_id=record.installation_id,
                                   operations=operations, fms_state="recorded_at_start",
                                   retained=retained, force=force)
    payload["attempt"] = {"state": state.kind,
                          "attempt_id": None if record is None else record.attempt_id,
                          "phase": None if record is None else record.phase}
    return payload


# ── authority helpers ─────────────────────────────────────────────────────────


def _authority(layout, lock, action: str):
    held = require_lock(lock, action)
    if held.layout != layout:
        raise LockNotHeld(
            f"{action} requires the lifecycle lock for {layout.lock_file}, not "
            f"{held.layout.lock_file}")
    return held


def _flavour_of(layout) -> str:
    """Windows keeps its locator in the registry; POSIX keeps it in a file. That is the difference
    the layout already encodes, so the flavour is read from it rather than from `os.name` — a test
    driving a Windows layout is driving a Windows uninstall."""
    return POSIX if layout.locator_file is not None else WINDOWS


def _read_pending(layout, authority=None):
    try:
        # The ordinary call is left exactly as it was; only an install attempt names its authority.
        return pending.read(layout) if authority is None else pending.read(layout, attempt=authority)
    except pending.PendingRecordRefused as exc:
        raise ResumeRefused(PENDING_UNREADABLE, str(exc)) from exc


def _locator_present(layout) -> bool:
    """`exists`, not `read`. The question is whether the locator is still there, and a locator that
    is present but unreadable is still present — the planner has its own named refusal for that, and
    answering *absent* here would let a record finalize over evidence nobody could read."""
    try:
        return locator_for(layout).exists()
    except OSError:
        return True


def _require_journal_clear(journal: Journal, lock) -> None:
    """A fresh uninstall over a prior journal: only a RESOLVED one may be discarded."""
    try:
        record = journal.read()
    except RecordInvalid as exc:
        raise ResumeRefused(JOURNAL_UNREADABLE, str(exc)) from exc
    if record is None:
        return
    if record.state != JOURNAL_RESOLVED:
        raise ResumeRefused(
            JOURNAL_UNRESOLVED,
            f"lifecycle operation {record.operation_id} ({record.mode}) is {record.state!r}; it is "
            "resumed or resolved before another operation begins")
    journal.discard(lock=lock)


def _recover_matching_storage_operation(layout, journal: Journal, lock, *, installation_id: str):
    """Undo this installation's unfinished storage work before beginning its uninstall.

    An ordinary uninstall is already authority to remove this installation's product data.  A
    storage bootstrap that stopped after placing that data must therefore be joined through its
    own durable operation id, not turned into an operator-only lifecycle detour.  The exception is
    deliberately narrow: every non-storage journal, every foreign installation and every unreadable
    record retains the historical refusal in ``_require_journal_clear``.

    Returns the storage report when a recovery route was taken, otherwise ``None``.  A successful
    abort must have resolved the same journal; only then may the caller retire it and start the
    independently recorded uninstall operation.
    """
    try:
        record = journal.read()
    except RecordInvalid as exc:
        raise ResumeRefused(JOURNAL_UNREADABLE, str(exc)) from exc
    if record is None:
        return None
    if record.installation_id.lower() != str(installation_id).lower():
        return None
    if record.current_subsystem not in _RECOVERABLE_STORAGE_CHECKPOINTS:
        return None

    # The journal is one operation's evidence, not proof that it belongs to the installation now
    # published on this box.  Establish that identity from the protected locator+manifest before
    # the recovery verb is allowed to remove anything.
    locator_state, manifest_state, manifest = inv.observe_locator_and_manifest(
        layout, expected_installation_id=installation_id)
    if (locator_state != inv.LOCATOR_VALID or manifest_state != inv.MANIFEST_VALID
            or manifest is None
            or manifest.installation_id.lower() != str(installation_id).lower()):
        raise ResumeRefused(
            INSTALLATION_MISMATCH,
            "the unfinished storage operation names an installation that the current protected "
            "locator and manifest do not both publish; nothing was recovered")

    # Local import keeps the uninstall planner independent of storage at import time.  The recovery
    # verb accepts no path or host: both come from the operation record it proves against this
    # journal and this installation identity.
    from . import storage_identity_ops

    if record.state == JOURNAL_RESOLVED:
        from . import storage_identity_recovery

        try:
            operation = storage_identity_recovery.read(
                storage_identity_ops.recovery_secrets_dir(layout))
        except Exception as exc:  # noqa: BLE001
            raise ResumeRefused(JOURNAL_UNREADABLE, str(exc)) from exc
        if operation is None:
            return None
        if (operation.operation_id != record.operation_id
                or operation.installation_id.lower() != record.installation_id.lower()):
            return None

    report = storage_identity_ops.abort(
        record.operation_id, record.installation_id, "uninstall",
        lock=lock, journal=journal, lifecycle_layout=layout)
    if report.result not in (R.ROLLED_BACK, R.NO_CHANGE):
        return report

    try:
        closed = journal.read()
    except RecordInvalid as exc:
        raise ResumeRefused(JOURNAL_UNREADABLE, str(exc)) from exc
    if (closed is None or closed.operation_id != record.operation_id
            or closed.installation_id.lower() != record.installation_id.lower()
            or closed.state != JOURNAL_RESOLVED):
        return storage_identity_ops.StorageReport(
            result=R.MANUAL_ACTION_REQUIRED,
            operation_id=record.operation_id,
            next_action=("The unfinished storage work was undone, but its lifecycle journal did "
                         "not resolve. The journal was retained and the uninstall did not begin."),
        )
    journal.discard(lock=lock)
    return report


def _join_journal(journal: Journal, record, lock) -> str | None:
    """Join the journal to THIS record, or refuse. Returns its state, opening one if there is none."""
    try:
        existing = journal.read()
    except RecordInvalid as exc:
        raise ResumeRefused(JOURNAL_UNREADABLE, str(exc)) from exc
    if existing is None:
        # The crash between `publish` and `begin`. The record says which operation this is, so the
        # journal is opened for it — no re-planning, and no new identity.
        journal.begin(lock=lock, operation_id=record.operation_id,
                      installation_id=record.installation_id, mode=UNINSTALL_MODE,
                      plan_digest=_plan_digest(record))
        return None
    if (existing.installation_id != record.installation_id
            or existing.operation_id != record.operation_id):
        raise ResumeRefused(
            JOURNAL_FOREIGN,
            f"the journal describes operation {existing.operation_id} of installation "
            f"{existing.installation_id} and the pending record describes {record.operation_id} of "
            f"{record.installation_id}")
    if existing.mode != UNINSTALL_MODE:
        raise ResumeRefused(
            JOURNAL_WRONG_MODE,
            f"the journal describes a {existing.mode!r} operation; an uninstall does not join it")
    return existing.state


def _plan_digest(record) -> str:
    """A stable fingerprint of the remaining set AND its order, so a journal joined to a record can
    be seen to describe that record. Never the record's contents — the journal holds references."""
    import hashlib

    material = "\n".join(f"{op.tag}:{op.resource}" for op in record.remaining)
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


# ── execution ─────────────────────────────────────────────────────────────────


def _executor_for(layout, lock, authority=None):
    """THE construction path, and the platform is decided by the layout rather than by a caller."""
    if _flavour_of(layout) == POSIX:
        from .uninstall_exec_posix import PosixExecutor

        return (PosixExecutor.for_installation(layout, lock=lock) if authority is None
                else PosixExecutor.for_installation(layout, lock=lock, attempt=authority))
    from .uninstall_exec_windows import WindowsExecutor

    return (WindowsExecutor.for_installation(layout, lock=lock) if authority is None
            else WindowsExecutor.for_installation(layout, lock=lock, attempt=authority))


def _dispatch(executor, operation, collaborators: Collaborators, *, flavour: str):
    """By TAG, to the one handler the executor names for it, with only the collaborators it needs.

    The credential provider is handed to the one operation that can need it, and that operation
    decides — from the observed fronts and the real plan — whether to call it. So an uninstall that
    never reaches a proxy edit never asks for a password, and one whose front publishes without
    activating never asks either.
    """
    def missing(what: str, *names: str):
        why = "; ".join(filter(None, (collaborators.why_unavailable(n) for n in names)))
        return _Missing(operation, what, why=why)

    tag = operation.tag
    method = getattr(executor, executor.HANDLERS[tag])
    if tag == pending.OP_EXACT_PATH:
        return method(operation.resource)
    if tag == pending.OP_MANAGED_UNIT or tag == pending.OP_ACCOUNT:
        # `runner=None` is CORRECT and is not a missing collaborator: it selects the package's own
        # fixed-argv subprocess execution, which is the real one.
        return method(operation.resource, runner=collaborators.runner)
    if tag == pending.OP_STORAGE:
        # **A genuinely absent FileMaker Server is never contacted, and never even connected to.**
        # §G: no credential is requested and no client is built — the executor establishes the
        # unhosted proof from the recorded root instead, which is the second admissible one.
        #
        # **Observed from THIS OPERATION's own recorded root** (stage 6). It used to read a state the
        # caller supplied, which a resume could not have derived anyway: `resume` never observes, and
        # the ordinary tail has no manifest to observe from. `StorageOperation.fms_root` is in the
        # record precisely so this question can be asked without one — the same exact-root and
        # fixed-service conjunction the fresh path proves, sourced from the durable record.
        #
        # **Three answers, and `None` is its own** (blind-review finding F1). A proved absence takes
        # no collaborator — the executor establishes the unhosted proof from the recorded root, which
        # is the second admissible one. A proved running or stopped server takes the adapter.
        #
        # **Evidence that establishes NEITHER retains the operation here.** `proved is None` is four
        # conditions, and one of them is the root and the fixed service DISAGREEING — which `start`
        # refuses by name, on the stated ground that *every reading of this is a guess, and the one
        # guess that would matter is the one that abandons work*. Passing `None` down would hand that
        # same disagreement to `run_storage`, which re-observes the ROOT ALONE: on an absent root it
        # would accept one fact as the whole proof, checkpoint, and report a completed removal on
        # evidence the observer had just refused to conclude from. A resume never calls `observe()`,
        # so that was reachable on every resumed run. It stays owed instead.
        proved, detail = _fms_presence_from_recorded_root(
            operation.fms_root, flavour=flavour, runner=collaborators.runner)
        if proved is None:
            return _DriverOutcome(
                resource=operation.resource, operation=tag, reason=FMS_PRESENCE_UNREADABLE,
                detail=f"FileMaker Server's presence could not be established from the recorded "
                       f"root, so neither unhosted proof is available: {detail}; the storage "
                       "removal stays owed")
        fms = None if proved == inv.FMS_ABSENT else collaborators.need("fms")
        return method(operation.resource, fms=fms)
    if tag == pending.OP_PROXY:
        # **Short-circuited.** Asking for the second collaborator after the first has already failed
        # constructs something nothing will use — and `_un_build_proxy_engine` reads the locator and
        # the manifest to do it. One failure is enough to retain the operation.
        observe = collaborators.need("proxy_observe")
        if observe is None:
            return missing("a proxy observation", "proxy_observe")
        engine = collaborators.need("proxy_engine")
        if engine is None:
            return missing("a proxy engine", "proxy_engine")
        # **The PROVIDER, not the value** (stage 6). `run_proxy` calls it only after the observed
        # fronts and the real plan say an activation restart is required, so no credential is
        # acquired — and, with a `prompt` transport, no operator is stopped at a console — for a
        # removal that does not need one.
        outcome = method(operation.resource, observe=observe, engine=engine,
                         credential=collaborators.lease)
        if collaborators.credential_failed():
            # A credential was CONFIGURED and could not be obtained. That is not the same as none
            # being supplied, and it must not be reported as `credential_required`: a launcher that
            # acted on that word would acquire another one and hand it to the same broken transport.
            return missing("an FMS administrator credential", "credential")
        return outcome
    if tag == pending.OP_PKI:
        admin_api = collaborators.need("admin_api")
        if admin_api is None:
            return missing("an FMS Admin API client", "admin_api")
        outcome = method(operation.resource, admin_api=admin_api,
                         credential=collaborators.lease)
        if collaborators.credential_failed():
            return missing("an FMS administrator credential", "credential")
        return outcome
    if tag == pending.OP_PATCH_SLOT:
        folders = collaborators.need("folders")
        if folders is None:
            return missing("an FMS folder-slot client", "folders")
        return method(operation.resource, folders=folders)
    return _DriverOutcome(resource=operation.resource, operation=tag,      # pragma: no cover
                          reason=REASON_UNREACHABLE,
                          detail=f"no handler dispatches {tag!r}")


@dataclass(frozen=True)
class _DriverOutcome:
    """A refusal the DRIVER produces, in the driver's own vocabulary.

    Shaped like an executor `Outcome` because the loop reads both the same way — but deliberately
    not one: `Outcome`'s reason vocabulary is the executor boundary's closed set, and a driver-level
    reason forced into it would make that set mean two different things.
    """

    resource: str
    operation: str
    reason: str
    detail: str
    result: str = "refused"
    checkpointable: bool = False
    observations: tuple = ()


def _Missing(operation, what: str, *, why: str = "") -> _DriverOutcome:
    """A collaborator this box could not construct. **The operation is RETAINED, never skipped.**

    `fms_folders.build_adapter` returns `None` when the PKI authority it needs is missing or
    unusable, and the honest translation of that is *this work is still owed and could not be
    attempted* — not a traceback, and certainly not a completion.
    """
    return _DriverOutcome(
        resource=operation.resource, operation=operation.tag, reason=COLLABORATOR_UNAVAILABLE,
        detail=f"{operation.resource!r} needs {what}, and this box could not construct one"
               + (f" ({why})" if why else "")
               + "; the operation stays owed")


def _blocked_by(record, retained: set) -> set:
    """Everything a retained operation stands in front of, from the record's own relation.

    **This is the force rule.** With `force`, an operation runs only when everything it must follow
    has run; without it, the invocation ends at the first incomplete operation and the question
    never arises. Transitive, and read in the record's own durable order.
    """
    edges = pending.dependency_edges(record.remaining)
    blocked = set(retained)
    for op in record.remaining:                       # in the record's durable order
        if edges[op.resource] & blocked:
            blocked.add(op.resource)
    return blocked


def _next_operation(record, *, executed: set, blocked: set):
    """The next operation this invocation may run, or `None`.

    Two conditions, and the second is **ruling 4 at execution time rather than at planning time**.

    *Predecessors first.* A checkpointed operation leaves the record, so an operation still naming
    predecessors in `dependency_edges` is one whose turn has not come.

    *The terminal footprint goes ABSOLUTELY LAST.* `recovery_closure` withholds the runtime when the
    PLAN already knows work is retained — but an operation can also become retained by REFUSING
    while it runs, and the plan cannot know that in advance.

    **Deferring the footprint to "after the ordinary operations" was not enough, and that is the
    correction this function carries.** The two cleans follow every product removal, so they run
    after everything — and a clean can refuse or fail on its read-back. A run that had already
    removed `install_dir` and then failed the `state_dir` clean left durable pending evidence on a
    box with no interpreter to read it: the same RC4, one position further along.

    So a footprint member is selected only when **every non-footprint operation has left the record
    by checkpointing**, which includes both cleans, and only when nothing is blocked — so no
    retained operation can be depending on footprint content either. `RESOURCE_FOLLOWS` encodes the
    same order, and this is the second half of it: the relation says the footprint may not go first,
    and this says it may not go while anything else is still owed.
    """
    edges = pending.dependency_edges(record.remaining)
    ready = [op for op in record.remaining
             if op.resource not in executed and op.resource not in blocked
             and not (edges[op.resource] - executed)]
    footprint = set(pending.TERMINAL_FOOTPRINT)
    ordinary = [op for op in ready if pending._decision_of(op.resource) not in footprint]
    if ordinary:
        return ordinary[0]
    if blocked:
        return None
    # **There is deliberately no third check here, and a mutation control is why.** A first draft
    # also refused the footprint while any non-footprint operation was still in the record — and
    # neutering that line broke nothing, because it could not fire: an unblocked operation whose
    # predecessors are all done is always selected before the footprint, and one whose predecessors
    # are not done is one whose predecessor is itself selectable. So `blocked` above, plus
    # `RESOURCE_FOLLOWS` putting the footprint after both cleans and the cleans after every other
    # product removal, is the whole guarantee. A safeguard that cannot fire reads like protection
    # and is not any, so it is gone rather than kept for comfort.
    return ready[0] if ready else None


def _is_footprint(resource: str) -> bool:
    return pending._decision_of(resource) in set(pending.TERMINAL_FOOTPRINT)


def is_reinstall_required(record) -> bool:
    """Whether THIS RECORD, as it stands on disk, describes a box that can no longer run this program.

    **Derived from the record alone, and that is the correction.** The first version asked a
    per-invocation `Progress` whether *this run* had removed a footprint member — so the same
    durable state reported `manual_action_required` on the run that did the removing and
    `incomplete_safe` on every later one, on a box whose interpreter was already gone. A result word
    that depends on which invocation is asking is not a description of the box.

    Two conditions, both readable from `remaining`:

    * everything still owed is terminal footprint — so every product and FileMaker Server operation
      has already checkpointed out, which is the only state a reinstall may adopt;
    * **`install_dir` is not among it.** That is the durable fact that matters: `install_dir` holds
      the bundled interpreter and the package, so its absence from the remaining set means it has
      been checkpointed away and removed. While it is still owed, the interpreter is still there and
      the run is an ordinary resumable one.

    Anything else — any non-footprint operation still owed — is ordinary incomplete work and is
    never reinstall-adoptable.
    """
    remaining = [op.resource for op in record.remaining]
    if not remaining or not all(_is_footprint(r) for r in remaining):
        return False
    return not any(pending._decision_of(r) == "install_dir" for r in remaining)


def _execute(layout, *, lock, record, journal: Journal, collaborators: Collaborators,
             force: bool, progress: Progress, authority=None) -> Report:
    """The recorded operations, in the recorded order, each one checkpointed only on proof.

    Every loop iteration is written so that a crash on either side of either checkpoint retries
    safely: the journal checkpoint before an operation is a statement of intent (a crash after it
    re-runs an operation that did not happen, which every handler tolerates), and the pending
    checkpoint after it is the only thing that retires authority — and only when the handler says
    the resource reached its terminal state *and was read back there*.
    """
    executor = _executor_for(layout, lock, authority)
    executed, retained, skipped, observations, refusals = [], [], [], [], []

    quiesce = executor.stop_services(runner=collaborators.runner)
    observations.extend(quiesce.observations)
    if quiesce.result not in _terminal_states():
        # Nothing destructive has been attempted, and nothing will be: deleting the tree of a
        # service that is still running is how a box ends up with a live process and no way to stop
        # it. The record and the journal both stand.
        # NOTHING was attempted, so nothing is *retained* in the sense the word carries elsewhere:
        # every operation is simply still owed and untouched. Reporting them as retained would
        # claim each had been tried and refused.
        return _incomplete(record, reason=QUIESCE_INCOMPLETE,
                           detail=f"{quiesce.result}: {quiesce.detail}",
                           executed=(), retained=(),
                           skipped=tuple(op.resource for op in record.remaining),
                           observations=tuple(observations))

    current = record
    while True:
        blocked = _blocked_by(current, set(retained))
        candidate = _next_operation(current, executed=set(executed), blocked=blocked)
        if candidate is None:
            break
        if authority is not None:
            # Packet 1398 §6.1: before EACH dispatch, the protected frozen plan must still authorize
            # this record, and the operation about to run must be the head of its suffix.
            _validate_attempt(authority, current)
            if candidate != current.remaining[0]:
                raise ResumeRefused(
                    ia.REFUSE_PLAN_MISMATCH,
                    "the next operation is not the head of the frozen plan's remaining suffix")
        journal.checkpoint(lock=lock, subsystem=candidate.resource,
                           intended_change=f"{candidate.tag}:{candidate.resource}",
                           resume_hint="the pending record holds the remaining operations in order")
        outcome = _dispatch(executor, candidate, collaborators, flavour=_flavour_of(layout))
        observations.extend(outcome.observations)
        if outcome.checkpointable:
            if authority is None:
                pending.checkpoint(layout, operation_id=current.operation_id,
                                   installation_id=current.installation_id,
                                   resource=candidate.resource, lock=lock)
            else:
                pending.checkpoint(layout, operation_id=current.operation_id,
                                   installation_id=current.installation_id,
                                   resource=candidate.resource, lock=lock, attempt=authority)
            progress.checkpoints += 1
            # THE REREAD. The record on disk is the authority for what is left, and a cached copy is
            # a second opinion nobody asked for.
            current = _read_pending(layout, authority)
            if current is None:                                          # pragma: no cover
                raise ResumeRefused(NO_PENDING_RECORD,
                                    "the pending record vanished mid-invocation")
            executed.append(candidate.resource)
            journal.checkpoint(lock=lock, subsystem=candidate.resource,
                               verified=candidate.resource,
                               intended_change=f"{candidate.tag}:{candidate.resource}",
                               resume_hint="verified and retired from the pending record")
            continue
        retained.append(candidate.resource)
        # **The executor's reason is kept.** It is a word from a closed vocabulary, chosen so a
        # caller can branch on WHY an operation stayed owed; aggregating into prose alone throws
        # away the only machine-readable part.
        refusals.append(f"{candidate.resource}={outcome.reason or outcome.result}: "
                        f"{outcome.detail}")
        if not force:
            break

    still_owed = tuple(op.resource for op in current.remaining)
    skipped = tuple(r for r in still_owed if r not in retained)
    if still_owed:
        if is_reinstall_required(current):
            return _reinstall_required(current, executed=tuple(executed),
                                       retained=tuple(retained), skipped=skipped,
                                       observations=tuple(observations), refusals=tuple(refusals))
        if _reportable_reason(refusals) in _unresumable_reasons():
            return Report(result=R.MANUAL_ACTION_REQUIRED, operation_id=current.operation_id,
                          installation_id=current.installation_id,
                          reason=_reportable_reason(refusals),
                          detail=_owed_detail(retained, skipped),
                          executed=tuple(executed), retained=tuple(retained), skipped=skipped,
                          observations=tuple(observations) + tuple(refusals))
        return _incomplete(current, reason=_reportable_reason(refusals),
                           detail=_owed_detail(retained, skipped),
                           executed=tuple(executed), retained=tuple(retained), skipped=skipped,
                           observations=tuple(observations) + tuple(refusals))
    if authority is not None:
        return _finalize_attempt(layout, lock=lock, journal=journal, authority=authority,
                                 executed=tuple(executed), observations=tuple(observations))
    return _finalize(layout, lock=lock, record=current, journal=journal, executed=tuple(executed),
                     retained=(), skipped=(), observations=tuple(observations))


def _terminal_states() -> frozenset:
    """The executor's own set, imported rather than restated. Two copies of a closed vocabulary is
    one copy that stops matching."""
    from .uninstall_exec_posix import EXEC_TERMINAL

    return EXEC_TERMINAL


#: The reasons a CALLER can act on, in the order it would act. `credential_required` is the only one
#: a launcher branches on today, and it is the reason this function exists. Imported from the
#: executor's own closed vocabulary rather than spelled again here — two copies of a reason word is
#: one copy that stops matching, and this one is the whole of the launcher's credential protocol.
def _actionable_reasons() -> tuple:
    from .uninstall_exec_posix import REFUSE_CREDENTIAL_REQUIRED

    return (REFUSE_CREDENTIAL_REQUIRED,)


def _unresumable_reasons() -> tuple:
    """Refusals a RE-RUN cannot clear, so the report must not offer one (packet 1000-14).

    `incomplete_safe` means *re-running resumes*, and the executor has exactly one refusal that
    every later invocation would reproduce identically: the tree still owed holds the interpreter
    executing the uninstall, on a platform that cannot remove a running image. That is a human's
    action — delete the directory once nothing is running out of it — and it is reported as one.

    Imported from the executor's own closed vocabulary rather than spelled again, for the reason
    `_actionable_reasons` gives: two copies of a reason word is one copy that stops matching.
    """
    from .uninstall_exec_posix import REFUSE_SELF_RUNTIME

    return (REFUSE_SELF_RUNTIME,)


def _reportable_reason(refusals) -> str:
    """The one reason word this report carries — the ACTIONABLE one if a run produced any.

    **Blind-review finding H1.** This used to be `refusals[0]`, unconditionally. Without `--force`
    the loop breaks at the first refusal, so there is exactly one and the two rules agree. **With
    `--force` it keeps going**, so any operation refusing before the proxy edit put its own word in
    `reason` and `credential_required` survived only inside `observations` — which no launcher reads,
    and could not be asked to: a caller that scanned free text for a reason word is the prose-parsing
    this whole boundary exists to remove. The run then stopped at exit 5 with a word nobody could act
    on, and the operator was never asked for the credential that would have finished it.

    Every refusal still travels, in `observations`, with its resource and its detail. What this
    chooses is which one the single machine-readable field carries.
    """
    if not refusals:
        return ""
    words = [entry.split("=", 1)[1].split(":", 1)[0] for entry in refusals]
    for actionable in _actionable_reasons():
        if actionable in words:
            return actionable
    return words[0]


def _owed_detail(retained, skipped) -> str:
    parts = []
    if retained:
        parts.append(f"{list(retained)} did not complete and remain owed")
    if skipped:
        parts.append(f"{list(skipped)} were not attempted")
    return "; ".join(parts) or "work remains"


def _reinstall_required(record, *, executed, retained, skipped, observations, refusals) -> Report:
    """**The accepted terminal limitation, reported as what it is.**

    The invocation removed part of the terminal footprint — the bundled interpreter and package, the
    launcher, or an elevation helper — and then could not finish. What remains is footprint-only, so
    the pending record and the locator are intact and no product or FileMaker Server operation is
    still owed; but the program that would resume it may no longer exist on this box.

    `manual_action_required` rather than `incomplete_safe`, deliberately: the second word promises a
    resume, and promising a resume through a deleted CLI is the one thing this state must not do.

    **1246-10 HANDOFF, recorded here because this is where the state is produced.** A reinstall may
    adopt EXACTLY this shape — a valid pending record whose remaining set is a suffix of the
    terminal footprint and nothing else — and it may never adopt arbitrary pending evidence. Any
    other remaining set describes an uninstall that stopped somewhere a reinstall cannot reason
    about, and that one stays a human's decision.
    """
    return Report(result=R.MANUAL_ACTION_REQUIRED, operation_id=record.operation_id,
                  installation_id=record.installation_id, reason=REINSTALL_REQUIRED,
                  detail=f"the terminal footprint was partly removed and "
                         f"{[op.resource for op in record.remaining]} remains; the pending record "
                         "and the locator are intact, and a reinstall adopts this state — this box "
                         "may no longer be able to run the uninstaller itself",
                  executed=executed, retained=retained, skipped=skipped,
                  observations=tuple(observations) + tuple(refusals))


def _incomplete(record, *, reason, detail, executed, retained, skipped, observations=()) -> Report:
    return Report(result=R.INCOMPLETE_SAFE, operation_id=record.operation_id,
                  installation_id=record.installation_id, reason=reason, detail=detail,
                  executed=executed, retained=retained, skipped=skipped,
                  observations=observations)


# ── finalization ──────────────────────────────────────────────────────────────


def _finalize(layout, *, lock, record, journal: Journal, executed, retained, skipped,
              observations=()) -> Report:
    """The tail: resolve · discard the journal · remove the locator · discard the record — LAST.

    **Only an observably empty record enters here**, re-read from disk rather than taken from the
    caller's copy. Each step is idempotent on its own, so a finalization interrupted anywhere
    completes on the next invocation, and a failure at any step leaves every later piece of evidence
    exactly where it is: the record outlives the locator, which outlives the journal, because that is
    the order in which each stops being needed.
    """
    on_disk = _read_pending(layout)
    if on_disk is None:
        # `finalized=False`: THIS invocation finalized nothing. The uninstall is finished, and
        # saying otherwise would credit this run with a tail somebody else ran.
        return Report(result=R.NO_CHANGE, operation_id=record.operation_id,
                      installation_id=record.installation_id, finalized=False,
                      detail="the pending record is already gone; the uninstall is finished",
                      executed=tuple(executed), observations=tuple(observations))
    if on_disk.remaining:
        # A BACKSTOP, and it has its own test. Both callers check before arriving here, so nothing
        # reaches it in ordinary operation — which is exactly why it is exercised directly: the step
        # it guards is the most destructive one in the package.
        raise ResumeRefused(
            JOURNAL_RESOLVED_WITH_WORK,
            f"finalization requires an empty pending record and this one owes "
            f"{[op.resource for op in on_disk.remaining]}")

    current = journal.read()
    if current is not None and current.state != JOURNAL_RESOLVED:
        journal.resolve(lock=lock, result=R.COMPLETED)
    if journal.read() is not None:
        journal.discard(lock=lock)
    adapter = locator_for(layout)
    if adapter.exists():
        adapter.remove(lock=lock)
    pending.discard(layout, operation_id=on_disk.operation_id,
                    installation_id=on_disk.installation_id, lock=lock)
    return Report(result=R.COMPLETED, operation_id=on_disk.operation_id,
                  installation_id=on_disk.installation_id, finalized=True,
                  detail="every recorded operation is complete; the journal, the locator and the "
                         "pending record are gone",
                  executed=tuple(executed), retained=tuple(retained), skipped=tuple(skipped),
                  observations=tuple(observations))


__all__ = ["Collaborators", "Report", "ResumeRefused", "REFUSAL_REASONS", "UNINSTALL_MODE",
           "attempt_finishes_outside_lock", "finish_attempt", "observe", "resume", "start"]
