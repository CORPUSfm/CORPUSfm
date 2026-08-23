"""The storage-identity operations (packet 1246-08 §6, §7, §8, §9, §10).

Seven verbs. ``observe`` and ``plan`` mutate nothing and take neither lock nor journal;
``bootstrap``, ``repair``, ``resume``, ``create_first_admin``, ``finalize`` and ``abort`` REFUSE
without both — they are not optional parameters, and a shipped path that ran every mutation with no
serialization while the tests exercised a bracket nothing used is a defect this family has already
paid for once.

Three rules that shape everything here:

* **A new mutation never resumes.** ``bootstrap`` and ``repair`` refuse over any operation evidence
  that is not NONE, and name ``resume``. ``resume`` continues only what its own record already
  authorized, from the phase that record names.
* **SETTINGS is initialized on exactly one path** — an operation whose own record says
  ``template_placed_by_this_run``. There is no other call site, which is what makes "never
  initialize somebody else's corpus" structural rather than documentary.
* **Rotation is classified by PROBING, never by trusting a return.**
  ``reset_automation_password`` can return ``ok=False, changed=True``; a crash can land anywhere in
  the call. So the outcome is established by probing the promoted, default and candidate secrets and
  reading the answer, and only a proven candidate is ever promoted.
"""

from __future__ import annotations

import getpass
import os
import secrets
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import app_paths
from .errors import LifecycleError
from .result import (
    COMPLETED,
    FAILED_BEFORE_CHANGE,
    INCOMPLETE_SAFE,
    MANUAL_ACTION_REQUIRED,
    NO_CHANGE,
    ROLLED_BACK,
)
from .schema import JOURNAL_RESOLVED, StorageBlock, utc_now_iso
from . import storage_identity as si
from . import storage_identity_recovery as rec
from . import storage_identity_store as store
from .storage_identity import (
    AUTOMATION_ACCOUNT,
    BOOTSTRAP_SECRET,
    OperationEvidence,
    OperationPhase,
    ProbeFact,
    RECOVERY_ACCOUNT,
    STORAGE_DATABASE_NAME,
    StorageFacts,
    StorageInputs,
    StorageState,
)

#: How many bytes of randomness a rotated secret carries. The current shipped strength.
SECRET_ENTROPY_BYTES = 32


class StorageOperationRefused(LifecycleError):
    """A verb refused before changing anything. Carried as a result, not raised past the CLI."""


# ── the exact CORPUSfm-Admin recovery procedure (§10.4) ──────────────────────

RECOVERY_PROCEDURE = (
    f"CORPUSfm cannot re-assert its own FileMaker password: that needs [Full Access], which the "
    f"{AUTOMATION_ACCOUNT} account deliberately does not have. To repair access: "
    f"(1) obtain a controlled copy or backup of the storage database through FileMaker's own "
    f"supported procedure — do not edit a live hosted file; "
    f"(2) close or otherwise handle the file through the supported FileMaker procedure; "
    f"(3) open it in FileMaker Pro with the {RECOVERY_ACCOUNT} account; "
    f"(4) in File > Manage > Security, set {AUTOMATION_ACCOUNT}'s password to its own account "
    f"name ({AUTOMATION_ACCOUNT}); "
    f"(5) close cleanly and return or host the file; "
    f"(6) run the installer's storage-access repair, which immediately rotates it to a fresh "
    f"random value. "
    f"If the {RECOVERY_ACCOUNT} password has been lost, there is no supported file-level repair."
)


# ── result ───────────────────────────────────────────────────────────────────


@dataclass
class StorageReport:
    """One tagged result, always — including on failure."""

    result: str
    state: str | None = None
    operation_id: str | None = None
    facts: StorageFacts | None = None
    findings: tuple[si.Finding, ...] = ()
    next_action: str = ""
    awaiting_composition: bool = False
    unresolved_operation: dict | None = None
    candidate: si.StorageCandidate | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "result": self.result,
            "operation_id": self.operation_id,
            "next_action": self.next_action,
            "facts": self.facts.to_dict() if self.facts is not None else None,
            "findings": [f.to_dict() for f in self.findings],
            "awaiting_composition": self.awaiting_composition,
            "unresolved_operation": self.unresolved_operation,
            "candidate": self.candidate.to_dict() if self.candidate is not None else None,
        }


def _refuse(code: str, detail: str, *, state: str | None = None,
            result: str = FAILED_BEFORE_CHANGE, facts: StorageFacts | None = None,
            next_action: str | None = None, operation_id: str | None = None) -> StorageReport:
    return StorageReport(
        result=result, state=state, facts=facts, operation_id=operation_id,
        findings=(si.Finding(code, detail),),
        next_action=next_action if next_action is not None else detail,
    )


# ── the secret transport (first administrator only) ──────────────────────────


class TransportRefused(LifecycleError):
    """The administrator secret could not be read. Never an empty password by accident."""


def read_transport(transport: str) -> str:
    """`prompt` | `stdin` | `fd:<n>`. There is no `absent`: a verb that cannot run without a
    secret must not accept a schema value that guarantees failure."""
    if transport == "prompt":
        first = getpass.getpass("  CORPUSfm administrator password: ")
        second = getpass.getpass("  Confirm password: ")
        if first != second:
            raise TransportRefused("the two passwords did not match; no administrator was created")
        value = first
    elif transport == "stdin":
        value = sys.stdin.read()
    elif transport.startswith("fd:") and transport[3:].isdigit():
        fd = int(transport[3:])
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        os.close(fd)
        value = b"".join(chunks).decode("utf-8")
    else:
        raise TransportRefused(f"unknown credential transport {transport!r}")
    # Trailing newline only — a password of spaces is a password, and trimming it would silently
    # change what the administrator typed.
    value = value.rstrip("\r\n")
    if not value:
        raise TransportRefused(
            "the administrator password was empty; refusing rather than creating an account with "
            "no password"
        )
    if len(value) < 8:
        raise TransportRefused(
            "the administrator password must be at least 8 characters; no administrator was created"
        )
    return value


# ── observation ──────────────────────────────────────────────────────────────


def _machine_key_ready(inputs: StorageInputs) -> bool:
    """Whether the Machine Key authority exists YET.

    This reads nothing and creates nothing: it asks only whether the key FILE is there. This
    component neither refuses a missing Machine Key nor regenerates one — that ruling belongs to
    the resolver in ``corpusfm.core.crypto`` and to the integrator (packet 1246-02/03), whose
    REPLACEABLE ruling (developer, 2026-08-03) this packet may not reverse.

    *The resolver is deliberately not named here.* ``tests/test_crypto_key_split.py``'s
    machine-crypto census is a text scan, and a module that merely EXPLAINS why it does not call
    the resolver would otherwise be classified as one that does — which would put a module with no
    machine-scoped secret into the allowlist and quietly widen it.
    """
    from .admin_identity_store import machine_key_present

    try:
        return bool(machine_key_present(inputs.secrets_dir))
    except Exception:  # noqa: BLE001 — an unreadable secrets dir is "not established yet"
        return False


def _probe_fact(result) -> str:
    """One probe, one axis value. INCONCLUSIVE stays distinct from REFUSED."""
    if result is None:
        return ProbeFact.NOT_ATTEMPTED.value
    if not getattr(result, "reachable", False):
        return ProbeFact.INCONCLUSIVE.value
    if getattr(result, "authed", False) and getattr(result, "has_odata", False):
        return ProbeFact.ACCEPTED.value
    if getattr(result, "authed", False):
        # Authenticates but no fmodata: a privilege problem, not a wrong secret. Reporting REFUSED
        # would send the administrator to rotate a password that is already correct.
        return ProbeFact.INCONCLUSIVE.value
    return ProbeFact.REFUSED.value


def _secrets_layout(lifecycle_layout):
    """The SECRETS store needs an ``OsLayout``; ``lifecycle_layout`` is the LIFECYCLE record layout.

    They are different types and neither is a superset of the other: ``LifecycleLayout`` carries the
    lock, journal and locator locations and has **no** ``secrets_dir``. Every ``rec.*`` / ``store.*``
    call in this module forwarded it into a parameter that means *OS layout*, and
    ``admin_identity_store.validated_secrets_dir`` then did ``Path(resolved_layout.secrets_dir)`` —
    raising ``AttributeError: 'LifecycleLayout' object has no attribute 'secrets_dir'`` on the first
    real box that reached it (fms-server, 2026-08-08, `storage observe` during installer phase 14).

    It never surfaced in tests because they monkeypatch ``os_layout.platform_os_layout`` and pass
    ``lifecycle_layout=None`` or a journal-less observe — so the wrong-typed argument was never the
    one consulted.

    Returning ``None`` for a non-``OsLayout`` is not a fallback that hides a caller error: the store
    accepts **only** the fixed OS secrets directory anyway, so ``None`` resolves to exactly the
    location it would have demanded. A genuine ``OsLayout`` (a test override) is passed through.
    """
    from . import os_layout as _os

    return lifecycle_layout if isinstance(lifecycle_layout, _os.OsLayout) else None


def collect_facts(inputs: StorageInputs, *, adapter, lifecycle_layout=None) -> StorageFacts:
    """Eleven axes, each from its own channel. No journal, no operation state."""
    target = si.storage_target(inputs.fms_database_dir)

    fms_presence = (
        si.FmsPresence.INSTALLED.value if Path(inputs.fms_root).is_dir()
        else si.FmsPresence.ABSENT.value
    )

    hosted = adapter.list_databases()
    if hosted is None:
        database_known = si.DatabaseKnown.UNKNOWN.value
        hosted_state = si.HostedState.UNKNOWN.value
        conflicts = si.find_conflicts(inputs.fms_database_dir, None)
    else:
        row = None
        for entry in hosted:
            name = str(entry.get("filename") or entry.get("name") or "")
            stem = name[:-6] if name.lower().endswith(".fmp12") else name
            if stem.lower() == STORAGE_DATABASE_NAME.lower():
                row = entry
                break
        database_known = (
            si.DatabaseKnown.KNOWN.value if row is not None else si.DatabaseKnown.NOT_KNOWN.value
        )
        if row is None:
            hosted_state = si.HostedState.UNKNOWN.value
        else:
            status = str(row.get("status") or "").upper()
            hosted_state = (
                si.HostedState.OPEN.value if status in ("OPEN", "OPENED", "NORMAL")
                else si.HostedState.CLOSED.value if status == "CLOSED"
                else si.HostedState.UNKNOWN.value
            )
        conflicts = si.find_conflicts(inputs.fms_database_dir, hosted)

    try:
        target_file = (
            si.TargetFile.PRESENT.value if target.exists() else si.TargetFile.ABSENT.value
        )
    except OSError:
        target_file = si.TargetFile.UNKNOWN.value

    key_ready = _machine_key_ready(inputs)
    local_material = store.classify_local(
        inputs.secrets_dir, machine_key_ready=key_ready, layout=_secrets_layout(lifecycle_layout)
    )

    promoted = staged = None
    if local_material == si.LocalMaterial.USABLE.value:
        promoted = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    if key_ready:
        try:
            staged = store.load_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        except Exception:  # noqa: BLE001 — an unreadable stage is simply "no candidate to probe"
            staged = None

    promoted_probe = ProbeFact.NOT_ATTEMPTED.value
    default_probe = ProbeFact.NOT_ATTEMPTED.value
    candidate_probe = ProbeFact.NOT_ATTEMPTED.value
    odata = si.Reachability.UNKNOWN.value
    settings_state = si.SettingsState.UNKNOWN.value

    default_result = adapter.probe(BOOTSTRAP_SECRET)
    odata = (
        si.Reachability.REACHABLE.value if getattr(default_result, "reachable", False)
        else si.Reachability.UNREACHABLE.value
    )
    # AN UNREACHABLE SERVER YIELDS NO PROBE FACTS AT ALL.
    #
    # CORRECTED after the blind implementation review of 2026-08-05, which reproduced this: the
    # first version recorded `default_probe = INCONCLUSIVE` beside `odata = UNREACHABLE`, and
    # `validate_relations` refuses exactly that pair by name — so an FMS that is installed but
    # STOPPED produced a relation violation instead of `FMS_UNREACHABLE`, making that state, its
    # next_action and §10.2's repair row unreachable code. A probe against a server that did not
    # answer was never attempted; recording it as attempted-and-inconclusive was the error.
    default_probe = (
        _probe_fact(default_result) if odata == si.Reachability.REACHABLE.value
        else ProbeFact.NOT_ATTEMPTED.value
    )
    if default_probe == ProbeFact.ACCEPTED.value:
        settings_state = _settings_value(default_result)

    if promoted is not None and odata == si.Reachability.REACHABLE.value:
        if promoted.secret == BOOTSTRAP_SECRET:
            # The promoted secret IS the bootstrap default — the state the recovery procedure
            # deliberately creates. One probe feeds both axes; probing twice would present one fact
            # as two independent authorities that happen to agree.
            promoted_probe = default_probe
        else:
            promoted_result = adapter.probe(promoted.secret)
            promoted_probe = _probe_fact(promoted_result)
            if promoted_probe == ProbeFact.ACCEPTED.value:
                settings_state = _settings_value(promoted_result)

    if staged is not None and odata == si.Reachability.REACHABLE.value:
        if staged.secret == BOOTSTRAP_SECRET:
            candidate_probe = default_probe
        elif promoted is not None and staged.secret == promoted.secret:
            candidate_probe = promoted_probe
        else:
            candidate_result = adapter.probe(staged.secret)
            candidate_probe = _probe_fact(candidate_result)
            if candidate_probe == ProbeFact.ACCEPTED.value:
                settings_state = _settings_value(candidate_result)

    user_table = si.UserTable.UNKNOWN.value
    accepted_secret = _first_accepted_secret(
        promoted, staged, promoted_probe, default_probe, candidate_probe
    )
    if accepted_secret is not None:
        user_table = _read_user_table(adapter, accepted_secret)

    manifest_expectation = _manifest_expectation(inputs, lifecycle_layout)

    return StorageFacts(
        fms_presence=fms_presence,
        database_known=database_known,
        target_file=target_file,
        hosted_state=hosted_state,
        local_material=local_material,
        promoted_probe=promoted_probe,
        default_probe=default_probe,
        candidate_probe=candidate_probe,
        odata=odata,
        settings_state=settings_state,
        user_table=user_table,
        manifest_expectation=manifest_expectation,
        conflicts=conflicts,
        observed_utc=utc_now_iso(),
    )


def _settings_value(result) -> str:
    value = str(getattr(result, "settings_state", "") or "unknown")
    return value if value in {s.value for s in si.SettingsState} else si.SettingsState.UNKNOWN.value


def _first_accepted_secret(promoted, staged, promoted_probe, default_probe, candidate_probe):
    if promoted is not None and promoted_probe == ProbeFact.ACCEPTED.value:
        return promoted.secret
    if staged is not None and candidate_probe == ProbeFact.ACCEPTED.value:
        return staged.secret
    if default_probe == ProbeFact.ACCEPTED.value:
        return BOOTSTRAP_SECRET
    return None


def _read_user_table(adapter, secret: str) -> str:
    """Through the EXPLICITLY constructed backend, never the ambient one.

    ``users_exist``'s default path resolves ``storage.get_backend()`` → ``read_install_config()``,
    the store this packet exists to retire — which on a new-format box answers LocalBackend and
    therefore "no users": a definite False about the wrong store.
    """
    from corpusfm.app.web import users

    try:
        backend = adapter.backend(secret)
        return (
            si.UserTable.NON_EMPTY.value
            if users.users_exist(backend=backend, raise_on_error=True)
            else si.UserTable.EMPTY.value
        )
    except Exception:  # noqa: BLE001 — an outage is UNKNOWN, never an empty user store
        return si.UserTable.UNKNOWN.value


def _read_manifest(inputs: StorageInputs):
    """The installation's own manifest, as a READER.

    ``ManifestStore(install_dir)`` with no layout is the read-only form, and it is the same
    mechanism 1246-07's ``_inspect_generation`` uses. ``published.read_published_installation()``
    is not used here because it projects no storage block — widening it would mean editing a
    module this packet does not own.
    """
    from .manifest import ManifestStore

    return ManifestStore(inputs.install_dir).read()


def _manifest_expectation(inputs: StorageInputs, lifecycle_layout) -> str:
    """EXPECTS_CORPUS / NO_EXPECTATION / UNREADABLE.

    ``UNREADABLE`` is a distinct value on purpose: a record that exists and cannot be read
    consistently REFUSES rather than falling back, which is 1246-03-01's rule. Collapsing it into
    ``NO_EXPECTATION`` would let a corrupt manifest read as a clean box.
    """
    from .manifest import ManifestStore

    try:
        store_ = ManifestStore(inputs.install_dir)
        if not store_.exists():
            return si.ManifestExpectation.NO_EXPECTATION.value
        manifest = store_.read()
    except Exception:  # noqa: BLE001
        return si.ManifestExpectation.UNREADABLE.value
    block = getattr(manifest, "storage", None)
    if block is None:
        return si.ManifestExpectation.NO_EXPECTATION.value
    if getattr(block, "corpus_id", None) or getattr(block, "initialized", False):
        return si.ManifestExpectation.EXPECTS_CORPUS.value
    return si.ManifestExpectation.NO_EXPECTATION.value


def _generation_authority(inputs: StorageInputs) -> int:
    """Establish the generation INDEPENDENTLY, then compare the caller's claim to it.

    Echoing ``expected_generation`` straight into the candidate would make the compare-and-swap
    check its own input — a defect 1246-07 shipped once and corrected, and there is no reason to
    re-earn it here.
    """
    manifest = _read_manifest(inputs)
    if manifest.installation_id != inputs.installation_id:
        raise StorageOperationRefused(
            f"the installation record identifies {manifest.installation_id}, and the request "
            f"claims {inputs.installation_id}"
        )
    if manifest.generation != inputs.expected_generation:
        raise StorageOperationRefused(
            f"the request expects generation {inputs.expected_generation} and the installation "
            f"is at generation {manifest.generation}"
        )
    return manifest.generation


def observe(inputs: StorageInputs, *, adapter, lifecycle_layout=None,
            journal=None) -> StorageReport:
    """Read-only. Takes neither lock nor journal, and reports any unresolved storage operation."""
    facts = collect_facts(inputs, adapter=adapter, lifecycle_layout=lifecycle_layout)
    try:
        state = si.classify(facts)
    except si.RelationViolated as exc:
        return _refuse("relation_violated", str(exc), facts=facts)

    unresolved = None
    if journal is not None:
        ev, record = rec.evidence(
            inputs.secrets_dir, inputs.installation_id, journal=journal, layout=_secrets_layout(lifecycle_layout)
        )
        if record is not None and ev in (
            OperationEvidence.MATCHING_OPEN.value, OperationEvidence.MATCHING_RESOLVED.value
        ):
            unresolved = record.public()
        elif ev in (OperationEvidence.FOREIGN_OPEN.value, OperationEvidence.UNREADABLE.value):
            unresolved = {"operation_id": None, "phase": ev}

    return StorageReport(
        result=NO_CHANGE, state=state, facts=facts,
        next_action=si.next_action_for(state), unresolved_operation=unresolved,
    )


# ── shared preconditions ─────────────────────────────────────────────────────


def _require_brackets(lock, journal) -> None:
    if lock is None or journal is None:
        raise StorageOperationRefused(
            "a mutating storage verb requires the lifecycle lock and the journal; refusing to run "
            "unserialized and unbracketed"
        )


#: Every result word that CLOSES the journal. `incomplete_safe` and `manual_action_required` leave
#: it open on purpose: work is owed, and a resolved journal beside owed work is the lie that makes
#: crash recovery guess.
_RESOLVES_JOURNAL = frozenset({COMPLETED, NO_CHANGE, ROLLED_BACK, FAILED_BEFORE_CHANGE})


def _open_journal(journal, lock, *, record) -> None:
    """Bracket the operation. ADDED after the blind implementation review of 2026-08-05, which
    found §9.3's bracket asserted in the contract and present in no code path at all."""
    try:
        journal.begin(lock=lock, operation_id=record.operation_id,
                      installation_id=record.installation_id, mode=record.mode)
    except Exception:  # noqa: BLE001
        # A journal that will not open is not a reason to run unbracketed, but it is also not a
        # reason to lose the operation record that is already on disk. The caller's own refusal
        # path reports it; the record stands.
        raise StorageOperationRefused(
            "the lifecycle journal could not be opened for this storage operation; nothing was "
            "changed"
        )


def _close_journal(journal, lock, report: StorageReport) -> StorageReport:
    """Resolve on a terminal word; leave it open when work is still owed."""
    if report.result in _RESOLVES_JOURNAL:
        try:
            journal.resolve(lock=lock, result=report.result)
        except Exception:  # noqa: BLE001 — a resolve that fails must not rewrite the outcome
            pass
    return report


def _checkpoint(journal, lock, subsystem: str) -> None:
    try:
        journal.checkpoint(lock=lock, subsystem=subsystem)
    except Exception:  # noqa: BLE001 — a checkpoint is evidence, never a gate
        pass


def _require_published_generation(inputs: StorageInputs) -> None:
    """`0` is not published authority (§8.2a, Codex R6).

    The foundational manifest is written at generation 1 BEFORE any provider runs, so a mutating
    verb handed 0 is being asked to mutate a box whose authority does not exist yet.
    """
    if inputs.expected_generation < 1:
        raise StorageOperationRefused(
            "expected_generation must be at least 1: the foundational manifest is published "
            "before storage runs, so generation 0 is not published authority"
        )


_EVIDENCE_DETAIL = {
    OperationEvidence.MATCHING_OPEN.value:
        "a storage operation is already in progress on this installation; continue it with "
        "`storage resume`, which is the only verb that may.",
    OperationEvidence.FOREIGN_OPEN.value:
        "another lifecycle operation is unresolved on this machine and it is not this storage "
        "operation; resolve it before running storage work.",
    OperationEvidence.UNREADABLE.value:
        "a storage operation record exists and its lifecycle evidence cannot be reconciled; "
        "nothing was changed.",
}


def _discharge_non_authority(inputs, ev, record, *, journal, lock, lifecycle_layout, verb: str):
    """THE ONE discharge for every disposition that is dischargeable but is NOT authority.

    `bootstrap`, `repair`, `resume`, `abort` and `finalize` all route here so they cannot diverge —
    and every one of them ENDS its invocation on the returned report. Recovery cleanup is never
    combined with new work: an invocation that finds residue retires it and tells the operator to
    run again, so the decision to start something is always taken against a clean box.

    Four dispositions, three discharges, and the JOURNAL is touched in exactly one of them:

    * ``EVIDENCE_INERT_PREPARED`` — `journal.begin` never landed, so there is nothing to resolve
      and nothing was mutated. Retire the record. **The journal is left untouched.**
    * ``EVIDENCE_TERMINAL_PENDING_JOURNAL`` — the work finished and the journal was never closed.
      **Resolve the journal FIRST, then retire the evidence.** That order is what makes a crash
      between the two retryable: the retry re-observes ``MATCHING_RESOLVED`` and performs
      retirement only, never product work.
    * ``EVIDENCE_TERMINAL_NO_JOURNAL`` — terminal with no entry to resolve. Retire only.
    * ``MATCHING_RESOLVED`` — the journal is already resolved. Retire only.
    """
    if ev == rec.EVIDENCE_TERMINAL_PENDING_JOURNAL:
        try:
            journal.resolve(lock=lock, result=COMPLETED)
        except Exception as exc:  # noqa: BLE001
            # The journal could not be closed, so the evidence STAYS. Retiring it here would
            # destroy the only record of what the unresolved entry belongs to.
            return _refuse(
                "journal_resolution_failed",
                f"the completed storage operation's lifecycle journal could not be resolved "
                f"({type(exc).__name__}); its evidence was retained.",
                result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id)

    if ev != rec.EVIDENCE_INERT_PREPARED:
        # An inert operation staged nothing and backed up nothing, so there is nothing but the
        # record to retire; the others may have.
        store.discard_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        store.discard_backup(inputs.secrets_dir, record.operation_id, layout=_secrets_layout(lifecycle_layout))
    rec.discharge(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))

    detail = {
        rec.EVIDENCE_INERT_PREPARED:
            "a storage operation record was found that had not begun and had changed nothing; it "
            "was retired.",
        rec.EVIDENCE_TERMINAL_PENDING_JOURNAL:
            "a completed storage operation had not been closed out; its journal was resolved and "
            "its evidence retired.",
        rec.EVIDENCE_TERMINAL_NO_JOURNAL:
            "a completed storage operation's evidence was found with no lifecycle entry; it was "
            "retired.",
        OperationEvidence.MATCHING_RESOLVED.value:
            "a completed storage operation's evidence was retired.",
    }[ev]
    return StorageReport(
        result=NO_CHANGE, operation_id=record.operation_id,
        findings=(si.Finding(f"discharged_{ev}", detail),),
        next_action=f"{detail} Nothing else was done — run the command again.",
    )


def _evidence_or_refuse(inputs, journal, lifecycle_layout, verb: str, *, lock=None):
    ev, record = rec.evidence(
        inputs.secrets_dir, inputs.installation_id, journal=journal, layout=_secrets_layout(lifecycle_layout)
    )
    if ev in rec.NON_AUTHORITY_DISPOSITIONS:
        return ev, _discharge_non_authority(
            inputs, ev, record, journal=journal, lock=lock, lifecycle_layout=lifecycle_layout,
            verb=verb)
    if ev != OperationEvidence.NONE.value:
        return ev, _refuse(f"operation_{ev}", f"{verb} refused: {_EVIDENCE_DETAIL[ev]}")
    return ev, None


def _require_matching_operation(inputs, operation_id, journal, lifecycle_layout, verb: str, *,
                                lock=None):
    """The gate every RECOVERY verb passes before it may touch anything.

    ``resume``, ``abort`` and ``finalize`` act on an operation's own evidence, so the evidence must
    be proven to BE this operation's — by storage record AND by journal entry, on both identifiers.
    Reading the storage record alone was the hole: an unresolved proxy operation beside a matching
    storage record answered "open" and authorized storage work on it.

    **ONLY ``MATCHING_OPEN`` is authority.** Everything dischargeable-but-not-authority routes to
    the shared discharge and ENDS the invocation. The closure inspection reproduced the alternative:
    ``EVIDENCE_INERT_PREPARED`` was accepted here, so a record that had begun nothing authorized a
    resume, a finalize, adapter calls and journal transitions.
    """
    ev, record = rec.evidence(
        inputs.secrets_dir, inputs.installation_id, journal=journal, layout=_secrets_layout(lifecycle_layout)
    )
    if ev == OperationEvidence.FOREIGN_OPEN.value:
        return None, _refuse(
            "operation_foreign_open",
            f"{verb} refused: {_EVIDENCE_DETAIL[OperationEvidence.FOREIGN_OPEN.value]}")
    if ev == OperationEvidence.UNREADABLE.value:
        return None, _refuse(
            "operation_unreadable",
            f"{verb} refused: {_EVIDENCE_DETAIL[OperationEvidence.UNREADABLE.value]}")
    if record is None or ev == OperationEvidence.NONE.value:
        return None, _refuse("no_operation",
                             f"there is no storage operation for {verb} to act on.")
    if record.operation_id != operation_id:
        return None, _refuse(
            "operation_id_mismatch",
            f"the recorded storage operation is {record.operation_id}, not {operation_id}.")
    if record.installation_id != inputs.installation_id:
        return None, _refuse(
            "operation_foreign",
            "the recorded storage operation belongs to another installation.")
    if ev in rec.NON_AUTHORITY_DISPOSITIONS:
        return None, _discharge_non_authority(
            inputs, ev, record, journal=journal, lock=lock, lifecycle_layout=lifecycle_layout,
            verb=verb)
    return (ev, record), None


# ── bootstrap ────────────────────────────────────────────────────────────────


def bootstrap(inputs: StorageInputs, *, adapter, lock, journal, lifecycle_layout=None,
              template: Path | None = None) -> StorageReport:
    """Provision a PROVEN FRESH corpus. Nine clauses, all of them, or nothing happens."""
    _require_brackets(lock, journal)
    _require_published_generation(inputs)

    ev, refusal = _evidence_or_refuse(inputs, journal, lifecycle_layout, "bootstrap", lock=lock)
    if refusal is not None:
        return refusal

    facts = collect_facts(inputs, adapter=adapter, lifecycle_layout=lifecycle_layout)
    try:
        state = si.classify(facts)
    except si.RelationViolated as exc:
        return _refuse("relation_violated", str(exc), facts=facts)

    ok, failures = si.proven_fresh(facts, mode=inputs.mode, evidence=ev)
    if not ok:
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=tuple(si.Finding("fresh_clause_unmet", c) for c in failures),
            next_action=si.next_action_for(state),
        )

    operation_id = str(uuid.uuid4())
    record = rec.OperationRecord(
        operation_id=operation_id, installation_id=inputs.installation_id, mode=inputs.mode,
        phase=OperationPhase.PREPARED.value, started_utc=utc_now_iso(),
        settings_state_before=facts.settings_state,
        # Persisted NOW so a later-process abort needs no caller paths (§8.2).
        fms_database_dir=str(inputs.fms_database_dir), host=inputs.host,
    )
    rec.write(inputs.secrets_dir, record, layout=_secrets_layout(lifecycle_layout))
    _open_journal(journal, lock, record=record)
    return _close_journal(journal, lock, _run_fresh_sequence(
        inputs, record, facts, adapter=adapter, journal=journal,
        lifecycle_layout=lifecycle_layout, template=template, lock=lock))


def _protect_placed_database(inputs: StorageInputs, target_dir: Path, target: Path,
                             lifecycle_layout, *, directory_created_by_this_run: bool) -> None:
    """Give a newly placed POSIX database the authority of FMS's own database directory.

    The destination is derived beneath ``inputs.fms_database_dir``; its owner and group are read
    from that authoritative parent instead of guessed from account names. Windows inherits its
    authority from the FileMaker directory's DACL and is deliberately left to that one authority.
    """
    kind = getattr(lifecycle_layout, "kind", "windows" if os.name == "nt" else "posix")
    if kind == "windows":                       # pragma: no cover - exercised on Windows
        return

    parent = inputs.fms_database_dir.lstat()
    directory = target_dir.lstat()
    placed = target.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        raise StorageOperationRefused("the recorded FMS database directory is not a real directory")
    if not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode):
        raise StorageOperationRefused("the storage directory is not a real directory")
    if not stat.S_ISREG(placed.st_mode) or stat.S_ISLNK(placed.st_mode):
        raise StorageOperationRefused("the placed storage database is not a regular file")

    directory_before = (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode))
    if directory_created_by_this_run:
        os.chown(target_dir, parent.st_uid, parent.st_gid)
        os.chmod(target_dir, 0o770)
    else:
        _validate_preexisting_storage_directory(inputs, target_dir, lifecycle_layout)
    os.chown(target, parent.st_uid, parent.st_gid)
    os.chmod(target, 0o660)

    directory = target_dir.lstat()
    placed = target.lstat()
    directory_after = (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode))
    if directory_created_by_this_run:
        if directory_after != (parent.st_uid, parent.st_gid, 0o770):
            raise StorageOperationRefused("the storage directory authority did not read back")
    elif directory_after != directory_before:
        raise StorageOperationRefused("the pre-existing storage directory metadata changed")
    if (placed.st_uid, placed.st_gid, stat.S_IMODE(placed.st_mode)) != (
            parent.st_uid, parent.st_gid, 0o660):
        raise StorageOperationRefused("the storage database authority did not read back")


def _validate_preexisting_storage_directory(inputs: StorageInputs, target_dir: Path,
                                            lifecycle_layout) -> None:
    """Refuse a foreign directory before any database bytes are copied into it."""
    kind = getattr(lifecycle_layout, "kind", "windows" if os.name == "nt" else "posix")
    if kind == "windows":                       # pragma: no cover - exercised on Windows
        return
    parent = inputs.fms_database_dir.lstat()
    directory = target_dir.lstat()
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        raise StorageOperationRefused("the recorded FMS database directory is not a real directory")
    if not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode):
        raise StorageOperationRefused("the storage directory is not a real directory")
    if ((directory.st_uid, directory.st_gid) != (parent.st_uid, parent.st_gid)
            or directory.st_mode & 0o700 != 0o700
            or directory.st_mode & 0o002):
        raise StorageOperationRefused(
            "the pre-existing storage directory does not carry FileMaker Server authority")


def _run_fresh_sequence(inputs, record, facts, *, adapter, journal, lifecycle_layout,
                        template: Path | None, lock=None) -> StorageReport:
    """Steps 2–10 of §6.2, resumable at every phase boundary."""
    target = si.storage_target(inputs.fms_database_dir)
    target_dir = si.storage_target_dir(inputs.fms_database_dir)

    if _before(record.phase, OperationPhase.TEMPLATE_PLACED):
        # THE LAST GATE BEFORE A DESTRUCTIVE WRITE, and it is checked against the machine rather
        # than against a decision taken earlier in another process.
        #
        # ADDED after the blind implementation review of 2026-08-05, which reproduced a live corpus
        # being overwritten by the blank shipped template: `resume` entered this sequence for a
        # repair operation recorded at PREPARED, `_before` was true, and `shutil.copy2` truncated
        # 45 bytes of customer data. `bootstrap` proves the nine clauses before ever getting here,
        # so the check looked redundant — and it was redundant only on the path that already had
        # it. A destructive step must carry its own precondition.
        if target.exists() and not record.template_placed_by_this_run:
            return _incomplete(
                record, "target_occupied",
                "a database already exists at this installation's storage location and this "
                "operation did not place it; nothing was written.")
        source = template if template is not None else _shipped_template(inputs)
        if source is None or not Path(source).is_file():
            return _incomplete(record, "template_missing",
                               "the shipped storage database was not found in the installation; "
                               "nothing was placed.")
        created_dir = not target_dir.exists()
        if not created_dir:
            try:
                _validate_preexisting_storage_directory(
                    inputs, target_dir, lifecycle_layout)
            except (OSError, StorageOperationRefused) as exc:
                return _incomplete(
                    record, "storage_permissions_failed",
                    f"the pre-existing storage directory is not safe to use: {exc}")
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(source), str(target))
        # The successful copy is recorded before its authority is applied. That makes a caught
        # chown/chmod failure resumable and abortable without prematurely claiming a target that
        # does not yet exist. The historical hard-crash window inside copy2 is unchanged here; it
        # needs operation-bound staging/digest evidence, not a false pre-copy ownership flag.
        record = rec.advance(
            inputs.secrets_dir, record, OperationPhase.TEMPLATE_PLACED.value,
            layout=_secrets_layout(lifecycle_layout),
            target_dir_created_by_this_run=created_dir,
            template_placed_by_this_run=True)
        if lock is not None:
            _checkpoint(journal, lock, "storage:template_placed")
        try:
            _protect_placed_database(
                inputs, target_dir, target, lifecycle_layout,
                directory_created_by_this_run=record.target_dir_created_by_this_run)
        except (OSError, StorageOperationRefused) as exc:
            return _incomplete(
                record, "storage_permissions_failed",
                f"the storage database was placed but FileMaker Server authority could not be "
                f"established: {exc}")
    if _before(record.phase, OperationPhase.HOSTED):
        # Also perform this at the resumable boundary. A process can stop after the copy and before
        # its authority is established; older builds did exactly that, leaving a root-owned 0640
        # file that FMS reported as "Permission denied". Reasserting the same derived authority is
        # idempotent and lets the recorded TEMPLATE_PLACED operation resume without another copy.
        try:
            _protect_placed_database(
                inputs, target_dir, target, lifecycle_layout,
                directory_created_by_this_run=record.target_dir_created_by_this_run)
        except (OSError, StorageOperationRefused) as exc:
            return _incomplete(
                record, "storage_permissions_failed",
                f"the placed storage database is not accessible to FileMaker Server: {exc}")
        try:
            adapter.open_database()
            hosted_ok = adapter.await_status("OPEN")
        except Exception as exc:  # noqa: BLE001
            return _incomplete(record, "host_failed",
                               f"the storage database was placed but could not be hosted: {exc}")
        if not hosted_ok:
            return _incomplete(record, "host_not_observed",
                               "the storage database was placed but never reached OPEN.")
        proof = adapter.probe(BOOTSTRAP_SECRET)
        if _probe_fact(proof) != ProbeFact.ACCEPTED.value:
            return _incomplete(record, "bootstrap_secret_refused",
                               "the placed database did not accept the shipped bootstrap "
                               "credential; it may not be the shipped template.")
        record = rec.advance(inputs.secrets_dir, record, OperationPhase.HOSTED.value,
                             layout=_secrets_layout(lifecycle_layout), hosted_by_this_run=True)

    if _before(record.phase, OperationPhase.SETTINGS_INITIALIZED):
        # THE ONLY initialization call site, and it is guarded by the record's own claim that this
        # operation placed the file. An existing corpus can never reach here.
        if not record.template_placed_by_this_run:
            return _incomplete(record, "initialization_not_authorized",
                               "this operation did not place the storage database, so it will not "
                               "initialize it.")
        try:
            adapter.init_settings(BOOTSTRAP_SECRET)
        except Exception as exc:  # noqa: BLE001
            return _incomplete(record, "settings_init_failed",
                               f"the settings record could not be initialized: {exc}")
        record = rec.advance(inputs.secrets_dir, record,
                             OperationPhase.SETTINGS_INITIALIZED.value,
                             layout=_secrets_layout(lifecycle_layout), settings_initialized_by_this_run=True)
        if lock is not None:
            _checkpoint(journal, lock, "storage:settings_initialized")

    corpus_id = None
    if _before(record.phase, OperationPhase.IDENTITY_ESTABLISHED):
        try:
            corpus_id = _establish_identity(adapter, BOOTSTRAP_SECRET)
        except Exception as exc:  # noqa: BLE001
            return _incomplete(record, "identity_not_established",
                               f"the corpus identity could not be established: {exc}")
        record = rec.advance(inputs.secrets_dir, record,
                             OperationPhase.IDENTITY_ESTABLISHED.value,
                             layout=_secrets_layout(lifecycle_layout), identity_established_by_this_run=True)

    report = _rotate(inputs, record, adapter=adapter, current=BOOTSTRAP_SECRET,
                     lifecycle_layout=lifecycle_layout)
    if report.result != COMPLETED:
        return report
    record = rec.read(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout)) or record

    return _compose(inputs, record, adapter=adapter, lifecycle_layout=lifecycle_layout,
                    corpus_id=corpus_id, mode=inputs.mode)


def _shipped_template(inputs: StorageInputs) -> Path | None:
    # `assets/`, not `src/` (packet 1257): installer-placed bytes are untracked content inside the
    # Git checkout, which a privileged update refuses. Derived from the install root this operation
    # was already given, so it needs no path of its own.
    candidate = (Path(inputs.install_dir) / app_paths.ASSETS_DIRNAME
                 / "db" / si.STORAGE_DATABASE_FILENAME)
    return candidate if candidate.is_file() else None


def _establish_identity(adapter, secret: str) -> str:
    from . import corpus_identity
    from corpusfm.core.crypto import get_corpus_key

    backend = adapter.backend(secret)
    record = corpus_identity.establish_identity(backend, get_corpus_key())
    return str(record["corpus_id"])


def _before(phase: str, target: OperationPhase) -> bool:
    return si.PHASE_ORDER.index(phase) < si.PHASE_ORDER.index(target.value)


def _incomplete(record, code: str, detail: str) -> StorageReport:
    """A mutation may have landed and nothing is worse than before. Resumable."""
    return StorageReport(
        result=INCOMPLETE_SAFE, operation_id=record.operation_id,
        findings=(si.Finding(code, detail),),
        next_action=(f"{detail} Continue with `storage resume --operation-id "
                     f"{record.operation_id}`, or undo it with `storage abort`."),
        unresolved_operation=record.public(),
    )


# ── rotation (§7) ────────────────────────────────────────────────────────────


def _rotate(inputs, record, *, adapter, current: str, lifecycle_layout) -> StorageReport:
    """Stage, change, PROBE, promote. Never promote on a return value alone."""
    if _before(record.phase, OperationPhase.ROTATION_ATTEMPTED):
        candidate_secret = secrets.token_urlsafe(SECRET_ENTROPY_BYTES)
        backup = store.back_up_promoted(inputs.secrets_dir, record.operation_id,
                                        layout=_secrets_layout(lifecycle_layout))
        staged = store.stage(
            inputs.secrets_dir,
            store.StorageAccess(account=AUTOMATION_ACCOUNT, secret=candidate_secret,
                                corpus_id=None, proven_utc=""),
            layout=_secrets_layout(lifecycle_layout),
        )
        record = rec.advance(
            inputs.secrets_dir, record, OperationPhase.ROTATION_ATTEMPTED.value,
            layout=_secrets_layout(lifecycle_layout), remote_change_attempted=True,
            prior_access_backup=str(backup) if backup is not None else None,
            staged_access_path=str(staged),
        )
        try:
            adapter.rotate(current, candidate_secret)
        except Exception:  # noqa: BLE001 — the outcome is established by probing, not by this call
            pass

    return _classify_rotation(inputs, record, adapter=adapter, lifecycle_layout=lifecycle_layout)


def _classify_rotation(inputs, record, *, adapter, lifecycle_layout) -> StorageReport:
    """§7.2's table. Probe candidate, then promoted, then default — and read the answer."""
    staged = store.load_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    promoted = None
    if record.prior_access_backup:
        promoted = store.load_backup(inputs.secrets_dir, record.operation_id,
                                     layout=_secrets_layout(lifecycle_layout))

    candidate_fact = _probe_fact(adapter.probe(staged.secret)) if staged else \
        ProbeFact.NOT_ATTEMPTED.value
    if candidate_fact == ProbeFact.ACCEPTED.value:
        store.promote(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        record = rec.advance(inputs.secrets_dir, record, OperationPhase.CANDIDATE_PROVEN.value,
                             layout=_secrets_layout(lifecycle_layout))
        return StorageReport(result=COMPLETED, operation_id=record.operation_id,
                             next_action="The automation credential was rotated and proven.")

    prior_fact = _probe_fact(adapter.probe(promoted.secret)) if promoted else \
        ProbeFact.NOT_ATTEMPTED.value
    if prior_fact == ProbeFact.ACCEPTED.value:
        store.discard_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        return StorageReport(
            result=NO_CHANGE, operation_id=record.operation_id,
            findings=(si.Finding("rotation_did_not_land",
                                 "the password change did not take effect; the previous "
                                 "credential still works and was kept."),),
            next_action="Nothing was changed. The previous credential is still in force.",
            unresolved_operation=record.public(),
        )

    default_fact = _probe_fact(adapter.probe(BOOTSTRAP_SECRET))
    if default_fact == ProbeFact.ACCEPTED.value:
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id,
            findings=(si.Finding("on_bootstrap_default",
                                 "FileMaker is on the shipped default password."),),
            next_action=("The automation account is on its default password. Run the "
                         "storage-access repair to rotate it."),
            unresolved_operation=record.public(),
        )

    if ProbeFact.INCONCLUSIVE.value in (candidate_fact, prior_fact, default_fact):
        return _incomplete(record, "rotation_inconclusive",
                           "the rotation outcome could not be established because FileMaker "
                           "Server did not answer; nothing was discarded.")

    return StorageReport(
        result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id,
        findings=(si.Finding("no_credential_authenticates",
                             "FileMaker holds a password CORPUSfm does not have."),),
        next_action=RECOVERY_PROCEDURE, unresolved_operation=record.public(),
    )


# ── composition ──────────────────────────────────────────────────────────────


def _compose(inputs, record, *, adapter, lifecycle_layout, corpus_id, mode) -> StorageReport:
    """Verify with the promoted secret, re-read the canary, and return a CANDIDATE. No write."""
    promoted = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    if promoted is None:
        return _incomplete(record, "no_promoted_credential",
                           "no promoted credential is recorded after rotation.")
    verify = adapter.probe(promoted.secret)
    if _probe_fact(verify) != ProbeFact.ACCEPTED.value:
        return _incomplete(record, "odata_not_verified",
                           "the promoted credential did not verify over OData.")

    try:
        canary_id = _require_identity(adapter, promoted.secret)
    except Exception as exc:  # noqa: BLE001
        return _incomplete(record, "canary_unreadable",
                           f"the corpus identity could not be re-read: {exc}")
    if corpus_id is not None and canary_id != corpus_id:
        return _refuse("corpus_id_mismatch",
                       "the corpus identity read back is not the one this operation established.",
                       result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id)

    store.save(
        inputs.secrets_dir,
        store.StorageAccess(account=AUTOMATION_ACCOUNT, secret=promoted.secret,
                            corpus_id=canary_id, proven_utc=utc_now_iso()),
        layout=_secrets_layout(lifecycle_layout),
    )

    settings_state = _settings_value(verify)
    block = StorageBlock(
        database_name=STORAGE_DATABASE_NAME,
        corpus_id=canary_id,
        connection_name=None,
        # NEVER inferred from a config file. True only because SETTINGS was OBSERVED initialized
        # and the canary verified in this run — the fence `bridge.py` already states from its side.
        initialized=settings_state == si.SettingsState.INITIALIZED.value,
    )
    # Round-trip through the schema so a block that the manifest would reject is caught HERE, by
    # the component that built it, rather than by the integrator's write.
    StorageBlock.from_dict(block.to_dict())
    try:
        inspected = _generation_authority(inputs)
    except StorageOperationRefused as exc:
        return _incomplete(record, "generation_divergence", str(exc))
    # THE UNINSTALL AUTHORITY. Bootstrap placed this exact file; adoption proved this exact hosted
    # corpus's identity with the carried key and accepted it as the installation's storage. The
    # developer ruling is that uninstall removes that storage in either case. Record the path now,
    # while the provider still holds the generation, corpus and FMS-directory authority; never make
    # the uninstaller reconstruct it later from a database name or search Removed_by_FMS.
    database_path = si.storage_target(Path(record.fms_database_dir))
    rc_path = database_path.parent / "RC_Data_FMS" / database_path.stem
    candidate = si.StorageCandidate(
        storage=block,
        inspected_generation=inspected,
        inspected_installation_id=inputs.installation_id,
        owned_paths=si.storage_ownership_entries(
            database_path=str(database_path), rc_paths=(str(rc_path),)),
    )
    record = rec.advance(inputs.secrets_dir, record, OperationPhase.AWAITING_COMPOSITION.value,
                         layout=_secrets_layout(lifecycle_layout))

    user_table = _read_user_table(adapter, promoted.secret)
    if mode == "fresh_install" and user_table != si.UserTable.NON_EMPTY.value:
        # §8.4a: a fresh install without a proven administrator is not a success. Storage is fine;
        # the install is not finished, and saying `completed` here is how a box nobody can sign in
        # to gets reported as done.
        return StorageReport(
            result=INCOMPLETE_SAFE, state=StorageState.EXISTING_CORPUS_REACHABLE.value,
            operation_id=record.operation_id, awaiting_composition=True, candidate=candidate,
            findings=(si.Finding("first_administrator_owed",
                                 "storage is ready and no CORPUSfm administrator exists yet."),),
            next_action=("Storage is ready. Create the first CORPUSfm administrator with "
                         "`storage create-first-admin` before reporting the install complete."),
            unresolved_operation=record.public(),
        )

    return StorageReport(
        result=COMPLETED, state=StorageState.EXISTING_CORPUS_REACHABLE.value,
        operation_id=record.operation_id, awaiting_composition=True, candidate=candidate,
        next_action=("Storage is ready. Compose the returned candidate into the installation "
                     "manifest, then call `storage finalize`."),
        unresolved_operation=record.public(),
    )


def _require_identity(adapter, secret: str) -> str:
    from . import corpus_identity

    backend = adapter.backend(secret)
    return str(corpus_identity.require_identity(backend)["corpus_id"])


# ── repair (§10) ─────────────────────────────────────────────────────────────


def repair(inputs: StorageInputs, *, adapter, lock, journal, lifecycle_layout=None) -> StorageReport:
    """Narrow. It rotates, and it does nothing else."""
    _require_brackets(lock, journal)
    _require_published_generation(inputs)

    expectation = _manifest_expectation(inputs, lifecycle_layout)
    if expectation != si.ManifestExpectation.EXPECTS_CORPUS.value:
        return _refuse(
            "no_published_corpus",
            "storage-access repair requires a published installation record naming this "
            "installation's corpus; none was found. Nothing was changed.",
        )

    ev, refusal = _evidence_or_refuse(inputs, journal, lifecycle_layout, "repair", lock=lock)
    if refusal is not None:
        return refusal

    facts = collect_facts(inputs, adapter=adapter, lifecycle_layout=lifecycle_layout)
    try:
        state = si.classify(facts)
    except si.RelationViolated as exc:
        return _refuse("relation_violated", str(exc), facts=facts)

    if state == StorageState.EXISTING_CORPUS_REACHABLE.value:
        return StorageReport(result=NO_CHANGE, state=state, facts=facts,
                             next_action="The stored storage credential already works.")
    if state == StorageState.EXISTING_CORPUS_UNREADABLE.value:
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=(si.Finding("no_credential_authenticates",
                                 "no known credential opens the storage database."),),
            next_action=RECOVERY_PROCEDURE,
        )
    if state != StorageState.EXISTING_CORPUS_ON_DEFAULT.value:
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=(si.Finding("repair_not_applicable",
                                 f"storage-access repair does not act on state {state}."),),
            next_action=si.next_action_for(state),
        )

    operation_id = str(uuid.uuid4())
    record = rec.OperationRecord(
        operation_id=operation_id, installation_id=inputs.installation_id, mode=inputs.mode,
        phase=OperationPhase.PREPARED.value, started_utc=utc_now_iso(),
        settings_state_before=facts.settings_state,
        # Persisted NOW so a later-process abort needs no caller paths (§8.2).
        fms_database_dir=str(inputs.fms_database_dir), host=inputs.host,
    )
    rec.write(inputs.secrets_dir, record, layout=_secrets_layout(lifecycle_layout))
    _open_journal(journal, lock, record=record)

    report = _rotate(inputs, record, adapter=adapter, current=BOOTSTRAP_SECRET,
                     lifecycle_layout=lifecycle_layout)
    if report.result != COMPLETED:
        return _close_journal(journal, lock, report)
    record = rec.read(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout)) or record

    promoted = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    try:
        canary_id = _require_identity(adapter, promoted.secret)
    except Exception as exc:  # noqa: BLE001
        return _close_journal(journal, lock, _incomplete(
            record, "canary_unreadable",
            f"the corpus identity could not be re-read after rotation: {exc}"))
    expected_id = _published_corpus_id(inputs)
    if expected_id and canary_id != expected_id:
        return _close_journal(journal, lock, StorageReport(
            result=MANUAL_ACTION_REQUIRED, state=StorageState.CONFLICTING_EVIDENCE.value,
            operation_id=record.operation_id,
            findings=(si.Finding("corpus_id_mismatch",
                                 "the database now reachable is not this installation's corpus."),),
            next_action=("The database reachable at this location is not this installation's "
                         "corpus. Stop and resolve which database this installation owns."),
        ))

    store.save(
        inputs.secrets_dir,
        store.StorageAccess(account=AUTOMATION_ACCOUNT, secret=promoted.secret,
                            corpus_id=canary_id, proven_utc=utc_now_iso()),
        layout=_secrets_layout(lifecycle_layout),
    )
    rec.advance(inputs.secrets_dir, record, OperationPhase.RESOLVED.value, layout=_secrets_layout(lifecycle_layout))
    rec.discharge(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    store.discard_backup(inputs.secrets_dir, record.operation_id, layout=_secrets_layout(lifecycle_layout))
    return _close_journal(journal, lock, StorageReport(
        result=COMPLETED, state=StorageState.EXISTING_CORPUS_REACHABLE.value,
        operation_id=record.operation_id,
        next_action="Storage access was repaired. Restart the CORPUSfm service if it is running.",
    ))


# ── adopt (packet 1246-10-04) ────────────────────────────────────────────────


def adopt(inputs: StorageInputs, *, adapter, lock, journal, lifecycle_layout=None) -> StorageReport:
    """Compose an EXISTING corpus that this fresh installation does not yet publish.

    **The gap this closes.** A fresh install had exactly two storage destinations: bootstrap a
    corpus this run PLACES, or repair one the manifest ALREADY publishes. A retained corpus is
    neither — it exists, it is initialized, it carries its own identity and accounts, and the new
    installation carries nothing that reaches it. Measured on fms-server 2026-08-08: phase 18
    refused, and no supported route existed.

    **It creates nothing.** No template placement, no `init_settings`, no `establish_identity`, no
    file write of any kind — it starts at the rotation `bootstrap` reaches only after all three, and
    the classifier state it requires is only reachable when SETTINGS is already initialized. The
    identity is REQUIRED to exist, read before any mutation; a corpus without one is refused, not
    given one.

    **The credential is never inferred.** The one secret it may use is the shipped default, which
    the administrator restores in FileMaker Pro (§10.4) and which `EXISTING_CORPUS_ON_DEFAULT`
    already proves was accepted over OData in this same observation.
    """
    _require_brackets(lock, journal)
    _require_published_generation(inputs)

    # BOTH ORDINARY MODES, AND ONLY THOSE (developer ruling, 2026-08-09). Adoption's subject is a
    # retained corpus that answers on its default credential over a record publishing no storage.
    # That is one situation, and the invocation's MODE describes the invocation, not the corpus: a
    # box whose generation has advanced through admin identity, patch and proxy calls itself
    # `forward_update` while its storage is still unowned, and refusing it there left the corpus
    # unadoptable by any route. Measured on winfms2026, 2026-08-09, at generation 15, after the
    # router had already been corrected to send exactly this case here.
    #
    # THE AUTHORITY IS UNCHANGED AND IS BELOW, NOT HERE: no published expectation, the classifier
    # reporting EXISTING_CORPUS_ON_DEFAULT, the database OPEN, an established identity that the
    # carried Corpus Key opens, and the default credential this same observation already proved
    # accepted. This gate only stops the two modes that must never adopt — `repair_storage_access`,
    # which has its own verb, and `uninstall`, which composes nothing.
    if inputs.mode not in ("fresh_install", "forward_update"):
        return _refuse(
            "adopt_not_applicable",
            f"adoption is reached from an ordinary install or update; this invocation is "
            f"{inputs.mode!r}.")

    expectation = _manifest_expectation(inputs, lifecycle_layout)
    if expectation != si.ManifestExpectation.NO_EXPECTATION.value:
        return _refuse(
            "manifest_already_speaks",
            "adoption requires an installation record that publishes no corpus; this one reports "
            f"{expectation!r}. Nothing was changed.")

    ev, refusal = _evidence_or_refuse(inputs, journal, lifecycle_layout, "adopt", lock=lock)
    if refusal is not None:
        return refusal

    facts = collect_facts(inputs, adapter=adapter, lifecycle_layout=lifecycle_layout)
    try:
        state = si.classify(facts)
    except si.RelationViolated as exc:
        return _refuse("relation_violated", str(exc), facts=facts)

    if state != StorageState.EXISTING_CORPUS_ON_DEFAULT.value:
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=(si.Finding(
                "adopt_not_applicable",
                f"adoption acts only on an initialized corpus answering on its default "
                f"credential; this machine reports {state}."),),
            next_action=si.next_action_for(state),
        )
    # HOSTED IS ITS OWN AXIS. The classifier separates states on credentials and settings; that a
    # named database is OPEN in FileMaker Server is a different fact, and adopting one the server
    # does not currently serve would compose a corpus nothing can reach.
    if facts.hosted_state != si.HostedState.OPEN.value:
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=(si.Finding(
                "corpus_not_hosted",
                f"FileMaker Server does not report {STORAGE_DATABASE_NAME} as open "
                f"(hosted_state={facts.hosted_state}); nothing was changed."),),
            next_action=(f"Host {STORAGE_DATABASE_NAME} in FileMaker Server, then run this step "
                         "again."),
        )
    # BEFORE ANY MUTATION. An existing corpus that carries no identity is not this installation's
    # to establish one for — that is the bootstrap sequence's step, guarded by its own record.
    try:
        corpus_id = _require_identity(adapter, BOOTSTRAP_SECRET)
    except Exception as exc:  # noqa: BLE001
        return StorageReport(
            result=FAILED_BEFORE_CHANGE, state=state, facts=facts,
            findings=(si.Finding(
                "corpus_identity_absent",
                f"the existing corpus carries no readable identity: {exc}"),),
            next_action=("This database has no corpus identity and CORPUSfm will not establish "
                         "one for a corpus it did not create. Nothing was changed."),
        )

    operation_id = str(uuid.uuid4())
    record = rec.OperationRecord(
        operation_id=operation_id, installation_id=inputs.installation_id, mode=inputs.mode,
        # IDENTITY_ESTABLISHED, and every `*_by_this_run` flag stays false. The phase says what is
        # already TRUE of the corpus, so a resume continues at the rotation and an abort undoes the
        # rotation alone — it can never delete or re-place a database this run did not place.
        phase=OperationPhase.IDENTITY_ESTABLISHED.value, started_utc=utc_now_iso(),
        settings_state_before=facts.settings_state,
        fms_database_dir=str(inputs.fms_database_dir), host=inputs.host,
    )
    rec.write(inputs.secrets_dir, record, layout=_secrets_layout(lifecycle_layout))
    _open_journal(journal, lock, record=record)

    report = _rotate(inputs, record, adapter=adapter, current=BOOTSTRAP_SECRET,
                     lifecycle_layout=lifecycle_layout)
    if report.result != COMPLETED:
        return _close_journal(journal, lock, report)
    record = rec.read(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout)) or record

    report = _compose(inputs, record, adapter=adapter, lifecycle_layout=lifecycle_layout,
                      corpus_id=corpus_id, mode=inputs.mode)
    # PROTOCOL F: A COMPOSED CANDIDATE LEAVES THE BRACKET OPEN for `commit-provider` and `finalize`.
    #
    # `_close_journal` resolves on `completed`, and `_compose` answers `completed` on the branch a
    # bootstrap never reaches: a corpus that ALREADY HAS users. A fresh install's own corpus has an
    # empty USER table, so bootstrap always takes the `incomplete_safe` branch and its bracket
    # stays open by accident of the data rather than by rule. Adoption reached the other branch on
    # fms-server 2026-08-08, resolved the journal, and `commit-provider` refused `ProviderMismatch`
    # with the candidate already proven and the credential already rotated.
    if report.awaiting_composition:
        return report
    return _close_journal(journal, lock, report)


def _published_corpus_id(inputs: StorageInputs) -> str | None:
    try:
        manifest = _read_manifest(inputs)
    except Exception:  # noqa: BLE001
        return None
    block = getattr(manifest, "storage", None)
    return getattr(block, "corpus_id", None) if block is not None else None


# ── resume / abort / finalize ────────────────────────────────────────────────


def resume(inputs: StorageInputs, operation_id: str, *, adapter, lock, journal,
           lifecycle_layout=None, template: Path | None = None) -> StorageReport:
    """Continue ONLY the work this exact operation already authorized."""
    _require_brackets(lock, journal)
    _require_published_generation(inputs)

    matched, refusal = _require_matching_operation(
        inputs, operation_id, journal, lifecycle_layout, "resume", lock=lock)
    if refusal is not None:
        return refusal
    _ev, record = matched
    if record.phase == OperationPhase.AWAITING_COMPOSITION.value:
        return StorageReport(
            result=NO_CHANGE, operation_id=operation_id, awaiting_composition=True,
            next_action=("That operation is waiting for the installation manifest to be composed. "
                         "Call `storage finalize` after the manifest write."),
            unresolved_operation=record.public(),
        )

    facts = collect_facts(inputs, adapter=adapter, lifecycle_layout=lifecycle_layout)
    disagreement = _phase_disagrees(record, facts)
    if disagreement is not None:
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED, operation_id=operation_id, facts=facts,
            findings=(si.Finding("phase_facts_disagree", disagreement),),
            next_action=(f"{disagreement} Nothing was re-done. Inspect the machine, then abort "
                         f"the operation if it cannot be continued."),
            unresolved_operation=record.public(),
        )

    if record.phase in (OperationPhase.ROTATION_ATTEMPTED.value,
                        OperationPhase.CANDIDATE_PROVEN.value):
        report = _classify_rotation(inputs, record, adapter=adapter,
                                    lifecycle_layout=lifecycle_layout)
        if report.result != COMPLETED:
            return report
        record = rec.read(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout)) or record
        return _compose(inputs, record, adapter=adapter, lifecycle_layout=lifecycle_layout,
                        corpus_id=None, mode=record.mode)

    # RESUME CONTINUES ONLY THE WORK THIS OPERATION AUTHORIZED, and the record's OWN mode is what
    # says which work that was — never the mode of the request now asking to continue.
    #
    # CORRECTED after the blind implementation review of 2026-08-05. The first implementation routed
    # every record before ROTATION_ATTEMPTED into the fresh sequence regardless of what the
    # operation had been, so resuming an interrupted REPAIR provisioned a fresh corpus over the one
    # it was repairing. A repair never places, hosts, initializes or establishes identity; the only
    # thing it can continue is its rotation.
    # AN ADOPTION INTERRUPTED BEFORE ITS ROTATION (developer ruling, 2026-08-09). An adoption places
    # nothing and initializes nothing; its first mutation is the rotation, so a `forward_update`
    # record still at `identity_established` has not rotated at all. `_classify_rotation` cannot
    # continue it — there is no attempt to classify — and answering from the shipped default would
    # report `on_bootstrap_default` for a box that is exactly where its own operation left it.
    #
    # Measured on winfms2026, 2026-08-09, operation ed0609f6: the record sat at
    # `identity_established`, FileMaker still accepted the shipped default, a staged candidate
    # existed that FileMaker had never accepted, and no promoted record existed. The staging write
    # had landed and its read-back had refused, so the rotation was never attempted. What follows is
    # therefore the FIRST rotation of this operation, not a second one.
    if record.mode == "forward_update" \
            and _before(record.phase, OperationPhase.ROTATION_ATTEMPTED):
        residue = _pre_rotation_residue(inputs, adapter, lifecycle_layout)
        if residue is not None:
            return residue
        report = _rotate(inputs, record, adapter=adapter, current=BOOTSTRAP_SECRET,
                         lifecycle_layout=lifecycle_layout)
        if report.result != COMPLETED:
            return report
        record = rec.read(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout)) or record
        return _compose(inputs, record, adapter=adapter, lifecycle_layout=lifecycle_layout,
                        corpus_id=None, mode=record.mode)

    if record.mode != "fresh_install":
        return _classify_rotation(inputs, record, adapter=adapter,
                                  lifecycle_layout=lifecycle_layout)

    return _run_fresh_sequence(inputs, record, facts, adapter=adapter, journal=journal,
                               lifecycle_layout=lifecycle_layout, template=template)


def _pre_rotation_residue(inputs, adapter, lifecycle_layout) -> StorageReport | None:
    """An UNRECORDED staged candidate found before any rotation was attempted, judged conservatively.

    The record says no rotation happened; the file says a candidate was written. Only one reading
    makes discarding it safe — the staged value is REJECTED and the shipped default is ACCEPTED,
    which together say the write landed and the change never reached FileMaker. Anything else is
    refused untouched: a staged value that authenticates may be the live credential, a default that
    does not authenticate means something holds a password this record cannot account for, and an
    inconclusive or unreadable answer is not an answer.
    """
    try:
        staged = store.load_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    except Exception as exc:                       # noqa: BLE001
        return _refuse(
            "staged_residue_unreadable",
            f"a staged credential is present and could not be read ({type(exc).__name__}); "
            "nothing was rotated, discarded or promoted.")
    if staged is None:
        return None

    staged_fact = _probe_fact(adapter.probe(staged.secret))
    default_fact = _probe_fact(adapter.probe(BOOTSTRAP_SECRET))
    if staged_fact == ProbeFact.ACCEPTED.value:
        return _refuse(
            "staged_residue_authenticates",
            "a staged credential this operation never recorded rotating IS accepted by FileMaker "
            "Server; refusing to discard or replace a credential that may be the live one.")
    if ProbeFact.INCONCLUSIVE.value in (staged_fact, default_fact):
        return _refuse(
            "residue_inconclusive",
            "FileMaker Server did not answer clearly about the staged or default credential; "
            "nothing was rotated, discarded or promoted.")
    if default_fact != ProbeFact.ACCEPTED.value:
        return _refuse(
            "default_does_not_authenticate",
            "the staged credential is rejected and the shipped default is not accepted either; "
            "FileMaker holds a password this operation cannot account for. Nothing was changed.")
    return None


def _phase_disagrees(record, facts) -> str | None:
    """A record that claims a mutation the machine does not show is not silently re-done."""
    placed = si.PHASE_ORDER.index(record.phase) >= si.PHASE_ORDER.index(
        OperationPhase.TEMPLATE_PLACED.value)
    if placed and record.template_placed_by_this_run \
            and facts.target_file == si.TargetFile.ABSENT.value:
        return ("the operation record says this run placed the storage database, but no file is "
                "present at the installation's storage location.")
    return None


def abort(operation_id: str, installation_id: str, actor: str, *, adapter=None, lock, journal,
          lifecycle_layout=None) -> StorageReport:
    """Remove only what this run placed; restore only what is restorable. Never claim more.

    **Takes NO paths and no host.** §8.2's abort request carries none, and both facts it needs —
    the FMS databases directory and the host — were persisted by the operation itself when it
    began. `adapter` remains injectable for tests; in production it is built from the RECORD.
    """
    _require_brackets(lock, journal)

    secrets_dir = recovery_secrets_dir(lifecycle_layout)
    inputs = _recovery_inputs(secrets_dir, installation_id, actor)
    matched, refusal = _require_matching_operation(
        inputs, operation_id, journal, lifecycle_layout, "abort", lock=lock)
    if refusal is not None:
        return refusal
    _ev, record = matched
    if adapter is None:
        adapter = _adapter_from_record(record, secrets_dir)
    if record.phase == OperationPhase.AWAITING_COMPOSITION.value:
        return _refuse(
            "already_composed",
            "that operation has already produced a candidate for the installation manifest and "
            "will not be aborted on a guess. Finalize it, or decide explicitly what to undo.",
        )

    undone: list[str] = []
    if record.remote_change_attempted:
        restored, did_restore = _restore_remote(inputs, record, adapter=adapter,
                                                lifecycle_layout=lifecycle_layout)
        if restored is not None:
            return restored
        # ONLY claim a restoration that actually happened. The first version appended this line
        # unconditionally, so an abort with nothing to restore reported that it had restored the
        # automation credential — a false statement in the one report an administrator reads to
        # decide whether the box is safe.
        if did_restore:
            undone.append("the previous automation credential was restored")

    if record.hosted_by_this_run:
        try:
            adapter.close_database()
            adapter.await_status("CLOSED")
            undone.append("the storage database was closed")
        except Exception:  # noqa: BLE001
            return StorageReport(
                result=MANUAL_ACTION_REQUIRED, operation_id=operation_id,
                findings=(si.Finding("close_failed",
                                     "the storage database could not be closed."),),
                next_action=("The storage database this run hosted could not be closed. Close it "
                             "in the FileMaker Server admin console, then abort again."),
                unresolved_operation=record.public(),
            )

    if record.template_placed_by_this_run:
        if not record.fms_database_dir:
            return StorageReport(
                result=MANUAL_ACTION_REQUIRED, operation_id=operation_id,
                findings=(si.Finding("target_location_unrecorded",
                                     "the operation record does not name the databases directory "
                                     "it placed into."),),
                next_action=("This operation placed a storage database but its record does not say "
                             "where. Nothing was removed. Inspect the FileMaker Server databases "
                             "directory before continuing."),
                unresolved_operation=record.public(),
            )
        target = si.storage_target(record.fms_database_dir)
        try:
            if target.exists():
                target.unlink()
            undone.append("the storage database this run placed was removed")
            if record.target_dir_created_by_this_run:
                parent = si.storage_target_dir(record.fms_database_dir)
                if parent.is_dir() and not any(parent.iterdir()):
                    parent.rmdir()
        except OSError as exc:
            return StorageReport(
                result=MANUAL_ACTION_REQUIRED, operation_id=operation_id,
                findings=(si.Finding("removal_failed", str(exc)),),
                next_action=(f"The storage database this run placed could not be removed "
                             f"({exc}). Remove it manually, then abort again."),
                unresolved_operation=record.public(),
            )

    # Deliberately does NOT claim SETTINGS was un-initialized or the identity un-established. Both
    # are irreversible; their only reversal is removing the file, which is what the message says.
    report = StorageReport(
        result=ROLLED_BACK, operation_id=operation_id,
        next_action=("The operation was undone: " + "; ".join(undone) + "."
                     if undone else "The operation was undone; nothing had been changed yet."),
    )

    # Resolve BEFORE retiring the evidence.  A crash after resolution leaves a matching-resolved
    # operation that the next abort safely discharges; the reverse order strands an unresolved
    # journal with no record proving what it belonged to.
    try:
        journal.resolve(lock=lock, result=report.result)
        closed = journal.read()
        if (closed is None or closed.operation_id != record.operation_id
                or closed.installation_id != record.installation_id
                or closed.state != JOURNAL_RESOLVED):
            raise StorageOperationRefused("the lifecycle journal did not read back as resolved")
    except Exception as exc:  # noqa: BLE001
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED, operation_id=operation_id,
            findings=(si.Finding("journal_resolution_failed", str(exc)),),
            next_action=("The storage changes were undone, but the lifecycle journal could not be "
                         "resolved. Its operation evidence was retained; run abort again."),
            unresolved_operation=record.public(),
        )

    try:
        store.discard_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        store.discard_backup(inputs.secrets_dir, record.operation_id,
                             layout=_secrets_layout(lifecycle_layout))
        rec.discharge(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    except Exception as exc:  # noqa: BLE001
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED, operation_id=operation_id,
            findings=(si.Finding("resolved_evidence_retained", str(exc)),),
            next_action=("The storage operation was undone and its journal resolved, but its "
                         "terminal evidence could not be retired. Run abort again."),
            unresolved_operation=record.public(),
        )
    return report


def _restore_remote(inputs, record, *, adapter, lifecycle_layout):
    """Put the previous FileMaker password back. Returns ``(refusal_or_None, did_restore)``.

    **CORRECTED in the closure round of 2026-08-05 (Codex fix 3).** The first version looked for
    the candidate authority in the STAGED file only — and ``promote()`` consumes that file, so at
    CANDIDATE_PROVEN there was never a staged candidate to find. The prior secret no longer
    authenticates (it was just rotated away), so every abort at that phase fell straight through to
    "no held credential authenticates" and printed the offline CORPUSfm-Admin procedure, while
    holding, in the canonical record, a credential that authenticates perfectly.

    **At CANDIDATE_PROVEN the PROMOTED record IS the candidate authority.** The order below tries
    every authority this component legitimately holds, in the order that makes each attempt
    informative:

      1. the prior secret — if it already works, FileMaker was never changed; restore locally only;
      2. the staged candidate, when one survives (a crash before promotion);
      3. the PROMOTED record — the CANDIDATE_PROVEN case, which is the whole of this correction.

    Every step is idempotent: each begins by asking whether the prior secret already authenticates,
    so a retry after a partial recovery resumes rather than repeating.
    """
    prior = None
    if record.prior_access_backup:
        prior = store.load_backup(inputs.secrets_dir, record.operation_id,
                                  layout=_secrets_layout(lifecycle_layout))
    if prior is None:
        # A fresh install has no prior secret: the way back is removing the placed file, and the
        # caller does that next. Nothing to restore, and nothing to claim.
        return None, False

    # (1) IDEMPOTENCE, and the cheapest proof: the prior secret already works.
    if _probe_fact(adapter.probe(prior.secret)) == ProbeFact.ACCEPTED.value:
        local = _restore_local(inputs, record, prior, lifecycle_layout)
        if local is not None:
            return local, False
        return None, True

    # (2) and (3): every authority this operation may still hold, most-recent first.
    authorities = []
    staged = store.load_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    if staged is not None:
        authorities.append(staged.secret)
    promoted = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    if promoted is not None and promoted.secret not in authorities:
        authorities.append(promoted.secret)

    inconclusive = False
    for secret in authorities:
        fact = _probe_fact(adapter.probe(secret))
        if fact == ProbeFact.INCONCLUSIVE.value:
            inconclusive = True
            continue
        if fact != ProbeFact.ACCEPTED.value:
            continue
        adapter.rotate(secret, prior.secret)
        # The RETURN is not the proof; the probe is. `reset_automation_password` can report
        # `ok=False, changed=True`, and a crash can land anywhere in the call.
        back = _probe_fact(adapter.probe(prior.secret))
        if back == ProbeFact.ACCEPTED.value:
            local = _restore_local(inputs, record, prior, lifecycle_layout)
            if local is not None:
                return local, False
            return None, True
        if back == ProbeFact.INCONCLUSIVE.value:
            inconclusive = True

    if inconclusive:
        # Nothing is established, and NOTHING is discarded. The staged file, the backup and the
        # record all stand, so a retry resumes from exactly here.
        return StorageReport(
            result=INCOMPLETE_SAFE, operation_id=record.operation_id,
            findings=(si.Finding("restoration_inconclusive",
                                 "FileMaker Server did not answer, so the restoration could not "
                                 "be established. Nothing was discarded."),),
            next_action=("The previous automation credential could not be confirmed because "
                         "FileMaker Server did not answer. Nothing was discarded; abort this "
                         "operation again once the server responds."),
            unresolved_operation=record.public(),
        ), False

    return StorageReport(
        result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id,
        findings=(si.Finding("cannot_restore_credential",
                             "no held credential authenticates, so the previous password cannot "
                             "be restored."),),
        next_action=RECOVERY_PROCEDURE, unresolved_operation=record.public(),
    ), False


def _restore_local(inputs, record, prior, lifecycle_layout) -> StorageReport | None:
    """Put the prior record back and VERIFY it. A restore that half-landed is not a restore."""
    try:
        store.restore_from_backup(inputs.secrets_dir, record.operation_id, layout=_secrets_layout(lifecycle_layout))
        back = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    except Exception as exc:  # noqa: BLE001
        back = None
        detail = str(exc)
    else:
        detail = "the restored record did not read back as the previous credential"
    if back is not None and back.secret == prior.secret:
        # FileMaker and the local record now agree on the prior secret, so the candidate is dead.
        store.discard_staged(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
        return None
    return StorageReport(
        result=MANUAL_ACTION_REQUIRED, operation_id=record.operation_id,
        findings=(si.Finding("local_restore_unverified", detail),),
        next_action=("FileMaker now holds the previous automation credential, but this "
                     "installation's own record of it could not be restored and verified. "
                     "Nothing was discarded. Re-run the abort; if it continues to fail, use the "
                     "storage-access repair."),
        unresolved_operation=record.public(),
    )


def _adapter_from_record(record, secrets_dir):
    """The adapter a RECOVERY verb uses, built from the operation's own recorded facts."""
    from . import storage_identity_adapter

    return storage_identity_adapter.LiveStorageAdapter(
        host=record.host or "localhost", secrets_dir=secrets_dir)


def recovery_secrets_dir(lifecycle_layout=None) -> Path:
    """The secrets directory for a RECOVERY verb, DERIVED from the fixed OS layout.

    ``finalize`` and ``abort`` run in a fresh process after the operation they discharge, and
    §8.2's request for each carries no paths. That is deliberate: their authority is the strict
    operation record plus the fixed layout, and accepting a path here would let a caller aim a
    recovery at a directory of its choosing — the caller-selected authority this component refuses
    everywhere else.
    """
    from . import os_layout as _os_layout

    return Path(_os_layout.platform_os_layout().secrets_dir)


def finalize(operation_id: str, installation_id: str, committed_generation: int, actor: str, *,
             lock, journal, lifecycle_layout=None) -> StorageReport:
    """Prove the manifest write happened, then retire the evidence an abort would restore from.

    **Takes NO paths.** It resolves the secrets directory from the fixed layout and every other
    fact it needs from the operation record the operation itself persisted.

    Takes the LOCK: it deletes the backups an abort restores from, and two of those running at once
    is a lost restore point.
    """
    _require_brackets(lock, journal)
    if committed_generation < 1:
        return _refuse("generation_not_committed",
                       "committed_generation must be a positive integer: a written manifest is at "
                       "least generation 1.")
    secrets_dir = recovery_secrets_dir(lifecycle_layout)
    probe_inputs = _recovery_inputs(secrets_dir, installation_id, actor)
    matched, refusal = _require_matching_operation(
        probe_inputs, operation_id, journal, lifecycle_layout, "finalize", lock=lock)
    if refusal is not None:
        return refusal
    _ev, record = matched

    store.discard_staged(secrets_dir, layout=_secrets_layout(lifecycle_layout))
    store.discard_backup(secrets_dir, operation_id, layout=_secrets_layout(lifecycle_layout))
    rec.advance(secrets_dir, record, OperationPhase.RESOLVED.value, layout=_secrets_layout(lifecycle_layout))
    rec.discharge(secrets_dir, layout=_secrets_layout(lifecycle_layout))
    _close_journal(journal, lock, StorageReport(result=COMPLETED))
    return StorageReport(result=COMPLETED, operation_id=operation_id,
                         next_action="The storage operation is complete.")


@dataclass(frozen=True)
class _RecoveryInputs:
    """The subset a recovery verb needs. NOT a `StorageInputs`: it carries no install dir, no FMS
    root, no database dir and no expected generation, because §8.2's request supplies none and
    inventing them would be inventing authority."""

    installation_id: str
    secrets_dir: Path
    actor: str


def _recovery_inputs(secrets_dir: Path, installation_id: str, actor: str) -> _RecoveryInputs:
    return _RecoveryInputs(installation_id=installation_id, secrets_dir=secrets_dir, actor=actor)


# ── the first administrator (§8.4) ───────────────────────────────────────────


def create_first_admin(inputs: StorageInputs, username: str, transport: str, *, adapter, lock,
                       journal, lifecycle_layout=None) -> StorageReport:
    """A different authority from storage bootstrap, with its own proof."""
    _require_brackets(lock, journal)
    _require_published_generation(inputs)

    from corpusfm.app.web import users

    cleaned = (username or "").strip()
    if not cleaned or not cleaned.replace("_", "").replace("-", "").replace(".", "").isalnum():
        return _refuse("invalid_username",
                       "the administrator username must be alphanumeric (plus _ . -).")

    promoted = store.load(inputs.secrets_dir, layout=_secrets_layout(lifecycle_layout))
    if promoted is None:
        return _refuse("no_storage_credential",
                       "no storage credential is recorded, so the user store cannot be reached.")

    backend = adapter.backend(promoted.secret)
    try:
        exists = users.users_exist(backend=backend, raise_on_error=True)
    except Exception as exc:  # noqa: BLE001 — an outage is UNKNOWN, never an empty user store
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED, state=None,
            findings=(si.Finding("user_table_unknown", str(exc)),),
            next_action=("Whether a CORPUSfm administrator exists could not be determined because "
                         "storage was unreachable. No account was created. Once storage is back, "
                         "create one with: corpusfm users create <name> --admin"),
        )
    if exists:
        return StorageReport(result=NO_CHANGE,
                             next_action="A CORPUSfm administrator already exists; nothing was "
                                         "changed and existing users were preserved.")

    try:
        secret = read_transport(transport)
    except TransportRefused as exc:
        return _refuse("credential_transport_refused", str(exc))

    try:
        users.create_user(cleaned, secret, set(users.GATES), created_by="installer",
                          backend=backend)
    except Exception as exc:  # noqa: BLE001
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED,
            findings=(si.Finding("create_failed", str(exc)),),
            next_action=("The CORPUSfm administrator could not be created, so this installation "
                         "has no way in. Fix the reported error and create one with: "
                         "corpusfm users create <name> --admin"),
        )
    finally:
        secret = ""

    if not users.users_exist(backend=backend, raise_on_error=True):
        return StorageReport(
            result=MANUAL_ACTION_REQUIRED,
            findings=(si.Finding("create_not_confirmed",
                                 "the account was created but did not read back."),),
            next_action=("The administrator account did not read back after creation. Verify the "
                         "storage database before relying on this installation."),
        )
    return StorageReport(result=COMPLETED,
                         next_action=f"The first CORPUSfm administrator '{cleaned}' was created.")


__all__ = [
    "RECOVERY_PROCEDURE",
    "SECRET_ENTROPY_BYTES",
    "StorageOperationRefused",
    "StorageReport",
    "TransportRefused",
    "abort",
    "bootstrap",
    "collect_facts",
    "create_first_admin",
    "finalize",
    "observe",
    "read_transport",
    "repair",
    "resume",
]
