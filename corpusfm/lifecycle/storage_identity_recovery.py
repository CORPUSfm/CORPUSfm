"""The operation-bound storage record (packet 1246-08 §5.4, §9.4).

This is a separate module from the operations because ``resume``, ``abort`` and ``finalize`` must
read it in a FRESH PROCESS with nothing carried in memory, and because 1246-01's secret fence
forbids the record from holding material — so the record names PATHS and phases, and this is where
that rule lives.

Two things it must get right, both learned from 1246-07's ledger rather than rediscovered:

* **Strict parsing.** ``bool("false")`` is ``True`` and ``str(None)`` is ``"None"``. A record parsed
  loosely turns a missing field into a plausible value, which is how an ABSENT thing becomes a
  PRESENT one and a record naming ``/etc/hosts`` selects a file.
* **Evidence is written BEFORE the journal is opened, and retired AFTER the journal resolves.** The
  opposite ordering leaves a crash window in which the journal says finished and the record says
  mid-flight, after which an abort performs a whole restore and only then discovers it was already
  resolved.

The record is storage-specific ON PURPOSE. The lifecycle journal is shared by eight modes; an
interrupted proxy operation is not evidence about storage, and a component that treated it as such
would resume somebody else's work.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .errors import LifecycleError
from .admin_identity_store import pinned_secrets_dir, SecretsDirRefused, validated_secrets_dir
from .schema import JOURNAL_RESOLVED
from .storage_identity import OperationEvidence, OperationPhase, PHASE_ORDER

RECORD_FILENAME = "storage_operation.json"
RECORD_FILE_MODE = 0o600
RECORD_VERSION = 1

#: The ONE crash-window disposition: a storage record at PREPARED whose `journal.begin` never
#: landed. Every phase after PREPARED is reached only after a product mutation, so a PREPARED
#: record that claims none is PROVEN INERT — it may be discharged, and nothing else. It is
#: deliberately NOT an `OperationEvidence` member: it is not a matching operation, and a caller
#: that treats it as one is doing the thing this value exists to prevent.
EVIDENCE_INERT_PREPARED = "inert_prepared"

#: A RESOLVED storage record beside its OWN journal entry that is still open, checkpointed or
#: needing recovery. The work finished; the journal was never closed. This is TERMINAL WORK
#: AWAITING JOURNAL RESOLUTION — not ordinary resumable work, and not authority for anything new.
#: Its one disposition is: resolve that journal, then retire the evidence.
EVIDENCE_TERMINAL_PENDING_JOURNAL = "terminal_pending_journal"

#: A RESOLVED storage record with NO corresponding journal entry. Terminal, with nothing to
#: resolve. It must not be labelled MATCHING_RESOLVED (there is no matching entry to have been
#: resolved) and must not silently authorize new work.
EVIDENCE_TERMINAL_NO_JOURNAL = "terminal_no_journal"

#: Everything that is dischargeable but is NOT operation authority. A consumer that treats any of
#: these as a matching operation is doing what this set exists to prevent — which is exactly the
#: defect the closure inspection reproduced for `EVIDENCE_INERT_PREPARED`.
NON_AUTHORITY_DISPOSITIONS: frozenset[str] = frozenset({
    EVIDENCE_INERT_PREPARED,
    EVIDENCE_TERMINAL_PENDING_JOURNAL,
    EVIDENCE_TERMINAL_NO_JOURNAL,
    OperationEvidence.MATCHING_RESOLVED.value,
})


class OperationRecordError(LifecycleError):
    """The record is unreadable, malformed, or names something it may not."""


@dataclass(frozen=True)
class OperationRecord:
    """Names PATHS and phases; holds no material.

    ``prior_access_backup`` / ``staged_access_path`` are named the way they are because 1246-01's
    ``secret_guard`` denies the tokens ``credential``, ``secret``, ``key``, ``password`` and
    ``token`` in any structured payload. The first frame called these ``credential_backup`` and
    ``credential_stage``, which could never have been emitted — the same collision 1246-07 hit with
    ``credentials_required`` and resolved by renaming rather than by weakening the fence.
    """

    operation_id: str
    installation_id: str
    mode: str
    phase: str
    started_utc: str
    #: Persisted AT OPERATION START so a later-process `abort` needs no caller paths. §8.2's abort
    #: request carries none by design, and a recovery that asked for one would let a caller aim it.
    #: `fms_database_dir` is what the ruled target is derived from; `host` is what the adapter needs
    #: to reach FileMaker. Both are non-secret facts about this installation, not credentials.
    fms_database_dir: str = ""
    host: str = ""
    settings_state_before: str = "unknown"
    target_dir_created_by_this_run: bool = False
    template_placed_by_this_run: bool = False
    hosted_by_this_run: bool = False
    settings_initialized_by_this_run: bool = False
    identity_established_by_this_run: bool = False
    remote_change_attempted: bool = False
    prior_access_backup: str | None = None
    staged_access_path: str | None = None
    version: int = RECORD_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "mode": self.mode,
            "phase": self.phase,
            "started_utc": self.started_utc,
            "fms_database_dir": self.fms_database_dir,
            "host": self.host,
            "settings_state_before": self.settings_state_before,
            "target_dir_created_by_this_run": self.target_dir_created_by_this_run,
            "template_placed_by_this_run": self.template_placed_by_this_run,
            "hosted_by_this_run": self.hosted_by_this_run,
            "settings_initialized_by_this_run": self.settings_initialized_by_this_run,
            "identity_established_by_this_run": self.identity_established_by_this_run,
            "remote_change_attempted": self.remote_change_attempted,
            "prior_access_backup": self.prior_access_backup,
            "staged_access_path": self.staged_access_path,
        }

    def public(self) -> dict[str, str]:
        """What a RESULT may carry: an id and a phase. Never a path, never a flag set."""
        return {"operation_id": self.operation_id, "phase": self.phase}


_BOOL_FIELDS = (
    "target_dir_created_by_this_run",
    "template_placed_by_this_run",
    "hosted_by_this_run",
    "settings_initialized_by_this_run",
    "identity_established_by_this_run",
    "remote_change_attempted",
)
_STR_FIELDS = ("operation_id", "installation_id", "mode", "phase", "started_utc",
               "settings_state_before")
#: Recorded facts a recovery verb needs. Strings, checked for type and shape but NOT constrained to
#: the secrets directory — they name this installation's FMS, not its secrets.
_FACT_FIELDS = ("fms_database_dir", "host")
_PATH_FIELDS = ("prior_access_backup", "staged_access_path")

_ALLOWED = (set(_BOOL_FIELDS) | set(_STR_FIELDS) | set(_PATH_FIELDS) | set(_FACT_FIELDS)
            | {"version"})


def record_path(secrets_dir: Path | str, *, layout=None) -> Path:
    return validated_secrets_dir(secrets_dir, layout=layout) / RECORD_FILENAME


def parse(data: object, *, secrets_dir: Path) -> OperationRecord:
    """STRICT. Every field is type-checked; every path must live in the validated secrets dir."""
    if not isinstance(data, dict):
        raise OperationRecordError("the operation record is not a JSON object")
    unknown = set(data) - _ALLOWED
    if unknown:
        raise OperationRecordError(
            f"the operation record carries unknown key(s): {', '.join(sorted(unknown))}"
        )
    if data.get("version") != RECORD_VERSION:
        raise OperationRecordError(
            f"operation record version {data.get('version')!r}; this build reads {RECORD_VERSION}"
        )
    values: dict[str, Any] = {"version": RECORD_VERSION}
    for name in _STR_FIELDS:
        value = data.get(name)
        if not isinstance(value, str) or not value:
            raise OperationRecordError(f"operation record: {name} must be a non-empty string")
        values[name] = value
    if values["phase"] not in PHASE_ORDER:
        raise OperationRecordError(f"operation record: unknown phase {values['phase']!r}")
    for name in _BOOL_FIELDS:
        value = data.get(name, False)
        # `isinstance(True, int)` is True, so the order matters: reject anything that is not a real
        # bool. A record carrying the STRING "false" must not read as True.
        if not isinstance(value, bool):
            raise OperationRecordError(f"operation record: {name} must be a boolean")
        values[name] = value
    for name in _FACT_FIELDS:
        value = data.get(name, "")
        if not isinstance(value, str):
            raise OperationRecordError(f"operation record: {name} must be a string")
        if name == "fms_database_dir" and value and not Path(value).is_absolute():
            raise OperationRecordError(
                f"operation record: fms_database_dir must be absolute, got {value!r}")
        values[name] = value
    fixed = validated_secrets_dir(secrets_dir)
    for name in _PATH_FIELDS:
        value = data.get(name)
        if value is None:
            values[name] = None
            continue
        if not isinstance(value, str) or not value:
            raise OperationRecordError(f"operation record: {name} must be a string or null")
        candidate = Path(value)
        if candidate.parent != fixed:
            raise OperationRecordError(
                f"operation record: {name} names {value!r}, which is not in the installation's "
                f"secrets directory {fixed}"
            )
        values[name] = value
    return OperationRecord(**values)


def read(secrets_dir: Path | str, *, layout=None) -> OperationRecord | None:
    """Returns None when absent. Raises ``OperationRecordError`` when present and malformed —
    those are different facts and the evidence vocabulary keeps them apart."""
    try:
        with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
            if not pinned.exists(RECORD_FILENAME):
                return None
            raw = pinned.read_bytes(RECORD_FILENAME)
    except (FileNotFoundError, SecretsDirRefused):
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise OperationRecordError(f"the operation record is not readable JSON: {exc}") from exc
    return parse(data, secrets_dir=validated_secrets_dir(secrets_dir, layout=layout))


def write(secrets_dir: Path | str, record: OperationRecord, *, layout=None) -> Path:
    with pinned_secrets_dir(secrets_dir, layout=layout, create=True) as pinned:
        payload = json.dumps(record.to_dict(), sort_keys=True, indent=2).encode("utf-8")
        pinned.write_private(RECORD_FILENAME, payload)
        back = json.loads(pinned.read_bytes(RECORD_FILENAME).decode("utf-8"))
        if back != record.to_dict():
            raise OperationRecordError("the operation record did not read back as it was written")
        return pinned.path / RECORD_FILENAME


def advance(secrets_dir: Path | str, record: OperationRecord, phase: str, *, layout=None,
            **updates: Any) -> OperationRecord:
    """Move the record forward. Never backward — a resume that rewound would re-do work."""
    if phase not in PHASE_ORDER:
        raise OperationRecordError(f"unknown phase {phase!r}")
    if PHASE_ORDER.index(phase) < PHASE_ORDER.index(record.phase):
        raise OperationRecordError(
            f"refusing to move the operation record from {record.phase} back to {phase}"
        )
    updated = replace(record, phase=phase, **updates)
    write(secrets_dir, updated, layout=layout)
    return updated


def discharge(secrets_dir: Path | str, *, layout=None) -> bool:
    """Remove the record. Idempotent — a second call is not an error."""
    try:
        with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
            if not pinned.exists(RECORD_FILENAME):
                return False
            pinned.unlink(RECORD_FILENAME)
            return True
    except (FileNotFoundError, SecretsDirRefused):
        return False


def evidence(
    secrets_dir: Path | str,
    installation_id: str,
    *,
    journal,
    layout=None,
) -> tuple[str, OperationRecord | None]:
    """The ``OperationEvidence`` axis: the storage record, CROSS-CHECKED against the journal.

    The storage record is the authority on WHOSE operation it is; the journal is the authority on
    whether it finished. An unresolved journal with no matching storage record is ``FOREIGN_OPEN``
    — a proxy, PKI, patch, recovery or updater operation — and is never storage evidence.
    """
    try:
        record = read(secrets_dir, layout=layout)
    except OperationRecordError:
        return OperationEvidence.UNREADABLE.value, None

    entry, journal_readable = _journal_entry(journal)
    journal_present = entry is not None or not journal_readable

    if record is None:
        # No storage record. Any unresolved journal belongs to somebody else, and an UNREADABLE
        # journal is treated the same way: "I cannot tell whose operation this is" is not
        # "it is not storage's".
        return (
            OperationEvidence.FOREIGN_OPEN.value if journal_present
            else OperationEvidence.NONE.value
        ), None
    if record.installation_id != installation_id:
        return OperationEvidence.FOREIGN_OPEN.value, None

    # THE JOURNAL ENTRY MUST BE THIS OPERATION'S, BY BOTH IDENTIFIERS.
    #
    # ADDED in the closure round of 2026-08-05 (Codex fix 1). §5.4 always required the comparison
    # and the code asked only `requires_recovery()`, a whole-journal boolean. So an unresolved
    # PROXY, PKI, patch or updater operation, sitting beside this installation's own storage record,
    # answered MATCHING_OPEN — and every storage verb then treated somebody else's unresolved work
    # as authority to resume, abort, finalize, discharge, checkpoint and resolve.
    if not journal_readable:
        return OperationEvidence.FOREIGN_OPEN.value, None
    if entry is not None and (
        entry.operation_id != record.operation_id
        or entry.installation_id != record.installation_id
    ):
        return OperationEvidence.FOREIGN_OPEN.value, None

    if record.phase == OperationPhase.RESOLVED.value:
        # TERMINAL. Which terminal disposition depends on the journal, and the three are kept
        # apart because they call for three different discharges.
        #
        # CORRECTED in the closure inspection round of 2026-08-05. This branch used to answer
        # MATCHING_OPEN when the matching entry was unresolved — treating finished work as
        # ordinary resumable work. `resume`/`abort` then discharged the storage record and never
        # resolved the journal, which DESTROYED the component's own evidence and left
        # `requires_recovery()` true forever. Reproduced directly before the fix.
        if entry is None:
            return EVIDENCE_TERMINAL_NO_JOURNAL, record
        if entry.state != JOURNAL_RESOLVED:
            return EVIDENCE_TERMINAL_PENDING_JOURNAL, record
        return OperationEvidence.MATCHING_RESOLVED.value, record

    if entry is None:
        # THE CRASH WINDOW: a storage record exists and `journal.begin` never landed.
        #
        # It gets ONE safe, explicit disposition and no more. A record still at PREPARED describes
        # an operation that wrote its intent and then died BEFORE touching anything — every phase
        # after PREPARED is reached only after a product mutation — so it is PROVEN INERT and may be
        # discharged. Any later phase means something was mutated with no journal entry to name it,
        # which is not a general matching operation and must not be resumed on this evidence.
        if record.phase == OperationPhase.PREPARED.value and not _claims_any_mutation(record):
            return EVIDENCE_INERT_PREPARED, record
        return OperationEvidence.UNREADABLE.value, record

    # A matching, unresolved journal entry beside a mid-flight record: this operation, unfinished.
    # THE STORAGE RECORD REMAINS AUTHORITATIVE FOR ITS OWN PHASE — the journal says WHOSE operation
    # is open, never how far it got. This is the ONE disposition that is operation authority.
    if entry.state != JOURNAL_RESOLVED:
        return OperationEvidence.MATCHING_OPEN.value, record
    # A resolved entry beside a MID-FLIGHT record is the crash window between resolving the journal
    # and retiring the evidence. The work finished; what is left is residue to discharge.
    return OperationEvidence.MATCHING_RESOLVED.value, record


def _journal_entry(journal):
    """``(entry, readable)``. A journal that cannot be parsed is NOT an absent one."""
    reader = getattr(journal, "read", None)
    if reader is None:
        return None, True
    try:
        return reader(), True
    except Exception:  # noqa: BLE001 — an unreadable journal is a distinct, refusing fact
        return None, False


def _claims_any_mutation(record: "OperationRecord") -> bool:
    return any((
        record.target_dir_created_by_this_run,
        record.template_placed_by_this_run,
        record.hosted_by_this_run,
        record.settings_initialized_by_this_run,
        record.identity_established_by_this_run,
        record.remote_change_attempted,
    ))


__all__ = [
    "EVIDENCE_INERT_PREPARED",
    "EVIDENCE_TERMINAL_NO_JOURNAL",
    "EVIDENCE_TERMINAL_PENDING_JOURNAL",
    "NON_AUTHORITY_DISPOSITIONS",
    "RECORD_FILENAME",
    "RECORD_VERSION",
    "OperationRecord",
    "OperationRecordError",
    "advance",
    "discharge",
    "evidence",
    "parse",
    "read",
    "record_path",
    "write",
]
