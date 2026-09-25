"""The no-secret lifecycle transaction journal (packet 1246-01, deliverable 4).

A logging-only journal was rejected during authoring, and the reason is the whole design: prose
cannot establish a commit boundary. After a crash, "removed the old service" in a log tells you a
line was printed, not whether the removal completed before the process died. A record with an
explicit state and a last-verified checkpoint tells you where to resume from — which is what makes
crash recovery evidence-based rather than an administrator's reconstruction.

Every mutator takes a **held** ``LifecycleLock``. Every write goes through the same structural secret
guard as the manifest, so a caller cannot journal a password even by accident, and ``backups`` holds
references — a path, an identifier — never content.

``requires_recovery()`` is what makes a second operation refuse: an unresolved record means some
earlier operation stopped in the middle, and starting a new one on top of it would destroy the only
evidence of where it stopped.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

from .atomic import _fsync_dir, atomic_write_text
from .errors import LockNotHeld, RecordInvalid, RecoveryRequired
from .layout import LifecycleLayout
from .lock import require_lock
from .result import validate_result
from .schema import (
    JOURNAL_CHECKPOINTED,
    assert_transition,
    JOURNAL_NEEDS_RECOVERY,
    JOURNAL_OPEN,
    JOURNAL_RESOLVED,
    LIFECYCLE_MODES,
    JournalRecord,
    utc_now_iso,
)
from .secret_guard import assert_no_secrets

JOURNAL_FILE_MODE = 0o600


class Journal:
    """One machine's lifecycle journal. At most one record: one operation runs at a time."""

    def __init__(self, layout: LifecycleLayout, *, path=None):
        # `path` selects the protected install-attempt container's journal (packet 1398 §6.1). The
        # lock authority is still THIS layout's lock; only where the one record lives changes.
        self._layout = layout
        self._path = layout.journal_file if path is None else Path(path)

    def _authority(self, lock: object, action: str):
        """Accept only a held lock for THIS machine's lifecycle state.

        ``require_lock`` proves a lock is held; it cannot prove it is the right one. Binding the
        journal to the layout it was built from closes the gap an independent review named: a lock
        taken on some other root would otherwise authorize writing this one.
        """
        held = require_lock(lock, action)
        if held.layout != self._layout:
            raise LockNotHeld(
                f"{action} requires the lifecycle lock for {self._layout.lock_file}, "
                f"not {held.layout.lock_file}"
            )
        return held

    @property
    def path(self):
        return self._path

    def read(self) -> JournalRecord | None:
        """The current record, or ``None`` when no operation has left one."""
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise RecordInvalid(f"journal at {self._path} is unreadable: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise RecordInvalid(f"journal at {self._path} is not valid JSON: {exc}") from exc
        return JournalRecord.from_dict(data)

    def requires_recovery(self) -> bool:
        """True when an earlier operation left work unresolved — or when that cannot be ruled out.

        An unreadable journal answers TRUE, not False. "I cannot tell whether recovery is owed" and
        "no recovery is owed" are different facts, and only one of them is safe to act on.
        """
        try:
            record = self.read()
        except RecordInvalid:
            return True
        return record is not None and record.state != JOURNAL_RESOLVED

    def assert_clear(self) -> None:
        """Refuse to start a new operation over an unresolved one, or over an unreadable record."""
        try:
            record = self.read()
        except RecordInvalid as exc:
            raise RecoveryRequired(
                f"the lifecycle journal at {self._path} cannot be read ({exc}); resolve it before "
                "starting another operation"
            ) from exc
        if record is not None and record.state != JOURNAL_RESOLVED:
            raise RecoveryRequired(
                f"lifecycle operation {record.operation_id} ({record.mode}) is unresolved at "
                f"'{record.current_subsystem or record.state}'; resume or resolve it before "
                "starting another operation"
            )

    def _persist(self, record: JournalRecord) -> JournalRecord:
        record = record.validated()
        payload = record.to_dict()
        assert_no_secrets(payload, what="the lifecycle journal")
        atomic_write_text(
            self._path,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            mode=JOURNAL_FILE_MODE,
        )
        return record

    def begin(
        self,
        *,
        lock: object,
        operation_id: str,
        installation_id: str,
        mode: str,
        plan_digest: str | None = None,
    ) -> JournalRecord:
        self._authority(lock, "opening a lifecycle journal record")
        if mode not in LIFECYCLE_MODES:
            raise RecordInvalid(f"mode must be one of {LIFECYCLE_MODES}, got {mode!r}")
        self.assert_clear()
        existing = self.read()
        assert_transition(existing.state if existing else None, JOURNAL_OPEN)
        return self._persist(
            JournalRecord(
                operation_id=operation_id,
                installation_id=installation_id,
                mode=mode,
                state=JOURNAL_OPEN,
                plan_digest=plan_digest,
                updated_utc=utc_now_iso(),
            )
        )

    def checkpoint(
        self,
        *,
        lock: object,
        subsystem: str,
        intended_change: str | None = None,
        backups: Iterable[str] = (),
        verified: str | None = None,
        resume_hint: str | None = None,
    ) -> JournalRecord:
        """Record what is about to happen, before it happens.

        The ordering is the point: a checkpoint written *after* a mutation proves nothing about a
        crash that lands between the two.
        """
        self._authority(lock, "checkpointing the lifecycle journal")
        record = self.read()
        if record is None:
            raise RecordInvalid("no open lifecycle journal record to checkpoint")
        assert_transition(record.state, JOURNAL_CHECKPOINTED)
        merged = tuple(dict.fromkeys((*record.backups, *(str(b) for b in backups))))
        return self._persist(
            JournalRecord(
                operation_id=record.operation_id,
                installation_id=record.installation_id,
                mode=record.mode,
                state=JOURNAL_CHECKPOINTED,
                plan_digest=record.plan_digest,
                current_subsystem=subsystem,
                intended_change=intended_change,
                backups=merged,
                last_checkpoint=verified if verified is not None else record.last_checkpoint,
                resume_hint=resume_hint,
                updated_utc=utc_now_iso(),
            )
        )

    def mark_needs_recovery(self, *, lock: object, reason: str) -> JournalRecord:
        self._authority(lock, "marking the lifecycle journal for recovery")
        record = self.read()
        if record is None:
            raise RecordInvalid("no lifecycle journal record to mark")
        assert_transition(record.state, JOURNAL_NEEDS_RECOVERY)
        return self._persist(
            JournalRecord(
                operation_id=record.operation_id,
                installation_id=record.installation_id,
                mode=record.mode,
                state=JOURNAL_NEEDS_RECOVERY,
                plan_digest=record.plan_digest,
                current_subsystem=record.current_subsystem,
                intended_change=record.intended_change,
                backups=record.backups,
                last_checkpoint=record.last_checkpoint,
                resume_hint=reason,
                updated_utc=utc_now_iso(),
            )
        )

    def resolve(self, *, lock: object, result: str) -> JournalRecord:
        """Close the operation with one of the six result words."""
        self._authority(lock, "resolving the lifecycle journal")
        record = self.read()
        if record is None:
            raise RecordInvalid("no lifecycle journal record to resolve")
        assert_transition(record.state, JOURNAL_RESOLVED)
        return self._persist(
            JournalRecord(
                operation_id=record.operation_id,
                installation_id=record.installation_id,
                mode=record.mode,
                state=JOURNAL_RESOLVED,
                plan_digest=record.plan_digest,
                current_subsystem=record.current_subsystem,
                intended_change=record.intended_change,
                backups=record.backups,
                last_checkpoint=record.last_checkpoint,
                resume_hint=record.resume_hint,
                result=validate_result(result),
                updated_utc=utc_now_iso(),
            )
        )

    def mark_resolved_checkpoint(self, *, lock: object, checkpoint: str) -> JournalRecord:
        """Durably record post-resolution work before its companion record is removed.

        Provider retirement spans two durable records.  This checkpoint is the receipt that lets a
        retry distinguish "recovery authority was cleared after verified retirement" from "the
        recovery record disappeared without proof".  It changes no result and is accepted only on
        an already-resolved operation.
        """
        self._authority(lock, "checkpointing a resolved lifecycle journal")
        record = self.read()
        if record is None:
            raise RecordInvalid("no resolved lifecycle journal record to checkpoint")
        if record.state != JOURNAL_RESOLVED:
            raise RecoveryRequired(
                f"refusing to record retirement for unresolved operation {record.operation_id}"
            )
        if not isinstance(checkpoint, str) or not checkpoint:
            raise RecordInvalid("a resolved lifecycle checkpoint must be a non-empty string")
        return self._persist(
            JournalRecord(
                operation_id=record.operation_id,
                installation_id=record.installation_id,
                mode=record.mode,
                state=record.state,
                plan_digest=record.plan_digest,
                current_subsystem=record.current_subsystem,
                intended_change=record.intended_change,
                backups=record.backups,
                last_checkpoint=checkpoint,
                resume_hint=record.resume_hint,
                result=record.result,
                updated_utc=utc_now_iso(),
            )
        )

    def discard(self, *, lock: object) -> None:
        """Remove a resolved record. Refuses while recovery is still owed."""
        self._authority(lock, "discarding the lifecycle journal")
        try:
            record = self.read()
        except RecordInvalid as exc:
            raise RecoveryRequired(
                f"refusing to discard an unreadable lifecycle journal ({exc}); it is the only "
                "evidence of where an interrupted operation stopped"
            ) from exc
        if record is not None and record.state != JOURNAL_RESOLVED:
            raise RecoveryRequired(
                f"refusing to discard journal for unresolved operation {record.operation_id}"
            )
        try:
            os.unlink(str(self._path))
        except FileNotFoundError:
            return
        _fsync_dir(self._path.parent)
