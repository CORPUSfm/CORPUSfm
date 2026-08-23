"""Operation-bound recovery evidence for the Admin-API identity (packet 1246-07).

``reconcile`` and ``remove`` publish one record BEFORE their first mutation and leave it in place
until ``finalize`` retires it or ``abort`` discharges it. Everything those two verbs need comes off
this record and the two backups it names — **never from a caller-supplied path**, because a recovery
authority a caller can aim is not a recovery authority.

**THE RECORD IS AUTHORITY, SO IT IS PARSED AS AUTHORITY.** An earlier version accepted a record whose
`operation_id` was `"not-a-uuid"`, whose paths were relative, whose `registration_name` was `"poison"`,
whose booleans were the *strings* ``"false"`` — silently coerced to ``True`` by ``bool()`` — and which
carried unknown keys, then handed the result to code that deletes files and DELETEs registrations.
Every field below is now checked for its own type and vocabulary, contradictions between fields are
refused, and **nothing is coerced**: `str()`, `bool()` and `int()` are not applied to parsed evidence,
because a coercion is a decision made on the reader's behalf about data it should have rejected.

**BACKUP PATHS ARE DERIVED, NOT TRUSTED.** Each is
``<lifecycle state dir>/admin-identity-<canonical operation uuid>.<fixed suffix>``. A serialized path
must equal its derived form exactly or the record is invalid, and every read, restore and unlink goes
through the derived path — so a record naming ``/etc/hosts`` selects nothing.

**BACKUPS ARE DURABLE AND INTEGRITY-BOUND.** Created ``O_CREAT|O_EXCL`` (never replacing anything),
written in full, fsynced, read back and verified against the captured bytes' SHA-256, with the
containing directory fsynced. The digest is bound into the record and reverified before any restore:
a truncated, replaced or missing backup is never restored from.

The local before-image is copied VERBATIM — it is already Machine-Key ciphertext, and a restore that
re-derived it would be a re-encryption that can fail with nothing left to fall back on.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .atomic import _fsync_dir, atomic_write_text
from .errors import LifecycleError, RecordInvalid
from .lock import require_lock
from .schema import canonical_path, path_flavour, same_path, utc_now_iso
from .secret_guard import assert_no_secrets

RECOVERY_FILENAME = "admin-identity-recovery.json"
RECOVERY_FILE_MODE = 0o600
BACKUP_FILE_MODE = 0o600
#: Bumped from 1 by the strict-parsing round: the shape gained a recorded path flavour and the two
#: backup digests, and the permissive reader is gone. An older record is refused, not migrated.
RECOVERY_SCHEMA_VERSION = 2

#: Evidence is published BEFORE the journal opens, so this phase exists: preparation is durable and
#: **nothing has been mutated**. A crash here leaves inert evidence and a clear journal.
PREPARED = "prepared"
#: The journal is open and a mutation may have happened.
OPEN = "open"
#: A reconcile that proved its new pair, waiting for the integrator's manifest write.
AWAITING_COMPOSITION = "awaiting_composition"
STATES: tuple[str, ...] = (PREPARED, OPEN, AWAITING_COMPOSITION)

KIND_RECONCILE = "reconcile"
KIND_REMOVE = "remove"
KINDS: tuple[str, ...] = (KIND_RECONCILE, KIND_REMOVE)

REMOTE_OPERATIONS: dict[str, tuple[str, ...]] = {
    KIND_RECONCILE: ("add", "update"),
    KIND_REMOVE: ("delete",),
}

LOCAL_BEFORE = "local-before"
REMOTE_BEFORE = "remote-before"
BACKUP_SUFFIXES: tuple[str, ...] = (LOCAL_BEFORE, REMOTE_BEFORE)

MAX_TEXT = 255

#: EVERY authority pattern is used with `fullmatch`, and none is `$`-anchored. `re.match(r"…$")`
#: accepts a TRAILING NEWLINE — so `"<uuid>\n"` parsed, and the newline propagated into the derived
#: backup FILENAME. `fullmatch` on an unanchored pattern is the whole rule with no such tail.
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")

_KEYS: frozenset[str] = frozenset({
    "schema_version", "operation_id", "installation_id", "kind", "mode", "actor", "host",
    "path_flavour", "install_dir", "secrets_dir", "registration_name", "inspected_generation",
    "state", "remote_operation", "prior_remote_present", "prior_remote_fingerprint",
    "prior_remote_backup", "prior_remote_backup_sha256", "attempted_fingerprint", "local_present",
    "local_backup", "local_backup_sha256", "created_utc",
})


class RecoveryEvidenceInvalid(LifecycleError):
    """The recovery record is missing, unreadable, malformed, or not about this operation."""


class BackupUnusable(RecoveryEvidenceInvalid):
    """A backup is absent, truncated, replaced, or does not match its recorded digest."""


# ── strict field readers. Each RAISES; none coerces. ────────────────────────

def _require(raw: dict, name: str):
    if name not in raw:
        raise RecoveryEvidenceInvalid(f"the recovery record carries no {name}")
    return raw[name]


def _uuid(raw: dict, name: str) -> str:
    value = _require(raw, name)
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise RecoveryEvidenceInvalid(
            f"{name} must be a canonical lowercase UUID, got {value!r}")
    return value


def _boolean(raw: dict, name: str) -> bool:
    value = _require(raw, name)
    # `isinstance(value, bool)` and nothing else. `bool("false")` is True, which is how a record
    # saying the local material was ABSENT came to mean it was PRESENT.
    if not isinstance(value, bool):
        raise RecoveryEvidenceInvalid(f"{name} must be a real boolean, got {value!r}")
    return value


def _generation(raw: dict, name: str) -> int:
    value = _require(raw, name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RecoveryEvidenceInvalid(
            f"{name} must be a non-negative integer (and `True` is not one), got {value!r}")
    return value


def _word(raw: dict, name: str, allowed) -> str:
    value = _require(raw, name)
    if not isinstance(value, str) or value not in allowed:
        raise RecoveryEvidenceInvalid(f"{name} must be one of {tuple(allowed)}, got {value!r}")
    return value


def _text(raw: dict, name: str) -> str:
    value = _require(raw, name)
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT:
        raise RecoveryEvidenceInvalid(
            f"{name} must be a non-empty string of at most {MAX_TEXT} characters, got {value!r}")
    return value


def _absolute(raw: dict, name: str, flavour: str) -> str:
    value = _require(raw, name)
    try:
        canonical = canonical_path(value, field_name=name)
    except RecordInvalid as exc:
        raise RecoveryEvidenceInvalid(str(exc)) from exc
    # The flavour is RECORDED, not read from the host: a record written on Windows must not be
    # re-interpreted as POSIX by whatever machine happens to be reading it.
    if path_flavour(canonical) != flavour:
        raise RecoveryEvidenceInvalid(
            f"{name} is a {path_flavour(canonical)} path in a record declaring {flavour}")
    return canonical


def _optional_fingerprint(raw: dict, name: str) -> str | None:
    value = _require(raw, name)
    if value is None:
        return None
    if not isinstance(value, str) or not _FINGERPRINT.fullmatch(value):
        raise RecoveryEvidenceInvalid(
            f"{name} must be null or sha256:<64 lowercase hex>, got {value!r}")
    return value


def _optional_digest(raw: dict, name: str) -> str | None:
    value = _require(raw, name)
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
        raise RecoveryEvidenceInvalid(
            f"{name} must be null or 64 lowercase hex characters, got {value!r}")
    return value


def _optional_path(raw: dict, name: str) -> str | None:
    value = _require(raw, name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecoveryEvidenceInvalid(f"{name} must be null or a path string, got {value!r}")
    return value


@dataclass(frozen=True)
class IdentityRecovery:
    """What an interrupted or unresolved identity operation left behind. Strictly typed."""

    operation_id: str
    installation_id: str
    kind: str
    mode: str
    actor: str
    host: str
    path_flavour: str
    install_dir: str
    secrets_dir: str
    registration_name: str
    inspected_generation: int
    state: str = PREPARED
    remote_operation: str | None = None
    prior_remote_present: bool = False
    prior_remote_fingerprint: str | None = None
    prior_remote_backup: str | None = None
    prior_remote_backup_sha256: str | None = None
    attempted_fingerprint: str | None = None
    local_present: bool = False
    local_backup: str | None = None
    local_backup_sha256: str | None = None
    created_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": RECOVERY_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "kind": self.kind,
            "mode": self.mode,
            "actor": self.actor,
            "host": self.host,
            "path_flavour": self.path_flavour,
            "install_dir": self.install_dir,
            "secrets_dir": self.secrets_dir,
            "registration_name": self.registration_name,
            "inspected_generation": self.inspected_generation,
            "state": self.state,
            "remote_operation": self.remote_operation,
            "prior_remote_present": self.prior_remote_present,
            "prior_remote_fingerprint": self.prior_remote_fingerprint,
            "prior_remote_backup": self.prior_remote_backup,
            "prior_remote_backup_sha256": self.prior_remote_backup_sha256,
            "attempted_fingerprint": self.attempted_fingerprint,
            "local_present": self.local_present,
            "local_backup": self.local_backup,
            "local_backup_sha256": self.local_backup_sha256,
            "created_utc": self.created_utc or utc_now_iso(),
        }

    @staticmethod
    def from_dict(raw: object, *, layout=None) -> "IdentityRecovery":
        """Parse authority strictly. Every failure is `RecoveryEvidenceInvalid`; nothing is coerced.

        ``layout`` is what turns a serialized backup path into a checkable claim: with it, each path
        must equal the derived operation-bound path exactly. `read_recovery` always supplies it.
        """
        from .admin_identity import MODES
        from .admin_identity_store import REGISTRATION_NAME

        if not isinstance(raw, dict):
            raise RecoveryEvidenceInvalid("the identity recovery record is not a JSON object")
        version = raw.get("schema_version")
        # `type(...) is int`, not `isinstance`: `True` IS an int to `isinstance`, and `2.0 != 2` is
        # `False`, so both a boolean and a float slipped through an equality check. A version is an
        # integer or it is not a version.
        if type(version) is not int or version != RECOVERY_SCHEMA_VERSION:
            raise RecoveryEvidenceInvalid(
                f"identity recovery schema_version {version!r}; this build reads "
                f"{RECOVERY_SCHEMA_VERSION} only, as an integer — an older record is refused, "
                "never migrated")
        unknown = set(raw) - _KEYS
        if unknown:
            raise RecoveryEvidenceInvalid(
                f"the recovery record carries unknown key(s): {', '.join(sorted(unknown))}")

        kind = _word(raw, "kind", KINDS)
        state = _word(raw, "state", STATES)
        flavour = _word(raw, "path_flavour", ("posix", "windows"))
        registration_name = _text(raw, "registration_name")
        if registration_name != REGISTRATION_NAME:
            raise RecoveryEvidenceInvalid(
                f"registration_name must be {REGISTRATION_NAME!r}, got {registration_name!r}; "
                "there is one registration per installation and its name is fixed")

        remote_operation = _require(raw, "remote_operation")
        if remote_operation is not None:
            remote_operation = _word(raw, "remote_operation", REMOTE_OPERATIONS[kind])

        record = IdentityRecovery(
            operation_id=_uuid(raw, "operation_id"),
            installation_id=_uuid(raw, "installation_id"),
            kind=kind,
            mode=_word(raw, "mode", MODES),
            actor=_text(raw, "actor"),
            host=_text(raw, "host"),
            path_flavour=flavour,
            install_dir=_absolute(raw, "install_dir", flavour),
            secrets_dir=_absolute(raw, "secrets_dir", flavour),
            registration_name=registration_name,
            inspected_generation=_generation(raw, "inspected_generation"),
            state=state,
            remote_operation=remote_operation,
            prior_remote_present=_boolean(raw, "prior_remote_present"),
            prior_remote_fingerprint=_optional_fingerprint(raw, "prior_remote_fingerprint"),
            prior_remote_backup=_optional_path(raw, "prior_remote_backup"),
            prior_remote_backup_sha256=_optional_digest(raw, "prior_remote_backup_sha256"),
            attempted_fingerprint=_optional_fingerprint(raw, "attempted_fingerprint"),
            local_present=_boolean(raw, "local_present"),
            local_backup=_optional_path(raw, "local_backup"),
            local_backup_sha256=_optional_digest(raw, "local_backup_sha256"),
            created_utc=_text(raw, "created_utc"),
        )
        _assert_coherent(record)
        _assert_backup_paths_are_derived(record, layout)
        return record


def _assert_coherent(record: "IdentityRecovery") -> None:
    """Relations BETWEEN fields. Each field can be individually well formed and jointly a lie."""
    def refuse(why: str):
        raise RecoveryEvidenceInvalid(f"incoherent recovery record: {why}")

    if record.state is PREPARED or record.state == PREPARED:
        if record.remote_operation is not None:
            refuse("a PREPARED record has not mutated anything, so it names no remote operation")
    if record.state == AWAITING_COMPOSITION:
        if record.kind != KIND_RECONCILE:
            refuse("only a reconcile produces a candidate to compose")
        if record.remote_operation is None:
            refuse("an awaiting-composition record must name the remote operation it published")

    if record.kind == KIND_RECONCILE:
        if record.state != PREPARED and record.attempted_fingerprint is None:
            refuse("a reconcile past preparation must record the fingerprint it tried to publish")
    else:
        for name, value in (("attempted_fingerprint", record.attempted_fingerprint),
                            ("local_backup", record.local_backup),
                            ("prior_remote_backup", record.prior_remote_backup)):
            if value is not None:
                # A deletion is terminal: it restores nothing, so it captures nothing. A removal
                # record naming a backup is claiming a way back that does not exist.
                refuse(f"a removal records no {name}")

    if not record.prior_remote_present:
        if record.prior_remote_fingerprint is not None or record.prior_remote_backup is not None:
            refuse("an absent prior registration has neither a fingerprint nor a backup")

    # A CLAIM WITHOUT ITS BEFORE-IMAGE IS THE WORST SHAPE THIS RECORD CAN TAKE, and it parsed. A
    # reconcile record saying `local_present` with no backup made `_restore_local` fall through both
    # its branches doing nothing, after which `abort` reported `rolled_back` — "the local material
    # was restored to its before-image" — and cleared the evidence. The claim and the means to honour
    # it now travel together, in EVERY phase, because preparation is exactly where they are captured.
    if record.kind == KIND_RECONCILE:
        if record.local_present and (record.local_backup is None
                                     or record.local_backup_sha256 is None):
            refuse("a reconcile that found local material must carry its exact before-image and "
                   "digest; a restore has no way back without them")
        if not record.local_present and (record.local_backup is not None
                                         or record.local_backup_sha256 is not None):
            refuse("absent local material has no before-image")
        # The mirror rule for the remote half: a prior registration this operation could READ is one
        # it claims to be able to put back, so it carries the bytes, the digest and the fingerprint
        # together. An unreadable one carries none of the three and is honestly unrestorable.
        if record.prior_remote_present and record.prior_remote_fingerprint is not None:
            if record.prior_remote_backup is None or record.prior_remote_backup_sha256 is None:
                refuse("a reconcile that read the prior registration must carry its exact backup "
                       "and digest alongside the fingerprint")
    elif record.local_backup is not None or record.local_backup_sha256 is not None:
        # A removal records `local_present` as an OBSERVATION — the interrupted-removal
        # classification reads it — but captures no before-image, because deletion is terminal.
        refuse("absent local material has no before-image")

    for path, digest, what in ((record.local_backup, record.local_backup_sha256, "local_backup"),
                               (record.prior_remote_backup, record.prior_remote_backup_sha256,
                                "prior_remote_backup")):
        if (path is None) != (digest is None):
            refuse(f"{what} and its digest must both be present or both absent")
    if record.prior_remote_backup is not None and record.prior_remote_fingerprint is None:
        refuse("a captured prior registration must record the fingerprint it was captured at")


def _assert_backup_paths_are_derived(record: "IdentityRecovery", layout) -> None:
    """A serialized backup path is a CLAIM about a derived path, and it is checked against it."""
    if layout is None:
        return
    for stored, suffix in ((record.local_backup, LOCAL_BEFORE),
                           (record.prior_remote_backup, REMOTE_BEFORE)):
        if stored is None:
            continue
        derived = str(backup_path(layout, record.operation_id, suffix))
        if not same_path(stored, derived):
            raise RecoveryEvidenceInvalid(
                f"the recovery record names {stored!r} as its {suffix} backup; this operation's "
                f"backup is {derived!r}. A record does not get to choose which file is read, "
                "restored or deleted."
            )


# ── derived, operation-bound locations ──────────────────────────────────────

def recovery_path(layout) -> Path:
    """Beside the journal, in the same lifecycle-controlled state directory."""
    return Path(layout.journal_file).parent / RECOVERY_FILENAME


def backup_path(layout, operation_id: str, suffix: str) -> Path:
    """``<state dir>/admin-identity-<canonical uuid>.<fixed suffix>`` — derived, never supplied."""
    if not isinstance(operation_id, str) or not _UUID.fullmatch(operation_id):
        raise RecoveryEvidenceInvalid(
            f"a backup path is derived from a canonical operation UUID, got {operation_id!r}")
    if suffix not in BACKUP_SUFFIXES:
        raise RecoveryEvidenceInvalid(
            f"{suffix!r} is not one of this operation's backup suffixes {BACKUP_SUFFIXES}")
    return Path(layout.journal_file).parent / f"admin-identity-{operation_id}.{suffix}"


# ── durable, integrity-bound backups ────────────────────────────────────────

# `_fsync_dir` IS ATOMIC.PY'S, NOT A SECOND COPY (packet 1246-10-04). This module carried its own,
# and the two disagreed in one line: `atomic._fsync_dir` opens the directory INSIDE its try — "a
# no-op where the platform does not permit it (Windows)" — while the copy here opened it outside,
# so the guard covered only the fsync. Windows refuses `os.open()` on a directory, so every backup
# and recovery write through this module died with `[Errno 13] Permission denied` on the state
# directory, and admin identity reconciled nothing. Measured on winfms2026, 2026-08-09; the
# manifest and locator were unaffected because they write through atomic.py. Duplicated helpers do
# not drift evenly — the copy nobody looks at is the one that is wrong.


def write_backup(layout, operation_id: str, suffix: str, data: bytes) -> tuple[Path, str]:
    """Create the backup with NO-REPLACE semantics and prove it landed. Returns ``(path, digest)``.

    ``O_CREAT|O_EXCL`` so an unrelated existing file is never truncated; a full write, an ``fsync``,
    a read-back verified against the captured bytes' SHA-256, and an ``fsync`` of the directory so
    the name survives a crash. A partial destination is removed on failure — and the SOURCE is never
    touched, because the source is the only remaining copy at that moment.
    """
    from corpusfm.core import secure_fs

    target = backup_path(layout, operation_id, suffix)
    secure_fs.secure_dir(target.parent)
    digest = hashlib.sha256(data).hexdigest()
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, BACKUP_FILE_MODE)
    except FileExistsError as exc:
        raise BackupUnusable(
            f"{target} already exists; this operation will not replace a file it did not create"
        ) from exc
    try:
        written = 0
        view = memoryview(data)
        while written < len(data):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        target.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
    try:
        landed = target.read_bytes()
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise BackupUnusable(f"{target} could not be read back ({exc})") from exc
    if hashlib.sha256(landed).hexdigest() != digest:
        # A short write that reported success, a filesystem that lost bytes, or a racing writer.
        target.unlink(missing_ok=True)
        raise BackupUnusable(
            f"{target} does not match the bytes it was given; the partial file was removed and "
            "nothing was taken from the source")
    _fsync_dir(target.parent)
    return target, digest


def read_backup(layout, operation_id: str, suffix: str, *, expected_sha256: str) -> bytes:
    """The DERIVED backup, verified against its recorded digest. Never a stored path."""
    if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(expected_sha256):
        raise BackupUnusable(f"no usable digest was recorded for the {suffix} backup")
    target = backup_path(layout, operation_id, suffix)
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise BackupUnusable(f"the {suffix} backup at {target} cannot be read ({exc})") from exc
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise BackupUnusable(
            f"the {suffix} backup at {target} does not match its recorded digest "
            f"({actual[:12]}… vs {expected_sha256[:12]}…); it is truncated, replaced or corrupt "
            "and must not be restored from")
    return data


def verify_backups(layout, record: "IdentityRecovery") -> None:
    """Re-verify every backup this record names, BEFORE anything is restored from any of them."""
    for suffix, digest in ((LOCAL_BEFORE, record.local_backup_sha256),
                           (REMOTE_BEFORE, record.prior_remote_backup_sha256)):
        if digest is not None:
            read_backup(layout, record.operation_id, suffix, expected_sha256=digest)


# ── publication and retirement ──────────────────────────────────────────────

def write_recovery(layout, record: IdentityRecovery, *, lock) -> Path:
    """Atomic, secret-fenced, lock-held, and re-parsed before it is trusted.

    The round trip is the point: a record this build could not read back is not evidence, and the
    moment to discover that is while the box is still untouched.
    """
    require_lock(lock, "recording admin-identity recovery authority")
    payload = record.to_dict()
    assert_no_secrets(payload, what="the admin-identity recovery record")
    IdentityRecovery.from_dict(json.loads(json.dumps(payload)), layout=layout)
    target = recovery_path(layout)
    atomic_write_text(target, json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      mode=RECOVERY_FILE_MODE)
    _fsync_dir(target.parent)
    return target


def read_recovery(layout) -> IdentityRecovery:
    target = recovery_path(layout)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RecoveryEvidenceInvalid(f"no admin-identity recovery record at {target}") from exc
    except (OSError, ValueError) as exc:
        raise RecoveryEvidenceInvalid(
            f"the recovery record at {target} cannot be read: {type(exc).__name__}") from exc
    return IdentityRecovery.from_dict(raw, layout=layout)


NO_RECORD = "no_record"
VALID = "valid"
INVALID = "invalid"


def inspect_recovery(layout) -> tuple[str, object]:
    """``(NO_RECORD, None)`` · ``(VALID, record)`` · ``(INVALID, reason)`` — three answers, not two.

    Collapsing the third into the first is how malformed evidence came to report *"nothing owed"*.
    "There is no record" and "there is a record I cannot adjudicate" owe opposite work, and only one
    of them is safe to start a new operation over.
    """
    if not recovery_path(layout).exists():
        return NO_RECORD, None
    try:
        return VALID, read_recovery(layout)
    except RecoveryEvidenceInvalid as exc:
        return INVALID, str(exc)


def clear_recovery(layout, *, lock) -> None:
    """Retire the record AND this operation's DERIVED backups — only after the journal resolved.

    **It refuses to delete evidence it could not read.** The predecessor caught
    `RecoveryEvidenceInvalid`, set `record = None`, and unlinked the file anyway — destroying the
    only account of an interrupted operation precisely when nobody could interpret it. Malformed
    evidence is RETAINED and reported; a human adjudicates it.
    """
    require_lock(lock, "clearing admin-identity recovery authority")
    record = read_recovery(layout)          # raises RecoveryEvidenceInvalid; deletes nothing
    for suffix in BACKUP_SUFFIXES:
        try:
            backup_path(layout, record.operation_id, suffix).unlink(missing_ok=True)
        except OSError:
            pass          # harmless residue; the record is what authority depends on
    recovery_path(layout).unlink(missing_ok=True)
    _fsync_dir(recovery_path(layout).parent)


class PreparationNotDischargeable(RecoveryEvidenceInvalid):
    """A PREPARED record and this box's journal cannot be reconciled. Everything is retained."""


def discharge_preparation(layout, *, lock, journal, operation_id: str,
                          installation_id: str | None = None) -> str:
    """THE ONE PLACE inert preparation is retired — and it takes the JOURNAL, not just the record.

    Its predecessor took only the record, so it answered *"nothing was mutated"* from the record
    alone. That is true of the record and not of the box: a failure between `journal.begin` and the
    PREPARED → OPEN write leaves a PREPARED record with an OPEN journal, and the predecessor deleted
    the evidence and returned without resolving anything — producing the unresolved-journal-with-no-
    evidence state the ordering exists to prevent, and making it unrecoverable, because every later
    verb then refuses for want of the record it had just destroyed. Reproduced end to end before this
    was written.

    **Nothing is ever cleared before an owed journal is resolved.** The order below is the whole
    function: resolve first, retire second.

    Why resolving as `no_change` is honest in the OPEN/CHECKPOINTED/NEEDS_RECOVERY case: the record
    is still PREPARED, and a record only leaves PREPARED in the same lock-held step that publishes
    `OPEN` **before the first mutation**. A PREPARED record is therefore positive evidence that no
    product mutation was reached, whatever the journal says about how far the bracket got.
    """
    from .schema import (
        JOURNAL_CHECKPOINTED, JOURNAL_NEEDS_RECOVERY, JOURNAL_OPEN, JOURNAL_RESOLVED,
    )
    from .result import NO_CHANGE

    require_lock(lock, "discharging inert admin-identity preparation")
    record = read_recovery(layout)
    if record.operation_id != operation_id:
        raise PreparationNotDischargeable(
            f"the stored recovery record is for operation {record.operation_id!r}, not "
            f"{operation_id!r}; nothing was retired")
    if installation_id is not None and record.installation_id != installation_id:
        raise PreparationNotDischargeable(
            "the stored recovery record belongs to a different installation; nothing was retired")
    if record.state != PREPARED:
        raise PreparationNotDischargeable(
            f"operation {operation_id} is in state {record.state!r}, not inert preparation; it must "
            "be discharged rather than discarded")

    try:
        entry = journal.read()
    except LifecycleError as exc:
        raise PreparationNotDischargeable(
            f"the lifecycle journal cannot be read ({exc}); the preparation evidence is retained "
            "and a human must adjudicate both") from exc

    if entry is not None:
        if entry.operation_id != record.operation_id:
            raise PreparationNotDischargeable(
                f"the journal names operation {entry.operation_id} and the preparation names "
                f"{record.operation_id}; nothing was resolved and nothing was retired")
        if entry.installation_id != record.installation_id:
            raise PreparationNotDischargeable(
                "the journal and the preparation name different installations")
        if entry.state in (JOURNAL_OPEN, JOURNAL_CHECKPOINTED, JOURNAL_NEEDS_RECOVERY):
            # RESOLVE FIRST. If this raises, the evidence is still on disk and the operation is
            # still discharge-able on the next invocation.
            journal.resolve(lock=lock, result=NO_CHANGE)
        elif entry.state != JOURNAL_RESOLVED:
            raise PreparationNotDischargeable(
                f"the journal is in state {entry.state!r}, which no preparation can accompany; "
                "everything is retained")
        # JOURNAL_RESOLVED: the crash landed between resolution and retirement. The journal already
        # carries its own result and must keep it — this only finishes the retirement.

    _retire(layout, record)
    return NO_CHANGE


#: What `discharge_terminal_evidence` answers with when the journal has already spoken.
TERMINAL = "terminal"
NOT_TERMINAL = "not_terminal"


def discharge_terminal_evidence(layout, *, lock, journal, operation_id: str,
                                installation_id: str) -> tuple[str, str | None, str]:
    """**A MATCHING RESOLVED JOURNAL IS TERMINAL AUTHORITY.** Returns ``(verdict, result, detail)``.

    Every mutating verb resolves the journal and then retires the evidence — two adjacent steps, and
    a crash between them is an ordinary power loss. That crash used to leave a record saying
    *mid-flight* beside a journal saying *finished*, and `abort` then performed **the entire remote
    restore** before raising on `resolved -> resolved`: the restore was never recorded, the evidence
    was never retired, and every retry re-issued the write to FileMaker Server. Reproduced end to end.

    The rule that removes it: if the journal is RESOLVED and its operation and installation match the
    record, the operation is **over**, whatever phase the record is in. This function then contacts no
    API, uses no credential, restores and deletes no product state — it retires the residual,
    operation-derived recovery files and hands back **the journal's own recorded result**. Calling it
    twice is harmless, because the second call finds no record and there is nothing left to do.

    If retirement itself fails the evidence survives, so the NEXT invocation retries only the
    retirement — never the product operation, which the journal has already settled.
    """
    from .schema import JOURNAL_RESOLVED

    require_lock(lock, "discharging terminal admin-identity evidence")
    if not recovery_path(layout).exists():
        return NOT_TERMINAL, None, "no residual recovery evidence"
    record = read_recovery(layout)          # strict; raises rather than guessing
    if record.operation_id != operation_id:
        raise PreparationNotDischargeable(
            f"the stored recovery record is for operation {record.operation_id!r}, not "
            f"{operation_id!r}; nothing was retired")
    if record.installation_id != installation_id:
        raise PreparationNotDischargeable(
            "the stored recovery record belongs to a different installation; nothing was retired")
    try:
        entry = journal.read()
    except LifecycleError as exc:
        raise PreparationNotDischargeable(
            f"the lifecycle journal cannot be read ({exc}); everything is retained") from exc
    if entry is None or entry.state != JOURNAL_RESOLVED:
        return NOT_TERMINAL, None, "the journal has not resolved this operation"
    if entry.operation_id != record.operation_id:
        raise PreparationNotDischargeable(
            f"the journal names operation {entry.operation_id} and the recovery record names "
            f"{record.operation_id}; nothing was retired")
    if entry.installation_id != record.installation_id:
        raise PreparationNotDischargeable(
            "the journal and the recovery record name different installations")

    _retire(layout, record)
    return (TERMINAL, entry.result,
            f"operation {record.operation_id} was already recorded {entry.result!r} in the lifecycle "
            "journal; that is terminal. No FileMaker Server call, credential, restore or deletion "
            "was performed — only the residual recovery files this operation left behind were "
            "retired.")


def _retire(layout, record) -> None:
    for suffix in BACKUP_SUFFIXES:
        backup_path(layout, record.operation_id, suffix).unlink(missing_ok=True)
    recovery_path(layout).unlink(missing_ok=True)
    _fsync_dir(recovery_path(layout).parent)


__all__ = [
    "AWAITING_COMPOSITION",
    "BACKUP_SUFFIXES",
    "BackupUnusable",
    "INVALID",
    "IdentityRecovery",
    "KINDS",
    "KIND_RECONCILE",
    "KIND_REMOVE",
    "LOCAL_BEFORE",
    "NO_RECORD",
    "OPEN",
    "PREPARED",
    "RECOVERY_FILENAME",
    "REMOTE_BEFORE",
    "RecoveryEvidenceInvalid",
    "STATES",
    "VALID",
    "backup_path",
    "clear_recovery",
    "NOT_TERMINAL",
    "PreparationNotDischargeable",
    "TERMINAL",
    "discharge_terminal_evidence",
    "discharge_preparation",
    "inspect_recovery",
    "read_backup",
    "read_recovery",
    "recovery_path",
    "verify_backups",
    "write_backup",
    "write_recovery",
]
