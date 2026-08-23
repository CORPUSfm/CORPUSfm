"""The reversible key-lifetime migration primitive (packet 1246-02, deliverable 4).

An existing installation holds its keys under the pre-1246-02 names. Moving to the ruled names is
not a rewrite of anything — **the bytes do not change**. Rotating during a rename would put every
encrypted byte in the corpus at risk to buy nothing, which is why the packet forbids it and why
`verify()` proves byte equality rather than trusting the copy.

**Four boundaries, and who crosses them.** This packet builds all four; **1246-03 drives them**
during its service cutover, and only that composed, verified cutover removes the old locations,
retires the environment override, or calls this migration finished:

    prepare()   research + stage. Nothing authoritative has moved.
    activate()  the new locations become the ones a fresh read would find.
    verify()    prove the corpus and the machine still open, BY PATH.
    commit()    record the migration as committed. Requires a cutover proof this packet never
                constructs in production code.

**Why `verify()` reads by path.** The ambient key resolver honours `CORPUSFM_ENCRYPTION_KEY` and
caches what it last resolved. Verifying through it could therefore pass while reading the
environment override, or a cached copy of the old file, and report a migration proven that never
touched the staged files at all (Codex design review, finding 1). So verification loads the staged
bytes directly and compares them to what the pre-migration source held.

**What rollback can and cannot undo** (finding 2). Files this operation staged are removed; files
that already existed are left exactly as found. The manifest returns to the generation this
operation started from — 1246-01 retains `.prev` per *operation*, not per write, so several writes
inside one migration still roll back to the state before any of them. The corpus identity record is
different in kind: it is a durable write to the corpus, it is idempotent, and it is what makes a
Recovery File verifiable at all. Rolling it back would discard the corpus's name to undo a local
file rename. So it is a **retained checkpoint**: rollback leaves it, and a later `prepare()`
recognises and reuses it. After `commit()` there is nothing to roll back to, and `rollback()` says
so rather than pretending.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

from . import corpus_identity
from datetime import datetime, timezone

from .errors import LifecycleError, RecordInvalid, RecordMissing
from .atomic import atomic_write_bytes
from .lock import require_lock
from .schema import MIGRATION_BRIDGED, KeyMigrationRecord
from .result import (
    COMPLETED,
    NO_CHANGE,
    ROLLED_BACK,
)

PREPARED = "prepared"
ACTIVATED = "activated"
VERIFIED = "verified"
COMMITTED = "committed"

MIGRATION_STATES = (PREPARED, ACTIVATED, VERIFIED, COMMITTED)

KEY_FILE_MODE = 0o600
KEY_DIR_MODE = 0o700


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# prepared → activated → verified → committed, and nothing else. A state machine rather than a set
# of labels, for the same reason the journal is one: an unreachable combination that validates is a
# state nobody designed and nobody tests.
MIGRATION_TRANSITIONS = {
    None: (PREPARED,),
    PREPARED: (PREPARED, ACTIVATED),
    ACTIVATED: (ACTIVATED, VERIFIED),
    VERIFIED: (VERIFIED, COMMITTED),
    COMMITTED: (),
}


class MigrationStateError(LifecycleError):
    """A migration step was asked for out of order."""


class KeyBytesChanged(LifecycleError):
    """A staged key does not hold the same bytes as its source. Never expected; never ignored."""


class SealResidueUnsupported(LifecycleError):
    """The corpus carries seal residue — an unsupported, unexpected state (1246-02)."""


@dataclass
class CutoverProof:
    """Evidence that a service cutover was performed and verified.

    1246-03 constructs this. Nothing in 1246-02's production code does, which is the mechanical
    form of "this packet does not cut services over": `commit()` cannot be reached from here.
    """
    services_restarted: bool
    storage_verified: bool
    pki_verified: bool
    performed_by: str

    def is_complete(self) -> bool:
        return bool(self.services_restarted and self.storage_verified and self.pki_verified
                    and self.performed_by)


@dataclass
class StagedKey:
    name: str
    source: Optional[Path]
    destination: Path
    source_kind: str = "file"
    created_by_this_operation: bool = False
    source_existed: bool = False


@dataclass
class MigrationState:
    state: Optional[str] = None
    corpus_id: str = ""
    staged: list[StagedKey] = field(default_factory=list)
    verified_probes: dict = field(default_factory=dict)

    def to_manifest_block(self) -> dict:
        return {
            "state": self.state or "",
            "corpus_id": self.corpus_id,
            "staged": [s.name for s in self.staged],
        }


def assert_migration_transition(current: Optional[str], proposed: str) -> None:
    allowed = MIGRATION_TRANSITIONS.get(current)
    if allowed is None:
        raise RecordInvalid(f"unknown migration state {current!r}")
    if proposed not in allowed:
        raise MigrationStateError(
            f"a key migration cannot go from {current or 'not started'} to {proposed}; "
            f"allowed: {', '.join(allowed) or 'nothing — it is finished'}"
        )


def _read_key_bytes(path: Path) -> Optional[bytes]:
    try:
        raw = path.read_bytes().strip()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RecordInvalid(f"could not read the key at {path}: {exc}") from exc
    return raw or None


class KeyMigration:
    """One idempotent, reversible migration of an installation's keys to the ruled names.

    `backend` is the storage backend for the corpus identity record. `probe` supplies the
    verification reads; it is injected so a test can prove each probe's absent-vs-unreadable
    behaviour without a live FileMaker Server.
    """

    def __init__(self, layout, *, corpus_source: Path | None, corpus_destination: Path,
                 machine_source: Path, machine_destination: Path,
                 backend=None, probe=None, corpus_source_bytes: bytes | None = None,
                 manifest_store=None):
        """`corpus_source_bytes` migrates an installation whose Corpus Key comes from the
        environment rather than a file.

        That case is not hypothetical — it is how the whole test suite runs, and how a container
        deployment runs. It has to be **explicit**: the caller states "these are the bytes currently
        in force", they are staged unchanged, and the environment variable is deliberately LEFT
        SHADOWING them until 1246-03's verified cutover retires it. Silently reading the variable
        here would make the migration source invisible in the record.
        """
        self._layout = layout
        self._backend = backend
        self._probe = probe
        self._manifest_store = manifest_store
        if corpus_source is None and not corpus_source_bytes:
            raise RecordMissing(
                "a key migration needs either a corpus key file to migrate from or the explicit "
                "bytes of an environment-sourced key"
            )
        self._corpus_source_bytes = corpus_source_bytes
        self._plan = [
            StagedKey("corpus", Path(corpus_source) if corpus_source else None,
                      Path(corpus_destination),
                      source_kind="environment" if corpus_source_bytes else "file"),
            StagedKey("machine", Path(machine_source), Path(machine_destination)),
        ]
        self.state = MigrationState()

    # ── boundary 1 ────────────────────────────────────────────────────────────────
    def prepare(self, *, lock) -> str:
        """Research, refuse unsupported state, stage identical bytes, establish corpus identity.

        Idempotent: a second call on an already-prepared migration re-checks and returns
        `no_change` rather than restaging.
        """
        self._authority(lock, "preparing the key migration")
        if self.state.state == PREPARED:
            self._assert_staged_bytes_match()
            return NO_CHANGE
        assert_migration_transition(self.state.state, PREPARED)

        self._refuse_seal_residue()

        corpus_bytes = None
        for staged in self._plan:
            source_bytes = (self._corpus_source_bytes
                            if staged.source_kind == "environment"
                            else _read_key_bytes(staged.source))
            existing = _read_key_bytes(staged.destination)
            staged.source_existed = source_bytes is not None
            if source_bytes is None and existing is None:
                where = staged.source if staged.source else "the environment"
                raise RecordMissing(
                    f"no {staged.name} key at {where} or {staged.destination} — there is "
                    "nothing to migrate and nothing to migrate to"
                )
            if existing is not None:
                # Already at the ruled name. If both exist they must agree, or this installation
                # has two different keys claiming the same role and a guess would be data loss.
                if source_bytes is not None and existing != source_bytes:
                    raise KeyBytesChanged(
                        f"the {staged.name} key at {staged.destination} does not match "
                        f"{staged.source}; refusing to choose between two different keys"
                    )
                staged.created_by_this_operation = False
            else:
                self._stage(staged, source_bytes)
            # `_stage` claims cleanup authority before its first byte, so `state.staged` is already
            # current here even when a write died halfway. Nothing to assign after the fact.
            if staged.name == "corpus":
                corpus_bytes = existing if existing is not None else source_bytes

        if corpus_bytes is None:
            raise RecordMissing("the corpus key could not be resolved for identity establishment")
        record = corpus_identity.establish_identity(self._require_backend(), corpus_bytes)
        self.state.corpus_id = record["corpus_id"]
        self.state.staged = list(self._plan)
        self.state.state = PREPARED
        return COMPLETED

    # ── boundary 2 ────────────────────────────────────────────────────────────────
    def activate(self, *, lock) -> str:
        """Stage the configuration reference, so the ruled locations are what the record names.

        The old files stay. The environment override stays. Neither is this packet's to remove —
        both belong to 1246-03's verified cutover.

        **This writes the manifest when it has one.** The first version only set an in-memory label
        and called that "activated", which meant the advertised boundary changed nothing an operator
        or a later child could observe. A `ManifestStore` is optional only so the primitive stays
        unit-testable without a published installation; when one is supplied, activation is durable
        and compare-and-swapped like every other lifecycle write.
        """
        self._authority(lock, "activating the key migration")
        if self._persisted_state() == ACTIVATED:
            return NO_CHANGE
        assert_migration_transition(self.state.state, ACTIVATED)
        self._assert_staged_bytes_match()
        if self._manifest_store is None:
            raise MigrationStateError(
                "activating a key migration requires the installation manifest — an activation that "
                "only sets an in-memory label has changed nothing an operator or a later child can "
                "observe, and must not report ACTIVATED"
            )
        self._write_reference(lock, ACTIVATED)
        self.state.state = ACTIVATED
        return COMPLETED

    def _write_reference(self, lock, state: str) -> None:
        """Record the migration in its OWN typed block, under the held lock.

        An earlier version wrote key paths into `migration.consumers`, whose values are authority
        OWNERS from a fixed vocabulary. A real validating `ManifestStore` rejected it outright —
        every test had omitted the store, so nothing noticed. A path is not an owner; overloading a
        field to avoid adding one is how it comes to mean two things.
        """
        manifest = self._manifest_store.read()
        migration = manifest.migration
        record = KeyMigrationRecord(
            state=state,
            source_kind=self._plan[0].source_kind,
            paths={s.name: str(s.destination) for s in self._plan},
            activated_utc=(_now_utc() if state == ACTIVATED
                           else (migration.key_locations.activated_utc
                                 if migration.key_locations else None)),
            committed_utc=_now_utc() if state == COMMITTED else None,
        )
        updated = replace(
            manifest,
            migration=replace(migration, state=MIGRATION_BRIDGED, key_locations=record),
        )
        self._manifest_store.write(updated, lock=lock,
                                   expected_generation=manifest.generation)

    def _persisted_state(self) -> Optional[str]:
        """The migration state the RECORD says, not the one this object remembers.

        `commit()` used to set an attribute and nothing else, so a new object — or a new process
        after a crash — knew nothing about it. The manifest is the authority; memory is a cache.
        """
        if self._manifest_store is None:
            return self.state.state
        try:
            record = self._manifest_store.read().migration.key_locations
        except LifecycleError:
            return self.state.state
        if record is not None:
            return record.state
        return self.state.state

    # ── boundary 3 ────────────────────────────────────────────────────────────────
    def verify(self, *, lock) -> str:
        """Prove the corpus and the machine still open under the new arrangement.

        Reads the staged files BY PATH — never through the ambient resolver, which honours the
        environment override and caches — and runs every probe the packet names, distinguishing
        *absent* (nothing of that kind exists in this corpus) from *unreadable* (it exists and the
        key did not open it). Only the second is a failure; treating absence as proof would let an
        empty corpus certify a migration that never worked.
        """
        self._authority(lock, "verifying the key migration")
        if self.state.state == VERIFIED:
            return NO_CHANGE
        assert_migration_transition(self.state.state, VERIFIED)
        self._assert_staged_bytes_match()

        corpus_key = _read_key_bytes(self._destination("corpus"))
        machine_key = _read_key_bytes(self._destination("machine"))
        if corpus_key is None or machine_key is None:
            raise RecordMissing("a staged key is missing at verification time")

        record = corpus_identity.require_identity(self._require_backend())
        corpus_identity.assert_key_opens(record, corpus_key)

        results = {}
        for name in ("corpus_blob", "user_secret", "job_credential", "ai_keys"):
            results[name] = self._run_probe(name, corpus_key)
        results["machine_pki"] = self._run_probe("machine_pki", machine_key)
        unreadable = [n for n, r in results.items() if r == "unreadable"]
        if unreadable:
            raise KeyBytesChanged(
                "the migrated keys did not open " + ", ".join(sorted(unreadable))
            )
        self.state.verified_probes = results
        self.state.state = VERIFIED
        return COMPLETED

    # ── boundary 4 ────────────────────────────────────────────────────────────────
    def commit(self, *, lock, cutover_proof: CutoverProof) -> str:
        """Record the migration as committed. Removes nothing.

        Deletion of the old locations and retirement of the environment override are 1246-03's,
        performed as part of the same verified cutover that produces the proof required here.
        """
        self._authority(lock, "committing the key migration")
        if self._persisted_state() == COMMITTED:
            return NO_CHANGE
        assert_migration_transition(self.state.state, COMMITTED)
        if not isinstance(cutover_proof, CutoverProof) or not cutover_proof.is_complete():
            raise MigrationStateError(
                "committing a key migration requires a complete service-cutover proof; a key "
                "migration is not finished by renaming files"
            )
        if self._manifest_store is None:
            raise MigrationStateError(
                "committing a key migration requires the installation manifest — a commit that only "
                "sets an in-memory label leaves nothing for the next process to read"
            )
        # ORDER IS THE SAFETY PROPERTY. Write `committed` while the retained generation still
        # exists, then drop it. A crash between the two leaves the record saying committed with a
        # stale `.prev` beside it — harmless, because `rollback()` reads the RECORD and refuses.
        # The other order loses the rollback target first and would leave a window in which the
        # migration is neither reversible nor committed.
        self._write_reference(lock, COMMITTED)
        self._manifest_store.commit(lock=lock)
        self.state.state = COMMITTED
        return COMPLETED

    # ── reversal ──────────────────────────────────────────────────────────────────
    def rollback(self, *, lock) -> str:
        """Undo what this operation created. Files it did not create are left exactly as found.

        **The record decides whether there is anything to undo, not this object's memory.** A fresh
        object — the case a crash actually produces — has no in-memory state at all, so the earlier
        version answered `no_change` and walked away from a persisted `activated` migration with a
        retained generation still sitting beside it. My own test asserted only that the call did not
        raise, which it did not: it silently did nothing. Found by review, and the test was as wrong
        as the code.
        """
        self._authority(lock, "rolling back the key migration")
        persisted = self._persisted_state()
        if persisted == COMMITTED:
            raise MigrationStateError(
                "this key migration is committed; there is no retained state to roll back to"
            )
        in_memory = self.state.state is not None or any(
            s.created_by_this_operation for s in self._plan)
        if not in_memory and persisted is None:
            return NO_CHANGE
        for staged in self._plan:
            if staged.created_by_this_operation and staged.destination.exists():
                staged.destination.unlink()
                staged.created_by_this_operation = False
        if self._manifest_store is not None and self._manifest_store.has_previous_generation():
            self._manifest_store.rollback(lock=lock)
        self.state.staged = []
        self.state.state = None
        # corpus_identity is deliberately NOT undone — a retained, idempotent checkpoint.
        return ROLLED_BACK

    # ── internals ─────────────────────────────────────────────────────────────────
    def _authority(self, lock, action: str):
        held = require_lock(lock, action)
        if held.layout != self._layout:
            raise LifecycleError(
                f"{action} requires the lifecycle lock for {self._layout.lock_file}, "
                f"not {held.layout.lock_file}"
            )
        return held

    def _destination(self, name: str) -> Path:
        for staged in self._plan:
            if staged.name == name:
                return staged.destination
        raise KeyError(name)

    def _stage(self, staged: StagedKey, source_bytes: bytes) -> None:
        """Atomic, and owned before it exists.

        Two separate defects lived here. `secure_fs.write_bytes_private` unlinks the destination,
        then does one unchecked `os.write` with no fsync — an injected mid-write failure left a
        seven-byte `corpus.key` on disk. And ownership was recorded only *after* a successful write,
        so that stump belonged to nobody and `rollback()` answered `no_change` and left it there.

        So: claim cleanup authority first, then write through the lifecycle's atomic writer
        (stage → flush → fsync → replace → fsync dir), which cannot leave a prefix behind at all.
        Claiming first is deliberately pessimistic — an operation that ends up owning a file it
        never created removes a file that was not there, which is a no-op.
        """
        pre_existing = staged.destination.exists()
        staged.created_by_this_operation = not pre_existing
        self.state.staged = [s for s in self._plan if s.created_by_this_operation]
        atomic_write_bytes(staged.destination, source_bytes, mode=KEY_FILE_MODE,
                           dir_mode=KEY_DIR_MODE)
        written = _read_key_bytes(staged.destination)
        if written != source_bytes:
            raise KeyBytesChanged(
                f"the staged {staged.name} key does not match its source byte for byte"
            )

    def _assert_staged_bytes_match(self) -> None:
        for staged in self._plan:
            destination = _read_key_bytes(staged.destination)
            if destination is None:
                raise RecordMissing(f"the staged {staged.name} key is missing")
            if staged.source_existed:
                source = (self._corpus_source_bytes if staged.source_kind == "environment"
                          else _read_key_bytes(staged.source))
                if source is not None and source != destination:
                    raise KeyBytesChanged(
                        f"the {staged.name} key changed between staging and verification"
                    )

    def _run_probe(self, name: str, key: bytes) -> str:
        """`absent` · `readable` · `unreadable`. No probe function means nothing to check."""
        if self._probe is None:
            return "absent"
        outcome = self._probe(name, key)
        if outcome not in ("absent", "readable", "unreadable"):
            raise RecordInvalid(f"probe {name} returned an unrecognised outcome {outcome!r}")
        return outcome

    def _require_backend(self):
        if self._backend is None:
            raise RecordMissing("a storage backend is required to establish corpus identity")
        return self._backend

    def _refuse_seal_residue(self) -> None:
        """Seal/restore is gone. A corpus still carrying its residue is an unsupported state that
        this code will not reason about — it is reported, not absorbed.

        **Fails CLOSED.** The first version returned quietly when the probe was missing or raised,
        so a network failure, an authentication failure, or a backend that simply lacks the method
        all read as "no residue" — absence assumed rather than established. A migration is a
        privileged, one-way-ish change; *not knowing* is not permission.
        """
        backend = self._backend
        probe = getattr(backend, "seal_residue_state", None)
        if probe is None:
            raise SealResidueUnsupported(
                "this storage backend cannot report whether retired seal residue is present, so its "
                "absence has not been established. Refusing to migrate on an unchecked assumption."
            )
        try:
            state = probe()
        except Exception as exc:
            raise SealResidueUnsupported(
                f"could not establish whether retired seal residue is present ({exc}). Refusing to "
                "migrate on an unchecked assumption."
            ) from exc
        if state == "absent":
            return
        if state == "present":
            raise SealResidueUnsupported(
                "this corpus carries sealed-migration residue from a retired feature. That is an "
                "unsupported, unexpected state; stop and report it rather than migrating over it."
            )
        raise SealResidueUnsupported(
            f"the seal-residue probe answered {state!r}, which is neither present nor absent. "
            "Refusing to migrate on an unclear answer."
        )
