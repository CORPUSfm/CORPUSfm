"""A001's authority tail — removing the retired `scheduler` entry from the installation record.

**Physical retirement and authority retirement are different things, and A001 owes both.** The
installers already prove the physical half: on Windows the service is unregistered and its
definition and wrapper are gone; on Linux the unit file is gone and systemd reports no loadable
unit. Neither retired the AUTHORITY. Measured on w-test-private, 2026-09-03: after a green upgrade
AND a green idempotent rerun, the published `installation.json` still recorded a `scheduler` service
with an identity that no longer resolves and a unit path that no longer exists, at generation 8.

These tests drive the real `ManifestStore` and its compare-and-swap, the real `Journal` and its
state machine, and the real schema validators. Only the locator's elevation check is doubled.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import replace

import pytest

from corpusfm.lifecycle import composition as comp
from corpusfm.lifecycle import layout as lm
from corpusfm.lifecycle import os_layout as ol
from corpusfm.lifecycle.errors import GenerationConflict
from corpusfm.lifecycle.journal import Journal
from corpusfm.lifecycle.lock import LifecycleLock
from corpusfm.lifecycle.manifest import ManifestStore
from corpusfm.lifecycle.schema import ServiceEntry
from corpusfm.lifecycle.service_identity import SCHEDULER_ROLE, WEB_ROLE

from tests.test_composition import INST, OTHER, FakeLocator, box, run_foundation  # noqa: F401


SCHED = ServiceEntry(name="corpusfm-scheduler", role=SCHEDULER_ROLE,
                     identity="NT SERVICE\\corpusfm-scheduler",
                     unit="C:\\Program Files\\CORPUSfm\\services\\corpusfm-scheduler.xml",
                     unit_kind="service")


def _store(box):
    return ManifestStore(box["install_dir"], layout=box["layout"])


def _seed(box, *, services):
    """Publish a foundation, then put the given service list on it — the two-service source state."""
    run_foundation(box, FakeLocator())
    store = _store(box)
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        current = store.read()
        store.write(replace(current, services=tuple(services)), lock=lock,
                    expected_generation=current.generation)
        store.commit(lock=lock)
        if j.read() is not None:
            j.discard(lock=lock)
    return store.read()


def _retire(box, *, generation, installation_id=INST):
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        return comp.retire_scheduler_authority(
            installation_id=installation_id, expected_generation=generation,
            install_dir=box["install_dir"], lock=lock, journal=j,
            lifecycle_layout=box["layout"])


WEB = ServiceEntry(name="corpusfm-web", role=WEB_ROLE, identity="NT SERVICE\\corpusfm-web",
                   unit="C:\\Program Files\\CORPUSfm\\services\\corpusfm-web.xml")
UPD = ServiceEntry(name="CORPUSfm Update", role="updater", identity="SYSTEM",
                   unit="C:\\Program Files\\CORPUSfm\\bin\\corpusfm-update.ps1",
                   unit_kind="scheduled_task")


# ── the removal, and EXACT preservation of everything else ────────────────────────────────────────

def test_it_removes_only_the_scheduler_entry_and_preserves_every_other_field(box):
    before = _seed(box, services=[WEB, SCHED, UPD])
    assert [s.role for s in before.services] == [WEB_ROLE, SCHEDULER_ROLE, "updater"]

    out = _retire(box, generation=before.generation)

    assert out.result == "completed" and out.removed is True
    after = _store(box).read()
    assert [s.role for s in after.services] == [WEB_ROLE, "updater"]
    # the survivors are carried by identity, field for field
    assert [s.to_dict() for s in after.services] == [WEB.to_dict(), UPD.to_dict()]
    # and NOTHING else moved except the generation and the timestamp
    b, a = before.to_dict(), after.to_dict()
    for key in ("services", "generation", "updated_utc"):
        b.pop(key, None); a.pop(key, None)
    assert a == b, "a field outside `services` changed"
    assert after.generation == before.generation + 1


def test_the_committed_generation_is_returned(box):
    before = _seed(box, services=[WEB, SCHED])
    out = _retire(box, generation=before.generation)
    assert out.generation == before.generation + 1 == _store(box).read().generation


def test_the_journal_is_resolved_and_discarded(box):
    before = _seed(box, services=[WEB, SCHED])
    _retire(box, generation=before.generation)
    assert Journal(box["layout"]).read() is None, "the journal was not retired"


# ── the true no-op ────────────────────────────────────────────────────────────────────────────────

def test_a_current_installation_is_a_true_no_op(box):
    before = _seed(box, services=[WEB, UPD])
    out = _retire(box, generation=before.generation)
    assert out.result == "no_change" and out.removed is False
    after = _store(box).read()
    assert after.generation == before.generation, "an absent entry moved the generation"
    assert after.to_dict() == before.to_dict(), "a no-op wrote to the manifest"
    assert Journal(box["layout"]).read() is None, "a no-op opened a journal"


def test_a_second_run_neither_rewrites_the_manifest_nor_advances_the_generation(box):
    before = _seed(box, services=[WEB, SCHED, UPD])
    first = _retire(box, generation=before.generation)
    once = _store(box).read()

    second = _retire(box, generation=first.generation)

    assert second.result == "no_change" and second.removed is False
    twice = _store(box).read()
    assert twice.generation == once.generation
    assert twice.to_dict() == once.to_dict(), "the second run rewrote the record"


# ── binding and refusals ──────────────────────────────────────────────────────────────────────────

def test_a_wrong_installation_id_refuses(box):
    before = _seed(box, services=[WEB, SCHED])
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation, installation_id=OTHER)
    assert "not" in str(e.value)
    assert any(s.role == SCHEDULER_ROLE for s in _store(box).read().services), \
        "the manifest was touched despite the refusal"


def test_a_stale_inspected_generation_refuses_before_writing(box):
    before = _seed(box, services=[WEB, SCHED])
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation + 5)
    assert "re-observe" in str(e.value)
    assert _store(box).read().generation == before.generation


def test_the_request_boundary_accepts_no_caller_selected_role():
    """The security property is an ABSENCE: there is no `role` key, so no request can aim this at
    `web` or `updater`. The retired role is the adapter's, fixed in code."""
    from corpusfm.lifecycle.cli import _CO_REQUEST_KEYS, _CO_OPTIONAL_KEYS
    keys = _CO_REQUEST_KEYS["retire-scheduler-authority"]
    assert "role" not in keys and "provider" not in keys and "services" not in keys
    assert "role" not in _CO_OPTIONAL_KEYS.get("retire-scheduler-authority", frozenset())
    # and it IS bound to the things it must be
    assert keys == frozenset({"schema_version", "installation_id", "expected_generation",
                              "install_dir", "actor"})


def test_a_duplicate_scheduler_entry_cannot_reach_the_operation_and_would_refuse_if_it_did(box):
    """Two guards, and the outer one is the schema's.

    `manifest.services` already refuses two entries for one role at write time, so a duplicate
    cannot be published at all — asserted here rather than assumed. The operation carries its own
    refusal anyway, driven directly, because "unreachable today" is not "unreachable".
    """
    from corpusfm.lifecycle.errors import RecordInvalid
    with pytest.raises(RecordInvalid) as outer:
        _seed(box, services=[WEB, SCHED, SCHED, UPD])
    assert "two entries for role" in str(outer.value)

    before = _seed(box, services=[WEB, SCHED, UPD])
    real_read = ManifestStore.read
    monkey = {"n": 0}

    def duplicating_read(self):
        m = real_read(self)
        monkey["n"] += 1
        if monkey["n"] == 1:
            return replace(m, services=(WEB, SCHED, SCHED, UPD))
        return m

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ManifestStore, "read", duplicating_read)
        with pytest.raises(comp.CompositionError) as inner:
            _retire(box, generation=before.generation)
    assert "exactly one" in str(inner.value)


# ── the two interruption boundaries ───────────────────────────────────────────────────────────────

def test_interrupted_BEFORE_the_write_is_re_entered_and_completes(box):
    """Crash boundary 1: journal open, manifest untouched."""
    before = _seed(box, services=[WEB, SCHED, UPD])
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id="op-crash-1", installation_id=INST, mode=comp.A001_MODE)

    out = _retire(box, generation=before.generation)

    assert out.result == "completed" and out.removed is True and out.resumed is True
    assert out.operation_id == "op-crash-1", "the resumed run opened a second operation"
    after = _store(box).read()
    assert [s.role for s in after.services] == [WEB_ROLE, "updater"]
    assert after.generation == before.generation + 1
    assert Journal(box["layout"]).read() is None


def test_interrupted_AFTER_the_write_finishes_without_a_second_write(box):
    """Crash boundary 2: the manifest write landed, the commit and journal retirement did not.

    An already-absent entry must NOT be read as `no_change` here — that is the difference between
    the healing path and the fresh path, and the generation is what proves no second write happened.
    """
    before = _seed(box, services=[WEB, SCHED, UPD])
    j = Journal(box["layout"])
    store = _store(box)
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id="op-crash-2", installation_id=INST, mode=comp.A001_MODE)
        j.checkpoint(lock=lock, subsystem=comp.A001_MODE, intended_change="x", resume_hint="y")
        current = store.read()
        store.write(replace(current, services=(WEB, UPD)), lock=lock,
                    expected_generation=current.generation)
    written = store.read().generation
    assert written == before.generation + 1

    out = _retire(box, generation=before.generation)

    assert out.operation_id == "op-crash-2" and out.resumed is True
    after = _store(box).read()
    assert after.generation == written, "the resumed run wrote the manifest a second time"
    assert not any(s.role == SCHEDULER_ROLE for s in after.services)
    assert Journal(box["layout"]).read() is None, "the journal was not retired"


def test_a_foreign_journal_refuses(box):
    before = _seed(box, services=[WEB, SCHED])
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        # A real, valid mode belonging to somebody else — `uninstall` is as foreign to A001 as a
        # mode gets, and unlike an invented word it is one the journal will actually accept.
        j.begin(lock=lock, operation_id="op-other", installation_id=INST, mode="uninstall")
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "resolve it before" in str(e.value)
    assert any(s.role == SCHEDULER_ROLE for s in _store(box).read().services)


def test_a_journal_for_another_installation_refuses(box):
    before = _seed(box, services=[WEB, SCHED])
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id="op-x", installation_id=OTHER, mode=comp.A001_MODE)
    with pytest.raises(comp.CompositionError):
        _retire(box, generation=before.generation)
    assert any(s.role == SCHEDULER_ROLE for s in _store(box).read().services)


def test_a_resumed_journal_with_a_contradictory_generation_refuses(box):
    before = _seed(box, services=[WEB, SCHED])
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id="op-far", installation_id=INST, mode=comp.A001_MODE)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation + 7)
    assert "expected generation" in str(e.value)


# ── CAS conflict and read-back failure ────────────────────────────────────────────────────────────

def test_a_concurrent_write_makes_the_compare_and_swap_conflict(box, monkeypatch):
    """The generation moves under the operation between its observation and its write."""
    before = _seed(box, services=[WEB, SCHED, UPD])
    real_write = ManifestStore.write
    state = {"bumped": False}

    def racing_write(self, manifest, *, lock, expected_generation):
        if not state["bumped"]:
            state["bumped"] = True
            current = ManifestStore.read(self)
            real_write(self, replace(current, services=(WEB, SCHED, UPD)), lock=lock,
                       expected_generation=current.generation)
        return real_write(self, manifest, lock=lock, expected_generation=expected_generation)

    monkeypatch.setattr(ManifestStore, "write", racing_write)
    with pytest.raises(GenerationConflict):
        _retire(box, generation=before.generation)


def test_a_read_back_that_still_shows_the_scheduler_refuses_to_report_success(box, monkeypatch):
    before = _seed(box, services=[WEB, SCHED, UPD])
    real_read = ManifestStore.read
    seen = {"n": 0}

    def lying_read(self):
        m = real_read(self)
        seen["n"] += 1
        if seen["n"] >= 3:                      # the post-write read-back
            return replace(m, services=(WEB, SCHED, UPD))
        return m

    monkeypatch.setattr(ManifestStore, "read", lying_read)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "still recorded" in str(e.value)


def test_a_read_back_whose_other_fields_moved_refuses(box, monkeypatch):
    """The preservation claim is MEASURED. If anything outside `services` differs on the read-back,
    nothing may be reported as retired."""
    before = _seed(box, services=[WEB, SCHED, UPD])
    real_read = ManifestStore.read
    seen = {"n": 0}

    def drifting_read(self):
        m = real_read(self)
        seen["n"] += 1
        if seen["n"] >= 3:
            return replace(m, storage=replace(m.storage, database_name="SOMETHING_ELSE"))
        return m

    monkeypatch.setattr(ManifestStore, "read", drifting_read)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "outside `services`" in str(e.value)


# ── it is not a general migration facility ────────────────────────────────────────────────────────

def test_it_does_not_regenerate_services_from_current_roles(box):
    """A rebuild from `SERVICE_ROLES` would silently repair any other drift — a different, larger and
    unreviewed claim.

    `SERVICE_ROLES` is `('web',)` alone, so a regenerated list would drop the `updater` entry too.
    Its survival is the discriminating observation, and it is a real entry rather than an invented
    stray because the schema allows only one entry per role.
    """
    from corpusfm.lifecycle.service_identity import SERVICE_ROLES
    assert SERVICE_ROLES == (WEB_ROLE,), "the premise moved; re-derive what a rebuild would drop"

    before = _seed(box, services=[WEB, SCHED, UPD])
    _retire(box, generation=before.generation)
    after = _store(box).read()
    assert [s.to_dict() for s in after.services] == [WEB.to_dict(), UPD.to_dict()]


def test_the_operation_names_one_role_and_takes_none(box):
    import inspect
    sig = inspect.signature(comp.retire_scheduler_authority)
    assert "role" not in sig.parameters, "the retired role is selectable by the caller"
    src = inspect.getsource(comp.retire_scheduler_authority)
    assert "SCHEDULER_ROLE" in src
    for rebuild in ("canonical_service_records", "SERVICE_ROLES"):
        assert rebuild not in src, f"the services list is rebuilt from {rebuild}"


def test_a_true_no_op_OPENS_NO_JOURNAL_AND_COMMITS_NOTHING(box, monkeypatch):
    """Control 87 came back NOT CAUGHT, and this is why.

    `test_a_current_installation_is_a_true_no_op` asserts the journal is absent AFTERWARDS — which
    is equally true of a run that opened one and then discarded it. Dropping the early return
    produced exactly that: a journal begun and retired, and `ManifestStore.commit` called, on every
    installer run of a current installation. `commit` is not free — it is what promotes and prunes
    the previous-generation file, i.e. the rollback evidence.

    So the property is that neither is REACHED, and it is asserted by counting the calls.
    """
    before = _seed(box, services=[WEB, UPD])
    calls = {"begin": 0, "commit": 0, "write": 0}
    for cls, name in ((Journal, "begin"), (ManifestStore, "commit"), (ManifestStore, "write")):
        real = getattr(cls, name)

        def spy(self, *a, __real=real, __name=name, **kw):
            calls[__name] += 1
            return __real(self, *a, **kw)

        monkeypatch.setattr(cls, name, spy)

    out = _retire(box, generation=before.generation)

    assert out.result == "no_change" and out.removed is False
    assert calls == {"begin": 0, "commit": 0, "write": 0}, (
        f"a true no-op reached the lifecycle machinery: {calls}")
    assert _store(box).read().generation == before.generation


# ── a matching mode and installation id are NOT sufficient ────────────────────────────────────────
#
# They say the record is about this adapter and this box. They say nothing about whether it is a
# state this operation may resume, and resuming the others would be inventing history.

def _put_journal(box, **fields):
    """Write a journal record directly, so states the state machine will not transition into can
    still be presented to the operation."""
    from corpusfm.lifecycle.schema import JournalRecord
    import json as _json
    rec = JournalRecord(**fields)
    box["layout"].journal_file.write_text(_json.dumps(rec.to_dict()), encoding="utf-8")


def test_a_needs_recovery_journal_is_not_resumable(box):
    before = _seed(box, services=[WEB, SCHED])
    _put_journal(box, operation_id="op-nr", installation_id=INST, mode=comp.A001_MODE,
                 state="needs_recovery", current_subsystem=comp.A001_MODE)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "needs_recovery" in str(e.value)
    assert any(s.role == SCHEDULER_ROLE for s in _store(box).read().services)


def test_a_contradictory_subsystem_is_not_resumable(box):
    before = _seed(box, services=[WEB, SCHED])
    _put_journal(box, operation_id="op-sub", installation_id=INST, mode=comp.A001_MODE,
                 state="checkpointed", current_subsystem="storage")
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "contradicts its own mode" in str(e.value)


def test_an_open_journal_that_names_a_subsystem_is_not_resumable(box):
    before = _seed(box, services=[WEB, SCHED])
    _put_journal(box, operation_id="op-open", installation_id=INST, mode=comp.A001_MODE,
                 state="open", current_subsystem=comp.A001_MODE)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "contradicts itself" in str(e.value)


#: `None` is deliberately absent: a resolved record carrying no result is refused by the journal's
#: own reader before this guard is reached, which is a stricter outer boundary and not this
#: operation's subject.
@pytest.mark.parametrize("result", ["rolled_back", "failed_before_change", "no_change"])
def test_a_resolved_journal_with_any_other_result_is_not_resumable(box, result):
    before = _seed(box, services=[WEB, SCHED])
    _put_journal(box, operation_id="op-res", installation_id=INST, mode=comp.A001_MODE,
                 state="resolved", current_subsystem=comp.A001_MODE, result=result)
    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=before.generation)
    assert "only a completed" in str(e.value)
    assert any(s.role == SCHEDULER_ROLE for s in _store(box).read().services)


def test_a_resolved_completed_journal_with_the_entry_ALREADY_GONE_is_resumable(box):
    """REPLACES a test that seeded `resolved/completed` with the scheduler still PRESENT and called
    it resumable. That pair is a history this operation could not have written — resolution follows
    the write that removes the entry — so the old test was asserting an impossible state.

    The real crash point is resolved-after-the-write, before the discard: the entry is gone and only
    the journal is left. That is what must still finish, and it must finish WITHOUT a second write.
    """
    seeded = _seed(box, services=[WEB, UPD])          # the write already happened
    _put_journal(box, operation_id="op-ok", installation_id=INST, mode=comp.A001_MODE,
                 state="resolved", current_subsystem=comp.A001_MODE, result="completed")

    out = _retire(box, generation=seeded.generation - 1)

    assert out.result == "no_change" and out.removed is False
    assert out.operation_id == "op-ok" and out.resumed is True
    after = _store(box).read()
    assert after.generation == seeded.generation, "the resumed run wrote a second time"
    assert not any(s.role == SCHEDULER_ROLE for s in after.services)
    assert Journal(box["layout"]).read() is None, "the journal was not retired"


def test_a001_is_NOT_a_provider():
    """A001 is routed ahead of provider disposition, never added to it.

    Making it a provider would look like it fixed the reachability defect and would in fact hand
    `_provider_for_journal` a fifth stem, a `_candidate_for` lookup and a `discard-provider` path
    none of which A001 has. The vocabulary is closed here so widening it is a deliberate act.
    """
    from corpusfm.lifecycle.installer_disposition import PROVIDERS, _provider_for_journal
    assert PROVIDERS == frozenset({"admin_identity", "patch", "proxy", "storage"})
    assert comp.A001_MODE not in PROVIDERS
    # and the journal really is unroutable by that boundary — which is WHY the installers must
    # recognise it first
    assert _provider_for_journal(
        {"mode": comp.A001_MODE, "current_subsystem": comp.A001_MODE}) is None


# ── THE STATE MATRIX, cell by cell ────────────────────────────────────────────────────────────────
#
# A journal record and a manifest are not independent facts. The journal is only ever begun while the
# scheduler entry is PRESENT, and only ever resolved after the write that made it ABSENT. So a state
# is legitimate only as a PAIR, and validating the fields separately accepted combinations this
# operation's own ordering cannot produce.
#
#   journal state          subsystem      scheduler entry
#   ─────────────────────  ─────────────  ───────────────────────────────────
#   (none)                 —              present -> begin; absent -> true no-op
#   open                   none           MUST be present
#   checkpointed           A001's         may be present or absent
#   resolved + completed   A001's         MUST be absent

_A001 = "a001_scheduler_authority"

#: (label, journal fields or None, scheduler present)
VALID_CELLS = [
    ("no journal, entry present", None, True),
    ("no journal, entry absent", None, False),
    ("open, entry present", dict(state="open", current_subsystem=None), True),
    ("checkpointed, entry present", dict(state="checkpointed", current_subsystem=_A001), True),
    ("checkpointed, entry absent", dict(state="checkpointed", current_subsystem=_A001), False),
    ("resolved completed, entry absent",
     dict(state="resolved", current_subsystem=_A001, result="completed"), False),
]

INVALID_CELLS = [
    ("open with the entry already absent",
     dict(state="open", current_subsystem=None), False, "could not have written"),
    ("open naming a subsystem",
     dict(state="open", current_subsystem=_A001), True, "contradicts itself"),
    ("checkpointed with no subsystem",
     dict(state="checkpointed", current_subsystem=None), True, "contradicts its own mode"),
    ("checkpointed under another subsystem",
     dict(state="checkpointed", current_subsystem="storage"), True, "contradicts its own mode"),
    ("resolved completed with the entry still recorded",
     dict(state="resolved", current_subsystem=_A001, result="completed"), True,
     "could not have written"),
    ("resolved under another subsystem",
     dict(state="resolved", current_subsystem="storage", result="completed"), False,
     "contradicts its own mode"),
    ("resolved rolled_back",
     dict(state="resolved", current_subsystem=_A001, result="rolled_back"), False,
     "only a completed"),
    ("needs_recovery",
     dict(state="needs_recovery", current_subsystem=_A001), True, "needs_recovery"),
]


def _setup_cell(box, journal_fields, present):
    services = [WEB, SCHED, UPD] if present else [WEB, UPD]
    seeded = _seed(box, services=services)
    if journal_fields is not None:
        _put_journal(box, operation_id="op-cell", installation_id=INST, mode=comp.A001_MODE,
                     **journal_fields)
    return seeded


@pytest.mark.parametrize("label,journal_fields,present",
                         VALID_CELLS, ids=[c[0] for c in VALID_CELLS])
def test_every_VALID_cell_of_the_matrix_is_accepted(box, label, journal_fields, present):
    seeded = _setup_cell(box, journal_fields, present)
    # A resumed record whose write already landed inspected the generation BEFORE that write.
    inspected = seeded.generation - 1 if (journal_fields and not present) else seeded.generation
    out = _retire(box, generation=inspected)
    assert out.result in ("completed", "no_change")
    assert not any(s.role == SCHEDULER_ROLE for s in _store(box).read().services)
    assert Journal(box["layout"]).read() is None, "an accepted cell left its journal behind"


@pytest.mark.parametrize("label,journal_fields,present,needle",
                         INVALID_CELLS, ids=[c[0] for c in INVALID_CELLS])
def test_every_INVALID_cell_refuses_and_MUTATES_NOTHING(box, label, journal_fields, present,
                                                        needle, monkeypatch):
    """The refusal is only half the property. The other half is that no boundary is touched: no
    manifest write or commit, and no journal checkpoint, resolve or discard."""
    seeded = _setup_cell(box, journal_fields, present)
    before_manifest = _store(box).read().to_dict()
    before_journal = box["layout"].journal_file.read_text(encoding="utf-8")

    calls: dict[str, int] = {}
    for cls, name in ((ManifestStore, "write"), (ManifestStore, "commit"),
                      (Journal, "checkpoint"), (Journal, "resolve"), (Journal, "discard"),
                      (Journal, "begin"), (Journal, "mark_needs_recovery")):
        calls[name] = 0
        real = getattr(cls, name)

        def spy(self, *a, __real=real, __name=name, **kw):
            calls[__name] += 1
            return __real(self, *a, **kw)

        monkeypatch.setattr(cls, name, spy)

    with pytest.raises(comp.CompositionError) as e:
        _retire(box, generation=seeded.generation)
    assert needle in str(e.value), f"{label}: {e.value}"

    assert calls == {k: 0 for k in calls}, f"{label} reached the lifecycle machinery: {calls}"
    assert _store(box).read().to_dict() == before_manifest, f"{label} changed the manifest"
    assert box["layout"].journal_file.read_text(encoding="utf-8") == before_journal, \
        f"{label} changed the journal"


def test_the_matrix_covers_every_journal_state_this_build_can_write():
    """A new journal state must not silently fall into an unexamined cell."""
    from corpusfm.lifecycle.schema import JOURNAL_STATES
    covered = {c[1]["state"] for c in VALID_CELLS if c[1]} | {c[1]["state"] for c in INVALID_CELLS}
    assert set(JOURNAL_STATES) <= covered, f"unexamined journal states: {set(JOURNAL_STATES) - covered}"
