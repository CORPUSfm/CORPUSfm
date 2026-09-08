"""Packet 1246-04 — the composition root: foundation, commit-provider, Protocol P and F.

**What the doubles replace.** Only the locator's privilege check, which needs root
(`ElevationRequired`), and the `patch-compartment`/provider CLIs, which are exercised by their own
packets. Everything under test runs in production code: the real `ManifestStore` and its CAS write,
the real `Journal` and its state machine, the real schema blocks and their validators, and the real
`app_paths` resolution rules.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import replace

import pytest

from corpusfm.lifecycle import composition as comp
from corpusfm.lifecycle import layout as lm
from corpusfm.lifecycle import os_layout as ol
from corpusfm.lifecycle.journal import Journal
from corpusfm.lifecycle.lock import LifecycleLock
from corpusfm.lifecycle.manifest import ManifestStore
from corpusfm.lifecycle.schema import JOURNAL_RESOLVED, LocatorRecord

INST = "3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"
OTHER = "11112222-3333-4444-5555-666677778888"


class FakeLocator:
    """The locator, minus the elevation check. Publication is otherwise the real shape:
    one record, replaced atomically, readable back."""

    def __init__(self):
        self.record = None
        self.publishes = 0

    def read(self):
        if self.record is None:
            raise FileNotFoundError("no locator")
        return self.record

    def publish(self, record, *, lock):
        assert lock is not None, "publication requires the lifecycle lock"
        self.publishes += 1
        self.record = record
        return record


@pytest.fixture
def box(tmp_path, monkeypatch):
    osl = ol.OsLayout(flavour="posix", config_dir=tmp_path / "etc", state_dir=tmp_path / "state",
                      secrets_dir=tmp_path / "secrets", log_dir=tmp_path / "log",
                      run_dir=tmp_path / "run")
    for d in osl.all_dirs():
        d.mkdir(parents=True, exist_ok=True)
    lay = lm.LifecycleLayout(kind=lm.POSIX, lock_file=osl.run_dir / "lifecycle.lock",
                             journal_file=osl.state_dir / "journal.json", locator_dir=osl.config_dir)
    monkeypatch.setattr(ol, "platform_os_layout", lambda: osl)
    monkeypatch.setattr(lm, "platform_layout", lambda: lay)
    install_dir = tmp_path / "opt" / "CORPUSfm"
    install_dir.mkdir(parents=True)
    (tmp_path / "fms").mkdir()
    return {"osl": osl, "layout": lay, "install_dir": install_dir, "fms_root": tmp_path / "fms",
            "hosting": tmp_path / "hosting", "tmp": tmp_path}


def run_foundation(box, locator, *, installation_id=INST, version=None, commit=None):
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        return comp.foundation(
            installation_id=installation_id, install_dir=box["install_dir"],
            fms_root=box["fms_root"], patch_hosting_dir=box["hosting"],
            version=version, commit=commit,
            lock=lock, journal=j, lifecycle_layout=box["layout"], os_layout=box["osl"],
            locator_adapter=locator)


# ── foundation ───────────────────────────────────────────────────────────────


def test_foundation_publishes_generation_1_then_the_locator(box):
    loc = FakeLocator()
    out = run_foundation(box, loc)
    assert out.result == "completed"
    assert out.generation == 1
    assert out.locator_published and loc.publishes == 1
    assert ManifestStore(box["install_dir"]).read().generation == 1


def test_foundation_publishes_the_installer_observed_build_identity(box):
    run_foundation(box, FakeLocator(), version="0.2362", commit="a" * 40)
    build = ManifestStore(box["install_dir"]).read().build
    assert build.version == "0.2362"
    assert build.commit == "a" * 40


def test_foundation_records_installer_identity_separately_from_application_build(box):
    entry_point = box["install_dir"] / "bin" / "corpusfm-installer"
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        comp.foundation(
            installation_id=INST, install_dir=box["install_dir"],
            fms_root=box["fms_root"], patch_hosting_dir=box["hosting"],
            version="0.2371", commit="a" * 40,
            installer_series="series-1", installer_version="0.2370",
            installer_bundle_protocol=1, installer_source="package",
            installer_entry_point=str(entry_point),
            lock=lock, journal=j, lifecycle_layout=box["layout"], os_layout=box["osl"],
            locator_adapter=FakeLocator(),
        )
    manifest = ManifestStore(box["install_dir"]).read()
    assert manifest.build.version == "0.2371"
    assert manifest.installer.series == "series-1"
    assert manifest.installer.version == "0.2370"
    assert manifest.installer.bundle_protocol == 1
    assert manifest.installer.source == "package"
    assert manifest.installer.entry_point == str(entry_point)


def _seed_schema_1(box):
    manifest = replace(comp.build_foundation_manifest(
        installation_id=INST, install_dir=box["install_dir"], fms_root=box["fms_root"],
        patch_hosting_dir=box["hosting"], os_layout=box["osl"],
        version="0.2300", commit="a" * 40), schema_version=1)
    with LifecycleLock(box["layout"]) as lock:
        ManifestStore(box["install_dir"], layout=box["layout"]).write(
            manifest, lock=lock, expected_generation=0)


def _publish_installer(box, *, generation=1, series="series-1", installer_version="0.2372",
                       installer_entry_point=None):
    with LifecycleLock(box["layout"]) as lock:
        return comp.publish_installer_identity(
            installation_id=INST, expected_generation=generation,
            install_dir=box["install_dir"], version="0.2372", commit="b" * 40,
            installer_series=series, installer_version=installer_version,
            installer_bundle_protocol=1, installer_source="package",
            installer_entry_point=installer_entry_point, lock=lock,
            journal=Journal(box["layout"]), lifecycle_layout=box["layout"])


def test_publish_installer_adopts_schema_1_without_rebuilding_other_blocks(box):
    _seed_schema_1(box)
    before = ManifestStore(box["install_dir"]).read()
    out = _publish_installer(box)
    after = ManifestStore(box["install_dir"]).read()
    assert out.result == "completed" and out.adopted
    assert after.schema_version == 2 and after.generation == 2
    assert after.paths == before.paths and after.web == before.web
    assert after.build.version == "0.2372" and after.build.commit == "b" * 40
    assert after.installer.series == "series-1"
    assert Journal(box["layout"]).read() is None


def test_publish_installer_records_and_reads_back_the_durable_entry_point(box):
    _seed_schema_1(box)
    entry_point = str(box["install_dir"] / "bin" / "corpusfm-installer")
    out = _publish_installer(box, installer_entry_point=entry_point)

    assert out.installer_entry_point == entry_point
    assert ManifestStore(box["install_dir"]).read().installer.entry_point == entry_point


def test_publish_installer_advances_within_series_and_is_idempotent(box):
    run_foundation(box, FakeLocator())
    first = _publish_installer(box)
    second = _publish_installer(box, generation=first.generation)
    assert first.generation == 2 and second.result == "no_change"
    assert second.generation == 2


def test_publish_installer_refuses_an_ordinary_cross_series_change(box):
    run_foundation(box, FakeLocator())
    _publish_installer(box)
    with pytest.raises(comp.CompositionError, match="designated bridge"):
        _publish_installer(box, generation=2, series="series-2", installer_version="0.3000")
    assert ManifestStore(box["install_dir"]).read().installer.series == "series-1"


def test_publish_installer_resumes_after_journal_begin_before_checkpoint(box):
    _seed_schema_1(box)
    journal = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        journal.begin(lock=lock, operation_id="interrupted", installation_id=INST,
                      mode="installer_identity")
    out = _publish_installer(box)
    assert out.result == "completed" and out.operation_id == "interrupted"
    assert ManifestStore(box["install_dir"]).read().schema_version == 2
    assert journal.read() is None


def test_publish_installer_resumes_after_manifest_replacement(box):
    _seed_schema_1(box)
    journal = Journal(box["layout"])
    store = ManifestStore(box["install_dir"], layout=box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        journal.begin(lock=lock, operation_id="interrupted", installation_id=INST,
                      mode="installer_identity")
        journal.checkpoint(lock=lock, subsystem="installer_identity")
        current = store.read()
        wanted = replace(
            current, schema_version=2,
            build=comp.BuildBlock(version="0.2372", commit="b" * 40,
                                  observed_at=comp.utc_now_iso()),
            installer=comp.InstallerBlock(series="series-1", version="0.2372",
                                          bundle_protocol=1, source="package"))
        store.write(wanted, lock=lock, expected_generation=1)
    out = _publish_installer(box)
    assert out.result == "no_change" and out.operation_id == "interrupted" and out.adopted
    assert store.read().generation == 2 and journal.read() is None


def test_foundation_records_the_installer_provisioned_uninstaller(box):
    launcher = box["install_dir"] / "uninstall.sh"
    manifest = comp.build_foundation_manifest(
        installation_id=INST,
        install_dir=box["install_dir"],
        fms_root=box["fms_root"],
        patch_hosting_dir=box["hosting"],
        os_layout=box["osl"],
        uninstaller_path=str(launcher),
    )

    assert manifest.uninstaller.entry_point == str(launcher)


def test_the_foundation_manifest_carries_all_SEVEN_path_fields(box):
    """Blocker B4: a manifest missing any of the five layout fields leaves `app_paths` refusing."""
    from corpusfm.lifecycle import app_paths

    run_foundation(box, FakeLocator())
    paths = ManifestStore(box["install_dir"]).read().paths
    assert paths.install_dir and paths.fms_root
    for field in comp.LAYOUT_PATH_FIELDS:
        assert getattr(paths, field), f"{field} was not published"
    assert set(comp.LAYOUT_PATH_FIELDS) == set(app_paths._PATH_FIELDS)


def test_the_published_paths_satisfy_app_paths(box):
    from corpusfm.lifecycle import app_paths

    run_foundation(box, FakeLocator())
    resolved = app_paths._paths_from_manifest(ManifestStore(box["install_dir"]).read(),
                                              source="test")
    assert resolved.secrets_dir == box["osl"].secrets_dir
    assert resolved.config_dir == box["osl"].config_dir


@pytest.mark.parametrize("drop", comp.LAYOUT_PATH_FIELDS)
def test_dropping_any_one_layout_field_makes_app_paths_refuse(box, drop):
    """The negative half — five ways, enumerated, because one missing field is the whole defect."""
    from corpusfm.lifecycle import app_paths
    from corpusfm.lifecycle.schema import InstallationManifest

    run_foundation(box, FakeLocator())
    raw = ManifestStore(box["install_dir"]).read().to_dict()
    raw["paths"][drop] = None
    with pytest.raises(app_paths.InstallationStateUnclear) as exc:
        app_paths._paths_from_manifest(InstallationManifest.from_dict(raw), source="test")
    assert drop in str(exc.value)


def test_the_foundation_publishes_the_fixed_web_facts(box):
    """Blocker B2: `_px_route_facts` requires both, with deliberately no fallback."""
    run_foundation(box, FakeLocator())
    web = ManifestStore(box["install_dir"]).read().web
    assert web.prefix == "/corpusfm" and web.internal_port == 8533


def test_the_foundation_is_not_a_bridged_conversion_manifest(box):
    """`bridge.propose_manifest` builds `migration.state = bridged` — the conversion shape 1246-10
    owns. A fresh installation publishing it would claim to be a converted one."""
    run_foundation(box, FakeLocator())
    m = ManifestStore(box["install_dir"]).read()
    assert m.migration.state != "bridged"
    assert m.migration.source_marker is None


def test_the_foundation_discards_its_own_journal(box):
    run_foundation(box, FakeLocator())
    assert Journal(box["layout"]).read() is None
    assert Journal(box["layout"]).requires_recovery() is False


def test_a_locator_that_never_landed_is_a_RESUMABLE_publication(box):
    """The one interruption a foundation can leave: manifest written, locator not."""
    loc = FakeLocator()

    class PublishDies(FakeLocator):
        def publish(self, record, *, lock):
            raise RuntimeError("died before the locator landed")

    with pytest.raises(RuntimeError):
        run_foundation(box, PublishDies())
    assert ManifestStore(box["install_dir"]).read().generation == 1     # the manifest DID land

    out = run_foundation(box, loc)                                       # the rerun
    assert out.resumed is True
    assert out.locator_published and loc.publishes == 1
    assert ManifestStore(box["install_dir"]).read().generation == 1      # and did NOT write again


def test_a_second_foundation_over_a_published_one_changes_nothing(box):
    loc = FakeLocator()
    run_foundation(box, loc)
    again = run_foundation(box, loc)
    assert again.result == "no_change"
    assert loc.publishes == 1
    assert ManifestStore(box["install_dir"]).read().generation == 1


def test_a_foundation_refuses_another_installations_manifest(box):
    run_foundation(box, FakeLocator())
    with pytest.raises(comp.CompositionError) as exc:
        run_foundation(box, FakeLocator(), installation_id=OTHER)
    assert "belongs to" in str(exc.value)


def test_a_foundation_refuses_over_an_unresolved_journal(box):
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id="somebody-else", installation_id=OTHER,
                mode="proxy_policy")
    with pytest.raises(comp.CompositionError) as exc:
        run_foundation(box, FakeLocator())
    assert "unresolved" in str(exc.value)


def test_a_foundation_refuses_when_it_would_publish_over_composed_work(box):
    """Generation 2+ means providers have already committed; a foundation is generation 1 only."""
    loc = FakeLocator()
    run_foundation(box, loc)
    store = ManifestStore(box["install_dir"], layout=box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        store.write(store.read(), lock=lock, expected_generation=1)      # now generation 2
    with pytest.raises(comp.CompositionError) as exc:
        run_foundation(box, loc)
    assert "already at generation 2" in str(exc.value)


# ── commit-provider: the two protocols ───────────────────────────────────────


PATCH_CANDIDATE = {"patch": {"folder_slot": "1", "registered": True, "verified": True,
                             "sandbox_file": "/srv/corpusfm/patch-hosting/CORPUSfm_Sandbox.fmp12"},
                   "patch_hosting_dir": "/srv/corpusfm/patch-hosting"}
PKI_CANDIDATE = {"pki": {"registration_name": "CORPUSfm-AdminAPI",
                         "public_fingerprint": "sha256:" + "ab" * 32,
                         "last_observation": "working", "last_success_utc": "2026-08-06T00:00:00Z"}}
STORAGE_CANDIDATE = {"storage": {"database_name": "CORPUSfm_DB", "corpus_id": "corpus-aaa",
                                 "connection_name": None, "initialized": True}}
PROXY_CANDIDATE = {"proxy_policy": {"fms-nginx": {"policy": "managed", "config_fingerprint": None}}}


def open_operation(box, op_id, mode="fresh_install", installation_id=INST, resolved=False):
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        j.begin(lock=lock, operation_id=op_id, installation_id=installation_id, mode=mode)
        if resolved:
            j.resolve(lock=lock, result="completed")
    return j


def commit(box, provider, candidate, *, op_id, generation, journal, installation_id=INST):
    with LifecycleLock(box["layout"]) as lock:
        return comp.commit_provider(
            provider=provider, operation_id=op_id, installation_id=installation_id,
            inspected_generation=generation, candidate=candidate,
            install_dir=box["install_dir"], lock=lock, journal=journal,
            lifecycle_layout=box["layout"])


def test_protocol_P_commits_patch_against_a_RESOLVED_entry(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "patch-op", resolved=True)
    out = commit(box, comp.PROVIDER_PATCH, PATCH_CANDIDATE, op_id="patch-op", generation=1,
                 journal=j)
    assert out.result == "completed" and out.committed_generation == 2
    m = ManifestStore(box["install_dir"]).read()
    assert m.patch.folder_slot == "1" and m.patch.verified is True
    assert m.paths.patch_hosting_dir == "/srv/corpusfm/patch-hosting"


def test_protocol_P_REFUSES_an_unresolved_entry(box):
    """Protocol P exists because `apply` resolves before returning. An unresolved entry means the
    apply did not finish, and committing its candidate would publish unfinished work."""
    run_foundation(box, FakeLocator())
    j = open_operation(box, "patch-op", resolved=False)
    with pytest.raises(comp.ProviderMismatch) as exc:
        commit(box, comp.PROVIDER_PATCH, PATCH_CANDIDATE, op_id="patch-op", generation=1, journal=j)
    assert "Protocol P" in str(exc.value)


@pytest.mark.parametrize("provider,candidate", [
    (comp.PROVIDER_PROXY, PROXY_CANDIDATE),
    (comp.PROVIDER_ADMIN_IDENTITY, PKI_CANDIDATE),
    (comp.PROVIDER_STORAGE, STORAGE_CANDIDATE),
])
def test_protocol_F_commits_against_an_UNRESOLVED_entry(box, provider, candidate):
    run_foundation(box, FakeLocator())
    j = open_operation(box, f"{provider}-op", resolved=False)
    out = commit(box, provider, candidate, op_id=f"{provider}-op", generation=1, journal=j)
    assert out.result == "completed" and out.committed_generation == 2


@pytest.mark.parametrize("provider,candidate", [
    (comp.PROVIDER_PROXY, PROXY_CANDIDATE),
    (comp.PROVIDER_ADMIN_IDENTITY, PKI_CANDIDATE),
    (comp.PROVIDER_STORAGE, STORAGE_CANDIDATE),
])
def test_protocol_F_REFUSES_a_resolved_entry(box, provider, candidate):
    """A resolved entry means the provider's finalize already ran; committing after it would leave
    the finalize describing a generation that no longer exists."""
    run_foundation(box, FakeLocator())
    j = open_operation(box, f"{provider}-op", resolved=True)
    with pytest.raises(comp.ProviderMismatch) as exc:
        commit(box, provider, candidate, op_id=f"{provider}-op", generation=1, journal=j)
    assert "Protocol F" in str(exc.value)


def test_a_commit_joins_the_operation_and_opens_NO_second_journal(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "proxy-op", mode="proxy_policy")
    before = Journal(box["layout"]).read()
    commit(box, comp.PROVIDER_PROXY, PROXY_CANDIDATE, op_id="proxy-op", generation=1, journal=j)
    after = Journal(box["layout"]).read()
    assert after.operation_id == before.operation_id == "proxy-op"
    assert after.state == before.state


def test_a_commit_refuses_a_foreign_operation_id(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "proxy-op", mode="proxy_policy")
    with pytest.raises(comp.ProviderMismatch):
        commit(box, comp.PROVIDER_PROXY, PROXY_CANDIDATE, op_id="somebody-else", generation=1,
               journal=j)


def test_a_commit_refuses_another_installations_operation(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "proxy-op", mode="proxy_policy", installation_id=OTHER)
    with pytest.raises(comp.ProviderMismatch):
        commit(box, comp.PROVIDER_PROXY, PROXY_CANDIDATE, op_id="proxy-op", generation=1, journal=j)


def test_a_commit_refuses_when_the_generation_moved(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "proxy-op", mode="proxy_policy")
    with pytest.raises(comp.CompositionError) as exc:
        commit(box, comp.PROVIDER_PROXY, PROXY_CANDIDATE, op_id="proxy-op", generation=7, journal=j)
    assert "re-observe" in str(exc.value)


def test_a_commit_writes_ONLY_its_own_provider_block(box):
    """Every other block is carried through untouched — the whole point of a per-provider write."""
    run_foundation(box, FakeLocator())
    j1 = open_operation(box, "patch-op", resolved=True)
    commit(box, comp.PROVIDER_PATCH, PATCH_CANDIDATE, op_id="patch-op", generation=1, journal=j1)
    with LifecycleLock(box["layout"]) as lock:
        j1.discard(lock=lock)
    patch_before = ManifestStore(box["install_dir"]).read().patch.to_dict()

    j2 = open_operation(box, "storage-op")
    commit(box, comp.PROVIDER_STORAGE, STORAGE_CANDIDATE, op_id="storage-op", generation=2,
           journal=j2)
    m = ManifestStore(box["install_dir"]).read()
    assert m.patch.to_dict() == patch_before, "the storage commit disturbed the patch block"
    assert m.storage.corpus_id == "corpus-aaa"
    assert m.web.prefix == "/corpusfm"                       # and the foundation's facts survive


def test_a_commit_cannot_write_an_arbitrary_manifest_field(box):
    """The candidate is parsed through the real schema type; unknown keys never reach the manifest."""
    run_foundation(box, FakeLocator())
    j = open_operation(box, "storage-op")
    with pytest.raises(comp.CompositionError):
        commit(box, comp.PROVIDER_STORAGE,
               {"storage": {"database_name": "CORPUSfm_DB", "surprise": "x"}},
               op_id="storage-op", generation=1, journal=j)


def test_an_invalid_candidate_is_refused_before_any_write(box):
    run_foundation(box, FakeLocator())
    before = ManifestStore(box["install_dir"]).read().to_dict()
    j = open_operation(box, "pki-op")
    with pytest.raises(comp.CompositionError):
        commit(box, comp.PROVIDER_ADMIN_IDENTITY, {"pki": {"registration_name": 7}},
               op_id="pki-op", generation=1, journal=j)
    assert ManifestStore(box["install_dir"]).read().to_dict() == before


def test_an_unknown_provider_is_refused(box):
    run_foundation(box, FakeLocator())
    j = open_operation(box, "x-op")
    with pytest.raises(comp.CompositionError):
        commit(box, "invented", {}, op_id="x-op", generation=1, journal=j)


# ── crash boundaries ─────────────────────────────────────────────────────────


def test_a_retry_after_the_write_landed_does_NOT_write_again(box):
    """The crash between CAS and the caller acting on it. A second write would move the generation
    under a provider about to be finalized against the first one."""
    run_foundation(box, FakeLocator())
    j = open_operation(box, "storage-op")
    first = commit(box, comp.PROVIDER_STORAGE, STORAGE_CANDIDATE, op_id="storage-op",
                   generation=1, journal=j)
    assert first.committed_generation == 2

    retry = commit(box, comp.PROVIDER_STORAGE, STORAGE_CANDIDATE, op_id="storage-op",
                   generation=1, journal=j)
    assert retry.result == "no_change"
    assert retry.already_committed is True
    assert retry.committed_generation == 2
    assert ManifestStore(box["install_dir"]).read().generation == 2


def test_a_retry_with_a_DIFFERENT_candidate_at_the_same_generation_refuses(box):
    """Idempotence is for the SAME candidate. A different one is a real generation conflict."""
    run_foundation(box, FakeLocator())
    j = open_operation(box, "storage-op")
    commit(box, comp.PROVIDER_STORAGE, STORAGE_CANDIDATE, op_id="storage-op", generation=1,
           journal=j)
    other = {"storage": {"database_name": "CORPUSfm_DB", "corpus_id": "corpus-DIFFERENT",
                         "connection_name": None, "initialized": True}}
    with pytest.raises(comp.CompositionError):
        commit(box, comp.PROVIDER_STORAGE, other, op_id="storage-op", generation=1, journal=j)


# ── the discard boundary ─────────────────────────────────────────────────────


def test_discard_refuses_an_unresolved_operation(box):
    j = open_operation(box, "proxy-op", mode="proxy_policy")
    with pytest.raises(comp.CompositionError) as exc:
        with LifecycleLock(box["layout"]) as lock:
            comp.discard_provider_journal(j, lock, operation_id="proxy-op")
    assert "not resolved" in str(exc.value)
    assert Journal(box["layout"]).read() is not None


def test_discard_refuses_somebody_elses_operation(box):
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    with pytest.raises(comp.ProviderMismatch):
        with LifecycleLock(box["layout"]) as lock:
            comp.discard_provider_journal(j, lock, operation_id="a-different-operation")


def test_discard_clears_the_boundary_so_the_next_provider_can_begin(box):
    """The measured reason discard is required: `storage` answers `foreign_open` on the PRESENCE of
    any record — resolved or not, ours or not."""
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    with LifecycleLock(box["layout"]) as lock:
        comp.discard_provider_journal(j, lock, operation_id="proxy-op")
    assert Journal(box["layout"]).read() is None
    with LifecycleLock(box["layout"]) as lock:
        Journal(box["layout"]).begin(lock=lock, operation_id="next-op", installation_id=INST,
                                     mode="fresh_install")
    assert Journal(box["layout"]).read().operation_id == "next-op"


def test_a_leftover_resolved_record_blocks_the_next_begin(box):
    """The control for the rule above: WITHOUT the discard, the next provider cannot start."""
    from corpusfm.lifecycle.errors import LifecycleError

    open_operation(box, "proxy-op", mode="proxy_policy", resolved=False)
    with pytest.raises(LifecycleError):
        with LifecycleLock(box["layout"]) as lock:
            Journal(box["layout"]).begin(lock=lock, operation_id="next-op", installation_id=INST,
                                         mode="fresh_install")


# ── the full serialized walk ─────────────────────────────────────────────────


def test_the_whole_fresh_walk_reaches_generation_5_in_the_ruled_order(box):
    """Foundation 1, patch 2, proxy 3, admin-identity 4, storage 5 — each discarding its journal
    before the next begins, which is what makes the next `begin` legal at all."""
    loc = FakeLocator()
    assert run_foundation(box, loc).generation == 1
    assert Journal(box["layout"]).read() is None

    seq = [
        (comp.PROVIDER_PATCH, PATCH_CANDIDATE, True, "fresh_install", 2),
        (comp.PROVIDER_PROXY, PROXY_CANDIDATE, False, "proxy_policy", 3),
        (comp.PROVIDER_ADMIN_IDENTITY, PKI_CANDIDATE, False, "fresh_install", 4),
        (comp.PROVIDER_STORAGE, STORAGE_CANDIDATE, False, "fresh_install", 5),
    ]
    for provider, candidate, resolved, mode, expected in seq:
        op = f"{provider}-op"
        j = open_operation(box, op, mode=mode, resolved=resolved)
        out = commit(box, provider, candidate, op_id=op, generation=expected - 1, journal=j)
        assert out.committed_generation == expected, provider
        with LifecycleLock(box["layout"]) as lock:
            if Journal(box["layout"]).read().state != JOURNAL_RESOLVED:
                j.resolve(lock=lock, result="completed")       # Protocol F: the provider's finalize
            comp.discard_provider_journal(j, lock, operation_id=op)
        assert Journal(box["layout"]).read() is None, f"{provider} left a journal behind"

    m = ManifestStore(box["install_dir"]).read()
    assert m.generation == 5
    assert m.patch.verified and m.pki.registration_name and m.storage.corpus_id
    assert m.proxy_policy["fms-nginx"].policy == "managed"
    assert m.web.prefix == "/corpusfm" and m.web.internal_port == 8533


# ── correction A: the boundary CHECKS identity instead of trusting the caller ────────────────
#
# `discard_provider_journal` had no production caller at all - `commit_provider` does not call it,
# no CLI verb exposed it, and both installers merely CLAIMED in a comment that the boundary
# performed it. So every provider ran with the previous provider's record still in place, which is
# precisely the condition `storage` answers `foreign_open` to. The verb below is that caller, and
# because its request arrives as a JSON file written by a shell, the identity in it is checked here
# rather than believed.


def test_discard_is_idempotent_when_there_is_nothing_to_retire(box):
    """`no_change`, and it touches nothing.

    A boundary whose whole purpose is that no record survives it must not fail when that is already
    true - otherwise the second half of a resumed run refuses over its own success.
    """
    j = Journal(box["layout"])
    with LifecycleLock(box["layout"]) as lock:
        assert comp.discard_provider_journal(j, lock, operation_id="proxy-op",
                                             installation_id=INST,
                                             provider=comp.PROVIDER_PROXY) == "no_change"
    assert Journal(box["layout"]).read() is None


def test_a_successful_discard_reports_completed(box):
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    with LifecycleLock(box["layout"]) as lock:
        assert comp.discard_provider_journal(j, lock, operation_id="proxy-op",
                                             installation_id=INST,
                                             provider=comp.PROVIDER_PROXY) == "completed"
    assert Journal(box["layout"]).read() is None


def test_discard_refuses_a_record_belonging_to_another_installation(box):
    """A foreign record is RETAINED. A journal is the only evidence of where an operation stopped,
    and discarding somebody else's is not recoverable by re-running anything."""
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    with pytest.raises(comp.ProviderMismatch, match="installation"):
        with LifecycleLock(box["layout"]) as lock:
            comp.discard_provider_journal(j, lock, operation_id="proxy-op",
                                          installation_id="some-other-installation",
                                          provider=comp.PROVIDER_PROXY)
    assert Journal(box["layout"]).read() is not None


def test_discard_refuses_a_record_belonging_to_another_provider(box):
    # Checkpoint BEFORE resolving: the journal permits `open -> checkpointed`, not the reverse, so
    # the subsystem has to be stamped while the operation is still open.
    j = open_operation(box, "op-1", mode="fresh_install")
    with LifecycleLock(box["layout"]) as lock:
        Journal(box["layout"]).checkpoint(lock=lock, subsystem="admin_identity")
    with LifecycleLock(box["layout"]) as lock:
        Journal(box["layout"]).resolve(lock=lock, result="completed")
    with pytest.raises(comp.ProviderMismatch, match="boundary is"):
        with LifecycleLock(box["layout"]) as lock:
            comp.discard_provider_journal(Journal(box["layout"]), lock, operation_id="op-1",
                                          installation_id=INST, provider=comp.PROVIDER_STORAGE)
    assert Journal(box["layout"]).read() is not None


@pytest.mark.parametrize("subsystem,provider,belongs", [
    ("admin_identity", "admin_identity", True),
    ("admin-identity", "admin_identity", True),
    ("patch_compartment", "patch", True),
    ("storage:template_placed", "storage", True),
    ("storage", "storage", True),
    ("patch_compartment", "proxy", False),
    ("admin_identity", "patch", False),
    ("proxy", "storage", False),
])
def test_the_subsystem_rule_is_a_boundary_not_a_substring(subsystem, provider, belongs):
    """The spellings are MEASURED from production, not guessed: `admin_identity_ops` writes
    `admin_identity`, the patch CLI writes `patch_compartment`, and storage writes
    `storage:<step>`. A substring rule would let one provider retire another's record; one exact
    spelling would refuse two of the three forms production actually writes."""
    assert comp._subsystem_belongs_to(subsystem, provider) is belongs


def test_a_record_that_names_no_subsystem_is_not_treated_as_foreign(box):
    """Absence of evidence is not evidence of a mismatch: a provider that cleared its subsystem on
    the way to resolution would otherwise strand its own record forever."""
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    assert Journal(box["layout"]).read().current_subsystem in (None, "")
    with LifecycleLock(box["layout"]) as lock:
        assert comp.discard_provider_journal(j, lock, operation_id="proxy-op",
                                             installation_id=INST,
                                             provider=comp.PROVIDER_PROXY) == "completed"


def test_an_unknown_provider_name_is_refused_before_anything_is_read(box):
    j = open_operation(box, "proxy-op", mode="proxy_policy", resolved=True)
    with pytest.raises(comp.ProviderMismatch, match="must be one of"):
        with LifecycleLock(box["layout"]) as lock:
            comp.discard_provider_journal(j, lock, operation_id="proxy-op",
                                          installation_id=INST, provider="not-a-provider")
    assert Journal(box["layout"]).read() is not None
