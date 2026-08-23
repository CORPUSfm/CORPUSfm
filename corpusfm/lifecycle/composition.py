"""The installer composition root (packet 1246-04 §4F).

Four component providers shipped before this module existed, and every one of them returns a
*candidate* and writes no manifest. Nothing wrote one either: `propose` prints, and
`bridge.propose_manifest` builds a ``migration.state = bridged`` CONVERSION manifest from a legacy
marker. So the family had four things to compose and no composition root. This is it.

**Two integrator-only operations, and nothing else.**

* ``foundation`` — the first write of a new installation. Builds an `InstallationManifest`
  DIRECTLY, writes it at ``expected_generation=0`` (which yields generation 1), reads that back, and
  only then publishes the locator. Manifest-written-but-locator-missing is a RESUMABLE publication,
  not a failure.
* ``commit_provider`` — publishes exactly one provider's owned fields at
  ``expected_generation=inspected_generation``, reads the block back for exact equality, and returns
  the committed generation the caller hands to that provider's ``finalize``.

**Two protocols, because the providers do not share one disposition** (§0.4B):

* **Protocol P** — ``patch-compartment`` alone. Its ``apply`` resolves its own journal and clears
  its recovery evidence before returning (`cli.py` ``_dispose``), so the commit REQUIRES a
  **resolved** entry, there is **no finalize verb**, and the sequence ends at the read-back.
* **Protocol F** — ``proxy``, ``admin-identity``, ``storage``. Each leaves its entry **unresolved**,
  so the commit REQUIRES an unresolved entry and the caller then invokes the provider's shipped
  ``finalize``.

**Discarding the journal at each boundary is REQUIRED, not optional.** ``storage``'s evidence rule
answers ``foreign_open`` on the PRESENCE of any journal record — including a resolved one, including
this installation's own — so a leftover record from the foundation or an earlier provider makes the
next provider refuse before it starts. ``Journal.discard`` already refuses while a record is
unresolved; this module supplies the other half of the rule by discarding only after the
provider-specific completion has been proven.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

from .errors import LifecycleError, RecordInvalid, RecordMissing
from .journal import Journal
from .locator import locator_for
from .result import COMPLETED, NO_CHANGE
from .manifest import ManifestStore
from .service_identity import (
    WEB_ROLE,
    canonical_service_records,
    expected_service_identity,
)
from .schema import (
    JOURNAL_RESOLVED,
    OWNERSHIP_KINDS_BY_PRODUCER,
    OWNERSHIP_KIND_CLI_SHIM,
    OWNERSHIP_KIND_PRIVILEGE_HELPER,
    OWNERSHIP_KIND_SERVICE_ACCOUNT,
    OWNERSHIP_KIND_SUPPORT_DIRECTORY,
    BuildBlock,
    InstallerBlock,
    InstallationManifest,
    LocatorRecord,
    OwnershipEntry,
    PathsBlock,
    ServiceEntry,
    PatchBlock,
    PkiBlock,
    ProxyPolicyEntry,
    StorageBlock,
    UninstallerBlock,
    WebBlock,
    canonical_path,
    utc_now_iso,
)

#: The reverse-proxy mount prefix and the loopback port, as IMPLEMENTATION CONSTANTS (§4F.5).
#: Not administrator inputs, not `install.yaml` fallbacks. `_px_route_facts` requires both from the
#: published manifest with deliberately no fallback, and before this module nothing ever wrote them
#: on a fresh install — so the shipped `corpusfm-proxy` wrapper could not resolve its own routing.
WEB_PREFIX = "/corpusfm"
WEB_INTERNAL_PORT = 8533

#: The provider names `commit_provider` accepts, and the manifest fields each may write. A provider
#: writes ITS fields and nothing else; every other block is carried through untouched.
PROVIDER_PATCH = "patch"
PROVIDER_PROXY = "proxy"
PROVIDER_ADMIN_IDENTITY = "admin_identity"
PROVIDER_STORAGE = "storage"
PROVIDERS: tuple[str, ...] = (
    PROVIDER_PATCH, PROVIDER_PROXY, PROVIDER_ADMIN_IDENTITY, PROVIDER_STORAGE
)

#: Protocol P requires a RESOLVED entry; Protocol F requires an UNRESOLVED one.
PROTOCOL_P = "P"
PROTOCOL_F = "F"
PROTOCOL: dict[str, str] = {
    PROVIDER_PATCH: PROTOCOL_P,
    PROVIDER_PROXY: PROTOCOL_F,
    PROVIDER_ADMIN_IDENTITY: PROTOCOL_F,
    PROVIDER_STORAGE: PROTOCOL_F,
}

#: The five fixed OS locations every published manifest must record. `app_paths._paths_from_manifest`
#: refuses if ANY of them is missing, and a foundation that omitted them left `app_paths` refusing
#: at the very boundary it was moved to fix.
LAYOUT_PATH_FIELDS: tuple[str, ...] = (
    "config_dir", "state_dir", "secrets_dir", "log_dir", "run_dir"
)

FOUNDATION_MODE = "fresh_install"


class CompositionError(LifecycleError):
    """A composition operation refused. Carried as a result, never raised past the CLI."""


class ProviderMismatch(CompositionError):
    """The journal does not hold the operation this commit claims to be part of."""


# ── results ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class FoundationResult:
    result: str
    operation_id: str
    generation: int
    installation_id: str
    locator_published: bool
    uninstaller_path: str | None = None
    installer_entry_point: str | None = None
    resumed: bool = False


@dataclass(frozen=True)
class CommitResult:
    result: str
    provider: str
    operation_id: str
    committed_generation: int
    already_committed: bool = False


@dataclass(frozen=True)
class InstallerIdentityResult:
    result: str
    operation_id: str
    generation: int
    previous_schema: int
    installer_entry_point: str | None = None
    adopted: bool = False


# ── foundation ───────────────────────────────────────────────────────────────


def build_foundation_manifest(
    *,
    installation_id: str,
    install_dir: Path | str,
    fms_root: Path | str,
    patch_hosting_dir: Path | str | None,
    os_layout,
    version: str | None = None,
    commit: str | None = None,
    installer_series: str | None = None,
    installer_version: str | None = None,
    installer_bundle_protocol: int | None = None,
    installer_source: str | None = None,
    installer_entry_point: str | None = None,
    created_service_account: bool = False,
    privilege_helpers: tuple = (),
    cli_shim: str | None = None,
    support_dir: str | None = None,
    uninstaller_path: str | None = None,
) -> InstallationManifest:
    """A NEW-FORMAT manifest, built directly.

    **Never through ``bridge.propose_manifest``**, whose ``migration.state`` is ``bridged`` — that
    is the conversion shape 1246-10 owns, and a fresh installation that published it would be
    claiming to be a converted one.

    The seven `PathsBlock` fields are the point: two the installer classified, and the five the
    CURRENT platform layout supplies through its own accessor. They are taken from the layout object
    rather than restated here, so no caller can substitute an alternate OS layout field.
    """
    layout_fields = os_layout.as_paths_fields()
    missing = [f for f in LAYOUT_PATH_FIELDS if not layout_fields.get(f)]
    if missing:
        raise CompositionError(
            f"the platform layout does not supply {', '.join(missing)}; a partially recorded layout "
            "is contradictory, not a reason to publish anything"
        )
    paths = PathsBlock(
        install_dir=canonical_path(str(install_dir), field_name="install_dir"),
        fms_root=canonical_path(str(fms_root), field_name="fms_root"),
        patch_hosting_dir=(
            canonical_path(str(patch_hosting_dir), field_name="patch_hosting_dir")
            if patch_hosting_dir else None
        ),
        **{k: canonical_path(v, field_name=k) for k, v in layout_fields.items()},
    )
    now = utc_now_iso()
    services = tuple(ServiceEntry.from_dict(r) for r in
                     canonical_service_records(os_layout.flavour, paths.install_dir))
    return InstallationManifest(
        installation_id=str(installation_id).lower(),
        paths=paths,
        generation=1,                      # replaced by `write`; a validated manifest needs > 0
        created_utc=now,
        updated_utc=now,
        build=BuildBlock(version=version, commit=commit, observed_at=now),
        installer=InstallerBlock(
            series=installer_series,
            version=installer_version,
            bundle_protocol=installer_bundle_protocol,
            source=installer_source,
            entry_point=installer_entry_point,
        ),
        uninstaller=UninstallerBlock(entry_point=uninstaller_path),
        web=WebBlock(internal_port=WEB_INTERNAL_PORT, prefix=WEB_PREFIX),
        services=services,
        ownership=_foundation_ownership(
            created_service_account=created_service_account,
            privilege_helpers=privilege_helpers, cli_shim=cli_shim,
            support_dir=support_dir, os_layout=os_layout),
    ).validated()


def _foundation_ownership(*, created_service_account: bool, privilege_helpers: tuple,
                          cli_shim: str | None, support_dir: str | None = None, os_layout) -> tuple:
    """The fixed installer-owned resources — and NOTHING conditional on observation.

    **The service account is the load-bearing one.** It is recorded only when the installer says
    *this run created it*, because a `corpusfm` account that already existed belongs to whoever made
    it. A fixed name is not a claim, and the whole point of recording ownership is to stop the
    uninstaller reasoning from names.
    """
    entries = []
    if cli_shim:
        entries.append(OwnershipEntry(ownership_class="exact_resource",
                                      kind=OWNERSHIP_KIND_CLI_SHIM, identifier=cli_shim))
    for helper in privilege_helpers:
        entries.append(OwnershipEntry(ownership_class="exact_resource",
                                      kind=OWNERSHIP_KIND_PRIVILEGE_HELPER, identifier=str(helper)))
    if support_dir:
        entries.append(OwnershipEntry(ownership_class="shared_conditional",
                                      kind=OWNERSHIP_KIND_SUPPORT_DIRECTORY,
                                      identifier=str(support_dir)))
    if created_service_account:
        identity = expected_service_identity(WEB_ROLE, os_layout.flavour)
        # **A Windows service identity is VIRTUAL and is not a removable account.** The service
        # manager creates and destroys `NT SERVICE\<service>` with the service itself, so recording
        # it as owned describes work nobody owes — and the stage-4 coverage gate found that the
        # record then blocked the whole Windows build, because the only correct execution of the
        # resulting operation was to refuse. Nothing is recorded; the identity goes with its
        # service, which is where it came from.
        if not identity.upper().startswith("NT SERVICE\\"):
            entries.append(OwnershipEntry(
                ownership_class="exact_resource", kind=OWNERSHIP_KIND_SERVICE_ACCOUNT,
                identifier=identity))
    return tuple(OwnershipEntry.from_dict(e.to_dict()) for e in entries)


def foundation(
    *,
    installation_id: str,
    install_dir: Path | str,
    fms_root: Path | str,
    patch_hosting_dir: Path | str | None,
    lock,
    journal: Journal,
    lifecycle_layout,
    os_layout,
    version: str | None = None,
    commit: str | None = None,
    installer_series: str | None = None,
    installer_version: str | None = None,
    installer_bundle_protocol: int | None = None,
    installer_source: str | None = None,
    installer_entry_point: str | None = None,
    locator_adapter=None,
    created_service_account: bool = False,
    privilege_helpers: tuple = (),
    cli_shim: str | None = None,
    support_dir: str | None = None,
    uninstaller_path: str | None = None,
) -> FoundationResult:
    """Publish generation 1, then the locator, then discard this operation's own journal."""
    store = ManifestStore(install_dir, layout=lifecycle_layout)
    adapter = locator_adapter if locator_adapter is not None else locator_for(lifecycle_layout)

    existing = _existing_foundation(store, adapter, installation_id)
    if existing is not None:
        return _resume_foundation(existing, store, adapter, installation_id, lock, journal,
                                  install_dir)

    _refuse_foreign_trace(store, adapter, installation_id, journal)

    operation_id = str(uuid.uuid4())
    journal.begin(lock=lock, operation_id=operation_id, installation_id=installation_id,
                  mode=FOUNDATION_MODE)
    manifest = build_foundation_manifest(
        installation_id=installation_id, install_dir=install_dir, fms_root=fms_root,
        patch_hosting_dir=patch_hosting_dir, os_layout=os_layout, version=version, commit=commit,
        installer_series=installer_series, installer_version=installer_version,
        installer_bundle_protocol=installer_bundle_protocol, installer_source=installer_source,
        installer_entry_point=installer_entry_point,
        created_service_account=created_service_account, privilege_helpers=privilege_helpers,
        cli_shim=cli_shim, support_dir=support_dir, uninstaller_path=uninstaller_path)
    written = store.write(manifest, lock=lock, expected_generation=0)

    read_back = store.read()
    if (read_back.generation != 1
            or read_back.generation != written.generation
            or read_back.installation_id != manifest.installation_id):
        raise CompositionError(
            f"the foundation manifest did not read back as generation 1 for "
            f"{manifest.installation_id} (saw generation {read_back.generation} for "
            f"{read_back.installation_id})"
        )

    # ONLY NOW. A locator that names a manifest which did not land is a pointer into nothing, and
    # every consumer of the published record would follow it.
    adapter.publish(
        LocatorRecord(installation_id=manifest.installation_id, install_dir=str(install_dir),
                      manifest_relative_path=store.relative_path).validated(),
        lock=lock,
    )
    _resolve_and_discard(journal, lock)
    return FoundationResult(result="completed", operation_id=operation_id,
                            generation=read_back.generation,
                            installation_id=manifest.installation_id, locator_published=True,
                            uninstaller_path=read_back.uninstaller.entry_point,
                            installer_entry_point=read_back.installer.entry_point)


def _existing_foundation(store, adapter, installation_id):
    """The manifest this installation already published, or None."""
    try:
        manifest = store.read()
    except (RecordMissing, RecordInvalid):
        return None
    if manifest.installation_id != str(installation_id).lower():
        return None
    return manifest


def _resume_foundation(manifest, store, adapter, installation_id, lock, journal, install_dir):
    """Manifest present. Either the locator landed too, or the publication is half done.

    A crash between the manifest write and the locator publish is the one interruption this
    operation can leave, and it is RESUMABLE: republishing the locator against a manifest that is
    already at generation 1 changes nothing else.
    """
    if manifest.generation != 1:
        raise CompositionError(
            f"this installation is already at generation {manifest.generation}; a foundation "
            "publishes generation 1 and will not re-run over composed provider work"
        )
    published = _locator_matches(adapter, manifest.installation_id)
    if not published:
        adapter.publish(
            LocatorRecord(installation_id=manifest.installation_id, install_dir=str(install_dir),
                          manifest_relative_path=store.relative_path).validated(),
            lock=lock,
        )
    _resolve_and_discard(journal, lock)
    return FoundationResult(
        result="no_change" if published else "completed",
        operation_id=_journal_operation(journal) or "",
        generation=manifest.generation, installation_id=manifest.installation_id,
        locator_published=True, uninstaller_path=manifest.uninstaller.entry_point,
        installer_entry_point=manifest.installer.entry_point, resumed=True)


def publish_installer_identity(
    *,
    installation_id: str,
    expected_generation: int,
    install_dir: Path | str,
    version: str,
    commit: str,
    installer_series: str,
    installer_version: str,
    installer_bundle_protocol: int,
    installer_source: str,
    installer_entry_point: str | None = None,
    lock,
    journal: Journal,
    lifecycle_layout,
) -> InstallerIdentityResult:
    """Adopt schema 1 or advance the installed identity within its current series.

    This runs only after the incoming source is deployed. It never selects a series: the verified
    installer supplies one, a schema-2 installation must already name the same one, and an ordinary
    installer refuses every cross-series attempt. The write is one journaled compare-and-swap and
    is resumable across a crash before or after the manifest replacement.
    """
    store = ManifestStore(install_dir, layout=lifecycle_layout)
    current = store.read()
    wanted_id = str(installation_id).lower()
    if current.installation_id != wanted_id:
        raise CompositionError(
            f"the published manifest is for {current.installation_id}, not {wanted_id}")
    build = BuildBlock.from_dict({"version": version, "commit": commit,
                                  "observed_at": utc_now_iso()})
    installer = InstallerBlock.from_dict({
        "series": installer_series, "version": installer_version,
        "bundle_protocol": installer_bundle_protocol, "source": installer_source,
        "entry_point": installer_entry_point,
    })
    previous_schema = current.schema_version
    if (current.schema_version >= 2 and current.installer.series is not None
            and current.installer.series != installer.series):
        raise CompositionError(
            f"ordinary installer {installer.series} cannot replace published series "
            f"{current.installer.series}; a designated bridge is required")

    same = (current.schema_version == 2 and current.build.version == build.version
            and current.build.commit == build.commit
            and current.installer.to_dict() == installer.to_dict())
    record = _journal_record(journal)
    resumable = (record is not None and record.installation_id == wanted_id
                 and record.mode == "installer_identity"
                 and record.current_subsystem in (None, "installer_identity"))
    if record is not None and not resumable:
        raise CompositionError(
            f"lifecycle operation {record.operation_id} ({record.mode}) is present; resolve it "
            "before publishing installer identity")
    if resumable and record.current_subsystem is None:
        journal.checkpoint(
            lock=lock, subsystem="installer_identity",
            intended_change=(f"publish {installer.series} installer {installer.version} and "
                             f"application {build.version}"),
            resume_hint="re-run the same verified installer bundle")
        record = journal.read()
    if resumable and same:
        try:
            previous_schema = store.read_previous().schema_version
        except (RecordMissing, RecordInvalid):
            previous_schema = current.schema_version

    if record is None:
        if same:
            return InstallerIdentityResult(
                result=NO_CHANGE, operation_id="", generation=current.generation,
                previous_schema=previous_schema,
                installer_entry_point=current.installer.entry_point, adopted=False)
        if current.generation != expected_generation:
            raise CompositionError(
                f"manifest generation is {current.generation}, not the inspected "
                f"generation {expected_generation}; re-observe before publishing")
        operation_id = str(uuid.uuid4())
        journal.begin(lock=lock, operation_id=operation_id, installation_id=wanted_id,
                      mode="installer_identity")
        journal.checkpoint(
            lock=lock, subsystem="installer_identity",
            intended_change=(f"publish {installer.series} installer {installer.version} and "
                             f"application {build.version}"),
            resume_hint="re-run the same verified installer bundle")
    else:
        operation_id = record.operation_id
        if current.generation not in (expected_generation, expected_generation + 1):
            raise CompositionError(
                f"resumed installer-identity operation expected generation {expected_generation} "
                f"or {expected_generation + 1}, found {current.generation}")

    if not same:
        if current.generation != expected_generation:
            raise CompositionError(
                "the installer-identity journal exists but its manifest write does not agree "
                "with this request")
        proposed = replace(current, schema_version=2, build=build, installer=installer)
        written = store.write(proposed, lock=lock, expected_generation=expected_generation)
        current = store.read()
        if (current.generation != written.generation or current.schema_version != 2
                or current.installer.to_dict() != installer.to_dict()
                or current.build.version != build.version or current.build.commit != build.commit):
            raise CompositionError("the installer identity did not read back exactly as written")

    store.commit(lock=lock)
    _resolve_and_discard(journal, lock)
    return InstallerIdentityResult(
        result=COMPLETED if not same else NO_CHANGE, operation_id=operation_id,
        generation=current.generation, previous_schema=previous_schema,
        installer_entry_point=current.installer.entry_point,
        adopted=previous_schema == 1)


def _locator_matches(adapter, installation_id) -> bool:
    try:
        record = adapter.read()
    except Exception:                      # noqa: BLE001 - absent or unreadable are both "not published"
        return False
    return getattr(record, "installation_id", None) == installation_id


def _refuse_foreign_trace(store, adapter, installation_id, journal) -> None:
    """Refuse any existing trace that is not this exact foundation's."""
    if store.exists():
        try:
            other = store.read().installation_id
        except (RecordMissing, RecordInvalid):
            other = "an unreadable record"
        raise CompositionError(
            f"a manifest already exists in this install directory and it belongs to {other}, not "
            f"{installation_id}; a foundation never writes over another installation"
        )
    try:
        record = adapter.read()
    except Exception:                      # noqa: BLE001
        record = None
    if record is not None and getattr(record, "installation_id", None) != str(installation_id).lower():
        raise CompositionError(
            f"a locator is already published for installation {record.installation_id}, not "
            f"{installation_id}; refusing to publish a second installation on this machine"
        )
    # DIAGNOSTIC, not the enforcement — `journal.begin` -> `assert_clear` raises RecoveryRequired
    # over an unresolved record. Refusing here says WHICH operation and mode is in the way.
    entry = _journal_record(journal)
    if entry is not None and entry.state != JOURNAL_RESOLVED:
        raise CompositionError(
            f"lifecycle operation {entry.operation_id} ({entry.mode}) is unresolved; resolve it "
            "before publishing a foundation"
        )


# ── commit-provider ──────────────────────────────────────────────────────────


def commit_provider(
    *,
    provider: str,
    operation_id: str,
    installation_id: str,
    inspected_generation: int,
    candidate: Mapping[str, Any],
    install_dir: Path | str,
    lock,
    journal: Journal,
    lifecycle_layout,
) -> CommitResult:
    """Publish exactly one provider's owned fields, then read them back.

    Opens **no second journal**: the provider's own operation is already there, and this joins it
    with `Journal.read()` under the held lock. Which STATE that entry must be in is the protocol
    difference (§0.4B), and it is checked rather than assumed.
    """
    if provider not in PROVIDERS:
        raise CompositionError(f"unknown provider {provider!r}; expected one of {PROVIDERS}")
    if inspected_generation < 1:
        raise CompositionError(
            "inspected_generation must be at least 1: providers run after the foundation has "
            "published generation 1"
        )

    _require_matching_entry(journal, provider, operation_id, installation_id)

    store = ManifestStore(install_dir, layout=lifecycle_layout)
    current = store.read()
    if current.installation_id != str(installation_id).lower():
        raise ProviderMismatch(
            f"the published manifest is for {current.installation_id}, the commit claims "
            f"{installation_id}"
        )

    block = _parse_candidate(provider, candidate)

    # IDEMPOTENCE ACROSS A CRASH. A retry after the write landed but before the caller could act
    # must not write a second time — the generation would move under a provider that is about to be
    # finalized against the first one. Without this branch the retry does not corrupt anything: the
    # stale-generation check below refuses it. What this adds is the SUCCESSFUL retry — the caller
    # gets `no_change` and the generation it must finalize against, instead of a refusal it cannot
    # act on.
    if (current.generation == inspected_generation + 1
            and _block_equals(current, provider, block)
            and _ownership_equals(current, provider, candidate)):
        return CommitResult(result="no_change", provider=provider, operation_id=operation_id,
                            committed_generation=current.generation, already_committed=True)

    # DIAGNOSTIC, not the enforcement. `ManifestStore.write` raises GenerationConflict from its own
    # CAS if this is wrong; refusing here names the candidate that went stale instead.
    if current.generation != inspected_generation:
        raise CompositionError(
            f"manifest generation is {current.generation}, the candidate inspected "
            f"{inspected_generation}; re-observe before committing"
        )

    proposed = _merge(current, provider, block, candidate)
    written = store.write(proposed, lock=lock, expected_generation=inspected_generation)

    read_back = store.read()
    if not _ownership_equals(read_back, provider, candidate):
        raise CompositionError(
            f"the {provider} ownership entries did not read back exactly as written; nothing may "
            "be reported as committed"
        )
    if not _block_equals(read_back, provider, block):
        raise CompositionError(
            f"the {provider} block did not read back exactly as written; nothing may be reported "
            "as committed"
        )
    if read_back.generation != written.generation:
        raise CompositionError(
            f"the manifest read back at generation {read_back.generation}, not "
            f"{written.generation}"
        )
    return CommitResult(result="completed", provider=provider, operation_id=operation_id,
                        committed_generation=read_back.generation)


def _require_matching_entry(journal, provider, operation_id, installation_id) -> None:
    """The journal entry must BE this provider's operation, in the state its protocol leaves."""
    entry = _journal_record(journal)
    if entry is None:
        raise ProviderMismatch(
            f"there is no lifecycle journal entry for {provider} operation {operation_id}; a "
            "commit joins an existing operation and never opens one"
        )
    if entry.operation_id != operation_id or entry.installation_id != str(installation_id).lower():
        raise ProviderMismatch(
            f"the lifecycle journal holds operation {entry.operation_id} for installation "
            f"{entry.installation_id}, not {operation_id} for {installation_id}"
        )
    protocol = PROTOCOL[provider]
    resolved = entry.state == JOURNAL_RESOLVED
    if protocol == PROTOCOL_P and not resolved:
        raise ProviderMismatch(
            f"{provider} follows Protocol P: its apply resolves its own journal, so the commit "
            f"requires a RESOLVED entry and this one is {entry.state!r}"
        )
    if protocol == PROTOCOL_F and resolved:
        raise ProviderMismatch(
            f"{provider} follows Protocol F: its reconcile leaves the entry unresolved for the "
            "commit and its finalize, and this one is already resolved"
        )


def _parse_candidate(provider: str, candidate: Mapping[str, Any]):
    """Through the REAL schema type, so a candidate the manifest would reject is refused here."""
    if not isinstance(candidate, Mapping):
        raise CompositionError("the candidate must be a mapping")
    try:
        if provider == PROVIDER_PATCH:
            return PatchBlock.from_dict(dict(candidate.get("patch") or {}))
        if provider == PROVIDER_ADMIN_IDENTITY:
            return PkiBlock.from_dict(dict(candidate.get("pki") or {}))
        if provider == PROVIDER_STORAGE:
            return StorageBlock.from_dict(dict(candidate.get("storage") or {}))
        policy = candidate.get("proxy_policy")
        if not isinstance(policy, Mapping) or not policy:
            raise RecordInvalid("proxy_policy must be a non-empty mapping of proxy type to entry")
        return {
            name: ProxyPolicyEntry.from_dict(dict(value), proxy_type=name)
            for name, value in policy.items()
        }
    except (RecordInvalid, TypeError, ValueError) as exc:
        raise CompositionError(f"the {provider} candidate is not valid for the manifest: {exc}") from exc


def _merge_ownership(raw: dict, provider: str, candidate: Mapping[str, Any]) -> None:
    """Fold this provider's ownership additions in — and ONLY this provider's (packet 1246-09, S1).

    An ownership entry authorizes a deletion, so the merge is written as a set of refusals rather
    than as a union:

    * a kind outside the caller's row of ``OWNERSHIP_KINDS_BY_PRODUCER`` is refused, so the storage
      provider can never mint a sandbox-RC entry and the patch provider can never mint a database
      one;
    * an entry that would REPLACE another provider's existing entry is refused, rather than winning
      by being later. Same-provider re-publication of an identical entry is a no-op, which is what a
      reconcile of an unchanged installation must be;
    * the merged table is re-validated by ``InstallationManifest.from_dict``, so duplicate semantic
      resources, duplicate identifiers and overlapping paths refuse there.
    """
    additions = candidate.get("ownership")
    if additions is None:
        return
    if not isinstance(additions, (list, tuple)):
        raise CompositionError("candidate ownership must be a list")
    permitted = OWNERSHIP_KINDS_BY_PRODUCER.get(provider, frozenset())
    existing = [OwnershipEntry.from_dict(e) for e in raw.get("ownership") or []]
    mine = {e.semantic_resource: e for e in existing if e.kind in permitted}
    theirs = {e.semantic_resource: e for e in existing if e.kind not in permitted}
    for item in additions:
        try:
            entry = OwnershipEntry.from_dict(item)
        except RecordInvalid as exc:
            raise CompositionError(f"the {provider} ownership addition is not valid: {exc}") from exc
        if entry.kind not in permitted:
            raise CompositionError(
                f"{provider} may not publish ownership of kind {entry.kind!r}; it may publish "
                f"{sorted(permitted)}"
            )
        if entry.semantic_resource in theirs:
            # BACKSTOP. Unreachable while `OWNERSHIP_KINDS_BY_PRODUCER` partitions the vocabulary —
            # the kind check above fires first — and kept because that partition is a table someone
            # can widen. `test_every_declared_kind_is_produced_by_exactly_one_provider` asserts the
            # precondition; this is what stands if it is ever relaxed.
            raise CompositionError(
                f"{provider} would replace another provider's ownership entry for "
                f"{entry.semantic_resource!r}"
            )
        mine[entry.semantic_resource] = entry
    raw["ownership"] = [e.to_dict() for e in (*theirs.values(), *mine.values())]


def _merge(current: InstallationManifest, provider: str, block, candidate: Mapping[str, Any]):
    """Replace exactly that provider's fields; carry every other block through untouched."""
    raw = current.to_dict()
    _merge_ownership(raw, provider, candidate)
    if provider == PROVIDER_PATCH:
        raw["patch"] = block.to_dict()
        hosting = candidate.get("patch_hosting_dir")
        if hosting:
            raw["paths"]["patch_hosting_dir"] = canonical_path(
                str(hosting), field_name="patch_hosting_dir")
    elif provider == PROVIDER_ADMIN_IDENTITY:
        raw["pki"] = block.to_dict()
    elif provider == PROVIDER_STORAGE:
        raw["storage"] = block.to_dict()
    else:
        raw["proxy_policy"] = {name: entry.to_dict() for name, entry in block.items()}
    return InstallationManifest.from_dict(raw)


def _ownership_equals(manifest: InstallationManifest, provider: str,
                     candidate: Mapping[str, Any]) -> bool:
    """Whether this provider's ownership rows already match the candidate's.

    Needed because the already-committed short-circuit compares the provider's BLOCK: without this,
    a re-run that adds only an ownership entry — which is exactly what a first storage or patch
    publication does — would read as "nothing changed" and never land.
    """
    additions = candidate.get("ownership")
    if additions is None:
        return True
    permitted = OWNERSHIP_KINDS_BY_PRODUCER.get(provider, frozenset())
    published = {e.semantic_resource: e.to_dict() for e in manifest.ownership
                 if e.kind in permitted}
    try:
        wanted = {OwnershipEntry.from_dict(a).semantic_resource: OwnershipEntry.from_dict(a).to_dict()
                  for a in additions}
    except (RecordInvalid, TypeError, ValueError):
        return False
    return all(published.get(k) == v for k, v in wanted.items())


def _block_equals(manifest: InstallationManifest, provider: str, block) -> bool:
    if provider == PROVIDER_PATCH:
        return manifest.patch.to_dict() == block.to_dict()
    if provider == PROVIDER_ADMIN_IDENTITY:
        return manifest.pki.to_dict() == block.to_dict()
    if provider == PROVIDER_STORAGE:
        return manifest.storage.to_dict() == block.to_dict()
    published = {name: entry.to_dict() for name, entry in (manifest.proxy_policy or {}).items()}
    return published == {name: entry.to_dict() for name, entry in block.items()}


# ── the journal boundary ─────────────────────────────────────────────────────


def _journal_record(journal):
    try:
        return journal.read()
    except Exception:                      # noqa: BLE001 - an unreadable journal is not an absent one
        raise CompositionError(
            "the lifecycle journal could not be read; it is the only evidence of where an "
            "interrupted operation stopped"
        )


def _journal_operation(journal) -> str | None:
    record = journal.read()
    return record.operation_id if record is not None else None


def _resolve_and_discard(journal: Journal, lock) -> None:
    record = journal.read()
    if record is not None and record.state != JOURNAL_RESOLVED:
        journal.resolve(lock=lock, result="completed")
    journal.discard(lock=lock)


def discard_provider_journal(journal: Journal, lock, *, operation_id: str,
                             installation_id: str | None = None, provider: str | None = None,
                             expect_resolved: bool = True) -> str:
    """Retire a provider's journal at the boundary, after its completion is proven.

    **Required, not optional.** `storage`'s evidence rule answers ``foreign_open`` on the presence
    of ANY record — resolved or not, ours or not — so a leftover entry from the foundation or an
    earlier provider makes the next provider refuse before it starts.

    **Identity is CHECKED here, not trusted from the caller (packet 1246-04 correction A).** The
    integrator surface is a shell writing a JSON file; if this function accepted whichever operation
    the caller named and discarded on that word alone, the boundary would be exactly as strong as
    the least careful request builder. So the record's own `operation_id`, `installation_id` and
    subsystem are compared against what the caller claims, and every disagreement is a refusal that
    LEAVES THE RECORD IN PLACE. A journal is the only evidence of where an operation stopped;
    discarding one that turns out to be somebody else's is not recoverable by re-running anything.

    Returns the result word: ``no_change`` when there was nothing to retire — which is what an
    idempotent boundary means here, and why a re-run after a successful discard is not an error —
    and ``completed`` when a matching resolved record was removed.
    """
    record = journal.read()
    if record is None:
        # Idempotent, and it touches nothing: the point of the boundary is that no record survives
        # it, and that is already true.
        return NO_CHANGE
    if record.operation_id != operation_id:
        raise ProviderMismatch(
            f"refusing to discard journal for operation {record.operation_id}; this boundary is "
            f"{operation_id}"
        )
    if installation_id is not None and record.installation_id != installation_id:
        raise ProviderMismatch(
            f"the journal record belongs to installation {record.installation_id}; this boundary "
            f"is {installation_id}. A foreign record is retained, never retired."
        )
    if provider is not None:
        if provider not in PROVIDERS:
            raise ProviderMismatch(f"provider must be one of {PROVIDERS}, got {provider!r}")
        subsystem = record.current_subsystem
        # A record that names a subsystem must name THIS provider's. One that names none is not
        # evidence of a mismatch, and refusing it would strand a legitimately terminal record that
        # a provider cleared on its way to resolution.
        if subsystem and not _subsystem_belongs_to(subsystem, provider):
            raise ProviderMismatch(
                f"the journal record is {subsystem!r} work; this boundary is {provider!r}. A "
                "record belonging to another provider is retained, never retired."
            )
    # DIAGNOSTIC, not the enforcement — `Journal.discard` refuses an unresolved record itself.
    if expect_resolved and record.state != JOURNAL_RESOLVED:
        raise CompositionError(
            f"operation {operation_id} is {record.state!r}, not resolved; its journal is the only "
            "evidence of where it stopped and will not be discarded"
        )
    journal.discard(lock=lock)
    return COMPLETED


def _subsystem_belongs_to(subsystem: str, provider: str) -> bool:
    """Whether a journal subsystem string names this provider's work.

    Measured, not guessed: providers write their subsystem in their own vocabulary -
    `admin_identity` writes exactly that, `patch_compartment` extends the provider name, and
    `storage` writes `storage:<step>`. So the rule is **the provider name, then a boundary**: equal,
    or followed by `:` or `_`. Substring matching would let `storage` retire a `storage`-prefixed
    record belonging to something else entirely; demanding one exact spelling would refuse the two
    forms production actually writes.
    """
    normal = str(subsystem).strip().lower().replace("-", "_")
    return normal == provider or normal.startswith(provider + ":") or \
        normal.startswith(provider + "_")


__all__ = [
    "LAYOUT_PATH_FIELDS",
    "PROTOCOL",
    "PROTOCOL_F",
    "PROTOCOL_P",
    "PROVIDERS",
    "PROVIDER_ADMIN_IDENTITY",
    "PROVIDER_PATCH",
    "PROVIDER_PROXY",
    "PROVIDER_STORAGE",
    "WEB_INTERNAL_PORT",
    "WEB_PREFIX",
    "CommitResult",
    "CompositionError",
    "FoundationResult",
    "InstallerIdentityResult",
    "ProviderMismatch",
    "build_foundation_manifest",
    "commit_provider",
    "discard_provider_journal",
    "foundation",
    "publish_installer_identity",
]
