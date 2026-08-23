"""What is here — observed, never touched (packet 1246-09, stage 2).

**This module reads. It has no other capability.** No removal, no service control, no FMS call, no
credential, no write of any kind — the structural guard in `tests/test_uninstall_stage_fence.py`
fails the build if one appears.

The separation matters because the two questions have different truth conditions. *What did this
installation record about itself* and *what is on the box right now* are both needed to plan a
removal, and conflating them is how a name search becomes deletion authority. So observation is
collected here as **facts with no verdicts attached**, and every decision is made in
`uninstall_plan`, from the facts plus the recorded authority.

The fact vocabulary is the one the design checker enumerated over. It is closed: a planner that
receives a state outside these tuples refuses rather than guessing.
"""

from __future__ import annotations

import stat as _stat
from dataclasses import dataclass, field
from pathlib import Path

from .errors import RecordInvalid
from .locator import locator_for
from .manifest import ManifestStore
from .schema import (
    OWNERSHIP_KIND_PATCH_SANDBOX_RC,
    OWNERSHIP_KIND_STORAGE_DATABASE,
    OWNERSHIP_KIND_SUPPORT_DIRECTORY,
    InstallationManifest,
)

# ── the closed fact vocabulary ────────────────────────────────────────────────

LOCATOR_ABSENT = "absent"
LOCATOR_VALID = "valid"
LOCATOR_UNREADABLE = "unreadable"
LOCATOR_POINTS_ELSEWHERE = "points_elsewhere"
LOCATOR_STATES = (LOCATOR_ABSENT, LOCATOR_VALID, LOCATOR_UNREADABLE, LOCATOR_POINTS_ELSEWHERE)

MANIFEST_ABSENT = "absent"
MANIFEST_VALID = "valid"
MANIFEST_INVALID = "invalid"
MANIFEST_ID_MISMATCH = "id_mismatch"
MANIFEST_STATES = (MANIFEST_ABSENT, MANIFEST_VALID, MANIFEST_INVALID, MANIFEST_ID_MISMATCH)

PATHS_COMPLETE = "all_six_recorded"
PATHS_INCOMPLETE = "a_required_field_missing"
PATHS_STATES = (PATHS_COMPLETE, PATHS_INCOMPLETE)

#: The six exclusive trees a removal needs. `PathsBlock` types five of them as optional, and on the
#: bridge path they are genuinely unset — which is why completeness is a FACT here rather than an
#: assumption in the planner (packet 1246-09 §O6).
REQUIRED_PATH_FIELDS = ("install_dir", "config_dir", "state_dir", "secrets_dir", "log_dir",
                        "run_dir")

FMS_RUNNING = "running"
FMS_INSTALLED_STOPPED = "installed_stopped"
FMS_ABSENT = "absent"
FMS_CRED_REJECTED = "cred_rejected"
FMS_STATES = (FMS_RUNNING, FMS_INSTALLED_STOPPED, FMS_ABSENT, FMS_CRED_REJECTED)

STORAGE_OWNED_PRESENT = "owned_present"
STORAGE_OWNED_ABSENT = "owned_absent"
STORAGE_NOT_OWNED = "not_owned"
STORAGE_STATES = (STORAGE_OWNED_PRESENT, STORAGE_OWNED_ABSENT, STORAGE_NOT_OWNED)

PATCHDIR_EMPTY = "recorded_empty"
PATCHDIR_ONLY_RECORDED = "recorded_only_installer_content"
PATCHDIR_HAS_WORK = "recorded_has_admin_work"
PATCHDIR_ABSENT = "recorded_absent"
PATCHDIR_NOT_RECORDED = "not_recorded"
PATCHDIR_STATES = (
    PATCHDIR_EMPTY, PATCHDIR_ONLY_RECORDED, PATCHDIR_HAS_WORK, PATCHDIR_ABSENT,
    PATCHDIR_NOT_RECORDED,
)

SANDBOX_PRESENT = "recorded_present"
SANDBOX_ABSENT = "recorded_absent"
SANDBOX_NOT_RECORDED = "not_recorded"
SANDBOX_STATES = (SANDBOX_PRESENT, SANDBOX_ABSENT, SANDBOX_NOT_RECORDED)

SANDRC_PRESENT = "recorded_present"
SANDRC_ABSENT = "recorded_absent"
SANDRC_UNRECORDED_PRESENT = "unrecorded_present"
SANDRC_AMBIGUOUS = "ambiguous"
SANDRC_STATES = (SANDRC_PRESENT, SANDRC_ABSENT, SANDRC_UNRECORDED_PRESENT, SANDRC_AMBIGUOUS)

SUPPORTDIR_EMPTY = "recorded_empty"
SUPPORTDIR_HAS_WORK = "recorded_has_work"
SUPPORTDIR_ABSENT = "recorded_absent"
SUPPORTDIR_NOT_RECORDED = "not_recorded"
SUPPORTDIR_AMBIGUOUS = "ambiguous"
SUPPORTDIR_STATES = (SUPPORTDIR_EMPTY, SUPPORTDIR_HAS_WORK, SUPPORTDIR_ABSENT,
                     SUPPORTDIR_NOT_RECORDED, SUPPORTDIR_AMBIGUOUS)

SVC_BOUND = "bound"
SVC_ALL_ABSENT = "all_absent"
SVC_BOUND_OR_ABSENT = "bound_or_absent"
SVC_NAME_ONLY = "name_only"
SVC_EXECUTABLE_OUTSIDE = "executable_outside"
SVC_IDENTITY_DISAGREES = "identity_disagrees"
SVC_STATES = (SVC_BOUND, SVC_ALL_ABSENT, SVC_BOUND_OR_ABSENT, SVC_NAME_ONLY, SVC_EXECUTABLE_OUTSIDE,
              SVC_IDENTITY_DISAGREES)

PROVIDER_RECORDED = "recorded"
PROVIDER_NOT_RECORDED = "not_recorded"
PROVIDER_INCOMPLETE = "incomplete"
PROVIDER_STATES = (PROVIDER_RECORDED, PROVIDER_NOT_RECORDED, PROVIDER_INCOMPLETE)

#: Whether the foundation recorded ownership of the CLI shim and the privilege helpers. There is no
#: default: an installer that supplied neither publishes an empty ownership table, and a planner that
#: removed them anyway would be doing exactly what that empty table forbids.
FIXED_OWNED = "recorded"
FIXED_NOT_RECORDED = "not_recorded"
FIXED_STATES = (FIXED_OWNED, FIXED_NOT_RECORDED)

ACCOUNT_OWNED = "owned"
ACCOUNT_NOT_OWNED = "not_owned"
ACCOUNT_STATES = (ACCOUNT_OWNED, ACCOUNT_NOT_OWNED)

PENDING_NONE = "none"
PENDING_MATCHING = "matching"
PENDING_FOREIGN = "foreign"
PENDING_STATES = (PENDING_NONE, PENDING_MATCHING, PENDING_FOREIGN)


@dataclass(frozen=True)
class Observation:
    """One installation, as observed. Facts only — no decision, no authority judgment."""

    locator: str
    manifest: str
    paths: str
    fms: str
    storage: str
    patchdir: str
    sandbox: str
    sandrc: str
    supportdir: str
    svcbind: str
    pki_registration: str
    patch_slot: str
    proxy_family: str
    fixed_resources: str
    account: str
    pending: str
    force: bool = False
    #: Carried so the planner can name what it decided about, never to re-derive a decision from.
    record: InstallationManifest | None = None
    notes: tuple = field(default_factory=tuple)

    def as_facts(self) -> dict:
        return {
            "locator": self.locator, "manifest": self.manifest, "paths": self.paths,
            "fms": self.fms, "storage": self.storage, "patchdir": self.patchdir,
            "sandbox": self.sandbox, "sandrc": self.sandrc, "supportdir": self.supportdir,
            "svcbind": self.svcbind,
            "pki_registration": self.pki_registration, "patch_slot": self.patch_slot,
            "proxy_family": self.proxy_family,
            "fixed_resources": self.fixed_resources,
            "account": self.account, "pending": self.pending, "force": self.force,
        }


_DOMAINS = {
    "locator": LOCATOR_STATES, "manifest": MANIFEST_STATES, "paths": PATHS_STATES,
    "fms": FMS_STATES, "storage": STORAGE_STATES, "patchdir": PATCHDIR_STATES,
    "sandbox": SANDBOX_STATES, "sandrc": SANDRC_STATES,
    "supportdir": SUPPORTDIR_STATES, "svcbind": SVC_STATES,
    "pki_registration": PROVIDER_STATES, "patch_slot": PROVIDER_STATES,
    "proxy_family": PROVIDER_STATES,
    "fixed_resources": FIXED_STATES, "account": ACCOUNT_STATES, "pending": PENDING_STATES,
}


def validate_facts(facts: dict) -> None:
    """Every fact must be inside its closed domain.

    A planner that accepts an unrecognised state has to decide what it means, and the only two
    honest answers — refuse, or treat it as the safest neighbour — are decisions the fact layer has
    no business making silently.
    """
    for name, domain in _DOMAINS.items():
        if name not in facts:
            raise RecordInvalid(f"observation is missing the fact {name!r}")
        if facts[name] not in domain:
            raise RecordInvalid(
                f"observation fact {name}={facts[name]!r} is outside its domain {domain}")
    if not isinstance(facts.get("force", False), bool):
        raise RecordInvalid("observation fact 'force' must be a boolean")


# ── read-only observation ─────────────────────────────────────────────────────


def observe_paths(manifest: InstallationManifest | None) -> str:
    """Whether all six exclusive trees are recorded. See `REQUIRED_PATH_FIELDS`."""
    if manifest is None:
        return PATHS_INCOMPLETE
    values = manifest.paths.to_dict()
    return (PATHS_COMPLETE if all(values.get(f) for f in REQUIRED_PATH_FIELDS)
            else PATHS_INCOMPLETE)


def missing_path_fields(manifest: InstallationManifest | None) -> tuple:
    if manifest is None:
        return REQUIRED_PATH_FIELDS
    values = manifest.paths.to_dict()
    return tuple(f for f in REQUIRED_PATH_FIELDS if not values.get(f))


def recorded_ownership(manifest: InstallationManifest | None, kind: str) -> tuple:
    if manifest is None:
        return ()
    return tuple(e for e in manifest.ownership if e.kind == kind)


def observe_support_dir(manifest: InstallationManifest | None) -> str:
    owned = recorded_ownership(manifest, OWNERSHIP_KIND_SUPPORT_DIRECTORY)
    if not owned:
        return SUPPORTDIR_NOT_RECORDED
    if len(owned) != 1:
        return SUPPORTDIR_AMBIGUOUS
    path = Path(owned[0].identifier)
    try:
        observed = path.lstat()
        if _stat.S_ISLNK(observed.st_mode) or not _stat.S_ISDIR(observed.st_mode):
            return SUPPORTDIR_HAS_WORK
        return SUPPORTDIR_EMPTY if not any(path.iterdir()) else SUPPORTDIR_HAS_WORK
    except FileNotFoundError:
        return SUPPORTDIR_ABSENT
    except OSError:
        return SUPPORTDIR_HAS_WORK


def observe_locator_and_manifest(layout, *, expected_installation_id: str | None = None,
                                 locator_adapter=None) -> tuple:
    """`(locator_state, manifest_state, manifest)` — reading only.

    A locator that cannot be read is REPORTED as unreadable rather than treated as absent: those
    two states lead to opposite actions, and the difference is exactly the ambiguity that must not
    be resolved by guessing.
    """
    adapter = locator_adapter if locator_adapter is not None else locator_for(layout)
    try:
        record = adapter.read()
    except RecordInvalid:
        return LOCATOR_UNREADABLE, MANIFEST_ABSENT, None
    except OSError:
        return LOCATOR_UNREADABLE, MANIFEST_ABSENT, None
    if record is None:
        return LOCATOR_ABSENT, MANIFEST_ABSENT, None
    if (expected_installation_id
            and record.installation_id.lower() != str(expected_installation_id).lower()):
        return LOCATOR_POINTS_ELSEWHERE, MANIFEST_ABSENT, None
    try:
        manifest = ManifestStore(Path(record.install_dir), layout=layout).read()
    except RecordInvalid:
        return LOCATOR_VALID, MANIFEST_INVALID, None
    except (OSError, LookupError):
        return LOCATOR_VALID, MANIFEST_ABSENT, None
    if manifest is None:
        return LOCATOR_VALID, MANIFEST_ABSENT, None
    if manifest.installation_id.lower() != record.installation_id.lower():
        return LOCATOR_VALID, MANIFEST_ID_MISMATCH, manifest
    return LOCATOR_VALID, MANIFEST_VALID, manifest


def observe_storage(manifest: InstallationManifest | None) -> str:
    """Owned-and-present, owned-and-gone, or not owned at all.

    `storage.database_name` is deliberately NOT consulted: a name is not a removable path, and the
    whole point of the ownership entry is that the name never becomes one.
    """
    entries = recorded_ownership(manifest, OWNERSHIP_KIND_STORAGE_DATABASE)
    if not entries:
        return STORAGE_NOT_OWNED
    return (STORAGE_OWNED_PRESENT if Path(entries[0].identifier).exists()
            else STORAGE_OWNED_ABSENT)


def observe_sandbox_rc(manifest: InstallationManifest | None) -> str:
    """Recorded-and-present, recorded-and-gone, present-but-unattributed, or ambiguous.

    The last two are the states O7 exists for: something is there, and nothing recorded says it is
    ours. Both preserve, and both keep the compartment.
    """
    entries = recorded_ownership(manifest, OWNERSHIP_KIND_PATCH_SANDBOX_RC)
    if entries:
        return SANDRC_PRESENT if Path(entries[0].identifier).exists() else SANDRC_ABSENT
    hosting = manifest.paths.patch_hosting_dir if manifest else None
    if not hosting:
        return SANDRC_ABSENT
    try:
        found = sorted(c.name for c in Path(hosting).iterdir() if c.name.endswith("_Data_FMS"))
    except OSError:
        return SANDRC_ABSENT
    if not found:
        return SANDRC_ABSENT
    return SANDRC_UNRECORDED_PRESENT if len(found) == 1 else SANDRC_AMBIGUOUS


def observe_fixed_resources(manifest: InstallationManifest | None) -> str:
    """Whether the foundation recorded the CLI shim / privilege helpers it created."""
    from .schema import OWNERSHIP_KIND_CLI_SHIM, OWNERSHIP_KIND_PRIVILEGE_HELPER

    if manifest is None:
        return FIXED_NOT_RECORDED
    kinds = {e.kind for e in manifest.ownership}
    return (FIXED_OWNED
            if kinds & {OWNERSHIP_KIND_CLI_SHIM, OWNERSHIP_KIND_PRIVILEGE_HELPER}
            else FIXED_NOT_RECORDED)


# ── the live control plane, derived rather than listed (packet 1246-09, §V) ────


def control_plane_paths(flavour: str) -> dict:
    """The lifecycle paths a running uninstall still needs, **derived from `paired_layouts()`**.

    Derived, never hand-listed: an exclusion list written out by hand is a list that silently stops
    matching the day a filename changes, and the thing it stops protecting is the only resume
    authority an interrupted uninstall has. `paired_layouts` already refuses to return a pair whose
    journal is not under `state`, whose lock is not under `run`, or whose POSIX locator is not under
    `config` — so this reads the relationship that module already proves.
    """
    from .os_layout import paired_layouts
    from .uninstall_pending import pending_path

    _os_layout, lifecycle = paired_layouts(flavour=flavour)
    plane = {
        "pending": pending_path(lifecycle),
        "journal": lifecycle.journal_file,
        "lock": lifecycle.lock_file,
    }
    if lifecycle.locator_file is not None:
        plane["locator"] = lifecycle.locator_file      # Windows keeps its locator in HKLM
    return plane


def control_plane_exclusions(flavour: str, tree) -> tuple:
    """The control-plane paths that live INSIDE `tree`, and must survive cleaning it."""
    from pathlib import Path as _Path

    root = _Path(tree)
    keep = []
    for name, path in sorted(control_plane_paths(flavour).items()):
        try:
            _Path(path).relative_to(root)
        except ValueError:
            continue
        keep.append((name, str(path)))
    return tuple(keep)
