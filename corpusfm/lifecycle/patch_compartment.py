"""Provision and PROVE one FileMaker Server Additional Database Folder (packet 1246-05-01).

The compartment is the only place CORPUSfm may patch, so this component's whole job is to make that
claim *earned*: a directory both identities can really use, a slot FileMaker Server really holds, and
one sandbox that really opened and really closed inside it.

Three separations carry the design.

**Registered is not verified.** `registered` means the PATCH read back. `verified` means all seven
proofs of `verify_report` passed. Nothing in the product may treat the first as the second.

**Inspect reads; apply mutates.** `inspect` contacts the API and captures a complete before-image
with no directory in existence, so a refusal — including a missing API — costs nothing. `apply`
re-reads that image and compares it before its first mutation.

**This child RETURNS candidate facts; it never writes the manifest.** The single composed write is
1246-04's, which is why `CandidateFacts` carries the generation and identity this run inspected: a
writer that cannot fail closed on a moved generation is not failing closed.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from . import app_paths
from . import fms_folders as ff
from .atomic import atomic_write_text
from .errors import LifecycleError
from .layout import POSIX, WINDOWS
from .lock import require_lock
from .result import (
    COMPLETED,
    FAILED_BEFORE_CHANGE,
    MANUAL_ACTION_REQUIRED,
    NO_CHANGE,
    ROLLED_BACK,
    classify_failure,
)
from .schema import LIFECYCLE_MODES, PatchBlock
from .secret_guard import assert_no_secrets
from .service_identity import ServiceIdentity

SANDBOX_NAME = "CORPUSfm_Sandbox"
SANDBOX_FILE = f"{SANDBOX_NAME}.fmp12"
# Install-root-relative. Moved out of `src/` by packet 1257: the checkout carries no installer
# assets, so the storage-DB template lives in the sibling asset tree.
SEED_RELATIVE = Path(app_paths.ASSETS_DIRNAME) / "db" / "CORPUSfm_DB.fmp12"

# ── the Windows rights this operation actually needs ──────────────────────────
# SPECIFIC (mapped) NTFS directory bits, named here because this is an OPERATION requirement and
# nothing else in the tree states one.
#
# `protection.py`'s DIRECTORY_AUTHORITY / FILE_WRITE_AUTHORITY must NOT be reused for this. They are
# NEGATIVE detection masks — "does the holder have ANY of these offending bits", tested as
# `held & MASK` truthiness — and they include GENERIC_ALL and GENERIC_WRITE. Read as an
# all-must-be-present requirement they demand generic bits that `GetEffectiveRightsFromAcl` never
# returns (it returns specific rights), so a genuinely full-control identity would fail and
# VERIFIED_READY would be unreachable on every real Windows box.
FILE_LIST_DIRECTORY = 0x0001        # read the directory
FILE_ADD_FILE = 0x0002              # create
FILE_ADD_SUBDIRECTORY = 0x0004      # create a subdirectory
FILE_TRAVERSE = 0x0020              # reach entries inside it
FILE_DELETE_CHILD = 0x0040          # delete and rename
FILE_READ_ATTRIBUTES = 0x0080       # read
FILE_WRITE_ATTRIBUTES = 0x0100      # write

#: Exactly the create / read / write / rename / delete evidence this component promises — no more.
#: WRITE_DAC and WRITE_OWNER are deliberately absent: re-permissioning is far past what the proof
#: claims, and demanding it would refuse a correctly-scoped grant.
WIN_REQUIRED_RIGHTS = (
    FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE
    | FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES
)

#: What Windows reports for full control as SPECIFIC rights — `FILE_ALL_ACCESS`. Named so the tests
#: can assert against the value a real box returns rather than against the mask above; a double that
#: returned the requirement itself would prove only that the code compares a number with itself.
WIN_FILE_ALL_ACCESS = 0x001F01FF


def _win_required_rights() -> int:
    return WIN_REQUIRED_RIGHTS


def _win_rights_satisfied(held: int) -> bool:
    """Generic bits, if an implementation returns them, are honoured consistently.

    `_RealWindowsAclApi.effective_rights` models a NULL DACL — unrestricted access — by returning a
    mask carrying GENERIC_ALL (`protection.py:466-470`), so GENERIC_ALL is accepted on its own. The
    ordinary path compares SPECIFIC rights, which is what the API returns for a real DACL.
    """
    from .protection import GENERIC_ALL

    if held & GENERIC_ALL:
        return True
    return held & WIN_REQUIRED_RIGHTS == WIN_REQUIRED_RIGHTS


class CompartmentState(str, Enum):
    """Lowest numeric precedence wins. `findings` carries every condition that holds."""

    PATH_REFUSED = "path_refused"
    API_REQUIRED_UNAVAILABLE = "api_required_unavailable"
    CONVERSION_REQUIRED = "conversion_required"
    ALL_SLOTS_OCCUPIED = "all_slots_occupied"
    REGISTERED_NOT_ENABLED = "registered_not_enabled"
    READBACK_MISMATCH = "readback_mismatch"
    RC_FIELDS_CHANGED = "rc_fields_changed"
    PERMISSIONS_INCOMPLETE = "permissions_incomplete"
    SANDBOX_CONFLICT = "sandbox_conflict"
    SANDBOX_SEED_FAILED = "sandbox_seed_failed"
    SANDBOX_NOT_OBSERVED_OPEN = "sandbox_not_observed_open"
    SANDBOX_NOT_OBSERVED_CLOSED = "sandbox_not_observed_closed"
    FREE_SLOT_AVAILABLE = "free_slot_available"
    VERIFIED_READY = "verified_ready"


_PRECEDENCE: tuple[CompartmentState, ...] = (
    CompartmentState.PATH_REFUSED,
    CompartmentState.API_REQUIRED_UNAVAILABLE,
    CompartmentState.CONVERSION_REQUIRED,
    CompartmentState.ALL_SLOTS_OCCUPIED,
    CompartmentState.REGISTERED_NOT_ENABLED,
    CompartmentState.READBACK_MISMATCH,
    CompartmentState.RC_FIELDS_CHANGED,
    CompartmentState.PERMISSIONS_INCOMPLETE,
    CompartmentState.SANDBOX_CONFLICT,
    CompartmentState.SANDBOX_SEED_FAILED,
    CompartmentState.SANDBOX_NOT_OBSERVED_OPEN,
    CompartmentState.SANDBOX_NOT_OBSERVED_CLOSED,
    CompartmentState.FREE_SLOT_AVAILABLE,
    CompartmentState.VERIFIED_READY,
)


class CompartmentRefused(LifecycleError):
    """A caller asked for something the contract forbids outright."""


class SandboxDecision(str, Enum):
    """What the caller has decided about a file already at the intended sandbox path.

    `CREATE` is the ordinary "there is nothing there, put the seed in" case and is what an absent
    sandbox takes; only `REPLACE_EXACT_NAME` authorises overwriting one that is already there, and
    `--yes`/silent cannot supply it.
    """

    NONE = "none"
    CREATE = "create"
    REPLACE_EXACT_NAME = "replace"


@dataclass(frozen=True)
class CompartmentInputs:
    requested: Path
    install_dir: Path
    fms_root: Path
    fms_database_dir: Path
    storage_dirs: tuple[Path, ...]
    protected_dirs: tuple[Path, ...]
    service_identity: ServiceIdentity
    fms_identity: ServiceIdentity
    flavour: str
    seed: Path


@dataclass(frozen=True)
class PermissionSnapshot:
    flavour: str
    existed: bool
    posix_owner: str | None = None
    posix_group: str | None = None
    posix_mode: int | None = None
    windows_sddl: str | None = None


@dataclass(frozen=True)
class SandboxSnapshot:
    path: Path
    existed: bool
    backup: Path | None = None
    posix_mode: int | None = None
    mtime_utc: str | None = None
    #: Content digest of the sandbox AS FOUND. Load-bearing twice over: rollback verifies its
    #: restoration against it, and — when the backup is gone — it is the only way to tell "the copy
    #: never happened" from "the replacement happened and the backup was cleaned up". An mtime
    #: cannot answer that; a digest can.
    digest: str | None = None


@dataclass(frozen=True)
class LegacySandboxFact:
    """A CORPUSfm_Sandbox that is NOT the compartment's — either conversion trigger.

    Exists precisely so a file OUTSIDE the intended compartment is representable: SandboxSnapshot
    describes the intended path only, and a fact that cannot be recorded cannot be compared.
    """

    trigger: str
    fms_filename: str | None = None
    fms_folder: str | None = None       # verbatim `folder` from GET /databases
    fms_folder_local: Path | None = None  # that folder as a local DIRECTORY, for comparison
    fms_status: str | None = None
    # Only ever the FILE, and only for the filesystem-only trigger. The first draft stored the
    # FOLDER here for the FMS-known trigger, so one field meant two different things depending on
    # which trigger produced it — and `disk_exists` then answered about a directory.
    disk_path: Path | None = None
    disk_exists: bool = False
    disk_size: int | None = None
    disk_mtime_utc: str | None = None


TRIGGER_FMS_KNOWN = "fms_known"
TRIGGER_FILESYSTEM_ONLY = "filesystem_only"


@dataclass(frozen=True)
class FmsFolderBeforeImage:
    slots: tuple[ff.SlotRecord, ...]
    rc_fields: dict
    legacy: tuple[LegacySandboxFact, ...]
    captured_utc: str


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    identity: str | None = None


@dataclass(frozen=True)
class UninstallHandoff:
    compartment_path: Path | None = None
    slot_index: str | None = None
    sandbox_file: Path | None = None
    other_content_count: int = 0
    fms_reachable: bool = False
    before: FmsFolderBeforeImage | None = None


@dataclass(frozen=True)
class CompartmentReport:
    state: CompartmentState
    result: str
    slots: tuple[ff.SlotRecord, ...] = ()
    findings: tuple[Finding, ...] = ()
    next_action: str = ""
    permissions: PermissionSnapshot | None = None
    sandbox: SandboxSnapshot | None = None
    before: FmsFolderBeforeImage | None = None
    handoff: UninstallHandoff = field(default_factory=UninstallHandoff)


@dataclass(frozen=True)
class PlannedChange:
    kind: str
    target: str
    detail: str


@dataclass(frozen=True)
class CompartmentPlan:
    inputs: CompartmentInputs
    before: FmsFolderBeforeImage
    report: CompartmentReport
    changes: tuple[PlannedChange, ...]


RECOVERY_SCHEMA_VERSION = 1
RECOVERY_FILENAME = "patch-compartment-recovery.json"
RECOVERY_FILE_MODE = 0o600


@dataclass(frozen=True)
class RollbackRecord:
    """Everything a LATER PROCESS needs to undo this operation.

    An administrator's `rollback --operation-id` is necessarily a new process, so a record held in
    memory is not a recovery authority at all — it is a record that exists only while the thing that
    might need it is still running. Every field here is serialisable for that reason.
    """

    before: FmsFolderBeforeImage
    permissions: PermissionSnapshot | None
    sandbox: SandboxSnapshot | None
    slot_touched: str | None
    directory_created_by_this_run: bool
    compartment_path: Path | None = None
    flavour: str = POSIX
    created_dirs: tuple[Path, ...] = ()
    operation_id: str = ""
    installation_id: str = ""
    mode: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": RECOVERY_SCHEMA_VERSION,
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "mode": self.mode,
            "flavour": self.flavour,
            "compartment_path": None if self.compartment_path is None else str(self.compartment_path),
            "slot_touched": self.slot_touched,
            "directory_created_by_this_run": self.directory_created_by_this_run,
            "created_dirs": [str(d) for d in self.created_dirs],
            "before": {
                "captured_utc": self.before.captured_utc,
                "rc_fields": dict(self.before.rc_fields),
                "slots": [
                    {"index": s.index, "fms_path": s.fms_path,
                     "local_path": None if s.local_path is None else str(s.local_path),
                     "enabled": s.enabled}
                    for s in self.before.slots
                ],
                "legacy": [
                    {"trigger": f.trigger, "fms_filename": f.fms_filename,
                     "fms_folder": f.fms_folder,
                     "fms_folder_local": None if f.fms_folder_local is None else str(f.fms_folder_local),
                     "fms_status": f.fms_status,
                     "disk_path": None if f.disk_path is None else str(f.disk_path),
                     "disk_exists": f.disk_exists, "disk_size": f.disk_size,
                     "disk_mtime_utc": f.disk_mtime_utc}
                    for f in self.before.legacy
                ],
            },
            "permissions": None if self.permissions is None else {
                "flavour": self.permissions.flavour, "existed": self.permissions.existed,
                "posix_owner": self.permissions.posix_owner,
                "posix_group": self.permissions.posix_group,
                "posix_mode": self.permissions.posix_mode,
                "windows_sddl": self.permissions.windows_sddl,
            },
            "sandbox": None if self.sandbox is None else {
                "path": str(self.sandbox.path), "existed": self.sandbox.existed,
                "backup": None if self.sandbox.backup is None else str(self.sandbox.backup),
                "posix_mode": self.sandbox.posix_mode, "mtime_utc": self.sandbox.mtime_utc,
                "digest": self.sandbox.digest,
            },
        }

    @classmethod
    def from_dict(cls, raw: object) -> "RollbackRecord":
        """STRICT. Recovery evidence that cannot be read completely and coherently is NOT evidence.

        A partial or coerced parse would restore some things, silently skip others, and then report
        success. `bool(...)` is refused deliberately: it turns `"false"`, `[]` and `0` into a verdict
        about whether a directory was created, and a rollback that removes a tree on the strength of
        the string `"false"` is worse than one that refuses.
        """
        _obj(raw, "the recovery record")
        _exact_keys(raw, {
            "schema_version", "operation_id", "installation_id", "mode", "flavour",
            "compartment_path", "slot_touched", "directory_created_by_this_run", "created_dirs",
            "before", "permissions", "sandbox",
        }, "the recovery record")

        if raw["schema_version"] != RECOVERY_SCHEMA_VERSION:
            raise RecoveryEvidenceInvalid(
                f"recovery schema version {raw['schema_version']!r}; this build writes "
                f"{RECOVERY_SCHEMA_VERSION}")

        operation_id = _uuid_text(raw["operation_id"], "operation_id")
        installation_id = _uuid_text(raw["installation_id"], "installation_id")
        mode = _one_of(raw["mode"], LIFECYCLE_MODES, "mode")
        flavour = _one_of(raw["flavour"], (POSIX, WINDOWS), "flavour")
        created_by_run = _real_bool(raw["directory_created_by_this_run"],
                                    "directory_created_by_this_run")
        slot_touched = None if raw["slot_touched"] is None else _one_of(
            raw["slot_touched"], tuple(i for i, _e, _p in ff.SLOT_FIELDS), "slot_touched")

        compartment = None if raw["compartment_path"] is None else _canonical_abs(
            raw["compartment_path"], "compartment_path", flavour=flavour)

        created_dirs = _ancestor_chain(
            _array(raw["created_dirs"], "created_dirs"), compartment, flavour=flavour)
        if created_by_run and not created_dirs:
            raise RecoveryEvidenceInvalid(
                "the record says this run created the compartment but names no created directories")
        if created_dirs and not created_by_run:
            raise RecoveryEvidenceInvalid(
                "the record names created directories but says this run created nothing")

        before = _before_image(raw["before"], flavour=flavour)
        permissions = _permissions(raw["permissions"], flavour=flavour)
        sandbox = _sandbox(raw["sandbox"], compartment, flavour=flavour)

        return cls(
            before=before, permissions=permissions, sandbox=sandbox, slot_touched=slot_touched,
            directory_created_by_this_run=created_by_run, compartment_path=compartment,
            flavour=flavour, created_dirs=created_dirs, operation_id=operation_id,
            installation_id=installation_id, mode=mode,
        )


# ── the strict readers `from_dict` is built from ──────────────────────────────
# Separate named functions rather than inline checks so each rule is testable on its own and so a
# reader can see that NOTHING here coerces.

def _obj(value, what: str) -> None:
    if not isinstance(value, dict):
        raise RecoveryEvidenceInvalid(f"{what} is not an object")


def _exact_keys(value: dict, expected: set, what: str) -> None:
    missing = expected - set(value)
    if missing:
        raise RecoveryEvidenceInvalid(f"{what} is missing {', '.join(sorted(missing))}")
    unknown = set(value) - expected
    if unknown:
        raise RecoveryEvidenceInvalid(
            f"{what} carries unknown field(s): {', '.join(sorted(unknown))}")


def _real_bool(value, what: str) -> bool:
    """A real bool. `bool("false")` is True, and that is a verdict about a filesystem."""
    if value is not True and value is not False:
        raise RecoveryEvidenceInvalid(f"{what} must be true or false, got {value!r}")
    return value


def _text(value, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise RecoveryEvidenceInvalid(f"{what} must be a non-empty string, got {value!r}")
    return value


def _uuid_text(value, what: str) -> str:
    """A CANONICAL UUID. `uuid.UUID()` accepts braces, urn prefixes and a bare 32-hex run, so
    parsing alone would let three spellings of one identity compare unequal — and identity
    comparison is what decides whether a record is evidence about this operation."""
    text = _text(value, what)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise RecoveryEvidenceInvalid(f"{what} must be a UUID, got {text!r}") from exc
    if text != str(parsed):
        raise RecoveryEvidenceInvalid(
            f"{what} must be the canonical lowercase hyphenated form; got {text!r}, "
            f"canonical is {parsed}")
    return text


_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _digest_text(value, what: str) -> str | None:
    """Exactly a normalized lowercase SHA-256 hex digest.

    Anything else would compare unequal to a digest this code computes, which turns "the content is
    unchanged" into "the content changed" — and that verdict decides whether a replaced sandbox is
    reported as unrecoverable.
    """
    if value is None:
        return None
    text = _text(value, what)
    if not _SHA256_HEX.match(text):
        raise RecoveryEvidenceInvalid(
            f"{what} must be 64 lowercase hex characters (SHA-256), got {text!r}")
    return text


def _one_of(value, allowed, what: str) -> str:
    if value not in allowed:
        raise RecoveryEvidenceInvalid(f"{what} must be one of {tuple(allowed)}, got {value!r}")
    return value


def _array(value, what: str) -> list:
    if not isinstance(value, list):
        raise RecoveryEvidenceInvalid(f"{what} must be an array, got {type(value).__name__}")
    return value


def _optional_int(value, what: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise RecoveryEvidenceInvalid(f"{what} must be an integer, got {value!r}")
    return value


def _optional_text(value, what: str) -> str | None:
    if value is None:
        return None
    return _text(value, what)


def _canonical_abs(value, what: str, *, flavour: str) -> Path:
    """Absolute and canonical BY THE RECORD'S OWN FLAVOUR.

    `Path` follows the HOST, so a Windows record read on a POSIX box had `C:\\h` judged relative
    and every Windows record was unreadable off Windows. A recovery record is exactly the artifact
    that gets read somewhere else — a support copy, a test, the other lane — so the pure flavour is
    what decides, as it already does for the manifest schema.
    """
    from pathlib import PurePosixPath, PureWindowsPath

    text = _text(value, what)
    pure = PureWindowsPath(text) if flavour == WINDOWS else PurePosixPath(text)
    if not pure.is_absolute():
        raise RecoveryEvidenceInvalid(f"{what} must be absolute, got {text!r}")
    if _collapse_text(text, flavour=flavour) != text:
        raise RecoveryEvidenceInvalid(f"{what} is not canonical: {text!r}")
    return Path(text)


def _collapse_text(text: str, *, flavour: str) -> str:
    import ntpath
    import posixpath

    if flavour == WINDOWS:
        return ntpath.normpath(text)
    return posixpath.normpath(text)


def _within(child: Path, parent: Path, *, flavour: str) -> bool:
    from pathlib import PurePosixPath, PureWindowsPath

    if ff.paths_equal(child, parent, flavour=flavour):
        return True
    pure = PureWindowsPath if flavour == WINDOWS else PurePosixPath
    pp, cp = pure(str(parent)).parts, pure(str(child)).parts
    if len(cp) <= len(pp):
        return False
    if flavour == WINDOWS:
        return [x.lower() for x in cp[: len(pp)]] == [x.lower() for x in pp]
    return cp[: len(pp)] == pp


def _ancestor_chain(values: list, compartment: Path | None, *, flavour: str) -> tuple[Path, ...]:
    """Every entry absolute and canonical, forming a strict ancestor chain ending at the
    compartment. A list that is not a chain cannot describe directories one `mkdir(parents=True)`
    made, and removing arbitrary paths on its word is the hazard."""
    if not values:
        return ()
    from pathlib import PurePosixPath, PureWindowsPath

    pure = PureWindowsPath if flavour == WINDOWS else PurePosixPath
    dirs = tuple(_canonical_abs(v, f"created_dirs[{i}]", flavour=flavour)
                 for i, v in enumerate(values))
    for earlier, later in zip(dirs, dirs[1:]):
        if pure(str(later)).parent != pure(str(earlier)):
            raise RecoveryEvidenceInvalid(
                f"created_dirs is not an ancestor chain: {later} does not sit directly in {earlier}")
    if compartment is None:
        raise RecoveryEvidenceInvalid("created_dirs is present without a compartment path")
    if dirs[-1] != compartment:
        raise RecoveryEvidenceInvalid(
            f"created_dirs ends at {dirs[-1]}, not at the compartment {compartment}")
    return dirs


def _before_image(raw, *, flavour: str) -> FmsFolderBeforeImage:
    _obj(raw, "the before-image")
    _exact_keys(raw, {"slots", "rc_fields", "legacy", "captured_utc"}, "the before-image")
    slots = []
    for i, s in enumerate(_array(raw["slots"], "before.slots")):
        _obj(s, f"before.slots[{i}]")
        _exact_keys(s, {"index", "fms_path", "local_path", "enabled"}, f"before.slots[{i}]")
        slots.append(ff.SlotRecord(
            index=_one_of(s["index"], tuple(i2 for i2, _e, _p in ff.SLOT_FIELDS),
                          f"before.slots[{i}].index"),
            fms_path=_optional_text(s["fms_path"], f"before.slots[{i}].fms_path"),
            local_path=None if s["local_path"] is None else _canonical_abs(
                s["local_path"], f"before.slots[{i}].local_path", flavour=flavour),
            enabled=_real_bool(s["enabled"], f"before.slots[{i}].enabled"),
        ))
    if len(slots) not in (0, len(ff.SLOT_FIELDS)):
        raise RecoveryEvidenceInvalid(
            f"before.slots holds {len(slots)} slots; FileMaker Server has exactly "
            f"{len(ff.SLOT_FIELDS)} and a partial image cannot restore the other")
    indices = [s.index for s in slots]
    if len(set(indices)) != len(indices):
        raise RecoveryEvidenceInvalid("before.slots names the same slot twice")

    rc = raw["rc_fields"]
    _obj(rc, "before.rc_fields")
    unknown_rc = set(rc) - set(ff.READ_RC_FIELDS)
    if unknown_rc:
        raise RecoveryEvidenceInvalid(
            f"before.rc_fields carries unknown field(s): {', '.join(sorted(unknown_rc))}")

    legacy = []
    for i, f in enumerate(_array(raw["legacy"], "before.legacy")):
        _obj(f, f"before.legacy[{i}]")
        _exact_keys(f, {"trigger", "fms_filename", "fms_folder", "fms_folder_local", "fms_status",
                        "disk_path", "disk_exists", "disk_size", "disk_mtime_utc"},
                    f"before.legacy[{i}]")
        legacy.append(LegacySandboxFact(
            trigger=_one_of(f["trigger"], (TRIGGER_FMS_KNOWN, TRIGGER_FILESYSTEM_ONLY),
                            f"before.legacy[{i}].trigger"),
            fms_filename=_optional_text(f["fms_filename"], f"before.legacy[{i}].fms_filename"),
            fms_folder=_optional_text(f["fms_folder"], f"before.legacy[{i}].fms_folder"),
            fms_folder_local=None if f["fms_folder_local"] is None else _canonical_abs(
                f["fms_folder_local"], f"before.legacy[{i}].fms_folder_local", flavour=flavour),
            fms_status=_optional_text(f["fms_status"], f"before.legacy[{i}].fms_status"),
            disk_path=None if f["disk_path"] is None else _canonical_abs(
                f["disk_path"], f"before.legacy[{i}].disk_path", flavour=flavour),
            disk_exists=_real_bool(f["disk_exists"], f"before.legacy[{i}].disk_exists"),
            disk_size=_optional_int(f["disk_size"], f"before.legacy[{i}].disk_size"),
            disk_mtime_utc=_optional_text(f["disk_mtime_utc"],
                                          f"before.legacy[{i}].disk_mtime_utc"),
        ))
    return FmsFolderBeforeImage(
        slots=tuple(slots), rc_fields=dict(rc), legacy=tuple(legacy),
        captured_utc=_text(raw["captured_utc"], "before.captured_utc"),
    )


def _permissions(raw, *, flavour: str) -> PermissionSnapshot | None:
    if raw is None:
        return None
    _obj(raw, "permissions")
    _exact_keys(raw, {"flavour", "existed", "posix_owner", "posix_group", "posix_mode",
                      "windows_sddl"}, "permissions")
    snap_flavour = _one_of(raw["flavour"], (POSIX, WINDOWS), "permissions.flavour")
    if snap_flavour != flavour:
        raise RecoveryEvidenceInvalid(
            f"permissions were captured on {snap_flavour} but the record is {flavour}")
    mode = _optional_int(raw["posix_mode"], "permissions.posix_mode")
    if mode is not None and not 0 <= mode <= 0o7777:
        raise RecoveryEvidenceInvalid(f"permissions.posix_mode is out of range: {mode!r}")
    existed = _real_bool(raw["existed"], "permissions.existed")
    owner = _optional_text(raw["posix_owner"], "permissions.posix_owner")
    group = _optional_text(raw["posix_group"], "permissions.posix_group")
    sddl = _optional_text(raw["windows_sddl"], "permissions.windows_sddl")

    # INTERNAL CONSISTENCY. A snapshot carrying the other platform's fields did not come from this
    # box, and restoring from it would apply a mode nobody captured or claim an SDDL nobody read.
    if snap_flavour == WINDOWS and (owner is not None or group is not None or mode is not None):
        raise RecoveryEvidenceInvalid(
            "permissions were captured on windows but carry POSIX owner/group/mode")
    if snap_flavour == POSIX and sddl is not None:
        raise RecoveryEvidenceInvalid(
            "permissions were captured on posix but carry a Windows security descriptor")
    if not existed and (owner is not None or group is not None or mode is not None
                        or sddl is not None):
        raise RecoveryEvidenceInvalid(
            "permissions describe a directory that did not exist yet carry captured values")
    if snap_flavour == POSIX and existed and mode is None:
        raise RecoveryEvidenceInvalid(
            "permissions describe an existing POSIX directory with no captured mode; the "
            "restoration could not be verified")

    return PermissionSnapshot(
        flavour=snap_flavour, existed=existed, posix_owner=owner, posix_group=group,
        posix_mode=mode, windows_sddl=sddl,
    )


def _sandbox(raw, compartment: Path | None, *, flavour: str) -> SandboxSnapshot | None:
    if raw is None:
        return None
    _obj(raw, "sandbox")
    _exact_keys(raw, {"path", "existed", "backup", "posix_mode", "mtime_utc", "digest"}, "sandbox")
    path = _canonical_abs(raw["path"], "sandbox.path", flavour=flavour)
    backup = None if raw["backup"] is None else _canonical_abs(
        raw["backup"], "sandbox.backup", flavour=flavour)
    if compartment is not None:
        for candidate, what in ((path, "sandbox.path"), (backup, "sandbox.backup")):
            if candidate is not None and not _within(candidate, compartment, flavour=flavour):
                raise RecoveryEvidenceInvalid(
                    f"{what} ({candidate}) is outside the compartment {compartment}")
    existed = _real_bool(raw["existed"], "sandbox.existed")
    digest = _digest_text(raw["digest"], "sandbox.digest")
    if existed and digest is None:
        raise RecoveryEvidenceInvalid(
            "sandbox.existed is true but no digest was captured; the restoration could not be "
            "verified and a missing backup could not be told from a completed replacement")
    if not existed and digest is not None:
        raise RecoveryEvidenceInvalid("sandbox.digest is present for a sandbox that did not exist")
    return SandboxSnapshot(
        path=path, existed=existed, backup=backup,
        posix_mode=_optional_int(raw["posix_mode"], "sandbox.posix_mode"),
        mtime_utc=_optional_text(raw["mtime_utc"], "sandbox.mtime_utc"), digest=digest,
    )


class RecoveryEvidenceInvalid(LifecycleError):
    """Recovery evidence is missing, malformed, mismatched or incomplete.

    Its own error because the ONE thing this must never do is fail into "nothing changed": a run
    that cannot read its own recovery record knows less than nothing about what is on the box.
    """


def recovery_path(layout) -> Path:
    """Beside the journal, in the same lifecycle-controlled state directory."""
    return Path(layout.journal_file).parent / RECOVERY_FILENAME


def write_recovery(layout, record: RollbackRecord, *, lock) -> Path:
    """Atomic, secret-fenced, root-owned-state. Written BEFORE the mutation it covers."""
    require_lock(lock, "recording patch-compartment recovery authority")
    payload = record.to_dict()
    assert_no_secrets(payload, what="the patch-compartment recovery record")
    target = recovery_path(layout)
    atomic_write_text(target, json.dumps(payload, indent=2, sort_keys=True) + "\n",
                      mode=RECOVERY_FILE_MODE)
    return target


def read_recovery(layout) -> RollbackRecord:
    target = recovery_path(layout)
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RecoveryEvidenceInvalid(
            f"no patch-compartment recovery record at {target}") from exc
    except (OSError, ValueError) as exc:
        raise RecoveryEvidenceInvalid(
            f"the recovery record at {target} cannot be read: {type(exc).__name__}") from exc
    return RollbackRecord.from_dict(raw)


def clear_recovery(layout, *, lock) -> None:
    """Retire the recovery record AND the backup it names — but only after the journal resolved.

    Order matters and is the whole point of this function existing: an unresolved journal must
    always still have a usable backup, so nothing here may run before resolution. Afterwards the
    backup is inert, and leaving it is harmless residue rather than a lost restore point.
    """
    require_lock(lock, "clearing patch-compartment recovery authority")
    target = recovery_path(layout)
    try:
        record = read_recovery(layout)
    except RecoveryEvidenceInvalid:
        record = None
    if record is not None and record.sandbox is not None and record.sandbox.backup is not None:
        try:
            record.sandbox.backup.unlink(missing_ok=True)
        except OSError:
            pass          # harmless residue; the record is what authority depends on
    target.unlink(missing_ok=True)


@dataclass(frozen=True)
class CompartmentResult:
    state: CompartmentState
    result: str
    applied: tuple[PlannedChange, ...]
    report: CompartmentReport
    rollback: RollbackRecord | None = None


@dataclass(frozen=True)
class CandidateFacts:
    """What 1246-04 composes into its single manifest write. This child performs no write."""

    patch: PatchBlock
    patch_hosting_dir: Path
    inspected_generation: int
    inspected_installation_id: str
    #: At most ONE ownership entry, for the sandbox's RC companion path, and only when attribution
    #: proved it (packet 1246-09 §O7). Empty when it could not be proved — which is the ordinary
    #: outcome on a compartment that already contained an `RC_Data_FMS` folder.
    ownership: tuple = ()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lowest(states: set[CompartmentState]) -> CompartmentState:
    for candidate in _PRECEDENCE:
        if candidate in states:
            return candidate
    return CompartmentState.VERIFIED_READY


# ── path validation ────────────────────────────────────────────────────────────

def _canonical(path: Path | str, *, flavour: str) -> Path:
    """Collapse then resolve. Collapsing first matters: `PurePath` does not collapse `..`, so a
    comparison done before this step can call a traversal equal to what it escapes."""
    text = str(path)
    if flavour == WINDOWS:
        import ntpath

        collapsed = Path(ntpath.normpath(text.replace("/", "\\")))
    else:
        import posixpath

        collapsed = Path(posixpath.normpath(text))
    try:
        return Path(os.path.realpath(str(collapsed)))
    except OSError:
        return collapsed


def _is_within(child: Path, parent: Path, *, flavour: str) -> bool:
    if ff.paths_equal(child, parent, flavour=flavour):
        return True
    parts_parent = _canonical(parent, flavour=flavour).parts
    parts_child = _canonical(child, flavour=flavour).parts
    if len(parts_child) < len(parts_parent):
        return False
    if flavour == WINDOWS:
        return [p.lower() for p in parts_child[: len(parts_parent)]] == [
            p.lower() for p in parts_parent
        ]
    return parts_child[: len(parts_parent)] == parts_parent


def validate_path(inputs: CompartmentInputs) -> tuple[Path | None, tuple[Finding, ...]]:
    """Canonicalize first, compare second. Returns (canonical path, findings)."""
    findings: list[Finding] = []
    raw = Path(inputs.requested)
    if not str(raw).strip():
        return None, (Finding(CompartmentState.PATH_REFUSED.value, "no path was requested"),)
    if not raw.is_absolute():
        return None, (
            Finding(CompartmentState.PATH_REFUSED.value,
                    f"{raw} is not absolute; a compartment is named by an absolute path"),
        )

    # A symlink is refused BEFORE resolution, so a link that currently points somewhere harmless
    # cannot be re-aimed after the check.
    if raw.is_symlink():
        return None, (
            Finding(CompartmentState.PATH_REFUSED.value,
                    f"{raw} is a symlink or junction; a compartment must be a real directory"),
        )

    canonical = _canonical(raw, flavour=inputs.flavour)
    if len(canonical.parts) <= 1:
        return None, (
            Finding(CompartmentState.PATH_REFUSED.value,
                    f"{canonical} is a filesystem root"),
        )

    forbidden: list[tuple[str, Path]] = [
        ("the installation directory", inputs.install_dir),
        ("the FileMaker Server root", inputs.fms_root),
        ("the main FileMaker Server database directory", inputs.fms_database_dir),
    ]
    forbidden += [("a storage directory", p) for p in inputs.storage_dirs]
    forbidden += [("a protected lifecycle directory", p) for p in inputs.protected_dirs]

    for label, other in forbidden:
        if other is None:
            continue
        if _is_within(canonical, Path(other), flavour=inputs.flavour) or _is_within(
            Path(other), canonical, flavour=inputs.flavour
        ):
            findings.append(Finding(
                CompartmentState.PATH_REFUSED.value,
                f"{canonical} overlaps {label} ({other}); the compartment must be its own tree",
            ))

    try:
        ff.fms_path_for(canonical, flavour=inputs.flavour)
    except ff.FmsPathRefused as exc:
        findings.append(Finding(CompartmentState.PATH_REFUSED.value, str(exc)))

    if findings:
        return None, tuple(findings)
    return canonical, ()


# ── effective access ───────────────────────────────────────────────────────────

_PROBE_SCRIPT = r"""
import os, sys
d = sys.argv[1]
uid, gid = int(sys.argv[2]), int(sys.argv[3])
groups = [int(g) for g in sys.argv[4].split(",") if g]
made = []
# Supplementary groups FIRST, then gid, then uid: a uid dropped first can no longer drop groups.
# When the caller is ALREADY the target identity there is nothing to drop and nothing to prove by
# trying — an unprivileged process cannot call setgroups at all, and treating that as a failed drop
# would report a compartment it can genuinely use as unusable.
if os.getuid() != uid:
    try:
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
    except Exception as exc:
        print("DROP_FAILED:" + type(exc).__name__)
        raise SystemExit(1)
if os.getuid() != uid or os.getuid() == 0:
    print("DROP_INEFFECTIVE")
    raise SystemExit(1)
probe = os.path.join(d, ".cfm-access-probe-%d" % os.getpid())
moved = probe + ".moved"
made.append(probe)
try:
    with open(probe, "wb") as fh:
        fh.write(b"probe")
    with open(probe, "rb") as fh:
        fh.read()
    made.append(moved)
    os.rename(probe, moved)
    made.remove(probe)
    os.remove(moved)
    made.remove(moved)
    print("OK")
except Exception as exc:
    print("PROBE_FAILED:" + type(exc).__name__)
    raise SystemExit(1)
finally:
    for leftover in made:
        try:
            os.remove(leftover)
        except OSError:
            pass
"""


def _posix_identity_ids(account: str) -> tuple[int, int, list[int]]:
    import grp
    import pwd

    entry = pwd.getpwnam(account)
    groups = [g.gr_gid for g in grp.getgrall() if account in g.gr_mem]
    if entry.pw_gid not in groups:
        groups.append(entry.pw_gid)
    return entry.pw_uid, entry.pw_gid, groups


def _probe_posix(directory: Path, identity: ServiceIdentity) -> tuple[bool, str]:
    """An elevated isolated child drops supplementary groups, then gid, then uid — that order; a
    uid dropped first can no longer drop groups — and performs a real create/write/read/rename/
    delete inside the directory, cleaning up on every exit path."""
    try:
        uid, gid, groups = _posix_identity_ids(identity.account)
        if uid == 0:
            # A "drop" to uid 0 proves nothing: root passes every filesystem check regardless of the
            # directory's ownership, so the probe would report success for a compartment no service
            # account can use.
            return False, (f"{identity.account!r} resolves to uid 0; the access proof requires an "
                           "unprivileged identity")
    except KeyError:
        return False, f"the account {identity.account!r} does not exist on this box"
    except Exception as exc:                       # pragma: no cover - platform-specific
        return False, f"could not resolve {identity.account!r}: {type(exc).__name__}"

    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", _PROBE_SCRIPT, str(directory),
             str(uid), str(gid), ",".join(str(g) for g in groups)],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as exc:                       # pragma: no cover - defensive
        return False, f"the access probe could not run: {type(exc).__name__}"

    out = (proc.stdout or "").strip().splitlines()
    marker = out[-1] if out else ""
    if proc.returncode == 0 and marker == "OK":
        return True, ""
    # Sanitized: a named reason, never raw child stderr and never a path outside the compartment.
    if marker == "DROP_INEFFECTIVE":
        return False, f"the probe did not actually become {identity.account!r}"
    if marker.startswith("DROP_FAILED:"):
        return False, f"could not assume {identity.account!r} ({marker.split(':', 1)[1]})"
    if marker.startswith("PROBE_FAILED:"):
        return False, (f"{identity.account!r} cannot create, write, read, rename and delete inside "
                       f"the compartment ({marker.split(':', 1)[1]})")
    return False, f"the access probe for {identity.account!r} produced no verdict"


def _probe_windows(directory: Path, identity: ServiceIdentity, *, acl_api=None) -> tuple[bool, str]:
    """Effective RIGHTS, through protection.py's existing WindowsAclApi.

    This is policy/effective-rights EVIDENCE. It is not proof that a real Windows process performed
    the operations, and nothing here may be reported as "acting as" the identity. The real
    service-identity exercise is 1246-10's.
    """
    if acl_api is None:                            # pragma: no cover - platform-specific
        from .protection import real_windows_acl_api

        acl_api = real_windows_acl_api()
    try:
        sid = acl_api.sid(identity.account)
        held = int(acl_api.effective_rights(directory, sid))
    except Exception as exc:
        return False, (f"could not read effective rights for {identity.account!r} "
                       f"({type(exc).__name__})")
    if not _win_rights_satisfied(held):
        missing = _win_required_rights() & ~held
        return False, (f"effective rights for {identity.account!r} are missing 0x{missing:x} of the "
                       "create/read/write/rename/delete set (effective-rights evidence, not a "
                       "performed operation)")
    return True, ""


def prove_effective_access(
    directory: Path, inputs: CompartmentInputs, *, acl_api=None, probe: Callable | None = None
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for identity in (inputs.service_identity, inputs.fms_identity):
        if probe is not None:
            ok, detail = probe(directory, identity)
        elif inputs.flavour == WINDOWS:
            ok, detail = _probe_windows(directory, identity, acl_api=acl_api)
        else:
            ok, detail = _probe_posix(directory, identity)
        if not ok:
            findings.append(Finding(
                CompartmentState.PERMISSIONS_INCOMPLETE.value, detail, identity.account,
            ))
    return tuple(findings)


# ── conversion detection ───────────────────────────────────────────────────────

def _legacy_disk_path(inputs: CompartmentInputs) -> Path:
    return Path(inputs.fms_database_dir) / SANDBOX_FILE


def _legacy_display_path(fact: LegacySandboxFact, *, flavour: str) -> str:
    """Best exact local filename available without pretending an FMS URI is a disk path."""
    if fact.disk_path is not None:
        return str(fact.disk_path)
    if fact.fms_folder_local is None:
        return "not derivable from the FileMaker registration"
    local = str(fact.fms_folder_local)
    if not (ntpath.isabs(local) if flavour == WINDOWS else posixpath.isabs(local)):
        return "not derivable from the FileMaker registration"
    filename = fact.fms_filename or SANDBOX_FILE
    if flavour == WINDOWS:
        return ntpath.join(local, filename)
    return posixpath.join(local, filename)


def _conversion_finding(fact: LegacySandboxFact, inputs: CompartmentInputs) -> Finding:
    registration = (
        f"filename={fact.fms_filename or 'not reported'}, "
        f"folder={fact.fms_folder or 'not registered'}, "
        f"status={fact.fms_status or 'not reported'}"
    )
    return Finding(
        CompartmentState.CONVERSION_REQUIRED.value,
        (f"{SANDBOX_FILE} exists outside the intended compartment; trigger={fact.trigger}; "
         f"disk path={_legacy_display_path(fact, flavour=inputs.flavour)}; "
         f"FileMaker registration: {registration}. The patch-compartment provider changed no "
         "sandbox and no FileMaker folder registration."),
    )


def _conversion_next_action() -> str:
    return (
        "Stop and resolve only the reported conflict, then re-run the ordinary Series 2 "
        "installer. If a Series 1 installation is still active, run its installed uninstaller. "
        "If Series 1 was already uninstalled, establish ownership independently: CORPUSfm does "
        "not infer ownership from a filename or default path. Preserve CORPUSfm_DB, its RC data, "
        "backups and Corpus Key. The sandbox RC_Data_FMS sidecar is not detected by this check; "
        "inspect it separately and act only with independently established authority. No deletion "
        "or conversion was performed."
    )


def detect_conversion(
    adapter: ff.FmsFolderAdapter, inputs: CompartmentInputs, compartment: Path | None
) -> tuple[LegacySandboxFact, ...]:
    """BOTH triggers. A definition that names only the first ships half the detection."""
    facts: list[LegacySandboxFact] = []

    for row in adapter.list_databases():
        filename = str(row.get("filename") or "")
        stem = filename[: -len(".fmp12")] if filename.lower().endswith(".fmp12") else filename
        if stem.lower() != SANDBOX_NAME.lower():
            continue
        folder = row.get("folder")
        local = None
        if isinstance(folder, str) and folder:
            try:
                local = ff.local_path_from_fms(folder, flavour=inputs.flavour)
            except ff.FmsPathRefused:
                local = Path(folder)
        if compartment is not None and local is not None and ff.paths_equal(
            local, compartment, flavour=inputs.flavour
        ):
            continue                                # this IS the compartment's sandbox
        facts.append(LegacySandboxFact(
            trigger=TRIGGER_FMS_KNOWN,
            fms_filename=filename or None,
            fms_folder=folder if isinstance(folder, str) else None,
            fms_folder_local=local,
            fms_status=str(row.get("status")) if row.get("status") is not None else None,
        ))

    legacy = _legacy_disk_path(inputs)
    if legacy.exists() and not any(
        f.fms_folder_local is not None
        and ff.paths_equal(f.fms_folder_local, legacy.parent, flavour=inputs.flavour)
        for f in facts
    ):
        try:
            st = legacy.stat()
            size = st.st_size
            # One line, deliberately: the UTC guard reads line by line, and wrapping this call put
            # `tz=timezone.utc` out of its sight — a true statement the guard could not see.
            mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        except OSError:
            size, mtime = None, None
        facts.append(LegacySandboxFact(
            trigger=TRIGGER_FILESYSTEM_ONLY,
            disk_path=legacy,
            disk_exists=True,
            disk_size=size,
            disk_mtime_utc=mtime,
        ))
    return tuple(facts)


# ── snapshots ──────────────────────────────────────────────────────────────────

def _security_descriptor(directory: Path) -> str | None:  # pragma: no cover - platform-specific
    """The SDDL, through `protection.py` — the module that owns the pywin32 seam.

    Reached by the factory rather than by importing `win32security` here: this module must contain
    no SID/DACL implementation of its own, and a capture written locally would be the third one in
    the tree."""
    from .protection import security_descriptor_of

    return security_descriptor_of(directory)


def capture_permissions(directory: Path, *, flavour: str) -> PermissionSnapshot:
    """What rollback needs to put back. A field that cannot be captured is left None AND the caller
    is told, because a silent None is indistinguishable from "there was nothing to restore"."""
    existed = directory.exists()
    if not existed:
        return PermissionSnapshot(flavour=flavour, existed=False)
    if flavour == WINDOWS:                          # pragma: no cover - platform-specific
        return PermissionSnapshot(
            flavour=flavour, existed=True, windows_sddl=_security_descriptor(directory),
        )
    st = directory.stat()
    owner = group = None
    try:
        import grp
        import pwd

        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        # A uid/gid with no passwd/group entry — real on a box where an account was removed. The
        # numeric ids still restore, so this is recorded rather than raised.
        owner = owner or str(st.st_uid)
        group = group or str(st.st_gid)
    return PermissionSnapshot(
        flavour=flavour, existed=True, posix_owner=owner, posix_group=group,
        posix_mode=stat.S_IMODE(st.st_mode),
    )


def apply_compartment_permissions(directory: Path, inputs: CompartmentInputs) -> None:
    """Make the compartment usable by BOTH identities, then let the proof judge it.

    POSIX mirrors what the installer established for this folder: owned by the service account,
    group of the FMS account, `2775` — setgid so files FileMaker Server creates inside (its own
    `RC_Data_FMS` bookkeeping) stay in the shared group. Without this step `mkdir` leaves the
    directory owned by the elevated caller, the FMS identity fails its proof, and VERIFIED_READY is
    unreachable on every real box — which is what a caller-injected-only hook produced.

    Windows needs no step here: the compartment inherits from its parent and the effective-rights
    proof is what decides whether that inheritance is sufficient.
    """
    if inputs.flavour == WINDOWS:                   # pragma: no cover - platform-specific
        return
    import grp
    import pwd

    uid = pwd.getpwnam(inputs.service_identity.account).pw_uid
    try:
        gid = grp.getgrnam(inputs.fms_identity.account).gr_gid
    except KeyError:
        gid = pwd.getpwnam(inputs.fms_identity.account).pw_gid
    os.chown(directory, uid, gid)
    directory.chmod(0o2775)


def apply_sandbox_permissions(sandbox: Path, inputs: CompartmentInputs) -> None:
    """Give the seeded database to the same two identities as its compartment.

    ``copy2`` deliberately preserves the versioned seed's mode, which is useful for ordinary files
    and wrong for a hosted FileMaker database.  On Linux a root-run install otherwise leaves the
    sandbox ``root:root 0644``: readable in the Unix sense, but not an admissible hosted database,
    so FileMaker omits it from its database inventory and the open proof can never succeed.  The
    service owns the file, FileMaker's primary group shares it, and nobody else receives access.

    Windows obtains the corresponding authority from the protected compartment DACL when the file
    is created.  Rewriting that DACL here would create a second Windows protection authority.
    """
    if inputs.flavour == WINDOWS:                   # pragma: no cover - platform-specific
        return
    import grp
    import pwd

    uid = pwd.getpwnam(inputs.service_identity.account).pw_uid
    try:
        gid = grp.getgrnam(inputs.fms_identity.account).gr_gid
    except KeyError:
        gid = pwd.getpwnam(inputs.fms_identity.account).pw_gid
    os.chown(sandbox, uid, gid)
    sandbox.chmod(0o660)


class BackupNotDurable(LifecycleError):
    """A backup was created but could not be proven complete. Never treated as a restore point."""


def _write_verified_backup(src: Path, dest: Path, expected_digest: str | None) -> None:
    """Create a backup that is PROVEN complete before anything relies on it.

    A backup's EXISTENCE is not proof that its copy completed. A crash — or a full disk — mid-copy
    leaves a file at the destination holding a prefix of the source, and every later reader sees a
    file that is there and is wrong. So this does four things and only then returns:

      * creates exclusively (`O_EXCL`) — `shutil.copy2` writes over whatever is there, and the one
        operation whose whole purpose is preserving content must never destroy any;
      * flushes and **fsyncs the file**, so the bytes are durable rather than merely written;
      * **verifies the digest** against what was captured from the original;
      * **fsyncs the containing directory**, so the entry itself survives.

    On any failure the partial destination is removed and the SOURCE IS NEVER TOUCHED — the sandbox
    is what the backup exists to protect, and a failed attempt to protect it must not damage it.
    """
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            with open(src, "rb") as source, os.fdopen(os.dup(fd), "wb") as handle:
                shutil.copyfileobj(source, handle)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(fd)

        shutil.copystat(src, dest)
        if expected_digest is not None:
            written = file_digest(dest)
            if written != expected_digest:
                raise BackupNotDurable(
                    f"{dest} does not match the captured original after copying; it is not a "
                    "restore point")
        _fsync_dir(dest.parent)
    except BaseException:
        # The partial backup goes; the sandbox is untouched either way.
        try:
            dest.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_dir(directory: Path) -> None:
    """Durably record the directory ENTRY, not only the file's bytes."""
    try:
        fd = os.open(str(directory), getattr(os, "O_DIRECTORY", os.O_RDONLY))
    except OSError:                                  # pragma: no cover - platform-specific
        return
    try:
        os.fsync(fd)
    except OSError:                                  # pragma: no cover - some filesystems refuse
        pass
    finally:
        os.close(fd)


def backup_path_for(target: Path, operation_id: str) -> Path:
    """The pre-seed backup, named for the operation that makes it.

    Operation-specific rather than a fixed `.pre-seed`: a shared name is a predictable path that the
    copy would overwrite without looking, which is the opposite of preserving what was there.
    """
    token = operation_id or "unknown"
    return target.with_name(f"{target.name}.{token}.pre-seed")


def file_digest(path: Path) -> str:
    """SHA-256 of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def capture_sandbox(compartment: Path) -> SandboxSnapshot:
    path = compartment / SANDBOX_FILE
    if not path.exists():
        return SandboxSnapshot(path=path, existed=False)
    st = path.stat()
    return SandboxSnapshot(
        path=path, existed=True, posix_mode=stat.S_IMODE(st.st_mode),
        mtime_utc=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        digest=file_digest(path),
    )


def capture_before_image(
    adapter: ff.FmsFolderAdapter, inputs: CompartmentInputs, compartment: Path | None
) -> FmsFolderBeforeImage:
    paths, settings = ff.capture_folder_state(adapter)      # ONE call per resource
    return FmsFolderBeforeImage(
        slots=ff.parse_slots(paths, settings, flavour=inputs.flavour),
        rc_fields=ff.read_rc_fields(settings),
        legacy=detect_conversion(adapter, inputs, compartment),
        captured_utc=_utc(),
    )


# ── slot policy ────────────────────────────────────────────────────────────────

def choose_slot(
    slots: tuple[ff.SlotRecord, ...], compartment: Path, *, flavour: str
) -> tuple[str | None, bool]:
    """(index, already_exact). Reuse an exact registration; else the lowest free slot; else None."""
    for slot in slots:
        if slot.local_path is not None and ff.paths_equal(
            slot.local_path, compartment, flavour=flavour
        ):
            return slot.index, True
    for slot in slots:
        if not slot.fms_path:
            return slot.index, False
    return None, False


# ── inspect / plan / apply / verify / rollback ─────────────────────────────────

def _handoff(
    compartment: Path | None, slot: str | None, before: FmsFolderBeforeImage | None,
    *, reachable: bool
) -> UninstallHandoff:
    others = 0
    sandbox = None
    if compartment is not None and compartment.is_dir():
        for entry in compartment.iterdir():
            if entry.name == SANDBOX_FILE:
                sandbox = entry
            else:
                others += 1
    return UninstallHandoff(
        compartment_path=compartment, slot_index=slot, sandbox_file=sandbox,
        other_content_count=others, fms_reachable=reachable, before=before,
    )


def preflight_report(inputs: CompartmentInputs, detail: str) -> CompartmentReport:
    """The report when no adapter could be built, or its first call failed.

    Returned rather than raised: a caller that never obtains an adapter would otherwise have to
    invent a state, a result word and a next action — exactly what 1246-04 was promised it would
    never do.
    """
    return CompartmentReport(
        state=CompartmentState.API_REQUIRED_UNAVAILABLE,
        result=FAILED_BEFORE_CHANGE,
        findings=(Finding(CompartmentState.API_REQUIRED_UNAVAILABLE.value, detail),),
        next_action=("Configure the co-located FileMaker Server Admin API PKI key, then re-run "
                     "patch-compartment inspect. Nothing was created or changed."),
        handoff=UninstallHandoff(fms_reachable=False),
    )


def inspect(
    inputs: CompartmentInputs, *, adapter: ff.FmsFolderAdapter, acl_api=None,
    probe: Callable | None = None,
) -> CompartmentReport:
    """Read-only. Contacts the API — a read, not a mutation — so a refusal costs nothing."""
    compartment, path_findings = validate_path(inputs)
    if path_findings:
        return CompartmentReport(
            state=CompartmentState.PATH_REFUSED, result=NO_CHANGE, findings=path_findings,
            next_action="Choose a compartment path outside every protected tree and re-run inspect.",
        )
    assert compartment is not None

    try:
        before = capture_before_image(adapter, inputs, compartment)
    except ff.FmsFolderError as exc:
        return preflight_report(inputs, str(exc))

    states: set[CompartmentState] = set()
    findings: list[Finding] = []

    for fact in before.legacy:
        states.add(CompartmentState.CONVERSION_REQUIRED)
        findings.append(_conversion_finding(fact, inputs))

    slot, exact = choose_slot(before.slots, compartment, flavour=inputs.flavour)
    if slot is None:
        states.add(CompartmentState.ALL_SLOTS_OCCUPIED)
        findings.append(Finding(
            CompartmentState.ALL_SLOTS_OCCUPIED.value,
            ("both Additional Database Folder slots hold other paths; this component never "
             "displaces one. Free a slot in the Admin Console, then re-run inspect."),
        ))
    elif exact:
        record = next(s for s in before.slots if s.index == slot)
        if not record.enabled:
            states.add(CompartmentState.REGISTERED_NOT_ENABLED)
            findings.append(Finding(
                CompartmentState.REGISTERED_NOT_ENABLED.value,
                f"slot {slot} already names this path but is not enabled",
            ))
    else:
        states.add(CompartmentState.FREE_SLOT_AVAILABLE)

    permissions = capture_permissions(compartment, flavour=inputs.flavour)
    sandbox = capture_sandbox(compartment) if compartment.is_dir() else SandboxSnapshot(
        path=compartment / SANDBOX_FILE, existed=False)

    if compartment.is_dir():
        access = prove_effective_access(compartment, inputs, acl_api=acl_api, probe=probe)
        if access:
            states.add(CompartmentState.PERMISSIONS_INCOMPLETE)
            findings.extend(access)

    if not states:
        states.add(CompartmentState.FREE_SLOT_AVAILABLE)

    state = _lowest(states)
    return CompartmentReport(
        state=state, result=NO_CHANGE, slots=before.slots, findings=tuple(findings),
        next_action=_next_action(state, slot),
        permissions=permissions, sandbox=sandbox, before=before,
        handoff=_handoff(compartment, slot, before, reachable=True),
    )


def _next_action(state: CompartmentState, slot: str | None) -> str:
    if state is CompartmentState.CONVERSION_REQUIRED:
        return _conversion_next_action()
    if state is CompartmentState.ALL_SLOTS_OCCUPIED:
        return "Free one Additional Database Folder slot, then re-run inspect."
    if state is CompartmentState.PERMISSIONS_INCOMPLETE:
        return "Grant both service identities effective access to the compartment, then re-run."
    if state is CompartmentState.VERIFIED_READY:
        return "The compartment is verified; the caller may publish the returned candidate facts."
    if state is CompartmentState.FREE_SLOT_AVAILABLE:
        return f"Run patch-compartment apply; it will take slot {slot}."
    return "Re-run patch-compartment inspect after resolving the reported finding."


def plan(report: CompartmentReport, inputs: CompartmentInputs) -> CompartmentPlan:
    """Pure. Carries the inputs and the before-image so apply can compare before it mutates."""
    if report.before is None:
        raise CompartmentRefused("cannot plan from a report that carries no before-image")
    compartment, _ = validate_path(inputs)
    if compartment is None:
        raise CompartmentRefused("cannot plan from a refused path")

    changes: list[PlannedChange] = []
    if report.state in (
        CompartmentState.FREE_SLOT_AVAILABLE, CompartmentState.REGISTERED_NOT_ENABLED,
        CompartmentState.PERMISSIONS_INCOMPLETE, CompartmentState.VERIFIED_READY,
    ):
        slot, _ = choose_slot(report.before.slots, compartment, flavour=inputs.flavour)
        changes = [
            PlannedChange("create_dir", str(compartment), "create the compartment directory"),
            PlannedChange("apply_permissions", str(compartment),
                          "grant both service identities effective access"),
            PlannedChange("patch_slot", str(slot),
                          f"register {compartment} as Additional Database Folder slot {slot}"),
            PlannedChange("seed_sandbox", str(compartment / SANDBOX_FILE),
                          "copy the versioned seed into the compartment"),
            PlannedChange("open_close_probe", SANDBOX_NAME,
                          "open, observe OPEN, close, observe CLOSED"),
        ]
    return CompartmentPlan(
        inputs=inputs, before=report.before, report=report, changes=tuple(changes),
    )


def _images_agree(left: FmsFolderBeforeImage, right: FmsFolderBeforeImage) -> str | None:
    if left.slots != right.slots:
        return "the Additional Database Folder slots changed since the plan was made"
    if left.rc_fields != right.rc_fields:
        return "a remote-container field changed since the plan was made"
    if len(left.legacy) != len(right.legacy):
        return ("a CORPUSfm_Sandbox outside the intended compartment appeared or disappeared since "
                "the plan was made")
    return None


def _local_state_agrees(
    planned: CompartmentReport, compartment: Path, *, flavour: str
) -> str | None:
    """The FILESYSTEM half of the pre-apply comparison — the FULL facts, not the existence flags.

    Comparing only `existed` was half of half a picture: a sandbox whose BYTES changed between plan
    and apply, or a compartment whose ownership was altered, both compared equal and the run went on
    to `mkdir`, `chown`, `PATCH`, back up and seed on the strength of a plan that no longer described
    the box. These are the facts that AUTHORIZE the mutation; every one of them is compared.
    """
    if planned.sandbox is not None:
        now = capture_sandbox(compartment) if compartment.is_dir() else SandboxSnapshot(
            path=compartment / SANDBOX_FILE, existed=False)
        was = planned.sandbox
        if now.existed != was.existed:
            return f"{now.path} appeared or disappeared since the plan was made"
        if str(now.path) != str(was.path):
            return f"the sandbox path moved from {was.path} to {now.path} since the plan was made"
        if was.existed:
            if now.digest != was.digest:
                return f"{now.path} holds different content than when the plan was made"
            if was.posix_mode is not None and now.posix_mode != was.posix_mode:
                return f"{now.path} changed mode since the plan was made"
            if was.mtime_utc is not None and now.mtime_utc != was.mtime_utc:
                return f"{now.path} was modified since the plan was made"

    if planned.permissions is not None:
        now_perms = capture_permissions(compartment, flavour=flavour)
        was_perms = planned.permissions
        if now_perms.existed != was_perms.existed:
            return f"{compartment} appeared or disappeared since the plan was made"
        if was_perms.existed:
            for label, before_value, now_value in (
                ("owner", was_perms.posix_owner, now_perms.posix_owner),
                ("group", was_perms.posix_group, now_perms.posix_group),
                ("mode", was_perms.posix_mode, now_perms.posix_mode),
                ("security descriptor", was_perms.windows_sddl, now_perms.windows_sddl),
            ):
                if before_value is not None and now_value != before_value:
                    return f"{compartment} changed {label} since the plan was made"
    return None


def apply(
    plan_obj: CompartmentPlan, *, adapter: ff.FmsFolderAdapter, lock,
    decision: SandboxDecision = SandboxDecision.NONE, acl_api=None,
    probe: Callable | None = None, apply_permissions: Callable | None = None,
    layout=None, operation_id: str = "", installation_id: str = "", mode: str = "",
) -> CompartmentResult:
    """Under the lifecycle lock. Re-reads and compares the complete before-image BEFORE the first
    mutation; any divergence refuses with nothing changed."""
    require_lock(lock, "provisioning the patch compartment")
    inputs = plan_obj.inputs
    compartment, path_findings = validate_path(inputs)
    if path_findings or compartment is None:
        return CompartmentResult(
            state=CompartmentState.PATH_REFUSED, result=FAILED_BEFORE_CHANGE, applied=(),
            report=CompartmentReport(
                state=CompartmentState.PATH_REFUSED, result=FAILED_BEFORE_CHANGE,
                findings=path_findings,
                next_action="Choose a compartment path outside every protected tree.",
            ),
        )

    if not plan_obj.changes:
        return CompartmentResult(
            state=plan_obj.report.state, result=FAILED_BEFORE_CHANGE, applied=(),
            report=replace(plan_obj.report, result=FAILED_BEFORE_CHANGE),
        )

    # ── the re-read, before anything is created ────────────────────────────────
    try:
        current = capture_before_image(adapter, inputs, compartment)
    except ff.FmsFolderError as exc:
        return CompartmentResult(
            state=CompartmentState.API_REQUIRED_UNAVAILABLE, result=FAILED_BEFORE_CHANGE,
            applied=(), report=preflight_report(inputs, str(exc)),
        )

    divergence = _images_agree(plan_obj.before, current) or _local_state_agrees(
        plan_obj.report, compartment, flavour=inputs.flavour)
    if divergence:
        state = (CompartmentState.CONVERSION_REQUIRED if current.legacy
                 else CompartmentState.READBACK_MISMATCH)
        return CompartmentResult(
            state=state, result=FAILED_BEFORE_CHANGE, applied=(),
            report=CompartmentReport(
                state=state, result=FAILED_BEFORE_CHANGE, slots=current.slots,
                findings=(Finding(state.value, divergence),), before=current,
                next_action="Re-run patch-compartment inspect; nothing was created or changed.",
                handoff=_handoff(compartment, None, current, reachable=True),
            ),
        )

    if current.legacy:
        return CompartmentResult(
            state=CompartmentState.CONVERSION_REQUIRED, result=FAILED_BEFORE_CHANGE, applied=(),
            report=CompartmentReport(
                state=CompartmentState.CONVERSION_REQUIRED, result=FAILED_BEFORE_CHANGE,
                slots=current.slots, before=current,
                findings=tuple(_conversion_finding(f, inputs) for f in current.legacy),
                next_action=_next_action(CompartmentState.CONVERSION_REQUIRED, None),
                handoff=_handoff(compartment, None, current, reachable=True),
            ),
        )

    slot, _exact = choose_slot(current.slots, compartment, flavour=inputs.flavour)
    if slot is None:
        return CompartmentResult(
            state=CompartmentState.ALL_SLOTS_OCCUPIED, result=FAILED_BEFORE_CHANGE, applied=(),
            report=CompartmentReport(
                state=CompartmentState.ALL_SLOTS_OCCUPIED, result=FAILED_BEFORE_CHANGE,
                slots=current.slots, before=current,
                findings=(Finding(CompartmentState.ALL_SLOTS_OCCUPIED.value,
                                  "both slots hold other paths; none is displaced"),),
                next_action=_next_action(CompartmentState.ALL_SLOTS_OCCUPIED, None),
                handoff=_handoff(compartment, None, current, reachable=True),
            ),
        )

    permissions = capture_permissions(compartment, flavour=inputs.flavour)
    sandbox_before = capture_sandbox(compartment) if compartment.is_dir() else SandboxSnapshot(
        path=compartment / SANDBOX_FILE, existed=False)

    # An unrelated file already sitting where this operation's backup would go. Refused BEFORE the
    # first mutation and left byte-identical: the copy below uses no-replace semantics, so the run
    # would fail there anyway — but it would fail with the directory created and the slot patched,
    # which is a mutation performed on the way to a refusal that was knowable up front.
    if sandbox_before.existed:
        candidate = backup_path_for(compartment / SANDBOX_FILE, operation_id)
        if candidate.exists() or candidate.is_symlink():
            return CompartmentResult(
                state=CompartmentState.SANDBOX_CONFLICT, result=FAILED_BEFORE_CHANGE, applied=(),
                report=CompartmentReport(
                    state=CompartmentState.SANDBOX_CONFLICT, result=FAILED_BEFORE_CHANGE,
                    slots=current.slots, before=current,
                    findings=(Finding(
                        CompartmentState.SANDBOX_CONFLICT.value,
                        f"{candidate} already exists; this operation will not overwrite it to make "
                        "room for its own backup"),),
                    next_action=("Remove or move the file at the reported path, then re-run. "
                                 "Nothing was created or changed."),
                    permissions=permissions, sandbox=sandbox_before,
                    handoff=_handoff(compartment, slot, current, reachable=True),
                ),
            )

    # NOTHING NEEDED TO CHANGE. Checked before any mutation is planned, because the alternative is
    # re-chowning, re-PATCHing and re-seeding an already-correct compartment purely so `apply` can
    # say `completed` — which is a durable write performed to produce a word.
    settled = _already_settled(
        current, compartment, permissions, sandbox_before, inputs,
        adapter=adapter, acl_api=acl_api, probe=probe)
    if settled is not None:
        return settled

    # Decided HERE, before the first mutation. Discovering it at seed time meant the directory was
    # created and the slot patched first, and the rollback then wrote a slot clear to a live FMS.
    if sandbox_before.existed and decision is not SandboxDecision.REPLACE_EXACT_NAME:
        return CompartmentResult(
            state=CompartmentState.SANDBOX_CONFLICT, result=FAILED_BEFORE_CHANGE, applied=(),
            report=CompartmentReport(
                state=CompartmentState.SANDBOX_CONFLICT, result=FAILED_BEFORE_CHANGE,
                slots=current.slots, before=current,
                findings=(Finding(
                    CompartmentState.SANDBOX_CONFLICT.value,
                    (f"{sandbox_before.path} already exists and no installation record vouches for "
                     "it; an explicit overwrite decision is required"),
                ),),
                next_action=("Confirm the existing sandbox may be replaced, then re-run apply with "
                             "that decision. Nothing was created or changed."),
                permissions=permissions, sandbox=sandbox_before,
                handoff=_handoff(compartment, slot, current, reachable=True),
            ),
        )

    # `created_dirs` is computed and ATTACHED BEFORE `mkdir(parents=True)` runs. Recording it after
    # the call means a partial mkdir that then raises leaves a tree on disk that the record does not
    # know about, and rollback removes only the leaf it can guess at.
    planned_dirs: list[Path] = []
    if not compartment.exists():
        planned_dirs = [a for a in reversed(compartment.parents) if not a.exists()]
        planned_dirs.append(compartment)

    rollback = RollbackRecord(
        before=current, permissions=permissions, sandbox=sandbox_before, slot_touched=None,
        directory_created_by_this_run=bool(planned_dirs),
        compartment_path=compartment, flavour=inputs.flavour,
        created_dirs=tuple(planned_dirs),
        operation_id=operation_id, installation_id=installation_id, mode=mode,
    )

    def _persist(record: RollbackRecord) -> None:
        """Recovery authority is durable BEFORE the mutation it covers, never after."""
        if layout is not None:
            write_recovery(layout, record, lock=lock)

    applied: list[PlannedChange] = []
    findings: list[Finding] = []

    def _fail(state: CompartmentState, detail: str, *, mutated: bool) -> CompartmentResult:
        findings.append(Finding(state.value, detail))
        restored = False
        manual = False
        if mutated:
            try:
                rollback_result = rollback_changes(rollback, adapter=adapter)
                restored = rollback_result.result == ROLLED_BACK
                # `rollback_changes` catches its OWN failures and returns the word; reading only the
                # raise left a failed restore reported as `incomplete_safe` while the FMS slot was
                # still registered to a directory the same rollback had deleted.
                manual = rollback_result.result == MANUAL_ACTION_REQUIRED
            except Exception:                       # pragma: no cover - defensive
                manual = True
        word = classify_failure(mutated=mutated, restored=restored, manual_action=manual)
        return CompartmentResult(
            state=state, result=word, applied=tuple(applied),
            report=CompartmentReport(
                state=state, result=word, slots=current.slots, findings=tuple(findings),
                next_action=_next_action(state, slot), permissions=permissions,
                sandbox=sandbox_before, before=current,
                handoff=_handoff(compartment, slot, current, reachable=True),
            ),
            rollback=rollback,
        )

    # 1. create — the record covering it is already durable.
    _persist(rollback)
    try:
        compartment.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _fail(CompartmentState.PERMISSIONS_INCOMPLETE,
                     f"could not create the compartment: {type(exc).__name__}",
                     mutated=any(d.exists() for d in planned_dirs))
    if planned_dirs:
        applied.append(PlannedChange("create_dir", str(compartment), "created"))
    mutated = bool(planned_dirs)

    # 2. permissions
    applier = apply_permissions if apply_permissions is not None else apply_compartment_permissions
    try:
        applier(compartment, inputs)
    except Exception as exc:
        return _fail(CompartmentState.PERMISSIONS_INCOMPLETE,
                     f"could not apply compartment permissions: {type(exc).__name__}",
                     mutated=mutated)
    applied.append(PlannedChange("apply_permissions", str(compartment), "applied"))

    access = prove_effective_access(compartment, inputs, acl_api=acl_api, probe=probe)
    if access:
        findings.extend(access)
        return _fail(CompartmentState.PERMISSIONS_INCOMPLETE,
                     "the compartment does not grant both identities effective access",
                     mutated=mutated)

    # 3. PATCH + 4. exact readback. An identical, already-enabled registration is NOT re-sent:
    # re-PATCHing the same value is a write against a live server that changes nothing, and it made
    # `no_change` — a word the result vocabulary defines — unreachable.
    existing = next((s for s in current.slots if s.index == slot), None)
    already_correct = bool(
        existing is not None and existing.enabled
        and ff.paths_equal(existing.local_path, compartment, flavour=inputs.flavour)
        # FMS can retain the configured path while marking the folder invalid at Database Server
        # startup because the directory did not yet exist.  In that state the config read-back is
        # exact but the engine has no active hosting folder.  Reassert the same slot after creating
        # the directory so FMS validates and scans it; only a directory that existed in the
        # before-image may use the no-PATCH optimization.  A fully working compartment returned
        # from `_already_settled` before reaching this mutation path.
        and permissions.existed
    )
    if not already_correct:
        rollback = replace(rollback, slot_touched=slot)
        _persist(rollback)                     # durable BEFORE the FMS mutation it covers
        try:
            fms_path = ff.fms_path_for(compartment, flavour=inputs.flavour)
            adapter.patch_additional_db_folder(ff.slot_patch_body(slot, fms_path=fms_path))
        except (ff.FmsFolderError, LifecycleError) as exc:
            return _fail(CompartmentState.READBACK_MISMATCH,
                         f"the Additional Database Folder PATCH failed: {exc}", mutated=mutated)
        applied.append(PlannedChange("patch_slot", slot, "registered"))
        mutated = True

    try:
        after_paths, after_settings = ff.capture_folder_state(adapter)   # ONE call per resource
        after_slots = ff.parse_slots(after_paths, after_settings, flavour=inputs.flavour)
        after_rc = ff.read_rc_fields(after_settings)
    except ff.FmsFolderError as exc:
        return _fail(CompartmentState.READBACK_MISMATCH,
                     f"could not read the slot back: {exc}", mutated=True)

    record = next((s for s in after_slots if s.index == slot), None)
    registered = bool(
        record is not None and record.enabled
        and ff.paths_equal(record.local_path, compartment, flavour=inputs.flavour)
    )
    if not registered:
        return _fail(CompartmentState.READBACK_MISMATCH,
                     "the slot did not read back as this compartment, enabled", mutated=True)

    if after_rc != current.rc_fields:
        return _fail(CompartmentState.RC_FIELDS_CHANGED,
                     "a remote-container field changed across the PATCH; none was sent",
                     mutated=True)

    # 5. seed the sandbox
    target = compartment / SANDBOX_FILE
    seed = Path(inputs.seed)
    if not seed.is_file():
        return _fail(CompartmentState.SANDBOX_SEED_FAILED,
                     f"the versioned seed {seed} is not present", mutated=True)
    # The backup PATH is chosen and published BEFORE the copy that creates it. The reverse order
    # left a window where a crash produced a stray `.pre-seed` no record named. `rollback_changes`
    # therefore has to tolerate a recorded backup that does not exist yet — see its own comment.
    #
    # The name is OPERATION-SPECIFIC. A fixed `.pre-seed` would be a shared, predictable path: a
    # second run, or anything else that had left a file there, would be silently overwritten by the
    # copy below — destroying content while claiming to preserve it.
    if sandbox_before.existed:
        rollback = replace(
            rollback,
            sandbox=replace(sandbox_before, backup=backup_path_for(target, operation_id)))
    _persist(rollback)                         # durable BEFORE anything touches the sandbox
    try:
        if sandbox_before.existed:
            _write_verified_backup(target, rollback.sandbox.backup, sandbox_before.digest)
        shutil.copy2(seed, target)
        # An injected directory-permission seam stands in for the whole POSIX identity boundary in
        # platform-neutral tests.  Production always takes the concrete file authority below.
        if apply_permissions is None:
            apply_sandbox_permissions(target, inputs)
    except (OSError, KeyError, BackupNotDurable) as exc:
        return _fail(CompartmentState.SANDBOX_SEED_FAILED,
                     f"could not place the sandbox seed: {type(exc).__name__}", mutated=True)
    applied.append(PlannedChange("seed_sandbox", str(target), "seeded"))

    # 6. open -> observe OPEN -> close -> observe CLOSED
    proof = prove_sandbox(adapter)
    if proof is not None:
        return _fail(proof[0], proof[1], mutated=True)
    applied.append(PlannedChange("open_close_probe", SANDBOX_NAME, "observed OPEN then CLOSED"))

    # The `.pre-seed` backup is deliberately NOT deleted here. Apply returns before the journal is
    # resolved, and a crash in that window would leave an UNRESOLVED journal with the backup already
    # gone — recovery owed, and the only thing that could satisfy it destroyed. Retirement is
    # `clear_recovery`'s, which runs only after the journal resolves.

    report = CompartmentReport(
        state=CompartmentState.VERIFIED_READY, result=COMPLETED, slots=after_slots,
        findings=(), next_action=_next_action(CompartmentState.VERIFIED_READY, slot),
        permissions=capture_permissions(compartment, flavour=inputs.flavour),
        sandbox=capture_sandbox(compartment), before=current,
        handoff=_handoff(compartment, slot, current, reachable=True),
    )
    return CompartmentResult(
        state=CompartmentState.VERIFIED_READY, result=COMPLETED, applied=tuple(applied),
        report=report, rollback=rollback,
    )


def _already_settled(
    current: FmsFolderBeforeImage, compartment: Path, permissions: PermissionSnapshot,
    sandbox: SandboxSnapshot, inputs: CompartmentInputs, *, adapter, acl_api, probe,
) -> CompartmentResult | None:
    """`no_change` when the revalidated state ALREADY satisfies the whole contract.

    Every condition is re-read here, not assumed from the plan: the directory exists with both
    identities' effective access, the slot names this compartment and is enabled, the sandbox is
    present, and the sandbox still opens and closes. One field different and this returns None, so
    the ordinary transaction runs.
    """
    if not permissions.existed or not sandbox.existed:
        return None
    slot, exact = choose_slot(current.slots, compartment, flavour=inputs.flavour)
    if slot is None or not exact:
        return None
    record = next((s for s in current.slots if s.index == slot), None)
    if record is None or not record.enabled:
        return None
    if prove_effective_access(compartment, inputs, acl_api=acl_api, probe=probe):
        return None
    if prove_sandbox(adapter) is not None:
        return None

    report = CompartmentReport(
        state=CompartmentState.VERIFIED_READY, result=NO_CHANGE, slots=current.slots,
        next_action=_next_action(CompartmentState.VERIFIED_READY, slot),
        permissions=permissions, sandbox=sandbox, before=current,
        handoff=_handoff(compartment, slot, current, reachable=True),
    )
    return CompartmentResult(
        state=CompartmentState.VERIFIED_READY, result=NO_CHANGE, applied=(), report=report,
    )


def prove_sandbox(adapter: ff.FmsFolderAdapter) -> tuple[CompartmentState, str] | None:
    """Open, observe OPEN, close, observe CLOSED. Between runs the sandbox is left CLOSED."""
    runtime_status = None
    try:
        wanted = ff.database_stem(SANDBOX_NAME)
        runtime_status = next(
            (
                str(row.get("status") or "").strip().upper()
                for row in adapter.list_databases()
                if ff.database_stem(str(row.get("filename") or "")) == wanted
            ),
            None,
        )
    except (ff.FmsFolderError, LifecycleError):
        # The open operation below remains authoritative when the preliminary observation is
        # unavailable.  It will either establish OPEN or return the ordinary named refusal.
        runtime_status = None

    open_observed = runtime_status in {"NORMAL", "OPEN", "OPENED"}
    if not open_observed:
        try:
            adapter.open_database(SANDBOX_NAME)
        except (ff.FmsFolderError, LifecycleError) as exc:
            # FileMaker can auto-open a registered database between observation and PATCH.  Accept
            # that race only when a fresh observation positively proves the requested state.
            try:
                open_observed = adapter.await_status(SANDBOX_NAME, "OPEN")
            except (ff.FmsFolderError, LifecycleError):
                open_observed = False
            if not open_observed:
                return (CompartmentState.SANDBOX_NOT_OBSERVED_OPEN,
                        f"the sandbox would not open: {exc}")
    if not open_observed and not adapter.await_status(SANDBOX_NAME, "OPEN"):
        try:
            adapter.close_database(SANDBOX_NAME)
        except Exception:                           # pragma: no cover - defensive
            pass
        return (CompartmentState.SANDBOX_NOT_OBSERVED_OPEN,
                "the sandbox never reached OPEN within the wait")
    try:
        adapter.close_database(SANDBOX_NAME)
    except (ff.FmsFolderError, LifecycleError) as exc:
        return CompartmentState.SANDBOX_NOT_OBSERVED_CLOSED, f"the sandbox would not close: {exc}"
    if not adapter.await_status(SANDBOX_NAME, "CLOSED"):
        return (CompartmentState.SANDBOX_NOT_OBSERVED_CLOSED,
                "the sandbox never reached CLOSED within the wait")
    return None


def verify(
    inputs: CompartmentInputs, *, adapter: ff.FmsFolderAdapter, acl_api=None,
    probe: Callable | None = None,
) -> CompartmentReport:
    """The seven proofs, without mutating. `verified` is true only when all seven hold."""
    compartment, path_findings = validate_path(inputs)
    if path_findings or compartment is None:
        return CompartmentReport(
            state=CompartmentState.PATH_REFUSED, result=NO_CHANGE, findings=path_findings,
            next_action="Choose a compartment path outside every protected tree.",
        )
    try:
        before = capture_before_image(adapter, inputs, compartment)
    except ff.FmsFolderError as exc:
        return preflight_report(inputs, str(exc))

    findings: list[Finding] = []
    states: set[CompartmentState] = set()

    for fact in before.legacy:
        states.add(CompartmentState.CONVERSION_REQUIRED)
        findings.append(_conversion_finding(fact, inputs))

    slot, exact = choose_slot(before.slots, compartment, flavour=inputs.flavour)
    record = next((s for s in before.slots if s.index == slot), None) if slot else None
    if not exact or record is None:
        states.add(CompartmentState.READBACK_MISMATCH)
        findings.append(Finding(CompartmentState.READBACK_MISMATCH.value,
                                "no slot names this compartment"))
    elif not record.enabled:
        states.add(CompartmentState.REGISTERED_NOT_ENABLED)
        findings.append(Finding(CompartmentState.REGISTERED_NOT_ENABLED.value,
                                f"slot {slot} names this compartment but is not enabled"))

    access = prove_effective_access(compartment, inputs, acl_api=acl_api, probe=probe)
    if access:
        states.add(CompartmentState.PERMISSIONS_INCOMPLETE)
        findings.extend(access)

    sandbox = capture_sandbox(compartment)
    if not sandbox.existed:
        states.add(CompartmentState.SANDBOX_SEED_FAILED)
        findings.append(Finding(CompartmentState.SANDBOX_SEED_FAILED.value,
                                f"{sandbox.path} is not present"))
    else:
        proof = prove_sandbox(adapter)
        if proof is not None:
            states.add(proof[0])
            findings.append(Finding(proof[0].value, proof[1]))

    state = _lowest(states) if states else CompartmentState.VERIFIED_READY
    return CompartmentReport(
        state=state, result=NO_CHANGE, slots=before.slots, findings=tuple(findings),
        next_action=_next_action(state, slot),
        permissions=capture_permissions(compartment, flavour=inputs.flavour),
        sandbox=sandbox, before=before,
        handoff=_handoff(compartment, slot, before, reachable=True),
    )


def _remove_created_dirs(created: tuple, undone: list) -> list[str]:
    """Remove what this run created, deepest-first, and READ BACK that every one is gone.

    A directory that is not empty, a path something has replaced with a file or a symlink, and a
    removal that simply failed are three different residues — and all three used to be indexed under
    "rolled_back" because nothing looked afterwards. Each is left untouched and named exactly.
    """
    problems: list[str] = []
    for made in tuple(created)[::-1]:
        try:
            if not made.exists() and not made.is_symlink():
                continue
            if made.is_symlink():
                problems.append(f"{made} is a symlink, not the directory this run created; "
                                "left untouched")
                continue
            if not made.is_dir():
                problems.append(f"{made} has been replaced by a file; left untouched")
                continue
            remaining = list(made.iterdir())
            if remaining:
                problems.append(
                    f"{made} is not empty ({len(remaining)} entr"
                    f"{'y' if len(remaining) == 1 else 'ies'}, first: {remaining[0].name}); "
                    "left untouched")
                continue
            made.rmdir()
            undone.append(PlannedChange("create_dir", str(made), "removed"))
        except OSError as exc:
            problems.append(f"{made} could not be removed ({type(exc).__name__}); left untouched")

    # READ BACK: every entry must really be gone, or this is not a rollback.
    for made in created:
        if made.exists() or made.is_symlink():
            if not any(str(made) in p for p in problems):
                problems.append(f"{made} is still present after removal")
    return problems


def _restore_permissions(directory: Path, snap: PermissionSnapshot, undone: list) -> list[str]:
    """Restore owner/group/mode (POSIX) or the SDDL (Windows) and READ IT BACK.

    Windows is restored only when THIS operation changed it — a captured SDDL with nothing to undo
    is evidence, not an instruction — and a mismatch is `manual_action_required`, never success.
    """
    problems: list[str] = []
    if not snap.existed or not directory.exists():
        return problems

    if snap.flavour == WINDOWS:                     # pragma: no cover - platform-specific
        if snap.windows_sddl is None:
            return problems
        from .protection import security_descriptor_of

        current = security_descriptor_of(directory)
        if current == snap.windows_sddl:
            return problems                          # this operation did not change it
        problems.append(
            f"{directory} carries a security descriptor this operation changed and this box cannot "
            "restore; a human must reapply the captured descriptor")
        return problems

    if snap.posix_mode is None:
        return problems
    _restore_posix_ownership(directory, snap)
    directory.chmod(snap.posix_mode)
    undone.append(PlannedChange("apply_permissions", str(directory), "restored"))

    now = capture_permissions(directory, flavour=snap.flavour)
    if now.posix_mode != snap.posix_mode:
        problems.append(
            f"{directory} reads back as mode {now.posix_mode:o}, not the captured "
            f"{snap.posix_mode:o}")
    if snap.posix_owner is not None and now.posix_owner != snap.posix_owner:
        problems.append(
            f"{directory} reads back owned by {now.posix_owner}, not the captured "
            f"{snap.posix_owner}")
    if snap.posix_group is not None and now.posix_group != snap.posix_group:
        problems.append(
            f"{directory} reads back in group {now.posix_group}, not the captured "
            f"{snap.posix_group}")
    return problems


def _restore_sandbox(snap: SandboxSnapshot, undone: list) -> list[str]:
    """Restore the sandbox and VERIFY it, deciding by digest rather than by file presence.

    A missing backup is ambiguous on its own: the copy may never have happened, or the replacement
    may have completed and the backup been retired. The captured digest is what tells them apart —
    and getting that wrong means reporting `rolled_back` over a compartment still holding the seed.
    """
    problems: list[str] = []

    if not snap.existed:
        if snap.path.exists():
            snap.path.unlink()
            undone.append(PlannedChange("seed_sandbox", str(snap.path), "removed"))
        if snap.path.exists():                       # readback: it must really be gone
            problems.append(f"{snap.path} is still present after removal")
        return problems

    target_is_original = (
        snap.digest is not None and snap.path.exists()
        and file_digest(snap.path) == snap.digest)

    if snap.backup is not None and snap.backup.exists():
        # THE BACKUP IS NOT TRUSTED BECAUSE IT EXISTS. A crash mid-copy leaves a file holding a
        # prefix of the original, and restoring from that would replace a recoverable sandbox with
        # a truncated one — turning a survivable interruption into permanent loss.
        held = file_digest(snap.backup)
        if snap.digest is not None and held != snap.digest:
            if target_is_original:
                # The copy never got far enough to replace anything, and the target is still what
                # was captured. Retire the partial residue; the sandbox needs nothing.
                try:
                    snap.backup.unlink()
                except OSError as exc:
                    problems.append(
                        f"{snap.backup} is an incomplete backup that could not be removed "
                        f"({type(exc).__name__}); it is not a restore point and must not be used")
                    return problems
                undone.append(PlannedChange(
                    "seed_sandbox", str(snap.path),
                    "left as found — the backup was incomplete and the original is intact, so the "
                    "partial copy was retired"))
                return problems
            problems.append(
                f"{snap.backup} is an incomplete copy of the original and {snap.path} is not what "
                "was captured; the original content cannot be restored from this box, and the "
                "partial backup was left in place rather than written over the sandbox")
            return problems

        shutil.copy2(snap.backup, snap.path)
        undone.append(PlannedChange("seed_sandbox", str(snap.path), "restored"))
    elif target_is_original:
        # No backup, and the sandbox still holds its ORIGINAL content: the replacement never
        # happened. Nothing to restore, and that is a fact rather than an assumption.
        undone.append(PlannedChange(
            "seed_sandbox", str(snap.path),
            "left as found — the original content is intact, so no replacement occurred"))
        return problems
    else:
        # No backup and the content is NOT the original: the replacement DID happen and the only
        # copy of what was there is gone. Never call that rolled back.
        problems.append(
            f"{snap.path} was replaced and no backup survives; its original content cannot be "
            "restored from this box")
        return problems

    if snap.digest is not None:
        restored = file_digest(snap.path) if snap.path.exists() else None
        if restored != snap.digest:
            problems.append(
                f"{snap.path} does not match its captured content after restoration")
    return problems


def _restore_posix_ownership(directory: Path, snap: PermissionSnapshot) -> None:
    """Owner and group, not mode alone — restoring 2775 onto a directory this run also chowned would
    leave it owned by the service account with the captured mode, which is not the captured state."""
    if snap.posix_owner is None or snap.posix_group is None:
        return
    import grp
    import pwd

    def _uid(value: str) -> int:
        return int(value) if value.isdigit() else pwd.getpwnam(value).pw_uid

    def _gid(value: str) -> int:
        return int(value) if value.isdigit() else grp.getgrnam(value).gr_gid

    os.chown(directory, _uid(snap.posix_owner), _gid(snap.posix_group))


def rollback_changes(
    record: RollbackRecord, *, adapter: ff.FmsFolderAdapter
) -> CompartmentResult:
    """Restore from the before-image per the packet's restoration table, then verify."""
    undone: list[PlannedChange] = []
    problems: list[str] = []

    if record.slot_touched is not None:
        original = next((s for s in record.before.slots if s.index == record.slot_touched), None)
        if original is not None:
            try:
                adapter.patch_additional_db_folder(
                    ff.slot_restore_body(record.slot_touched, original))
                undone.append(PlannedChange("patch_slot", record.slot_touched, "restored"))
            except (ff.FmsFolderError, LifecycleError) as exc:
                problems.append(f"could not restore slot {record.slot_touched}: {exc}")

    sandbox = record.sandbox
    if sandbox is not None:
        try:
            problems.extend(_restore_sandbox(sandbox, undone))
        except OSError as exc:
            problems.append(f"could not restore the sandbox: {type(exc).__name__}")

    compartment = record.compartment_path
    # Never remove a directory while the slot restore is unresolved: FMS would be left registered to
    # a path that no longer exists, which is worse than the half-applied state being undone.
    if problems:
        pass
    elif compartment is not None and record.directory_created_by_this_run:
        problems.extend(_remove_created_dirs(record.created_dirs or (compartment,), undone))
    elif compartment is not None and record.permissions is not None and record.permissions.existed:
        snap = record.permissions
        try:
            problems.extend(_restore_permissions(compartment, snap, undone))
        except OSError as exc:
            problems.append(f"could not restore compartment permissions: {type(exc).__name__}")

    # READ BACK. Every restoration above is verified against what was captured — a restore that
    # reports success without reading anything back is the defect this whole component exists to
    # avoid one layer up.
    if record.slot_touched is not None:
        try:
            after = ff.read_slots(adapter, flavour=record.flavour)
            original = next((s for s in record.before.slots if s.index == record.slot_touched), None)
            now = next((s for s in after if s.index == record.slot_touched), None)
            if original is None or now is None:
                problems.append("the restored slot could not be read back")
            elif now.enabled != original.enabled:
                problems.append(
                    f"slot {record.slot_touched} reads back "
                    f"{'enabled' if now.enabled else 'disabled'}, not as captured")
            elif original.fms_path and now.fms_path != original.fms_path:
                problems.append("the restored slot does not name its captured path")
            elif not original.fms_path and now.fms_path:
                # The slot was captured FREE and is now DISABLED with a stale path still stored.
                # The API documents no clear operation — `UseOtherDatabaseRoot: false` IS how it
                # expresses "not in use" — so this is fully restored in the only terms the server
                # offers, and calling it a failure would make rollback useless for the commonest
                # case (a run that took a free slot). Recorded, not silently equated.
                undone.append(PlannedChange(
                    "patch_slot", record.slot_touched,
                    "disabled — the API has no operation to clear a stored path, and a disabled "
                    "slot is how it expresses 'not in use'"))
        except ff.FmsFolderError as exc:
            problems.append(f"could not verify the restored slot: {exc}")

    word = ROLLED_BACK if not problems else MANUAL_ACTION_REQUIRED
    state = (CompartmentState.FREE_SLOT_AVAILABLE if not problems
             else CompartmentState.PERMISSIONS_INCOMPLETE)
    return CompartmentResult(
        state=state, result=word, applied=tuple(undone),
        report=CompartmentReport(
            state=state, result=word,
            findings=tuple(Finding("rollback_incomplete", p) for p in problems),
            next_action=("The compartment was restored to its captured state." if not problems
                         else "Restoration is incomplete; a human must reconcile the reported item."),
            before=record.before,
        ),
    )


#: The name FileMaker Server gives a database's container-data companion. Recognising the shape is
#: how a candidate path is FOUND; it is never how one is CLAIMED — see `attribute_sandbox_rc`.
RC_SUFFIX = "_Data_FMS"
SANDBOX_RC_NAME = f"{SANDBOX_NAME}{RC_SUFFIX}"


def compartment_inventory(compartment: Path) -> frozenset:
    """The compartment's immediate entry names, as observed. Read-only.

    Taken BEFORE the sandbox is placed and again after the open/close proof. The difference is the
    only evidence that ties an `RC_Data_FMS` folder to *this* sandbox: nothing about the folder
    itself distinguishes ours from one that was already there.
    """
    try:
        return frozenset(child.name for child in compartment.iterdir())
    except OSError:
        return frozenset()


def attribute_sandbox_rc(*, compartment: Path, before: frozenset, after: frozenset,
                         reported: str | None = None) -> tuple:
    """At most one ownership entry for the sandbox's RC path — or none, and a reason (§O7).

    **Attribution, not recognition.** A folder named `CORPUSfm_Sandbox_Data_FMS` sitting in the
    compartment proves nothing: it may predate this installation, or belong to a compartment an
    administrator reused. So an entry is minted only when the path is

    * **newly created** — absent from the before-inventory and present in the after-inventory — or
      **unambiguously reported** by the operation that placed it; and
    * **canonically contained** inside the recorded compartment.

    Anything else yields `((), reason)`. Returning the reason rather than an empty tuple alone is
    deliberate: a caller must be able to *report the limitation*, which is what the ruling requires,
    and a silent empty result cannot be distinguished from "there was nothing there".
    """
    root = compartment.resolve()
    if reported:
        candidate = Path(reported)
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        # STRICTLY inside. `relative_to` succeeds when the two are equal, so a caller reporting the
        # compartment itself would have minted an ownership entry for the whole hosting directory —
        # which is the opposite of a contained companion path.
        if candidate == root:
            return (), (f"the reported RC path is the compartment itself ({root}); an RC entry names "
                        "a path INSIDE the compartment, never the compartment")
        try:
            candidate.relative_to(root)
        except ValueError:
            return (), (f"the reported RC path {reported!r} is not inside the recorded compartment "
                        f"{root}; a path outside the compartment is never adopted")
        return (_rc_entry(candidate),), ""

    appeared = sorted(after - before)
    rc = [name for name in appeared if name.endswith(RC_SUFFIX)]
    if not rc:
        present = sorted(n for n in after if n.endswith(RC_SUFFIX))
        if present:
            return (), (f"an RC path was already present before this sandbox "
                        f"({', '.join(present)}); a pre-existing path is never adopted")
        return (), "no RC path was created for this sandbox; there is nothing to record"
    if len(rc) > 1:
        return (), (f"more than one RC path appeared ({', '.join(rc)}); attribution is ambiguous "
                    "and no entry is recorded")
    return (_rc_entry(root / rc[0]),), ""


def _rc_entry(path: Path) -> dict:
    """Shared/conditional: the compartment is a place the administrator can also put things."""
    return {"ownership_class": "shared_conditional", "kind": "patch_sandbox_rc_path",
            "identifier": str(path)}


def candidate_facts(
    report: CompartmentReport, *, compartment: Path, slot: str, generation: int,
    installation_id: str, sandbox_rc_ownership: tuple = (),
) -> CandidateFacts:
    """The RETURN value. This child performs no manifest write.

    `inspected_generation` and `inspected_installation_id` exist so 1246-04's single composed write
    can fail closed on a generation that moved underneath it and on an identity that does not agree.
    """
    if report.state is not CompartmentState.VERIFIED_READY:
        raise CompartmentRefused(
            f"candidate facts are only produced from a verified compartment, not {report.state.value}"
        )
    return CandidateFacts(
        patch=PatchBlock(
            folder_slot=slot, registered=True, verified=True,
            sandbox_file=str(compartment / SANDBOX_FILE),
        ),
        patch_hosting_dir=compartment,
        inspected_generation=generation,
        inspected_installation_id=installation_id,
        ownership=tuple(sandbox_rc_ownership),
    )


def new_operation_id() -> str:
    return str(uuid.uuid4())
