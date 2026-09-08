"""The pending-uninstall record — stable from its first write (packet 1246-09, stage 3).

**It never moves.** An earlier design wrote it inside the installation and relocated it before the
application tree could disappear; that created a window in which the old copy was gone and the new
one was not yet durable, and the answer was to design the window out rather than to build recovery
around it. So the record is written to the **fixed stable config/locator authority** at its first
write and stays there until cleanup completes: `/etc/corpusfm` on POSIX, the protected fixed config
namespace bound to the HKLM locator identity on Windows.

**This module writes and reads one file. It deletes nothing.** `discard()` exists as the interface
stage 5 will call and deliberately raises — the executor stages do not exist yet, and a module that
could already remove the last resume authority would be the RC4 this packet exists to prevent.

The durability chain is the whole value of the record, so it is not optional anywhere:

    sibling create → write in full → fsync(file) → replace → fsync(directory) → read back → digest

A record that cannot be read back exactly is treated as never written.

**What the read-back does NOT do.** It is not concurrency control. It compares the bytes that landed
against the bytes intended, at the moment it reads them — so writer B replacing the record after
writer A's read-back succeeded, but before A returns, is invisible to it, and A reports success over
B's content. **Serialization comes from the lifecycle lock, which both mutators require**; the
read-back catches a torn or corrupted write, not a competing one.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path

from .atomic import _fsync_dir
from .errors import LifecycleError, RecordInvalid
from .lock import LockNotHeld, require_lock
from .schema import canonical_path, utc_now_iso
from .service_identity import MANAGED_ROLES, UNIT_KINDS

PENDING_FILENAME = "uninstall-pending.json"
#: **Version 2 replaces version 1 outright — there is no v1 reader.** No shipped code path ever
#: called `publish`, so no record was ever written to any box; a compatibility reader would exist
#: solely to parse documents that do not exist. A v1 document produces a NAMED refusal instead.
#:
#: **The number stays 2 while v2's own shape changes, and the reason is the same measured fact.**
#: `PkiOperation` gained `secrets_dir` and `flavour` (F3), and `StorageOperation` has now gained
#: `fms_root` (stage 5 ruling 1) — each would ordinarily be a version bump. A bump exists to tell a
#: reader which of two shapes a document on a box actually has, and there is no such document:
#: `publish` still has no caller outside the tests, and no v2 record has ever been written
#: operationally either. Versioning against an empty population buys nothing and costs a
#: compatibility branch nobody can exercise.
#:
#: Version 3 adds the exact empty directory scaffolding a patch-slot operation may retire before it
#: disables that slot. Version 4 orders every PKI-authenticated FileMaker operation before PKI
#: deregistration and keeps their shared identity store until all have completed. Versions 2 and 3
#: remain readable below; v2 maps scaffolding to an empty set and keeps its conservative behavior.
PENDING_SCHEMA_VERSION = 4
PENDING_SCHEMA_UNSUPPORTED = "pending_schema_unsupported"
PENDING_FILE_MODE = 0o600

# ── typed remaining OPERATIONS (packet 1246-09 §Y) ────────────────────────────────────────────
#
# **Version 1 held `(resource, kind, identifier, authority)` — one string — for all twenty-one
# operations, and that was the defect §X reproduced seven times.** A service removal needs five
# facts; a storage removal needs a proof that something else happened first; a proxy removal needs a
# fingerprint to compare. Everything an operation actually needed therefore arrived from the CALLER,
# and a caller that supplies target authority could supply any target.
#
# So a pending record now holds typed OPERATIONS. Each variant carries exactly the durable facts its
# execution and its re-check require, and **collections stay collections**: a database has however
# many RC paths it has, an installation has however many privilege helpers it wrote, and a box has
# however many proxy fronts it edited. Collapsing any of those into one identifier is how the v1
# shape lost information it could never recover.

OP_EXACT_PATH = "exact_path"
OP_MANAGED_UNIT = "managed_unit"
OP_STORAGE = "storage"
OP_PROXY = "proxy"
OP_PKI = "pki"
OP_PATCH_SLOT = "patch_slot"
OP_ACCOUNT = "account"
OPERATION_TAGS: tuple = (OP_EXACT_PATH, OP_MANAGED_UNIT, OP_STORAGE, OP_PROXY, OP_PKI,
                         OP_PATCH_SLOT, OP_ACCOUNT)

#: What an `exact_path` operation does to its target.
PATH_ACTION_REMOVE_FILE = "remove_file"
PATH_ACTION_REMOVE_TREE = "remove_tree"
PATH_ACTION_CLEAN_TREE = "clean_tree"
PATH_ACTION_REMOVE_EMPTY_DIR = "remove_empty_dir"
PATH_ACTIONS: tuple = (PATH_ACTION_REMOVE_FILE, PATH_ACTION_REMOVE_TREE, PATH_ACTION_CLEAN_TREE,
                       PATH_ACTION_REMOVE_EMPTY_DIR)

#: The platform a recorded path belongs to, so absoluteness is judged under the right rules.
FLAVOURS: tuple = ("posix", "windows")

class PendingRecordRefused(LifecycleError):
    """A pending record that must not be adopted, acted on, or overwritten."""




# ── the seven variants ────────────────────────────────────────────────────────


def _text(raw: dict, key: str, what: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise RecordInvalid(f"{what} needs a non-empty {key}")
    return value


def _abs_path(raw: dict, key: str, *, flavour: str, what: str) -> str:
    """Canonical and ABSOLUTE under the recorded platform's rules.

    A POSIX-absolute path is not Windows-absolute and the reverse, so judging both by one rule lets
    a relative Windows path through as though it were fine. The flavour is recorded on the operation
    precisely so this can be judged correctly.
    """
    value = canonical_path(_text(raw, key, what), field_name=f"{what}.{key}")
    if flavour == "posix":
        if not value.startswith("/"):
            raise RecordInvalid(f"{what}.{key} is not POSIX-absolute: {value!r}")
    else:
        if not (len(value) > 2 and value[1] == ":" and value[2] in "\\/") \
                and not value.startswith("\\\\"):
            raise RecordInvalid(f"{what}.{key} is not Windows-absolute: {value!r}")
    return value


def _abs_list(raw: dict, key: str, *, flavour: str, what: str, allow_empty=True) -> tuple:
    """A COLLECTION stays a collection. Two RC paths are two RC paths."""
    values = raw.get(key)
    if not isinstance(values, list):
        raise RecordInvalid(f"{what}.{key} must be a list")
    if not values and not allow_empty:
        raise RecordInvalid(f"{what}.{key} must not be empty")
    out = []
    for index, value in enumerate(values):
        out.append(_abs_path({key: value}, key, flavour=flavour, what=f"{what}.{key}[{index}]"))
    if len(set(out)) != len(out):
        raise RecordInvalid(f"{what}.{key} repeats a path")
    return tuple(out)


class _Operation:
    """Shared shape. Every variant is frozen, closed-key, and knows its own resource name."""

    tag: str = ""
    keys: frozenset = frozenset()

    def to_dict(self) -> dict:
        raise NotImplementedError

    @staticmethod
    def _checked(raw: object, tag: str, keys: frozenset):
        if not isinstance(raw, dict):
            raise RecordInvalid("a remaining operation must be a JSON object")
        if raw.get("operation") != tag:
            raise RecordInvalid(f"expected operation {tag!r}, got {raw.get('operation')!r}")
        unknown = set(raw) - keys - {"operation", "resource"}
        if unknown:
            raise RecordInvalid(f"{tag} operation has unknown key(s): {', '.join(sorted(unknown))}")
        missing = keys - set(raw)
        if missing:
            raise RecordInvalid(f"{tag} operation is missing key(s): {', '.join(sorted(missing))}")
        return raw


@dataclass(frozen=True)
class ExactPathOperation(_Operation):
    """One recorded file or tree, and what is done to it.

    `keep` is the derived control-plane exclusion set for a `clean_tree`, carried in the record so
    the executor does not re-derive it from a layout it was handed.
    """

    resource: str
    path: str
    action: str
    flavour: str
    keep: tuple = ()
    tag = OP_EXACT_PATH
    keys = frozenset({"resource", "path", "action", "flavour", "keep"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource, "path": self.path,
                "action": self.action, "flavour": self.flavour, "keep": list(self.keep)}

    @staticmethod
    def from_dict(raw: object) -> "ExactPathOperation":
        raw = _Operation._checked(raw, OP_EXACT_PATH, ExactPathOperation.keys)
        flavour = _flavour(raw)
        action = _text(raw, "action", "exact_path")
        if action not in PATH_ACTIONS:
            raise RecordInvalid(f"exact_path action must be one of {PATH_ACTIONS}, got {action!r}")
        keep = _abs_list(raw, "keep", flavour=flavour, what="exact_path")
        if action == PATH_ACTION_CLEAN_TREE and not keep:
            raise RecordInvalid(
                "a clean_tree exists because the tree holds control-plane paths; one with an empty "
                "keep set is a tree removal wearing the wrong name")
        if action != PATH_ACTION_CLEAN_TREE and keep:
            raise RecordInvalid(f"a {action} carries no keep set")
        path = _abs_path(raw, "path", flavour=flavour, what="exact_path")
        separator = "/" if flavour == "posix" else "\\"
        for kept in keep:
            # The tree itself is a legitimate kept path: it means *preserve the directory, remove
            # its contents*, which is what a clean with nothing else to protect is.
            if kept != path and not kept.startswith(path.rstrip("/\\") + separator):
                raise RecordInvalid(f"exact_path keep {kept!r} is neither {path!r} nor inside it")
        return ExactPathOperation(resource=_text(raw, "resource", "exact_path"), path=path,
                                  action=action, flavour=flavour, keep=keep)


@dataclass(frozen=True)
class ManagedUnitOperation(_Operation):
    """A service or scheduled task, with **all five** of O4's parts recorded."""

    resource: str
    role: str
    name: str
    definition_path: str
    expected_identity: str
    unit_kind: str
    install_dir: str
    flavour: str
    tag = OP_MANAGED_UNIT
    keys = frozenset({"resource", "role", "name", "definition_path", "expected_identity",
                      "unit_kind", "install_dir", "flavour"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource, "role": self.role,
                "name": self.name, "definition_path": self.definition_path,
                "expected_identity": self.expected_identity, "unit_kind": self.unit_kind,
                "install_dir": self.install_dir, "flavour": self.flavour}

    @staticmethod
    def from_dict(raw: object) -> "ManagedUnitOperation":
        raw = _Operation._checked(raw, OP_MANAGED_UNIT, ManagedUnitOperation.keys)
        flavour = _flavour(raw)
        role = _text(raw, "role", "managed_unit")
        if role not in MANAGED_ROLES:
            raise RecordInvalid(f"managed_unit role must be one of {MANAGED_ROLES}, got {role!r}")
        kind = _text(raw, "unit_kind", "managed_unit")
        if kind not in UNIT_KINDS:
            raise RecordInvalid(f"managed_unit unit_kind must be one of {UNIT_KINDS}, got {kind!r}")
        return ManagedUnitOperation(
            resource=_text(raw, "resource", "managed_unit"), role=role,
            name=_text(raw, "name", "managed_unit"),
            definition_path=_abs_path(raw, "definition_path", flavour=flavour,
                                      what="managed_unit"),
            expected_identity=_text(raw, "expected_identity", "managed_unit"),
            unit_kind=kind,
            install_dir=_abs_path(raw, "install_dir", flavour=flavour, what="managed_unit"),
            flavour=flavour)


@dataclass(frozen=True)
class StorageOperation(_Operation):
    """**One atomic operation**: close, prove unhosted, then remove the exact file and its RC paths.

    §X reproduced a live hosted database being deleted because `close`, `verify` and `remove` were
    three externally orderable methods and a caller could simply not call the first two. They are
    one operation now, and the sequence is the executor's obligation rather than the caller's
    discipline.

    `fms_root` is the recorded FileMaker Server root, and it is here for the reason `secrets_dir` is
    on `PkiOperation` (F3). The planner permits an exact local removal when FileMaker Server is
    **genuinely absent** — nothing can host a database on a box with no FileMaker Server — but the
    executor previously had no way to establish that for itself and refused the operation outright,
    so the record retained work nothing could ever execute. It could instead have taken *FMS is
    absent* from its caller, and that is precisely what F3 ruled against: a proof supplied by the
    caller is a proof the caller could get wrong, and the consequence here is deleting a database
    FileMaker Server is actually hosting.

    So the absence is **observed by the executor, at the exact recorded path**, every time. The
    database and its RC paths remain the separately recorded exact paths they always were; this
    field decides only whether an unhosted proof can be established without contacting anything.
    """

    resource: str
    database_name: str
    database_path: str
    rc_paths: tuple
    fms_root: str
    flavour: str
    tag = OP_STORAGE
    keys = frozenset({"resource", "database_name", "database_path", "rc_paths", "fms_root",
                      "flavour"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource,
                "database_name": self.database_name, "database_path": self.database_path,
                "rc_paths": list(self.rc_paths), "fms_root": self.fms_root,
                "flavour": self.flavour}

    @staticmethod
    def from_dict(raw: object) -> "StorageOperation":
        raw = _Operation._checked(raw, OP_STORAGE, StorageOperation.keys)
        flavour = _flavour(raw)
        return StorageOperation(
            resource=_text(raw, "resource", "storage"),
            database_name=_text(raw, "database_name", "storage"),
            database_path=_abs_path(raw, "database_path", flavour=flavour, what="storage"),
            rc_paths=_abs_list(raw, "rc_paths", flavour=flavour, what="storage"),
            fms_root=_abs_path(raw, "fms_root", flavour=flavour, what="storage"),
            flavour=flavour)


@dataclass(frozen=True)
class ProxyFront:
    """One edited front. A box may have several, and they do not collapse."""

    proxy_type: str
    config_location: str
    config_fingerprint: str

    def to_dict(self) -> dict:
        return {"proxy_type": self.proxy_type, "config_location": self.config_location,
                "config_fingerprint": self.config_fingerprint}

    @staticmethod
    def from_dict(raw: object, *, flavour: str) -> "ProxyFront":
        if not isinstance(raw, dict):
            raise RecordInvalid("a proxy front must be a JSON object")
        unknown = set(raw) - {"proxy_type", "config_location", "config_fingerprint"}
        if unknown:
            raise RecordInvalid(f"proxy front has unknown key(s): {', '.join(sorted(unknown))}")
        return ProxyFront(
            proxy_type=_text(raw, "proxy_type", "proxy front"),
            config_location=_abs_path(raw, "config_location", flavour=flavour, what="proxy front"),
            config_fingerprint=_text(raw, "config_fingerprint", "proxy front"))


@dataclass(frozen=True)
class ProxyOperation(_Operation):
    resource: str
    fronts: tuple
    flavour: str
    tag = OP_PROXY
    keys = frozenset({"resource", "fronts", "flavour"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource,
                "fronts": [f.to_dict() for f in self.fronts], "flavour": self.flavour}

    @staticmethod
    def from_dict(raw: object) -> "ProxyOperation":
        raw = _Operation._checked(raw, OP_PROXY, ProxyOperation.keys)
        flavour = _flavour(raw)
        fronts = raw.get("fronts")
        if not isinstance(fronts, list) or not fronts:
            raise RecordInvalid("a proxy operation needs a non-empty list of fronts")
        parsed = tuple(ProxyFront.from_dict(f, flavour=flavour) for f in fronts)
        if len({f.proxy_type for f in parsed}) != len(parsed):
            raise RecordInvalid("a proxy operation names one proxy type twice")
        return ProxyOperation(resource=_text(raw, "resource", "proxy"), fronts=parsed,
                              flavour=flavour)


@dataclass(frozen=True)
class PkiOperation(_Operation):
    """The registration, its fingerprint, and **where the identity that may delete it lives**.

    `secrets_dir` is the fixed installed secrets directory, recorded at install. It is here because
    the executor previously took the FMS `host` and the private key from its caller: a caller could
    therefore point an otherwise valid recorded deletion at a *different* FileMaker Server, which is
    target authority arriving from outside the record. Recording the directory means the endpoint and
    the credential are both read from fixed installed evidence — the caller supplies neither.

    **An ordering obligation this field creates, stated rather than left implied:** the same record
    may carry an `exact_path` removal of `secrets_dir`. The PKI operation must be executed before it,
    because afterwards the identity store is gone and the operation can only refuse. The record has no
    place to express an order and stage 5 (the resume driver) does not exist yet, so this is owed
    there rather than checked here.
    """

    resource: str
    registration_name: str
    public_fingerprint: str
    secrets_dir: str
    flavour: str
    tag = OP_PKI
    keys = frozenset({"resource", "registration_name", "public_fingerprint", "secrets_dir",
                      "flavour"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource,
                "registration_name": self.registration_name,
                "public_fingerprint": self.public_fingerprint,
                "secrets_dir": self.secrets_dir, "flavour": self.flavour}

    @staticmethod
    def from_dict(raw: object) -> "PkiOperation":
        raw = _Operation._checked(raw, OP_PKI, PkiOperation.keys)
        flavour = _flavour(raw)
        return PkiOperation(resource=_text(raw, "resource", "pki"),
                            registration_name=_text(raw, "registration_name", "pki"),
                            public_fingerprint=_text(raw, "public_fingerprint", "pki"),
                            secrets_dir=_abs_path(raw, "secrets_dir", flavour=flavour, what="pki"),
                            flavour=flavour)


@dataclass(frozen=True)
class PatchSlotOperation(_Operation):
    """The slot, and the path it must still hold. A slot holding somebody else's path is refused."""

    resource: str
    slot: str
    hosting_dir: str
    flavour: str
    scaffolding: tuple = ()
    tag = OP_PATCH_SLOT
    keys = frozenset({"resource", "slot", "hosting_dir", "flavour", "scaffolding"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource, "slot": self.slot,
                "hosting_dir": self.hosting_dir, "flavour": self.flavour,
                "scaffolding": list(self.scaffolding)}

    @staticmethod
    def from_dict(raw: object) -> "PatchSlotOperation":
        # Records published before empty-scaffolding retirement named no such paths; their empty
        # set remains valid and resumable.
        if isinstance(raw, dict) and "scaffolding" not in raw:
            raw = {**raw, "scaffolding": []}
        raw = _Operation._checked(raw, OP_PATCH_SLOT, PatchSlotOperation.keys)
        flavour = _flavour(raw)
        slot = _text(raw, "slot", "patch_slot")
        if slot not in ("1", "2"):
            raise RecordInvalid(f"patch_slot slot must be '1' or '2', got {slot!r}")
        hosting = _abs_path(raw, "hosting_dir", flavour=flavour, what="patch_slot")
        scaffolding = _abs_list(raw, "scaffolding", flavour=flavour, what="patch_slot")
        module = posixpath if flavour == "posix" else ntpath
        root = module.normcase(module.normpath(hosting))
        for path in scaffolding:
            candidate = module.normcase(module.normpath(path))
            try:
                contained = module.commonpath((root, candidate)) == root
            except ValueError:
                contained = False
            if not contained or candidate == root:
                raise RecordInvalid(
                    f"patch_slot scaffolding {path!r} is not strictly inside {hosting!r}")
        return PatchSlotOperation(
            resource=_text(raw, "resource", "patch_slot"), slot=slot,
            hosting_dir=hosting, flavour=flavour, scaffolding=scaffolding)


@dataclass(frozen=True)
class AccountOperation(_Operation):
    resource: str
    account: str
    flavour: str
    tag = OP_ACCOUNT
    keys = frozenset({"resource", "account", "flavour"})

    def to_dict(self) -> dict:
        return {"operation": self.tag, "resource": self.resource, "account": self.account,
                "flavour": self.flavour}

    @staticmethod
    def from_dict(raw: object) -> "AccountOperation":
        raw = _Operation._checked(raw, OP_ACCOUNT, AccountOperation.keys)
        return AccountOperation(resource=_text(raw, "resource", "account"),
                                account=_text(raw, "account", "account"),
                                flavour=_flavour(raw))


_VARIANTS = {
    OP_EXACT_PATH: ExactPathOperation, OP_MANAGED_UNIT: ManagedUnitOperation,
    OP_STORAGE: StorageOperation, OP_PROXY: ProxyOperation, OP_PKI: PkiOperation,
    OP_PATCH_SLOT: PatchSlotOperation, OP_ACCOUNT: AccountOperation,
}


def _flavour(raw: dict) -> str:
    value = raw.get("flavour")
    if value not in FLAVOURS:
        raise RecordInvalid(f"operation flavour must be one of {FLAVOURS}, got {value!r}")
    return value


# ── the canonical order (packet 1246-09 stage 5, ruling 3) ────────────────────
#
# **A resume may have no manifest and no plan.** The ordinary tail of a *successful* uninstall has
# already removed `install_dir`, so the manifest is gone at every boundary after it; a resume that
# re-planned would refuse there, and one that re-planned earlier would produce a different remaining
# set that `publish` refuses by design. The record is therefore the ONLY thing that can say what
# order the remaining work must run in, and until now it did not: `remaining_from_plan` emitted
# `sorted(decisions.items())`, so the order was alphabetical. That put `install_dir` before every
# service, `patch_dir` before its slot, and `service_account` before the units that run as it —
# and on Windows, where every service definition lives INSIDE `install_dir`, it made the service
# removal permanently unexecutable: the five-part conjunction cannot be re-proved from a definition
# that is gone, and this platform has no residual branch.
#
# `pki` before `secrets_dir` held only because `p` sorts before `s`.

#: `resource -> the resources it must FOLLOW`. Each edge is a fact about what one operation needs to
#: still exist when it runs, and each is cross-checked against the operations' own FIELDS in
#: `_require_coherence` — a declared edge whose paths disagree with it is a record that has drifted
#: from the structure this table describes.
_LEGACY_RESOURCE_FOLLOWS_V3: dict = {
    "secrets_dir": ("pki",),
    "patch_dir": ("patch_slot",),
    "patch_slot": ("sandbox", "sandbox_rc"),
    "install_dir": ("web_service", "scheduler_service", "updater_task", "state_dir", "config_dir"),
    "service_account": ("web_service", "scheduler_service", "updater_task"),
    "cli_shim": ("state_dir", "config_dir"),
    "sudoers_helpers": ("state_dir", "config_dir"),
}


RESOURCE_FOLLOWS: dict = {
    # The storage and folder-slot adapters authenticate with the installation's recorded PKI
    # identity. Deregistering that identity first makes both clients fail with an invalid token on
    # the same ordinary uninstall that just proved the identity existed. The PKI registration is
    # therefore the LAST FileMaker provider resource removed: first close/unhost/remove the storage
    # database and empty/deregister its patch slot, then retire the credential they used.
    "pki": ("storage_db", "patch_slot"),
    # All three FileMaker provider operations authenticate with the identity store under
    # `secrets_dir`. Name every direct consumer: after any one checkpoints out of a partial record,
    # the surviving consumers still keep their key material until their own work completes.
    "secrets_dir": ("pki", "storage_db", "patch_slot"),
    # A slot is deregistered while it still serves the directory it names; the executor also proves
    # the compartment empty, which a removed directory cannot be observed to be.
    "patch_dir": ("patch_slot",),
    # ...and *empty* is the load-bearing word: `run_patch_slot` refuses a slot whose hosting
    # directory still holds anything, so the sandbox database and its RC path — both inside that
    # directory — go first. They are one StorageOperation: FileMaker is closed and proved not serving
    # before either recorded path is removed, and no caller can reorder the two halves.
    "patch_slot": ("sandbox",),
    # The five-part conjunction proves the executable beneath `install_dir` and reads the definition
    # — on Windows both live inside it. It is also part of the TERMINAL FOOTPRINT below, so it
    # follows the two cleans as well.
    "install_dir": ("web_service", "scheduler_service", "updater_task", "state_dir", "config_dir"),
    # An account is removed after everything that runs as it.
    "service_account": ("web_service", "scheduler_service", "updater_task"),
    # THE TERMINAL FOOTPRINT. These three are what *invoking the next run* is made of — the bundled
    # interpreter and the package under `install_dir`, the launcher that `exec`s them, and the
    # elevation helpers — so they go after everything else, INCLUDING the two cleans.
    #
    # **Ordering them merely ahead of the cleans was not enough, and that is the correction.** A
    # clean can refuse (a control-plane path the record does not preserve) or fail (a leftover on
    # read-back) AFTER the footprint has already gone, which leaves durable pending evidence on a
    # box with no interpreter able to read it. Last is the only position from which nothing else can
    # still fail behind them.
    "cli_shim": ("state_dir", "config_dir"),
    "sudoers_helpers": ("state_dir", "config_dir"),
}

#: The three above, named once. `uninstall_plan.INVOCATION_FOOTPRINT` is the same set seen from the
#: planner's side, and a test holds the two together.
TERMINAL_FOOTPRINT: tuple = ("install_dir", "cli_shim", "sudoers_helpers")

#: **The storage operation's dependent cleanup is not an edge here, and that is the point.** Its
#: remote-container paths are the only thing that depends on it, and they are INSIDE it: close,
#: prove unhosted, remove the file, then the RC paths, as one operation with no seam a caller could
#: reorder (§Y). An ordering edge would be a weaker version of a guarantee the type already makes,
#: and writing one would suggest the sequence is arrangeable when it is not.
_STORAGE_DEPENDENT_CLEANUP_IS_INTERNAL = True

#: The two CLEAN operations are the control-plane's own trees. They run after every product removal
#: — that is what "product work, then finalization" means — and they are independent of each other:
#: each preserves only its own live paths and removes nothing the other needs. An earlier draft made
#: each follow *everything*, which is a cycle rather than a dependency.
CLEANED_RESOURCES: tuple = ("state_dir", "config_dir")


def _decision_of(resource: str) -> str:
    """`sudoers_helpers[1]` is ordered as `sudoers_helpers`. Several files, one dependency."""
    return resource.split("[")[0]


def dependency_edges(operations: tuple, *, follows=None) -> dict:
    """`resource -> the resources present in THIS record that it must follow`."""
    relation = RESOURCE_FOLLOWS if follows is None else follows
    present = {}
    for op in operations:
        present.setdefault(_decision_of(op.resource), []).append(op.resource)
    edges = {}
    for op in operations:
        base = _decision_of(op.resource)
        required = []
        if base in CLEANED_RESOURCES:
            # A clean follows every product removal that is NOT terminal footprint. The two cleans
            # are independent of each other, and the footprint follows THEM — including either here
            # would be a cycle rather than a dependency.
            required = [other.resource for other in operations
                        if _decision_of(other.resource) not in CLEANED_RESOURCES
                        and _decision_of(other.resource) not in TERMINAL_FOOTPRINT]
        else:
            for name in relation.get(base, ()):
                required.extend(present.get(name, ()))
        edges[op.resource] = frozenset(required)
    return edges


def canonical_order(operations: tuple, *, follows=None) -> tuple:
    """The one order a record may be written in. Deterministic, so the same facts always produce the
    same document — a builder that reordered itself between runs could never be compared against a
    published record, and `publish` compares the remaining set exactly."""
    edges = dependency_edges(operations, follows=follows)
    by_name = {op.resource: op for op in operations}
    ordered, placed = [], set()
    while len(ordered) < len(operations):
        ready = sorted(name for name in by_name if name not in placed and edges[name] <= placed)
        if not ready:
            raise RecordInvalid(
                "the pending operations have a circular dependency: "
                f"{sorted(set(by_name) - placed)}")
        for name in ready:
            ordered.append(by_name[name])
            placed.add(name)
    return tuple(ordered)


def _require_order(operations: tuple, *, follows=None) -> None:
    """**A reordered record REFUSES.** It is not quietly sorted back into safety.

    Sorting it would mean the document and the behaviour disagree, silently, in the one place whose
    entire job is to be the durable truth about what remains. If the order on disk violates what the
    record itself says the work depends on, that is not a record to act on.

    **What is checked is the DEPENDENCY property, not equality with `canonical_order`**, and the
    difference is load-bearing rather than lax. A checkpoint removes one entry and leaves the rest
    in place; the canonical order of the smaller set is not always the surviving subsequence of the
    larger one, because dropping an operation can drop the edges that held two independent entries
    apart. Requiring exact equality would therefore refuse a record this module itself had just
    written — a resume that could not read its own checkpoint. The property that actually matters is
    the one asserted here: nothing appears before something it must follow.
    """
    edges = dependency_edges(operations, follows=follows)
    placed = set()
    for op in operations:
        missing = sorted(edges[op.resource] - placed)
        if missing:
            raise RecordInvalid(
                f"the pending record lists {op.resource!r} before {missing}, which it must follow; "
                "the recorded order is the only order a resume has")
        placed.add(op.resource)


def parse_operation(raw: object):
    """One operation, by its closed tag. An unknown tag is never guessed at."""
    if not isinstance(raw, dict):
        raise RecordInvalid("a remaining operation must be a JSON object")
    tag = raw.get("operation")
    if tag not in _VARIANTS:
        raise RecordInvalid(f"operation must be one of {OPERATION_TAGS}, got {tag!r}")
    return _VARIANTS[tag].from_dict(raw)

@dataclass(frozen=True)
class PendingRecord:
    """The complete record. Nothing is optional: a partial one cannot drive a resume."""

    operation_id: str
    installation_id: str
    manifest_generation: int
    remaining: tuple
    schema_version: int = PENDING_SCHEMA_VERSION
    created_utc: str = ""
    updated_utc: str = ""

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "manifest_generation": self.manifest_generation,
            "created_utc": self.created_utc,
            "updated_utc": self.updated_utc,
            "remaining": [op.to_dict() for op in self.remaining],
        }

    @staticmethod
    def from_dict(data: object) -> "PendingRecord":
        if not isinstance(data, dict):
            raise RecordInvalid("the pending record must be a JSON object")
        version = data.get("schema_version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise RecordInvalid("pending schema_version must be an integer")
        if version not in (2, 3, PENDING_SCHEMA_VERSION):
            # A NAMED refusal, not a parse error. Version 1 was never written to any box and held
            # untyped resource/identifier pairs. Versions 2 and 3 are historical typed documents;
            # v2 is upgraded operation-by-operation by the compatibility default above.
            raise RecordInvalid(
                f"{PENDING_SCHEMA_UNSUPPORTED}: this build reads pending schema "
                f"2, 3 or {PENDING_SCHEMA_VERSION} and the record declares {version}; version 1 "
                "held untyped resource/identifier pairs and is not readable"
            )
        allowed = {"schema_version", "operation_id", "installation_id", "manifest_generation",
                   "created_utc", "updated_utc", "remaining"}
        unknown = set(data) - allowed
        if unknown:
            raise RecordInvalid(
                f"the pending record has unknown key(s): {', '.join(sorted(unknown))}")
        missing = allowed - set(data)
        if missing:
            raise RecordInvalid(
                f"the pending record is missing key(s): {', '.join(sorted(missing))}")
        for field_name in ("operation_id", "installation_id"):
            value = data.get(field_name)
            if not isinstance(value, str) or not _CANONICAL_UUID.match(value):
                raise RecordInvalid(
                    f"the pending record's {field_name} must be a canonical lowercase UUID, "
                    f"got {value!r}")
        generation = data.get("manifest_generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise RecordInvalid("manifest_generation must be a positive integer")
        raw_remaining = data.get("remaining")
        if not isinstance(raw_remaining, list):
            raise RecordInvalid("the pending record's remaining set must be a list")
        remaining = tuple(parse_operation(op) for op in raw_remaining)
        _reject_duplicates(remaining)
        _require_coherence(remaining)
        if version in (2, 3):
            # Versions 2 and 3 were published with PKI alphabetically ahead of the two FileMaker
            # clients that authenticate through it. Accept only a record valid under that exact
            # historical relation, then migrate its surviving typed operations into v4's stronger
            # order. Arbitrary old reorderings are still refused rather than laundered by sorting.
            _require_order(remaining, follows=_LEGACY_RESOURCE_FOLLOWS_V3)
            remaining = canonical_order(remaining)
        else:
            _require_order(remaining)
        return PendingRecord(
            operation_id=str(data["operation_id"]),
            installation_id=str(data["installation_id"]),
            manifest_generation=generation,
            remaining=remaining,
            created_utc=str(data.get("created_utc") or ""),
            updated_utc=str(data.get("updated_utc") or ""),
        )

    def validated(self) -> "PendingRecord":
        return PendingRecord.from_dict(self.to_dict())


_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _reject_duplicates(operations: tuple) -> None:
    """One operation per resource, and one resource per operation."""
    seen = set()
    for op in operations:
        if op.resource in seen:
            raise RecordInvalid(
                f"the pending record lists {op.resource!r} twice; a duplicate makes the resume "
                "ambiguous")
        seen.add(op.resource)


def _require_coherence(operations: tuple) -> None:
    """Cross-field rules a single operation cannot check alone.

    * every operation on one record describes ONE platform — a record naming both is a record
      assembled from two machines;
    * a `patch_slot` and an `exact_path` for the compartment must name the same directory, or the
      slot and the folder it points at have drifted apart inside our own record;
    * a `clean_tree`'s excluded paths may not be another operation's removal target, which is the
      §V collision expressed inside the record rather than only in the plan.
    """
    flavours = {getattr(op, "flavour", None) for op in operations} - {None}
    if len(flavours) > 1:
        raise RecordInvalid(f"the pending record mixes platform flavours {sorted(flavours)}")
    hosting = {op.hosting_dir for op in operations if isinstance(op, PatchSlotOperation)}
    compartments = {op.path for op in operations
                    if isinstance(op, ExactPathOperation) and op.resource == "patch_dir"}
    if hosting and compartments and hosting != compartments:
        raise RecordInvalid(
            f"the patch slot names {sorted(hosting)} and the compartment removal names "
            f"{sorted(compartments)}; they must be the same directory")
    # **The declared dependency edges, cross-checked against the operations' own fields.**
    # `RESOURCE_FOLLOWS` says *the PKI operation needs `secrets_dir`*; these say the two are actually
    # talking about the same directory. A table that names an edge the paths contradict is a table
    # ordering work it has misunderstood, and the ordering is the only thing a resume has.
    trees = {op.resource: op.path for op in operations if isinstance(op, ExactPathOperation)}
    for op in operations:
        if isinstance(op, PkiOperation) and "secrets_dir" in trees:
            if not _canonical_eq(op.secrets_dir, trees["secrets_dir"], op.flavour):
                raise RecordInvalid(
                    f"the PKI operation reads its identity from {op.secrets_dir!r} and the record "
                    f"removes {trees['secrets_dir']!r}; the ordering rule that keeps the first "
                    "before the second is describing two different directories")
        if isinstance(op, ManagedUnitOperation) and "install_dir" in trees:
            if not _canonical_eq(op.install_dir, trees["install_dir"], op.flavour):
                raise RecordInvalid(
                    f"{op.resource!r} is bound to install directory {op.install_dir!r} and the "
                    f"record removes {trees['install_dir']!r}")
    # A clean legitimately preserves its OWN directory — that is what "remove the contents, keep
    # the directory" is — so an operation's own path is not a collision with itself. The rule is
    # about one operation removing what ANOTHER preserves, which is the §V hazard.
    kept = {(op.resource, k) for op in operations if isinstance(op, ExactPathOperation)
            for k in op.keep}
    targets = {op.path: op.resource for op in operations if isinstance(op, ExactPathOperation)
               and op.action != PATH_ACTION_CLEAN_TREE}
    collision = sorted({path for resource, path in kept
                        if path in targets and targets[path] != resource})
    if collision:
        raise RecordInvalid(
            f"the record both preserves and removes {collision}")


def _canonical_eq(left: str, right: str, flavour: str) -> bool:
    if flavour == "windows":
        return left.replace("/", "\\").rstrip("\\").lower() == \
            right.replace("/", "\\").rstrip("\\").lower()
    return left.rstrip("/") == right.rstrip("/")


def _authority(layout, lock: object, action: str):
    """Accept only a held lock for THIS machine's lifecycle state — the Journal/Manifest pattern.

    **The lock requirement was very nearly deferred to stage 4, and deferring it would have been
    wrong.** `publish` and `checkpoint` mutate machine lifecycle authority *now*: the pending record
    decides what a later resume believes is still owed. A mutator that acquires its authority in a
    later packet is a mutator that races until that packet lands, and "no caller exists yet" is a
    reason nobody would notice the race, not a reason there isn't one.

    `require_lock` proves a lock is held; it cannot prove it is the RIGHT one, so the layout is
    compared too — a lock taken on another root must not authorize writing this one.
    """
    held = require_lock(lock, action)
    if held.layout != layout:
        raise LockNotHeld(
            f"{action} requires the lifecycle lock for {layout.lock_file}, "
            f"not {held.layout.lock_file}"
        )
    return held


def pending_path(layout) -> Path:
    """The fixed stable location. Derived from the lifecycle layout, never from a caller."""
    if layout.locator_dir is not None:
        return Path(layout.locator_dir) / PENDING_FILENAME
    # Windows: the protected fixed config namespace beside the lock and journal, whose identity is
    # bound to the HKLM locator. The registry holds the locator; a JSON document of this shape does
    # not belong in a registry value.
    return Path(layout.journal_file).parent / PENDING_FILENAME


def _serialize(record: PendingRecord) -> bytes:
    return json.dumps(record.to_dict(), indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_durably(path: Path, payload: bytes, *, exclusive: bool) -> None:
    """Write through a sibling and `os.replace` onto the final name — on BOTH paths.

        create sibling -> write -> fsync(file) -> replace -> fsync(directory)

    **The first write goes through the sibling too, and that is a correction.** It originally used
    `O_EXCL` directly on the final name, which is exclusive but not atomic: a torn first write left
    a half-written file AT the record's own path, so a rerun found neither a complete old record nor
    a complete new one — it refused as malformed and the uninstall could not restart. The record is
    the only resume authority an interrupted uninstall has; a crash that destroys it is precisely the
    failure this module exists to prevent.

    Through the sibling, the final name is **never** half-written. A crash before the replace leaves
    only the sibling, and the record reads as absent — which is true, because no record was ever
    published.

    `exclusive` therefore no longer means `O_EXCL`; it means *this is a first publish, so the final
    name must not already exist*. `publish` establishes that by reading first, and a concurrent
    publisher that slipped in is caught by the read-back digest comparison, which is a stronger
    check than `O_EXCL` gave: it verifies the content that actually landed, not merely that we were
    the one who created the file.

    A leftover sibling is overwritten rather than treated as authority: it is by definition the
    residue of a publish that never completed, and it is not a record.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if exclusive and path.exists():
        raise PendingRecordRefused(
            f"a pending record already exists at {path}; a first publish never overwrites one")
    sibling = path.parent / (path.name + ".next")
    # Windows opens low-level descriptors in TEXT mode unless O_BINARY is requested. `os.write`
    # then expands every LF in the canonical JSON payload to CRLF: the record lands parseable, but
    # its digest can never equal the bytes `_serialize` produced. This writer is explicitly binary
    # because the durability contract is byte equality, not merely equivalent JSON.
    fd = os.open(str(sibling), os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | getattr(os, "O_BINARY", 0), PENDING_FILE_MODE)
    try:
        # `os.write` may write FEWER bytes than it was given and return the short count without
        # raising. Ignoring that return value is how a half-written record reaches `os.replace` and
        # lands at the record's own path — the exact outcome the sibling exists to prevent.
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count <= 0:
                raise PendingRecordRefused(
                    f"the pending record could not be written to {sibling}: the write returned "
                    f"{count} after {written} of {len(payload)} bytes")
            written += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(sibling), str(path))
    _fsync_dir(path.parent)


def read(layout) -> PendingRecord | None:
    """The record, or None. A malformed one REFUSES rather than reading as absent."""
    path = pending_path(layout)
    try:
        payload = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PendingRecordRefused(f"the pending record at {path} could not be read: {exc}") from exc
    try:
        return PendingRecord.from_dict(json.loads(payload.decode("utf-8")))
    except (ValueError, RecordInvalid) as exc:
        raise PendingRecordRefused(
            f"the pending record at {path} is malformed and will not be adopted: {exc}") from exc


def publish(layout, record: PendingRecord, *, lock: object) -> PendingRecord:
    """Write the record BEFORE the first destructive action, and prove it landed.

    Idempotent for the SAME operation — republishing an identical record is a no-op, which is what a
    rerun that crashed before its first removal must be. A record belonging to another operation or
    another installation is refused, never overwritten: it is somebody else's only resume authority.

    **Authority is checked before ANYTHING** — before the read, before the directory is created,
    before the sibling is written, before the replace. A refusal must leave the record and the
    sibling exactly as it found them, and a check placed after a `mkdir` would not.

    **What the read-back does and does not prove.** It proves the bytes that landed are the bytes
    intended, at the moment it read them. It does **not** detect a concurrent publisher: writer B
    can replace the record after writer A's read-back succeeded and before A returns, and A would
    report success over B's content. Serialization is the lifecycle lock's job, and this is why the
    lock is required here rather than in a later stage.
    """
    _authority(layout, lock, "publishing the pending-uninstall record")
    record = record.validated()
    path = pending_path(layout)
    existing = read(layout)
    if existing is not None:
        _require_same_operation(existing, record)
        if existing.remaining != record.remaining:
            raise PendingRecordRefused(
                "a pending record for this operation already exists with a different remaining "
                "set; publish happens once, and checkpointing is how it shrinks")
        return existing
    payload = _serialize(record)
    _write_durably(path, payload, exclusive=True)
    return _verify_readback(layout, payload)


def checkpoint(layout, *, operation_id: str, installation_id: str, resource: str,
               lock: object) -> PendingRecord:
    """Remove EXACTLY ONE completed entry and republish durably.

    One at a time, deliberately: a checkpoint that could clear several entries would let a partial
    removal report more progress than it made, and the resume would skip work nobody did.

    **This is a read-modify-write with no compare-and-swap**, so the lifecycle lock is not
    defence-in-depth here — it is the only thing that makes it correct. Two unserialized checkpoints
    both read the same remaining set, each drops its own entry, and the second write silently
    restores the first one's: a resource that was removed reappears as still owed, and the resume
    tries to delete it again.
    """
    _authority(layout, lock, "checkpointing the pending-uninstall record")
    existing = read(layout)
    if existing is None:
        raise PendingRecordRefused(
            "there is no pending record to checkpoint; a checkpoint never creates one")
    _require_same_operation(
        existing,
        PendingRecord(operation_id=operation_id, installation_id=installation_id,
                      manifest_generation=existing.manifest_generation, remaining=()),
    )
    remaining = tuple(e for e in existing.remaining if e.resource != resource)
    if len(remaining) == len(existing.remaining):
        raise PendingRecordRefused(
            f"{resource!r} is not in the remaining set; checkpointing something that was never "
            "owed would report progress that did not happen")
    updated = PendingRecord(
        operation_id=existing.operation_id, installation_id=existing.installation_id,
        manifest_generation=existing.manifest_generation, remaining=remaining,
        created_utc=existing.created_utc, updated_utc=utc_now_iso(),
    ).validated()
    payload = _serialize(updated)
    _write_durably(pending_path(layout), payload, exclusive=False)
    return _verify_readback(layout, payload)


def _require_same_operation(existing: PendingRecord, incoming: PendingRecord) -> None:
    if existing.installation_id != incoming.installation_id:
        raise PendingRecordRefused(
            f"the pending record belongs to installation {existing.installation_id}, not "
            f"{incoming.installation_id}; a foreign record is never adopted")
    if existing.operation_id != incoming.operation_id:
        raise PendingRecordRefused(
            f"the pending record belongs to operation {existing.operation_id}, not "
            f"{incoming.operation_id}")


#: `discard`'s journal verdict. Two values, because the record's answer to every other journal state
#: is the same: leave it exactly where it is.
_JOURNAL_DISCARDABLE = object()
_JOURNAL_BLOCKS = object()


def _JOURNAL_FROM_LAYOUT(layout, operation_id: str, installation_id: str) -> tuple:
    """Read this machine's journal and say whether it permits the record to go.

    Permits only **absent** or **matching and resolved**. An unreadable journal is not an absent one
    — that distinction is `Journal.requires_recovery`'s whole subject — and a foreign one describes
    somebody else's operation, which is not an operation whose evidence we may retire.
    """
    from .journal import Journal
    from .schema import JOURNAL_RESOLVED

    try:
        record = Journal(layout).read()
    except Exception as exc:                                              # noqa: BLE001
        return _JOURNAL_BLOCKS, f"could not be read ({exc}); unreadable is not absent"
    if record is None:
        return _JOURNAL_DISCARDABLE, "is absent"
    if (record.installation_id != installation_id or record.operation_id != operation_id):
        return _JOURNAL_BLOCKS, (
            f"belongs to operation {record.operation_id} of installation "
            f"{record.installation_id}, not {operation_id} of {installation_id}")
    if record.state != JOURNAL_RESOLVED:
        return _JOURNAL_BLOCKS, f"is {record.state!r} rather than {JOURNAL_RESOLVED!r}"
    return _JOURNAL_DISCARDABLE, "is resolved"


def _verify_readback(layout, payload: bytes) -> PendingRecord:
    """Read the file back and compare digests. A record that does not read back exactly is treated
    as never written — reporting a durable record that is not there is the one failure this whole
    module exists to prevent."""
    path = pending_path(layout)
    try:
        landed = path.read_bytes()
    except OSError as exc:
        raise PendingRecordRefused(
            f"the pending record could not be read back from {path}: {exc}") from exc
    if _digest(landed) != _digest(payload):
        raise PendingRecordRefused(
            f"the pending record at {path} did not read back as written "
            f"({_digest(landed)[:12]} vs {_digest(payload)[:12]})")
    return PendingRecord.from_dict(json.loads(landed.decode("utf-8")))


def discard(layout, *, operation_id: str, installation_id: str, lock: object,
            journal_state=_JOURNAL_FROM_LAYOUT) -> None:
    """Remove the record — the LAST act of an uninstall, and the most bounded thing in this module.

    Through stages 1-4 this raised, because removing the only resume authority before anything could
    have earned that right is the RC4 the packet was opened to prevent. What earns it is not the
    existence of a caller; it is **five conditions, every one of them re-established here rather
    than trusted from the caller that says it is time**:

    1. the held lifecycle lock for THIS layout — the same authority `publish` and `checkpoint` take;
    2. the operation and installation the caller expects, matched against the record on disk. A
       caller finishing operation A must not discard operation B's record because B is what happens
       to be there;
    3. a record that reads back and validates. A malformed one refuses: it is evidence, and evidence
       that cannot be read is not evidence that can be thrown away;
    4. **`remaining` is empty.** This is the whole point. A record still naming work is the only
       thing that knows the work is owed, and nothing about being at the end of a plan makes that
       false;
    5. the journal is **absent, or matching and RESOLVED**. An open, checkpointed or
       needs-recovery journal says an operation is still in flight, and a foreign one says this is
       not our operation at all. Either way the record stays.

    **No caller-selected path**, here as everywhere in this module: the target is `pending_path`
    derived from the layout. `journal_state` is a seam for the same reason `_installed_identity` is
    one on the executor — it is *how the journal is read*, never *which journal*.

    Idempotent by construction: a record that is already gone returns quietly, so a finalization
    interrupted after the unlink and re-run completes rather than refusing.
    """
    _authority(layout, lock, "discarding the pending-uninstall record")
    record = read(layout)
    if record is None:
        return
    _require_same_operation(
        record,
        PendingRecord(operation_id=operation_id, installation_id=installation_id,
                      manifest_generation=record.manifest_generation, remaining=()))
    if record.remaining:
        raise PendingRecordRefused(
            f"the pending record still owes {[op.resource for op in record.remaining]}; it is the "
            "only thing that knows that work is owed and it is not discarded while it does")
    state, detail = journal_state(layout, operation_id, installation_id)
    if state is not _JOURNAL_DISCARDABLE:
        raise PendingRecordRefused(
            f"the pending record is not discarded while the lifecycle journal {detail}")
    path = pending_path(layout)
    try:
        os.unlink(str(path))
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


#: Kinds whose identifier is NOT a filesystem path, so canonicalizing it would corrupt it.
NON_PATH_KINDS = frozenset({"service_account", "patch_folder_slot", "service_definition",
                            "pki_registration"})


class AuthorityIncomplete(LifecycleError):
    """The manifest cannot supply a field a planned operation requires. Nothing is guessed."""


#: Which manifest-derived operation each planner resource becomes. A planner decision this table
#: does not name cannot become pending authority at all.
_RESOURCE_BUILDERS: dict = {}


def _builds(resource):
    def register(fn):
        _RESOURCE_BUILDERS[resource] = fn
        return fn
    return register


def remaining_from_plan(manifest, decisions: dict, *, flavour: str) -> tuple:
    """Every remaining operation, derived from the VALIDATED MANIFEST and the planner's decisions.

    **The caller-supplied `identifiers` mapping is gone.** In version 1 it was, literally, the thing
    that decided what got deleted: the planner said *remove `install_dir`* and the caller said *and
    `install_dir` means this path*. §X reproduced what that costs. Caller data may select an
    operation, and may later supply credentials or collaborators; **it may never supply a target.**

    Refuses — it does not skip — when the manifest cannot supply a field a planned operation needs.
    A missing field means the installation did not record what it is now being asked to remove, and
    omitting the operation would silently leave the resource behind while reporting a clean plan.

    **What counts as work (stage 5, ruling 3).** Three decisions build an operation:

    * `REMOVE` — the resource goes;
    * `DEREGISTER_ONLY` — a folder slot is deregistered, not removed, and a builder that looked only
      at removals would leave the slot registered on every uninstall;
    * `UNAVAILABLE` **carrying `RECORDED` authority** — work this installation owns and cannot do
      *yet*. This was the durable hole: the PKI deregistration, the storage database and its RC
      paths, the proxy edits and the folder slot all became `UNAVAILABLE` the moment FileMaker
      Server was not usable, and the record then said nothing about them. The plan's `unfinished`
      tuple naming them is a return value, not evidence — so a forced run finished its local
      cleanup, removed the manifest with `install_dir`, and left a box that could neither resume
      from the record nor re-plan from anything.

    `UNAVAILABLE` with **no** authority is not work: nothing recorded the resource, so there is
    nothing owed and nothing to manufacture.

    The result is emitted in `canonical_order`, never in decision order — see that function.
    """
    from .uninstall_plan import DEREGISTER_ONLY, RECORDED, REMOVE, UNAVAILABLE

    operations = []
    for resource, decision in sorted(decisions.items()):
        verdict = getattr(decision, "decision", None)
        owed = verdict in (REMOVE, DEREGISTER_ONLY) or (
            verdict == UNAVAILABLE and getattr(decision, "authority", None) == RECORDED)
        if not owed:
            continue
        if resource in _ABSORBED_BY:
            if _ABSORBED_BY[resource] not in decisions:
                raise AuthorityIncomplete(
                    f"{resource!r} is carried by {_ABSORBED_BY[resource]!r}, which this plan does "
                    "not remove")
            continue
        builder = _RESOURCE_BUILDERS.get(resource)
        if builder is None:
            raise AuthorityIncomplete(
                f"the plan would remove {resource!r} and nothing derives its authority from the "
                "manifest; a resource with no derivation cannot become pending authority")
        built_one = builder(manifest, resource, flavour)
        # A builder may legitimately return SEVERAL operations — several privilege helpers are
        # several files, and collapsing them was the v1 information loss.
        operations.extend(built_one if isinstance(built_one, tuple) else (built_one,))
    built = canonical_order(tuple(operations))
    _reject_duplicates(built)
    _require_coherence(built)
    _require_order(built)
    return built


def _require(value, what: str):
    if not value:
        raise AuthorityIncomplete(
            f"the manifest does not record {what}; the installation never wrote down what it is "
            "now being asked to remove")
    return value


def _ownership(manifest, kind: str) -> tuple:
    return tuple(e.identifier for e in manifest.ownership if e.kind == kind)


def _exact(resource, path, action, flavour, keep=()):
    return ExactPathOperation(resource=resource, path=str(path), action=action, flavour=flavour,
                              keep=tuple(str(k) for k in keep))


@_builds("install_dir")
@_builds("log_dir")
@_builds("secrets_dir")
def _tree(manifest, resource, flavour):
    return _exact(resource, _require(getattr(manifest.paths, resource, None),
                                     f"paths.{resource}"), PATH_ACTION_REMOVE_TREE, flavour)


@_builds("config_dir")
@_builds("state_dir")
def _clean(manifest, resource, flavour):
    from . import uninstall_inventory as inv

    tree = _require(getattr(manifest.paths, resource, None), f"paths.{resource}")
    keep = [path for _name, path in inv.control_plane_exclusions(flavour, tree)]
    if not keep:
        # **Windows `config` holds no control-plane path** — its locator is in HKLM and its pending
        # record is under `state` — so deriving nothing there is correct, and refusing meant a
        # Windows uninstall could never build a pending record at all. Found by the stage-4
        # coverage gate.
        #
        # The directory ITSELF is what is preserved. §V ruled the fixed control directories stay in
        # place, so the two platforms behave identically: product content goes, the directory
        # remains. Recording the tree as its own kept path says that in the record rather than
        # leaving it to an executor to remember.
        keep = [tree]
    return _exact(resource, tree, PATH_ACTION_CLEAN_TREE, flavour, keep)


@_builds("sandbox")
def _sandbox(manifest, resource, flavour):
    """One hosted-database operation: close, prove unhosted, remove file, then its RC path."""
    owned = _ownership(manifest, "patch_sandbox_rc_path")
    if len(owned) != 1:
        raise AuthorityIncomplete(
            f"the manifest records {len(owned)} sandbox RC paths; exactly one is required")
    return StorageOperation(
        resource=resource,
        database_name="CORPUSfm_Sandbox",
        database_path=_require(manifest.patch.sandbox_file, "patch.sandbox_file"),
        rc_paths=owned,
        fms_root=_require(manifest.paths.fms_root, "paths.fms_root"),
        flavour=flavour)


@_builds("support_dir")
def _support_dir(manifest, resource, flavour):
    owned = _ownership(manifest, "support_directory_path")
    if len(owned) != 1:
        raise AuthorityIncomplete(
            f"the manifest records {len(owned)} support directories; exactly one is required")
    return _exact(resource, owned[0], PATH_ACTION_REMOVE_EMPTY_DIR, flavour)


@_builds("patch_dir")
def _patch_dir(manifest, resource, flavour):
    return _exact(resource, _require(manifest.paths.patch_hosting_dir, "paths.patch_hosting_dir"),
                  PATH_ACTION_REMOVE_EMPTY_DIR, flavour)


@_builds("cli_shim")
def _cli_shim(manifest, resource, flavour):
    owned = _ownership(manifest, "cli_shim_path")
    if len(owned) != 1:
        raise AuthorityIncomplete(f"the manifest records {len(owned)} CLI shims; one is required")
    return _exact(resource, owned[0], PATH_ACTION_REMOVE_FILE, flavour)


@_builds("sudoers_helpers")
def _helpers(manifest, resource, flavour):
    """**Several helpers stay several.** A single-identifier record could name only one, and the
    others would survive an uninstall that reported itself complete."""
    owned = _ownership(manifest, "privilege_helper_path")
    _require(owned, "any privilege helper")
    return tuple(_exact(f"{resource}[{index}]", path, PATH_ACTION_REMOVE_FILE, flavour)
                 for index, path in enumerate(owned))


@_builds("storage_db")
def _storage(manifest, resource, flavour):
    """ONE atomic operation: close, prove unhosted, remove the file, then its RC paths."""
    owned = _ownership(manifest, "storage_database_path")
    if len(owned) != 1:
        raise AuthorityIncomplete(
            f"the manifest records {len(owned)} storage database paths; exactly one is required")
    return StorageOperation(
        resource=resource,
        database_name=_require(manifest.storage.database_name, "storage.database_name"),
        database_path=owned[0],
        rc_paths=_ownership(manifest, "storage_rc_path"),
        fms_root=_require(manifest.paths.fms_root, "paths.fms_root"),
        flavour=flavour)


@_builds("proxy_edits")
def _proxy(manifest, resource, flavour):
    fronts = []
    for proxy_type, entry in sorted((manifest.proxy_policy or {}).items()):
        if not entry.config_location or not entry.config_fingerprint:
            continue
        fronts.append(ProxyFront(proxy_type=proxy_type, config_location=entry.config_location,
                                 config_fingerprint=entry.config_fingerprint))
    _require(fronts, "any proxy front with a location and a fingerprint")
    return ProxyOperation(resource=resource, fronts=tuple(fronts), flavour=flavour)


@_builds("pki")
def _pki(manifest, resource, flavour):
    return PkiOperation(
        resource=resource,
        registration_name=_require(manifest.pki.registration_name, "pki.registration_name"),
        public_fingerprint=_require(manifest.pki.public_fingerprint, "pki.public_fingerprint"),
        secrets_dir=_require(manifest.paths.secrets_dir, "paths.secrets_dir"),
        flavour=flavour)


@_builds("patch_slot")
def _patch_slot(manifest, resource, flavour):
    hosting = _require(manifest.paths.patch_hosting_dir, "paths.patch_hosting_dir")
    module = posixpath if flavour == "posix" else ntpath
    root = module.normpath(hosting)
    scaffolding: set[str] = set()
    for rc_path in _ownership(manifest, "patch_sandbox_rc_path"):
        current = module.dirname(module.normpath(rc_path))
        while not _canonical_eq(current, root, flavour):
            try:
                contained = module.commonpath((module.normcase(root),
                                               module.normcase(current))) == module.normcase(root)
            except ValueError:
                contained = False
            if not contained or current == module.dirname(current):
                raise AuthorityIncomplete(
                    f"the recorded sandbox RC path {rc_path!r} is not inside {hosting!r}")
            scaffolding.add(current)
            current = module.dirname(current)
    return PatchSlotOperation(
        resource=resource, slot=_require(manifest.patch.folder_slot, "patch.folder_slot"),
        hosting_dir=hosting, flavour=flavour,
        scaffolding=tuple(sorted(scaffolding, key=lambda p: (-len(module.normpath(p)), p))))


#: ABSORBED, not unregistered. Each RC classification has real authority carried inside its
#: database's atomic `StorageOperation`. An unregistered resource would refuse, while a silent skip
#: would hide work the plan still owes.
_ABSORBED_BY = {"storage_rc": "storage_db", "sandbox_rc": "sandbox"}


@_builds("service_account")
def _account(manifest, resource, flavour):
    """**Never on Windows.** A `NT SERVICE\\<service>` identity is a VIRTUAL account: the service
    manager creates and destroys it with the service, and there is no separate account to remove.
    Emitting one produced an operation whose only correct execution was to refuse — and an operation
    that can only refuse is a record of work nobody owes.

    Found by the stage-4 coverage gate; corrected here rather than in the executor, because the
    executor refusing it would still leave the pending record claiming the work.
    """
    if flavour == "windows":
        raise AuthorityIncomplete(
            "a Windows service identity is virtual and is removed with its service; there is no "
            "separately owned account, so no account operation may be recorded")
    owned = _ownership(manifest, "service_account")
    if len(owned) != 1:
        raise AuthorityIncomplete(
            f"the manifest records {len(owned)} service accounts; exactly one is required")
    if owned[0].upper().startswith("NT SERVICE\\"):
        raise AuthorityIncomplete(
            f"{owned[0]!r} is a virtual Windows service identity and is not a removable account")
    return AccountOperation(resource=resource, account=owned[0], flavour=flavour)


def _managed_unit(role, *, retired: bool = False):
    """Build the removal operation for one managed unit, from the manifest's own record of it.

    `retired` names a role this build no longer creates but must still be able to remove (packet
    1361-01, round 3: the standalone `corpusfm-scheduler` service). For such a role, ZERO manifest
    entries is not incomplete authority — it is an installation that never registered the unit, so
    there is nothing owed and nothing to manufacture. That is the same rule `remaining_from_plan`
    states for an `UNAVAILABLE` decision with no authority, applied one level down. Two or more
    entries still refuse, because a record that names the same unit twice is not a record anyone
    should delete from.
    """
    def build(manifest, resource, flavour):
        entries = [s for s in manifest.services if s.role == role]
        if retired and not entries:
            return ()
        if len(entries) != 1:
            raise AuthorityIncomplete(
                f"the manifest records {len(entries)} services for role {role!r}; one is required")
        entry = entries[0]
        return ManagedUnitOperation(
            resource=resource, role=role, name=entry.name,
            definition_path=_require(entry.unit, f"services[{role}].unit"),
            expected_identity=_require(entry.identity, f"services[{role}].identity"),
            unit_kind=entry.unit_kind,
            install_dir=_require(manifest.paths.install_dir, "paths.install_dir"),
            flavour=flavour)
    return build


for _resource, _role, _retired in (("web_service", "web", False),
                                   ("scheduler_service", "scheduler", True),
                                   ("updater_task", "updater", False)):
    _RESOURCE_BUILDERS[_resource] = _managed_unit(_role, retired=_retired)
del _resource, _role, _retired
