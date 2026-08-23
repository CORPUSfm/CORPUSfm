"""Versioned lifecycle record structures and their validation (packet 1246-01, deliverable 1).

One schema module for the locator, the installation manifest, the proxy-policy and ownership
sub-records, and the transaction journal. Every one of them is versioned, every one round-trips
through plain JSON, and every one is refused rather than repaired when it does not validate.

**Path handling is flavour-aware on purpose.** A manifest describes the box it was written on, and a
Windows manifest must stay readable (and refusable) when a Linux test, a support session or a future
cross-platform tool opens it. So paths are canonicalized through ``PurePath`` rather than the running
host's ``os.path``: absolute-only, no ``..``, never a filesystem or share root, and — inside one
record — all of one flavour. Mixed flavours are a corrupt record, not a portability feature.

**What this child validates and what it deliberately leaves open.** Structure, versions, identity,
path shape and the parent-ruled vocabularies (result words, proxy types, policy values, ownership
classes, migration states) are enforced here. The *content* those blocks will eventually carry
belongs to later children — 1246-07 owns what a PKI observation may say, 1246-06 owns what a proxy
transaction records, 1246-09 owns how a resource is classified. Blocks are therefore optional and
their free-form fields stay free-form: requiring what a later child has not built yet would make
this substrate unusable by the very installs it has to keep working.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any, Mapping

from .errors import IdentityMismatch, RecordInvalid, SchemaVersionUnsupported
from .result import RESULT_VOCABULARY

LOCATOR_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 2
READABLE_MANIFEST_SCHEMA_VERSIONS: tuple[int, ...] = (1, MANIFEST_SCHEMA_VERSION)
JOURNAL_SCHEMA_VERSION = 1

DEFAULT_MANIFEST_RELPATH = "manifest/installation.json"

PROXY_TYPES: tuple[str, ...] = ("fms-nginx", "apache", "iis", "claris-nginx")
PROXY_POLICIES: tuple[str, ...] = ("managed", "ignored")

#: Imported here so a manifest can validate what it stores. `service_identity` imports nothing from
#: this module, so the direction of dependency is unchanged.
from .service_identity import (  # noqa: E402  (placed with the vocabularies it belongs beside)
    MANAGED_ROLES,
    UNIT_KIND_SERVICE,
    UNIT_KINDS,
)

OWNERSHIP_CLASSES: tuple[str, ...] = (
    "exclusive_tree",
    "exact_resource",
    "shared_conditional",
    "never_owned",
)

#: The CLOSED ownership-kind vocabulary (packet 1246-09, stage 1). An ownership entry exists to
#: authorize a deletion, so an open vocabulary would let any future caller invent a kind and have it
#: honoured. Each kind names ONE semantic resource; `PATH_BEARING_KINDS` are the ones whose
#: identifier is a filesystem path and are canonicalized on the way in.
#:
#: The vocabulary is deliberately small. `ownership` records only what has no OTHER exact authority:
#: `PathsBlock` still owns the six exclusive trees, `patch.sandbox_file` still owns the sandbox file,
#: and neither is duplicated here — two authorities for one resource is how they drift apart.
OWNERSHIP_KIND_STORAGE_DATABASE = "storage_database_path"
OWNERSHIP_KIND_STORAGE_RC = "storage_rc_path"
OWNERSHIP_KIND_PATCH_SANDBOX_RC = "patch_sandbox_rc_path"
OWNERSHIP_KIND_CLI_SHIM = "cli_shim_path"
OWNERSHIP_KIND_PRIVILEGE_HELPER = "privilege_helper_path"
OWNERSHIP_KIND_SERVICE_ACCOUNT = "service_account"
OWNERSHIP_KIND_SUPPORT_DIRECTORY = "support_directory_path"

OWNERSHIP_KINDS: tuple[str, ...] = (
    OWNERSHIP_KIND_STORAGE_DATABASE,
    OWNERSHIP_KIND_STORAGE_RC,
    OWNERSHIP_KIND_PATCH_SANDBOX_RC,
    OWNERSHIP_KIND_CLI_SHIM,
    OWNERSHIP_KIND_PRIVILEGE_HELPER,
    OWNERSHIP_KIND_SERVICE_ACCOUNT,
    OWNERSHIP_KIND_SUPPORT_DIRECTORY,
)

#: Identifiers that are paths, and are therefore canonicalized and compared as paths.
PATH_BEARING_KINDS: frozenset[str] = frozenset({
    OWNERSHIP_KIND_STORAGE_DATABASE,
    OWNERSHIP_KIND_STORAGE_RC,
    OWNERSHIP_KIND_PATCH_SANDBOX_RC,
    OWNERSHIP_KIND_CLI_SHIM,
    OWNERSHIP_KIND_PRIVILEGE_HELPER,
    OWNERSHIP_KIND_SUPPORT_DIRECTORY,
})

#: Kinds of which an installation may hold AT MOST ONE. A second `storage_database_path` is not a
#: second database; it is a record that cannot be acted on, because nothing says which one is real.
SINGLETON_KINDS: frozenset[str] = frozenset({
    OWNERSHIP_KIND_STORAGE_DATABASE,
    OWNERSHIP_KIND_PATCH_SANDBOX_RC,
    OWNERSHIP_KIND_SERVICE_ACCOUNT,
    OWNERSHIP_KIND_SUPPORT_DIRECTORY,
})

#: Which provider may contribute which kinds. Composition rejects anything outside its caller's row,
#: so one provider can never write, replace, or shadow another's ownership.
OWNERSHIP_KINDS_BY_PRODUCER: dict[str, frozenset[str]] = {
    "foundation": frozenset({OWNERSHIP_KIND_CLI_SHIM, OWNERSHIP_KIND_PRIVILEGE_HELPER,
                             OWNERSHIP_KIND_SERVICE_ACCOUNT,
                             OWNERSHIP_KIND_SUPPORT_DIRECTORY}),
    "storage": frozenset({OWNERSHIP_KIND_STORAGE_DATABASE, OWNERSHIP_KIND_STORAGE_RC}),
    "patch": frozenset({OWNERSHIP_KIND_PATCH_SANDBOX_RC}),
}

MIGRATION_NOT_MIGRATED = "not_migrated"
MIGRATION_BRIDGED = "bridged"
MIGRATION_NATIVE = "native"
MIGRATION_STATES: tuple[str, ...] = (
    MIGRATION_NOT_MIGRATED,
    MIGRATION_BRIDGED,
    MIGRATION_NATIVE,
)

# The key migration's own durable record (packet 1246-02). Its OWN type, deliberately: an earlier
# version wrote key paths into `migration.consumers`, whose values are authority OWNERS from a fixed
# vocabulary — a path is not an owner, and a real validating store rejected it. Overloading a schema
# to avoid adding one is how a field comes to mean two things.
KEY_MIGRATION_PREPARED = "prepared"
KEY_MIGRATION_ACTIVATED = "activated"
KEY_MIGRATION_VERIFIED = "verified"
KEY_MIGRATION_COMMITTED = "committed"
KEY_MIGRATION_STATES: tuple[str, ...] = (
    KEY_MIGRATION_PREPARED,
    KEY_MIGRATION_ACTIVATED,
    KEY_MIGRATION_VERIFIED,
    KEY_MIGRATION_COMMITTED,
)
KEY_ROLES: tuple[str, ...] = ("corpus", "machine")
KEY_SOURCE_KINDS: tuple[str, ...] = ("file", "environment")

CONSUMER_INSTALL_YAML = "install_yaml"
CONSUMER_LIFECYCLE = "lifecycle_manifest"
CONSUMER_OWNERS: tuple[str, ...] = (CONSUMER_INSTALL_YAML, CONSUMER_LIFECYCLE)

JOURNAL_OPEN = "open"
JOURNAL_CHECKPOINTED = "checkpointed"
JOURNAL_NEEDS_RECOVERY = "needs_recovery"
JOURNAL_RESOLVED = "resolved"
JOURNAL_STATES: tuple[str, ...] = (
    JOURNAL_OPEN,
    JOURNAL_CHECKPOINTED,
    JOURNAL_NEEDS_RECOVERY,
    JOURNAL_RESOLVED,
)

# Permitted transitions. An enum is not a state machine: without this, a resolved operation could be
# checkpointed back into life, and an operation could be resolved twice with different results.
# `None` is the starting point — no record on disk.
JOURNAL_TRANSITIONS: dict[str | None, frozenset[str]] = {
    None: frozenset({JOURNAL_OPEN}),
    JOURNAL_OPEN: frozenset({JOURNAL_CHECKPOINTED, JOURNAL_NEEDS_RECOVERY, JOURNAL_RESOLVED}),
    JOURNAL_CHECKPOINTED: frozenset(
        {JOURNAL_CHECKPOINTED, JOURNAL_NEEDS_RECOVERY, JOURNAL_RESOLVED}
    ),
    JOURNAL_NEEDS_RECOVERY: frozenset(
        {JOURNAL_CHECKPOINTED, JOURNAL_NEEDS_RECOVERY, JOURNAL_RESOLVED}
    ),
    # A resolved operation is over. Beginning the NEXT one is a fresh record, handled as `None`.
    JOURNAL_RESOLVED: frozenset({JOURNAL_OPEN}),
}


def assert_transition(current: str | None, target: str) -> None:
    """Refuse a journal state change the lifecycle does not permit."""
    allowed = JOURNAL_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise RecordInvalid(
            f"journal transition {current or 'none'} -> {target} is not permitted; "
            f"allowed from {current or 'none'}: {', '.join(sorted(allowed)) or 'nothing'}"
        )

# The COMPLETE set of operations that take the machine lifecycle lock and therefore journal,
# reconciled against every 1246 child at authoring time. Deliverable 4 says the one lock covers
# "installer, uninstaller, proxy mutations, recovery adoption and privileged update" — the first
# draft encoded only D5's four installer MODES and would have forced 1246-02, 1246-03 and 1246-06 to
# reopen schema 1 just to name their own operations. A later child adding a mode is a schema
# version bump; that must not be the cost of using the journal as designed.
#
#   fresh_install         1246-04  first installation
#   forward_update        1246-04  elevated installer update
#   installer_identity    compatibility-series adoption/advance after verified source deployment
#   code_update           1246-03  the one-shot privileged code-only updater the web identity triggers
#   repair_storage_access 1246-08  the narrow automation-credential repair mode
#   proxy_policy          1246-06  corpusfm-proxy add / ignore / remove / reconcile (status is read-only)
#   recovery_create       1246-02  corpusfm-recovery create
#   recovery_adopt        1246-02  corpusfm-recovery adopt
#   uninstall             1246-09  removal, including a resumed pending cleanup
LIFECYCLE_MODES: tuple[str, ...] = (
    "fresh_install",
    "forward_update",
    "installer_identity",
    "code_update",
    "repair_storage_access",
    "proxy_policy",
    "recovery_create",
    "recovery_adopt",
    "uninstall",
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── path canonicalization ─────────────────────────────────────────────────────────────────────


def path_flavour(value: str) -> str:
    """``"windows"`` for a drive-letter or UNC path, ``"posix"`` for a rooted slash path."""
    if re.match(r"^[A-Za-z]:[\\/]", value) or value.startswith("\\\\"):
        return "windows"
    return "posix"


def _pure(value: str) -> PurePath:
    return PureWindowsPath(value) if path_flavour(value) == "windows" else PurePosixPath(value)


def canonical_path(value: object, *, field_name: str) -> str:
    """Return the canonical absolute form of ``value``, or raise ``RecordInvalid``.

    Filesystem state is never consulted — a manifest is validated on boxes where the paths it names
    do not exist (a support copy, a test, a cross-platform reader), and existence is a question for
    the operation that uses the path, not for the record that holds it.
    """
    if not isinstance(value, str) or not value.strip():
        raise RecordInvalid(f"{field_name} must be a non-empty path string")
    pure = _pure(value)
    if not pure.is_absolute():
        raise RecordInvalid(f"{field_name} must be an absolute path, got {value!r}")
    if ".." in pure.parts:
        raise RecordInvalid(f"{field_name} must not contain '..', got {value!r}")
    if pure.parent == pure:
        raise RecordInvalid(f"{field_name} must not be a filesystem or share root, got {value!r}")
    return str(pure)


def canonical_relative_path(value: object, *, field_name: str) -> str:
    """Return the canonical form of a path that must stay INSIDE its base."""
    if not isinstance(value, str) or not value.strip():
        raise RecordInvalid(f"{field_name} must be a non-empty relative path")
    pure = PurePosixPath(value.replace("\\", "/"))
    if pure.is_absolute():
        raise RecordInvalid(f"{field_name} must be relative, got {value!r}")
    if ".." in pure.parts:
        raise RecordInvalid(f"{field_name} must not escape its base, got {value!r}")
    return str(pure)


def _comparable(value: str) -> tuple[str, ...]:
    pure = _pure(value)
    parts = pure.parts
    return tuple(p.lower() for p in parts) if isinstance(pure, PureWindowsPath) else parts


def same_path(a: str, b: str) -> bool:
    """Path equality as this record model defines it: flavour-aware, Windows case-insensitive."""
    return path_flavour(a) == path_flavour(b) and _comparable(a) == _comparable(b)


def paths_overlap(a: str, b: str) -> bool:
    """True when one path is the other, or contains it. Different flavours never overlap."""
    if path_flavour(a) != path_flavour(b):
        return False
    pa, pb = _comparable(a), _comparable(b)
    short, long_ = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    return long_[: len(short)] == short


def _assert_one_flavour(named: Mapping[str, str]) -> None:
    flavours = {path_flavour(v) for v in named.values() if v}
    if len(flavours) > 1:
        raise RecordInvalid(
            "a lifecycle record must describe one machine: mixed path flavours in "
            + ", ".join(sorted(named))
        )


def _assert_pairwise_disjoint(named: Mapping[str, str]) -> None:
    items = [(k, v) for k, v in named.items() if v]
    for i, (name_a, value_a) in enumerate(items):
        for name_b, value_b in items[i + 1:]:
            if paths_overlap(value_a, value_b):
                raise RecordInvalid(
                    f"{name_a} and {name_b} overlap ({value_a} / {value_b}); "
                    "lifecycle paths must be disjoint so removal of one cannot take another"
                )


def _require_version(value: object, expected: int, *, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RecordInvalid(f"{what} schema_version must be an integer, got {value!r}")
    if value != expected:
        raise SchemaVersionUnsupported(
            f"{what} declares schema_version {value}; this build implements {expected}"
        )
    return value


def _require_uuid(value: object, *, what: str) -> str:
    if not isinstance(value, str) or not _UUID_RE.match(value):
        raise RecordInvalid(f"{what} installation_id must be a UUID, got {value!r}")
    return value.lower()


def _require_mapping(value: object, *, what: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RecordInvalid(f"{what} must be an object, got {type(value).__name__}")
    return dict(value)


def _reject_unknown(raw: Mapping[str, Any], allowed: "set[str] | frozenset[str]", *, what: str) -> None:
    """Refuse a field this build does not know.

    Silently discarding an unrecognized key is the quiet version of the drift D2 exists to stop: a
    misspelled ownership entry or policy field validates, is dropped on the next write, and the
    authoritative record is incomplete with nothing to show for it. An unknown field is either a
    typo or a newer schema, and both are refusals — the version fence names the second case.
    """
    unknown = set(raw) - set(allowed)
    if unknown:
        raise RecordInvalid(f"{what} has unknown field(s): " + ", ".join(sorted(unknown)))


def _optional_str(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise RecordInvalid(f"{field_name} must be a string or null")
    return value


# ── locator ───────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LocatorRecord:
    """The machine-wide pointer. Deliberately the smallest object in the system.

    D2 allows it three facts and no more: which installation this is, where its software root is,
    and where inside that root the authoritative manifest sits. Everything else was rejected — a
    locator that grows policy becomes a second mutable store, and the two then drift.
    """

    installation_id: str
    install_dir: str
    manifest_relative_path: str = DEFAULT_MANIFEST_RELPATH
    schema_version: int = LOCATOR_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "installation_id": self.installation_id,
            "install_dir": self.install_dir,
            "manifest_relative_path": self.manifest_relative_path,
        }

    @staticmethod
    def from_dict(data: object) -> "LocatorRecord":
        raw = _require_mapping(data, what="locator")
        version = _require_version(
            raw.get("schema_version"), LOCATOR_SCHEMA_VERSION, what="locator"
        )
        unknown = set(raw) - {
            "schema_version",
            "installation_id",
            "install_dir",
            "manifest_relative_path",
        }
        if unknown:
            raise RecordInvalid(
                "locator carries fields it is not allowed to hold: " + ", ".join(sorted(unknown))
            )
        return LocatorRecord(
            installation_id=_require_uuid(raw.get("installation_id"), what="locator"),
            install_dir=canonical_path(raw.get("install_dir"), field_name="locator.install_dir"),
            manifest_relative_path=canonical_relative_path(
                raw.get("manifest_relative_path", DEFAULT_MANIFEST_RELPATH),
                field_name="locator.manifest_relative_path",
            ),
            schema_version=version,
        )

    def validated(self) -> "LocatorRecord":
        return LocatorRecord.from_dict(self.to_dict())


# ── manifest blocks ───────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PathsBlock:
    install_dir: str
    patch_hosting_dir: str | None = None
    fms_root: str | None = None
    config_dir: str | None = None
    state_dir: str | None = None
    secrets_dir: str | None = None
    log_dir: str | None = None
    run_dir: str | None = None

    def as_mapping(self) -> dict[str, str]:
        return {k: v for k, v in self.to_dict().items() if v}

    def to_dict(self) -> dict[str, Any]:
        return {
            "install_dir": self.install_dir,
            "patch_hosting_dir": self.patch_hosting_dir,
            "fms_root": self.fms_root,
            "config_dir": self.config_dir,
            "state_dir": self.state_dir,
            "secrets_dir": self.secrets_dir,
            "log_dir": self.log_dir,
            "run_dir": self.run_dir,
        }

    @staticmethod
    def from_dict(data: object) -> "PathsBlock":
        raw = _require_mapping(data, what="manifest.paths")
        known = set(PathsBlock.__dataclass_fields__)
        unknown = set(raw) - known
        if unknown:
            raise RecordInvalid("manifest.paths unknown fields: " + ", ".join(sorted(unknown)))
        values: dict[str, str | None] = {}
        for name in known:
            value = raw.get(name)
            if name == "install_dir":
                values[name] = canonical_path(value, field_name="paths.install_dir")
            elif value is None:
                values[name] = None
            else:
                values[name] = canonical_path(value, field_name=f"paths.{name}")
        block = PathsBlock(**values)  # type: ignore[arg-type]
        named = block.as_mapping()
        _assert_one_flavour(named)
        _assert_pairwise_disjoint(named)
        return block


@dataclass(frozen=True)
class BuildBlock:
    version: str | None = None
    commit: str | None = None
    observed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "commit": self.commit, "observed_at": self.observed_at}

    @staticmethod
    def from_dict(data: object) -> "BuildBlock":
        raw = _require_mapping(data, what="manifest.build")
        _reject_unknown(raw, {"version", "commit", "observed_at"}, what="manifest.build")
        return BuildBlock(
            version=_optional_str(raw.get("version"), field_name="build.version"),
            commit=_optional_str(raw.get("commit"), field_name="build.commit"),
            observed_at=_optional_str(raw.get("observed_at"), field_name="build.observed_at"),
        )


@dataclass(frozen=True)
class InstallerBlock:
    """Installer identity, separate from the application build it delivered."""

    series: str | None = None
    version: str | None = None
    bundle_protocol: int | None = None
    source: str | None = None
    entry_point: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "series": self.series,
            "version": self.version,
            "bundle_protocol": self.bundle_protocol,
            "source": self.source,
            "entry_point": self.entry_point,
        }

    @staticmethod
    def from_dict(data: object) -> "InstallerBlock":
        raw = _require_mapping(data, what="manifest.installer")
        _reject_unknown(raw, {"series", "version", "bundle_protocol", "source", "entry_point"},
                        what="manifest.installer")
        entry_point = raw.get("entry_point")
        values = (raw.get("series"), raw.get("version"), raw.get("bundle_protocol"),
                  raw.get("source"))
        if all(value is None for value in values):
            if entry_point is not None:
                raise RecordInvalid(
                    "manifest.installer.entry_point requires a complete installer identity")
            return InstallerBlock()
        if any(value is None for value in values):
            raise RecordInvalid("manifest.installer identity must be complete or wholly absent")
        series, version, protocol, source = values
        if not isinstance(series, str) or re.fullmatch(r"series-[1-9][0-9]*", series) is None:
            raise RecordInvalid(f"manifest.installer.series is invalid: {series!r}")
        if not isinstance(version, str) or re.fullmatch(r"0\.[0-9]+", version) is None:
            raise RecordInvalid(f"manifest.installer.version is invalid: {version!r}")
        if not isinstance(protocol, int) or isinstance(protocol, bool) or protocol < 1:
            raise RecordInvalid(
                f"manifest.installer.bundle_protocol must be a positive integer, got {protocol!r}")
        if source not in ("package", "development"):
            raise RecordInvalid(
                "manifest.installer.source must be 'package' or 'development', "
                f"got {source!r}")
        return InstallerBlock(
            series=series, version=version, bundle_protocol=protocol, source=str(source),
            entry_point=(
                None if entry_point is None
                else canonical_path(entry_point, field_name="installer.entry_point")
            ),
        )


@dataclass(frozen=True)
class UninstallerBlock:
    """The canonical launcher provisioned by this installation.

    The lifecycle runtime already lives beneath ``paths.install_dir``.  This block names the
    installed entry point separately so a source file left in the checkout is never mistaken for
    an installer-provisioned uninstaller.
    """

    entry_point: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"entry_point": self.entry_point}

    @staticmethod
    def from_dict(data: object) -> "UninstallerBlock":
        raw = _require_mapping(data, what="manifest.uninstaller")
        _reject_unknown(raw, {"entry_point"}, what="manifest.uninstaller")
        value = raw.get("entry_point")
        return UninstallerBlock(
            entry_point=(
                None if value is None
                else canonical_path(value, field_name="uninstaller.entry_point")
            )
        )


@dataclass(frozen=True)
class WebBlock:
    internal_port: int | None = None
    prefix: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"internal_port": self.internal_port, "prefix": self.prefix}

    @staticmethod
    def from_dict(data: object) -> "WebBlock":
        raw = _require_mapping(data, what="manifest.web")
        _reject_unknown(raw, {"internal_port", "prefix"}, what="manifest.web")
        port = raw.get("internal_port")
        if port is not None and (not isinstance(port, int) or isinstance(port, bool)
                                 or not 1 <= port <= 65535):
            raise RecordInvalid(f"web.internal_port must be a TCP port, got {port!r}")
        prefix = _optional_str(raw.get("prefix"), field_name="web.prefix")
        if prefix is not None and not prefix.startswith("/"):
            raise RecordInvalid(f"web.prefix must start with '/', got {prefix!r}")
        return WebBlock(internal_port=port, prefix=prefix)


@dataclass(frozen=True)
class ServiceEntry:
    """One managed unit this installation created.

    `unit_kind` exists because **removal differs by kind**: a systemd unit is disabled, a WinSW
    service is `sc delete`d, and a scheduled task is unregistered. The privileged updater is a
    scheduled task on Windows and a one-shot unit on POSIX, and it was recorded nowhere at all until
    packet 1246-09 §Y — so an uninstall had to invent its name and path, which is the category of
    authority this packet exists to retire.
    """

    name: str
    role: str
    identity: str | None = None
    unit: str | None = None
    unit_kind: str = UNIT_KIND_SERVICE

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "identity": self.identity,
            "unit": self.unit,
            "unit_kind": self.unit_kind,
        }

    @staticmethod
    def from_dict(data: object) -> "ServiceEntry":
        raw = _require_mapping(data, what="manifest.services[]")
        _reject_unknown(raw, {"name", "role", "identity", "unit", "unit_kind"},
                        what="manifest.services[]")
        name = raw.get("name")
        role = raw.get("role")
        if not isinstance(name, str) or not name:
            raise RecordInvalid("service entry needs a name")
        if not isinstance(role, str) or not role:
            raise RecordInvalid(f"service {name!r} needs a role")
        if role not in MANAGED_ROLES:
            raise RecordInvalid(
                f"service {name!r} names role {role!r}; the managed roles are {MANAGED_ROLES}")
        kind = raw.get("unit_kind", UNIT_KIND_SERVICE)
        if kind not in UNIT_KINDS:
            raise RecordInvalid(
                f"service {name!r} has unit_kind {kind!r}; the kinds are {UNIT_KINDS}")
        return ServiceEntry(
            name=name,
            role=role,
            identity=_optional_str(raw.get("identity"), field_name="service.identity"),
            unit=_optional_str(raw.get("unit"), field_name="service.unit"),
            unit_kind=kind,
        )


@dataclass(frozen=True)
class StorageBlock:
    """Storage IDENTITY, never storage access. No credential field exists to be filled in."""

    database_name: str | None = None
    corpus_id: str | None = None
    connection_name: str | None = None
    initialized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "database_name": self.database_name,
            "corpus_id": self.corpus_id,
            "connection_name": self.connection_name,
            "initialized": self.initialized,
        }

    @staticmethod
    def from_dict(data: object) -> "StorageBlock":
        raw = _require_mapping(data, what="manifest.storage")
        _reject_unknown(raw, {"database_name", "corpus_id", "connection_name", "initialized"}, what="manifest.storage")
        initialized = raw.get("initialized", False)
        if not isinstance(initialized, bool):
            raise RecordInvalid("storage.initialized must be a boolean")
        return StorageBlock(
            database_name=_optional_str(raw.get("database_name"), field_name="storage.database_name"),
            corpus_id=_optional_str(raw.get("corpus_id"), field_name="storage.corpus_id"),
            connection_name=_optional_str(
                raw.get("connection_name"), field_name="storage.connection_name"
            ),
            initialized=initialized,
        )


@dataclass(frozen=True)
class PatchBlock:
    folder_slot: str | None = None
    registered: bool = False
    verified: bool = False
    sandbox_file: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "folder_slot": self.folder_slot,
            "registered": self.registered,
            "verified": self.verified,
            "sandbox_file": self.sandbox_file,
        }

    @staticmethod
    def from_dict(data: object) -> "PatchBlock":
        raw = _require_mapping(data, what="manifest.patch")
        _reject_unknown(raw, {"folder_slot", "registered", "verified", "sandbox_file"}, what="manifest.patch")
        for flag in ("registered", "verified"):
            if not isinstance(raw.get(flag, False), bool):
                raise RecordInvalid(f"patch.{flag} must be a boolean")
        return PatchBlock(
            folder_slot=_optional_str(raw.get("folder_slot"), field_name="patch.folder_slot"),
            registered=bool(raw.get("registered", False)),
            verified=bool(raw.get("verified", False)),
            sandbox_file=_optional_str(raw.get("sandbox_file"), field_name="patch.sandbox_file"),
        )


@dataclass(frozen=True)
class PkiBlock:
    """Name, public fingerprint and observation only. There is no field a PEM could live in."""

    registration_name: str | None = None
    public_fingerprint: str | None = None
    last_observation: str | None = None
    last_success_utc: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "registration_name": self.registration_name,
            "public_fingerprint": self.public_fingerprint,
            "last_observation": self.last_observation,
            "last_success_utc": self.last_success_utc,
        }

    @staticmethod
    def from_dict(data: object) -> "PkiBlock":
        raw = _require_mapping(data, what="manifest.pki")
        _reject_unknown(raw, {"registration_name", "public_fingerprint", "last_observation", "last_success_utc"}, what="manifest.pki")
        return PkiBlock(
            registration_name=_optional_str(
                raw.get("registration_name"), field_name="pki.registration_name"
            ),
            public_fingerprint=_optional_str(
                raw.get("public_fingerprint"), field_name="pki.public_fingerprint"
            ),
            last_observation=_optional_str(
                raw.get("last_observation"), field_name="pki.last_observation"
            ),
            last_success_utc=_optional_str(
                raw.get("last_success_utc"), field_name="pki.last_success_utc"
            ),
        )


@dataclass(frozen=True)
class ProxyPolicyEntry:
    """CORPUSfm's RESPONSIBILITY for one front — not a claim that the front exists (D9)."""

    policy: str
    detected: bool = False
    active: bool | None = None
    config_location: str | None = None
    config_fingerprint: str | None = None
    last_result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy,
            "detected": self.detected,
            "active": self.active,
            "config_location": self.config_location,
            "config_fingerprint": self.config_fingerprint,
            "last_result": self.last_result,
        }

    @staticmethod
    def from_dict(data: object, *, proxy_type: str) -> "ProxyPolicyEntry":
        raw = _require_mapping(data, what=f"manifest.proxy_policy[{proxy_type}]")
        _reject_unknown(
            raw,
            {"policy", "detected", "active", "config_location", "config_fingerprint", "last_result"},
            what=f"manifest.proxy_policy[{proxy_type}]",
        )
        policy = raw.get("policy")
        if policy not in PROXY_POLICIES:
            raise RecordInvalid(
                f"proxy_policy[{proxy_type}].policy must be one of {PROXY_POLICIES}, got {policy!r}"
            )
        detected = raw.get("detected", False)
        if not isinstance(detected, bool):
            raise RecordInvalid(f"proxy_policy[{proxy_type}].detected must be a boolean")
        active = raw.get("active")
        if active is not None and not isinstance(active, bool):
            raise RecordInvalid(f"proxy_policy[{proxy_type}].active must be a boolean or null")
        last_result = raw.get("last_result")
        if last_result is not None and last_result not in RESULT_VOCABULARY:
            raise RecordInvalid(
                f"proxy_policy[{proxy_type}].last_result must be a lifecycle result, "
                f"got {last_result!r}"
            )
        location = raw.get("config_location")
        if location is not None:
            location = canonical_path(
                location, field_name=f"proxy_policy[{proxy_type}].config_location"
            )
        return ProxyPolicyEntry(
            policy=str(policy),
            detected=detected,
            active=active,
            config_location=location,
            config_fingerprint=_optional_str(
                raw.get("config_fingerprint"),
                field_name=f"proxy_policy[{proxy_type}].config_fingerprint",
            ),
            last_result=last_result,
        )


@dataclass(frozen=True)
class OwnershipEntry:
    """One recorded resource and the class that decides what removal may do to it (D13)."""

    ownership_class: str
    kind: str
    identifier: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "ownership_class": self.ownership_class,
            "kind": self.kind,
            "identifier": self.identifier,
        }

    @staticmethod
    def from_dict(data: object) -> "OwnershipEntry":
        raw = _require_mapping(data, what="manifest.ownership[]")
        _reject_unknown(raw, {"ownership_class", "kind", "identifier"}, what="manifest.ownership[]")
        klass = raw.get("ownership_class")
        if klass not in OWNERSHIP_CLASSES:
            raise RecordInvalid(
                f"ownership_class must be one of {OWNERSHIP_CLASSES}, got {klass!r}"
            )
        kind = raw.get("kind")
        identifier = raw.get("identifier")
        if not isinstance(kind, str) or not kind:
            raise RecordInvalid("ownership entry needs a kind")
        # THE CLOSED VOCABULARY. This used to accept any non-empty string and canonicalize only the
        # literal kind `"path"` — so an entry could name an unknown kind, carry an uncanonicalized
        # path, and still validate. An ownership entry authorizes a deletion; an unrecognised one
        # authorizes a deletion nobody defined.
        if kind not in OWNERSHIP_KINDS:
            raise RecordInvalid(
                f"ownership kind must be one of {OWNERSHIP_KINDS}, got {kind!r}"
            )
        if not isinstance(identifier, str) or not identifier:
            raise RecordInvalid("ownership entry needs an identifier")
        if kind in PATH_BEARING_KINDS:
            identifier = canonical_path(identifier, field_name=f"ownership[{kind}].identifier")
        return OwnershipEntry(ownership_class=str(klass), kind=kind, identifier=identifier)

    @property
    def semantic_resource(self) -> str:
        """What this entry is ABOUT. Two entries with the same semantic resource are a conflict,
        even when their identifiers differ — especially then, because nothing says which is real."""
        return self.kind if self.kind in SINGLETON_KINDS else f"{self.kind}:{self.identifier}"


def _is_inside(candidate: str, container: str) -> bool:
    """Whether `candidate` lies beneath `container`, on EITHER separator.

    The first version tested `candidate.startswith(container.rstrip("/") + "/")`, which is blind on
    Windows: `canonical_path` returns `str(PureWindowsPath(...))`, and that never emits a forward
    slash — so two genuinely nested Windows ownership paths passed validation while the identical
    POSIX pair was refused. An overlap rule that only works on one platform is not an overlap rule.
    """
    trimmed = container.rstrip("/\\")
    return any(candidate.startswith(trimmed + sep) for sep in ("/", "\\"))


def _reject_ownership_conflicts(entries: "tuple[OwnershipEntry, ...]") -> None:
    """Uniqueness by SEMANTIC RESOURCE and by IDENTIFIER, plus path overlap (packet 1246-09, S1).

    Three distinct ways an ownership table stops being an authority, and each is refused:

    * **two entries for one semantic resource** — two `storage_database_path` rows do not describe
      two databases, they describe a record nobody can act on;
    * **two entries sharing an identifier** — the same path claimed under two kinds means two
      different removal rules apply to one file;
    * **one path CONTAINING another** — removing the outer takes the inner with it, so a rule that
      preserves the inner is a rule that cannot be honoured.

    A conflicting table refuses at parse, so it can never reach a planner.
    """
    by_resource: dict[str, str] = {}
    by_identifier: dict[str, str] = {}
    for entry in entries:
        resource = entry.semantic_resource
        if resource in by_resource:
            raise RecordInvalid(
                f"manifest.ownership holds two entries for {resource!r}; an ownership table with a "
                "duplicate semantic resource cannot authorize anything"
            )
        by_resource[resource] = entry.kind
        if entry.identifier in by_identifier:
            raise RecordInvalid(
                f"manifest.ownership claims {entry.identifier!r} under both "
                f"{by_identifier[entry.identifier]!r} and {entry.kind!r}"
            )
        by_identifier[entry.identifier] = entry.kind
    paths = sorted((e.identifier, e.kind) for e in entries if e.kind in PATH_BEARING_KINDS)
    for index, (identifier, kind) in enumerate(paths):
        for other, other_kind in paths[index + 1:]:
            if other == identifier or _is_inside(other, identifier):
                raise RecordInvalid(
                    f"manifest.ownership entry {other_kind!r} ({other!r}) lies inside "
                    f"{kind!r} ({identifier!r}); overlapping ownership cannot be honoured"
                )


def _reject_service_conflicts(entries: "tuple[ServiceEntry, ...]") -> None:
    """One entry per role and one per name. A second entry for a role makes the recorded service
    ambiguous exactly where the uninstaller needs it to be exact."""
    roles: set[str] = set()
    names: set[str] = set()
    for entry in entries:
        if entry.role in roles:
            raise RecordInvalid(f"manifest.services holds two entries for role {entry.role!r}")
        if entry.name in names:
            raise RecordInvalid(f"manifest.services holds two entries named {entry.name!r}")
        roles.add(entry.role)
        names.add(entry.name)


@dataclass(frozen=True)
class MigrationBlock:
    """How much of this installation the lifecycle record actually owns yet (deliverable 6).

    The transitional bridge cannot flip every consumer at once, and a boolean "migrated" would hide
    exactly the state later children have to work in. So the state is named and the consumers are
    listed individually, each pointing at whichever store is still authoritative for it.
    """

    state: str = MIGRATION_NOT_MIGRATED
    source_marker: str | None = None
    bridged_at: str | None = None
    consumers: dict[str, str] = field(default_factory=dict)
    key_locations: "KeyMigrationRecord | None" = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "source_marker": self.source_marker,
            "bridged_at": self.bridged_at,
            "consumers": dict(self.consumers),
            "key_locations": None if self.key_locations is None else self.key_locations.to_dict(),
        }

    @staticmethod
    def from_dict(data: object) -> "MigrationBlock":
        raw = _require_mapping(data, what="manifest.migration")
        _reject_unknown(raw, {"state", "source_marker", "bridged_at", "consumers", "key_locations"},
                        what="manifest.migration")
        state = raw.get("state", MIGRATION_NOT_MIGRATED)
        if state not in MIGRATION_STATES:
            raise RecordInvalid(
                f"migration.state must be one of {MIGRATION_STATES}, got {state!r}"
            )
        consumers_raw = raw.get("consumers") or {}
        consumers = _require_mapping(consumers_raw, what="manifest.migration.consumers")
        for name, owner in consumers.items():
            if owner not in CONSUMER_OWNERS:
                raise RecordInvalid(
                    f"migration.consumers[{name}] must be one of {CONSUMER_OWNERS}, got {owner!r}"
                )
        marker = raw.get("source_marker")
        if marker is not None:
            marker = canonical_path(marker, field_name="migration.source_marker")
        return MigrationBlock(
            state=str(state),
            source_marker=marker,
            bridged_at=_optional_str(raw.get("bridged_at"), field_name="migration.bridged_at"),
            consumers={str(k): str(v) for k, v in consumers.items()},
            key_locations=(None if raw.get("key_locations") in (None, {})
                           else KeyMigrationRecord.from_dict(raw.get("key_locations"))),
        )


@dataclass(frozen=True)
class KeyMigrationRecord:
    """Where this installation's keys live and how far their migration got.

    **Locations only — never key material.** The paths are canonicalized and the whole block goes
    through the secret fence like every other part of the manifest, so a role can never become a
    place somebody parks bytes.
    """

    state: str
    source_kind: str = "file"
    paths: dict[str, str] = field(default_factory=dict)
    activated_utc: str | None = None
    committed_utc: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "source_kind": self.source_kind,
            "paths": dict(self.paths),
            "activated_utc": self.activated_utc,
            "committed_utc": self.committed_utc,
        }

    @staticmethod
    def from_dict(data: object) -> "KeyMigrationRecord":
        raw = _require_mapping(data, what="manifest.migration.key_locations")
        _reject_unknown(
            raw,
            {"state", "source_kind", "paths", "activated_utc", "committed_utc"},
            what="manifest.migration.key_locations",
        )
        state = raw.get("state")
        if state not in KEY_MIGRATION_STATES:
            raise RecordInvalid(
                f"migration.key_locations.state must be one of {KEY_MIGRATION_STATES}, got {state!r}"
            )
        source_kind = raw.get("source_kind", "file")
        if source_kind not in KEY_SOURCE_KINDS:
            raise RecordInvalid(
                f"migration.key_locations.source_kind must be one of {KEY_SOURCE_KINDS}, got {source_kind!r}"
            )
        locations_raw = _require_mapping(raw.get("paths") or {},
                                         what="manifest.migration.key_locations.paths")
        locations = {}
        for role, path in locations_raw.items():
            if role not in KEY_ROLES:
                raise RecordInvalid(
                    f"migration.key_locations.paths has an unknown role {role!r}; "
                    f"expected one of {KEY_ROLES}"
                )
            locations[str(role)] = canonical_path(
                path, field_name=f"migration.key_locations.paths[{role}]")
        return KeyMigrationRecord(
            state=str(state),
            source_kind=str(source_kind),
            paths=locations,
            activated_utc=_optional_str(raw.get("activated_utc"),
                                        field_name="migration.key_locations.activated_utc"),
            committed_utc=_optional_str(raw.get("committed_utc"),
                                        field_name="migration.key_locations.committed_utc"),
        )


@dataclass(frozen=True)
class LastResultBlock:
    mode: str
    result: str
    operation_id: str
    completed_utc: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "result": self.result,
            "operation_id": self.operation_id,
            "completed_utc": self.completed_utc,
        }

    @staticmethod
    def from_dict(data: object) -> "LastResultBlock":
        raw = _require_mapping(data, what="manifest.last_result")
        _reject_unknown(raw, {"mode", "result", "operation_id", "completed_utc"}, what="manifest.last_result")
        mode = raw.get("mode")
        if mode not in LIFECYCLE_MODES:
            raise RecordInvalid(f"last_result.mode must be one of {LIFECYCLE_MODES}, got {mode!r}")
        result = raw.get("result")
        if result not in RESULT_VOCABULARY:
            raise RecordInvalid(f"last_result.result must be a lifecycle result, got {result!r}")
        operation_id = raw.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            raise RecordInvalid("last_result.operation_id is required")
        completed = raw.get("completed_utc")
        if not isinstance(completed, str) or not completed:
            raise RecordInvalid("last_result.completed_utc is required")
        return LastResultBlock(
            mode=str(mode),
            result=str(result),
            operation_id=operation_id,
            completed_utc=completed,
        )


# ── manifest ──────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InstallationManifest:
    """The authoritative installation record (D2). Administrator-written, service-readable.

    ``generation`` is the compare-and-swap token, not decoration: two lifecycle tools that both read
    generation N may both produce a complete, valid manifest, and without the token the second write
    silently discards the first one's policy.
    """

    installation_id: str
    paths: PathsBlock
    generation: int = 1
    schema_version: int = MANIFEST_SCHEMA_VERSION
    created_utc: str = ""
    updated_utc: str = ""
    build: BuildBlock = field(default_factory=BuildBlock)
    installer: InstallerBlock = field(default_factory=InstallerBlock)
    uninstaller: UninstallerBlock = field(default_factory=UninstallerBlock)
    web: WebBlock = field(default_factory=WebBlock)
    services: tuple[ServiceEntry, ...] = ()
    storage: StorageBlock = field(default_factory=StorageBlock)
    patch: PatchBlock = field(default_factory=PatchBlock)
    pki: PkiBlock = field(default_factory=PkiBlock)
    proxy_policy: dict[str, ProxyPolicyEntry] = field(default_factory=dict)
    ownership: tuple[OwnershipEntry, ...] = ()
    migration: MigrationBlock = field(default_factory=MigrationBlock)
    last_result: LastResultBlock | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "installation_id": self.installation_id,
            "generation": self.generation,
            "created_utc": self.created_utc,
            "updated_utc": self.updated_utc,
            "paths": self.paths.to_dict(),
            "build": self.build.to_dict(),
            "uninstaller": self.uninstaller.to_dict(),
            "web": self.web.to_dict(),
            "services": [s.to_dict() for s in self.services],
            "storage": self.storage.to_dict(),
            "patch": self.patch.to_dict(),
            "pki": self.pki.to_dict(),
            "proxy_policy": {k: v.to_dict() for k, v in self.proxy_policy.items()},
            "ownership": [o.to_dict() for o in self.ownership],
            "migration": self.migration.to_dict(),
            "last_result": None if self.last_result is None else self.last_result.to_dict(),
        }
        if self.schema_version >= 2:
            payload["installer"] = self.installer.to_dict()
        return payload

    @staticmethod
    def from_dict(data: object) -> "InstallationManifest":
        raw = _require_mapping(data, what="manifest")
        declared_version = raw.get("schema_version")
        if (not isinstance(declared_version, int) or isinstance(declared_version, bool)
                or declared_version not in READABLE_MANIFEST_SCHEMA_VERSIONS):
            raise SchemaVersionUnsupported(
                "manifest schema_version must be one of "
                f"{READABLE_MANIFEST_SCHEMA_VERSIONS}, got {declared_version!r}")
        known = {
            "schema_version", "installation_id", "generation", "created_utc", "updated_utc",
            "paths", "build", "uninstaller", "web", "services", "storage", "patch", "pki",
            "proxy_policy", "ownership", "migration", "last_result",
        }
        if declared_version >= 2:
            known.add("installer")
        _reject_unknown(
            raw,
            known,
            what="manifest",
        )
        version = int(declared_version)
        generation = raw.get("generation")
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
            raise RecordInvalid(f"manifest.generation must be a positive integer, got {generation!r}")

        proxy_raw = _require_mapping(raw.get("proxy_policy") or {}, what="manifest.proxy_policy")
        proxy_policy: dict[str, ProxyPolicyEntry] = {}
        for proxy_type, entry in proxy_raw.items():
            if proxy_type not in PROXY_TYPES:
                raise RecordInvalid(
                    f"proxy_policy names an unsupported type {proxy_type!r}; "
                    f"supported types are {PROXY_TYPES}"
                )
            proxy_policy[proxy_type] = ProxyPolicyEntry.from_dict(entry, proxy_type=proxy_type)

        ownership_raw = raw.get("ownership") or []
        if not isinstance(ownership_raw, (list, tuple)):
            raise RecordInvalid("manifest.ownership must be a list")
        services_raw = raw.get("services") or []
        if not isinstance(services_raw, (list, tuple)):
            raise RecordInvalid("manifest.services must be a list")
        ownership = tuple(OwnershipEntry.from_dict(o) for o in ownership_raw)
        _reject_ownership_conflicts(ownership)
        services = tuple(ServiceEntry.from_dict(s) for s in services_raw)
        _reject_service_conflicts(services)

        paths = PathsBlock.from_dict(raw.get("paths"))
        installer = (InstallerBlock.from_dict(raw.get("installer") or {})
                     if version >= 2 else InstallerBlock())
        if installer.entry_point is not None:
            _assert_one_flavour({
                "paths.install_dir": paths.install_dir,
                "installer.entry_point": installer.entry_point,
            })
            if not _is_inside(installer.entry_point, paths.install_dir):
                raise RecordInvalid(
                    "installer.entry_point must be inside paths.install_dir; the installed "
                    "bootstrap is part of this installation, not a caller-owned package"
                )
        uninstaller = UninstallerBlock.from_dict(raw.get("uninstaller") or {})
        if uninstaller.entry_point is not None:
            _assert_one_flavour({
                "paths.install_dir": paths.install_dir,
                "uninstaller.entry_point": uninstaller.entry_point,
            })
            if not _is_inside(uninstaller.entry_point, paths.install_dir):
                raise RecordInvalid(
                    "uninstaller.entry_point must be inside paths.install_dir; the installed "
                    "uninstaller is part of this installation, not a machine-wide cleanup tool"
                )

        return InstallationManifest(
            installation_id=_require_uuid(raw.get("installation_id"), what="manifest"),
            paths=paths,
            generation=generation,
            schema_version=version,
            created_utc=str(raw.get("created_utc") or ""),
            updated_utc=str(raw.get("updated_utc") or ""),
            build=BuildBlock.from_dict(raw.get("build") or {}),
            installer=installer,
            uninstaller=uninstaller,
            web=WebBlock.from_dict(raw.get("web") or {}),
            services=services,
            storage=StorageBlock.from_dict(raw.get("storage") or {}),
            patch=PatchBlock.from_dict(raw.get("patch") or {}),
            pki=PkiBlock.from_dict(raw.get("pki") or {}),
            proxy_policy=proxy_policy,
            ownership=ownership,
            migration=MigrationBlock.from_dict(raw.get("migration") or {}),
            last_result=(
                None if raw.get("last_result") is None
                else LastResultBlock.from_dict(raw["last_result"])
            ),
        )

    def validated(self) -> "InstallationManifest":
        return InstallationManifest.from_dict(self.to_dict())

    def with_generation(self, generation: int, *, updated_utc: str | None = None) -> "InstallationManifest":
        return replace(
            self, generation=generation, updated_utc=updated_utc or utc_now_iso()
        )


# ── journal ───────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class JournalRecord:
    """One lifecycle operation's crash-recovery evidence (deliverable 4).

    Prose in a log cannot establish a commit boundary after a crash, which is why this is a record
    and not a log line. ``backups`` holds REFERENCES — a path or an identifier — never content, so a
    journal can never become an accidental copy of what it points at.
    """

    operation_id: str
    installation_id: str
    mode: str
    state: str = JOURNAL_OPEN
    schema_version: int = JOURNAL_SCHEMA_VERSION
    plan_digest: str | None = None
    current_subsystem: str | None = None
    intended_change: str | None = None
    backups: tuple[str, ...] = ()
    last_checkpoint: str | None = None
    resume_hint: str | None = None
    result: str | None = None
    updated_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "operation_id": self.operation_id,
            "installation_id": self.installation_id,
            "mode": self.mode,
            "state": self.state,
            "plan_digest": self.plan_digest,
            "current_subsystem": self.current_subsystem,
            "intended_change": self.intended_change,
            "backups": list(self.backups),
            "last_checkpoint": self.last_checkpoint,
            "resume_hint": self.resume_hint,
            "result": self.result,
            "updated_utc": self.updated_utc,
        }

    @staticmethod
    def from_dict(data: object) -> "JournalRecord":
        raw = _require_mapping(data, what="journal")
        _reject_unknown(
            raw,
            {
                "schema_version", "operation_id", "installation_id", "mode", "state", "plan_digest",
                "current_subsystem", "intended_change", "backups", "last_checkpoint", "resume_hint",
                "result", "updated_utc",
            },
            what="journal",
        )
        version = _require_version(
            raw.get("schema_version"), JOURNAL_SCHEMA_VERSION, what="journal"
        )
        mode = raw.get("mode")
        if mode not in LIFECYCLE_MODES:
            raise RecordInvalid(f"journal.mode must be one of {LIFECYCLE_MODES}, got {mode!r}")
        state = raw.get("state", JOURNAL_OPEN)
        if state not in JOURNAL_STATES:
            raise RecordInvalid(f"journal.state must be one of {JOURNAL_STATES}, got {state!r}")
        result = raw.get("result")
        if result is not None and result not in RESULT_VOCABULARY:
            raise RecordInvalid(f"journal.result must be a lifecycle result, got {result!r}")
        # State and result are one fact, not two fields that happen to agree. A record claiming
        # `resolved` with no result is exactly the shape that makes `requires_recovery()` answer
        # "nothing owed" about an operation whose outcome nobody recorded.
        if state == JOURNAL_RESOLVED and result is None:
            raise RecordInvalid(
                "journal.state is 'resolved' but no result was recorded; a resolved operation "
                "always carries one of the six lifecycle result words"
            )
        if state != JOURNAL_RESOLVED and result is not None:
            raise RecordInvalid(
                f"journal.state is {state!r} but a result {result!r} was recorded; only a resolved "
                "operation carries a result"
            )
        operation_id = raw.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            raise RecordInvalid("journal.operation_id is required")
        backups = raw.get("backups") or []
        if not isinstance(backups, (list, tuple)) or any(not isinstance(b, str) for b in backups):
            raise RecordInvalid("journal.backups must be a list of reference strings")
        return JournalRecord(
            operation_id=operation_id,
            installation_id=_require_uuid(raw.get("installation_id"), what="journal"),
            mode=str(mode),
            state=str(state),
            schema_version=version,
            plan_digest=_optional_str(raw.get("plan_digest"), field_name="journal.plan_digest"),
            current_subsystem=_optional_str(
                raw.get("current_subsystem"), field_name="journal.current_subsystem"
            ),
            intended_change=_optional_str(
                raw.get("intended_change"), field_name="journal.intended_change"
            ),
            backups=tuple(str(b) for b in backups),
            last_checkpoint=_optional_str(
                raw.get("last_checkpoint"), field_name="journal.last_checkpoint"
            ),
            resume_hint=_optional_str(raw.get("resume_hint"), field_name="journal.resume_hint"),
            result=result,
            updated_utc=str(raw.get("updated_utc") or ""),
        )

    def validated(self) -> "JournalRecord":
        return JournalRecord.from_dict(self.to_dict())


# ── cross-record identity ─────────────────────────────────────────────────────────────────────


def assert_identity_agrees(
    locator: LocatorRecord, manifest: InstallationManifest, *, manifest_path: str | None = None
) -> None:
    """Refuse when locator and manifest do not describe the same installation.

    The packet's word is *refuses*, not *reconciles*: a mismatch means one of two records is from a
    different installation, and picking either one is a guess about which. Both the ID and the
    manifest's location have to agree, because a right ID at the wrong path is the shape a
    half-completed relocation leaves behind.
    """
    if locator.installation_id != manifest.installation_id:
        raise IdentityMismatch(
            f"locator installation {locator.installation_id} does not match manifest "
            f"installation {manifest.installation_id}"
        )
    if not same_path(locator.install_dir, manifest.paths.install_dir):
        raise IdentityMismatch(
            f"locator install_dir {locator.install_dir} does not match manifest "
            f"install_dir {manifest.paths.install_dir}"
        )
    if manifest_path is not None:
        expected = str(_pure(locator.install_dir) / locator.manifest_relative_path)
        if not same_path(expected, manifest_path):
            raise IdentityMismatch(
                f"locator points at {expected}; manifest was read from {manifest_path}"
            )
