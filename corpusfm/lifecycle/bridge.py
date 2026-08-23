"""The transitional bridge from `install.yaml` (packet 1246-01, deliverable 6).

This child creates the neutral substrate. It does **not** move every consumer, and it must not break
the installations that exist today — so it reads a few facts from the current marker to *propose* a
manifest, and changes nothing about the marker itself.

Three fences, each with a reason:

1. **`install.yaml` is never declared the locator.** It cannot be one: Linux keeps it under
   `INSTALL_DIR` and Windows under a selectable `ConfigHome`, so finding it requires already knowing
   the path it would exist to supply.
2. **Read-only, and no runtime field is deleted.** The application still owns `install.yaml` and
   still reads and rewrites it as runtime/storage configuration. Later children move consumers one at
   a time; until then both stores are real and this one is the newcomer.
3. **Raw YAML against a key allowlist — NOT `install.read_install_config()`.** That function
   decrypts `fm_password` into the dict it returns (`corpusfm/install.py:104-115`). Routing the
   bridge through it would put a plaintext automation password one dict-copy away from a manifest
   proposal, guarded only by remembering to drop the key. The allowlist is the fence and the
   structural secret guard is the backstop; neither depends on a careful caller.

The `migration` block records what was bridged and, per consumer, which store is still authoritative
— so a later child can flip exactly one and prove it.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Mapping

import yaml

from .errors import RecordInvalid, RecordMissing
from .schema import (
    CONSUMER_INSTALL_YAML,
    CONSUMER_LIFECYCLE,
    MIGRATION_BRIDGED,
    BuildBlock,
    InstallationManifest,
    MigrationBlock,
    PathsBlock,
    StorageBlock,
    WebBlock,
    canonical_path,
    utc_now_iso,
)

# Facts the lifecycle record may take from the legacy marker. Everything else — above all
# `fm_password` and `fm_user` — stays where it is; storage ACCESS is 1246-08's, not this child's.
BRIDGE_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        "mode",
        "version",
        "installed_at",
        "fm_database",
        "storage_backend",
        "storage_connection",
        "web_prefix",
        "web_port",
    }
)

# Which store answers for what, the moment a bridge is taken. Later children move entries to
# CONSUMER_LIFECYCLE one at a time, and the manifest records each move.
# `storage_access` rather than `storage_credential`: the structural secret guard rejected the first
# name, and it was right to — a consumer key names a TOPIC, and a topic that reads like a value is
# how a value eventually gets stored under it. `access` is also the packet's own word
# (`repair-storage-access`).
INITIAL_CONSUMERS: dict[str, str] = {
    "deployment_mode": CONSUMER_INSTALL_YAML,
    "storage_connection": CONSUMER_INSTALL_YAML,
    "storage_access": CONSUMER_INSTALL_YAML,
    "topology_paths": CONSUMER_LIFECYCLE,
    "installation_identity": CONSUMER_LIFECYCLE,
}


def read_legacy_marker(path: Path | str) -> dict[str, Any]:
    """Return the allowlisted facts from an `install.yaml`, and nothing else.

    Keys outside the allowlist are dropped here, before any of this module's own logic sees them —
    so a marker that grows a new secret-bearing field cannot leak through a later code path that
    forgot about it.
    """
    marker = Path(path)
    try:
        raw = marker.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RecordMissing(f"no install marker at {marker}") from exc
    except OSError as exc:
        raise RecordInvalid(f"install marker at {marker} is unreadable: {exc}") from exc
    try:
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise RecordInvalid(f"install marker at {marker} is not valid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise RecordInvalid(f"install marker at {marker} is not a mapping")
    return {str(k): v for k, v in data.items() if str(k) in BRIDGE_ALLOWED_KEYS}


def propose_manifest(
    *,
    install_dir: str,
    marker_path: Path | str | None = None,
    installation_id: str | None = None,
    patch_hosting_dir: str | None = None,
    fms_root: str | None = None,
) -> InstallationManifest:
    """Build a first-generation manifest for an existing installation. Writes nothing.

    A proposal, not a commitment: the caller validates it, presents it, and only then writes it under
    the lifecycle lock. Nothing here touches `install.yaml`, the running services, or any key.
    """
    facts = read_legacy_marker(marker_path) if marker_path is not None else {}

    # `PatchHostingDir` is NOT derived from the legacy `hosting_dir`. An independent review was
    # right that the first draft made a topology claim this child does not own: `hosting_dir` is the
    # generated-database home (`corpusfm/install.py:20-30`), while D8's PatchHostingDir is a
    # dedicated FMS Additional Database Folder. Silently equating them would mislabel existing
    # administrator data and pre-decide 1246-05. Only an explicitly supplied path is recorded.
    paths = PathsBlock(
        install_dir=canonical_path(install_dir, field_name="install_dir"),
        patch_hosting_dir=(
            canonical_path(patch_hosting_dir, field_name="patch_hosting_dir")
            if patch_hosting_dir
            else None
        ),
        fms_root=canonical_path(fms_root, field_name="fms_root") if fms_root else None,
    )

    port = facts.get("web_port")
    web = WebBlock(
        internal_port=int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None,
        prefix=facts.get("web_prefix") if isinstance(facts.get("web_prefix"), str) else None,
    )

    database = facts.get("fm_database")
    connection = facts.get("storage_connection")
    # `initialized` stays False on a bridged proposal. It is a storage-lifecycle OBSERVATION owned
    # by 1246-08, and all that has happened here is reading a name out of a config file. Inferring
    # it would convert legacy configuration into a lifecycle fact nobody verified.
    storage = StorageBlock(
        database_name=database if isinstance(database, str) else None,
        connection_name=connection if isinstance(connection, str) else None,
        initialized=False,
    )

    version = facts.get("version")
    now = utc_now_iso()
    manifest = InstallationManifest(
        installation_id=(installation_id or str(uuid.uuid4())).lower(),
        paths=paths,
        # A legacy-marker bridge cannot invent the installer-series identity introduced by
        # manifest schema 2. It remains schema 1 until the incoming installer performs the
        # separately measured adoption operation.
        schema_version=1,
        generation=1,
        created_utc=now,
        updated_utc=now,
        build=BuildBlock(version=str(version) if version is not None else None, observed_at=now),
        web=web,
        storage=storage,
        migration=MigrationBlock(
            state=MIGRATION_BRIDGED,
            source_marker=(
                canonical_path(str(Path(marker_path).resolve()), field_name="migration.source_marker")
                if marker_path is not None
                else None
            ),
            bridged_at=now,
            consumers=dict(INITIAL_CONSUMERS),
        ),
    )
    return manifest.validated()
