"""MergedXML artifact creation — merge SaveAsXML + AddonXML artifacts.

Public API:
    check_eligibility(saveas, addon) -> tuple[bool, str]
    merge_artifacts(saveas, addon) -> Artifact
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from corpusfm.artifact.types import (
    ARTIFACT_VERSION,
    Artifact,
    ArtifactProvenance,
    ArtifactType,
    XRefRecord,
)

if TYPE_CHECKING:
    pass

# Security catalogs absent from AddonXML by design — excluded from count checks.
_SECURITY_SECTIONS = frozenset({
    "FileAccessCatalog",
    "PrivilegeSetsCatalog",
    "ExtendedPrivilegesCatalog",
    "AccountsCatalog",
})


def check_eligibility(saveas: Artifact, addon: Artifact) -> tuple[bool, str]:
    """Return (eligible, reason) for merging two artifacts.

    Requirements:
      - saveas must be ArtifactType.SAVE_AS_XML
      - addon must be ArtifactType.ADDON_XML
      - root UUIDs must match
    """
    if saveas.type != ArtifactType.SAVE_AS_XML:
        return False, f"First artifact must be SaveAsXML, got {saveas.type.value}"
    if addon.type != ArtifactType.ADDON_XML:
        return False, f"Second artifact must be AddonXML, got {addon.type.value}"
    if not saveas.identity.root_uuid:
        return False, "SaveAsXML artifact has no root UUID"
    if saveas.identity.root_uuid != addon.identity.root_uuid:
        return False, (
            f"Root UUID mismatch: SaveAsXML has {saveas.identity.root_uuid!r}, "
            f"AddonXML has {addon.identity.root_uuid!r}"
        )
    return True, ""


def merge_artifacts(saveas: Artifact, addon: Artifact) -> Artifact:
    """Merge a SaveAsXML artifact with an AddonXML artifact.

    Three merge cases:
      1. Same fm_uuid in both → SaveAsXML primary, name resolved from AddonXML.
      2. SaveAsXML-only item → kept as-is.
      3. AddonXML-only item → included from AddonXML.

    Returns a MergedXML artifact with resolved names and merged xref. It records NOTHING about
    its parents: a parent link is a fact about a record in this catalog, and it lives on the RECORD
    (``merge_parent_refs``), never in the artifact — an artifact travels, and our record UUIDs mean
    nothing wherever it lands (packet 1216).
    """
    eligible, reason = check_eligibility(saveas, addon)
    if not eligible:
        raise ValueError(f"Cannot merge: {reason}")

    # Build lookup: fm_uuid → addon item (non-folder items only).
    addon_by_uuid: dict[str, object] = {
        item.fm_uuid: item
        for item in addon.items.values()
        if item.fm_uuid and not item.is_folder
    }

    # Build name map: fm_uuid → resolved human name (from addon).
    addon_name_by_uuid: dict[str, str] = {
        uuid: item.name  # type: ignore[union-attr]
        for uuid, item in addon_by_uuid.items()
    }

    merged_items: dict = {}
    addon_uuids_matched: set[str] = set()

    for item_id, item in saveas.items.items():
        if item.fm_uuid and item.fm_uuid in addon_by_uuid:
            # Case 1: addon item visible in SaveAsXML — resolve name.
            addon_uuids_matched.add(item.fm_uuid)
            addon_item = addon_by_uuid[item.fm_uuid]
            merged_items[item_id] = replace(item, name=addon_item.name)  # type: ignore[arg-type]
        else:
            # Case 2: host-only item — kept as-is.
            merged_items[item_id] = item

    # Case 3: addon-only items (in AddonXML but not in SaveAsXML).
    for item_id, item in addon.items.items():
        if item_id not in merged_items:
            if not item.is_folder or item_id not in merged_items:
                uuid = item.fm_uuid if not item.is_folder else None
                if uuid and uuid not in addon_uuids_matched:
                    merged_items[item_id] = item
                elif item.is_folder:
                    merged_items[item_id] = item

    # Merge xref_map: start from SaveAsXML xrefs, resolve names for addon items.
    merged_xrefs: list[XRefRecord] = []
    saveas_xref_pairs: set[tuple[str, str]] = set()

    for xr in saveas.xref_map:
        from_item = saveas.items.get(xr.from_id)
        to_item = saveas.items.get(xr.to)
        from_name = xr.from_name
        to_name = xr.to_name
        if from_item and from_item.fm_uuid in addon_name_by_uuid:
            from_name = addon_name_by_uuid[from_item.fm_uuid]
        if to_item and to_item.fm_uuid in addon_name_by_uuid:
            to_name = addon_name_by_uuid[to_item.fm_uuid]
        merged_xrefs.append(XRefRecord(
            from_id=xr.from_id,
            from_name=from_name,
            to=xr.to,
            to_name=to_name,
            type=xr.type,
        ))
        saveas_xref_pairs.add((xr.from_id, xr.to))

    # Add addon-only xrefs (cross-refs within addon-only items).
    for xr in addon.xref_map:
        if (xr.from_id, xr.to) not in saveas_xref_pairs:
            merged_xrefs.append(xr)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    merged = Artifact(
        artifact_version=ARTIFACT_VERSION,
        type=ArtifactType.MERGED_XML,
        identity=saveas.identity,
        provenance=ArtifactProvenance(
            ingested_at=now,
            catalog_version=saveas.provenance.catalog_version,
            source="manual",
        ),
        sections=saveas.sections,
        items=merged_items,
        xref_map=merged_xrefs,
        completeness_profile=saveas.completeness_profile,
    )
    return merged
