"""Generate FMUpgradeToolPatch XML from two Artifact objects.

Public API:
    generate_patch(art_a, art_b) -> (patch_xml: str, PatchCoverageReport)

art_a is the baseline (what is currently deployed at client sites).
art_b is the new version (what you want to deploy).

XML format reference: github.com/soliantconsulting/patchlab (MIT)
FM Upgrade Tool docs: help.claris.com/en/app-upgrade-tool-guide/
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from corpusfm.extensions.export.coverage_gate import (
    gate_action,
    preexisting_folder_caveat,
)

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact, ArtifactItem


# Name of the CORPUSfm export script the jobs pull path depends on. Track-B
# injection adds this script to a client file; ingestion detects its presence.
# Writes to Get(DocumentsPath) (persistent, world-readable) — see CLAUDE.md.
# Canonical name lives in core/addon/scripts.py; re-exported here for callers.
from corpusfm.core.addon.scripts import SAVE_TO_DOCUMENTS as CFM_EXPORT_SCRIPT


# ---------------------------------------------------------------------------
# Reference type names for ItemReference (DeleteAction)
# ---------------------------------------------------------------------------

_REF_TYPE: dict[str, str] = {
    "ScriptCatalog":             "ScriptReference",
    "CustomFunctionsCatalog":    "CustomFunctionReference",
    "ValueListCatalog":          "ValueListReference",
    "LayoutCatalog":             "LayoutReference",
    "BaseTableCatalog":          "BaseTableReference",
    "TableOccurrenceCatalog":    "TableOccurrenceReference",
    "RelationshipCatalog":       "RelationshipReference",
    "PrivilegeSetsCatalog":      "PrivilegeSetReference",
    "AccountsCatalog":           "AccountReference",
    "ThemeCatalog":              "ThemeReference",
    "CustomMenuSetCatalog":      "CustomMenuSetReference",
    "ExternalDataSourceCatalog": "DataSourceReference",
}

# Object type names for Replace element (ReplaceAction)
_OBJ_TYPE: dict[str, str] = {
    "ScriptCatalog":             "Script",
    "CustomFunctionsCatalog":    "CustomFunction",
    "ValueListCatalog":          "ValueList",
    "LayoutCatalog":             "Layout",
    "BaseTableCatalog":          "BaseTable",
    "TableOccurrenceCatalog":    "TableOccurrence",
    "RelationshipCatalog":       "Relationship",
    "PrivilegeSetsCatalog":      "PrivilegeSet",
    "AccountsCatalog":           "Account",
    "ThemeCatalog":              "Theme",
    "CustomMenuSetCatalog":      "CustomMenuSet",
    "ExternalDataSourceCatalog": "ExternalDataSource",
    "FieldsForTables":           "Field",
}

def _field_type(item: "ArtifactItem") -> str:
    """The field's fieldtype (Normal | Calculated | Summary), FM casing varies."""
    for k in ("fieldtype", "fieldType"):
        v = item.attributes.get(k)
        if v:
            return v
    return ""


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------

@dataclass
class PatchCoverageEntry:
    section: str
    name: str
    action: str    # "Add" | "Delete" | "Replace"
    status: str    # "patchable" | "not_patchable"
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "section": self.section,
            "name": self.name,
            "action": self.action,
            "status": self.status,
            "reason": self.reason,
        }


@dataclass
class PatchCoverageReport:
    entries: list = field(default_factory=list)  # list[PatchCoverageEntry]
    fm_version: str = ""
    version_mismatch: bool = False

    @property
    def patchable_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "patchable")

    @property
    def not_patchable_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "not_patchable")

    def to_dict(self) -> dict:
        return {
            "fm_version": self.fm_version,
            "version_mismatch": self.version_mismatch,
            "patchable_count": self.patchable_count,
            "not_patchable_count": self.not_patchable_count,
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_patch(
    art_a: "Artifact",
    art_b: "Artifact",
    inject_export_script: bool = False,
) -> tuple[str, PatchCoverageReport]:
    """Generate FMUpgradeToolPatch XML from two Artifact objects.

    Returns (patch_xml, coverage_report).  patch_xml is a complete, valid
    XML document ready for FMUpgradeTool --validatePatch.
    """
    from corpusfm.core.comparator import compare_artifacts

    cr = compare_artifacts(art_a, art_b)
    coverage = PatchCoverageReport(
        fm_version=art_b.identity.fm_version,
        version_mismatch=(art_a.identity.fm_version != art_b.identity.fm_version),
    )

    items_a = _index_by_name(art_a)
    items_b = _index_by_name(art_b)
    fields_a = _index_fields(art_a)
    fields_b = _index_fields(art_b)

    structure = ET.Element("Structure")

    # Non-field sections
    for section, sr in cr.sections.items():
        # Detect renames: same UUID across added/removed → ReplaceAction, not Delete+Add
        renames = _detect_renames(section, set(sr.added), set(sr.removed), items_a, items_b)
        renamed_old = set(renames.keys())
        renamed_new = set(renames.values())

        for old_name, new_name in renames.items():
            item_a2 = items_a.get((section, old_name))
            item_b2 = items_b.get((section, new_name))
            if item_a2 and item_b2:
                elem, ok, reason = _build_replace(section, item_a2, item_b2, items_b)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section=section,
                    name=f"{old_name} → {new_name}",
                    action="Rename",
                    status="patchable" if ok else "not_patchable",
                    reason=reason,
                ))

        if section == "ScriptCatalog":
            # Folder-aware: emit added folders/scripts in document order together
            # with the close markers that bound new folders (the comparator never
            # surfaces a close marker as added — they all share the name "--").
            _emit_foldered_additions(structure, coverage, section, set(sr.added),
                                     renamed_new, art_b, items_b)
        else:
            for name in sr.added:
                if name in renamed_new:
                    continue
                item = items_b.get((section, name))
                if item:
                    elem, ok, reason = _build_add(section, item, items_b)
                    if elem is not None:
                        structure.append(elem)
                    coverage.entries.append(PatchCoverageEntry(
                        section=section, name=name, action="Add",
                        status="patchable" if ok else "not_patchable", reason=reason,
                    ))

        for name in sr.removed:
            if name in renamed_old:
                continue
            item = items_a.get((section, name))
            if item:
                elem, ok, reason = _build_delete(section, item, items_a)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section=section, name=name, action="Delete",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))

        for name in sr.changed:
            item_a2 = items_a.get((section, name))
            item_b2 = items_b.get((section, name))
            if item_a2 and item_b2:
                elem, ok, reason = _build_replace(section, item_a2, item_b2, items_b)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section=section, name=name, action="Replace",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))

    # Fields (grouped by table in CompareResult)
    for table, sr in cr.fields.items():
        # Detect field renames: same UUID in both added and removed → ReplaceAction
        uuid_to_removed: dict[str, str] = {}
        for fname in sr.removed:
            item = fields_a.get((table, fname))
            if item and item.fm_uuid:
                uuid_to_removed[item.fm_uuid] = fname

        field_renamed_old: set[str] = set()
        field_renamed_new: set[str] = set()

        for fname in sr.added:
            item_b2 = fields_b.get((table, fname))
            if item_b2 and item_b2.fm_uuid and item_b2.fm_uuid in uuid_to_removed:
                old_name = uuid_to_removed[item_b2.fm_uuid]
                item_a2 = fields_a.get((table, old_name))
                if item_a2:
                    elem, ok, reason = _build_field_replace(item_a2, item_b2, table, items_b)
                    if elem is not None:
                        structure.append(elem)
                    coverage.entries.append(PatchCoverageEntry(
                        section="FieldsForTables",
                        name=f"{table}::{old_name} → {fname}",
                        action="Replace",
                        status="patchable" if ok else "not_patchable",
                        reason=reason,
                    ))
                    field_renamed_old.add(old_name)
                    field_renamed_new.add(fname)

        for fname in sr.added:
            if fname in field_renamed_new:
                continue
            item = fields_b.get((table, fname))
            if item:
                elem, ok, reason = _build_field_add(item, table, items_b)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section="FieldsForTables", name=f"{table}::{fname}", action="Add",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))

        for fname in sr.removed:
            if fname in field_renamed_old:
                continue
            item = fields_a.get((table, fname))
            if item:
                elem, ok, reason = _build_field_delete(item, table, items_a)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section="FieldsForTables", name=f"{table}::{fname}", action="Delete",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))

        for fname in sr.changed:
            item_a2 = fields_a.get((table, fname))
            item_b2 = fields_b.get((table, fname))
            if item_a2 and item_b2:
                elem, ok, reason = _build_field_replace(item_a2, item_b2, table, items_b)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section="FieldsForTables", name=f"{table}::{fname}", action="Replace",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))

    # Track B: inject CORPUSfm export script only when caller explicitly opts in.
    if inject_export_script and not art_b.has_corpusfm_export:
        _append_cfm_export_script_actions(structure)

    version = (
        (art_b.structure_catalog.schema_version if art_b.structure_catalog else "")
        or "2.2.3.0"
    )
    root = ET.Element("FMUpgradeToolPatch", version=version)
    root.append(_flatten_structure(structure))
    ET.indent(root, space="\t")
    xml_body = ET.tostring(root, encoding="unicode", xml_declaration=False)
    patch_xml = f'<?xml version="1.0"?>\n{xml_body}'

    return patch_xml, coverage


# ---------------------------------------------------------------------------
# Rename detection
# ---------------------------------------------------------------------------

def _detect_renames(
    section: str,
    added: set,
    removed: set,
    items_a: dict,
    items_b: dict,
) -> dict[str, str]:
    """Return {old_name: new_name} for items with same UUID across added/removed sets.

    FMUpgradeTool confirmed (2026-05-28 test): ReplaceAction targets by UUID,
    not by name.  A new name in ScriptReference renames the script in place,
    preserving caller UUID references.  ObjectList is a full replacement —
    empty ObjectList wipes all steps.  StepsForScripts must always be included
    in the ObjectList; _build_replace() handles this.
    """
    uuid_to_new: dict[str, str] = {}
    for name in added:
        item = items_b.get((section, name))
        if item and item.fm_uuid:
            uuid_to_new[item.fm_uuid] = name

    renames: dict[str, str] = {}
    for name in removed:
        item = items_a.get((section, name))
        if item and item.fm_uuid and item.fm_uuid in uuid_to_new:
            renames[name] = uuid_to_new[item.fm_uuid]
    return renames


# ---------------------------------------------------------------------------
# Index helpers
# ---------------------------------------------------------------------------

def _index_by_name(art: "Artifact") -> dict:
    """Map (section, name) → ArtifactItem.

    Folders are included so folder additions are surfaced and the folder-open
    element is emitted — previously folders were dropped here, so an added script
    silently lost its containing folder and landed at the catalog root.  Folder
    *close* markers all share the name "--" and collide in this map, and the
    comparator never surfaces them as added; ScriptCatalog additions are instead
    emitted by _emit_foldered_additions, which walks art_b in document order and
    carries the close markers that bound new folders (see container_grammar in
    structure_catalog.yaml).
    """
    return {
        (it.section, it.name): it
        for it in art.items.values()
    }


def _index_fields(art: "Artifact") -> dict:
    """Map (table_name, field_name) → ArtifactItem for FieldsForTables."""
    result: dict = {}
    for it in art.items.values():
        if it.section != "FieldsForTables" or it.is_folder:
            continue
        if "::" in it.name:
            table, fname = it.name.split("::", 1)
        elif it.folder_path:
            table, fname = it.folder_path[0], it.name
        else:
            continue
        result[(table, fname)] = it
    return result


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _parse_src(xml_str: str) -> "ET.Element | None":
    """Parse an FM XML string into an Element, stripping any XML declaration."""
    if not xml_str:
        return None
    s = xml_str.strip()
    if s.startswith("<?"):
        end = s.find("?>")
        if end != -1:
            s = s[end + 2:].strip()
    try:
        return ET.fromstring(s)
    except ET.ParseError:
        return None


def _find_objectlist(steps_xml: str) -> "ET.Element | None":
    """Extract the ObjectList element from a StepsForScripts XML string."""
    root = _parse_src(steps_xml)
    if root is None:
        return None
    # root may itself be an ObjectList, or it may be a Script containing one
    if root.tag == "ObjectList":
        return root
    return root.find("ObjectList")


def _base_table_ref(table_name: str, items: dict) -> "ET.Element | None":
    """Build a BaseTableReference element from the artifact item index."""
    bt = items.get(("BaseTableCatalog", table_name))
    if bt is None:
        return None
    attrs: dict = {"name": table_name, "UUID": bt.fm_uuid}
    if bt.attributes.get("id"):
        attrs["id"] = bt.attributes["id"]
    return ET.Element("BaseTableReference", attrs)


# ---------------------------------------------------------------------------
# AddAction builders
# ---------------------------------------------------------------------------

def _emit_foldered_additions(
    structure: ET.Element,
    coverage: "PatchCoverageReport",
    section: str,
    added: set,
    renamed_new: set,
    art_b: "Artifact",
    items_b: dict,
) -> None:
    """Emit ScriptCatalog additions preserving FM's positional folder grammar.

    FM encodes folder hierarchy as a flat, ordered run of <Script>-shaped
    elements: isFolder="True" opens a folder, isFolder="Marker" (name "--")
    closes the nearest open one; membership is the span between an open and its
    matching close.  FMUpgradeTool reconstructs nesting from this ordering on
    --update (verified live 2026-06-03: an added folder-open emitted before a
    script nests that script).  But a folder left unclosed runs to the end of
    the catalog, so >1 new folder — or a new folder followed by other added
    root items — needs the bounding close marker or the later items wrongly
    nest inside the first folder.

    So we walk art_b's section in document order with an open/close stack and
    emit, in order: each added folder-open, each added script, and the close
    marker of every folder-open we emitted.  Close markers are structural — they
    carry no coverage entry.  A script added into a *pre-existing* folder still
    lands at the catalog root (AddAction appends; positional re-insertion into an
    already-closed folder is a tool limitation, not expressible as an ordered
    add) — it is emitted anyway so the script is not lost.
    """
    ordered = [it for it in art_b.items.values() if it.section == section]
    stack: list[bool] = []  # one bool per open folder: was its open emitted?
    for it in ordered:
        role = it.attributes.get("isFolder")
        if role == "True":  # folder open
            is_added = it.name in added and it.name not in renamed_new
            stack.append(is_added)
            if is_added:
                elem, ok, reason = _build_add(section, it, items_b)
                if elem is not None:
                    structure.append(elem)
                coverage.entries.append(PatchCoverageEntry(
                    section=section, name=it.name, action="Add",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))
        elif role == "Marker":  # folder close
            emitted = stack.pop() if stack else False
            if emitted:
                elem, ok, _ = _build_add(section, it, items_b)
                if elem is not None:
                    structure.append(elem)
        else:  # regular script
            if it.name in added and it.name not in renamed_new:
                elem, ok, reason = _build_add(section, it, items_b)
                if elem is not None:
                    structure.append(elem)
                # Ledger caveat: a script destined for a folder that already exists
                # in the target (one we did NOT open in this patch) lands at root.
                if ok and not reason and it.folder_path and not (stack and stack[-1]):
                    reason = preexisting_folder_caveat()
                coverage.entries.append(PatchCoverageEntry(
                    section=section, name=it.name, action="Add",
                    status="patchable" if ok else "not_patchable", reason=reason,
                ))


def _build_add(
    section: str,
    item_b: "ArtifactItem",
    items_b: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build an AddAction element for a non-field item."""
    if not item_b.xml_sources:
        return None, False, "No XML source available"

    src_elem = _parse_src(item_b.xml_sources[0].xml)
    if src_elem is None:
        return None, False, "Could not parse XML source"

    action = ET.Element("AddAction")

    if section == "ScriptCatalog":
        if item_b.is_folder:
            # Script folder open (isFolder="True") or close marker (isFolder="Marker").
            # Emit the element faithfully so the patch carries folder structure.
            # FM nests by POSITION (open..close span) and FMUpgradeTool honors the
            # ordering on --update (verified live 2026-06-03). _emit_foldered_additions
            # drives the document-ordered open/script/close sequence; this branch
            # just renders one catalog element.
            cat = ET.SubElement(action, "ScriptCatalog")
            cat.append(src_elem)
            return action, True, "script folder (open/close carried in document order)"

        # Action 1: script definition (no steps)
        cat = ET.SubElement(action, "ScriptCatalog")
        cat.append(src_elem)

        # Action 2: steps (separate AddAction child appended after)
        if len(item_b.xml_sources) > 1:
            steps_elem = _find_objectlist(item_b.xml_sources[1].xml)
            if steps_elem is not None:
                steps_action = ET.Element("AddAction")
                sfs = ET.SubElement(steps_action, "StepsForScripts")
                script_wrap = ET.SubElement(sfs, "Script")
                ref_attrs: dict = {"name": item_b.name, "UUID": item_b.fm_uuid}
                if item_b.attributes.get("id"):
                    ref_attrs["id"] = item_b.attributes["id"]
                ET.SubElement(script_wrap, "ScriptReference", ref_attrs)
                script_wrap.append(steps_elem)
                # Return a wrapper fragment — caller receives two actions
                frag = ET.Element("_frag")
                frag.append(action)
                frag.append(steps_action)
                return frag, True, ""

        return action, True, ""

    elif section == "CustomFunctionsCatalog":
        # CF definition + calc in same AddAction
        cf_cat = ET.SubElement(action, "CustomFunctionsCatalog")
        obj_list = ET.SubElement(cf_cat, "ObjectList")
        obj_list.append(src_elem)

        if len(item_b.xml_sources) > 1:
            calc_elem = _parse_src(item_b.xml_sources[1].xml)
            if calc_elem is not None:
                calcs_cat = ET.SubElement(action, "CalcsForCustomFunctions")
                calcs_obj = ET.SubElement(calcs_cat, "ObjectList")
                calcs_obj.append(calc_elem)

        return action, True, ""

    else:
        # Generic: wrap item XML in catalog element
        cat = ET.SubElement(action, section)
        cat.append(src_elem)
        return action, True, ""


# ---------------------------------------------------------------------------
# DeleteAction builders
# ---------------------------------------------------------------------------

def _build_delete(
    section: str,
    item_a: "ArtifactItem",
    items_a: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build a DeleteAction element."""
    # Ledger-driven blocks: accounts, built-in privilege sets, add-only sections.
    allowed, reason = gate_action(section, "Delete", item_name=item_a.name)
    if not allowed:
        return None, False, reason

    ref_type = _REF_TYPE.get(section)
    if not ref_type:
        return None, False, f"No reference type known for section '{section}'"

    if not item_a.fm_uuid:
        return None, False, "Item has no FM UUID — cannot generate DeleteAction"

    action = ET.Element("DeleteAction")
    ref = ET.SubElement(action, "ItemReference", UUID=item_a.fm_uuid, type=ref_type)

    # Fields need a BaseTableReference — handled in _build_field_delete
    # For FieldsForTables items that appear in section iteration (shouldn't normally happen):
    if section == "FieldsForTables" and item_a.folder_path:
        bt_ref = _base_table_ref(item_a.folder_path[0], items_a)
        if bt_ref is not None:
            ref.append(bt_ref)

    return action, True, ""


# ---------------------------------------------------------------------------
# ReplaceAction builders
# ---------------------------------------------------------------------------

def _build_replace(
    section: str,
    item_a: "ArtifactItem",
    item_b: "ArtifactItem",
    items_b: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build a ReplaceAction element."""
    # Ledger-driven block: layouts are add-only (no targetable UUID).
    allowed, reason = gate_action(section, "Replace")
    if not allowed:
        return None, False, reason

    obj_type = _OBJ_TYPE.get(section)
    if not obj_type:
        return None, False, f"No object type known for section '{section}'"

    if not item_a.fm_uuid:
        return None, False, "Baseline item has no FM UUID — cannot generate ReplaceAction"

    if not item_b.xml_sources:
        return None, False, "No XML source in new artifact"

    src_elem = _parse_src(item_b.xml_sources[0].xml)
    if src_elem is None:
        return None, False, "Could not parse XML source from new artifact"

    action = ET.Element("ReplaceAction")
    replace = ET.SubElement(action, "Replace", type=obj_type, UUID=item_a.fm_uuid)

    if section == "ScriptCatalog":
        # Script replace: outer Script element with ScriptReference + ObjectList of steps
        script_outer = ET.SubElement(replace, "Script")
        ref_attrs: dict = {"name": item_b.name, "UUID": item_b.fm_uuid}
        if item_b.attributes.get("id"):
            ref_attrs["id"] = item_b.attributes["id"]
        ET.SubElement(script_outer, "ScriptReference", ref_attrs)

        if len(item_b.xml_sources) > 1:
            steps_elem = _find_objectlist(item_b.xml_sources[1].xml)
            if steps_elem is not None:
                script_outer.append(steps_elem)
            else:
                ET.SubElement(script_outer, "ObjectList", membercount="0")
        else:
            ET.SubElement(script_outer, "ObjectList", membercount="0")

    else:
        replace.append(src_elem)

    return action, True, ""


# ---------------------------------------------------------------------------
# Field-specific builders
# ---------------------------------------------------------------------------

def _build_field_add(
    item_b: "ArtifactItem",
    table_name: str,
    items_b: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build an AddAction for a new field."""
    if not item_b.xml_sources:
        return None, False, "No XML source available"

    field_elem = _parse_src(item_b.xml_sources[0].xml)
    if field_elem is None:
        return None, False, "Could not parse field XML source"

    bt_ref = _base_table_ref(table_name, items_b)

    action = ET.Element("AddAction")
    fft = ET.SubElement(action, "FieldsForTables")
    fc = ET.SubElement(fft, "FieldCatalog")
    if bt_ref is not None:
        fc.append(bt_ref)
    obj_list = ET.SubElement(fc, "ObjectList")
    obj_list.append(field_elem)

    return action, True, ""


def _build_field_delete(
    item_a: "ArtifactItem",
    table_name: str,
    items_a: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build a DeleteAction for a removed field."""
    if not item_a.fm_uuid:
        return None, False, "Field has no FM UUID — cannot generate DeleteAction"

    action = ET.Element("DeleteAction")
    ref = ET.SubElement(action, "ItemReference", UUID=item_a.fm_uuid, type="FieldReference")

    bt_ref = _base_table_ref(table_name, items_a)
    if bt_ref is not None:
        ref.append(bt_ref)

    return action, True, ""


def _build_field_replace(
    item_a: "ArtifactItem",
    item_b: "ArtifactItem",
    table_name: str,
    items_b: dict,
) -> "tuple[ET.Element | None, bool, str]":
    """Build a ReplaceAction for a modified field."""
    # Ledger-driven block: a field Replace that CHANGES fieldtype leaves the file
    # unhostable (field-replace-sametype-ok-typechange-unhostable). Same-type edits
    # (comment/options/calc text) are fine.
    ta, tb = _field_type(item_a), _field_type(item_b)
    type_change = bool(ta and tb and ta != tb)
    allowed, reason = gate_action("FieldsForTables", "Replace", field_type_change=type_change)
    if not allowed:
        return None, False, reason

    if not item_a.fm_uuid:
        return None, False, "Baseline field has no FM UUID — cannot generate ReplaceAction"

    if not item_b.xml_sources:
        return None, False, "No XML source in new artifact"

    field_elem = _parse_src(item_b.xml_sources[0].xml)
    if field_elem is None:
        return None, False, "Could not parse field XML source from new artifact"

    action = ET.Element("ReplaceAction")
    replace = ET.SubElement(action, "Replace", type="Field", UUID=item_a.fm_uuid)

    bt_ref = _base_table_ref(table_name, items_b)
    if bt_ref is not None:
        replace.append(bt_ref)

    replace.append(field_elem)

    return action, True, ""


# ---------------------------------------------------------------------------
# Fragment serialization helper (used by generate_patch for _frag elements)
# ---------------------------------------------------------------------------

# Static script resources Track-B injects into a client file, so a patched
# file supports the full jobs pull lifecycle: export the schema AND clean up the
# exported file afterward (both write to / read Get(DocumentsPath)).
_CFM_SCRIPT_RESOURCES = ("cfm_save_to_documents.xml", "cfm_delete_from_documents.xml")


def _append_cfm_script_resource(structure: ET.Element, resource_name: str) -> None:
    """Append AddActions (ScriptCatalog + StepsForScripts) for one script resource.

    Loads a static resource extracted from CORPUSfm_ADDON.xml and builds the two
    AddAction elements matching the pattern used by _build_add for ScriptCatalog
    items. Missing/malformed resources are skipped silently rather than breaking
    patch generation.
    """
    resource_path = Path(__file__).parent / "resources" / resource_name
    try:
        res_root = ET.parse(resource_path).getroot()
    except Exception:
        return

    sc_entry = res_root.find("ScriptEntry/Script")
    sfs_entry = res_root.find("StepsEntry/Script")
    if sc_entry is None or sfs_entry is None:
        return

    uuid_el = sc_entry.find("UUID")
    script_uuid = uuid_el.text.strip() if uuid_el is not None else ""
    script_name = sc_entry.get("name", CFM_EXPORT_SCRIPT)

    # Action 1: ScriptCatalog entry
    add1 = ET.Element("AddAction")
    cat = ET.SubElement(add1, "ScriptCatalog")
    cat.append(sc_entry)
    structure.append(add1)

    # Action 2: StepsForScripts entry
    ol = _find_objectlist(ET.tostring(sfs_entry, encoding="unicode"))
    if ol is not None:
        add2 = ET.Element("AddAction")
        sfs_wrap = ET.SubElement(add2, "StepsForScripts")
        script_wrap = ET.SubElement(sfs_wrap, "Script")
        ref_attrs: dict = {"name": script_name, "UUID": script_uuid}
        src_ref = sfs_entry.find("ScriptReference")
        if src_ref is not None and src_ref.get("id"):
            ref_attrs["id"] = src_ref.get("id")
        ET.SubElement(script_wrap, "ScriptReference", ref_attrs)
        script_wrap.append(ol)
        structure.append(add2)


def _append_cfm_export_script_actions(structure: ET.Element) -> None:
    """Track B: inject the CORPUSfm export + cleanup scripts into a client file.

    Injects SaveToDocumentsFolder (writes the schema to Get(DocumentsPath) — the
    persistent, world-readable Data/Documents folder) AND its cleanup companion
    DeleteExportFileFromDocumentsFolder. The jobs pull path calls both: export,
    read the file, then delete it. Without the delete companion a patched client
    would accumulate Cfm_*.xml files in Documents.
    """
    for resource_name in _CFM_SCRIPT_RESOURCES:
        _append_cfm_script_resource(structure, resource_name)


def _flatten_structure(structure: ET.Element) -> ET.Element:
    """Unwrap any _frag wrapper elements, promoting their children into structure."""
    clean = ET.Element("Structure")
    for child in structure:
        if child.tag == "_frag":
            for sub in child:
                clean.append(sub)
        else:
            clean.append(child)
    return clean
