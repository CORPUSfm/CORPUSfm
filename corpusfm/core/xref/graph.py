"""XRefGraph — cross-reference index for a single FM snapshot.

Build once from a ParseResult; serialize to xref.json alongside snapshot.json.

Phase 1:
  Forward indexes  — catalog name/id lookups for all section types
  Script reverse   — script→script (Perform Script), script→field (FieldReference)
  CF reverse       — CF→field (formula parser; dynamic refs flagged, not extracted)

Phase 2:
  UUID indexes     — all catalog types; UUID-keyed reverse indexes for scripts,
                     fields, layouts, value lists.

Phase 3:
  Layout reverse   — layout→field and layout→VL (UUID-keyed, structural);
                     layout formula slots → field/CF (name-keyed).
  Menu reverse     — custom menu formula slots → field/CF (name-keyed).
"""

from __future__ import annotations

import json
import re as _re
from corpusfm.core import safe_xml as ET
from collections import defaultdict

_ADDON_CMT_LF_PAT = _re.compile(r'(//com\.fmi\.calculation\.text\.[0-9A-Fa-f]{32})(?:\t|(?=[\[;]))')
_HEX32_PAT = _re.compile(r'^[0-9A-Fa-f]{32}$')   # addon field name-suffix UUID form
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from corpusfm.formula import analyze

if TYPE_CHECKING:
    from corpusfm.core.parser import ParseResult


def _display_name(xml_key: str) -> str:
    """Strip parser disambiguation suffix ('Foo__2' → 'Foo')."""
    idx = xml_key.rfind("__")
    if idx != -1 and xml_key[idx + 2:].isdigit():
        return xml_key[:idx]
    return xml_key


# Step names that carry a ScriptReference child element.
_SCRIPT_REF_STEPS = frozenset({"Perform Script", "Perform Script on Server"})

# Steps that MUTATE their target field. In a step's XML the structural
# <FieldReference> is the operand target; for these steps that target is a WRITE.
# (Fields named inside the step's <Text> calculation slots are always reads.)
_FIELD_WRITE_STEPS = frozenset({
    "Set Field", "Set Field By Name", "Insert Calculated Result", "Insert Text",
    "Insert from URL", "Insert from Device", "Insert from Index",
    "Insert from Last Visited", "Insert File", "Insert Picture",
    "Insert Audio/Video", "Insert PDF", "Insert Current Date", "Insert Current Time",
    "Insert Current User Name", "Replace Field Contents", "Cut", "Clear", "Paste",
})

# Steps whose effective target is computed at runtime → statically unresolvable.
# Recorded as honest limits so a workflow declares "continues into a computed
# target" rather than silently dropping the edge.
_DYNAMIC_DISPATCH_STEPS = {
    "Set Field By Name": "field write to a computed name",
    "Insert from URL":   "value fetched from a computed URL",
}

# FM ExecuteSQL() names table-occurrence names as SQL table names, bypassing the
# relationship graph — a data-flow blind spot. Best-effort table extraction from
# FROM / JOIN clauses (quoted or bare). SELECT-only (FM ExecuteSQL cannot write).
_SQL_TABLE_PAT = _re.compile(
    r'\b(?:FROM|JOIN)\s+(?:"([^"]+)"|([A-Za-z_][\w$]*))', _re.IGNORECASE)


def _sql_tables_in(text: str) -> list[str]:
    """Table-occurrence names referenced in any ExecuteSQL() call within `text`."""
    if "ExecuteSQL" not in text:
        return []
    out: list[str] = []
    for m in _SQL_TABLE_PAT.finditer(text):
        name = m.group(1) or m.group(2)
        if name and name not in out:
            out.append(name)
    return out


# Control-flow step names (stable FM vocabulary) — a script's step list is FLAT and
# ordered; block structure is implicit via these openers/closers/continues.
_IF_OPEN, _ELSE_IF, _ELSE, _IF_CLOSE = "If", "Else If", "Else", "End If"
_LOOP_OPEN, _LOOP_CLOSE = "Loop", "End Loop"
_LOOP_MARK = "(loop)"

# Navigation steps that move to a layout → fire the destination's OnLayoutEnter
# trigger (the basis for trigger cascades: a hidden workflow continuation).
_NAV_STEPS = frozenset({"Go to Layout", "Go to Related Record", "New Window"})


def _first_calc_text(el) -> str:
    t = el.find(".//Text")
    return (t.text or "").strip() if t is not None and t.text else ""


def _perform_param(step) -> str:
    """The parameter calculation passed by a Perform Script step (the data riding the
    call), as opposed to the ScriptReference (the callee)."""
    pp = step.find(".//Parameter[@type='Parameter']")
    if pp is None:
        return ""
    t = pp.find(".//Text")
    return (t.text or "").strip() if t is not None and t.text else ""


def _current_guard(cond_stack: list) -> str:
    """Innermost real condition enclosing the current step (loop markers skipped)."""
    for c in reversed(cond_stack):
        if c and c != _LOOP_MARK:
            return c
    return ""


@dataclass
class XRefGraph:
    """Cross-reference index for a single FM snapshot.

    Serialisable to/from JSON for archive storage as xref.json.
    """

    # ── Catalog forward indexes ────────────────────────────────────────────────
    script_name_to_id: dict[str, str]        # ScriptCatalog: name → id
    script_id_to_name: dict[str, str]        # ScriptCatalog: id → name
    layout_name_to_id: dict[str, str]        # LayoutCatalog: name → id
    layout_id_to_name: dict[str, str]        # LayoutCatalog: id → name

    # Sorted name lists for catalog types used in DDR Browser navigation
    custom_functions: list[str]
    value_lists: list[str]
    base_tables: list[str]
    table_occurrences: list[str]
    accounts: list[str]
    privilege_sets: list[str]
    extended_privileges: list[str]
    external_data_sources: list[str]
    custom_menus: list[str]
    custom_menu_sets: list[str]
    relationships: list[str]
    addons: list[str]
    themes: list[str]

    # ── Script reverse indexes ─────────────────────────────────────────────────
    script_calls: dict[str, list[str]]          # script → [scripts it calls]
    script_called_by: dict[str, list[str]]      # script → [scripts that call it]
    script_uses_fields: dict[str, list[str]]    # script → ["TO::Field", ...]
    field_used_in_scripts: dict[str, list[str]] # "TO::Field" → [script names]

    # ── CF reverse indexes ─────────────────────────────────────────────────────
    cf_uses_fields: dict[str, list[str]]        # cf_name → ["TO::Field", ...]
    field_used_in_cfs: dict[str, list[str]]     # "TO::Field" → [cf names]

    # ── Metadata ───────────────────────────────────────────────────────────────
    fm_file: str
    schema_version: str
    built_at: str   # ISO 8601

    # ── UUID forward indexes (Phase 1) ────────────────────────────────────────
    # uuid_to_name: maps any catalog object's FM UUID → its display name.
    # UUIDs are globally unique across all FM object types so a single flat
    # dict is sufficient.  For FieldsForTables entries the display name is the
    # full "BaseTable::FieldName" xml_key so callers get useful context without
    # a second lookup.
    uuid_to_name: dict = dc_field(default_factory=dict)

    # catalog_xml_key_to_uuid: section_key → {xml_key → UUID}.
    # Allows Phase 2 reverse-index builders to resolve a step_xml / section_xml
    # key (e.g. a script name) to the stable FM UUID used as the edge source.
    catalog_xml_key_to_uuid: dict = dc_field(default_factory=dict)

    # ── UUID reverse indexes (Phase 2) ────────────────────────────────────────
    # All keyed by FM UUID strings.  "uuids" suffix distinguishes these from
    # the legacy name-keyed indexes above; the name-keyed ones are retained
    # until Phase 3/4 updates dead_ends.py and the pipeline.

    # Script → script (Perform Script / Perform Script on Server)
    script_calls_uuids: dict = dc_field(default_factory=dict)       # src_UUID → [called_UUIDs]
    script_called_by_uuids: dict = dc_field(default_factory=dict)   # called_UUID → [src_UUIDs]

    # Script → field (FieldReference in steps)
    script_uses_field_uuids: dict = dc_field(default_factory=dict)       # script_UUID → [field_UUIDs]
    field_used_in_script_uuids: dict = dc_field(default_factory=dict)    # field_UUID → [script_UUIDs]

    # Script → layout (LayoutReference in steps: Go to Layout, Go to Related Record, New Window)
    script_uses_layout_uuids: dict = dc_field(default_factory=dict)      # script_UUID → [layout_UUIDs]
    layout_used_in_script_uuids: dict = dc_field(default_factory=dict)   # layout_UUID → [script_UUIDs]

    # Layout → script (ScriptTrigger events and button actions in LayoutCatalog XML)
    layout_triggers_script_uuids: dict = dc_field(default_factory=dict)       # layout_UUID → [script_UUIDs]
    script_triggered_by_layout_uuids: dict = dc_field(default_factory=dict)   # script_UUID → [layout_UUIDs]

    # Field → value list (ValueListReference in FieldsForTables validation XML)
    value_list_used_in_field_uuids: dict = dc_field(default_factory=dict)

    # ── CF→CF and relationship reverse indexes ────────────────────────────────
    cf_calls_cf: dict = dc_field(default_factory=dict)                  # cf_name → [cf names it calls]
    cf_called_by_cf: dict = dc_field(default_factory=dict)              # cf_name → [cf names that call it]
    relationship_uses_field: dict = dc_field(default_factory=dict)      # rel_name → ["TO::Field", ...]
    field_used_in_relationships: dict = dc_field(default_factory=dict)  # "TO::Field" → [rel_names]

    # ── Layout UUID reverse indexes (Phase 3) ─────────────────────────────────
    # Structural FieldReference / ValueListReference elements found in LayoutCatalog XML.
    layout_uses_field_uuids: dict = dc_field(default_factory=dict)      # layout_UUID → [field_UUIDs]
    field_used_in_layout_uuids: dict = dc_field(default_factory=dict)   # field_UUID  → [layout_UUIDs]
    layout_uses_vl_uuids: dict = dc_field(default_factory=dict)         # layout_UUID → [vl_UUIDs]
    vl_used_in_layout_uuids: dict = dc_field(default_factory=dict)      # vl_UUID     → [layout_UUIDs]

    # ── Value list per-source reverse indexes ─────────────────────────────────
    # Separate from the mixed value_list_used_in_field_uuids above; each tracks
    # references to a VL UUID from exactly one XML source type.
    vl_used_in_field_uuids: dict = dc_field(default_factory=dict)        # vl_UUID → [field_UUIDs] (validation)
    vl_used_in_relationship_ids: dict = dc_field(default_factory=dict)   # vl_UUID → [rel_xml_keys] (portal sort)
    vl_used_in_script_names: dict = dc_field(default_factory=dict)       # vl_UUID → [script_names] (sort steps)

    # ── Layout formula indexes (Phase 3, name-keyed) ──────────────────────────
    # Derived by running the formula parser on every <Calculation><Text> slot in
    # LayoutCatalog XML (hide-object, conditional formatting, tooltip, portal
    # filter, badge, placeholder, button bar visibility).
    layout_formula_field_refs: dict = dc_field(default_factory=dict)    # layout_name → ["TO::Field", ...]
    field_used_in_layout_formulas: dict = dc_field(default_factory=dict) # "TO::Field" → [layout_names]
    layout_formula_cf_calls: dict = dc_field(default_factory=dict)      # layout_name → [cf_names]
    cf_called_by_layout: dict = dc_field(default_factory=dict)          # cf_name     → [layout_names]

    # ── Custom menu formula indexes (Phase 3, name-keyed) ─────────────────────
    # Derived from enabled condition, dynamic label, dynamic value formula slots
    # in CustomMenuCatalog XML.  No implicit TO — menus use explicit TO::Field.
    menu_formula_field_refs: dict = dc_field(default_factory=dict)      # menu_name  → ["TO::Field", ...]
    field_used_in_menu_formulas: dict = dc_field(default_factory=dict)  # "TO::Field" → [menu_names]
    menu_formula_cf_calls: dict = dc_field(default_factory=dict)        # menu_name  → [cf_names]
    cf_called_by_menu: dict = dc_field(default_factory=dict)            # cf_name    → [menu_names]

    # ── Field-calculation indexes ─────────────────────────────────────────────
    # Derived by running the formula parser on every <Calculation><Text> slot in a
    # field's XML (stored calc, auto-enter, validation). Captures the calc-field
    # dependency graph — what a calculated field reads, and what reads it.
    field_calc_uses_fields: dict = dc_field(default_factory=dict)       # "T::Field" → ["TO::Field", ...]
    field_used_in_field_calcs: dict = dc_field(default_factory=dict)    # "TO::Field" → ["T::Field", ...]
    field_calc_calls_cf: dict = dc_field(default_factory=dict)          # "T::Field" → [cf_names]
    cf_called_by_field: dict = dc_field(default_factory=dict)           # cf_name    → ["T::Field", ...]

    # ── Addon field identity index ────────────────────────────────────────────
    # Addon fields carry TWO UUIDs: the <UUID> child (FM modification-tracking,
    # what uuid_to_name is keyed on) and the *name-suffix* UUID — the trailing
    # 32-hex segment of the field's name/xml_key (e.g. ...::19F4BE2F...). Addon
    # calc text references fields by that name-suffix UUID
    # (`com.fmi.tableoccurrence.field.<TO>::<FIELD_UUID>`), NOT by the <UUID>
    # child, so resolving addon calc→field edges needs this dedicated index.
    field_ref_uuid_to_key: dict = dc_field(default_factory=dict)        # name-suffix UUID → field xml_key

    # ── Script→field data-flow direction (rung-4 data effects) ────────────────
    # The structural <FieldReference> target of a field-mutating step is a WRITE;
    # fields named in a step's <Text> calculation slots are READS. Together these
    # give the blast radius of a script: what it changes vs what it depends on.
    script_writes_fields: dict = dc_field(default_factory=dict)      # script → ["TO::Field" written]
    script_reads_fields: dict = dc_field(default_factory=dict)       # script → ["TO::Field" read]
    field_written_by_scripts: dict = dc_field(default_factory=dict)  # "TO::Field" → [scripts]
    field_read_by_scripts: dict = dc_field(default_factory=dict)     # "TO::Field" → [scripts]

    # ── Script→table via ExecuteSQL (the SQL blind spot, made visible) ────────
    script_sql_tables: dict = dc_field(default_factory=dict)         # script → [table names in SQL]

    # ── Dynamic / opaque dispatch (honest limits) ─────────────────────────────
    script_dynamic_dispatch: dict = dc_field(default_factory=dict)   # script → [note strings]

    # ── Control flow + parameter data flow on calls (rung-4) ──────────────────
    # Per script, each Perform Script call with the parameter it passes and the
    # nearest enclosing guard condition ("" = unconditional). Distinct (called, param,
    # guard) triples so a script that calls B both conditionally and not is preserved.
    script_call_details: dict = dc_field(default_factory=dict)  # script → [(called, param, guard)]

    # ── Navigation (rung-4): layouts a script moves to (Go to Layout etc.) ─────
    script_navigates_layouts: dict = dc_field(default_factory=dict)  # script → [layout names]

    # ── Navigation (rung-2 C): the TO CONTEXT a script lands the user in via
    # Go to Related Record / portal-row navigation. Distinct from the layout it
    # shows — it is the related-record table occurrence the user ends up in.
    script_navigates_tos: dict = dc_field(default_factory=dict)  # script → [TO names]

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "XRefGraph":
        return cls(**data)


# Catalog sections covered by UUID forward indexes.
# FieldsForTables is handled separately (nested BaseTable → Field structure).
_UUID_CATALOG_SECTIONS: tuple[str, ...] = (
    "ScriptCatalog",
    "LayoutCatalog",
    "CustomFunctionsCatalog",
    "ValueListCatalog",
    "TableOccurrenceCatalog",
    "BaseTableCatalog",
    "ExternalDataSourceCatalog",
    "CustomMenuSetCatalog",
)


def _extract_item_uuid(el: ET.Element) -> str:
    """Return the FM UUID from a catalog item's <UUID> child element, or ''."""
    uuid_el = el.find("UUID")
    return uuid_el.text.strip() if uuid_el is not None and uuid_el.text else ""


def _build_uuid_indexes(
    result: "ParseResult",
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Build UUID forward indexes from all catalog sections.

    Returns:
        uuid_to_name: {FM_UUID → display_name} across all catalog types.
        catalog_xml_key_to_uuid: {section_key → {xml_key → FM_UUID}}.

    For FieldsForTables, the display name in uuid_to_name is the full
    "BaseTable::FieldName" xml_key (not just the field name alone) so callers
    get table context without a second lookup.
    """
    uuid_to_name: dict[str, str] = {}
    by_section: dict[str, dict[str, str]] = {}

    # Standard catalog sections: xml value is the item element directly.
    for section in _UUID_CATALOG_SECTIONS:
        section_map: dict[str, str] = {}
        for xml_key, xml_str in (result.section_xml or {}).get(section, {}).items():
            if not xml_str:
                continue
            try:
                el = ET.fromstring(xml_str)
            except ET.ParseError:
                continue
            uuid = _extract_item_uuid(el)
            if not uuid:
                continue
            name = el.get("name") or xml_key
            uuid_to_name[uuid] = name
            section_map[xml_key] = uuid
        if section_map:
            by_section[section] = section_map

    # FieldsForTables: xml value is a <Field> element; xml_key is "TABLE::FIELD".
    # Use the full xml_key as the display name so table context is preserved.
    field_map: dict[str, str] = {}
    for xml_key, xml_str in (result.section_xml or {}).get("FieldsForTables", {}).items():
        if not xml_str:
            continue
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        uuid = _extract_item_uuid(el)
        if not uuid:
            continue
        uuid_to_name[uuid] = xml_key   # "BaseTable::FieldName" for display
        field_map[xml_key] = uuid
    if field_map:
        by_section["FieldsForTables"] = field_map

    return uuid_to_name, by_section


def _build_uuid_reverse_indexes(
    result: "ParseResult",
    catalog_xml_key_to_uuid: dict[str, dict[str, str]],
) -> dict:
    """Build all UUID-keyed reverse indexes from step, layout, and field XML.

    Returns a dict of nine index dicts, all keyed by FM UUID strings.
    Reference elements without a UUID attribute are silently skipped so the
    indexes degrade gracefully on older or partial XML.

    CF→CF tracking is intentionally absent: FM stores CF formula bodies as
    plain text (<Text>) with no structural CustomFunctionReference for calls
    to other CFs.  That remains regex-based in the legacy cf_uses_fields index.
    """
    script_uuids = catalog_xml_key_to_uuid.get("ScriptCatalog", {})
    layout_uuids = catalog_xml_key_to_uuid.get("LayoutCatalog", {})
    field_uuids  = catalog_xml_key_to_uuid.get("FieldsForTables", {})

    script_calls_uuids:      dict[str, list[str]] = defaultdict(list)
    script_called_by_uuids:  dict[str, list[str]] = defaultdict(list)
    script_uses_field_uuids: dict[str, list[str]] = defaultdict(list)
    field_used_in_script_uuids: dict[str, list[str]] = defaultdict(list)
    script_uses_layout_uuids:   dict[str, list[str]] = defaultdict(list)
    layout_used_in_script_uuids: dict[str, list[str]] = defaultdict(list)

    # ── Step XML: script→script, script→field, script→layout ─────────────────
    for xml_key, xml_str in (result.step_xml or {}).items():
        source_uuid = script_uuids.get(xml_key, "")
        if not source_uuid or not xml_str:
            continue
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        seen_scripts: set[str] = set()
        seen_fields:  set[str] = set()
        seen_layouts: set[str] = set()

        for step in el.iter("Step"):
            if step.get("name", "") in _SCRIPT_REF_STEPS:
                for ref in step.iter("ScriptReference"):
                    called_uuid = ref.get("UUID", "")
                    if called_uuid and called_uuid not in seen_scripts:
                        seen_scripts.add(called_uuid)
                        script_calls_uuids[source_uuid].append(called_uuid)
                        script_called_by_uuids[called_uuid].append(source_uuid)

            for ref in step.iter("FieldReference"):
                field_uuid = ref.get("UUID", "")
                if field_uuid and field_uuid not in seen_fields:
                    seen_fields.add(field_uuid)
                    script_uses_field_uuids[source_uuid].append(field_uuid)
                    field_used_in_script_uuids[field_uuid].append(source_uuid)

            for ref in step.iter("LayoutReference"):
                layout_uuid = ref.get("UUID", "")
                if layout_uuid and layout_uuid not in seen_layouts:
                    seen_layouts.add(layout_uuid)
                    script_uses_layout_uuids[source_uuid].append(layout_uuid)
                    layout_used_in_script_uuids[layout_uuid].append(source_uuid)

    # ── Layout catalog: layout→script, layout→field, layout→VL ──────────────────
    layout_triggers_script_uuids:     dict[str, list[str]] = defaultdict(list)
    script_triggered_by_layout_uuids: dict[str, list[str]] = defaultdict(list)
    layout_uses_field_uuids:          dict[str, list[str]] = defaultdict(list)
    field_used_in_layout_uuids:       dict[str, list[str]] = defaultdict(list)
    layout_uses_vl_uuids:             dict[str, list[str]] = defaultdict(list)
    vl_used_in_layout_uuids:          dict[str, list[str]] = defaultdict(list)

    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        layout_uuid = layout_uuids.get(xml_key, "")
        if not layout_uuid or not xml_str:
            continue
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        seen_scripts: set[str] = set()
        seen_fields:  set[str] = set()
        seen_vls:     set[str] = set()

        for ref in el.iter("ScriptReference"):
            script_uuid = ref.get("UUID", "")
            if script_uuid and script_uuid not in seen_scripts:
                seen_scripts.add(script_uuid)
                layout_triggers_script_uuids[layout_uuid].append(script_uuid)
                script_triggered_by_layout_uuids[script_uuid].append(layout_uuid)

        for ref in el.iter("FieldReference"):
            field_uuid = ref.get("UUID", "")
            if field_uuid and field_uuid not in seen_fields:
                seen_fields.add(field_uuid)
                layout_uses_field_uuids[layout_uuid].append(field_uuid)
                field_used_in_layout_uuids[field_uuid].append(layout_uuid)

        for ref in el.iter("ValueListReference"):
            vl_uuid = ref.get("UUID", "")
            if vl_uuid and vl_uuid not in seen_vls:
                seen_vls.add(vl_uuid)
                layout_uses_vl_uuids[layout_uuid].append(vl_uuid)
                vl_used_in_layout_uuids[vl_uuid].append(layout_uuid)

    # ── Value list references (all contexts) ─────────────────────────────────
    # FM value lists are referenced from four distinct locations:
    #   FieldsForTables  — field validation "In Value List" rules
    #   LayoutCatalog    — layout controls (popup menu, checkbox, radio, drop-down)
    #   RelationshipCatalog — portal sort-by-value-list order definitions
    #   step_xml         — Sort Records / Sort Portal steps sorted by value list order
    value_list_used_in_field_uuids: dict[str, list[str]] = defaultdict(list)
    vl_used_in_field_uuids:        dict[str, list[str]] = defaultdict(list)
    vl_used_in_relationship_ids:   dict[str, list[str]] = defaultdict(list)
    vl_used_in_script_names:       dict[str, list[str]] = defaultdict(list)

    def _scan_for_vl_uuids(xml_str: str, ref_id: str, extra: dict | None = None) -> None:
        """Add every ValueListReference.UUID found in xml_str to the mixed index.

        If extra is given it also receives the same (vl_uuid → ref_id) entries,
        allowing per-source tracking alongside the combined index.
        """
        if not xml_str:
            return
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            return
        seen: set[str] = set()
        for ref in el.iter("ValueListReference"):
            vl_uuid = ref.get("UUID", "")
            if vl_uuid and vl_uuid not in seen:
                seen.add(vl_uuid)
                value_list_used_in_field_uuids[vl_uuid].append(ref_id)
                if extra is not None:
                    extra[vl_uuid].append(ref_id)

    for xml_key, xml_str in (result.section_xml or {}).get("FieldsForTables", {}).items():
        field_uuid = field_uuids.get(xml_key, "")
        if field_uuid:
            _scan_for_vl_uuids(xml_str, field_uuid, vl_used_in_field_uuids)

    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        layout_uuid = layout_uuids.get(xml_key, "")
        if layout_uuid:
            _scan_for_vl_uuids(xml_str, layout_uuid)  # mixed dict only; layout already in vl_used_in_layout_uuids

    for xml_key, xml_str in (result.section_xml or {}).get("RelationshipCatalog", {}).items():
        _scan_for_vl_uuids(xml_str, xml_key, vl_used_in_relationship_ids)

    for xml_key, xml_str in (result.step_xml or {}).items():
        _scan_for_vl_uuids(xml_str, xml_key, vl_used_in_script_names)

    return {
        "script_calls_uuids":               dict(script_calls_uuids),
        "script_called_by_uuids":           dict(script_called_by_uuids),
        "script_uses_field_uuids":          dict(script_uses_field_uuids),
        "field_used_in_script_uuids":       dict(field_used_in_script_uuids),
        "script_uses_layout_uuids":         dict(script_uses_layout_uuids),
        "layout_used_in_script_uuids":      dict(layout_used_in_script_uuids),
        "layout_triggers_script_uuids":     dict(layout_triggers_script_uuids),
        "script_triggered_by_layout_uuids": dict(script_triggered_by_layout_uuids),
        "value_list_used_in_field_uuids":   dict(value_list_used_in_field_uuids),
        "vl_used_in_field_uuids":           dict(vl_used_in_field_uuids),
        "vl_used_in_relationship_ids":      dict(vl_used_in_relationship_ids),
        "vl_used_in_script_names":          dict(vl_used_in_script_names),
        "layout_uses_field_uuids":          dict(layout_uses_field_uuids),
        "field_used_in_layout_uuids":       dict(field_used_in_layout_uuids),
        "layout_uses_vl_uuids":             dict(layout_uses_vl_uuids),
        "vl_used_in_layout_uuids":          dict(vl_used_in_layout_uuids),
    }


def _build_formula_indexes(result: "ParseResult") -> dict:
    """Scan formula slots in LayoutCatalog and CustomMenuCatalog XML.

    For each <Calculation><Text> element found, runs the formula parser to
    extract field refs (with implicit_to from a sibling TableOccurrenceReference)
    and CF calls (intersected with known CF names).

    Custom menu formulas have no implicit TO — menus must use explicit TO::Field.
    """
    _cf_keys = list((result.section_xml or {}).get("CustomFunctionsCatalog", {}).keys())
    known_cf_names: set[str] = {k.lower() for k in _cf_keys}
    cf_display_names: dict[str, str] = {k.lower(): k for k in _cf_keys}

    layout_formula_field_refs:    dict[str, list[str]] = defaultdict(list)
    field_used_in_layout_formulas: dict[str, list[str]] = defaultdict(list)
    layout_formula_cf_calls:      dict[str, list[str]] = defaultdict(list)
    cf_called_by_layout:          dict[str, list[str]] = defaultdict(list)

    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        if not xml_str:
            continue
        layout_name = _display_name(xml_key)
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        seen_fields: set[str] = set()
        seen_cfs:   set[str] = set()
        for calc in el.iter("Calculation"):
            text_el = calc.find("Text")
            if text_el is None or not text_el.text:
                continue
            to_ref = calc.find("TableOccurrenceReference")
            implicit_to = to_ref.get("name", "").strip() if to_ref is not None else None
            refs = analyze(_ADDON_CMT_LF_PAT.sub(r'\1\n', text_el.text), implicit_to=implicit_to or None)
            for fref in refs.field_refs:
                key = str(fref)
                if key not in seen_fields:
                    seen_fields.add(key)
                    layout_formula_field_refs[layout_name].append(key)
                    field_used_in_layout_formulas[key].append(layout_name)
            for fn in refs.func_calls:
                fn_lower = fn.lower()
                if fn_lower in known_cf_names and fn_lower not in seen_cfs:
                    seen_cfs.add(fn_lower)
                    canonical = cf_display_names[fn_lower]
                    layout_formula_cf_calls[layout_name].append(canonical)
                    cf_called_by_layout[canonical].append(layout_name)

    menu_formula_field_refs:    dict[str, list[str]] = defaultdict(list)
    field_used_in_menu_formulas: dict[str, list[str]] = defaultdict(list)
    menu_formula_cf_calls:      dict[str, list[str]] = defaultdict(list)
    cf_called_by_menu:          dict[str, list[str]] = defaultdict(list)

    for xml_key, xml_str in (result.section_xml or {}).get("CustomMenuCatalog", {}).items():
        if not xml_str:
            continue
        menu_name = _display_name(xml_key)
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        seen_fields2: set[str] = set()
        seen_cfs2:   set[str] = set()
        for calc in el.iter("Calculation"):
            text_el = calc.find("Text")
            if text_el is None or not text_el.text:
                continue
            refs = analyze(_ADDON_CMT_LF_PAT.sub(r'\1\n', text_el.text))  # no implicit_to — menus use explicit TO::Field
            for fref in refs.field_refs:
                key = str(fref)
                if key not in seen_fields2:
                    seen_fields2.add(key)
                    menu_formula_field_refs[menu_name].append(key)
                    field_used_in_menu_formulas[key].append(menu_name)
            for fn in refs.func_calls:
                fn_lower = fn.lower()
                if fn_lower in known_cf_names and fn_lower not in seen_cfs2:
                    seen_cfs2.add(fn_lower)
                    canonical = cf_display_names[fn_lower]
                    menu_formula_cf_calls[menu_name].append(canonical)
                    cf_called_by_menu[canonical].append(menu_name)

    return {
        "layout_formula_field_refs":     dict(layout_formula_field_refs),
        "field_used_in_layout_formulas": dict(field_used_in_layout_formulas),
        "layout_formula_cf_calls":       dict(layout_formula_cf_calls),
        "cf_called_by_layout":           dict(cf_called_by_layout),
        "menu_formula_field_refs":       dict(menu_formula_field_refs),
        "field_used_in_menu_formulas":   dict(field_used_in_menu_formulas),
        "menu_formula_cf_calls":         dict(menu_formula_cf_calls),
        "cf_called_by_menu":             dict(cf_called_by_menu),
    }


# ── Builder ────────────────────────────────────────────────────────────────────

def build_xref_graph(result: "ParseResult") -> XRefGraph:
    """Build an XRefGraph from a ParseResult.

    Uses result.section_xml for catalog id extraction,
    result.step_xml for script reverse indexes, and
    result.cf_xml for CF formula reverse indexes.

    Never raises — skips malformed XML items silently.
    """

    # ── UUID indexes ───────────────────────────────────────────────────────────
    uuid_to_name, catalog_xml_key_to_uuid = _build_uuid_indexes(result)
    uuid_reverse = _build_uuid_reverse_indexes(result, catalog_xml_key_to_uuid)
    formula_indexes = _build_formula_indexes(result)

    # Addon field identity: name-suffix UUID (trailing 32-hex of the xml_key) →
    # xml_key. SaveAsXML field keys are "Table::FieldName" (no hex suffix) so this
    # is empty there and only fires for addon calc→field resolution.
    field_ref_uuid_to_key: dict[str, str] = {}
    for xml_key in (result.section_xml or {}).get("FieldsForTables", {}):
        last = xml_key.rsplit("::", 1)[-1]
        if _HEX32_PAT.match(last):
            field_ref_uuid_to_key[last] = xml_key

    # ── Forward indexes ────────────────────────────────────────────────────────

    def _id_maps(section_key: str) -> tuple[dict[str, str], dict[str, str]]:
        n2i: dict[str, str] = {}
        i2n: dict[str, str] = {}
        for name, xml_str in result.section_xml.get(section_key, {}).items():
            try:
                el = ET.fromstring(xml_str)
                item_id = el.get("id", "")
                if item_id:
                    n2i[name] = item_id
                    i2n[item_id] = name
            except ET.ParseError:
                pass
        return n2i, i2n

    def _names(section_key: str) -> list[str]:
        return sorted(result.sections.get(section_key, {}).keys())

    script_name_to_id, script_id_to_name = _id_maps("ScriptCatalog")
    layout_name_to_id, layout_id_to_name = _id_maps("LayoutCatalog")

    # ── Script reverse indexes ─────────────────────────────────────────────────

    script_calls:          dict[str, list[str]] = defaultdict(list)
    script_called_by:      dict[str, list[str]] = defaultdict(list)
    script_uses_fields:    dict[str, list[str]] = defaultdict(list)   # union (read ∪ write)
    field_used_in_scripts: dict[str, list[str]] = defaultdict(list)
    # Direction-split data effects (rung-4): writes vs reads.
    script_writes_fields:     dict[str, list[str]] = defaultdict(list)
    script_reads_fields:      dict[str, list[str]] = defaultdict(list)
    field_written_by_scripts: dict[str, list[str]] = defaultdict(list)
    field_read_by_scripts:    dict[str, list[str]] = defaultdict(list)
    script_sql_tables:        dict[str, list[str]] = defaultdict(list)
    script_dynamic_dispatch:  dict[str, list[str]] = defaultdict(list)
    script_call_details:      dict[str, list[tuple]] = defaultdict(list)
    script_navigates_layouts: dict[str, list[str]] = defaultdict(list)
    script_navigates_tos:     dict[str, list[str]] = defaultdict(list)

    for script_name, xml_str in result.step_xml.items():
        try:
            script_el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        seen_scripts: set[str] = set()
        seen_uses:    set[str] = set()
        wrote:        set[str] = set()
        read:         set[str] = set()
        sql_seen:     set[str] = set()
        dyn_seen:     set[str] = set()
        nav_seen:     set[str] = set()
        nav_to_seen:  set[str] = set()
        cond_stack:   list = []        # control-flow guard stack (If/Else/Loop)
        detail_seen:  set = set()      # distinct (called, param, guard)

        def _use(field_ref: str):
            if field_ref not in seen_uses:
                seen_uses.add(field_ref)
                script_uses_fields[script_name].append(field_ref)
                field_used_in_scripts[field_ref].append(script_name)

        for step in script_el.iter("Step"):
            step_name = step.get("name", "")

            # Control-flow tracking: maintain the enclosing-condition stack so each
            # call below can record the guard it runs under.
            if step_name == _IF_OPEN:
                cond_stack.append(_first_calc_text(step) or "if")
            elif step_name == _ELSE_IF:
                if cond_stack:
                    cond_stack[-1] = _first_calc_text(step) or "else if"
            elif step_name == _ELSE:
                if cond_stack:
                    cond_stack[-1] = "(else)"
            elif step_name == _IF_CLOSE:
                if cond_stack:
                    cond_stack.pop()
            elif step_name == _LOOP_OPEN:
                cond_stack.append(_LOOP_MARK)
            elif step_name == _LOOP_CLOSE:
                if cond_stack:
                    cond_stack.pop()

            if step_name in _SCRIPT_REF_STEPS:
                guard = _current_guard(cond_stack)
                param = _perform_param(step)
                step_refs = [r.get("name", "") for r in step.iter("ScriptReference") if r.get("name")]
                for called in step_refs:
                    if called not in seen_scripts:
                        seen_scripts.add(called)
                        script_calls[script_name].append(called)
                        script_called_by[called].append(script_name)
                    key = (called, param, guard)
                    if key not in detail_seen:
                        detail_seen.add(key)
                        script_call_details[script_name].append((called, param, guard))
                if not step_refs:   # Perform Script with a computed target → dynamic
                    note = f"{step_name} (computed target)"
                    if note not in dyn_seen:
                        dyn_seen.add(note)
                        script_dynamic_dispatch[script_name].append(note)

            if step_name in _DYNAMIC_DISPATCH_STEPS:
                note = f"{step_name} ({_DYNAMIC_DISPATCH_STEPS[step_name]})"
                if note not in dyn_seen:
                    dyn_seen.add(note)
                    script_dynamic_dispatch[script_name].append(note)

            if step_name in _NAV_STEPS:
                for lr in step.iter("LayoutReference"):
                    lname = lr.get("name", "")
                    if lname and lname not in nav_seen:
                        nav_seen.add(lname)
                        script_navigates_layouts[script_name].append(lname)
                # The TO context the nav lands in (Go to Related Record / portal).
                # Skip TO refs nested in a FieldReference — those carry the field's
                # own TO context, not the navigation destination.
                field_to_ids = {id(t) for fr in step.iter("FieldReference")
                                for t in fr.iter("TableOccurrenceReference")}
                for tr in step.iter("TableOccurrenceReference"):
                    if id(tr) in field_to_ids:
                        continue
                    tname = tr.get("name", "")
                    if tname and tname not in nav_to_seen:
                        nav_to_seen.add(tname)
                        script_navigates_tos[script_name].append(tname)

            # Structural <FieldReference> = the step's operand target.
            is_write = step_name in _FIELD_WRITE_STEPS
            for ref in step.iter("FieldReference"):
                to_ref = ref.find("TableOccurrenceReference")
                field_name = ref.get("name", "")
                to_name = to_ref.get("name", "") if to_ref is not None else ""
                if not (field_name and to_name):
                    continue
                field_ref = f"{to_name}::{field_name}"
                _use(field_ref)
                if is_write:
                    if field_ref not in wrote:
                        wrote.add(field_ref)
                        script_writes_fields[script_name].append(field_ref)
                        field_written_by_scripts[field_ref].append(script_name)
                else:
                    if field_ref not in read:
                        read.add(field_ref)
                        script_reads_fields[script_name].append(field_ref)
                        field_read_by_scripts[field_ref].append(script_name)

            # Fields named inside step <Text> calculation slots are always READS;
            # ExecuteSQL() table references are the SQL blind spot, surfaced here.
            for text_el in step.iter("Text"):
                txt = text_el.text or ""
                if not txt.strip():
                    continue
                for sql_tbl in _sql_tables_in(txt):
                    if sql_tbl not in sql_seen:
                        sql_seen.add(sql_tbl)
                        script_sql_tables[script_name].append(sql_tbl)
                try:
                    refs = analyze(_ADDON_CMT_LF_PAT.sub(r'\1\n', txt)).field_refs
                except Exception:
                    refs = []
                for fr in (str(r) for r in refs):
                    if "::" not in fr:
                        continue
                    _use(fr)
                    if fr not in wrote and fr not in read:
                        read.add(fr)
                        script_reads_fields[script_name].append(fr)
                        field_read_by_scripts[fr].append(script_name)

    # ── CF reverse indexes ─────────────────────────────────────────────────────

    cf_uses_fields:    dict[str, list[str]] = defaultdict(list)
    field_used_in_cfs: dict[str, list[str]] = defaultdict(list)
    cf_calls_cf:       dict[str, list[str]] = defaultdict(list)
    cf_called_by_cf:   dict[str, list[str]] = defaultdict(list)

    _cf_keys = list((result.section_xml or {}).get("CustomFunctionsCatalog", {}).keys())
    known_cf_names: set[str] = {k.lower() for k in _cf_keys}
    cf_display_names: dict[str, str] = {k.lower(): k for k in _cf_keys}

    for cf_name, xml_str in result.cf_xml.items():
        try:
            cf_el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        text_el = cf_el.find(".//Text")
        if text_el is None or not text_el.text:
            continue

        formula_refs = analyze(_ADDON_CMT_LF_PAT.sub(r'\1\n', text_el.text))

        seen_fields: set[str] = set()
        for field_ref in [str(r) for r in formula_refs.field_refs]:
            if field_ref not in seen_fields:
                seen_fields.add(field_ref)
                cf_uses_fields[cf_name].append(field_ref)
                field_used_in_cfs[field_ref].append(cf_name)

        seen_cfs: set[str] = set()
        for fn in formula_refs.func_calls:
            fn_lower = fn.lower()
            if fn_lower in known_cf_names and fn_lower not in seen_cfs:
                seen_cfs.add(fn_lower)
                canonical = cf_display_names[fn_lower]
                cf_calls_cf[cf_name].append(canonical)
                cf_called_by_cf[canonical].append(cf_name)

    # ── Field calculation → field / CF indexes ─────────────────────────────────
    # A calculated field (stored calc, auto-enter, or validation) references other
    # fields and custom functions. Scan every <Calculation> slot in the field XML;
    # implicit TO = the field's own table (unqualified refs resolve there).
    field_calc_uses_fields:    dict[str, list[str]] = defaultdict(list)
    field_used_in_field_calcs: dict[str, list[str]] = defaultdict(list)
    field_calc_calls_cf:       dict[str, list[str]] = defaultdict(list)
    cf_called_by_field:        dict[str, list[str]] = defaultdict(list)

    for xml_key, xml_str in (result.section_xml or {}).get("FieldsForTables", {}).items():
        if not xml_str:
            continue
        try:
            fld_el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        implicit_to = xml_key.split("::", 1)[0] if "::" in xml_key else None
        seen_ff: set[str] = set()
        seen_fcf: set[str] = set()
        for calc in fld_el.iter("Calculation"):
            text_el = calc.find("Text")
            if text_el is None or not text_el.text:
                continue
            refs = analyze(_ADDON_CMT_LF_PAT.sub(r'\1\n', text_el.text), implicit_to=implicit_to or None)
            for fref in refs.field_refs:
                key = str(fref)
                if key == xml_key or key in seen_ff:   # skip self-reference
                    continue
                name_part = key.split("::", 1)[1] if "::" in key else key
                if name_part == "Self":                # FM keyword, not a field edge
                    continue
                seen_ff.add(key)
                field_calc_uses_fields[xml_key].append(key)
                field_used_in_field_calcs[key].append(xml_key)
            for fn in refs.func_calls:
                fn_lower = fn.lower()
                if fn_lower in known_cf_names and fn_lower not in seen_fcf:
                    seen_fcf.add(fn_lower)
                    canonical = cf_display_names[fn_lower]
                    field_calc_calls_cf[xml_key].append(canonical)
                    cf_called_by_field[canonical].append(xml_key)

    # ── Relationship → field indexes ───────────────────────────────────────────

    relationship_uses_field:    dict[str, list[str]] = defaultdict(list)
    field_used_in_relationships: dict[str, list[str]] = defaultdict(list)

    for rel_key, xml_str in (result.section_xml or {}).get("RelationshipCatalog", {}).items():
        if not xml_str:
            continue
        try:
            rel_el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        if rel_el.get("type") == "folder":
            continue
        rel_name = rel_el.get("name", rel_key)
        seen_rel_fields: set[str] = set()
        for ref in rel_el.iter("FieldReference"):
            to_ref = ref.find("TableOccurrenceReference")
            field_name = ref.get("name", "").strip()
            to_name = to_ref.get("name", "").strip() if to_ref is not None else ""
            if field_name and to_name:
                field_ref = f"{to_name}::{field_name}"
                if field_ref not in seen_rel_fields:
                    seen_rel_fields.add(field_ref)
                    relationship_uses_field[rel_name].append(field_ref)
                    field_used_in_relationships[field_ref].append(rel_name)

    # ── Assemble ───────────────────────────────────────────────────────────────

    return XRefGraph(
        script_name_to_id=script_name_to_id,
        script_id_to_name=script_id_to_name,
        layout_name_to_id=layout_name_to_id,
        layout_id_to_name=layout_id_to_name,
        custom_functions=_names("CustomFunctionsCatalog"),
        value_lists=_names("ValueListCatalog"),
        base_tables=_names("BaseTableCatalog"),
        table_occurrences=_names("TableOccurrenceCatalog"),
        accounts=_names("AccountsCatalog"),
        privilege_sets=_names("PrivilegeSetsCatalog"),
        extended_privileges=_names("ExtendedPrivilegesCatalog"),
        external_data_sources=_names("ExternalDataSourceCatalog"),
        custom_menus=_names("CustomMenuCatalog"),
        custom_menu_sets=_names("CustomMenuSetCatalog"),
        relationships=_names("RelationshipCatalog"),
        addons=_names("BaseDirectoryCatalog"),
        themes=_names("ThemeCatalog"),
        script_calls=dict(script_calls),
        script_called_by=dict(script_called_by),
        script_uses_fields=dict(script_uses_fields),
        field_used_in_scripts=dict(field_used_in_scripts),
        script_writes_fields=dict(script_writes_fields),
        script_reads_fields=dict(script_reads_fields),
        field_written_by_scripts=dict(field_written_by_scripts),
        field_read_by_scripts=dict(field_read_by_scripts),
        script_sql_tables=dict(script_sql_tables),
        script_dynamic_dispatch=dict(script_dynamic_dispatch),
        script_call_details=dict(script_call_details),
        script_navigates_layouts=dict(script_navigates_layouts),
        script_navigates_tos=dict(script_navigates_tos),
        cf_uses_fields=dict(cf_uses_fields),
        field_used_in_cfs=dict(field_used_in_cfs),
        cf_calls_cf=dict(cf_calls_cf),
        cf_called_by_cf=dict(cf_called_by_cf),
        relationship_uses_field=dict(relationship_uses_field),
        field_used_in_relationships=dict(field_used_in_relationships),
        field_calc_uses_fields=dict(field_calc_uses_fields),
        field_used_in_field_calcs=dict(field_used_in_field_calcs),
        field_calc_calls_cf=dict(field_calc_calls_cf),
        cf_called_by_field=dict(cf_called_by_field),
        field_ref_uuid_to_key=field_ref_uuid_to_key,
        fm_file=result.label,
        schema_version=result.schema_version or "",
        built_at=datetime.now(timezone.utc).isoformat(),
        uuid_to_name=uuid_to_name,
        catalog_xml_key_to_uuid=catalog_xml_key_to_uuid,
        **uuid_reverse,
        **formula_indexes,
    )


# ── Formula field-ref extraction ───────────────────────────────────────────────

def _extract_field_refs(formula: str) -> list[str]:
    """Extract TableOccurrence::FieldName refs from a formula string.

    Uses the formula parser — string literals and comments are excluded,
    Let/While binding names are not promoted to field refs, and dynamic
    calls (GetField, ExecuteSQL, Evaluate) are flagged rather than extracted.
    """
    return [str(r) for r in analyze(formula).field_refs]


# ── Serialization ──────────────────────────────────────────────────────────────

def save_xref_graph(graph: XRefGraph, path: Path) -> None:
    path.write_text(
        json.dumps(graph.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_xref_graph(path: Path) -> XRefGraph:
    data = json.loads(path.read_text(encoding="utf-8"))
    return XRefGraph.from_dict(data)
