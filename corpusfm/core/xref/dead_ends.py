"""Dead-end analysis — items with no inbound references.

Dead-end definitions:
  ScriptCatalog:           not called by any other script; not a layout trigger
  CustomFunctionsCatalog:  name not found as a function call in any formula
  ValueListCatalog:        not referenced in any field validation binding
  FieldsForTables:         not referenced in scripts, CFs, field formulas,
                           relationship predicates, or layout objects (field
                           placements, portals, merge fields).
  LayoutCatalog:           never navigated to by any script (Go to Layout,
                           Go to Related Record, New Window).

Analysis strategy (Phase 3):
  UUID-based comparison is primary for all analyses that have UUID indexes
  from Phase 2.  Name-based comparison is retained as a fallback for catalog
  items that lack a <UUID> child element (pre-FM-21 edge cases) and for
  sources where FM stores references as formula text rather than structured
  XML (CF formulas, field auto-enter/validation formulas).
"""

from __future__ import annotations

import json
from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from corpusfm.formula import analyze

if TYPE_CHECKING:
    from corpusfm.core.parser import ParseResult
    from corpusfm.core.xref.graph import XRefGraph


@dataclass
class DeadEndReport:
    """Per-section sets of item names considered dead-ends."""
    scripts: set[str] = field(default_factory=set)
    custom_functions: set[str] = field(default_factory=set)
    value_lists: set[str] = field(default_factory=set)
    fields: set[str] = field(default_factory=set)   # "BaseTable::FieldName" keys
    layouts: set[str] = field(default_factory=set)  # layout display names

    def is_dead_end(self, section_key: str, item_name: str) -> bool:
        if section_key == "ScriptCatalog":
            return item_name in self.scripts
        if section_key == "CustomFunctionsCatalog":
            return item_name in self.custom_functions
        if section_key == "ValueListCatalog":
            return item_name in self.value_lists
        if section_key == "FieldsForTables":
            return item_name in self.fields
        if section_key == "LayoutCatalog":
            return item_name in self.layouts
        return False

    def count(self, section_key: str) -> int:
        if section_key == "ScriptCatalog":
            return len(self.scripts)
        if section_key == "CustomFunctionsCatalog":
            return len(self.custom_functions)
        if section_key == "ValueListCatalog":
            return len(self.value_lists)
        if section_key == "FieldsForTables":
            return len(self.fields)
        if section_key == "LayoutCatalog":
            return len(self.layouts)
        return 0

    def as_dict(self) -> dict:
        return {
            "ScriptCatalog": sorted(self.scripts),
            "CustomFunctionsCatalog": sorted(self.custom_functions),
            "ValueListCatalog": sorted(self.value_lists),
            "FieldsForTables": sorted(self.fields),
            "LayoutCatalog": sorted(self.layouts),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeadEndReport":
        return cls(
            scripts=set(data.get("ScriptCatalog", [])),
            custom_functions=set(data.get("CustomFunctionsCatalog", [])),
            value_lists=set(data.get("ValueListCatalog", [])),
            fields=set(data.get("FieldsForTables", [])),
            layouts=set(data.get("LayoutCatalog", [])),
        )


def compute_dead_ends(result: "ParseResult", xref: "XRefGraph") -> DeadEndReport:
    return DeadEndReport(
        scripts=_dead_scripts(result, xref),
        custom_functions=_dead_custom_functions(result, xref),
        value_lists=_dead_value_lists(result, xref),
        fields=_dead_fields(result, xref),
        layouts=_dead_layouts(result, xref),
    )


# ── Empty folder detection ─────────────────────────────────────────────────────

def _empty_folders(xml_section: dict) -> set[str]:
    """Return display names of folders whose subtree contains no real items.

    A folder is empty if every descendant is also a folder, separator, or marker.
    Useful for scripts, CFs, value lists, and layouts that support FM folder hierarchy.
    """
    keys = list(xml_section.keys())

    folder_children: dict[str, list[str]] = {}
    stack: list[str] = []
    for key in keys:
        ft = _folder_type(xml_section[key])
        if ft == "marker":
            if stack:
                stack.pop()
        elif ft == "folder":
            folder_children.setdefault(key, [])
            if stack:
                folder_children[stack[-1]].append(key)
            stack.append(key)
        else:
            if stack:
                folder_children[stack[-1]].append(key)

    def has_real_items(folder_key: str) -> bool:
        for child in folder_children.get(folder_key, []):
            ft = _folder_type(xml_section.get(child, ""))
            if ft == "folder":
                if has_real_items(child):
                    return True
            elif ft != "separator":
                return True
        return False

    return {_display_name(k) for k in folder_children if not has_real_items(k)}


# ── Scripts ────────────────────────────────────────────────────────────────────

# Addon-internal scripts in host DDR exports have UUID-based names.  They appear
# unreferenced because their callers are other addon scripts (not host scripts) —
# exclude them to prevent false positives regardless of UUID availability.
_ADDON_UUID_PREFIX = "com.fmi.script.UUID-"


def _layout_trigger_scripts(result: "ParseResult") -> set[str]:
    """Name-based fallback: collect script names from layout ScriptTrigger elements."""
    triggered: set[str] = set()
    for xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).values():
        if not xml_str:
            continue
        try:
            elem = ET.fromstring(xml_str)
        except ET.ParseError:
            continue
        for container in elem.iter("ScriptTriggers"):
            for trig in container.findall("ScriptTrigger"):
                sr = trig.find("ScriptReference")
                if sr is not None:
                    name = sr.get("name", "").strip()
                    if name:
                        triggered.add(name)
    return triggered


def _dead_scripts(result: "ParseResult", xref: "XRefGraph") -> set[str]:
    # UUID-based: scripts called by other scripts + scripts referenced in layouts.
    # layout_triggers includes both ScriptTrigger events and button actions.
    referenced_uuids = (
        set((xref.script_called_by_uuids or {}).keys())
        | set((xref.script_triggered_by_layout_uuids or {}).keys())
    )

    # Name-based fallback (used when a catalog item has no <UUID> child).
    referenced_names = set((xref.script_called_by or {}).keys()) | _layout_trigger_scripts(result)

    section = (result.section_xml or {}).get("ScriptCatalog", {})
    script_uuid_map = (xref.catalog_xml_key_to_uuid or {}).get("ScriptCatalog", {})

    dead: set[str] = set()
    for xml_key, xml_str in section.items():
        if _folder_type(xml_str):
            continue
        name = _display_name(xml_key)
        if name.startswith(_ADDON_UUID_PREFIX):
            continue
        uuid = script_uuid_map.get(xml_key, "")
        if uuid:
            if uuid not in referenced_uuids:
                dead.add(name)
        else:
            if name not in referenced_names:
                dead.add(name)

    return dead | _empty_folders(section)


# ── Custom functions ───────────────────────────────────────────────────────────

def _dead_custom_functions(result: "ParseResult", xref: "XRefGraph") -> set[str]:
    # FM stores CF formula bodies as plain text with no structural
    # CustomFunctionReference elements.  Parse each formula and collect the
    # set of all function names called; a CF absent from that set is dead.
    called: set[str] = set()

    for xml_str in (result.cf_xml or {}).values():
        if not xml_str:
            continue
        try:
            text_el = ET.fromstring(xml_str).find(".//Text")
            if text_el is not None and text_el.text:
                for fn in analyze(text_el.text).func_calls:
                    called.add(fn.lower())
        except ET.ParseError:
            pass

    for xml_str in (result.section_xml or {}).get("FieldsForTables", {}).values():
        if not xml_str:
            continue
        try:
            for calc in ET.fromstring(xml_str).iter("Calculation"):
                t = calc.find("Text")
                if t is not None and t.text:
                    for fn in analyze(t.text).func_calls:
                        called.add(fn.lower())
        except ET.ParseError:
            pass

    # Layout formula slots (hide-object, conditional formatting, tooltip, etc.)
    for xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).values():
        if not xml_str:
            continue
        try:
            for calc in ET.fromstring(xml_str).iter("Calculation"):
                t = calc.find("Text")
                if t is not None and t.text:
                    for fn in analyze(t.text).func_calls:
                        called.add(fn.lower())
        except ET.ParseError:
            pass

    # Custom menu formula slots (enabled condition, dynamic label, dynamic value)
    for xml_str in (result.section_xml or {}).get("CustomMenuCatalog", {}).values():
        if not xml_str:
            continue
        try:
            for calc in ET.fromstring(xml_str).iter("Calculation"):
                t = calc.find("Text")
                if t is not None and t.text:
                    for fn in analyze(t.text).func_calls:
                        called.add(fn.lower())
        except ET.ParseError:
            pass

    section = (result.section_xml or {}).get("CustomFunctionsCatalog", {})
    dead: set[str] = set()
    for cf_name in (xref.custom_functions or []):
        if cf_name.lower() not in called:
            dead.add(cf_name)
    return dead | _empty_folders(section)


# ── Value lists ────────────────────────────────────────────────────────────────

def _dead_value_lists(result: "ParseResult", xref: "XRefGraph") -> set[str]:
    # UUID-based: VL UUIDs found in field validation ValueListReference elements.
    referenced_uuids = set((xref.value_list_used_in_field_uuids or {}).keys())

    # Name-based fallback for VL items without a <UUID> child.
    # FM references value lists from four locations: layout controls, field
    # validation, relationship portal sort orders, and Sort Records/Sort Portal steps.
    referenced_names: set[str] = set()

    def _collect_vl_names(xml_str: str) -> None:
        if not xml_str:
            return
        try:
            elem = ET.fromstring(xml_str)
            for ref in elem.iter("ValueListReference"):
                n = ref.get("name", "").strip()
                if n:
                    referenced_names.add(n)
        except ET.ParseError:
            pass

    for section_key in ("FieldsForTables", "LayoutCatalog", "RelationshipCatalog"):
        for xml_str in (result.section_xml or {}).get(section_key, {}).values():
            _collect_vl_names(xml_str)

    for xml_str in (result.step_xml or {}).values():
        _collect_vl_names(xml_str)

    section = (result.section_xml or {}).get("ValueListCatalog", {})
    vl_uuid_map = (xref.catalog_xml_key_to_uuid or {}).get("ValueListCatalog", {})

    dead: set[str] = set()
    for xml_key, xml_str in section.items():
        if _folder_type(xml_str):
            continue
        name = _display_name(xml_key)
        uuid = vl_uuid_map.get(xml_key, "")
        if uuid:
            if uuid not in referenced_uuids:
                dead.add(name)
        else:
            if name not in referenced_names:
                dead.add(name)

    return dead | _empty_folders(section)


# ── Fields ────────────────────────────────────────────────────────────────────

def _build_to_base_table_map(result: "ParseResult") -> dict[str, str]:
    """Return {to_name: base_table_name} from TableOccurrenceCatalog."""
    to_base: dict[str, str] = {}
    for to_key, to_xml in (result.section_xml or {}).get("TableOccurrenceCatalog", {}).items():
        if not to_xml or _folder_type(to_xml):
            continue
        try:
            elem = ET.fromstring(to_xml)
        except ET.ParseError:
            continue
        to_name = elem.get("name", _display_name(to_key))
        src_ref = elem.find("BaseTableSourceReference")
        if src_ref is not None and src_ref.get("type") == "BaseTableReference":
            bt_ref = src_ref.find("BaseTableReference")
            if bt_ref is not None:
                to_base[to_name] = bt_ref.get("name", to_name)
        else:
            to_base[to_name] = to_name
    return to_base


def _collect_field_refs_from_xml(xml_str: str) -> set[tuple[str, str]]:
    """Return {(to_name, field_name)} from FieldReference elements in xml_str."""
    refs: set[tuple[str, str]] = set()
    if not xml_str:
        return refs
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return refs
    for ref in root.iter("FieldReference"):
        to_ref = ref.find("TableOccurrenceReference")
        field_name = ref.get("name", "").strip()
        to_name = to_ref.get("name", "").strip() if to_ref is not None else ""
        if field_name and to_name:
            refs.add((to_name, field_name))
    return refs


def _collect_field_refs_from_formula(
    formula: str,
    *,
    implicit_to: str | None = None,
) -> set[tuple[str, str]]:
    """Return {(to_name, field_name)} from a formula string.

    Pass implicit_to when the formula is a calc-field body so that bare
    field names (no TO:: prefix) are resolved to the implicit table context.
    """
    return {(r.table, r.field) for r in analyze(formula, implicit_to=implicit_to).field_refs}


def _dead_fields(result: "ParseResult", xref: "XRefGraph") -> set[str]:
    """Fields not referenced in scripts, CFs, field formulas, relationship
    predicates, or layout objects.

    UUID-based check covers scripts (via Phase 2 index), relationships, and
    layouts.  Name-based check supplements for CF formulas and field formulas
    where FM stores references as plain text with no structural UUID element,
    and serves as a complete fallback for fields that lack a <UUID> child.
    """
    field_uuid_map = (xref.catalog_xml_key_to_uuid or {}).get("FieldsForTables", {})

    # ── UUID-based referenced field UUIDs ─────────────────────────────────────
    referenced_uuids: set[str] = set((xref.field_used_in_script_uuids or {}).keys())

    # Relationships and layouts: direct FieldReference.UUID scan.
    for section_key in ("RelationshipCatalog", "LayoutCatalog"):
        for xml_str in (result.section_xml or {}).get(section_key, {}).values():
            if not xml_str:
                continue
            try:
                for ref in ET.fromstring(xml_str).iter("FieldReference"):
                    uuid = ref.get("UUID", "")
                    if uuid:
                        referenced_uuids.add(uuid)
            except ET.ParseError:
                pass

    # ── Name-based referenced fields ──────────────────────────────────────────
    # Needed for CF formulas, field formulas (text-only), and as a fallback for
    # any field item that lacks a <UUID> child element.
    to_base = _build_to_base_table_map(result)
    all_to_refs: set[tuple[str, str]] = set()

    for xml_str in (result.step_xml or {}).values():
        all_to_refs |= _collect_field_refs_from_xml(xml_str)

    for xml_str in (result.cf_xml or {}).values():
        if not xml_str:
            continue
        try:
            text_el = ET.fromstring(xml_str).find(".//Text")
            if text_el is not None and text_el.text:
                all_to_refs |= _collect_field_refs_from_formula(text_el.text)
        except ET.ParseError:
            pass

    for xml_str in (result.section_xml or {}).get("FieldsForTables", {}).values():
        if not xml_str:
            continue
        try:
            for calc in ET.fromstring(xml_str).iter("Calculation"):
                t = calc.find("Text")
                if t is None or not t.text:
                    continue
                to_ref = calc.find("TableOccurrenceReference")
                impl_to = to_ref.get("name", "").strip() if to_ref is not None else None
                all_to_refs |= _collect_field_refs_from_formula(t.text, implicit_to=impl_to or None)
        except ET.ParseError:
            pass

    for xml_str in (result.section_xml or {}).get("RelationshipCatalog", {}).values():
        all_to_refs |= _collect_field_refs_from_xml(xml_str)

    for xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).values():
        all_to_refs |= _collect_field_refs_from_xml(xml_str)
        # Formula slots: hide-object, conditional formatting, tooltip, portal filter, etc.
        if xml_str:
            try:
                for calc in ET.fromstring(xml_str).iter("Calculation"):
                    t = calc.find("Text")
                    if t is None or not t.text:
                        continue
                    to_ref = calc.find("TableOccurrenceReference")
                    impl_to = to_ref.get("name", "").strip() if to_ref is not None else None
                    all_to_refs |= _collect_field_refs_from_formula(t.text, implicit_to=impl_to or None)
            except ET.ParseError:
                pass

    # Custom menu formula slots (no implicit TO — must use explicit TO::Field)
    for xml_str in (result.section_xml or {}).get("CustomMenuCatalog", {}).values():
        if not xml_str:
            continue
        try:
            for calc in ET.fromstring(xml_str).iter("Calculation"):
                t = calc.find("Text")
                if t is not None and t.text:
                    all_to_refs |= _collect_field_refs_from_formula(t.text)
        except ET.ParseError:
            pass

    referenced_base_fields: set[str] = set()
    for to_name, field_name in all_to_refs:
        base = to_base.get(to_name, to_name)
        referenced_base_fields.add(f"{base}::{field_name}")
        referenced_base_fields.add(f"{to_name}::{field_name}")

    # ── Dead field determination ───────────────────────────────────────────────
    field_section = (result.section_xml or {}).get("FieldsForTables", {})
    dead: set[str] = set()
    for field_ref, xml_str in field_section.items():
        if _folder_type(xml_str):
            continue
        uuid = field_uuid_map.get(field_ref, "")
        if uuid:
            if uuid not in referenced_uuids and field_ref not in referenced_base_fields:
                dead.add(field_ref)
        else:
            if field_ref not in referenced_base_fields:
                dead.add(field_ref)

    return dead


# ── Layouts ───────────────────────────────────────────────────────────────────

def _dead_layouts(result: "ParseResult", xref: "XRefGraph") -> set[str]:
    """Layouts never navigated to by any script.

    Covers Go to Layout, Go to Related Record, and New Window steps via the
    layout_used_in_script_uuids Phase 2 index.  UUID-only: layouts without a
    <UUID> child are skipped rather than falsely flagged.
    """
    referenced_uuids = set((xref.layout_used_in_script_uuids or {}).keys())
    layout_uuid_map = (xref.catalog_xml_key_to_uuid or {}).get("LayoutCatalog", {})

    section = (result.section_xml or {}).get("LayoutCatalog", {})
    dead: set[str] = set()
    for xml_key, xml_str in section.items():
        if _folder_type(xml_str):
            continue
        uuid = layout_uuid_map.get(xml_key, "")
        if uuid and uuid not in referenced_uuids:
            dead.add(_display_name(xml_key))

    return dead | _empty_folders(section)


# ── Helpers (duplicated from explorer.py to keep module standalone) ───────────

def _folder_type(xml_str: str) -> str:
    s = xml_str or ""
    if 'isFolder="True"' in s:
        return "folder"
    if 'isFolder="Marker"' in s:
        return "marker"
    if 'isSeparatorItem="True"' in s:
        return "separator"
    return ""


def _display_name(xml_key: str) -> str:
    idx = xml_key.rfind("__")
    if idx != -1 and xml_key[idx + 2:].isdigit():
        return xml_key[:idx]
    return xml_key


# ── Serialization ──────────────────────────────────────────────────────────────

def save_dead_ends(report: DeadEndReport, path: Path) -> None:
    path.write_text(json.dumps(report.as_dict(), indent=2, ensure_ascii=False), encoding="utf-8")


def load_dead_ends(path: Path) -> DeadEndReport:
    data = json.loads(path.read_text(encoding="utf-8"))
    return DeadEndReport.from_dict(data)
