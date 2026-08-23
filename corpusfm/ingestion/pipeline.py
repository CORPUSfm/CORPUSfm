"""Ingestion pipeline — FM XML bytes → Artifact.

Public API:
    ingest(xml_bytes, label, *, source_type, name_map, keep_source_xml) -> Artifact

Six stages, each a pure function that mutates PipelineState:
    1. _stage_parse          — xml_bytes → ParseResult
    2. _stage_mine           — ParseResult → XRefGraph
    3. _stage_gap_analyze    — xml_bytes + schema_version → GapReport
    4. _stage_dead_ends      — ParseResult + XRefGraph → DeadEndReport
    5. _stage_assemble_items — all above → items dict + xref_records list
    6. _stage_build_artifact — assembled state → Artifact

ParseResult is ephemeral — it never leaves the pipeline.
"""

from __future__ import annotations

import logging
from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from corpusfm.artifact import (
    ARTIFACT_VERSION,
    Artifact,
    ArtifactIdentity,
    ArtifactItem,
    ArtifactProvenance,
    ArtifactType,
    CompletenessProfile,
    StructureCatalogSnapshot,
    XmlSource,
    XRefRecord,
    make_item_id,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline state
# ---------------------------------------------------------------------------

@dataclass
class PipelineState:
    """Carrier passed through all pipeline stages.

    Stages mutate this object rather than taking / returning many arguments.
    Never serialise or return this outside the pipeline.
    """
    xml_bytes: bytes
    label: str
    source_type: str       # "manual" | "job"
    name_map: dict         # {uuid_key: human_name}; empty for SaveAsXML
    keep_source_xml: bool

    result: object = None      # ParseResult
    xref_graph: object = None  # XRefGraph
    dead_ends: object = None   # DeadEndReport
    gap_report: object = None  # GapReport
    structure_snapshot: object = None  # StructureCatalogSnapshot

    miner_skipped: list = field(default_factory=list)
    unresolved_uuids: list = field(default_factory=list)
    render_errors: list = field(default_factory=list)  # caught-and-degraded render failures
    analyzer_failed: list = field(default_factory=list)  # forward-compat miners that CRASHED (packet 072-D)

    items: dict = field(default_factory=dict)          # {item_id: ArtifactItem}
    xref_records: list = field(default_factory=list)   # [XRefRecord]


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _folder_type(xml_str: str) -> str:
    if not xml_str:
        return ""
    try:
        root = ET.fromstring(xml_str)
        v = root.get("isFolder", "")
        if v == "True":   return "folder"
        if v == "Marker": return "marker"
        if root.get("isSeparatorItem") == "True": return "separator"
    except ET.ParseError:
        pass
    return ""


def _field_has_calc(xml_str: str) -> bool:
    """(packet 053) True when a Field carries a calculation worth summarizing — a calculation field,
    an auto-enter calc, or a validation calc. Plain data fields → False (not summarized)."""
    if not xml_str:
        return False
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return False
    if (root.get("fieldType") or "") == "Calculated":
        return True
    ae = root.find("AutoEnter")
    if ae is not None and (ae.get("type") or "") == "Calculated":
        return True
    if root.find(".//Validation/Calculation/Text") is not None:
        return True
    # also catch a non-empty calc/auto-enter formula even if the type attr is absent
    for path in (".//Calculation/Text", ".//AutoEnter/Calculation/Text"):
        t = root.find(path)
        if t is not None and (t.text or "").strip():
            return True
    return False


import re as _re

_FM_UUID_PAT = _re.compile(
    r'com\.fmi\.'
    r'(?:[a-zA-Z]+\.)*'
    r'(?:'
        r'[0-9A-Fa-f]{32}(?:::[0-9A-Fa-f]{32})?'
        r'|[A-Za-z0-9_|!.]+::(?:text\.)?[0-9A-Fa-f]{32}'
    r')'
)


def _apply_name_map(text: str, name_map: dict) -> str:
    """Replace FM addon UUID keys in text with their resolved names."""
    if not name_map or not text:
        return text
    def _sub(m: _re.Match) -> str:
        key = m.group(0)
        resolved = name_map.get(key)
        if resolved is not None:
            return resolved
        if "::text." in key:
            text_uuid = key.rsplit("::text.", 1)[-1]
            resolved = name_map.get(f"com.fmi.calculation.text.{text_uuid}")
            if resolved is not None:
                return resolved
        return key
    return _FM_UUID_PAT.sub(_sub, text)


def _resolve_addon_field_ref(to_ref: str, name_map: dict, field_name_to_id: dict):
    """Map an addon field reference to a (field_item_id, resolved_name).

    Addon calc/script text names a field by the locale-keyed form
    `com.fmi.tableoccurrence.field.<TO>::<UUID>` — optionally nested under an outer
    TO context (`com.fmi.tableoccurrence.<TO-UUID>::…`). The plain TO→base path
    can't map that, but the locale name_map resolves the key to a readable name,
    which we match against the (already resolved) field-item names — directly, or
    as `<TO>::<field>`. No guessing: returns (None, "") unless it lands on a real
    field item. SaveAsXML never reaches this (name_map is empty)."""
    name = name_map.get(to_ref)
    if name and name in field_name_to_id:
        return field_name_to_id[name], name
    idx = to_ref.rfind("com.fmi.tableoccurrence.field.")
    if idx < 0:
        return None, ""
    inner = to_ref[idx:]
    seg = inner.split("::", 1)
    if len(seg) < 2:
        return None, ""
    to_seg = seg[0].rsplit(".", 1)[-1]
    resolved = name_map.get(inner)
    if not resolved:
        return None, ""
    fld = resolved.split("::", 1)[-1]
    for cand in (resolved, f"{to_seg}::{fld}"):
        if cand in field_name_to_id:
            return field_name_to_id[cand], cand
    return None, ""


def _display_name(xml_key: str) -> str:
    """Strip disambiguation suffix produced by the parser ('Foo__2' → 'Foo')."""
    idx = xml_key.rfind("__")
    if idx != -1 and xml_key[idx + 2:].isdigit():
        return xml_key[:idx]
    return xml_key


def _elem_attrs(xml_str: str) -> dict:
    if not xml_str:
        return {}
    try:
        return dict(ET.fromstring(xml_str).attrib)
    except ET.ParseError:
        return {}


def _fm_uuid(xml_str: str) -> str:
    if not xml_str:
        return ""
    try:
        elem = ET.fromstring(xml_str)
    except ET.ParseError:
        return ""
    # Some element types carry UUID as an attribute; others (ScriptCatalog,
    # CustomFunctionsCatalog, FieldsForTables, etc.) store it as a child
    # <UUID> element whose text is the GUID.
    if "UUID" in elem.attrib:
        return elem.attrib["UUID"]
    uuid_el = elem.find("UUID")
    return uuid_el.text.strip() if uuid_el is not None and uuid_el.text else ""


def _compute_folder_paths(xml_section: dict) -> dict:
    """Return {xml_key: [ancestor_folder_names]} via stack-walk in FM document order.

    FM encodes folder hierarchy with open (isFolder="True") / close (isFolder="Marker")
    pairs; everything between them is a child of that folder.
    """
    stack: list = []
    paths: dict = {}
    for xml_key, xml_str in xml_section.items():
        ft = _folder_type(xml_str)
        if ft == "marker":
            paths[xml_key] = list(stack)
            if stack:
                stack.pop()
        elif ft == "folder":
            paths[xml_key] = list(stack)
            stack.append(_display_name(xml_key))
        else:
            paths[xml_key] = list(stack)
    return paths


def _render_steps_body(step_xml: str, schema_version: str, _errors: list | None = None,
                       _label: str = "") -> str:
    """Return plain-text step body for a script. Empty string on any error."""
    if not step_xml:
        return ""
    try:
        from corpusfm.core.rendering.step_renderer import render_script
        from corpusfm.core.rendering.catalog import load_catalog
        catalog, _ = load_catalog(schema_version)
        elem = ET.fromstring(step_xml)
        rendered = render_script(elem, catalog, show_hidden=False)
        return "\n".join(
            ("// " if rs.disabled else "   ") + rs.full_text for rs in rendered
        )
    except Exception as exc:
        if _errors is not None:
            _errors.append(f"{_label or 'script'} steps: {exc}")
        logger.debug("step render error: %s", exc)
        return ""


def _render_item_text(section_key: str, name: str, xml_str: str,
                      _errors: list | None = None, **kwargs) -> str:
    """Return '{summary}\\n{body}' for a catalog item. Falls back to name on error."""
    try:
        from corpusfm.core.rendering.section_renderer import render_section_item
        ri = render_section_item(section_key, name, xml_str, **kwargs)
        parts = [ri.summary or name]
        if ri.body:
            parts.append(ri.body)
        return "\n".join(parts)
    except Exception as exc:
        if _errors is not None:
            _errors.append(f"{section_key}/{name}: {exc}")
        logger.debug("render error %s/%s: %s", section_key, name, exc)
        return name


def assemble_rendered_text(section_key: str, name: str, primary_xml: str, *,
                           rk: dict | None = None, steps_xml: str = "",
                           is_addon: bool = False, name_map: dict | None = None,
                           schema_version: str = "", _errors: list | None = None) -> str:
    """Produce an item's rendered_text from its primary XML + render inputs.

    THE single render-assembly path — called by both ingest (inputs from ParseResult) and
    the self-heal (inputs reconstructed from the stored artifact). Sharing it guarantees a
    healed re-render is byte-identical to a fresh ingest, which is load-bearing: rendered_text
    is the Diff change-fingerprint, so any divergence would manufacture phantom diffs."""
    # Pass name_map INTO the renderer (not just the post-pass below) so a field
    # formula's UUIDs resolve BEFORE it is split into indented lines — a multi-line
    # resolved value then inherits the formula's indent instead of going flush-left.
    rk2 = {**(rk or {}), "name_map": name_map} if (is_addon and name_map) else (rk or {})
    rendered = _render_item_text(section_key, name, primary_xml, _errors=_errors, **rk2)
    if steps_xml:
        step_body = _render_steps_body(steps_xml, schema_version, _errors=_errors, _label=name)
        if step_body:
            rendered = f"{rendered}\n--- Steps ---\n{step_body}"
    if is_addon and name_map and rendered:
        rendered = _apply_name_map(rendered, name_map)
    return rendered


def _build_to_base_table_map(result: object) -> dict:
    """Return {to_name: base_table_name} from TableOccurrenceCatalog."""
    to_base: dict = {}
    for to_xml in (result.section_xml or {}).get("TableOccurrenceCatalog", {}).values():
        if not to_xml or _folder_type(to_xml):
            continue
        try:
            elem = ET.fromstring(to_xml)
            to_name = elem.get("name", "")
            if not to_name:
                continue
            src_ref = elem.find("BaseTableSourceReference")
            if src_ref is not None and src_ref.get("type") == "BaseTableReference":
                bt = src_ref.find("BaseTableReference")
                to_base[to_name] = bt.get("name", to_name) if bt is not None else to_name
            else:
                to_base[to_name] = to_name
        except ET.ParseError:
            pass
    return to_base


# ---------------------------------------------------------------------------
# Stage 1: Parse
# ---------------------------------------------------------------------------

def _stage_parse(state: PipelineState) -> None:
    from corpusfm.core.parser import load_file
    state.result = load_file(state.xml_bytes, state.label)


# ---------------------------------------------------------------------------
# Stage 2: Mine (XRef graph via existing builder)
# ---------------------------------------------------------------------------

def _stage_mine(state: PipelineState) -> None:
    from corpusfm.core.xref.graph import build_xref_graph
    state.xref_graph = build_xref_graph(state.result)


# ---------------------------------------------------------------------------
# Stage 3: Gap analyze
# ---------------------------------------------------------------------------

def _stage_gap_analyze(state: PipelineState) -> None:
    if state.result.is_addon:
        return  # gap analyzer is SaveAsXML-specific
    try:
        from corpusfm.tools.xml_inspector import inspect as xml_inspect
        from corpusfm.tools.gap_analyzer import analyze
        from corpusfm.core.schemas.registry import load_mapping_config
        inspector = xml_inspect(state.xml_bytes)
        if inspector.error:
            return
        config, _ = load_mapping_config(state.result.schema_version)
        state.gap_report = analyze(inspector, config)
    except Exception as exc:
        logger.warning("gap analyze failed: %s", exc)
        state.analyzer_failed.append("gap_analyze")  # packet 072-D: crashed ≠ clean


# ---------------------------------------------------------------------------
# Stage 3b: Structure mine
# ---------------------------------------------------------------------------

def _stage_structure_mine(state: PipelineState) -> None:
    try:
        from corpusfm.core.schemas.registry import load_structure_catalog
        from corpusfm.core.structure_catalog.miner import mine

        schema_ver = state.result.schema_version or ""
        catalog, _ = load_structure_catalog(schema_ver)

        fields_section = (state.result.section_xml or {}).get("FieldsForTables", {})
        state.structure_snapshot = mine(
            step_xml=state.result.step_xml or {},
            fields_section_xml=fields_section,
            catalog=catalog,
        )
    except Exception as exc:
        logger.warning("structure mine failed: %s", exc)
        state.analyzer_failed.append("structure_mine")  # packet 072-D: crashed ≠ clean


# ---------------------------------------------------------------------------
# Stage 4: Dead ends
# ---------------------------------------------------------------------------

def _stage_dead_ends(state: PipelineState) -> None:
    from corpusfm.core.xref.dead_ends import compute_dead_ends
    try:
        state.dead_ends = compute_dead_ends(state.result, state.xref_graph)
    except Exception as exc:
        logger.warning("dead-end computation failed: %s", exc)


# ---------------------------------------------------------------------------
# Stage 5: Assemble items
# ---------------------------------------------------------------------------

_SCRIPT_SECTIONS = frozenset({"ScriptCatalog"})
_CF_SECTIONS = frozenset({"CustomFunctionsCatalog"})
_VL_SECTIONS = frozenset({"ValueListCatalog"})


def _stage_assemble_items(state: PipelineState) -> None:
    result = state.result
    name_map = state.name_map
    schema_ver = result.schema_version

    to_base = _build_to_base_table_map(result)

    # Extended privileges xml for PrivilegeSetsCatalog rendering
    ext_privs_xml: dict = {}
    for ep_key, ep_xml in (result.section_xml or {}).get("ExtendedPrivilegesCatalog", {}).items():
        ext_privs_xml[_display_name(ep_key)] = ep_xml

    # (section_key, display_name) → item_id, built as we go for xref resolution
    name_to_id: dict = {}
    items: dict = {}

    for section_key, xml_section in (result.section_xml or {}).items():
        folder_paths = _compute_folder_paths(xml_section)

        for xml_key, xml_str in xml_section.items():
            if not xml_str:
                continue

            display = _display_name(xml_key)

            # Resolve name: addon UUID keys → human label; SaveAsXML → display_name
            if result.is_addon:
                name = name_map.get(xml_key)
                if name is None and section_key == "FieldsForTables" and "::" in xml_key:
                    # Addon FieldsForTables key is TABLE_UUID::FIELD_UUID.  Resolve both
                    # parts so the name matches SaveAsXML's TABLE::FIELD format — required
                    # for consistent rendered_text when diffing a SaveAsXML against its
                    # companion addon (same data, same fingerprint, no false "changed").
                    _tpart, _fpart = xml_key.split("::", 1)
                    _field_name = name_map.get(_fpart)
                    _table_name = name_map.get(_tpart)
                    if _field_name is not None:
                        name = f"{_table_name}::{_field_name}" if _table_name else _field_name
                if name is None:
                    name = name_map.get(display, display)
            else:
                name = display

            fm_uuid_val = _fm_uuid(xml_str)
            item_id = make_item_id(section_key, fm_uuid_val, name)

            # Resolve collision for non-UUID items that share the same safe-name
            if item_id in items:
                item_id = f"{section_key}/{xml_key}"

            name_to_id[(section_key, display)] = item_id
            folder_path = folder_paths.get(xml_key, [])
            if result.is_addon and name_map:
                folder_path = [name_map.get(fp, fp) for fp in folder_path]
            is_fld = bool(_folder_type(xml_str))
            # For FieldsForTables fields without a folder path, derive table name from key
            # (SaveAsXML keys are TABLE_NAME::FIELD_NAME; addon keys are TABLE_UUID::FIELD_UUID)
            if not is_fld and not folder_path and section_key == "FieldsForTables" and "::" in xml_key:
                table_part = xml_key.split("::", 1)[0]
                if result.is_addon and name_map:
                    folder_path = [name_map.get(table_part, table_part)]
                else:
                    folder_path = [table_part]
            attrs = _elem_attrs(xml_str)

            # Build xml_sources (primary catalog first, supplemental after). Every render
            # input that isn't on the primary element is stored here so rendered_text can be
            # re-derived from the artifact alone (used by re-ingestion / clip emit; the old lazy
            # self-heal that consumed these was retired in packet 1062).
            sources = [XmlSource(catalog=section_key, xml=xml_str)]
            if section_key in _SCRIPT_SECTIONS:
                sxml = result.step_xml.get(display, "")
                if sxml:
                    sources.append(XmlSource(catalog="StepsForScripts", xml=sxml))
            elif section_key in _CF_SECTIONS:
                cxml = result.cf_xml.get(display, "")
                if cxml:
                    sources.append(XmlSource(catalog="CalcsForCustomFunctions", xml=cxml))
            elif section_key in _VL_SECTIONS:
                oxml = result.options_xml.get(display, "")
                if oxml:
                    sources.append(XmlSource(catalog="ValueListOptions", xml=oxml))

            # Renderer kwargs per section type
            rk: dict = {}
            if section_key == "BaseTableCatalog":
                rk["field_names"] = result.field_names.get(display, [])
            elif section_key in _CF_SECTIONS:
                rk["calc_xml_str"] = result.cf_xml.get(display, "")
            elif section_key in _VL_SECTIONS:
                rk["options_xml"] = result.options_xml.get(display, "")
            elif section_key == "PrivilegeSetsCatalog":
                rk["ext_privs_xml"] = ext_privs_xml

            steps_xml = (result.step_xml.get(display, "")
                         if section_key in _SCRIPT_SECTIONS and not is_fld else "")
            rendered = assemble_rendered_text(
                section_key, name, xml_str, rk=rk, steps_xml=steps_xml,
                is_addon=result.is_addon, name_map=name_map, schema_version=schema_ver,
                _errors=state.render_errors)

            # Dead-end flag — folders are always False; real items use is_dead_end()
            # which covers Scripts, CFs, Value Lists, Fields, and Layouts (Phase 3+).
            dead_end = False
            de = state.dead_ends
            if de is not None and not is_fld:
                dead_end = de.is_dead_end(section_key, display)

            items[item_id] = ArtifactItem(
                item_id=item_id,
                section=section_key,
                name=name,
                xml_key=xml_key,
                fm_uuid=fm_uuid_val,
                attributes=attrs,
                xml_sources=sources,
                rendered_text=rendered,
                summary=None,
                is_folder=is_fld,
                folder_path=folder_path,
                dead_end=dead_end,
                # (packet 053) mark calc-bearing fields so they become summarizable items.
                has_calc=(section_key == "FieldsForTables" and not is_fld
                          and _field_has_calc(xml_str)),
            )

    state.items = items

    # Build XRefRecord list from XRefGraph
    xref = state.xref_graph
    records: list = []

    def _resolved_name(raw: str) -> str:
        return name_map.get(raw, raw) if result.is_addon else raw

    # Script → script (ScriptReference), enriched with control flow + parameter data
    # flow (rung-4): `via` carries the parameter the call passes, `cond` the nearest
    # enclosing guard ("" = unconditional). Emitted from script_call_details (distinct
    # called/param/guard triples); falls back to the flat script_calls list otherwise.
    _call_details = getattr(xref, "script_call_details", None) or {}

    def _trim(s: str, n: int) -> str:
        s = " ".join((s or "").split())
        return (s[:n] + "…") if len(s) > n else s

    for sname, called_list in (getattr(xref, "script_calls", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            state.miner_skipped.append(f"ScriptCatalog/{sname}")
            continue
        details = _call_details.get(sname)
        triples = details if details else [(c, "", "") for c in called_list]
        for called, param, guard in triples:
            to_id = name_to_id.get(("ScriptCatalog", called))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(sname),
                    to=to_id, to_name=_resolved_name(called),
                    type="ScriptReference",
                    via=_trim(param, 80), cond=_trim(guard, 100),
                ))
            else:
                state.unresolved_uuids.append(f"ScriptCatalog/{called}")

    # Addon field items carry the RESOLVED name (e.g. ESAQUEUE::UUID); name_to_id is
    # keyed by the raw xml_key display, so resolve against the item names directly.
    _field_name_to_id = {it.name: iid for iid, it in items.items()
                         if it.section == "FieldsForTables"}

    # Script → field (FieldReference) via TO→BaseTable resolution, with data-flow
    # direction: a field a script WRITES (mutating-step target) vs one it READS
    # (operand or calculation dependency). One edge per (script, field); write wins
    # when a field is both. This is the rung-4 data-effects substrate.
    script_writes = getattr(xref, "script_writes_fields", None) or {}
    for sname, field_refs in (getattr(xref, "script_uses_fields", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            continue
        written = set(script_writes.get(sname, ()))
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = name_to_id.get(("FieldsForTables", field_key))
            if to_id is None and result.is_addon and name_map:
                to_id, field_key = _resolve_addon_field_ref(to_ref, name_map, _field_name_to_id)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(sname),
                    to=to_id, to_name=field_key,
                    type="FieldReference",
                    mode="write" if to_ref in written else "read",
                ))
            else:
                state.unresolved_uuids.append(f"FieldsForTables/{to_ref}")

    # Script → table via ExecuteSQL — the SQL blind spot, made a visible edge.
    # FM SQL names table-occurrence names; resolve to the TO when known, otherwise
    # keep the raw SQL name (FM system tables like FileMaker_Tables won't resolve).
    for sname, sql_tables in (getattr(xref, "script_sql_tables", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            continue
        for tbl in sql_tables:
            to_id = name_to_id.get(("TableOccurrenceCatalog", tbl), "")
            records.append(XRefRecord(
                from_id=from_id, from_name=_resolved_name(sname),
                to=to_id, to_name=tbl,
                type="SQLQuery", mode="read", via="sql",
            ))

    # Script dynamic/opaque dispatch — runtime-computed targets a static graph can't
    # resolve (Perform Script by computed name, Set Field By Name, Insert from URL).
    # Surfaced as edges (no target) so a workflow can declare the honest limit.
    for sname, notes in (getattr(xref, "script_dynamic_dispatch", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            continue
        for note in notes:
            records.append(XRefRecord(
                from_id=from_id, from_name=_resolved_name(sname),
                to="", to_name=note,
                type="DynamicDispatch", via="dynamic",
            ))

    # CF → CF (CustomFunctionReference in formula text)
    for cf_name, called_list in (getattr(xref, "cf_calls_cf", None) or {}).items():
        from_id = name_to_id.get(("CustomFunctionsCatalog", cf_name))
        if not from_id:
            continue
        for called in called_list:
            to_id = name_to_id.get(("CustomFunctionsCatalog", called))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(cf_name),
                    to=to_id, to_name=_resolved_name(called),
                    type="CustomFunctionReference",
                ))

    # Relationship → field (join predicates)
    for rel_name, field_refs in (getattr(xref, "relationship_uses_field", None) or {}).items():
        from_id = name_to_id.get(("RelationshipCatalog", rel_name))
        if not from_id:
            continue
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = name_to_id.get(("FieldsForTables", field_key))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(rel_name),
                    to=to_id, to_name=field_key,
                    type="RelationshipJoin",
                ))

    # Relationship → TO↔TO adjacency (rung-2 topology). The relationship catalog
    # renders its predicate, but TO-to-TO reachability — the spine of how FM data
    # connects — was not a queryable edge. Each relationship links a Left and Right
    # TableOccurrence; FM traverses it both ways, so emit both directions. `via`
    # carries the relationship id so the edge resolves back to its predicate.
    for rel_key, rel_xml in (result.section_xml or {}).get("RelationshipCatalog", {}).items():
        if not rel_xml:
            continue
        try:
            rel_el = ET.fromstring(rel_xml)
        except ET.ParseError:
            continue
        left = rel_el.find("./LeftTable/TableOccurrenceReference")
        right = rel_el.find("./RightTable/TableOccurrenceReference")
        if left is None or right is None:
            continue
        ln, rn = left.get("name", ""), right.get("name", "")
        lid = name_to_id.get(("TableOccurrenceCatalog", ln))
        rid = name_to_id.get(("TableOccurrenceCatalog", rn))
        if not (lid and rid):
            continue
        rel_id = _display_name(rel_key)
        for a_id, a_n, b_id, b_n in ((lid, ln, rid, rn), (rid, rn, lid, ln)):
            records.append(XRefRecord(
                from_id=a_id, from_name=_resolved_name(a_n),
                to=b_id, to_name=_resolved_name(b_n),
                type="RelationshipTO", via=rel_id))

    _uuid_to_name = getattr(xref, "uuid_to_name", None) or {}
    _field_ref_uuid_to_key = getattr(xref, "field_ref_uuid_to_key", None) or {}

    def _resolve_field_id(to_ref: str):
        """Resolve a parsed 'TO::Field' calc reference to a field item id.

        SaveAsXML: name path (TO→base, then base::field) — the primary, verified path.
        Addon: calc text references fields by their *name-suffix* UUID
        (`com.fmi.tableoccurrence.field.<TO>::<FIELD_UUID>`), so the field part is a
        32-hex UUID resolved via field_ref_uuid_to_key. (uuid_to_name is keyed on the
        field's <UUID> child, a different value, so it does not serve this path.)
        """
        if "::" not in to_ref:
            return None, ""
        to_part, field_part = to_ref.split("::", 1)
        field_key = f"{to_base.get(to_part, to_part)}::{field_part}"
        to_id = name_to_id.get(("FieldsForTables", field_key))
        if to_id is None:
            resolved = _field_ref_uuid_to_key.get(field_part)  # addon: name-suffix UUID → field xml_key
            if resolved is None:
                resolved = _uuid_to_name.get(field_part)       # legacy: field <UUID> → "BaseTable::FieldName"
            if resolved:
                to_id = name_to_id.get(("FieldsForTables", resolved))
                field_key = resolved
        return to_id, field_key

    # CF → field (cf_uses_fields, parsed from the function body)
    for cf_name, field_refs in (getattr(xref, "cf_uses_fields", None) or {}).items():
        from_id = name_to_id.get(("CustomFunctionsCatalog", cf_name))
        if not from_id:
            continue
        for to_ref in field_refs:
            to_id, field_key = _resolve_field_id(to_ref)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(cf_name),
                    to=to_id, to_name=field_key,
                    type="CustomFunctionField",
                ))

    # Case-insensitive CF lookups, for recovering no-paren CF calls the formula
    # parser misparses as field refs in addon calcs (FM strips parens from 0-arg
    # CF calls). FM resolves an unqualified bareword to a function before a field,
    # so a ref matching a known CF that resolves to NO field is a CF call.
    _cf_lower_to_id: dict = {}
    _cf_lower_to_name: dict = {}
    for (sec, nm), iid in name_to_id.items():
        if sec == "CustomFunctionsCatalog":
            _cf_lower_to_id[nm.lower()] = iid
            _cf_lower_to_name[nm.lower()] = nm
    _field_cf_pairs: set = set()  # (from_id, cf_id) FieldCFCall edges already emitted

    # Field calculation → field (a calc/auto-enter/validation reads other fields)
    for field_xml_key, field_refs in (getattr(xref, "field_calc_uses_fields", None) or {}).items():
        from_id = name_to_id.get(("FieldsForTables", field_xml_key))
        if not from_id:
            continue
        for to_ref in field_refs:
            to_id, field_key = _resolve_field_id(to_ref)
            if to_id and to_id != from_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(field_xml_key),
                    to=to_id, to_name=field_key,
                    type="FieldCalculation",
                ))
            elif to_id is None:
                name_part = to_ref.split("::", 1)[1] if "::" in to_ref else to_ref
                cf_id = _cf_lower_to_id.get(name_part.lower())
                if cf_id and (from_id, cf_id) not in _field_cf_pairs:
                    _field_cf_pairs.add((from_id, cf_id))
                    records.append(XRefRecord(
                        from_id=from_id, from_name=_resolved_name(field_xml_key),
                        to=cf_id, to_name=_cf_lower_to_name.get(name_part.lower(), name_part),
                        type="FieldCFCall",
                    ))

    # Field calculation → custom function (parenthesized CF calls)
    for field_xml_key, cf_names in (getattr(xref, "field_calc_calls_cf", None) or {}).items():
        from_id = name_to_id.get(("FieldsForTables", field_xml_key))
        if not from_id:
            continue
        for cf_name in cf_names:
            to_id = name_to_id.get(("CustomFunctionsCatalog", cf_name))
            if to_id and (from_id, to_id) not in _field_cf_pairs:
                _field_cf_pairs.add((from_id, to_id))
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(field_xml_key),
                    to=to_id, to_name=_resolved_name(cf_name),
                    type="FieldCFCall",
                ))

    # Layout → field (UUID-based, structural FieldReference elements)
    for layout_uuid, field_uuid_list in (getattr(xref, "layout_uses_field_uuids", None) or {}).items():
        layout_name = _uuid_to_name.get(layout_uuid, "")
        from_id = name_to_id.get(("LayoutCatalog", layout_name))
        if not from_id:
            continue
        for field_uuid in field_uuid_list:
            field_key = _uuid_to_name.get(field_uuid, "")  # already "BaseTable::FieldName"
            if not field_key:
                continue
            to_id = name_to_id.get(("FieldsForTables", field_key))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=field_key,
                    type="LayoutField",
                ))

    # Layout → VL (UUID-based, structural ValueListReference elements)
    for layout_uuid, vl_uuid_list in (getattr(xref, "layout_uses_vl_uuids", None) or {}).items():
        layout_name = _uuid_to_name.get(layout_uuid, "")
        from_id = name_to_id.get(("LayoutCatalog", layout_name))
        if not from_id:
            continue
        for vl_uuid in vl_uuid_list:
            vl_name = _uuid_to_name.get(vl_uuid, "")
            if not vl_name:
                continue
            to_id = name_to_id.get(("ValueListCatalog", vl_name))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=_resolved_name(vl_name),
                    type="LayoutValueList",
                ))

    # Field → VL (FieldsForTables validation: "In Value List")
    for vl_uuid, field_uuid_list in (getattr(xref, "vl_used_in_field_uuids", None) or {}).items():
        vl_name = _uuid_to_name.get(vl_uuid, "")
        vl_id = name_to_id.get(("ValueListCatalog", vl_name))
        if not vl_id:
            continue
        for field_uuid in field_uuid_list:
            field_name = _uuid_to_name.get(field_uuid, "")
            field_id = name_to_id.get(("FieldsForTables", field_name))
            if field_id:
                records.append(XRefRecord(
                    from_id=field_id, from_name=field_name,
                    to=vl_id, to_name=_resolved_name(vl_name),
                    type="FieldValidation",
                ))

    # Relationship → VL (portal sort-by-value-list order)
    for vl_uuid, rel_key_list in (getattr(xref, "vl_used_in_relationship_ids", None) or {}).items():
        vl_name = _uuid_to_name.get(vl_uuid, "")
        vl_id = name_to_id.get(("ValueListCatalog", vl_name))
        if not vl_id:
            continue
        for rel_xml_key in rel_key_list:
            rel_id = name_to_id.get(("RelationshipCatalog", rel_xml_key))
            if rel_id:
                records.append(XRefRecord(
                    from_id=rel_id, from_name=rel_xml_key,
                    to=vl_id, to_name=_resolved_name(vl_name),
                    type="RelationshipSort",
                ))

    # Script → VL (Sort Records / Sort Portal steps sorted by value list)
    for vl_uuid, script_name_list in (getattr(xref, "vl_used_in_script_names", None) or {}).items():
        vl_name = _uuid_to_name.get(vl_uuid, "")
        vl_id = name_to_id.get(("ValueListCatalog", vl_name))
        if not vl_id:
            continue
        for script_name in script_name_list:
            script_id = name_to_id.get(("ScriptCatalog", script_name))
            if script_id:
                records.append(XRefRecord(
                    from_id=script_id, from_name=_resolved_name(script_name),
                    to=vl_id, to_name=_resolved_name(vl_name),
                    type="ScriptSort",
                ))

    # Layout → field (formula-based: hide-object, conditional formatting, etc.)
    for layout_name, field_refs in (getattr(xref, "layout_formula_field_refs", None) or {}).items():
        from_id = name_to_id.get(("LayoutCatalog", layout_name))
        if not from_id:
            continue
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = name_to_id.get(("FieldsForTables", field_key))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=field_key,
                    type="LayoutCalculation",
                ))

    # Layout → CF (formula-based: layout conditions calling custom functions)
    for layout_name, cf_names in (getattr(xref, "layout_formula_cf_calls", None) or {}).items():
        from_id = name_to_id.get(("LayoutCatalog", layout_name))
        if not from_id:
            continue
        for cf_name in cf_names:
            to_id = name_to_id.get(("CustomFunctionsCatalog", cf_name))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=_resolved_name(cf_name),
                    type="LayoutCFCall",
                ))

    # Custom menu → field (formula-based)
    for menu_name, field_refs in (getattr(xref, "menu_formula_field_refs", None) or {}).items():
        from_id = name_to_id.get(("CustomMenuCatalog", menu_name))
        if not from_id:
            continue
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = name_to_id.get(("FieldsForTables", field_key))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(menu_name),
                    to=to_id, to_name=field_key,
                    type="MenuCalculation",
                ))

    # Custom menu → CF (formula-based)
    for menu_name, cf_names in (getattr(xref, "menu_formula_cf_calls", None) or {}).items():
        from_id = name_to_id.get(("CustomMenuCatalog", menu_name))
        if not from_id:
            continue
        for cf_name in cf_names:
            to_id = name_to_id.get(("CustomFunctionsCatalog", cf_name))
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(menu_name),
                    to=to_id, to_name=_resolved_name(cf_name),
                    type="MenuCFCall",
                ))

    # ── Entry-point edges (user actions → scripts) ────────────────────────────
    # A workflow begins where a USER acts: a layout/object ScriptTrigger, a Button,
    # or a custom-menu command that runs a script. The Explorer parsed these inline
    # but they never reached the canonical graph, so workflows could not be traced
    # from the things a person actually clicks. Emit them as LayoutScript / MenuScript
    # so the graph becomes traversable from its entry points (rung-4 workflow analysis).
    from corpusfm.core import safe_xml as _ET

    def _layout_script_refs(elem) -> list:
        # Each (script, via) a user-invoked script is reached by. `via` carries the
        # trigger EVENT (ScriptTrigger @action, e.g. "OnLayoutEnter") or "button" —
        # so a workflow says *how* it is invoked, not just from where. Covers all FM
        # forms: layout/object ScriptTriggers and Button/ButtonObj (older action and
        # modern Perform-Script-step). Dedup on (name, via) is per-layout.
        out: list = []
        for trig in elem.iter("ScriptTrigger"):
            via = trig.get("action") or trig.get("name") or trig.get("event") or "trigger"
            for sr in trig.iter("ScriptReference"):
                if sr.get("name"):
                    out.append((sr.get("name"), via))
        for tag in ("Button", "ButtonObj"):
            for parent in elem.iter(tag):
                for sr in parent.iter("ScriptReference"):
                    if sr.get("name"):
                        out.append((sr.get("name"), "button"))
        return out

    def _menu_script_refs(elem) -> list:
        return [(sr.get("name"), "menu command")
                for sr in elem.iter("ScriptReference") if sr.get("name")]

    def _emit_entry_edges(section_key: str, edge_type: str, finder) -> None:
        for xml_key, xml_str in (result.section_xml or {}).get(section_key, {}).items():
            if not xml_str:
                continue
            from_id = name_to_id.get((section_key, _display_name(xml_key)))
            if not from_id:
                continue
            try:
                elem = _ET.fromstring(xml_str)
            except _ET.ParseError:
                continue
            seen: set = set()
            for sname, via in finder(elem):
                if (sname, via) in seen:
                    continue
                seen.add((sname, via))
                to_id = name_to_id.get(("ScriptCatalog", sname))
                if to_id:
                    records.append(XRefRecord(
                        from_id=from_id, from_name=_resolved_name(_display_name(xml_key)),
                        to=to_id, to_name=_resolved_name(sname),
                        type=edge_type, via=via,
                    ))

    _emit_entry_edges("LayoutCatalog", "LayoutScript", _layout_script_refs)
    _emit_entry_edges("CustomMenuCatalog", "MenuScript", _menu_script_refs)

    # File-level entry points: startup/shutdown/window ScriptTriggers live in the
    # file's Metadata block (not in any catalog), so the catalog scan misses them.
    # "What runs when the file opens" is a first-class workflow — stream the raw XML
    # and capture file/window-scoped ScriptTriggers that are NOT inside a Layout.
    _FILE_TRIGGER_ACTIONS = {"OnFirstWindowOpen", "OnLastWindowClose",
                             "OnWindowOpen", "OnWindowClose"}
    # Big repeating subtrees cleared on their 'end' to bound memory (ScriptReference
    # attrs survive — they're only cleared with their processed ScriptTrigger parent).
    _CLEARABLE = {"Layout", "Script", "BaseTable", "Theme", "CustomFunction",
                  "ValueList", "Relationship", "TableOccurrence", "CustomMenu"}
    try:
        import io as _io
        layout_depth = 0
        file_seen: set = set()
        for ev, el in _ET.iterparse(_io.BytesIO(state.xml_bytes), events=("start", "end")):
            if ev == "start":
                if el.tag == "Layout":
                    layout_depth += 1
                continue
            if el.tag == "Layout":
                layout_depth -= 1
                el.clear()
            elif el.tag == "ScriptTrigger" and layout_depth == 0:
                action = el.get("action", "")
                if action in _FILE_TRIGGER_ACTIONS:
                    sr = el.find(".//ScriptReference")
                    sname = sr.get("name", "") if sr is not None else ""
                    to_id = name_to_id.get(("ScriptCatalog", sname)) if sname else None
                    if to_id and (sname, action) not in file_seen:
                        file_seen.add((sname, action))
                        records.append(XRefRecord(
                            from_id="", from_name=result.label or "File",
                            to=to_id, to_name=_resolved_name(sname),
                            type="FileScript", via=action,
                        ))
                el.clear()
            elif el.tag in _CLEARABLE:
                el.clear()
    except Exception:
        pass

    # ── Security graph (rung-2): privilege set → the objects it can reach ──────
    # A privset's <access> lists per-object access. Layout/Script/ValueList carry an
    # `access` attr; a Table splits it across View/Edit/Create/Delete children. Emit
    # an edge for every object the set can actually reach (access != NoAccess), with
    # the level in `via` — so "what can the Manager privset see/do" is traceable, and
    # a privilege-gated workflow can be reasoned about. (Default/uniform sets carry no
    # per-object list — only Custom sets produce edges.)
    _PRIV_REF = {"Layout": ("LayoutCatalog", "LayoutReference"),
                 "Script": ("ScriptCatalog", "ScriptReference"),
                 "ValueList": ("ValueListCatalog", "ValueListReference")}
    for ps_key, ps_xml in (result.section_xml or {}).get("PrivilegeSetsCatalog", {}).items():
        ps_name = _display_name(ps_key)
        from_id = name_to_id.get(("PrivilegeSetsCatalog", ps_name))
        if not (from_id and ps_xml):
            continue
        try:
            ps_el = _ET.fromstring(ps_xml)
        except _ET.ParseError:
            continue
        # Layout / Script / ValueList — access attr on the element itself.
        for tag, (section_key, ref_tag) in _PRIV_REF.items():
            for entry in ps_el.iter(tag):
                access = entry.get("access", "")
                ref = entry.find(ref_tag)
                if not access or access == "NoAccess" or ref is None:
                    continue
                to_id = name_to_id.get((section_key, ref.get("name", "")))
                if to_id:
                    records.append(XRefRecord(
                        from_id=from_id, from_name=_resolved_name(ps_name),
                        to=to_id, to_name=_resolved_name(ref.get("name", "")),
                        type="PrivilegeAccess", via=access))
        # Table — reachable if View != NoAccess; write if any of Edit/Create/Delete grant.
        for tbl in ps_el.iter("Table"):
            ref = tbl.find("BaseTableReference")
            if ref is None:
                continue
            def _acc(child):
                c = tbl.find(child)
                return c.get("access", "") if c is not None else ""
            view = _acc("View")
            if not view or view == "NoAccess":
                continue
            to_id = name_to_id.get(("BaseTableCatalog", ref.get("name", "")))
            if to_id:
                can_write = any(_acc(c) not in ("", "NoAccess") for c in ("Edit", "Create", "Delete"))
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(ps_name),
                    to=to_id, to_name=_resolved_name(ref.get("name", "")),
                    type="PrivilegeAccess", mode="write" if can_write else "read", via=view))

    # Account → privilege set (non-sensitive; the password stays redacted).
    for ac_key, ac_xml in (result.section_xml or {}).get("AccountsCatalog", {}).items():
        if not ac_xml:
            continue
        from_id = name_to_id.get(("AccountsCatalog", _display_name(ac_key)))
        if not from_id:
            continue
        try:
            psr = _ET.fromstring(ac_xml).find(".//PrivilegeSetReference")
        except _ET.ParseError:
            psr = None
        if psr is None:
            continue
        to_id = name_to_id.get(("PrivilegeSetsCatalog", psr.get("name", "")))
        if to_id:
            records.append(XRefRecord(
                from_id=from_id, from_name=_resolved_name(_display_name(ac_key)),
                to=to_id, to_name=_resolved_name(psr.get("name", "")),
                type="AccountPrivilege"))

    # ── Trigger cascades (rung-4): navigation → the destination's enter-trigger ──
    # A Go to Layout fires the destination layout's OnLayoutEnter trigger — a hidden
    # workflow continuation a flat call graph misses. Emit the navigation itself
    # (ScriptNavigate) and, where the destination has an enter-trigger, the implied
    # call (TriggerCascade script→triggered-script). Derived from the LayoutScript
    # entry edges already in `records`.
    _ENTER_EVENTS = {"OnLayoutEnter", "OnRecordLoad"}
    enter_triggers: dict = {}   # layout name → [(script_id, script_name)]
    for r in records:
        if r.type == "LayoutScript" and r.via in _ENTER_EVENTS:
            enter_triggers.setdefault(r.from_name, []).append((r.to, r.to_name))
    for sname, lnames in (getattr(xref, "script_navigates_layouts", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            continue
        for lname in lnames:
            lid = name_to_id.get(("LayoutCatalog", lname))
            if lid:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(sname),
                    to=lid, to_name=_resolved_name(lname),
                    type="ScriptNavigate", via="Go to Layout"))
            for trig_id, trig_name in enter_triggers.get(_resolved_name(lname), ()):
                if trig_id and trig_id != from_id:
                    records.append(XRefRecord(
                        from_id=from_id, from_name=_resolved_name(sname),
                        to=trig_id, to_name=trig_name,
                        type="TriggerCascade", via=f"OnLayoutEnter@{lname}"))

    # ── Relationship traversal (rung-2 C): the TO context a script lands the user
    # in via Go to Related Record. "Where they end up", as opposed to which layout
    # is shown — a workflow's data context after navigation.
    for sname, tnames in (getattr(xref, "script_navigates_tos", None) or {}).items():
        from_id = name_to_id.get(("ScriptCatalog", sname))
        if not from_id:
            continue
        for tname in tnames:
            tid = name_to_id.get(("TableOccurrenceCatalog", tname))
            if tid:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(sname),
                    to=tid, to_name=_resolved_name(tname),
                    type="ScriptNavigateTO", via="Go to Related Record"))

    state.xref_records = records


# ---------------------------------------------------------------------------
# Stage 6: Build artifact
# ---------------------------------------------------------------------------

def _stage_build_artifact(state: PipelineState) -> Artifact:
    result = state.result
    gap = state.gap_report

    art_type = ArtifactType.ADDON_XML if result.is_addon else ArtifactType.SAVE_AS_XML

    sections = list((result.section_xml or {}).keys())

    sc = state.structure_snapshot
    unknown_step_ids = sc.steps_unknown if sc else []
    unknown_ref_types = gap.unknown_reference_types if gap else []

    if unknown_step_ids:
        logger.warning(
            "unknown step IDs in '%s' (fm_version=%s): %s",
            state.label,
            (state.result.metadata or {}).get("Source", "?"),
            unknown_step_ids,
        )
    if unknown_ref_types:
        logger.warning(
            "unknown reference types in '%s': %s",
            state.label,
            unknown_ref_types,
        )

    # Render-layer diagnostics — deterministic scan of the just-assembled items
    # (unresolved addon refs, empty-with-params steps) + the errors caught during
    # rendering. Never fatal to ingestion.
    try:
        from corpusfm.core.render_diagnostics import scan as _scan_render
        _rd = _scan_render(state.items.values(), result.is_addon, result.schema_version or "")
    except Exception as exc:
        logger.debug("render diagnostics scan failed: %s", exc)
        _rd = {"unresolved_in_render": [], "empty_renders": []}
    if state.render_errors:
        logger.warning("render errors in '%s': %d", state.label, len(state.render_errors))

    profile = CompletenessProfile(
        sections_present=sections,
        sections_absent=gap.stale if gap else [],
        gap_sections_unknown=gap.unmapped if gap else [],
        absent_by_design=[],
        unknown_step_ids=unknown_step_ids,
        unknown_reference_types=unknown_ref_types,
        unresolved_uuids=list(dict.fromkeys(state.unresolved_uuids)),
        miner_skipped=state.miner_skipped,
        unresolved_in_render=_rd["unresolved_in_render"],
        empty_renders=_rd["empty_renders"],
        render_errors=list(dict.fromkeys(state.render_errors)),
        analyzer_failed=list(dict.fromkeys(state.analyzer_failed)),
    )

    metadata = result.metadata or {}
    # An FM file's own name is canonicalized WITH the .fmp12 suffix (the project standard —
    # see core.filenames). Only the root File= attribute is a real FM file name; the label
    # fallback (e.g. a pasted clip fragment, which has no File=) passes through unchanged.
    from corpusfm.core.filenames import ensure_fmp12
    fm_file = metadata.get("File")
    file_name = ensure_fmp12(fm_file) if fm_file else (result.label or "").strip()
    identity = ArtifactIdentity(
        root_uuid=metadata.get("UUID", ""),
        file_name=file_name,
        fm_version=metadata.get("Source", ""),
    )

    try:
        from corpusfm import __version__ as _cfm_build
    except Exception:
        _cfm_build = ""
    provenance = ArtifactProvenance(
        ingested_at=datetime.now(timezone.utc).isoformat(),
        catalog_version=result.schema_version or "",
        source=state.source_type,
        corpusfm_build=_cfm_build,
    )

    # Promote StructureCatalogSnapshot from miner result (or empty placeholder)
    sc_snapshot = state.structure_snapshot
    if sc_snapshot is None:
        sc_snapshot = StructureCatalogSnapshot.empty(
            schema_version=result.schema_version or ""
        )

    # Canonical addon script name (single source of truth). Track-B injection adds
    # this script; this detects it.
    from corpusfm.core.addon.scripts import SAVE_TO_DOCUMENTS as _CFM_EXPORT_SCRIPT
    has_export = any(
        item.name == _CFM_EXPORT_SCRIPT
        for item in state.items.values()
        if not item.is_folder
    )

    from corpusfm.core.rendering.section_renderer import RENDER_VERSION
    artifact = Artifact(
        artifact_version=ARTIFACT_VERSION,
        type=art_type,
        identity=identity,
        provenance=provenance,
        sections=sections,
        items=state.items,
        xref_map=state.xref_records,
        completeness_profile=profile,
        structure_catalog=sc_snapshot,
        has_corpusfm_export=has_export,
        # rendered_text was just produced by the current renderer; stamp it current.
        render_version=RENDER_VERSION,
        # Carry the name_map so addon artifacts are self-contained (no sidecar dependency).
        name_map=(state.name_map or None) if result.is_addon else None,
    )

    # Rung 5 — embed the deterministic structural-intent block so the biscuit is
    # self-contained (AI/MCP read it without recompute). Never fatal to ingestion.
    try:
        from corpusfm.core.structure_intent import compute_structure_block
        artifact.structure_intent = compute_structure_block(artifact)
    except Exception:
        logger.exception("structure-intent embedding failed for '%s'", state.label)

    # Content-hash identity (packet 033, #3) — LAST, so it covers the fully-built artifact.
    return artifact


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ingest(
    xml_bytes: bytes,
    label: str,
    *,
    source_type: str = "manual",
    name_map: Optional[dict] = None,
    keep_source_xml: bool = False,
) -> Artifact:
    """Ingest raw FM XML bytes and return an Artifact.

    Args:
        xml_bytes:       UTF-16 encoded FM XML (FMSaveAsXML or FMAdd_on)
        label:           display label for this file
        source_type:     "manual" | "job"
        name_map:        {uuid_key: human_name} for addon name resolution
        keep_source_xml: passed through to callers who decide whether to
                         persist raw XML alongside the artifact

    Returns:
        Artifact — ready to pass to store_artifact(), Explorer, or git formatter.

    Raises:
        ValueError: if xml_bytes is not a recognised FM XML format with DDR_INFO.
    """
    state = PipelineState(
        xml_bytes=xml_bytes,
        label=label,
        source_type=source_type,
        name_map=name_map or {},
        keep_source_xml=keep_source_xml,
    )
    _stage_parse(state)
    _stage_mine(state)
    _stage_gap_analyze(state)
    _stage_structure_mine(state)
    _stage_dead_ends(state)
    _stage_assemble_items(state)
    return _stage_build_artifact(state)
