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
from corpusfm.core.identity import (
    ID_KIND, UUID_KIND, CatalogIdentity, build_indexes, identity_key, owner_identity,
    owner_identity_from_xml, reference_identity,
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


def _fm_uuid(xml_str: str, section: str = "") -> str:
    """The UUID a catalog item asserts, or "" — one rule, shared with the xref graph."""
    identity = owner_identity_from_xml(section, xml_str)
    return identity.value if identity is not None and identity.kind == UUID_KIND else ""


def _script_body(result, section_key: str, xml_str: str, display: str) -> str:
    """The step body belonging to THIS catalog item.

    Joined on the item's own identity. `step_xml` is keyed by display name, and FM
    permits duplicate script names, so a name lookup hands both twins the surviving
    body — measured in MicroK12_dev, where one script's 59 steps vanished and the
    other's 51 were rendered for both and mined under the wrong UUID. The name view
    stays as the fallback for a fragment that asserts no identity.
    """
    key = identity_key(owner_identity_from_xml(section_key, xml_str))
    by_identity = getattr(result, "step_xml_by_identity", None) or {}
    if key and key in by_identity:
        return by_identity[key]
    return (result.step_xml or {}).get(display, "")


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
            step_xml=(state.result.step_xml_by_identity or state.result.step_xml or {}),
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

#: Sections a STRUCTURED reference can name. A catalog index is built for each so a
#: reference resolves by UUID (else id) rather than through a display name.
_RESOLVABLE_SECTIONS: tuple = (
    "ScriptCatalog", "LayoutCatalog", "ValueListCatalog", "TableOccurrenceCatalog",
    "BaseTableCatalog", "CustomMenuCatalog", "CustomMenuSetCatalog",
    "PrivilegeSetsCatalog", "AccountsCatalog", "ExternalDataSourceCatalog",
    "CustomFunctionsCatalog", "RelationshipCatalog",
)
_VL_SECTIONS = frozenset({"ValueListCatalog"})


def _plan_logical_items(section_xml: dict) -> tuple[dict, list]:
    """Decide one artifact item id per LOGICAL catalog object, before assembly.

    Returns ``(alias, content_key, diagnostics)``. `alias` maps EVERY ``(section, xml_key)`` —
    including the fragments that coalesce away — to the id its logical object will
    carry, so a reference through any fragment's key still lands on one item.

    FileMaker projects a rename as a second catalog fragment carrying the same UUID.
    Assembly used to collide on the second and escape to ``Section/<xml_key>``,
    producing two artifact items for one layout: measured 8 in MicroK12_dev, with 111
    stored edge endpoints landing on the escape ids rather than the UUID id.

    CORRECTION (packet 1353). The 4 groups this once also claimed in
    CMP_Operations_UI_rev2, with 76 endpoints, were NOT renames: CMP has zero
    repeated-UUID groups inside its AddAction node. They appeared only because the
    parser paired a ModifyAction fragment by display name and wrote its UUID onto a
    second key. They no longer occur, and the rule below is unaffected — grouping by
    UUID is right on either reading. 1349 is not reopened; only its CMP evidence is.

    Rules, in order:
      * a non-empty UUID groups fragments — one item at the existing
        ``Section/<UUID>`` id, so every id that exists today is byte-identical;
      * an id-bearing item with no UUID gets ``Section/id:<id>`` only when that id has
        exactly ONE owner in its section. Two DISTINCT objects sharing an id are not
        revisions: both stay visible under their xml_key, and the id is diagnosed and
        excluded rather than one of them being silently merged away;
      * folders, markers, separators and anything asserting no identity keep the
        existing name-derived id with the xml_key escape. They are not
        structured-reference targets.
    """
    alias: dict = {}
    content_key: dict = {}     # item_id -> the xml_key whose XML the item carries
    diagnostics: list = []
    for section_key, xml_section in (section_xml or {}).items():
        by_uuid: dict = {}
        by_id: dict = {}
        for xml_key, xml_str in xml_section.items():
            if not xml_str or _folder_type(xml_str):
                continue
            identity = owner_identity_from_xml(section_key, xml_str)
            if identity is None:
                continue
            (by_uuid if identity.kind == UUID_KIND else by_id).setdefault(
                identity.value, []).append(xml_key)

        for uuid, keys in by_uuid.items():
            item_id = f"{section_key}/{uuid}"
            for key in keys:
                alias[(section_key, key)] = item_id
            # The LAST fragment supplies the current name, but not the content: a
            # ModifyAction projection is a partial redefinition, and in 5 of the 8
            # MicroK12_dev rename groups it is SMALLER than the AddAction fragment it
            # follows (Scripts_AccessLog 1,819 bytes vs Dev_AccessLog 1,203). Taking
            # the last wholesale discarded the full layout body. Content comes from
            # the fullest fragment; the name is applied afterwards.
            if len(keys) > 1:
                content_key[item_id] = max(keys, key=lambda k: len(xml_section.get(k) or ""))

        for id_value, keys in by_id.items():
            if len(keys) == 1:
                alias[(section_key, keys[0])] = f"{section_key}/id:{id_value}"
            else:
                diagnostics.append(
                    f"{section_key}/id:{id_value} claimed by {len(keys)} items: "
                    + ", ".join(sorted(keys))
                )
    return alias, content_key, diagnostics


def _stage_assemble_items(state: PipelineState) -> None:
    result = state.result
    name_map = state.name_map
    schema_ver = result.schema_version

    to_base = _build_to_base_table_map(result)

    # Extended privileges xml for PrivilegeSetsCatalog rendering
    ext_privs_xml: dict = {}
    for ep_key, ep_xml in (result.section_xml or {}).get("ExtendedPrivilegesCatalog", {}).items():
        ext_privs_xml[_display_name(ep_key)] = ep_xml

    # One id per LOGICAL object, decided before assembly; `alias` also routes the
    # fragments that coalesce away, so a reference through any of their keys resolves.
    alias, content_key, alias_diagnostics = _plan_logical_items(result.section_xml)
    state.unresolved_uuids.extend(alias_diagnostics)
    # item_id -> (display name, xml_key) of the LAST fragment of a coalesced group
    coalesced_name: dict = {}

    # (section_key, display_name) → item_id, built as we go for xref resolution.
    # LEGACY: a display name is not a reference (FM permits duplicates), so this is
    # for the formula boundary and for graph maps that have not yet been re-keyed —
    # never for a structured reference that carries a UUID or an id.
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

            fm_uuid_val = _fm_uuid(xml_str, section_key)
            item_id = alias.get((section_key, xml_key))
            if item_id is None:
                item_id = make_item_id(section_key, fm_uuid_val, name)
                # A folder/marker/separator or an identity-less item sharing a
                # safe-name: keep both visible under their own keys.
                if item_id in items:
                    item_id = f"{section_key}/{xml_key}"
                alias[(section_key, xml_key)] = item_id

            name_to_id[(section_key, display)] = item_id
            rep = content_key.get(item_id)
            if rep is not None:
                # A coalesced group: every fragment contributes its current name in
                # document order (last wins), only the fullest contributes content.
                coalesced_name[item_id] = (name, xml_key)
                if xml_key != rep:
                    continue

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
                sxml = _script_body(result, section_key, xml_str, display)
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

            steps_xml = (_script_body(result, section_key, xml_str, display)
                         if section_key in _SCRIPT_SECTIONS and not is_fld else "")
            rendered = assemble_rendered_text(
                section_key, name, xml_str, rk=rk, steps_xml=steps_xml,
                is_addon=result.is_addon, name_map=name_map, schema_version=schema_ver,
                _errors=state.render_errors)

            # Dead-end flag — folders are always False; real items use is_dead_end()
            # which covers Scripts, CFs, Value Lists, Fields, and Layouts (Phase 3+).
            # Keyed on xml_key, not the display name: FM permits duplicate script and
            # layout names, and a name lookup reported the LIVE twin dead (packet 1348).
            dead_end = False
            de = state.dead_ends
            if de is not None and not is_fld:
                dead_end = de.is_dead_end(section_key, xml_key)

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

    # The latest logical name, applied to the item that carries the fullest content.
    for item_id, (name, xml_key) in coalesced_name.items():
        item = items.get(item_id)
        if item is not None:
            item.name, item.xml_key = name, xml_key

    state.items = items

    # ── Structured-reference resolution (packet 1349-C) ───────────────────────
    # A reference carrying a UUID or an id resolves through the catalog index and
    # the logical-item alias. It never goes through the display-name dictionary,
    # because a name is not a reference.
    _catalog_indexes = build_indexes(result.section_xml, _RESOLVABLE_SECTIONS)
    _uuid_to_item = {(it.section, it.fm_uuid): iid
                     for iid, it in items.items() if it.fm_uuid and not it.is_folder}

    def _item_for_identity(section: str, identity) -> str | None:
        index = _catalog_indexes.get(section)
        if index is None or identity is None:
            return None
        resolution = index.resolve(identity)
        if not resolution.resolved:
            return None
        candidates = {alias.get((section, key)) for key in resolution.xml_keys}
        candidates.discard(None)
        return candidates.pop() if len(candidates) == 1 else None

    def _item_for_reference(section: str, ref) -> str | None:
        """The logical item a structured reference element names, or None."""
        if ref is None:
            return None
        return _item_for_identity(section, reference_identity(section, ref))

    def _item_for_uuid(section: str, uuid: str) -> str | None:
        """A target the graph already resolved to a UUID — no name round trip."""
        return _uuid_to_item.get((section, uuid)) if uuid else None

    #: (section, display name) → item id, ONLY where exactly one logical item owns
    #: that name. For the formula boundary, where FM supplies no identity — never a
    #: last-write-wins dictionary.
    # (base table, field id) -> field item. A field id is unique only WITHIN its base
    # table — 108 duplicated field-id groups in MicroK12_dev, 7 in CMP — so a bare
    # (FieldsForTables, id) lookup is invalid and this is the only id route a
    # structured field reference may take.
    _field_by_context: dict = {}
    for iid, it in items.items():
        if it.section != "FieldsForTables" or it.is_folder or "::" not in it.xml_key:
            continue
        fid = (it.attributes or {}).get("id", "")
        if fid:
            _field_by_context.setdefault((it.xml_key.split("::", 1)[0], fid), []).append(iid)
    _field_by_context = {k: v[0] for k, v in _field_by_context.items() if len(v) == 1}

    _unique_name_to_id: dict = {}
    for iid, it in items.items():
        if it.is_folder:
            continue
        nkey = (it.section, _display_name(it.xml_key))
        _unique_name_to_id[nkey] = None if nkey in _unique_name_to_id else iid
    _unique_name_to_id = {k: v for k, v in _unique_name_to_id.items() if v}

    # Add-on formula text can carry locale keys that `name_map` resolves to the
    # item's final human label rather than its raw XML key. Keep that narrow text
    # boundary ambiguity-safe: one logical, non-folder field owns the label or no
    # field does. This is deliberately separate from `_unique_name_to_id`, whose
    # keys are raw catalog display names and cannot represent this add-on form.
    _unique_addon_field_name_to_id: dict = {}
    if result.is_addon and name_map:
        for iid, it in items.items():
            if it.section != "FieldsForTables" or it.is_folder or not it.name:
                continue
            _unique_addon_field_name_to_id[it.name] = (
                None if it.name in _unique_addon_field_name_to_id else iid
            )
        _unique_addon_field_name_to_id = {
            name: iid for name, iid in _unique_addon_field_name_to_id.items()
            if iid is not None
        }

    def _text_target(section: str, name: str) -> str | None:
        """Resolve a target FileMaker named as TEXT — the only sanctioned name match.

        Formula bodies and ExecuteSQL carry no identifier, so their targets have
        nothing but a name. Everything else is a STRUCTURED reference and resolves by
        identity.

        This is deliberately the sole reader of `_unique_name_to_id`, and
        `tests/test_structured_references_never_resolve_by_name.py` fails the build if
        another one appears. The previous guard keyed on the assigned variable being
        `to_id`, which the original wrong-object defect also spelled — it would have
        approved it (Codex confirmation round 2).
        """
        return _unique_name_to_id.get((section, name)) if name else None

    def detail_src(detail: dict) -> dict:
        """The SOURCE end of a detail record, in the shape `_detail_identity` reads."""
        return {"uuid": detail.get("src_uuid", ""), "id": detail.get("src_id", "")}

    def _detail_identity(section: str, detail: dict):
        """The identity a detail record offers — UUID first, else id."""
        uuid = (detail.get("uuid") or "").strip()
        if uuid:
            return CatalogIdentity(section, UUID_KIND, uuid)
        ref_id = (detail.get("id") or "").strip()
        return CatalogIdentity(section, ID_KIND, ref_id) if ref_id else None

    _unresolved_seen: set = set()

    def _resolve_detail_target(section: str, detail: dict) -> str | None:
        """The item a STRUCTURED reference names — by UUID, else by id, never by name.

        An offered identity is authoritative: if it does not match, the answer is
        nothing. A structured reference that offers NO identity resolves to nothing
        either, and is diagnosed — falling back to a display name is exactly how a
        duplicate silently selects the wrong object, and this packet's outcome
        forbids it. Only the formula boundary is name-matched, and it does not come
        through here.
        """
        return _item_for_identity(section, _detail_identity(section, detail))

    def _note_identity(section: str, detail: dict) -> None:
        identity = _detail_identity(section, detail)
        offered = f"{identity.kind}:{identity.value}" if identity else "no-identity"
        entry = f"{section}/{offered}"
        if entry not in _unresolved_seen:
            _unresolved_seen.add(entry)
            state.unresolved_uuids.append(entry)

    def _note_unresolved(section: str, ref) -> None:
        """One bounded line per distinct unresolved structured reference."""
        if ref is None:
            return
        identity = reference_identity(section, ref)
        offered = f"{identity.kind}:{identity.value}" if identity else "no-identity"
        entry = f"{section}/{offered}"
        if entry not in _unresolved_seen:
            _unresolved_seen.add(entry)
            state.unresolved_uuids.append(entry)

    # Build XRefRecord list from XRefGraph
    xref = state.xref_graph
    records: list = []

    def _resolved_name(raw: str) -> str:
        return name_map.get(raw, raw) if result.is_addon else raw

    def _trim(s: str, n: int) -> str:
        s = " ".join((s or "").split())
        return (s[:n] + "…") if len(s) > n else s

    # ── Every script edge, projected from the identity-bearing detail stream ──
    # (packet 1349-C2). The graph's script maps are keyed by DISPLAY NAME, which FM
    # permits to repeat, so projecting through them put every duplicate's edges on
    # whichever twin was indexed last and gave the other none. Measured: 17
    # ScriptReference and 46 script→field edges in MicroK12_dev touch a
    # duplicate-named script, and 9 more in CMP_Operations_UI_rev2.
    #
    # `via` on a ScriptReference carries the parameter the call passes and `cond` the
    # nearest enclosing guard ("" = unconditional) — the rung-4 control/data flow.
    _field_written: set = set()

    def _field_display(name: str) -> str:
        """The "BaseTable::Field" label for a mined "TO::Field" reference."""
        if "::" not in name:
            return name
        to_name_part, field_name = name.split("::", 1)
        return f"{to_base.get(to_name_part, to_name_part)}::{field_name}"

    def _formula_field_target(name: str):
        """A field named in FORMULA TEXT — matched by name, because FileMaker puts no
        identifier there. A structured reference must not come through here."""
        if "::" not in name:
            return None, name
        field_key = _field_display(name)
        to_id = _text_target("FieldsForTables", field_key)
        if to_id is None and result.is_addon and name_map:
            to_id, field_key = _resolve_addon_field_ref(
                name, name_map, _unique_addon_field_name_to_id)
        return to_id, field_key

    def _structured_field_target(detail: dict):
        """A field named by a STRUCTURED <FieldReference>.

        UUID first. An id may be used ONLY through the reference's own table
        occurrence, resolved to its local base table, because a field id is unique
        only within a base table. No context, an external source, a missing field or
        any ambiguity refuses. The display name is never consulted — a reference
        offering UUID A with a stale name pointing at B used to emit an edge to B.
        """
        label = _field_display(detail.get("name", ""))
        uuid = (detail.get("uuid") or "").strip()
        if uuid:
            resolved = _item_for_uuid("FieldsForTables", uuid)
            # Label the object we RESOLVED, not the text the reference carried: a
            # stale name belongs to a different field and would mislabel the edge.
            return resolved, (items[resolved].xml_key if resolved in items else label)
        field_id = (detail.get("id") or "").strip()
        if not field_id:
            return None, label
        ctx = _item_for_identity("TableOccurrenceCatalog", _detail_identity(
            "TableOccurrenceCatalog",
            {"uuid": detail.get("ctx_uuid", ""), "id": detail.get("ctx_id", "")}))
        if ctx is None or ctx not in items:
            return None, label
        base = to_base.get(items[ctx].name)
        resolved = _field_by_context.get((base, field_id)) if base else None
        return resolved, (items[resolved].xml_key if resolved in items else label)

    for detail in (getattr(xref, "script_edge_details", None) or ()):
        # The SOURCE resolves by identity too. It used to fall back to the owner
        # reference's display name, which attached a script's calls to a same-named
        # sibling — the very error this packet exists to remove, on the other end of
        # the edge (Codex confirmation of packet 1349).
        src_uuid = detail.get("src", "")
        from_id = _item_for_identity("ScriptCatalog", _detail_identity(
            "ScriptCatalog", {"uuid": src_uuid, "id": detail.get("src_id", "")}))
        if not from_id:
            state.miner_skipped.append(
                f"ScriptCatalog/{src_uuid or ('id:' + detail.get('src_id', '') if detail.get('src_id') else 'no-identity')}")
            continue
        from_name = _resolved_name(items[from_id].name if from_id in items else "")
        edge_type = detail.get("type", "")
        section = detail.get("section", "")
        target_name = detail.get("name", "")
        kind = detail.get("kind", "uuid")

        if edge_type == "DynamicDispatch":
            records.append(XRefRecord(
                from_id=from_id, from_name=from_name, to="", to_name=target_name,
                type="DynamicDispatch", via="dynamic"))
            continue

        if edge_type == "SQLQuery":
            # FM SQL names a table occurrence as text; an unresolved one keeps its
            # raw name and an empty target, which is an honest limit, not a dangling
            # structured edge (FileMaker_Tables and friends never resolve).
            to_id = _text_target("TableOccurrenceCatalog", target_name) or ""
            records.append(XRefRecord(
                from_id=from_id, from_name=from_name, to=to_id, to_name=target_name,
                type="SQLQuery", mode="read", via="sql"))
            continue

        if edge_type == "FieldReference":
            to_id, field_key = (_formula_field_target(target_name) if kind == "formula-name"
                                else _structured_field_target(detail))
            if not to_id:
                if kind != "formula-name":
                    _note_identity(section, detail)
                continue
            mode = detail.get("mode", "read")
            if mode == "write":
                _field_written.add((from_id, to_id))
            records.append(XRefRecord(
                from_id=from_id, from_name=from_name, to=to_id, to_name=field_key,
                type="FieldReference", mode=mode))
            continue

        to_id = _resolve_detail_target(section, detail)
        if not to_id:
            _note_identity(section, detail)
            continue
        if edge_type == "ScriptReference":
            # Label the object resolved, not the reference's text: FileMaker blanks
            # the name on a reference it cannot resolve, and a stale one names another
            # script entirely.
            records.append(XRefRecord(
                from_id=from_id, from_name=from_name,
                to=to_id, to_name=_resolved_name(items[to_id].name if to_id in items
                                                 else target_name), type="ScriptReference",
                via=_trim(detail.get("via", ""), 80),
                cond=_trim(detail.get("cond", ""), 100)))
        else:
            records.append(XRefRecord(
                from_id=from_id, from_name=from_name,
                to=to_id, to_name=_resolved_name(items[to_id].name if to_id in items
                                                 else target_name), type=edge_type,
                via=detail.get("via", "")))

    # One edge per (script, field): a field a script WRITES outranks one it merely
    # READS, which the detail stream cannot decide because reads and writes are found
    # in different steps.
    if _field_written:
        records = [r for r in records
                   if not (r.type == "FieldReference" and r.mode == "read"
                           and (r.from_id, r.to) in _field_written)]

    # CF → CF (CustomFunctionReference in formula text)
    for cf_name, called_list in (getattr(xref, "cf_calls_cf", None) or {}).items():
        from_id = alias.get(("CustomFunctionsCatalog", cf_name))
        if not from_id:
            continue
        for called in called_list:
            to_id = _text_target("CustomFunctionsCatalog", called)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(cf_name),
                    to=to_id, to_name=_resolved_name(called),
                    type="CustomFunctionReference",
                ))

    # Relationship → field (join predicates)
    # Projected from the identity-bearing detail stream, not from the name-keyed map:
    # a join predicate names its fields structurally, so a stale name would select the
    # wrong field exactly as it did for script steps (Codex review of packet 1349).
    for detail in (getattr(xref, "relationship_join_details", None) or ()):
        from_id = alias.get(("RelationshipCatalog", detail.get("src_key", "")))
        if not from_id or from_id not in items:
            continue
        to_id, field_key = _structured_field_target(detail)
        if not to_id:
            _note_identity("FieldsForTables", detail)
            continue
        records.append(XRefRecord(
            from_id=from_id, from_name=_resolved_name(detail.get("src_name", "")),
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
        lid = _item_for_reference("TableOccurrenceCatalog", left)
        rid = _item_for_reference("TableOccurrenceCatalog", right)
        if not (lid and rid):
            _note_unresolved("TableOccurrenceCatalog", left if not lid else right)
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
        to_id = _text_target("FieldsForTables", field_key)
        if to_id is None:
            resolved = _field_ref_uuid_to_key.get(field_part)  # addon: name-suffix UUID → field xml_key
            if resolved is None:
                resolved = _uuid_to_name.get(field_part)       # legacy: field <UUID> → "BaseTable::FieldName"
            if resolved:
                to_id = _text_target("FieldsForTables", resolved)
                field_key = resolved
        return to_id, field_key

    # CF → field (cf_uses_fields, parsed from the function body)
    for cf_name, field_refs in (getattr(xref, "cf_uses_fields", None) or {}).items():
        from_id = alias.get(("CustomFunctionsCatalog", cf_name))
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
        from_id = alias.get(("FieldsForTables", field_xml_key))
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
        from_id = alias.get(("FieldsForTables", field_xml_key))
        if not from_id:
            continue
        for cf_name in cf_names:
            to_id = _text_target("CustomFunctionsCatalog", cf_name)
            if to_id and (from_id, to_id) not in _field_cf_pairs:
                _field_cf_pairs.add((from_id, to_id))
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(field_xml_key),
                    to=to_id, to_name=_resolved_name(cf_name),
                    type="FieldCFCall",
                ))

    # Layout → field (UUID-based, structural FieldReference elements)
    for layout_uuid, field_uuid_list in (getattr(xref, "layout_uses_field_uuids", None) or {}).items():
        from_id = _item_for_uuid("LayoutCatalog", layout_uuid)
        layout_name = _uuid_to_name.get(layout_uuid, "")
        if not from_id:
            continue
        for field_uuid in field_uuid_list:
            field_key = _uuid_to_name.get(field_uuid, "")  # already "BaseTable::FieldName"
            to_id = _item_for_uuid("FieldsForTables", field_uuid)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=field_key,
                    type="LayoutField",
                ))

    # ── Value list edges, from the identity-bearing detail stream (packet 1358) ──
    # ONE projection for all four contexts. The four UUID-keyed maps this replaces could
    # not carry a value list referenced by ID alone — the combined id map keeps neither the
    # source section nor the edge kind — so such an edge was silently absent while dead-end
    # analysis, which already resolves UUID-or-id, called the same value list live. Section
    # is part of identity: `LayoutCatalog/id:7` and `ValueListCatalog/id:7` are unrelated
    # objects, and only the source section decides which one a reference meant.
    for detail in (getattr(xref, "value_list_edge_details", None) or ()):
        section = detail.get("src_section", "")
        # The source resolves by its OWN catalog identity, else by the exact parser key —
        # never by its display name. A value list, a layout and a script may share both.
        if section == "ScriptCatalog":
            from_id = _item_for_identity("ScriptCatalog", _detail_identity("ScriptCatalog", detail_src(detail)))
        elif detail.get("src_uuid"):
            from_id = _item_for_uuid(section, detail["src_uuid"])
        else:
            from_id = alias.get((section, detail.get("src_key", "")))
        if not from_id or from_id not in items:
            _note_identity(section, detail_src(detail))
            continue

        to_id = _resolve_detail_target("ValueListCatalog", detail)
        if not to_id:
            # `id="-1"` never reaches here — the miner treats FileMaker's no-selection
            # sentinel as no offered target, so it is an absence, not a failed lookup.
            _note_identity("ValueListCatalog", detail)
            continue

        records.append(XRefRecord(
            from_id=from_id, from_name=_resolved_name(items[from_id].name),
            to=to_id, to_name=_resolved_name(items[to_id].name if to_id in items
                                             else detail.get("name", "")),
            type=detail.get("kind", "LayoutValueList"),
        ))

    # Layout → field (formula-based: hide-object, conditional formatting, etc.)
    for layout_key, field_refs in (getattr(xref, "layout_formula_field_refs", None) or {}).items():
        from_id = alias.get(("LayoutCatalog", layout_key))
        layout_name = _display_name(layout_key)
        if not from_id or from_id not in items:
            continue
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = _text_target("FieldsForTables", field_key)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=field_key,
                    type="LayoutCalculation",
                ))

    # Layout → CF (formula-based: layout conditions calling custom functions)
    for layout_key, cf_names in (getattr(xref, "layout_formula_cf_calls", None) or {}).items():
        from_id = alias.get(("LayoutCatalog", layout_key))
        layout_name = _display_name(layout_key)
        if not from_id or from_id not in items:
            continue
        for cf_name in cf_names:
            to_id = _text_target("CustomFunctionsCatalog", cf_name)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(layout_name),
                    to=to_id, to_name=_resolved_name(cf_name),
                    type="LayoutCFCall",
                ))

    # Custom menu → field (formula-based)
    for menu_key, field_refs in (getattr(xref, "menu_formula_field_refs", None) or {}).items():
        from_id = alias.get(("CustomMenuCatalog", menu_key))
        menu_name = _display_name(menu_key)
        if not from_id or from_id not in items:
            continue
        for to_ref in field_refs:
            if "::" not in to_ref:
                continue
            to_name_part, field_name = to_ref.split("::", 1)
            base = to_base.get(to_name_part, to_name_part)
            field_key = f"{base}::{field_name}"
            to_id = _text_target("FieldsForTables", field_key)
            if to_id:
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(menu_name),
                    to=to_id, to_name=field_key,
                    type="MenuCalculation",
                ))

    # Custom menu → CF (formula-based)
    for menu_key, cf_names in (getattr(xref, "menu_formula_cf_calls", None) or {}).items():
        from_id = alias.get(("CustomMenuCatalog", menu_key))
        menu_name = _display_name(menu_key)
        if not from_id or from_id not in items:
            continue
        for cf_name in cf_names:
            to_id = _text_target("CustomFunctionsCatalog", cf_name)
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
                out.append((sr, via))
        for tag in ("Button", "ButtonObj"):
            for parent in elem.iter(tag):
                for sr in parent.iter("ScriptReference"):
                    out.append((sr, "button"))
        return out

    def _menu_script_refs(elem) -> list:
        return [(sr, "menu command") for sr in elem.iter("ScriptReference")]

    def _emit_entry_edges(section_key: str, edge_type: str, finder) -> None:
        for xml_key, xml_str in (result.section_xml or {}).get(section_key, {}).items():
            if not xml_str:
                continue
            from_id = alias.get((section_key, xml_key))
            if not from_id or from_id not in items:
                continue
            try:
                elem = _ET.fromstring(xml_str)
            except _ET.ParseError:
                continue
            seen: set = set()
            for ref, via in finder(elem):
                to_id = _item_for_reference("ScriptCatalog", ref)
                if not to_id or (to_id, via) in seen:
                    if not to_id:
                        _note_unresolved("ScriptCatalog", ref)
                    continue
                seen.add((to_id, via))
                records.append(XRefRecord(
                    from_id=from_id, from_name=_resolved_name(_display_name(xml_key)),
                    to=to_id, to_name=_resolved_name(ref.get("name", "")),
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
                    to_id = _item_for_reference("ScriptCatalog", sr)
                    if to_id and (to_id, action) not in file_seen:
                        file_seen.add((to_id, action))
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
        from_id = alias.get(("PrivilegeSetsCatalog", ps_key))
        if not (from_id and from_id in items and ps_xml):
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
                to_id = _item_for_reference(section_key, ref)
                if to_id:
                    records.append(XRefRecord(
                        from_id=from_id, from_name=_resolved_name(ps_name),
                        to=to_id, to_name=_resolved_name(ref.get("name", "")),
                        type="PrivilegeAccess", via=access))
                else:
                    _note_unresolved(section_key, ref)
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
            to_id = _item_for_reference("BaseTableCatalog", ref)
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
        from_id = alias.get(("AccountsCatalog", ac_key))
        if not from_id or from_id not in items:
            continue
        try:
            psr = _ET.fromstring(ac_xml).find(".//PrivilegeSetReference")
        except _ET.ParseError:
            psr = None
        if psr is None:
            continue
        to_id = _item_for_reference("PrivilegeSetsCatalog", psr)
        if to_id:
            records.append(XRefRecord(
                from_id=from_id, from_name=_resolved_name(_display_name(ac_key)),
                to=to_id, to_name=_resolved_name(psr.get("name", "")),
                type="AccountPrivilege"))

    # ── Trigger cascades (rung-4): navigation → the destination's enter-trigger ──
    # A Go to Layout fires the destination layout's OnLayoutEnter trigger — a hidden
    # workflow continuation a flat call graph misses. The navigation itself is already
    # an edge (ScriptNavigate, from the identity-bearing detail stream above); this
    # derives the IMPLIED call from those records, so the two can never disagree about
    # where a script navigates.
    _ENTER_EVENTS = {"OnLayoutEnter", "OnRecordLoad"}
    # Keyed on the layout's ITEM ID, not its display name: FM permits duplicate layout
    # names, and a name join would fire one layout's enter-trigger for its twin.
    enter_triggers: dict = {}   # layout item_id → [(script_id, script_name)]
    for r in records:
        if r.type == "LayoutScript" and r.via in _ENTER_EVENTS:
            enter_triggers.setdefault(r.from_id, []).append((r.to, r.to_name))
    _cascade_seen: set = set()
    for r in [rec for rec in records if rec.type == "ScriptNavigate"]:
        for trig_id, trig_name in enter_triggers.get(r.to, ()):
            key = (r.from_id, trig_id)
            if not trig_id or trig_id == r.from_id or key in _cascade_seen:
                continue
            _cascade_seen.add(key)
            records.append(XRefRecord(
                from_id=r.from_id, from_name=r.from_name,
                to=trig_id, to_name=trig_name,
                type="TriggerCascade", via=f"OnLayoutEnter@{r.to_name}"))

    # ── Layout-embedded navigation (packet 1347) ──────────────────────────────
    # Packet 1340 mined a button's Go to Layout / Go to Related Record into the graph
    # but never projected it, so everything reading the PERSISTED xref layer received
    # none of it. Sources resolve through the exact catalog key, never the display
    # name: FM permits duplicate layout names, and a name lookup would attach one
    # layout's navigation to whichever twin was indexed last. Targets resolve by
    # identity (packet 1348) or by a TO name that identifies exactly one occurrence.
    # An endpoint that does not resolve uniquely records a miner diagnostic and emits
    # nothing — never an empty `to`.
    # From the ALIAS, not from items: a coalesced fragment keeps no item of its own,
    # and its navigation must still resolve to the logical layout it belongs to.
    _key_to_id = {key: iid for (sec, key), iid in alias.items()
                  if sec == "LayoutCatalog" and iid in items and not items[iid].is_folder}
    _uuid_to_layout_id = {it.fm_uuid: iid for iid, it in items.items()
                          if it.section == "LayoutCatalog" and it.fm_uuid and not it.is_folder}
    _to_by_name: dict = {}
    for iid, it in items.items():
        if it.section != "TableOccurrenceCatalog" or it.is_folder:
            continue
        nm = _display_name(it.xml_key)
        _to_by_name[nm] = None if nm in _to_by_name else iid   # duplicate name → refuse
    _to_by_name = {k: v for k, v in _to_by_name.items() if v}

    # One bounded diagnostic per distinct unresolved endpoint: a layout with many
    # buttons pointing at one missing occurrence must not append one line per button.
    _nav_unresolved: set = set()

    def _nav_note(entry: str) -> None:
        if entry not in _nav_unresolved:
            _nav_unresolved.add(entry)
            state.unresolved_uuids.append(entry)

    def _layout_source(src_key: str):
        from_id = _key_to_id.get(src_key)
        if not from_id and f"LayoutCatalog/{src_key}" not in _nav_unresolved:
            _nav_unresolved.add(f"LayoutCatalog/{src_key}")
            state.miner_skipped.append(f"LayoutCatalog/{src_key}")
        return from_id

    _nav_seen: set = set()

    def _emit_layout_edge(from_id, src_key, to_id, to_name, edge_type, via):
        key = (from_id, to_id, edge_type, via)
        if key in _nav_seen:
            return
        _nav_seen.add(key)
        records.append(XRefRecord(
            from_id=from_id, from_name=_resolved_name(_display_name(src_key)),
            to=to_id, to_name=_resolved_name(to_name),
            type=edge_type, via=via))

    for detail in (getattr(xref, "layout_navigation_details", None) or ()):
        src_key, _src_uuid, tgt_uuid, tgt_name, step_name = detail[:5]
        tgt_id = detail[5] if len(detail) > 5 else ""
        from_id = _layout_source(src_key)
        if not from_id:
            continue
        to_id = _item_for_identity("LayoutCatalog", _detail_identity(
            "LayoutCatalog", {"uuid": tgt_uuid, "id": tgt_id}))
        if not to_id:
            _nav_note(f"LayoutCatalog/{tgt_uuid or (f'id:{tgt_id}' if tgt_id else tgt_name)}")
            continue
        _emit_layout_edge(from_id, src_key, to_id, tgt_name or _display_name(src_key),
                          "LayoutNavigation", step_name)

    def _to_target(to_name: str, to_uuid: str, to_id_attr: str) -> str | None:
        """A table-occurrence destination, by identity where FM gave one.

        The name route survives only as a last resort, and only when exactly one
        occurrence carries that name — `<Table Missing>` and a duplicate both refuse.
        """
        return _resolve_detail_target("TableOccurrenceCatalog", {
            "uuid": to_uuid, "id": to_id_attr, "name": to_name})

    for src_key, to_name, to_uuid, to_id_attr in (
            getattr(xref, "layout_context_details", None) or ()):
        from_id = _layout_source(src_key)
        if not from_id:
            continue
        to_id = _to_target(to_name, to_uuid, to_id_attr)
        if not to_id:
            _nav_note(f"TableOccurrenceCatalog/{to_uuid or to_id_attr or to_name}")
            continue
        # No `via`: this is the direct show-records-from binding, not a Step.
        _emit_layout_edge(from_id, src_key, to_id, to_name, "LayoutContextTO", "")

    for src_key, to_name, step_name, to_uuid, to_id_attr in (
            getattr(xref, "layout_to_navigation_details", None) or ()):
        from_id = _layout_source(src_key)
        if not from_id:
            continue
        to_id = _to_target(to_name, to_uuid, to_id_attr)
        if not to_id:
            _nav_note(f"TableOccurrenceCatalog/{to_uuid or to_id_attr or to_name}")
            continue
        _emit_layout_edge(from_id, src_key, to_id, to_name, "LayoutNavigateTO", step_name)

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
