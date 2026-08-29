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

from corpusfm.core.identity import (UUID_KIND, identity_key, owner_identity,
                                    owner_identity_from_xml)
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

#: Destinations FileMaker resolves at runtime. A step naming one of these has a real destination that
#: this catalog cannot know, so no target is invented — it becomes a bounded diagnostic instead.
#: FileMaker serialises the mode two ways and `_container_mode` reads both: as a `type` attribute on the
#: `LayoutReferenceContainer`, and as a `<Label>` child with no `type` at all. Reading only the first is
#: what left 417 steps reporting no navigation and no limit (packet 1357).
_ORIGINAL_LAYOUT_MODES = frozenset({"original layout", "current layout", "original", "current"})
_CALCULATED_LAYOUT_MODES = frozenset({"calculation", "calculated", "layout name by calculation",
                                      "layout number by calculation"})

#: Which modes make a step's LAYOUT destination unknowable, per step. The label is NOT uniformly
#: dynamic, and treating it that way would have been the mirror of the defect it fixes:
#:   * `Go to Layout` / `New Window` — "original layout" IS the destination, chosen at runtime;
#:   * `Go to Related Record` — "original layout" means the layout does not change, so the destination
#:     is known. Only a genuinely calculated layout is unknowable there.
#: `Go to List of Records` is absent from `_NAV_STEPS` and so never reaches here; its value-1 mode is
#: already encoded by the emitter as `CurrentLayout`.
_DYNAMIC_LAYOUT_MODES_BY_STEP = {
    "Go to Layout":         _ORIGINAL_LAYOUT_MODES | _CALCULATED_LAYOUT_MODES,
    "New Window":           _ORIGINAL_LAYOUT_MODES | _CALCULATED_LAYOUT_MODES,
    "Go to Related Record": _CALCULATED_LAYOUT_MODES,
}


def _container_mode(container) -> str:
    """What ONE `<LayoutReferenceContainer>` says its destination is.

    Returns the mode as FileMaker words it — `"original layout"`, `"calculated"`, … — or `""` when the
    container names a layout outright or says nothing at all. Structural, in this order: a named layout
    wins; then the `type` attribute; then the direct `<Label>`; then a `<Calculation>` INSIDE this
    container, which is a computed destination however it is labelled.
    """
    if container.find("LayoutReference") is not None:
        return ""
    token = (container.get("type") or "").strip().lower()
    if not token:
        label = container.find("Label")
        token = (label.text or "").strip().lower() if label is not None and label.text else ""
    if token == "layoutreference":
        return ""
    if token in _ORIGINAL_LAYOUT_MODES or token in _CALCULATED_LAYOUT_MODES:
        return token
    # A DIRECT child only. Measured across the corpus, a container holds exactly one of
    # `<Calculation>`, `<Label>`, `<LayoutReference>` or nothing — a window name's calculation is a
    # sibling of this container, not inside it, and must not be read as a computed layout.
    return "calculated" if container.find("Calculation") is not None else ""


def _mine_layout_navigation(els, xml_key, lname, layout_uuid, id_index, context_tos, navigates_tos,
                            dynamic_nav, navigates_layouts, navigated_by,
                            nav_details, ctx_details, to_details) -> None:
    """Navigation embedded in ONE layout's objects (packet 1340).

    `els` is every projection of that one layout — its authoritative AddAction body first,
    then any supplemental ModifyAction projections (packet 1353). They are mined together,
    under one set of de-duplication sets, because they describe the same layout: mining
    them in separate calls emitted every shared destination twice.

    SEMANTIC, from `<Step>` elements — never by harvesting every descendant reference tag. That
    boundary is what keeps the layout's OWN header `<LayoutReference>` out: it is not inside a Step,
    so it is never examined as navigation and no layout self-references through it.

    The five reachability maps are name- or UUID-keyed and retain destinations only, so they cannot
    say which Step produced an edge or which of two same-named layouts produced it. The three detail
    lists (packet 1347) carry the exact source `xml_key` and the Step name alongside, so the
    ingestion pipeline can project these edges without re-parsing layout XML into a second miner.
    """
    seen_l: set = set()
    seen_t: set = set()
    seen_d: set = set()
    seen_detail: set = set()
    seen_ctx: set = set()
    for el in els:
        ctx = el.find("TableOccurrenceReference")          # direct child = show-records-from
        if ctx is not None and ctx.get("name") and ctx.get("name") not in seen_ctx:
            seen_ctx.add(ctx.get("name"))
            context_tos[lname] = [ctx.get("name")]
            ctx_details.append([xml_key, ctx.get("name"), ctx.get("UUID", ""), ctx.get("id", "")])
        for step in el.iter("Step"):
            nav = step_navigation(step)
            step_name = step.get("name") or "?"
            if nav["dynamic"]:
                if step_name not in seen_d:
                    seen_d.add(step_name)
                    dynamic_nav[lname].append(step_name)
            for to_uuid, to_id, to_name in nav["tos"]:
                if to_name not in seen_t:
                    seen_t.add(to_name)
                    navigates_tos[lname].append(to_name)
                key = ("to", to_uuid or to_id or to_name, step_name)
                if key not in seen_detail:
                    seen_detail.add(key)
                    to_details.append([xml_key, to_name, step_name, to_uuid, to_id])
            if not layout_uuid:
                continue                                   # no identity → no reachability claim
            for target_uuid, target_id, target_name in nav["layouts"]:
                # UUID, else the offered id through the catalog — never the display name.
                # A name match here made the REACHABILITY map disagree with the emitted
                # edge: a name-only reference marked its destination live while producing
                # no record, and an id-only reference produced the record while leaving
                # the destination dead (Codex confirmation of packet 1349).
                resolved = target_uuid or (id_index.get(target_id) or "" if target_id else "")
                # A self-loop must never rescue an otherwise unreachable layout, even from an explicit
                # button. Excluded from the REACHABILITY indexes, not merely deduplicated.
                if resolved and resolved != layout_uuid and resolved not in seen_l:
                    seen_l.add(resolved)
                    navigates_layouts[layout_uuid].append(resolved)
                    navigated_by[resolved].append(layout_uuid)
                # The DETAIL keeps whatever the reference offered, including a bare id.
                # Discarding it left the empty-UUID/id route working for script navigation
                # and not for layout-embedded navigation (Codex review of packet 1349).
                if not (target_uuid or target_id) or resolved == layout_uuid:
                    continue
                key = ("layout", target_uuid or f"id:{target_id}", step_name)
                if key not in seen_detail:
                    seen_detail.add(key)
                    nav_details.append([xml_key, layout_uuid, target_uuid, target_name,
                                        step_name, target_id])


def step_navigation(step) -> dict:
    """What ONE `<Step>` navigates to. Pure; shared by the script scan and the layout scan.

    Returns ``{"layouts": [(uuid, id, name)], "tos": [(uuid, id, name)], "dynamic": bool}``.
    Identities travel with the destination so a caller never has to re-derive one
    from a display name (packet 1349).

    Two rules that look like details and are not:

    * a `TableOccurrenceReference` **nested inside a `FieldReference`** describes the step's OPERAND
      field, not the destination — harvesting it would call a field's own context a navigation target;
    * a computed / original / current destination invents nothing. `dynamic` is set so a caller can
      report the limit honestly rather than silently returning an empty answer — and it is set
      PER STEP (`_DYNAMIC_LAYOUT_MODES_BY_STEP`), because "original layout" means the destination is
      chosen at runtime for a Go to Layout and means the layout does not change for a Go to Related
      Record.
    """
    if (step.get("name") or "") not in _NAV_STEPS:
        return {"layouts": [], "tos": [], "dynamic": False}

    layouts, tos, seen_l, seen_t = [], [], set(), set()
    for lr in step.iter("LayoutReference"):
        uuid, ref_id, name = lr.get("UUID", ""), lr.get("id", ""), lr.get("name", "")
        # `id` counts toward identity: FileMaker blanks BOTH the UUID and the name on
        # a reference it cannot resolve itself, and keying on `uuid or name` dropped
        # those before any caller saw them.
        key = uuid or ref_id or name
        if key and key not in seen_l:
            seen_l.add(key)
            layouts.append((uuid, ref_id, name))

    field_to_ids = {id(t) for fr in step.iter("FieldReference")
                    for t in fr.iter("TableOccurrenceReference")}
    for tr in step.iter("TableOccurrenceReference"):
        if id(tr) in field_to_ids:
            continue
        tname = tr.get("name", "")
        tkey = tr.get("UUID", "") or tr.get("id", "") or tname
        if tkey and tkey not in seen_t:
            seen_t.add(tkey)
            tos.append((tr.get("UUID", ""), tr.get("id", ""), tname))

    # The blanket "any Calculation anywhere in an otherwise empty step" fallback is retired: a New
    # Window's name or bound calculation is not evidence that its LAYOUT destination is computed.
    modes = _DYNAMIC_LAYOUT_MODES_BY_STEP.get(step.get("name") or "", frozenset())
    dynamic = any(_container_mode(c) in modes for c in step.iter("LayoutReferenceContainer"))
    return {"layouts": layouts, "tos": tos, "dynamic": dynamic}


def _layout_nav_projections(result, xml_key: str, layout_uuid: str) -> list:
    """The supplemental ModifyAction projections belonging to ONE layout entry.

    Keyed by the identity the projection asserted, which is the body's identity — so a
    projection reaches the layout it names and no other, even where two layouts share a
    display name (packet 1353).
    """
    nav = getattr(result, "layout_nav_xml", None)
    if not nav:
        return []
    if layout_uuid:
        return nav.get(f"{UUID_KIND}:{layout_uuid}", [])
    body = (result.section_xml or {}).get("LayoutCatalog", {}).get(xml_key, "")
    ident = owner_identity_from_xml("LayoutCatalog", body)
    return nav.get(identity_key(ident), []) if ident is not None else []


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

    # Layout → layout / TO, mined SEMANTICALLY from navigation Steps embedded in layout objects
    # (a button's Go to Layout / Go to Related Record). Packet 1340: the same step inside a SCRIPT was
    # already an edge, so a layout reachable only from a button looked unreferenced to dead-end
    # analysis. Context and motion are kept apart — a layout's own show-records-from TO is not a
    # navigation destination.
    layout_navigates_layout_uuids: dict = dc_field(default_factory=dict)    # src layout_UUID → [target UUIDs]
    layout_navigated_by_layout_uuids: dict = dc_field(default_factory=dict) # target UUID → [src layout_UUIDs]
    layout_context_tos: dict = dc_field(default_factory=dict)               # layout name → [its header TO]
    layout_navigates_tos: dict = dc_field(default_factory=dict)             # layout name → [TOs it navigates to]
    layout_dynamic_navigation: dict = dc_field(default_factory=dict)        # layout name → [step names]
    # Packet 1347 — the same navigation, with the provenance the maps above discard: the exact
    # source layout xml_key (a display name can name several layouts) and the Step that produced
    # the edge. The ingestion pipeline projects XRefRecords from these, not from the maps.
    layout_navigation_details: list = dc_field(default_factory=list)   # [src_key, src_uuid, tgt_uuid, tgt_name, step, tgt_id]
    layout_context_details: list = dc_field(default_factory=list)      # [src_key, to_name, to_uuid, to_id]
    layout_to_navigation_details: list = dc_field(default_factory=list)  # [src_key, to_name, step, to_uuid, to_id]

    # Layout → script (ScriptTrigger events and button actions in LayoutCatalog XML)
    layout_triggers_script_uuids: dict = dc_field(default_factory=dict)       # layout_UUID → [script_UUIDs]
    script_triggered_by_layout_uuids: dict = dc_field(default_factory=dict)   # script_UUID → [layout_UUIDs]

    # Field → value list (ValueListReference in FieldsForTables validation XML)
    value_list_used_in_field_uuids: dict = dc_field(default_factory=dict)

    # ── CF→CF and relationship reverse indexes ────────────────────────────────
    cf_calls_cf: dict = dc_field(default_factory=dict)                  # cf_name → [cf names it calls]
    cf_called_by_cf: dict = dc_field(default_factory=dict)              # cf_name → [cf names that call it]
    relationship_uses_field: dict = dc_field(default_factory=dict)      # rel_name → ["TO::Field", ...]
    # Packet 1349 correction — the same join predicates with the identities the map
    # above discards, so the artifact projects them without a name match.
    relationship_join_details: list = dc_field(default_factory=list)
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
    vl_used_in_script_names: dict = dc_field(default_factory=dict)       # vl_UUID → ["uuid:…"/"id:…"/"name:…"]

    # Packet 1358-C. The four maps above are keyed by the target's UUID, so a value list
    # referenced by ID ALONE reaches none of them and the artifact loses the edge — while
    # dead-end analysis, which already resolves UUID-or-id, still calls that value list
    # live. The two layers then disagreed about one structured reference. These records
    # carry what a map cannot: the SOURCE's section and identity, the target's offered
    # identity, and the edge kind, so the projection resolves each end by identity and
    # emits exactly one edge. One flat, ordered, JSON-round-trippable list; the artifact
    # projection reads THIS, never the name- or UUID-keyed maps.
    #   {kind, src_section, src_uuid, src_id, src_key, uuid, id, name}
    value_list_edge_details: list = dc_field(default_factory=list)

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

    # Packet 1349-C2 — the same script edges with the identities the maps above
    # discard. Every record carries the SOURCE script's UUID and, for a structured
    # target, the UUID/id the reference offered. `kind` says how the target may be
    # matched: "uuid" for a structured reference, "formula-name" where FileMaker
    # supplies only text, "dynamic" for a destination it computes at runtime.
    # One flat, ordered, JSON-round-trippable list; the artifact projection reads
    # THIS, never the name-keyed maps.
    script_edge_details: list = dc_field(default_factory=list)

    # ── id-keyed reachability (packet 1348) ───────────────────────────────────
    # A structured reference that offers NO UUID may still name its target by id
    # — measured in an FM 2026 FMDeveloperTool export, where ten
    # `<LayoutReference UUID="" id="4">` elements inside script steps produced no
    # edge at all. These indexes are the id half of "UUID, else id, never name";
    # a reference that DOES carry a UUID never reaches them, because an id
    # belonging to a different object is a wrong answer, not a weaker one.
    # Fields are deliberately absent: a field id is unique only within its base
    # table, so an id route for fields needs a resolved table context first.
    script_called_by_ids: dict = dc_field(default_factory=dict)          # script id → [caller UUIDs]
    layout_used_in_script_ids: dict = dc_field(default_factory=dict)     # layout id → [script UUIDs]
    script_triggered_by_layout_ids: dict = dc_field(default_factory=dict)  # script id → [layout UUIDs]
    value_list_used_in_field_ids: dict = dc_field(default_factory=dict)  # VL id → [source keys]

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


def _script_fragments(result: "ParseResult") -> list:
    """Every StepsForScripts fragment as (owner UUID, owner id, owner name, xml).

    `ParseResult.step_xml` is keyed by display name and FM permits duplicates, so it
    drops a twin's body and mis-attributes the survivor. Every fragment carries an
    owner <ScriptReference> with a UUID, so the identity view is complete; the name
    is read back off that same reference. Falls back to the name view for a parse
    that produced no identity view at all.
    """
    by_identity = getattr(result, "step_xml_by_identity", None) or {}
    if not by_identity:
        return [("", "", name, xml) for name, xml in (result.step_xml or {}).items()]
    out = []
    for key, xml_str in by_identity.items():
        uuid = key.split(":", 1)[1] if key.startswith(f"{UUID_KIND}:") else ""
        name = ref_id = ""
        try:
            ref = ET.fromstring(xml_str).find("ScriptReference")
            if ref is not None:
                name, ref_id = ref.get("name", ""), ref.get("id", "")
        except ET.ParseError:
            pass
        out.append((uuid, ref_id, name, xml_str))
    return out


def _extract_item_uuid(el: ET.Element, section: str = "") -> str:
    """Return the FM UUID a catalog item asserts, or ''.

    Delegates to the identity resolver so the ModifyAction fragment form — no root
    `name`, identity on a direct child owner reference — is seen. Before packet
    1348 those fragments returned '' and dropped out of every UUID-keyed index:
    165 layouts across two real exports, contributing no reachability edges and
    skipped entirely by dead-end analysis.
    """
    identity = owner_identity(section, el)
    return identity.value if identity is not None and identity.kind == UUID_KIND else ""


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
            uuid = _extract_item_uuid(el, section)
            if not uuid:
                continue
            name = el.get("name") or _display_name(xml_key)
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
        uuid = _extract_item_uuid(el, "FieldsForTables")
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
    # id-keyed halves (packet 1348) — filled only when a reference offers no UUID.
    script_called_by_ids:        dict[str, list[str]] = defaultdict(list)
    layout_used_in_script_ids:   dict[str, list[str]] = defaultdict(list)

    # ── Step XML: script→script, script→field, script→layout ─────────────────
    # The source is only the LABEL on these edges; the reverse indexes below are
    # keyed on the TARGET's identity and are read by their keys alone. Gating the
    # whole scan on the source carrying a UUID therefore discarded every edge out
    # of a UUID-less script — including the target's own inbound evidence.
    for source_uuid, _source_id, script_name, xml_str in _script_fragments(result):
        if not xml_str:
            continue
        if not source_uuid:
            source_uuid = script_uuids.get(script_name, "")
        source_label = source_uuid or script_name
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        seen_scripts: set[str] = set()
        seen_fields:  set[str] = set()
        seen_layouts: set[str] = set()
        seen_script_ids: set[str] = set()
        seen_layout_ids: set[str] = set()

        for step in el.iter("Step"):
            if step.get("name", "") in _SCRIPT_REF_STEPS:
                for ref in step.iter("ScriptReference"):
                    called_uuid = ref.get("UUID", "")
                    if called_uuid:
                        if called_uuid not in seen_scripts:
                            seen_scripts.add(called_uuid)
                            if source_uuid:
                                script_calls_uuids[source_uuid].append(called_uuid)
                            script_called_by_uuids[called_uuid].append(source_label)
                        continue
                    called_id = (ref.get("id") or "").strip()
                    if called_id and called_id not in seen_script_ids:
                        seen_script_ids.add(called_id)
                        script_called_by_ids[called_id].append(source_label)

            for ref in step.iter("FieldReference"):
                field_uuid = ref.get("UUID", "")
                if field_uuid and field_uuid not in seen_fields:
                    seen_fields.add(field_uuid)
                    if source_uuid:
                        script_uses_field_uuids[source_uuid].append(field_uuid)
                    field_used_in_script_uuids[field_uuid].append(source_label)

            for ref in step.iter("LayoutReference"):
                layout_uuid = ref.get("UUID", "")
                if layout_uuid:
                    if layout_uuid not in seen_layouts:
                        seen_layouts.add(layout_uuid)
                        if source_uuid:
                            script_uses_layout_uuids[source_uuid].append(layout_uuid)
                        layout_used_in_script_uuids[layout_uuid].append(source_label)
                    continue
                layout_id = (ref.get("id") or "").strip()
                if layout_id and layout_id not in seen_layout_ids:
                    seen_layout_ids.add(layout_id)
                    layout_used_in_script_ids[layout_id].append(source_label)

    # ── Layout catalog: layout→script, layout→field, layout→VL ──────────────────
    layout_triggers_script_uuids:     dict[str, list[str]] = defaultdict(list)
    script_triggered_by_layout_uuids: dict[str, list[str]] = defaultdict(list)
    script_triggered_by_layout_ids:   dict[str, list[str]] = defaultdict(list)
    layout_uses_field_uuids:          dict[str, list[str]] = defaultdict(list)
    field_used_in_layout_uuids:       dict[str, list[str]] = defaultdict(list)
    layout_uses_vl_uuids:             dict[str, list[str]] = defaultdict(list)
    vl_used_in_layout_uuids:          dict[str, list[str]] = defaultdict(list)
    layout_navigates_layout_uuids:    dict[str, list[str]] = defaultdict(list)
    layout_navigated_by_layout_uuids: dict[str, list[str]] = defaultdict(list)
    layout_context_tos:               dict[str, list[str]] = defaultdict(list)
    layout_navigates_tos:             dict[str, list[str]] = defaultdict(list)
    layout_dynamic_navigation:        dict[str, list[str]] = defaultdict(list)
    layout_navigation_details:        list = []
    layout_context_details:           list = []
    layout_to_navigation_details:     list = []
    #: name → uuid, used ONLY when a reference carries no UUID. A duplicate display name resolves to
    #: nothing rather than to a guess — an ambiguous target is not a target.
    #: layout catalog id → the UUIDs claiming it. Repeated fragments of ONE logical
    #: layout share its id as well as its UUID, so an id is ambiguous only when
    #: DISTINCT objects claim it — the same rule CatalogIndex applies. Collapsing on
    #: the second occurrence marked a coalesced destination dead while its edge was
    #: emitted correctly (Codex confirmation round 2).
    _layout_ids: dict = {}
    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        uuid = layout_uuids.get(xml_key, "")
        if not uuid:
            continue
        try:
            own_id = (ET.fromstring(xml_str).get("id") or "").strip()
        except ET.ParseError:
            own_id = ""
        if own_id:
            _layout_ids.setdefault(own_id, set()).add(uuid)
    layout_id_to_uuid = {i: next(iter(u)) for i, u in _layout_ids.items() if len(u) == 1}
    #: identities whose supplemental projections have been mined. One logical layout may
    #: hold TWO catalog keys (FileMaker projects a rename that way), and its projections
    #: belong to the object, not to each key — mining them per key would double every
    #: edge they contribute.
    _mined_projections: set = set()

    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        layout_uuid = layout_uuids.get(xml_key, "")
        if not xml_str:
            continue
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        # The NAME-keyed navigation surfaces do not need a UUID and must not be gated on one
        # (packet 1340). Measured: a real customer layout carries its UUID only as an attribute on
        # its header `<LayoutReference>`, with no `<UUID>` child — so the UUID guard skipped it
        # entirely, and the layout the developer reported produced nothing at all. The UUID-keyed
        # reachability edges below still require one, because a reachability claim without an
        # identity is not a claim.
        # The body first, then this layout's supplemental ModifyAction projections
        # (packet 1353) — one call, so a destination both carry is emitted once and every
        # edge attributes to the same source key. Measured: the projections add no
        # destination the body lacks; what they add is the runtime-computed destination
        # the body serialises in a form the dynamic test does not read. Mined against the
        # first key claiming the identity, because one logical layout may hold two keys.
        nav_ident = layout_uuid or xml_key
        projections = ([] if nav_ident in _mined_projections
                       else _layout_nav_projections(result, xml_key, layout_uuid))
        _mined_projections.add(nav_ident)
        els = [el]
        for nav_xml in projections:
            try:
                els.append(ET.fromstring(nav_xml))
            except ET.ParseError:
                continue

        _mine_layout_navigation(
            els, xml_key, _display_name(xml_key), layout_uuid, layout_id_to_uuid,
            layout_context_tos, layout_navigates_tos, layout_dynamic_navigation,
            layout_navigates_layout_uuids, layout_navigated_by_layout_uuids,
            layout_navigation_details, layout_context_details, layout_to_navigation_details)

        layout_label = layout_uuid or xml_key

        seen_scripts: set[str] = set()
        seen_fields:  set[str] = set()
        seen_vls:     set[str] = set()

        seen_script_ids: set[str] = set()
        for ref in el.iter("ScriptReference"):
            script_uuid = ref.get("UUID", "")
            if script_uuid:
                if script_uuid not in seen_scripts:
                    seen_scripts.add(script_uuid)
                    if layout_uuid:
                        layout_triggers_script_uuids[layout_uuid].append(script_uuid)
                    script_triggered_by_layout_uuids[script_uuid].append(layout_label)
                continue
            script_id = (ref.get("id") or "").strip()
            if script_id and script_id not in seen_script_ids:
                seen_script_ids.add(script_id)
                script_triggered_by_layout_ids[script_id].append(layout_label)

        for ref in el.iter("FieldReference"):
            field_uuid = ref.get("UUID", "")
            if field_uuid and field_uuid not in seen_fields:
                seen_fields.add(field_uuid)
                if layout_uuid:
                    layout_uses_field_uuids[layout_uuid].append(field_uuid)
                field_used_in_layout_uuids[field_uuid].append(layout_label)

        for ref in el.iter("ValueListReference"):
            vl_uuid = ref.get("UUID", "")
            if vl_uuid and vl_uuid not in seen_vls:
                seen_vls.add(vl_uuid)
                if layout_uuid:
                    layout_uses_vl_uuids[layout_uuid].append(vl_uuid)
                vl_used_in_layout_uuids[vl_uuid].append(layout_label)

    # ── Value list references (all contexts) ─────────────────────────────────
    # FM value lists are referenced from four distinct locations:
    #   FieldsForTables  — field validation "In Value List" rules
    #   LayoutCatalog    — layout controls (popup menu, checkbox, radio, drop-down)
    #   RelationshipCatalog — portal sort-by-value-list order definitions
    #   step_xml         — Sort Records / Sort Portal steps sorted by value list order
    value_list_used_in_field_uuids: dict[str, list[str]] = defaultdict(list)
    value_list_used_in_field_ids:   dict[str, list[str]] = defaultdict(list)
    vl_used_in_field_uuids:        dict[str, list[str]] = defaultdict(list)
    vl_used_in_relationship_ids:   dict[str, list[str]] = defaultdict(list)
    vl_used_in_script_names:       dict[str, list[str]] = defaultdict(list)
    value_list_edge_details:       list = []

    #: FileMaker's no-value-list sentinel. A control that selects none writes `id="-1"`, which is
    #: an explicit ABSENCE, not a target that failed to resolve — so it earns neither an edge nor
    #: an unresolved-reference warning. Measured: the 4 UUID-less references in the repository
    #: corpus are all this.
    NO_VALUE_LIST = "-1"

    def _scan_for_vl_uuids(xml_str: str, ref_id: str, extra: dict | None = None, *,
                           kind: str = "", src_section: str = "", src_uuid: str = "",
                           src_id: str = "", src_key: str = "") -> None:
        """Index every ValueListReference in xml_str, and record it as an edge detail.

        The maps keep their existing shape for their existing consumers. The detail list is
        the one the artifact projection reads: it keeps the SOURCE's section and identity
        alongside the target's, which is what lets an id-only reference resolve at all —
        `LayoutCatalog/id:7` and `ValueListCatalog/id:7` are unrelated objects, and a map
        keyed by the target alone cannot say which section asked (packet 1358).
        """
        if not xml_str:
            return
        try:
            el = ET.fromstring(xml_str)
        except ET.ParseError:
            return
        seen: set[str] = set()
        seen_ids: set[str] = set()
        seen_detail: set[str] = set()
        for ref in el.iter("ValueListReference"):
            vl_uuid = ref.get("UUID", "")
            vl_id = (ref.get("id") or "").strip()
            offered = vl_uuid or (vl_id if vl_id and vl_id != NO_VALUE_LIST else "")
            if kind and offered and offered not in seen_detail:
                seen_detail.add(offered)
                value_list_edge_details.append({
                    "kind": kind, "src_section": src_section, "src_uuid": src_uuid,
                    "src_id": src_id, "src_key": src_key,
                    "uuid": vl_uuid, "id": "" if vl_uuid else vl_id,
                    "name": ref.get("name", ""),
                })
            if vl_uuid:
                if vl_uuid not in seen:
                    seen.add(vl_uuid)
                    value_list_used_in_field_uuids[vl_uuid].append(ref_id)
                    if extra is not None:
                        extra[vl_uuid].append(ref_id)
                continue
            if vl_id and vl_id not in seen_ids:
                seen_ids.add(vl_id)
                value_list_used_in_field_ids[vl_id].append(ref_id)

    # The SOURCE identity is only a label on the edge; whether the source carries
    # a UUID must not decide whether the target is seen as referenced. Gating the
    # scan on it hid every value list bound to a control on a UUID-less layout.
    for xml_key, xml_str in (result.section_xml or {}).get("FieldsForTables", {}).items():
        _scan_for_vl_uuids(xml_str, field_uuids.get(xml_key, "") or xml_key, vl_used_in_field_uuids,
                           kind="FieldValidation", src_section="FieldsForTables",
                           src_uuid=field_uuids.get(xml_key, ""), src_key=xml_key)

    for xml_key, xml_str in (result.section_xml or {}).get("LayoutCatalog", {}).items():
        # mixed dict only; layout already in vl_used_in_layout_uuids
        _scan_for_vl_uuids(xml_str, layout_uuids.get(xml_key, "") or xml_key,
                           kind="LayoutValueList", src_section="LayoutCatalog",
                           src_uuid=layout_uuids.get(xml_key, ""), src_key=xml_key)

    for xml_key, xml_str in (result.section_xml or {}).get("RelationshipCatalog", {}).items():
        _scan_for_vl_uuids(xml_str, xml_key, vl_used_in_relationship_ids,
                           kind="RelationshipSort", src_section="RelationshipCatalog",
                           src_key=xml_key)

    for src_uuid, src_id, script_name, xml_str in _script_fragments(result):
        # The source label is the script's UUID where it has one: FM permits
        # duplicate script names, so a name would attach two scripts' sort orders
        # to whichever was indexed last (packet 1349-C3).
        # An IDENTITY string, not a name: the projection used to fall through to the
        # display name here, which is the one source path the round-3 audit missed
        # (Codex confirmation round 2).
        label = (f"uuid:{src_uuid}" if src_uuid
                 else (f"id:{src_id}" if src_id else f"name:{script_name}"))
        _scan_for_vl_uuids(xml_str, label, vl_used_in_script_names,
                           kind="ScriptSort", src_section="ScriptCatalog",
                           src_uuid=src_uuid, src_id=src_id, src_key=script_name)

    return {
        "script_calls_uuids":               dict(script_calls_uuids),
        "script_called_by_uuids":           dict(script_called_by_uuids),
        "script_uses_field_uuids":          dict(script_uses_field_uuids),
        "field_used_in_script_uuids":       dict(field_used_in_script_uuids),
        "script_uses_layout_uuids":         dict(script_uses_layout_uuids),
        "layout_used_in_script_uuids":      dict(layout_used_in_script_uuids),
        "layout_navigates_layout_uuids":    dict(layout_navigates_layout_uuids),
        "layout_navigated_by_layout_uuids": dict(layout_navigated_by_layout_uuids),
        "layout_context_tos":               dict(layout_context_tos),
        "layout_navigates_tos":             dict(layout_navigates_tos),
        "layout_dynamic_navigation":        dict(layout_dynamic_navigation),
        "layout_navigation_details":        layout_navigation_details,
        "layout_context_details":           layout_context_details,
        "layout_to_navigation_details":     layout_to_navigation_details,
        "layout_triggers_script_uuids":     dict(layout_triggers_script_uuids),
        "script_triggered_by_layout_uuids": dict(script_triggered_by_layout_uuids),
        "value_list_used_in_field_uuids":   dict(value_list_used_in_field_uuids),
        "vl_used_in_field_uuids":           dict(vl_used_in_field_uuids),
        "vl_used_in_relationship_ids":      dict(vl_used_in_relationship_ids),
        "vl_used_in_script_names":          dict(vl_used_in_script_names),
        "value_list_edge_details":          list(value_list_edge_details),
        "layout_uses_field_uuids":          dict(layout_uses_field_uuids),
        "field_used_in_layout_uuids":       dict(field_used_in_layout_uuids),
        "layout_uses_vl_uuids":             dict(layout_uses_vl_uuids),
        "vl_used_in_layout_uuids":          dict(vl_used_in_layout_uuids),
        "script_called_by_ids":             dict(script_called_by_ids),
        "layout_used_in_script_ids":        dict(layout_used_in_script_ids),
        "script_triggered_by_layout_ids":   dict(script_triggered_by_layout_ids),
        "value_list_used_in_field_ids":     dict(value_list_used_in_field_ids),
    }


def field_calc_locality(xml_key: str, calc: "ET.Element") -> str | None:
    """The locality a field's own calculation evaluates in.

    A field calculation — auto-enter, validation, or a stored calc — has TWO
    locality facts, and they are not interchangeable (developer, 2026-08-27):

      * the **base table** the field lives in, always recoverable from the
        catalog key, and
      * the **context table occurrence** chosen on the calculation, which says
        which occurrence relationships are traversed from.

    Measured across MicroK12_dev, SeedDB and PTLaunchPad: every calculation that
    carries a context TO carries one that is an occurrence of the field's OWN base
    table — 459/459, 253/253 and 254/254, no exceptions. So the two never disagree
    about WHICH table; the context TO is the more precise of the two, and the base
    table is the fallback for the calculations that carry no context at all (31 of
    490 in MicroK12).

    Their NAMES do differ — 106 times in MicroK12, e.g. a TO `Labels` over a base
    table `NavigationLabels` — but because the pipeline maps a TO name to its base
    table anyway, **no current analysis can tell the two apart**: removing the
    context-TO branch changes no result on any measured export. The context TO is
    returned in preference because it is FileMaker's own model and is the fact a
    future relationship-aware analysis would need; the base table is what makes the
    31-of-490 no-context calculations resolve at all.
    """
    ctx = calc.find("TableOccurrenceReference")
    if ctx is not None and (ctx.get("name") or "").strip():
        return ctx.get("name").strip()
    return xml_key.split("::", 1)[0] if "::" in xml_key else None


def _build_formula_indexes(result: "ParseResult") -> dict:
    """Scan formula slots in LayoutCatalog and CustomMenuCatalog XML.

    For each <Calculation><Text> element found, runs the formula parser to
    extract field refs (with implicit_to from a sibling TableOccurrenceReference)
    and CF calls (intersected with known CF names).

    Custom menu formulas have no implicit TO — menus must use explicit TO::Field.

    Keyed by the catalog's exact xml_key, not the display name (packet 1349-C3).
    Measured across 100 exports, LayoutCatalog and ScriptCatalog are the ONLY
    reference-target sections that carry genuinely duplicated names — which is what
    FileMaker permits — and a duplicate-named layout's formula refs collapsed onto
    one twin. The TARGETS here stay name-matched by construction: a formula names
    its field or function as text and FileMaker puts no identifier there.
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
        layout_name = xml_key
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
        menu_name = xml_key
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
    script_edge_details:      list = []

    for _src_uuid, _src_id, script_name, xml_str in _script_fragments(result):
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
        edge_seen:    set = set()

        def _edge(edge_type, section="", uuid="", ref_id="", name="",
                  mode="", via="", cond="", kind="uuid", ctx_uuid="", ctx_id="", ctx_name=""):
            """One identity-bearing record for the artifact projection.

            The maps above are keyed by the script's DISPLAY NAME, which FM permits
            to repeat, so projecting through them lands every duplicate's edges on
            whichever twin was indexed last. These records carry the source UUID.
            """
            key = (edge_type, section, uuid, ref_id, name, mode, via, cond, ctx_uuid, ctx_id)
            if key in edge_seen:
                return
            edge_seen.add(key)
            script_edge_details.append({
                "src": _src_uuid, "src_id": _src_id, "src_name": script_name,
                "type": edge_type, "section": section,
                "uuid": uuid, "id": ref_id, "name": name,
                "mode": mode, "via": via, "cond": cond, "kind": kind,
                # A field id is unique only within its base table, so an id-only field
                # target needs its TO context before it can be resolved at all.
                "ctx_uuid": ctx_uuid, "ctx_id": ctx_id, "ctx_name": ctx_name,
            })

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
                step_refs = []
                offered_target = False
                for r in step.iter("ScriptReference"):
                    # An identity is emitted whatever the display name says, for the
                    # same reason as fields: FileMaker blanks the name on a reference
                    # it cannot itself resolve, and skipping those reported a real
                    # structured call as a computed one. A reference offering only a
                    # name is emitted too, so the projection can REFUSE it by name
                    # and say so, rather than dropping it silently.
                    if r.get("UUID", "") or r.get("id", ""):
                        offered_target = True
                    if r.get("UUID", "") or r.get("id", "") or r.get("name"):
                        _edge("ScriptReference", "ScriptCatalog", r.get("UUID", ""),
                              r.get("id", ""), r.get("name", ""), via=param, cond=guard)
                    if r.get("name"):
                        step_refs.append(r.get("name", ""))
                for called in step_refs:
                    if called not in seen_scripts:
                        seen_scripts.add(called)
                        script_calls[script_name].append(called)
                        script_called_by[called].append(script_name)
                    key = (called, param, guard)
                    if key not in detail_seen:
                        detail_seen.add(key)
                        script_call_details[script_name].append((called, param, guard))
                # Computed only when the step offered NO structured target identity.
                if not (step_refs or offered_target):
                    note = f"{step_name} (computed target)"
                    _edge("DynamicDispatch", name=note, via="dynamic", kind="dynamic")
                    if note not in dyn_seen:
                        dyn_seen.add(note)
                        script_dynamic_dispatch[script_name].append(note)

            if step_name in _DYNAMIC_DISPATCH_STEPS:
                note = f"{step_name} ({_DYNAMIC_DISPATCH_STEPS[step_name]})"
                _edge("DynamicDispatch", name=note, via="dynamic", kind="dynamic")
                if note not in dyn_seen:
                    dyn_seen.add(note)
                    script_dynamic_dispatch[script_name].append(note)

            if step_name in _NAV_STEPS:
                # ONE navigation reader, shared with the layout scan (packet 1340), so the two cannot
                # disagree about what a Go to Related Record targets — including the rule that a TO
                # nested in a FieldReference is the step's operand, not the destination.
                nav = step_navigation(step)
                # A destination FileMaker picks at runtime is a bounded diagnostic, never an edge:
                # the script scan reported nothing at all for it until packet 1357, so a step whose
                # layout is computed read as a step that navigates nowhere. No layout edge is created
                # — inventing one is the failure this deliberately avoids.
                if nav["dynamic"]:
                    note = f"{step_name} (computed layout destination)"
                    _edge("DynamicDispatch", name=note, via="dynamic", kind="dynamic")
                    if note not in dyn_seen:
                        dyn_seen.add(note)
                        script_dynamic_dispatch[script_name].append(note)
                for l_uuid, l_id, lname in nav["layouts"]:
                    _edge("ScriptNavigate", "LayoutCatalog", l_uuid, l_id, lname,
                          via=step_name)
                    if lname and lname not in nav_seen:
                        nav_seen.add(lname)
                        script_navigates_layouts[script_name].append(lname)
                for t_uuid, t_id, tname in nav["tos"]:
                    _edge("ScriptNavigateTO", "TableOccurrenceCatalog", t_uuid, t_id,
                          tname, via=step_name)
                    if tname not in nav_to_seen:
                        nav_to_seen.add(tname)
                        script_navigates_tos[script_name].append(tname)

            # Structural <FieldReference> = the step's operand target.
            is_write = step_name in _FIELD_WRITE_STEPS
            for ref in step.iter("FieldReference"):
                to_ref = ref.find("TableOccurrenceReference")
                field_name = ref.get("name", "")
                to_name = to_ref.get("name", "") if to_ref is not None else ""
                # An identity-bearing reference is emitted even with an EMPTY name:
                # FileMaker blanks the name (and the UUID) on a reference it cannot
                # itself resolve, and every measured id-only <FieldReference> is of
                # that shape. Requiring a name skipped them before they reached the
                # projection, so they could be neither resolved nor diagnosed.
                if ref.get("UUID", "") or ref.get("id", ""):
                    _edge("FieldReference", "FieldsForTables", ref.get("UUID", ""),
                          ref.get("id", ""), f"{to_name}::{field_name}" if field_name else "",
                          mode="write" if is_write else "read",
                          ctx_uuid=to_ref.get("UUID", "") if to_ref is not None else "",
                          ctx_id=to_ref.get("id", "") if to_ref is not None else "",
                          ctx_name=to_name)
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
                    # FM SQL names a table occurrence as TEXT; there is no identity
                    # to carry, so this stays name-matched by construction.
                    _edge("SQLQuery", "TableOccurrenceCatalog", name=sql_tbl,
                          mode="read", via="sql", kind="formula-name")
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
                    # A formula names its field as text — the formula boundary.
                    _edge("FieldReference", "FieldsForTables", name=fr,
                          mode="read", kind="formula-name")
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
        seen_ff: set[str] = set()
        seen_fcf: set[str] = set()
        for calc in fld_el.iter("Calculation"):
            text_el = calc.find("Text")
            if text_el is None or not text_el.text:
                continue
            implicit_to = field_calc_locality(xml_key, calc)
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
    relationship_join_details:  list = []

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
        seen_rel_detail: set = set()
        for ref in rel_el.iter("FieldReference"):
            to_ref = ref.find("TableOccurrenceReference")
            field_name = ref.get("name", "").strip()
            to_name = to_ref.get("name", "").strip() if to_ref is not None else ""
            # A join predicate names its fields structurally, so it carries the same
            # identities a script step does — and projecting it by name selects the
            # wrong field for exactly the same reason (Codex review of packet 1349).
            if ref.get("UUID", "") or ref.get("id", ""):
                key = (rel_key, ref.get("UUID", ""), ref.get("id", ""))
                if key not in seen_rel_detail:
                    seen_rel_detail.add(key)
                    relationship_join_details.append({
                        "src_key": rel_key, "src_name": rel_name,
                        "uuid": ref.get("UUID", ""), "id": ref.get("id", ""),
                        "name": f"{to_name}::{field_name}" if field_name else "",
                        "ctx_uuid": to_ref.get("UUID", "") if to_ref is not None else "",
                        "ctx_id": to_ref.get("id", "") if to_ref is not None else "",
                    })
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
        script_edge_details=script_edge_details,
        cf_uses_fields=dict(cf_uses_fields),
        field_used_in_cfs=dict(field_used_in_cfs),
        cf_calls_cf=dict(cf_calls_cf),
        cf_called_by_cf=dict(cf_called_by_cf),
        relationship_uses_field=dict(relationship_uses_field),
        relationship_join_details=relationship_join_details,
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
