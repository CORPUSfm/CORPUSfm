"""Schema context builder for AI write-path use.

build_schema_context(artifact, label, *, include_bodies=True, focus=None) -> str
  Returns an ID-explicit text representation of an Artifact for AI generation: object
  names + internal IDs (the spine), enriched with the structural logic the artifact
  already renders — the relationship graph, field comments + calculations, custom
  function bodies, per-script cross-references, and a security summary.

  Two retrieval modes (docs/completeness-audit.md, Step 2):
    - always-on **spine** (symbol table + relationships + xref summaries + security),
      with size-driving bodies gated behind include_bodies;
    - task-scoped **focus**: pass seed object names/ids; they are graph-expanded one hop
      through the xref map and a FOCUS DETAIL section renders full depth (script step
      bodies, field/CF/VL bodies, layout objects) for just that neighborhood, while the
      spine drops to bounded — so large files surface deep, relevant detail without dumping.

Used by both the MCP server (get_schema_context tool) and the standalone fmClip /
Patch (AI) generation features.
"""

from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact

_XREF_CAP = 12  # max referenced names listed per object in the xref summary
_SPINE_BODIES_AUTOOFF = 150  # no-focus: above this many bodied items, auto-suppress spine bodies
_SEC_LABEL = {"LayoutCatalog": "layouts", "ScriptCatalog": "scripts",
              "ValueListCatalog": "value lists", "BaseTableCatalog": "tables"}


def _attr(item, *keys, default: str = "") -> str:
    """First present attribute among keys (FM XML casing varies: dataType vs datatype)."""
    for k in keys:
        v = item.attributes.get(k)
        if v not in (None, ""):
            return v
    return default


def _formula_block(rendered_text: str) -> str:
    """The calc/CF body: everything after the first blank line in rendered_text."""
    lines = (rendered_text or "").splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() == "" and i + 1 < len(lines):
            return "\n".join(lines[i + 1:]).rstrip()
    return ""


def _content_lines(rendered_text: str) -> list[str]:
    return [ln.strip() for ln in (rendered_text or "").splitlines() if ln.strip()]


# A relationship join side that points at a MISSING/external file renders as a bare
# `TO::` with no field name — FM stores cross-file join fields by internal id only, so the
# name is blank in the export. Without annotation this reads to the AI as a broken/empty
# predicate. We mark it and carry the local key across as the inferred relink name (FM joins
# like-keyed fields), reusing the same join-partner inference the cross-file reconstructor uses.
_BLANK_JOIN_FIELD_RE = re.compile(r"::(?=\s|$)")
_NAMED_JOIN_FIELD_RE = re.compile(r"::(\w+)")


def _annotate_external_predicate(predicate: str) -> tuple:
    """(annotated_predicate, was_annotated). No-op when no blank external join side."""
    if not _BLANK_JOIN_FIELD_RE.search(predicate):
        return predicate, False
    named = _NAMED_JOIN_FIELD_RE.findall(predicate)
    hint = (f"name inferred from the local key {named[0]!r}" if named
            else "name absent from export")
    annotated = _BLANK_JOIN_FIELD_RE.sub(
        f"::«external field, id-only — {hint}»", predicate)
    return annotated, True


_STEPS_MARKER = "--- Steps ---"
_FOCUS_BODY_MAX_LINES = 400  # cap any single focused body so one huge script can't blow the budget


def _script_steps_body(rendered_text: str) -> str:
    """The rendered step body of a script (everything after the '--- Steps ---' marker).

    Scripts already carry their full rendered steps in rendered_text; this just lifts
    the body out so it can be surfaced as task-scoped depth (not in the always-on spine).
    """
    idx = (rendered_text or "").find(_STEPS_MARKER)
    if idx == -1:
        return ""
    return rendered_text[idx + len(_STEPS_MARKER):].strip()


def _layout_objects_summary(item) -> list[str]:
    """Full per-object inventory of a layout — what's ON it and what each thing does.

    The shared distillation (core/layout_objects): every object's type, the field it
    shows / script it runs / portal TO, its label, and its display formatting, in z-order.
    This is the structured "what the user sees" — far more legible than a wireframe and
    the same data the Explorer reads. Capped (this renders in task-scoped focus depth).
    """
    xml = item.xml_sources[0].xml if item.xml_sources else ""
    if not xml:
        return []
    from corpusfm.core.layout_objects import extract_layout_objects
    objs = extract_layout_objects(xml)
    if not objs:
        return []
    out: list = []
    type_counts: dict = defaultdict(int)
    for o in objs:
        type_counts[o.type] += 1
    ordered = sorted(type_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    out.append("objects: " + ", ".join(f"{n}× {t}" for t, n in ordered))
    # Per-object lines — only the ones that carry meaning (bound / labeled / formatted
    # / conditional). Behavior (hide-when, conditional formatting, tooltip) is part of
    # "what the user sees" — an object that hides on a condition is not always visible.
    meaningful = [o for o in objs if o.field or o.script or o.to or o.label or o.fmt
                  or o.hide or o.tooltip or o.cond_format]
    for o in meaningful[:25]:
        bits = [o.type]
        if o.field:  bits.append(f"field={o.field}")
        if o.to:     bits.append(f"portal→{o.to}")
        if o.script: bits.append(f"runs={o.script}")
        if o.label:  bits.append(f'"{o.label[:30]}"')
        if o.fmt:    bits.append(f"[{o.fmt}]")
        if o.hide:   bits.append(f"hides-when: {o.hide[:40]}")
        if o.cond_format: bits.append(f"{o.cond_format} cond-format")
        if o.tooltip: bits.append("tooltip")
        out.append("  · " + "  ".join(bits))
    if len(meaningful) > 25:
        out.append(f"  … +{len(meaningful) - 25} more objects")
    return out


_DM_EDGE_CAP = 90  # max data-model edges rendered into the mermaid block


def _structure_section(artifact) -> list:
    """The STRUCTURE block: structural-idiom shape + the true data model (mermaid).

    All deterministic — classifications of present structure, never inferred purpose.
    Gives the AI the schema's *grammar* (what's a PK, a join table, a self-join, the
    real table relationships under the TO graph) so generated changes fit the design."""
    from collections import Counter
    from corpusfm.core.structure_intent import structure_intent_dict, to_mermaid_erd

    si = structure_intent_dict(artifact)
    rels, flds, tos = si.get("relationships", []), si.get("fields", []), si.get("tos", [])
    dm = si.get("data_model")
    if not (rels or flds or (dm and dm.get("edges"))):
        return []

    rel_tags = Counter(t for r in rels for t in r.get("tags", []))
    fld_tags = Counter(t for f in flds for t in f.get("tags", []))
    hubs = sorted([t for t in tos if "hub" in t.get("tags", [])], key=lambda t: -t["degree"])
    n_anchor = sum(1 for t in tos if "anchor" in t.get("tags", []))
    n_iso = sum(1 for t in tos if "isolated" in t.get("tags", []))
    n_tog = len({t["component"] for t in tos if t["degree"] > 0})

    out = ["STRUCTURE — deterministic structural intent (classifications of present structure, not inferred purpose):"]

    def _csv(counter, keys):
        bits = [f"{counter[k]} {k}" for k in keys if counter.get(k)]
        return " · ".join(bits)
    rel_line = _csv(rel_tags, ["self-join", "cross-join", "filtered", "compound-key",
                               "allow-create", "global-anchored", "multikey", "live-key"])
    if rel_line:
        out.append(f"  relationship idioms: {rel_line}")
    fld_line = _csv(fld_tags, ["primary-key", "match-field", "unstored-calc", "calc-stored",
                               "summary", "lookup", "global-key", "utility-global",
                               "multikey-field", "live-key"])
    if fld_line:
        out.append(f"  field roles: {fld_line}")
    # FileMaker key idioms a SQL eye would misread — name them explicitly when present.
    fm = [k for k in ("global-anchored", "multikey", "live-key") if rel_tags.get(k)]
    if fm:
        notes = {"global-anchored": "global-keyed joins (filtered/navigation)",
                 "multikey": "multi-line keys (one field, many keys)",
                 "live-key": "unstored-calc keys (recalculate live)"}
        out.append("  FileMaker key idioms (valid grammar, not flaws): "
                   + " · ".join(f"{rel_tags[k]} {notes[k]}" for k in fm))
    if hubs:
        out.append("  hub tables (most-connected occurrences): "
                   + ", ".join(f"{t['to']}({t['degree']})" for t in hubs[:6]))
    out.append(f"  topology: {n_tog} table-occurrence groups · {n_anchor} anchors · {n_iso} isolated")

    if dm and dm.get("edges"):
        tbls, edges = dm.get("tables", []), dm.get("edges", [])
        out.append(f"  DATA MODEL — the real table relationships under the TO graph "
                   f"({len(tbls)} tables, {len(edges)} relationships), as mermaid:")
        mm = (si.get("mermaid") or to_mermaid_erd(dm)).splitlines()
        # Cap the rendered edges; the header + capped edges still convey the model.
        shown = mm[: _DM_EDGE_CAP + 1]
        out.extend("    " + ln for ln in shown)
        if len(mm) > len(shown):
            out.append(f"    %% … +{len(mm) - len(shown)} more relationships")
    out.append("")
    return out


def _resolve_focus_seeds(artifact, focus) -> set:
    """Map focus tokens (item_ids or object names, case-insensitive) to item_ids."""
    if not focus:
        return set()
    by_name: dict = {}
    for iid, it in artifact.items.items():
        by_name.setdefault(it.name, iid)
        by_name.setdefault(it.name.casefold(), iid)
    seeds: set = set()
    for tok in focus:
        if tok in artifact.items:
            seeds.add(tok)
        elif tok in by_name:
            seeds.add(by_name[tok])
        elif tok.casefold() in by_name:
            seeds.add(by_name[tok.casefold()])
    return seeds


def _expand_focus(artifact, seeds) -> set:
    """Seed set + its 1-hop xref neighborhood (both directions) — the graph-expand step."""
    out = set(seeds)
    for r in artifact.xref_map:
        if r.from_id in seeds:
            out.add(r.to)
        if r.to in seeds:
            out.add(r.from_id)
    return out


def focus_seeds_from_search(artifact, query, cfg, *, top_k: int = 8):
    """Semantic-search seeds for build_schema_context's focus mode — the on-ramp.

    Runs the query against the vector index scoped to this artifact's file and returns
    the matched object names (the seeds for graph-expansion), or None when no index is
    configured or the artifact isn't indexed. Returning None — not [] — is deliberate:
    callers fall back to the full schema context rather than a seedless bounded spine.
    """
    if not query or not query.strip():
        return None
    try:
        from corpusfm.server.ai.vector_index import get_vector_index
        idx = get_vector_index(cfg)
        if idx is None:
            return None
        results = idx.search(query, top_k=top_k, file_name=artifact.identity.file_name)
    except Exception:
        return None
    seeds: list = []
    for r in results or []:
        name = (r.get("item_name") or "").strip()
        if name and name not in seeds:
            seeds.append(name)
    return seeds or None


def build_schema_context(
    artifact: "Artifact",
    label: str = "",
    *,
    include_bodies: bool = True,
    focus=None,
    focus_neighbor_bodies: bool = False,
    max_chars: int = None,
) -> str:
    """Build ID-explicit, structurally-enriched schema context from an artifact.

    Always-on spine (bounded, high value): identity, table occurrences, the relationship
    graph (predicate + operator), base tables + fields (type, comment), per-script xref
    summary, layouts, value-list names, custom-function signatures, external sources,
    security summary, structure catalog.

    Two retrieval modes (see docs/completeness-audit.md, Step 2):

    - include_bodies (default True): inline the per-object *bodies* — field calculations,
      custom-function formulas, value-list definitions — across the whole spine. The size
      drivers. Pass False for the bounded symbol-table spine only.

    - focus (iterable of object names and/or item_ids): task-scoped depth. The seeds are
      graph-expanded one hop through the xref map (both directions), and a FOCUS DETAIL
      section renders each object's signature (header + uses/used-by). Full bodies render
      for the SEEDS; 1-hop NEIGHBORS show signature only (a pointer to fetch the body)
      unless focus_neighbor_bodies=True — a hub seed can have dozens of neighbors, so
      dumping every body blows the token ceiling. When focus is set the spine is rendered
      bounded (include_bodies suppressed). This is the "semantic-seed → graph-expand"
      pattern.

    - max_chars: optional running budget on the FOCUS DETAIL *body* emission. Seed bodies
      are emitted first (so a tight budget always preserves them); once the accumulated
      body output would exceed max_chars, further bodies are dropped and their items are
      listed by name with a pointer footer. On the NO-focus path it caps the whole emission
      (truncate-with-marker). None = no cap.

    On the no-focus path, when an artifact has more than _SPINE_BODIES_AUTOOFF (150) bodied
    items, per-object bodies are auto-suppressed (include_bodies forced False) with a header
    NOTE pointing to focus=/get_object — the bounded symbol-table spine still emits whole.
    """

    seed_ids = _resolve_focus_seeds(artifact, focus) if focus else set()
    focus_ids = _expand_focus(artifact, seed_ids) if seed_ids else set()

    # No-focus spine bodies (field calcs + CF formulas + VL defs) are the size driver on a
    # real file. On a large artifact, auto-suppress them and point the caller to a focused
    # fetch — the bounded symbol-table spine still goes out whole.
    auto_bodies_off = False
    if include_bodies and not focus_ids:
        # The size drivers on the no-focus path: calc-field formulas, value-list defs, and
        # custom-function formulas (each emits a per-object body below).
        n_bodied = 0
        for it in artifact.items.values():
            if getattr(it, "is_folder", False):
                continue
            if it.section == "FieldsForTables" and "Formula:" in (it.rendered_text or ""):
                n_bodied += 1
            elif it.section in ("ValueListCatalog", "CustomFunctionsCatalog"):
                n_bodied += 1
        if n_bodied > _SPINE_BODIES_AUTOOFF:
            include_bodies = False
            auto_bodies_off = n_bodied
    spine_bodies = include_bodies and not focus_ids

    def _id(item) -> str:
        return _attr(item, "id", default="?")

    def _primary_xml(item) -> str:
        return item.xml_sources[0].xml if item.xml_sources else ""

    def _to_base(xml_str: str) -> str:
        try:
            elem = ET.fromstring(xml_str)
            src = elem.find("BaseTableSourceReference")
            if src is None:
                return "?"
            if src.attrib.get("type") == "BaseTableReference":
                bt = src.find("BaseTableReference")
                return bt.attrib.get("name", "?") if bt is not None else "?"
            ds = src.find("DataSourceReference")
            return f'{ds.attrib.get("name", "?")} [ext]' if ds is not None else "?"
        except Exception:
            return "?"

    def _layout_to_name(xml_str: str) -> str:
        try:
            elem = ET.fromstring(xml_str)
            ref = elem.find("TableOccurrenceReference")
            return ref.attrib.get("name", "?") if ref is not None else "?"
        except Exception:
            return "?"

    def _layout_wiring(item) -> str:
        """What a layout DOES, for the AI: the scripts its buttons/triggers run and how
        many fields it places — the structured 'what the user can do here' (not a render)."""
        froms = from_idx.get(item.item_id, [])
        runs = sorted({r.to_name for r in froms if r.type == "LayoutScript"})
        nfields = sum(1 for r in froms if r.type == "LayoutField")
        bits = []
        if runs:
            bits.append("runs: " + ", ".join(runs[:5]) + ("…" if len(runs) > 5 else ""))
        if nfields:
            bits.append(f"{nfields} fields")
        return ("  | " + "  ".join(bits)) if bits else ""

    def _sort_id(item):
        v = _attr(item, "id")
        return int(v) if v.isdigit() else 0

    # Pre-index xrefs by source so the per-script summary is O(1), not O(n) per call.
    from_idx: dict = defaultdict(list)
    to_idx: dict = defaultdict(list)
    for rec in artifact.xref_map:
        from_idx[rec.from_id].append(rec)
        to_idx[rec.to].append(rec)

    def _xref_summary(item) -> str:
        recs = from_idx.get(item.item_id, [])
        if not recs:
            return ""
        names: list = []
        for r in recs:
            n = r.to_name or r.to
            if n and n not in names:
                names.append(n)
        shown = names[:_XREF_CAP]
        more = f", +{len(names) - _XREF_CAP} more" if len(names) > _XREF_CAP else ""
        return f"uses: {', '.join(shown)}{more}"

    lines: list = []

    ident = artifact.identity
    prov = artifact.provenance
    lines.append(f"File: {ident.file_name}  FM: {ident.fm_version}  UUID: {ident.root_uuid}")
    if label:
        lines.append(f"Path: {label}")
    lines.append(f"Ingested: {prov.ingested_at}  Type: {artifact.type.value}")
    if auto_bodies_off:
        lines.append(
            f"NOTE: {auto_bodies_off} bodied items (> {_SPINE_BODIES_AUTOOFF}) — per-object "
            f"bodies (field calcs, CF formulas, value-list defs) are SUPPRESSED to stay within "
            f"the context window. This is the bounded symbol-table spine; fetch bodies with "
            f"focus=[name] or get_object(artifact, name).")
    lines.append("")

    by_section: dict = defaultdict(list)
    for item in artifact.items.values():
        by_section[item.section].append(item)

    # ── Table Occurrences ──────────────────────────────────────────────────────
    tos = sorted(
        [i for i in by_section.get("TableOccurrenceCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    lines.append(f"TABLE OCCURRENCES ({len(tos)}):")
    for item in tos:
        # Relationship adjacency (rung-2 topology): which TOs this one joins to — the
        # traversable graph, so the AI knows what data is reachable from each context.
        adj = sorted({r.to_name for r in from_idx.get(item.item_id, [])
                      if r.type == "RelationshipTO"})
        connects = ("  ↔ " + ", ".join(adj[:8]) + ("…" if len(adj) > 8 else "")) if adj else ""
        lines.append(f"  id={_id(item)}  {item.name}  →  {_to_base(_primary_xml(item))}{connects}")
    if not tos:
        lines.append("  (none)")
    lines.append("")

    # ── Relationships (the graph: predicate + operator) ────────────────────────
    rels = [i for i in by_section.get("RelationshipCatalog", []) if not i.is_folder]
    if rels:
        lines.append(f"RELATIONSHIPS ({len(rels)}):")
        seen: set = set()
        annotated_any = False
        for item in rels:
            predicate = next(iter(_content_lines(item.rendered_text)), "")
            if predicate and predicate not in seen:
                seen.add(predicate)
                predicate, was = _annotate_external_predicate(predicate)
                annotated_any = annotated_any or was
                lines.append(f"  {predicate}")
        if annotated_any:
            lines.append("  (« » marks a cross-file join field stored by id only — the named "
                         "local side is the relink key; FM will not auto-rematch a recreated field.)")
        lines.append("")

    # ── Structure — deterministic structural intent ────────────────────────────
    # The role each piece of schema plays in the schema's own machinery (idioms +
    # the true data model under the TO graph). Facts computed by rule, NOT inferred
    # purpose — purpose comes from the prompt, not the file. See core/structure_intent.
    lines.extend(_structure_section(artifact))

    # ── Base Tables + Fields (type, comment, calculation) ──────────────────────
    tables = sorted(
        [i for i in by_section.get("BaseTableCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    fields_by_table: dict = defaultdict(list)
    for fi in by_section.get("FieldsForTables", []):
        if fi.is_folder:
            continue
        tbl_name = (
            fi.name.split("::", 1)[0] if "::" in fi.name
            else (fi.folder_path[0] if fi.folder_path else "?")
        )
        fields_by_table[tbl_name].append(fi)

    lines.append(f"BASE TABLES ({len(tables)}):")
    for tbl in tables:
        tfields = sorted(fields_by_table.get(tbl.name, []), key=_sort_id)
        lines.append(f"  id={_id(tbl)}  {tbl.name}  ({len(tfields)} fields)")
        for fi in tfields:
            fname = fi.name.split("::", 1)[1] if "::" in fi.name else fi.name
            dtype = _attr(fi, "dataType", "datatype", default="?")
            ftype = _attr(fi, "fieldType", "fieldtype")
            ftype_str = f"  {ftype}" if ftype and ftype.lower() not in ("normal", "") else ""
            lines.append(f"    id={_id(fi)}  {fname}  {dtype}{ftype_str}")
            comment = _attr(fi, "comment")
            if comment:
                lines.append(f"      // {comment}")
            fxs = _xref_summary(fi)  # calc-field dependencies (field → fields/CFs)
            if fxs:
                lines.append(f"      {fxs}")
            if spine_bodies and "Formula:" in (fi.rendered_text or ""):
                formula = _formula_block(fi.rendered_text)
                if formula:
                    for fl in formula.splitlines():
                        lines.append(f"      {fl.strip()}")
    if not tables:
        lines.append("  (none)")
    lines.append("")

    # ── Scripts (with cross-reference summary) ─────────────────────────────────
    scripts = sorted(
        [i for i in by_section.get("ScriptCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    lines.append(f"SCRIPTS ({len(scripts)}):")
    for item in scripts:
        folder = "/".join(item.folder_path) if item.folder_path else ""
        parts = [f"  id={_id(item)}  {item.name}"]
        if item.dead_end:
            parts.append("  ☠")
        if folder:
            parts.append(f"  [{folder}]")
        lines.append("".join(parts))
        xs = _xref_summary(item)
        if xs:
            lines.append(f"      {xs}")
    if not scripts:
        lines.append("  (none)")
    lines.append("")

    # ── Workflows (what the solution DOES: user action → script call-tree) ──────
    # Rung-4: synthesized from the entry edges (layout/menu → script) + the call graph.
    # One line per user-invocable action, richest first, capped for the spine.
    from corpusfm.core.workflows import extract_workflows
    _WF_CAP = 25
    wf = extract_workflows(artifact, max_workflows=_WF_CAP)
    if wf.has_scripted_ui:
        lines.append(
            f"WORKFLOWS (user actions → scripts → data effects; {wf.entry_point_count} entry points):")
        for w in wf.workflows:
            surfaces = ", ".join(
                f"{n}" + (f"·{v}" if v else "") for _, n, v in w.invoked_from[:3])
            line = f"  {w.entry_name}  ⟵ {surfaces}"
            if w.calls:
                line += f"  →  {', '.join(w.calls[:6])}" + ("…" if len(w.calls) > 6 else "")
            lines.append(line)
            if w.writes:
                lines.append(f"      writes: {', '.join(w.writes[:6])}"
                             + (f"… (+{len(w.writes) - 6})" if len(w.writes) > 6 else ""))
            if w.reads:
                lines.append(f"      reads: {', '.join(w.reads[:6])}"
                             + (f"… (+{len(w.reads) - 6})" if len(w.reads) > 6 else ""))
            if w.sql_tables:
                lines.append(f"      via SQL (outside the relationship graph): {', '.join(w.sql_tables)}")
            if w.conditions:
                shown = w.conditions[:4]
                lines.append("      branches on: " + " · ".join(shown)
                             + (f" (+{len(w.conditions) - 4})" if len(w.conditions) > 4 else ""))
            if w.triggers:
                lines.append("      triggers (via navigation): " + ", ".join(w.triggers[:6]))
            if w.lands_in:
                lines.append("      lands in (related-record context): " + ", ".join(w.lands_in[:6]))
            if w.dynamic:
                lines.append(f"      ⚠ runtime-computed (unresolved): {'; '.join(w.dynamic)}")
        if wf.entry_point_count > len(wf.workflows):
            lines.append(f"  … +{wf.entry_point_count - len(wf.workflows)} more entry points")
    else:
        lines.append("WORKFLOWS: (no scripted UI — no layout/menu action invokes a script)")
    lines.append("")

    # ── AI usage (FM2026 native-AI lens) ───────────────────────────────────────
    try:
        from corpusfm.core.ai_usage import analyze_ai_usage, render_ai_usage
        ai_block = render_ai_usage(analyze_ai_usage(artifact))
        if ai_block:
            lines.append(ai_block)
            lines.append("")
    except Exception:
        pass

    # ── Layouts ────────────────────────────────────────────────────────────────
    layouts = sorted(
        [i for i in by_section.get("LayoutCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    lines.append(f"LAYOUTS ({len(layouts)}):")
    for item in layouts:
        lines.append(
            f"  id={_id(item)}  {item.name}  →  {_layout_to_name(_primary_xml(item))}"
            f"{_layout_wiring(item)}")
    if not layouts:
        lines.append("  (none)")
    lines.append("")

    # ── Value Lists (with definition when rendered) ────────────────────────────
    vls = sorted(
        [i for i in by_section.get("ValueListCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    lines.append(f"VALUE LISTS ({len(vls)}):")
    for item in vls:
        lines.append(f"  id={_id(item)}  {item.name}")
        if spine_bodies:
            detail = _content_lines(item.rendered_text)
            for d in detail[1:3]:  # skip the name line; show up to 2 definition lines
                lines.append(f"      {d}")
    if not vls:
        lines.append("  (none)")
    lines.append("")

    # ── Custom Functions (with formula body) ───────────────────────────────────
    cfs = sorted(
        [i for i in by_section.get("CustomFunctionsCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    lines.append(f"CUSTOM FUNCTIONS ({len(cfs)}):")
    for item in cfs:
        params = _attr(item, "parameters")
        sig = f"{item.name}({params})" if params else item.name
        lines.append(f"  id={_id(item)}  {sig}")
        if spine_bodies:
            formula = _formula_block(item.rendered_text)
            if formula:
                for fl in formula.splitlines():
                    lines.append(f"      {fl.strip()}")
    if not cfs:
        lines.append("  (none)")
    lines.append("")

    # ── External Data Sources ──────────────────────────────────────────────────
    ext_sources = sorted(
        [i for i in by_section.get("ExternalDataSourceCatalog", []) if not i.is_folder],
        key=_sort_id,
    )
    if ext_sources:
        lines.append(f"EXTERNAL DATA SOURCES ({len(ext_sources)}):")
        for item in ext_sources:
            lines.append(f"  id={_id(item)}  {item.name}")
        lines.append("")

    # ── Security (privilege sets + extended privileges) ────────────────────────
    priv_sets = [i for i in by_section.get("PrivilegeSetsCatalog", []) if not i.is_folder]
    ext_privs = [i for i in by_section.get("ExtendedPrivilegesCatalog", []) if not i.is_folder]
    if priv_sets or ext_privs:
        lines.append("SECURITY:")
        for item in priv_sets:
            detail = _content_lines(item.rendered_text)
            summary = detail[1] if len(detail) > 1 else ""
            lines.append(f"  privilege set: {item.name}" + (f"  — {summary}" if summary else ""))
            # Reach summary from the security graph — what this set can see/do, so a
            # privilege-gated workflow can be reasoned about (not just the coarse grid).
            reach = from_idx.get(item.item_id, [])
            by_sec: dict = defaultdict(int)
            write_tables: list = []
            for r in reach:
                if r.type != "PrivilegeAccess":
                    continue
                tgt = artifact.items.get(r.to)
                sec = tgt.section if tgt else "?"
                by_sec[sec] += 1
                if sec == "BaseTableCatalog" and r.mode == "write":
                    write_tables.append(r.to_name)
            if by_sec:
                parts = [f"{n} {_SEC_LABEL.get(s, s)}" for s, n in sorted(by_sec.items())]
                line = "      reaches: " + ", ".join(parts)
                if write_tables:
                    line += "  | writes tables: " + ", ".join(sorted(write_tables)[:6]) + (
                        "…" if len(write_tables) > 6 else "")
                lines.append(line)
        if ext_privs:
            names = ", ".join(i.name for i in ext_privs)
            lines.append(f"  extended privileges: {names}")
        lines.append("")

    # ── Structure Catalog Snapshot ─────────────────────────────────────────────
    sc = artifact.structure_catalog
    if sc is not None:
        lines.append(
            f"STRUCTURE CATALOG (catalog v{sc.schema_version}"
            f"  known steps: {sc.steps_in_catalog}):"
        )
        step_names: dict = {}
        grammar: dict = {}
        try:
            from corpusfm.core.schemas.registry import load_structure_catalog
            cat, _ = load_structure_catalog(sc.schema_version)
            step_names = {sid: entry.name for sid, entry in cat.steps.items()}
            grammar = cat.container_grammar or {}
        except Exception:
            pass
        if grammar:
            applies = ", ".join(grammar.get("applies_to") or []) or "ScriptCatalog"
            lines.append(
                f"  Folder grammar ({applies}): flat ordered list; "
                f"{grammar.get('folder_role_attr', 'isFolder')}=\"{grammar.get('folder_open_value', 'True')}\" opens a folder, "
                f"=\"{grammar.get('folder_close_value', 'Marker')}\" closes it; membership is positional. "
                f"A foldered object = open + object + close, in order (an Add of the bare object lands at root)."
            )
        if sc.steps_observed:
            lines.append(f"  Step types observed ({len(sc.steps_observed)}):")
            for sid in sc.steps_observed:
                name = step_names.get(sid, "unknown")
                tmpl_flag = "  [template]" if str(sid) in sc.steps_templates else ""
                lines.append(f"    id={sid}  {name}{tmpl_flag}")
        if sc.steps_unknown:
            ids_str = ", ".join(str(s) for s in sc.steps_unknown)
            lines.append(f"  Unknown step IDs (not in catalog): {ids_str}")
        if sc.field_types_observed:
            lines.append(f"  Field types: {', '.join(sc.field_types_observed)}")
        lines.append("")

    # ── Focus detail (task-scoped depth: seed + xref neighborhood) ─────────────
    if focus_ids:
        def _neighbor_names(recs, attr_id, attr_name) -> list:
            names: list = []
            for r in recs:
                n = getattr(r, attr_name) or getattr(r, attr_id)
                if n and n not in names:
                    names.append(n)
            return names

        # Seeds render before neighbors so that under a tight max_chars budget the seed
        # bodies always survive; within each group, section/id/name order.
        detail_items = sorted(
            (artifact.items[i] for i in focus_ids if i in artifact.items),
            key=lambda it: (it.item_id not in seed_ids, it.section, _sort_id(it), it.name),
        )
        n_seed = sum(1 for it in detail_items if it.item_id in seed_ids)
        n_neigh = len(detail_items) - n_seed
        if focus_neighbor_bodies:
            hdr = (f"FOCUS DETAIL ({len(detail_items)} objects: {n_seed} seed + {n_neigh} "
                   f"neighbor; all bodies included — task-relevant neighborhood, "
                   f"graph-expanded from the seed via xref):")
        else:
            hdr = (f"FOCUS DETAIL ({len(detail_items)} objects: {n_seed} seed + {n_neigh} "
                   f"neighbor; neighbor bodies omitted — pass focus_neighbor_bodies=true "
                   f"or get_object for them):")
        lines.append(hdr)

        def _item_body(it) -> str:
            if it.section == "ScriptCatalog":
                return _script_steps_body(it.rendered_text)
            if it.section == "LayoutCatalog":
                return "\n".join(_layout_objects_summary(it))
            body = _formula_block(it.rendered_text)
            if not body:
                body = "\n".join(_content_lines(it.rendered_text)[1:])
            return body

        body_chars = 0
        budget_hit = False
        deferred: list = []
        for it in detail_items:
            is_seed = it.item_id in seed_ids
            lines.append(f"  [{it.section}] {it.name}  id={_id(it)}")
            uses = _neighbor_names(from_idx.get(it.item_id, []), "to", "to_name")
            used_by = _neighbor_names(to_idx.get(it.item_id, []), "from_id", "from_name")
            if uses:
                lines.append(f"    uses: {', '.join(uses[:_XREF_CAP])}")
            if used_by:
                lines.append(f"    used by: {', '.join(used_by[:_XREF_CAP])}")

            if not (is_seed or focus_neighbor_bodies):
                lines.append(
                    f"    body omitted (1-hop neighbor) — get_object(artifact, "
                    f"\"{it.name}\", \"{it.section}\") or add it to focus=[...] for the body")
                continue

            body = _item_body(it)
            blines = body.splitlines()
            rendered = blines[:_FOCUS_BODY_MAX_LINES]
            block = "".join(f"    {bl.rstrip()}\n" for bl in rendered)
            if max_chars is not None and body_chars + len(block) > max_chars and body_chars > 0:
                budget_hit = True
                deferred.append(it)
                lines.append("    body omitted (max_chars budget reached) — "
                              f"get_object(artifact, \"{it.name}\", \"{it.section}\")")
                continue
            body_chars += len(block)
            for bl in rendered:
                lines.append(f"    {bl.rstrip()}")
            if len(blines) > _FOCUS_BODY_MAX_LINES:
                lines.append(f"    … ({len(blines) - _FOCUS_BODY_MAX_LINES} more lines truncated)")
        if budget_hit and deferred:
            noun = "bodies" if len(deferred) != 1 else "body"
            lines.append(
                f"  … {len(deferred)} more {noun} omitted "
                f"under the max_chars={max_chars} budget: "
                f"{', '.join(it.name for it in deferred)} — fetch with get_object.")
        lines.append("")

    out = "\n".join(lines).rstrip()
    # Whole-emission cap (no-focus path uses it too — the focus path already budgets bodies
    # above, but this is the final guard so neither path can exceed max_chars).
    if max_chars is not None and not focus_ids and len(out) > max_chars:
        out = out[:max_chars].rstrip() + (
            f"\n\n… [schema context truncated at {max_chars} chars — narrow with "
            f"focus=[name] / get_object, or render one section via render_section]")
    return out
