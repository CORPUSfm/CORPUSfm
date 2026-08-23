"""Structural intent — the role each piece of schema plays in the schema's own machinery.

NOT business intent ("this is the invoicing module" — that's unknowable, and arrives with
the prompt). This is the *structural* idiom: a self-join is a self-join, an unstored calc
is a display formatter, a join table resolves a many-to-many. FileMaker's structural
grammar is finite and idiomatic, so these are CLASSIFICATIONS OF PRESENT STRUCTURE — facts,
computed by graph + flag rules over the canonical layer (Artifact.items + xref_map). No AI,
no inference of purpose or history: we classify what *is*, never claim *why*.

The flagship is the data model: FileMaker's relationship graph shows table OCCURRENCES (a
view); collapse the TOs back to their base tables and union the relationships and you get
the real ER diagram underneath — which tables actually relate, and how.

EMBEDDED at ingestion into the artifact (Artifact.structure_intent) — rung 5 is real
structural fact, so it rides in the biscuit and is readable by any consumer of the stored
artifact (AI, MCP, Explorer) with no recompute. Improvements flow on re-ingest. Old
artifacts (pre-embedding) recompute on demand via structure_intent_dict(). Two consumers,
one embedded block: build_schema_context (AI) and the Explorer (human/mermaid).

Public API:
    analyze_structure(artifact)      -> StructureIntent      (compute)
    structure_intent_dict(artifact)  -> dict                 (read embedded, else compute)
    to_mermaid_erd(data_model)       -> str                  (DataModel or its dict)
"""

from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact

# Hub = a table occurrence wired into at least this many relationships. An explicit,
# stated threshold (shown as a number to the user) — a tunable constant, not a model.
_HUB_DEGREE = 6

# Embedded-block schema version. The structure_intent block rides in artifact.json.gz,
# computed at ingest — but it's derived from the artifact (items + xref_map), NOT from
# the raw XML, which we can't expect to still have. So when the algorithm improves there
# is nothing to re-ingest: BUMP THIS, and structure_intent_dict() treats every stored
# block stamped with an older version as wiped, recomputing fresh from the artifact.
# Self-healing — the update process needs no migration. Bump on any rule/tag change.
STRUCTURE_INTENT_VERSION = 2

_UUID_CALC = re.compile(r"Get\s*\(\s*UUID", re.IGNORECASE)
# A calc that builds a return-delimited value — the FileMaker multi-line ("multikey")
# key idiom: one field, many keys, each line matched independently. List(...) is the
# canonical builder; a literal pilcrow ¶ is the return character in a calc.
_LIST_CALC = re.compile(r"\bList\s*\(|¶")


@dataclass
class RelationshipShape:
    rel_id: str
    left_to: str
    right_to: str
    left_base: str
    right_base: str
    predicate: str          # "equi" | "cross" | "comparative" | "mixed"
    predicate_count: int
    self_join: bool
    allow_create: list      # sides that allow record creation: ["left"|"right"]
    left_fields: list       # base::field match fields on the left side
    right_fields: list      # base::field match fields on the right side
    tags: list

    def to_dict(self) -> dict:
        return {"rel_id": self.rel_id, "left": self.left_to, "right": self.right_to,
                "predicate": self.predicate, "self_join": self.self_join, "tags": self.tags}


@dataclass
class FieldRole:
    field: str              # "BaseTable::Field"
    fieldtype: str
    tags: list

    def to_dict(self) -> dict:
        return {"field": self.field, "fieldtype": self.fieldtype, "tags": self.tags}


@dataclass
class TORole:
    to: str
    base: str
    degree: int
    component: int          # connected-component id (the TOG this TO belongs to)
    tags: list

    def to_dict(self) -> dict:
        return {"to": self.to, "base": self.base, "degree": self.degree,
                "component": self.component, "tags": self.tags}


@dataclass
class ScriptRole:
    script: str
    tags: list

    def to_dict(self) -> dict:
        return {"script": self.script, "tags": self.tags}


@dataclass
class ModelEdge:
    a: str
    b: str
    relationship_count: int
    self_loop: bool
    cardinality: str        # "1:1" | "1:N" | "N:N" | "cross" | "?"
    join_keys: list = field(default_factory=list)   # ["a::field <op> b::field", …] distinct

    def to_dict(self) -> dict:
        return {"a": self.a, "b": self.b, "relationships": self.relationship_count,
                "self_loop": self.self_loop, "cardinality": self.cardinality,
                "join_keys": self.join_keys}


@dataclass
class DataModel:
    tables: list            # [{"name","fields","occurrences"}]
    edges: list             # [ModelEdge]

    def to_dict(self) -> dict:
        return {"tables": self.tables, "edges": [e.to_dict() for e in self.edges]}


@dataclass
class StructureIntent:
    relationships: list = field(default_factory=list)
    fields: list = field(default_factory=list)       # only fields with a notable role
    tos: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    data_model: "DataModel | None" = None

    def to_dict(self) -> dict:
        return {
            "relationships": [r.to_dict() for r in self.relationships],
            "fields": [f.to_dict() for f in self.fields],
            "tos": [t.to_dict() for t in self.tos],
            "scripts": [s.to_dict() for s in self.scripts],
            "data_model": self.data_model.to_dict() if self.data_model else None,
        }


# ── helpers ──────────────────────────────────────────────────────────────────

def _items(artifact, section):
    return [i for i in artifact.items.values() if i.section == section and not i.is_folder]


def _primary_xml(item) -> str:
    return item.xml_sources[0].xml if item.xml_sources else ""


def _to_base_map(artifact) -> dict:
    """Table-occurrence name → base-table name (the collapse key)."""
    out: dict = {}
    for it in _items(artifact, "TableOccurrenceCatalog"):
        try:
            el = ET.fromstring(_primary_xml(it))
        except ET.ParseError:
            continue
        bt = el.find(".//BaseTableReference")
        out[it.name] = bt.get("name", it.name) if bt is not None else it.name
    return out


_OP = {"Equal": "equi", "CartesianProduct": "cross"}


def _classify_relationships(artifact, to_base, finfo) -> tuple:
    """Per-relationship shape + the (base, field) match-field set, from the predicate
    grammar (JoinPredicate@type, JoinPredicateList membership, cascade flags).

    finfo (Base::Field → field facts) lets us name FileMaker's key idioms on the
    relationship: a global-anchored join (filtered portal / x-from-global navigation),
    a multi-line ("multikey") key, a live unstored-calc key. None of these are flaws —
    they're idiomatic FileMaker, valid grammar a SQL eye would misread."""
    shapes: list = []
    match_fields: set = set()
    for it in _items(artifact, "RelationshipCatalog"):
        try:
            el = ET.fromstring(_primary_xml(it))
        except ET.ParseError:
            continue
        lt = el.find("./LeftTable/TableOccurrenceReference")
        rt = el.find("./RightTable/TableOccurrenceReference")
        if lt is None or rt is None:
            continue
        lto, rto = lt.get("name", ""), rt.get("name", "")
        lbase, rbase = to_base.get(lto, lto), to_base.get(rto, rto)

        preds = el.findall(".//JoinPredicate")
        ptypes = {p.get("type", "Equal") for p in preds}
        kinds = {_OP.get(t, "comparative") for t in ptypes}
        predicate = next(iter(kinds)) if len(kinds) == 1 else "mixed"

        # Match fields per side, resolved to base::field (FieldsForTables item naming).
        def _side_fields(tag: str) -> list:
            out: list = []
            for fr in el.findall(f".//JoinPredicate/{tag}/FieldReference"):
                tor = fr.find("TableOccurrenceReference")
                tname = tor.get("name", "") if tor is not None else ""
                base = to_base.get(tname, tname)
                fname = fr.get("name", "")
                if base and fname:
                    key = f"{base}::{fname}"
                    out.append(key)
                    match_fields.add(key)
            return out
        left_fields, right_fields = _side_fields("LeftField"), _side_fields("RightField")

        allow = []
        lte, rte = el.find("./LeftTable"), el.find("./RightTable")
        if lte is not None and lte.get("cascadeCreate") == "True":
            allow.append("left")
        if rte is not None and rte.get("cascadeCreate") == "True":
            allow.append("right")

        self_join = lbase == rbase
        keys = set(left_fields) | set(right_fields)
        tags: list = []
        if self_join:
            tags.append("self-join")
        if predicate == "cross":
            tags.append("cross-join")
        elif predicate != "equi":
            tags.append("filtered")          # comparative / mixed = non-equijoin
        if len(preds) > 1:
            tags.append("compound-key")
        if allow:
            tags.append("allow-create")
        # FileMaker key idioms (read off the participating match fields) — valid grammar,
        # not anomalies: a global side, a multi-line key, a live unstored-calc key.
        if any(finfo.get(k, {}).get("global") for k in keys):
            tags.append("global-anchored")
        if any(finfo.get(k, {}).get("multikey") for k in keys):
            tags.append("multikey")
        if any(finfo.get(k, {}).get("unstored_calc") and not finfo.get(k, {}).get("global")
               for k in keys):
            tags.append("live-key")
        shapes.append(RelationshipShape(
            rel_id=it.name, left_to=lto, right_to=rto, left_base=lbase, right_base=rbase,
            predicate=predicate, predicate_count=len(preds), self_join=self_join,
            allow_create=allow, left_fields=left_fields, right_fields=right_fields, tags=tags))
    return shapes, match_fields


def _scan_fields(artifact) -> dict:
    """One pass over FieldsForTables → per-field structural facts, keyed Base::Field.

    Each value: {fieldtype, unique, global, unstored_calc, multikey, lookup, summary}.
    These are FileMaker's own field properties read straight off the XML — the raw
    facts the idiom classifiers (PK, match key, multikey, global key) build on."""
    info: dict = {}
    for it in _items(artifact, "FieldsForTables"):
        xml = _primary_xml(it)
        try:
            el = ET.fromstring(xml) if xml else None
        except ET.ParseError:
            el = None
        ft = (el.get("fieldtype") if el is not None else "") or it.attributes.get("fieldtype", "")
        rec = {"fieldtype": ft or "?", "unique": False, "global": False,
               "unstored_calc": False, "multikey": False, "lookup": False,
               "summary": ft == "Summary"}
        if el is not None:
            val = el.find("Validation")
            storage = el.find("Storage")
            ae = el.find("AutoEnter")
            # Unique = the PK signal. Strongest: a unique-validation constraint. Idiomatic:
            # an auto-enter serial (<AutoEnter type="SerialNumber"><SerialNumber/>) or a
            # Get(UUID) auto-enter calc.
            if val is not None and val.get("unique") == "True":
                rec["unique"] = True
            if ae is not None:
                if ae.get("type") == "SerialNumber" or ae.find("SerialNumber") is not None:
                    rec["unique"] = True
                elif _UUID_CALC.search(ET.tostring(ae, encoding="unicode")):
                    rec["unique"] = True
                if ae.get("valueFromField") == "True" or ae.find(".//Lookup") is not None:
                    rec["lookup"] = True
            if storage is not None and storage.get("global") == "True":
                rec["global"] = True
            if ft == "Calculated":
                stored = storage is not None and storage.get("storeCalculationResults") == "True"
                rec["unstored_calc"] = not stored
                if _LIST_CALC.search(xml):
                    rec["multikey"] = True
        info[it.name] = rec
    return info


def _classify_fields(artifact, finfo, match_fields, unique) -> list:
    """Per-field structural role from field facts + relationship participation. Only
    fields with a notable role are returned (plain stored data fields carry no idiom).

    The key idioms are the point: a global used as a match field is a global key (a
    filtered/navigation anchor, not a mistake); an unstored calc used as a key is a
    live key (recalculates as data changes); a list-building calc key is a multikey
    (one field, many keys). A global NOT used as a key is a utility global (FileMaker's
    session/scratch variable)."""
    roles: list = []
    for name in finfo:
        rec = finfo[name]
        ft = rec["fieldtype"]
        is_match = name in match_fields
        tags: list = []
        if name in unique:
            tags.append("primary-key")
        if is_match:
            tags.append("match-field")
        if rec["unstored_calc"]:
            tags.append("unstored-calc")
        elif ft == "Calculated":
            tags.append("calc-stored")
        if rec["summary"]:
            tags.append("summary")
        if rec["lookup"]:
            tags.append("lookup")
        if rec["global"]:
            tags.append("global-key" if is_match else "utility-global")
        if is_match:
            if rec["multikey"]:
                tags.append("multikey-field")
            if rec["unstored_calc"] and not rec["global"]:
                tags.append("live-key")
        if tags:
            roles.append(FieldRole(field=name, fieldtype=ft or "?", tags=sorted(set(tags))))
    return roles


def _components(adj) -> dict:
    """Connected-component id per node (the TOGs / relationship-graph islands)."""
    comp: dict = {}
    cid = 0
    for node in adj:
        if node in comp:
            continue
        stack, cid = [node], cid + 1
        while stack:
            n = stack.pop()
            if n in comp:
                continue
            comp[n] = cid
            stack.extend(adj.get(n, ()))
    return comp


def _classify_tos(artifact, to_base) -> list:
    """TO topology from the RelationshipTO adjacency: degree, hubs, isolated, the TOG
    (component), and the anchor/buoy shape within each component."""
    adj: dict = defaultdict(set)
    tos = [i.name for i in _items(artifact, "TableOccurrenceCatalog")]
    for name in tos:
        adj.setdefault(name, set())
    for r in artifact.xref_map:
        if r.type == "RelationshipTO":
            adj[r.from_name].add(r.to_name)
            adj[r.to_name].add(r.from_name)
    comp = _components(adj)
    # Per component, the highest-degree node is the anchor; degree-1 nodes hanging only
    # off the anchor are buoys (the anchor/buoy idiom).
    by_comp: dict = defaultdict(list)
    for name in adj:
        by_comp[comp.get(name, 0)].append(name)
    anchors: set = set()
    for members in by_comp.values():
        if len(members) > 2:
            anchors.add(max(members, key=lambda n: len(adj[n])))

    roles: list = []
    for name in sorted(adj):
        deg = len(adj[name])
        tags: list = []
        if deg == 0:
            tags.append("isolated")
        if deg >= _HUB_DEGREE:
            tags.append("hub")
        if name in anchors:
            tags.append("anchor")
        elif deg == 1 and (next(iter(adj[name])) in anchors):
            tags.append("buoy")
        roles.append(TORole(to=name, base=to_base.get(name, name), degree=deg,
                            component=comp.get(name, 0), tags=tags))
    return roles


def _classify_scripts(artifact) -> list:
    """Script role from the xref edge TYPES: entry point vs internal worker, trigger
    handler, parameterized sub, dead-end."""
    entry_kind: dict = defaultdict(set)   # script_id -> {"layout","menu","file","trigger","button"}
    called: set = set()
    has_param: set = set()
    for r in artifact.xref_map:
        if r.type in ("LayoutScript", "MenuScript", "FileScript"):
            entry_kind[r.to].add({"LayoutScript": "layout", "MenuScript": "menu",
                                  "FileScript": "file"}[r.type])
            if r.type == "LayoutScript":
                entry_kind[r.to].add("trigger" if r.via not in ("", "button") else "button")
        elif r.type == "ScriptReference":
            called.add(r.to)
            if r.via:
                has_param.add(r.to)
    roles: list = []
    for it in _items(artifact, "ScriptCatalog"):
        kinds = entry_kind.get(it.item_id, set())
        tags: list = []
        if kinds & {"layout", "menu", "file"}:
            tags.append("entry-point")
            if "trigger" in kinds:
                tags.append("trigger-handler")
        elif it.item_id in called:
            tags.append("worker")
        if it.dead_end:
            tags.append("dead-end")
        if it.item_id in has_param:
            tags.append("parameterized")
        if tags:
            roles.append(ScriptRole(script=it.name, tags=sorted(set(tags))))
    return roles


def _build_data_model(artifact, shapes, to_base, unique) -> DataModel:
    """Collapse the TO relationship graph to its base tables — the real ER model. One
    edge per distinct base-table pair, annotated with how many relationships collapsed
    onto it and a cardinality read from match-field uniqueness."""
    base_tables = _items(artifact, "BaseTableCatalog")
    occ: dict = defaultdict(int)
    for to in to_base.values():
        occ[to] += 1
    fcount: dict = defaultdict(int)
    for it in _items(artifact, "FieldsForTables"):
        base = it.name.split("::", 1)[0]
        fcount[base] += 1
    tables = [{"name": b.name, "fields": fcount.get(b.name, 0), "occurrences": occ.get(b.name, 0)}
              for b in base_tables]

    pairs: dict = defaultdict(list)
    for s in shapes:
        key = (s.left_base, s.right_base) if s.left_base <= s.right_base else (s.right_base, s.left_base)
        pairs[key].append(s)

    def _uniq_side(fields: list) -> bool:
        # A side is the "one" side when it has match fields and they're ALL unique (PK).
        return bool(fields) and all(f in unique for f in fields)

    _PRED_OP = {"equi": "=", "cross": "×", "comparative": "~", "mixed": "~"}

    def _join_keys(a: str, rels: list) -> list:
        # The distinct predicate field pairs collapsed onto this base-table edge, each
        # oriented so the left of the pair belongs to column `a`. This is the "which
        # fields actually join these two tables" that cardinality alone can't answer.
        out: list = []
        seen: set = set()
        for r in rels:
            op = _PRED_OP.get(r.predicate, "~")
            for lf, rf in zip(r.left_fields, r.right_fields):
                lo, ro = (lf, rf) if lf.split("::", 1)[0] == a else (rf, lf)
                pair = f"{lo} {op} {ro}"
                if pair not in seen:
                    seen.add(pair)
                    out.append(pair)
        return out

    edges: list = []
    for (a, b), rels in sorted(pairs.items()):
        cross = any(r.predicate == "cross" for r in rels)
        ones = sum(1 for r in rels if _uniq_side(r.left_fields) or _uniq_side(r.right_fields))
        boths = sum(1 for r in rels if _uniq_side(r.left_fields) and _uniq_side(r.right_fields))
        any_fields = any(r.left_fields or r.right_fields for r in rels)
        if cross:
            card = "cross"
        elif boths == len(rels) and boths:
            card = "1:1"
        elif ones:
            card = "1:N"
        elif any_fields:
            card = "N:N"
        else:
            card = "?"
        edges.append(ModelEdge(a=a, b=b, relationship_count=len(rels),
                               self_loop=(a == b), cardinality=card,
                               join_keys=_join_keys(a, rels)))
    return DataModel(tables=sorted(tables, key=lambda t: t["name"]), edges=edges)


def analyze_structure(artifact: "Artifact") -> StructureIntent:
    """Compute the deterministic structural-intent classification for an artifact."""
    to_base = _to_base_map(artifact)
    finfo = _scan_fields(artifact)
    unique = {n for n, r in finfo.items() if r["unique"]}
    shapes, match_fields = _classify_relationships(artifact, to_base, finfo)
    return StructureIntent(
        relationships=shapes,
        fields=_classify_fields(artifact, finfo, match_fields, unique),
        tos=_classify_tos(artifact, to_base),
        scripts=_classify_scripts(artifact),
        data_model=_build_data_model(artifact, shapes, to_base, unique),
    )


def compute_structure_block(artifact: "Artifact") -> dict:
    """Compute the full embedded block: the classification + mermaid + version stamp.

    This is what gets stored in the artifact at ingestion and what the accessor falls
    back to. Derived entirely from the artifact (items + xref_map) — no raw XML."""
    si = analyze_structure(artifact)
    block = si.to_dict()
    block["mermaid"] = to_mermaid_erd(si.data_model) if si.data_model else ""
    block["v"] = STRUCTURE_INTENT_VERSION
    return block


def structure_intent_dict(artifact: "Artifact") -> dict:
    """The embedded structural-intent block — the single source of rung-5 facts.

    Returns the block STORED in the artifact at ingestion (the biscuit carries it). Packet 1062
    RETIRED the on-read recompute fallback: a missing or stale (older ``STRUCTURE_INTENT_VERSION``)
    block is NOT recomputed here — reads stay fast (the 26–123 ms ``compute_structure_block`` no
    longer runs on every read of a stale artifact). A stale/absent block is refreshed by
    RE-INGESTION (the canonical pipeline re-embeds a current block), not on read. An artifact with
    no stored block (very old, or source-less and never re-ingested) yields an empty block until it
    is re-ingested — consistent with the "no source → not our problem" posture; ``{}`` is a safe,
    honest empty rather than a silent expensive recompute."""
    si = getattr(artifact, "structure_intent", None)
    return si if isinstance(si, dict) else {}


def _mm_id(name: str) -> str:
    """A mermaid-safe entity id (alnum + underscore)."""
    s = re.sub(r"[^0-9A-Za-z_]", "_", name).strip("_")
    return s or "T"


_CARD_MM = {"1:1": "||--||", "1:N": "||--o{", "N:N": "}o--o{", "cross": "}o--o{", "?": "}o--o{"}


def to_mermaid_erd(data_model) -> str:
    """Render the collapsed data model as a mermaid erDiagram — the real table-to-table
    model under the TO graph. Text, so both the human and the AI can read it.

    Accepts a DataModel or its dict form (the embedded block), so the stored biscuit
    renders without rebuilding dataclasses."""
    dm = data_model.to_dict() if isinstance(data_model, DataModel) else (data_model or {})
    edges = dm.get("edges", [])
    tables = dm.get("tables", [])
    lines = ["erDiagram"]
    related: set = set()
    for e in edges:
        ea, eb = e["a"], e["b"]
        related.add(ea); related.add(eb)
        card = e.get("cardinality", "?")
        rc = e.get("relationships", 1)
        token = _CARD_MM.get(card, "}o--o{")
        label = card + (f" x{rc}" if rc > 1 else "")
        a, b = _mm_id(ea), _mm_id(eb)
        if e.get("self_loop"):
            lines.append(f'    {a} {token} {a} : "{label} (self)"')
        else:
            lines.append(f'    {a} {token} {b} : "{label}"')
    # Include un-related tables as bare entities so the model is complete.
    for t in tables:
        if t["name"] not in related:
            lines.append(f'    {_mm_id(t["name"])} {{')
            lines.append("    }")
    return "\n".join(lines)
