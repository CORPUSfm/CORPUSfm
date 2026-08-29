"""Which table occurrences does a layout bind to, and can we say we found them all (packet 1337)?

WHY THIS EXISTS. All FileMaker data access goes through table occurrences (developer, 2026-08-26), so
"pull what this layout shows" is really "pull from this set of TOs" — and working that set out by hand
from layout XML is the labour this answers. It is a QUERY-TIME analysis over the retained layout XML,
not another persisted xref layer: a stored index could predate packet 1340 or need a re-ingestion, and
then this report would be quietly answering from stale data.

COMPLETENESS IS THE POINT, NOT THE TO LIST. A short answer that looks total is the failure mode here —
the same one packet 072-D named when a crashed miner reported a clean analysis. So `complete` is true
only when the XML parsed, packet 1338's object scan reported no unexamined form, EVERY structural TO
reference received a known classification, and no dynamic TO-bearing expression was seen. A reference
whose path this module does not recognise is still returned, as `unclassified_reference` with its
element path — never dropped.

TWO PASSES, DELIBERATELY OVERLAPPING. The object scan supplies meaning (which object, what kind of
binding); an independent structural census of every `TableOccurrenceReference` supplies coverage. The
second is what makes the first's blind spots visible instead of invisible.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _dcfield

from corpusfm.core import safe_xml as ET

#: Where a TO reference can sit, in the vocabulary the report speaks.
LAYOUT_CONTEXT = "layout_context"          # the layout's own show-records-from
FIELD_OBJECT = "field_object"              # a placed field's TO context
PORTAL_CONTEXT = "portal_context"          # a portal's TO
OBJECT_NAVIGATION = "object_navigation"    # a Go to Related Record / New Window inside an object
LAYOUT_FORMULA = "layout_formula"          # a TO::Field in a hide/tooltip/conditional formula
UNCLASSIFIED = "unclassified_reference"    # object-like path this module does not recognise
UNRESOLVED_FIELD = "unresolved_field"      # a placed field with no TO and no qualified name


@dataclass
class TOBinding:
    name: str
    reasons: list = _dcfield(default_factory=list)     # ordered, deduplicated
    examples: list = _dcfield(default_factory=list)    # bounded, human-readable
    first_seen: int = 0                                # document position, for a stable sort

    def to_dict(self) -> dict:
        return {"table_occurrence": self.name, "reasons": list(self.reasons),
                "examples": list(self.examples)}


@dataclass
class LayoutBindingReport:
    bindings: list = _dcfield(default_factory=list)
    complete: bool = False
    unexamined_constructs: list = _dcfield(default_factory=list)
    dynamic_references: list = _dcfield(default_factory=list)
    unresolved_fields: list = _dcfield(default_factory=list)   # placed fields with no TO to attribute
    parse_error: str = ""

    def to_dict(self) -> dict:
        return {
            "bindings": [b.to_dict() for b in self.bindings],
            "complete": self.complete,
            "unexamined_constructs": list(self.unexamined_constructs),
            "dynamic_references": list(self.dynamic_references),
            "unresolved_fields": list(self.unresolved_fields),
            "parse_error": self.parse_error,
        }


_MAX_EXAMPLES = 3
_FORMULA_TAGS = ("Hide", "Tooltip", "Placeholder", "Conditions")


def _path_of(parents: dict, el) -> str:
    """A sanitized ancestor path, so an unclassified reference is actionable rather than mysterious."""
    parts = []
    cur = el
    while cur is not None and len(parts) < 6:
        parts.append(cur.tag)
        cur = parents.get(id(cur))
    return "/".join(reversed(parts))


def _classify(parents: dict, el) -> str:
    """Where does this `TableOccurrenceReference` sit? Decided from its ancestors, not from guesswork."""
    chain = []
    cur = parents.get(id(el))
    while cur is not None:
        chain.append(cur.tag)
        cur = parents.get(id(cur))
    if not chain:
        return UNCLASSIFIED
    if chain[0] == "FieldReference":
        return FIELD_OBJECT
    if chain[0] == "Layout":
        return LAYOUT_CONTEXT
    if "Step" in chain:
        return OBJECT_NAVIGATION
    if "Portal" in chain:
        return PORTAL_CONTEXT
    if any(t in chain for t in _FORMULA_TAGS):
        return LAYOUT_FORMULA
    return UNCLASSIFIED


def analyze_layout_bindings(layout_xml: str) -> LayoutBindingReport:
    """Every table occurrence this layout binds to, with why — and whether that list is complete."""
    from corpusfm.core.layout_objects import scan_layout_objects

    report = LayoutBindingReport()
    if not layout_xml:
        report.parse_error = "empty layout xml"
        return report
    try:
        root = ET.fromstring(layout_xml)
    except ET.ParseError as exc:
        # A malformed layout is an ERROR, not an empty binding set. Returning "no TOs" here would be
        # the confident-empty answer this module exists to prevent.
        report.parse_error = str(exc)
        return report

    scan = scan_layout_objects(layout_xml)
    report.unexamined_constructs = [dict(u) for u in scan.unexamined]

    parents = {}
    order = {}
    for pos, el in enumerate(root.iter()):
        order[id(el)] = pos
        for child in el:
            parents[id(child)] = el

    by_name: dict = {}

    def add(name, reason, example, pos):
        if not name:
            return
        entry = by_name.get(name)
        if entry is None:
            entry = by_name[name] = TOBinding(name=name, first_seen=pos)
        if reason not in entry.reasons:
            entry.reasons.append(reason)
        if example and example not in entry.examples and len(entry.examples) < _MAX_EXAMPLES:
            entry.examples.append(example)

    # Pass 1 — the structural census. EVERY reference, classified or not.
    unclassified = 0
    for el in root.iter("TableOccurrenceReference"):
        name = el.get("name", "")
        kind = _classify(parents, el)
        if kind == UNCLASSIFIED:
            unclassified += 1
            add(name, kind, _path_of(parents, el), order.get(id(el), 0))
        else:
            add(name, kind, "", order.get(id(el), 0))

    # Pass 2 — meaning, from packet 1338's object scan. It refines examples; it never gates coverage.
    for obj in scan.objects:
        pos = 0
        if obj.field_to:
            add(obj.field_to, FIELD_OBJECT, f"{obj.type} {obj.name or ''}".strip(), pos)
        elif obj.field:
            # A placed field carrying NO structural TO and no qualified name. It is reported as
            # unresolved rather than silently dropped, and it blocks `complete` — assigning it the
            # layout context would be a guess (found by Codex review, 2026-08-26).
            report.unresolved_fields.append(
                {"field": obj.field, "object": f"{obj.type} {obj.name or ''}".strip()})
        if obj.to:
            add(obj.to, PORTAL_CONTEXT, f"{obj.type} {obj.name or ''}".strip(), pos)
        for act in (obj.actions or []):
            if act.get("to"):
                add(act["to"], OBJECT_NAVIGATION, act.get("step", ""), pos)
            if act.get("dynamic"):
                report.dynamic_references.append(
                    {"kind": "navigation", "step": act.get("step", "?")})

    # Static `TO::Field` inside layout formulas, via the existing analyzer.
    from corpusfm.formula import analyze
    for tag in _FORMULA_TAGS:
        for holder in root.iter(tag):
            for text_el in holder.iter("Text"):
                formula = (text_el.text or "").strip()
                if not formula:
                    continue
                refs = analyze(formula)
                for fr in refs.field_refs:
                    if fr.table:
                        add(fr.table, LAYOUT_FORMULA, f"{tag} formula", 0)
                for dyn in refs.dynamic_refs:
                    report.dynamic_references.append(
                        {"kind": "formula", "slot": tag, "detail": getattr(dyn, "kind", str(dyn))})

    report.bindings = sorted(by_name.values(), key=lambda b: (b.first_seen, b.name))
    report.complete = (not report.parse_error and not report.unexamined_constructs
                       and unclassified == 0 and not report.dynamic_references
                       and not report.unresolved_fields)
    return report
