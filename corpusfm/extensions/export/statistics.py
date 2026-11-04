"""Descriptive per-file statistics and reference findings for Explorer (packet 1446).

Facts only: units and coverage are reported, nothing is scored, and a source that could not be examined
is reported as such rather than counted as zero. Everything is read from the artifact's retained XML, so
an older artifact needs a new Explorer and not a re-ingestion. `explorer_statistics` is the compact
projection the Statistics page reads: owners, slots and numbers, never formula text or step values.
"""
from __future__ import annotations

import re
import statistics as _stats
from collections import deque

from corpusfm.artifact.types import ArtifactType
from corpusfm.core import safe_xml as ET
from corpusfm.core.identity import AMBIGUOUS, CatalogIndex, field_context_index, reference_identity
from corpusfm.core.layout_objects import scan_layout_objects
from corpusfm.formula._lexer import _MISSING_MARKER

COMMENT_STEP_ID = 89

# States a structured reference can be in. `NOT_FOUND` is the only one that claims a target is absent,
# and only from this snapshot: it never claims the live database lacks it.
RESOLVED = "resolved"
NOT_FOUND = "not_found_in_snapshot"
AMBIGUOUS_TARGET = "ambiguous"
NO_TARGET = "no_target_identity"
EXTERNAL = "external_file"
UNVERIFIABLE = "catalog_incomplete"
MARKED_MISSING = "marked_missing_in_formula"

_REFERENCE_SECTIONS = {
    "ScriptReference": "ScriptCatalog",
    "LayoutReference": "LayoutCatalog",
    "ValueListReference": "ValueListCatalog",
    "TableOccurrenceReference": "TableOccurrenceCatalog",
    "FieldReference": "FieldsForTables",
    "CustomMenuReference": "CustomMenuCatalog",
}

# One pass, because a quote inside a comment and a comment marker inside a string each mean nothing.
_FORMULA_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|//[^\r\n]*', re.S)
KINDS_EXAMINED = ["scripts", "layouts", "value lists", "table occurrences", "fields", "custom menus"]
_SENTINEL_IDS = frozenset({"", "0", "-1"})


def summarize(values: list) -> dict:
    """Count, median and maximum: the neutral summary every ranked list leads with."""
    if not values:
        return {"count": 0, "median": None, "max": None}
    return {"count": len(values), "median": _stats.median(values), "max": max(values)}


def _sources(item) -> list:
    return list(getattr(item, "xml_sources", None) or [])


def _distinct_sources(item) -> list:
    """An item's sources without a repeat of its own content. FM 2026 stores value-list options inline
    and the parser projects them into a `ValueListOptions` source for older readers, so reading both
    counts each option's references twice. Older exports split them, and there both are read."""
    sources = _sources(item)
    if item.section != "ValueListCatalog":
        return sources
    primary = next((s for s in sources if s.catalog == "ValueListCatalog"), None)
    try:
        inline = primary is not None and any(c.tag in ("Source", "CustomValues", "Field") for c in ET.fromstring(primary.xml))
    except ET.ParseError:
        inline = False
    return [s for s in sources if not (inline and s.catalog == "ValueListOptions")]


def _real_items(artifact, section: str) -> list:
    return [i for i in artifact.items.values() if i.section == section and not i.is_folder]


# ── Scripts and steps ─────────────────────────────────────────────────────────

def step_facts(steps: list) -> list:
    """(step id, disabled, partial, step name, code points, blank) for rendered steps whose `full_text`
    is final: captured by Explorer before pooling removes it, so nothing renders twice."""
    return [(s.get("step_id"), bool(s.get("disabled")), bool(s.get("partial")), s.get("step_name", ""),
             len(s.get("full_text", "")), not s.get("full_text", "").strip()) for s in steps]


def _render_facts(source_xml: str, schema: str, name_map: dict):
    from corpusfm.extensions.export.explorer import _render_script_steps, _resolve_uuids

    steps, body = _render_script_steps(source_xml, schema)
    if not steps and body.startswith("(render error"):
        return None
    if name_map:
        for step in steps:
            step["full_text"] = _resolve_uuids(step.get("full_text", ""), name_map)
    return step_facts(steps)


def script_rows(artifact, facts: "dict | None" = None) -> list:
    """One row per script. Step classes overlap (a disabled comment is both), so they are not parts of
    the total. `chars` are Unicode code points of the fully rendered step before any display bounding:
    labels and punctuation are included, and values the renderer deliberately hides are not."""
    name_map = getattr(artifact, "_name_map", None) or getattr(artifact, "name_map", None) or {}
    schema = artifact.provenance.catalog_version
    rows = []
    for item in _real_items(artifact, "ScriptCatalog"):
        source = next((s for s in _sources(item) if s.catalog == "StepsForScripts"), None)
        row = {"item": item.item_id, "name": item.name, "status": "measured", "steps": 0, "comments": 0,
               "blank": 0, "disabled": 0, "partial": 0, "step_chars": []}
        rows.append(row)
        if source is None:
            row["status"] = "no_step_source"
            continue
        found = (facts or {}).get(item.item_id)
        if found is None:
            try:
                ET.fromstring(source.xml)
            except ET.ParseError:
                row["status"] = "unparseable"
                continue
            found = _render_facts(source.xml, schema, name_map)
            if found is None:
                row["status"] = "render_error"
                continue
        for number, (step_id, disabled, partial, step_name, chars, blank) in enumerate(found, 1):
            row["steps"] += 1
            row["comments"] += step_id == COMMENT_STEP_ID
            row["blank"] += blank
            row["disabled"] += disabled
            row["partial"] += partial
            row["step_chars"].append((number, step_name, chars))
    return rows


# ── Calculations ──────────────────────────────────────────────────────────────

def _slot_paths(root) -> list:
    """(calculation element, slot label, step number or None) for every Calculation that directly holds
    Text, so a nested wrapper counts once. The label is the nearest named ancestors, for orientation."""
    out = []

    def walk(el, trail, step_number):
        for child in el:
            number = step_number
            label = child.tag
            if child.tag == "Step":
                walk.count += 1
                number = walk.count
                label = child.get("name", "Step")
                walk.step_names.add(label)
            elif child.get("type") and child.tag in ("Parameter", "LayoutObject"):
                label = child.get("type")
            if child.tag == "Calculation" and child.find("Text") is not None:
                step_label = [t for t in trail if t in walk.step_names][:1]
                out.append((child, " › ".join(dict.fromkeys(step_label + trail[-1:])), number))
            walk(child, (trail + [label]) if child.tag != "Calculation" else trail, number)

    walk.count = 0
    walk.step_names = set()
    walk(root, [], None)
    return out


def calculation_rows(artifact) -> list:
    """One row per stored calculation slot in any object, in Unicode code points of the formula text.
    A function's supplemental catalog repeats its formula, so that one repeat counts once. Everywhere
    else identical text is a separate calculation: forty objects can share one hide formula."""
    rows = []
    for item in artifact.items.values():
        if item.is_folder:
            continue
        seen = set()
        for source in _distinct_sources(item):
            try:
                root = ET.fromstring(source.xml)
            except ET.ParseError:
                rows.append({"item": item.item_id, "name": item.name, "section": item.section,
                             "slot": source.catalog, "step": None, "chars": None})
                continue
            for calc, slot, step in _slot_paths(root):
                text = calc.find("Text").text or ""
                if not text.strip():
                    continue
                if item.section == "CustomFunctionsCatalog":
                    slot = "Formula"
                    if text in seen:
                        continue
                    seen.add(text)
                # A step number means something only in a script; a button's step has none to show.
                rows.append({"item": item.item_id, "name": item.name, "section": item.section,
                             "slot": slot or "Calculation", "step": step if source.catalog == "StepsForScripts" else None,
                             "chars": len(text)})
    return rows


# ── Layouts ───────────────────────────────────────────────────────────────────

def layout_rows(artifact) -> list:
    """One row per layout. Counts every stored entry once, including containers, their children and
    Table View columns; `by_type` keeps those apart. `unexamined` and `parse_error` say the count is
    not complete rather than letting it read as one."""
    rows = []
    for item in _real_items(artifact, "LayoutCatalog"):
        source = next((s for s in _sources(item) if s.catalog == "LayoutCatalog"), None)
        scan = scan_layout_objects(source.xml if source else "")
        by_type: dict = {}
        for obj in scan.objects:
            by_type[obj.type] = by_type.get(obj.type, 0) + 1
        rows.append({"item": item.item_id, "name": item.name, "objects": len(scan.objects), "by_type": by_type,
                     "unexamined": len(scan.unexamined), "parse_error": bool(scan.parse_error),
                     "no_source": source is None})
    return rows


# ── Relationship distance ─────────────────────────────────────────────────────

def _catalog(artifact, section: str) -> tuple:
    """(xml_key → item, xml_key → catalog xml, how many fragments could not be parsed)."""
    keyed, xml, unparsed = {}, {}, 0
    for item in artifact.items.values():
        if item.section != section:
            continue
        source = next((s for s in _sources(item) if s.catalog == section), None)
        if source is None:
            continue
        keyed[item.xml_key], xml[item.xml_key] = item, source.xml
        try:
            ET.fromstring(source.xml)
        except ET.ParseError:
            unparsed += 1
    return keyed, xml, unparsed


def _farthest(adjacency: dict, start: str) -> int:
    depth = {start: 0}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbour in adjacency[node]:
            if neighbour not in depth:
                depth[neighbour] = depth[node] + 1
                queue.append(neighbour)
    return max(depth.values())


def relationship_summary(artifact) -> dict:
    """Undirected TO adjacency from the full relationship inventory, not the drawing, which drops TOs
    without coordinates. `max_distance` is the largest SHORTEST jump count between two members of a
    component. One edge is one jump however many relationships join that pair. A TO belongs to
    its own file: no adjacency is invented across files or by matching base-table names."""
    keyed, xml, _ = _catalog(artifact, "TableOccurrenceCatalog")
    index = CatalogIndex("TableOccurrenceCatalog", xml)
    adjacency = {i.item_id: set() for i in _real_items(artifact, "TableOccurrenceCatalog")}
    pairs: dict = {}
    relationships = self_joins = unresolved = 0

    def endpoint(ref):
        resolution = index.resolve_reference(ref) if ref is not None else None
        if resolution is None or not resolution.resolved:
            return None
        items = {keyed[k].item_id for k in resolution.xml_keys if k in keyed}
        only = items.pop() if len(items) == 1 else None
        return only if only in adjacency else None

    for item in _real_items(artifact, "RelationshipCatalog"):
        source = next((s for s in _sources(item) if s.catalog == "RelationshipCatalog"), None)
        try:
            root = ET.fromstring(source.xml) if source else None
        except ET.ParseError:
            root = None
        if root is None:
            unresolved += 1
            continue
        relationships += 1
        left = endpoint(root.find("./LeftTable/TableOccurrenceReference"))
        right = endpoint(root.find("./RightTable/TableOccurrenceReference"))
        if not (left and right):
            unresolved += 1
            continue
        if left == right:
            self_joins += 1
            continue
        adjacency[left].add(right)
        adjacency[right].add(left)
        pair = tuple(sorted((left, right)))
        pairs[pair] = pairs.get(pair, 0) + 1

    components, seen = [], set()
    for node in sorted(adjacency):
        if node in seen:
            continue
        members, todo = {node}, [node]
        while todo:
            for neighbour in adjacency[todo.pop()]:
                if neighbour not in members:
                    members.add(neighbour)
                    todo.append(neighbour)
        seen |= members
        links = sum(len(adjacency[m]) for m in members) // 2
        components.append({"size": len(members), "links": links,
                           "max_distance": max(_farthest(adjacency, m) for m in members),
                           "members": sorted(members)})
    components.sort(key=lambda c: (-c["size"], c["members"][0]))
    return {"tos": len(adjacency), "relationships": relationships, "linked_pairs": len(pairs),
            "parallel_pairs": sum(1 for n in pairs.values() if n > 1), "self_joins": self_joins,
            "unresolved_relationships": unresolved, "components": components,
            "adjacency": {k: sorted(v) for k, v in adjacency.items()}}


# ── Reference findings ────────────────────────────────────────────────────────

def _external_data_source(parent):
    data_source = parent.find("DataSourceReference") if parent is not None else None
    return data_source if data_source is not None and data_source.get("id", "") != "0" else None


class _Classifier:
    def __init__(self, artifact):
        self.partial = artifact.type != ArtifactType.SAVE_AS_XML
        self.catalogs = {}
        for section in set(_REFERENCE_SECTIONS.values()):
            keyed, xml, unparsed = _catalog(artifact, section)
            self.catalogs[section] = {"keyed": keyed, "xml": xml, "unparsed": unparsed,
                                      "index": CatalogIndex(section, xml) if xml else None}
        self.fields = field_context_index(artifact.items)

    def _to(self, to_ref):
        """(external data-source name or None, base table name or None, resolved) for a TO reference."""
        catalog = self.catalogs["TableOccurrenceCatalog"]
        if to_ref is None or catalog["index"] is None:
            return None, None, False
        resolution = catalog["index"].resolve_reference(to_ref)
        if not resolution.resolved:
            return None, None, False
        root = ET.fromstring(catalog["xml"][resolution.xml_keys[0]])
        source = root.find("BaseTableSourceReference")
        if source is not None and source.get("type") != "BaseTableReference":
            data_source = source.find("DataSourceReference")
            return (data_source.get("name", "") if data_source is not None else "") or "external", None, True
        base = root.find("BaseTableSourceReference/BaseTableReference")
        return None, base.get("name") if base is not None else None, True

    def context(self, ref, parent) -> dict:
        """What separates two targets offering the same id or none: a field id means something only
        through its table occurrence, and an external target only with its file."""
        out = {}
        to_ref = ref.find("TableOccurrenceReference")
        if to_ref is not None and to_ref.get("name"):
            out["via"] = to_ref.get("name")
        data_source = _external_data_source(parent)
        external = data_source.get("name", "") if data_source is not None else self._to(to_ref)[0]
        if external:
            out["file"] = external
        return out

    def _related_record_step_is_external(self, step) -> bool:
        """A Go to Related Record through an external TO can name a layout in that other file."""
        if step is None or step.get("name") != "Go to Related Record":
            return False
        return any(self._to(ref)[0] for ref in step.iter("TableOccurrenceReference"))

    def classify(self, tag: str, ref, parent, step=None) -> str:
        section = _REFERENCE_SECTIONS[tag]
        uuid, ref_id = (ref.get("UUID") or "").strip(), (ref.get("id") or "").strip()
        if _MISSING_MARKER.fullmatch((ref.get("name") or "").strip()):
            return MARKED_MISSING
        if not uuid and ref_id in _SENTINEL_IDS:
            return NO_TARGET
        if _external_data_source(parent) is not None:
            return EXTERNAL
        catalog = self.catalogs[section]
        if tag == "FieldReference":
            external, base, to_resolved = self._to(ref.find("TableOccurrenceReference"))
            if external:
                return EXTERNAL
            if not uuid:
                if base is None:
                    return UNVERIFIABLE
                found = self.fields.get((base, ref_id), [])
                return RESOLVED if len(found) == 1 else (AMBIGUOUS_TARGET if found else self._absent(catalog))
        if catalog["index"] is None:
            return UNVERIFIABLE
        resolution = catalog["index"].resolve(reference_identity(section, ref))
        if tag == "LayoutReference" and self._related_record_step_is_external(step):
            # An id alone could match a same-id local layout; only a UUID shows it is this file's.
            return RESOLVED if resolution.resolved and uuid else EXTERNAL
        if resolution.resolved:
            return RESOLVED
        if resolution.kind == AMBIGUOUS:
            return AMBIGUOUS_TARGET
        return self._absent(catalog)

    def _absent(self, catalog) -> str:
        return UNVERIFIABLE if (self.partial or catalog["unparsed"] or catalog["index"] is None) else NOT_FOUND


def _walk_references(root, owner_tag: str = ""):
    """(element, parent, step number, step name, step element) for every reference. A projected fragment
    opens with a reference to its own owner, which is identity and not a dependency."""
    number = 0

    def walk(el, step_no, step_name, step):
        nonlocal number
        for child in el:
            current = (step_no, step_name, step)
            if child.tag == "Step":
                number += 1
                current = (number, child.get("name", ""), child)
            if child.tag in _REFERENCE_SECTIONS and not (child.tag == owner_tag and el is root):
                yield (child, el, *current)
            yield from walk(child, *current)

    yield from walk(root, None, "", None)


def reference_report(artifact) -> dict:
    """Every structured reference classified, unresolved ones grouped by target with every referring
    location kept. A count of resolved references is reported but their locations are not."""
    classifier = _Classifier(artifact)
    counts: dict = {}
    findings: dict = {}
    unexamined: list = []

    def record(state, section, offered, item, source, location, disabled):
        counts[state] = counts.get(state, 0) + 1
        key = (state, section, *(offered.get(k, "") for k in ("uuid", "id", "name", "via", "file")))
        finding = findings.setdefault(key, {"state": state, "section": section, "offered": offered, "referrers": []})
        finding["referrers"].append({"item": item.item_id, "section": item.section, "name": item.name,
                                     "catalog": source.catalog, "location": location, "disabled": disabled})

    for item in artifact.items.values():
        if item.is_folder:
            continue
        formulas_seen = set()
        for source in _distinct_sources(item):
            try:
                root = ET.fromstring(source.xml)
            except ET.ParseError:
                unexamined.append({"item": item.item_id, "catalog": source.catalog})
                continue
            disabled_steps = {}
            for number, step in enumerate(root.iter("Step"), 1):
                disabled_steps[number] = step.get("enable") == "False"
            owner_tag = {"StepsForScripts": "ScriptReference", "ValueListOptions": "ValueListReference"}.get(source.catalog, "")
            for ref, parent, step_no, step_name, step in _walk_references(root, owner_tag):
                state = classifier.classify(ref.tag, ref, parent, step)
                if state == RESOLVED:
                    counts[RESOLVED] = counts.get(RESOLVED, 0) + 1
                    continue
                offered = {k: v for k, v in (("uuid", ref.get("UUID", "")), ("id", ref.get("id", "")),
                                             ("name", ref.get("name", ""))) if v}
                offered.update(classifier.context(ref, parent))
                in_script = source.catalog == "StepsForScripts"
                location = (f"Step {step_no}: {step_name}" if in_script and step_no else step_name or parent.tag)
                record(state, _REFERENCE_SECTIONS[ref.tag], offered, item, source, location,
                       disabled_steps.get(step_no, False))
            for calc, slot, step_no in _slot_paths(root):
                raw = calc.find("Text").text or ""
                # Only a function's supplemental catalog repeats a formula; elsewhere each slot is its own place.
                if item.section == "CustomFunctionsCatalog":
                    if raw in formulas_seen:
                        continue
                    formulas_seen.add(raw)
                text = _FORMULA_LITERAL.sub("", raw)
                for marker in _MISSING_MARKER.findall(text):
                    record(MARKED_MISSING, "Formula", {"name": marker}, item, source,
                           (f"Step {step_no}: {slot}" if source.catalog == "StepsForScripts" and step_no else slot or "Calculation"),
                           disabled_steps.get(step_no, False))
    return {"counts": counts, "findings": list(findings.values()), "unexamined": unexamined,
            "partial_catalogs": classifier.partial, "kinds_examined": KINDS_EXAMINED}


# ── The compact projection the Statistics page reads ───────────────────────────

class _Table:
    """A value → small integer table, so repeated owners and labels cost one entry."""

    def __init__(self):
        self.index: dict = {}
        self.values: list = []

    def of(self, value) -> int:
        at = self.index.get(value)
        if at is None:
            at = self.index[value] = len(self.values)
            self.values.append(value)
        return at


def _guarded(build):
    """One category that fails says so; it never takes Explorer down or reads as an empty result."""
    try:
        return build()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def explorer_statistics(artifact, facts: "dict | None" = None) -> dict:
    owners = _Table()

    def owner(item_id: str, section: str, name: str) -> int:
        return owners.of((section, item_id, name))

    labels = _Table()

    def scripts_and_steps():
        rows, step_rows, status = [], [], {}
        measured = []
        for row in script_rows(artifact, facts):
            at = owner(row["item"], "ScriptCatalog", row["name"])
            status[row["status"]] = status.get(row["status"], 0) + 1
            rows.append([at, row["steps"], row["comments"], row["blank"], row["disabled"], row["partial"], row["status"]])
            step_rows.extend([at, number, labels.of(name), chars] for number, name, chars in row["step_chars"])
            if row["status"] == "measured":
                measured.append(row)
        step_rows.sort(key=lambda r: -r[3])
        rows.sort(key=lambda r: -r[1])
        return {"rows": rows, "step_rows": step_rows, "status": status,
                "steps": summarize([r["steps"] for r in measured]),
                "non_comment": summarize([r["steps"] - r["comments"] for r in measured]),
                "chars": summarize([r[3] for r in step_rows]),
                "totals": {k: sum(r[k] for r in measured) for k in ("steps", "comments", "blank", "disabled", "partial")}}

    def calculations():
        all_rows = calculation_rows(artifact)
        rows = [[owner(r["item"], r["section"], r["name"]), labels.of(r["slot"]), r["step"], r["chars"]]
                for r in all_rows]
        rows.sort(key=lambda r: -(r[3] if r[3] is not None else -1))
        by_section: dict = {}
        for r in all_rows:
            if r["chars"] is not None:
                by_section.setdefault(r["section"], []).append(r["chars"])
        return {"rows": rows, "chars": summarize([r[3] for r in rows if r[3] is not None]),
                "unparsed_sources": sum(r[3] is None for r in rows),
                "by_section": {k: summarize(v) for k, v in by_section.items()}}

    def layouts():
        all_rows = layout_rows(artifact)
        rows = [[owner(r["item"], "LayoutCatalog", r["name"]), r["objects"], r["by_type"], r["unexamined"],
                 r["parse_error"], r["no_source"]] for r in all_rows]
        rows.sort(key=lambda r: -r[1])
        by_type: dict = {}
        for r in all_rows:
            for kind, count in r["by_type"].items():
                by_type[kind] = by_type.get(kind, 0) + count
        return {"rows": rows, "objects": summarize([r["objects"] for r in all_rows if not (r["parse_error"] or r["no_source"])]),
                "total": sum(r["objects"] for r in all_rows), "by_type": by_type,
                "unexamined": sum(r["unexamined"] for r in all_rows),
                "parse_errors": sum(r["parse_error"] for r in all_rows), "no_source": sum(r["no_source"] for r in all_rows)}

    def relationships():
        summary = relationship_summary(artifact)
        for item_id in summary["adjacency"]:
            item = artifact.items[item_id]
            owner(item_id, item.section, item.name)
        def at(item_id):
            item = artifact.items[item_id]
            return owner(item_id, item.section, item.name)
        summary["components"] = [{**c, "members": [at(m) for m in c["members"]]} for c in summary["components"]]
        summary["adjacency"] = {str(at(k)): [at(n) for n in v] for k, v in summary["adjacency"].items()}
        return summary

    def references():
        report = reference_report(artifact)
        for finding in report["findings"]:
            finding["referrers"] = [[owner(r["item"], r["section"], r["name"]), labels.of(r["location"]), r["disabled"]]
                                    for r in finding["referrers"]]
        report["findings"].sort(key=lambda f: -len(f["referrers"]))
        report["unexamined"] = [[owner(u["item"], artifact.items[u["item"]].section, artifact.items[u["item"]].name),
                                 u["catalog"]] for u in report["unexamined"]]
        return report

    return {"scripts": _guarded(scripts_and_steps),
            "calculations": _guarded(calculations), "layouts": _guarded(layouts),
            "relationships": _guarded(relationships), "references": _guarded(references),
            "owners": owners.values, "labels": labels.values}
