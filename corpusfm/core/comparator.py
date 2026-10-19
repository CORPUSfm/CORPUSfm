"""Comparison logic for parsed FM XML results.

Public API:
    compare_dicts(a, b, section_label)               -> SectionResult
    compare_fields(fields_a, fields_b)               -> {table: SectionResult}
    compare_steps(steps_a, steps_b)                  -> SectionResult
    compare_calcs(calcs_a, calcs_b)                  -> SectionResult
    compare_options(opts_a, opts_b)                  -> SectionResult
    compare_all(result_a, result_b)                  -> CompareResult
    inline_diff(text_a, text_b, label_a, label_b)    -> str
"""

from __future__ import annotations

import difflib
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from corpusfm.core.parser import ParseResult


@dataclass
class SectionResult:
    label: str
    added: list = field(default_factory=list)
    removed: list = field(default_factory=list)
    changed: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.changed)

    @property
    def has_diff(self) -> bool:
        return self.total > 0


@dataclass
class CompareResult:
    label_a: str
    label_b: str
    sections: dict          # {section_key: SectionResult}
    fields: dict            # {table_name: SectionResult}
    steps: SectionResult
    calcs: SectionResult
    options: SectionResult  # value list content (OptionsForValueLists)

    @property
    def total_real(self) -> int:
        total = sum(s.total for s in self.sections.values())
        total += sum(s.total for s in self.fields.values())
        total += self.steps.total
        total += self.calcs.total
        total += self.options.total
        return total


def inline_diff(text_a: str, text_b: str, label_a: str = "A", label_b: str = "B") -> str:
    """Return a unified diff string between two fingerprint strings."""
    lines_a = text_a.splitlines(keepends=True)
    lines_b = text_b.splitlines(keepends=True)
    diff = difflib.unified_diff(
        lines_a, lines_b,
        fromfile=label_a, tofile=label_b,
        lineterm="",
    )
    return "".join(diff)


def compare_dicts(a: dict, b: dict, section_label: str) -> SectionResult:
    """Compare two flat {name: fingerprint_or_name} dicts.

    Returns a SectionResult with sorted added / removed / changed lists.
    """
    added   = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    changed = sorted(k for k in set(a) & set(b) if a[k] != b[k])
    return SectionResult(label=section_label, added=added, removed=removed, changed=changed)


def compare_fields(fields_a: dict, fields_b: dict) -> dict:
    """Compare fields grouped by table.

    Returns {table_name: SectionResult} for tables that have any difference.
    Tables with no differences are omitted.
    """
    results: dict[str, SectionResult] = {}
    all_tables = sorted(set(fields_a) | set(fields_b))
    for table in all_tables:
        fa = fields_a.get(table, {})
        fb = fields_b.get(table, {})
        sr = compare_dicts(fa, fb, f"Fields/{table}")
        if sr.has_diff:
            results[table] = sr
    return results


def compare_steps(steps_a: dict, steps_b: dict) -> SectionResult:
    """Compare script step bodies keyed by script name."""
    return compare_dicts(steps_a, steps_b, "Script Steps (body)")


def compare_calcs(calcs_a: dict, calcs_b: dict) -> SectionResult:
    """Compare custom function formula bodies keyed by function name."""
    return compare_dicts(calcs_a, calcs_b, "Custom Function Bodies")


def compare_options(opts_a: dict, opts_b: dict) -> SectionResult:
    """Compare value list option bodies (OptionsForValueLists) keyed by VL name."""
    return compare_dicts(opts_a, opts_b, "Value List Options")


def serialize_compare_result(cr: "CompareResult") -> dict:
    """Serialize a CompareResult to a plain JSON-safe dict."""
    def _sr(s: SectionResult) -> dict:
        return {"label": s.label, "added": s.added, "removed": s.removed, "changed": s.changed}
    return {
        "label_a": cr.label_a,
        "label_b": cr.label_b,
        "sections": {k: _sr(v) for k, v in cr.sections.items()},
        "fields":   {k: _sr(v) for k, v in cr.fields.items()},
        "steps":    _sr(cr.steps),
        "calcs":    _sr(cr.calcs),
        "options":  _sr(cr.options),
    }


def deserialize_compare_result(data: dict) -> "CompareResult":
    """Reconstruct a CompareResult from a dict produced by serialize_compare_result."""
    def _sr(d: dict) -> SectionResult:
        return SectionResult(
            label=d["label"], added=d["added"], removed=d["removed"], changed=d["changed"]
        )
    return CompareResult(
        label_a=data["label_a"],
        label_b=data["label_b"],
        sections={k: _sr(v) for k, v in data["sections"].items()},
        fields={k:   _sr(v) for k, v in data["fields"].items()},
        steps=_sr(data["steps"]),
        calcs=_sr(data["calcs"]),
        options=_sr(data["options"]),
    )


def compare_artifacts(art_a: "object", art_b: "object") -> CompareResult:
    """Compare two Artifact objects and return a CompareResult.

    Uses rendered_text as the change fingerprint — no XML re-parse required.
    FieldsForTables is excluded from sections (handled via cr.fields, same as compare_all).
    """
    _FIELDS_SECTION = "FieldsForTables"

    def _section_names(art, section: str) -> dict:
        return {
            item.name: item.rendered_text or ""
            for item in art.items.values()
            if item.section == section
        }

    def _fields_by_table(art) -> dict:
        tables: dict = {}
        for item in art.items.values():
            if item.section != _FIELDS_SECTION or item.is_folder:
                continue
            name = item.name
            if "::" in name:
                table, field = name.split("::", 1)
            elif item.folder_path:
                table, field = item.folder_path[0], name
            else:
                continue
            tables.setdefault(table, {})[field] = item.rendered_text or ""
        return tables

    all_sections = sorted(
        {item.section for item in art_a.items.values()}
        | {item.section for item in art_b.items.values()}
    )
    sections: dict = {}
    for key in all_sections:
        if key == _FIELDS_SECTION:
            continue  # handled via cr.fields
        a = _section_names(art_a, key)
        b = _section_names(art_b, key)
        sections[key] = compare_dicts(a, b, key)

    fields = compare_fields(_fields_by_table(art_a), _fields_by_table(art_b))

    return CompareResult(
        label_a=art_a.identity.file_name or "",
        label_b=art_b.identity.file_name or "",
        sections=sections,
        fields=fields,
        steps=SectionResult(label="Script Steps (body)"),
        calcs=SectionResult(label="Custom Function Bodies"),
        options=SectionResult(label="Value List Options"),
    )


def compare_all(result_a: ParseResult, result_b: ParseResult) -> CompareResult:
    """Run all comparisons and return a structured CompareResult."""
    all_sections = sorted(
        set(result_a.sections) | set(result_b.sections)
    )
    sections: dict[str, SectionResult] = {}
    for key in all_sections:
        a = result_a.sections.get(key, {})
        b = result_b.sections.get(key, {})
        sections[key] = compare_dicts(a, b, key)

    fields   = compare_fields(result_a.fields, result_b.fields)
    steps    = compare_steps(result_a.steps, result_b.steps)
    calcs    = compare_calcs(result_a.calcs, result_b.calcs)
    options  = compare_options(result_a.options, result_b.options)

    return CompareResult(
        label_a=result_a.label,
        label_b=result_b.label,
        sections=sections,
        fields=fields,
        steps=steps,
        calcs=calcs,
        options=options,
    )


# ── Report alignment (packet 1425) ────────────────────────────────────────────
#
# The human HTML Diff pairs objects through ONE authority per mode, and every source item survives
# into exactly one entry. `compare_artifacts` above is deliberately left name-keyed: patch build /
# verification and the MCP compare tools depend on its legacy name-list contract.

ALIGN_ID = "id"
ALIGN_NAME = "name"
ALIGNMENTS = (ALIGN_ID, ALIGN_NAME)

PAIRED = "paired"
ONLY_A = "only_a"
ONLY_B = "only_b"
AMBIGUOUS = "ambiguous"
MISSING_KEY = "missing_key"

_FIELDS_SECTION = "FieldsForTables"
_TABLE_SECTION = "BaseTableCatalog"


@dataclass(frozen=True)
class AlignedEntry:
    """One report entry. PAIRED holds one item per side; every other status holds exactly one item,
    on the side named by ``side``. ``key`` is the matching key the item asserted (None when it has
    none); ``reason`` says why an item is not aligned."""
    section: str
    status: str
    a: Optional[object] = None
    b: Optional[object] = None
    key: Optional[tuple] = None
    reason: str = ""

    @property
    def side(self) -> str:
        return "a" if self.a is not None and self.b is None else ("b" if self.b is not None and self.a is None else "")

    @property
    def item(self):
        return self.b if self.b is not None else self.a


def _primary_el(item):
    from corpusfm.core import safe_xml as ET
    xml = item.xml_sources[0].xml if getattr(item, "xml_sources", None) else ""
    if not xml:
        return None
    try:
        return ET.fromstring(xml)
    except ET.ParseError:
        return None


def _asserted(item, el, attr: str) -> str:
    return (el.get(attr) if el is not None else None) or (item.attributes or {}).get(attr) or ""


def item_kind(item) -> str:
    """The structural kind the source ASSERTS, in ingestion's order (`pipeline._folder_type`):
    `isFolder` "True" is a folder and "Marker" its `--` end marker; otherwise `isSeparatorItem`
    "True" is a separator. Any other asserted `isFolder` value is kept distinct, never guessed."""
    el = _primary_el(item)
    v = _asserted(item, el, "isFolder")
    if v == "True":
        return "folder"
    if v == "Marker":
        return "marker"
    if _asserted(item, el, "isSeparatorItem") == "True":
        return "separator"
    if v and v != "False":
        return f"isFolder={v}"
    return "folder" if item.is_folder else "object"


def item_serial_id(item) -> "tuple[str, str]":
    """(serial id, reason). The id comes from the stored root attributes and the primary XML's
    owner identity (ID kind only — never the UUID, item_id or name). Disagreeing evidence is
    unresolved, not guessed."""
    from corpusfm.core.identity import ID_KIND, owner_identities
    found = set()
    attr = str((item.attributes or {}).get("id") or "").strip()
    if attr:
        found.add(attr)
    el = _primary_el(item)
    if el is not None:
        found.update(i.value for i in owner_identities(item.section, el) if i.kind == ID_KIND)
    if not found:
        return "", "no serial ID in the stored item"
    if len(found) > 1:
        return "", "conflicting serial IDs (" + ", ".join(sorted(found)) + ")"
    return next(iter(found)), ""


def field_context(item) -> "tuple[str, str]":
    """(table name, field name) from the stored field item, or ("", name) without table context."""
    name = item.name or ""
    if "::" in name:
        t, f = name.split("::", 1)
        return t, f
    if item.folder_path:
        return item.folder_path[0], name
    return "", name


def _table_ids(art) -> dict:
    """{table name: (serial id, reason)} for ONE snapshot. The parent scope must be owned uniquely
    both ways: exactly one BaseTable with that name, carrying an id no other BaseTable carries.
    Anything else yields an empty id and the reason the field cannot be scoped."""
    tables = [it for it in art.items.values()
              if it.section == _TABLE_SECTION and item_kind(it) == "object"]
    ids = [(it.name, *item_serial_id(it)) for it in tables]
    id_count = Counter(i for _, i, _ in ids if i)
    by_name: dict = {}
    for name, sid, _why in ids:
        by_name.setdefault(name, []).append(sid)
    out: dict = {}
    for name, sids in by_name.items():
        if len(sids) > 1:
            out[name] = ("", f"parent table '{name}' is ambiguous in this snapshot")
        elif not sids[0]:
            why = next(w for n, _i, w in ids if n == name)
            detail = f" ({why})" if why.startswith("conflicting") else ""
            out[name] = ("", f"parent table '{name}' has no serial ID{detail}")
        elif id_count[sids[0]] > 1:
            out[name] = ("", f"parent table '{name}' ID {sids[0]} is shared by another table in this snapshot")
        else:
            out[name] = (sids[0], "")
    return out


def _id_named_sections(art) -> frozenset:
    """Catalogs whose stored display label IS the serial id (`name_attr: id` in the artifact's own
    schema mapping — relationships and file-access authorizations carry no name). Such a label is not
    a name, so By Name must not match on it."""
    from corpusfm.core.schemas.registry import load_mapping_config
    cfg, _warn = load_mapping_config(getattr(art.provenance, "catalog_version", "") or "")
    return frozenset(c["key"] for c in cfg.get("catalogs", []) if c.get("name_attr") == "id")


def _alignment_key(item, mode: str, table_ids: dict,
                   unnamed: frozenset = frozenset()) -> "tuple[Optional[tuple], str]":
    kind = item_kind(item)
    sec = item.section
    if sec == _FIELDS_SECTION and kind == "object":
        table, fname = field_context(item)
        if mode == ALIGN_NAME:
            if not table:
                return None, "missing table context"
            if not fname:
                return None, "missing name"
            return (sec, kind, table, fname), ""
        fid, why = item_serial_id(item)
        if not fid:
            return None, why
        if not table:
            return None, "missing table context"
        if table not in table_ids:
            return None, f"parent table '{table}' not found in this snapshot"
        parent, why = table_ids[table]
        if not parent:
            return None, why
        return (sec, kind, parent, fid), ""
    if mode == ALIGN_NAME:
        if sec in unnamed:
            return None, "no object name (this catalog's label is its serial ID)"
        if not item.name:
            return None, "missing name"
        return (sec, kind, item.name), ""
    sid, why = item_serial_id(item)
    if not sid:
        return None, why
    return (sec, kind, sid), ""


def align_artifacts(art_a, art_b, mode: str = ALIGN_ID) -> "list[AlignedEntry]":
    """Pair the items of two artifacts by exactly one authority (`mode`), losslessly.

    A key pairs only when exactly one item on each side asserts it. A key asserted on one side only
    is ONLY_A / ONLY_B. Several candidates on either side pair nothing: each candidate becomes its
    own AMBIGUOUS entry. An item asserting no key is MISSING_KEY. No fallback between modes, no
    case-folding, no tie-breaking."""
    if mode not in ALIGNMENTS:
        raise ValueError(f"unknown alignment {mode!r}")
    buckets: dict = {}
    entries: list[AlignedEntry] = []
    for side, art in (("a", art_a), ("b", art_b)):
        tids = _table_ids(art)
        unnamed = _id_named_sections(art) if mode == ALIGN_NAME else frozenset()
        for item in art.items.values():
            key, why = _alignment_key(item, mode, tids, unnamed)
            if key is None:
                entries.append(AlignedEntry(item.section, MISSING_KEY,
                                            a=item if side == "a" else None,
                                            b=item if side == "b" else None, reason=why))
                continue
            buckets.setdefault(key, ([], []))[0 if side == "a" else 1].append(item)
    for key, (la, lb) in buckets.items():
        sec = key[0]
        if len(la) == 1 and len(lb) == 1:
            entries.append(AlignedEntry(sec, PAIRED, a=la[0], b=lb[0], key=key))
        elif len(la) <= 1 and len(lb) <= 1:
            if la:
                entries.append(AlignedEntry(sec, ONLY_A, a=la[0], key=key))
            else:
                entries.append(AlignedEntry(sec, ONLY_B, b=lb[0], key=key))
        else:
            why = (f"{len(la)} in A and {len(lb)} in B share this "
                   + ("name" if mode == ALIGN_NAME else "ID"))
            entries.extend(AlignedEntry(sec, AMBIGUOUS, a=i, key=key, reason=why) for i in la)
            entries.extend(AlignedEntry(sec, AMBIGUOUS, b=i, key=key, reason=why) for i in lb)
    entries.sort(key=lambda e: (e.section, (e.item.name or "").lower(), e.item.name or "",
                                e.a.item_id if e.a is not None else "",
                                e.b.item_id if e.b is not None else ""))
    return entries
