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
