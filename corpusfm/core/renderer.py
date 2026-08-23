"""Formatting helpers for the plain-text export report (Diff/MCP/CLI compare output)."""

from __future__ import annotations

from datetime import datetime, timezone
from corpusfm.core.comparator import CompareResult, SectionResult, inline_diff

SECTION_LABELS = {
    "BaseDirectoryCatalog":      "Addons",
    "BaseTableCatalog":          "Base Tables",
    "CustomFunctionsCatalog":    "Custom Functions",
    "ValueListCatalog":          "Value Lists",
    "ScriptCatalog":             "Scripts",
    "LayoutCatalog":             "Layouts",
    "PrivilegeSetsCatalog":      "Privilege Sets",
    "AccountsCatalog":           "Accounts",
    "ExternalDataSourceCatalog": "External Data Sources",
    "ThemeCatalog":              "Themes",
    "CustomMenuCatalog":         "Custom Menus",
    "TableOccurrenceCatalog":    "Table Occurrences",
    "RelationshipCatalog":       "Relationships",
}


def format_report(cr: CompareResult, section_cap: int = None) -> str:
    """Produce a plain-text export report matching the compare_fm.py output format.

    section_cap: OPT-IN per-list name cap (default None = no cap — the HTML Diff, git-export,
    and the `compare` CLI rely on the full report). When set (the MCP `compare` tool sets it),
    each added/removed/changed list shows only the first `section_cap` names followed by a
    "…N more" marker, mirroring temporal_diff's [:10] cap. The counts always stay accurate.
    """

    def _names(prefix: str, indent: str, sr: SectionResult, marker: str) -> list:
        out = []
        for names in (
            [f"{indent}+ {n}\n" for n in sr.added],
            [f"{indent}- {n}\n" for n in sr.removed],
            [f"{indent}~ {n}\n" for n in sr.changed],
        ):
            if section_cap is not None and len(names) > section_cap:
                extra = len(names) - section_cap
                names = names[:section_cap] + [f"{indent}…{extra} more\n"]
            out.extend(names)
        return out

    lines = []
    lines.append(f"=== FileMaker Diff: {cr.label_a}  vs  {cr.label_b} ===\n")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\n")

    total = 0

    for key, sr in cr.sections.items():
        label = SECTION_LABELS.get(key, key)
        if not sr.has_diff:
            lines.append(f"  {label}: no differences\n")
        else:
            lines.append(
                f"\n  [{label}]  +{len(sr.added)} added  "
                f"-{len(sr.removed)} removed  ~{len(sr.changed)} changed\n"
            )
            lines.extend(_names(label, "    ", sr, "    "))
            total += sr.total

    # Fields
    if cr.fields:
        lines.append("\n  [Fields by Table]\n")
        for table, sr in cr.fields.items():
            lines.append(
                f"    Table: {table}  +{len(sr.added)} -{len(sr.removed)} ~{len(sr.changed)}\n"
            )
            lines.extend(_names(table, "      ", sr, "      "))
        total += sum(s.total for s in cr.fields.values())
    else:
        lines.append("  [Fields]: no differences\n")

    # Script steps
    sr = cr.steps
    if not sr.has_diff:
        lines.append("  [Script Steps]: no differences\n")
    else:
        lines.append(
            f"\n  [Script Steps (body)]  +{len(sr.added)} -{len(sr.removed)} ~{len(sr.changed)}\n"
        )
        lines.extend(_names("Script Steps", "    ", sr, "    "))
        total += sr.total

    lines.append(f"\n=== Total differences: {total} ===\n")
    return "".join(lines)
