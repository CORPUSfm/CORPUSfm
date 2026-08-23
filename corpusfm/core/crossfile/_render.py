"""Human/AI-readable text rendering of cross-file analysis (for MCP tools + CLI)."""

from __future__ import annotations

from ._types import KIND_SCRIPT


def render_reference_set(refset) -> str:
    """What one file references in its siblings — data sources + refs grouped by file."""
    lines = [f"EXTERNAL REFERENCES FROM: {refset.source_file}", ""]
    fm = [d for d in refset.data_sources if d.is_filemaker]
    other = [d for d in refset.data_sources if not d.is_filemaker]
    lines.append("Data sources (FileMaker siblings):")
    if fm:
        for d in sorted(fm, key=lambda x: x.target_file):
            lines.append(f"  {d.name}  →  {d.target_file}")
    else:
        lines.append("  (none)")
    if other:
        lines.append("Data sources (non-FileMaker, not reconstructable):")
        for d in other:
            lines.append(f"  {d.name}  [{d.ds_type}]")
    lines.append("")

    by_file = refset.by_target_file()
    if not by_file:
        lines.append("No cross-file references found.")
        return "\n".join(lines)

    for tfile in sorted(by_file):
        refs = by_file[tfile]
        tables: dict = {}
        scripts: set = set()
        for r in refs:
            if r.kind == KIND_SCRIPT:
                scripts.add(r.external_script)
                continue
            tname = r.external_table or (r.external_to and f"(via TO {r.external_to})") or f"(via TO {r.via_name})"
            entry = tables.setdefault(tname, set())
            if r.external_field:
                entry.add(r.external_field)
            elif r.external_field_id:                 # name absent (cross-file id-only ref)
                entry.add(f"#{r.external_field_id}")
        lines.append(f"→ {tfile}  ({len(refs)} references)")
        for tname in sorted(tables):
            flds = sorted(tables[tname])
            shown = ", ".join(flds[:12]) + (f" …(+{len(flds) - 12})" if len(flds) > 12 else "")
            lines.append(f"    table {tname}: {shown}" if flds else f"    table {tname}")
        if scripts:
            lines.append(f"    scripts: {', '.join(sorted(scripts))}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_interface(iface) -> str:
    """The reconstructed external interface of a missing file — the skeleton."""
    d = iface.to_dict()
    cov = d["coverage"]
    lines = [
        f"RECONSTRUCTED EXTERNAL INTERFACE: {d['target_file']}",
        f"(rebuilt from {cov['contributing_files']} sibling file(s); "
        f"{cov['tables']} tables, {cov['fields']} fields, {cov['scripts']} scripts)",
        "",
        "This is the EXTERNAL INTERFACE ONLY — what siblings reference. It is NOT the whole",
        "file. Inferred types are guesses from usage; trust the confidence.",
        "",
        f"Contributing siblings: {', '.join(d['contributing_files']) or '(none)'}",
        "",
    ]
    if d["tables"]:
        lines.append("TABLES (referenced externally):")
        for t in d["tables"]:
            tag = " [base table inferred from TO]" if t["name_is_inferred"] else ""
            refby = ", ".join(t["referenced_by_files"])
            lines.append(f"\n  TABLE {t['name']}{tag}   (referenced by: {refby})")
            if t.get("merged_from"):
                lines.append(f"    consolidated with (same table, other TO aliases): {', '.join(t['merged_from'])}")
            if t["name_is_inferred"] and t.get("from_tos"):
                lines.append(f"    via external TOs: {', '.join(t['from_tos'])}")
            if not t["fields"]:
                lines.append("    (no specific fields referenced — table-level use only)")
            for f in t["fields"]:
                key = " ★KEY" if f["used_as_key"] else ""
                idtag = f" (id {f['field_id']})" if f["field_id"] else ""
                nameflag = " ~inferred" if f["name_is_inferred"] else ""
                lines.append(
                    f"    - {f['name']}{nameflag}{idtag}{key}  : {f['inferred_type']} "
                    f"(confidence {f['confidence']:.2f} — {f['rationale']})")
                for c in f.get("candidate_names", []):
                    lines.append(
                        f"        ? candidate name: {c['name']}  "
                        f"(conf {c['confidence']:.2f}, {c['source']}: {c['evidence']})")
        lines.append("")
    if d["scripts"]:
        lines.append("SCRIPTS (called cross-file — entry points the file must publish):")
        for s in d["scripts"]:
            lines.append(f"  - {s['name']}   (called by: {', '.join(s['called_by_files'])})")
        lines.append("")
    lines.append("BLIND SPOTS (NOT recoverable from references — do not fabricate):")
    for b in d["blind_spots"]:
        lines.append(f"  • {b}")
    return "\n".join(lines)
