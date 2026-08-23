"""CLI: corpusfm gap-analyze <path>

Batch-run the schema gap analyzer against one or more FM DDR XML files.
Useful during development to catch mapping drift before users see it.

Usage examples:
    corpusfm gap-analyze xmlsamples/
    corpusfm gap-analyze xmlsamples/CMP_Operations.xml
    corpusfm gap-analyze xmlsamples/ --json
    corpusfm gap-analyze xmlsamples/ --only-issues
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "gap-analyze",
        help="Batch-run the schema gap analyzer against FM DDR XML files",
        description=(
            "Analyze one or more FM DDR XML files for schema mapping gaps: "
            "unmapped catalog keys, stale declarations, and attribute drift. "
            "Accepts a single .xml file or a directory (scanned recursively)."
        ),
    )
    p.add_argument(
        "path",
        help="Path to an FM DDR XML file or a directory containing .xml files",
    )
    p.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output full results as JSON instead of human-readable text",
    )
    p.add_argument(
        "--only-issues",
        action="store_true",
        help="Show only files that have at least one gap finding",
    )
    p.add_argument(
        "--no-stale",
        action="store_true",
        help="Suppress stale catalog warnings (optional catalogs still filtered by mappings.yaml)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.tools.xml_inspector import inspect as xml_inspect
    from corpusfm.tools.gap_analyzer import analyze
    from corpusfm.core.schemas.registry import load_mapping_config

    target = Path(args.path)
    if not target.exists():
        print(f"Error: path not found: {target}", file=sys.stderr)
        return 1

    # Collect XML files
    if target.is_file():
        xml_files = [target] if target.suffix.lower() == ".xml" else []
        if not xml_files:
            print(f"Error: not an XML file: {target}", file=sys.stderr)
            return 1
    else:
        xml_files = sorted(target.rglob("*.xml"))
        if not xml_files:
            print(f"No .xml files found under: {target}", file=sys.stderr)
            return 1

    results = []
    for xml_path in xml_files:
        entry = _analyze_file(xml_path, load_mapping_config, xml_inspect, analyze)
        results.append(entry)

    if args.json_output:
        return _output_json(results)
    else:
        return _output_text(results, args.only_issues, args.no_stale)


def _analyze_file(xml_path: Path, load_mapping_config, xml_inspect, analyze) -> dict:
    try:
        xml_bytes = xml_path.read_bytes()
        inspector = xml_inspect(xml_bytes)
        if inspector.error:
            return {"path": str(xml_path), "error": inspector.error}
        config, _warning = load_mapping_config(inspector.version)
        report = analyze(inspector, config)
        return {
            "path": str(xml_path),
            "fm_version": inspector.version,
            "schema_version": inspector.schema_version if hasattr(inspector, "schema_version") else "",
            "unmapped": report.unmapped,
            "stale": report.stale,
            "attribute_drift": [
                {
                    "catalog_key": e.catalog_key,
                    "item_xpath": e.item_xpath,
                    "missing_name_attr": e.missing_name_attr,
                    "declared_name_attr": e.declared_name_attr,
                    "new_attrs": e.new_attrs,
                }
                for e in report.attribute_drift
            ],
            "total_issues": report.total_issues,
        }
    except Exception as exc:
        return {"path": str(xml_path), "error": str(exc)}


def _output_json(results: list[dict]) -> int:
    import json

    total = len(results)
    errors = sum(1 for r in results if "error" in r)
    with_issues = sum(1 for r in results if not r.get("error") and r.get("total_issues", 0) > 0)
    unmapped_total = sum(len(r.get("unmapped", [])) for r in results)
    stale_total = sum(len(r.get("stale", [])) for r in results)
    drift_total = sum(len(r.get("attribute_drift", [])) for r in results)

    out = {
        "summary": {
            "total_files": total,
            "errors": errors,
            "clean": total - errors - with_issues,
            "with_issues": with_issues,
            "unmapped_total": unmapped_total,
            "stale_total": stale_total,
            "attribute_drift_total": drift_total,
        },
        "files": results,
    }
    print(json.dumps(out, indent=2))
    return 1 if (with_issues or errors) else 0


def _effective_issues(r: dict, no_stale: bool) -> int:
    if r.get("error"):
        return 0
    return (len(r.get("unmapped", []))
            + (0 if no_stale else len(r.get("stale", [])))
            + len(r.get("attribute_drift", [])))


def _output_text(results: list[dict], only_issues: bool, no_stale: bool) -> int:
    total = len(results)
    errors = sum(1 for r in results if "error" in r)
    with_issues = sum(1 for r in results if not r.get("error") and _effective_issues(r, no_stale) > 0)
    clean = total - errors - with_issues

    _w = max((len(Path(r["path"]).name) for r in results), default=20)
    _w = max(_w, 20)

    print(f"\nGap Analysis — {total} file{'s' if total != 1 else ''}")
    print("-" * (_w + 44))

    for r in results:
        name = Path(r["path"]).name
        if "error" in r:
            print(f"  {'ERROR':<8}  {name:<{_w}}  {r['error']}")
            continue

        unmapped = r.get("unmapped", [])
        stale = r.get("stale", [])
        drift = r.get("attribute_drift", [])
        n_effective = _effective_issues(r, no_stale)

        if only_issues and n_effective == 0:
            continue

        status = "ISSUES" if n_effective > 0 else "ok"
        fm_ver = (r.get("fm_version") or "?")[:12]
        print(f"  {status:<8}  {name:<{_w}}  FM {fm_ver}")

        if unmapped:
            print(f"           {'unmapped:':<13} {', '.join(unmapped)}")
        if stale and not no_stale:
            print(f"           {'stale:':<13} {', '.join(stale)}")
        for d in drift:
            parts = []
            if d["missing_name_attr"]:
                parts.append(f"missing name_attr={d['declared_name_attr']!r}")
            if d["new_attrs"]:
                parts.append(f"new attrs: {d['new_attrs']}")
            print(f"           {'drift:':<13} {d['catalog_key']} — {'; '.join(parts)}")

    print("-" * (_w + 44))
    print(f"  {total} file{'s' if total != 1 else ''}  |  {clean} clean"
          f"  |  {with_issues} with issues"
          + (f"  |  {errors} errors" if errors else ""))

    unmapped_total = sum(len(r.get("unmapped", [])) for r in results)
    stale_total    = sum(len(r.get("stale", [])) for r in results)
    drift_total    = sum(len(r.get("attribute_drift", [])) for r in results)
    print(f"  unmapped:{unmapped_total}  stale:{stale_total}  attribute_drift:{drift_total}\n")

    return 1 if (with_issues or errors) else 0
