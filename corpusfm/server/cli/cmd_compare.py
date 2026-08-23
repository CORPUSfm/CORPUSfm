"""CLI: corpusfm compare <file_a> <file_b>

Parses two FM DDR XML files and prints a human-readable diff summary.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "compare",
        help="Compare two FM DDR XML files",
        description="Parse two FMSaveAsXML DDR exports and print schema differences.",
    )
    p.add_argument("file_a", help="Baseline XML file (e.g. live.xml)")
    p.add_argument("file_b", help="Comparison XML file (e.g. dev.xml)")
    p.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--label-a", default=None,
        help="Label for file A (default: auto-detected from file or filename)",
    )
    p.add_argument(
        "--label-b", default=None,
        help="Label for file B (default: auto-detected from file or filename)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.core.parser import load_file
    from corpusfm.core.comparator import compare_all
    from corpusfm.core.renderer import format_report

    path_a = Path(args.file_a)
    path_b = Path(args.file_b)

    for p in (path_a, path_b):
        if not p.exists():
            print(f"Error: file not found: {p}", file=sys.stderr)
            return 1

    try:
        label_a = args.label_a or path_a.stem
        label_b = args.label_b or path_b.stem

        result_a = load_file(path_a.read_bytes(), label_a)
        result_b = load_file(path_b.read_bytes(), label_b)

        # Override with FM file name if available
        if not args.label_a:
            fm_name = result_a.metadata.get("File", "")
            if fm_name:
                label_a = fm_name.replace(".fmp12", "")
                result_a.label = label_a
        if not args.label_b:
            fm_name = result_b.metadata.get("File", "")
            if fm_name:
                label_b = fm_name.replace(".fmp12", "")
                result_b.label = label_b

        cr = compare_all(result_a, result_b)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        import json
        out = {
            "label_a": cr.label_a,
            "label_b": cr.label_b,
            "total_real": cr.total_real,
            "sections": {
                key: {
                    "added": sr.added,
                    "removed": sr.removed,
                    "changed": sr.changed,
                }
                for key, sr in cr.sections.items()
            },
        }
        print(json.dumps(out, indent=2))
    else:
        report = format_report(cr)
        print(report)

    return 0 if cr.total_real == 0 else 1
