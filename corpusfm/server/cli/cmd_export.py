"""CLI: corpusfm export <xml_file> <registration>

Parse an FM DDR XML file and export it as .txt files to a named git registration.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "export",
        help="Export an FM XML file as .txt files to a git registration",
        description=(
            "Parse a FMSaveAsXML file and write one .txt per catalog item "
            "to a named git registration. Creates a git commit."
        ),
    )
    p.add_argument("xml_file", help="FMSaveAsXML DDR export file (.xml)")
    p.add_argument("registration", help="Registration name (or 'ALL' to export to all)")
    p.add_argument("--modes", default=None,
                   help="Override modes: comma-separated (structured,rendered)")
    p.add_argument("--no-rendered", action="store_true",
                   help="Export structured mode only")
    p.add_argument("--no-hidden", action="store_true",
                   help="Disable hidden character marking in rendered output")
    p.add_argument("--label", default=None,
                   help="Override the file label used in the git repo path")
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.core.parser import load_file
    from corpusfm.core.git_formatter import (
        ExportConfig, export, export_to_registration,
        list_registrations, resolve_local_path,
    )

    xml_path = Path(args.xml_file)
    if not xml_path.exists():
        print(f"Error: file not found: {xml_path}", file=sys.stderr)
        return 1

    # Parse XML
    try:
        print(f"Parsing {xml_path.name}…")
        result = load_file(xml_path.read_bytes(), args.label or xml_path.stem)
        if not args.label:
            fm_name = result.metadata.get("File", "")
            if fm_name:
                result.label = fm_name.replace(".fmp12", "")
    except Exception as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1

    # Build export config overrides
    config_kwargs = {}
    if args.modes:
        config_kwargs["modes"] = [m.strip() for m in args.modes.split(",") if m.strip()]
    elif args.no_rendered:
        config_kwargs["modes"] = ["structured"]
    if args.no_hidden:
        config_kwargs["show_hidden"] = False

    # Determine target registrations
    if args.registration.upper() == "ALL":
        regs = list_registrations()
        if not regs:
            print("No registrations found.", file=sys.stderr)
            return 1
        targets = [r.name for r in regs]
    else:
        targets = [args.registration]

    rc = 0
    for reg_name in targets:
        try:
            er = export_to_registration(
                result, reg_name,
                **config_kwargs,
            )
            deleted_note = f", {er.files_deleted} deleted" if er.files_deleted else ""
            print(
                f"  {reg_name}: {er.files_written} files written{deleted_note}"
                f"  commit {er.commit_sha[:8]}"
            )
        except Exception as exc:
            print(f"  {reg_name}: ERROR — {exc}", file=sys.stderr)
            rc = 1

    return rc
