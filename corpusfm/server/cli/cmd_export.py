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
    p.add_argument("xml_file", help="FMSaveAsXML export (.xml), FMAdd_on XML, or an add-on package (.fmaddon)")
    p.add_argument("registration", help="Registration name (or 'ALL' to export to all)")
    p.add_argument("--modes", default=None,
                   help="Override modes: comma-separated (structured,rendered)")
    p.add_argument("--no-rendered", action="store_true",
                   help="Export structured mode only")
    p.add_argument("--no-hidden", action="store_true",
                   help="Disable hidden character marking in rendered output")
    p.add_argument("--name-map", default=None, metavar="JSON",
                   help="An add-on's names as a JSON object of key → name (the retained name map, as "
                        "downloaded). A .fmaddon package supplies its own. Without one an add-on "
                        "exports under its identifiers.")
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

    # An add-on's names come from its package, or from a supplied map (packet 1460). Never required.
    name_map: dict = {}
    try:
        if xml_path.suffix.lower() == ".fmaddon":
            from corpusfm.core.addon.package import parse_addon_xar
            package = parse_addon_xar(xml_path)
            xml_bytes, name_map = package.xml_bytes, dict(package.name_map or {})
        else:
            xml_bytes = xml_path.read_bytes()
        if args.name_map:
            import json
            supplied = json.loads(Path(args.name_map).read_text(encoding="utf-8"))
            if not isinstance(supplied, dict):
                raise ValueError("--name-map must be a JSON object of key → name")
            name_map = {str(k): str(v) for k, v in supplied.items()}
    except Exception as exc:
        print(f"Read error: {exc}", file=sys.stderr)
        return 1

    # Parse XML
    try:
        print(f"Parsing {xml_path.name}…")
        result = load_file(xml_bytes, args.label or xml_path.stem)
        if not args.label:
            fm_name = result.metadata.get("File", "")
            if fm_name:
                result.label = fm_name.replace(".fmp12", "")
    except Exception as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 1

    # Build export config overrides (packet 1461: these reach the export; none is silently dropped)
    config_kwargs = {}
    if args.modes is not None:
        modes = [m.strip() for m in args.modes.split(",") if m.strip()]
        bad = [m for m in modes if m not in ("structured", "rendered")]
        if not modes or bad:
            print(f"Error: --modes takes structured, rendered or both (got {args.modes!r})", file=sys.stderr)
            return 1
        if args.no_rendered and "rendered" in modes:
            print("Error: --no-rendered conflicts with --modes including rendered", file=sys.stderr)
            return 1
        config_kwargs["modes"] = list(dict.fromkeys(modes))
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
                name_map=name_map or None,
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
