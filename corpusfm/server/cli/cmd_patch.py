"""CLI: corpusfm patch <artifact_a> <artifact_b>

Generate an FMUpgradeToolPatch XML from two stored CORPUSfm artifacts.

Usage examples:
    corpusfm patch MyFile/20260601T120000/ MyFile/20260615T120000/ -o patch.xml
    corpusfm patch snap_a snap_b --inject-export-script
    corpusfm patch snap_a snap_b --coverage-only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "patch",
        help="Generate an FMUpgradeToolPatch XML from two artifacts",
        description=(
            "Compare two stored CORPUSfm artifacts and generate an "
            "FMUpgradeToolPatch XML file. artifact_a is the baseline; "
            "artifact_b is the new version."
        ),
    )
    p.add_argument("artifact_a", help="Relative archive path for the baseline artifact")
    p.add_argument("artifact_b", help="Relative archive path for the new-version artifact")
    p.add_argument(
        "-o", "--output",
        metavar="PATH",
        default="patch.xml",
        help="Output path for the patch XML (default: patch.xml)",
    )
    p.add_argument(
        "--inject-export-script",
        action="store_true",
        default=False,
        help=(
            "Include the CORPUSfm SaveToDocumentsFolder export script in the patch "
            "when artifact_b lacks it. Disabled by default — read the CORPUSfm "
            "Addon documentation before using."
        ),
    )
    p.add_argument(
        "--coverage-only",
        action="store_true",
        default=False,
        help="Print coverage report only; do not write the patch XML",
    )
    p.add_argument(
        "--archive-dir",
        metavar="DIR",
        default=None,
        help="Override the archive directory",
    )
    p.set_defaults(func=run)


def run(args) -> int:
    from corpusfm.runtime import build_context
    from corpusfm.extensions.export.patch_build import generate_patch

    archive_dir = Path(args.archive_dir) if args.archive_dir else None
    backend = build_context(archive_dir=archive_dir).storage()   # active backend, composed (S7)
    adir = backend.archive_dir if hasattr(backend, "archive_dir") else None

    # Resolve artifact paths
    def _resolve(rel: str) -> Path:
        if adir:
            candidate = adir / rel / "artifact.json.gz"
            if candidate.exists():
                return candidate
        p = Path(rel)
        if (p / "artifact.json.gz").exists():
            return p / "artifact.json.gz"
        if p.name == "artifact.json.gz" and p.exists():
            return p
        print(f"ERROR: artifact not found: {rel}", file=sys.stderr)
        sys.exit(1)

    gz_a = _resolve(args.artifact_a)
    gz_b = _resolve(args.artifact_b)

    from corpusfm.artifact import Artifact
    try:
        art_a = Artifact.load_gz(gz_a)
        art_b = Artifact.load_gz(gz_b)
    except Exception as exc:
        print(f"ERROR loading artifacts: {exc}", file=sys.stderr)
        return 1

    # Notice when export script absent
    if not art_b.has_corpusfm_export:
        if args.inject_export_script:
            print(
                "NOTE: artifact_b does not have the CORPUSfm export script. "
                "It will be added to the patch (--inject-export-script)."
            )
        else:
            print(
                "NOTE: artifact_b does not have the CORPUSfm export script. "
                "Use --inject-export-script to include it so the patched file can "
                "push its schema back to CORPUSfm."
            )

    try:
        patch_xml, coverage = generate_patch(
            art_a, art_b,
            inject_export_script=args.inject_export_script,
        )
    except Exception as exc:
        print(f"ERROR generating patch: {exc}", file=sys.stderr)
        return 1

    cr = coverage.to_dict()
    print(
        f"Coverage: {coverage.patchable_count} patchable, "
        f"{coverage.not_patchable_count} not patchable"
    )
    for entry in cr.get("entries", []):
        status = entry.get("status", "?")
        reason = f" — {entry['reason']}" if entry.get("reason") else ""
        print(
            f"  [{status}] {entry.get('section','?')} / "
            f"{entry.get('name','?')} ({entry.get('action','?')}){reason}"
        )

    if args.coverage_only:
        return 0

    out_path = Path(args.output)
    try:
        out_path.write_text(patch_xml, encoding="utf-8")
        print(f"\nPatch written to: {out_path}")
    except Exception as exc:
        print(f"ERROR writing patch: {exc}", file=sys.stderr)
        return 1

    return 0
