"""CLI: corpusfm archive list|show

List and inspect the local artifact store.
"""

from __future__ import annotations

import argparse
import sys


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "archive",
        help="Manage the local artifact store",
        description="List and inspect artifacts in the local store.",
    )
    sub = p.add_subparsers(dest="archive_cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List all artifacts")
    p_list.add_argument("--archive-dir", default=None, help="Archive directory (default: project_root/archive/)")
    p_list.add_argument("--limit", type=int, default=None, help="Maximum artifacts to show per FM file")

    # show
    p_show = sub.add_parser("show", help="Show metadata for an artifact")
    p_show.add_argument("rel_path", help="Artifact record UUID (or a PrimaryName/FileName alias)")
    p_show.add_argument("--archive-dir", default=None, help="Archive directory (default: project_root/archive/)")

    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.storage.local import LocalBackend, default_archive_dir
    from pathlib import Path

    archive_dir = Path(args.archive_dir) if args.archive_dir else default_archive_dir()

    if args.archive_cmd == "list":
        if not archive_dir.exists():
            print(f"Archive directory does not exist: {archive_dir}", file=sys.stderr)
            return 1

        all_metas = LocalBackend(archive_dir).iter_artifact_metas()
        if not all_metas:
            print("No artifacts found.")
            return 0

        # Group the flat metas by file_name locally for the grouped CLI listing (the backend no
        # longer groups). Sort each file's versions newest-first, matching the old grouped output.
        by_file: dict = {}
        for m in all_metas:
            by_file.setdefault(m.file_name, []).append(m)
        for metas in by_file.values():
            metas.sort(key=lambda m: m.timestamp, reverse=True)

        for file_name, metas in sorted(by_file.items()):
            print(f"\n{file_name}  ({len(metas)} artifact{'s' if len(metas) != 1 else ''})")
            limit = args.limit if args.limit else len(metas)
            for m in metas[:limit]:
                ts = m.timestamp.replace("_", " ").replace("T", " ")
                print(f"  {ts}  FM {m.fm_version}  schema {m.schema_version}  {m.uuid}")
        return 0

    if args.archive_cmd == "show":
        try:
            _be = LocalBackend(archive_dir)
            from corpusfm.storage import resolve as _resolve
            _uuid = _resolve.resolve_uuid(_be, args.rel_path) or args.rel_path
            art = _be.load_artifact(_uuid)
        except FileNotFoundError:
            print(f"No artifact found for {args.rel_path}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Error loading artifact: {exc}", file=sys.stderr)
            return 1
        print(f"File:           {art.identity.file_name}")
        print(f"FM Version:     {art.identity.fm_version}")
        print(f"Sections:       {', '.join(art.sections)}")
        print(f"Items:          {len(art.items)}")
        return 0

    return 0
