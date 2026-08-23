"""corpusfm CLI entry point.

Usage:
    python -m corpusfm.server.cli [command] [subcommand] [args]
    python -m corpusfm.server.cli --help

Commands:
    compare        Compare two FM DDR XML files
    archive        List and inspect the local snapshot archive
    ingest         Ingest a local SaveAsXML/addon export into the catalog
    jobs           Manage automation jobs
    registrations  Manage named git export registrations (alias: regs)
    export         Export an FM XML file as .txt files to a git registration
    scheduler      Start the cron scheduler or check its status
    gap-analyze    Batch-run the schema gap analyzer against FM DDR XML files
    diff-companion A/B an addon vs its SaveAsXML twin for renderer divergences
    patch          Generate an FMUpgradeToolPatch XML from two artifacts
    pki            Manage the FMS Admin API PKI key (generate/test/delete/status)
    users          On-box user administration (create/reset/gates)
    storage        probe | repair  — out-of-band FM storage-credential recovery
    setup-embeddings  Stand up a local embedder (Ollama) and wire CORPUSfm at it
    reencode       Bulk re-encode stored blobs (--on/--off) + set the config flag
    status         Readiness/diagnostic report (tiers + per-capability status)
    migrate-storage / backfill-{system-tags,latest,storage-projections}
                   Storage-schema migration + idempotent data backfills
"""

from __future__ import annotations

import argparse
import sys

from corpusfm.server.cli import (
    cmd_archive, cmd_compare, cmd_diff_companion, cmd_export, cmd_gap_analyze,
    cmd_ingest, cmd_jobs, cmd_migrate, cmd_patch, cmd_reencode,
    cmd_registrations, cmd_scheduler, cmd_setup_embeddings,
    cmd_status, cmd_update_notice, cmd_users,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="corpusfm",
        description="FileMaker XML Diff Tool — CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="store_true", help="Show version and exit")
    sub = p.add_subparsers(dest="command")

    cmd_compare.add_parser(sub)
    cmd_archive.add_parser(sub)
    cmd_ingest.add_parser(sub)
    cmd_jobs.add_parser(sub)
    cmd_registrations.add_parser(sub)
    cmd_export.add_parser(sub)
    cmd_scheduler.add_parser(sub)
    cmd_gap_analyze.add_parser(sub)
    cmd_diff_companion.add_parser(sub)
    cmd_patch.add_parser(sub)
    cmd_users.add_parser(sub)
    cmd_setup_embeddings.add_parser(sub)
    cmd_migrate.add_parser(sub)
    cmd_reencode.add_parser(sub)
    cmd_status.add_parser(sub)
    cmd_update_notice.add_parser(sub)

    return p


def _quiet_console_logging() -> None:
    """Keep CLI console output clean. The CLI configures no logging handlers, so Python's last-resort
    handler prints WARNING+ (with full tracebacks) straight to stderr — meaning a recovered,
    already-handled ``logger.error(..., exc_info=True)`` deep in the storage/OData layer dumps a scary
    traceback even when the command SUCCEEDS. That leaked into installer output (a benign
    projection-backfill log nearly read as a failure). Attach a NullHandler so corpusfm log records
    are absorbed instead of last-resorted to stderr — CLI commands report their own outcomes via
    print(); set ``CORPUSFM_CLI_DEBUG=1`` to see the logs. urllib3's verify_ssl=False warning (already
    disabled in the OData backend) is silenced here too, before any import order can matter."""
    import logging
    import os
    import warnings
    if os.environ.get("CORPUSFM_CLI_DEBUG"):
        logging.basicConfig(level=logging.DEBUG)
        return
    logging.getLogger("corpusfm").addHandler(logging.NullHandler())
    warnings.simplefilter("ignore")
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass


def _make_console_encoding_safe() -> None:
    """Never let a console encoding crash a CLI command.

    Windows consoles default to cp1252, which can't encode some output glyphs (notably the "->" arrow
    U+2192). An inline ``print()`` of such a glyph raises ``UnicodeEncodeError`` and aborts the command
    — which once made the installer's projection-backfill step look like it failed (the re-projection
    had actually completed; only the success message crashed). Setting ``errors='backslashreplace'``
    keeps the console's native encoding but renders an unencodable glyph as ``\\uXXXX`` instead of
    crashing. Output strings are also kept ASCII (below), so this is a belt-and-suspenders net for
    anything missed or added later. Best-effort: a redirected/captured stream may not support it."""
    import sys
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except Exception:
            pass


def main(argv=None) -> int:
    _make_console_encoding_safe()
    _quiet_console_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from corpusfm import __version__
        print(f"corpusfm {__version__}")
        return 0

    if not args.command:
        parser.print_help()
        return 0

    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return 0

    return func(args)


if __name__ == "__main__":
    sys.exit(main())
