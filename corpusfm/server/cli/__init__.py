"""corpusfm CLI — command-line interface for all corpusfm operations.

Entry point:
    python -m corpusfm.server.cli [command] [subcommand] [args]

Commands:
    compare            Compare two FM DDR XML files and print the diff
    archive            Manage the local XML snapshot archive
    ingest             Ingest a local SaveAsXML/addon export into the catalog
    jobs               Create, run, list, validate, and delete automation jobs
    registrations      Manage named git export registrations (alias: regs)
    export             Export a parsed FM file to a git registration as .txt files
    scheduler          Start or query the cron job scheduler (server mode)
    gap-analyze        Batch-run the schema gap analyzer against FM DDR XML files
    diff-companion     A/B an addon vs its SaveAsXML twin for renderer divergences
    patch              Generate an FMUpgradeToolPatch XML from two artifacts
    pki                Manage the FMS Admin API PKI key (generate/test/delete/status)
    users              On-box user administration (create/reset password/gates)
    storage            probe | repair  — out-of-band FM storage-credential recovery
    reencode           Bulk re-encode stored blobs (--on/--off) + set the config flag
    status             Readiness/diagnostic report (tiers + per-capability status)
    migrate-storage / backfill-{system-tags,latest,storage-projections}
                       Storage-schema migration + idempotent data backfills
    migrate job-identity
                       JOB identity conversion — diagnosis/recovery (startup activates)

The authoritative command list is built in main.py::build_parser().
"""
