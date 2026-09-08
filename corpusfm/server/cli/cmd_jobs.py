"""CLI: corpusfm jobs list|create|validate|run|delete|history

Manage automation jobs from the command line.

**The filesystem job model is gone (packet 1361-01).** `--jobs-dir`, `--archive-dir` and
`--history-dir` are removed from every verb, along with the `local_file` source and its `--path`.
They selected a job store, an archive and a run history off disk and executed against them — a model
the product does not support. A CORPUSfm Job pulls XML from a HOSTED FileMaker file, stores the
artifact internally, and may export to GitHub. Jobs live in the JOB table, runs live in HISTORY, and
`run` ENQUEUES onto the one QUEUE the worker drains.

Ingesting a file from disk is still fully supported — it is `corpusfm ingest`, which is ingestion
rather than an automation unit.
"""

from __future__ import annotations

import argparse
import sys


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "jobs",
        help="Manage automation jobs",
        description="Create, list, validate, run, and delete corpusfm automation jobs.",
    )
    sub = p.add_subparsers(dest="jobs_cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List all configured jobs")

    # validate
    p_val = sub.add_parser("validate", help="Validate a job's configuration")
    p_val.add_argument("job_uuid", help="Job UUID (see `corpusfm jobs list`)")

    # run
    p_run = sub.add_parser("run", help="Run a job immediately")
    p_run.add_argument("job_uuid", help="Job UUID (see `corpusfm jobs list`)")
    p_run.add_argument("--trigger", default="manual", help="Trigger label (default: manual)")

    # delete
    p_del = sub.add_parser("delete", help="Delete a job")
    p_del.add_argument("job_uuid", help="Job UUID (see `corpusfm jobs list`)")
    p_del.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    # history
    p_hist = sub.add_parser("history", help="Show run history for a job")
    p_hist.add_argument("job_uuid", help="Job UUID (see `corpusfm jobs list`)")
    p_hist.add_argument("--limit", type=int, default=20)

    # create (guided)
    p_create = sub.add_parser("create", help="Create a new job interactively (YAML output)")
    p_create.add_argument("name", help="Job name (a label; it need not be unique)")
    p_create.add_argument("--source-type", default="fms_save_to_documents",
                          choices=["fms_local", "fms_save_to_documents",
                                   "fms_save_to_file_path", "fms_push"])
    p_create.add_argument("--server", default=None, help="FMS server URL (fms_* types)")
    p_create.add_argument("--database", default=None,
                          help="The hosted FM file this job pulls — its OWNER FILE. Required.")
    p_create.add_argument("--script", default=None, help="FM script name to call (fms_* types)")
    p_create.add_argument("--trigger-manual", action="store_true", default=True)
    p_create.add_argument("--trigger-schedule", default=None, metavar="WHEN",
                          help="Add a schedule: 'HH:MM' (every day) or 'mon,wed HH:MM' "
                               "(those days). Server-local time.")
    p_create.add_argument("--trigger-webhook", action="store_true")
    p_create.add_argument("--registrations", default=None,
                          help="Comma-separated git registration names for git export")
    p_create.add_argument("--modes", default="structured,rendered",
                          help="Comma-separated export modes (default: structured,rendered)")
    p_create.add_argument("--description", default=None)
    p_create.add_argument("--account", default=None,
                          help="FileMaker account for this job's pull (required for fms_* sources)")
    p_create.add_argument("--password-stdin", action="store_true",
                          help="Read the FileMaker password from stdin. There is deliberately no "
                               "--password: a secret on the command line is visible in the process "
                               "list to every user on the box.")

    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.server.jobs import (
        list_jobs, load_job, validate_job, delete_job,
        list_runs_for, save_job,
        JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger, generate_token,
    )

    # ── list ──────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "list":
        all_jobs = list_jobs()
        if not all_jobs:
            print("No jobs configured.")
            return 0
        for cfg, err in all_jobs:
            if err:
                print(f"  [INVALID] {err}")
            else:
                triggers = ", ".join(sorted({t.type for t in cfg.triggers}))
                state_desc = ""
                try:
                    from corpusfm.server.jobs.state import read_state
                    s = read_state(getattr(cfg, "id", "") or "")
                    if s.last_status:
                        ts = (s.last_run_ts or "")[:19].replace("T", " ")
                        state_desc = f"  last: {ts} {s.last_status}"
                except Exception:
                    pass
                # The UUID is the address; the name is a label. Both are shown so an operator can
                # pick a job and then act on it (packet 1372-02).
                print(f"  {getattr(cfg, 'id', '') or '(no id)'}  {cfg.name}  "
                      f"[{cfg.source.type}]  triggers: {triggers}{state_desc}")
        return 0

    # ── validate ──────────────────────────────────────────────────────────────
    if args.jobs_cmd == "validate":
        try:
            cfg = load_job(args.job_uuid)
        except (KeyError, FileNotFoundError):
            print(f"Error: no job with id '{args.job_uuid}'", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Error loading job: {exc}", file=sys.stderr)
            return 1
        errors = validate_job(cfg)
        if errors:
            print(f"Validation failed ({len(errors)} error{'s' if len(errors) != 1 else ''}):")
            for e in errors:
                print(f"  - {e}")
            return 1
        print(f"Job '{cfg.name}' ({args.job_uuid}) is valid.")
        return 0

    # ── run ───────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "run":
        # ENQUEUE, never execute (packet 1361-01, ruling 10). Every other production trigger — the
        # scheduler, the browser and MCP — already puts a Job Run on the QUEUE and lets the single
        # pull worker execute it; this command called the synchronous runner directly, which is a
        # SECOND production pull path, outside the worker's mutual exclusion, whose write dies with
        # the terminal that started it. The queue acquire→ingest path is now the only one.
        from corpusfm.server import queue_handlers as QH
        from corpusfm.server import queue_workers as W
        from corpusfm.storage import queue_record as Q
        from corpusfm.server.jobs.store import load_job
        from corpusfm.storage import get_backend
        try:
            job = load_job(args.job_uuid)
        except KeyError:
            print(f"Error: job '{args.job_uuid}' not found", file=sys.stderr)
            return 1
        try:
            backend = get_backend()
            qid, run_id = QH.enqueue_job_run(
                backend, job_name=job.name, job_uuid=args.job_uuid,
                file_name=getattr(job.source, "file_name", "") or "",
                trigger=args.trigger)
            try:
                W.poke(Q.ACQUIRE)      # nudge the in-process worker when there is one
            except Exception:
                pass
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        print(f"Queued a run of '{job.name}' ({args.job_uuid}).")
        print(f"  queue id: {qid}")
        print(f"  run id:   {run_id}")
        print("  follow:   the Runs page, or `corpusfm jobs history`")
        return 0

    # ── delete ────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "delete":
        if not getattr(args, "yes", False):
            confirm = input(f"Delete job {args.job_uuid}? [y/N] ").strip().lower()
            if confirm != "y":
                print("Cancelled.")
                return 0
        deleted = delete_job(args.job_uuid)
        if deleted:
            print(f"Deleted job {args.job_uuid}.")
        else:
            print(f"No job with id '{args.job_uuid}'.", file=sys.stderr)
            return 1
        return 0

    # ── history ───────────────────────────────────────────────────────────────
    if args.jobs_cmd == "history":
        from corpusfm.storage import get_backend
        try:
            _label = load_job(args.job_uuid).name
        except Exception:
            _label = args.job_uuid
        runs = list_runs_for(args.job_uuid, limit=args.limit, backend=get_backend())
        if not runs:
            print(f"No run history for job {args.job_uuid}.")
            return 0
        print(f"Run history for '{_label}' ({args.job_uuid}, newest first):")
        for r in runs:
            ts = r.ts[:19].replace("T", " ")
            dur = f"{r.duration_s:.1f}s" if r.duration_s else "?"
            err = f"  error: {r.error}" if r.error else ""
            print(f"  {ts}  {r.status}  {r.trigger}  {dur}{err}")
        return 0

    # ── create ────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "create":
        triggers = []
        if args.trigger_manual:
            triggers.append(JobTrigger(type="manual"))
        if args.trigger_schedule:
            from corpusfm.server.jobs.schedule import parse_cli_schedule
            sched, err = parse_cli_schedule(args.trigger_schedule)
            if err:
                print(f"--trigger-schedule: {err}", file=sys.stderr)
                return 2
            triggers.append(JobTrigger(type="schedule", schedule=sched))
        token = None
        if args.trigger_webhook:
            token = generate_token()
            triggers.append(JobTrigger(type="webhook"))

        regs = [r.strip() for r in args.registrations.split(",") if r.strip()] if args.registrations else []
        modes = [m.strip() for m in args.modes.split(",") if m.strip()]
        git_export = JobGitExport(registrations=regs, modes=modes) if regs else None

        # THE JOB'S IDENTITY, MINTED HERE (packet 1372-02). The shipped CLI create path used to
        # construct no id at all — the reachable id-less class the parent packet measured, whose
        # scheduled runs then wrote a blank `UUIDJob` and produced job-less artifacts. `save_job`
        # now refuses a config without one, so this is the fix and its own regression guard.
        import uuid as _uuidlib
        job_id = str(_uuidlib.uuid4())

        # EVERY job pulls from FileMaker and therefore needs a credential — the `local_file` exemption
        # went with the source type (packet 1361-01), so R3's wording is unconditional again and this
        # surface now agrees with the browser about every job a user can create. The secret never
        # travels in argv: it would be visible in the process list to every user on the box.
        account = (args.account or "").strip()
        if not account:
            print("Error: --account is required — a job cannot pull without a credential.",
                  file=sys.stderr)
            return 1
        if not args.password_stdin:
            print("Error: pass --password-stdin and provide the password on stdin.",
                  file=sys.stderr)
            return 1
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            print("Error: no password was read from stdin.", file=sys.stderr)
            return 1

        # THE OWNER FILE, named explicitly (packet 086 file-centric / 1361-01). Every remaining
        # source pulls from a hosted file, so `--database` IS the job's owner file and the CLI must
        # say so on the config — a job with no `file` cannot pull, and the browser has always set it.
        _dbs = [d.strip() for d in args.database.split(",") if d.strip()] if args.database else []
        cfg = JobConfig(
            name=args.name,
            id=job_id,
            description=args.description,
            file=_dbs[0] if _dbs else None,
            source=JobSource(
                type=args.source_type,
                server=args.server,
                databases=_dbs or None,
                script=args.script,
            ),
            process=JobProcess(git_export=git_export),
            triggers=triggers or [JobTrigger(type="manual")],
            webhook_token=token,
        )

        errors = validate_job(cfg)
        if errors:
            print("Validation errors:")
            for e in errors:
                print(f"  - {e}")
            return 1

        try:
            save_job(cfg)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        from corpusfm.server.jobs.store import delete_job, set_job_credential
        try:
            set_job_credential(job_id, account, password)
        except Exception as exc:
            # All-or-nothing, for the same reason as the browser create: the record must exist
            # before a credential can attach to it, and reporting "created but has no credential"
            # as a normal error path is how the invariant gets violated in practice.
            try:
                delete_job(job_id)
                print(f"Error: the credential was not stored ({exc}); the job was not created.",
                      file=sys.stderr)
            except Exception:
                print(f"Error: the credential was not stored ({exc}), and the partially created "
                      f"job {job_id} could not be removed. Delete it and try again.",
                      file=sys.stderr)
            return 1

        print(f"Job '{args.name}' created.")
        print(f"  id: {job_id}")          # the address every other verb takes
        if token:
            from corpusfm.server.jobs.webhook import webhook_url, DEFAULT_PORT
            print(f"Webhook URL: {webhook_url(job_id, token, port=DEFAULT_PORT)}")
        return 0

    return 0
