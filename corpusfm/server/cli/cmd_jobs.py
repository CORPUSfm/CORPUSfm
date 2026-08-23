"""CLI: corpusfm jobs list|create|validate|run|delete|history

Manage automation jobs from the command line.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "jobs",
        help="Manage automation jobs",
        description="Create, list, validate, run, and delete corpusfm automation jobs.",
    )
    sub = p.add_subparsers(dest="jobs_cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List all configured jobs")
    p_list.add_argument("--jobs-dir", default=None)

    # validate
    p_val = sub.add_parser("validate", help="Validate a job's configuration")
    p_val.add_argument("name", help="Job name")
    p_val.add_argument("--jobs-dir", default=None)

    # run
    p_run = sub.add_parser("run", help="Run a job immediately")
    p_run.add_argument("name", help="Job name")
    p_run.add_argument("--jobs-dir", default=None)
    p_run.add_argument("--archive-dir", default=None)
    p_run.add_argument("--history-dir", default=None)
    p_run.add_argument("--trigger", default="manual", help="Trigger label (default: manual)")

    # delete
    p_del = sub.add_parser("delete", help="Delete a job")
    p_del.add_argument("name", help="Job name")
    p_del.add_argument("--jobs-dir", default=None)
    p_del.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    # history
    p_hist = sub.add_parser("history", help="Show run history for a job")
    p_hist.add_argument("name", help="Job name")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.add_argument("--history-dir", default=None)

    # create (guided)
    p_create = sub.add_parser("create", help="Create a new job interactively (YAML output)")
    p_create.add_argument("name", help="Job name (alphanumeric + underscore/hyphen)")
    p_create.add_argument("--source-type", default="local_file",
                          choices=["local_file", "fms_local", "fms_save_to_documents", "fms_push"])
    p_create.add_argument("--path", default=None, help="Source file path (local_file)")
    p_create.add_argument("--server", default=None, help="FMS server URL (fms_* types)")
    p_create.add_argument("--database", default=None,
                          help="FM database name(s), comma-separated (fms_* types)")
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
    p_create.add_argument("--jobs-dir", default=None)

    p.set_defaults(func=run)


def _resolve_dirs(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    from corpusfm.server.jobs.store import default_jobs_dir, default_history_dir
    from corpusfm.storage.local import default_archive_dir

    jobs_dir = Path(args.jobs_dir) if getattr(args, "jobs_dir", None) else default_jobs_dir()
    archive_dir = Path(args.archive_dir) if getattr(args, "archive_dir", None) else default_archive_dir()
    history_dir = Path(args.history_dir) if getattr(args, "history_dir", None) else default_history_dir()
    return jobs_dir, archive_dir, history_dir


def run(args: argparse.Namespace) -> int:
    from corpusfm.server.jobs import (
        list_jobs, load_job, validate_job, delete_job,
        list_runs_for, save_job,
        JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger, generate_token,
    )

    jobs_dir, archive_dir, history_dir = _resolve_dirs(args)

    # ── list ──────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "list":
        all_jobs = list_jobs(jobs_dir)
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
                    s = read_state(cfg.name, jobs_dir)
                    if s.last_status:
                        ts = (s.last_run_ts or "")[:19].replace("T", " ")
                        state_desc = f"  last: {ts} {s.last_status}"
                except Exception:
                    pass
                print(f"  {cfg.name}  [{cfg.source.type}]  triggers: {triggers}{state_desc}")
        return 0

    # ── validate ──────────────────────────────────────────────────────────────
    if args.jobs_cmd == "validate":
        try:
            cfg = load_job(args.name, jobs_dir)
        except (KeyError, FileNotFoundError):
            print(f"Error: job '{args.name}' not found in {jobs_dir}", file=sys.stderr)
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
        print(f"Job '{args.name}' is valid.")
        return 0

    # ── run ───────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "run":
        from corpusfm.server.jobs.runner import run_job
        try:
            print(f"Running job '{args.name}'…")
            run_record = run_job(
                job_name=args.name,
                jobs_dir=jobs_dir,
                archive_dir=archive_dir,
                history_dir=history_dir,
                trigger=args.trigger,
            )
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        if run_record.status == "ok":
            dur = f"{run_record.duration_s:.1f}s" if run_record.duration_s else "?"
            print(f"OK  —  {dur}  —  {run_record.archive_path}")
            if run_record.git_commits:
                for c in run_record.git_commits:
                    print(f"  git: {c}")
        else:
            print(f"FAILED: {run_record.error}", file=sys.stderr)
            return 1
        return 0

    # ── delete ────────────────────────────────────────────────────────────────
    if args.jobs_cmd == "delete":
        if not getattr(args, "yes", False):
            confirm = input(f"Delete job '{args.name}'? [y/N] ").strip().lower()
            if confirm != "y":
                print("Cancelled.")
                return 0
        deleted = delete_job(args.name, jobs_dir)
        if deleted:
            print(f"Deleted job '{args.name}'.")
        else:
            print(f"Job '{args.name}' not found.", file=sys.stderr)
            return 1
        return 0

    # ── history ───────────────────────────────────────────────────────────────
    if args.jobs_cmd == "history":
        from corpusfm.storage import get_backend
        _job_uuid = ""
        try:
            _job_uuid = getattr(load_job(args.name, jobs_dir), "id", "") or ""
        except Exception:
            pass
        runs = list_runs_for(args.name, history_dir, limit=args.limit,
                             backend=get_backend(), job_uuid=_job_uuid)
        if not runs:
            print(f"No run history for job '{args.name}'.")
            return 0
        print(f"Run history for '{args.name}' (newest first):")
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

        cfg = JobConfig(
            name=args.name,
            description=args.description,
            source=JobSource(
                type=args.source_type,
                path=args.path,
                server=args.server,
                databases=[d.strip() for d in args.database.split(",") if d.strip()] if args.database else None,
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
            save_job(cfg, jobs_dir)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print(f"Job '{args.name}' created in {jobs_dir}")
        if token:
            from corpusfm.server.jobs.webhook import webhook_url, DEFAULT_PORT
            print(f"Webhook URL: {webhook_url(args.name, token, port=DEFAULT_PORT)}")
        return 0

    return 0
