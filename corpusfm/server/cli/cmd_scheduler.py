"""CLI: corpusfm scheduler start|status

Start the cron scheduler or query its status.
"""

from __future__ import annotations

import argparse
import sys


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "scheduler",
        help="Start the job scheduler or check its status",
        description=(
            "The scheduler is a separate long-running process that fires jobs "
            "whose schedule matches the current minute on the server's own clock. "
            "Both the scheduler and the web UI communicate only through the shared filesystem."
        ),
    )
    sub = p.add_subparsers(dest="sched_cmd", required=True)

    # start
    p_start = sub.add_parser("start", help="Start the scheduler (blocks until stopped)")
    p_start.add_argument("--jobs-dir", default=None)
    p_start.add_argument("--archive-dir", default=None)
    p_start.add_argument("--history-dir", default=None)
    # Retired (packet 1185): schedules have minute resolution and the scheduler observes one
    # server-local minute per cycle. Still parsed so an existing service unit keeps starting.
    p_start.add_argument("--poll-interval", type=int, default=None, help=argparse.SUPPRESS)
    p_start.add_argument("-v", "--verbose", action="store_true")

    # status
    p_status = sub.add_parser("status", help="Show scheduler status (from status file)")
    p_status.add_argument("--jobs-dir", default=None)

    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.server.jobs.store import default_jobs_dir, default_history_dir
    from corpusfm.storage.local import default_archive_dir
    from pathlib import Path

    # ── status ────────────────────────────────────────────────────────────────
    if args.sched_cmd == "status":
        jobs_dir = Path(args.jobs_dir) if args.jobs_dir else default_jobs_dir()
        from corpusfm.server.scheduler import read_scheduler_status, scheduler_is_running
        info = read_scheduler_status(jobs_dir)
        if not info:
            print("No scheduler status file found — scheduler may not have run yet.")
            return 1
        running = scheduler_is_running(jobs_dir)
        ts = info.get("ts", "")[:19].replace("T", " ")
        status = info.get("status", "?")
        poll = info.get("poll_interval", "?")
        active = info.get("active_jobs") or []
        from corpusfm.core import servertime
        clock = servertime.clock_info()
        # WAITING IS ITS OWN ANSWER (packet 1372-01). `running` here means the process is alive, and
        # a gated scheduler IS alive — but printing "running" for a process that will fire nothing is
        # the comfortable answer, not the true one. The word the process wrote is shown on this line
        # rather than demoted to `Status file:` below.
        if not running:
            print("Status:        stopped (stale)")
        elif status == "waiting":
            print("Status:        waiting — this corpus is not at the projection version this "
                  "build requires, so no schedule will fire")
        else:
            print("Status:        running")
        print(f"Last update:   {ts} UTC")
        print(f"Status file:   {status}")
        print(f"Check every:   {poll}s")
        # Schedules are matched against THIS clock, so `status` is where an operator finds out what
        # it is — including when it is the honest UTC fallback rather than a real local zone.
        print(f"Server clock:  {servertime.local_now().strftime('%Y-%m-%d %H:%M')} {clock.label()}")
        if active:
            print(f"Active jobs:   {', '.join(active)}")
        return 0 if running else 1

    # ── start ─────────────────────────────────────────────────────────────────
    if args.sched_cmd == "start":
        import logging
        level = logging.DEBUG if args.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

        jobs_dir = Path(args.jobs_dir) if args.jobs_dir else default_jobs_dir()
        archive_dir = Path(args.archive_dir) if args.archive_dir else default_archive_dir()
        history_dir = Path(args.history_dir) if args.history_dir else default_history_dir()

        for d in (jobs_dir, archive_dir, history_dir):
            d.mkdir(parents=True, exist_ok=True)

        from corpusfm.server.scheduler import Scheduler
        import signal

        scheduler = Scheduler(
            jobs_dir=jobs_dir,
            archive_dir=archive_dir,
            history_dir=history_dir,
            poll_interval=args.poll_interval,
        )

        def _handle(signum, frame):
            scheduler.stop()

        signal.signal(signal.SIGINT, _handle)
        signal.signal(signal.SIGTERM, _handle)

        scheduler.run()
        return 0

    return 0
