"""Job scheduler for server deployment mode — one observation per server-local minute.

Runs as a standalone background process separate from the FastAPI web process
(the corpusfm-scheduler service). Shares state with the web process through the
storage backend (FM OData in production) plus the local jobs/history dirs.

Usage:
    python -m corpusfm.server.scheduler [options]

Options:
    --jobs-dir PATH          directory containing job YAML files (default: project_root/jobs/)
    --archive-dir PATH       XML archive directory (default: project_root/archive/)
    --history-dir PATH       run history directory (default: project_root/history/)

THE OCCURRENCE MODEL (packet 1185, tranche A)
    A schedule is a description of *which minutes match*, evaluated against the server's own local
    wall clock (``core.servertime``). Each cycle asks one question — "does the minute I am standing
    in match?" — and that is the whole contract.

    Three behaviours fall out of it, and each replaces a defect:

    - **No catch-up.** A minute that passed while the scheduler was down is simply gone. The old
      model computed the next fire *after the last run* and asked whether it had passed, so a job
      idle over a weekend fired the instant the process came back — a stampede dressed as recovery.
    - **A never-run job is not due.** Absence of run state used to mean "fire immediately", so
      saving a schedule ran the job. It now waits for its next matching minute; **Run now** is the
      only immediate action (packet 1185 decision 7).
    - **Minute resolution only.** Seconds-level scheduling is retired (decision 5). Schedules are
      the structured ``once``/``weekly`` shapes in ``server.jobs.schedule``; a stored cron
      expression is translated once on load, and an expression the model cannot express stops
      firing and says so rather than being approximated.

    **Not at-most-once, and the packet says so.** An occurrence is enqueued once in normal
    operation. A process restart landing inside a matching minute can observe that minute again,
    and a crash between the enqueue and its durable record can run it twice. HISTORY is best-effort
    instrumentation, not an authority that refuses a second attempt (ruled in packet 1209 — do not
    build a duplicate-refusal check on top of it). ``_fire``'s in-flight guard covers the common
    case; the rest is stated honestly rather than defended against.

Design:
    - One cycle per server-local minute boundary, recomputed from the clock so work duration
      cannot make the observation drift forward through the minute
    - A Job Run is enqueued onto the QUEUE workspace; the pull worker executes it
    - Graceful shutdown on SIGINT / SIGTERM
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from corpusfm.core import servertime
from corpusfm.server.jobs import schedule as _schedule
from corpusfm.server.jobs.store import default_jobs_dir, list_jobs

log = logging.getLogger("corpusfm.scheduler")

STATUS_FILE = "scheduler.json"

# One cycle per server-local minute. Schedules have minute resolution, so a faster cadence buys
# nothing and costs a duplicate: a schedule matches for the WHOLE minute, so a 30-second poll
# matched the same minute twice and fired twice. Monitoring reads this back out of the status file
# to decide staleness, so the two stay in step by construction.
CYCLE_SECONDS = 60

# Wake a beat past the boundary. A timer that fires a few milliseconds EARLY lands on :59.99x of the
# previous minute, which would observe that minute a second time and skip the one it was aiming at.
_BOUNDARY_GRACE = 0.5

# The longest the loop parks before re-checking the stop flag. Bounds shutdown latency on a platform
# whose signal cannot interrupt a blocked wait — see `_sleep_until_next_cycle`.
_STOP_CHECK_SECONDS = 3.0


def previous_fire(trigger, now: Optional[datetime] = None) -> Optional[datetime]:
    """The most recent instant this trigger's schedule matched, or None.

    Computed against the SERVER-LOCAL clock, because that is the clock the scheduler matches
    against. Reading it against UTC — as the overdue checks did — asks "when would this have fired
    if the box were in London", so on a box seven hours out every daily schedule looked overdue for
    seven hours a day, or looked fine for seven hours after it had genuinely stopped running.
    """
    s = _resolve(trigger)
    return None if s is None else _schedule.previous_match(s, now or servertime.local_now())


def next_fire(trigger, now: Optional[datetime] = None) -> Optional[datetime]:
    """The next instant this trigger's schedule will match, aware and server-local, or None."""
    s = _resolve(trigger)
    if s is None:
        return None
    nxt = _schedule.next_matches(s, now or servertime.local_now(), count=1)
    return nxt[0] if nxt else None


def _resolve(trigger) -> Optional[object]:
    """Accept either a JobTrigger or an already-resolved Schedule, so every caller has one door."""
    if trigger is None:
        return None
    if isinstance(trigger, _schedule.Schedule):
        return trigger
    try:
        return trigger.resolved_schedule()
    except Exception:
        return None


class Scheduler:
    """Fires jobs whose schedule matches the current server-local minute."""

    def __init__(
        self,
        jobs_dir: Path,
        archive_dir: Path,
        history_dir: Path,
        poll_interval: Optional[int] = None,
    ):
        self.jobs_dir = jobs_dir
        self.archive_dir = archive_dir
        self.history_dir = history_dir
        # Accepted, reported, and NOT honoured. Callers (the service unit, the CLI, older configs)
        # still pass it; refusing to start over a retired knob would be a worse trade than saying
        # plainly that the cadence is fixed. Sub-minute polling is not a shipped mode any more —
        # it double-fired, because a match is true for the whole minute.
        if poll_interval is not None and int(poll_interval) != CYCLE_SECONDS:
            log.info("poll interval %ss ignored — the scheduler observes one server-local minute "
                     "per cycle (schedules have minute resolution)", poll_interval)
        self.poll_interval = CYCLE_SECONDS
        self._stop = threading.Event()
        self._last_minute: Optional[datetime] = None
        self._warned_seconds: set[str] = set()
        # One log line per gated stretch, not one per cycle (see `_job_work_permitted`).
        self._version_gate_logged = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Block and run the scheduler loop until stop() is called."""
        info = servertime.clock_info()
        log.info("Scheduler started — one cycle per minute, server clock %s%s",
                 info.label(), " (DST not predicted)" if not info.predicts_dst else "")
        self._write_status("running")

        consecutive_failures = 0
        try:
            while not self._stop.is_set():
                try:
                    self._check_and_fire()
                    consecutive_failures = 0
                except Exception as exc:
                    # A transient backend blip (storage DB down / OData refusing) must NOT kill the
                    # scheduler: an unguarded raise here exits the loop → the process dies → Restart=always
                    # crash-loops it, re-importing the whole dep tree every cycle (a sustained CPU burn
                    # until the backend returns). Log, keep running, and ride it out to the next poll —
                    # self-recovers when storage is back. (Mirrors _check_alerts, already guarded.)
                    # Traceback ONCE (first failure of a run of them); after that a terse one-line per
                    # cycle so a sustained outage doesn't spew a full stack every minute (packet 1067).
                    consecutive_failures += 1
                    if consecutive_failures == 1:
                        log.warning("scheduler cycle failed (backend unavailable?) — backing off, "
                                    "not stopping", exc_info=True)
                    else:
                        log.info("scheduler still can't reach storage (cycle %d) — waiting for recovery: %s",
                                 consecutive_failures, exc)
                self._sleep_until_next_cycle()
        finally:
            self._write_status("stopped")
            log.info("Scheduler stopped")

    def stop(self) -> None:
        """Signal the scheduler to stop after the current poll."""
        self._stop.set()

    # ── Internal ───────────────────────────────────────────────────────────────

    def _seconds_to_next_minute(self, now: Optional[datetime] = None) -> float:
        """How long to wait for the next server-local minute boundary.

        Recomputed from the clock every cycle. Waiting a flat 60 seconds *after* the work would add
        each cycle's own duration to every later wake, so the observation walks forward through the
        minute until it steps over one entirely — the drift packet 1185 names explicitly.

        Zero when we are already standing in a minute nobody has looked at. A cycle that runs long
        enough to cross a boundary returns inside an unobserved minute, and waiting for the *next*
        boundary would step straight over it: observe 12:00, work for 60s, and 12:01 is silently
        gone even though we are standing in it. This is not catch-up — the only minute ever observed
        is the current one, and a minute that has genuinely passed stays gone.
        """
        now = now or servertime.local_now()
        if now.replace(second=0, microsecond=0) != self._last_minute:
            return 0.0
        into_minute = now.second + now.microsecond / 1_000_000
        return max(1.0, CYCLE_SECONDS - into_minute + _BOUNDARY_GRACE)

    def _sleep_until_next_cycle(self) -> None:
        """Wait for the next boundary, in slices, so a stop is never more than a slice away.

        `Event.wait(60)` returns the instant `stop()` is called FROM ANOTHER THREAD — but the
        scheduler's stop arrives as a SIGNAL, and a signal handler runs on the main thread, which is
        the one parked in the wait. On Windows the service manager stops the process this way, and
        this cycle went from 30 seconds to 60 when the loop moved to minute boundaries, so a
        shutdown that already printed six "waiting for service to stop" lines could have doubled.

        I could not verify Windows signal delivery into a blocked wait from this machine, so rather
        than reason about it, the wait is sliced: whatever the platform does with the signal, the
        loop re-checks the flag at least every few seconds and the boundary is still recomputed from
        the clock, so nothing drifts.
        """
        deadline = time.monotonic() + self._seconds_to_next_minute()
        while not self._stop.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._stop.wait(timeout=min(_STOP_CHECK_SECONDS, remaining))

    def _job_work_permitted(self) -> bool:
        """May this cycle fire anything? (packet 1372-01)

        The scheduler is a SEPARATE PROCESS from the web service and it never converts. The web
        service owns the `ProjectionVersion` 1 → 2 transition that re-keys every JOB record; until
        that stamp lands, a schedule fired from here would enqueue work against a table this build
        cannot address. So the scheduler reads the stored version and, while it is absent, behind,
        malformed or unreadable, fires nothing and says so.

        WAITING IS THE WHOLE MECHANISM AND IT NEEDS NO NEW ONE: the loop already runs a cycle per
        minute, so returning False here IS the recheck. There is no separate poller, no timeout and
        no give-up — a corpus that never converts simply never fires, which is the honest outcome.

        A failure to READ is treated exactly like "not converted". Firing a job because storage was
        briefly unreachable is the opposite of what an unreadable answer should license.
        """
        from corpusfm.storage import get_backend, projections
        try:
            permitted = projections.conversion_complete(get_backend(self.archive_dir))
        except Exception:
            log.warning("scheduler: could not read the corpus projection version; firing nothing "
                        "this cycle", exc_info=True)
            permitted = False
        if permitted:
            self._version_gate_logged = False
            return True
        if not self._version_gate_logged:
            # ONCE per gated stretch, not once a minute: a corpus that sits unconverted overnight
            # would otherwise write 480 identical lines into the journal, which is how a real signal
            # gets tuned out.
            log.warning("scheduler: this corpus is not at the projection version this build "
                        "requires, so the JOB identity conversion has not completed. No schedule "
                        "will fire until the web service converts and stamps it. Re-checking every "
                        "cycle; nothing is being skipped permanently.")
            self._version_gate_logged = True
        return False

    def _check_and_fire(self) -> None:
        """Observe the current server-local minute; fire every schedule that matches it."""
        now = servertime.local_now()
        minute = now.replace(second=0, microsecond=0)
        # THE GATE SUPPRESSES FIRING AND NOTHING ELSE (packet 1372-01). Status and alerts still run
        # below: a box sitting unconverted is exactly when an operator needs monitoring to keep
        # working, and silencing the alert path would turn one problem into two invisible ones.
        permitted = self._job_work_permitted()
        # An early-firing timer, a manual poke, or a retry after a failed cycle can land twice in
        # one minute. This is loop hygiene, NOT an occurrence authority: a process that restarts
        # inside a matching minute starts with no marker and observes it again (packet 1209).
        #
        # THE MINUTE IS NOT CONSUMED WHILE GATED: `_last_minute` only advances on a cycle that was
        # allowed to fire, so the minute in which the conversion lands is still observed rather than
        # having been marked seen by a cycle that fired nothing.
        if permitted and minute != self._last_minute:
            self._last_minute = minute
            self._fire_matching_schedules(minute)

        # In-flight runs are QUEUE pull records now (packet 086), not scheduler threads.
        try:
            from corpusfm.server.jobs.run_queue import active_runs
            from corpusfm.storage import get_backend
            active = sorted({m.get("job_name", "") for m in active_runs(get_backend(self.archive_dir))
                             if m.get("job_name")})
        except Exception:
            active = []
        self._write_status("running" if permitted else "waiting", active_jobs=active)

        # Evaluate and dispatch alerts (errors here never kill the scheduler)
        self._check_alerts()

    def _check_alerts(self) -> None:
        """Evaluate alert conditions and dispatch new unsuppressed alerts."""
        try:
            from corpusfm.server.monitor.alerts import evaluate_alerts, append_alert
            from corpusfm.server.monitor.notify import dispatch_alert
            from corpusfm.server.monitor.config import load_monitor_config

            config = load_monitor_config()
            new_alerts = evaluate_alerts(
                self.jobs_dir, self.history_dir, self.archive_dir, config
            )
            for alert in new_alerts:
                # Guard EACH alert: append_alert is now an OData write (packet 1019), far more
                # failure-prone than the retired jsonl append — an unguarded raise here would skip
                # every REMAINING alert's record AND notification for the cycle (packet 1000 re-sweep).
                try:
                    append_alert(alert)                 # DB-backed history (packet 1019)
                    dispatch_alert(alert, config)
                except Exception as exc:
                    log.warning("alert record/dispatch failed for one alert (continuing): %s", exc)
        except Exception as exc:
            log.debug("Alert check error (non-fatal): %s", exc)

    def _fire_matching_schedules(self, minute: datetime) -> None:
        """CARRY THE ENUMERATED CONFIG, do not reload it (packet 1372-02, R4).

        It used to pass `job_cfg.name` to `_fire`, which loaded the job again — by name. That threw
        away the identity it was already holding, and with duplicate names now ordinary it could
        reload a DIFFERENT job than the one whose schedule matched.
        """
        for job_cfg, _load_error in list_jobs(self.jobs_dir):
            if job_cfg is None:
                continue
            for trigger in (t for t in (job_cfg.triggers or []) if t.type == "schedule"):
                if self._matches(job_cfg.name, trigger, minute):
                    self._fire(job_cfg)
                    break  # one fire per job per minute, however many triggers agree

    def _matches(self, job_name: str, trigger, minute: datetime) -> bool:
        """Does this schedule describe the server-local minute we are standing in?

        The whole due-decision, and it deliberately reads no run state. State-based due-ness is
        what produced both defects packet 1185 names: a job with no state was "due" the moment it
        was saved, and a job idle through an outage was "due" the moment the process came back.
        """
        try:
            sched = trigger.resolved_schedule()
        except Exception as exc:
            log.warning("Job '%s': unreadable schedule (%s)", job_name, exc)
            return False
        if sched is None:
            return False
        if sched.needs_update:
            if job_name not in self._warned_seconds:
                self._warned_seconds.add(job_name)
                log.warning("Job '%s' will not fire: its old schedule '%s' cannot be expressed in "
                            "the current model — open the job and set a new one",
                            job_name, sched.legacy_cron)
            return False
        return _schedule.matches(sched, minute)

    def _fire(self, job) -> None:
        """Enqueue a Job Run onto the QUEUE workspace (packet 086 — the pull worker executes it, so
        the scheduler no longer spawns a run thread). Cron-overrun guard: skip this fire if the job
        already has an in-flight run (a still-running schedule must not stack). A crashed run's record
        ages out (staleness), so it can't block fires forever; fail-open (enqueue anyway) on a read
        error — better a rare double-run than a silently never-fired schedule. A MANUAL run bypasses
        this guard (it's the web/MCP path, which always enqueues)."""
        from corpusfm.storage import get_backend
        backend = get_backend(self.archive_dir)
        job_uuid = getattr(job, "id", "") or ""
        if not job_uuid:
            # Unreachable after the 1372-01 conversion, which gives every job a sound id, and worth
            # refusing rather than enqueueing an unattributable run that would block the next start.
            log.error("Job %r carries no id and will not be fired", getattr(job, "name", "?"))
            return
        try:
            from corpusfm.server import queue_handlers
            from corpusfm.server.jobs.run_queue import has_active_run_for_job
            # Cron-overrun guard: skip if this job already has a non-stale in-flight run (indexed read).
            if has_active_run_for_job(backend, job_uuid):
                log.info("Job '%s' (%s) already running — skipping fire", job.name, job_uuid)
                return
            queue_handlers.enqueue_job_run(
                backend, job_name=job.name, job_uuid=job_uuid,
                file_name=getattr(job, "file", "") or "", trigger="schedule")
            log.info("Firing job: %s (%s)", job.name, job_uuid)
        except Exception as exc:
            # Fail-open would double-run; but an enqueue error means we couldn't fire at all —
            # log and move on (the schedule re-fires next tick).
            log.error("Job '%s' fire failed: %s", getattr(job, "name", "?"), exc)

    def _write_status(self, status: str, active_jobs: Optional[list] = None) -> None:
        status_path = self.jobs_dir / STATUS_FILE
        try:
            status_path.write_text(
                json.dumps(
                    {
                        "status": status,
                        "ts": datetime.now(tz=timezone.utc).isoformat(),
                        "poll_interval": self.poll_interval,
                        "active_jobs": active_jobs or [],
                    },
                    indent=2,
                )
            )
        except Exception:
            pass  # status writes are best-effort


# ── Status helpers (used by UI) ───────────────────────────────────────────────

def read_scheduler_status(jobs_dir: Path) -> dict:
    """Read scheduler.json; returns empty dict if not present or invalid."""
    status_path = jobs_dir / STATUS_FILE
    try:
        return json.loads(status_path.read_text())
    except Exception:
        return {}


#: Status words a LIVE scheduler process writes. `waiting` (packet 1372-01) means the process is
#: alive and cycling but firing nothing, because the corpus has not reached the projection version
#: this build requires. It is deliberately a distinct word rather than a flag on `running`, and both
#: consumers were updated to say so: `corpusfm scheduler status` prints "waiting" with the reason,
#: and the Recent-activity pop-over says "Scheduler waiting — jobs paused". Writing the word without
#: teaching the readers it would have left every surface reporting "running" while nothing could
#: fire, which is the comfortable answer rather than the true one.
_LIVE_STATUSES = ("running", "waiting")


def scheduler_is_running(jobs_dir: Path) -> bool:
    """True if a scheduler PROCESS has written a recent live status.

    Liveness, not productivity — the callers use it to decide whether a scheduler exists at all (the
    monitor raises a "scheduler down" alert from it). A gated scheduler is up: reporting it as down
    would raise the wrong alarm and, worse, would make the real problem look like a dead process.
    """
    info = read_scheduler_status(jobs_dir)
    if info.get("status") not in _LIVE_STATUSES:
        return False
    ts_str = info.get("ts")
    if not ts_str:
        return False
    try:
        ts = datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        # Stale if last write is more than 3× the cycle interval ago. The interval is read back out
        # of the file the running scheduler wrote, so a box still running an older build is judged
        # by ITS cadence rather than this one.
        poll = int(info.get("poll_interval", CYCLE_SECONDS))
        return (now - ts).total_seconds() < poll * 3
    except Exception:
        return False


# ── CLI entry point ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m corpusfm.server.scheduler",
        description="corpusfm scheduler — runs jobs on the server's own local clock, checking once a minute",
    )
    p.add_argument("--jobs-dir", default=None, help="Job YAML directory (default: project_root/jobs/)")
    p.add_argument("--archive-dir", default=None, help="XML archive directory")
    p.add_argument("--history-dir", default=None, help="Run history directory")
    # Still parsed so an installed service unit or an operator's muscle memory does not fail to
    # start; the value is reported as ignored rather than silently dropped.
    p.add_argument("--poll-interval", type=int, default=None,
                   help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return p


def main(argv=None) -> None:
    args = _build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Resolve directories
    from corpusfm.server.jobs.store import default_history_dir

    jobs_dir = Path(args.jobs_dir) if args.jobs_dir else default_jobs_dir()
    archive_dir = Path(args.archive_dir) if args.archive_dir else jobs_dir.parent / "archive"
    history_dir = Path(args.history_dir) if args.history_dir else default_history_dir()

    for d in (jobs_dir, archive_dir, history_dir):
        d.mkdir(parents=True, exist_ok=True)

    # No startup sweep (packet 086): a Job Run is a durable [pull] QUEUE record — a run interrupted by
    # a restart is NOT orphaned, it's re-run by the pull worker (existence = not-done). Failed runs
    # park durably for a human Restart/Delete. clear_all_runs is gone.

    scheduler = Scheduler(
        jobs_dir=jobs_dir,
        archive_dir=archive_dir,
        history_dir=history_dir,
        poll_interval=args.poll_interval,
    )

    def _handle_signal(signum, frame):
        log.info("Received signal %d — stopping scheduler", signum)
        scheduler.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    scheduler.run()
    sys.exit(0)


if __name__ == "__main__":
    main()
