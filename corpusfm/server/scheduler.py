"""Job scheduling — a WEB-OWNED background component, one observation per server-local minute.

**It is no longer a separate process** (packet 1361-01, availability correction round 2). The
standalone `corpusfm-scheduler` service was a second process with its own unsupervised in-memory
readiness gate: while the web process was PAUSED it went on reading the JOB table, reading the
projection version, writing HISTORY, evaluating ALERTs and enqueueing QUEUE work against a FileMaker
the product had just declared unreadable. That is the exact state the two-state ruling forbids —

    CORPUSfm is either database-ready or paused. There is no partially operational state.

— and a second process cannot honour a process-wide gate. So the clock moved into the one process
that owns readiness. It starts from the SAME resume path that starts the catalog synchronizer and
the queue workers, it consults the SAME `availability` gate before every cycle, and it stops with
the web process.

**The occurrence model is unchanged** (packet 1185, tranche A), and none of it is negotiable here:

    A schedule is a description of *which minutes match*, evaluated against the server's own local
    wall clock (``core.servertime``). Each cycle asks one question — "does the minute I am standing
    in match?" — and that is the whole contract.

    - **No catch-up.** A minute that passed while the process was down — or PAUSED — is simply gone.
      The only minute ever observed is the current one. Pausing therefore needs no special rule: a
      cycle that returns early has not consumed a minute and has not deferred one.
    - **A never-run job is not due.** Absence of run state is not a reason to fire. **Run now** is
      the only immediate action (packet 1185 decision 7).
    - **Minute resolution only.** Seconds-level scheduling is retired (decision 5). A stored cron
      expression is translated once on load; one the model cannot express stops firing and says so.

    **Not at-most-once, and the packet says so.** An occurrence is enqueued once in normal
    operation. A restart landing inside a matching minute can observe that minute again, and a crash
    between the enqueue and its durable record can run it twice. HISTORY is best-effort
    instrumentation, not an authority that refuses a second attempt (ruled in packet 1209 — do not
    build a duplicate-refusal check on top of it). ``_fire``'s in-flight guard covers the common
    case; the rest is stated honestly rather than defended against.

**What the readiness gate changes, precisely.** Before every cycle the component asks
``availability.is_open()``. While it is closed the cycle performs NO JOB, HISTORY, QUEUE, ALERT or
any other FileMaker operation and enqueues nothing — it records that it is paused in memory and
parks until the next boundary. It creates no recovery mechanism of its own: the availability
coordinator is the only component that contacts FileMaker while paused, and this one simply waits
for it to succeed.

**It asks no projection-version question of its own** (packet 1361-01, round 3). That check was a
per-cycle FileMaker read asking whether this build may address this corpus at all — a STARTUP
question whose answer cannot change without the conversion only startup performs. It is asked once,
by :mod:`corpusfm.server.startup`, before this component is started; a clock that is running is
therefore running on a corpus this build may address, and the `waiting` status it used to report is
gone with it.

**Status is in MEMORY, not a file.** The old `scheduler.json` liveness file existed so another
process could tell whether the scheduler was alive. There is no other process now, so the surface
that reports it lives where the answer is exact — and reading it touches no database, which is what
lets an operator ask while the box is paused.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from corpusfm.core import servertime
from corpusfm.server.jobs import schedule as _schedule
from corpusfm.server.jobs.store import list_jobs

log = logging.getLogger("corpusfm.scheduler")

# `STATUS_FILE` and `state_dir()` are GONE (packet 1361-01, round 2). They existed so a SEPARATE
# process could publish its liveness for the web process to read, and staleness stood in for "is it
# alive". There is no separate process, so the answer is exact and lives in memory — and asking for
# it touches neither the filesystem nor FileMaker, which is what makes it answerable while paused.

# One cycle per server-local minute. Schedules have minute resolution, so a faster cadence buys
# nothing and costs a duplicate: a schedule matches for the WHOLE minute, so a 30-second poll
# matched the same minute twice and fired twice. It is fixed, and there is no longer any surface
# through which an operator can ask for a different one.
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

    def __init__(self):
        # NO CONSTRUCTOR ARGUMENTS AT ALL (packet 1361-01, round 2). `archive_dir`, `poll_interval`
        # and `status_dir` were process-only knobs: a standalone service selected its own archive,
        # asked for its own cadence and published its own liveness file. A web-owned component reads
        # the one backend the process already composed, runs the one fixed cadence, and reports its
        # state from memory — so there is nothing left to configure and nothing left to disagree.
        self.poll_interval = CYCLE_SECONDS
        self._stop = threading.Event()
        self._last_minute: Optional[datetime] = None
        self._warned_seconds: set[str] = set()
        # One log line per paused stretch, not one per cycle (see `_check_and_fire`).
        self._paused_logged = False
        # ── the in-memory status surface ────────────────────────────────────────
        self._status_lock = threading.Lock()
        # starting → running (firing) | paused (CORPUSfm cannot read the database) → stopped.
        # `starting` exists so a component whose thread has been created but has not yet reached its
        # first cycle never reports `stopped`, which would read as "the clock died" during the start
        # race. There is no `waiting` state: the projection-version question is answered once by the
        # startup authority, before this component is started at all (packet 1361-01, round 3).
        self._state = "starting"
        self._last_cycle_utc = ""
        self._active_jobs: list = []
        self._cycles = 0

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Block and run the scheduler loop until stop() is called.

        Runs on the web process's own background thread (see :func:`ensure_started`); nothing calls
        this from a `__main__`."""
        info = servertime.clock_info()
        log.info("Scheduler started — one cycle per minute, server clock %s%s",
                 info.label(), " (DST not predicted)" if not info.predicts_dst else "")
        # The status is NOT set to "running" here. The first cycle decides what this component is
        # actually doing — and on a paused box the honest word is `paused`, not a "running" that the
        # next tick corrects. It stays `starting` until then (set in `__init__`).

        consecutive_failures = 0
        try:
            while not self._stop.is_set():
                try:
                    self._check_and_fire()
                    consecutive_failures = 0
                except Exception as exc:
                    # A transient backend blip must NOT kill the clock: an unguarded raise here exits
                    # the loop and the component is simply gone for the life of the process, with
                    # only the `scheduler_stopped` alert to say so. Log, keep running, ride it out.
                    # (When the blip is a genuine availability failure the readiness gate has already
                    # closed and the next cycle returns at the gate — this guard is for everything
                    # else. Mirrors _check_alerts, already guarded.)
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
            self._set_status("stopped")
            log.info("Scheduler stopped")

    def stop(self) -> None:
        """Signal the scheduler to stop after the current poll."""
        self._stop.set()

    # ── the in-memory status surface ───────────────────────────────────────────

    def _set_status(self, state: str, active_jobs: Optional[list] = None) -> None:
        """Record what this component is doing. MEMORY ONLY — no file, no database.

        That is what lets an operator ask while the box is paused: the honest answer to "is the
        scheduler alive and is it firing" must not itself require the thing that is unavailable."""
        with self._status_lock:
            self._state = state
            self._last_cycle_utc = datetime.now(tz=timezone.utc).isoformat()
            self._cycles += 1
            if active_jobs is not None:
                self._active_jobs = list(active_jobs)

    def status(self) -> dict:
        """This component's own state. Costs one lock and reads nothing."""
        with self._status_lock:
            return {"status": self._state,
                    "ts": self._last_cycle_utc,
                    "poll_interval": self.poll_interval,
                    "cycles": self._cycles,
                    "active_jobs": list(self._active_jobs)}

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

    def _check_and_fire(self) -> None:
        """Observe the current server-local minute; fire every schedule that matches it.

        **THE READINESS GATE IS THE FIRST THING THIS DOES, before any database operation at all**
        (packet 1361-01, round 2). A paused CORPUSfm performs no JOB, HISTORY, QUEUE or ALERT read
        or write, and enqueues nothing — so the check cannot live inside the schedule enumeration,
        which is itself a FileMaker read, nor inside `_fire`, which is already past it.

        **A PAUSED CYCLE STILL OBSERVES ITS MINUTE.** This is the whole of the hot-loop correction
        (packet 1361-01). The paused branch used to return WITHOUT advancing `_last_minute`, and
        `_seconds_to_next_minute` answers `0.0` for a minute nobody has looked at — so every paused
        cycle asked for a zero-length wait and the loop spun. Measured on u-test-private,
        2026-09-03: one thread at 100.07% of a core for as long as the database stayed closed, with
        no FileMaker traffic at all, because the spin never got past this gate.

        Recording the minute is a CLOCK read and nothing else — no JOB, HISTORY, QUEUE or ALERT
        access, no enqueue, no schedule evaluation — so the paused contract is untouched.

        It also keeps "a minute missed while paused is not caught up" true, and makes it stronger
        rather than weaker. The minute is CONSUMED here, so a recovery landing inside that same
        minute finds `minute == self._last_minute` and does not fire it; the following minute is a
        new observation and fires normally when eligible. The old comment claimed the no-catch-up
        rule came from NOT advancing the marker. That reasoning was wrong on both halves: it is the
        forward-only observation that provides the rule, and not advancing bought nothing except
        the spin.
        """
        from corpusfm.server import availability
        if not availability.is_open():
            if not self._paused_logged:
                # ONCE per paused stretch. An outage lasting a shift would otherwise write one line
                # a minute into the journal, which is how a real signal gets tuned out.
                log.info("scheduler: CORPUSfm is paused — no schedule is evaluated and nothing is "
                         "enqueued until one complete database validation succeeds. Missed minutes "
                         "are not caught up.")
                self._paused_logged = True
            self._set_status("paused")
            # OBSERVE, DO NOT FIRE. Consuming the minute is what turns the next
            # `_seconds_to_next_minute` into a real boundary wait instead of zero.
            self._last_minute = servertime.local_now().replace(second=0, microsecond=0)
            return
        self._paused_logged = False
        now = servertime.local_now()
        minute = now.replace(second=0, microsecond=0)
        # THERE IS NO PER-CYCLE PROJECTION-VERSION READ ANY MORE (packet 1361-01, round 3). The
        # `ProjectionVersion` / JOB-identity conversion question is asked ONCE, by the startup
        # authority, before this component or a queue worker exists — so a clock that is running at
        # all is running on a corpus this build may address. The old per-cycle read was a FileMaker
        # operation on a repeating clock asking a question whose answer cannot change without the
        # conversion that only startup performs, and its `waiting` state went with it.
        #
        # An early-firing timer, a manual poke, or a retry after a failed cycle can land twice in
        # one minute. This is loop hygiene, NOT an occurrence authority: a process that restarts
        # inside a matching minute starts with no marker and observes it again (packet 1209).
        if minute != self._last_minute:
            self._last_minute = minute
            self._fire_matching_schedules(minute)

        # In-flight runs are QUEUE pull records now (packet 086), not scheduler threads.
        try:
            from corpusfm.server.jobs.run_queue import active_runs
            from corpusfm.storage import get_backend
            active = sorted({m.get("job_name", "") for m in active_runs(get_backend())
                             if m.get("job_name")})
        except Exception:
            active = []
        self._set_status("running", active_jobs=active)

        # Evaluate and dispatch alerts (errors here never kill the scheduler)
        self._check_alerts()

    def _check_alerts(self) -> None:
        """Evaluate alert conditions and dispatch new unsuppressed alerts."""
        try:
            from corpusfm.server.monitor.alerts import evaluate_alerts, append_alert
            from corpusfm.server.monitor.notify import dispatch_alert
            from corpusfm.server.monitor.config import load_monitor_config
            from corpusfm.storage import get_backend

            config = load_monitor_config()
            new_alerts = evaluate_alerts(get_backend().archive_dir, config)
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
        for job_cfg, _load_error in list_jobs():
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
        backend = get_backend()
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

# ── The one web-owned component, and its status surface ───────────────────────

_component: Optional[Scheduler] = None
_thread: Optional[threading.Thread] = None
_ever_started = False
_component_lock = threading.Lock()


def ensure_started() -> bool:
    """Start the scheduler clock on this process's own thread. Returns True on the START edge only.

    **Called from the readiness RESUME path and from nowhere else** — the same callback that starts
    the catalog synchronizer and the queue workers, on every closed→open edge. It is idempotent by
    the same discipline `catalog.start_synchronizer` uses: the whole start happens under ONE lock
    acquisition, so two concurrent resumes cannot produce two clocks, and repeated pause/recovery
    cycles cannot accumulate threads.

    The component is NOT stopped when readiness closes. It stays alive and no-ops its cycles, which
    is what "sleeps until readiness reopens" means here — one loop, one clock, and no second recovery
    mechanism competing with the availability coordinator for the database.
    """
    global _component, _thread, _ever_started
    with _component_lock:
        if _thread is not None and _thread.is_alive():
            return False
        _component = Scheduler()
        t = threading.Thread(target=_component.run, name="cfm-scheduler", daemon=True)
        _thread = t
        _ever_started = True
        t.start()
        return True


def stop_scheduler(timeout: float = 5.0) -> None:
    """Stop the component and join it. Web shutdown, and the test seam."""
    global _component, _thread
    with _component_lock:
        component, thread = _component, _thread
        _component = None
        _thread = None
    if component is not None:
        component.stop()
    if thread is not None:
        thread.join(timeout=timeout)


def reset_for_testing() -> None:
    """Stop the component AND forget that one ever ran (test seam / process shutdown)."""
    global _ever_started
    stop_scheduler()
    with _component_lock:
        _ever_started = False


def scheduler_is_running() -> bool:
    """Is the web-owned scheduler clock alive in THIS process?

    Liveness, not productivity — the callers use it to decide whether a scheduler exists at all (the
    monitor raises a "scheduler down" alert from it). A PAUSED scheduler is alive: reporting it as
    down would raise the wrong alarm and, worse, would make the real problem look like a dead clock.

    It used to be a staleness judgement over a file another process wrote. There is no other process,
    so this is now the exact answer, and it reads nothing.
    """
    with _component_lock:
        return bool(_thread is not None and _thread.is_alive())


def scheduler_ever_started() -> bool:
    """Has this process ever started the clock? The in-memory successor to "a status file exists"."""
    with _component_lock:
        return _ever_started


def read_scheduler_status() -> dict:
    """The web-owned scheduler's own state, from memory. Empty when it has never run.

    Keys are the ones the operator surfaces already read (`status` / `ts` / `poll_interval` /
    `active_jobs`), so the Recent-activity pop-over and the monitor needed no change. `status` is
    one of `running` (firing), `paused` (alive, but CORPUSfm cannot read the database) or
    `stopped`.

    **It reads no file and no database**, which is the point: the honest answer to "is the scheduler
    alive" must not itself require the thing that may be unavailable.
    """
    with _component_lock:
        component = _component
    return component.status() if component is not None else {}


# ── There is no standalone scheduler process ──────────────────────────────────
#
# `main()`, `_build_parser()`, the argparse surface and the signal handling are DELETED (packet
# 1361-01, round 2). They started a second process with its own unsupervised readiness state, which
# is the defect this round exists to remove.
#
# What remains is a REFUSAL, not an entry point. It is here rather than absent for one reason: an
# obsolete `corpusfm-scheduler` unit still runs `python -m corpusfm.server.scheduler`, and a module
# with no `__main__` would import cleanly, exit 0, and be restarted forever by `Restart=always` —
# a silent crash-loop. Exiting non-zero with the reason is the loud outcome an operator can act on.
#
# ⚠ OWED, DELIBERATELY NOT DONE HERE: the private installer repository must remove or rewrite the
# `corpusfm-scheduler` service unit. That change is not authorized in this round and this repository
# does not touch the installer.

_STANDALONE_REFUSAL = (
    "corpusfm.server.scheduler is no longer a runnable process.\n"
    "\n"
    "Scheduling is part of the CORPUSfm web service now: it starts with the catalog synchronizer "
    "and the queue workers when the database becomes readable, and it stops when the web service "
    "stops. A second process could not honour the process-wide database-readiness gate — it kept "
    "reading and writing FileMaker while CORPUSfm was paused.\n"
    "\n"
    "Stop and remove the corpusfm-scheduler service. Nothing else is needed: the web service "
    "already schedules.\n"
)


def main(argv=None) -> int:                       # pragma: no cover - exercised by its own test
    """Refuse, loudly and non-zero. This is not an entry point; it is the absence of one."""
    import sys
    sys.stderr.write(_STANDALONE_REFUSAL)
    return 2


if __name__ == "__main__":                        # pragma: no cover - process entry
    import sys as _sys
    _sys.exit(main())
