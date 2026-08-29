"""Per-type FIFO queue workers (packet 086 / Ruling B — brick 3, the framework).

One worker per step ``Type`` drains its type(s) FIFO from the QUEUE workspace: claim the oldest
non-failed record (``QueueRepo.next_for``), run the registered handler for its ``Type``, then
``advance_or_delete`` on success or ``set_failed`` on failure — **try once, move on** (no auto-retry).
Workers are **N daemon threads in the ONE uvicorn process** (single-worker is load-bearing); cross-type
isolation means a slow enrichment never head-of-line-blocks a quick land. **``summarize`` and ``index``
are SEPARATE workers** (packet 1170) — a slow summary (LLM, up to an hour) must never head-of-line-block
the fast index step, so search freshness is decoupled from the summary lane.

The step HANDLERS live in the producers (brick 4) and ``register()`` here; this module is the
framework only — claim, dispatch, transition, hand-off wake. A handler returns ``StepResult(ok,
outcome)``; a raised exception is caught and treated as a failure (try-once). A step with no
registered handler parks the record (``set_failed``) rather than spinning.

Inert until ``start_all()`` is called at app boot AND producers have registered handlers (brick 4).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from corpusfm.storage.queue_record import (
    ACQUIRE, GIT_EXPORT, INDEX, INGEST, REINGEST, SUMMARIZE,
)

log = logging.getLogger("corpusfm.queue_workers")

# ── progress-timeout (packet 1003 / concept C) ────────────────────────────────────
# Each in-flight step carries a no-progress DEADLINE that any progress signal pushes forward — so the
# timeout is the MAX GAP between progress ticks, never a total-runtime cap (a legitimately long step
# never trips while it keeps making progress; "enrichment can take a long time"). The watchdog fails +
# reclaims a step that goes silent past its deadline (a hang: no exception, so try-once can't catch it,
# and it stays forever as a non-failed active row that nothing will finish).
# DEFAULT_EXPORT_TIMEOUT_SECS (packet 1142 §H) — the default per-job bound on ONE FileMaker export
# (the acquire step's blocking script call). Raised above the largest observed export (fms-dev
# measured 197–214s to land, most of it export) so growth / a busier FMS / a slower link do not trip a
# healthy run. A job may override it via JobSource.export_timeout_s; the acquire handler passes the
# effective value to the trigger call AND sets the worker's no-progress deadline to it (+ margin), so
# the watchdog is DERIVED from the same bound and can never fire before the call's own limit.
DEFAULT_EXPORT_TIMEOUT_SECS = 600.0
_ACQUIRE_DEADLINE_MARGIN = 120.0     # the watchdog sits this far OUTSIDE the acquire's own bound

_STEP_TIMEOUTS: dict[str, float] = {
    INGEST: 600.0,        # parse + store (mostly atomic; generous)
    SUMMARIZE: 600.0,     # one AI summary call (progress resets per item)
    # The no-progress tick fires once per batch, BEFORE the embedding upsert — so the deadline must
    # exceed a SINGLE batch's worst-case retry envelope, or a legitimately slow embed on a loaded CPU
    # box (exactly the packet-1013 case) trips the watchdog into a hard os._exit. That envelope is
    # 4 attempts × 330s wall-clock + backoff(1.5+3+4.5) ≈ 1329s; 1800s clears it with margin. A
    # genuinely hung embed still fails fast on its own via the per-attempt deadline (packet 1000 re-sweep).
    INDEX: 1800.0,        # one embedding batch incl. its full retry envelope (progress resets per batch)
    # ACQUIRE default = the default export bound + margin. The acquire handler REPLACES this with the
    # job's own bound + margin via set_step_deadline() once it resolves the job, so a job raised to
    # 20 min is not killed by a static 10-min watchdog (packet 1142 §H).
    ACQUIRE: DEFAULT_EXPORT_TIMEOUT_SECS + _ACQUIRE_DEADLINE_MARGIN,
    GIT_EXPORT: 300.0,
    REINGEST: 900.0,      # re-run the ingest pipeline on retained source (parse+mine+render) — atomic
}
_DEFAULT_STEP_TIMEOUT = 600.0

# Maps the running worker onto its own thread so a step handler's progress hook can find it.
_tls = threading.local()


def _timeout_for(step: str) -> float:
    return _STEP_TIMEOUTS.get(step, _DEFAULT_STEP_TIMEOUT)


def _kill_process() -> None:      # pragma: no cover - the real, drastic kill (injected in tests)
    """Hard-exit to reclaim a hung worker thread (a Python thread can't be cleanly killed). systemd
    (Restart=) / WinSW restart the process; the timed-out record is already parked (visible, failed)."""
    import os
    log.error("queue watchdog: hard-exiting to reclaim a hung worker thread")
    os._exit(1)


def note_progress() -> None:
    """A running step calls this (via its handler's progress hook) to push its worker's no-progress
    deadline forward — proof of life. A no-op off a worker thread."""
    w = getattr(_tls, "worker", None)
    if w is not None:
        w.push_deadline()


def set_step_deadline(seconds: float) -> None:
    """A running step sets its OWN no-progress deadline to ``seconds`` from now (packet 1142 §H): the
    acquire handler calls this once it resolves the job's effective export bound, so the watchdog is
    derived from the SAME bound the blocking call uses rather than a static per-type constant — a job
    raised to 20 minutes is not killed by a 10-minute default. A no-op off a worker thread."""
    w = getattr(_tls, "worker", None)
    if w is not None and w.current_id:
        w.current_deadline = time.monotonic() + max(1.0, seconds)


def cancel_requested() -> bool:
    """True if a user asked to cancel the step this worker is running right now — polled by a
    cooperative step (e.g. the indexer, between embedding batches) to bail cleanly. A no-op (False) off
    a worker thread."""
    w = getattr(_tls, "worker", None)
    return bool(w is not None and w._cancel_requested)


def request_cancel(qid: str) -> bool:
    """Flag the RUNNING record ``qid`` for cooperative cancel (called from a request thread, not the
    worker). Returns True if a worker is holding it right now; False if none is (already finished /
    advanced) — the caller then treats it as nothing-to-cancel. Only steps that poll cancel_requested()
    actually stop; others run to completion regardless."""
    for w in _WORKERS.values():
        if w.current_id == qid:
            w._cancel_requested = True
            return True
    return False

# Worker groups: name → the step types that single FIFO worker owns. SUMMARIZE and INDEX get SEPARATE
# workers (packet 1170) so a slow summary (an LLM call, up to an hour) can never head-of-line-block the
# fast index step — a newly landed artifact becomes searchable without waiting on a summary ahead of it
# in the same lane. Still one FIFO worker per group (no pool, no atomic claim); they share no resource
# (summarize uses the LLM provider, index uses the embedder).
_GROUPS: dict[str, list] = {
    "acquire": [ACQUIRE],         # fires the blocking FM export script (packet 1142 — replaces `pull`)
    "ingest": [INGEST],
    "summarize": [SUMMARIZE],     # its own FIFO worker (packet 1170 — slow LLM lane)
    "index": [INDEX],             # its own FIFO worker (packet 1170 — fast embed lane; search freshness)
    "git_export": [GIT_EXPORT],
    "reingest": [REINGEST],       # its own FIFO worker (packet 1062 — heavy, must not block ingest/enrichment)
}
_TYPE_TO_GROUP = {t: name for name, types in _GROUPS.items() for t in types}

_IDLE_WAIT = 30.0        # idle poll; poke() wakes a worker sooner
_ERROR_BACKOFF = 20.0    # after a claim/scan error, back off before retrying (no hot loop)


@dataclass
class StepResult:
    """A handler's verdict. ``ok`` → advance/delete; else the record parks with ``outcome``."""
    ok: bool
    outcome: str = ""


def ok() -> StepResult:
    return StepResult(True)


def fail(outcome: str) -> StepResult:
    return StepResult(False, outcome or "step failed")


# step type → handler(repo, row) -> StepResult. Registered by the producers (brick 4).
_HANDLERS: dict[str, Callable] = {}


def register(step_type: str, handler: Callable) -> None:
    """Register the handler that DOES a step type. Idempotent (last registration wins)."""
    _HANDLERS[step_type] = handler


def _repo():
    from corpusfm.storage import get_backend
    from corpusfm.storage.repos import queue_repo
    return queue_repo(get_backend())


def _poke_type(step_type: str) -> None:
    """Wake the worker that owns a step type (used to hand a record to the next worker on advance)."""
    name = _TYPE_TO_GROUP.get(step_type)
    if name:
        _WORKERS[name].poke()


class _Worker:
    """One FIFO thread draining a set of step types. Serial within the worker (single-flight); the
    ephemeral ``current_id`` lets the Queue view mark the row it's on and refuse a mid-step cancel."""

    def __init__(self, name: str, types: list):
        self.name = name
        self.types = types
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._running = False
        self.current_id = ""
        self.current_step = ""
        self.current_deadline = 0.0      # monotonic; 0 = idle (packet 1003)
        self._cancel_requested = False   # set by request_cancel(); polled by cancel_requested()

    def push_deadline(self) -> None:
        """Reset the no-progress deadline for the step in flight (called on any progress signal)."""
        if self.current_id:
            self.current_deadline = time.monotonic() + _timeout_for(self.current_step)

    # -- claim + process (the test seam is process_next) ---------------------
    def _claim(self, repo):
        """The oldest non-failed record across my types (FIFO by created_at). FIFO is **best-effort**
        (packet 1004 / E1): ``created_at`` is UTC µs ISO, so the order is chronological, but it is
        clock-dependent — a backward NTP step could mildly reorder two records. Harmless: queue records
        are independent, so order affects only fairness/latency, never correctness."""
        cands = [r for r in (repo.next_for(t) for t in self.types) if r is not None]
        if not cands:
            return None
        return min(cands, key=lambda r: r.jor.get("created_at", ""))

    def process_next(self, repo) -> bool:
        """Claim + run ONE record. Returns True if it processed something (test seam / loop body)."""
        try:
            row = self._claim(repo)
        except Exception:
            log.debug("queue worker %s: claim failed", self.name, exc_info=True)
            raise
        if row is None:
            return False
        self._process(repo, row)
        return True

    def _process(self, repo, row) -> None:
        step = row.jor.get("Type", "")
        qid = row.key
        handler = _HANDLERS.get(step)
        # Clear any stale cancel FIRST, then publish current_id LAST — otherwise a cancel arriving in the
        # window after we advertise this qid as running would be clobbered by the reset (packet 1000
        # re-sweep). request_cancel() matches on current_id, so once it's published the flag sticks.
        self._cancel_requested = False
        self.current_step = step
        self.current_deadline = time.monotonic() + _timeout_for(step)   # packet 1003
        self.current_id = qid
        _tls.worker = self
        try:
            if handler is None:
                repo.set_failed(qid, f"no handler registered for step '{step}'")
                return
            try:
                result = handler(repo, row)
            except Exception as exc:
                log.warning("queue %s: step '%s' raised on %s: %s", self.name, step, qid, exc,
                            exc_info=True)
                repo.set_failed(qid, f"{step} failed: {exc}")
                return
            if result.ok:
                # The cursor transition can fail loud on a corrupt record (Type ∉ Steps). Guard it like
                # the handler — otherwise the exception escapes to _loop, which re-claims + RE-RUNS the
                # (already-succeeded) handler unbounded, and for `land` could re-ingest (packet 1000 re-sweep).
                try:
                    nxt = repo.advance_or_delete(qid)
                except Exception as exc:
                    log.warning("queue %s: '%s' succeeded but the transition raised on %s: %s",
                                self.name, step, qid, exc, exc_info=True)
                    repo.set_failed(qid, f"{step} advance failed: {exc}")
                    return
                if nxt:
                    _poke_type(nxt)     # hand the record to the worker that owns the next step
            else:
                repo.set_failed(qid, result.outcome or f"{step} failed")
        finally:
            self.current_id = ""
            self.current_step = ""
            self.current_deadline = 0.0
            _tls.worker = None

    # -- thread lifecycle ----------------------------------------------------
    def _loop(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    repo = _repo()            # backend construction can raise transiently — keep it
                    if repo is None:          # INSIDE the guard so a hiccup backs off, never kills the
                        self._idle(_IDLE_WAIT)  # thread (a dead worker stops draining its whole type
                        continue              # silently + its non-failed rows then never drain).
                    did = self.process_next(repo)
                except Exception:
                    self._idle(_ERROR_BACKOFF)
                    continue
                if not did:
                    self._idle(_IDLE_WAIT)
        finally:
            with self._lock:
                self._running = False

    def _idle(self, timeout: float) -> None:
        self._wake.wait(timeout=timeout)
        self._wake.clear()

    def poke(self) -> None:
        self._wake.set()
        self.ensure()

    def ensure(self) -> None:
        # Only a WORKER-HOST process (one that called start_all() at boot — the web process) may spawn
        # a draining thread. The scheduler is a SEPARATE process that enqueues + pokes but must NOT
        # drain: a second pull worker there would claim the same non-failed [pull] row the web worker
        # is already running (there is no atomic claim), double-executing the run (dup snapshot +
        # RunRecord). Off-host, poke() still set the wake event (harmless); the web worker drains the
        # row on its next poll. See start_all().
        if not _worker_host:
            return
        with self._lock:
            if self._running:
                return
            self._running = True
        self._stop.clear()
        threading.Thread(target=self._loop, name=f"queue-{self.name}-worker", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()


# True only in a process that called start_all() AND won the worker-host lock (the web/uvicorn
# process). Gates worker-thread creation so the separate scheduler process — which enqueues + pokes
# but never calls start_all — cannot spin up a second draining worker (packet 1000 Phase 2:
# cross-process double-drain of pull), and so a second web process (deploy overlap, restart race)
# stands down instead of silently double-draining (packet 1001 / concept A).
_worker_host: bool = False

# Held for the whole life of the worker-host process (packet 1001): the OS advisory lock that makes
# "exactly one drainer" provable. A module global so the handle is never GC'd/closed (closing frees
# the lock). None until start_all() wins it.
_host_lock = None


def _worker_host_lock_path():
    """The stable, service-writable lock path, in the application's **runtime** directory — the same
    path for any second web process on this box. Overridable via ``CORPUSFM_WORKER_LOCK`` (tests point
    it at a temp file).

    A runtime lock, not durable state (packet 1333): it means nothing across a reboot, so it belongs in
    ``app_paths.run_dir()`` rather than beside persistent records. The old derivation used the install
    marker's directory, which the installer deliberately keeps root-owned — so on every published
    installation this detector could not even be evaluated, and said so on each start. Its fail-OPEN
    behaviour below is unchanged and is still correct: the DEPLOYMENT owns one-web-process, and this
    lock only DETECTS a hand-launched second instance (packet 1204).
    """
    import os
    from pathlib import Path
    override = os.environ.get("CORPUSFM_WORKER_LOCK")
    if override:
        return Path(override)
    from corpusfm.lifecycle import app_paths
    return app_paths.run_dir() / "worker-host.lock"


def _acquire_worker_host(retry_seconds: float) -> bool:
    """Try to become THE worker host. Wins the OS lock → True (host). Another live host holds it →
    briefly retry (a clean restart releases within seconds — hand over seamlessly) then stand down →
    False. A lock EVALUATION error (unwritable dir, odd FS) fails OPEN → True.

    WHO OWNS THIS INVARIANT (packet 1204 — read before "fixing" the fail-open): **the deployment does,
    not this lock.** CORPUSfm installs as ONE systemd unit (`Restart=always`) or ONE registered Windows
    service, so the OS guarantees a single web process and therefore a single worker host; see the
    Deployment invariants in CLAUDE.md. This lock DETECTS a violation — someone hand-launching a second
    instance — it does not arbitrate the invariant. That is why failing open is correct: refusing to
    drain when the service manager says this is the one instance would turn a rare operator mistake into
    a self-inflicted outage, where the whole QUEUE silently stops. The fail-open path is logged instead,
    so the rare real case is visible rather than prevented at the cost of the common one."""
    global _host_lock
    import time
    from corpusfm.core.proc_lock import ProcessLock, ACQUIRED, HELD, ERROR
    if _host_lock is not None and _host_lock.held:
        return True                                   # this process already holds it (idempotent)
    lock = ProcessLock(_worker_host_lock_path())
    deadline = time.monotonic() + max(0.0, retry_seconds)
    while True:
        res = lock.try_acquire()
        if res == ACQUIRED:
            _host_lock = lock
            log.info("worker-host lock acquired (%s) — this process drains the QUEUE",
                     _worker_host_lock_path())
            return True
        if res == ERROR:
            # Already logged before packet 1204; the CONSEQUENCE is what an operator needs, so it is
            # stated here rather than left to be inferred from "fail-open".
            log.warning("worker-host lock could not be evaluated (%s) — draining anyway, WITHOUT being "
                        "able to prove this is the only draining process. If a second CORPUSfm instance "
                        "was started by hand on this box, stop it: two drainers can run the same queue "
                        "record twice.", _worker_host_lock_path())
            return True
        if time.monotonic() >= deadline:              # res == HELD, retry window exhausted
            return False
        time.sleep(0.5)

_WORKERS: dict[str, _Worker] = {name: _Worker(name, types) for name, types in _GROUPS.items()}


def poke(step_type: str) -> None:
    """Wake the worker owning ``step_type`` (call after enqueueing a record of that type)."""
    _poke_type(step_type)


# ── upload watchdog (packet 086 — the `upload` step's server-side deadline) ───────
# The `upload` step is PERFORMED BY THE CLIENT (browser / MCP deliverable POSTs bytes into the record's
# SourceXML container); the server advances upload→ingest on the final bytes. This watchdog performs
# nothing — it fails records that overstay the deadline (a crashed/abandoned client upload), so a stuck
# upload never lingers and the ingest worker only ever sees present sources. NOTE (packet 1142): a Job
# Run / fms_push is NO LONGER an `upload` record — it is a worker-held `acquire` step bounded by its own
# blocking call (with the no-progress watchdog derived from the job's export bound). So this deadline
# governs ONLY client-supplied uploads, which carry no job bound; it is kept at/above the default export
# bound purely for a slow client link on a large file.
_UPLOAD_DEADLINE_SECS = max(600.0, DEFAULT_EXPORT_TIMEOUT_SECS)
_WATCHDOG_INTERVAL = 60.0
_watchdog_stop = threading.Event()
_watchdog_running = False
_watchdog_lock = threading.RLock()


def _parse_iso(s: str):
    if not s:
        return None
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def sweep_stale_uploads(repo) -> int:
    """Fail every ``upload``-step record past the deadline (unknown/absent timestamp counts as aged).
    Returns the number failed. Idempotent — a parked failure isn't re-listed."""
    from datetime import datetime, timezone
    from corpusfm.storage.queue_record import UPLOAD
    now = datetime.now(timezone.utc)
    failed = 0
    for row in repo.list_by_type(UPLOAD):          # non-failed upload records only
        ts = _parse_iso(row.jor.get("created_at", ""))
        if ts is None or (now - ts).total_seconds() > _UPLOAD_DEADLINE_SECS:
            repo.set_failed(row.key, "Upload did not complete in time.")
            failed += 1
    return failed


def _sweep_stuck_steps(repo) -> int:
    """Fail + reclaim any in-flight record whose worker has passed its no-progress deadline (a hang,
    packet 1003). A hang raises nothing (so try-once can't catch it) and counts as a non-failed active
    row that never drains. The watchdog parks it (``IsFailed`` → visible, Restart/Delete)
    then hard-exits so systemd/WinSW restart the process and free the hung thread. It kills ONLY after
    the record is safely parked, so a restart doesn't re-hang on the same row."""
    now = time.monotonic()
    parked = 0
    for w in _WORKERS.values():
        qid, dl = w.current_id, w.current_deadline
        if not qid or not dl or now <= dl:
            continue
        secs = int(_timeout_for(w.current_step))
        log.error("queue worker %s: step '%s' on %s made no progress for %ss — timing it out",
                  w.name, w.current_step, qid, secs)
        try:
            repo.set_failed(qid, f"timed out — no progress for {secs}s")
        except Exception:
            log.error("queue watchdog: could not park timed-out %s; retrying next tick", qid,
                      exc_info=True)
            continue                      # only kill once the record is safely parked
        parked += 1
    if parked:
        _kill_process()
    return parked


def _watchdog_loop() -> None:
    global _watchdog_running
    try:
        while not _watchdog_stop.is_set():
            try:
                repo = _repo()            # inside the guard — a transient backend error must back off,
                if repo is not None:      # not kill the watchdog (a dead watchdog stops reaping stale
                    sweep_stale_uploads(repo)  # uploads → they linger as active → never drain).
                    _sweep_stuck_steps(repo)   # + reclaim hung steps (packet 1003)
            except Exception:
                log.debug("watchdog sweep failed", exc_info=True)
            _watchdog_stop.wait(timeout=_WATCHDOG_INTERVAL)
    finally:
        with _watchdog_lock:
            _watchdog_running = False


def _ensure_watchdog() -> None:
    global _watchdog_running
    with _watchdog_lock:
        if _watchdog_running:
            return
        _watchdog_running = True
    _watchdog_stop.clear()
    threading.Thread(target=_watchdog_loop, name="queue-upload-watchdog", daemon=True).start()


def start_all(retry_seconds: float = 20.0) -> None:
    """Start every worker + the upload watchdog (called once at app boot, web process only). First
    win the worker-host lock (packet 1001) — only the winner marks itself a worker host and spawns
    draining threads; a second web process (deploy overlap / restart race) or the scheduler process
    stands down and does NOT drain. On a clean restart the previous host releases the lock within
    seconds, so the new process retries briefly and hands over seamlessly."""
    global _worker_host
    if not _acquire_worker_host(retry_seconds):
        log.warning("another CORPUSfm worker host is active — this process will NOT drain the QUEUE")
        return
    _worker_host = True
    for w in _WORKERS.values():
        w.ensure()
    _ensure_watchdog()


def stop_all() -> None:
    """Stop every worker (tests / shutdown) and release the worker-host lock so a later start_all in
    this interpreter can re-acquire."""
    global _worker_host, _host_lock
    for w in _WORKERS.values():
        w.stop()
    if _host_lock is not None:
        _host_lock.release()
        _host_lock = None
    _worker_host = False


def current_ids() -> set:
    """The record ids being processed right now (for the Queue view + mid-step cancel refusal)."""
    return {w.current_id for w in _WORKERS.values() if w.current_id}


def worker_for(step_type: str) -> Optional[_Worker]:
    """The worker owning a step type (tests)."""
    name = _TYPE_TO_GROUP.get(step_type)
    return _WORKERS.get(name) if name else None


def assert_single_worker(worker_count: int) -> None:
    """The per-type FIFO workers assume ONE process (no cross-process double-drain). Refuse to run
    with more, where the queue would silently fork (two worker sets racing the same records)."""
    if worker_count and worker_count > 1:
        raise RuntimeError(
            f"CORPUSfm requires a single web worker (got --workers {worker_count}). The QUEUE "
            "workers drain their type FIFO in-process; multiple workers would fork the queue."
        )
