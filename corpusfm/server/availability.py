"""Database readiness — CORPUSfm is either database-ready or PAUSED. There is no third state.

Packet 1361-01, availability correction (developer ruling, 2026-09-02). This is a PROCESS-WIDE gate,
not a per-endpoint policy, and the distinction is the whole point of the module:

    CORPUSfm is either database-ready or paused. There is no partially operational state. Startup
    begins paused. Any genuine FileMaker database availability/read failure returns the process to
    paused. While paused, CORPUSfm retains memory but does not trust or operate from it; it sleeps
    and performs only bounded recovery validation until FileMaker is available again. One complete
    successful STORAGE/TAG/STORAGELINK validation reopens the process.

**What this replaces.** The persistent-catalog algorithm was reviewed twice and found sound; what was
missing was a process-wide answer to "the database went away". Without one, each surface invented its
own degradation — an MCP tool that answered "no stored file references X", an overview that reported
zero artifacts, a tag datalist that answered `[]` — and a request thread could be handed the job of
reconstructing the read model. Those are not endpoint bugs to patch one at a time. They are what a
missing gate looks like from the outside.

**The five properties, and where each is enforced:**

1. **Begins closed.** The module-level gate starts paused with reason ``startup``. Nothing opens it
   but a COMPLETE catalog validation.
2. **Opens once, after the prerequisite chain and one complete build.** ``open_on_complete_validation``
   is called only by :func:`corpusfm.server.catalog.validate_now` on a successful pass, which the web
   lifespan places after the synchronous prerequisite chain. Opening runs the registered ``resume``
   callback EXACTLY ONCE per closed→open edge, under the state lock, so the synchronizer and the
   queue workers can never be started twice.
3. **Closes on a genuine availability/transport/read failure**, observed either by catalog validation
   (any incomplete three-table read) or by an ordinary keyed database operation. The keyed-operation
   half comes from ONE chokepoint — ``fm_odata._TimeoutSession.request``, through which every
   FileMaker HTTP call already passes and which already classifies transport failures and the
   502/503/504 down-family. A 4xx (missing record, validation refusal, conflict, expected write
   rejection) is not an availability failure and is in fact evidence the channel is UP.
4. **While closed, the only component that contacts FileMaker is the coordinator.** It sleeps
   :data:`RECOVERY_INTERVAL_S` between transient retries — a bounded cadence, never a hot loop.
5. **Runtime loss and startup loss are the same state machine**, run by the same thread.

**ONE PERSISTENT COORDINATOR (packet 1361-01, round 7).** Service initialization is a first-class
process, so it has a first-class owner: one thread, started once from the web lifespan, whose FIRST
ACTION is the initial prerequisite attempt and which then lives for the process.

    start → attempt → ok?      → open, resume, DORMANT until the gate closes again
                    → blocked? → DORMANT with an intervention explanation; no retry loop
                    → else     → sleep the bounded interval, run the SAME chain from stage one

What this replaces: a foreground `startup.attempt()` on the lifespan thread PLUS a recovery thread
spawned by `close()`. Two mechanisms, two places a thread could exist, and a hand-off between them
that round 2 recorded as a transient overlap of coordinators and argued was safe. It was — but a
single persistent owner makes the question unaskable instead of arguable, and it takes thread
creation off the FileMaker transport's failure path, which is reached from arbitrary request and
worker threads.

**There is no attempt lock, epoch, failure serial or generation**, and none is needed: only one
thread ever attempts, so nothing can overlap. Concurrent `close()` calls set one event; the dormant
coordinator wakes once.

**Supervision is deliberate.** The coordinator runs only in a process that called :func:`supervise`
and then :func:`start_coordinator` — which the web lifespan does and nothing else does. A CLI or a
test can close the gate without any thread then talking to a database nobody asked it to talk to.

**The paused process still explains itself.** :data:`PHASE_INITIALIZING`, :data:`PHASE_UNAVAILABLE`
and :data:`PHASE_INTERVENTION` are DIAGNOSTIC reasons within the single PAUSED state — what the
waiting page and the local probe render. They are not readiness states: every functional surface
refuses identically under all three, and none of them permits partial operation.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

#: How long the recovery coordinator sleeps between attempts while paused. INTERNAL, not an
#: administrator setting, and deliberately CONSTANT rather than a backoff: a paused product must come
#: back promptly, and one complete three-table read every few seconds against a database that is down
#: costs a refused connection. A module attribute so a test can drive the coordinator without
#: sleeping.
RECOVERY_INTERVAL_S = 5.0

PAUSED = "paused"
READY = "ready"

#: The DIAGNOSTIC reasons a paused process can give for itself. They are explanations WITHIN the one
#: PAUSED state — never additional operational states, and never a licence for partial operation.
#: Every functional surface refuses identically under all three.
PHASE_INITIALIZING = "initializing"   # an initialization attempt is running right now
PHASE_UNAVAILABLE = "unavailable"     # the last attempt hit a database outage; waiting to retry
PHASE_INTERVENTION = "intervention"   # a deterministic refusal; not retrying, an operator is needed
PHASE_BUILD_MISMATCH = "build_mismatch"   # a proven schema/build incompatibility; run the installer

#: The phases that mean "stopped on a deterministic refusal". Both park; they differ only in what
#: the administrator is told to DO, which is the whole reason the second one exists — "read the log"
#: and "run the installer" are different actions.
_TERMINAL_PHASES = (PHASE_INTERVENTION, PHASE_BUILD_MISMATCH)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class _Gate:
    """The process-wide database-readiness state.

    ``_lock`` guards every field and is held only for state transitions — never across a database
    read, never across the ``resume`` callback's own work beyond the one-shot guard it needs.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._open = False
        self._reason = "startup"
        self._detail = ""
        self._changed_utc = _utc()
        self._closed_count = 0
        self._opened_count = 0
        # Supervision: set by the web lifespan, and by nothing else.
        self._backend = None
        self._resume = None
        self._supervised = False
        self._recover = None
        # ── THE ONE COORDINATOR (packet 1361-01, round 7) ────────────────────────────────────────
        # One persistent thread owns initialization AND later recovery, for the life of the process.
        # `_wake` is "there is work to do" — set by `close()` and by shutdown; `_stop` is shutdown
        # alone. Both are created once, with the gate, so a signal can never race their existence.
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._first_attempt = threading.Event()
        self._phase = PHASE_INITIALIZING
        self._attempts = 0
        self._last_error = ""
        # THE PREREQUISITE INTERLOCK (packet 1361-01, round 3). True means "a complete validation may
        # open the process". A process with a STARTUP AUTHORITY clears it for the duration of an
        # attempt, so a catalog scan that happens to succeed after an EARLIER prerequisite failed
        # cannot open the gate on its own. It defaults True because a process with no startup
        # authority — the CLI, a test, any composition with no lifespan — has no chain to wait for,
        # and inventing one for them would only make the gate unopenable where nothing arms it.
        self._prereq_ok = True

    # ── state ────────────────────────────────────────────────────────────────────────────────────

    def is_open(self) -> bool:
        with self._lock:
            return self._open

    def state(self) -> str:
        with self._lock:
            return READY if self._open else PAUSED

    def reason(self) -> str:
        with self._lock:
            return "" if self._open else (self._reason or "storage")

    def detail(self) -> str:
        """The paused process's own explanation, when a stage composed one. Local, and read-only."""
        with self._lock:
            return "" if self._open else (self._detail or "")

    def diagnostics(self) -> dict:
        """Cheap facts only — no database read, no catalog read, no secret."""
        with self._lock:
            return {
                "state": READY if self._open else PAUSED,
                "reason": "" if self._open else (self._reason or "storage"),
                "detail": "" if self._open else self._detail,
                "changed_utc": self._changed_utc,
                "phase": "" if self._open else self._phase,
                "supervised": self._supervised,
                "coordinator_running": bool(self._thread is not None and self._thread.is_alive()),
                "coordinator_stopping": bool(self._stop.is_set() and self._thread is not None
                                             and self._thread.is_alive()),
                "recovering": bool(self._thread is not None and self._thread.is_alive()
                                   and not self._open),
                "first_attempt_done": self._first_attempt.is_set(),
                "recovery_attempts": self._attempts,
                "recovery_interval_s": RECOVERY_INTERVAL_S,
                "last_recovery_error": self._last_error,
                "prerequisites_armed": self._prereq_ok,
                "closed_count": self._closed_count,
                "opened_count": self._opened_count,
            }

    # ── transitions ──────────────────────────────────────────────────────────────────────────────

    def open_on_complete_validation(self) -> bool:
        """Reopen the process. Returns True on the closed→open EDGE only.

        The single opening authority, and it is called from exactly one place: a complete, successful
        STORAGE/TAG/STORAGELINK validation. The ``resume`` callback runs on the edge, inside the state
        lock, so two threads reaching a first success together cannot both start the synchronizer or
        the queue workers.
        """
        with self._lock:
            if self._open:
                return False
            if not self._prereq_ok:
                # A startup attempt is in flight and its prerequisite chain has NOT completed. A
                # complete three-table scan is necessary for readiness and is not sufficient for it:
                # opening here would publish a box whose projection assert, conversion, tag
                # integrity or promotion repair failed moments ago (packet 1361-01, round 3).
                logger.debug("database readiness: a complete validation succeeded, but the startup "
                             "prerequisite chain has not; the gate stays closed")
                return False
            if self._stop.is_set():
                # SHUTDOWN HAS BEGUN — DO NOT PUBLISH READINESS (packet 1361-01, round 9).
                #
                # A retired coordinator's in-flight attempt can still complete after shutdown
                # signalled it. Round 8 let it OPEN the gate and merely skipped `resume()`, which is
                # the worst of the available answers: a process reporting itself READY with no
                # synchronizer, no scheduler and no queue workers behind it — every functional
                # surface answering from a model nothing is validating — and, through
                # `startup.attempt`, a `_complete` flag saying initialization had succeeded.
                #
                # The refusal is INSIDE the locked transition on purpose: checking after it would
                # leave a window in which the gate is briefly open, and the freeze it lifts is not
                # something a later correction can put back.
                logger.info("database readiness NOT opened: a complete validation finished after "
                            "shutdown began, so the gate stays PAUSED and no background work is "
                            "resumed.")
                return False
            self._open = True
            self._reason = ""
            self._detail = ""
            self._changed_utc = _utc()
            self._opened_count += 1
            self._attempts = 0
            self._last_error = ""
            self._phase = ""
            resume = self._resume
        # THE COORDINATOR IS NOT RETIRED HERE (round 7). It is persistent: it goes dormant and the
        # next `close()` wakes the SAME thread. Retiring it on every open and starting a fresh one
        # on every close is what produced the overlapping-coordinator hand-off round 2 recorded.
        logger.info("database readiness OPEN: one complete STORAGE/TAG/STORAGELINK validation "
                    "succeeded; CORPUSfm is serving.")
        if resume is not None:
            try:
                resume()
            except Exception:               # pragma: no cover - a resume problem must not re-pause
                logger.error("database readiness: the resume callback raised; the gate is open but "
                             "background work may not have restarted", exc_info=True)
        return True

    def close(self, reason: str, detail: str = "") -> bool:
        """Pause the process. Returns True on the open→closed EDGE only.

        Idempotent and cheap: a storm of failures on a channel that is already down costs one lock
        acquisition each and logs nothing after the edge.
        """
        with self._lock:
            was_open = self._open
            self._open = False
            self._reason = reason or "storage"
            self._detail = detail or ""
            if was_open:
                self._changed_utc = _utc()
                self._closed_count += 1
            # THE COORDINATOR OWNS THE PHASE while it is working; `close()` sets it only where it
            # knows better. `intervention` comes from the startup chain's own deterministic verdict
            # and must survive. An empty phase means we were READY, so a close is an outage — and
            # saying so covers the window before the dormant coordinator wakes, and covers a process
            # that has no coordinator at all.
            if reason == "build_mismatch":
                self._phase = PHASE_BUILD_MISMATCH
            elif reason == "intervention":
                self._phase = PHASE_INTERVENTION
            elif not self._phase:
                self._phase = PHASE_UNAVAILABLE
        if was_open:
            logger.error("database readiness CLOSED (%s%s): CORPUSfm is paused. The persistent "
                         "catalog is retained but not operated from; queue work stops claiming; "
                         "database-dependent surfaces refuse. Recovery validation retries every "
                         "%.0fs.", reason, f": {detail}" if detail else "", RECOVERY_INTERVAL_S)
        # SIGNAL ONLY — this NEVER starts a thread (round 7). `close()` is reached from the
        # FileMaker transport chokepoint, which means from arbitrary request and worker threads, on
        # a path that is already failing; creating threads there was always the wrong place. Any
        # number of concurrent closes set the same event, which wakes the same dormant coordinator
        # once. A process with no coordinator (a CLI, a test) simply stays closed, which is correct:
        # nothing there asked to recover.
        self._wake.set()
        return was_open

    def note_database_unreachable(self, detail: str = "") -> None:
        """A genuine FileMaker availability/transport failure, observed by ANY database operation.

        This is what makes the gate architectural rather than catalog-specific: an ordinary keyed
        read or write that cannot reach FileMaker pauses the whole process, without that operation's
        caller having to know the gate exists. Never raises — an observation must not become a second
        failure on a path that is already failing.
        """
        try:
            self.close("storage", detail)
        except Exception:                   # pragma: no cover - bookkeeping must never raise
            pass

    # ── supervision + the recovery coordinator ───────────────────────────────────────────────────

    def supervise(self, backend, resume=None, recover=None) -> None:
        """Adopt this process as the one that recovers. Called by the web lifespan, and only there.

        ``resume`` is the idempotent "make the steady state true" callback — start the catalog
        synchronizer, start the queue workers — run exactly once per closed→open edge.

        **Registration only: it does not start the coordinator.** :meth:`start_coordinator` does,
        immediately afterwards, and it is the only thing that ever does — `close()` signals and
        never spawns (round 7). Registering first is what puts the resume callback in place before
        the coordinator's first attempt can open the gate.
        """
        with self._lock:
            self._backend = backend
            self._resume = resume
            self._recover = recover
            self._supervised = True

    # ── the prerequisite interlock ───────────────────────────────────────────────────────────────

    def begin_startup(self) -> None:
        """A startup authority is taking responsibility for this process: hold the gate shut.

        Called at the START of every startup attempt — the initial one and every pre-startup
        recovery attempt. Until :meth:`prerequisites_satisfied` is reached, NOTHING opens the
        process, so an ordinary validation pass that completes while the chain is still running (or
        after part of it failed) cannot declare the box ready on the chain's behalf."""
        with self._lock:
            self._prereq_ok = False

    def prerequisites_satisfied(self) -> None:
        """The whole idempotent prerequisite chain completed. A complete validation may now open."""
        with self._lock:
            self._prereq_ok = True

    def shutting_down(self) -> bool:
        """Has this process been told to stop? Cheap, lock-free, and read by the startup authority.

        A validation that completes after this becomes true is real work whose RESULT is no longer
        publishable: the gate refuses to open on it, so reporting it as successful readiness — or
        marking startup complete on it — would be a claim about a process that is going away.
        """
        return self._stop.is_set()

    def prerequisites_armed(self) -> bool:
        """May a complete validation open the process right now? Diagnostics and tests."""
        with self._lock:
            return self._prereq_ok

    # ── THE ONE COORDINATOR ──────────────────────────────────────────────────────────────────────

    def start_coordinator(self) -> bool:
        """Start THE readiness coordinator. Returns True on the START edge only.

        Called once, from the web lifespan. **Its first action is the initial prerequisite
        attempt** — the lifespan does not run one itself, so there is exactly one thread that ever
        performs a startup or recovery attempt and no arrangement in which two can overlap. The
        first attempt begins immediately; nothing sleeps before initialization.

        The whole start happens under ONE lock acquisition, so two callers produce one thread.
        """
        with self._lock:
            if not self._supervised or self._backend is None:
                return False
            if self._thread is not None and self._thread.is_alive():
                if self._stop.is_set():
                    # A RETIRED coordinator that has not exited yet — it is still inside a database
                    # call. Starting a replacement here is precisely the overlap this design
                    # forbids, so the new lifespan goes without one until that thread is gone.
                    logger.error("a readiness coordinator was requested while the previous one is "
                                 "still alive inside a database call; NOT starting a second.")
                return False
            self._stop.clear()
            self._wake.clear()
            self._first_attempt.clear()
            self._phase = PHASE_INITIALIZING
            backend, recover = self._backend, self._recover
            t = threading.Thread(target=self._coordinate, args=(backend, recover),
                                 name="cfm-readiness", daemon=True)
            self._thread = t
            t.start()
            return True

    def stop_coordinator(self, timeout: float = 5.0) -> bool:
        """Signal and JOIN the coordinator. Returns True only when it ACTUALLY TERMINATED.

        Signalling is cheap and reaches it wherever it is parked — both events are set, so a dormant
        wait with no timeout and a bounded retry sleep both return at once. **Joining is the part
        that can fail**: a coordinator blocked inside a FileMaker call returns when that call
        returns, and a FileMaker call can outlast any join timeout worth having.

        **A COORDINATOR IS NEVER FORGOTTEN BEFORE IT DIES (packet 1361-01, round 8).** This used to
        clear ``_thread`` up front and join afterwards, and ``reset()`` then cleared ``_stop``. On a
        slow shutdown that produced exactly the state round 7 exists to make impossible: the old
        thread, still blocked in FileMaker, came back to a CLEARED stop signal and resumed its loop,
        while ``start_coordinator`` saw ``_thread is None`` and started a second one. Two
        coordinators, two attempt streams, from a five-second timeout.

        So on a failed join the thread authority is RETAINED and the stop signal stays SET:

        * ``_thread`` still points at the live thread, so ``start_coordinator`` refuses and
          ``diagnostics()["coordinator_running"]`` keeps telling the truth;
        * ``_stop`` stays set, so the moment that in-flight call returns the loop checks it and
          exits without another attempt;
        * the caller is told, loudly and in the return value, rather than being allowed to believe
          shutdown completed.

        The bound is deliberate. Waiting indefinitely would hang the process where a supervisor
        would eventually SIGKILL it anyway; the honest answer is a bounded wait plus a truthful
        report.
        """
        with self._lock:
            thread = self._thread
        # SIGNAL FIRST, and never withdraw it. This is the one signal that retires this coordinator
        # for good, and it must outlive a join that does not complete.
        self._stop.set()
        self._wake.set()
        if thread is None or not thread.is_alive():
            self._release_thread(thread)
            return True
        thread.join(timeout=timeout)
        if thread.is_alive():
            logger.error(
                "readiness coordinator did NOT terminate within %.1fs — it is still inside a "
                "database call. It is retired and will exit as soon as that call returns; it makes "
                "no further attempt. Nothing will start a replacement while it is alive, and the "
                "gate's state is left untouched.", timeout)
            return False
        self._release_thread(thread)
        return True

    def _release_thread(self, thread) -> None:
        """Clear the handle ONLY when it still names the thread this call stopped.

        **An unconditional `self._thread = None` was a second way to end up with two coordinators**
        (packet 1361-01, round 9). Between a join completing and the handle being cleared, another
        lifespan can legitimately call `start_coordinator()`: it sees a dead thread, starts a
        REPLACEMENT and records it. The stopping caller then erased the replacement's authority, and
        a third `start_coordinator()` — seeing `_thread is None` — would have started another one.

        Identity, not presence, is the test. A handle that no longer names our thread belongs to
        somebody else and is not ours to clear.
        """
        if thread is None:
            return
        with self._lock:
            if self._thread is thread:
                self._thread = None

    def await_first_attempt(self, timeout: float = 5.0) -> bool:
        """Has initialization been ATTEMPTED at least once? A one-shot fact, not a counter.

        Authorized as first-class initialization state (developer ruling, 2026-09-02). It exists
        because moving startup off the lifespan thread removed the only synchronous signal that an
        attempt had happened. **It must never gate a request** — the readiness gate alone decides
        what may serve. Health reporting and tests may observe it.
        """
        return self._first_attempt.wait(timeout)

    def _coordinate(self, backend, recover) -> None:
        """The whole readiness lifecycle, in one thread, for the life of the process.

            attempt → ok?      → open + resume, then DORMANT until the gate closes again
                    → blocked? → DORMANT with an intervention explanation; no retry loop
                    → else     → sleep the bounded interval and run the SAME chain from stage one

        `recover` is the startup authority's own entry point, and it is what keeps boot conversions
        once-per-process: before startup completes it runs the whole prerequisite chain, and after
        it completes it runs a complete catalog validation and nothing else. This loop does not
        know or care which; it classifies the RESULT and decides only what to do next.
        """
        from corpusfm.server import catalog
        attempt = recover if recover is not None else catalog.validate_now
        never_ready = True
        while not self._stop.is_set():
            with self._lock:
                # `initializing` means an attempt is IN FLIGHT and startup has never succeeded. A
                # recovery attempt after a box HAS served is not initialization, so it keeps the
                # outage word an operator is already reading.
                self._phase = PHASE_INITIALIZING if never_ready else PHASE_UNAVAILABLE
                self._attempts += 1
            try:
                res = attempt(backend)
            except Exception as exc:                # pragma: no cover - the attempt never raises
                res = {"ok": False}
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                logger.error("readiness coordinator: the attempt raised", exc_info=True)
            self._first_attempt.set()
            if self._stop.is_set():
                return

            if res.get("ok"):
                never_ready = False
                self._park_until_closed()
                continue
            with self._lock:
                self._last_error = str(res.get("reason") or res.get("error") or "")
            if res.get("blocked"):
                # The COORDINATOR sets the phase from the RESULT, rather than trusting the attempt
                # to have closed the gate with the right reason. The classification lives in one
                # place — the returned verdict — and one reader honours it.
                with self._lock:
                    # A stage that already named a MORE SPECIFIC terminal reason keeps it: the
                    # coordinator classifies "deterministic", the stage knows which one.
                    if self._phase not in _TERMINAL_PHASES:
                        self._phase = PHASE_INTERVENTION
                # DETERMINISTIC. Its inputs were read successfully and the answer is decided, so
                # running this chain again every few seconds buys nothing and costs a full
                # projection assert, a lineage-wide promotion repair and a seed gate each time. The
                # recovery route is an operator correcting the condition and restarting the service.
                self._park_until_signalled()
                continue
            # Transient: the bounded cadence, then the SAME chain from stage one. The phase says
            # what is true DURING the wait — the database is away and we are retrying — rather than
            # leaving "initializing" up for the whole outage, which would hide the one fact an
            # administrator can act on.
            with self._lock:
                self._phase = PHASE_UNAVAILABLE
            self._stop.wait(RECOVERY_INTERVAL_S)

    def _park_until_closed(self) -> None:
        """Dormant while the process is READY. Returns when the gate closes, or on shutdown.

        The clear-then-recheck is what makes a concurrent `close()` impossible to lose: `close()`
        sets ``_open`` False BEFORE it sets ``_wake``, so a close that lands before the clear is
        seen by the state read, and one that lands after it sets the event we are about to wait on.
        """
        while not self._stop.is_set():
            self._wake.clear()
            if self._stop.is_set() or not self.is_open():
                return
            self._wake.wait()

    def _park_until_signalled(self) -> None:
        """Dormant after a deterministic refusal. Returns on any wake signal or on shutdown.

        A signal here means something closed the gate again — which, while paused, only shutdown
        normally does. It re-attempts rather than assuming, because a wake is cheap and being wrong
        about "nothing has changed" is not.
        """
        self._wake.clear()
        if self._stop.is_set():
            return
        self._wake.wait()

    # ── lifecycle ────────────────────────────────────────────────────────────────────────────────

    def reset(self, timeout: float = 5.0) -> bool:
        """Back to the startup state: paused, unsupervised, no coordinator. Process shutdown and the
        test seam. Returns True when it actually reset.

        **It REFUSES while a retired coordinator is still alive (packet 1361-01, round 8)**, and the
        refusal is the correction: every field below is state that coordinator reads, and clearing
        ``_stop`` in particular would un-retire a thread that is still inside a FileMaker call. A
        reset that cannot be performed safely is reported, not faked — the alternative is two
        coordinators in one process, which is the invariant round 7 exists for.
        """
        if not self.stop_coordinator(timeout):
            logger.error("readiness gate NOT reset: a retired coordinator is still alive. Its stop "
                         "signal and thread authority are left in place, and no replacement can "
                         "start until it exits.")
            return False
        # ONE UNINTERRUPTED CRITICAL SECTION (packet 1361-01, round 10). The replacement check and
        # every mutation it authorises happen under a single acquisition. Round 9 checked in one
        # locked section, RELEASED, then cleared in a second — and `start_coordinator` acquires the
        # same lock, so it could install a replacement in that gap and have its backend, resume and
        # recovery callbacks, and its stop signal, cleared out from under it a moment later. The
        # check is only meaningful while it is still true.
        #
        # `stop_coordinator` stays OUTSIDE it, deliberately: it joins a thread, and holding the lock
        # every reader takes across a join is how a slow shutdown becomes a stalled process.
        refused = False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                # Our thread terminated, but a REPLACEMENT started while we were joining. Clearing
                # the fields below would take that live coordinator's backend, resume callback and
                # stop signal out from under it — the same class of error as erasing its handle.
                refused = True
            else:
                self._reset_locked()
        if refused:
            # Logged outside the section: a logging handler is arbitrary code, and the critical
            # section this correction exists to keep short must not contain any.
            logger.error("readiness gate NOT reset: a replacement coordinator is running. The stop "
                         "this call issued was for a thread that has already exited.")
            return False
        # The startup authority's own once-per-process record travels with the gate: a reset process
        # owes its prerequisite chain again (packet 1361-01, round 3). It takes its own lock, so it
        # is reached after this one is released.
        try:
            from corpusfm.server import startup as _startup
            _startup.reset_for_testing()
        except Exception:                   # pragma: no cover - import-time only
            pass
        return True

    def _reset_locked(self) -> None:
        """Every field of the startup state, cleared. CALLED WITH ``_lock`` HELD, always.

        Split out so the replacement check and these mutations are visibly one critical section
        rather than two that happen to be adjacent — which is exactly the shape that regressed.
        """
        self._stop.clear()
        self._wake.clear()
        self._first_attempt.clear()
        self._phase = PHASE_INITIALIZING
        self._open = False
        self._reason = "startup"
        self._detail = ""
        self._changed_utc = _utc()
        self._backend = None
        self._resume = None
        self._recover = None
        self._supervised = False
        self._prereq_ok = True
        self._attempts = 0
        self._last_error = ""
        self._closed_count = 0
        self._opened_count = 0


_gate = _Gate()

# ── Module surface ────────────────────────────────────────────────────────────────────────────────

is_open = _gate.is_open
state = _gate.state
reason = _gate.reason
diagnostics = _gate.diagnostics
open_on_complete_validation = _gate.open_on_complete_validation
close = _gate.close
note_database_unreachable = _gate.note_database_unreachable
supervise = _gate.supervise
start_coordinator = _gate.start_coordinator
stop_coordinator = _gate.stop_coordinator
await_first_attempt = _gate.await_first_attempt
phase = lambda: _gate.diagnostics()["phase"]        # noqa: E731 - one local read, no import cycle
detail = _gate.detail
shutting_down = _gate.shutting_down
begin_startup = _gate.begin_startup
prerequisites_satisfied = _gate.prerequisites_satisfied
prerequisites_armed = _gate.prerequisites_armed
reset = _gate.reset


def unavailable_payload() -> dict:
    """The ONE body every paused database-dependent surface answers with.

    Deliberately the same keys AND the same values the catalog failure already used
    (``catalog_failed`` / ``unavailable`` / ``reason: "storage"``), so every existing banner, freeze
    and refusal path renders it with no per-surface change — which is what "contain it in the gate,
    do not patch the endpoints" means in practice.

    ``reason`` is the WIRE vocabulary, and it is always ``"storage"``: the browser branches on
    ``server`` versus everything-else, so a new word here would only be a word no surface knows. The
    precise internal reason (``startup``, a transport detail) belongs in :func:`diagnostics` and the
    log, where something can actually act on it.
    """
    return {"catalog_failed": True, "unavailable": True, "reason": "storage"}


def unavailable_message() -> str:
    """The honest one-liner for a text surface (MCP tools, the CLI)."""
    return ("Catalog unavailable — CORPUSfm is paused because the FileMaker database could not be "
            "read. The stored artifacts are unaffected; it resumes automatically when the database "
            "is reachable again.")
