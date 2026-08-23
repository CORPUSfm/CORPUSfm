"""The scheduled refusal-only update observation on a published installation (packet 1281).

Since packet 1251 (ruling D2) the browser's two-hour update poll is PASSIVE — it classifies the
Git refs already on disk and fetches nothing, because a real check on an installed box means
starting the root privileged one-shot, and that must not multiply per authenticated browser. What
nothing did after D2 was refresh those refs on the box's own clock: they advanced only when an
administrator clicked *Check for updates*, so the sidebar badge stayed faithfully dark against
stale refs. This module is the ONE box-wide clock D2 left room for — one privileged observation
per installation per cycle, never one per user.

Boundaries, all inherited rather than invented:

* **Published installations only.** `start_if_published()` starts nothing on a development,
  unpublished or indeterminate layout — `app_paths.is_published()` raises on indeterminate (its
  refuse-don't-guess contract) and both `False` and a raise read as "start nothing". The gate
  cannot be delegated to `update_service.check()`: its development route deliberately fetches
  directly, which is exactly what a background worker must never do from a dev checkout.
* **Refusal-only, by construction.** The worker calls `update_service.check(refresh=True)` and
  nothing else. The explicit observation submits the all-zero consent SHA, which can only ever be
  refused — the elevated updater keeps every origin/ancestry/classification gate, and this worker
  adds no endpoint, no credential and no Git access.
* **Off the event loop.** `check(refresh=True)` can block up to the privileged outcome timeout
  (300 s), so the worker is a daemon thread on the `app.py` lifespan pattern, with a fixed delay
  after each COMPLETED observation — a slow cycle cannot overlap itself or hot-loop.
* **Single flight by result.** A concurrent Settings/MCP check owns the in-process lock;
  `update_in_progress` (or any error) is a logged skip, and the next look is a full interval away.
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

#: Codex-scoped cadence (packet 1281): first look well clear of boot, then the browser's own clock.
STARTUP_DELAY_S = 300
INTERVAL_S = 7200


class UpdateObserver:
    """One box-wide observation loop. `stop()` prevents any later cycle; it never joins an
    observation already handed to the privileged one-shot."""

    def __init__(self, *, check=None, delay_s: float = STARTUP_DELAY_S,
                 interval_s: float = INTERVAL_S):
        self._check = check
        self._delay_s = delay_s
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="cfm-update-observer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self) -> None:
        if self._stop.wait(self._delay_s):
            return
        while not self._stop.is_set():
            self.observe_once()
            if self._stop.wait(self._interval_s):
                return

    def observe_once(self) -> None:
        """One observation. Every outcome — refusal, busy, exception — is a logged skip; the
        worker survives and the next look is a full interval away (no hot retry)."""
        try:
            check = self._check
            if check is None:
                from corpusfm.server.update_service import check
            res = check(refresh=True)
            error_class = getattr(res, "error_class", "") or ""
            if error_class:
                logger.info("scheduled update observation: %s", error_class)
            elif getattr(res, "update_available", False):
                logger.info("scheduled update observation: update available (%s)",
                            getattr(res, "target_version", "") or "unknown")
            else:
                logger.debug("scheduled update observation: current")
        except Exception:  # noqa: BLE001 — a failed observation is a skipped cycle, never a crash
            logger.info("scheduled update observation failed; next look in one interval",
                        exc_info=True)


def start_if_published(*, check=None, delay_s: float = STARTUP_DELAY_S,
                       interval_s: float = INTERVAL_S) -> UpdateObserver | None:
    """Start the observer on a PUBLISHED installation; `None` (and no worker, no fetch, no
    `update_service` call) everywhere else. A raise from `is_published()` is an indeterminate
    layout and reads as "start nothing" — the same conservative answer `update_service.apply()`
    gives it."""
    try:
        from corpusfm.lifecycle import app_paths
        published = bool(app_paths.is_published())
    except Exception:  # noqa: BLE001 — indeterminate is not published
        return None
    if not published:
        return None
    observer = UpdateObserver(check=check, delay_s=delay_s, interval_s=interval_s)
    observer.start()
    return observer
