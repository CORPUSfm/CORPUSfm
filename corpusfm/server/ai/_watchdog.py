"""Wall-clock watchdog for AI provider calls (packet 057).

A `requests` read timeout is unreliable against a proxy that holds a connection open (a k8s NodePort in
front of the model kept a summarize call blocked for 20+ min despite `timeout=120`, freezing the enrich
queue). A `threading.Event.wait(deadline)` fires regardless of socket state, so it's the reliable bound.

`call_with_deadline` runs the call in a daemon thread and abandons it on timeout — a blocking HTTP read
can't be force-interrupted, so the thread is LEFT running (it ends when the underlying socket eventually
closes). Callers MUST bound the leak with a circuit breaker (e.g. abort after N consecutive timeouts).
"""
from __future__ import annotations

import threading
import time
from typing import Callable, Optional, TypeVar

T = TypeVar("T")


class CallTimeout(Exception):
    """An AI call exceeded its wall-clock deadline (distinct from a normal error so callers can count
    consecutive hangs and trip a circuit breaker)."""


class CallCancelled(Exception):
    """A cooperative Stop fired while the call was in flight — abandon it and unwind now."""


def call_with_deadline(fn: "Callable[[], T]", timeout_s: float,
                       should_cancel: "Optional[Callable[[], bool]]" = None, poll: float = 0.5) -> T:
    """Return ``fn()``; raise CallTimeout if it doesn't finish within ``timeout_s`` seconds, or
    CallCancelled if ``should_cancel()`` goes true while it's in flight (Stop stays responsive — checked
    every ``poll`` seconds — instead of waiting out the whole deadline). A fn exception is re-raised
    unchanged. A timed-out/cancelled call's daemon thread is LEFT running (a blocking read can't be
    force-interrupted); it ends when the underlying socket closes."""
    box: dict = {}
    done = threading.Event()

    def _run() -> None:
        try:
            box["v"] = fn()
        except BaseException as exc:   # noqa: BLE001 — carry any failure back to the caller thread
            box["e"] = exc
        finally:
            done.set()

    threading.Thread(target=_run, name="ai-call", daemon=True).start()
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CallTimeout(f"AI call exceeded {int(timeout_s)}s")
        if should_cancel is not None and should_cancel():
            raise CallCancelled("cancelled")
        if done.wait(min(poll, remaining)):
            break
    if "e" in box:
        raise box["e"]
    return box["v"]
