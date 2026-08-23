"""The one machine lifecycle lock (packet 1246-01, deliverable 4).

One lock covers installer, uninstaller, proxy mutation, recovery adoption and privileged update,
because those are not independent activities: they all end up writing the same manifest and touching
the same services. A per-tool lock was rejected for exactly that reason — two tools each holding
their own lock is two writers, politely.

The kernel mechanism is ``core.proc_lock``, already in the tree and already proven: the lock dies
with its holder, so a crashed installer does not leave a stale lockfile that the next run has to
guess about.

**The policy is inverted from ``proc_lock``'s other caller, deliberately.** The QUEUE worker host
fails OPEN when the lock cannot be evaluated — refusing to do any work over an unreadable guard is
worse than a duplicate drain. A lifecycle mutation is the opposite case: it changes services, keys
and databases, and an operation that cannot prove it is alone must not proceed. Same mechanism,
opposite failure direction, and the difference is stated here so neither one gets "fixed" into the
other.
"""

from __future__ import annotations

from types import TracebackType
from typing import Optional

from corpusfm.core import proc_lock

from .errors import LockNotHeld, LockUnavailable
from .layout import LifecycleLayout


class LifecycleLock:
    """Exclusive authority to mutate this machine's lifecycle state."""

    def __init__(self, layout: LifecycleLayout):
        self._layout = layout
        self._lock = proc_lock.ProcessLock(layout.lock_file)

    @property
    def layout(self) -> LifecycleLayout:
        return self._layout

    @property
    def held(self) -> bool:
        return self._lock.held

    @property
    def path(self) -> str:
        return str(self._layout.lock_file)

    def acquire(self) -> "LifecycleLock":
        outcome = self._lock.try_acquire()
        if outcome == proc_lock.ACQUIRED:
            return self
        if outcome == proc_lock.HELD:
            raise LockUnavailable(
                f"another CORPUSfm lifecycle operation holds {self.path}; wait for it to finish"
            )
        raise LockUnavailable(
            f"the CORPUSfm lifecycle lock at {self.path} could not be evaluated; refusing to "
            "mutate this installation without proof that no other operation is running"
        )

    def release(self) -> None:
        self._lock.release()

    def assert_held(self, action: str) -> None:
        """Raise ``LockNotHeld`` unless this lock is currently ours."""
        if not self.held:
            raise LockNotHeld(
                f"{action} requires the held CORPUSfm lifecycle lock ({self.path})"
            )

    def __enter__(self) -> "LifecycleLock":
        return self.acquire()

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.release()


def require_lock(lock: object, action: str) -> LifecycleLock:
    """Accept only a genuinely held ``LifecycleLock``.

    Every mutator in this package takes its authority as an argument rather than checking a global.
    That is what makes "the application may read lifecycle state but never mutate the manifest" a
    property of the API's shape instead of a convention a caller can forget: application code has no
    held lock to pass, and passing anything else fails here.
    """
    if not isinstance(lock, LifecycleLock):
        raise LockNotHeld(f"{action} requires a LifecycleLock, got {type(lock).__name__}")
    lock.assert_held(action)
    return lock
