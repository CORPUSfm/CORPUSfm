"""Cross-platform, kernel-owned single-holder process lock (packet 1001 / concept A).

An OS **advisory** lock held for a process's whole life. Its one property that matters: the kernel
releases it the instant the holder dies — crash or clean exit — so liveness is FREE (no heartbeat, no
staleness timeout, no clock). CORPUSfm uses it to make "exactly one worker-host process drains the
QUEUE" a provable, self-healing runtime fact instead of an implicit deployment assumption.

Same-box only — which is exactly (and only) CORPUSfm's contention space (a second box pointed at the
same storage DB is not offered and can't work). POSIX uses ``fcntl.flock``; Windows uses
``msvcrt.locking`` — both are dropped by the OS when the process exits or the handle closes.

``try_acquire`` returns one of three outcomes so the caller can apply the packet's fail policy:
- ``ACQUIRED`` — this process is the holder (the handle is kept alive on the instance for life);
- ``HELD``     — another LIVE process owns it → stand down (fail CLOSED);
- ``ERROR``    — the lock couldn't be evaluated (unwritable dir, odd FS) → the caller should fail
                 OPEN (proceed, log a warning) rather than refuse to work over a missing guard.
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

log = logging.getLogger("corpusfm.proc_lock")

ACQUIRED = "acquired"
HELD = "held"
ERROR = "error"

# errno values that mean "another holder has it" (contention) rather than a real fault.
_CONTENDED = {errno.EACCES, errno.EAGAIN, getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
              getattr(errno, "EDEADLK", 36)}

if os.name == "nt":                                          # pragma: no cover - platform-specific
    import msvcrt

    def _lock_nb(fd: int) -> None:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def _unlock(fd: int) -> None:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _lock_nb(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass


class ProcessLock:
    """A single-holder lock on ``path``. Non-blocking. Keep the instance alive for as long as you
    want to hold the lock — dropping/closing it (or the process dying) releases it."""

    def __init__(self, path: "str | Path"):
        self._path = Path(path)
        self._fd: "int | None" = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def try_acquire(self) -> str:
        """Attempt the lock once, non-blocking. Returns ``ACQUIRED`` / ``HELD`` / ``ERROR``."""
        if self._fd is not None:
            return ACQUIRED                                  # already ours (idempotent)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self._path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            log.debug("proc_lock: cannot open %s", self._path, exc_info=True)
            return ERROR
        try:
            _lock_nb(fd)
        except OSError as exc:
            os.close(fd)
            return HELD if exc.errno in _CONTENDED else ERROR
        except Exception:                                    # pragma: no cover - defensive
            os.close(fd)
            return ERROR
        self._fd = fd
        return ACQUIRED

    def release(self) -> None:
        """Release + close (idempotent). The OS would do this on process exit anyway."""
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        _unlock(fd)
        try:
            os.close(fd)
        except OSError:
            pass
