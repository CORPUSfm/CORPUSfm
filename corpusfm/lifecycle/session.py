"""Starting a lifecycle operation (packet 1246-01, deliverable 4).

The packet's rule is *"a second operation refuses while the lock/journal requires recovery"* — one
sentence naming two gates. Building them as two independent objects left a hole an independent review
found: a caller could acquire the lock, skip ``Journal.begin()`` entirely, and mutate the manifest
while an earlier interrupted operation still had unresolved work recorded. The lock alone cannot see
that, because a crash releases it — that is the whole point of a kernel-owned lock — so after a crash
the lock says "free" and the journal says "recovery owed", and only one of them is right.

So the two gates get one door. ``lifecycle_operation`` acquires the lock, then refuses on an
unresolved journal, and hands back both. Recovery work passes ``recovering=True`` — the one caller
that is *supposed* to open over an unresolved record, and it says so explicitly rather than by
omission.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from .journal import Journal
from .layout import LifecycleLayout
from .lock import LifecycleLock


@dataclass(frozen=True)
class LifecycleSession:
    """The authority and the evidence trail for one lifecycle operation."""

    lock: LifecycleLock
    journal: Journal
    layout: LifecycleLayout


@contextmanager
def lifecycle_operation(
    layout: LifecycleLayout, *, recovering: bool = False
) -> Iterator[LifecycleSession]:
    """Hold the machine lifecycle lock for one operation, refusing over unresolved work.

    Raises ``LockUnavailable`` when another operation holds the lock or the lock cannot be
    evaluated, and ``RecoveryRequired`` when an earlier operation left work unresolved and this one
    did not declare itself a recovery.
    """
    lock = LifecycleLock(layout)
    lock.acquire()
    try:
        journal = Journal(layout)
        if not recovering:
            journal.assert_clear()
        yield LifecycleSession(lock=lock, journal=journal, layout=layout)
    finally:
        lock.release()
