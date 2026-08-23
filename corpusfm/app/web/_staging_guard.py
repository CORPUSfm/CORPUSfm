"""Shared disk guard for the LOCAL reabsorb staging area (`_reabsorb_staging`) — packet 056.

The reabsorb flow stages raw `.artifact` bytes locally (each ≤ 1 GB) before the server validates + stores
them. On a dev/staging box with a small disk that can fill up. This refuses a stage when it would push the
box below a free-disk floor OR over a total staging-dir budget, so a big drop can't exhaust the disk out
from under FMS/CORPUSfm. Local-FS bounds only; sane constants, no config required. Callers TTL-sweep before
staging, so the budget reflects genuinely in-flight bytes.

(Packet 060 retired the IMPORT staging path — imports now land as durable pending storage records with no
local staging — so this guard now protects only reabsorb.)
"""
from __future__ import annotations

import shutil
from pathlib import Path

# Keep at least this much disk free after the stage, and cap the whole staging dir. Conservative defaults
# tuned for a modest dev box; both are hard local bounds, not tunables.
FREE_FLOOR_BYTES = 2 * 1024 * 1024 * 1024   # 2 GB headroom
DIR_BUDGET_BYTES = 5 * 1024 * 1024 * 1024   # 5 GB total across the staging dir


class StagingSpaceError(RuntimeError):
    """Raised when staging a file would exhaust local disk or the staging budget."""


def _dir_size(directory: Path) -> int:
    total = 0
    try:
        entries = list(directory.glob("*"))
    except OSError:
        return 0
    for p in entries:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    return total


def ensure_space(directory: Path, incoming: int) -> None:
    """Raise StagingSpaceError if staging `incoming` bytes into `directory` would drop free disk below
    the floor or push the dir over budget. A transient stat failure never blocks (fail-open on I/O error —
    the 1 GB per-file cap + TTL sweep are the backstops)."""
    try:
        free = shutil.disk_usage(directory).free
    except OSError:
        return
    if free - incoming < FREE_FLOOR_BYTES:
        raise StagingSpaceError(
            "Not enough free disk to stage this import — free up space or wait for in-flight imports "
            "to finish, then retry."
        )
    if _dir_size(directory) + incoming > DIR_BUDGET_BYTES:
        raise StagingSpaceError(
            "Local staging is full — wait for in-flight imports to finish, then retry (or use fewer / "
            "smaller files)."
        )
