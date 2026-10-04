"""The one durable-write primitive every lifecycle record uses (packet 1246-01).

Four ordered steps, and the order is the whole point:

1. write the complete new content to a **sibling** temporary in the destination directory — a
   sibling, because ``os.replace`` is only atomic within one filesystem;
2. ``flush`` + ``fsync`` the temporary, so its bytes are on the device before anything points at them;
3. ``os.replace`` — the instant at which a reader starts seeing the new content, and the only instant
   at which it can see anything other than the complete old content;
4. ``fsync`` the containing **directory**, so the rename itself survives power loss.

Step 4 is the one usually left out, and leaving it out is how a record that "was written" is missing
after a crash: the file's bytes were durable but the directory entry naming them was not.

The house idiom this follows is already in ``server/update_service.py`` and ``server/db_helper.py``;
what is added here is the directory fsync and the mode-at-creation, because these files are
machine-wide state rather than application scratch.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path


def atomic_write_text(
    target: Path, content: str, *, mode: int = 0o600, dir_mode: int | None = None,
    replace_retry: tuple[float, ...] = (),
) -> None:
    """Durably replace ``target`` with ``content``. Never leaves a partial file at ``target``."""
    atomic_write_bytes(target, content.encode("utf-8"), mode=mode, dir_mode=dir_mode,
                       replace_retry=replace_retry)


def atomic_write_bytes(
    target: Path, payload: bytes, *, mode: int = 0o600, dir_mode: int | None = None,
    prepare=None, replace_retry: tuple[float, ...] = (),
) -> None:
    """The byte-level form. Copying a file must go through here too, not ``shutil.copy2``.

    A plain copy writes straight onto the destination: interrupt it and the destination holds a
    prefix of the source, which is exactly the "complete old or complete new, never a truncated
    thing that parses far enough" property this module exists to provide. It is the same rule for
    the retained manifest generation as for the manifest itself.

    ``prepare`` is called with the **staged temporary** after its bytes are durable and before the
    replace. It exists so ownership and access protection can be established on the artifact
    *before* anything at the destination path points at it — a file published first and secured
    afterwards is readable by whoever gets there in between, and on a shared destination that window
    is the whole problem. A ``prepare`` that raises aborts the write and leaves the destination
    untouched, which is the same guarantee as a failed write.

    ``replace_retry`` is a bounded schedule of pauses before re-attempting a rename that raised
    ``PermissionError``. On Windows that was measured while another process held the destination
    open: a Python reader with the default share mode, and a .NET reader sharing ReadWrite|Delete.
    Only the rename is retried; the staged temporary stays durable throughout, and when the schedule
    is spent the last error is raised and the destination still holds the complete old content.
    """
    target = Path(target)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    if dir_mode is not None:
        try:
            os.chmod(parent, dir_mode)
        except OSError:
            pass
    fd, tmp_name = tempfile.mkstemp(
        dir=str(parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        if prepare is not None:
            prepare(tmp)
        _replace(tmp, target, replace_retry)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    _fsync_dir(parent)


def _replace(tmp: Path, target: Path, delays: tuple[float, ...]) -> None:
    for delay in delays:
        try:
            os.replace(str(tmp), str(target))
            return
        except PermissionError:
            time.sleep(delay)
    os.replace(str(tmp), str(target))


def _fsync_file(path: Path) -> None:
    """Force one file's bytes to the device. Used where content is copied rather than staged."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _fsync_dir(directory: Path) -> None:
    """Make a rename durable. A no-op where the platform does not permit it (Windows)."""
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
