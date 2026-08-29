"""Read the tail of the CORPUSfm log across its rotations, without loading a file (packet 1344).

WHAT WAS WRONG. `GET /api/logs` read only `corpusfm.log`, so three quarters of the retained history —
`.1`, `.2`, `.3` — was unreachable from the Logs page; on a live box the current file covered about
four hours during an incident that started earlier. It filtered by testing whether the level word
appeared ANYWHERE in the line, so a message mentioning `ERROR` filtered as one. And it called
`read_text().splitlines()` to return the last 100 lines: 3.8 MB read for 100 lines, and 5 MB just
before a rotation — worst exactly when someone is most likely to be reading it.

WHAT THIS GUARANTEES. Fixed chunk memory, never a whole-file read, and an early stop as soon as enough
selected lines are known. It does NOT promise to touch few bytes: if a requested level is sparse or
absent, answering honestly means looking at all of it. Bounded memory is the guarantee; bounded work
is not one it can make and should not pretend to.

RECORDS, NOT LINES. The shipped formatter is
``%(asctime)s %(levelname)-8s %(name)s: %(message)s``. A physical line that does not start with that
prefix is a CONTINUATION of the record above it — a traceback frame, a wrapped message — and inherits
that record's level. Without this a filtered view would show a warning's first line and drop its
traceback, which is the half that explains it.
"""
from __future__ import annotations

import re
from pathlib import Path

#: Anchored on the shipped formatter: date, time, padded uppercase level, logger, message.
_RECORD = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} ([A-Z]+)\s")

LEVELS = ("ALL", "WARNING", "ERROR")
MAX_LINES = 5000                 #: matches the page's largest option; a hard server-side ceiling
_CHUNK = 64 * 1024

#: A record's continuation lines are held until its header is reached (we read backwards). A single
#: pathological record — a huge traceback, a dumped payload — would otherwise accumulate a whole
#: member into memory even for `lines=1`, which contradicts the fixed-memory guarantee this module
#: makes (found by Codex review, 2026-08-26). Beyond this many held lines the OLDEST are dropped and
#: the truncation is reported, because silently returning a trimmed traceback would be worse.
_MAX_PENDING = 2000


class LogReadError(RuntimeError):
    """Every member of the rotation family failed to read — which is not the same as an empty log."""


def parse_level(line: str) -> str:
    """The record's own level, or "" for a continuation/malformed line."""
    m = _RECORD.match(line)
    return m.group(1) if m else ""


def _selects(level: str, record_level: str) -> bool:
    if level == "ALL":
        return True
    return record_level == level


def _iter_lines_backward(path: Path):
    """Yield a file's lines newest-first, reading fixed-size chunks from the end."""
    with path.open("rb") as fh:
        fh.seek(0, 2)
        pos = fh.tell()
        tail = b""
        while pos > 0:
            size = min(_CHUNK, pos)
            pos -= size
            fh.seek(pos)
            block = fh.read(size) + tail
            parts = block.split(b"\n")
            tail = parts.pop(0)          # may be an incomplete line; it belongs to the next chunk
            for raw in reversed(parts):
                yield raw.decode("utf-8", errors="replace")
        if tail:
            yield tail.decode("utf-8", errors="replace")


def _prime(gen):
    """Pull the first item so the generator's `open()` happens inside the caller's try/except."""
    import itertools
    try:
        head = next(gen)
    except StopIteration:
        return iter(())
    return itertools.chain([head], gen)


def read_tail(members, *, lines: int, level: str) -> tuple:
    """The newest `lines` physical lines matching `level`, oldest-first.

    `members` is newest → oldest. Returns ``(lines, read_members, failures)``.
    """
    if lines < 1 or lines > MAX_LINES:
        raise ValueError(f"lines must be 1..{MAX_LINES}")
    if level not in LEVELS:
        raise ValueError(f"level must be one of {', '.join(LEVELS)}")

    collected: list = []             # newest-first
    pending: list = []               # continuation lines awaiting their record's level (bounded)
    truncated = False
    read_members: list = []
    failures: list = []

    for path in members:
        if len(collected) >= lines:
            break                    # early stop: older history cannot be newer
        try:
            if not path.exists():
                continue
            member_lines = _iter_lines_backward(path)
            # Force the open NOW. `_iter_lines_backward` is a generator, so without this the file is
            # not opened until the first `next()` — and a member that cannot be opened was being
            # counted as successfully read, which would report an unreadable log as an empty one.
            member_lines = _prime(member_lines)
            read_members.append(path)
            first = True
            for line in member_lines:
                if first:
                    first = False
                    if line == "":
                        continue       # the trailing newline's empty final line, not a record
                rec_level = parse_level(line)
                if not rec_level:
                    # A continuation, or a malformed standalone line. Held until its record appears
                    # (we are reading backwards, so the record comes AFTER it here).
                    if len(pending) >= _MAX_PENDING:
                        if not truncated:
                            truncated = True
                            pending.append(f"… [continuation truncated at {_MAX_PENDING} lines]")
                        continue          # bounded: drop the OLDEST, keep what is nearest the record
                    pending.append(line)
                    continue
                if _selects(level, rec_level):
                    # `collected` is NEWEST-first, and a continuation is NEWER than the record it
                    # belongs to, so the held lines go in BEFORE the record. Reversed at the boundary
                    # this yields record-then-its-traceback, which is how it was written.
                    collected.extend(pending)
                    collected.append(line)
                elif level == "ALL":
                    collected.extend(pending)
                pending.clear()
                if len(collected) >= lines:
                    break
        except OSError as exc:
            # A member that vanished mid-rotation, or is unreadable, is not evidence that the log is
            # empty. Record it and keep going into older history.
            failures.append(f"{path.name}: {exc}")
            continue

    if level == "ALL" and pending and len(collected) < lines:
        collected.extend(pending)     # leading malformed lines stay visible under ALL

    if not read_members and failures:
        raise LogReadError("; ".join(failures))

    # Trim the OLDEST excess so newer diagnostic context wins, then flip to oldest-first.
    return list(reversed(collected[:lines])), read_members, failures
