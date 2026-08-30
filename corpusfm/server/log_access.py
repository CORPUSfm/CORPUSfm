"""Bounded, read-only catalog and tail reader for the approved server log roots (packet 1360-01).

Two directories are in scope and nothing else: FileMaker Server's ``Logs`` directory and CORPUSfm's own
log directory. A caller names a source by an opaque id this module minted; it can never hand in a path.

Deliberately separate from ``corpusfm.app.web.log_reader``. That module serves ``/api/logs`` for one
known file family and its behaviour is not being changed under this packet, so the small reverse-read
primitive is duplicated here rather than shared. Sharing can be reconsidered once behavioural
equivalence is proven, which is a different packet.

**No redaction (developer ruling, 2026-08-29).** Approved log text is returned verbatim. These are
administrator-gated troubleshooting tools and the application is not the policy authority for what
FileMaker Server or CORPUSfm wrote. Decoding, complete-line handling, the caller's own filter and the
output ceiling are the only things that shape the return. An "improvement" that scrubs, masks or drops
content is a regression against that ruling — the disclosure controls are the two MCP gate rails and the
approved-root fence, enforced by packet 1360-02 and by this module respectively.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat as _stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Bytes of log data one request may EXAMINE. Measured, not chosen for roundness (packet 1360-01 census,
# 2026-08-29): the largest real rotation family on `w-test-private` is TopCallStats at 67.34 MiB, so a
# 64 MiB budget would make an exhaustive search of the two families most worth searching report
# `search_complete: false`. 128 MiB is the next power of two above the measured maximum. It bounds work,
# never memory — reads are fixed-size chunks regardless.
SCAN_BUDGET_BYTES = 128 * 1024 * 1024

MAX_LINES = 2000
DEFAULT_LINES = 200
MAX_OUTPUT_BYTES = 256 * 1024
MAX_CONTAINS_CHARS = 200
_CHUNK = 65536

_OWNER_FMS = "fms"
_OWNER_CORPUSFM = "corpusfm"

# `X.log.1`, `X.log.23` — a positive integer only, so `X.log.old` is handled by its own rule and
# `X.log.0` is not treated as a rotation.
_NUMBERED = re.compile(r"^(?P<base>.+\.log)\.(?P<n>[1-9][0-9]*)$")


class LogAccessError(Exception):
    """A request this module refuses. The message is safe to return to the caller."""


class UnknownSource(LogAccessError):
    pass


class InvalidArgument(LogAccessError):
    pass


@dataclass(frozen=True)
class _Member:
    member_id: str
    name: str
    path: Path
    size_bytes: int
    modified_utc: str
    readable: bool
    current: bool
    mtime: float
    # The identity the CATALOG saw. Revalidating only across the lstat→open window would leave the
    # wider catalog→read window unchecked: the caller would be handed the new file's content beside
    # the old file's size and timestamp, with nothing saying they disagree.
    dev: int
    ino: int


@dataclass(frozen=True)
class _Source:
    source_id: str
    owner: str
    family: str
    available: bool
    reason: str | None
    members: tuple[_Member, ...]


@dataclass(frozen=True)
class _Root:
    owner: str
    path: Path | None
    reason: str | None


def _oid(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


# ── root resolution ───────────────────────────────────────────────────────────────────────────

def _corpusfm_root() -> _Root:
    from corpusfm.lifecycle.app_paths import log_dir

    try:
        return _Root(_OWNER_CORPUSFM, Path(log_dir()), None)
    except Exception:
        # A development layout or an unpublished/disputed installation. Unavailable is a real state and
        # is reported as one; it is never a licence to guess at a home directory.
        return _Root(_OWNER_CORPUSFM, None, "root_not_published")


def _fms_root() -> _Root:
    from corpusfm.lifecycle.proxy_inventory import fms_installation_root
    from corpusfm.lifecycle.published import read_published_installation

    try:
        published = read_published_installation()
    except Exception:
        return _Root(_OWNER_FMS, None, "root_not_published")

    recorded = getattr(published, "fms_root", None)
    if not recorded:
        return _Root(_OWNER_FMS, None, "root_not_recorded")

    # Route (a), developer ruling 2026-08-29. On Windows the manifest records the 'Database Server'
    # directory, and `…\Database Server\Logs` DOES NOT EXIST — measured on w-test-private, where only
    # `…\FileMaker Server\Logs` is present. This resolver derives the enclosing root from FMS-owned
    # evidence markers, never from a basename, and returns a POSIX root unchanged, so this call is not
    # platform-conditional. It is the ONLY derivation permitted: no disk search, no fallback root.
    root = fms_installation_root(recorded)
    if root is None:
        return _Root(_OWNER_FMS, None, "root_not_recorded")
    return _Root(_OWNER_FMS, Path(root) / "Logs", None)


def approved_root(owner: str, path) -> _Root:
    """An explicitly supplied root, for tests and for a caller that already holds approved authority.

    This is the injectable-root path packet 1360-01 requires. It is NOT a way for an MCP caller to name
    a directory: the MCP wrappers call `list_server_logs()` / `read_server_log()` with no roots argument,
    so production resolution always goes through the two authorities above.
    """
    if owner not in (_OWNER_FMS, _OWNER_CORPUSFM):
        raise InvalidArgument("owner must be 'fms' or 'corpusfm'")
    return _Root(owner, Path(path), None)


def _production_roots() -> list[_Root]:
    return [_fms_root(), _corpusfm_root()]


# ── family classification ─────────────────────────────────────────────────────────────────────

def _classify(name: str) -> tuple[str, bool] | None:
    """``(family, is_current)`` for a name we admit, or ``None`` for one we do not catalog.

    Only `.log` families are admitted (Codex ruling, 2026-08-29). The census found a 7.5 MB
    `fmserver.exe.*.dmp` crash dump sitting in FMS's Logs directory; decoding a binary dump into "lines"
    would be misleading, and the contract's family vocabulary is `.log`-only. Uncatalogued files are
    surfaced as an anonymous COUNT in `warnings` — never a name, never silently dropped.

    **This is SOURCE SCOPING, not log-content redaction.** The no-redaction ruling in the module
    docstring governs the text of an approved log, and nothing inside a catalogued log is altered or
    withheld. It does not make a memory dump a log. The object out of scope here is the FILE, not any
    part of a file's contents.
    """
    if name.endswith(".lck"):
        return None
    if name.endswith("-old.log"):
        return name[: -len("-old.log")] + ".log", False
    if name.endswith(".log.old"):
        return name[: -len(".old")], False
    m = _NUMBERED.match(name)
    if m:
        return m.group("base"), False
    if name.endswith(".log"):
        return name, True
    return None


# ── filesystem acceptance ─────────────────────────────────────────────────────────────────────

def _is_reparse(st: os.stat_result) -> bool:
    return bool(getattr(st, "st_file_attributes", 0)
                & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _accept(root: Path, name: str) -> tuple[Path, os.stat_result] | None:
    """A no-follow, containment-checked acceptance of one immediate child, or ``None``.

    **A candidate with more than one hard link is REFUSED (Codex ruling, 2026-08-29, finding F3).** A
    hardlink is indistinguishable from an ordinary file to `lstat`, and `O_NOFOLLOW` does not apply to
    one, so a link placed in an approved root reads a file from outside it — proven by review. The
    approved source model is the two directories, and a second name for a file elsewhere is not in it.
    We do not try to work out which link is canonical and we expose no other path: the entry is simply
    not catalogued, and it joins the anonymous "not an ordinary file" count.

    Measured before adopting the refusal, so it excludes nothing real (Codex, 2026-08-29, read-only, no
    contents): every observed `.log`-family member had link count 1 — all of them on `u-test-private`,
    and all 11 on `w-test-private`.
    """
    if not name or name in (".", "..") or os.sep in name or (os.altsep and os.altsep in name):
        return None
    path = root / name
    if path.parent != root:
        return None
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not _stat.S_ISREG(st.st_mode) or _is_reparse(st) or st.st_nlink > 1:
        return None
    return path, st


def _readable(path: Path) -> bool:
    """Probe by opening. `os.access` answers about mode bits, not about a Windows ACL or a writer's
    share mode — and the census measured FMS holding its busiest logs open, so the honest answer needs
    a real open."""
    try:
        fd = _open_nofollow(path)
    except OSError:
        return False
    os.close(fd)
    return True


def _open_nofollow(path: Path) -> int:
    """Open read-only without following a link.

    Windows has no `O_NOFOLLOW`; the reparse-point rejection in `_accept` plus the post-open identity
    revalidation cover it there. The share mode is deliberately CPython's default (`_SH_DENYNO`):
    measured on w-test-private, FileMaker Server holds `Stats.log`, `fmodata.log` and
    `TopCallStats.log` open for writing, and any narrower share mode is DENIED on exactly the files an
    administrator most wants to read.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    return os.open(path, flags)


def _same_identity(dev: int, ino: int, opened: os.stat_result) -> bool:
    """Is the opened handle the file the catalog accepted?

    A zero inode means the platform did not give us an identity, NOT that the file is a different one.
    Treating it as a mismatch would fail every read on such a platform — a fail-closed break that could
    only appear where it cannot be tested from here. When identity is unavailable the residual risk is
    a same-NAME replacement inside an approved root (a rotation), not an escape: the path came from the
    root's own listing and reparse points and non-regular files were already rejected before the open,
    and the post-open type check below still runs.
    """
    if ino == 0 or opened.st_ino == 0:
        return True
    return (dev, ino) == (opened.st_dev, opened.st_ino)


# ── catalog ───────────────────────────────────────────────────────────────────────────────────

def build_catalog(roots: list[_Root] | None = None) -> tuple[list[_Source], list[str]]:
    """Rebuilt on every call, by contract: an id must not outlive the approved boundary."""
    sources: list[_Source] = []
    warnings: list[str] = []

    for root in (roots if roots is not None else _production_roots()):
        if root.path is None:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False,
                                   root.reason or "root_not_published", ()))
            continue
        # F4 (Codex ruling, 2026-08-29). The FINAL log-root directory must be an ordinary real
        # directory: a symlinked, junctioned or reparse-point root is reported unavailable and is never
        # enumerated through, resolved, or followed. Measured before adopting it, so it excludes no real
        # deployment (Codex, 2026-08-29, read-only): `/opt/FileMaker/FileMaker Server/Logs` on
        # `u-test-private` is type=directory and not a symlink, and the Windows root on
        # `w-test-private` reports `Attributes=Directory` with an empty LinkType and Target.
        try:
            root_st = os.lstat(root.path)
        except OSError:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False, "root_missing", ()))
            continue
        if not _stat.S_ISDIR(root_st.st_mode) or _is_reparse(root_st):
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False,
                                   "root_not_a_real_directory", ()))
            continue

        try:
            names = sorted(os.listdir(root.path))
        except NotADirectoryError:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False, "root_not_a_directory", ()))
            continue
        except FileNotFoundError:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False, "root_missing", ()))
            continue
        except PermissionError:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False, "permission_denied", ()))
            continue
        except OSError:
            sources.append(_Source(_oid(root.owner, "*"), root.owner, "*", False, "root_unreadable", ()))
            continue

        families: dict[str, list[_Member]] = {}
        skipped = 0
        rejected = 0
        for name in names:
            accepted = _accept(root.path, name)
            if accepted is None:
                # Counted SEPARATELY from "not a log". This is where a symlink, a junction, a
                # directory or a device lands, and telling an administrator that a rejected symlink
                # named `Event.log` is "not a log" hides the one rejection they would want to know
                # about. The reason is stated; the name is not, because a name here is attacker-chosen.
                if not name.endswith(".lck"):
                    rejected += 1
                continue
            path, st = accepted
            classified = _classify(name)
            if classified is None:
                if not name.endswith(".lck"):
                    skipped += 1
                continue
            family, current = classified
            families.setdefault(family, []).append(_Member(
                member_id=_oid(root.owner, name),
                name=name,
                path=path,
                size_bytes=st.st_size,
                modified_utc=_utc(st.st_mtime),
                readable=_readable(path),
                current=current,
                mtime=st.st_mtime,
                dev=st.st_dev,
                ino=st.st_ino,
            ))
        if skipped:
            warnings.append(f"{root.owner}: {skipped} file(s) in the log root are not logs and were not cataloged")
        if rejected:
            warnings.append(f"{root.owner}: {rejected} entr(y/ies) were refused as not being an ordinary "
                            f"file — a link, reparse point, directory or device is never followed")

        for family, members in sorted(families.items()):
            ordered = sorted(members, key=lambda m: (not m.current, -m.mtime, m.name))
            sources.append(_Source(_oid(root.owner, family), root.owner, family, True, None, tuple(ordered)))

    return sources, warnings


def list_server_logs(roots: list[_Root] | None = None) -> dict:
    sources, warnings = build_catalog(roots)
    return {
        "sources": [
            {
                "source_id": s.source_id,
                "owner": s.owner,
                "family": s.family,
                "available": s.available,
                "reason": s.reason,
                "members": [
                    {
                        "member_id": m.member_id,
                        "name": m.name,
                        "size_bytes": m.size_bytes,
                        "modified_utc": m.modified_utc,
                        "readable": m.readable,
                        "current": m.current,
                    }
                    for m in s.members
                ],
            }
            for s in sources
        ],
        "warnings": warnings,
    }


# ── bounded backward reading ──────────────────────────────────────────────────────────────────

class _Budget:
    def __init__(self, total: int | None = None) -> None:
        # Read at construction, never bound as a default argument: the module constant is the single
        # place the measured number lives, and a default would freeze a copy of it at import.
        self.left = SCAN_BUDGET_BYTES if total is None else total
        self.stopped = False

    def take(self, n: int) -> int:
        if n > self.left:
            self.stopped = True
            n = self.left
        self.left -= n
        return n


class _LineTooLong(Exception):
    """A single physical line exceeded what the output could hold, so the scan stopped there."""


def _iter_lines_backward(fd: int, size: int, budget: _Budget, max_line: int):
    """Yield ``(text_bytes, at_file_start)`` newest-first, reading fixed chunks and never the whole file.

    A line is never decoded until it is complete, so a multibyte UTF-8 sequence spanning a chunk
    boundary cannot be split. Raises ``OSError`` if the file shrinks under the read — a concurrent
    rotation is reported as a member failure, never as a short answer that looks complete.

    ``max_line`` is what makes "never reads an entire file into memory" TRUE rather than merely usual.
    The partial line being reassembled is the one unbounded structure here: a member with no newline
    in its trailing region — a corrupt log, or a writer emitting one enormous record — would otherwise
    grow it to the whole file, and `chunk + tail` would transiently double that. Such a line cannot be
    returned anyway (the output ceiling would drop it), so the scan stops at it and the caller is told
    the result was cut. Found by review, 2026-08-29; the module comment had claimed the opposite.
    """
    if size == 0:
        return
    pos = size
    tail = b""
    first = True
    while pos > 0:
        want = min(_CHUNK, pos)
        granted = budget.take(want)
        if granted <= 0:
            return
        pos -= granted
        os.lseek(fd, pos, os.SEEK_SET)
        chunk = os.read(fd, granted)
        if len(chunk) < granted:
            raise OSError("the log file shrank while it was being read")
        buf = chunk + tail
        if first:
            first = False
            if buf.endswith(b"\n"):        # the file's own final terminator, not an empty last line
                buf = buf[:-1]
        parts = buf.split(b"\n")
        tail = parts[0]
        for part in reversed(parts[1:]):
            yield part, False
        if len(tail) > max_line:
            raise _LineTooLong
        if budget.stopped:
            return
    yield tail, True


def _decode(raw: bytes, at_start: bool) -> str:
    text = raw.decode("utf-8", errors="replace")
    if text.endswith("\r"):                 # CRLF is universal on Windows (census, 2026-08-29)
        text = text[:-1]
    if at_start and text.startswith("﻿"):
        # A UTF-8 BOM is an encoding marker, not log text. Measured on fmodata.log / fmodata.log.1 /
        # scriptEvent.log. Stripped ONLY at file offset 0, so nothing inside a record is touched.
        text = text[1:]
    return text


def _read_member(member: _Member, *, needed: int, contains: str | None, budget: _Budget,
                 out: list[str], out_bytes: int, ceiling: int) -> tuple[int, bool, bool, str | None]:
    """Collect newest-first from one member. Returns (out_bytes, truncated, exhausted, failure)."""
    try:
        fd = _open_nofollow(member.path)
    except OSError:
        return out_bytes, False, False, "unreadable"
    try:
        st_open = os.fstat(fd)
        if (not _stat.S_ISREG(st_open.st_mode)
                or not _same_identity(member.dev, member.ino, st_open)
                or st_open.st_nlink != 1):
            # Replaced or rotated between catalog and open, or a second link appeared after the catalog
            # accepted it (Codex ruling, 2026-08-29, F3 — revalidated here, not only at catalog time).
            # Not an escape and not content: a structured failure, which falsifies `search_complete`.
            return out_bytes, False, False, "changed_during_read"
        needle = contains.lower() if contains else None
        try:
            for raw, at_start in _iter_lines_backward(fd, st_open.st_size, budget, ceiling):
                if len(out) >= needed:
                    return out_bytes, False, True, None
                text = _decode(raw, at_start)
                if needle is not None and needle not in text.lower():
                    continue
                cost = len(text.encode("utf-8")) + 1
                if out_bytes + cost > ceiling:
                    # The newest complete lines are retained; this older one is dropped. The result is
                    # cut, so it is neither satisfied nor exhausted — `truncated` says why.
                    return out_bytes, True, False, None
                out.append(text)
                out_bytes += cost
        except _LineTooLong:
            return out_bytes, True, False, None
        except OSError:
            return out_bytes, False, False, "changed_during_read"
        return out_bytes, False, not budget.stopped, None
    finally:
        os.close(fd)


def read_server_log(source_id: str, member_id: str | None = None, lines: int = DEFAULT_LINES,
                    contains: str | None = None, roots: list[_Root] | None = None,
                    max_output_bytes: int | None = None) -> dict:
    """Bounded tail of one approved log family.

    ``max_output_bytes`` lowers the contract ceiling for a transport that cannot carry it — the MCP
    wrapper passes one, because the shared response-size middleware would otherwise byte-truncate the
    serialized JSON into something unparseable. It can only ever LOWER the ceiling.
    """
    if not isinstance(lines, int) or isinstance(lines, bool):
        raise InvalidArgument("lines must be an integer")
    if not 1 <= lines <= MAX_LINES:
        raise InvalidArgument(f"lines must be between 1 and {MAX_LINES}")
    if contains is not None:
        if not isinstance(contains, str):
            raise InvalidArgument("contains must be text")
        if len(contains) > MAX_CONTAINS_CHARS:
            raise InvalidArgument(f"contains must be at most {MAX_CONTAINS_CHARS} characters")
        if contains == "":
            contains = None

    # A FRESH catalog, by contract: an id minted before a root moved must not resolve afterwards.
    sources, _ = build_catalog(roots)
    source = next((s for s in sources if s.source_id == source_id), None)
    if source is None:
        raise UnknownSource("no such log source")
    if not source.available:
        raise UnknownSource("that log source is not available")

    if member_id:
        selected = [m for m in source.members if m.member_id == member_id]
        if not selected:
            raise UnknownSource("that member does not belong to this source")
    else:
        selected = list(source.members)

    ceiling = MAX_OUTPUT_BYTES if max_output_bytes is None else min(MAX_OUTPUT_BYTES, max_output_bytes)
    if ceiling < 1:
        raise InvalidArgument("max_output_bytes must be positive")

    budget = _Budget()
    collected: list[str] = []
    out_bytes = 0
    truncated = False
    failures: list[dict] = []
    exhausted_all = True

    for member in selected:
        if len(collected) >= lines or budget.stopped or truncated:
            # `truncated` joins the stop conditions because once the ceiling is reached every further
            # line is rejected on arrival — continuing would back-scan whole rotations, under a filter
            # up to the entire scan budget, to collect nothing.
            exhausted_all = False
            break
        out_bytes, cut, exhausted, failure = _read_member(
            member, needed=lines, contains=contains, budget=budget,
            out=collected, out_bytes=out_bytes, ceiling=ceiling)
        truncated = truncated or cut
        if failure is not None:
            failures.append({"member_id": member.member_id, "reason": failure})
            exhausted_all = False
        elif not exhausted:
            exhausted_all = False

    # A request can be "satisfied" by line COUNT while the newest member was unreadable or the output
    # was cut — and the first draft returned `search_complete: true` in exactly that case, beside a
    # non-empty `failures` list, because `satisfied or …` short-circuited the guard written next to it.
    # Found by review, 2026-08-29. Authoritative now means: nothing was missed, by any route.
    satisfied = len(collected) >= lines
    complete = ((satisfied or exhausted_all)
                and not failures and not truncated and not budget.stopped)
    return {
        "source_id": source.source_id,
        "selected_members": [m.member_id for m in selected],
        "lines": list(reversed(collected)),
        "requested_lines": lines,
        "returned_lines": len(collected),
        "truncated": truncated,
        # True only when the answer is authoritative: the request was satisfied, or the family was
        # examined to its start — and in either case nothing was skipped, failed or cut.
        "search_complete": bool(complete),
        "failures": failures,
    }
