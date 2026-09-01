"""Bounded, read-only catalog and tail reader for the approved server log roots (packet 1360-01).

Two directories are in scope and nothing else: FileMaker Server's ``Logs`` directory and CORPUSfm's own
log directory. A caller names a source by an opaque id this module minted; it can never hand in a path.

Deliberately separate from ``corpusfm.app.web.log_reader``. That module serves ``/api/logs`` for one
known file family and its behaviour is not being changed under this packet, so the small reverse-read
primitive is duplicated here rather than shared. Sharing can be reconsidered once behavioural
equivalence is proven, which is a different packet.

**No redaction (developer ruling, 2026-08-29).** Approved log text is returned verbatim. These are
administrator-gated troubleshooting tools and the application is not the policy authority for what
FileMaker Server or CORPUSfm wrote. The page ceiling is the ONLY thing that shapes the return. An
"improvement" that scrubs, masks or drops content is a regression against that ruling — the disclosure
controls are the two MCP gate rails and the approved-root fence, enforced by packet 1360-02 and by this
module respectively.

**Raw acquisition (developer simplification ruling, 2026-08-30).** This module acquires approved log
BYTES; the calling AI interprets them. It holds no timestamp grammar, no window arithmetic, no logical-
record assembly and no content filter, because four review rounds showed that a transport layer asked
to understand heterogeneous, version-dependent log text drops content while reporting success.

**LIVE, not a snapshot (developer rulings 1-4, 2026-08-30).** Reads are strictly read-only and never
lock, copy aside, or otherwise stabilise a log. Concurrent writes and rotation are normal operating
conditions rather than errors to eliminate, so nothing here promises a single-generation traversal. A
date range selects FILES from filesystem metadata; it never parses a timestamp out of log text.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat as _stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The cumulative 128 MiB traversal budget that used to live here is REMOVED (developer ruling 2,
# 2026-08-30). It was not the MCP transport ceiling; it was an application limit that made every byte
# of a selected family beyond it permanently unreachable over MCP — a prefix cutoff, reproduced at
# proportional scale as ranges [24,32) and [16,24) of a 32-byte member followed by an empty terminal
# reply with no cursor. In this reader there is no hidden scan: bytes examined are bytes returned, the
# per-page ceiling already bounds work per call, and the concurrency seam bounds competing reads.

#: Bytes of log text ONE page may carry. The transport lowers it; nothing raises it.
MAX_OUTPUT_BYTES = 256 * 1024
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


# ══════════════════════════════════════════════════════════════════════════════════════════════
# Packet 1363 — LIVE raw byte acquisition (developer rulings, 2026-08-30)
# ══════════════════════════════════════════════════════════════════════════════════════════════
#
# Three contracts have stood here in succession, and the differences matter more than the code.
#
# 1. The INTERPRETING reader understood log text — time windows, a timestamp grammar with runtime
#    probing, DST placement, multi-line records, keyword filtering, record counting, a fragment
#    protocol. Four review rounds each found a fresh way for it to drop content while reporting
#    success; CXR-1 returned two of a four-line fixture because a traceback carries no timestamp.
# 2. The FROZEN-SNAPSHOT reader replaced it with byte pagination, but promised each traversal was one
#    coherent generation of the file. It could not keep that promise: the cursor embedded the whole
#    member list (so a 900-rotation family could not be paged at all), a 64-byte tail anchor was
#    trivially evaded by an in-place rewrite that preserved those bytes, and a 128 MiB traversal
#    budget silently made older bytes unreachable for ever.
# 3. THIS reader is honestly LIVE (rulings 1–4, 2026-08-30). It is strictly read-only: it never locks,
#    snapshots, or tries to stabilise a log. It starts at the newest content and works backward.
#    Concurrent writes and rotation are NORMAL OPERATING CONDITIONS, not errors to eliminate — so
#    nothing here claims a single-generation traversal, and `traversal_complete` says only that every
#    range this traversal addressed was read with no detected failure.
#
# The cursor is BOUNDED: a position and the selection parameters, never a member list. Every page
# rebuilds the live catalog and reapplies every fence. Cursor size does not grow with rotation count,
# so a large family is paged rather than refused.

CURSOR_VERSION = 3
#: HMAC domain separation. The web session secret is the INPUT; this label makes the cursor key a
#: different key, so a cursor can never be confused with (or forged from) a session cookie. The
#: version rides in the label, so a cursor minted by either earlier contract cannot validate here.
_CURSOR_PURPOSE = b"corpusfm/log_access/cursor/v3"

#: A page may never be smaller than this, or a cursor could fail to advance.
MIN_PAGE_BYTES = 1


class CursorInvalid(LogAccessError):
    """The cursor is not this server's, not this query's, or not this format's."""


# ── authenticated cursor ──────────────────────────────────────────────────────────────────────

def _cursor_key() -> bytes:
    """A sub-key derived from the installation's session secret with a versioned purpose label.

    Developer ruling, packet 1363: the session secret is the INPUT, never the signing key. Domain
    separation means a cursor cannot be forged from (or mistaken for) a session cookie.
    """
    from corpusfm.app.web.auth import session_secret
    return hmac.new(session_secret().encode("utf-8"), _CURSOR_PURPOSE, hashlib.sha256).digest()


def _seal_cursor(state: dict) -> str:
    body = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    mac = hmac.new(_cursor_key(), body, hashlib.sha256).digest()[:16]
    return (base64.urlsafe_b64encode(body).decode("ascii").rstrip("=") + "."
            + base64.urlsafe_b64encode(mac).decode("ascii").rstrip("="))


def _unseal_cursor(token: str) -> dict:
    if not isinstance(token, str) or token.count(".") != 1:
        raise CursorInvalid("cursor_invalid")
    body_b64, mac_b64 = token.split(".")
    try:
        body = base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4))
        mac = base64.urlsafe_b64decode(mac_b64 + "=" * (-len(mac_b64) % 4))
    except Exception:
        raise CursorInvalid("cursor_invalid")
    if not hmac.compare_digest(mac, hmac.new(_cursor_key(), body, hashlib.sha256).digest()[:16]):
        raise CursorInvalid("cursor_invalid")
    try:
        state = json.loads(body.decode("utf-8"))
    except Exception:
        raise CursorInvalid("cursor_invalid")
    if not isinstance(state, dict) or state.get("v") != CURSOR_VERSION:
        raise CursorInvalid("cursor_invalid")
    return state


# ── the concurrency seam ──────────────────────────────────────────────────────────────────────

class _ScanSeam:
    """One active scan per process — the shared backend concurrency seam.

    **The value is PROVISIONAL and local-correctness only.** Ownership is settled here; the shipped
    concurrency number needs measured load evidence through the running service, which is a separately
    authorized live step. Nothing may quote `1` as the shipped value.
    """
    def __init__(self, limit: int = 1) -> None:
        import threading
        self.limit = limit
        self._sem = threading.BoundedSemaphore(limit)

    def __enter__(self):
        self._sem.acquire()
        return self

    def __exit__(self, *exc):
        self._sem.release()
        return False


SCAN_SEAM = _ScanSeam()


# ── page assembly ─────────────────────────────────────────────────────────────────────────────

def _decode_page(raw: bytes) -> str:
    """Bytes to text, and nothing else.

    Malformed bytes decode to U+FFFD (ruling 4). That is READABLE, not byte-identical: one `0xff`
    source byte becomes a three-byte UTF-8 replacement character in the returned JSON text. Which is
    why every POSITION and every source-byte count in a reply is in ORIGINAL FILE BYTES, and the
    length of the text is reported separately — conflating the two was CXR2-4. Exact recovery of
    malformed source bytes is an SSH use case; there is no base64 mode and no second binary reader.
    """
    return raw.decode("utf-8", errors="replace")


def _codepoint_start(fd: int, lo: int) -> int:
    """``lo``, moved back to the start of the UTF-8 code point it falls inside.

    This is the ONLY boundary rule in the module, and it is what lets a page be a plain byte range.
    A page always begins on a lead byte, so the older page that ends where it begins also ends on a
    complete code point — no fragment protocol and no per-line state.

    **The walk must MOVE ONLY IF IT FOUND A LEAD BYTE.** A code point carries at most three
    continuation bytes, so a walk of three reaches the lead byte of any well-formed character. If it
    does not find one within reach, `lo` cannot be inside a valid code point — the bytes there are
    already invalid — so the position is left where it is. Returning `lo - 3` unconditionally was a
    real content-loss defect: one stray continuation byte after any 4-byte character made the walk
    overshoot INTO that character and split it, destroying it in both pages.
    """
    if lo <= 0:
        return 0
    back = min(3, lo)
    os.lseek(fd, lo - back, os.SEEK_SET)
    probe = os.read(fd, back + 1)
    if len(probe) < back + 1:
        return lo
    i = back
    while i > 0 and (probe[i] & 0xC0) == 0x80:
        i -= 1
    if (probe[i] & 0xC0) == 0x80:
        return lo                   # no lead byte within reach: these bytes are already invalid
    return lo - (back - i)


def _created_at(path: Path) -> float | None:
    """The member's creation time, or ``None`` where the platform does not record one.

    macOS and Windows expose a real birth time; ext4 on Linux usually does not through `os.stat`, and
    `st_ctime` there is the INODE-CHANGE time, which a chmod moves. Guessing with it would silently
    misfile a rotation, so an absent birth time is reported as absent and modification time is used
    instead (ruling 1).
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    born = getattr(st, "st_birthtime", None)
    if born:
        return float(born)
    if os.name == "nt":
        return float(st.st_ctime)
    return None


def _order_key(member) -> list:
    """The traversal order, as data a bounded cursor can carry.

    Current member first, then rotations by DESCENDING modification time, with the name only as a
    tie-break. That is what the catalog actually does; the docs used to describe `X.log`, `X.log.1`,
    `X.log.2` in numeric-suffix order, which is a different and stronger claim that disagrees whenever
    timestamps are copied or rewritten (CXR2-6).
    """
    return [0 if member.current else 1, -member.mtime, member.name]


def _order_fingerprint(selected) -> str:
    """A FIXED-SIZE digest of the traversal's ordering — never the member list itself.

    What it hashes is the ORDERED SEQUENCE OF MEMBER IDENTITIES, deliberately, and not the raw order
    inputs. An ordinary append to the current log changes that member's mtime and therefore its order
    key, while changing nothing about the order — `current` sorts first regardless. Hashing the raw
    inputs would raise `catalog_changed_during_traversal` on essentially every traversal of an actively
    written log, which is the honesty signal crying wolf until nobody reads it. The resulting order is
    the thing coverage actually depends on.

    Sixteen hex characters whatever the family holds, so the cursor cannot grow with rotation count
    (ruling 3).
    """
    return hashlib.sha256("\x00".join(m.member_id for m in selected).encode("utf-8")).hexdigest()[:16]


def _select(members, since: datetime | None, until: datetime | None):
    """The members a date range selects, and how honestly it could be decided.

    A date range selects FILES from filesystem metadata (ruling 1). It never parses a timestamp out of
    log text, and it is NOT a promise that every returned line falls inside the range — a selected
    file is one whose own coverage overlaps it. A member covers roughly `[created, modified]`, so the
    overlap test is `modified >= since` and `created < until`; where creation time is unavailable,
    modification time stands in for it and the reply says so.
    """
    if since is None and until is None:
        return list(members), {"applied": False, "creation_time_available": None}
    kept, born_seen, born_missing = [], 0, 0
    for m in members:
        born = _created_at(m.path)
        if born is None:
            born_missing += 1
        else:
            born_seen += 1
        low = born if born is not None else m.mtime
        if since is not None and m.mtime < since.timestamp():
            continue
        if until is not None and low >= until.timestamp():
            continue
        kept.append(m)
    return kept, {
        "applied": True,
        "creation_time_available": (born_missing == 0) if (born_seen or born_missing) else None,
        "members_without_creation_time": born_missing,
        "basis": ("creation_and_modification" if born_missing == 0
                  else "modification_only" if born_seen == 0 else "mixed"),
    }


def read_server_log(source_id: str = "", member_id: str | None = None, *,
                    max_bytes: int | None = None, cursor: str | None = None,
                    since: str | None = None, until: str | None = None,
                    lookback_hours: float | None = None,
                    roots: list[_Root] | None = None, now: datetime | None = None,
                    lines: int | None = None, contains: str | None = None,
                    max_output_bytes: int | None = None) -> dict:
    """One bounded, contiguous page of raw text from an approved log family — read LIVE.

    **Live, never a snapshot (ruling 1).** Access is strictly read-only: nothing here locks a file,
    copies it aside, or tries to stabilise it. The traversal starts at the newest available content
    and works backward toward progressively less-active members. Concurrent writes and rotation are
    normal operating conditions, and this reader does not pretend to eliminate them — it will not tell
    you that everything you received came from one generation of a file, because a stateless reader
    over a live file cannot know that. A later request rereads the current log as it exists then.

    **Order.** The current member first, then rotations by DESCENDING modification time, name only as
    a tie-break. Within a member the tail comes first and each continuation moves backward. A page
    never spans two members — two files are not contiguous — so every page names its member and its
    exact `[page_byte_start, page_byte_end)` range in ORIGINAL FILE BYTES.

    **Coverage.** Following `next_cursor` transports the ranges it addresses exactly once, and
    `traversal_complete` says precisely that: every range this traversal addressed was read with no
    detected failure. It is NOT a claim that the file did not change underneath it.

    **Date ranges select FILES, from filesystem metadata (ruling 1).** `since`/`until` are server-local
    wall-clock times and `lookback_hours` is relative to the server clock; a member is selected when
    its own coverage overlaps the range. Log TEXT is never parsed, so this is not a promise that every
    returned line falls inside the range, and the reply reports whether creation time was actually
    available or modification time had to stand in for it.

    **Refused arguments.** `lines` and `contains` were record counting and server-side filtering; they
    are refused rather than ignored, so a caller relying on them learns instead of quietly receiving a
    different answer. `max_output_bytes` is accepted as the old spelling of `max_bytes`, and
    `max_bytes` MAY accompany a cursor — it is a property of the transport carrying one page, not of
    the query, and the MCP adapter lowers it and re-asks.
    """
    from corpusfm.core import servertime

    for name, value in (("lines", lines), ("contains", contains)):
        if value not in (None, "", 0):
            raise InvalidArgument(
                f"{name} is no longer supported: this reader returns raw log text and does not "
                f"filter or interpret it — read pages and search them yourself")
    if max_bytes is None:
        max_bytes = max_output_bytes
    if max_bytes is None:
        max_bytes = MAX_OUTPUT_BYTES
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise InvalidArgument("max_bytes must be an integer")
    if max_bytes < MIN_PAGE_BYTES:
        raise InvalidArgument(f"max_bytes must be at least {MIN_PAGE_BYTES}")
    room = min(max_bytes, MAX_OUTPUT_BYTES)

    zone = servertime.local_zone()
    observed = (now or servertime.local_now())
    observed = (observed.replace(tzinfo=zone) if observed.tzinfo is None
                else observed.astimezone(zone))

    state = None
    if cursor:
        state = _unseal_cursor(cursor)
        for name, value in (("source_id", source_id), ("member_id", member_id),
                            ("since", since), ("until", until)):
            if value:
                raise InvalidArgument(f"{name} cannot be supplied with a cursor")
        if lookback_hours is not None:
            raise InvalidArgument("lookback_hours cannot be supplied with a cursor")
        source_id = state["src"]
        member_id = state["mem"] or None
        query_id, page_number = state["q"], state["p"]
        prior_failures = state.get("f", 0)
        eff_since = datetime.fromisoformat(state["since"]) if state.get("since") else None
        eff_until = datetime.fromisoformat(state["until"]) if state.get("until") else None
        at_key, at_member, at_pos = state.get("key"), state.get("cm"), state.get("pos")
        prior_fingerprint = state.get("fp")
        catalog_changed = state.get("cc", 0)
    else:
        if lookback_hours is not None:
            if isinstance(lookback_hours, bool) or not isinstance(lookback_hours, (int, float)):
                raise InvalidArgument("lookback_hours must be a number")
            if lookback_hours <= 0:
                raise InvalidArgument("lookback_hours must be positive")
            if since or until:
                raise InvalidArgument("lookback_hours cannot be combined with since/until")
            eff_until = observed
            eff_since = observed - timedelta(hours=float(lookback_hours))
        else:
            eff_since = _parse_wall(since, "since", zone) if since else None
            eff_until = _parse_wall(until, "until", zone) if until else None
        if eff_since and eff_until and eff_since >= eff_until:
            raise InvalidArgument("since must be earlier than until")
        query_id = hashlib.sha256(
            f"{source_id}|{member_id}|{since}|{until}|{lookback_hours}|"
            f"{observed.isoformat()}".encode("utf-8")).hexdigest()[:16]
        page_number, prior_failures = 1, 0
        at_key = at_member = at_pos = None
        prior_fingerprint, catalog_changed = None, 0

    # EVERY page rebuilds the catalog from the approved roots and reapplies every fence. A
    # continuation is a fresh, fully fenced request that happens to carry a position; it is never a
    # handle onto an open file, and it carries no member list (ruling 3).
    sources, _ = build_catalog(roots)
    source = next((s for s in sources if s.source_id == source_id), None)
    if source is None:
        raise UnknownSource("no such log source")
    if not source.available:
        raise UnknownSource("that log source is not available")

    candidates = list(source.members)
    if member_id:
        candidates = [m for m in source.members if m.member_id == member_id]
        if not candidates:
            raise UnknownSource("that member does not belong to this source")
    selected, selection = _select(candidates, eff_since, eff_until)
    selected.sort(key=_order_key)

    # A live traversal sorts a MUTABLE catalog on every page, so a rotation whose mtime moves can cross
    # the cursor while the walk is in progress. Measured on one current file and three rotations at a
    # 16-byte page: moving an already-read member behind the cursor returned it TWICE (80 of 40 bytes),
    # and moving an unread member ahead of the cursor omitted it entirely — both with
    # `traversal_complete: true` and zero failures, and on the omission path the terminal page's own
    # `selected_members` still listed the member it never returned (Codex CXR3-1).
    #
    # This does NOT reinstate the withdrawn snapshot contract. Nothing is frozen, locked or refused, and
    # the walk continues best-effort. What changes is the CLAIM: once the ordering has moved, exact
    # family coverage is no longer knowable, so the traversal says so instead of reporting clean.
    fingerprint = _order_fingerprint(selected)
    if prior_fingerprint is not None and prior_fingerprint != fingerprint and not catalog_changed:
        catalog_changed = page_number

    failures: list = []
    idx, pos = 0, None
    if at_member is not None:
        found = next((k for k, m in enumerate(selected) if m.member_id == at_member), None)
        if found is not None:
            idx, pos = found, at_pos
        else:
            # Live semantics: the member this cursor was reading is gone from the live catalog — it
            # rotated away, was pruned, or dropped out of the date selection. Say so and resume at the
            # first member that sorts strictly OLDER than the recorded position, rather than starting
            # the family again or refusing outright (ruling 1 + 3).
            failures.append({"member_id": at_member, "reason": "member_no_longer_present"})
            idx = next((k for k, m in enumerate(selected) if _order_key(m) > at_key), len(selected))
            pos = None

    text = ""
    page_member = page_index = None
    page_start = page_end = 0

    with SCAN_SEAM:
        while idx < len(selected):
            member = selected[idx]
            try:
                fd = _open_nofollow(member.path)
            except OSError:
                failures.append({"member_id": member.member_id, "reason": "unreadable"})
                idx, pos = idx + 1, None
                continue
            try:
                st = os.fstat(fd)
                if (not _stat.S_ISREG(st.st_mode)
                        or not _same_identity(member.dev, member.ino, st)
                        or st.st_nlink != 1):
                    failures.append({"member_id": member.member_id, "reason": "changed_during_read"})
                    idx, pos = idx + 1, None
                    continue
                upper = st.st_size if pos is None else pos
                if upper > st.st_size:
                    # The file is shorter than where this cursor was reading. Under live semantics
                    # that is a real event to REPORT, not an error to eliminate: read what is there.
                    failures.append({"member_id": member.member_id, "reason": "member_shrank"})
                    upper = st.st_size
                if upper <= 0:
                    idx, pos = idx + 1, None
                    continue
                lo = _codepoint_start(fd, max(0, upper - room))
                want = upper - lo
                os.lseek(fd, lo, os.SEEK_SET)
                raw = b""
                while len(raw) < want:
                    part = os.read(fd, min(_CHUNK, want - len(raw)))
                    if not part:
                        break
                    raw += part
                if len(raw) < want:
                    failures.append({"member_id": member.member_id, "reason": "member_shrank"})
                    if not raw:
                        idx, pos = idx + 1, None
                        continue
                    lo = upper - len(raw)
            finally:
                os.close(fd)
            text = _decode_page(raw)
            page_member, page_index, page_start, page_end = member.member_id, idx, lo, lo + len(raw)
            if lo > 0:
                pos = lo
            else:
                idx, pos = idx + 1, None
            break
        else:
            idx, pos = len(selected), None

    has_more = idx < len(selected)
    failed_total = prior_failures + len(failures)
    cursor_out = _seal_cursor({
        "v": CURSOR_VERSION, "q": query_id, "p": page_number + 1, "src": source.source_id,
        "mem": member_id or "", "cm": selected[idx].member_id, "key": _order_key(selected[idx]),
        "pos": pos, "f": failed_total, "fp": fingerprint, "cc": catalog_changed,
        "since": eff_since.isoformat() if eff_since else "",
        "until": eff_until.isoformat() if eff_until else "",
    }) if has_more else None

    ci = servertime.clock_info()
    return {
        "source_id": source.source_id,
        "selected_members": [m.member_id for m in selected],
        "text": text,
        # ORIGINAL FILE BYTES vs the length of the JSON text, kept apart deliberately. One `0xff`
        # source byte is 1 source byte and 3 text bytes; reporting a single `returned_bytes` conflated
        # the two (CXR2-4).
        "source_bytes": page_end - page_start,
        "returned_text_bytes": len(text.encode("utf-8")),
        "replacement_characters": text.count("�"),
        "member_id": page_member,
        "member_index": page_index,
        "page_byte_start": page_start if page_member else None,
        "page_byte_end": page_end if page_member else None,
        "failures": failures,
        # A failure on page 1 must still be visible on page 9. Keeping only THIS page's failures let
        # the final reply say `traversal_complete: true` after a whole member had been skipped.
        "failed_members_so_far": failed_total,
        "selection": selection,
        # ONE structured condition, recorded at the page that first noticed and carried forward by the
        # cursor, so a caller reading only the terminal reply still sees it.
        "conditions": ([{"condition": "catalog_changed_during_traversal",
                         "first_seen_page": catalog_changed,
                         "detail": ("the family's member ordering changed while this traversal was in "
                                    "progress, so exact coverage of it can no longer be claimed")}]
                       if catalog_changed else []),
        "query_id": query_id,
        "page_number": page_number,
        "traversal": "current_member_first_then_rotations_by_descending_mtime",
        # Stated in the payload, not only in prose: this reader does not promise a snapshot.
        "live_read": True,
        "server_time_observed": observed.isoformat(),
        "server_clock": {"zone_id": ci.zone_id, "abbreviation": ci.abbreviation,
                         "source": ci.source, "predicts_dst": ci.predicts_dst},
        # Every range this traversal ADDRESSED was read with no detected failure. Never a claim that
        # the underlying files held still (CXR2-1, ruling 1).
        "traversal_complete": bool(not has_more and not failed_total and not catalog_changed),
        "has_more": has_more,
        "next_cursor": cursor_out,
    }


def _parse_wall(text: str, what: str, zone) -> datetime:
    """A server-local wall-clock ISO timestamp, as the caller is told to write it."""
    if not isinstance(text, str):
        raise InvalidArgument(f"{what} must be text")
    try:
        parsed = datetime.fromisoformat(text.strip())
    except Exception:
        raise InvalidArgument(
            f"{what} must be a server-local wall-clock time such as 2026-08-30T02:15:00")
    return parsed.replace(tzinfo=zone) if parsed.tzinfo is None else parsed.astimezone(zone)


#: The retired name. `query_log` was the interpreting engine's entry point; the raw reader IS the query.
query_log = read_server_log
