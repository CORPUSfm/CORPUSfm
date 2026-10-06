"""Server-local wall clock — the authority a schedule is interpreted against (packet 1185, Stage A).

Everything CORPUSfm stores and transmits is UTC (packet 1005). A *schedule* is the deliberate
exception: a person picks "08:30 Tuesdays" and means their server's wall clock, so the scheduler has
to match against server-local time and the UI has to say which clock that was.

WHY NOT THE OBVIOUS LOCAL-CONVERSION IDIOM
    Converting an aware "now" to local time yields a correct offset *for right now* and a ``timezone``
    object frozen at that offset. Ask it about any other date and it answers with today's offset — so
    a "next run" preview computed across a DST boundary is silently an hour wrong. Measured
    2026-07-28: it reports -07:00 for both 2026-08-15 and 2026-12-15, while the box genuinely moves to
    -08:00 in between. The packet-1005 timestamp guard forbids that idiom outright, which is why the
    degraded fallback below builds its offset explicitly instead of borrowing it.

WHY ``dateutil.tz.tzlocal()``
    It reads the OS time-zone database, so it *predicts*: PDT/-07:00 in August, PST/-08:00 in
    December, on the same box, in the same process. It is already pinned in **both** platform locks
    (``python-dateutil==2.9.0.post0``), and on Windows it reads the registry — so this needs **no new
    dependency**, which matters because ``tzdata`` is in neither lock and the Windows installer ships
    the *embeddable* CPython, where ``zoneinfo`` alone would raise ``ZoneInfoNotFoundError``.

BEHAVIOR vs IDENTITY — kept apart on purpose
    ``tzlocal()`` gives correct *behavior* but no IANA *name*. The name is a separate, weaker thing:
    derivable from ``TZ`` or ``/etc/localtime`` on Linux/macOS, and normally **absent on Windows**. An
    absent name is reported as absent. Per the packet: never infer a Windows IANA zone from an
    abbreviation like "PST" — abbreviations are ambiguous across the world and guessing produces a
    confident lie.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Optional

# How the local zone was obtained, worst to best. The UI shows this rather than implying certainty.
SOURCE_OS_TZDB = "os_tzdb"          # dateutil read the OS database — DST-correct into the future
SOURCE_FIXED_OFFSET = "fixed_offset"  # degraded: today's offset only, cannot predict a DST change
SOURCE_UTC_FALLBACK = "utc_fallback"  # no local clock at all; UTC, and SAID to be UTC


@dataclass(frozen=True)
class ClockInfo:
    """What this box can honestly say about its own wall clock."""
    offset_seconds: int
    abbreviation: str          # "PDT", "GMT+2", … — display only, NEVER an identity
    zone_id: Optional[str]     # IANA name when the OS exposes one; None otherwise (usually Windows)
    source: str                # one of the SOURCE_* constants
    predicts_dst: bool         # False → previews across a DST boundary may be an hour off

    @property
    def degraded(self) -> bool:
        return self.source != SOURCE_OS_TZDB

    def label(self) -> str:
        """A short, non-lying label for the UI."""
        if self.source == SOURCE_UTC_FALLBACK:
            return "UTC (server local time unavailable)"
        base = self.zone_id or self.abbreviation or "server local"
        return base if not self.degraded else f"{base} (offset only)"


def local_zone() -> tzinfo:
    """The server's local zone. DST-predicting when the OS database is reachable."""
    try:
        from dateutil import tz
        z = tz.tzlocal()
        if z is not None:
            return z
    except Exception:
        pass
    # Degraded but still local: the CURRENT offset, frozen. Better than pretending the box is UTC,
    # and `clock_info()` reports that it cannot predict a DST change.
    # Degraded but still LOCAL: build the current offset explicitly from the `time` module rather
    # than borrowing a local-conversion idiom. Explicit is the point — this branch CANNOT predict a
    # DST change, and constructing it by hand keeps that limitation visible instead of hiding it
    # behind something that merely looks authoritative. (It also stays clear of the packet-1005
    # guard, which forbids that idiom app-wide for good reason.)
    try:
        import time as _time
        is_dst = bool(_time.localtime().tm_isdst) and bool(_time.daylight)
        offset = -(_time.altzone if is_dst else _time.timezone)
        name = _time.tzname[1 if is_dst else 0] or ""
        return timezone(timedelta(seconds=offset), name) if name else timezone(timedelta(seconds=offset))
    except Exception:
        pass
    return timezone.utc


def local_now() -> datetime:
    """Server-local aware 'now' — what a schedule is matched against."""
    return datetime.now(tz=local_zone())


def _zone_identity() -> Optional[str]:
    """An IANA zone name when the OS genuinely exposes one, else None.

    Deliberately conservative. `TZ` is authoritative when set to a zone name; `/etc/localtime` is the
    Linux/macOS convention. Windows has neither, and its abbreviation is NOT a substitute — mapping
    "PST" back to a zone is a guess that reads as a fact.
    """
    tzenv = (os.environ.get("TZ") or "").strip().lstrip(":")
    if tzenv:
        # A set TZ governs the process clock (dateutil follows it), so /etc/localtime no longer
        # describes it (packet 1400-06: TZ=UTC was labelled with the box's /etc/localtime zone).
        # A zone name is the identity; anything else (a POSIX rule like "PST8PDT", or a file path
        # such as ":/etc/localtime") has none.
        named = ("/" in tzenv or tzenv == "UTC") and not tzenv.startswith("/")
        return tzenv if named else None
    try:
        p = Path("/etc/localtime")
        if p.exists():
            real = os.path.realpath(p)
            if "zoneinfo" in real:
                # …/zoneinfo/America/Los_Angeles → America/Los_Angeles
                tail = real.split("zoneinfo", 1)[1].strip("/")
                if tail and "/" in tail:
                    return tail
    except Exception:
        pass
    return None


def clock_info(at: Optional[datetime] = None) -> ClockInfo:
    """Describe the server clock honestly, at `at` (default: now)."""
    z = local_zone()
    # `at` names a LOCAL WALL time (that is the question this module answers), so its components are
    # read against the local zone. No naive server timestamp is ever produced.
    when = datetime.now(tz=z) if at is None else at.replace(tzinfo=z)
    off = when.utcoffset()
    if off is None:
        return ClockInfo(0, "UTC", "UTC", SOURCE_UTC_FALLBACK, predicts_dst=False)
    if z is timezone.utc:
        return ClockInfo(0, "UTC", "UTC", SOURCE_UTC_FALLBACK, predicts_dst=False)

    # Does this tzinfo actually PREDICT, or is it frozen at today's offset? Ask it about two dates
    # six months apart: a real zone with DST answers differently, a fixed offset does not. A zone
    # genuinely without DST also answers the same — hence the dateutil check, which distinguishes
    # "no DST here" from "cannot represent DST at all".
    predicts = False
    try:
        from dateutil import tz as _tz
        predicts = isinstance(z, _tz.tzlocal) or type(z).__module__.startswith("dateutil")
    except Exception:
        predicts = False

    return ClockInfo(
        offset_seconds=int(off.total_seconds()),
        abbreviation=(when.tzname() or ""),
        zone_id=_zone_identity(),
        source=SOURCE_OS_TZDB if predicts else SOURCE_FIXED_OFFSET,
        predicts_dst=predicts,
    )


def short_label(info: Optional[ClockInfo] = None, *, at: Optional[datetime] = None) -> str:
    """A compact clock label to append to a wall-clock time shown to a user.

    An unlabelled "next 02:00" is the defect packet 1185 names: the reader supplies a zone from
    their own head, and it is usually the wrong one. Prefers the OS abbreviation ("PDT"), falls
    back to the zone identity, then to a numeric offset — never to nothing.

    **Pass ``at`` whenever the time being labelled is not now.** A label describes an *instant*, and
    a summer server previewing a December run would otherwise stamp "PDT" on a time that will
    actually happen in PST — an hour-wrong claim, made by the very mechanism added to stop readers
    guessing the zone themselves.
    """
    i = info or clock_info(at)
    if i.source == SOURCE_UTC_FALLBACK:
        return "UTC"
    abbr = (i.abbreviation or "").strip()
    # A tzname like "+07" or "UTC+02:00" is an offset wearing a name; prefer the real identity when
    # one exists and fall through to the formatted offset when it does not.
    if abbr and not abbr.startswith(("+", "-")) and not abbr.upper().startswith("UTC"):
        return abbr
    if i.zone_id:
        return i.zone_id
    total = abs(i.offset_seconds)
    sign = "+" if i.offset_seconds >= 0 else "-"
    return f"UTC{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"
