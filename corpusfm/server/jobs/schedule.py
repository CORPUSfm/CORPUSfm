"""The job schedule (packet 1185) — and the one-time migration off cron.

ONE SHAPE: WHICH DAYS, AND WHAT TIME
    Selected days of the week, one server-local hour and minute. That is the entire vocabulary.

    No one-time dates, no start or end dates, no monthly rules, no ordinal weekdays, no intervals,
    no arbitrary expressions, no seconds. Every one of those is a thing a user has to *learn*
    before they can schedule a nightly export, and none of them is a thing they asked for.
    (Ruled by the developer, 2026-07-28: *"Occurrence within a week is all that matters. Which days
    and what minute."* An earlier draft carried a one-time kind and an end date; both are gone.)

CRON IS GONE AS AN INTERFACE, AND ALMOST GONE AS A REPRESENTATION
    A stored cron expression is migrated **at load** by ``from_cron``. What it can represent exactly
    becomes a schedule; what it cannot is kept verbatim as bounded evidence, marked
    ``needs_update``, and — this is the part that matters — **stops firing**. Guessing at a schedule
    nobody can express in the new model would be worse than saying so: a job that runs at the wrong
    time is harder to notice than a job that says it needs attention.

    There is no second scheduling engine. Nothing here interprets cron at run time; ``from_cron`` is
    a translator that runs once and then has nothing left to do.

SAVING DOES NOT RUN THE JOB — BUT THE NEXT MINUTE IS FAIR GAME
    ``effective_after`` is stamped by the server at save and never accepted from a client. A minute
    that had already begun when the save landed does not fire; the minute after it does. Set a
    schedule at 08:30:12 for 08:31 and it runs at 08:31 (developer, 2026-07-28).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Optional

# Monday-first, matching `datetime.weekday()`. Stored lowercase; the UI supplies the display names.
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_WEEKDAY_INDEX = {d: i for i, d in enumerate(WEEKDAYS)}

_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# cron's day-of-week vocabulary: 0 AND 7 are both Sunday, and its week starts there.
_CRON_DOW = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}


@dataclass(frozen=True)
class Schedule:
    """One job's schedule. Frozen: a change produces a new revision, never an edit in place."""
    weekdays: tuple = ()                       # a non-empty subset of WEEKDAYS
    server_time: str = ""                      # "HH:MM", minute resolution, seconds never authored
    revision: str = ""                         # server-authored, opaque
    effective_after: str = ""                  # server-authored, aware ISO (UTC)
    # Migration residue: an old expression the current model cannot represent. Kept so the user can
    # see what they had, never interpreted, and never fired.
    legacy_cron: str = ""

    @property
    def is_set(self) -> bool:
        return bool(self.weekdays) and bool(_TIME_RE.match(self.server_time or ""))

    @property
    def needs_update(self) -> bool:
        return bool(self.legacy_cron) and not self.is_set

    def to_dict(self) -> dict:
        d: dict = {}
        for k in ("server_time", "revision", "effective_after", "legacy_cron"):
            v = getattr(self, k)
            if v:
                d[k] = v
        if self.weekdays:
            d["weekdays"] = list(self.weekdays)
        return d


def from_dict(d: dict) -> Schedule:
    d = d or {}
    return Schedule(
        weekdays=tuple(str(x).lower() for x in (d.get("weekdays") or [])),
        server_time=str(d.get("server_time") or ""),
        revision=str(d.get("revision") or ""),
        effective_after=str(d.get("effective_after") or ""),
        legacy_cron=str(d.get("legacy_cron") or ""),
    )


# ── migration ───────────────────────────────────────────────────────────────────

def from_cron(expr: str) -> Optional[Schedule]:
    """Translate a stored cron expression, or return None when the current model cannot hold it.

    Deliberately narrow. Only a plain minute, a plain hour, an unrestricted day-of-month and month,
    and a day-of-week that names whole days survive — nothing is inferred. A step (`*/5`), a range
    or list in the minute or hour, a day-of-month rule, or a month restriction returns None, because
    approximating any of them would silently move a job.

    Both schedules on this developer's box (`0 2 * * *`, `0 3 * * 0`) translate exactly; the
    expressions that do not are test fixtures.
    """
    fields = (expr or "").strip().split()
    if len(fields) == 7:
        # A seventh field is a YEAR restriction, and the model has no way to say "only in 2026".
        # Dropping it would silently widen the schedule to every year — the exact class of quiet
        # behaviour change this migration refuses to make.
        if fields[6] != "*":
            return None
        fields = fields[:6]
    if len(fields) == 6:
        # A sixth field is SECONDS. A single instant inside the minute may be shifted to the top of
        # it — seconds are retired outright and that costs under a minute. Anything that names MORE
        # than one second may not: `*` is sixty runs a minute and would become one, and an
        # unparseable field is not something to translate at all. Validated, not assumed.
        secs = fields[5]
        if not (secs.isdigit() and 0 <= int(secs) < 60):
            return None
        fields = fields[:5]
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = fields
    if dom != "*" or month != "*":
        return None
    if not (minute.isdigit() and hour.isdigit()):
        return None
    m, h = int(minute), int(hour)
    if not (0 <= m < 60 and 0 <= h < 24):
        return None
    days = _weekdays_from_cron(dow)
    if days is None:
        return None
    return Schedule(weekdays=days, server_time=f"{h:02d}:{m:02d}")


def _weekdays_from_cron(dow: str) -> Optional[tuple]:
    """cron's day-of-week field as our weekday names, or None if it says something we don't offer."""
    dow = dow.strip().lower()
    if dow in ("*", "?"):
        return WEEKDAYS
    out: set[str] = set()
    for part in dow.split(","):
        part = part.strip()
        if not part:
            return None
        # No explicit step guard: `_cron_dow_raw` matches a token WHOLE, so `*/2` and `5/2` fail
        # there. One that stood here was dead — removing it changed no outcome, which is how it was
        # found. The behaviour it was meant to protect is pinned by tests instead.
        bounds = part.split("-")
        if len(bounds) > 2:
            return None
        raw = [_cron_dow_raw(b) for b in bounds]
        if any(n is None for n in raw):
            return None
        if len(raw) == 1:
            out.add(_day_name(raw[0]))
            continue
        lo, hi = raw
        if lo <= hi:
            # Expanded over the RAW numbers, which is why `7` must survive this far. cron counts
            # Sunday as BOTH 0 and 7, so `0-7` spans the whole week — and normalising 7 to 0 before
            # expanding turned it into a zero-width range meaning Sunday alone. That is a silent
            # seven-fold narrowing of a daily schedule, found by review.
            values = range(lo, hi + 1)
        else:
            # A wrapping range (fri-mon). With a `7` bound the wrap is genuinely ambiguous — is
            # `7-0` an empty range, or the whole week? — so it is refused rather than guessed.
            if 7 in (lo, hi):
                return None
            values = [(lo + i) % 7 for i in range(((hi - lo) % 7) + 1)]
        for v in values:
            out.add(_day_name(v))
    return tuple(d for d in WEEKDAYS if d in out) or None


def _day_name(raw: int) -> str:
    """A raw cron day number (0-7, where 0 and 7 are both Sunday) as our weekday name."""
    return WEEKDAYS[_cron_to_python_weekday(0 if raw == 7 else raw)]


def _cron_dow_raw(token: str) -> Optional[int]:
    """One day-of-week token as its RAW cron number, keeping 7 distinct from 0 (see above)."""
    token = token.strip().lower()
    if token.isdigit():
        n = int(token)
        return n if 0 <= n <= 7 else None
    return _CRON_DOW.get(token)


def _cron_to_python_weekday(n: int) -> int:
    """cron counts from Sunday=0; `datetime.weekday()` counts from Monday=0."""
    return (n - 1) % 7


# ── validation ──────────────────────────────────────────────────────────────────

def validate(s: Schedule) -> list[str]:
    """Everything wrong with this schedule, in words a user could act on. Empty means valid."""
    errors: list[str] = []
    if not _TIME_RE.match(s.server_time or ""):
        errors.append("time must be a 24-hour server-local time, 00:00 to 23:59")
    if not s.weekdays:
        errors.append("choose at least one day")
    unknown = [d for d in s.weekdays if d not in _WEEKDAY_INDEX]
    if unknown:
        errors.append(f"unknown day(s): {', '.join(unknown)}")
    return errors


def _combine(day: date, hhmm: str, tzinfo) -> Optional[datetime]:
    try:
        h, m = (int(x) for x in hhmm.split(":"))
        return datetime(day.year, day.month, day.day, h, m, tzinfo=tzinfo)
    except Exception:
        return None


def _exists_on_the_clock(when: Optional[datetime]) -> bool:
    """Does the server's wall clock ever actually READ this local time?

    On the morning clocks go forward an hour of local times never happens, and Python will build one
    quite happily — `datetime(2026, 3, 8, 2, 30, tzinfo=los_angeles)` is a valid object that no
    clock in California will ever show. Such a minute must not fire and must not be previewed.

    The round trip is the test: convert to UTC and back, and a nonexistent local time comes back as
    a different one. A fixed-offset zone always round-trips, so this costs nothing where there is no
    DST.
    """
    if when is None or when.tzinfo is None:
        return when is not None
    try:
        return when.astimezone(timezone.utc).astimezone(when.tzinfo) == when
    except Exception:
        return True


# ── matching and preview ────────────────────────────────────────────────────────

def matches(s: Schedule, minute: datetime) -> bool:
    """Does this schedule describe `minute` — a server-local, aware, second-zero instant?"""
    if s.needs_update or not s.is_set:
        return False
    h, m = (int(x) for x in s.server_time.split(":"))
    if minute.hour != h or minute.minute != m:
        return False
    if WEEKDAYS[minute.weekday()] not in s.weekdays:
        return False
    if not _exists_on_the_clock(minute):
        return False
    return _effective_before(s, minute)


def _effective_instant(s: Schedule) -> Optional[datetime]:
    """`effective_after` as an aware instant, or None when absent/unparseable."""
    if not s.effective_after:
        return None
    try:
        eff = datetime.fromisoformat(s.effective_after)
    except ValueError:
        return None
    return eff.replace(tzinfo=timezone.utc) if eff.tzinfo is None else eff


def _effective_before(s: Schedule, minute: datetime) -> bool:
    """A revision must have been effective BEFORE this minute began.

    That is what makes "saving does not run the job" true without making it useless: the minute the
    save landed in does not fire, and the very next one does.

    Absent means always-effective, which is the right answer for a schedule migrated from cron: it
    was running before the migration, and translating it is not a reason to suspend it.
    """
    eff = _effective_instant(s)
    return True if eff is None else minute > eff


def next_matches(s: Schedule, after: datetime, count: int = 3) -> list:
    """The next `count` server-local instants this schedule will match, soonest first.

    Server-side and authoritative: the browser previews what the scheduler will actually do rather
    than reimplementing recurrence and disagreeing with it.
    """
    if s.needs_update or not s.is_set:
        return []
    # Jump to the point the schedule becomes effective instead of walking there a day at a time.
    # Converted into the caller's zone, not assigned raw: `effective_after` is stored UTC, and
    # taking its tzinfo would build every later candidate as a UTC wall time — a schedule that means
    # 09:00 in the server room previewed as 09:00 UTC.
    eff = _effective_instant(s)
    if eff is not None and eff > after:
        after = eff.astimezone(after.tzinfo)

    out = []
    day = after.date()
    for _ in range((count + 1) * 7 + 1):        # a week of candidates per result, plus a day slack
        if len(out) >= count:
            break
        when = _combine(day, s.server_time, after.tzinfo)
        day = day + timedelta(days=1)
        if when is None or when <= after:
            continue
        if WEEKDAYS[when.weekday()] in s.weekdays and _exists_on_the_clock(when):
            out.append(when)
    return out


def previous_match(s: Schedule, before: datetime):
    """The most recent instant this schedule matched at or before `before`, or None.

    Used by the overdue check, which needs to know when the job was *expected* — a question that
    only makes sense against the same clock the scheduler fires on.
    """
    if s.needs_update or not s.is_set:
        return None
    day = before.date()
    for _ in range(8):                          # a week plus today covers every weekly shape
        when = _combine(day, s.server_time, before.tzinfo)
        day = day - timedelta(days=1)
        if when is None or when > before:
            continue
        if (WEEKDAYS[when.weekday()] in s.weekdays and _effective_before(s, when)
                and _exists_on_the_clock(when)):
            return when
    return None


# ── the command line ────────────────────────────────────────────────────────────

def parse_cli_schedule(text: str):
    """A schedule written on a command line, as (Schedule, error). Exactly one of the two is set.

    Two forms, server-local, shortest for the common case:

        08:30                   every day
        mon,wed 08:30           those days

    Deliberately not cron. The point of the packet is that a person should not have to know cron to
    schedule a nightly export, and a CLI user is a person too.
    """
    parts = (text or "").strip().split()
    if len(parts) == 1:
        s = Schedule(weekdays=WEEKDAYS, server_time=parts[0])
    elif len(parts) == 2:
        days = [d.strip().lower()[:3] for d in parts[0].split(",") if d.strip()]
        s = Schedule(weekdays=tuple(d for d in WEEKDAYS if d in days), server_time=parts[1])
    else:
        return None, "expected 'HH:MM' or '<days> HH:MM' (server-local time)"
    errors = validate(s)
    return (None, "; ".join(errors)) if errors else (s, "")


# ── how it reads to a person ────────────────────────────────────────────────────

_DISPLAY = {"mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri",
            "sat": "Sat", "sun": "Sun"}
_WEEKDAY_SET = ("mon", "tue", "wed", "thu", "fri")

NEEDS_UPDATE = "Schedule needs updating"


def summary(s: Schedule) -> str:
    """One sentence, in the words a person would use. Shown wherever a schedule is listed."""
    if s.needs_update:
        return NEEDS_UPDATE
    if not s.is_set:
        return "No schedule"
    if len(s.weekdays) == 7:
        days = "Every day"
    elif tuple(s.weekdays) == _WEEKDAY_SET:
        days = "Weekdays"
    else:
        days = ", ".join(_DISPLAY[d] for d in WEEKDAYS if d in s.weekdays)
    return f"{days} at {s.server_time}"
