"""Strict UTC-instant parsing for request bounds and raw API fields (packet 1418).

Storage and APIs stay UTC (packet 1005). The browser presents instants locally (static/cfm_time.js);
the server's job is to hand it unambiguous values and to read the browser's instant bounds strictly.
Nothing here consults the server's local zone.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

_COMPACT = re.compile(r"^(\d{4})-(\d{2})-(\d{2})_(\d{2})(\d{2})(\d{2})(?:_(\d{1,6}))?$")
_OFFSET_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})$")
# The explicit full datetime shape `utc_iso` will vouch for: what `datetime.isoformat()` writes (seconds,
# optional fraction), naive or with an offset. `fromisoformat` alone also accepts date-only, compact-date,
# ISO-week and hour-only strings and would invent an instant from them.
_FULL_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?$")
_YMD = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_compact_utc(value: str) -> datetime:
    """A CORPUSfm compact artifact timestamp (``YYYY-MM-DD_HHMMSS[_ffffff]``) as an aware UTC datetime.
    Raises ValueError for any other shape or an impossible calendar value."""
    m = _COMPACT.match(value or "")
    if not m:
        raise ValueError("not a compact UTC timestamp")
    y, mo, d, h, mi, s, frac = m.groups()
    micro = int((frac or "0").ljust(6, "0"))
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=timezone.utc)


def parse_offset_instant(value: str) -> datetime:
    """An offset-qualified ISO-8601 instant (``…Z`` or ``…±HH:MM``) as an aware UTC datetime.
    A naive or date-only value is refused — the browser must say which instant it means."""
    s = (value or "").strip()
    if not _OFFSET_ISO.match(s):
        raise ValueError("an offset-qualified ISO-8601 instant is required")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def utc_iso(value, *, naive_is_utc: bool = False) -> str:
    """A raw instant for the browser: an offset-qualified UTC ISO string, or ``""`` when the value is
    not an instant this layer can vouch for. ``naive_is_utc`` may be set ONLY where the producing
    contract proves a naive value was written as UTC (legacy durable records); otherwise a naive value
    stays unrendered rather than acquiring a guessed zone."""
    if not value:
        return ""
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip()
        if not _FULL_DATETIME.match(s):
            return ""
        try:
            dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
        except ValueError:
            return ""
    if dt.tzinfo is None:
        if not naive_is_utc:
            return ""
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def date_filter_bounds(from_date: str, to_date: str, from_utc: str,
                       before_utc: str) -> tuple:
    """Validate the Artifact date-filter parameters. Returns
    ``(from_date, to_date, from_instant, before_instant)``; raises ValueError with a caller-facing
    message for a malformed value or a request that mixes the legacy UTC-date family with the
    instant-bound family."""
    from datetime import date
    legacy = bool(from_date or to_date)
    instant = bool(from_utc or before_utc)
    if legacy and instant:
        raise ValueError("use either from_date/to_date (UTC calendar dates) or from_utc/before_utc "
                         "(instant bounds), not both")
    for name, v in (("from_date", from_date), ("to_date", to_date)):
        if v:
            # Exact YYYY-MM-DD first: date.fromisoformat also accepts 20261012 and 2026-W41-1.
            try:
                if not _YMD.match(v):
                    raise ValueError
                date.fromisoformat(v)
            except ValueError:
                raise ValueError(f"{name} must be a YYYY-MM-DD date") from None
    lo: Optional[datetime] = None
    hi: Optional[datetime] = None
    try:
        lo = parse_offset_instant(from_utc) if from_utc else None
        hi = parse_offset_instant(before_utc) if before_utc else None
    except ValueError:
        raise ValueError("from_utc and before_utc must be offset-qualified ISO-8601 instants") from None
    if lo and hi and not lo < hi:
        raise ValueError("from_utc must be earlier than before_utc")
    return from_date, to_date, lo, hi


def browser_time_js() -> str:
    """The ONE browser formatter source (``app/web/static/cfm_time.js``), for embedding into the
    portable Explorer/Diff reports (packet 1418) — the same implementation the web app serves, never a
    hand-maintained copy."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "app" / "web" / "static" / "cfm_time.js").read_text(
        encoding="utf-8")
    if "</script" in src.lower():
        raise ValueError("cfm_time.js must not contain '</script' — it is embedded in an inline <script>")
    return src
