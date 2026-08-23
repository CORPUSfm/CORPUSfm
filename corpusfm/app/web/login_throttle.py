"""Bounded brute-force throttle for the interactive login path (packet 1175, design fact 7).

The design's threat model (§12) requires a per-identity **and** per-source backoff on `/login` and the
LDAP bind — there was none. This is that throttle: a small, box-local, **cross-process** sliding-window
counter that blocks an identity or a source once it accumulates too many failures inside the window, and
recovers automatically once those failures age out.

Why a SQLite file, not in-process state
---------------------------------------
CORPUSfm is co-located: all web workers (and any stray second `python -m` the single-worker guard cannot
catch) run on the ONE box. An in-memory counter would be a *per-process illusion* — a second worker/process
would each keep its own tally, so N processes multiply the real attempt ceiling by N. A single SQLite file
under ``~/.corpusfm`` is shared by every process on the box, so the ceiling is global. SQLite's own file
locking (plus a busy-timeout) makes the concurrent increments safe without our own lock.

Two buckets, checked independently
----------------------------------
- **identity** — the normalized username: casefold + strip, so ``Alice``/``alice ``/``ALICE`` collapse to
  one bucket (no trivial casing/whitespace bypass), and an EMPTY/whitespace username maps to a fixed
  sentinel so a blank identity still accumulates (no empty-identity bypass — it does not disable the
  throttle, it shares one bucket).
- **source** — the caller IP (higher ceiling, to tolerate a shared NAT egress). A missing/untrusted source
  maps to its own sentinel; it never disables throttling (the identity bucket still applies).

A login is blocked when EITHER bucket is at/over its ceiling within the window. That catches both
one-source-many-usernames (source bucket) and many-sources-one-username (identity bucket).

Fail-OPEN by deliberate choice
------------------------------
This is a hardening layer in front of password hashing (the real boundary), not itself an auth gate. If the
throttle store is unwritable/corrupt, we let the login proceed (logged) rather than lock every user out — a
throttle that fails closed is a self-inflicted DoS. (Contrast the TOKEN path, which fails closed: there the
store IS the boundary.)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

_LOG = logging.getLogger(__name__)

# Sliding window + per-bucket ceilings. Bounded and self-recovering: a bucket that stops failing drops back
# under its ceiling once its oldest in-window failure ages past WINDOW_SECONDS.
WINDOW_SECONDS = 900          # 15 minutes
MAX_IDENTITY_FAILS = 5        # a single account: 5 bad tries / 15 min → locked until they age out
MAX_SOURCE_FAILS = 50         # a single source IP: higher, so a shared NAT of real users isn't locked out

_EMPTY_IDENTITY = "\x00empty-identity"     # blank/whitespace username → still ONE throttled bucket
_NO_SOURCE = "\x00no-source"               # unknown/untrusted origin → its own bucket, never a bypass


def _db_path() -> Path:
    """The box-local throttle DB (``~/.corpusfm/login_throttle.sqlite3``). Overridable via
    ``CORPUSFM_LOGIN_THROTTLE_DB`` for tests / non-standard installs."""
    override = os.environ.get("CORPUSFM_LOGIN_THROTTLE_DB")
    if override:
        return Path(override)
    from corpusfm.install import marker_path
    return marker_path().parent / "login_throttle.sqlite3"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # autocommit (isolation_level=None) + a busy timeout so concurrent workers serialize instead of raising
    # "database is locked". check_same_thread=False: a fresh connection is opened per call, never shared.
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS login_failures (bucket TEXT NOT NULL, ts REAL NOT NULL)"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS ix_login_failures_bucket ON login_failures (bucket)")
    return conn


def _normalize_identity(username: "str | None") -> str:
    """Collapse casing + surrounding whitespace so variants share one bucket; blank → the sentinel."""
    norm = (username or "").strip().casefold()
    return norm if norm else _EMPTY_IDENTITY


def _normalize_source(source: "str | None") -> str:
    norm = (source or "").strip()
    return norm if norm else _NO_SOURCE


def _id_bucket(username: "str | None") -> str:
    return "id:" + _normalize_identity(username)


def _src_bucket(source: "str | None") -> str:
    return "src:" + _normalize_source(source)


@dataclass(frozen=True)
class Decision:
    blocked: bool
    retry_after: int          # whole seconds until the soonest bucket drops under its ceiling (0 if allowed)


def _now() -> float:
    return time.time()


def _bucket_retry_after(conn: sqlite3.Connection, bucket: str, ceiling: int, now: float) -> float:
    """>0 seconds if this bucket is at/over its ceiling within the window (the wait until its OLDEST
    in-window failure ages out, which drops the count by one), else 0."""
    cutoff = now - WINDOW_SECONDS
    rows = conn.execute(
        "SELECT ts FROM login_failures WHERE bucket=? AND ts>? ORDER BY ts ASC", (bucket, cutoff)
    ).fetchall()
    if len(rows) < ceiling:
        return 0.0
    oldest = rows[0][0]
    return max(0.0, (oldest + WINDOW_SECONDS) - now)


def evaluate(username: "str | None", source: "str | None") -> Decision:
    """Is this (identity, source) currently allowed to attempt a login? Blocked when EITHER bucket is
    at/over its ceiling within the window. Does NOT itself record anything. Fail-open."""
    try:
        conn = _connect()
        try:
            now = _now()
            ra = max(
                _bucket_retry_after(conn, _id_bucket(username), MAX_IDENTITY_FAILS, now),
                _bucket_retry_after(conn, _src_bucket(source), MAX_SOURCE_FAILS, now),
            )
        finally:
            conn.close()
    except Exception:
        _LOG.warning("login throttle evaluate failed — allowing login (fail-open)", exc_info=True)
        return Decision(blocked=False, retry_after=0)
    if ra > 0:
        # ceil, and never report 0 while blocked
        return Decision(blocked=True, retry_after=max(1, int(ra + 0.999)))
    return Decision(blocked=False, retry_after=0)


def note_failure(username: "str | None", source: "str | None") -> None:
    """Record one failed attempt against BOTH buckets, and opportunistically prune aged rows. Fail-open."""
    try:
        conn = _connect()
        try:
            now = _now()
            conn.execute("INSERT INTO login_failures (bucket, ts) VALUES (?, ?)", (_id_bucket(username), now))
            conn.execute("INSERT INTO login_failures (bucket, ts) VALUES (?, ?)", (_src_bucket(source), now))
            conn.execute("DELETE FROM login_failures WHERE ts < ?", (now - WINDOW_SECONDS,))
        finally:
            conn.close()
    except Exception:
        _LOG.warning("login throttle note_failure failed — continuing (fail-open)", exc_info=True)


def note_success(username: "str | None", source: "str | None") -> None:
    """Clear the IDENTITY bucket after a real login, so a user who finally succeeds isn't left locked by
    their own earlier typos. The SOURCE bucket is intentionally left intact — one success from a shared
    egress must not wipe an ongoing spray from that same source. Fail-open."""
    try:
        conn = _connect()
        try:
            conn.execute("DELETE FROM login_failures WHERE bucket=?", (_id_bucket(username),))
        finally:
            conn.close()
    except Exception:
        _LOG.warning("login throttle note_success failed — continuing (fail-open)", exc_info=True)
