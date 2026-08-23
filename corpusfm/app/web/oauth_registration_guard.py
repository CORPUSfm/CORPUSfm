"""Box-wide durable admission bound for anonymous OAuth dynamic registration.

The guard limits FileMaker write amplification; it is not an authentication decision. A metadata-valid
attempt reserves its slot before the OAUTH create, and conservatively keeps that reservation when the
remote create fails or is indeterminate. SQLite is the one small box-local authority because no atomic
transaction spans local state and FileMaker.
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

WINDOW_SECONDS = 3600
MAX_ADMISSIONS = 30


class RegistrationAdmissionUnavailable(RuntimeError):
    """The durable local authority could not make an admission decision."""


class RegistrationRateExceeded(RuntimeError):
    """The current box-wide admission window is full."""


def _db_path() -> Path:
    from corpusfm.lifecycle import app_paths

    override = app_paths.development_override(
        "CORPUSFM_OAUTH_REGISTRATION_GUARD",
        lambda: os.environ.get("CORPUSFM_OAUTH_REGISTRATION_GUARD"),
        what="the OAuth registration admission database",
    )
    if override:
        return Path(str(override))
    return app_paths.state_dir() / "oauth_registration_guard.sqlite3"


def _now() -> float:
    return time.time()


def admit() -> None:
    """Atomically reserve one metadata-valid DCR attempt in the current sliding window.

    Raises before any FileMaker write when the window is full or the local authority is unavailable.
    A successful return is durable; callers must never refund it after an indeterminate remote create.
    """
    path = _db_path()
    conn = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("CREATE TABLE IF NOT EXISTS admissions (ts REAL NOT NULL)")
        conn.execute("CREATE INDEX IF NOT EXISTS ix_oauth_registration_admissions_ts ON admissions(ts)")
        now = _now()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM admissions WHERE ts <= ?", (now - WINDOW_SECONDS,))
        count = int(conn.execute("SELECT COUNT(*) FROM admissions").fetchone()[0])
        if count >= MAX_ADMISSIONS:
            conn.execute("ROLLBACK")
            raise RegistrationRateExceeded(
                f"OAuth client registration is limited to {MAX_ADMISSIONS} attempts per hour"
            )
        conn.execute("INSERT INTO admissions(ts) VALUES (?)", (now,))
        conn.execute("COMMIT")
    except RegistrationRateExceeded:
        raise
    except Exception as exc:
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        raise RegistrationAdmissionUnavailable(
            "OAuth client registration admission state is unavailable"
        ) from exc
    finally:
        if conn is not None:
            conn.close()
