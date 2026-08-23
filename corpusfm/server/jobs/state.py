"""Job state sidecar (.state file per job in jobs/ folder).

Tracks last run timestamp, status, and error — used for fast display
in the jobs list without reading full history.

Public API:
    JobState
    read_state(job_name, jobs_dir) -> JobState
    update_state(job_name, run, jobs_dir)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from corpusfm.server.jobs.history import RunRecord


def _repo():
    """The JobsRepo on a server (fm_odata) install, else None — one gate with jobs/store."""
    from corpusfm.server.jobs.store import _repo as _store_repo
    return _store_repo()


@dataclass
class JobState:
    last_run_ts: Optional[str] = None
    last_status: Optional[str] = None    # ok | error | running | None
    last_error: Optional[str] = None
    last_archive_path: Optional[str] = None  # "<fm_file>/<timestamp>" from last ok run
    last_duration: Optional[str] = None  # seconds as string; None if not yet run


def _state_path(job_name: str, jobs_dir: Path) -> Path:
    from corpusfm.server.jobs.store import _safe_name   # shared injective encoder (space-safe, collision-free)
    return jobs_dir / f"{_safe_name(job_name)}.state"


def read_state(job_name: str, jobs_dir: Path) -> JobState:
    """Read last-run state for a job. Server mode: from the JOBS record. Local: .state sidecar."""
    r = _repo()
    if r is not None:
        return r.read_state(job_name)
    path = _state_path(job_name, jobs_dir)
    if not path.exists():
        return JobState()
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return JobState(
            last_run_ts=d.get("last_run_ts"),
            last_status=d.get("last_status"),
            last_error=d.get("last_error"),
            last_archive_path=d.get("last_archive_path"),
            last_duration=d.get("last_duration"),
        )
    except Exception:
        return JobState()


def update_state(job_name: str, run: RunRecord, jobs_dir: Path) -> None:
    """Persist run state. Server mode: merges into the JOBS record. Local: .state sidecar."""
    r = _repo()
    if r is not None:
        try:
            r.update_state(job_name, run)
        except Exception:
            pass
        return
    jobs_dir.mkdir(parents=True, exist_ok=True)
    path = _state_path(job_name, jobs_dir)
    duration_s = getattr(run, "duration_s", None)
    state = {
        "last_run_ts": run.ts,
        "last_status": run.status,
        "last_error": run.error,
        "last_archive_path": run.archive_path,
        "last_duration": str(duration_s) if duration_s is not None else None,
    }
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")
