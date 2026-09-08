"""Job last-run state — fields on the JOB record, read for fast display in the jobs list.

The `<job_uuid>.state` sidecar is REMOVED with the YAML job store it sat beside (packet 1361-01):
filesystem-selected job state belongs to a job model the product does not support. State lives on the
JOB record, over whichever engine the live backend exposes.

Public API:
    JobState
    read_state(job_uuid) -> JobState
    update_state(job_uuid, run)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from corpusfm.server.jobs.history import RunRecord


def _repo():
    """The JobsRepo over the live backend's engine — one gate with jobs/store."""
    from corpusfm.server.jobs.store import _repo as _store_repo
    return _store_repo()


@dataclass
class JobState:
    last_run_ts: Optional[str] = None
    last_status: Optional[str] = None    # ok | error | running | None
    last_error: Optional[str] = None
    last_archive_path: Optional[str] = None  # "<fm_file>/<timestamp>" from last ok run
    last_duration: Optional[str] = None  # seconds as string; None if not yet run


def read_state(job_uuid: str) -> JobState:
    """Last-run state for a job, from its JOB record."""
    return _repo().read_state(job_uuid)


def update_state(job_uuid: str, run: RunRecord) -> None:
    """Persist run state onto the JOB record. Best-effort — a display field never fails a run."""
    try:
        _repo().update_state(job_uuid, run)
    except Exception:
        pass
