"""Job run history — the ``RunRecord`` shape + the run read/write path.

⚠️ Packet 085 Unit 3c: the per-job JSONL mirror and the FM-RUNS-vs-JSONL dual path are GONE.
Run outcomes are now HISTORY ``Type=Run`` rows on the storage engine, uniform across BOTH
backends (LocalBackend SQLite mirror + FM OData) — see :mod:`corpusfm.server.history`. There is
one system of record and no local file mirror; ``RunRecord`` is just the in-memory shape a run
is described in, and the two functions here delegate to the HISTORY layer.

Public API:
    RunRecord
    default_history_dir()                                   — vestigial dir (nothing is written)
    record_run(backend, run)                                — write a HISTORY Type=Run row
    list_runs_for(job_name, history_dir, limit, backend, job_uuid) — read Type=Run for a job
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_PROJECT_ROOT = Path(__file__).parent.parent.parent


@dataclass
class RunRecord:
    ts: str                          # ISO timestamp of completion
    status: str                      # ok | error | running
    trigger: str                     # manual | webhook | schedule
    duration_s: float
    archive_path: Optional[str] = None   # path relative to archive_dir
    git_commits: Optional[list] = None   # list of short SHAs or error strings
    error: Optional[str] = None
    run_id: Optional[str] = None         # stable run uuid — the FK artifacts carry (Artifact→Run)
    job_uuid: Optional[str] = None       # the job this run belongs to (Run→Job), by uuid never name
    # The job's name AS IT WAS at run time (packet 1149) — frozen data, never the link. History must
    # render without consulting live config: a deleted job's runs still say which job they were.
    job_name: Optional[str] = None


def default_history_dir() -> Path:
    """Vestigial: the JSONL run mirror is retired (085 U3c). Kept only so the historical
    ``history_dir`` plumbing still resolves; nothing is written or read here now."""
    return _PROJECT_ROOT / "history"


def record_run(backend, run: RunRecord) -> None:
    """Persist a run outcome as a HISTORY Type=Run row (best-effort)."""
    from corpusfm.server.history import record_run as _record
    _record(backend, run)


def list_runs_for(
    job_name: str,
    history_dir: Path = None,
    limit: int = 50,
    backend=None,
    job_uuid: str = "",
) -> list[RunRecord]:
    """Run history for a job, newest first — HISTORY Type=Run scoped by UUIDJob, on both
    backends. ``history_dir`` is accepted for call-site compatibility but unused (no JSONL)."""
    from corpusfm.server.history import list_run_records
    return list_run_records(backend, job_uuid, limit=limit)
