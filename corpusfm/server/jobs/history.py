"""Job run history — the ``RunRecord`` shape + the run read/write path.

⚠️ Packet 085 Unit 3c: the per-job JSONL mirror and the FM-RUNS-vs-JSONL dual path are GONE.
Run outcomes are now HISTORY ``Type=Run`` rows on the storage engine, uniform across BOTH
backends (LocalBackend SQLite mirror + FM OData) — see :mod:`corpusfm.server.history`. There is
one system of record and no local file mirror; ``RunRecord`` is just the in-memory shape a run
is described in, and the two functions here delegate to the HISTORY layer.

``default_history_dir`` is REMOVED (packet 1361-01). It resolved a directory nothing wrote to and
nothing read from, and it existed only to keep the ``history_dir`` plumbing of a filesystem-executed
job model resolving — a model the product does not support.

Public API:
    RunRecord
    record_run(backend, run)                    — write a HISTORY Type=Run row
    list_runs_for(job_uuid, limit, backend)     — read Type=Run for one job
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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


def record_run(backend, run: RunRecord) -> None:
    """Persist a run outcome as a HISTORY Type=Run row (best-effort)."""
    from corpusfm.server.history import record_run as _record
    _record(backend, run)


def list_runs_for(job_uuid: str, limit: int = 50, backend=None) -> list[RunRecord]:
    """Run history for one job, newest first — HISTORY Type=Run scoped by `UUIDJob`.

    **The first positional is the job's UUID.** It used to be `job_name`, which the body then
    ignored in favour of a `job_uuid=` keyword — a dead parameter that made every call site read as
    though history were name-scoped, and an open invitation to reintroduce exactly that. The dead
    `history_dir` second positional went the same way (packet 1361-01).
    """
    from corpusfm.server.history import list_run_records
    return list_run_records(backend, job_uuid, limit=limit)
