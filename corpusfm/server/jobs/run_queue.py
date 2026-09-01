"""Job Run read helpers over the QUEUE workspace (packet 086 / 1142).

A Job Run is now ONE unified ``[acquire, ingest, git_export?, summarize?, index?]`` record (packet
1142 — the run IS the acquire); the single acquire worker IS the mutual exclusion, so the old
``run_claim`` create-then-verify wait/takeover is gone. A run is "producing" while it is on its
``acquire`` (the blocking pull) or ``ingest`` (the store) step; once it advances past ingest the
artifact is stored and the run is effectively done (git/enrichment are downstream tail). Two READS:

- ``active_runs`` — the in-flight runs for the Jobs/Files "Running" badge (non-failed run records on a
  producing step).
- ``has_active_run_for_job`` — the scheduler's "already running → skip this fire" guard (cron-overrun
  protection). Stale records (a wedged worker) age out so a fire is never blocked forever.

A crashed run's record is NOT swept on startup: existence = not-done, so the acquire worker re-runs it.
Failed runs park durably (``IsFailed``) and are a human Restart/Delete on the Queue page — excluded here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from corpusfm.storage import queue_record as Q
from corpusfm.storage.repos import queue_repo

log = logging.getLogger("corpusfm.server.jobs.run_queue")

# The steps on which a run is still PRODUCING (pulling / storing) — the window the scheduler's overrun
# guard cares about. Past ingest (git/summarize/index) the artifact is stored and the run is done, so
# the scheduler may fire again while the enrichment tail drains (preserving the old decoupled behavior).
_RUN_ACTIVE_STEPS = (Q.ACQUIRE, Q.INGEST)

# A run record older than this with no progress is presumed wedged → it no longer blocks a fresh
# scheduled fire (mirrors run_claim's staleness). The acquire worker still re-runs it independently.
_STALE_SECONDS = 1800.0


def _age_seconds(iso: str, now: datetime) -> float:
    try:
        ts = datetime.fromisoformat(iso)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return (now - ts).total_seconds()
    except Exception:
        return _STALE_SECONDS + 1.0     # unparseable → treat as stale


def active_runs(backend) -> list[dict]:
    """The in-flight Job Runs (non-failed run records on a producing step), oldest-first. Each:
    {job_uuid, job_name, run_id, started_at, file_name}. A backend without an engine reports none.
    ``run_id`` is the QUEUE record key (its operational address while active), preserving the pre-1142
    contract. ``job_uuid`` is what callers JOIN on (packet 1372-02) — ``job_name`` is a frozen label
    and two jobs may share it."""
    repo = queue_repo(backend)
    if repo is None:
        return []
    out = []
    for step in _RUN_ACTIVE_STEPS:
        for r in repo.list_by_type(step):        # non-failed only
            p = r.jor.get("Payload", {}) or {}
            from corpusfm.server.queue_handlers import is_job_run
            if not is_job_run(r):                # a browser import ([upload, ingest]) is not a Job Run
                continue
            out.append({"job_uuid": r.jor.get("UUIDJob", "") or "",
                        "job_name": p.get("job_name", ""), "run_id": r.key,
                        "started_at": r.jor.get("created_at", ""),
                        "file_name": p.get("file_name", "")})
    out.sort(key=lambda d: d.get("started_at", ""))
    return out


def has_active_run_for_job(backend, job_uuid: str) -> bool:
    """True if this job (by uuid) already has a non-failed, non-stale run record on a PRODUCING step
    (acquire / ingest) — the scheduler's 'don't re-fire a still-running schedule' guard. A run past
    ingest (git/enrichment tail) no longer blocks a fire (the artifact is stored). Stale records
    (a wedged worker) don't count."""
    repo = queue_repo(backend)
    if repo is None or not job_uuid:
        return False
    eng = getattr(backend, "engine", None)
    if eng is None:
        return False
    now = datetime.now(timezone.utc)
    for r in eng.get_many("QUEUE", "UUIDJob", [job_uuid]):
        j = r.jor
        if j.get("Type") not in _RUN_ACTIVE_STEPS or Q.is_failed(j):
            continue
        if _age_seconds(j.get("created_at", ""), now) <= _STALE_SECONDS:
            return True
    return False
