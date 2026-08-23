"""Latest-version maintenance for the stored, indexed STORAGE.IsLatest flag.

FileMaker exposes ``IsLatest`` as a stored+indexed calc reading ``JSONOfRecord``, so
``$filter=IsLatest eq true`` pages DB-side. CORPUSfm owns the WRITE side: exactly one record
flagged per lineage.

**Packet 086 / Ruling A — lineage is ``job_uuid`` ALONE (immutable).** A Job is created against
exactly one hosted file and produces one artifact per run; only the latest is tracked. ``FileName``
(repair-editable, mutable) and ``RootUUID`` are BOTH out of the key. "Newest" orders by the immutable
``ArtifactTimestamp``. A newly-stored artifact lands ``IsLatest=true`` (artifact-record/2), so
maintenance is **Option A**: demote the prior ``UUIDJob=X AND IsLatest=1`` row(s) via one indexed
read — no lineage scan, no sort. **Manual / job-less uploads (no ``job_uuid``) are always-latest
singletons** — never demoted. FM backend + the new schema only; never fails ingest.

Reads run through the StorageEngine (``backend.engine.page``) — indexed + uniform across the FM OData
and SQLite backends. Engine-less test fakes fall back to a ``list_fm_artifact_records`` scan.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict

# Serialize the read-modify-write of a lineage's IsLatest flag. mark_latest_on_store (the pull worker)
# and repromote_after_delete (a web request thread) both run in the ONE web process; without this a
# delete+repromote can interleave with a new-run demote and leave TWO IsLatest=1 (or briefly zero) in a
# lineage (packet 1000 Phase 2). Process-local is sufficient — all latest writes happen in-process.
_latest_lock = threading.Lock()

logger = logging.getLogger(__name__)


def latest_available(backend) -> bool:
    """True when the IsLatest flag is usable: the backend can set it AND the new schema
    (the field) is live (storage migration not pending)."""
    if backend is None or not hasattr(backend, "set_storage_is_latest"):
        return False
    try:
        from corpusfm.storage import storage_migration as M
        return not M.is_pending(backend)
    except Exception:
        return False


def job_records(backend, job_uuid, *, newest_first: bool = False, limit: int | None = None) -> list:
    """The STORAGE records of ONE job (indexed ``UUIDJob`` read). Prefers the StorageEngine;
    an engine-less test fake falls back to a full-scan Python filter. Same dict shape either way
    (``uuid``/``job_uuid``/``file_name``/``timestamp``/``is_latest``)."""
    eng = getattr(backend, "engine", None)
    if eng is not None:
        from corpusfm.storage.artifact_record import record_from_jor
        rows, _ = eng.page("STORAGE", eq={"UUIDJob": job_uuid}, orderby="ArtifactTimestamp",
                           desc=newest_first, per_page=(limit or 500), count=False)
        return [record_from_jor(r.key, r.jor) for r in rows]
    recs = [r for r in backend.list_fm_artifact_records() if r.get("job_uuid") == job_uuid]
    recs.sort(key=lambda r: r.get("timestamp", ""), reverse=newest_first)
    return recs[:limit] if limit else recs


def current_latest(backend, job_uuid) -> list:
    """Records currently flagged ``IsLatest`` within a job — normally 0 or 1 (the prior latest,
    plus the just-stored one before its demote). One indexed ``UUIDJob eq X and IsLatest eq 1``
    read; engine-less fakes filter a scan."""
    eng = getattr(backend, "engine", None)
    if eng is not None:
        from corpusfm.storage.artifact_record import record_from_jor
        rows, _ = eng.page("STORAGE", eq={"UUIDJob": job_uuid, "IsLatest": True},
                           per_page=50, count=False)
        return [record_from_jor(r.key, r.jor) for r in rows]
    return [r for r in backend.list_fm_artifact_records()
            if r.get("job_uuid") == job_uuid and r.get("is_latest")]


def mark_latest_on_store(backend, *, job_uuid, new_uuid: str = "") -> None:
    """After a job run stores a new artifact (already ``IsLatest=true``), demote any OTHER row
    still flagged latest in the job — Option A single-record demote, keyed on ``job_uuid`` alone.
    Manual uploads (no ``job_uuid``) are singletons — nothing to demote.

    ``new_uuid`` (the just-stored record) is excluded from the demote. When it's not supplied,
    fall back to a job reconcile (newest-by-timestamp wins) so the flag never lands on nothing."""
    if not job_uuid:
        return
    with _latest_lock:
        if new_uuid:
            for r in current_latest(backend, job_uuid):
                if r["uuid"] != new_uuid and r.get("is_latest"):
                    backend.set_storage_is_latest(r["uuid"], False)
        else:
            recs = job_records(backend, job_uuid)
            if recs:
                _reconcile_job(backend, recs)


def repromote_after_delete(backend, *, job_uuid) -> None:
    """After deleting an artifact, ensure its job still has a latest. If the deleted one was the
    latest, promote the next-newest by immutable timestamp. No-op for manual singletons."""
    if not job_uuid:
        return
    with _latest_lock:
        if current_latest(backend, job_uuid):
            return
        newest = job_records(backend, job_uuid, newest_first=True, limit=1)
        if newest:
            backend.set_storage_is_latest(newest[0]["uuid"], True)


def _reconcile_job(backend, members) -> int:
    """Newest member → IsLatest true, all others false. Returns # of flags flipped."""
    members.sort(key=lambda r: r.get("timestamp", ""))
    newest_uuid = members[-1]["uuid"]
    changed = 0
    for r in members:
        want = (r["uuid"] == newest_uuid)
        if bool(r.get("is_latest", False)) != want:
            backend.set_storage_is_latest(r["uuid"], want)
            changed += 1
    return changed


def backfill_latest(backend) -> dict:
    """Reconcile IsLatest across EVERY job (idempotent). Job artifacts group by ``job_uuid``;
    manual uploads are singletons (always latest). Returns {artifacts, updated}."""
    recs = backend.list_fm_artifact_records()
    groups: dict = defaultdict(list)
    for r in recs:
        ju = r.get("job_uuid", "")
        key = ju if ju else ("__manual__", r.get("uuid"))     # manual = singleton
        groups[key].append(r)
    changed = 0
    for members in groups.values():
        changed += _reconcile_job(backend, members)
    return {"artifacts": len(recs), "updated": changed}
