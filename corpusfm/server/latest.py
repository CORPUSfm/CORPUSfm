"""Latest-artifact promotion — one STORAGELINK row per job lineage (packet 1361-01).

**The `IsLatest` flag is gone from artifact JSON.** It was a per-record boolean that every producer
had to remember to flip and every deleter had to remember to repair, so "which artifact is current"
was a property spread across N records that nothing could assert as a whole. Promotion is now ONE
relationship row:

    STORAGELINK  Type="Latest Artifact"  UUIDJob=<job>  UUIDStorage=<artifact>

keyed at a DETERMINISTIC record UUID derived from the job (:func:`promotion_key`), so a lineage
structurally cannot carry two promotions and a promote is an idempotent upsert rather than a
read-modify-write race.

**Lineage is ``job_uuid`` alone** (packet 086 / Ruling A, unchanged). A Job is created against
exactly one hosted file and produces one artifact per run. ``FileName`` (repair-editable) and
``RootUUID`` are both out of the key.

Semantics — the developer's ruling, and the last clause is the one that matters:

* an artifact with **no job** is latest;
* a promotion resolving to a **current STORAGE artifact** makes exactly that artifact latest;
* a promotion that is **missing, blank or unresolvable** makes **every artifact in that lineage
  temporarily latest** — "we cannot tell which one is current" must never render as "none of them",
  which is what a dangling pointer would otherwise do to a whole lineage's visibility.

The catalog derives the verdict from its own synchronized STORAGELINK rows (``catalog._Index``); it
never asks this module at read time. What lives here is the WRITE side plus the one-time startup
conversion and repair.
"""

from __future__ import annotations

import logging
import threading
import uuid as _uuid

logger = logging.getLogger(__name__)

_STORAGE = "STORAGE"
_LINK = "STORAGELINK"
_JOB = "JOB"

LATEST_LINK = "Latest Artifact"

# Serialize the read-modify-write of a lineage's promotion. `mark_latest_on_store` (the pull worker)
# and `repromote_after_delete` (a web request thread) both run in the ONE web process, and both run
# only AFTER startup has finished — the startup conversion is not a participant in this lock's
# reason for existing (packet 1361-01, ruling 8).
_latest_lock = threading.Lock()

# The deterministic key namespace. A promotion link's record UUID is a pure function of its job, so
# two concurrent promotions collide on ONE row instead of minting two.
_PROMOTION_NS = _uuid.UUID("6f1a2c48-0e3d-4a71-9d55-9a2c3f0b7e10")


def promotion_key(job_uuid: str) -> str:
    """The STORAGELINK record key that holds this job's promotion. Stable, derived, collision-free."""
    return str(_uuid.uuid5(_PROMOTION_NS, f"latest:{job_uuid}"))


def _link_jor(job_uuid: str, artifact_uuid: str) -> dict:
    return {"Type": LATEST_LINK, "UUIDJob": job_uuid, "UUIDStorage": artifact_uuid or ""}


def latest_available(backend) -> bool:
    """True when promotion links are usable: the backend exposes a StorageEngine AND the schema is
    live (the storage migration is not pending)."""
    if backend is None or getattr(backend, "engine", None) is None:
        return False
    try:
        from corpusfm.storage import storage_migration as M
        return not M.is_pending(backend)
    except Exception:
        return False


# ── reads (authoritative, keyed — never a scan) ───────────────────────────────────

def promoted_uuid(backend, job_uuid: str) -> str:
    """The artifact this job's promotion names, read AUTHORITATIVELY by the link's own key.

    Deliberately not a catalog read: a promote is a read-modify-write and must not act on a view
    that may be up to the reconciliation age stale."""
    if not job_uuid:
        return ""
    eng = getattr(backend, "engine", None)
    if eng is None:
        return ""
    rows = eng.get_by_keys(_LINK, [promotion_key(job_uuid)])
    if not rows:
        return ""
    jor = rows[0].jor if isinstance(rows[0].jor, dict) else {}
    return jor.get("UUIDStorage") or "" if jor.get("Type") == LATEST_LINK else ""


def job_records(backend, job_uuid, *, newest_first: bool = False, limit: int | None = None) -> list:
    """The STORAGE records of ONE job (indexed ``UUIDJob`` read), newest-first when asked."""
    eng = getattr(backend, "engine", None)
    if eng is None or not job_uuid:
        return []
    from corpusfm.storage.artifact_record import record_from_jor
    rows, _ = eng.page(_STORAGE, eq={"UUIDJob": job_uuid}, orderby="ArtifactTimestamp",
                       desc=newest_first, per_page=(limit or 500), count=False)
    return [record_from_jor(r.key, r.jor) for r in rows]


# ── writes ────────────────────────────────────────────────────────────────────────

def _upsert(backend, job_uuid: str, artifact_uuid: str) -> None:
    """Create-or-update the one promotion row for ``job_uuid``. Publishes what the substrate
    confirmed; never raises out of a best-effort caller."""
    from corpusfm.server import catalog
    eng = backend.engine
    key = promotion_key(job_uuid)
    jor = _link_jor(job_uuid, artifact_uuid)
    existing = eng.get_by_keys(_LINK, [key])
    if existing:
        if (existing[0].jor or {}).get("UUIDStorage") == (artifact_uuid or ""):
            return                                    # already promoted — no write, no publication
        written = eng.update(_LINK, key, jor)
    else:
        written = eng.create(_LINK, key, jor)
    catalog.publish_write(backend, catalog.TABLE_LINK, key, written, operation="promote_latest")


def promote(backend, job_uuid: str, artifact_uuid: str) -> None:
    """Make ``artifact_uuid`` the current artifact of ``job_uuid``. Idempotent."""
    if not job_uuid:
        return
    with _latest_lock:
        _upsert(backend, job_uuid, artifact_uuid)


def mark_latest_on_store(backend, *, job_uuid, new_uuid: str = "") -> None:
    """After a job run stores a new artifact, PROMOTE it. Manual uploads (no ``job_uuid``) are
    job-less singletons and are always latest — nothing to write.

    Replaces the Option-A demote sweep: there is no other record to change, because the flag it used
    to clear no longer exists."""
    if not job_uuid:
        return
    if not latest_available(backend):
        return
    try:
        with _latest_lock:
            target = new_uuid
            if not target:
                newest = job_records(backend, job_uuid, newest_first=True, limit=1)
                target = newest[0]["uuid"] if newest else ""
            if target:
                _upsert(backend, job_uuid, target)
    except Exception:
        logger.warning("latest: promotion after store failed for job %s", job_uuid, exc_info=True)


def repromote_after_delete(backend, *, job_uuid) -> None:
    """After an artifact is deleted, repoint this job's promotion at the newest SURVIVOR.

    With no survivor the link is RETAINED with a blank ``UUIDStorage`` (developer ruling): the
    lineage still exists as a job, and dropping the row would lose the fact that this job is one
    CORPUSfm promotes for. The startup repair is the only thing that removes a promotion, and only
    when neither a live JOB nor any live lineage artifact remains."""
    if not job_uuid or not latest_available(backend):
        return
    try:
        with _latest_lock:
            newest = job_records(backend, job_uuid, newest_first=True, limit=1)
            _upsert(backend, job_uuid, newest[0]["uuid"] if newest else "")
    except Exception:
        logger.warning("latest: repromotion after delete failed for job %s", job_uuid, exc_info=True)


# ── startup conversion + repair (idempotent; runs once, never inside a read) ───────

_LEGACY_FLAG = "IsLatest"


def _truthy(v) -> bool:
    return v in (True, 1, "1", "true", "True")


def convert_and_repair(backend) -> dict:
    """Bring every job lineage to exactly one resolvable promotion. Idempotent and bounded.

    Four things happen, in this order, and each is a no-op on an already-correct corpus:

    1. **CONVERT** a lineage that has no promotion yet, preferring the UNIQUE legacy ``IsLatest``
       row and otherwise the newest ``ArtifactTimestamp``. This is the only place the retired flag
       is ever read.
    2. **DEDUPE** — any promotion row for a job other than the one at its deterministic key is
       removed, after its target has been considered.
    3. **RE-RESOLVE** a promotion whose target is not a current artifact of that lineage, pointing
       it at the newest survivor (or blank when the lineage is empty).
    4. **REMOVE** a promotion with neither a live JOB nor any live lineage artifact — the only
       deletion this module performs.

    Returns a summary. Raises nothing; an incomplete read ABORTS without writing, because a partial
    picture of the lineage is exactly the state in which a repair would delete something real.

    **It runs in the SYNCHRONOUS startup prerequisite chain, and that placement is what makes it
    correct** (packet 1361-01, ruling 5/8). This is a read-modify-write over the whole lineage
    picture: it snapshots STORAGE, STORAGELINK and JOB, decides, and then writes. Nothing else may
    be promoting while it does — and nothing is, because the queue workers, the scheduler, the
    background mutations and request serving all start AFTER it returns. An earlier revision ran it
    in a boot daemon thread and tried to buy safety with a lock held across the repair walk; that
    does not help, because the snapshot it repairs from was taken before the lock. The fix is the
    ordering, and no concurrency machinery is added here to accommodate a race that the ordering
    removes.
    """
    out = {"ok": False, "lineages": 0, "converted": 0, "repointed": 0,
           "deduped": 0, "removed": 0, "reason": "", "read_failed": False, "write_failed": False}
    eng = getattr(backend, "engine", None)
    if eng is None:
        out["reason"] = "no storage engine"
        return out
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    try:
        members: dict = {}
        legacy: dict = {}
        stamps: dict = {}
        for r in eng.list_where(_STORAGE, isin={"Type": sorted(VISIBLE_TYPES)}):
            jor = r.jor if isinstance(r.jor, dict) else {}
            job = jor.get("UUIDJob") or ""
            if not job:
                continue
            members.setdefault(job, []).append(r.key)
            stamps[r.key] = jor.get("ArtifactTimestamp") or ""
            if _truthy(jor.get(_LEGACY_FLAG)):
                legacy.setdefault(job, []).append(r.key)
        links = [r for r in eng.list_where(_LINK, eq={"Type": LATEST_LINK})]
        live_jobs = {r.key for r in eng.list_all(_JOB)}
    except Exception as exc:                                       # noqa: BLE001
        out["reason"] = f"{type(exc).__name__}: {exc}"
        # `read_failed` is the machine-readable half of the same fact, and the startup authority
        # branches on it (packet 1361-01, round 3): an incomplete read STOPS the startup attempt,
        # while "no storage engine" above is a safe decline that must not.
        out["read_failed"] = True
        logger.warning("latest: promotion repair aborted on an incomplete read — nothing was "
                       "changed", exc_info=True)
        return out

    by_job: dict = {}
    for r in links:
        jor = r.jor if isinstance(r.jor, dict) else {}
        by_job.setdefault(jor.get("UUIDJob") or "", []).append((r.key, jor.get("UUIDStorage") or ""))

    from corpusfm.server import catalog
    jobs = set(members) | {j for j in by_job if j}
    out["lineages"] = len(jobs)
    # The lock is taken for form, not for safety: the startup ordering above guarantees no other
    # promotion writer exists yet. It costs nothing and keeps every mutation of a promotion row
    # going through one door.
    with _latest_lock:
        _repair_lineages(backend, eng, jobs, members, by_job, stamps, legacy, live_jobs, out,
                         catalog)
    if out["write_failed"]:
        # A PARTIALLY APPLIED REPAIR IS NOT A COMPLETED ONE (packet 1361-01, round 4). Every write
        # below used to be swallowed into a debug line and this still answered `ok: True` — so a
        # lineage left with two promotions, or with none, was reported as repaired. The walk stops at
        # the first failed write and says so; what it already applied stays applied (each write is
        # idempotent and the next attempt re-derives from the substrate), and the startup authority
        # stops the attempt rather than opening a box whose promotions are half-converted.
        logger.error("latest: promotion repair could not complete (%s); %d converted, %d repointed, "
                     "%d deduped, %d removed before it stopped", out["reason"], out["converted"],
                     out["repointed"], out["deduped"], out["removed"])
        return out
    out["ok"] = True
    logger.info("latest: promotion repair over %d lineage(s) — %d converted, %d repointed, "
                "%d deduped, %d removed", out["lineages"], out["converted"], out["repointed"],
                out["deduped"], out["removed"])
    return out


def _repair_lineages(backend, eng, jobs, members, by_job, stamps, legacy, live_jobs, out,
                     catalog) -> None:
    """The repair walk itself — called with :data:`_latest_lock` held."""
    for job in sorted(jobs):
        canonical = promotion_key(job)
        rows = by_job.get(job, [])
        current = next((t for k, t in rows if k == canonical), None)
        strays = [k for k, _t in rows if k != canonical]
        pool = members.get(job, [])

        if out["write_failed"]:
            return                      # the substrate is not answering; stop the walk
        if not pool and job not in live_jobs:
            # Ruling: a promotion with neither a live JOB nor any live lineage artifact may go.
            doomed = ([canonical] if current is not None else []) + strays
            for k in doomed:
                try:
                    eng.delete(_LINK, k)
                except Exception as exc:                            # noqa: BLE001
                    out["write_failed"] = True
                    out["reason"] = (f"the orphan promotion {k} could not be removed: "
                                     f"{type(exc).__name__}: {exc}")
                    return
                catalog.publish_deleted(backend, catalog.TABLE_LINK, k)
                out["removed"] += 1
            continue

        want = current if (current and current in pool) else None
        if want is None:
            # Prefer a stray that DOES resolve (it carried the real answer), then the unique legacy
            # flag, then the newest timestamp.
            want = next((t for _k, t in rows if t and t in pool), None)
            if want is None:
                flagged = [u for u in legacy.get(job, []) if u in pool]
                want = flagged[0] if len(flagged) == 1 else None
            if want is None and pool:
                want = max(pool, key=lambda u: (stamps.get(u, ""), u))
            want = want or ""

        for k in strays:
            try:
                eng.delete(_LINK, k)
            except Exception as exc:                                # noqa: BLE001
                out["write_failed"] = True
                out["reason"] = (f"the duplicate promotion {k} could not be removed: "
                                 f"{type(exc).__name__}: {exc}")
                return
            catalog.publish_deleted(backend, catalog.TABLE_LINK, k)
            out["deduped"] += 1

        if current is None:
            try:
                _upsert(backend, job, want)
            except Exception as exc:                                # noqa: BLE001
                out["write_failed"] = True
                out["reason"] = (f"the promotion for job {job} could not be minted: "
                                 f"{type(exc).__name__}: {exc}")
                return
            out["converted"] += 1
        elif current != want:
            try:
                _upsert(backend, job, want)
            except Exception as exc:                                # noqa: BLE001
                out["write_failed"] = True
                out["reason"] = (f"the promotion for job {job} could not be repointed: "
                                 f"{type(exc).__name__}: {exc}")
                return
            out["repointed"] += 1
