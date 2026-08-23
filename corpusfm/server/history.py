"""HISTORY — append-only artifact-activity event mentions (packet 085 Unit 3c).

Replaces ACTIONHISTORY + ACTIONHISTORYLINK (the event + join-table pair) and FM RUNS with a
single ``HISTORY`` logical table (``fm_registry`` TABLE5). Events are written and read through
the storage **engine** on BOTH backends — the LocalBackend SQLite mirror and the FileMaker
OData substrate share one implementation here (no per-backend duplication, no dual paths).

"Mentions of activity around artifacts" — a diff, an explorer render, a merge, a patch, a job
run, an arrival, an enrichment completion. Each row projects the query slots (Type · Timestamp ·
UUIDStorage · UUIDRelatedStorage · UUIDJob · ParentRootUUID) and snapshots
its display facts into ``snapshot`` in JSONOfRecord, so a deleted STORAGE/JOB row never breaks
rendering. **Age nothing** — the UI bounds what it shows.

Recording is best-effort: instrumentation must never break a real operation, so every writer
swallows its own errors. Artifacts are referenced by their **record UUID** — the canonical address
(packet 085 U3f); the UUIDStorage / UUIDRelatedStorage slots now genuinely hold record UUIDs (a
rename-stable foreign key), so ``list_history_for``/``purge_history_for_artifact`` are called with
the artifact's UUID and the Related reverse lookup hydrates children by ``get_by_keys``.

set_memory / delete_source / transform / apply are NOT history events — they ride the security
audit ledger (``server/audit.py``); HISTORY is artifact-activity, not an audit log.
"""
from __future__ import annotations

import logging
import uuid as _uuidlib
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_HISTORY = "HISTORY"

# ── The closed event vocabulary (12) ──────────────────────────────────────────────
ARRIVAL = "Arrival"
MERGE_PARENT_SAVEXML = "Merge Parent SaveXML"
MERGE_PARENT_ADDONXML = "Merge Parent AddonXML"
MERGE_CHILD = "Merge Child"
RUN = "Run"
DIFF = "Diff"
EXPLORER = "Explorer"
PATCH_SOURCE = "Patch Source"
PATCH_TARGET = "Patch Target"
PATCH_CHILD = "Patch Child"
ENRICH_SUMMARIES = "Enrichment Summaries"
ENRICH_INDEXING = "Enrichment Indexing"

HISTORY_TYPES = frozenset({
    ARRIVAL, MERGE_PARENT_SAVEXML, MERGE_PARENT_ADDONXML, MERGE_CHILD, RUN, DIFF, EXPLORER,
    PATCH_SOURCE, PATCH_TARGET, PATCH_CHILD, ENRICH_SUMMARIES, ENRICH_INDEXING,
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _engine(backend):
    return getattr(backend, "engine", None)


def _slots(event_type: str, *, storage_ref="", related_ref="", job_uuid="",
           parent_root_uuid="", timestamp=None) -> dict:
    return {
        "Type": event_type,
        "Timestamp": timestamp or _now(),
        "UUIDStorage": storage_ref or "",
        "UUIDRelatedStorage": related_ref or "",
        "UUIDJob": job_uuid or "",
        "ParentRootUUID": parent_root_uuid or "",
    }


# ── Low-level append (shared by artifact events + run events) ──────────────────────

def write_history_row(backend, jor: dict, *, key: str = "") -> None:
    """Append ONE HISTORY row (best-effort, never raises)."""
    try:
        eng = _engine(backend)
        if eng is None:
            return
        eng.create(_HISTORY, key or str(_uuidlib.uuid4()), jor)
    except Exception:
        logger.debug("history: write failed (best-effort)", exc_info=True)


def record_history(backend, event_type: str, *, snapshot: dict = None, **slots) -> None:
    """Write one artifact-activity event. ``slots`` = the projected keys (storage_ref /
    related_ref / job_uuid / parent_root_uuid / timestamp); ``snapshot`` =
    display facts folded into JSONOfRecord so a later deletion can't break rendering."""
    jor = _slots(event_type, **slots)
    if snapshot:
        jor["snapshot"] = dict(snapshot)
    write_history_row(backend, jor)


# ── Typed writers (the semantic events) ───────────────────────────────────────────

def record_arrival(backend, storage_ref: str, *, filename: str = "", origin: str = "",
                   owner: str = "", byte_size: int = 0, name: str = "") -> None:
    """The provenance/backup record written at landing — every artifact's birth."""
    record_history(backend, ARRIVAL, storage_ref=storage_ref,
                   snapshot={"filename": filename, "origin": origin, "owner": owner,
                             "byte_size": byte_size, "name": name})


def record_diff(backend, ref_a: str, ref_b: str, *, label_a: str = "", label_b: str = "") -> None:
    """One Diff row spanning both artifacts (each side surfaces it — UUIDStorage/UUIDRelatedStorage)."""
    record_history(backend, DIFF, storage_ref=ref_a, related_ref=ref_b,
                   snapshot={"label_a": label_a, "label_b": label_b})


def record_explorer(backend, storage_ref: str, *, label: str = "") -> None:
    record_history(backend, EXPLORER, storage_ref=storage_ref, snapshot={"label": label})


def record_merge(backend, child_ref: str, saveas_ref: str, addon_ref: str, *,
                 root_uuid: str = "") -> None:
    """The three merge rows: the child's birth-from-merge + each parent's participation. Each
    parent row carries that parent's RECORD UUID as UUIDRelatedStorage, which is both how the
    parent's own History surfaces the merge and how :func:`list_merges_built_from` reads the
    relationship backwards (packet 1216 — a parent link is a fact about a record)."""
    record_history(backend, MERGE_CHILD, storage_ref=child_ref, parent_root_uuid=root_uuid,
                   snapshot={"saveas": saveas_ref, "addon": addon_ref})
    record_history(backend, MERGE_PARENT_SAVEXML, storage_ref=child_ref, related_ref=saveas_ref,
                   parent_root_uuid=root_uuid, snapshot={"parent": saveas_ref})
    record_history(backend, MERGE_PARENT_ADDONXML, storage_ref=child_ref, related_ref=addon_ref,
                   parent_root_uuid=root_uuid, snapshot={"parent": addon_ref})


def _has_patch_child(backend, patch_ref: str) -> bool:
    """Whether a Patch Child row already exists for this patch record (indexed UUIDStorage read)."""
    eng = _engine(backend)
    if eng is None or not patch_ref:
        return False
    try:
        rows = eng.get_many(_HISTORY, "UUIDStorage", [patch_ref])
        return any((r.jor.get("Type") == PATCH_CHILD) for r in rows)
    except Exception:
        return False


def record_patch(backend, patch_ref: str, source_ref: str, target_ref: str, *,
                 label: str = "") -> None:
    """The three patch rows: the saved patch (Patch Child) + its two inputs (Patch Source on the
    before, Patch Target on the after), each cross-linked to the patch via UUIDRelatedStorage.

    Idempotent by the patch's record UUID (packet 1009/F3): a deliverable land can re-run after a
    post-commit crash (``store_deliverable`` replaces its stable pre-generated UUID), so a second
    ``record_patch`` for the same patch must NOT double-log the history rows."""
    if _has_patch_child(backend, patch_ref):
        return
    record_history(backend, PATCH_CHILD, storage_ref=patch_ref,
                   snapshot={"label": label, "source": source_ref, "target": target_ref})
    if source_ref:
        record_history(backend, PATCH_SOURCE, storage_ref=source_ref, related_ref=patch_ref,
                       snapshot={"label": label})
    if target_ref:
        record_history(backend, PATCH_TARGET, storage_ref=target_ref, related_ref=patch_ref,
                       snapshot={"label": label})


def record_enrichment(backend, storage_ref: str, kind: str) -> None:
    """An enrichment completion. ``kind`` = "summaries" | "indexing"."""
    event = ENRICH_SUMMARIES if kind == "summaries" else ENRICH_INDEXING
    record_history(backend, event, storage_ref=storage_ref)


# ── Run events (Type=Run; job-scoped via UUIDJob) ─────────────────────────────────

def record_run(backend, run) -> None:
    """Write a job-run outcome as a HISTORY Type=Run row, keyed by the run's ``run_id`` and
    linked to its job by UUIDJob (never the name — a renamed job keeps its runs)."""
    jor = {
        "Type": RUN,
        "Timestamp": getattr(run, "ts", "") or _now(),
        "UUIDStorage": "",
        "UUIDRelatedStorage": "",
        "UUIDJob": getattr(run, "job_uuid", "") or "",
        "ParentRootUUID": "",
        "snapshot": {
            "status": getattr(run, "status", ""),
            "trigger": getattr(run, "trigger", ""),
            "duration_s": getattr(run, "duration_s", 0) or 0,
            "archive_path": getattr(run, "archive_path", "") or "",
            "git_commits": getattr(run, "git_commits", None) or [],
            "error": getattr(run, "error", "") or "",
            "run_id": getattr(run, "run_id", "") or "",
            # The label frozen at write time (packet 1149). UUIDJob remains the only link; this is
            # display data, so a renamed-away or deleted job never re-labels or hides its history.
            "job_name": getattr(run, "job_name", "") or "",
        },
    }
    _upsert_run_row(backend, jor, getattr(run, "run_id", "") or "")


def _upsert_run_row(backend, jor: dict, run_id: str) -> None:
    """Idempotent terminal write for a Type=Run row (packet 1058 P0-B). A Restart re-runs the SAME
    logical ``run_id``; because ``eng.create`` is INSERT-ONLY (FM OData POST / SQLite INSERT) and
    ``write_history_row`` swallows the duplicate-key failure, a naive create would silently DROP a
    restart's outcome and leave the run stuck showing its first error. So when a Type=Run row already
    exists for this ``run_id`` we UPDATE it in place (the latest attempt wins); otherwise create it.
    A run with NO ``run_id`` (a legacy/very-early error with no stable key) is appended under a fresh
    key, exactly as before.

    Scope (guardrail): update-in-place lives ONLY here, for Type=Run. Every other event type keeps the
    append-only ``write_history_row`` path — this function must never be reused for a non-Run row."""
    try:
        eng = _engine(backend)
        if eng is None:
            return
        if not run_id:
            eng.create(_HISTORY, str(_uuidlib.uuid4()), jor)
            return
        exists = False
        try:
            rows = eng.get_by_keys(_HISTORY, [run_id])
            exists = any((r.jor or {}).get("Type") == RUN for r in rows)
        except Exception:
            exists = False
        if exists:
            eng.update(_HISTORY, run_id, jor)
        else:
            eng.create(_HISTORY, run_id, jor)
    except Exception:
        logger.debug("history: record_run upsert failed (best-effort)", exc_info=True)


def get_run_record(backend, run_id: str):
    """The exact Type=Run row for a ``run_id`` (packet 1058 P0-B), as a ``RunRecord``, or ``None``.
    An O(1) primary-key read — ``run_id`` IS the HISTORY key. Never falls back to 'the latest run':
    an unknown id returns ``None`` so ``get_job_run`` can report an honest not-found."""
    if not run_id:
        return None
    eng = _engine(backend)
    if eng is None:
        return None
    try:
        rows = eng.get_by_keys(_HISTORY, [run_id])
    except Exception:
        logger.debug("history: get_run_record failed for '%s'", run_id, exc_info=True)
        return None
    from corpusfm.server.jobs.history import RunRecord
    for r in rows:
        j = r.jor
        if j.get("Type") != RUN:
            continue
        s = j.get("snapshot") or {}
        return RunRecord(
            ts=j.get("Timestamp", ""),
            status=s.get("status", ""),
            trigger=s.get("trigger", ""),
            duration_s=s.get("duration_s", 0.0) or 0.0,
            archive_path=s.get("archive_path") or None,
            git_commits=s.get("git_commits") or None,
            error=s.get("error") or None,
            run_id=s.get("run_id") or r.key,
            job_uuid=j.get("UUIDJob") or None,
            job_name=s.get("job_name") or None,
        )
    return None


def list_run_records(backend, job_uuid: str, limit: int = 50) -> list:
    """The most recent Type=Run rows for a job (newest first), as ``RunRecord`` objects.

    Runs link to their job by UUIDJob; without it the query can't be scoped → []. Run counts
    per job are small, so one indexed UUIDJob read + a Python sort is enough on both backends."""
    if not job_uuid:
        return []
    eng = _engine(backend)
    if eng is None:
        return []
    try:
        rows = eng.get_many(_HISTORY, "UUIDJob", [job_uuid])
    except Exception:
        logger.debug("history: list_run_records failed for job_uuid '%s'", job_uuid, exc_info=True)
        return []
    from corpusfm.server.jobs.history import RunRecord
    out = []
    for r in rows:
        j = r.jor
        if j.get("Type") != RUN or j.get("UUIDJob") != job_uuid:
            continue
        s = j.get("snapshot") or {}
        out.append(RunRecord(
            ts=j.get("Timestamp", ""),
            status=s.get("status", ""),
            trigger=s.get("trigger", ""),
            duration_s=s.get("duration_s", 0.0) or 0.0,
            archive_path=s.get("archive_path") or None,
            git_commits=s.get("git_commits") or None,
            error=s.get("error") or None,
            run_id=s.get("run_id") or r.key,
            job_uuid=j.get("UUIDJob") or None,
            job_name=s.get("job_name") or None,
        ))
    out.sort(key=lambda r: r.ts, reverse=True)
    return out[: max(0, limit)] if limit else out


def list_all_runs(backend, limit: int = 500) -> list:
    """Every Type=Run row, newest first — regardless of whether its job still exists (packet 1149).

    The per-job reader above answers "this job's runs"; this one answers "what has run", which is a
    different question and the one a history page must ask. Enumerating live job configs instead drops
    the runs of a DELETED job even though their HISTORY rows are intact — history that exists but
    cannot be reached is the failure this packet is about. Each row carries its own frozen job label,
    so nothing here needs the job to be alive."""
    eng = _engine(backend)
    if eng is None:
        return []
    try:
        rows, _ = eng.page(_HISTORY, eq={"Type": RUN}, orderby="Timestamp", desc=True,
                           page=1, per_page=(limit or 500), count=False)
    except Exception:
        logger.debug("history: list_all_runs failed", exc_info=True)
        return []
    from corpusfm.server.jobs.history import RunRecord
    out = []
    for r in rows:
        j = r.jor
        if j.get("Type") != RUN:
            continue
        s = j.get("snapshot") or {}
        out.append(RunRecord(
            ts=j.get("Timestamp", ""),
            status=s.get("status", ""),
            trigger=s.get("trigger", ""),
            duration_s=s.get("duration_s", 0.0) or 0.0,
            archive_path=s.get("archive_path") or None,
            git_commits=s.get("git_commits") or None,
            error=s.get("error") or None,
            run_id=s.get("run_id") or r.key,
            job_uuid=j.get("UUIDJob") or None,
            job_name=s.get("job_name") or None,
        ))
    out.sort(key=lambda r: r.ts or "", reverse=True)
    return out[: max(0, limit)] if limit else out


# ── Readers (the detail History tab + the Logs page) ──────────────────────────────

def _row_view(row) -> dict:
    """A HISTORY row as a display dict. Carries both the new event fields and the
    ``action``/``tool``/``details``/``artifact_refs`` keys the existing Logs + History-tab UI
    consumes, so the frontend is unchanged this unit."""
    jor = row.jor
    snap = jor.get("snapshot", {})
    if not isinstance(snap, dict):
        snap = {}
    refs = [r for r in (jor.get("UUIDStorage", ""), jor.get("UUIDRelatedStorage", "")) if r]
    return {
        "id": row.key,
        "type": jor.get("Type", ""),
        "ts": jor.get("Timestamp", ""),
        "storage_ref": jor.get("UUIDStorage", ""),
        "related_ref": jor.get("UUIDRelatedStorage", ""),
        "job_uuid": jor.get("UUIDJob", ""),
        "snapshot": snap,
        # UI-compat keys (Logs panel / detail History tab):
        "action": jor.get("Type", ""),
        "tool": snap.get("tool", ""),
        "details": snap,
        "artifact_refs": refs,
    }


def list_history(backend, limit: int = 200) -> list[dict]:
    """All HISTORY events, newest-first (the Logs page)."""
    eng = _engine(backend)
    if eng is None:
        return []
    try:
        rows, _ = eng.page(_HISTORY, orderby="Timestamp", desc=True,
                           page=1, per_page=(limit or 200))
    except Exception:
        logger.debug("history: list_history failed", exc_info=True)
        return []
    return [_row_view(r) for r in rows]


def list_history_for(backend, storage_ref: str, limit: int = 200) -> list[dict]:
    """One artifact's history, newest-first — rows where it is the primary (UUIDStorage) OR the
    counterpart (UUIDRelatedStorage, e.g. a diff/patch/merge partner). Two indexed reads + a
    Python merge; the slot match is case-insensitive on FM so exact refs are re-checked."""
    if not storage_ref:
        return []
    eng = _engine(backend)
    if eng is None:
        return []
    try:
        rows = list(eng.get_many(_HISTORY, "UUIDStorage", [storage_ref]))
        rows += list(eng.get_many(_HISTORY, "UUIDRelatedStorage", [storage_ref]))
    except Exception:
        logger.debug("history: list_history_for failed for '%s'", storage_ref, exc_info=True)
        return []
    seen: set = set()
    out: list[dict] = []
    for r in rows:
        if r.key in seen:
            continue
        j = r.jor
        if j.get("UUIDStorage") != storage_ref and j.get("UUIDRelatedStorage") != storage_ref:
            continue  # defensive: only exact-ref rows
        seen.add(r.key)
        out.append(_row_view(r))
    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return out[: max(0, limit)] if limit else out


def list_merges_built_from(backend, parent_uuid: str, limit: int = 200) -> list[dict]:
    """The reverse Related lookup: the merges built FROM this artifact.

    A merge stamps each parent-participation row (Merge Parent SaveXML / AddonXML) with that
    parent's RECORD UUID in ``UUIDRelatedStorage``, so an indexed read on that slot finds every
    merge child this artifact fed. Each row's ``UUIDStorage`` is the merge child; the caller
    hydrates it (or renders the snapshot when the child is gone). Newest-first, deduped by child.

    This used to key off the parent's content hash so the link would survive a REIMPORT, which a
    record UUID does not. Packet 1216 ruled that trade the wrong way round: a reimported parent is
    a new record, and a link that cannot travel should not pretend it can."""
    if not parent_uuid:
        return []
    eng = _engine(backend)
    if eng is None:
        return []
    try:
        rows = eng.get_many(_HISTORY, "UUIDRelatedStorage", [parent_uuid])
    except Exception:
        logger.debug("history: list_merges_built_from failed for '%s'", parent_uuid, exc_info=True)
        return []
    seen: set = set()
    out: list[dict] = []
    for r in rows:
        j = r.jor
        if j.get("Type") not in (MERGE_PARENT_SAVEXML, MERGE_PARENT_ADDONXML):
            continue
        if (j.get("UUIDRelatedStorage") or "") != parent_uuid:  # FM slot match is case-insensitive
            continue
        child = j.get("UUIDStorage", "")
        if not child or child in seen:
            continue
        seen.add(child)
        snap = j.get("snapshot") if isinstance(j.get("snapshot"), dict) else {}
        out.append({"child_ref": child, "type": j.get("Type", ""),
                    "ts": j.get("Timestamp", ""), "snapshot": snap})
    out.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return out[: max(0, limit)] if limit else out


def purge_history_for_artifact(backend, storage_ref: str) -> None:
    """Drop every HISTORY row mentioning this artifact (primary or counterpart). Called on
    artifact delete — 'no artifact, no history'."""
    if not storage_ref:
        return
    eng = _engine(backend)
    if eng is None:
        return
    try:
        rows = list(eng.get_many(_HISTORY, "UUIDStorage", [storage_ref]))
        rows += list(eng.get_many(_HISTORY, "UUIDRelatedStorage", [storage_ref]))
    except Exception:
        logger.debug("history: purge listing failed for '%s'", storage_ref, exc_info=True)
        return
    done: set = set()
    for r in rows:
        if r.key in done:
            continue
        j = r.jor
        if j.get("UUIDStorage") != storage_ref and j.get("UUIDRelatedStorage") != storage_ref:
            continue  # slot match is case-insensitive; delete exact-ref rows only
        done.add(r.key)
        try:
            eng.delete(_HISTORY, r.key)
        except Exception:
            logger.debug("history: purge delete failed for row %s", r.key, exc_info=True)
