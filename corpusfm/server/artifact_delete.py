"""The single artifact-removal cascade + bulk retention pruning that uses it (packet 1054).

One place performs the full removal of an artifact so the interactive delete route and retention
pruning cannot drift. The cascade is: record delete (each backend's ``delete_artifact`` also purges
the artifact's HISTORY), tag/lineage cache bust, vector deindex (best-effort, embedder-gated), and
latest-lineage repromotion. Each step is guarded so one failure never aborts the rest.

Retention previously raw-deleted job artifacts in the backend, bypassing deindex + cache-bust +
repromotion (and, on the FM backend, history). ``prune_job_artifacts`` routes each pruned artifact
through the same cascade, so "delete the artifact, the index goes with it" holds for pruning too.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def delete_artifact_fully(backend, uuid: str) -> bool:
    """Fully remove ONE artifact (by record uuid) through the whole cascade. Returns False if the
    artifact was not found. Steps after the record delete are best-effort — a failing enrichment/
    cache/latest step never resurrects the record or aborts the others."""
    meta = backend.get_artifact_meta(uuid)
    if meta is None:
        return False
    job_uuid = getattr(meta, "job_uuid", "") or ""

    # Deindex FIRST — drop THIS artifact's vectors (by record uuid, so sibling versions + same-named
    # files survive; no-op when no embedder is configured). Ordering matters for crash-safety (packet
    # 1000 P2): a crash between the record delete and the deindex would strand orphan vectors pointing at
    # a gone record (semantic_search surfaces hits that resolve to nothing, with no reconcile sweep).
    # Deindexing first means a crash instead leaves a still-present record with a stale-but-recoverable
    # index that self-corrects on the next enrichment.
    try:
        from corpusfm.server.ai.vector_index import has_embedding_configured, get_vector_index
        from corpusfm.app.app_config import load_app_config
        cfg = load_app_config()
        if has_embedding_configured(cfg):
            idx = get_vector_index(cfg)
            if idx is not None:
                idx.delete_artifact(uuid)
    except Exception:
        logger.debug("delete cascade: deindex failed for %s", uuid, exc_info=True)

    # Publishes the removal itself (packet 1361-01); also purges the artifact's history (both backends).
    backend.delete_artifact(uuid)

    # Repoint this job's PROMOTION link at the newest survivor (packet 1361-01). With no survivor
    # the link is kept with a blank target, and the lineage's remaining artifacts — if any ever
    # return — read as temporarily latest rather than as none.
    #
    # It lives HERE, in the cascade, and deliberately NOT in `backend.delete_artifact`: a low-level
    # deletion method must not carry lineage policy, or every caller of it silently acquires a
    # promotion side effect it never asked for.
    try:
        from corpusfm.server import latest as _latest
        if _latest.latest_available(backend):
            _latest.repromote_after_delete(backend, job_uuid=job_uuid)
    except Exception:
        logger.debug("delete cascade: repromote failed for %s", uuid, exc_info=True)

    return True


def prune_job_artifacts(backend, job_uuid: str, max_keep: int) -> int:
    """Retention: remove a job's artifacts beyond the newest ``max_keep`` — each through the full
    cascade (deindex + history + cache-bust + repromote), never a raw record delete. Returns the
    number removed. A no-op when the backend can't enumerate a job's artifacts."""
    if max_keep <= 0 or not job_uuid:
        return 0
    if not hasattr(backend, "overlimit_job_artifacts"):
        return 0
    removed = 0
    for uuid in backend.overlimit_job_artifacts(job_uuid, max_keep):
        try:
            if delete_artifact_fully(backend, uuid):
                removed += 1
        except Exception:
            logger.debug("prune: delete_artifact_fully failed for %s", uuid, exc_info=True)
    return removed
