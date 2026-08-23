"""Indexed corpus management API.

Vector-index management (list/reset/delete/check) stays here. The enrichment ACTIONS
(summarize / index / de-index) no longer run inline — they ENQUEUE one QUEUE record per target
(packet 086; each artifact is its own laundry-list record) and return {queued: N}. Work is never
rejected; the Queue page (/queue, /api/queue) is the shared, system-wide view of what's running.
Cancel/restart/clear live on the queue router.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import current_user, require_auth, require_any_gate

log = logging.getLogger("corpusfm.indexed")

# Vector-index management is reachable from both the Library page (Artifacts) and admin Settings →
# Integrations, so it requires EITHER the library_mcp gate OR settings (admin).
router = APIRouter(dependencies=[Depends(require_auth),
                                 Depends(require_any_gate("library_mcp", "settings"))])


def _get_index():
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index
    return get_vector_index(load_app_config())


def _embedder_configured() -> bool:
    return _get_index() is not None


def _summary_provider_configured() -> bool:
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai import summary_provider_ready
    return summary_provider_ready(load_app_config())


def _bust_indexed_badge_cache() -> None:
    try:
        from corpusfm.app.web.routes.api.library import invalidate_indexed_cache
        invalidate_indexed_cache()
    except Exception:
        pass


def _owner(request: Request) -> str:
    u = current_user(request)
    return getattr(u, "username", None) or "local"


# ── Vector-index management (unchanged) ────────────────────────────────────────

@router.get("/indexed/list")
def list_indexed() -> JSONResponse:
    """Return grouped summary of what's in the vector index."""
    index = _get_index()
    if index is None:
        return JSONResponse({"ok": True, "configured": False, "rows": [], "total": 0})
    rows = index.list_indexed()
    total = sum(r["count"] for r in rows)
    est_total = sum(r.get("est_bytes", 0) for r in rows)
    disk_bytes = index.disk_usage_bytes()
    return JSONResponse({"ok": True, "configured": True, "rows": rows,
                         "total": total, "est_total_bytes": est_total,
                         "disk_bytes": disk_bytes})


@router.post("/indexed/reset")
def reset_index() -> JSONResponse:
    """Wipe the ENTIRE vector index (drop + recreate the collection)."""
    index = _get_index()
    if index is None:
        return JSONResponse({"ok": False, "error": "No embedder configured — nothing to reset."},
                            status_code=400)
    try:
        cleared = index.count()
        index.reset()
        _bust_indexed_badge_cache()
        return JSONResponse({"ok": True, "cleared": cleared})
    except Exception as exc:
        log.warning("index reset failed", exc_info=True)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/indexed/artifact/{uuid}")
def deindex_artifact(uuid: str) -> JSONResponse:
    """De-index ONE artifact (immediate; not queued) — the per-artifact inverse of the index action,
    keyed by the record uuid, so siblings + same-named files are untouched. Registered before the
    {file_name:path} catch-all so this path isn't swallowed by it."""
    index = _get_index()
    if index is None:
        return JSONResponse({"ok": False, "error": "Vector index not configured."}, status_code=400)
    if not uuid:
        return JSONResponse({"ok": False, "error": "Artifact not found."}, status_code=404)
    deleted = index.delete_artifact(uuid)
    _bust_indexed_badge_cache()
    return JSONResponse({"ok": True, "deleted": deleted, "uuid": uuid})


@router.delete("/indexed/{file_name:path}")
def delete_indexed(file_name: str) -> JSONResponse:
    """Delete EVERY indexed artifact whose file name matches (immediate; not queued) — the whole-file
    admin/scripting + MCP file-name convenience. The human UI de-indexes per artifact (see above)."""
    index = _get_index()
    if index is None:
        return JSONResponse({"ok": False, "error": "Vector index not configured."}, status_code=400)
    deleted = index.delete_file(file_name)
    _bust_indexed_badge_cache()
    return JSONResponse({"ok": True, "deleted": deleted, "file_name": file_name})


@router.get("/indexed/check")
def check_indexed(uuid: str = "") -> JSONResponse:
    """Check whether ONE artifact is in the vector index (per-artifact, keyed by the record uuid).
    Returns {configured, indexed, count}."""
    from corpusfm.app.web.routes.api.library import _embedder_on, indexed_status
    if not _embedder_on():
        return JSONResponse({"configured": False, "indexed": False, "count": 0})
    if not uuid:
        return JSONResponse({"configured": True, "indexed": False, "count": 0})
    indexed, count = indexed_status(uuid)
    return JSONResponse({"configured": True, "indexed": indexed, "count": count})


# ── Enrichment actions → enqueue QUEUE records (packet 086; never reject) ──────

def _enqueue_sync(kind: str, targets: list[str], owner: str) -> int:
    """Enqueue one QUEUE record per target (packet 086 — each artifact is its own laundry-list
    record). Returns the count queued (deduped entries are skipped). Blocking — call off the loop."""
    from corpusfm.server import queue_handlers
    from corpusfm.storage import get_backend
    from corpusfm.storage.queue_record import INDEX, SUMMARIZE
    be = get_backend()
    n = 0
    for t in targets:
        if kind == "deindex":
            queue_handlers.enqueue_deindex(be, t, owner=owner)
            n += 1
        else:
            # Type guard (packet 1035): don't enqueue an op a KNOWN record can't complete — it would
            # park a FAILED queue row (the doomed auto-index-on-paste bug). INDEX handles schema +
            # fmClip/fmScript/fmCalc (deliverable text); PatchXML has no searchable content. SUMMARIZE
            # is schema-only (a deliverable has no items/summaries). An unknown/unresolved target is
            # left permissive (the worker handles it) so callers passing bare refs aren't blocked.
            meta = be.get_artifact_meta(t)
            if meta is not None:
                from corpusfm.artifact.capabilities import is_indexable_type
                is_schema = getattr(meta, "is_schema", False)
                atype = getattr(meta, "artifact_type", "")
                if kind == "index":
                    if not is_indexable_type(atype):     # schema + fmClip/fmScript/fmCalc; not PatchXML
                        continue
                elif not is_schema:                      # SUMMARIZE stays schema-only
                    continue
            step = SUMMARIZE if kind == "summarize" else INDEX
            if queue_handlers.enqueue_enrichment_steps(be, t, [step], owner=owner):
                n += 1
    return n


async def _enqueue(kind: str, targets: list[str], request: Request) -> JSONResponse:
    # The enqueue does BLOCKING FM OData reads (dedup scans) + writes; offload it off the event loop.
    owner = _owner(request)
    try:
        queued = await run_in_threadpool(_enqueue_sync, kind, targets, owner)
    except Exception:
        log.warning("enqueue %s failed", kind, exc_info=True)
        return JSONResponse(
            {"ok": False, "error": "Could not queue the job — storage is unreachable. Try again."},
            status_code=503,
        )
    return JSONResponse({"ok": True, "queued": queued})


def _targets(body) -> list[str]:
    """Record-UUID enrichment targets (packet 085 U3f). Accepts `uuids` (canonical); tolerates the
    transitional `rel_paths` key (values are UUIDs)."""
    raw = body.get("uuids") or body.get("rel_paths") or []
    out: list[str] = []
    for p in raw:
        s = str(p).strip()
        if s and s not in out:
            out.append(s)
    return out


@router.post("/indexed/index-batch")
async def index_batch(request: Request) -> JSONResponse:
    """Enqueue an index job for a list of artifacts. Body: {uuids: [record-uuid]}."""
    if not _embedder_configured():
        return JSONResponse({"ok": False, "error": "Vector index not configured."}, status_code=400)
    body = await request.json()
    targets = _targets(body)
    if not targets:
        return JSONResponse({"ok": False, "error": "uuids required"}, status_code=400)
    return await _enqueue("index", targets, request)


@router.post("/indexed/summarize-batch")
async def summarize_batch(request: Request) -> JSONResponse:
    """Enqueue a summarize job for a list of artifacts. Body: {uuids: [record-uuid]}.
    Gated on the summary (chat) provider — independent of the embedder (D3)."""
    if not _summary_provider_configured():
        return JSONResponse({"ok": False, "error": "No AI summary (chat) provider configured."},
                            status_code=400)
    body = await request.json()
    targets = _targets(body)
    if not targets:
        return JSONResponse({"ok": False, "error": "uuids required"}, status_code=400)
    return await _enqueue("summarize", targets, request)


@router.post("/indexed/deindex-batch")
async def deindex_batch(request: Request) -> JSONResponse:
    """Enqueue a de-index job for a list of FM files. Body: {file_names:[str]} or {uuids:[record-uuid]}
    (a UUID is resolved to its FM file name — de-index is by whole file, not per version)."""
    if not _embedder_configured():
        return JSONResponse({"ok": False, "error": "Vector index not configured."}, status_code=400)
    body = await request.json()
    names = body.get("file_names")
    if not names:
        from corpusfm.storage import get_backend
        backend = get_backend()
        names = []
        for u in _targets(body):
            m = backend.get_artifact_meta(u)
            if m is not None and m.file_name:
                names.append(m.file_name)
    file_names = []
    for n in names or []:
        n = str(n).strip()
        if n and n not in file_names:
            file_names.append(n)
    if not file_names:
        return JSONResponse({"ok": False, "error": "file_names required"}, status_code=400)
    return await _enqueue("deindex", file_names, request)
