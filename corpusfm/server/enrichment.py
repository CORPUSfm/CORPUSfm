"""Enrichment work ops (packet 086 brick 4b) — the pure "do one artifact" functions.

The AI/index work itself, factored out of the retired ``enrich_queue`` drainer so the QUEUE worker
handlers (``queue_handlers``) can call it one artifact at a time. Each op does ONE target and RAISES
on failure — the ``try-once`` worker framework catches the exception and parks the record as failed
(``IsFailed`` + ``Outcome``); a human Restart re-runs the step. There is no queue, no retry, no
in-memory running state here — the QUEUE record IS the state.

``summarize`` and ``index`` run on SEPARATE FIFO workers (packet 1170 — a slow LLM summary must not
head-of-line-block fast indexing); ``deindex`` folds into ``index`` via a Payload op flag (packet-075
parity).
"""

from __future__ import annotations

import logging

log = logging.getLogger("corpusfm.enrichment")


# ── provider resolution / readiness ──────────────────────────────────────────────

def summary_provider():
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai import get_provider
    return get_provider(load_app_config())


def vector_index():
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_vector_index
    return get_vector_index(load_app_config())


def provider_ready() -> bool:
    try:
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server.ai import summary_provider_ready
        return bool(summary_provider_ready(load_app_config()))
    except Exception:
        return False


def embedder_ready() -> bool:
    try:
        return vector_index() is not None
    except Exception:
        return False


# ── shared helpers (ported from enrich_queue) ────────────────────────────────────

def index_key(be, uuid: str) -> tuple:
    """(file_name, timestamp, display_name) for an enrichment target (a record UUID, 085 U3f). The
    vector index is keyed by the record UUID now; file_name/timestamp ride along as DISPLAY metadata
    only (packet 1010/1021) — resolve them here."""
    try:
        m = be.get_artifact_meta(uuid)
        if m is not None:
            return m.file_name, m.timestamp, (m.name or m.file_name or uuid)
    except Exception:
        pass
    return "", "", uuid


def _load_sidecar(be, uuid: str) -> dict:
    try:
        return be.load_summaries(uuid) or {}
    except Exception:
        return {}


def record_enrichment_event(be, uuid: str, kind: str) -> None:
    """Best-effort HISTORY Enrichment completion mention (085 U3c) — UUID-addressed (U3f)."""
    try:
        from corpusfm.server.history import record_enrichment
        record_enrichment(be, uuid, kind)
    except Exception:
        pass


def bust_indexed_badge_cache() -> None:
    """Bust the indexed membership cache so the catalog badge reflects a just-finished step on the
    next list. Best-effort. (The `summarized` badge is per-record — HasSummaries on the record —
    so it needs no cache bust; it is fresh on the next list as soon as store_summaries commits.)"""
    try:
        from corpusfm.app.web.routes.api.library import invalidate_indexed_cache
        invalidate_indexed_cache()
    except Exception:
        pass


# ── the ops (one target each; RAISE on failure) ──────────────────────────────────

def summarize_one(be, uuid: str, *, on_progress=None, should_cancel=None) -> None:
    """Generate + store AI one-line summaries for one artifact. Raises if no provider is configured
    or the provider call fails (the worker parks the record). ``should_cancel`` is polled per object
    (packet 1155) — on a cooperative Stop, generate_summaries returns the partial dict gathered so far,
    which is stored (summaries are additive; a partial set is valid, nothing to undo)."""
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai import generate_summaries
    provider = summary_provider()
    if provider is None:
        raise RuntimeError("No AI summary (chat) provider configured.")
    cfg = load_app_config()
    budget = int(getattr(cfg, "ai_summary_max_content_chars", 12000) or 0)
    include_xref = bool(getattr(cfg, "ai_summary_include_xref", False))
    artifact = be.load_artifact(uuid)
    summaries = generate_summaries(artifact, provider, on_progress=on_progress,
                                   should_cancel=should_cancel,
                                   max_content_chars=budget, include_xref=include_xref)
    if summaries:
        be.store_summaries(uuid, summaries)
    record_enrichment_event(be, uuid, "summaries")


def _batch_hook(on_progress, should_cancel):
    """Fold the per-batch liveness tick + the cooperative-cancel poll into the single ``should_cancel``
    callable the vector index consults between embedding batches: tick progress, then report whether a
    cancel was requested (so the indexer bails cleanly at the next batch boundary). None when neither
    is wired."""
    if on_progress is None and should_cancel is None:
        return None

    def _hook() -> bool:
        if on_progress is not None:
            on_progress()
        return bool(should_cancel()) if should_cancel is not None else False
    return _hook


def index_one(be, uuid: str, *, on_progress=None, should_cancel=None) -> None:
    """Build/refresh the RAW search layer for one artifact (packet 1006 — the search substrate, from
    deterministic rendered text; summaries are NOT consulted). Raises if the embedder is unconfigured
    or the embedding call fails. ``on_progress`` (packet 1003) is called between embedding batches as a
    liveness tick; ``should_cancel`` is polled there too — when it returns True **at a batch boundary**
    the indexer stops with a PARTIAL index the caller should clean up. A cancel that arrives after the
    final batch never reaches the poll, so the index COMPLETES normally — the caller must key its
    cleanup on whether the poll actually fired, not on a post-hoc "was a cancel requested?" (see the
    index handler's ``stopped_early`` flag; packet 1000 re-sweep)."""
    idx = vector_index()
    if idx is None:
        raise RuntimeError("Vector index not configured.")
    file_name, timestamp, _name = index_key(be, uuid)
    hook = _batch_hook(on_progress, should_cancel)
    meta = be.get_artifact_meta(uuid)
    if meta is not None and not getattr(meta, "is_schema", False):
        # A DELIVERABLE has no gz-pickled Artifact — index its text instead (packet 1035).
        _index_deliverable(be, uuid, meta, file_name, timestamp, idx, hook)
    else:
        artifact = be.load_artifact(uuid)
        idx.index_artifact(uuid, file_name, timestamp, artifact, should_cancel=hook)
    record_enrichment_event(be, uuid, "indexing")


def _index_deliverable(be, uuid, meta, file_name, timestamp, idx, hook) -> None:
    """Index a stored deliverable (packet 1035): an fmClip re-parses to an Artifact (its steps carry
    rendered text, indexed per-step); an fmScript/fmCalc — or a clip that won't parse — is one text
    doc. PatchXML has no searchable content and is skipped upstream (the enqueue guard), so it should
    not reach here; if it does, the raw text is indexed harmlessly."""
    atype = getattr(meta, "artifact_type", "")
    raw = be.load_deliverable_xml(uuid)
    if not raw:
        return
    if atype == "fmClip":
        from corpusfm.ingestion.clip import ingest_clip
        try:
            artifact = ingest_clip(raw, meta.name or "clip")
        except Exception:
            artifact = None
        # A clip that PARSES but yields no indexable items (a bare-steps XMSS clip has no ScriptCatalog
        # object → 0 rows) must still become searchable: treat per-step indexing as done ONLY when it
        # actually wrote docs (>0), else fall through to raw-text below (packet 1069 — an empty parse
        # slipped past the exception-only fallback and left the clip at 0 docs / never "indexed").
        if artifact is not None and idx.index_artifact(uuid, file_name, timestamp, artifact,
                                                       should_cancel=hook) > 0:
            return
    idx.index_deliverable_text(uuid, file_name, timestamp, meta.name or atype,
                               raw.decode("utf-8", "replace"), should_cancel=hook)


def index_summaries_one(be, uuid: str, *, on_progress=None, should_cancel=None) -> None:
    """Build/refresh the SUMMARY layer for one artifact (packet 1006 — additive; never touches the
    raw layer). No-op when the artifact has no stored summaries. Raises if the embedder is
    unconfigured or the embedding call fails — and raises ``SummaryLayerDeferred`` (packet 1008/C)
    when a model/schema change needs a raw reindex first, so the QUEUE record parks Restartable with
    an actionable Outcome instead of being silently dropped."""
    idx = vector_index()
    if idx is None:
        raise RuntimeError("Vector index not configured.")
    summaries = _load_sidecar(be, uuid)
    if not summaries:
        return
    file_name, timestamp, _name = index_key(be, uuid)
    artifact = be.load_artifact(uuid)
    idx.index_summaries(uuid, file_name, timestamp, artifact, summaries,
                        should_cancel=_batch_hook(on_progress, should_cancel))
    record_enrichment_event(be, uuid, "indexing")


def deindex_one(file_name: str) -> None:
    """Remove EVERY indexed artifact whose file name matches — the whole-file de-index (the QUEUE
    de-index step + batch/admin path). Per-artifact de-index is deindex_artifact_one(uuid). Raises if the
    embedder is unconfigured."""
    idx = vector_index()
    if idx is None:
        raise RuntimeError("Vector index not configured.")
    idx.delete_file(file_name)


def deindex_artifact_one(uuid: str) -> None:
    """De-index ONE artifact (its record uuid, all layers) — leaving siblings + same-named files intact.
    The per-artifact inverse of index_one; used by the detail De-index action + cancel cleanup. Raises if
    the embedder is unconfigured."""
    idx = vector_index()
    if idx is None:
        raise RuntimeError("Vector index not configured.")
    idx.delete_artifact(uuid)


def indexed_uuids() -> frozenset:
    """Record UUIDs currently present in the vector index. Empty when no embedder is configured or the
    index is unreadable (fail-open — nothing to preserve)."""
    try:
        idx = vector_index()
        if idx is None:
            return frozenset()
        return frozenset(r.get("uuid", "") for r in idx.list_indexed() if r.get("uuid"))
    except Exception:
        return frozenset()
