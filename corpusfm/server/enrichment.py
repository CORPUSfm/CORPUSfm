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


# ── the ops (one target each; RAISE on failure) ──────────────────────────────────

def summarize_one(be, uuid: str, *, on_progress=None, should_cancel=None) -> int:
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
    from corpusfm.server.ai.summarize import summarizable_items
    # None when the content has nothing to summarise: an empty result is then not a provider failure.
    return len(summaries) if summarizable_items(artifact) else None


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


class IndexStageError(RuntimeError):
    """An index stage's failure in a named category, with a message safe to show on the Queue
    (packet 1462); the cause stays chained, and the details go to the log."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def live_index():
    """The live index, or an :class:`IndexStageError` saying why not: ``no_provider``,
    ``provider_incomplete`` or ``open_failed`` (the search index would not open)."""
    idx = vector_index()
    if idx is not None:
        return idx
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import IndexUnavailable, open_vector_index
    try:
        return open_vector_index(load_app_config())
    except IndexUnavailable as exc:
        log.warning("index: %s", exc, exc_info=exc.__cause__ is not None)
        raise IndexStageError(exc.category, str(exc)) from exc


_UNREACHABLE_HINTS = ("max retries exceeded", "connection refused", "failed to establish a new connection",
                      "name or service not known", "nodename nor servname", "timed out", "read timeout")


def _unreachable(exc) -> bool:
    """True when the embedding endpoint could not be reached (connection or timeout), through whatever
    wrapping the store applies to the provider's exception."""
    import requests
    from corpusfm.server.ai._watchdog import CallTimeout
    seen = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, (requests.exceptions.ConnectionError, requests.exceptions.Timeout, CallTimeout)):
            return True
        if any(h in str(exc).lower() for h in _UNREACHABLE_HINTS):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class _IndexingFailure:
    """Re-raise an embedding/indexing failure as an :class:`IndexStageError`: ``provider_unreachable``,
    or ``indexing_failed`` (naming the provider's HTTP status when it answered). A summary-layer
    deferral keeps its own actionable message."""

    def __enter__(self):
        return self

    def __exit__(self, kind, exc, tb):
        if exc is None or isinstance(exc, IndexStageError):
            return False
        from corpusfm.server.ai.vector_index import SummaryLayerDeferred
        if isinstance(exc, SummaryLayerDeferred):
            return False
        log.warning("index: indexing failed: %s", exc, exc_info=(kind, exc, tb))
        if _unreachable(exc):
            raise IndexStageError("provider_unreachable", "The embedding provider could not be reached.") from exc
        status = getattr(getattr(exc, "response", None), "status_code", None)
        detail = f"the embedding provider answered HTTP {status}" if status else type(exc).__name__
        raise IndexStageError("indexing_failed", f"Indexing failed ({detail}).") from exc


def index_one(be, uuid: str, *, on_progress=None, should_cancel=None) -> None:
    """Build/refresh the RAW search layer for one artifact (packet 1006 — the search substrate, from
    deterministic rendered text; summaries are NOT consulted). Raises if the embedder is unconfigured
    or the embedding call fails. ``on_progress`` (packet 1003) is called between embedding batches as a
    liveness tick; ``should_cancel`` is polled there too — when it returns True **at a batch boundary**
    the indexer stops with a PARTIAL index the caller should clean up. A cancel that arrives after the
    final batch never reaches the poll, so the index COMPLETES normally — the caller must key its
    cleanup on whether the poll actually fired, not on a post-hoc "was a cancel requested?" (see the
    index handler's ``stopped_early`` flag; packet 1000 re-sweep)."""
    idx = live_index()
    file_name, timestamp, _name = index_key(be, uuid)
    hook = _batch_hook(on_progress, should_cancel)
    meta = be.get_artifact_meta(uuid)
    if meta is not None and not getattr(meta, "is_schema", False):
        # A DELIVERABLE has no gz-pickled Artifact — index its text instead (packet 1035).
        _index_deliverable(be, uuid, meta, file_name, timestamp, idx, hook)
    else:
        artifact = be.load_artifact(uuid)     # a storage read failure is not an indexing failure
        with _IndexingFailure():
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
    idx = live_index()
    summaries = _load_sidecar(be, uuid)
    if not summaries:
        return
    file_name, timestamp, _name = index_key(be, uuid)
    artifact = be.load_artifact(uuid)
    with _IndexingFailure():
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


def stored_index():
    from corpusfm.app.app_config import load_app_config
    from corpusfm.server.ai.vector_index import get_stored_index
    return get_stored_index(load_app_config())


def deindex_artifact_one(uuid: str) -> None:
    """De-index ONE artifact (its record uuid, all layers) — leaving siblings + same-named files intact.
    The per-artifact inverse of index_one; used by the detail De-index action + cancel cleanup. Works on
    the stored index even with no embedder configured (deletion embeds nothing); a no-op when there is no
    stored index at all."""
    idx = stored_index()
    if idx is not None:
        idx.delete_artifact(uuid)


def index_membership(uuid: str):
    """Whether ONE artifact has a raw index: True / False, or None when it could not be read (packet
    1460). Reads the stored index even with no embedder configured. Only a store that does not exist at
    all is a definite False; one that fails to open or read is unknown, and the failure is logged with its
    cause (packet 1461) — the caller then attempts the refresh rather than treating it as absent."""
    try:
        idx = stored_index()
        if idx is None:
            return False
        return idx.index_status(uuid)["raw"] > 0
    except Exception as exc:
        log.warning("index: could not read whether %s has a search index (%s); refreshing it anyway", uuid, exc)
        return None


def indexed_uuids() -> frozenset:
    """Record UUIDs with raw indexed content, from one ids-only read (packet 1416). Empty when no
    embedder is configured or membership cannot be established (fail-open — nothing to preserve; the
    caller only decides whether to re-enqueue an index)."""
    try:
        idx = vector_index()
        if idx is None:
            return frozenset()
        return idx.raw_member_uuids()
    except Exception:
        return frozenset()
