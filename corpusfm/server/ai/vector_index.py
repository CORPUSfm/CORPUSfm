"""Chroma-backed vector index for CORPUSfm schema items.

Indexing is the search substrate; summaries are optional descriptive enrichment (packet 1006).
The index is built from DETERMINISTIC rendered object text — it never depends on AI summaries, so
semantic search works the moment an artifact is indexed, with or without a summary provider.

Documents live in explicit LAYERS (all in one collection, distinguished by a `layer` metadata field
and a layer-prefixed id):

  - ``object_raw``     — one doc per schema item, embedding its deterministic rendered text. Built by
                         the primary index action; powers search and MCP retrieval immediately.
  - ``object_summary`` — one doc per item that has an AI summary, embedding the summary text. Added by
                         summary-layer indexing when a summary provider AND an embedder are configured.
                         Its failure never touches or stales ``object_raw``. Summary text NEVER replaces
                         a raw object vector — it is an ADDITIONAL layer.

Embeddings use an OpenAI-compatible /embeddings endpoint (same infrastructure as the AI summary
provider). Without a configured embedding provider, the index cannot be built.

Index layout:
  ~/.corpusfm/vector_index/  (or overridden via AppConfig.vector_index_dir)
    chroma.sqlite3 + segment files (Chroma's persistent storage)
    embedding_model.txt   — the embedding model (a same-dim model swap resets the index)
    index_schema.txt      — the layered document-schema version (a bump resets the index)

Collection: "corpusfm_items"  (single collection, all FM files, all layers)
Metadata:    layer, uuid, file_name, timestamp, folder_name, item_name
Doc id:      {layer}/{uuid}/{folder}/{item} — keyed by the artifact's FM record UUID (per-artifact,
             independent). file_name/timestamp are display metadata only, never the key (mutable + non-
             unique: two different FM files can share a name).

Public API:
    get_vector_index(app_config) -> CORPUSfmVectorIndex | None
    CORPUSfmVectorIndex.index_artifact(uuid, file_name, timestamp, artifact)          # object_raw
    CORPUSfmVectorIndex.index_summaries(uuid, file_name, timestamp, artifact, summaries)  # object_summary
    CORPUSfmVectorIndex.delete_artifact(uuid) -> int          # per-artifact de-index (all layers)
    CORPUSfmVectorIndex.delete_file(file_name) -> int         # whole-file convenience (all matching artifacts)
    CORPUSfmVectorIndex.search(query, top_k, file_name, include_summaries) -> list[dict]
    CORPUSfmVectorIndex.count() -> int
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from corpusfm.app.app_config import AppConfig
    from corpusfm.artifact import Artifact

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "corpusfm_items"
# Embedding batch size is ENDPOINT-AWARE (packet 1159). A big batch of CPU forward passes on a loaded box
# can exceed the read timeout and park a large file's index as failed — so a LOCAL, CPU-only embedder
# (Ollama, packet 1013) keeps small batches, and the extra localhost round-trips are cheap. A REMOTE
# hosted endpoint (Azure/OpenAI) parallelizes internally and returns fast, but every request pays real
# network + TLS, so batching 16-at-a-time there makes ~1-2 orders of magnitude more round-trips than
# necessary (Azure /embeddings accepts up to 2048 inputs/call). Batch LARGE when remote, small when local.
_EMBED_BATCH_SIZE_LOCAL = 16
_EMBED_BATCH_SIZE_REMOTE = int(os.environ.get("CORPUSFM_EMBED_BATCH_REMOTE", "") or 128)
_MAX_TEXT_CHARS = 1500

# Document layers (packet 1006). Raw is the search substrate; summary is optional additive enrichment.
LAYER_RAW = "object_raw"
LAYER_SUMMARY = "object_summary"


class SummaryLayerDeferred(Exception):
    """Raised when a summary-layer write is deferred because a model/schema change needs a RAW
    reindex first (packet 1008/C). It is NOT a data error — raw is left fully intact — but it must be
    a VISIBLE non-success so the queued job parks (Restartable) instead of being silently dropped.
    The message is operator-facing (it becomes the QUEUE Outcome)."""

# Bumped whenever the document id/metadata shape changes. A stored index stamped with an older schema
# is structurally incompatible (v1 ids had no layer prefix / no `layer` metadata; v2 keyed docs by the
# mutable, non-unique file_name) — the vector index is derived data, so we reset+rebuild rather than carry
# a compat shim (packet 1006 migration stance). v3: docs are keyed by the artifact's FM record UUID
# (per-artifact, independent) — the collision-prone file_name is metadata-only (display), never the key.
_INDEX_SCHEMA_VERSION = "3"

# Every CORPUSfmVectorIndex in a process writes ONE on-disk Chroma store — get_vector_index()
# builds a fresh PersistentClient per call, not a singleton. Chroma's sqlite backend locks/corrupts
# under concurrent writers, and reset() (delete + recreate the collection) racing a mid-flight upsert
# can drop freshly-written vectors. Interactive ingestion now runs in worker threads (upload.py's
# CapacityLimiter(3)), so these writes genuinely overlap — serialize every mutating op process-wide.
# Reentrant: index_artifact() calls reset() internally on a model/dimension change. Writes are not the
# throughput bottleneck (the offload's goal is loop-responsiveness, not index parallelism).
_WRITE_LOCK = threading.RLock()

# get_vector_index() returns a PROCESS-WIDE SINGLETON per resolved config. A fresh instance per call
# means a fresh PersistentClient AND a fresh cached `self._col` handle each time — so when one caller's
# reset() deletes+recreates the collection, every OTHER live instance's cached handle points to a
# deleted collection UUID (chromadb NotFoundError on its next op). One shared instance per store closes
# that: reset() updates the single `self._col` under _WRITE_LOCK, and all writers see it. (Cross-PROCESS
# concurrency — the scheduler vs. the web app — is separate and pre-existing; a singleton can't span
# processes, and Chroma's sqlite WAL is what mediates that case.)
_INDEX_CACHE: dict[tuple, "CORPUSfmVectorIndex"] = {}
_INDEX_CACHE_LOCK = threading.Lock()

_CATALOG_TO_FOLDER = {
    "ScriptCatalog":          "scripts",
    "CustomFunctionsCatalog": "custom_functions",
    "BaseTableCatalog":       "tables",
    "LayoutCatalog":          "layouts",
    "ValueListCatalog":       "value_lists",
    "RelationshipCatalog":    "relationships",
    "BaseDirectoryCatalog":   "addons",
}


def _is_local_endpoint(base_url: str) -> bool:
    """A loopback / ``*.local`` endpoint is a co-located CPU embedder (Ollama); anything else is a remote
    hosted endpoint that pays real network + TLS per request (packet 1159)."""
    try:
        from urllib.parse import urlparse
        host = (urlparse(base_url).hostname or "").lower()
    except Exception:
        return False
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"} or host.endswith(".local")


def _batch_size_for(base_url: str) -> int:
    return _EMBED_BATCH_SIZE_LOCAL if _is_local_endpoint(base_url) else _EMBED_BATCH_SIZE_REMOTE


def _default_index_dir() -> Path:
    from corpusfm.lifecycle import app_paths
    return app_paths.state_dir() / "vector_index"


def resolve_index_dir(app_config) -> Path:
    """Where the index lives for this installation.

    A named function rather than four lines inside `get_vector_index`, so the rule can be tested by
    CALLING it (packet 1246-03-01). The first attempt at that test re-implemented these lines in the
    test file, which is a test-owned mirror: it passed while the production fence was mutated away,
    and the mutation battery caught exactly that.

    DEVELOPMENT ONLY for the configured setting. On a published installation the index is
    machine-owned state under the published state directory; a stored setting that could move it is
    an alternate path authority, and it answered even when the installation's record could not be
    read.
    """
    from corpusfm.lifecycle import app_paths

    configured = app_paths.development_override(
        "the configured vector_index_dir setting",
        lambda: getattr(app_config, "vector_index_dir", "") or "",
        what="the vector index location")
    return Path(configured) if configured else _default_index_dir()


class _OpenAICompatEmbeddingFunction:
    """Minimal OpenAI-compatible embedding function for Chroma."""

    def __init__(self, model: str, api_key: str, base_url: str,
                 provider: str = "openai_compat", api_version: str = ""):
        self._model = model
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        # packet 1151: Azure OpenAI differs only in URL (deployment-in-path + api-version) and the
        # api-key header; the /embeddings body + response are identical. For Azure, `model` is the
        # embedding DEPLOYMENT name (routed in the URL).
        self._provider = provider or "openai_compat"
        self._api_version = api_version
        # packet 1159: a persistent Session (built lazily on first call, reused across every batch) gives
        # HTTP keep-alive, so a long index pass reuses ONE TCP+TLS connection instead of handshaking on
        # every request. The EF is a per-config singleton (_INDEX_CACHE), so one session serves the whole
        # pass; requests.Session is thread-safe for issuing requests (a concurrent search embed_query is
        # fine).
        self._session = None

    def name(self) -> str:
        # chromadb >= 1.x validates EF identity on get_or_create_collection via
        # name(); without it the collection load raises AttributeError and the
        # whole index silently fails to initialize. Any stable non-"default"
        # string works — this EF is re-supplied on every open (see is_legacy()).
        return "corpusfm-openai-compat"

    def is_legacy(self) -> bool:
        # Declared legacy on purpose: this EF carries a secret api_key, and
        # legacy mode keeps Chroma from serializing it into the on-disk
        # collection config. CORPUSfm re-supplies the EF on every
        # get_or_create_collection, so no persisted config is needed.
        return True

    # chromadb's query path embeds query_texts by calling embed_query/embed_documents
    # on the EF (not __call__) in some 1.x builds; provide them so a query never fails
    # with "no attribute 'embed_query'". (The index/search code also passes
    # query_embeddings directly, which is the primary, dispatch-independent path.)
    def embed_documents(self, input: list[str]) -> list[list[float]]:
        return self.__call__(input)

    def embed_query(self, query: str) -> list[float]:
        return self.__call__([query])[0]

    def __call__(self, input: list[str]) -> list[list[float]]:
        import time

        import requests

        from corpusfm.server.ai._endpoints import auth_headers, endpoint_url
        headers = auth_headers(self._provider, self._api_key)
        embed_url = endpoint_url(self._provider, self._base_url, "embeddings",
                                 deployment=self._model, api_version=self._api_version)
        payload = json.dumps({"model": self._model, "input": input})

        session = self._session
        if session is None:
            session = self._session = requests.Session()

        # Hosted endpoints reset connections / rate-limit mid-run on large index
        # passes; one failed batch must not abort a whole file. Retry transient
        # failures (network drops, 429, 5xx) with backoff; surface client errors
        # (400/401/403/404 — bad model/key) immediately.
        from corpusfm.server.ai._watchdog import CallTimeout, call_with_deadline

        last_exc: Exception | None = None
        for attempt in range(4):
            try:
                # Packet 057: a hard wall-clock deadline so a hung embedding call (proxy holds the socket)
                # can't block forever; a CallTimeout is transient → the retry loop below handles it, and
                # after 4 attempts the index job fails cleanly instead of freezing.
                # Timeouts sized for LOCAL CPU embedding (packet 1013 co-located default): a small batch
                # of forward passes on a loaded box legitimately takes tens of seconds, so the old
                # hosted-endpoint numbers (60s read / 90s wall-clock) killed real work mid-inference. The
                # read timeout is the primary limit; the wall-clock deadline sits just above it as the
                # backstop for a genuinely hung socket.
                resp = call_with_deadline(
                    lambda: session.post(
                        embed_url,
                        headers=headers, data=payload, timeout=(10, 300),
                    ),
                    330,
                )
                resp.raise_for_status()
                data = resp.json()["data"]
                # A short response (endpoint dropped/rate-limited some inputs on a big batch)
                # would otherwise surface as a confusing Chroma id/embedding count mismatch.
                if len(data) != len(input):
                    raise ValueError(
                        f"Embedding endpoint returned {len(data)} vectors for {len(input)} "
                        f"inputs — the model/endpoint dropped some (try a smaller batch).")
                data.sort(key=lambda d: d["index"])
                return [d["embedding"] for d in data]
            except Exception as exc:
                last_exc = exc
                status = getattr(getattr(exc, "response", None), "status_code", None)
                transient = status is None or status == 429 or status >= 500
                if not transient or attempt == 3:
                    raise
                time.sleep(1.5 * (attempt + 1))
        raise last_exc  # pragma: no cover - loop always returns or raises


class CORPUSfmVectorIndex:
    """Chroma-backed semantic index of FM schema items."""

    def __init__(self, index_dir: Path, embedding_fn, model: str = "",
                 batch_size: int = _EMBED_BATCH_SIZE_LOCAL):
        import chromadb
        self._index_dir = Path(index_dir)
        self._client = chromadb.PersistentClient(path=str(index_dir))
        self._embedding_fn = embedding_fn
        self._model = model or ""
        # packet 1159: endpoint-aware upsert batch size (defaults to the CPU-timeout-safe LOCAL value so
        # a direct construction is unchanged; get_vector_index passes the remote size for hosted endpoints).
        self._batch_size = int(batch_size) or _EMBED_BATCH_SIZE_LOCAL
        self._dim_cache: Optional[int] = None
        self._col = self._client.get_or_create_collection(
            _COLLECTION_NAME,
            embedding_function=embedding_fn,
            metadata={"hnsw:space": "cosine"},
        )

    @property
    def _model_marker(self) -> Path:
        return self._index_dir / "embedding_model.txt"

    @property
    def _schema_marker(self) -> Path:
        return self._index_dir / "index_schema.txt"

    def _ensure_schema(self) -> bool:
        """A stored index built under an older document schema (v1: no `layer` prefix / metadata) is
        structurally incompatible — searching it would silently mix un-layered and layered docs. The
        index is derived data, so on a schema-marker mismatch we reset and rebuild (packet 1006).
        Returns True if a reset happened. A fresh/empty store just gets stamped."""
        try:
            stored = self._schema_marker.read_text(encoding="utf-8").strip() \
                if self._schema_marker.exists() else ""
        except Exception:
            stored = ""
        if stored == _INDEX_SCHEMA_VERSION:
            return False
        # Mismatch (or unstamped) with existing content → the old docs are the wrong shape: wipe them.
        reset = False
        try:
            if self._col.count() > 0:
                self.reset()
                reset = True
        except Exception:
            pass
        self._stamp_schema()
        return reset

    def _stamp_schema(self) -> None:
        try:
            self._index_dir.mkdir(parents=True, exist_ok=True)
            self._schema_marker.write_text(_INDEX_SCHEMA_VERSION, encoding="utf-8")
        except Exception:
            pass

    def _schema_mismatch(self) -> bool:
        """True when the stored schema marker differs from the code version (a reset is pending).
        Non-destructive — used to protect the raw layer from a summary-triggered wipe (see
        _upsert_layer)."""
        try:
            stored = self._schema_marker.read_text(encoding="utf-8").strip() \
                if self._schema_marker.exists() else ""
        except Exception:
            stored = ""
        return stored != _INDEX_SCHEMA_VERSION

    def _model_mismatch(self) -> bool:
        """True when the stored model marker names a DIFFERENT embedding model (a reset is pending).
        Non-destructive. An absent marker is NOT a mismatch (nothing to invalidate)."""
        current = (self._model or "").strip()
        if not current:
            return False
        try:
            stored = self._model_marker.read_text(encoding="utf-8").strip() \
                if self._model_marker.exists() else ""
        except Exception:
            stored = ""
        return bool(stored) and stored != current

    def _ensure_model(self) -> bool:
        """Chroma is model-BLIND — it enforces only the vector dimension, so a same-dimension
        swap to a different embedding model is accepted silently and quietly corrupts search
        (old vectors and new queries live in different semantic spaces). We track the model in
        a sidecar marker and reset the index when it changes. Returns True if a reset happened."""
        current = (self._model or "").strip()
        if not current:
            return False  # unknown model — can't track; leave as-is
        try:
            stored = self._model_marker.read_text(encoding="utf-8").strip() \
                if self._model_marker.exists() else ""
        except Exception:
            stored = ""
        if stored and stored != current:
            self.reset()
            self._stamp_model(current)
            return True
        if stored != current:           # absent → stamp it (first run / post-dimension-reset)
            self._stamp_model(current)
        return False

    def _stamp_model(self, model: str) -> None:
        try:
            self._index_dir.mkdir(parents=True, exist_ok=True)
            self._model_marker.write_text(model, encoding="utf-8")
        except Exception:
            pass

    def count(self) -> int:
        return self._col.count()

    def reset(self) -> None:
        """Drop and recreate the collection — used when the embedder's vector DIMENSION
        changes (Chroma bakes the dimension at creation, so a model swap from e.g. 1536-dim
        to 768-dim makes every existing vector incompatible). The old vectors are from the
        prior model and unsearchable against new queries anyway, so discarding them is correct."""
        with _WRITE_LOCK:
            try:
                self._client.delete_collection(_COLLECTION_NAME)
            except Exception:
                pass
            self._dim_cache = None
            self._col = self._client.get_or_create_collection(
                _COLLECTION_NAME,
                embedding_function=self._embedding_fn,
                metadata={"hnsw:space": "cosine"},
            )

    def _vector_dim(self) -> int:
        """Embedding dimensionality (queried once from a stored vector)."""
        if self._dim_cache is not None:
            return self._dim_cache
        try:
            got = self._col.get(limit=1, include=["embeddings"])
            embs = got.get("embeddings")
            self._dim_cache = len(embs[0]) if embs is not None and len(embs) else 0
        except Exception:
            self._dim_cache = 0
        return self._dim_cache

    def _est_bytes_per_item(self) -> int:
        """Rough on-disk cost of one indexed item: the float32 vector (+~10% HNSW
        graph overhead) plus the stored document text and metadata. An estimate —
        Chroma shares one sqlite across all files, so exact per-file size isn't
        recoverable, but this scales correctly with item count (so it drops as you
        delete)."""
        dim = self._vector_dim() or 1536
        return int(dim * 4 * 1.1) + 900

    def disk_usage_bytes(self) -> int:
        """Actual bytes on disk for the whole index dir (all files combined)."""
        total = 0
        try:
            for p in self._index_dir.rglob("*"):
                if p.is_file():
                    total += p.stat().st_size
        except Exception:
            pass
        return total

    def index_artifact(
        self,
        uuid: str,
        file_name: str,
        timestamp: str,
        artifact: "Artifact",
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> int:
        """Build/refresh the ``object_raw`` layer for one artifact from DETERMINISTIC rendered text.
        Returns count of items indexed. This is the primary, search-enabling action — it never reads
        AI summaries (packet 1006: indexing is the search substrate, summaries are optional).

        Keyed by the artifact's FM record ``uuid`` (per-artifact, independent — indexing one version never
        touches another; ``file_name``/``timestamp`` are carried as display metadata only). Existing
        raw-layer docs for THIS artifact are cleared first, so a reindex is a true refresh (removed items
        don't linger).

        should_cancel: an optional poll checked between embedding-upsert batches; when it returns
        truthy the upsert stops and the count written so far is returned. Cooperative Stop for the
        background sweep — partial is safe (upsert is idempotent; a re-run completes the rest)."""
        rows = []
        for item in artifact.items.values():
            if item.is_folder:
                continue
            folder_name = _CATALOG_TO_FOLDER.get(item.section)
            if folder_name is None:
                continue
            text = (item.rendered_text or item.name)[:_MAX_TEXT_CHARS]
            rows.append((folder_name, item.name, text))
        return self._upsert_layer(LAYER_RAW, uuid, file_name, timestamp, rows, should_cancel=should_cancel)

    def index_deliverable_text(
        self,
        uuid: str,
        file_name: str,
        timestamp: str,
        name: str,
        text: str,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> int:
        """Index a STORED DELIVERABLE that has no parsed Artifact — an fmScript/fmCalc text blob, or a
        clip that could not be re-parsed — as ONE raw-layer doc keyed by the record uuid (packet 1035).
        An fmClip that DOES parse is indexed per-step via index_artifact instead. Same layer/store as a
        schema artifact, so semantic_search surfaces deliverables alongside schema objects."""
        body = (text or name or "")[:_MAX_TEXT_CHARS]
        rows = [("Deliverable", name or uuid, body)]
        return self._upsert_layer(LAYER_RAW, uuid, file_name, timestamp, rows, should_cancel=should_cancel)

    def index_summaries(
        self,
        uuid: str,
        file_name: str,
        timestamp: str,
        artifact: "Artifact",
        summaries: Optional[dict] = None,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> int:
        """Build/refresh the ``object_summary`` layer from AI summary text (packet 1006). ADDITIVE —
        it writes a separate layer and never touches ``object_raw``, so a summary failure can't stale
        the raw search substrate. Items with no summary are skipped. Returns count of summary docs
        written (0 when there are no summaries).

        Raises ``SummaryLayerDeferred`` when a model/schema change is pending and raw content exists —
        the summary write must not trigger the whole-collection reset that only a RAW reindex can
        repair (packet 1008/C). The caller parks the job Restartable; raw is left intact."""
        if not summaries:
            return 0
        from corpusfm.server.ai.summarize import lookup_summary
        rows = []
        for item in artifact.items.values():
            if item.is_folder:
                continue
            folder_name = _CATALOG_TO_FOLDER.get(item.section)
            if folder_name is None:
                continue
            text = lookup_summary(summaries, item)
            if not text:
                continue
            rows.append((folder_name, item.name, text[:_MAX_TEXT_CHARS]))
        return self._upsert_layer(LAYER_SUMMARY, uuid, file_name, timestamp, rows,
                                  should_cancel=should_cancel)

    def _upsert_layer(
        self,
        layer: str,
        uuid: str,
        file_name: str,
        timestamp: str,
        rows: list,
        should_cancel: Optional[Callable[[], bool]] = None,
    ) -> int:
        """Refresh one (layer, artifact) slice of the collection: delete its existing docs, then upsert
        `rows` (each ``(folder_name, item_name, text)``). Keyed by the artifact ``uuid``. Serialized
        process-wide (see _WRITE_LOCK) because reset()/dimension-retry can recreate the shared collection
        mid-flight."""
        with _WRITE_LOCK:
            # INVARIANT: the additive summary layer must NEVER be the op that wipes the raw substrate
            # (packet 1006). A model/schema change forces a whole-collection rebuild that only the RAW
            # path can repair — so if a summary write arrives with a reset pending AND there is existing
            # content to lose, DEFER it (return 0, leaving raw intact) rather than reset-then-write a
            # misleading summaries-only index. On an empty collection there is no raw to protect, so a
            # summary write falls through and simply stamps the markers.
            if layer == LAYER_SUMMARY and (self._schema_mismatch() or self._model_mismatch()):
                try:
                    has_content = self._col.count() > 0
                except Exception:
                    has_content = False
                if has_content:
                    logger.info("vector_index: deferring the summary-layer write — a model/schema "
                                "change needs a raw reindex first (not wiping raw for a summary write)")
                    # A VISIBLE non-success (packet 1008/C): raise so the queued job parks Restartable
                    # rather than being deleted as a silent success. Raw is untouched.
                    raise SummaryLayerDeferred(
                        "Summary-layer indexing deferred: the search index needs a raw reindex first "
                        "(its embedding model or schema changed). Reindex this file, then Restart.")
            # Reset on an embedding-model change (Chroma checks only dimension) or a document-schema
            # bump (v1 un-layered docs) — either silently corrupts search otherwise.
            self._ensure_schema()
            self._ensure_model()
            ids: list[str] = []
            texts: list[str] = []
            metas: list[dict] = []
            # Chroma requires ids unique within an upsert. Item names are NOT unique (addon-heavy files
            # collapse many items to the same folder/name, and empty names collide) — disambiguate
            # collisions deterministically so the same artifact re-indexes to stable ids.
            seen: dict[str, int] = {}
            for folder_name, item_name, text in rows:
                base_id = f"{layer}/{uuid}/{folder_name}/{item_name}"
                n = seen.get(base_id, 0)
                seen[base_id] = n + 1
                doc_id = base_id if n == 0 else f"{base_id}#{n}"
                ids.append(doc_id)
                texts.append(text or item_name or doc_id)
                metas.append({
                    "layer": layer,
                    "uuid": uuid,
                    "file_name": file_name,      # display metadata only — NOT the key (mutable, non-unique)
                    "timestamp": timestamp,      # display metadata only
                    "folder_name": folder_name,
                    "item_name": item_name,
                })

            # One index per ARTIFACT (record UUID), independent: drop THIS artifact's prior slice of this
            # layer so a reindex is a true refresh — indexing another version (a different uuid) never
            # touches this one. Layer-scoped — a RAW reindex never touches the additive SUMMARY layer (the
            # 1006 invariant above), and vice versa.
            self._delete_artifact_layer(layer, uuid)
            if not ids:
                return 0

            # Upsert in batches to avoid oversized embedding requests. A dimension mismatch (model
            # swap) on the first batch → reset the incompatible collection once and retry from the top.
            did_reset = False
            i = 0
            while i < len(ids):
                if should_cancel is not None and should_cancel():
                    return min(i, len(ids))
                batch_ids   = ids[i:i + self._batch_size]
                batch_texts = texts[i:i + self._batch_size]
                batch_metas = metas[i:i + self._batch_size]
                try:
                    self._col.upsert(ids=batch_ids, documents=batch_texts, metadatas=batch_metas)
                    i += self._batch_size
                except Exception as exc:
                    # Only the RAW path may reset-and-retry on a dimension mismatch — resetting for a
                    # SUMMARY write would wipe the raw substrate to build summaries-only (the same
                    # invariant as above). For the summary layer, re-raise → the record parks (visible)
                    # and raw is left intact.
                    if (layer == LAYER_RAW and not did_reset
                            and "dimension" in str(exc).lower()):
                        self.reset()
                        did_reset = True
                        i = 0  # the reset emptied the collection — re-upsert from the top
                        continue
                    raise

            return len(ids)

    def _delete_artifact_layer(self, layer: str, uuid: str) -> None:
        """Delete every doc for one (layer, artifact) — the replace-per-artifact primitive. Layer-scoped
        so a RAW reindex leaves the SUMMARY layer intact. A fresh collection returns no ids; inability
        to establish or delete the old slice is different and must stop the replacement before upsert,
        otherwise removed objects remain searchable beside the new ones."""
        existing = self._col.get(where={"$and": [
            {"layer": {"$eq": layer}},
            {"uuid": {"$eq": uuid}},
        ]})
        ids = existing.get("ids") or []
        if ids:
            self._col.delete(ids=ids)

    def delete_artifact(self, uuid: str) -> int:
        """De-index ONE artifact — every layer for its record ``uuid`` — leaving sibling versions (and any
        other artifact sharing the file name) intact. Returns count deleted. The per-artifact inverse of
        index_artifact; used by the detail De-index action, the artifact-delete cleanup, and cancel."""
        if not uuid:
            return 0
        with _WRITE_LOCK:
            existing = self._col.get(where={"uuid": uuid})
            ids = existing.get("ids") or []
            if ids:
                self._col.delete(ids=ids)
            return len(ids)

    def delete_file(self, file_name: str) -> int:
        """Delete EVERY indexed artifact whose display file_name matches — the whole-file admin/scripting
        convenience (drops all versions/records of that name at once). Per-artifact de-index is
        delete_artifact(uuid). Returns count deleted."""
        with _WRITE_LOCK:
            existing = self._col.get(where={"file_name": file_name})
            ids = existing.get("ids") or []
            if ids:
                self._col.delete(ids=ids)
            return len(ids)

    def list_indexed(self) -> list[dict]:
        """Return grouped summary of indexed content — the ``object_raw`` substrate (packet 1006), so
        the count reflects searchable objects, not doubled by an optional summary layer.

        One row PER ARTIFACT (record uuid): keys uuid, file_name, timestamp, count. `file_name`/`timestamp`
        are display fields; `uuid` is the identity (drives the per-artifact `indexed` badge). Sorted by
        file_name then timestamp (newest first). Empty when a schema rebuild is pending (an older-keyed
        index is incompatible — it must be reindexed; reporting it would mislabel membership)."""
        if self._schema_mismatch():
            return []
        try:
            result = self._col.get(include=["metadatas"])
            metas = result.get("metadatas") or []
        except Exception:
            return []

        groups: dict[str, dict] = {}
        for m in metas:
            # Old v1 docs carry no `layer`; treat them as raw so a pre-1006 index still reports.
            if (m.get("layer") or LAYER_RAW) != LAYER_RAW:
                continue
            uuid = m.get("uuid", "")
            g = groups.get(uuid)
            if g is None:
                groups[uuid] = {"uuid": uuid, "file_name": m.get("file_name", ""),
                                "timestamp": m.get("timestamp", ""), "count": 1}
            else:
                g["count"] += 1

        per_item = self._est_bytes_per_item()
        rows = list(groups.values())
        for r in rows:
            r["est_bytes"] = r["count"] * per_item
        rows.sort(key=lambda r: (r["file_name"], r["timestamp"]), reverse=False)
        # Newest timestamp first within each file
        from itertools import groupby
        ordered: list[dict] = []
        for _, group in groupby(rows, key=lambda r: r["file_name"]):
            ordered.extend(sorted(group, key=lambda r: r["timestamp"], reverse=True))
        return ordered

    def index_status(self, uuid: str) -> dict:
        """Per-artifact index membership (packet 1036): doc counts by layer for one record ``uuid``.
        Returns {raw, summary, total} — the RAW layer is the search substrate, SUMMARY the optional
        AI-summary layer. All zero when the record is not indexed (or a schema rebuild is pending)."""
        out = {"raw": 0, "summary": 0, "total": 0}
        if not uuid or self._schema_mismatch():
            return out
        try:
            got = self._col.get(where={"uuid": uuid}, include=["metadatas"])
            for m in (got.get("metadatas") or []):
                if (m.get("layer") or LAYER_RAW) == LAYER_SUMMARY:
                    out["summary"] += 1
                else:
                    out["raw"] += 1
            out["total"] = out["raw"] + out["summary"]
        except Exception:
            pass
        return out

    def search(
        self,
        query: str,
        top_k: int = 5,
        file_name: Optional[str] = None,
        include_summaries: bool = True,
        uuid: Optional[str] = None,
    ) -> list[dict]:
        """Return top_k results for query. Each result has ``uuid`` (the record it came from, so the
        caller can disambiguate same-named files), file_name, timestamp, folder_name, item_name,
        distance, and ``layer`` (``object_raw`` | ``object_summary``) so the evidence layer is visible
        to the caller (packet 1006).

        Search works on ``object_raw`` alone — no summaries required. When ``include_summaries`` and a
        summary layer exists, both layers are queried and results are DEDUPED per object — keyed on the
        collision-free ``(uuid, folder, item)`` (packet 1010 identity), keeping the closer match — so an
        optional summary vector can win when it is the better semantic match without doubling the rows,
        and two distinct same-named artifacts never collapse into one."""
        count = self.count()
        if count <= 0:
            return []
        where = None
        clauses = []
        if file_name:
            clauses.append({"file_name": {"$eq": file_name}})
        if uuid:
            clauses.append({"uuid": {"$eq": uuid}})          # scope to ONE record (packet 1036)
        if not include_summaries:
            clauses.append({"layer": {"$eq": LAYER_RAW}})
        if len(clauses) == 1:
            where = clauses[0]
        elif clauses:
            where = {"$and": clauses}
        # Embed the query with our own EF (__call__) and pass query_embeddings — this is
        # independent of chromadb's internal query-text→EF dispatch, which varies across
        # 1.x builds (some call embed_query, absent on a __call__-only EF → AttributeError).
        qvec = self._embedding_fn([query])
        # Over-fetch: with both layers queried, an object can appear twice (raw + summary); fetch
        # extra so that after per-object dedupe we can still return up to top_k distinct objects.
        want = top_k * 2 if include_summaries else top_k
        kwargs = {"query_embeddings": qvec, "n_results": min(want, count)}
        if where:
            kwargs["where"] = where
        results = self._col.query(**kwargs)
        best: dict[tuple, dict] = {}
        order: list[tuple] = []
        for i, meta in enumerate(results["metadatas"][0]):
            # Dedupe per OBJECT by the collision-free record uuid (packet 1010 identity), not the
            # mutable/non-unique file_name — the raw + summary layers of one object share (uuid, folder,
            # item), so they collapse correctly while two distinct artifacts never do. uuid is surfaced
            # on the row so a caller can disambiguate which artifact a hit came from.
            key = (meta.get("uuid", ""), meta.get("folder_name", ""), meta.get("item_name", ""))
            dist = results["distances"][0][i] if results.get("distances") else None
            row = {
                "uuid":        meta.get("uuid", ""),
                "file_name":   meta.get("file_name", ""),
                "timestamp":   meta.get("timestamp", ""),
                "folder_name": meta.get("folder_name", ""),
                "item_name":   meta.get("item_name", ""),
                "layer":       meta.get("layer") or LAYER_RAW,
                "distance":    dist,
                "document":    results["documents"][0][i] if results.get("documents") else "",
            }
            prev = best.get(key)
            if prev is None:
                best[key] = row
                order.append(key)
            elif dist is not None and (prev.get("distance") is None or dist < prev["distance"]):
                best[key] = row
        return [best[k] for k in order][:top_k]


def has_embedding_configured(app_config: "AppConfig") -> bool:
    """Return True if the embedding endpoint is configured (does not test connectivity)."""
    base_url = getattr(app_config, "ai_embedding_base_url", "") or \
               getattr(app_config, "ai_summary_base_url", "") or ""
    if base_url:
        return True
    return bool(
        os.environ.get("AI_SUMMARY_API_KEY", "") or
        os.environ.get("OPENAI_API_KEY", "")
    )


def embedding_ready(app_config: "AppConfig") -> bool:
    """True only when an embedding endpoint is configured AND tested working.

    This is the gate for user-facing index features — mere presence of a key is
    not enough, because a chat-only endpoint (e.g. a gpt gateway with no
    /embeddings) passes has_embedding_configured() but fails at index time.
    """
    return has_embedding_configured(app_config) and bool(
        getattr(app_config, "ai_embedding_verified", False)
    )


def test_embedding_endpoint(
    base_url: str, model: str = "", api_key: str = "", timeout: int = 20,
    provider: str = "openai_compat", api_version: str = ""
) -> dict:
    """Do a tiny live /embeddings round-trip. Returns {ok, dims?, model?, error?}.

    Resolves the API key from env (AI_SUMMARY_API_KEY → OPENAI_API_KEY) when not
    passed, and falls back to the OpenAI endpoint when no base_url is given but a
    key exists — same precedence as get_vector_index(). For provider=azure_openai,
    `model` is the embedding DEPLOYMENT name and api_version routes the request.
    """
    import json as _json
    import requests

    from corpusfm.server.ai._endpoints import auth_headers, endpoint_url, is_azure
    base_url = (base_url or "").rstrip("/")
    model = model or ("" if is_azure(provider) else "text-embedding-3-small")
    api_key = api_key or os.environ.get("AI_SUMMARY_API_KEY", "") or \
        os.environ.get("OPENAI_API_KEY", "")
    if not base_url:
        if is_azure(provider):
            return {"ok": False, "error": "Azure OpenAI needs a resource URL "
                    "(https://<resource>.openai.azure.com)."}
        if not api_key:
            return {"ok": False, "error": "No embedding endpoint or API key configured."}
        base_url = "https://api.openai.com/v1"
    if is_azure(provider) and not model:
        return {"ok": False, "error": "Azure OpenAI needs an embedding deployment name."}

    headers = auth_headers(provider, api_key)
    embed_url = endpoint_url(provider, base_url, "embeddings",
                             deployment=model, api_version=api_version)
    try:
        resp = requests.post(
            embed_url,
            headers=headers,
            data=_json.dumps({"model": model, "input": ["corpusfm embedding test"]}),
            timeout=timeout,
        )
    except Exception as exc:
        return {"ok": False, "error": f"Could not reach {base_url}: {exc}"}
    if resp.status_code != 200:
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:300]}"}
    try:
        dims = len(resp.json()["data"][0]["embedding"])
    except Exception as exc:
        return {"ok": False, "error": f"Endpoint reachable but response was not embeddings: {exc}"}
    return {"ok": True, "dims": dims, "model": model, "endpoint": base_url}


def list_endpoint_models(base_url: str, api_key: str = "", timeout: int = 15,
                         provider: str = "openai_compat") -> dict:
    """GET {base_url}/models — what the endpoint actually serves. {ok, models?, error?}.

    Azure OpenAI does not enumerate deployments on the data plane like /models, so for
    provider=azure_openai this returns a not-supported result — the user types the
    deployment name (they know it).

    The model a user has is happenstance (whatever they pulled/loaded); the URL is
    stable. So presets set only the URL and this discovers the models from the
    reachable endpoint. Both Ollama and LM Studio serve OpenAI-compatible
    /v1/models, but the list mixes chat + embedding models with no reliable
    capability flag — it's a pick-list, and test_embedding_endpoint remains the
    proof that the chosen one actually embeds. Key/base_url precedence mirrors
    test_embedding_endpoint().
    """
    import requests

    from corpusfm.server.ai._endpoints import is_azure
    if is_azure(provider):
        return {"ok": False, "error": "Azure OpenAI does not list deployments here — "
                "enter the deployment name from the Azure portal."}
    base_url = (base_url or "").rstrip("/")
    api_key = api_key or os.environ.get("AI_SUMMARY_API_KEY", "") or \
        os.environ.get("OPENAI_API_KEY", "")
    if not base_url:
        if not api_key:
            return {"ok": False, "error": "No embedding endpoint or API key configured."}
        base_url = "https://api.openai.com/v1"

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        resp = requests.get(f"{base_url}/models", headers=headers, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"Could not reach {base_url}: {exc}"}
    if resp.status_code != 200:
        return {"ok": False, "error": f"HTTP {resp.status_code}: {resp.text[:300]}"}
    try:
        # An empty Ollama returns {"data": null} (not []), so coerce — a reachable
        # endpoint with no models is ok with models=[], not a parse error.
        data = resp.json().get("data") or []
        models = sorted({str(m.get("id", "")) for m in data if m.get("id")})
    except Exception as exc:
        return {"ok": False, "error": f"Endpoint reachable but response was not a model list: {exc}"}
    return {"ok": True, "models": models, "endpoint": base_url}


def get_vector_index(app_config: "AppConfig") -> Optional[CORPUSfmVectorIndex]:
    """Return a ready-to-use index, or None if embedding is not configured."""
    from corpusfm.server.ai._endpoints import is_azure
    # packet 1151: the embedding endpoint is a first-class, decoupled provider — it no longer infers
    # its provider/key from the chat side. It keeps the base-url fallback to the chat URL only for a
    # legacy openai_compat install (an Azure embed endpoint always carries its own resource URL).
    provider = getattr(app_config, "ai_embedding_provider", "") or ""
    base_url = getattr(app_config, "ai_embedding_base_url", "") or \
               (getattr(app_config, "ai_summary_base_url", "") if not provider else "") or ""
    api_version = getattr(app_config, "ai_embedding_api_version", "") or ""
    model = getattr(app_config, "ai_embedding_model", "") or \
        ("" if is_azure(provider) else "text-embedding-3-small")
    # UI-settable EMBED key first (packet 1007 container; packet 1151 decoupled chat/embed keys),
    # env var fallback.
    try:
        from corpusfm.server import ai_env
        ui_key = ai_env.read_ai_key("embed")
    except Exception:
        ui_key = ""
    api_key = ui_key or os.environ.get("AI_SUMMARY_API_KEY", "")

    if is_azure(provider) and (not base_url or not model):
        logger.debug("vector_index: azure embedding endpoint incomplete (need resource URL + deployment)")
        return None
    if not base_url:
        # Try OpenAI default if we have a key
        api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            logger.debug("vector_index: no embedding endpoint configured")
            return None
        base_url = "https://api.openai.com/v1"

    index_dir = resolve_index_dir(app_config)

    # packet 1161: an explicit Settings batch size (1..2048) overrides the endpoint-aware Auto (packet
    # 1159). 0 / unset = Auto. Chunking only — never changes a vector — so it does not affect verification.
    try:
        configured_batch = int(getattr(app_config, "ai_embedding_batch_size", 0) or 0)
    except (TypeError, ValueError):
        configured_batch = 0
    batch_size = min(2048, max(1, configured_batch)) if configured_batch > 0 else _batch_size_for(base_url)

    # One live instance (one PersistentClient + one cached collection) per resolved config — see
    # _INDEX_CACHE. Keyed on everything that defines the store + how we talk to it; a config change
    # (key rotation, model/endpoint swap, relocated dir) yields a new instance.
    cache_key = (str(index_dir), base_url, model, api_key, provider, api_version, batch_size)
    with _INDEX_CACHE_LOCK:
        cached = _INDEX_CACHE.get(cache_key)
        if cached is not None:
            return cached

        index_dir.mkdir(parents=True, exist_ok=True)
        embedding_fn = _OpenAICompatEmbeddingFunction(
            model=model, api_key=api_key, base_url=base_url,
            provider=provider or "openai_compat", api_version=api_version
        )
        try:
            idx = CORPUSfmVectorIndex(index_dir=index_dir, embedding_fn=embedding_fn, model=model,
                                      batch_size=batch_size)
        except Exception:
            logger.error("Failed to initialize vector index", exc_info=True)
            return None
        _INDEX_CACHE[cache_key] = idx
        return idx
