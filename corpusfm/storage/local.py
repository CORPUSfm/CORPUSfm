"""Local storage — the SQLite-uniform StorageBackend (packet 084, Phase 1).

The FM substrate model, in SQLite: catalog records live as canonical artifact-record/1
jors in a :class:`~corpusfm.storage.engine.SqliteEngine` store (``<archive_dir>/corpusfm.sqlite``
— registry-generated slot columns, blobs in ``_blobs``), sharing one record schema
(``storage.artifact_record``) and one blob encoding (``core.crypto.encode_blob``) with the
FM OData backend, so the two backends cannot drift.

``archive_dir`` remains a SCRATCH directory only — git registrations, discovery logs, patch
working dirs, and the derived ``summaries.json`` sidecar cache (which the catalog's summarized
scan + git export + vector index read on BOTH backends). Artifact records never live there.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import logging
import os
import uuid as _uuidlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# corpusfm/storage/local.py → corpusfm/storage → corpusfm → project root
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_SETTINGS_FILE = _PROJECT_ROOT / ".corpusfm_settings.json"


_DB_FILENAME = "corpusfm.sqlite"
_STORAGE = "STORAGE"
_SETTING_SINGLETON_KEY = "__setting_singleton__"   # fixed blob key for the SETTING singleton's containers
_QUEUE = "QUEUE"


@dataclass
class ArtifactMeta:
    """The canonical artifact-record/2 metadata (packet 085 seven-table model)."""
    file_name: str       # from the root File= attribute (.fmp12-suffixed); xref resolution key
    timestamp: str       # YYYY-MM-DD_HHMMSS_ffffff (ArtifactTimestamp, primary order)
    path: Path           # rel_path as a Path — an OPAQUE id, not a filesystem location
    name: str            # PrimaryName — the editable, extensionless human identity
    schema_version: str
    fm_version: str
    uuid: str = ""                     # canonical record address (the engine record key); packet 085 U3f
    origin: str = "Import"             # closed vocabulary {WebUI, Job, MCP, Merge, Patch (ISV), Reabsorb, Seed}; "Import" = legacy/generic-default (packet 1169)
    description: str = ""              # human-authored note (searchable)
    memory: str = ""                  # agent-authored note (searchable; written via MCP)
    gap_issues: int = 0                 # total gap analyzer issue count
    gap_count_version: int = 0          # actionable_gaps() logic version gap_issues was computed under (packet 014 #5)
    gap_unmapped: list[str] = field(default_factory=list)  # unmapped section names
    xml_bytes: int = 0                  # original XML file size
    enc_bytes: int = 0                  # legacy on-disk size; 0 on record-store backends
    job_uuid: str = ""                 # job that produced this artifact, by uuid (empty for manual)
    run_uuid: str = ""                 # the run that produced this artifact, by uuid (empty for manual)
    addon_version: str = ""            # Version from info.json (addon only)
    addon_locale: str = ""             # Locale code used for name resolution (addon only)
    has_name_map: bool = False         # addon name map stored with the record
    has_summaries: bool = False        # AI summaries stored with the record (HasSummaries slot)
    has_source: bool = False           # compressed source XML retained + deletable
    has_icon: bool = False             # addon icon (icon_b64) present in the record
    summarizable_count: int = 0        # of summarizable objects, computed at store
    root_uuid: str = ""                # FM file root UUID — a FILTER key ("same file" / Related), NOT the
                                       # lineage key (lineage/IsLatest is job_uuid alone; packet 086/Ruling A)
    artifact_type: str = ""            # ArtifactType value (the visibility/capability driver)
    analyzer_failed: list[str] = field(default_factory=list)  # crashed miners (packet 072-D) — card-cheap
    acceptance_state: str = ""         # packet 1121 — paste-acceptance OBSERVATION state (fmClip cases only)
    acceptance_batch: str = ""         # packet 1121 — acceptance batch id (cheap filter key; no FM slot)

    @property
    def is_addon(self) -> bool:
        """Derived from the canonical type — no longer a stored field."""
        return self.artifact_type == "AddonXML"

    @property
    def is_schema(self) -> bool:
        """True iff the type carries full artifact layers (replaced the stored has_artifact)."""
        from corpusfm.artifact.capabilities import is_schema_type
        return is_schema_type(self.artifact_type)

    @property
    def rel_path(self) -> str:
        return f"{self.file_name}/{self.timestamp}"


def _published_state_dir():
    """The published writable state directory, or `None` when nothing is published.

    THE SOURCE TREE IS NOT WRITABLE (packet 1246-10-04). `_PROJECT_ROOT` is `/opt/CORPUSfm/src` on
    an installed box — root-owned 0750 and inside the systemd sandbox's read-only world — so a
    default that puts mutable job, history or archive material there is a scheduler that cannot
    run. The published `state_dir` is the authority the unit already grants (`ReadWritePaths`), and
    a tree that publishes no installation keeps `_PROJECT_ROOT`.
    """
    from corpusfm.lifecycle import app_paths

    try:
        return app_paths.state_dir()
    except Exception:  # noqa: BLE001 - nothing published: the development tree, unchanged
        return None


def default_archive_dir() -> Path:
    state = _published_state_dir()
    return (state if state is not None else _PROJECT_ROOT) / "archive"


def load_settings() -> dict:
    if _SETTINGS_FILE.exists():
        try:
            return json.loads(_SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_settings(settings: dict) -> None:
    _SETTINGS_FILE.write_text(json.dumps(settings, indent=2), encoding="utf-8")


def _safe_dir_name(artifact) -> str:
    """Catalog-safe file_name derived from artifact identity.

    Uses artifact.identity.file_name verbatim (now WITH the .fmp12 suffix); the '.' is
    a kept char so the catalog key reads like the file (e.g. Foo.fmp12/<timestamp>).
    Addon artifacts get an _addon suffix to separate them from SaveAsXML snapshots.
    """
    from corpusfm.artifact.types import ArtifactType
    raw = getattr(getattr(artifact, "identity", None), "file_name", "") or "unknown"
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)
    base = safe.strip("._-") or "unknown"
    return f"{base}_addon" if getattr(artifact, "type", None) == ArtifactType.ADDON_XML else base


def _safe_join(archive_dir: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` strictly UNDER ``archive_dir``; raise ValueError on escape.

    ``rel_path`` arrives from request bodies / query params. A naive ``archive_dir / rel_path``
    is exploitable: an absolute value ("/etc/passwd") wins over the base, and ".." walks out of
    the scratch dir. Used for the derived sidecar cache paths (records themselves are addressed
    by key in the SQLite store, where traversal is moot).
    """
    base = os.path.normpath(str(archive_dir))
    target = os.path.normpath(os.path.join(base, rel_path or ""))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError(f"path escapes archive root: {rel_path!r}")
    return Path(target)


# ── catalog publication (packet 1361-01) ──────────────────────────────────────
# Placed on the BACKEND methods rather than on `StorageEngine`, for symmetry with
# `FileMakerODataBackend`, which writes STORAGE directly for six of these operations and would be
# missed entirely by an engine-level hook. Both helpers run only after the write was confirmed and
# neither can raise — a publication failure costs freshness, never a write's outcome.

def _publish_committed(backend, committed, record_uuid: str, *, operation: str = "write") -> None:
    """``committed`` is the engine's ``WriteRow`` (UUID + the opaque JSONOfRecord). ``None`` means
    the substrate returned no usable record — publish nothing derived from the request, record the
    failure, and let the next read synchronize."""
    from corpusfm.server import catalog
    catalog.publish_write(backend, catalog.TABLE_STORAGE, record_uuid, committed,
                          operation=operation)


def _publish_removed(backend, record_uuid: str) -> None:
    from corpusfm.server import catalog
    catalog.publish_deleted(backend, catalog.TABLE_STORAGE, record_uuid)


class LocalBackend:
    """StorageBackend over the local SqliteEngine — the FM substrate model without FileMaker.

    Satisfies the StorageBackend protocol defined in storage/backend.py. Records are canonical
    artifact-record/1 jors (storage.artifact_record); blobs are encode_blob-encoded exactly like
    the FM container fields. ``engine`` is exposed so the repos share THIS store.
    """

    def __init__(self, archive_dir: Path) -> None:
        from corpusfm.storage.engine import SqliteEngine
        self._archive_dir = Path(archive_dir)
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        self._engine = SqliteEngine(self._archive_dir / _DB_FILENAME)

    @property
    def archive_dir(self) -> Path:
        return self._archive_dir

    @property
    def engine(self):
        return self._engine

    # ── shared helpers ────────────────────────────────────────────────────────

    def _encrypt_blobs(self) -> bool:
        """Whether new blobs should be Fernet-encrypted (encrypt_blobs setting)."""
        from corpusfm.app.app_config import load_app_config
        return bool(load_app_config().encrypt_blobs)

    def _row(self, ref: str):
        """The STORAGE Row for a record UUID — the canonical address (packet 085 U3f). A direct
        engine-key hydrate (rename-stable), or None. ``ref`` is ALWAYS the record UUID now; the
        FileName/Timestamp rel_path is retired as an address (aliases resolve to a UUID at the edge)."""
        if not ref:
            return None
        rows = self._engine.get_by_keys(_STORAGE, [ref])
        return rows[0] if rows else None

    # ── Protocol methods ────────────────────────────────────────────────────────

    def iter_artifact_metas(self) -> "list[ArtifactMeta]":
        """Flat list of every VISIBLE_TYPES artifact meta (packet 1021 — the targeted-enumeration
        replacement for list_artifacts()'s file_name-grouped dict, for callers that just enumerate all
        records; the mutable/non-unique file_name is never a grouping key here)."""
        from corpusfm.storage.artifact_record import meta_from_jor
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        try:
            # The visibility fence runs on the indexed Type slot (packet 1210) — the same change the
            # tag layer got, found here because `count_artifacts` DIRECTLY BELOW already asked the
            # substrate this exact question while this method read the table and filtered in Python.
            # The Python fence is retained as the authority on what is visible (the slot is
            # CF-lowercased, VISIBLE_TYPES is mixed-case — different layers, never allowed to disagree).
            rows = self._engine.list_where(_STORAGE, isin={"Type": sorted(VISIBLE_TYPES)})
        except Exception:
            logger.error("local: iter_artifact_metas failed", exc_info=True)
            return []
        out = [meta_from_jor(r.jor, uuid=r.key) for r in rows]
        return [m for m in out if m.artifact_type in VISIBLE_TYPES]

    def count_artifacts(self) -> int:
        """Count of VISIBLE_TYPES artifact records (packet 1021) — a cheap indexed count, not a scan."""
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        try:
            _, total = self._engine.page(_STORAGE, isin={"Type": sorted(VISIBLE_TYPES)},
                                         per_page=1, count=True)
            return max(0, total)
        except Exception:
            return len(self.iter_artifact_metas())

    def store_artifact(
        self,
        artifact,
        xml_bytes: Optional[bytes] = None,
        *,
        label: str = "",
        origin: str = "Import",
        job_uuid: str = "",
        run_uuid: str = "",
        addon_package=None,
        keep_source_xml: bool = False,
    ) -> ArtifactMeta:
        # Shared engine write path (artifact_store): typed create → containers → publish, identical
        # on both backends (packet 1361-01).
        from corpusfm.storage.artifact_store import store_artifact as _store
        return _store(self, artifact, xml_bytes, label=label, origin=origin,
                      job_uuid=job_uuid, run_uuid=run_uuid, addon_package=addon_package,
                      keep_source_xml=keep_source_xml)

    def store_deliverable(
        self,
        xml_bytes: bytes,
        *,
        artifact_type: str,
        origin: str,
        name: str,
        description: str = "",
        memory: str = "",
        record_uuid: str = "",
    ) -> ArtifactMeta:
        """Store a degenerate deliverable (a patch or clip) as a STORAGE catalog record.

        ``record_uuid`` may be pre-supplied (packet 086 — the QUEUE deliverable path pre-generates it
        so the enqueue-and-wait caller knows the produced address without a post-hoc lookup).

        A deliverable carries no parsed schema — just the raw XML in the shared content blob
        and a canonical artifact-record/2 (a DELIVERABLE_TYPES member; the Type says it all).
        Synthetic identity (patch:<sha>/clip:<sha> + timestamp). See unified-artifacts plan §6.
        """
        import hashlib
        from corpusfm.core.crypto import compress, encode_blob
        from corpusfm.storage.artifact_record import meta_from_jor

        # Prefix follows the deliverable type so fmScript/fmCalc aren't mislabeled `clip:`
        # (root_uuid is filter-only, never identity).
        _prefix = {"PatchXML": "patch", "fmClip": "clip",
                   "fmScript": "fmscript", "fmCalc": "fmcalc"}.get(artifact_type, "clip")
        digest = hashlib.sha256(xml_bytes).hexdigest()[:16]
        root_uuid = f"{_prefix}:{digest}"

        raw = (name or "").replace(".fmp12", "").strip() or _prefix
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in raw)
        file_name = safe.strip("._-") or _prefix
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")   # UTC (packet 1005)
        supplied = bool(record_uuid)     # the QUEUE deliverable path pre-generates a stable uuid
        record_uuid = record_uuid or str(_uuidlib.uuid4())
        if supplied:
            # Re-run safety (packet 1002/B): a pre-supplied uuid is stable across a Restart, so a
            # re-run must REPLACE its prior output, not IntegrityError on the duplicate key. Drop any
            # prior attempt first (no-op when there is none) — one QUEUE record → one STORAGE artifact.
            try:
                self._engine.delete(_STORAGE, record_uuid)
                _publish_removed(self, record_uuid)
            except Exception:
                pass

        jor = {
            "Type": artifact_type,
            "PrimaryName": name,
            "FileName": file_name,
            "Origin": origin,
            "RootUUID": root_uuid,
            "ArtifactTimestamp": timestamp,
            "HasSummaries": False,
            "Description": description,
            "Memory": memory,
            "FMVersion": "",
            "schema_version": "",
            "has_name_map": False,
            "gap_issues": 0,
            "gap_unmapped": [],
            "xml_bytes": len(xml_bytes),
        }
        committed = self._engine.create(_STORAGE, record_uuid, jor)
        self._engine.blob_put(_STORAGE, record_uuid, "ArtifactData",
                              encode_blob(compress(xml_bytes), encrypt_on=self._encrypt_blobs()))
        _publish_committed(self, committed, record_uuid)
        return meta_from_jor(jor, uuid=record_uuid)

    def load_deliverable_xml(self, record_uuid: str) -> Optional[bytes]:
        """Return a deliverable's raw XML bytes from the content blob, or None. Addressed by the
        RECORD UUID (packet 085 U3f) — a rel_path resolves to nothing and returns None silently."""
        from corpusfm.core.crypto import decode_blob, decompress
        row = self._row(record_uuid)
        if row is None:
            return None
        raw = self._engine.blob_get(_STORAGE, row.key, "ArtifactData")
        if raw is None:
            return None
        try:
            return decompress(decode_blob(raw))
        except Exception:
            logger.debug("local: load_deliverable_xml failed for %s", record_uuid, exc_info=True)
            return None

    def delete_artifact(self, rel_path: str) -> None:
        # Cascade: drop the artifact's HISTORY event mentions first (085 U3c — "no artifact,
        # no history").
        from corpusfm.server.history import purge_history_for_artifact
        purge_history_for_artifact(self, rel_path)
        row = self._row(rel_path)
        if row is not None:
            self._engine.delete(_STORAGE, row.key)
            _publish_removed(self, row.key)

    def delete_source(self, rel_path: str) -> bool:
        """Packet 059: drop the retained compressed source XML (the SourceXML blob) + flip the
        has_source flag. The derived artifact is untouched. Idempotent — True if source was present."""
        row = self._row(rel_path)
        if row is None:
            return False
        had = bool(row.jor.get("has_source", False))
        self._engine.blob_delete(_STORAGE, row.key, "SourceXML")
        jor = dict(row.jor)
        jor["has_source"] = False
        _publish_committed(self, self._engine.update(_STORAGE, row.key, jor), row.key)
        return had

    # ── QUEUE workspace source staging (packet 086) ──────────────────────────────
    # An import is a [upload, land] laundry-list record (server/queue_handlers.enqueue_import) whose
    # SourceXML container holds the staged source bytes — STORAGE only ever holds LANDED records. The
    # land worker reads the staged source and lands it (artifact_store.land_artifact, moving the
    # source container). The backend supplies only the source READ + the move.

    def load_staged_source(self, queue_id: str) -> Optional[bytes]:
        from corpusfm.core.crypto import decode_blob, decompress
        raw = self._engine.blob_get(_QUEUE, queue_id, "SourceXML")
        if not raw:
            return None
        try:
            return decompress(decode_blob(raw))
        except Exception:
            # A corrupt/undecodable blob is NOT transient — the stored bytes are bad. None lets the
            # worker age-gate it (matching the FM backend; local reads have no transient failures).
            logger.debug("local: load_staged_source decode failed for %s", queue_id, exc_info=True)
            return None

    def move_container(self, src_logical: str, src_key: str, src_field: str,
                       dst_logical: str, dst_key: str, dst_field: str) -> bool:
        """Move an (already-encoded) container blob between two records. On LocalBackend this is a
        blob copy+delete within the engine; the FM backend runs it FM-internally via
        ``CFM.SRV.MoveContainerData``. The bytes are moved verbatim (already gzip/Fernet-encoded).
        Returns True only when the target holds bytes and the source is empty afterwards."""
        raw = self._engine.blob_get(src_logical, src_key, src_field)
        if not raw:
            return False
        self._engine.blob_put(dst_logical, dst_key, dst_field, raw)
        self._engine.blob_delete(src_logical, src_key, src_field)
        return bool(self._engine.blob_exists(dst_logical, dst_key, dst_field)) \
            and not self._engine.blob_exists(src_logical, src_key, src_field)

    # ── AI summaries blob (packet 054) ───────────────────────────────────────────
    # Durable copy lives in the SummariesData blob. A sidecar is ALSO written as a derived cache
    # so the catalog's summarized scan + git export + vector index reads keep working unchanged
    # (same model as the FM backend); the blob is the source of truth.

    def _summaries_sidecar_for(self, row) -> "Optional[Path]":
        """The derived summaries.json path for a STORAGE row, laid out by FileName/Timestamp
        (the natural key the catalog's `summarized` scan + git export read) — NOT by the record
        UUID, so the on-disk layout is unchanged by the U3f address flip."""
        fn, ts = row.jor.get("FileName", ""), row.jor.get("ArtifactTimestamp", "")
        if not fn or not ts:
            return None
        return _safe_join(self._archive_dir, f"{fn}/{ts}") / "summaries.json"

    def store_summaries(self, ref: str, summaries: dict) -> None:
        from corpusfm.core.crypto import encode_blob
        row = self._row(ref)
        if row is None:
            return
        try:
            blob = encode_blob(
                gzip.compress(json.dumps(summaries, ensure_ascii=False).encode("utf-8")),
                encrypt_on=self._encrypt_blobs())
            self._engine.blob_put(_STORAGE, row.key, "SummariesData", blob)
            jor = dict(row.jor)
            jor["HasSummaries"] = bool(summaries)   # slotted bool — one JOR representation
            _publish_committed(self, self._engine.update(_STORAGE, row.key, jor), row.key)
        except Exception:
            logger.debug("store_summaries failed (best-effort)", exc_info=True)
        try:
            sp = self._summaries_sidecar_for(row)
            if sp is not None:
                sp.parent.mkdir(parents=True, exist_ok=True)
                sp.write_text(json.dumps(summaries, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            logger.debug("store_summaries sidecar failed for %s", ref, exc_info=True)

    def load_summaries(self, ref: str) -> dict:
        from corpusfm.core.crypto import decode_blob
        row = self._row(ref)
        if row is None:
            return {}
        try:
            raw = self._engine.blob_get(_STORAGE, row.key, "SummariesData")
            if raw:
                data = json.loads(gzip.decompress(decode_blob(raw)).decode("utf-8"))
                if data:
                    try:  # ensure the derived sidecar exists for the scan/export path
                        sp = self._summaries_sidecar_for(row)
                        if sp is not None and not sp.exists():
                            sp.parent.mkdir(parents=True, exist_ok=True)
                            sp.write_text(json.dumps(data, indent=2, ensure_ascii=False),
                                          encoding="utf-8")
                    except Exception:
                        pass
                    return data
        except Exception:
            logger.debug("load_summaries (blob) failed for %s", ref, exc_info=True)
        # Lazy migration: a sidecar with no blob → read it, write it into the blob.
        try:
            sp = self._summaries_sidecar_for(row)
            if sp is not None and sp.exists():
                data = json.loads(sp.read_text(encoding="utf-8"))
                if data:
                    self.store_summaries(ref, data)
                return data or {}
        except Exception:
            logger.debug("load_summaries (sidecar) failed for %s", ref, exc_info=True)
        return {}

    def update_record(self, rel_path: str, fields: dict) -> None:
        """Merge editable fields into the record's jor (read-merge-write); slots re-derive.
        merge_parent_refs (a MergedXML's parent {uuid} refs) is an unprojected jor key the detail
        reads cheaply — parents resolve by record UUID, never the blob."""
        key_map = {"name": "PrimaryName", "description": "Description", "memory": "Memory",
                   "merge_parent_refs": "MergeParentRefs",
                   # gap-badge self-heal write-back (packet 014 #5)
                   "gap_issues": "gap_issues", "gap_count_version": "gap_count_version",
                   # FileName is repair-editable (user-possessions principle): the stored name is
                   # how OTHER files' cross-file references FIND this artifact.
                   "file_name": "FileName",
                   # analyzer status re-stamp on heal (packet 1121) + the additive acceptance-case record
                   # (a dict; the JOR is opaque JSON on both backends, so nested keys ride unprojected).
                   "analyzer_failed": "analyzer_failed",
                   "acceptance_case": "AcceptanceCase"}
        editable = {key_map[k]: fields[k] for k in key_map if k in fields}
        if not editable:
            return
        row = self._row(rel_path)
        if row is None:
            return
        jor = dict(row.jor)
        jor.update(editable)
        _publish_committed(self, self._engine.update(_STORAGE, row.key, jor), row.key)

    def get_artifact_meta(self, ref: str) -> Optional[ArtifactMeta]:
        from corpusfm.storage.artifact_record import meta_from_jor
        row = self._row(ref)
        if row is None:
            return None
        return meta_from_jor(row.jor, uuid=row.key)

    def load_record_jor(self, rel_path: str) -> dict:
        """The raw stored record dict (jor) — cheap, no blob; carries fields not on ArtifactMeta."""
        row = self._row(rel_path)
        return dict(row.jor) if row is not None else {}

    def load_name_map(self, rel_path: str) -> dict:
        """Load the addon name map from the NameMapData blob; returns {} when absent."""
        from corpusfm.core.crypto import decode_blob, decompress
        row = self._row(rel_path)
        if row is None:
            return {}
        raw = self._engine.blob_get(_STORAGE, row.key, "NameMapData")
        if raw is None:
            return {}
        try:
            return json.loads(decompress(decode_blob(raw)))
        except Exception:
            return {}

    def load_icon(self, rel_path: str) -> Optional[bytes]:
        """The addon icon bytes (icon_b64 in the record), or None."""
        row = self._row(rel_path)
        if row is None:
            return None
        b64 = row.jor.get("icon_b64", "")
        if not b64:
            return None
        try:
            return base64.b64decode(b64)
        except Exception:
            return None

    def load_artifact(self, ref: str):
        from corpusfm.artifact import Artifact
        from corpusfm.core.crypto import decode_blob
        row = self._row(ref)
        if row is None:
            raise FileNotFoundError(f"No STORAGE record found for {ref!r}")
        raw = self._engine.blob_get(_STORAGE, row.key, "ArtifactData")
        if raw is None:
            raise FileNotFoundError(f"No ArtifactData for {ref!r}")
        artifact = Artifact.load_gz(io.BytesIO(decode_blob(raw)))
        # Load-time self-heal was RETIRED by packet 1062: a stored artifact picks up code
        # improvements via RE-INGESTION (the canonical pipeline, from retained source), not a lazy
        # on-load re-render. Reads stay fast (no per-load recompute) and there is no phantom-diff
        # risk from a divergent re-render.
        return artifact

    def load_raw_xml(self, record_uuid: str) -> Optional[bytes]:
        """Return raw FM XML bytes from the SourceXML blob, or None if not stored. Addressed by the
        RECORD UUID (packet 085 U3f). A rel_path returns None SILENTLY, which reads as "no source
        retained" rather than as a bad address — pass ``meta.uuid``, never ``meta.rel_path``."""
        from corpusfm.core.crypto import decode_blob, decompress
        row = self._row(record_uuid)
        if row is None:
            return None
        raw = self._engine.blob_get(_STORAGE, row.key, "SourceXML")
        if raw is None:
            return None
        try:
            return decompress(decode_blob(raw))
        except Exception:
            logger.debug("local: load_raw_xml failed for %s", record_uuid, exc_info=True)
            return None

    def reencode_all_blobs(self, target_encrypt: bool, progress_cb=None) -> int:
        """Re-encode every stored record's blobs (ArtifactData / SourceXML / NameMapData /
        SummariesData) to the target form (plaintext gzip vs Fernet(gzip)). Idempotent;
        tolerates absent/empty blobs. progress_cb(done, total) after each record.

        Raises ``ReencodeIncomplete`` if the listing fails or any blob could not be converted
        (packet 1208) — a normal return is the caller's only evidence that the store now matches
        the setting."""
        from corpusfm.core.crypto import blob_is_encrypted, decode_blob, encode_blob, is_real_blob
        from corpusfm.storage.backend import ReencodeIncomplete

        try:
            rows = self._engine.list_all(_STORAGE)
        except Exception:
            logger.warning("local: reencode_all_blobs listing failed", exc_info=True)
            raise ReencodeIncomplete(converted=0, failed=0, total=0, listed=False)
        total = len(rows)
        done = 0
        converted = 0
        failed = 0
        fields = ("ArtifactData", "SourceXML", "NameMapData", "SummariesData")
        for row in rows:
            for fld in fields:
                try:
                    raw = self._engine.blob_get(_STORAGE, row.key, fld)
                    if not is_real_blob(raw) or blob_is_encrypted(raw) == target_encrypt:
                        continue
                    payload = decode_blob(raw)
                    self._engine.blob_put(_STORAGE, row.key, fld,
                                          encode_blob(payload, encrypt_on=target_encrypt))
                    converted += 1
                except Exception:
                    failed += 1
                    logger.warning("local: reencode_all_blobs failed on %s/%s", row.key, fld,
                                   exc_info=True)
            done += 1
            if progress_cb is not None:
                try:
                    progress_cb(done, total)
                except Exception:
                    pass
        if failed:
            raise ReencodeIncomplete(converted=converted, failed=failed, total=total)
        return converted

    def overlimit_job_artifacts(self, job_uuid: str, max_keep: int) -> list[str]:
        """The uuids of a job's artifacts BEYOND the newest ``max_keep`` (oldest-first tail), for
        retention. Selection only — the removal cascade (deindex + history + cache + repromote) runs
        at the server layer via ``artifact_delete.prune_job_artifacts`` (packet 1054), never a raw
        backend delete."""
        if max_keep <= 0 or not job_uuid:
            return []
        rows = self._engine.get_many(_STORAGE, "UUIDJob", [job_uuid])
        rows.sort(key=lambda r: r.jor.get("ArtifactTimestamp", ""), reverse=True)
        return [row.key for row in rows[max_keep:]]

    # ── Retired seal residue (packet 1246-02) ─────────────────────────────────────
    # Presence only. Nothing here reads, parses or restores the retired envelope.
    def seal_residue_state(self) -> str:
        try:
            raw = self._engine.blob_get("SETTING", _SETTING_SINGLETON_KEY, "SealData")
        except Exception:
            return "error"
        # ANY content is residue. The old length heuristic let a short non-empty blob pass as empty.
        return "absent" if not raw else "present"

    # ── SETTING AiKeys container (AI provider secrets, packet 1007) ───────────────
    # The AI provider key is app-scoped (it belongs to the corpus) → it rides the SETTING singleton's
    # AiKeys container so it TRAVELS with the .fmp12, Corpus-Key-encrypted (the caller does the crypto; this
    # stores raw bytes, same singleton addressing as the other SETTING containers).
    def read_ai_keys(self) -> "Optional[bytes]":
        raw = self._engine.blob_get("SETTING", _SETTING_SINGLETON_KEY, "AiKeys")
        from corpusfm.core.crypto import is_real_blob
        return raw if is_real_blob(raw) else None

    def write_ai_keys(self, data: bytes) -> None:
        self._engine.blob_put("SETTING", _SETTING_SINGLETON_KEY, "AiKeys", data)

    def clear_ai_keys(self) -> None:
        self._engine.blob_delete("SETTING", _SETTING_SINGLETON_KEY, "AiKeys")

    # ── SETTING NotifySecret container (SMTP password, packet 1009) ───────────────
    # The monitor SMTP password is app-scoped → it rides the SETTING singleton's NotifySecret
    # container so it TRAVELS with the .fmp12, Corpus-Key-encrypted (the caller does the crypto; this
    # stores raw bytes, same singleton addressing as AiKeys).
    def read_notify_secret(self) -> "Optional[bytes]":
        raw = self._engine.blob_get("SETTING", _SETTING_SINGLETON_KEY, "NotifySecret")
        from corpusfm.core.crypto import is_real_blob
        return raw if is_real_blob(raw) else None

    def write_notify_secret(self, data: bytes) -> None:
        self._engine.blob_put("SETTING", _SETTING_SINGLETON_KEY, "NotifySecret", data)

    def clear_notify_secret(self) -> None:
        self._engine.blob_delete("SETTING", _SETTING_SINGLETON_KEY, "NotifySecret")

    # ── SETTING OidcSecret container (external-auth secrets, packet 1065) ─────────
    # The OIDC client_secret + LDAP bind password are app-scoped → they ride the SETTING singleton's
    # OidcSecret container so they TRAVEL with the .fmp12, Corpus-Key-encrypted (the caller does the crypto;
    # this stores raw bytes, same singleton addressing as AiKeys/NotifySecret).
    def read_oidc_secret(self) -> "Optional[bytes]":
        raw = self._engine.blob_get("SETTING", _SETTING_SINGLETON_KEY, "OidcSecret")
        from corpusfm.core.crypto import is_real_blob
        return raw if is_real_blob(raw) else None

    def write_oidc_secret(self, data: bytes) -> None:
        self._engine.blob_put("SETTING", _SETTING_SINGLETON_KEY, "OidcSecret", data)

    def clear_oidc_secret(self) -> None:
        self._engine.blob_delete("SETTING", _SETTING_SINGLETON_KEY, "OidcSecret")
