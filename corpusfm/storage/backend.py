"""StorageBackend protocol — the interface all storage backends must satisfy.

Current implementations:
    LocalBackend           (corpusfm/storage/local.py)     — local filesystem, Fernet-encrypted XML
    FileMakerODataBackend  (corpusfm/storage/fm_odata.py)  — FM container fields via OData v4 (server mode)

Listing seam: the flat ``iter_artifact_metas()`` + the cheap ``count_artifacts()`` (packet 1021 retired
the old file-name-grouped ``list_artifacts()``; callers that need a per-file grouping build it locally).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pathlib import Path
    from corpusfm.artifact import Artifact
    from corpusfm.storage.local import ArtifactMeta


class ReencodeIncomplete(RuntimeError):
    """A bulk blob re-encode did not finish. Carries exactly what did and did not happen.

    Raised rather than returned because every caller already treats an exception as failure and a
    return value as success — and the defect this closes (packet 1208) was precisely that: the
    listing could fail, or every single upload could fail, and the run still ENDED NORMALLY. The
    worker left its `error` empty, the status page computed 100%, and the CLI printed
    "reencode complete: 0 blob(s)" and then persisted the setting. The configuration said the store
    was encrypted; the store was not; nothing anywhere said so.

    The partial work is kept, never rolled back: re-encoding is idempotent and skips blobs already
    in the target form, so a retry finishes the job rather than starting it again.
    """

    def __init__(self, *, converted: int, failed: int, total: int, listed: bool = True):
        self.converted, self.failed, self.total, self.listed = converted, failed, total, listed
        if not listed:
            msg = ("could not list the stored records, so NO blobs were converted — the encryption "
                   "setting and the stored blobs now disagree. Fix the storage connection and set "
                   "the encryption setting again.")
        else:
            msg = (f"{failed} blob(s) across {total} record(s) could not be converted "
                   f"({converted} succeeded) — some blobs remain in the previous form. Setting the "
                   "encryption setting again converts only what is left.")
        super().__init__(msg)


@runtime_checkable
class StorageBackend(Protocol):
    """Minimal interface all storage backends must satisfy."""

    def iter_artifact_metas(self) -> "list[ArtifactMeta]": ...

    def count_artifacts(self) -> int: ...

    def store_artifact(
        self,
        artifact: "Artifact",
        xml_bytes: Optional[bytes] = None,
        *,
        label: str = "",
        origin: str = "Import",
        job_uuid: str = "",
        run_uuid: str = "",
        addon_package=None,
        keep_source_xml: bool = False,
    ) -> "ArtifactMeta": ...

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
    ) -> "ArtifactMeta":
        """Store a degenerate deliverable (a patch or clip) as a STORAGE catalog record.

        A deliverable carries no parsed schema — just the canonical artifact-record/1 and
        the raw XML in the shared content container; a DELIVERABLE_TYPES member. Synthetic identity
        (patch:<sha>/clip:<sha> + timestamp). See unified-artifacts plan §6."""
        ...

    def load_deliverable_xml(self, record_uuid: str) -> "Optional[bytes]":
        """Return a deliverable's raw XML bytes, or None if absent. Addressed by the RECORD UUID —
        the FileName/Timestamp rel_path was retired as an address (packet 085 U3f); a rel_path
        silently resolves to nothing here."""
        ...

    def delete_artifact(self, rel_path: str) -> None: ...

    def delete_source(self, rel_path: str) -> bool:
        """Packet 059: drop the retained compressed source XML (the archived original) to reclaim space;
        the derived artifact is untouched. Idempotent — True if a source was present."""
        ...

    def update_record(self, rel_path: str, fields: dict) -> None:
        """Update editable fields ({name, description, memory}) on an existing
        record, leaving heavy content untouched."""
        ...

    # ── QUEUE workspace source staging (packet 086) ──────────────────────────────
    # An import is a [upload, land] laundry-list record whose SourceXML container holds the uploaded
    # raw source bytes (compressed, encoded per encrypt_blobs), with NO parsed artifact yet. The land
    # worker reads the staged source and LANDS it into a fresh STORAGE record (artifact_store.
    # land_artifact — moving the staged source container in FM-internally). Record creation + the
    # source blob write go through QueueRepo + the engine (server/queue_handlers.enqueue_import); the
    # backend supplies only the source READ + the move.

    def load_staged_source(self, queue_id: str) -> "Optional[bytes]":
        """The decompressed staged source bytes for a QUEUE row, or None if missing. Raises
        ``StagedSourceUnavailable`` on a transient transport error (the worker keeps + retries)."""
        ...

    def move_container(self, src_logical: str, src_key: str, src_field: str,
                       dst_logical: str, dst_key: str, dst_field: str) -> bool:
        """Move an (already-encoded) container blob between two records — FM-internally via
        ``CFM.SRV.MoveContainerData`` on the FM backend, a blob copy+delete on LocalBackend. Returns
        True only when the target holds bytes afterwards (app-side verify). Used by landing to bring
        the staged source into the landed record without proxying the bytes through the app."""
        ...

    def get_artifact_meta(self, record_uuid: str) -> "Optional[ArtifactMeta]": ...

    def load_artifact(self, record_uuid: str) -> "Artifact": ...

    # Addressed by the RECORD UUID (packet 085 U3f retired the FileName/Timestamp rel_path as an
    # address). Passing a rel_path returns None SILENTLY — it reads as "no source retained" rather
    # than as an error, which is why the parameter is named for what it actually is.
    def load_raw_xml(self, record_uuid: str) -> "Optional[bytes]": ...

    def reencode_all_blobs(self, target_encrypt: bool, progress_cb=None) -> int:
        """Re-encode every stored container blob to the target form (plaintext gzip vs
        Fernet(gzip)) per the encrypt_blobs setting. Idempotent — a blob already in the
        target form is skipped. decode_blob auto-detects, so reads work mid-conversion.

        ``progress_cb(done, total)`` is called after each record (total = record count).
        Returns the number of blobs re-encoded. Tolerates absent/empty containers.

        Raises ``ReencodeIncomplete`` if the record listing fails or any blob could not be
        converted. A normal return therefore means every blob is in the target form — which is the
        only thing that makes the caller's "done, no error" honest (packet 1208)."""
        ...

    # ── Retired seal residue (packet 1246-02) ─────────────────────────────────────
    # Seal/restore is gone: the feature and its code path were removed, and the FileMaker container
    # it used stays inert because the shipped file is frozen. What remains is a PRESENCE probe and
    # nothing else — no read of the envelope, no parse, no unwrap, no restore. It exists because a
    # corpus that still carries that residue is an unsupported, unexpected state, and the lifecycle
    # must be able to say so and stop instead of migrating over something it will not reason about.
    def seal_residue_state(self) -> str:
        """`present` · `absent` · `error`. Never interpreted, never returned as bytes.

        `error` is a real answer and a distinct one: a probe that could not reach the container has
        NOT established that it is empty, and a caller must be able to tell those apart rather than
        inheriting a reassuring default.
        """
        ...

    # HISTORY (append-only artifact-activity events, packet 085 U3c) is NOT a backend Protocol
    # concern — it is engine-based and lives in corpusfm.server.history, uniform across backends.

    # The QUEUE workspace (packet 086) is engine-based too — QueueRepo (storage.repos) over the
    # generic engine, not a backend Protocol concern. (The old per-job enqueue_job/list_jobs/
    # update_job/delete_job primitives — packet 052's ENRICHQUEUE FIFO — were retired with the
    # enrich_queue drainer.)

    # ── AI summaries blob (packet 054) ───────────────────────────────────────────
    # Store the summaries.json content WITH the artifact (FM container blob) so it survives an
    # app reinstall / archive wipe / db restore-or-move, instead of as an orphan-able local sidecar.

    def store_summaries(self, rel_path: str, summaries: dict) -> None:
        """Persist an artifact's AI summaries (sets the HasSummaries flag). Best-effort."""
        ...

    def load_summaries(self, record_uuid: str) -> dict:
        """Return an artifact's stored summaries ({} when none). Falls back to a local sidecar
        (lazy-migrating it into the blob) for back-compat."""
        ...

    # ── Addon companion containers (packet 1166 A1) ──────────────────────────────
    # Both impls already have these; declared here for protocol uniformity so the container-download
    # resolver can address every retained container the same way (all keyed by the record UUID).
    def load_name_map(self, record_uuid: str) -> dict:
        """The addon UUID→readable-name map ({} when absent — a non-addon record legitimately has none)."""
        ...

    def load_icon(self, record_uuid: str) -> "Optional[bytes]":
        """The addon icon bytes (None when absent)."""
        ...
