"""Shared artifact-store WRITE path over the StorageEngine (packet 084 Phase 4 + 085 U3a).

One implementation of the artifact write choreography for both backends.

**A STORAGE record carries its real ``Type`` from its initial create (packet 1361-01, final
ruling).** The blank-``Type`` staging phase and the visibility PATCH that ended it are GONE. They
existed to keep a record out of the catalog until its container landed, and they bought that with
two writes per artifact, a second row state every reader had to know about, and a startup sweep
that scanned STORAGE for the residue — a policing job the product does not want. What replaces
them is ordinary, local, and anchored:

1. CREATE the record, typed;
2. upload the container;
3. on a caught failure at either step, best-effort DELETE that exact record and report the
   failure. If the compensation itself fails, the record is PRESERVED for administration and the
   failure says so — it is never reported as removed.

A hard process death between (1) and (2) can leave a containerless record. That is accepted: it is
visible, it is addressable, and an administrator can act on it. Nothing scans for it, and nothing
deletes it behind the operator's back.

- :func:`store_artifact` — the DIRECT store path (reabsorb, job runs, MCP/queue saves).
- :func:`land_artifact` — the QUEUE-workspace landing path (packet 085). The QUEUE row's
  ``UUIDStorage`` anchor is written BEFORE the create, so a re-land inspects and cleans only the
  exact UUID its own unfinished queue operation anchored — never a global STORAGE scan.
"""
from __future__ import annotations

import io
import json
import logging
import uuid as _uuidlib
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_STORAGE = "STORAGE"
_QUEUE = "QUEUE"


def _now_ts() -> str:
    # UTC, microsecond precision (packet 1005 / 064): the ArtifactTimestamp lineage key. Same
    # lexically-sortable %Y-%m-%d_%H%M%S_%f shape as before — only the basis is now UTC, so ordering
    # is unambiguous across boxes/DST. Fresh-install substrate (085), so no old-local/new-UTC mixing.
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")


def _encoded_blobs(artifact, *, addon_package, xml_bytes, keep_source_xml, encrypt_on) -> list:
    """[(container_field, encoded_bytes)] for an artifact store — ArtifactData always,
    NameMapData for addons, SourceXML when kept (callers drop it when the staged source
    is being MOVED in from the QUEUE row instead of re-uploaded)."""
    from corpusfm.core.crypto import compress, encode_blob
    buf = io.BytesIO()
    artifact.dump_gz(buf)
    blobs = [("ArtifactData", encode_blob(buf.getvalue(), encrypt_on=encrypt_on))]
    if addon_package is not None and addon_package.name_map:
        nm = json.dumps(addon_package.name_map, ensure_ascii=False).encode("utf-8")
        blobs.append(("NameMapData", encode_blob(compress(nm), encrypt_on=encrypt_on)))
    if keep_source_xml and xml_bytes:
        blobs.append(("SourceXML", encode_blob(compress(xml_bytes), encrypt_on=encrypt_on)))
    return blobs


# ── catalog publication (packet 1361-01) ──────────────────────────────────────
# The persistent catalog is published only from a CONFIRMED write, and never before. Both helpers
# swallow their own failures: a publication that fails costs freshness (the next read synchronizes),
# and it must never be mistaken for the write failing.

def publish_committed(backend, committed, record_uuid: str, *, operation: str = "store") -> None:
    """Publish one confirmed record.

    ``committed`` is the engine's ``WriteRow`` — ``UUID`` + the opaque ``JSONOfRecord`` exactly as
    the substrate returned them, narrowed at the engine boundary. ``None`` means the response was
    not a usable full record; the mutation contract forbids publishing the request document in that
    case, so nothing is published and the ordinary reconciliation age recovers. The write itself is
    already confirmed and is never reported as failed either way."""
    from corpusfm.server import catalog
    catalog.publish_write(backend, catalog.TABLE_STORAGE, record_uuid, committed,
                          operation=operation)


def publish_removed(backend, record_uuid: str) -> None:
    """Publish one record's confirmed removal."""
    from corpusfm.server import catalog
    catalog.publish_deleted(backend, catalog.TABLE_STORAGE, record_uuid)


def _record_arrival(backend, meta, *, origin: str = "", filename: str = "", owner: str = "",
                    byte_size: int = 0) -> None:
    """Write the HISTORY Arrival event for a freshly landed record (best-effort, 085 U3c) —
    every artifact's birth/provenance mention. UUID-addressed (packet 085 U3f)."""
    try:
        from corpusfm.server.history import record_arrival
        record_arrival(backend, meta.uuid, filename=filename, origin=origin, owner=owner,
                       byte_size=byte_size, name=getattr(meta, "name", "") or "")
    except Exception:
        logger.debug("arrival history write failed (best-effort)", exc_info=True)


def _compensate(backend, record_uuid: str, what: str) -> bool:
    """Best-effort delete of the EXACT record this operation created, after it failed.

    Returns whether the record is gone. A failed compensation is not silent and is not dressed up:
    the record is PRESERVED, the log names it, and the caller's failure carries that fact — the one
    thing that must never happen is claiming a removal that did not occur (packet 1361-01)."""
    eng = backend.engine
    try:
        eng.delete(_STORAGE, record_uuid)
    except Exception:
        logger.error("%s failed AND its compensating delete failed — STORAGE record %s is "
                     "PRESERVED with no usable content and needs administrator attention",
                     what, record_uuid, exc_info=True)
        return False
    publish_removed(backend, record_uuid)
    return True


def store_artifact(backend, artifact, xml_bytes: Optional[bytes] = None, *, label: str = "",
                   origin: str = "Import", job_uuid: str = "", run_uuid: str = "",
                   addon_package=None, keep_source_xml: bool = False):
    """Store an artifact directly (deliverables, reabsorb, job runs, MCP/queue saves).

    1. CREATE the record with its REAL ``Type`` — one write, catalog-visible immediately;
    2. upload the containers (separate writes — neither substrate has a multi-write transaction);
    3. publish what the substrate confirmed.

    An ordinary caught failure at either step best-effort deletes this exact record and re-raises.
    If that compensation fails the record is preserved and the raised error says so, because
    claiming a removal that did not happen is the one outcome that would mislead an administrator.

    There is no anchor hook here (packet 1361-01, ruling 10). The path that genuinely needs one —
    a pull job — does not come through this function at all: it lands through :func:`land_artifact`
    from its own QUEUE row, which writes ``UUIDStorage`` before the create. The hook this function
    briefly carried had no production caller and anchored nothing while looking as though it did.
    """
    from corpusfm.storage.artifact_record import build_record, meta_from_jor

    eng = backend.engine
    timestamp = _now_ts()
    record_uuid = str(_uuidlib.uuid4())
    jor = build_record(artifact, timestamp=timestamp, label=label, origin=origin,
                       job_uuid=job_uuid, run_uuid=run_uuid, addon_package=addon_package,
                       xml_bytes=xml_bytes, keep_source_xml=keep_source_xml)
    committed = eng.create(_STORAGE, record_uuid, jor)
    try:
        for field, data in _encoded_blobs(artifact, addon_package=addon_package,
                                          xml_bytes=xml_bytes, keep_source_xml=keep_source_xml,
                                          encrypt_on=backend._encrypt_blobs()):
            eng.blob_put(_STORAGE, record_uuid, field, data)
    except Exception as exc:
        if _compensate(backend, record_uuid, "artifact store"):
            raise
        raise RuntimeError(
            f"artifact store failed ({exc}) and the record could not be removed — STORAGE record "
            f"{record_uuid} is preserved with no content and needs administrator attention"
        ) from exc
    publish_committed(backend, committed, record_uuid)
    # NB: the direct store path does NOT write an Arrival — Arrival is the IMPORT provenance
    # event, written at the landing chokepoint (land_artifact, §5). A direct store (MCP save,
    # reabsorb, job-run artifact) is not an "arrival"; job runs carry their own Run event.
    return meta_from_jor(jor, uuid=record_uuid)


def land_artifact(backend, queue_id: str, artifact, *, xml_bytes: Optional[bytes] = None,
                  label: str = "", origin: str = "Import", addon_package=None,
                  keep_source_xml: bool = False):
    """Land a QUEUE "Artifact Ingestion" row (``queue_id``) into a FRESH STORAGE record.

    Typed create → artifact containers → (schema-XML+keep) MOVE the staged source container from the
    QUEUE row into the new record FM-internally, no bytes back through the app. The addon+keep path
    re-uploads the extracted XML (its staged blob is the .fmaddon package, not the SourceXML);
    no-keep uploads no source and the staged blob dies with the QUEUE row.

    **Crash idempotency is ANCHORED, never scanned.** The QUEUE row's ``UUIDStorage`` is written
    BEFORE the STORAGE create, so a re-land after a mid-landing crash inspects exactly ONE record —
    the one this queue operation itself anchored. A prior attempt whose ArtifactData container is
    definitely absent is deleted and re-landed; anything else (present, or uncertain) is treated as
    already landed and short-circuits, so a completed landing whose QUEUE row never advanced is
    never destroyed and re-minted under a different UUID. Nothing here reads any other record.

    Lineage: ``UUIDJob``/``RunUUID`` are read from the QUEUE row (its ``UUIDJob`` slot and
    ``Payload.run_id``), never from a parameter — the record is the authority. The caller owns the
    promotion (``server.latest.mark_latest_on_store``), as the pull path does."""
    from corpusfm.storage.artifact_record import build_record, meta_from_jor

    eng = backend.engine
    qrows = eng.get_by_keys(_QUEUE, [queue_id])
    qjor = dict(qrows[0].jor) if qrows else {}
    prior = (qjor.get("UUIDStorage") or "") if qrows else ""
    if prior:
        prows = eng.get_by_keys(_STORAGE, [prior])
        if prows:
            # `blob_exists is None` (uncertain) counts as present: on doubt KEEP the record rather
            # than delete it. Only a definite absence proves the prior attempt never finished.
            if eng.blob_exists(_STORAGE, prior, "ArtifactData") is not False:
                return meta_from_jor(dict(prows[0].jor), uuid=prior)
            try:
                eng.delete(_STORAGE, prior)
                publish_removed(backend, prior)
            except Exception:
                logger.warning("land: could not clean the incomplete prior attempt %s anchored on "
                               "queue %s — it is preserved", prior, queue_id, exc_info=True)

    record_uuid = str(_uuidlib.uuid4())
    # Job identity comes off the QUEUE row itself (packet 1145) — the record carries what it needs, so
    # no caller has to thread it in. A browser import has no UUIDJob and stays a job-less always-latest
    # singleton; a job-produced landing (fms_push) gets the same lineage keys the pull path writes
    # through store_artifact, or its artifact is invisible to UUIDJob-scoped reads (latest, retention).
    job_uuid = (qjor.get("UUIDJob") or "") if qrows else ""
    run_uuid = ((qjor.get("Payload") or {}).get("run_id") or "") if qrows else ""
    if job_uuid and origin == "Import":
        origin = "Job"
    jor = build_record(artifact, timestamp=_now_ts(), label=label, origin=origin,
                       job_uuid=job_uuid, run_uuid=run_uuid,
                       addon_package=addon_package, xml_bytes=xml_bytes,
                       keep_source_xml=keep_source_xml)
    # Anchor the new landing on the QUEUE row BEFORE creating the STORAGE row (crash anchor).
    if qrows:
        qjor["UUIDStorage"] = record_uuid
        eng.update(_QUEUE, queue_id, qjor)
    committed = eng.create(_STORAGE, record_uuid, jor)

    # The staged source is byte-identical to the final SourceXML only on the plain schema-XML
    # path (an addon's staged blob is the .fmaddon package). Move it in; else upload fresh/skip.
    move_source = bool(keep_source_xml and xml_bytes and addon_package is None)
    try:
        for field, data in _encoded_blobs(
                artifact, addon_package=addon_package, xml_bytes=xml_bytes,
                keep_source_xml=(keep_source_xml and not move_source),
                encrypt_on=backend._encrypt_blobs()):
            eng.blob_put(_STORAGE, record_uuid, field, data)
        if move_source:
            if not backend.move_container(_QUEUE, queue_id, "SourceXML",
                                          _STORAGE, record_uuid, "SourceXML"):
                raise RuntimeError(f"staged source container move/verify failed for {queue_id}")
    except Exception as exc:
        if _compensate(backend, record_uuid, "artifact landing"):
            raise
        raise RuntimeError(
            f"artifact landing failed ({exc}) and the record could not be removed — STORAGE record "
            f"{record_uuid} is preserved with no content and needs administrator attention"
        ) from exc
    publish_committed(backend, committed, record_uuid)
    meta = meta_from_jor(jor, uuid=record_uuid)
    _record_arrival(backend, meta, origin=origin,
                    filename=(qjor.get("filename") or "") or label,
                    owner=(qjor.get("owner") or ""),
                    byte_size=len(xml_bytes or b""))
    return meta


# Fields carried over UNCHANGED across an in-place re-ingest (packet 1062): the record's identity /
# lineage key, the user's own content, and addon PRESENTATION facts a source-XML re-ingest can't
# reproduce (the addon icon/version/locale/name-map ride the record + the NameMapData blob, not the
# extracted XML). Everything else (rendered layers in the blob, gap counts, schema_version,
# provenance) is taken FRESH from the re-ingest — that is the whole point of refreshing.
_REINGEST_PRESERVE_KEYS = (
    "ArtifactTimestamp",   # the lineage/version key — MUST NOT change (this is a refresh, not a snapshot)
    "Description", "Memory", "Origin", "UUIDJob", "RunUUID",
    "icon_b64", "addon_version", "addon_locale", "has_name_map",
)


class ReingestResult:
    """Outcome of an in-place re-ingest. ``ok`` + ``meta`` on success; ``error`` on failure (the old
    record was left untouched). ``was_addon`` lets the caller resolve the addon name_map path."""
    __slots__ = ("ok", "meta", "error", "was_addon")

    def __init__(self, ok, *, meta=None, error="", was_addon=False):
        self.ok = ok
        self.meta = meta
        self.error = error
        self.was_addon = was_addon


def reingest_artifact(backend, record_uuid: str, *, keep_source_xml: bool = True) -> "ReingestResult":
    """Atomically re-ingest a stored SCHEMA artifact from its RETAINED source XML and REPLACE the
    record IN PLACE — same record UUID, same identity/lineage (ArtifactTimestamp), fresh derived
    layers (rendered_text / xref / gaps / structure_intent). This is an *in-place refresh*, NOT a new
    snapshot or lineage (contrast :func:`land_artifact` and ``reimport_after_patch``, which mint a NEW
    identity).

    All fallible computation — reading the source, parsing, mining, rendering, encoding the new blob —
    happens BEFORE any write to the record, so a parse error / version-fence rejection / incomplete
    layers leaves the OLD record entirely untouched (the packet's core guarantee). The only writes are
    the final blob swap + jor commit under the existing UUID; the source XML is already present (we read
    it from there) and is left in place. Returns a :class:`ReingestResult`.

    Re-ingesting the same source yields the same ``.fmp12`` identity (the File= name normalizes
    identically), so the record UUID and lineage stay stable with no new-snapshot risk."""
    from corpusfm.ingestion.pipeline import ingest
    from corpusfm.storage.artifact_record import build_record, meta_from_jor

    eng = backend.engine
    try:
        old_jor = dict(backend.load_record_jor(record_uuid) or {})
    except Exception:
        old_jor = {}
    if not old_jor:
        return ReingestResult(False, error="artifact not found")

    from corpusfm.artifact.capabilities import SCHEMA_TYPES
    if old_jor.get("Type") not in SCHEMA_TYPES:
        return ReingestResult(False, error="not a schema artifact — nothing to re-ingest")
    if not old_jor.get("has_source"):
        return ReingestResult(
            False, error="no retained source XML — re-upload the file to refresh it")

    try:
        source_xml = backend.load_raw_xml(record_uuid)
    except Exception:
        source_xml = None
    if not source_xml:
        return ReingestResult(False, error="stored source XML is missing or unreadable")

    was_addon = bool(old_jor.get("has_name_map")) or old_jor.get("Type") == "AddonXML"
    name_map = {}
    if was_addon:
        try:
            name_map = backend.load_name_map(record_uuid) or {}
        except Exception:
            name_map = {}

    label = old_jor.get("PrimaryName", "") or old_jor.get("FileName", "") or "artifact"
    # THE fallible stage — a bad source / version-fence / incomplete layers raises here, BEFORE any
    # write, so the old record is left intact.
    try:
        artifact = ingest(source_xml, label, source_type="manual", name_map=name_map or None)
        fresh = build_record(
            artifact, timestamp=old_jor.get("ArtifactTimestamp", "") or _now_ts(),
            label=label, origin=old_jor.get("Origin", "Import"),
            job_uuid=old_jor.get("UUIDJob", ""), run_uuid=old_jor.get("RunUUID", ""),
            xml_bytes=source_xml, keep_source_xml=keep_source_xml)
        blobs = _encoded_blobs(artifact, addon_package=None, xml_bytes=source_xml,
                               keep_source_xml=False,   # source already present — never rewrite it
                               encrypt_on=backend._encrypt_blobs())
    except (ValueError, SyntaxError) as exc:
        return ReingestResult(False, error=str(exc) or "re-ingest could not parse the stored source")
    except Exception as exc:
        return ReingestResult(False, error=f"re-ingest failed: {exc}")
    if not getattr(artifact, "items", None):
        return ReingestResult(False, error="re-ingest produced an empty artifact — old record kept")

    # Merge: OLD jor is the base (keeps git_targets + any custom keys), FRESH derived fields overlay,
    # then the identity/user/presentation preserve-list is restored from OLD.
    merged = {**old_jor, **fresh}
    for k in _REINGEST_PRESERVE_KEYS:
        if k in old_jor:
            merged[k] = old_jor[k]
    merged["has_source"] = bool(keep_source_xml)   # the source stays as it was
    # A fresh re-ingest carries no summaries; the caller re-enqueues SUMMARIZE if it had them.
    merged["HasSummaries"] = False

    # The only writes: swap the ArtifactData blob (+ NameMapData for an addon), then commit the jor.
    # No transaction primitive exists on either substrate; blob-first-then-jor mirrors store_artifact.
    try:
        for field, data in blobs:
            if field == "SourceXML":
                continue     # never touch the retained source
            eng.blob_put(_STORAGE, record_uuid, field, data)
        committed = eng.update(_STORAGE, record_uuid, merged)
    except Exception as exc:
        logger.warning("reingest: blob/jor write failed for %s", record_uuid, exc_info=True)
        return ReingestResult(False, error=f"re-ingest write failed: {exc}")

    publish_committed(backend, committed, record_uuid)
    return ReingestResult(True, meta=meta_from_jor(merged, uuid=record_uuid), was_addon=was_addon)


# `heal_publish_integrity` is GONE (packet 1361-01, final ruling). It scanned STORAGE at every
# startup for two things the product has decided it does not police: Type-less staged residue (a
# state that no longer exists, because a record is typed from its create) and "poison" rows whose
# ArtifactData container was missing. The second was a container-integrity verdict reached from a
# listing, acted on by DELETING a database record — and a `blob_exists` that answered False for a
# transport reason would have destroyed a real artifact. Container existence is nobody's startup
# business now: queue recovery cleans only the exact UUID its own unfinished operation anchored,
# and anything else is an administrator's call.
