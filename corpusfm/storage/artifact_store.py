"""Shared artifact-store WRITE path over the StorageEngine (packet 084 Phase 4 + 077-E + 085 U3a).

One implementation of the artifact write choreography for both backends, built on the
publish-after-blob invariant (RELEASE-GATING, dev-ratified 2026-07-03): **a record is never
catalog-visible before its required blobs exist.** Packet 085 makes this STRUCTURAL — a record
becomes visible only when its ``Type`` (a VISIBLE_TYPES member) appears; the staged phase is a
Type-LESS row (invisible under the Type fence), so there is no sentinel value anymore.

- :func:`store_artifact` — the DIRECT store path (deliverables, reabsorb, job runs, MCP saves):
  create the record STAGED (Type-less → invisible), upload the blobs, then ONE full-jor update
  is the atomic visibility commit (Type appears). A blob failure compensates with a best-effort
  delete of the (never visible) staged record.
- :func:`land_artifact` — the QUEUE-workspace landing path (packet 085): land a QUEUE "Artifact
  Ingestion" row into a FRESH STORAGE record. Bare Type-less create → artifact blobs → the staged
  source container is MOVED FM-internally into the new record (``move_container``, no bytes back
  through the app) on the schema-XML+keep path (addon/keep re-uploads the extracted XML; no-keep
  skips it) → one visibility commit. Crash-idempotent: a prior partial (Type-less) STORAGE row
  anchored on the QUEUE row is deleted before re-landing, so one QUEUE row yields exactly one
  landed record.
- :func:`heal_publish_integrity` — the 077-E startup heal: drop aged Type-less staged-store crash
  residue and any catalog-VISIBLE row whose required ArtifactData blob is missing (poison rows
  from pre-invariant code). Best-effort, fail-open — never blocks startup.
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

# Staged crash residue younger than this is left alone (an in-flight store on another worker
# thread may still be uploading its blobs).
_STAGED_RESIDUE_MIN_AGE_S = 3600


def _now_ts() -> str:
    # UTC, microsecond precision (packet 1005 / 064): the ArtifactTimestamp lineage key. Same
    # lexically-sortable %Y-%m-%d_%H%M%S_%f shape as before — only the basis is now UTC, so ordering
    # is unambiguous across boxes/DST. Fresh-install substrate (085), so no old-local/new-UTC mixing.
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_%f")


def _staged_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


def store_artifact(backend, artifact, xml_bytes: Optional[bytes] = None, *, label: str = "",
                   origin: str = "Import", job_uuid: str = "", run_uuid: str = "",
                   addon_package=None, keep_source_xml: bool = False):
    """Store an artifact directly (deliverables, reabsorb, job runs, MCP saves) under the
    publish-after-blob invariant (077-E order):

    1. CREATE the record STAGED: the final identity jor with ``Type`` blanked (+ ``IsLatest`` off).
       A Type-less row is outside VISIBLE_TYPES, so it is structurally invisible to the catalog /
       picker / facets / lineage / enrichment — no sentinel value.
    2. Upload the blobs (separate writes — neither substrate has a multi-write transaction).
    3. ONE full-jor update sets the real ``Type`` — the atomic visibility commit (slots re-derive:
       FM auto-enter CF / SQLite generated columns).

    A blob/commit failure compensates by best-effort deleting the staged (never visible) record
    and re-raising. A hard crash mid-store leaves an invisible Type-less row the startup heal
    reaps once aged."""
    from corpusfm.storage.artifact_record import build_record, meta_from_jor

    eng = backend.engine
    timestamp = _now_ts()
    record_uuid = str(_uuidlib.uuid4())
    jor = build_record(artifact, timestamp=timestamp, label=label, origin=origin,
                       job_uuid=job_uuid, run_uuid=run_uuid, addon_package=addon_package,
                       xml_bytes=xml_bytes, keep_source_xml=keep_source_xml)
    staged = {**jor, "Type": "", "IsLatest": False, "staged_created": _staged_stamp()}
    eng.create(_STORAGE, record_uuid, staged)
    try:
        for field, data in _encoded_blobs(artifact, addon_package=addon_package,
                                          xml_bytes=xml_bytes, keep_source_xml=keep_source_xml,
                                          encrypt_on=backend._encrypt_blobs()):
            eng.blob_put(_STORAGE, record_uuid, field, data)
        eng.update(_STORAGE, record_uuid, jor)
    except Exception:
        # Compensate: the staged record was never visible, so this only prevents invisible
        # residue; a failed compensate is reaped by the startup heal.
        try:
            eng.delete(_STORAGE, record_uuid)
        except Exception:
            logger.warning("store compensate-delete failed for %s (staged residue; the startup "
                           "heal reaps it)", record_uuid, exc_info=True)
        raise
    # NB: the direct store path does NOT write an Arrival — Arrival is the IMPORT provenance
    # event, written at the landing chokepoint (land_artifact, §5). A direct store (MCP save,
    # reabsorb, job-run artifact) is not an "arrival"; job runs carry their own Run event.
    return meta_from_jor(jor, uuid=record_uuid)


def land_artifact(backend, queue_id: str, artifact, *, xml_bytes: Optional[bytes] = None,
                  label: str = "", origin: str = "Import", addon_package=None,
                  keep_source_xml: bool = False):
    """Land a QUEUE "Artifact Ingestion" row (``queue_id``) into a FRESH STORAGE record.

    Bare Type-less create → artifact blobs → (schema-XML+keep) MOVE the staged source container
    from the QUEUE row into the new record FM-internally, no bytes back through the app → one
    full-jor visibility commit. The addon+keep path re-uploads the extracted XML (its staged blob
    is the .fmaddon package, not the SourceXML); no-keep uploads no source and the staged blob
    dies with the QUEUE row (the caller deletes it after landing).

    Crash idempotency: the QUEUE row carries a ``UUIDStorage`` anchor set BEFORE the STORAGE
    create; a re-land after a mid-landing crash first deletes the prior partial (Type-less) STORAGE
    row, so one QUEUE row yields exactly one landed record.

    Lineage: ``UUIDJob``/``RunUUID`` are read from the QUEUE row (its ``UUIDJob`` slot and
    ``Payload.run_id``), never from a parameter — the record is the authority. The caller owns the
    IsLatest demote (``server.latest.mark_latest_on_store``), as the pull path does."""
    from corpusfm.storage.artifact_record import build_record, meta_from_jor

    eng = backend.engine
    qrows = eng.get_by_keys(_QUEUE, [queue_id])
    qjor = dict(qrows[0].jor) if qrows else {}
    prior = (qjor.get("UUIDStorage") or "") if qrows else ""
    if prior:
        # The anchor may point at a prior attempt in one of two states (packet 1009/F1). A Type-LESS
        # row is an interrupted partial (crash BEFORE the visibility commit) → delete and re-land.
        # But a crash AFTER the visibility commit + its Arrival, yet BEFORE the QUEUE row advanced,
        # leaves the anchor pointing at a FULLY LANDED, catalog-visible artifact — blindly deleting
        # it would destroy a live record (that Arrival history already references) and mint a
        # DIFFERENT UUID. Detect the completed landing and short-circuit so the caller just advances
        # the QUEUE row. `blob_exists is None` (uncertain) counts as present here: on doubt we keep
        # the visible record rather than delete it (mirrors the startup heal's fail-safe).
        prows = eng.get_by_keys(_STORAGE, [prior])
        pjor = dict(prows[0].jor) if prows else {}
        if pjor.get("Type") and eng.blob_exists(_STORAGE, prior, "ArtifactData") is not False:
            return meta_from_jor(pjor, uuid=prior)
        try:
            eng.delete(_STORAGE, prior)   # drop a prior interrupted (Type-less/poison) partial row
        except Exception:
            logger.debug("land: prior-partial delete failed for %s (heal reaps it)", prior,
                         exc_info=True)

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
    staged = {**jor, "Type": "", "IsLatest": False, "staged_created": _staged_stamp()}
    eng.create(_STORAGE, record_uuid, staged)

    # The staged source is byte-identical to the final SourceXML only on the plain schema-XML
    # path (an addon's staged blob is the .fmaddon package). Move it in; else upload fresh/skip.
    move_source = bool(keep_source_xml and xml_bytes and addon_package is None)
    for field, data in _encoded_blobs(
            artifact, addon_package=addon_package, xml_bytes=xml_bytes,
            keep_source_xml=(keep_source_xml and not move_source),
            encrypt_on=backend._encrypt_blobs()):
        eng.blob_put(_STORAGE, record_uuid, field, data)
    if move_source:
        if not backend.move_container(_QUEUE, queue_id, "SourceXML",
                                      _STORAGE, record_uuid, "SourceXML"):
            raise RuntimeError(f"staged source container move/verify failed for {queue_id}")
    eng.update(_STORAGE, record_uuid, jor)   # atomic visibility commit
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
    "IsLatest", "Description", "Memory", "Origin", "UUIDJob", "RunUUID",
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
        eng.update(_STORAGE, record_uuid, merged)
    except Exception as exc:
        logger.warning("reingest: blob/jor write failed for %s", record_uuid, exc_info=True)
        return ReingestResult(False, error=f"re-ingest write failed: {exc}")

    try:
        from corpusfm.server.tags_store import invalidate_record_views
        invalidate_record_views()
    except Exception:
        pass
    return ReingestResult(True, meta=meta_from_jor(merged, uuid=record_uuid), was_addon=was_addon)


def heal_publish_integrity(backend) -> dict:
    """The 077-E startup heal. Two sweeps, both best-effort and fail-open:

    1. **Staged crash residue** — Type-LESS STORAGE rows (a store/landing crashed between create
       and the visibility commit; the row was never visible) older than an hour → delete.
    2. **Poison rows** — catalog-VISIBLE rows (a SCHEMA_TYPES ``Type``) whose required ArtifactData
       blob is missing/empty (pre-invariant crash residue; the new write order cannot create these)
       → delete, loudly. Existence is checked with the engine's cheap ``blob_exists`` (never a
       download) and BOUNDED to the newest 25 rows per boot — a crash's residue is by nature the
       most recent writes; the bound is logged, never silent. ``blob_exists`` returning None
       (uncertain) NEVER deletes.

    Returns {"staged_residue": n, "poison": n}."""
    out = {"staged_residue": 0, "poison": 0}
    eng = getattr(backend, "engine", None)
    if eng is None:
        return out
    try:
        now = datetime.now(timezone.utc)   # UTC to match _staged_stamp (packet 1005); both tz-aware
        rows, _ = eng.page(_STORAGE, eq={"Type": ""}, per_page=200)
        for r in rows:
            created = r.jor.get("staged_created", "")
            try:
                age_s = (now - datetime.fromisoformat(created)).total_seconds()
            except Exception:
                age_s = _STAGED_RESIDUE_MIN_AGE_S + 1
            if age_s > _STAGED_RESIDUE_MIN_AGE_S:
                eng.delete(_STORAGE, r.key)
                out["staged_residue"] += 1
                logger.warning("heal: reaped Type-less staged crash residue %s (%s)",
                               r.key, r.jor.get("FileName", "?"))
    except Exception:
        logger.debug("heal: staged-residue sweep failed (skipped)", exc_info=True)
    try:
        limit = 25
        from corpusfm.artifact.capabilities import SCHEMA_TYPES
        rows, _ = eng.page(_STORAGE, isin={"Type": sorted(SCHEMA_TYPES)},
                           orderby="ArtifactTimestamp", desc=True, page=1, per_page=limit)
        if len(rows) == limit:
            logger.info("heal: poison sweep bounded to the newest %d visible rows", limit)
        for r in rows:
            if eng.blob_exists(_STORAGE, r.key, "ArtifactData") is False:
                eng.delete(_STORAGE, r.key)
                out["poison"] += 1
                logger.warning("heal: removed poison row %s (%s/%s) — schema type with no "
                               "ArtifactData blob", r.key, r.jor.get("FileName", "?"),
                               r.jor.get("ArtifactTimestamp", "?"))
    except Exception:
        logger.debug("heal: poison-row sweep failed (skipped)", exc_info=True)
    if out["staged_residue"] or out["poison"]:
        try:
            from corpusfm.server.tags_store import invalidate_record_views
            invalidate_record_views()
        except Exception:
            pass
    return out
