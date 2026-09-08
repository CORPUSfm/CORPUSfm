"""Shared import ingest — route raw import bytes by type → parse → store → tags (packet 055).

The single source of truth for turning ONE uploaded import file into a stored artifact. Both
`POST /api/upload` (the interactive + bearer/push path) and the QUEUE ``land`` handler
(server/queue_handlers.py, packet 086 — the land worker of the unified queue workspace) call it, so
the type routing lives in one place instead of drifting between two.

SYNCHRONOUS + blocking on purpose: call it under the upload route's `_offload` (to keep the single event
loop free) or directly from the land worker's thread (already off the loop). It never runs the push
pipeline or enrichment — those stay with their callers (push is bearer-only; enrichment is a queue step
/ the land handler's bridge per the import's options).

The XML hardening (`safe_xml`/defusedxml, applied inside `ingest`/`parse_addon_xar`/`parse_uploaded_
artifact`) and the size cap (enforced by the caller before the bytes reach here) are unchanged — this
helper only reorganizes WHICH function routes the already-hardened code.
"""
from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path

from corpusfm.core.filenames import primary_name_from_filename

log = logging.getLogger("corpusfm.import_ingest")


class IngestOutcome:
    """Result of ingesting one import file. `payload` is the JSON body the upload route returns as-is;
    the queue path reads `ok` / `rel_path` to decide enrichment."""

    __slots__ = ("ok", "status", "payload", "artifact", "meta", "rel_path", "uuid",
                 "is_clip", "is_addon", "reabsorbed", "ran_pipeline", "error")

    def __init__(self, ok, *, status=200, payload=None, artifact=None, meta=None, rel_path="",
                 uuid="", is_clip=False, is_addon=False, reabsorbed=False,
                 ran_pipeline=False, error=""):
        self.ok = ok
        self.status = status
        self.payload = payload or {}
        self.artifact = artifact
        self.meta = meta
        self.rel_path = rel_path
        self.uuid = uuid   # canonical record address of the landed artifact (packet 085 U3f)
        self.is_clip = is_clip
        self.is_addon = is_addon
        self.reabsorbed = reabsorbed
        self.ran_pipeline = ran_pipeline
        self.error = error


def _err(msg: str, status: int = 400) -> IngestOutcome:
    return IngestOutcome(False, status=status, error=msg, payload={"ok": False, "error": msg})


def _label_from_identity(artifact) -> str:
    from corpusfm.app.web.routes.api.upload import _label_from_identity as _impl
    return _impl(artifact)


def ingest_import_bytes(raw: bytes, filename: str, *, name: str = "", locale: str = "",
                        backend=None, cfg=None, land_from: str = "",
                        origin: str = "Import",
                        keep_source_xml: bool = False) -> IngestOutcome:
    """Route `raw` bytes by `filename` extension → parse → store → tags. Returns an IngestOutcome.

    ``land_from`` (the ingest worker's path): the QUEUE "Artifact Ingestion" row id these bytes
    came from. The schema-XML/addon store then LANDS a fresh STORAGE record via
    ``artifact_store.land_artifact``, moving the staged source container in from the QUEUE row
    (schema-XML+keep path) instead of re-uploading it. Clip and reabsorb intakes use the plain
    ``store_artifact`` (V1 scope); the worker deletes the QUEUE row after any successful land.

    ``origin`` (packet 1169) is the stored provenance/channel for the landed artifact. A human web
    upload passes ``"WebUI"`` (both ``/api/upload`` and the queue browser-import branch); an MCP import
    passes ``"MCP"``. It defaults to the generic ``"Import"`` fallback for any caller that names no
    channel. A ``.artifact`` reabsorb always stamps ``"Reabsorb"`` internally and ignores this. On the
    land path a job run passes ``"Import"`` so ``land_artifact`` promotes it to ``"Job"`` via the
    queue row's ``UUIDJob`` — the promotion only fires while ``origin == "Import"``, so a non-Import
    channel (WebUI/MCP) flows straight through unchanged.

    ``keep_source_xml`` is the per-intake OPT-IN that unions with the configured default (the CLI's
    ``--keep-source-xml`` reaches the worker through the queue payload; nothing else sets it)."""
    # No catalog bust here (packet 1361-01): the store / land chokepoints publish the record they
    # committed, so the just-imported artifact is in the catalog before this returns.
    return _ingest_import_bytes(raw, filename, name=name, locale=locale, backend=backend, cfg=cfg,
                                land_from=land_from, origin=origin,
                                keep_source_xml=keep_source_xml)


def _ingest_import_bytes(raw: bytes, filename: str, *, name: str = "", locale: str = "",
                         backend=None, cfg=None, land_from: str = "",
                         origin: str = "Import",
                         keep_source_xml: bool = False) -> IngestOutcome:
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    if cfg is None:
        from corpusfm.app.app_config import load_app_config
        cfg = load_app_config()

    fn = filename or "unknown"
    low = fn.lower()

    if low.endswith(".xml"):
        from corpusfm.ingestion.clip import detect_clip, ingest_clip
        # fmxmlsnippet clip — handled before the FMAdd_on / FMPReport rejections.
        if detect_clip(raw):
            label = (name or "").strip() or primary_name_from_filename(fn)
            try:
                clip_artifact = ingest_clip(raw, label)
            except (ValueError, SyntaxError) as exc:
                # A malformed clip is a HARD failure (bad bytes), not a transient one — return an
                # outcome so the pending worker records + drops it instead of retrying forever (077-A).
                return _err(str(exc) or "This clip could not be parsed.")
            clip_meta = backend.store_artifact(clip_artifact, label=label, origin=origin)
            return IngestOutcome(
                True, artifact=clip_artifact, meta=clip_meta, rel_path=clip_meta.rel_path,
                uuid=clip_meta.uuid, is_clip=True,
                payload={"ok": True, "name": label, "uuid": clip_meta.uuid, "rel_path": clip_meta.rel_path,
                         "artifact_type": "fmClip", "is_clip": True, "is_addon": False,
                         "root_uuid": clip_artifact.identity.root_uuid,
                         "addon_locale": "", "has_name_map": False, "has_icon": False,
                         "gap_issues": 0, "gap_unmapped": []})
        if b"<FMAdd_on" in raw[:1024]:
            return _err("This is an addon XML file. Import the .fmaddon archive instead "
                        "— it includes locale names, metadata, and icons.")
        if b"<FMPReport" in raw[:1024]:
            return _err("This is a Database Design Report (FMPReport format), which CORPUSfm does not "
                        "support. Export a Schema XML instead: in FileMaker choose File → Save a Copy "
                        "as XML → select ‘Include details for analysis tools’ → OK.")
        return _pipeline(raw, primary_name_from_filename(fn), name, None, backend, cfg,
                         land_from=land_from, origin=origin)

    if low.endswith(".fmaddon"):
        from corpusfm.core.addon.package import parse_addon_xar
        # The staged/uploaded bytes are already bounded by the 1 GB cap; addons are small in practice
        # (UI component packages), so a full-RAM read is acceptable. parse_addon_xar needs a path.
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".fmaddon")
        try:
            os.close(tmp_fd)
            Path(tmp_path).write_bytes(raw)
            try:
                addon_package = parse_addon_xar(Path(tmp_path), locale=locale or "")
            except (ValueError, SyntaxError) as exc:
                # A malformed addon package is a HARD failure (077-A). The finally still cleans tmp.
                return _err(str(exc) or "This addon package could not be parsed.")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        return _pipeline(addon_package.xml_bytes, primary_name_from_filename(fn), name,
                         addon_package, backend, cfg, keep_source_xml=keep_source_xml,
                         land_from=land_from, origin=origin)

    from corpusfm.ingestion.reabsorb import is_artifact_envelope
    if is_artifact_envelope(fn, raw):
        return _reabsorb(raw, fn, name, backend)

    # A file that CLAIMS to be an artifact but isn't readable as one gets a specific answer, not
    # "unsupported type" — the user knows what they dropped, and being told the format is unknown
    # sends them looking for the wrong problem. (Before packet 1226 this case never reached here:
    # the recogniser accepted anything named `.artifact` on sight and the failure surfaced deeper in,
    # which is the trade the strict recogniser makes and this branch pays back.)
    if (fn or "").lower().endswith((".artifact", ".artifact.zip")):
        return _err("This artifact file could not be read as a CORPUSfm artifact — it may be "
                    "truncated, or it may not be a CORPUSfm download.")

    return _err("Unsupported file type. Import a .xml schema export (SaveAsXML), a .fmaddon "
                "addon package, or a downloaded artifact .zip (reabsorb).")


def _pipeline(xml_bytes: bytes, label: str, name: str, addon_package, backend, cfg,
              keep_source_xml: bool = False,
              land_from: str = "", origin: str = "Import") -> IngestOutcome:
    """The common SaveAsXML / addon path: ingest → store → discovery-log.
    With ``land_from`` set, the artifact is LANDED into a fresh STORAGE record from that QUEUE
    row (moving the staged source in) instead of a plain store (store/land errors still propagate
    as transient — only the parse stage converts to a hard-fail outcome).

    ``keep_source_xml`` is the per-intake OPT-IN, unioned with the configured default — the CLI's
    ``--keep-source-xml`` reaches here through the queue payload.

    ``origin`` (packet 1169) is stamped on the landed record. On the land path a job run passes
    ``"Import"`` and ``land_artifact`` promotes it to ``"Job"`` from the queue row's ``UUIDJob``.

    System tags (type:/origin:/fm:) are NOT written here — they are computed at read time from
    the stored record (packet 085 U3e)."""
    from corpusfm.ingestion.pipeline import ingest
    name_map = addon_package.name_map if addon_package else {}
    try:
        artifact = ingest(xml_bytes, label, source_type="manual", name_map=name_map)
    except (ValueError, SyntaxError) as exc:
        # Unrecognised root / version-fence rejection / DDR gate / XML syntax error — all raise here and
        # are HARD failures about the bytes, NOT transient. Return an outcome so the pending worker
        # records + drops the record instead of re-parsing it forever (packet 077-A). store_artifact
        # errors below still propagate as transient (a real network/FMS failure → keep + retry).
        return _err(str(exc) or "This file could not be parsed as a FileMaker schema export.")
    # Naming doctrine: PRIMARY = the uploaded filename stem (an explicit intake `name` overrides).
    label = (name or "").strip() or label or _label_from_identity(artifact)
    if land_from:
        from corpusfm.storage.artifact_store import land_artifact
        meta = land_artifact(backend, land_from, artifact, xml_bytes=xml_bytes, label=label,
                             origin=origin, addon_package=addon_package,
                             keep_source_xml=(keep_source_xml or cfg.keep_source_xml))
    else:
        meta = backend.store_artifact(
            artifact, xml_bytes=xml_bytes, label=label, origin=origin,
            addon_package=addon_package,
            keep_source_xml=(keep_source_xml or cfg.keep_source_xml),
        )
    if hasattr(backend, "archive_dir"):
        try:
            from corpusfm.tools.discovery_log import append_discovery
            append_discovery(artifact, backend.archive_dir / "discovery.jsonl")
        except Exception:
            log.debug("discovery_log failed for ‘%s’", label, exc_info=True)
    has_icon = addon_package is not None and bool(addon_package.icon_bytes)
    return IngestOutcome(
        True, artifact=artifact, meta=meta, rel_path=meta.rel_path, uuid=meta.uuid,
        is_addon=meta.is_addon, ran_pipeline=True,
        payload={"ok": True, "name": meta.name, "uuid": meta.uuid, "rel_path": meta.rel_path,
                 "artifact_type": artifact.type.value, "is_clip": False,
                 "is_addon": meta.is_addon, "root_uuid": artifact.identity.root_uuid,
                 "addon_locale": addon_package.addon_locale if addon_package else "",
                 "has_name_map": addon_package is not None and bool(addon_package.name_map),
                 "has_icon": has_icon,
                 "gap_issues": meta.gap_issues, "gap_unmapped": meta.gap_unmapped})


def _reabsorb(raw: bytes, filename: str, name: str, backend) -> IngestOutcome:
    """A previously-downloaded CORPUSfm `.artifact` envelope comes back in: validate + store AS-IS
    (no re-ingest). Handles BOTH kinds — a schema artifact and a deliverable (fmClip/fmScript/fmCalc/
    PatchXML) — mirroring the synchronous commit path (upload.py `_commit_reabsorb_token`) so the QUEUE
    ingest worker lands deliverable `.artifact` envelopes too, not only schema ones (packet 1064)."""
    from corpusfm.ingestion.reabsorb import parse_uploaded_envelope, validate_reabsorb_payload
    incoming = parse_uploaded_envelope(filename, raw)
    if incoming is None:
        return _err("This .artifact file could not be read as a CORPUSfm artifact.")
    ok, reason = validate_reabsorb_payload(incoming)
    if not ok:
        return _err(f"Cannot reabsorb this artifact — {reason}.")

    if incoming.kind == "deliverable":
        label = ((name or "").strip() or incoming.name
                 or primary_name_from_filename(filename) or "clip")
        meta = backend.store_deliverable(
            incoming.raw, artifact_type=incoming.deliverable_type, origin="Reabsorb",
            name=label, description=incoming.description, memory=incoming.memory)
        if incoming.tags:
            try:
                from corpusfm.server.tags import set_record_tags
                set_record_tags(meta.uuid, incoming.tags)
            except Exception:
                pass
        is_clip = incoming.deliverable_type == "fmClip"
        return IngestOutcome(
            True, meta=meta, rel_path=meta.rel_path, uuid=meta.uuid, reabsorbed=True, is_clip=is_clip,
            payload={"ok": True, "reabsorbed": True, "name": meta.name, "uuid": meta.uuid,
                     "rel_path": meta.rel_path,
                     "artifact_type": incoming.deliverable_type, "is_clip": is_clip, "is_addon": False,
                     "root_uuid": getattr(meta, "root_uuid", ""),
                     "gap_issues": 0, "gap_unmapped": []})

    art = incoming.artifact
    label = ((name or "").strip() or incoming.name
             or primary_name_from_filename(filename) or _label_from_identity(art))
    # The addon presentation (icon/version/locale) lands through the SAME jor builder the fresh-addon
    # ingest uses (packet 1254), by handing `store_artifact` a package carrying only those three. The
    # obvious alternative — patching them afterwards through `update_record` — CANNOT work: that method
    # is whitelisted (`key_map` in both backends) and silently drops any key not on the list, so the
    # write would look like it succeeded. `addon_title` is deliberately left empty: `build_record`
    # overrides PrimaryName with it, which would clobber the label resolved above. An empty `name_map`
    # is correct — the NameMapData container does not travel, and resolved names already ride inside
    # the payload.
    addon_presentation = None
    if incoming.icon_b64 or incoming.addon_version or incoming.addon_locale:
        from corpusfm.core.addon.package import AddonPackage
        import base64 as _b64
        try:
            icon_bytes = _b64.b64decode(incoming.icon_b64) if incoming.icon_b64 else b""
        except Exception:
            icon_bytes = b""
        addon_presentation = AddonPackage(xml_bytes=b"", icon_bytes=icon_bytes,
                                          addon_version=incoming.addon_version,
                                          addon_locale=incoming.addon_locale)
    meta = backend.store_artifact(art, label=label, origin="Reabsorb",
                                  addon_package=addon_presentation)
    # store_artifact carries no memory/description — restore the envelope's sidecar; tags are a
    # separate table. Both best-effort (the artifact already landed).
    _restore = {}
    if incoming.description:
        _restore["description"] = incoming.description
    if incoming.memory:
        _restore["memory"] = incoming.memory
    try:
        if _restore:
            backend.update_record(meta.uuid, _restore)
        if incoming.tags:
            from corpusfm.server.tags import set_record_tags
            set_record_tags(meta.uuid, incoming.tags)
    except Exception:
        pass
    is_clip = art.type.value == "fmClip"
    is_addon = art.type.value == "AddonXML"
    return IngestOutcome(
        True, artifact=art, meta=meta, rel_path=meta.rel_path, uuid=meta.uuid, reabsorbed=True,
        is_clip=is_clip, is_addon=is_addon,
        payload={"ok": True, "reabsorbed": True, "name": meta.name, "uuid": meta.uuid,
                 "rel_path": meta.rel_path,
                 "artifact_type": art.type.value, "is_clip": is_clip, "is_addon": is_addon,
                 "root_uuid": art.identity.root_uuid,
                 "gap_issues": 0, "gap_unmapped": []})
