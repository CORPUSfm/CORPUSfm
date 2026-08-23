"""Upload API — POST /api/upload"""

from __future__ import annotations

import functools
import logging
from typing import Optional

import anyio
from fastapi import APIRouter, Depends, Form, Request, UploadFile, File
from fastapi.responses import JSONResponse

from fastapi import HTTPException
from corpusfm.app.web.auth import require_auth, require_gate, require_upload_auth
from corpusfm.core.filenames import primary_name_from_filename

log = logging.getLogger("corpusfm.upload")
router = APIRouter()

# Upload DoS ceiling: a HARD, fixed 1 GB bound (NOT a tunable setting, no soft limit) that refuses a
# runaway or abusive body. It is justified as a CEILING and deliberately makes NO claim about how large
# a real export is — the product cannot know a customer's schema (packet 1203; the Unknowable-Install
# Principle one layer below the network). The retired assumption and the measurement that killed it are
# in the packet, not here.
#
# NOTE: `/upload` reads EVERY type into memory, `.fmaddon` included; only `/upload/inspect` streams an
# addon to a temp file. A parse-time / XML-entity-expansion limit is separate, parser-level hardening
# (defusedxml / expat limits).
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024

# ── Keep ingestion off the event loop ───────────────────────────────────────────────
# The web app runs on a SINGLE uvicorn worker = one event loop. Ingestion's heavy work — the
# XML/XAR parse, building the artifact, the FM/OData store, vector indexing, and the addon git-push —
# is CPU-bound or blocking I/O. Running it inline in an `async def` route blocks the loop for the
# whole ingest, so every other request (the docs page, navigation, polls) queues behind a large DDR
# parse. `_offload` moves each heavy step to a worker thread so the loop stays responsive.
#
# `_INGEST_LIMITER` bounds CONCURRENT heavy ingests (each holds a size-capped payload in memory and
# can saturate a core) so the offload can't become a CPU/memory-exhaustion vector. It does NOT change
# any security control: the XML hardening (`safe_xml`/defusedxml), the hard size cap (`_read_capped`/
# 413), and auth all run unchanged — the offload only changes WHICH thread runs the already-hardened
# code. Concurrency on this path is now genuinely possible (it serialized on the loop before): `ingest`
# is a pure function, and `store_artifact` writes per-artifact records, so the steps are independent.
_INGEST_LIMITER = anyio.CapacityLimiter(3)

# ── How many upload BODIES may exist in memory at once (packet 1203) ─────────────────────────────────
# `_INGEST_LIMITER` above bounds the offloaded CPU work; it does NOT bound this, because `_read_capped`
# runs on the event loop BEFORE the first `_offload`. N concurrent uploads therefore held N bodies no
# matter what that limiter said — tuning it changed peak memory not at all.
#
# The bound must cover the whole read→ingest span, because the ingest is handed the same bytes: releasing
# after the read would bound nothing. MEASURED 2026-07-27: a real customer export is 220.8 MB, not the
# size this repo had assumed, so three concurrent ORDINARY imports approached ~660 MB resident on the
# box that is also running FileMaker Server.
#
# ONE is deliberate. Uploads are human-initiated and infrequent; the event loop stays responsive
# regardless because the heavy work is still offloaded (packet 078) — what serialises here is only the
# body-holding span. A second uploader waits instead of adding another whole file to memory. Raising it
# is one edit, and each unit costs one more full body.
MAX_CONCURRENT_UPLOAD_BODIES = 1
_BODY_LIMITER = anyio.CapacityLimiter(MAX_CONCURRENT_UPLOAD_BODIES)


async def _offload(func, /, *args, **kwargs):
    """Run a blocking/CPU-bound ingest step in a worker thread, bounded by `_INGEST_LIMITER`."""
    return await anyio.to_thread.run_sync(functools.partial(func, *args, **kwargs),
                                          limiter=_INGEST_LIMITER)


def _reject_if_oversized(request: Request) -> None:
    """Fast pre-read reject on the declared body size (the per-read cap below is the real guard)."""
    clen = request.headers.get("content-length", "")
    if clen.isdigit() and int(clen) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")


async def _read_capped(upload: UploadFile) -> bytes:
    """Read an UploadFile fully into memory, aborting at MAX_UPLOAD_BYTES (a lying/absent
    Content-Length can't bypass the limit)."""
    out = bytearray()
    while True:
        chunk = await upload.read(4 * 1024 * 1024)
        if not chunk:
            break
        out += chunk
        if len(out) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413,
                                detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")
    return bytes(out)


def _label_from_identity(artifact) -> str:
    """Sanitized artifact label derived from the schema's own file name.

    The schema XML carries the source file in its root File= attribute, which the
    pipeline parses into identity.file_name (kept verbatim, WITH the .fmp12 suffix —
    the suffix is part of the file name and is never hidden). Preferring it over the
    upload filename means a pushed Cfm_<ts>.xml is labeled by the real DB name. FM
    file names can contain unsafe characters, so sanitize. Returns "" when no usable
    name is present (e.g. fmClip fragments carry no File=), leaving the caller to
    fall back to the upload filename.
    """
    raw = getattr(getattr(artifact, "identity", None), "file_name", "") or ""
    return "".join(c if c.isalnum() or c in " ._-" else "_" for c in raw).strip(" ._-")


def _sniff_xml_head(head: bytes) -> tuple[str, str]:
    """Sniff (type, internal_name) from the head bytes of an .xml file.

    type ∈ {SaveAsXML, AddonXML, FMPReport, fmClip}; internal_name is the
    SaveAsXML File= attribute (else "" when underivable — clip / no File=).
    """
    import re
    from corpusfm.ingestion.clip import detect_clip

    if detect_clip(head):
        return "fmClip", ""
    if b"<FMAdd_on" in head[:1024]:
        return "AddonXML", ""
    if b"<FMPReport" in head[:1024]:
        return "FMPReport", ""
    # SaveAsXML — pull the root File= attribute (.fmp12-stripped) from the head.
    try:
        text = head.decode("utf-16", errors="ignore") if head[:2] in (b"\xff\xfe", b"\xfe\xff") \
            else head.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    m = re.search(r'File="([^"]*)"', text)
    name = (m.group(1) if m else "").strip()
    if name.lower().endswith(".fmp12"):
        name = name[: -len(".fmp12")]
    return "SaveAsXML", name


@router.post("/upload/inspect",
             dependencies=[Depends(require_auth), Depends(require_gate("library_mcp"))])
async def upload_inspect(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    """Pre-scan a file head to drive intake defaults: returns {type, internal_name}.

    For .xml, sniffs the root File= attr (SaveAsXML) / FMAdd_on / FMPReport / clip.
    For .fmaddon, does a metadata-only XAR read (info.json) for the addon's title —
    template.xml and records are never parsed. internal_name is "" when underivable.
    """
    _reject_if_oversized(request)
    filename = (file.filename or "").lower()
    try:
        # Routed on the NAME here, because the branch has to be chosen before the body is read
        # (the size limiter owns the read). `.zip` is the current download name and `.artifact` the
        # historical one; `parse_uploaded_envelope` below is the actual authority and rejects a zip
        # that is not an envelope.
        if filename.endswith((".artifact", ".zip")):
            # Reabsorb intake (single-upload model): read + validate the WHOLE .artifact server-side,
            # then STAGE the validated bytes locally under a token. NO DB WRITE here — the commit
            # (token-based) does the one and only store. No dedup (packet 085): duplicates land
            # and are surfaced in the Related tab, never prevented.
            from corpusfm.app.web import _reabsorb_staging as staging
            from corpusfm.ingestion.reabsorb import parse_uploaded_envelope, validate_reabsorb_payload
            # packet 1203: held until `raw` is no longer needed — releasing at the parse would bound
            # nothing, since the bytes stay resident all the way through `staging.stage`.
            async with _BODY_LIMITER:                  # a `.artifact` is a body too
                raw = await _read_capped(file)
                incoming = parse_uploaded_envelope(file.filename or filename, raw)
                if incoming is None:
                    return JSONResponse(
                        {"type": "", "internal_name": "", "reabsorb": True,
                         "error": "This file could not be read as a CORPUSfm artifact. "
                                  "Reabsorb takes the .zip that Download produces."})
                ok, reason = validate_reabsorb_payload(incoming)
                if not ok:
                    return JSONResponse(
                        {"type": "", "internal_name": "", "reabsorb": True,
                         "error": f"Cannot reabsorb this artifact — {reason}."})
                # TTL-sweep abandoned tokens opportunistically (inspected but never committed/cancelled).
                await _offload(staging.sweep, staging.STAGING_TTL_SECONDS)
                token = await _offload(staging.stage, raw)
            if incoming.kind == "schema":
                _type, _internal = incoming.artifact.type.value, _label_from_identity(incoming.artifact)
            else:
                _type, _internal = incoming.deliverable_type, incoming.name
            return JSONResponse({
                "type": _type,
                "internal_name": _internal,
                "primary_name": incoming.name or primary_name_from_filename(file.filename or filename),
                "reabsorb": True,
                "token": token,
            })
        if filename.endswith(".fmaddon"):
            import tempfile, os as _os
            from corpusfm.core.addon.package import inspect_addon_xar
            from pathlib import Path
            tmp_fd, tmp_path = tempfile.mkstemp(suffix=".fmaddon")
            try:
                _os.close(tmp_fd)
                _total = 0
                with open(tmp_path, "wb") as fout:
                    while True:
                        chunk = await file.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        _total += len(chunk)
                        if _total > MAX_UPLOAD_BYTES:
                            raise HTTPException(status_code=413, detail="Upload too large")
                        fout.write(chunk)
                title, _guid = await _offload(inspect_addon_xar, Path(tmp_path))
            finally:
                _os.unlink(tmp_path)
            return JSONResponse({"type": "AddonXML", "internal_name": title or ""})
        if filename.endswith(".xml"):
            head = await file.read(8192)
            art_type, name = _sniff_xml_head(head)
            return JSONResponse({"type": art_type, "internal_name": name})
        return JSONResponse({"type": "", "internal_name": ""})
    except Exception:
        return JSONResponse({"type": "", "internal_name": ""})


@router.post("/upload")
async def upload_xml(
    request: Request,
    file: UploadFile = File(None),
    locale: str = Form(""),
    name: str = Form(""),
    token: str = Form(""),
    _push_queue_id: Optional[str] = Depends(require_upload_auth),
) -> JSONResponse:
    _reject_if_oversized(request)   # before the try so the 413 isn't reshaped into a 400
    # Bearer fms_push (packet 1015 / 1142): require_upload_auth resolved the one-time token to the
    # ACQUIRING run record (still on its `acquire` step, held by the acquire worker blocking on the FM
    # trigger). Instead of ingesting inline, DEPOSIT the posted DDR into that record and RETURN — the
    # acquire step, still blocking on the same record, reads its trigger verdict and OWNS the transition
    # to `ingest` (packet 1142 §E: /api/upload deposits only; one party moves the record — the one that
    # owns the step). This makes failure honest: if the POST lands and the script then errors, acquire
    # sees the error WITH bytes in hand and can decide, instead of the arrival racing the transition.
    if _push_queue_id is not None:
        if file is None:
            return JSONResponse({"ok": False, "error": "No file provided."}, status_code=400)
        async with _BODY_LIMITER:                      # packet 1203 — same bound, same reason
            raw = await _read_capped(file)
            result = await _offload(_stage_push_into_queue, _push_queue_id, raw)
        return JSONResponse(result, status_code=result.pop("status", 200))
    # Reabsorb commit (single-upload model): the validated `.artifact` was already uploaded +
    # staged at inspect; the commit carries only its token (no re-upload). This is the one and
    # only DB write for reabsorb. Kept separate from the file paths so the existing branches are
    # untouched. The direct `.artifact` upload branch below stays as the non-staged/API fallback.
    if token.strip():
        return await _commit_reabsorb_token(token.strip(), name)
    if file is None:
        return JSONResponse({"ok": False, "error": "No file provided."}, status_code=400)
    try:
        from corpusfm.storage import get_backend
        from corpusfm.app.app_config import load_app_config, system_locale_code, FM_ADDON_LOCALES
        from corpusfm.app.web._import_ingest import ingest_import_bytes

        filename = file.filename or "unknown"
        cfg = load_app_config()
        backend = get_backend()
        # Locale precedence: explicit per-import pick → the importing user's personal pref →
        # the app default → the system locale. (Addon name resolution is interactive-only.)
        from corpusfm.app.web.auth import current_user
        _u = current_user(request)
        _user_loc = (_u.prefs.get("addon_locale") if _u else "") or ""
        _req = locale.strip().lower()
        addon_locale = (_req if _req in FM_ADDON_LOCALES
                        else (_user_loc or cfg.preferred_addon_locale or system_locale_code()))

        # Read the whole file off the wire (capped), then route+ingest it in one offloaded step so the
        # single event loop stays free (the type routing, XML/XAR parse, store, and tagging are shared
        # with the import queue in `_import_ingest.ingest_import_bytes`). Enrichment stays decoupled
        # (packet 050): import returns fast; AI summaries / indexing run on the enrich queue, kicked off
        # explicitly from the catalog or (packet 055) as an import-option follow-on.
        # packet 1203: the bound is taken BEFORE the read and held across the ingest, because the ingest
        # is handed the same bytes. Note this path reads EVERY type into memory, `.fmaddon` included —
        # only `/upload/inspect` streams an addon to a temp file.
        async with _BODY_LIMITER:
            raw = await _read_capped(file)
            # A human interactive upload is the WebUI channel (packet 1169); a .artifact reabsorb ignores
            # this and stamps "Reabsorb" internally. The bearer fms_push path returned above (it becomes a
            # Job run via its acquire step), so this call is only ever the browser upload.
            outcome = await _offload(ingest_import_bytes, raw, filename,
                                     name=name, locale=addon_locale, backend=backend, cfg=cfg,
                                     origin="WebUI")
        if not outcome.ok:
            return JSONResponse(outcome.payload, status_code=outcome.status)
        return JSONResponse(outcome.payload)
    except HTTPException:
        raise   # preserve the 413 (size cap) / 401 / 403 rather than reshaping to a 400
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)


def _stage_push_into_queue(queue_id: str, raw: bytes) -> dict:
    """DEPOSIT a resolved fms_push into its ACQUIRING run record and return (packet 1142 §E — the
    acquire step, still blocking on the FM trigger, owns the transition to ingest; /api/upload never
    advances the record). Sync/blocking (FM blob write) — call under ``_offload``. The one-time bearer
    token that resolved this record IS the isolation (single-use, keyed to this exact run); there is no
    source-IP policy. Returns a JSON body dict with a ``status`` key the route pops for the HTTP status."""
    from corpusfm.core.crypto import compress, encode_blob
    from corpusfm.storage import get_backend
    from corpusfm.storage import queue_record as Q
    from corpusfm.storage.repos import queue_repo

    backend = get_backend()
    repo = queue_repo(backend)
    row = repo.get(queue_id) if repo is not None else None
    # The record was resolvable at auth time; a race (used/advanced/failed) must not create a stray. The
    # acquiring record sits on `acquire` (held by the acquire worker) until IT advances to ingest.
    if row is None or Q.is_failed(row.jor) or row.jor.get("Type") != Q.ACQUIRE:
        return {"ok": False, "status": 409, "error": "This push is no longer awaiting an upload."}

    backend.engine.blob_put("QUEUE", queue_id, "SourceXML",
                            encode_blob(compress(raw), encrypt_on=backend._encrypt_blobs()))
    # Do NOT advance or poke — the acquire step, blocking on the trigger call, reads its verdict and
    # advances acquire→ingest itself (one party moves the record: the one that owns the step).
    return {"ok": True, "queued": True, "id": queue_id, "status": 200}


async def _commit_reabsorb_token(token: str, name: str) -> JSONResponse:
    """Commit a previously-staged `.artifact` by token: read the staged local file → store →
    delete the staged file. The one and only DB write for reabsorb (no re-upload)."""
    from corpusfm.storage import get_backend
    from corpusfm.app.web import _reabsorb_staging as staging
    from corpusfm.ingestion.reabsorb import parse_uploaded_envelope, validate_reabsorb_payload
    from corpusfm.server.tags import set_record_tags
    raw = await _offload(staging.read, token)
    if raw is None:
        return JSONResponse({"ok": False, "error": (
            "This import expired or was already committed — re-add the .artifact file."
        )}, status_code=400)
    try:
        incoming = parse_uploaded_envelope(f"{token}.artifact", raw)
        if incoming is None:
            await _offload(staging.discard, token)
            return JSONResponse({"ok": False, "error": (
                "The staged file could not be read as a CORPUSfm artifact."
            )}, status_code=400)
        ok, reason = validate_reabsorb_payload(incoming)
        if not ok:
            await _offload(staging.discard, token)
            return JSONResponse({"ok": False, "error": f"Cannot reabsorb this artifact — {reason}."},
                                status_code=400)
        backend = get_backend()
        # Naming doctrine: PRIMARY = the edited intake name (the filename stem prefilled it at
        # inspect), else the envelope's own meta.json name, else the identity/legacy fallback.
        if incoming.kind == "deliverable":
            # A deliverable rides the same portable envelope (packet 1034): store_deliverable takes
            # its memory/description directly; tags are a separate normalized table (restore after).
            label = (name or "").strip() or incoming.name or "clip"
            meta = await _offload(backend.store_deliverable, incoming.raw,
                                  artifact_type=incoming.deliverable_type, origin="Reabsorb",
                                  name=label, description=incoming.description, memory=incoming.memory)
            # Tags live in a separate table — restore best-effort (the record already landed).
            if incoming.tags:
                try:
                    await _offload(set_record_tags, meta.uuid, incoming.tags)
                except Exception:
                    pass
            await _offload(staging.discard, token)
            return JSONResponse({"ok": True, "reabsorbed": True, "name": meta.name, "uuid": meta.uuid,
                                 "artifact_type": incoming.deliverable_type,
                                 "is_clip": incoming.deliverable_type == "fmClip",
                                 "is_addon": False, "root_uuid": getattr(meta, "root_uuid", ""),
                                 "gap_issues": 0, "gap_unmapped": []})
        art = incoming.artifact
        label = (name or "").strip() or incoming.name or _label_from_identity(art)
        meta = await _offload(backend.store_artifact, art, label=label, origin="Reabsorb")
        # store_artifact doesn't take memory/description — restore the envelope's via update_record;
        # tags are a separate table. Both best-effort (the artifact already landed).
        _restore = {}
        if incoming.description:
            _restore["description"] = incoming.description
        if incoming.memory:
            _restore["memory"] = incoming.memory
        try:
            if _restore:
                await _offload(backend.update_record, meta.uuid, _restore)
            if incoming.tags:
                await _offload(set_record_tags, meta.uuid, incoming.tags)
        except Exception:
            pass
        await _offload(staging.discard, token)
        return JSONResponse({"ok": True, "reabsorbed": True, "name": meta.name,
                             "uuid": meta.uuid,
                             "artifact_type": art.type.value,
                             "is_clip": art.type.value == "fmClip",
                             "is_addon": art.type.value == "AddonXML",
                             "root_uuid": art.identity.root_uuid,
                             "gap_issues": 0, "gap_unmapped": []})
    except Exception as exc:
        await _offload(staging.discard, token)
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)

