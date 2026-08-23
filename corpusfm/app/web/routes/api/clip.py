"""Clipboard Paste intake (packet 1025) — turn pasted clipboard TEXT into a deliverable artifact.

Formal separation from file Import: `/api/upload` handles FILES (SaveAsXML/addon/.artifact); this
handles clipboard TEXT that becomes a DELIVERABLE text type — fmClip / fmCalc / fmScript.

Recognition, not judgment (see packet 1025 "Validation philosophy"):
  - fmClip acceptance gate = RECOGNITION only (well-formed XML + a clip root). FRAGMENTS are welcome;
    the deep `validate_clip` ladder (block balance / refs / calc parse) is ADVISORY, never a block.
  - fmCalc / fmScript = opaque text, stored as-is (no gate — a bare `{}` is a valid calc).
  - Only fmClip is auto-detectable (it's XML with a known root); non-XML text is USER-picked.
  - Files (SaveAsXML/addon/FMPReport) are REJECTED here with a pointer to Import.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from corpusfm.app.web.auth import require_auth

router = APIRouter()

_TEXT_TYPES = {"fmCalc", "fmScript"}
_ALL_TYPES = {"fmClip"} | _TEXT_TYPES

# A clip is text — a few MB at most. Bound it: there is no global body-size middleware, so (like
# /api/upload) each route caps itself, else a large paste reads unbounded RAM and CPU-parses it all.
_MAX_PASTE_BYTES = 8 * 1024 * 1024


def _oversized(request: Request) -> bool:
    """Content-Length pre-check (best-effort — the header may be absent)."""
    try:
        return int(request.headers.get("content-length") or 0) > _MAX_PASTE_BYTES
    except (TypeError, ValueError):
        return False


def _too_big(text: str) -> bool:
    return len((text or "").encode("utf-8", "ignore")) > _MAX_PASTE_BYTES

# File formats that belong to the Import tool, not Paste — {head-marker: (label, redirect)}.
_FILE_MARKERS = [
    ("<FMSaveAsXML", "a schema XML file (SaveAsXML)"),
    ("<FMAdd_on", "an FM add-on package"),
    ("<FMPReport", "a Database Design Report (FMPReport)"),
]


# Top-level clip OBJECT tags → their human kind. Only DEFINITIONS (direct children of the snippet /
# inside Group folders) count; step-internal <Script>/<Field>/<Layout> references are never reached
# because the walk descends only into <Group>, not into <Step>.
_OBJ_KIND = {
    "Script": "Script", "Field": "Field", "BaseTable": "Table", "Table": "Table",
    "ValueList": "Value List", "CustomFunction": "Custom Function", "Layout": "Layout",
    "CustomMenuSet": "Custom Menu",
}


def _fmclip_descriptor(text: str) -> str:
    """A STRUCTURAL descriptor for a clip — never trusts comment text (comments are optional/freeform;
    the XML structure is the reliable signal). Returns e.g. 'UMA.APP.Features.Goto', '3 Scripts',
    '3 Objects', '7 Script Steps'."""
    from corpusfm.core import safe_xml as ET
    from corpusfm.ingestion.clip import _strip_xml_decl
    try:
        root = ET.fromstring(_strip_xml_decl((text or "").strip()))
    except Exception:
        return "Clip"
    if root.tag == "FMObjectTransfer":
        return "Custom Menu"
    objs, steps = [], []

    def _walk(el):
        for c in el:
            if c.tag == "Group":
                _walk(c)                       # descend folder trees (foldered clips)
            elif c.tag in _OBJ_KIND:
                objs.append(c)                 # a defined object
            elif c.tag == "Step":
                steps.append(c)                # a bare script step (XMSS)
    _walk(root)

    if objs:
        if len(objs) == 1:
            nm = (objs[0].get("name") or "").strip()
            return nm or ("1 " + _OBJ_KIND[objs[0].tag])
        kinds = {_OBJ_KIND[o.tag] for o in objs}
        if len(kinds) == 1:
            return f"{len(objs)} {next(iter(kinds))}s"     # '3 Scripts', '5 Fields', '2 Value Lists'
        return f"{len(objs)} Objects"
    if steps:
        n = len(steps)
        return f"{n} Script Step" + ("" if n == 1 else "s")
    return "Clip"


def suggest_clip_name(text: str, artifact_type: str) -> str:
    """A findable, always-generatable name (never required, always editable). Type prefix kept on
    purpose — it's naming fodder + a convention, and self-describing wherever the name travels alone
    (MCP list_artifacts, search hits, git export)."""
    if artifact_type == "fmCalc":
        return "fmCalc: Untitled Calc"
    if artifact_type == "fmScript":
        return "fmScript: Untitled Script"
    return "fmClip: " + _fmclip_descriptor(text)


def _looks_like_fmscript(text: str) -> bool:
    """Weak heuristic for the fmCalc-vs-fmScript PRE-FILL only (never a gate): several lines shaped
    like `StepName [ … ]`. fmscript.org has no parser here, so this is a suggestion, not a verdict."""
    import re
    lines = [ln for ln in text.splitlines() if ln.strip()]
    steps = sum(1 for ln in lines if re.match(r"^\s*[A-Z][A-Za-z0-9 /?&]*\[", ln))
    return steps >= 2 and steps >= len(lines) // 2


def classify_paste(text: str) -> dict:
    """Classify pasted text → {kind, ...}. kind ∈ {fmClip, file, text, empty}.

    fmClip carries object_class/fm_class + an advisory (well_formed/blocks_balanced/reference_count).
    file carries a redirect message (→ Import). text carries a suggested type (user confirms)."""
    from corpusfm.ingestion.clip import classify_clip
    from corpusfm.core.clip_validate import validate_clip

    s = (text or "").strip()
    if not s:
        return {"kind": "empty"}
    head = s[:1024]

    # fmClip — fmxmlsnippet FMObjectList (the common case) OR FMObjectTransfer (custom menus).
    if ("<fmxmlsnippet" in head and "FMObjectList" in head):
        res = validate_clip(s)
        info = classify_clip(s) or {}
        return {
            "kind": "fmClip",
            "type": "fmClip",
            "object_class": info.get("kind") or "clip",
            "fm_class": info.get("fm_class") or "",
            "suggested_name": suggest_clip_name(s, "fmClip"),
            "advisory": {
                "well_formed": res.well_formed,
                "blocks_balanced": res.blocks_balanced,
                "block_errors": res.block_errors[:20],
                "reference_count": len(res.references),
            },
        }
    if "<FMObjectTransfer" in head:
        return {"kind": "fmClip", "type": "fmClip", "object_class": "custom menu",
                "fm_class": "", "note": "menu clip (limited analysis)",
                "suggested_name": "fmClip: Custom Menu",
                "advisory": {"well_formed": True, "blocks_balanced": True,
                             "block_errors": [], "reference_count": 0}}

    # Files → Import (defensively caught even though these rarely arrive as pasted text).
    for marker, label in _FILE_MARKERS:
        if marker in head:
            return {"kind": "file", "detected": label,
                    "message": f"That looks like {label} — use Import for files."}

    # Non-XML text → user picks fmCalc / fmScript (opaque text; no reliable auto-detect).
    suggest = "fmScript" if _looks_like_fmscript(s) else "fmCalc"
    return {"kind": "text", "type": None, "suggest": suggest,
            "suggested_name": suggest_clip_name(s, suggest)}


@router.post("/clip/inspect", dependencies=[Depends(require_auth)])
async def clip_inspect(request: Request) -> JSONResponse:
    """Classify pasted text for the Paste pop-over. Body: {text}. Returns the classify_paste dict.

    classify_paste runs a full XML + per-calc formula parse, so it is offloaded to a thread (never the
    event loop) and size-capped — the global @paste handler fires this with the WHOLE clipboard."""
    if _oversized(request):
        return JSONResponse({"kind": "text", "type": None, "suggest": None,
                             "error": "Clipboard too large to inspect."}, status_code=413)
    body = await request.json()
    text = body.get("text", "")
    if _too_big(text):
        return JSONResponse({"kind": "text", "type": None, "suggest": None,
                             "error": "Clipboard too large to inspect."}, status_code=413)
    return JSONResponse(await run_in_threadpool(classify_paste, text))


def _store_paste(text: str, artifact_type: str, name: str, tags: list) -> dict:
    """Blocking: recognize (fmClip only), store as a deliverable, apply tags. Returns {ok,uuid,type,error}."""
    from corpusfm.storage import get_backend
    from corpusfm.server import queue_handlers

    cls = classify_paste(text)
    if cls["kind"] == "file":
        return {"ok": False, "error": cls["message"]}

    if artifact_type == "fmClip":
        # RECOGNITION gate (fragments pass — this only proves it IS a clip and will render/round-trip).
        if cls["kind"] != "fmClip":
            return {"ok": False, "error": "Not a recognizable FileMaker clip — pick fmCalc/fmScript to "
                                          "store it as text, or fix the clip XML."}
        if "<fmxmlsnippet" in text:
            from corpusfm.ingestion.clip import extract_clip_xml
            try:
                payload = extract_clip_xml(text)          # well-formed + fmxmlsnippet + FMObjectList
            except ValueError as exc:
                return {"ok": False, "error": f"Not a valid clip — {exc}"}
        else:  # FMObjectTransfer (menu) — store as-is with a declaration
            payload = text if text.lstrip().startswith("<?xml") \
                else '<?xml version="1.0" encoding="UTF-8"?>\n' + text.strip()
        raw = payload.encode("utf-8")
    else:  # fmCalc / fmScript — opaque text, no gate
        t = (text or "").strip()
        if not t:
            return {"ok": False, "error": f"Empty {artifact_type} — nothing to store."}
        raw = t.encode("utf-8")

    nm = (name or "").strip() or suggest_clip_name(text, artifact_type)   # never a bare type name
    nm = (nm[:80] + "…") if len(nm) > 80 else nm
    backend = get_backend()
    # A paste lands in <1s; cap the wait at 20s (not the 120s default) so a wedged/dead land worker
    # under a paste burst can't pin threadpool threads for two minutes each (packet 1000 Phase-2).
    res = queue_handlers.enqueue_deliverable_and_wait(
        backend, raw, artifact_type=artifact_type, origin="paste",
        name=nm, description=f"pasted {artifact_type}: {nm}", timeout=20.0)
    if res["status"] == "failed":
        return {"ok": False, "error": res["error"]}

    uuid = res["uuid"]
    clean_tags = [t.strip() for t in (tags or []) if isinstance(t, str) and t.strip()]
    if clean_tags:
        try:
            from corpusfm.server.tags_store import set_artifact_tags
            set_artifact_tags(backend, uuid, clean_tags)
        except Exception:
            pass  # tagging is best-effort — the artifact is already stored
    return {"ok": True, "uuid": uuid, "type": artifact_type, "status": res["status"]}


@router.post("/clip/paste", dependencies=[Depends(require_auth)])
async def clip_paste(request: Request) -> JSONResponse:
    """Store pasted clipboard text as a deliverable artifact.

    Body: {text, type ∈ {fmClip,fmCalc,fmScript}, name?, tags?[], index?}. Index is handled by the
    caller via /api/indexed/index-batch on the returned uuid (reuses the existing embedder gate)."""
    if _oversized(request):
        return JSONResponse({"ok": False, "error": "Paste too large."}, status_code=413)
    body = await request.json()
    text = body.get("text", "")
    artifact_type = (body.get("type") or "").strip()
    if artifact_type not in _ALL_TYPES:
        return JSONResponse({"ok": False, "error": "type must be one of fmClip, fmCalc, fmScript."},
                            status_code=400)
    if not (text or "").strip():
        return JSONResponse({"ok": False, "error": "Nothing to paste."}, status_code=400)
    if _too_big(text):
        return JSONResponse({"ok": False, "error": "Paste too large."}, status_code=413)

    out = await run_in_threadpool(_store_paste, text, artifact_type,
                                  body.get("name", ""), body.get("tags") or [])
    return JSONResponse(out, status_code=200 if out.get("ok") else 400)
