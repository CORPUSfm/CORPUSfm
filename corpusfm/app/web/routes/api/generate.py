"""Background HTML generation tasks — Explorer and Diff.

POST /api/generate/explorer  { artifact_path: str }
POST /api/generate/diff      { artifact_a: str, artifact_b: str }
GET  /api/generate/status/{task_id}

Standalone: opens the generated file in the system browser server-side (same machine).
Server mode: returns a /api/preview/{task_id} URL for the client to open in a new tab.
"""

from __future__ import annotations

import concurrent.futures
import multiprocessing
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse

from corpusfm.runtime import build_context
from corpusfm.app.web.auth import require_auth, require_gate, require_any_gate
from corpusfm.generation_jobs import explorer_job, diff_job, patch_job
from corpusfm.server import activity_contract

router = APIRouter()

# Per-route gates (mixed router): Explorer/Diff generation are Artifacts-page (library_mcp);
# patch generation/preflight/confirm/result are the ISV page (patching). The shared task
# status/preview polling is reachable from either flow → require_any_gate.
_LIBRARY = [Depends(require_auth), Depends(require_gate("library_mcp"))]
_PATCHING = [Depends(require_auth), Depends(require_gate("patching"))]
_LIBRARY_OR_PATCHING = [Depends(require_auth), Depends(require_any_gate("library_mcp", "patching"))]

# In-memory task store: {task_id: {status, result_path, error}}
_tasks: dict[str, dict[str, Any]] = {}
_tasks_lock = threading.Lock()


def _resolve_refs(refs: list) -> "tuple[list, JSONResponse | None]":
    """Resolve each artifact ref (record UUID or human alias, packet 085 U3f) to a UUID; ('' entries
    dropped). Returns (uuids, error) — error is a 404/409 JSONResponse if any ref won't resolve."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    backend = get_backend()
    out: list = []
    for r in refs:
        if not r:
            continue
        u, err = resolve_ref(backend, r)
        if err is not None:
            return [], err
        out.append(u)
    return out, None


def _syntax_palette_selection(request: Request) -> dict[str, str | int]:
    """Resolve once in the request process; workers receive only the two validated ids."""
    from corpusfm.app.web.auth import current_user
    from corpusfm.extensions.export.syntax_palettes import resolve_selection
    user = current_user(request)
    if user is not None:
        prefs = user.prefs
    else:
        from corpusfm.app.web.appearance_preferences import load
        prefs = load()
    return resolve_selection(prefs).as_dict()


def _new_task(kind: str = "generate", target: str = "") -> str:
    """Register a fresh ephemeral generation task. Alongside the generation bookkeeping (status /
    result), each task now carries the activity-record contract fields (packet 1136 Stage 1): a
    monotonic ``progress`` token + UTC ``created_at``/``updated_at`` that advance ONLY on a real state
    change (never on a poll — observation is not progress), and a ``finished_at`` MONOTONIC stamp that
    drives terminal retention in the unified activity feed."""
    tid = uuid.uuid4().hex
    now = activity_contract.utcnow_iso()
    with _tasks_lock:
        _tasks[tid] = {"status": "pending", "result_path": None, "error": None, "rel_path": None,
                       "kind": kind, "target": target, "progress": 0,
                       "created_at": now, "updated_at": now, "finished_at": None}
    return tid


def _finish_task(tid: str, path: Path | None, error: str | None) -> None:
    import time
    with _tasks_lock:
        if tid in _tasks:
            t = _tasks[tid]
            t["status"] = "done" if path else "error"
            t["result_path"] = str(path) if path else None
            t["error"] = error
            t["progress"] = int(t.get("progress", 0)) + 1        # a REAL transition — bump the token
            t["updated_at"] = activity_contract.utcnow_iso()      # updated_at == last progress change
            t["finished_at"] = time.monotonic()                   # retention clock (monotonic, wall-safe)


# ── Ephemeral activity snapshot (packet 1136 Stage 1) ─────────────────────────────
# Explorer/Diff renders are the contract kind "generate"; the ISV patch preflight/confirm flow is
# "patch-task". Ephemeral pending → contract "queued" (a submitted render is in-flight but reports no
# sub-progress — the Stage-0 mapping); done → "done"; error → "failed".
_EPHEMERAL_KIND = {"generate": "generate", "preview": "preview", "patch-task": "patch-task"}
_EPHEMERAL_STATUS = {"pending": "queued", "done": "done", "error": "failed"}


def ephemeral_activity_snapshot(now_monotonic: "float | None" = None) -> "list[dict]":
    """A PURE read of the in-memory generation registry as activity-contract records (packet 1136
    Stage 1). A terminal task stays in the snapshot for ``TERMINAL_RETENTION_SECONDS`` after it
    finished, then drops out — VIEW-ONLY pruning: the underlying ``_tasks`` entry is KEPT so an
    already-open preview tab can still be served. Reads only; it never writes task state, so a failed
    observation of any OTHER source can never false-finish these (pin #1)."""
    import time
    now = time.monotonic() if now_monotonic is None else now_monotonic
    out: "list[dict]" = []
    with _tasks_lock:
        for tid, t in _tasks.items():
            fin = t.get("finished_at")
            if fin is not None and (now - fin) > activity_contract.TERMINAL_RETENTION_SECONDS:
                continue      # terminal + past retention → stop advertising (the entry itself is kept)
            out.append({
                "id": tid,
                "kinds": [_EPHEMERAL_KIND.get(t.get("kind", "generate"), "generate")],
                "status": _EPHEMERAL_STATUS.get(t.get("status", "pending"), "queued"),
                "progress": int(t.get("progress", 0)),
                "created_at": t.get("created_at", "") or activity_contract.utcnow_iso(),
                "updated_at": (t.get("updated_at", "") or t.get("created_at", "")
                               or activity_contract.utcnow_iso()),
                "cancelable": False,          # a pool render has no clean cancel checkpoint
                "cancel_route": None,
                "target": t.get("target", "") or "",
                "error": t.get("error") or "",
                "ephemeral": True,
            })
    return out


# ── Generation runs in a separate PROCESS ────────────────────────────────────────
# Explorer/Diff/Patch rendering is CPU-bound pure Python; in a thread it would hold the GIL
# and stall the web process (the Artifacts list, status polling, etc. freeze mid-generation).
# A spawn-based process pool gives each job its own interpreter + GIL + backend session. A
# done-callback (runs in THIS process) writes the result back into _tasks. spawn (not fork) is
# mandatory — forking a live uvicorn event loop + threads is deadlock-prone. The job functions
# live in corpusfm.generation_jobs (lean, never imports the FastAPI app) and return a picklable
# {"path", "error"} dict.
_pool: "concurrent.futures.ProcessPoolExecutor | None" = None
_pool_lock = threading.Lock()


def _max_generation_workers() -> int:
    """Concurrent generation processes, scaled to the box: reserve 2 cores of headroom for the
    co-located FileMaker Server + the web process, and cap so a big/idle box can't spawn a pile
    of heavy (~minutes-of-CPU, hundreds-of-MB) renders at once. 8 cores → 4; 4 → 2; 2 → 1."""
    cores = os.cpu_count() or 4
    return max(1, min(4, cores - 2))


def _get_pool() -> "concurrent.futures.ProcessPoolExecutor":
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = concurrent.futures.ProcessPoolExecutor(
                max_workers=_max_generation_workers(),
                mp_context=multiprocessing.get_context("spawn"))
    return _pool


def _submit(tid: str, job_fn, *args) -> None:
    """Submit a generation job to the process pool; record its result into _tasks when done."""
    def _done(fut) -> None:
        try:
            res = fut.result()
            path, error = res.get("path"), res.get("error")
        except Exception as exc:
            path, error = None, str(exc)
        _finish_task(tid, Path(path) if path else None, error)
        if path and not build_context().is_server:   # standalone: open locally (no-op in server mode)
            try:
                import webbrowser
                webbrowser.open(Path(path).as_uri())
            except Exception:
                pass
    try:
        _get_pool().submit(job_fn, *args).add_done_callback(_done)
    except Exception as exc:
        _finish_task(tid, None, f"Could not start generation: {exc}")



@router.get("/explorer/candidates", dependencies=_LIBRARY)
async def explorer_candidates(request: Request) -> JSONResponse:
    """Return the EXPLORER-capable artifacts as Explorer session candidates.

    Candidate eligibility consults the capability map (packet 040) — only types with the
    `explorer` capability (SaveAsXML / AddonXML / MergedXML) are offered, so a low-fidelity
    tenant (fmClip / fmScript / fmCalc / PatchXML) is never wrongly presented a lens.

    Served from the persistent catalog's TYPE index (packet 1361-01) — this enumerated STORAGE with
    `iter_artifact_metas()` on every dialog open and discarded most of it. A catalog whose database
    read failed says so rather than returning an empty candidate list, which on this dialog reads as
    "you have nothing to explore"."""
    from corpusfm.storage import get_backend
    from corpusfm.server import catalog
    from corpusfm.artifact.capabilities import has_capability, EXPLORER, VISIBLE_TYPES

    backend = get_backend()
    view = catalog.view(backend)
    if view.failed:
        return JSONResponse({"candidates": [], "catalog_failed": True,
                             "unavailable": True, "reason": "storage"})

    items: list[dict] = []
    for art_type in sorted(t for t in VISIBLE_TYPES if has_capability(t, EXPLORER)):
        for rec in view.select(type=art_type):
            meta = rec.get("meta")
            if meta is None:
                continue
            fm_file = meta.file_name
            items.append({
                "uuid":      meta.uuid,        # canonical record address (packet 085 U3f)
                "type":      art_type,
                "label":     (meta.name or fm_file) if meta.is_addon else fm_file,
                "fm_file":   fm_file,
                "timestamp": meta.timestamp,
                "root_uuid": meta.root_uuid,
            })

    return JSONResponse({"candidates": items})


@router.post("/generate/explorer", dependencies=_LIBRARY)
async def start_explorer(request: Request) -> JSONResponse:
    body = await request.json()
    artifact_paths = body.get("artifact_paths") or body.get("snap_paths") or []
    if not artifact_paths:
        single = body.get("artifact_path") or body.get("snap_path", "")
        artifact_paths = [single] if single else []
    if not artifact_paths:
        return JSONResponse({"error": "artifact_path or artifact_paths required"}, status_code=400)
    artifact_paths, err = _resolve_refs(artifact_paths)
    if err is not None:
        return err
    # Record the launch in the Explorer history (convenience trail for quick re-open).
    if body.get("record_history", True):
        try:
            from corpusfm.app.explore_history import record_explore
            record_explore(artifact_paths, body.get("labels") or [])
        except Exception:
            pass
    labels = body.get("labels") or []
    target = ", ".join(l for l in labels if l) or f"Explorer ({len(artifact_paths)})"
    tid = _new_task(kind="generate", target=target)
    _submit(tid, explorer_job, artifact_paths, _syntax_palette_selection(request))
    return JSONResponse({"task_id": tid})


@router.post("/generate/diff", dependencies=_LIBRARY)
async def start_diff(request: Request) -> JSONResponse:
    body = await request.json()
    snap_a = body.get("artifact_a") or body.get("snap_a", "")
    snap_b = body.get("artifact_b") or body.get("snap_b", "")
    record_history = body.get("record_history", True)
    if not snap_a or not snap_b:
        return JSONResponse({"error": "artifact_a and artifact_b required"}, status_code=400)
    (uuids, err) = _resolve_refs([snap_a, snap_b])
    if err is not None:
        return err
    snap_a, snap_b = uuids
    tid = _new_task(kind="generate", target="Diff")
    _submit(tid, diff_job, snap_a, snap_b, record_history, _syntax_palette_selection(request))
    return JSONResponse({"task_id": tid})


@router.post("/generate/patch", dependencies=_PATCHING)
async def start_patch(request: Request) -> JSONResponse:
    body = await request.json()
    snap_a = body.get("artifact_a") or body.get("snap_a", "")
    snap_b = body.get("artifact_b") or body.get("snap_b", "")
    if not snap_a or not snap_b:
        return JSONResponse({"error": "artifact_a and artifact_b required"}, status_code=400)
    (uuids, err) = _resolve_refs([snap_a, snap_b])
    if err is not None:
        return err
    snap_a, snap_b = uuids
    tid = _new_task(kind="patch-task", target="Patch")
    _submit(tid, patch_job, snap_a, snap_b)
    return JSONResponse({"task_id": tid})


@router.post("/generate/patch/preflight", dependencies=_PATCHING)
async def preflight_patch(request: Request) -> JSONResponse:
    """Run patch generation without saving — caches result for confirm."""
    body = await request.json()
    snap_a = body.get("artifact_a") or body.get("snap_a", "")
    snap_b = body.get("artifact_b") or body.get("snap_b", "")
    if not snap_a or not snap_b:
        return JSONResponse({"error": "artifact_a and artifact_b required"}, status_code=400)
    (uuids, err) = _resolve_refs([snap_a, snap_b])
    if err is not None:
        return err
    snap_a, snap_b = uuids
    tid = _new_task(kind="patch-task", target="Patch preflight")
    _submit(tid, patch_job, snap_a, snap_b)
    return JSONResponse({"task_id": tid})


@router.post("/generate/patch/confirm/{task_id}", dependencies=_PATCHING)
async def confirm_patch(task_id: str, request: Request) -> JSONResponse:
    """Persist a completed preflight result as a PatchXML catalog artifact.

    Body (optional): { "inject_export_script": bool }
    When inject_export_script=True and the preflight noted needs_export_script,
    patch generation is re-run with the flag before saving. The patch becomes one
    first-class catalog record (type=PatchXML, origin="Patch (ISV)"); see
    unified-artifacts plan §6. Returns the new artifact's rel_path + the patch XML.
    """
    import json as _json
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    inject_export_script = bool(body.get("inject_export_script", False))

    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    if task["status"] != "done" or not task["result_path"]:
        return JSONResponse({"error": "Preflight not complete"}, status_code=400)
    try:
        with open(task["result_path"]) as f:
            data = _json.load(f)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

    patch_xml = data.get("patch_xml", "")

    # Already saved (and not re-injecting) — return the cached artifact UUID.
    existing_uuid = task.get("rel_path")   # task slot stores the saved artifact's UUID (085 U3f)
    if existing_uuid and not inject_export_script:
        return JSONResponse({"uuid": existing_uuid, "patch_xml": patch_xml, "ok": True})

    from corpusfm.storage import get_backend
    backend = get_backend()

    # Re-run with injection if user opted in and the artifact needs it
    if inject_export_script and data.get("needs_export_script"):
        try:
            from corpusfm.extensions.export.patch_build import generate_patch
            art_a = backend.load_artifact(data["snap_a"])
            art_b = backend.load_artifact(data["snap_b"])
            patch_xml, _coverage_obj = generate_patch(art_a, art_b, inject_export_script=True)
        except Exception as exc:
            return JSONResponse({"error": f"Re-generation failed: {exc}"}, status_code=500)

    name = f"{data.get('label_a', '')} → {data.get('label_b', '')}".strip(" →") or "ISV patch"
    saved = backend.store_deliverable(
        patch_xml.encode("utf-8"),
        artifact_type="PatchXML",
        origin="Patch (ISV)",
        name=name,
    )
    snap_a, snap_b = data.get("snap_a", ""), data.get("snap_b", "")
    from corpusfm.server.history import record_patch
    record_patch(backend, saved.uuid, snap_a, snap_b, label=name)
    with _tasks_lock:
        if task_id in _tasks:
            _tasks[task_id]["rel_path"] = saved.uuid
    return JSONResponse({"uuid": saved.uuid, "patch_xml": patch_xml, "ok": True})


@router.get("/generate/patch/result/{task_id}", dependencies=_PATCHING)
async def patch_result(task_id: str) -> JSONResponse:
    import json as _json
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        return JSONResponse({"error": "Task not found"}, status_code=404)
    if task["status"] == "error":
        return JSONResponse({"error": task["error"]}, status_code=400)
    if task["status"] != "done" or not task["result_path"]:
        return JSONResponse({"error": "Task not complete"}, status_code=400)
    try:
        with open(task["result_path"]) as f:
            data = _json.load(f)
        return JSONResponse(data)
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/generate/status/{task_id}", dependencies=_LIBRARY_OR_PATCHING)
async def task_status(task_id: str, request: Request) -> JSONResponse:
    with _tasks_lock:
        task = _tasks.get(task_id)
    if task is None:
        return JSONResponse({"status": "not_found"}, status_code=404)

    result: dict[str, Any] = {"status": task["status"]}
    if task["status"] == "done" and task["result_path"]:
        # Prefix with root_path so the URL is correct behind a reverse proxy
        # (FMS web server at /corpusfm). window.open() bypasses the client-side
        # fetch wrapper, so the URL must be deployment-correct as returned.
        # At root (root_path == "") this is byte-identical to "/api/preview/...".
        prefix = request.scope.get("root_path", "")
        result["preview_url"] = f"{prefix}/api/preview/{task_id}"
        if not build_context().is_server:
            result["file_uri"] = Path(task["result_path"]).as_uri()
    if task["status"] == "error":
        result["error"] = task["error"]
    return JSONResponse(result)


@router.get("/preview/{task_id}", dependencies=_LIBRARY_OR_PATCHING)
async def preview(task_id: str):
    """Serve generated HTML in server mode — opens in client's browser tab."""
    with _tasks_lock:
        task = _tasks.get(task_id)
    if not task or not task.get("result_path"):
        return JSONResponse({"error": "Not found"}, status_code=404)
    from pathlib import Path as _Path
    if not _Path(task["result_path"]).exists():
        # The self-contained HTML was swept (TTL/restart). The already-open tab is unaffected;
        # a reload lands here — tell the client to regenerate rather than 500 on a missing file.
        return JSONResponse({"error": "This preview has expired — regenerate it."}, status_code=404)
    return FileResponse(task["result_path"], media_type="text/html")
