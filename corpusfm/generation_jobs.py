"""Heavy HTML/patch generation jobs — run in a separate PROCESS, not the web thread.

Explorer/Diff/Patch generation is CPU-bound *pure-Python* rendering. Run in a thread it would
hold the GIL and starve the web process (the Artifacts list, etc. stall mid-generation). These
functions are submitted to a spawn-based ProcessPoolExecutor (see routes/api/generate.py), so
the heavy work happens in a child interpreter with its own GIL and its own backend session.

Contract: each returns a plain, picklable dict ``{"path": str|None, "error": str|None}``.
- ``path`` — a temp file the PARENT serves (Explorer/Diff HTML, or the patch result JSON).
- side effects (diff-history JSONL, action-history OData write) happen here in the child;
  they are file/network writes that work fine cross-process.
All imports are inside the functions so the child loads only the generation stack (core /
storage / extensions), never the FastAPI app.
"""

from __future__ import annotations

from pathlib import Path


def explorer_job(snap_paths: list, syntax_palettes: object = None) -> dict:
    try:
        from corpusfm.app.web._temp_cleanup import sweep_preview_temp, PREVIEW_TTL_SECONDS
        sweep_preview_temp(PREVIEW_TTL_SECONDS)
        from corpusfm.extensions.export import generate_explorer_html
        from corpusfm.storage import get_backend
        backend = get_backend()
        inputs = []
        for sp in snap_paths:
            meta = backend.get_artifact_meta(sp)
            if meta is None:
                return {"path": None, "error": f"Artifact not found: {sp}"}
            if not getattr(meta, "is_schema", False):
                return {"path": None, "error": f"Artifact not ingested: {sp}. Re-import to generate an artifact."}
            artifact = backend.load_artifact(sp)
            if getattr(meta, "has_name_map", False):
                try:
                    artifact._name_map = backend.load_name_map(sp)
                except Exception:
                    artifact._name_map = {}
            inputs.append(artifact)
        html_path = generate_explorer_html(inputs, syntax_palettes=syntax_palettes)
        return {"path": str(html_path), "error": None}
    except Exception as exc:
        return {"path": None, "error": str(exc)}


def diff_job(snap_a: str, snap_b: str, record_history: bool = True,
             syntax_palettes: object = None) -> dict:
    try:
        from corpusfm.app.web._temp_cleanup import sweep_preview_temp, PREVIEW_TTL_SECONDS
        sweep_preview_temp(PREVIEW_TTL_SECONDS)
        from corpusfm.extensions.export import generate_diff_html
        from corpusfm.extensions.export.contracts import ArtifactDiffInput
        from corpusfm.storage import get_backend
        backend = get_backend()
        meta_a = backend.get_artifact_meta(snap_a)
        meta_b = backend.get_artifact_meta(snap_b)
        if meta_a is None or meta_b is None:
            return {"path": None, "error": "One or both artifacts not found."}
        if not getattr(meta_a, "is_schema", False) or not getattr(meta_b, "is_schema", False):
            return {"path": None, "error": "Both artifacts must be ingested before generating a diff. Re-import to generate an artifact."}
        art_a = backend.load_artifact(snap_a)
        art_b = backend.load_artifact(snap_b)
        inp = ArtifactDiffInput(artifact_a=art_a, artifact_b=art_b, meta_a=meta_a, meta_b=meta_b)
        html_path = generate_diff_html(inp, syntax_palettes=syntax_palettes)

        if record_history:
            label_a = (f"{meta_a.fm_file}  {meta_a.timestamp[:10]}"
                       if (hasattr(meta_a, "fm_file") and meta_a.fm_file) else snap_a)
            label_b = (f"{meta_b.fm_file}  {meta_b.timestamp[:10]}"
                       if (hasattr(meta_b, "fm_file") and meta_b.fm_file) else snap_b)
            try:
                from corpusfm.app.diff_history import record_diff
                record_diff(artifact_a=snap_a, artifact_b=snap_b, label_a=label_a, label_b=label_b)
            except Exception:
                pass
            try:
                from corpusfm.server.history import record_diff as _record_diff_event
                _record_diff_event(backend, snap_a, snap_b, label_a=label_a, label_b=label_b)
            except Exception:
                pass
        return {"path": str(html_path), "error": None}
    except Exception as exc:
        return {"path": None, "error": str(exc)}


def patch_job(snap_a: str, snap_b: str, inject_export_script: bool = False) -> dict:
    try:
        import json
        import tempfile
        from corpusfm.extensions.export.patch_build import generate_patch
        from corpusfm.storage import get_backend
        backend = get_backend()
        meta_a = backend.get_artifact_meta(snap_a)
        meta_b = backend.get_artifact_meta(snap_b)
        if meta_a is None or meta_b is None:
            return {"path": None, "error": "One or both artifacts not found."}
        if not getattr(meta_a, "is_schema", False) or not getattr(meta_b, "is_schema", False):
            return {"path": None, "error": "Both artifacts must be ingested before generating a patch."}
        art_a = backend.load_artifact(snap_a)
        art_b = backend.load_artifact(snap_b)
        needs_export_script = not art_b.has_corpusfm_export
        patch_xml, coverage = generate_patch(art_a, art_b, inject_export_script=inject_export_script)
        coverage_dict = coverage.to_dict()

        from_label = f"{meta_a.name}  {meta_a.timestamp[:10]}" if getattr(meta_a, "name", "") else snap_a
        to_label   = f"{meta_b.name}  {meta_b.timestamp[:10]}" if getattr(meta_b, "name", "") else snap_b

        summary: dict = {"sections": {}, "patchable": 0, "not_patchable": 0, "blocked": 0, "total": 0}
        for entry_d in coverage_dict.get("entries", []):
            sec = entry_d.get("section", "Other")
            act = entry_d.get("action", "?")
            sts = entry_d.get("status", "")
            summary["sections"].setdefault(sec, {})
            summary["sections"][sec][act] = summary["sections"][sec].get(act, 0) + 1
            summary["total"] += 1
            if sts == "patchable":
                summary["patchable"] += 1
            elif sts == "blocked":
                summary["blocked"] += 1
            else:
                summary["not_patchable"] += 1

        result = {
            "patch_xml": patch_xml, "coverage": coverage_dict, "summary": summary,
            "snap_a": snap_a, "snap_b": snap_b, "label_a": from_label, "label_b": to_label,
            "needs_export_script": needs_export_script,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="corpusfm_patch_") as f:
            json.dump(result, f)
            json_path = Path(f.name)
        return {"path": str(json_path), "error": None}
    except Exception as exc:
        return {"path": None, "error": str(exc)}
