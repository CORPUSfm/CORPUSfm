"""Merge tool API — candidates + create.

Merged artifacts are first-class ``MergedXML`` records in the unified STORAGE
catalog (unified-artifacts plan §5). Listing, detail, Explore, git-export, and
delete are served generically by the catalog + detail drawer — there is no
merged-specific list/delete/explore/git-export route here.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/merged-artifacts/candidates", dependencies=[Depends(require_auth)])
async def merge_candidates() -> JSONResponse:
    """Return SaveAsXML and AddonXML snapshots that have an artifact (can be merged)."""
    from corpusfm.storage import get_backend
    from corpusfm.artifact.capabilities import has_capability, MERGE
    backend = get_backend()
    saveas = []
    addons = []
    for meta in backend.iter_artifact_metas():
        if not getattr(meta, "is_schema", False):
            continue
        atype = getattr(meta, "artifact_type", None) or (
            "AddonXML" if meta.is_addon else "SaveAsXML")
        if not has_capability(atype, MERGE):
            continue
        entry = {
            "uuid": meta.uuid,        # canonical record address (packet 085 U3f)
            "fm_file": meta.file_name,
            "timestamp": meta.timestamp,
            "name": meta.name or "",
            "is_addon": meta.is_addon,
                        }
        if meta.is_addon:
            addons.append(entry)
        else:
            saveas.append(entry)
    return JSONResponse({"saveas": saveas, "addons": addons})


@router.post("/merged-artifacts/create", dependencies=[Depends(require_auth)])
async def create_merged(request: Request) -> JSONResponse:
    body = await request.json()
    saveas_ref = body.get("saveas_uuid") or body.get("saveas_rel_path", "")
    addon_ref = body.get("addon_uuid") or body.get("addon_rel_path", "")
    if not saveas_ref or not addon_ref:
        return JSONResponse(
            {"ok": False, "error": "saveas_uuid and addon_uuid required"},
            status_code=400,
        )
    try:
        from corpusfm.app.web.artifact_ref import resolve_ref
        from corpusfm.storage import get_backend
        from corpusfm.artifact.merge import check_eligibility, merge_artifacts

        backend = get_backend()
        saveas_uuid, err = resolve_ref(backend, saveas_ref)
        if err is not None:
            return err
        addon_uuid, err = resolve_ref(backend, addon_ref)
        if err is not None:
            return err
        saveas_artifact = backend.load_artifact(saveas_uuid)
        addon_artifact = backend.load_artifact(addon_uuid)
        eligible, reason = check_eligibility(saveas_artifact, addon_artifact)
        if not eligible:
            return JSONResponse({"ok": False, "error": reason}, status_code=422)

        merged = merge_artifacts(saveas_artifact, addon_artifact)
        # Store as a first-class MergedXML record in the unified catalog (origin="Merge"). The display
        # name follows the naming doctrine: a caller-supplied `name` (from the merge name pop-over) wins,
        # else the PRIMARY name — the source file's stem — NOT the raw ".fmp12" file_name.
        from corpusfm.core.filenames import primary_name_from_filename
        name = (body.get("name") or "").strip() or primary_name_from_filename(merged.identity.file_name)
        meta = backend.store_artifact(merged, label=name, origin="Merge")
        # Bust the catalog tag/lineage snapshot — the new MergedXML row shows immediately.
        try:
            from corpusfm.server.tags_store import invalidate_record_views
            invalidate_record_views()
        except Exception:
            pass
        # Stamp the parent RECORD UUIDs into the cheap record so the detail's "Merged from" reads
        # them without loading the merged blob. This is the ONLY place the link is kept — never in
        # the artifact, which travels somewhere our UUIDs mean nothing (packet 1216).
        try:
            backend.update_record(meta.uuid, {"merge_parent_refs": [
                {"uuid": saveas_uuid},
                {"uuid": addon_uuid},
            ]})
        except Exception:
            pass
        # Record the merge: the child's birth-from-merge + each parent's participation, so the
        # History tab (and Logs) show the event with links back to the source files. Each parent row
        # carries that parent's record UUID, which is what the reverse "built from this" lookup reads.
        from corpusfm.server.history import record_merge
        record_merge(backend, meta.uuid, saveas_uuid, addon_uuid,
                     root_uuid=getattr(getattr(merged, "identity", None), "root_uuid", "") or "")
        return JSONResponse({"ok": True, "uuid": meta.uuid})
    except FileNotFoundError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
