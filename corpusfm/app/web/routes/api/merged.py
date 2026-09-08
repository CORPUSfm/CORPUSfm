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
    """SaveAsXML and AddonXML snapshots that can be merged, from the catalog generation.

    Served off the persistent catalog's TYPE index (packet 1361-01) — the incumbent enumerated
    STORAGE with `iter_artifact_metas()` on every dialog open and then threw most of it away. A
    catalog whose database read failed says so rather than rendering an empty candidate list, which
    on this dialog reads as "you have nothing to merge"."""
    from corpusfm.storage import get_backend
    from corpusfm.server import catalog
    from corpusfm.artifact.capabilities import has_capability, MERGE

    backend = get_backend()
    view = catalog.view(backend)
    if view.failed:
        return JSONResponse({"saveas": [], "addons": [],
                             "catalog_failed": True, "unavailable": True, "reason": "storage"})

    saveas = []
    addons = []
    for atype in ("SaveAsXML", "AddonXML"):
        if not has_capability(atype, MERGE):
            continue
        for rec in view.select(type=atype):
            meta = rec.get("meta")
            if meta is None or not getattr(meta, "is_schema", False):
                continue
            entry = {
                "uuid": meta.uuid,        # canonical record address (packet 085 U3f)
                "fm_file": meta.file_name,
                "timestamp": meta.timestamp,
                "name": meta.name or "",
                "is_addon": meta.is_addon,
            }
            (addons if meta.is_addon else saveas).append(entry)
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
        # store_artifact publishes the record it committed (packet 1361-01) — the new MergedXML
        # row is in the persistent catalog before this returns.
        meta = backend.store_artifact(merged, label=name, origin="Merge")
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
