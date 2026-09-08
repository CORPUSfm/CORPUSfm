"""Tags API — manage user-defined multi-valued labels for artifact grouping."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth
from corpusfm.app.web.deps import get_ctx
from corpusfm.runtime import AppContext

router = APIRouter()


@router.get("/tags/names", dependencies=[Depends(require_auth)])
async def tag_names() -> JSONResponse:
    """Return distinct tag names (for datalist autocomplete)."""
    from corpusfm.server.tags import list_tag_names
    return JSONResponse({"names": list_tag_names()})


@router.get("/tags", dependencies=[Depends(require_auth)])
async def list_tags(ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    """Every tag with its per-record members + resolved display names.

    Served EXCLUSIVELY from the persistent catalog (packet 1361-01). TAG and STORAGELINK are
    first-class records in it, validated alongside visible STORAGE, so this page needs no read of
    its own — names, named-but-empty tags and grouped membership all fall out of the one model.
    There is no direct-FileMaker fallback: a catalog whose database read FAILED says so rather than
    rendering an empty tag vocabulary, which would read as "you have no tags".

    It reports NO integrity verdict and offers no cleanup. A link whose endpoints do not resolve is
    simply not a membership fact here; deleting one is the tag subsystem's own startup pass
    (``server.tag_integrity``), which proves absence by a keyed read before it removes anything."""
    from corpusfm.server import tags_store

    backend = ctx.storage()
    _fail = {"groups": [], "catalog_failed": True, "unavailable": True, "reason": "storage"}
    try:
        view, groups, recs = tags_store.tag_page_view(backend)
    except Exception:
        return JSONResponse(_fail)
    if view.failed:
        return JSONResponse(_fail)

    # artifact_uuid → {display, timestamp, type} (packet 048: timestamp + type chip disambiguate
    # member rows when several versions of the same file share a display name). Members are keyed
    # by the record UUID (the canonical address, packet 085 U3f).
    uuid_to_meta = {
        rec["uuid"]: {"display": rec.get("name") or rec.get("file_name") or rec["uuid"],
                      "timestamp": rec.get("timestamp", ""),
                      "type": rec.get("artifact_type", "")}
        for rec in recs if rec.get("uuid")}

    result = []
    for g in groups:
        members = []
        for au in g["members"]:
            m = uuid_to_meta.get(au)
            if not m:
                continue
            members.append({
                "uuid": au,
                "display": m["display"],
                "timestamp": m.get("timestamp", ""),
                "type": m.get("type", ""),
            })
        result.append({"name": g["name"], "count": len(members), "members": members})
    return JSONResponse({"groups": result})


@router.post("/tags/set", dependencies=[Depends(require_auth)])
async def set_tags(request: Request) -> JSONResponse:
    """Replace the tag set for ONE artifact record, addressed by its UUID (or a human alias,
    resolved here — packet 085 U3f). Strictly per-record — siblings sharing a root_uuid are not
    affected. Accepts `tags` (list or comma-separated string)."""
    try:
        body = await request.json()
        ref = (body.get("uuid") or body.get("ref") or "").strip()
        if not ref:
            return JSONResponse({"ok": False, "error": "uuid is required."}, status_code=400)
        from corpusfm.app.web.artifact_ref import resolve_ref
        from corpusfm.storage import get_backend
        uuid, err = resolve_ref(get_backend(), ref)
        if err is not None:
            return err
        from corpusfm.server.tags import parse_tags, set_record_tags
        raw = body.get("tags", body.get("name", ""))
        tag_list = parse_tags(raw) if isinstance(raw, str) else [str(t).strip() for t in (raw or []) if str(t).strip()]
        set_record_tags(uuid, tag_list)
        return JSONResponse({"ok": True, "tags": tag_list})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/tags/adjust", dependencies=[Depends(require_auth)])
async def adjust_tags(request: Request, ctx: AppContext = Depends(get_ctx)) -> JSONResponse:
    """Bulk assignment DELTA over a Catalog selection (packet 1280): add tags to and/or remove
    tags from a set of records, per-record and idempotent, through the delta primitive — never
    the whole-set reconcile. Body: ``{uuids: [...], add: [...], remove: [...]}`` (lists required).

    Refusals, in order: malformed body 400 · tag storage unavailable **503** (checked before any
    write — a bulk apply must never no-op silently) · invalid add name 400 · empty adjustment 400 ·
    add∩remove overlap 400 (no silent precedence) · no valid records 400 (unknown UUIDs listed).
    Partial failure is a reported outcome: exact per-direction counts, ``failed``/``unknown``
    lists, and the final user-tag list per successful record so the client renders what the
    server did rather than what it hoped."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "a JSON body is required."}, status_code=400)
    uuids, add, remove = body.get("uuids"), body.get("add"), body.get("remove")
    if not (isinstance(uuids, list) and isinstance(add, list) and isinstance(remove, list)):
        return JSONResponse({"ok": False, "error": "uuids, add and remove must each be a list."},
                            status_code=400)

    from corpusfm.server.tags import parse_tags, tags_available, validate_tag_name
    if not tags_available():
        return JSONResponse({"ok": False, "error": "tag storage is unavailable."}, status_code=503)

    add_names: list[str] = []
    for entry in add:                      # flatten comma-separated entries; lowercase + dedup
        for n in parse_tags(str(entry or "")):
            if n not in add_names:
                add_names.append(n)
    for n in add_names:
        normalized, err = validate_tag_name(n)
        if err:
            return JSONResponse({"ok": False, "error": err}, status_code=400)
    remove_names: list[str] = []
    for entry in remove:
        n = str(entry or "").strip().lower()
        if n and n not in remove_names:
            remove_names.append(n)

    if not add_names and not remove_names:
        return JSONResponse({"ok": False, "error": "nothing to apply — no tags to add or remove."},
                            status_code=400)
    overlap = sorted(set(add_names) & set(remove_names))
    if overlap:
        return JSONResponse(
            {"ok": False, "error": "these tags are staged both to add and to remove — resolve "
                                   f"the conflict: {', '.join(overlap)}"}, status_code=400)

    from corpusfm.server import tags_store
    requested = [str(u or "").strip() for u in uuids]
    requested = [u for u in dict.fromkeys(requested) if u]
    backend = ctx.storage()
    visible = tags_store.visible_record_uuids(backend, requested)
    unknown = [u for u in requested if u not in visible]
    valid = [u for u in requested if u in visible]
    if not valid:
        return JSONResponse(
            {"ok": False, "error": "none of the selected records exist in storage.",
             "unknown": unknown}, status_code=400)

    from corpusfm.server.tags import adjust_record_tags
    assignments_added = assignments_removed = records_changed = 0
    failed: list[str] = []
    tags_by_uuid: dict[str, list[str]] = {}
    # ONE catalog publication for the whole operation (packet 1361-01). Each `adjust_record_tags` is
    # itself multi-row, so without this outer scope a 200-record selection published 200 times and
    # copied the generation's record map on each — O(N x catalog) for one atomic change to the tag
    # dimension. A record that fails marks the operation unpublishable: memory may not hold half of
    # it, and the ordinary reconciliation recovers.
    with tags_store.publishing(backend):
        for u in valid:
            try:
                res = adjust_record_tags(u, add_names, remove_names)
            except Exception:
                res = None
            if res is None:
                failed.append(u)
                tags_store.mark_unpublishable()
                continue
            assignments_added += res["added"]
            assignments_removed += res["removed"]
            if res["added"] or res["removed"]:
                records_changed += 1
            tags_by_uuid[u] = res["tags"]
    return JSONResponse({
        "ok": not failed,
        "assignments_added": assignments_added,
        "assignments_removed": assignments_removed,
        "records_changed": records_changed,
        "failed": failed,
        "unknown": unknown,
        "tags_by_uuid": tags_by_uuid,
    })


@router.post("/tags/rename", dependencies=[Depends(require_auth)])
async def rename_tag(request: Request) -> JSONResponse:
    """Rename a tag across every file that carries it."""
    try:
        body = await request.json()
        old_name = (body.get("old_name") or "").strip()
        new_name = (body.get("new_name") or "").strip()
        if not old_name or not new_name:
            return JSONResponse({"ok": False, "error": "old_name and new_name are required."}, status_code=400)
        from corpusfm.server.tags import rename_tag as _rename_tag
        return JSONResponse({"ok": True, "updated": _rename_tag(old_name, new_name)})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/tags/commit", dependencies=[Depends(require_auth)])
async def commit_tag(request: Request) -> JSONResponse:
    """Declaratively commit a tag from the buffered editor: create (original_name='') or rename,
    then reconcile membership to EXACTLY `members` (record UUIDs, packet 085 U3f). An emptied tag
    persists — only an explicit Delete removes a tag. Validates `name` (non-empty, lowercased, no
    reserved system namespace)."""
    try:
        body = await request.json()
        original_name = body.get("original_name", "")
        name = body.get("name", "")
        members = body.get("members", []) or []
        if not isinstance(members, list):
            return JSONResponse({"ok": False, "error": "members must be a list."}, status_code=400)
        from corpusfm.server.tags import commit_tag as _commit_tag
        result = _commit_tag(original_name, name, members)
        return JSONResponse(result, status_code=200 if result.get("ok") else 400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/tags/{name:path}", dependencies=[Depends(require_auth)])
async def delete_tag(name: str) -> JSONResponse:
    """Delete a tag — removes it from every file that carries it."""
    try:
        from corpusfm.server.tags import delete_tag as _delete_tag
        return JSONResponse({"ok": True, "removed": _delete_tag(name)})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
