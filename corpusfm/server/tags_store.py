"""Tag system — normalized access over the TAG + STORAGELINK tables, on the StorageEngine.

TAG        : one row per distinct tag name (record key = tag UUID; Name lowercased). USER tags
             ONLY — system tags (type:/origin:/fm:) are COMPUTED at read time from the record
             itself and NEVER stored (packet 085 U3e; ``type_tag``/``origin_tag``/``fm_tag`` are
             the pure computation helpers the catalog read path uses).
STORAGELINK: one row per relationship — Type="User Tag" for a tag assignment, UUIDStorage → STORAGE
             record UUID, UUIDTag → TAG UUID. (STORAGELINK is the generic current-state relationship
             surface; tags are its only vocabulary today.)

Reap-at-zero (hard): a tag with no remaining assignments is deleted — no lingering vocabulary.
(Exception: ``reconcile_tag_members``/``commit_tag`` deliberately persist a named-but-empty tag.)

Tags are **strictly per-record** (per artifact-record, addressed by ``rel_path`` =
``file_name/timestamp``). Records NEVER inherit tags: a version, a SaveAsXML/Addon companion,
or a FileMaker clone sharing a ``root_uuid`` carries only its OWN assignments.
``set_record_tags`` is the per-record surface the app addresses; there is no root_uuid union.

**This module is the WRITE path (packet 1361-01).** Every catalog READ of tags — names, empty tags,
membership — comes from ``corpusfm.server.catalog``'s ONE persistent model, which retains
TAG and STORAGELINK as first-class raw records alongside visible STORAGE. What remains here are the
mutations and the authoritative direct lookups a mutation needs: a tag registry read must never be
up to 15 seconds stale, or a rename would fork a tag. Link INTEGRITY is neither read-time nor here —
it is ``server.tag_integrity``, a startup pass that deletes only what it can prove absent.

Writes go through ``backend.engine``: keyed/indexed reads where a slot exists (UUIDStorage /
UUIDTag / the STORAGE rel_path pair) and ``list_all`` for the small TAG registry. Both backends
qualify — FM OData in production, the SQLite mirror on LocalBackend (dev/test) — gated only by the
storage migration not being pending.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import uuid as _uuid

logger = logging.getLogger(__name__)


def tables_available(backend) -> bool:
    """True when the v2 tag tables are usable: the backend exposes a StorageEngine AND the
    new schema is live (the storage migration is not pending — Build matches the shipped
    target, which is exactly when TAG/STORAGELINK exist). LocalBackend's SQLite mirror creates
    the tables from the registry, so it always qualifies."""
    if backend is None or getattr(backend, "engine", None) is None:
        return False
    try:
        from corpusfm.storage import storage_migration as M
        return not M.is_pending(backend)
    except Exception:
        return False


def _gen() -> str:
    return str(_uuid.uuid4())


def _clean(names) -> list[str]:
    """Lowercased, de-duplicated, order-preserving."""
    out: list[str] = []
    for n in names or []:
        n = (n or "").strip().lower()
        if n and n not in out:
            out.append(n)
    return out


# ── catalog publication (packet 1361-01) ─────────────────────────────────────
# TAG and STORAGELINK rows are FIRST-CLASS records in the persistent catalog, so every tag write
# publishes the record the substrate confirmed — not a recomputed tag map.
#
# A tag operation is almost never one row: setting a record's tags creates links, deletes links and
# may reap tag rows. Those are collected and published as ONE atomic in-memory batch, and only
# after the whole operation succeeded. If ANY of the operation's confirmed writes came back without
# a publishable record, NONE of the batch is published (developer ruling) — a half-published
# multi-record operation is a picture nobody committed. The durable writes stand, and the ordinary
# reconciliation age brings memory back into line.

_batches = threading.local()


class _Batch:
    """One operation's confirmed tag writes, awaiting atomic publication."""

    __slots__ = ("backend", "upserts", "removals", "unpublishable")

    def __init__(self, backend) -> None:
        self.backend = backend
        self.upserts: list = []
        self.removals: list = []
        self.unpublishable = False


@contextlib.contextmanager
def _publishing(backend):
    """Collect this operation's confirmed writes; publish one atomic batch on success.

    Re-entrant: ``commit_tag`` runs ``rename_tag`` then ``reconcile_tag_members``, and the developer
    ruling makes that ONE application operation — so the inner calls join the outer batch instead of
    publishing an intermediate state nobody asked for."""
    outer = getattr(_batches, "current", None)
    if outer is not None:
        yield outer
        return
    batch = _Batch(backend)
    _batches.current = batch
    try:
        yield batch
    except BaseException:
        # Partial failure. Some writes may have landed and must never be concealed, but this
        # process does not know which — so publish nothing and let reconciliation recover.
        _batches.current = None
        _report_unpublished(batch, "tag operation failed part-way")
        raise
    _batches.current = None
    _publish(batch)


def _report_unpublished(batch: "_Batch", operation: str) -> None:
    """Confirmed writes this operation will not publish still reach the synchronizer's prompt wake
    (packet 1388-03); otherwise an idle catalog could hold the stale picture for a full idle wait."""
    confirmed = batch.upserts or batch.removals
    if not confirmed:
        return
    try:
        from corpusfm.server import catalog
        catalog.note_unpublishable_write(confirmed[0][0], confirmed[0][1], operation)
    except Exception:
        logger.debug("catalog unpublished-batch bookkeeping failed", exc_info=True)


@contextlib.contextmanager
def publishing(backend):
    """PUBLIC: make a caller's whole multi-record operation ONE catalog publication.

    The bulk-tag endpoint adjusts N records in a loop, and each call is itself a multi-row operation.
    Without an outer scope that is N separate applications of one logical change, and a reader could
    observe half of it. Wrapping the loop makes it ONE short atomic application to the persistent
    model, after the whole operation succeeded (packet 1361-01)."""
    with _publishing(backend) as batch:
        yield batch


def mark_unpublishable() -> None:
    """Tell the enclosing operation it may not publish: something in it did not fully succeed, and
    memory must not hold half of a multi-record operation. Reconciliation recovers. No-op outside
    an operation scope."""
    batch = _current_batch()
    if batch is not None:
        batch.unpublishable = True


def _current_batch():
    return getattr(_batches, "current", None)


def _publish(batch: "_Batch") -> None:
    """Publish one operation's collected upserts and removals atomically. Never raises.

    An operation carrying even ONE unpublishable response publishes nothing at all: memory may not
    hold half of a multi-record operation, and the next validation pass is the recovery."""
    if batch.unpublishable:
        _report_unpublished(batch, "tag operation not published")
        return
    try:
        from corpusfm.server import catalog
        if batch.upserts or batch.removals:
            catalog.publish_batch(batch.backend, batch.upserts, batch.removals)
    except Exception:
        logger.debug("catalog tag batch publication failed", exc_info=True)


def _w_create(backend, table: str, key: str, jor: dict) -> str:
    """``engine.create`` + collect what the substrate returned. Returns the record key."""
    written = backend.engine.create(table, key, jor)
    _collect(backend, table, key, written, "create")
    return key


def _w_update(backend, table: str, key: str, jor: dict) -> None:
    written = backend.engine.update(table, key, jor)
    _collect(backend, table, key, written, "update")


def _w_delete(backend, table: str, key: str) -> None:
    backend.engine.delete(table, key)
    batch = _current_batch()
    if batch is not None:
        batch.removals.append((table, key))
    else:
        try:
            from corpusfm.server import catalog
            catalog.publish_deleted(backend, table, key)
        except Exception:
            logger.debug("catalog removal publication failed for %s/%s", table, key, exc_info=True)


def _collect(backend, table: str, key: str, written, operation: str) -> None:
    """Record one CONFIRMED write for the batch, or note that it produced nothing publishable."""
    batch = _current_batch()
    if written is None:
        try:
            from corpusfm.server import catalog
            catalog.note_unpublishable_write(table, key, operation)
        except Exception:
            logger.debug("catalog write-failure bookkeeping failed", exc_info=True)
        if batch is not None:
            batch.unpublishable = True
        return
    if batch is not None:
        batch.upserts.append((table, written.key, written.raw))
        return
    try:
        from corpusfm.server import catalog
        catalog.publish(backend, table, written.key, written.raw)
    except Exception:
        logger.debug("catalog publication failed for %s/%s", table, key, exc_info=True)


def _tag_registry(backend):
    """One read of the (small) TAG registry.

    Returns (name_to_uuid, uuid_to_name):
      name_to_uuid: {name: tag_uuid}
      uuid_to_name: {tag_uuid: name}
    All tags are user tags (system tags are computed, never stored), so there is no source
    partition any more (packet 085 U3e).
    """
    name_to_uuid: dict[str, str] = {}
    uuid_to_name: dict[str, str] = {}
    for r in backend.engine.list_all("TAG"):
        nm = (r.jor.get("Name") or "").strip().lower()
        if not nm:
            continue
        name_to_uuid[nm] = r.key
        uuid_to_name[r.key] = nm
    return name_to_uuid, uuid_to_name


def _assigns_for_artifact(backend, artifact_uuid) -> list[dict]:
    """ONE artifact's STORAGELINK rows via the indexed UUIDStorage slot (one engine read)."""
    return [{"UUID": r.key, **r.jor}
            for r in backend.engine.get_many("STORAGELINK", "UUIDStorage", [artifact_uuid])]


# The record_view SNAPSHOT and the `catalog_rows` fold are BOTH retired (packet 1361-01).
# `record_views`, `record_views_cached`, `_rv_cache`, `_rv_key`, `invalidate_record_views`,
# `load_record_view`, `catalog_view`, `catalog_rows` and `visible_storage_rows` are gone. There is
# no per-request three-table fold any more: `corpusfm.server.catalog` holds every STORAGE, TAG and
# STORAGELINK record in ONE persistent model and every consumer reads that. The functions below are
# the WRITE path plus the authoritative direct lookups a write needs (a tag registry read must never
# be a validation cycle behind, or a rename would fork a tag).


# ── tag registry (TAG) ────────────────────────────────────────────────────────

def _tag_jor(name: str) -> dict:
    """The TAG row payload. JOR key conventions are dictated by the calc accessors in
    CORPUSfm_DB: Name, Color, Description. Names are canonical lowercase (callers lower
    before this). All tags are user tags (packet 085 U3e)."""
    return {"Name": name, "Color": "", "Description": ""}


def get_or_create_tag(backend, name, *, name_to_uuid=None) -> str:
    """Find-or-create a user tag by name."""
    name = (name or "").strip().lower()
    if not name:
        return ""
    if name_to_uuid is None:
        name_to_uuid, _ = _tag_registry(backend)
    tid = name_to_uuid.get(name)
    if tid:
        return tid
    tid = _gen()
    _w_create(backend, "TAG", tid, _tag_jor(name))
    name_to_uuid[name] = tid
    return tid


def _reap(backend, tag_uuids) -> None:
    """Delete any tag in ``tag_uuids`` that now has zero assignments — ONE indexed UUIDTag
    read scoped to the candidates (audit #5), never a full STORAGELINK scan."""
    ids = [t for t in tag_uuids if t]
    if not ids:
        return
    live = {r.jor.get("UUIDTag") for r in backend.engine.get_many("STORAGELINK", "UUIDTag", ids)}
    for tid in ids:
        if tid not in live:
            _w_delete(backend, "TAG", tid)


# ── per-artifact assignments (STORAGELINK) ─────────────────────────────────────

def artifact_tags(backend, artifact_uuid) -> list[str]:
    """Tag names on an artifact — one indexed UUIDStorage read + the small registry."""
    if not artifact_uuid:
        return []
    _, uuid_to_name = _tag_registry(backend)
    out: list[str] = []
    for a in _assigns_for_artifact(backend, artifact_uuid):
        nm = uuid_to_name.get(a.get("UUIDTag"), "")
        if nm and nm not in out:
            out.append(nm)
    return sorted(out)


def set_artifact_tags(backend, artifact_uuid, names) -> None:
    """Reconcile ONE artifact's user-tag assignments to exactly ``names``; reap orphaned tags."""
    if not artifact_uuid:
        return
    desired = _clean(names)
    name_to_uuid, uuid_to_name = _tag_registry(backend)
    have: dict[str, dict] = {}
    for a in _assigns_for_artifact(backend, artifact_uuid):
        nm = uuid_to_name.get(a.get("UUIDTag"), "")
        if nm:
            have[nm] = a
    with _publishing(backend):
        for nm in desired:
            if nm not in have:
                tid = get_or_create_tag(backend, nm, name_to_uuid=name_to_uuid)
                _w_create(backend, "STORAGELINK", _gen(),
                          {"Type": "User Tag", "UUIDStorage": artifact_uuid, "UUIDTag": tid})
        orphaned: set[str] = set()
        for nm, a in have.items():
            if nm not in desired:
                _w_delete(backend, "STORAGELINK", a["UUID"])
                orphaned.add(a.get("UUIDTag"))
        _reap(backend, orphaned)


# ── per-record set (the app's tag-edit entry point) ──────────────────────────

def set_record_tags(backend, artifact_uuid, names) -> None:
    """Set the USER tag set for the ONE artifact record identified by its UUID (packet 085 U3f).
    Strictly per-record: sibling records (other versions / companions / clones sharing a
    root_uuid) are untouched. An empty OR unknown UUID is a no-op — the per-record entry point
    verifies the record exists before writing an assignment (no orphan STORAGELINK rows)."""
    if not artifact_uuid:
        return
    try:
        if not backend.engine.get_by_keys("STORAGE", [artifact_uuid]):
            return
    except Exception:
        return
    set_artifact_tags(backend, artifact_uuid, names)


def visible_record_uuids(backend, uuids) -> set[str]:
    """The subset of ``uuids`` that are VISIBLE STORAGE records — keyed reads, no scan.

    The bulk tag endpoint's UUID gate (packet 1280): an unknown or non-visible UUID is reported to
    the caller, and no tag row is created for a selection that validates down to nothing."""
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    ids = [u for u in dict.fromkeys(uuids or []) if u]
    if not ids:
        return set()
    out: set[str] = set()
    for r in backend.engine.get_by_keys("STORAGE", ids):
        if r.jor.get("Type") in VISIBLE_TYPES:
            out.add(r.key)
    return out


def adjust_artifact_tags(backend, artifact_uuid, add, remove) -> dict:
    """Apply an assignment DELTA to ONE artifact record (packet 1280): create the missing
    assignments named in ``add``, delete only the assignments explicitly named in ``remove``.

    Deliberately NOT ``set_artifact_tags``: reconcile replaces the whole set (a stale merge
    clobbers tags the caller never saw) and its ``_reap`` deletes a tag whose last assignment
    goes. **No reap here** — an emptied tag persists as its TAG row, exactly as
    ``reconcile_tag_members`` persists a named-but-empty tag. The add path structurally cannot
    remove an assignment.

    Idempotent: an add already present and a remove already absent are no-ops. Names arrive
    canonical from the caller but are re-cleaned here so the primitive cannot be misused into
    case-variant duplicates. Returns ``{"added": n, "removed": n, "tags": [final names]}``.
    """
    add = _clean(add)
    remove = _clean(remove)
    name_to_uuid, uuid_to_name = _tag_registry(backend)
    # name → EVERY assignment row carrying it (a historical duplicate must not survive a remove).
    have: dict[str, list[dict]] = {}
    for a in _assigns_for_artifact(backend, artifact_uuid):
        nm = uuid_to_name.get(a.get("UUIDTag"), "")
        if nm:
            have.setdefault(nm, []).append(a)
    added = removed = 0
    with _publishing(backend):
        for nm in add:
            if nm not in have:
                tid = get_or_create_tag(backend, nm, name_to_uuid=name_to_uuid)
                row_uuid = _gen()
                _w_create(backend, "STORAGELINK", row_uuid,
                          {"Type": "User Tag", "UUIDStorage": artifact_uuid, "UUIDTag": tid})
                have[nm] = [{"UUID": row_uuid, "UUIDTag": tid}]
                added += 1
        for nm in remove:
            for a in have.pop(nm, []):
                _w_delete(backend, "STORAGELINK", a["UUID"])
                removed += 1
    return {"added": added, "removed": removed, "tags": sorted(have)}


def tag_page_view(backend):
    """Everything the Tags management page shows, from the ONE persistent catalog.

    Returns ``(view, groups, records)``. ``groups`` is ``[{name, members}]`` INCLUDING
    named-but-empty tags (a TAG row with no live link — the state ``commit_tag`` deliberately
    persists), and ``records`` are the visible STORAGE projections the page resolves member display
    names from.

    Nothing here reads FileMaker, and nothing here reports or repairs a link: link integrity is the
    tag subsystem's own startup pass (``server.tag_integrity``), never a read-time inference behind
    a destructive button (packet 1361-01). When the catalog's database read has FAILED the caller
    reports that instead of rendering an empty tag vocabulary."""
    from corpusfm.server import catalog
    view = catalog.view(backend)
    if view.failed:
        return view, [], []
    groups = [{"name": n, "members": ms} for n, ms in sorted(view.tag_groups.items())]
    return view, groups, view.records


def rename_tag(backend, old, new) -> int:
    """Rename ``old`` → ``new``. O(1) when ``new`` is free (rename the TAG row); merges
    onto an existing ``new`` otherwise (repoint assignments, drop dups, delete old).
    Returns the number of assignments that carried the old name."""
    old = (old or "").strip().lower()
    new = (new or "").strip().lower()
    if not old or not new or old == new:
        return 0
    name_to_uuid, _ = _tag_registry(backend)
    old_uuid = name_to_uuid.get(old)
    if not old_uuid:
        return 0
    assigns = [{"UUID": r.key, **r.jor}
               for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [old_uuid])]
    affected = len(assigns)
    new_uuid = name_to_uuid.get(new)
    with _publishing(backend):
        if new_uuid:
            have_new = {r.jor.get("UUIDStorage")
                        for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [new_uuid])}
            for a in assigns:
                _w_delete(backend, "STORAGELINK", a["UUID"])
                art = a.get("UUIDStorage")
                if art not in have_new:
                    _w_create(backend, "STORAGELINK", _gen(),
                              {"Type": "User Tag", "UUIDStorage": art, "UUIDTag": new_uuid})
                    have_new.add(art)
            _w_delete(backend, "TAG", old_uuid)
        else:
            rows = backend.engine.get_by_keys("TAG", [old_uuid])
            if rows:
                _w_update(backend, "TAG", old_uuid, {**rows[0].jor, "Name": new})
    return affected


def reconcile_tag_members(backend, name, member_uuids) -> dict:
    """Reconcile the USER tag ``name`` to carry EXACTLY the records identified by ``member_uuids``
    (record UUIDs — the canonical address, packet 085 U3f). The tag is created if absent. Computes
    the current-vs-desired delta and writes the STORAGELINK add/remove rows. A member UUID that
    isn't a currently-visible record is dropped.

    Unlike per-record set reconcile, an emptied tag is NEVER reaped here — a named user tag with
    zero members persists (only an explicit delete removes it). Returns {added, removed, count}."""
    name = (name or "").strip().lower()
    if not name:
        return {"added": 0, "removed": 0, "count": 0}
    # Validate ONLY the UUIDs actually offered, by record key (packet 1210). This used to read the
    # ENTIRE catalog to build a `known` set and then test a handful of members against it — the cost
    # scaled with the catalog while the question scaled with the caller's argument. `get_by_keys`
    # asks about exactly the offered rows and makes no request at all for an empty list. Same rule
    # enforced: a member that is not a currently-VISIBLE record is dropped.
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    offered = [u for u in dict.fromkeys(member_uuids or []) if u]
    desired_aus = {r.key for r in backend.engine.get_by_keys("STORAGE", offered)
                   if r.jor.get("Type") in VISIBLE_TYPES}

    name_to_uuid, _ = _tag_registry(backend)
    added = 0
    removed = 0
    # ONE application operation, ONE batch: creating the tag row and reconciling its membership are
    # not two publishable states (developer ruling, 2026-09-01). The reads between them are the
    # authoritative direct lookups the write needs, not consumers of the catalog.
    with _publishing(backend):                # never reaps the tag row itself
        tid = name_to_uuid.get(name) or get_or_create_tag(backend, name, name_to_uuid=name_to_uuid)
        have: dict[str, dict] = {
            r.jor.get("UUIDStorage"): {"UUID": r.key, **r.jor}
            for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [tid])}
        have_aus = set(have)
        for au in desired_aus - have_aus:
            _w_create(backend, "STORAGELINK", _gen(),
                      {"Type": "User Tag", "UUIDStorage": au, "UUIDTag": tid})
            added += 1
        for au in have_aus - desired_aus:
            _w_delete(backend, "STORAGELINK", have[au]["UUID"])
            removed += 1
    return {"added": added, "removed": removed, "count": len(desired_aus)}


def commit_tag(backend, original_name, name, member_uuids) -> dict:
    """One declarative tag commit: create (``original_name``=='') or rename
    (``original_name`` != ``name``; rename-into-existing merges), then reconcile the tag's
    membership to EXACTLY ``member_uuids`` (record UUIDs, packet 085 U3f). Returns {ok, name, count}.

    Name is normalized lowercase; an empty membership persists the tag (no reap)."""
    original_name = (original_name or "").strip().lower()
    name = (name or "").strip().lower()
    # ONE application operation, ONE atomic publication (developer ruling, 2026-09-01): a rename
    # followed by a membership reconcile must not publish the intermediate state in between.
    with _publishing(backend):
        if original_name and original_name != name:
            rename_tag(backend, original_name, name)
        res = reconcile_tag_members(backend, name, member_uuids)
    return {"ok": True, "name": name, "count": res["count"]}


def copy_forward_on_run(backend, *, job_uuid, new_timestamp="", job_tags=None) -> list[str]:
    """Tag a freshly-ingested job artifact: copy the PRIOR version's tags forward and
    union the job's own tags on top.

    Lineage is ``job_uuid`` alone (packet 086 / Ruling A — a Job is one file; matched by job
    UUID, never name; NOT root_uuid, NOT file_name). The just-stored artifact is identified in
    that job's history by ``new_timestamp`` (falling back to the newest); the prior version is
    the next-newest. Job-tags are union-applied each run; copy-forward carries everything the
    prior version had — so removing a job-tag stops fresh application but does NOT retro-strip
    what was already copied (per the v2 design). Returns the tag set applied to the new artifact
    (``[]`` if nothing to apply or tables aren't live)."""
    if not job_uuid:
        return []                                          # manual uploads are singletons
    from corpusfm.server.latest import job_records
    group = job_records(backend, job_uuid)
    if not group:
        return []
    group.sort(key=lambda r: r.get("timestamp", ""))
    new = None
    if new_timestamp:
        new = next((r for r in group if r.get("timestamp") == new_timestamp), None)
    if new is None:
        new = group[-1]                                   # newest = the just-stored one
    others = [r for r in group if r.get("uuid") != new.get("uuid")]
    prior = others[-1] if others else None                # next-newest in the lineage
    prior_names = artifact_tags(backend, prior["uuid"]) if prior else []
    final = _clean(list(prior_names) + list(job_tags or []))
    if final:
        set_artifact_tags(backend, new["uuid"], final)
    return final


def delete_tag(backend, name) -> int:
    """Delete a USER tag everywhere (its assignments then the tag row). Returns the number of
    assignments removed."""
    name = (name or "").strip().lower()
    name_to_uuid, _ = _tag_registry(backend)
    tid = name_to_uuid.get(name)
    if not tid:
        return 0
    affected = 0
    with _publishing(backend):
        for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [tid]):
            _w_delete(backend, "STORAGELINK", r.key)
            affected += 1
        _w_delete(backend, "TAG", tid)
    return affected


# ── computed system tags (packet 085 U3e — derived at read time, NEVER stored) ───
# Intrinsic facts about an artifact (its type, origin, FileMaker version). They are computed
# per-row from the STORAGE record on every catalog read — no TAG/STORAGELINK rows, no backfill,
# no drift. Used DESCRIPTIVELY (badge / optional filter); the catalog read path (library.py)
# injects them into each row's system_tags. `indexed`/`summarized` are likewise computed live.

_TYPE_TOKEN = {
    "SaveAsXML": "saveasxml", "AddonXML": "addonxml",
    "fmClip": "clip", "MergedXML": "merged",
}


def type_tag(type_value: str) -> str:
    """The single canonical `type:<token>` system tag for an artifact type value
    (e.g. "SaveAsXML" → "type:saveasxml", "fmClip" → "type:clip"); "" if unknown.
    The ONE place type becomes a system tag — the Artifacts type filter folds into this
    (no separate type-filter mechanism)."""
    tv = (type_value or "").strip()
    tok = _TYPE_TOKEN.get(tv, tv.lower())
    return f"type:{tok}" if tok else ""


def origin_tag(value: str) -> str:
    """The single canonical `origin:<token>` system tag for an artifact origin value
    (e.g. "Import" → "origin:import", "Patch (ISV)" → "origin:patch-(isv)"); "" if blank.
    Mirrors ``type_tag`` — origin folds into the one system-tag mechanism so the facet
    surfaces it for free."""
    v = (value or "").strip()
    return f"origin:{v.lower().replace(' ', '-')}" if v else ""


def fm_tag(fm_version: str) -> str:
    """The single canonical `fm:<major>` system tag for an FM version string
    (e.g. "22.0.1" → "fm:22"); "" when blank or non-numeric. Computed from the stored
    FMVersion at read time (packet 085 U3e — never a stored system tag)."""
    major = (fm_version or "").strip().split(".", 1)[0]
    return f"fm:{major}" if major.isdigit() else ""
