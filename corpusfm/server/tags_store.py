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
or a FileMaker clone sharing a ``root_uuid`` carries only its OWN assignments. ``record_views`` /
``set_record_tags`` are the per-record surface the app addresses; there is no root_uuid union.

Every read/write goes through ``backend.engine`` (Phase 4 tags fold): keyed/indexed reads where a
slot exists (UUIDStorage / UUIDTag / the STORAGE rel_path pair), ``list_all`` for the small TAG
registry and the view-building folds. Both backends qualify — FM OData in production, the SQLite
mirror on LocalBackend (dev/test) — gated only by the storage migration not being pending.
"""

from __future__ import annotations

import logging
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


def _artifact_records(backend) -> list[dict]:
    """Every VISIBLE STORAGE record as the canonical lineage/identity dict (one engine
    read). The tag layer's view of the catalog — visibility is Type-driven (packet 085):
    a mid-landing/queue row is outside VISIBLE_TYPES and never taggable.

    The visibility fence runs on the SERVER (``Type`` is an indexed slot). It used to read the whole
    of STORAGE and discard the non-visible rows in Python, which meant every queue/mid-landing row in
    the table crossed the wire to be thrown away (packet 1210). The Python check is KEPT as the
    authority on what is visible: the slot comparison is against a CF-lowercased index, so it is the
    transport narrowing, not the semantic definition, and the two must not be allowed to disagree
    about a Type that differs only by case."""
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    from corpusfm.storage.artifact_record import record_from_jor
    rows = backend.engine.list_where("STORAGE", isin={"Type": sorted(VISIBLE_TYPES)})
    return [record_from_jor(r.key, r.jor) for r in rows if r.jor.get("Type") in VISIBLE_TYPES]


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


def _all_assigns(backend) -> list[dict]:
    """Every TAG ASSIGNMENT as {UUID, Type, UUIDStorage, UUIDTag} (one engine read) — for the
    view-building folds that genuinely need every assignment.

    Narrowed to ``Type == "User Tag"`` on the server (packet 1210). STORAGELINK is deliberately the
    GENERIC current-state relationship surface and tags are merely its only vocabulary *today*, so
    an unfiltered read is a read that grows with every future link type for no benefit here.
    Behavior is unchanged: ``_fold_assignments`` already dropped any row whose ``UUIDTag`` was absent
    from the tag registry, so a non-tag link was never counted — it was only ever transferred."""
    return [{"UUID": r.key, **r.jor}
            for r in backend.engine.list_where("STORAGELINK", eq={"Type": "User Tag"})]


def _partition(backend):
    """The TAG registry (``_tag_registry``) + ALL STORAGELINK rows — for the view-building
    reads. Single-artifact reconciles use ``_assigns_for_artifact`` instead (audit #5)."""
    name_to_uuid, uuid_to_name = _tag_registry(backend)
    return name_to_uuid, uuid_to_name, _all_assigns(backend)


def _assigns_for_artifact(backend, artifact_uuid) -> list[dict]:
    """ONE artifact's STORAGELINK rows via the indexed UUIDStorage slot (one engine read)."""
    return [{"UUID": r.key, **r.jor}
            for r in backend.engine.get_many("STORAGELINK", "UUIDStorage", [artifact_uuid])]


def _fold_assignments(assigns, uuid_to_name):
    """Fold raw assignments into {artifact_uuid: sorted tag names} — strictly PER RECORD (no
    root_uuid union; a record carries only its own assignments). Keyed by the record UUID (the
    canonical address, packet 085 U3f — STORAGELINK.UUIDStorage IS the record UUID). All user tags."""
    art_names: dict[str, set] = {}
    for a in assigns:
        nm = uuid_to_name.get(a.get("UUIDTag"), "")
        if not nm:
            continue
        au = a.get("UUIDStorage")
        if au:
            art_names.setdefault(au, set()).add(nm)
    return {au: sorted(names) for au, names in art_names.items() if names}


def record_views(backend):
    """The per-record USER-tag map keyed by the record UUID + the STORAGE lineage records, from a
    SINGLE read of STORAGE + TAG + STORAGELINK.

    The list route's one-stop tag fetch. **Strictly per-record** — each UUID maps to only
    that record's own assignments (no root_uuid union → no version/companion/clone bleed).
    Returns (user_view{uuid: [tags]}, artifact_records). System tags are NOT here — they are
    computed at read time from the lineage records (packet 085 U3e).
    """
    recs = _artifact_records(backend)
    _, uuid_to_name, assigns = _partition(backend)
    user_view = _fold_assignments(assigns, uuid_to_name)
    return user_view, recs


# ── record_views snapshot (audit #2 SNAPSHOT) ─────────────────────────────────
# The catalog list route (incl. every 300ms search keystroke) reused to do the FULL
# STORAGE + TAG + STORAGELINK read per request. A short TTL snapshot serves those reads;
# every tag/artifact mutation chokepoint busts it (set_artifact_tags / rename_tag /
# delete_tag here; the delete-artifact + import chokepoints call invalidate_record_views).
# Keyed by store identity so parallel test backends never share a snapshot.

_RV_TTL_S = 60.0
_rv_cache: dict = {"key": None, "at": 0.0, "val": None}


def _rv_key(backend) -> tuple:
    return (type(backend).__name__,
            str(getattr(backend, "archive_dir", "") or ""),
            str(getattr(backend, "host", "") or ""),
            str(getattr(backend, "database", "") or ""))


def invalidate_record_views() -> None:
    """Bust the catalog tag/lineage snapshot — call after any mutation that changes what the
    catalog shows (tag writes bust automatically; artifact add/delete chokepoints call this)."""
    _rv_cache["val"] = None
    _rv_cache["at"] = 0.0


def record_views_cached(backend):
    """``record_views`` behind the TTL snapshot. Only SUCCESSFUL reads are cached — a raising
    backend propagates (the route's three-state 'storage unreachable' stays honest)."""
    import time
    now = time.monotonic()
    if _rv_cache["val"] is not None and _rv_cache["key"] == _rv_key(backend) \
            and (now - _rv_cache["at"]) < _RV_TTL_S:
        return _rv_cache["val"]
    val = record_views(backend)
    _rv_cache.update(key=_rv_key(backend), at=now, val=val)
    return val


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
    backend.engine.create("TAG", tid, _tag_jor(name))
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
            backend.engine.delete("TAG", tid)


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
    for nm in desired:
        if nm not in have:
            tid = get_or_create_tag(backend, nm, name_to_uuid=name_to_uuid)
            backend.engine.create(
                "STORAGELINK", _gen(),
                {"Type": "User Tag", "UUIDStorage": artifact_uuid, "UUIDTag": tid})
    orphaned: set[str] = set()
    for nm, a in have.items():
        if nm not in desired:
            backend.engine.delete("STORAGELINK", a["UUID"])
            orphaned.add(a.get("UUIDTag"))
    _reap(backend, orphaned)
    invalidate_record_views()


# ── per-record set (the app's tag-edit entry point) ──────────────────────────

def load_record_view(backend) -> dict[str, list[str]]:
    """{artifact_uuid: [name, …]} — USER tags PER RECORD (no root union), keyed by the record
    UUID (the canonical address, packet 085 U3f)."""
    user_view, _ = record_views(backend)
    return user_view


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
    for nm in add:
        if nm not in have:
            tid = get_or_create_tag(backend, nm, name_to_uuid=name_to_uuid)
            row_uuid = _gen()
            backend.engine.create(
                "STORAGELINK", row_uuid,
                {"Type": "User Tag", "UUIDStorage": artifact_uuid, "UUIDTag": tid})
            have[nm] = [{"UUID": row_uuid, "UUIDTag": tid}]
            added += 1
    for nm in remove:
        for a in have.pop(nm, []):
            backend.engine.delete("STORAGELINK", a["UUID"])
            removed += 1
    if added or removed:
        invalidate_record_views()
    return {"added": added, "removed": removed, "tags": sorted(have)}


def list_user_tag_names(backend) -> list[str]:
    """Every USER tag name, sorted — straight from the TAG registry (one small read), so
    named-but-empty tags (persisted by commit_tag) are included."""
    name_to_uuid, _ = _tag_registry(backend)
    return sorted(name_to_uuid)


def grouped_user_tags(backend):
    """USER tags grouped by name with per-record members (record UUIDs, packet 085 U3f),
    INCLUDING named-but-empty tags (a registry row with zero assignments — the state commit_tag
    deliberately persists). Returns ([{name, members}], artifact_records) from ONE read of
    STORAGE+TAG+STORAGELINK — the Tags-page fetch (the records let the route resolve member
    display names from the UUID with no 2nd scan)."""
    recs = _artifact_records(backend)
    name_to_uuid, uuid_to_name, assigns = _partition(backend)
    user_view = _fold_assignments(assigns, uuid_to_name)
    groups: dict[str, list[str]] = {n: [] for n in name_to_uuid}
    for au, names in user_view.items():
        for n in names:
            groups.setdefault(n, []).append(au)
    return ([{"name": n, "members": sorted(ms)} for n, ms in sorted(groups.items())], recs)


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
    if new_uuid:
        have_new = {r.jor.get("UUIDStorage")
                    for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [new_uuid])}
        for a in assigns:
            backend.engine.delete("STORAGELINK", a["UUID"])
            art = a.get("UUIDStorage")
            if art not in have_new:
                backend.engine.create(
                    "STORAGELINK", _gen(),
                    {"Type": "User Tag", "UUIDStorage": art, "UUIDTag": new_uuid})
                have_new.add(art)
        backend.engine.delete("TAG", old_uuid)
    else:
        rows = backend.engine.get_by_keys("TAG", [old_uuid])
        if rows:
            backend.engine.update("TAG", old_uuid, {**rows[0].jor, "Name": new})
    invalidate_record_views()
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
    tid = name_to_uuid.get(name)
    if not tid:
        tid = get_or_create_tag(backend, name, name_to_uuid=name_to_uuid)
    have: dict[str, dict] = {
        r.jor.get("UUIDStorage"): {"UUID": r.key, **r.jor}
        for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [tid])}
    have_aus = set(have)

    added = 0
    for au in desired_aus - have_aus:
        backend.engine.create(
            "STORAGELINK", _gen(),
            {"Type": "User Tag", "UUIDStorage": au, "UUIDTag": tid})
        added += 1
    removed = 0
    for au in have_aus - desired_aus:
        backend.engine.delete("STORAGELINK", have[au]["UUID"])
        removed += 1
    invalidate_record_views()                 # never reaps the tag row itself
    return {"added": added, "removed": removed, "count": len(desired_aus)}


def commit_tag(backend, original_name, name, member_uuids) -> dict:
    """One declarative tag commit: create (``original_name``=='') or rename
    (``original_name`` != ``name``; rename-into-existing merges), then reconcile the tag's
    membership to EXACTLY ``member_uuids`` (record UUIDs, packet 085 U3f). Returns {ok, name, count}.

    Name is normalized lowercase; an empty membership persists the tag (no reap)."""
    original_name = (original_name or "").strip().lower()
    name = (name or "").strip().lower()
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
    for r in backend.engine.get_many("STORAGELINK", "UUIDTag", [tid]):
        backend.engine.delete("STORAGELINK", r.key)
        affected += 1
    backend.engine.delete("TAG", tid)
    invalidate_record_views()
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
