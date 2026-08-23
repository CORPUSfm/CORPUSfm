"""Library API — artifact listing, deletion, and icon serving."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from corpusfm.app.web.auth import require_auth, require_auth_or_mcp_token
from corpusfm.app.web.deps import get_ctx
from corpusfm.artifact.capabilities import capabilities_for, is_indexable_type
from corpusfm.artifact.types import ArtifactType
from corpusfm.runtime import AppContext

router = APIRouter()


def _latest_map(backend) -> dict:
    """{uuid: is_latest} when the IsLatest schema is live, else {} — empty means "no latest
    filtering" (non-FM backends / pre-migration show everything). Keyed on the record UUID
    (collision-free), matching the write side (server.latest keys IsLatest on the record uuid)."""
    try:
        from corpusfm.server import latest as _latest
        if _latest.latest_available(backend):
            return {r.get("uuid"): bool(r.get("is_latest", False))
                    for r in backend.list_fm_artifact_records()}
    except Exception:
        pass
    return {}


def _csv(s: str) -> list[str]:
    return [p.strip() for p in (s or "").split(",") if p.strip()]


def _xml_type_rec(rec: dict) -> str:
    """Normalized XML type from a STORAGE *lineage* record, which carries `artifact_type`
    directly (e.g. "AddonXML") but no `is_addon` flag — so trust the stored type."""
    at = rec.get("artifact_type") or ""
    return at if at in ("fmClip", "MergedXML", "AddonXML") else "SaveAsXML"


def _inject_signals(system_tags, *, gap_issues, analyzer_failed, acceptance_state) -> list[str]:
    """Append the packet-1121 COMPUTED signal tags (never stored): `has-gaps` when the warning badge is
    nonzero (schema OR clip — the clip badge now counts clip_gaps too), `analysis-incomplete` when a
    forward-compat analyzer crashed (visible even at gap_issues==0, so a fail-open can't read as clean), and
    `acceptance:<state>` for an fmClip carrying a paste-acceptance observation. No `clean` tag: analyzer
    coverage can be partial."""
    from corpusfm.core.acceptance import SYSTEM_TAG
    tags = list(system_tags or [])
    if gap_issues and int(gap_issues) > 0:
        tags.append("has-gaps")
    if analyzer_failed:
        tags.append("analysis-incomplete")
    at = SYSTEM_TAG.get(acceptance_state or "")
    if at:
        tags.append(at)
    return tags


def _inject_type(system_tags, type_value: str) -> list[str]:
    """Set THIS artifact's canonical `type:<token>` system tag, REPLACING any existing
    type:* — type is a per-artifact property. Starting from an empty base and setting the
    row's own type keeps type per-row (a SaveAsXML host + its AddonXML companion each carry
    only their own type) so the facet counts and the (single) system-tag filter are correct
    for companions (packet 085 U3e — computed at read time)."""
    from corpusfm.server.tags_store import type_tag
    base = [s for s in (system_tags or []) if not s.startswith("type:")]
    tt = type_tag(type_value)
    return [*base, tt] if tt else base


def _inject_origin(system_tags, origin_value: str) -> list[str]:
    """Set THIS artifact's canonical `origin:<token>` system tag, REPLACING any existing
    origin:* — origin is a per-artifact property. Mirrors ``_inject_type`` so the Origin
    facet falls out of the generic system-tag faceting (count/filter for free)."""
    from corpusfm.server.tags_store import origin_tag
    base = [s for s in (system_tags or []) if not s.startswith("origin:")]
    ot = origin_tag(origin_value)
    return [*base, ot] if ot else base


def _inject_fm(system_tags, fm_version: str) -> list[str]:
    """Set THIS artifact's canonical `fm:<major>` system tag, REPLACING any existing fm:* —
    the FileMaker major version, computed from the stored FMVersion. Packet 085 U3e: system
    tags are computed at read time, never stored; no tag when the version is blank/non-numeric."""
    from corpusfm.server.tags_store import fm_tag
    base = [s for s in (system_tags or []) if not s.startswith("fm:")]
    ft = fm_tag(fm_version)
    return [*base, ft] if ft else base


# Short TTL cache for index membership. list_indexed() scans ALL vector-index metadata
# (thousands of item rows) to derive a few dozen (file_name, timestamp) keys — ~1.2s on a
# real index — and it ran on EVERY Artifacts list request. Membership is mutable but only
# via explicit index/unindex, so a brief TTL (plus an explicit bust on those ops) keeps the
# `indexed` badge fresh while taking the cost off the hot path.
_INDEXED_TTL_S = 60.0
_indexed_cache: dict = {"rows": None, "at": 0.0}


def invalidate_indexed_cache() -> None:
    """Drop the cached index membership — call after any index/unindex so the `indexed`
    badge + per-artifact status reflect the change on the next read without waiting the TTL."""
    _indexed_cache["rows"] = None
    _indexed_cache["at"] = 0.0


def _indexed_rows() -> list:
    """TTL-cached list_indexed() rows ({file_name, timestamp, count}), or [] when no embedder
    is configured / the index is unavailable. ONE expensive metadata scan serves the whole
    process for the TTL — the `indexed` badge (every list) AND per-artifact status (every
    detail open) read from here instead of re-scanning. Membership is mutable only via
    index/unindex, which bust the cache (see invalidate_indexed_cache)."""
    import time
    now = time.monotonic()
    rows = _indexed_cache["rows"]
    if rows is not None and (now - _indexed_cache["at"]) < _INDEXED_TTL_S:
        return rows
    try:
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server.ai.vector_index import get_vector_index
        idx = get_vector_index(load_app_config())
        rows = [] if idx is None else list(idx.list_indexed())
    except Exception:
        rows = []
    _indexed_cache["rows"] = rows
    _indexed_cache["at"] = now
    return rows


def _indexed_keys() -> frozenset:
    """{uuid} currently in the vector index — drives the derived `indexed` system tag. PER-ARTIFACT
    (keyed by the FM record UUID; each artifact is indexed independently), so only the actually-indexed
    snapshot reads indexed, not every version sharing a name. Never materialized into TAGASSIGN;
    membership is mutable. Reads the cache."""
    return frozenset(r.get("uuid", "") for r in _indexed_rows())


def indexed_status(uuid: str) -> tuple:
    """(indexed: bool, count: int) for ONE artifact — per-artifact (matched on the record uuid). Count is
    that artifact's indexed-object count. Used by /indexed/check (the detail pop-over)."""
    total = 0
    hit = False
    for r in _indexed_rows():
        if r.get("uuid") == uuid:
            hit = True
            total += int(r.get("count", 0))
    return (True, total) if hit else (False, 0)


def _embedder_on() -> bool:
    """True when a semantic-search embedder is configured (so the indexed/unindexed split is
    meaningful). Cheap config check — no index read."""
    try:
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server.ai.vector_index import embedding_ready
        return embedding_ready(load_app_config())
    except Exception:
        return False


def _with_indexed(system_tags: list[str], uuid: str, indexed_keys,
                  embedder_on: bool = False) -> list[str]:
    """Append the `indexed` system tag when THIS artifact (its record uuid) is in the vector index
    (per-artifact — only the indexed snapshot reads indexed); when an embedder is configured, an
    un-indexed artifact gets `unindexed` (the complement, so 'what still needs indexing' is filterable).
    Matched on the record uuid. Idempotent."""
    if uuid in indexed_keys:
        return system_tags if "indexed" in system_tags else [*system_tags, "indexed"]
    if embedder_on:
        return system_tags if "unindexed" in system_tags else [*system_tags, "unindexed"]
    return system_tags


def _ensure_index_facets(facets, embedder_on):
    """Keep Indexed + Unindexed as persistent System-facet options when an embedder is
    configured — even at count 0 — so 'find what still needs indexing' is always reachable."""
    if not (embedder_on and facets):
        return facets
    sys = facets.get("system_tags") or []
    names = {s["name"] for s in sys}
    for n in ("indexed", "unindexed"):
        if n not in names:
            sys.append({"name": n, "count": 0})
    facets["system_tags"] = sorted(sys, key=lambda s: s["name"])
    return facets


# ── AI-summary membership (packet 051; per-record since packet 1021 A1) ─────────
# Membership is the per-record HasSummaries slot (both backends' store_summaries set it, and
# meta.has_summaries projects it — collision-free, per uuid). No archive glob / TTL cache: the
# flag rides each record, so nothing to scan or invalidate.


def _summarizer_on() -> bool:
    """True when an AI summary (chat) provider is configured — so the summarized/unsummarized
    split is meaningful. Cheap config check."""
    try:
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server.ai import summary_provider_ready
        return summary_provider_ready(load_app_config())
    except Exception:
        return False


def _with_summarized(system_tags: list[str], has_summaries: bool,
                     summarizer_on: bool = False) -> list[str]:
    """Append `summarized` when THIS artifact's record carries HasSummaries (the per-record slot,
    collision-free — no (file_name, timestamp) archive glob); when a chat provider is configured,
    an un-summarized artifact gets `unsummarized` (the complement). Idempotent."""
    if has_summaries:
        return system_tags if "summarized" in system_tags else [*system_tags, "summarized"]
    if summarizer_on:
        return system_tags if "unsummarized" in system_tags else [*system_tags, "unsummarized"]
    return system_tags


def _ensure_summary_facets(facets, summarizer_on):
    """Keep Summarized + Unsummarized as persistent System-facet options when a chat provider is
    configured — even at count 0 — so 'what still needs summaries' is always reachable."""
    if not (summarizer_on and facets):
        return facets
    sys = facets.get("system_tags") or []
    names = {s["name"] for s in sys}
    for n in ("summarized", "unsummarized"):
        if n not in names:
            sys.append({"name": n, "count": 0})
    facets["system_tags"] = sorted(sys, key=lambda s: s["name"])
    return facets


def _rec_has_summaries(rec) -> bool:
    """The per-record HasSummaries flag off a STORAGE lineage record. Prefer a projected top-level
    slot; else read it from the canonical ``meta`` the record carries (record_from_jor)."""
    if "has_summaries" in rec:
        return bool(rec["has_summaries"])
    return bool(getattr(rec.get("meta"), "has_summaries", False))


def facets_from_records(records, tags_map, *, latest_only: bool,
                        indexed_keys=frozenset(), embedder_on: bool = False,
                        summarizer_on: bool = False) -> dict:
    """Compute the facets block from the cheap STORAGE *lineage* records (record_views already
    fetched them) instead of the heavy pull-all of full artifact metadata. Counts are over the
    base set (latest applied here; search/date are never active on the DB-page path, and the
    type/tag SELECTIONS are deliberately not applied — facets show the full vocabulary). Same
    shape as apply_facets_and_page's facets so the two paths are interchangeable.

    ``tags_map`` is PER-RECORD (keyed by the record UUID, packet 085 U3f) — a record's tags come
    from its own assignments only, never a root_uuid union. System tags (type:/origin:/fm:) are
    COMPUTED per record from its own fields (packet 085 U3e — never stored)."""
    from collections import Counter
    tag_c, sys_c = Counter(), Counter()
    untagged_n = base_total = 0
    for rec in records:
        if latest_only and not rec.get("is_latest", True):
            continue
        base_total += 1
        au = rec.get("uuid", "")
        rtags = tags_map.get(au, []) if au else []
        if rtags:
            tag_c.update(set(rtags))
        else:
            untagged_n += 1
        # System tags are computed from the record: type:/origin:/fm:; `indexed`/`summarized`
        # derived live. No stored system-tag base (packet 085 U3e).
        sys = _inject_type([], _xml_type_rec(rec))
        sys = _inject_origin(sys, rec.get("origin", "Import"))
        sys = _inject_fm(sys, rec.get("fm_version", ""))
        sys = _with_indexed(sys, rec.get("uuid", ""), indexed_keys, embedder_on)
        sys = _with_summarized(sys, _rec_has_summaries(rec), summarizer_on)
        # packet 1121 — the computed gap/analyzer/acceptance signals fall out of the same faceting (count +
        # filter for free), read from the cheap meta carried on the lineage record (no blob).
        _m = rec.get("meta")
        sys = _inject_signals(sys, gap_issues=getattr(_m, "gap_issues", 0),
                              analyzer_failed=getattr(_m, "analyzer_failed", []),
                              acceptance_state=getattr(_m, "acceptance_state", ""))
        sys_c.update(sys)
    return {
        "tags":        [{"name": n, "count": c} for n, c in sorted(tag_c.items())],
        "system_tags": [{"name": n, "count": c} for n, c in sorted(sys_c.items())],
        "untagged":    untagged_n,
        "base_total":  base_total,
    }


def apply_facets_and_page(
    rows: list[dict],
    *,
    search: str = "",
    tags: list[str] | None = None,
    tag_mode: str = "any",
    untagged: bool = False,
    sys_tags: list[str] | None = None,
    from_date: str = "",
    to_date: str = "",
    latest_only: bool = False,
    latest_tracked: bool = False,
    sort: str = "timestamp",
    direction: str = "desc",
    page: int = 1,
    per_page: int = 25,
    want_facets: bool = True,
) -> dict:
    """Pure faceted filter + sort + paginate over enriched artifact rows.

    Facet counts are computed over the *base set* (search + date + latest applied;
    tag / system-tag selections NOT applied) so the pop-over always shows the full
    available vocabulary with stable counts. Returns one page of rows plus the
    facets block and pagination metadata. No backend access — unit-testable.
    """
    from collections import Counter
    from datetime import date

    tags = [t for t in (tags or []) if t]
    sys_tags = [t for t in (sys_tags or []) if t]
    search_l = (search or "").strip().lower()

    def _in_date(r) -> bool:
        if not (from_date or to_date):
            return True
        try:
            d = date.fromisoformat(str(r.get("timestamp", ""))[:10])
        except Exception:
            return True  # undated rows are never excluded by a date filter
        if from_date and d < date.fromisoformat(from_date):
            return False
        if to_date and d > date.fromisoformat(to_date):
            return False
        return True

    # Base set: search + date + latest. Drives facet counts.
    base = []
    for r in rows:
        if search_l and not any(
            search_l in str(r.get(k, "")).lower()
            for k in ("fm_file", "name", "description", "memory")
        ):
            continue
        if not _in_date(r):
            continue
        if latest_only and latest_tracked and not r.get("is_latest", True):
            continue
        base.append(r)

    facets = {}
    if want_facets:
        tag_c, sys_c = Counter(), Counter()
        untagged_n = 0
        for r in base:
            rtags = r.get("tags") or []
            if rtags:
                tag_c.update(set(rtags))
            else:
                untagged_n += 1
            # type:* is folded in as a system tag (no separate Type facet).
            sys_c.update(r.get("system_tags") or [])
        facets = {
            "tags":         [{"name": n, "count": c} for n, c in sorted(tag_c.items())],
            "system_tags":  [{"name": n, "count": c} for n, c in sorted(sys_c.items())],
            "untagged":     untagged_n,
            "base_total":   len(base),
        }

    # Apply the narrowing facet selections.
    tag_set = set(tags)
    sys_set = set(sys_tags)
    filtered = []
    for r in base:
        rtags = set(r.get("tags") or [])
        if untagged and rtags:
            continue
        if tag_set:
            if tag_mode == "all":
                if not tag_set.issubset(rtags):
                    continue
            elif not (tag_set & rtags):
                continue
        if sys_set and not (sys_set & set(r.get("system_tags") or [])):
            continue
        filtered.append(r)

    # Sort.
    def _key(r):
        v = r.get(sort, "")
        if isinstance(v, list):
            return ", ".join(v)
        return v if v is not None else ""
    filtered.sort(key=_key, reverse=(direction != "asc"))

    total = len(filtered)
    per_page = max(1, min(int(per_page or 25), 200))
    page = max(1, int(page or 1))
    start = (page - 1) * per_page
    page_rows = filtered[start:start + per_page]

    return {
        "rows":     page_rows,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "has_more": start + per_page < total,
        "facets":   facets,
    }


def _refresh_gap_badges(backend, rows: list[dict]) -> list[dict]:
    """Correct a STALE stored gap_issues on the card badge — and stamp it so we never reload again.

    Artifacts whose count was computed under an older actionable_gaps() logic (pre-stamp, or an
    earlier GAP_COUNT_VERSION) carry an inflated count; for such a flagged row we recompute from the
    stored profile, write the corrected count + the current stamp back, and skip it forever after.
    Bounded to flagged AND stale rows — current rows (the overwhelming majority, born stamped) and
    unflagged rows cost nothing (no body load). packet 014 #5."""
    from corpusfm.artifact.types import GAP_COUNT_VERSION
    healed = False
    for r in rows:
        if (r.get("gap_issues", 0) and r.get("is_schema") and r.get("uuid")
                and int(r.get("gap_count_version", 0) or 0) < GAP_COUNT_VERSION):
            try:
                prof = getattr(backend.load_artifact(r["uuid"]), "completeness_profile", None)
                if prof is not None:
                    fresh = prof.actionable_gaps()["issues"]
                    r["gap_issues"] = fresh
                    r["gap_count_version"] = GAP_COUNT_VERSION
                    # Persist so this row is never reloaded again (best-effort; the gate self-heals
                    # next listing if the write-back fails).
                    try:
                        backend.update_record(r["uuid"],
                                              {"gap_issues": fresh, "gap_count_version": GAP_COUNT_VERSION})
                        healed = True
                    except Exception:
                        pass
            except Exception:
                pass
    if healed:
        # Rows now build from the record_views snapshot — without a bust, the stale carried
        # meta would re-trigger this heal (a blob load) on every request until the TTL.
        try:
            from corpusfm.server.tags_store import invalidate_record_views
            invalidate_record_views()
        except Exception:
            pass
    return rows


def _enrich_meta(fm_file, meta, tags_map, is_latest, indexed_keys=frozenset(),
                 embedder_on=False, summarizer_on=False) -> dict:
    enc_kb = round(meta.enc_bytes / 1024) if meta.enc_bytes > 0 else 0
    pct = int(100 - meta.enc_bytes / meta.xml_bytes * 100) if meta.xml_bytes > 0 else 0
    has_icon = getattr(meta, "has_icon", False)
    return {
        "fm_file":       fm_file,
        "timestamp":     meta.timestamp,
        "uuid":          meta.uuid,        # canonical record address (packet 085 U3f)
        "name":          meta.name or "",
        "origin":        meta.origin,
        "description":   meta.description,
        "memory":        meta.memory,
        "enc_kb":        enc_kb,
        "pct":           pct,
        "gap_issues":    meta.gap_issues,
        "gap_count_version": getattr(meta, "gap_count_version", 0),
        "is_addon":      meta.is_addon,
        "has_icon":      has_icon,
        # Provenance: whether a job produced this artifact (packet 033, #7 "Job" card badge).
        # Just the uuid presence — NO per-row name lookup (that'd be N store hits); the detail
        # pane resolves the name. "" for manual uploads → no badge.
        "job_uuid":      getattr(meta, "job_uuid", "") or "",
        "root_uuid":     meta.root_uuid,
        "artifact_type": meta.artifact_type,
        # Server-authored per-artifact capabilities (packet 040): the front-end gates
        # affordances on these flags, never re-deriving a type→capability rule.
        "capabilities":  sorted(capabilities_for(meta.artifact_type)),
        "is_schema":     getattr(meta, "is_schema", False),
        # Vector-index eligibility (packet 1042) — schema + fmClip/fmScript/fmCalc, NOT PatchXML. The UI
        # gates Index/Reindex/De-index on THIS, computed from the same helper as the enqueue guard.
        "indexable":     is_indexable_type(meta.artifact_type),
        # Packet 059: whether the compressed source XML is retained (deletable to reclaim space) + its
        # original size, so the detail can show "Source XML — N MB" + a Delete-source action.
        "has_source":    getattr(meta, "has_source", False),
        "xml_bytes":     getattr(meta, "xml_bytes", 0),
        # Per-record (packet 1021 A1): the HasSummaries slot, projected onto meta.has_summaries by
        # both backends — collision-free (per uuid), unlike the retired (file_name, timestamp) glob.
        # Drives the Summarized badge + the contextual Summaries/Re-summarize button.
        "has_summaries": getattr(meta, "has_summaries", False),
        # Tags are PER-RECORD: keyed by this record's UUID (packet 085 U3f), never a root_uuid
        # union, so a version / companion / clone sharing the root never inherits this row's tags.
        "tags":          tags_map.get(meta.uuid, []),
        # System tags are COMPUTED from this record (packet 085 U3e — never stored): type:* /
        # origin:* / fm:* from the canonical artifact_type / origin / fm_version, plus the live
        # `indexed`/`summarized` membership. Derive type from artifact_type (NOT an is_addon
        # path) so a row can never carry two type tags.
        "system_tags":   _inject_signals(
            _with_summarized(
                _with_indexed(
                    _inject_fm(
                        _inject_origin(
                            _inject_type([], meta.artifact_type),
                            meta.origin),
                        getattr(meta, "fm_version", "")),
                    meta.uuid, indexed_keys, embedder_on),
                getattr(meta, "has_summaries", False), summarizer_on),
            gap_issues=meta.gap_issues, analyzer_failed=getattr(meta, "analyzer_failed", []),
            acceptance_state=getattr(meta, "acceptance_state", "")),
        # packet 1121 — the acceptance OBSERVATION is a separate axis from format gaps; the card shows its
        # badge, the detail links batch/case/source/return. Both may coexist on one artifact.
        "acceptance_state": getattr(meta, "acceptance_state", ""),
        "acceptance_batch": getattr(meta, "acceptance_batch", ""),
        "analysis_incomplete": bool(getattr(meta, "analyzer_failed", [])),
        "is_latest":     is_latest,
    }


def _snapshot_metas(art_records) -> list | None:
    """(fm_file, meta) pairs carried by the record_views snapshot records, or None when any
    record lacks the carried meta (stub backends in tests) — the caller then falls back to
    the full ``iter_artifact_metas()`` scan."""
    if art_records is None:
        return None
    pairs = []
    for r in art_records:
        meta = r.get("meta") if isinstance(r, dict) else None
        if meta is None:
            return None
        if meta.file_name:
            pairs.append((meta.file_name, meta))
    return pairs


def _enriched_rows(backend, tags_map, latest_map, indexed_keys=frozenset(),
                   embedder_on=False, summarizer_on=False,
                   art_records=None) -> list[dict]:
    """Enrich every artifact with tags / system tags / latest / size. When the record_views
    snapshot's records are supplied (each carrying the canonical ``meta`` from the same
    JSONOfRecord parse), rows build from THEM — the filtered path then costs no second full
    STORAGE scan in the same request (audit #2 FETCH-ONCE)."""
    pairs = _snapshot_metas(art_records)
    if pairs is None:
        pairs = [(meta.file_name, meta) for meta in backend.iter_artifact_metas()]
    rows: list[dict] = []
    for fm_file, meta in pairs:
        # Defensive skip-on-load (packet 040): a single un-loadable record (e.g. a stored
        # artifact carrying a retired type value → ArtifactType() ValueError) is logged and
        # omitted so it can never blank the whole catalog listing. The is_latest lookup (on the
        # record uuid — A2) is inside the guard too, so a record raising on attribute access is
        # skipped, not fatal.
        try:
            is_latest = latest_map.get(meta.uuid, True)
            rows.append(_enrich_meta(fm_file, meta, tags_map, is_latest, indexed_keys,
                                     embedder_on, summarizer_on))
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "skipping un-loadable artifact record %s/%s: %s",
                fm_file, getattr(meta, "timestamp", "?"), exc)
    return rows


def _try_db_page(backend, *, latest_only, direction, page, per_page,
                 tags_map, tag="", art_records=None, want_facets=False,
                 indexed_keys=frozenset(), embedder_on=False,
                 summarizer_on=False, job_uuid="") -> dict | None:
    """Huge-scale drop-in: one bounded indexed page via ArtifactsRepo.page_metas over the
    backend's engine (a tag filter is the repo's JOIN(sql)→get_by_keys). The displayed page's
    full meta crosses the wire; the facet counts (when wanted) come from the cheap lineage
    records `art_records` — so the default FACETED view no longer triggers a pull-all.
    Returns the response dict, or None to signal "fall back to the pull-all path"."""
    try:
        from corpusfm.server import latest as _latest
        from corpusfm.storage.repos import artifacts_repo
        repo = artifacts_repo(backend)
        if repo is None or not _latest.latest_available(backend):
            return None
        if want_facets and art_records is None:
            return None                     # can't build facets without the lineage records
        # Engine-uniform page (audit #2): one bounded indexed read; a tag filter is the
        # repo's JOIN(sql)→get_by_keys — no backend-bespoke OData/SQL on this path.
        metas, total = repo.page_metas(latest_only=latest_only, desc=(direction != "asc"),
                                       page=page, per_page=per_page, tag=tag, job_uuid=job_uuid)
    except Exception:
        return None
    rows = []
    for m in metas:
        try:
            rows.append(_enrich_meta(m.file_name, m, tags_map, True,
                                     indexed_keys, embedder_on, summarizer_on))
        except Exception as exc:
            logging.getLogger(__name__).warning(
                "skipping un-loadable artifact record %s/%s: %s",
                getattr(m, "file_name", "?"), getattr(m, "timestamp", "?"), exc)
    per_page = max(1, min(int(per_page or 25), 200))
    page = max(1, int(page or 1))
    out = {
        "rows":     rows,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "has_more": (page - 1) * per_page + per_page < total,
        "facets":   facets_from_records(art_records, tags_map, latest_only=latest_only,
                                        indexed_keys=indexed_keys, embedder_on=embedder_on,
                                        summarizer_on=summarizer_on)
                    if want_facets else {},
        "db_paged": True,
    }
    if art_records is not None:
        out["fm_files"] = sorted({r.get("file_name") for r in art_records if r.get("file_name")})
    return out


@router.get("/library/artifact-types", dependencies=[Depends(require_auth)])
def artifact_types() -> JSONResponse:
    """The artifact type registry (packet 040): the single server-authored source for the
    type filter dropdown and any type-aware UI. value == display (no separate label map);
    each carries its capability set so the front-end never re-derives a type→capability rule."""
    from corpusfm.artifact.capabilities import capability_matrix
    matrix = capability_matrix()
    return JSONResponse({
        "types": [{"value": t, "label": t, "capabilities": caps} for t, caps in matrix.items()],
    })


@router.get("/library/resolve", dependencies=[Depends(require_auth)])
def resolve_artifact(ref: str = "") -> JSONResponse:
    """Resolve a human alias (PrimaryName / FileName / tag) OR a UUID to the canonical record
    UUID (packet 085 U3f). A single match → {ok, uuid}; several → {ok:False, ambiguous:true,
    candidates:[…]} (409); none → 404. Lets a caller holding only a name reach the UUID-addressed
    routes."""
    from corpusfm.storage import get_backend
    from corpusfm.storage import resolve as _resolve
    r = _resolve.resolve(get_backend(), ref)
    if r.found:
        return JSONResponse({"ok": True, "uuid": r.uuid})
    if r.ambiguous:
        return JSONResponse({"ok": False, "ambiguous": True, "candidates": r.candidates},
                            status_code=409)
    return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)


@router.get("/library/artifacts", dependencies=[Depends(require_auth)])
def list_artifacts(
    search: str = "",
    q: str = "",
    file: str = "All",
    tags: str = "",
    tag_mode: str = "any",
    untagged: bool = False,
    sys_tags: str = "",
    from_date: str = "",
    to_date: str = "",
    latest_only: bool = False,
    job_uuid: str = "",
    page: int = 1,
    per_page: int = 25,
    sort: str = "timestamp",
    dir: str = "desc",
    facets: bool = True,
    ctx: AppContext = Depends(get_ctx),
) -> JSONResponse:
    # Storage via the composed runtime context (packet 006, S4); ctx.storage() is get_backend()
    # under the hood, so behaviour is unchanged and a test can override get_ctx to point elsewhere.
    backend = ctx.storage()
    try:
        return _list_artifacts_result(
            backend, search=(q or search).strip(), file=file, tags=tags, tag_mode=tag_mode,
            untagged=untagged, sys_tags=sys_tags, from_date=from_date, to_date=to_date,
            latest_only=latest_only, job_uuid=job_uuid, page=page, per_page=per_page,
            sort=sort, dir=dir, facets=facets)
    except Exception:
        # Three-state read (packet 071): the backend RAISED (storage momentarily unreachable) —
        # distinct from a genuinely empty catalog. Signal `unavailable` so the page shows a
        # "storage unreachable — retrying" banner instead of a blank "no artifacts" grid that
        # reads as data loss. The traceback stays in the log so a real bug is still diagnosable.
        logging.getLogger(__name__).warning("catalog list read failed — storage unavailable",
                                             exc_info=True)
        return JSONResponse({
            "rows": [], "total": 0, "page": page, "per_page": per_page,
            "facets": {}, "fm_files": [], "latest_tracked": False,
            "unavailable": True, "reason": "storage",
        })


def _list_artifacts_result(
    backend, *, search, file, tags, tag_mode, untagged, sys_tags, from_date, to_date,
    latest_only, page, per_page, sort, dir, facets, job_uuid="",
) -> JSONResponse:
    from corpusfm.server.tags import load_tags

    indexed_keys = _indexed_keys()   # {uuid} in the vector index → per-artifact `indexed` system tag
    embedder_on = _embedder_on()     # when configured, the complement gets `unindexed` (filterable)
    summarizer_on = _summarizer_on()  # when configured, the un-summarized complement gets `unsummarized`

    # One-stop tag/lineage fetch. When the v2 tables are live, user tags + the STORAGE lineage
    # records (which carry IsLatest + the fields system tags are computed from) come from a
    # SINGLE read of STORAGE+TAG+STORAGELINK, gated by ONE Build check — instead of independent
    # view-builders that each re-read the tables and re-ran the Build probe. A backend outage
    # here RAISES (not the silent load_tags() fallback), so the caller can honestly report
    # `unavailable` rather than a catalog that looks empty. System tags are computed per-row
    # (packet 085 U3e — no stored system-tag map to fetch).
    art_records = None
    try:
        from corpusfm.server import tags_store
        _tables = tags_store.tables_available(backend)
    except Exception:
        _tables = False
    if _tables:
        # 60s TTL snapshot (audit #2): the per-request/per-keystroke FULL STORAGE+TAG+STORAGELINK
        # read is served from one cached fetch; tag writes + the artifact add/delete chokepoints
        # bust it (tags_store.invalidate_record_views), so it's fresh where it matters.
        tags_map, art_records = tags_store.record_views_cached(backend)
    else:
        tags_map = load_tags()

    # Huge-scale drop-in: facet-less paging with only DB-expressible filters
    # (latest_only + timestamp order, optionally ONE user tag on the indexed Tags
    # calc — no type/sys-tag/search/date) pages STORAGE server-side instead of
    # pulling every record.
    tag_list = _csv(tags)
    db_expressible = (
        latest_only and sort == "timestamp"
        and not search and len(tag_list) <= 1
        and not _csv(sys_tags) and not untagged
        and not from_date and not to_date and (not file or file == "All")
        # facets, when wanted, are computed from the lineage records — which only the v2
        # tag tables provide; without them, fall through to the pull-all facet path.
        and (not facets or art_records is not None)
    )
    if db_expressible:
        fast = _try_db_page(
            backend, latest_only=latest_only, direction=dir,
            page=page, per_page=per_page, tags_map=tags_map,
            tag=(tag_list[0] if tag_list else ""),
            art_records=art_records, want_facets=facets, indexed_keys=indexed_keys, embedder_on=embedder_on,
            summarizer_on=summarizer_on, job_uuid=job_uuid)
        if fast is not None:
            fast["latest_tracked"] = True
            _ensure_index_facets(fast.get("facets"), embedder_on)
            _ensure_summary_facets(fast.get("facets"), summarizer_on)
            _refresh_gap_badges(backend, fast.get("rows", []))
            return JSONResponse(fast)

    # Latest-version map: derive from the lineage records record_views already fetched
    # (they carry is_latest), else fall back to a dedicated read. Keyed on the record UUID
    # (collision-free — packet 1021 A2), matching the write side.
    if art_records is not None:
        latest_map = {r.get("uuid"): bool(r.get("is_latest", False)) for r in art_records}
    else:
        latest_map = _latest_map(backend)
    rows = _enriched_rows(backend, tags_map, latest_map, indexed_keys, embedder_on,
                          summarizer_on, art_records=art_records)
    if file and file != "All":
        rows = [r for r in rows if r["fm_file"] == file]
    if job_uuid:
        # "Artifacts produced by this job" (packet 1143). Lineage is UUIDJob alone — never the
        # file name, which many unrelated artifacts can share.
        rows = [r for r in rows if r.get("job_uuid") == job_uuid]

    result = apply_facets_and_page(
        rows,
        search=search,
        tags=_csv(tags),
        tag_mode=tag_mode,
        untagged=untagged,
        sys_tags=_csv(sys_tags),
        from_date=from_date,
        to_date=to_date,
        latest_only=latest_only,
        latest_tracked=bool(latest_map),
        sort=sort,
        direction=dir,
        page=page,
        per_page=per_page,
    )
    result["fm_files"] = sorted({r["fm_file"] for r in rows})
    result["latest_tracked"] = bool(latest_map)
    _ensure_index_facets(result.get("facets"), embedder_on)
    _ensure_summary_facets(result.get("facets"), summarizer_on)
    _refresh_gap_badges(backend, result.get("rows", []))
    return JSONResponse(result)


def _picker_item(fm_file: str, meta, tags_map: dict) -> dict:
    """One artifact-picker result row — the shape the picker dialog expects. Shared by the
    server-side page and the scan fallback so both produce byte-identical rows."""
    art_type = (meta.artifact_type if getattr(meta, "artifact_type", None)
                else ("AddonXML" if meta.is_addon else "SaveAsXML"))
    # Naming doctrine: list rows show the PRIMARY name (meta.name — an addon's PrimaryName is
    # its title, packet 085), falling back to the internal-derived dir name for legacy rows.
    display_name = meta.name or fm_file
    return {
        "uuid":          meta.uuid,        # canonical record address (packet 085 U3f)
        "name":          display_name,
        "fm_file":       fm_file,
        "timestamp":     meta.timestamp,
        "artifact_type": art_type,
        "capabilities":  sorted(capabilities_for(art_type)),
        "origin":        getattr(meta, "origin", "Import"),
        "is_addon":      meta.is_addon,
        "root_uuid":     meta.root_uuid or "",
        "tags":          tags_map.get(meta.uuid, []),
        "is_schema":     getattr(meta, "is_schema", False),
        "indexable":     is_indexable_type(art_type),
        "has_source":    getattr(meta, "has_source", False),
        "xml_bytes":     getattr(meta, "xml_bytes", 0),
    }


@router.get("/library/artifacts/search", dependencies=[Depends(require_auth)])
def search_artifacts(
    q: str = "",
    type: str = "",
    origin: str = "",
    tag: str = "",
    root_uuid: str = "",
    exclude: str = "",
    requires_artifact: bool = False,
    page: int = 1,
    per_page: int = 20,
) -> JSONResponse:
    """Paginated artifact search used by the Artifact Picker dialog and Explorer session modal.

    `origin` filters by creation flow ({WebUI, Job, Merge, Patch (ISV), MCP, Reabsorb, Seed}; `Import`
    remains a recognized legacy value — packet 1169) — e.g. the Patch (ISV) page lists recent ISV
    patches via origin="Patch (ISV)"."""
    from corpusfm.storage import get_backend
    from corpusfm.server.tags import load_tags

    per_page = max(1, min(per_page, 100))
    page = max(1, page)

    backend = get_backend()
    # Tag chips from the record_views snapshot (audit #6): the per-keystroke load_tags() was a
    # full STORAGE+TAGS+TAGASSIGN read BEFORE the bounded page — the 60s snapshot (busted on
    # every tag/artifact mutation chokepoint) serves it for ~0 reads. Non-v2 backends keep the
    # legacy load_tags path.
    try:
        from corpusfm.server import tags_store
        if tags_store.tables_available(backend):
            tags_map, _recs = tags_store.record_views_cached(backend)
        else:
            tags_map = load_tags()
    except Exception:
        tags_map = load_tags()

    # Server-side path (packet 014 #1; Phase 4: on the repo, not a backend-bespoke method): when
    # the projection backfill is complete AND there's no tag filter (the picker's tag filter is
    # rare — it keeps the scan), the engine pages on the indexed slots (root_uuid / the Type
    # fence / Origin + contains() across the search slots for q, an engine-side `exclude` for the
    # compared-against artifact) — no full-scan. Falls back to the scan below on LocalBackend, a
    # pending backfill, a tag filter, or any OData error, so results are always correct.
    from corpusfm.storage import projections
    from corpusfm.storage.repos import artifacts_repo
    repo = artifacts_repo(backend)
    if not tag and repo is not None and projections.ready(backend):
        try:
            metas, total = repo.page_metas(
                latest_only=False, q=q, type=type, origin=origin, root_uuid=root_uuid,
                requires_artifact=requires_artifact, exclude_uuid=exclude,
                page=page, per_page=per_page)
            rows = [_picker_item(m.file_name, m, tags_map) for m in metas]
            return JSONResponse({
                "rows":     rows,
                "total":    total,
                "page":     page,
                "per_page": per_page,
                "has_more": (page - 1) * per_page + per_page < total,
            })
        except Exception:
            pass  # any OData error → fall through to the always-correct scan

    all_items: list[dict] = []
    for meta in backend.iter_artifact_metas():
        all_items.append(_picker_item(meta.file_name, meta, tags_map))

    q_lower = q.strip().lower()
    filtered: list[dict] = []
    for item in all_items:
        if type and item["artifact_type"] != type:
            continue
        if origin and item["origin"] != origin:
            continue
        if requires_artifact and not item["is_schema"]:
            continue
        if q_lower and q_lower not in item["name"].lower() and q_lower not in item["fm_file"].lower():
            continue
        if tag:
            if tag == "__untagged__":
                if item["tags"]:
                    continue
            elif tag not in item["tags"]:
                continue
        if root_uuid and item["root_uuid"] != root_uuid:
            continue
        if exclude and item["uuid"] == exclude:
            continue
        filtered.append(item)

    filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    total = len(filtered)
    start = (page - 1) * per_page
    page_items = filtered[start:start + per_page]

    return JSONResponse({
        "rows":     page_items,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "has_more": start + per_page < total,
    })


from corpusfm.artifact.capabilities import DELIVERABLE_EXT as _DELIVERABLE_EXT


# `_meta_sidecar` is gone (packet 1226). It ferried the record fields an Artifact does not carry —
# name/description/memory/tags/origin — beside the payload as a separate `meta.json` member, because
# the download had no single document to put them in. It has one now, and those fields live INSIDE the
# externalized artifact: `corpusfm.artifact.document`.


def require_download_access(request: Request) -> None:
    """Auth for the download route: session OR MCP bearer (existing) OR a the Machine Key-signed expiring URL
    (packet 1166 A3-auth). The signed path lets the AI `curl` a container's bytes with NO standing
    credential — the signature carries no secret. `container=` is the SOLE selector bound into the
    signature (no `form`), so the signed path uses `container=` only. The VISIBLE_TYPES fence runs AFTER
    the signature check (a valid sig to a non-visible/typeless record is still refused)."""
    q = request.query_params
    sig = q.get("sig")
    if sig:
        from corpusfm.app.web.artifact_ref import resolve_ref
        from corpusfm.app.web.container_download import is_visible
        from corpusfm.core import crypto
        from corpusfm.storage import get_backend
        container = q.get("container") or ""
        exp = q.get("exp") or ""
        ref = request.path_params.get("ref") or ""
        backend = get_backend()
        uuid, err = resolve_ref(backend, ref)
        if err is None and crypto.verify_download(uuid, container, exp, sig):
            if is_visible(backend.get_artifact_meta(uuid)):
                return
        raise HTTPException(status_code=403, detail="Invalid or expired download signature")
    # No signature → the standing session/bearer path (unchanged), gated by library_mcp.
    require_auth_or_mcp_token(request)


@router.get("/artifact-download/{ref:path}", dependencies=[Depends(require_download_access)])
def artifact_download(ref: str, form: str = None, container: str = None):
    """Download an artifact — never the original ingested XML unless it was retained (packet 1034).

    `container` (packet 1166) selects a RAW retained container directly, reaching all four blobs + icon:
      • SourceXML → `.xml`; ArtifactData → the deliverable file (deliverable) or `.artifact`
        (schema); SummariesData / NameMapData → `.json`; icon → `.png`.
      An absent slot 404s with a "slot not present" reason (never a 500). This is the SOLE addressing
      scheme on the Machine Key-signed path (no `form=` on a signed URL — two schemes for the same bytes make
      the signature ambiguous). The legacy `form=` below stays on the session/bearer path.

    `form` (session/bearer only) selects the packaged shape:
      • form="artifact"  → the portable envelope, downloaded as a plain **.zip** (`meta.json`
        sidecar + payload). Re-import recognises it by content, not by name.
      • form="raw"       → the simple text file (deliverable raw XML, or a schema's retained source).
      • default (no form / no container) → back-compat: raw for a deliverable, envelope for a schema.

    ``ref`` is the record UUID (or a human alias, resolved here — packet 085 U3f); the served
    filename derives from the artifact's PrimaryName."""
    from fastapi.responses import Response
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.artifact.capabilities import DELIVERABLE_TYPES
    from corpusfm.storage import get_backend
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        raise HTTPException(status_code=err.status_code, detail="Not found")
    meta = backend.get_artifact_meta(uuid)
    if meta is None:
        raise HTTPException(status_code=404, detail="Not found")
    atype = getattr(meta, "artifact_type", "")
    is_deliverable = atype in DELIVERABLE_TYPES

    # container= : raw single-container download (packet 1166 A2). VISIBLE_TYPES-fenced; an absent slot
    # 404s with a reason (the has_* flags decide presence — an empty slot is normal, not an error).
    if container:
        from corpusfm.app.web import container_download as _cd
        if container not in _cd.CONTAINER_NAMES:
            raise HTTPException(status_code=400,
                                detail=f"Unknown container '{container}'. One of: {', '.join(_cd.CONTAINER_NAMES)}")
        if not _cd.is_visible(meta):
            raise HTTPException(status_code=404, detail="Not found")
        if not _cd.present(meta, container):
            raise HTTPException(status_code=404,
                                detail=f"Container '{container}' not present — {_cd.absent_reason(container)}.")
        payload = _cd.load_container(backend, uuid, container, meta=meta)
        if payload is None:
            raise HTTPException(status_code=404,
                                detail=f"Container '{container}' has no content for this record.")
        media_type, ext = _cd.content_type_and_ext(container, meta)
        _cbase = _envelope_base(meta)
        if _cd.is_zipped(container, meta):
            return _zipped(f"{_cbase}.{ext}", payload)
        return Response(content=payload, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{_cbase}.{ext}"'})
    # Naming doctrine (packet 036): the download is named with the PRIMARY name (the headline shown
    # in the catalog) so the round-trip holds — download → filename = primary → reimport reads the
    # stem back as the primary. Sanitize for a filesystem-safe filename; fall back to the FileName
    # (or a generic) when no primary is stored.
    _primary = (meta.name or "").strip()
    base = "".join(c if c.isalnum() or c in " ._-" else "_" for c in _primary).strip(" ._-") \
        or (meta.file_name or "artifact")

    form = (form or "").lower()
    if not form:
        form = "raw" if is_deliverable else "artifact"

    if form == "raw":
        if is_deliverable:
            xml = backend.load_deliverable_xml(uuid)
            if xml is None:
                raise HTTPException(status_code=404, detail="No deliverable XML for this artifact")
            ext = _DELIVERABLE_EXT.get(atype, "xml")
            return _zipped(f"{base}.{ext}", xml)
        # Schema raw = the retained source XML, only when the user chose to keep it.
        if not getattr(meta, "has_source", False):
            raise HTTPException(status_code=404,
                                detail="Raw source XML was not retained for this artifact.")
        xml = backend.load_raw_xml(uuid)
        if xml is None:
            raise HTTPException(status_code=404, detail="No source XML stored for this artifact")
        # Zipped, always (packet 1226): a retained SaveAsXML export runs to tens or hundreds of MB and
        # compresses enormously. Deliverable raw above is NOT zipped — it is small, and it is the
        # paste-ready file, so wrapping a clip the user is about to paste would be hostile.
        return _zipped(f"{base}.xml", xml)

    # form == "artifact": the portable .artifact envelope (zip = meta.json sidecar + one payload).
    built = _build_artifact_envelope(backend, uuid, meta)
    if built is None:
        raise HTTPException(status_code=404, detail="No artifact to download")
    _base, blob = built
    # `<name>.artifact.zip` (packet 1226) — this REVERSES the earlier `.artifact` → `.zip` rename,
    # deliberately. That rename argued a bespoke extension "told nothing downstream what to do with
    # it". Under the current frame the extension's job is to say THIS IS A CORPUSFM ARTIFACT, which is
    # exactly what a user handing the file to an AI needs it to say. Keeping `.zip` on the end means it
    # still double-clicks open on Windows and macOS with nothing installed. Re-import continues to
    # recognise the envelope by CONTENT, so every older download still imports.
    return Response(content=blob, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{_base}.artifact.zip"'})


def _zipped(inner_name: str, payload: bytes):
    """Serve `payload` as a single-member zip named `<inner_name>.zip`.

    ZIP rather than gzip on purpose: a `.zip` opens by double-click on Windows and macOS with nothing
    installed and `.gz` does not, and the whole point is handing the file to a person or an AI with no
    tooling to hand.
    """
    import io
    import zipfile
    from fastapi.responses import Response
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(inner_name, payload)
    return Response(content=buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{inner_name}.zip"'})


def _envelope_base(meta) -> str:
    """Filesystem-safe base name for an artifact's `.artifact` envelope (the PrimaryName, sanitized)."""
    primary = (getattr(meta, "name", "") or "").strip()
    return "".join(c if c.isalnum() or c in " ._-" else "_" for c in primary).strip(" ._-") \
        or (getattr(meta, "file_name", "") or "artifact")


def _build_artifact_envelope(backend, uuid: str, meta):
    """Build the externalized artifact — ONE document, zipped (packet 1226).

    Returns (base, zip_bytes), or None when the payload can't be read. Shared by the single-artifact
    download route and the multi-item bundle (packet 1063).

    Every artifact type produces the same top-level key set; only the payload's content differs. The
    document is ASSEMBLED here from the stored artifact plus the record row — nothing is stored in this
    form, so no record is reingested and no stored blob is rewritten.
    """
    import base64
    import io
    import json
    import zipfile
    from corpusfm.artifact.capabilities import DELIVERABLE_TYPES
    from corpusfm.artifact.document import build_document
    from corpusfm.server import tags as _tags
    base = _envelope_base(meta)
    atype = getattr(meta, "artifact_type", "")
    if atype in DELIVERABLE_TYPES:
        # A deliverable's stored bytes ARE its content, not its source — they travel inside the
        # document. (The fence is on the retained SourceXML CONTAINER, which never travels; there is
        # a separate button for that.)
        payload = backend.load_deliverable_xml(uuid)
        if payload is None:
            return None
    else:
        try:
            payload = backend.load_artifact(uuid).to_dict()
        except Exception:
            return None
    try:
        record_tags = _tags.get_tags(uuid)
    except Exception:
        record_tags = []
    # The icon travels base64 (packet 1254). Read through the storage protocol's `load_icon` rather
    # than the jor's already-base64 `icon_b64`: the protocol method exists on both backends, raw jor
    # access does not, and one decode+encode of a few KB does not justify a backend-specific path.
    icon = getattr(backend, "load_icon", lambda _u: None)(uuid)
    icon_b64 = base64.b64encode(icon).decode("ascii") if icon else ""
    doc = build_document(meta, payload, record_tags, icon_b64)
    blob = json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{base}.artifact", blob)
    return base, buf.getvalue()


@router.post("/artifacts/download-bundle", dependencies=[Depends(require_auth_or_mcp_token)])
async def artifacts_download_bundle(request: Request):
    """Stream ONE `.zip` bundle of several selected artifacts (packet 1063; extended packet 1166).

    A deliberate single-download: browsers block/prompt on multiple simultaneous downloads, so firing
    N `<a download>` clicks is unreliable — this bundles the selection server-side instead.

    Body: ``{"refs": [<ref>, …], "form": "artifact", "containers": [<name>, …]}``.
      • `containers` (packet 1166) → RAW container mode: each selected container of each record is laid
        out ``<artifact_type>/<sanitized_name>__<uuid8>.<ext>`` plus a top-level ``MANIFEST.json`` that
        carries the provenance filenames can't (per record: uuid · type · name · file_name · timestamp ·
        origin · fm_version · description · memory · containers saved · skipped-with-reason). An absent
        slot / non-VISIBLE ref is SKIPPED with a reason, never failing the whole bundle.
      • else `form` (default "artifact") → each record's `.artifact` envelope, as before.

    An unreadable/not-found ref is skipped (never fails the whole bundle); 400 on empty refs; 404 when
    nothing was served. Auth: session or MCP token, then the router's `library_mcp` gate."""
    import io
    import json as _json
    import zipfile
    from fastapi.responses import Response
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.app.web import container_download as _cd
    from corpusfm.storage import get_backend
    try:
        body = await request.json()
    except Exception:
        body = {}
    refs = [r for r in (body.get("refs") or []) if isinstance(r, str) and r.strip()]
    if not refs:
        raise HTTPException(status_code=400, detail="No artifacts selected.")
    containers = [c for c in (body.get("containers") or []) if isinstance(c, str) and c in _cd.CONTAINER_NAMES]
    backend = get_backend()
    outer = io.BytesIO()
    used: dict = {}
    n_added = 0

    with zipfile.ZipFile(outer, "w", zipfile.ZIP_DEFLATED) as z:
        if containers:
            manifest = []
            for ref in refs:
                uuid, err = resolve_ref(backend, ref)
                meta = backend.get_artifact_meta(uuid) if err is None else None
                if not _cd.is_visible(meta):
                    manifest.append({"ref": ref, "skipped": "not a visible catalog record"})
                    continue
                atype = getattr(meta, "artifact_type", "") or "Unknown"
                base = _envelope_base(meta)
                saved, skipped = [], {}
                for c in containers:
                    if not _cd.present(meta, c):
                        skipped[c] = _cd.absent_reason(c)
                        continue
                    payload = _cd.load_container(backend, uuid, c, meta=meta)
                    if payload is None:
                        skipped[c] = "container has no readable content"
                        continue
                    _mt, ext = _cd.content_type_and_ext(c, meta)
                    member = f"{atype}/{base}__{uuid[:8]}.{ext}"
                    if member in used:            # de-collide equal (type,name,uuid8,ext)
                        used[member] += 1
                        member = f"{atype}/{base}__{uuid[:8]} ({used[member]}).{ext}"
                    else:
                        used[member] = 0
                    z.writestr(member, payload)
                    saved.append(c)
                    n_added += 1
                manifest.append({
                    "uuid": uuid, "artifact_type": atype, "name": getattr(meta, "name", ""),
                    "file_name": getattr(meta, "file_name", ""), "timestamp": getattr(meta, "timestamp", ""),
                    "origin": getattr(meta, "origin", ""), "fm_version": getattr(meta, "fm_version", ""),
                    "description": getattr(meta, "description", ""), "memory": getattr(meta, "memory", ""),
                    "containers_saved": saved, "skipped": skipped,
                })
            z.writestr("MANIFEST.json", _json.dumps(manifest, ensure_ascii=False, indent=2))
        else:
            for ref in refs:
                uuid, err = resolve_ref(backend, ref)
                if err is not None:
                    continue
                meta = backend.get_artifact_meta(uuid)
                if meta is None:
                    continue
                built = _build_artifact_envelope(backend, uuid, meta)
                if built is None:
                    continue
                base, blob = built
                # De-collide equal PrimaryNames so a member isn't silently overwritten in the zip.
                name = f"{base}.artifact.zip"
                if name in used:
                    used[name] += 1
                    name = f"{base} ({used[name]}).artifact.zip"
                else:
                    used[name] = 0
                z.writestr(name, blob)
                n_added += 1

    if n_added == 0:
        raise HTTPException(status_code=404, detail="None of the selected artifacts could be read.")
    return Response(content=outer.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="corpusfm-artifacts-{n_added}.zip"'})


@router.get("/artifact-icon/{ref:path}", dependencies=[Depends(require_auth)])
def artifact_icon(ref: str) -> Response:
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        raise HTTPException(status_code=404, detail="Icon not found")
    # The icon rides in the record (icon_b64) on both backends — record-keyed, no filesystem path.
    icon = getattr(backend, "load_icon", lambda _u: None)(uuid)
    if not icon:
        raise HTTPException(status_code=404, detail="Icon not found")
    return Response(content=icon, media_type="image/png")


def _raw_record(backend, uuid: str) -> dict:
    """The raw stored record dict (jor) — cheap (no artifact-blob download); carries fields
    not on ArtifactMeta. Both backends expose load_record_jor (addressed by record UUID)."""
    try:
        return backend.load_record_jor(uuid) or {}
    except Exception:
        return {}


def _provenance_from_record(raw: dict) -> dict:
    """Best-effort {created_at, corpusfm_build, catalog_version} from the raw stored record.
    These provenance fields are not on ArtifactMeta, so the detail reads them off the record."""
    out = {}
    for canon, keys in (
        ("created_at", ("created_at", "CreatedAt")),
        ("corpusfm_build", ("corpusfm_build", "CorpusfmBuild", "build")),
        ("catalog_version", ("catalog_version", "CatalogVersion")),
    ):
        for k in keys:
            if raw.get(k):
                out[canon] = raw[k]
                break
    return out


@router.get("/library/git-registrations", dependencies=[Depends(require_auth)])
def library_git_registrations() -> JSONResponse:
    """Registered git credentials for the Export-tab picker. cred_type + repo_locked let the UI
    follow the credential's character: a PAT exposes an editable repo, a deploy key a fixed one."""
    try:
        from corpusfm.core.git_formatter import list_registrations
        regs = [{"name": r.name, "cred_type": getattr(r, "cred_type", "pat"),
                 "repo": getattr(r, "repo", ""), "branch": getattr(r, "branch", ""),
                 "repo_locked": getattr(r, "cred_type", "pat") == "deploy_key"}
                for r in list_registrations()]
    except Exception:
        regs = []
    return JSONResponse({"registrations": regs})


# NOTE: defined BEFORE the greedy {rel_path:path} detail route so the suffix matches here.
@router.get("/library/artifacts/{ref:path}/git-target", dependencies=[Depends(require_auth)])
def get_artifact_git_target(ref: str) -> JSONResponse:
    """The artifact's OWN git target — {registration, repo}, inherited from its job at ingest
    then independently editable. Empty when none set. ``ref`` = record UUID (or alias, 085 U3f)."""
    try:
        from corpusfm.app.web.artifact_ref import resolve_ref
        from corpusfm.server import git_targets
        from corpusfm.storage import get_backend
        uuid, err = resolve_ref(get_backend(), ref)
        if err is not None:
            return JSONResponse({"registration": "", "repo": ""})
        return JSONResponse(git_targets.get_target(uuid))
    except Exception:
        return JSONResponse({"registration": "", "repo": ""})


@router.put("/library/artifacts/{ref:path}/git-target", dependencies=[Depends(require_auth)])
def set_artifact_git_target(ref: str, body: dict) -> JSONResponse:
    """Set the artifact's git target (decoupled from its job). A deploy-key credential's repo
    is fixed — the stored repo is forced to the registration's bound repo regardless of input."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.server import git_targets
    from corpusfm.storage import get_backend
    uuid, err = resolve_ref(get_backend(), ref)
    if err is not None:
        return err
    registration = "" if body is None else (body.get("registration") or "").strip()
    repo = "" if body is None else (body.get("repo") or "").strip()
    if registration:
        try:
            from corpusfm.core.git_formatter import get_registration
            reg = get_registration(registration)
            if getattr(reg, "cred_type", "pat") == "deploy_key":
                repo = reg.repo  # bound — ignore any caller override
        except Exception:
            pass
    return JSONResponse(git_targets.set_target(uuid, registration, repo))


# NOTE: defined BEFORE the greedy {rel_path:path} detail route so "/…/history" matches here.
@router.get("/library/artifacts/{ref:path}/history", dependencies=[Depends(require_auth)])
def artifact_history(ref: str) -> JSONResponse:
    """This artifact's HISTORY event mentions (diffs/patches/merges/arrival/enrichment) —
    the same HISTORY source the Logs panel reads, scoped to one record (085 U3c). An indexed
    two-slot read (UUIDStorage OR UUIDRelatedStorage) newest-first. ``ref`` = record UUID (085 U3f)."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.server.history import list_history_for
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return err
    return JSONResponse({"events": list_history_for(backend, uuid)})


def _related_row(v) -> dict:
    return {"uuid": v.uuid, "file_name": v.file_name, "name": v.name, "type": v.type,
            "origin": v.origin, "timestamp": v.timestamp, "is_latest": v.is_latest}


@router.get("/library/artifacts/{ref:path}/related", dependencies=[Depends(require_auth)])
def artifact_related(ref: str) -> JSONResponse:
    """The detail pop-over's Related tab — two neutral relationship sections, each ONE bounded
    indexed read, the viewed artifact excluded. Lazy: fetched only when the tab is opened.
    Duplicates are surfaced, never prevented (packet 077-D principle).

    - ``same_root``: the same FM file lineage (same RootUUID) — other snapshots of the file, the
      addon companion, merged children.
    - ``built_from_this``: the merges built FROM this artifact (HISTORY reverse lookup on the
      parent's record UUID; a child no longer in the catalog renders inert from its snapshot).

    Packet 1216 removed a third section, ``same_source`` ("byte-identical stored source"). It
    answered "these are the same snapshot", a distinction that only mattered to dedup — and dedup
    was retired by packet 085. Two exports of one file still find each other here, through the
    file's own identity."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.storage.repos import artifacts_repo
    from corpusfm.server.history import list_merges_built_from
    backend = get_backend()
    repo = artifacts_repo(backend)
    empty = {"same_root": [], "built_from_this": []}
    if repo is None:
        return JSONResponse(empty)
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return err
    view = repo.get(uuid)
    if view is None:
        return JSONResponse({"error": "artifact not found"}, status_code=404)
    same_root = [_related_row(c) for c in repo.same_root(view.root_uuid, exclude_uuid=uuid)]
    built: list = []
    for m in list_merges_built_from(backend, uuid):
        child = m.get("child_ref", "")   # the merge child's record UUID (085 U3f)
        cv = repo.get(child) if child else None
        if cv is not None:
            built.append({"uuid": cv.key, "name": cv.name or cv.file_name,
                          "type": cv.type, "timestamp": cv.timestamp, "exists": True})
        else:
            snap = m.get("snapshot") or {}
            built.append({"uuid": child, "name": snap.get("label") or child or "(removed)",
                          "type": "MergedXML", "timestamp": m.get("ts", ""), "exists": False})
    return JSONResponse({"same_root": same_root, "built_from_this": built})


# ── Object evidence (detail pop-over Evidence tab) ────────────────────────────────
# The browser arm of the evidence workflow — same neutral, query-time core logic the MCP tools
# use (corpusfm/core/evidence.py), nothing computed in the browser, nothing stored. Registered
# BEFORE the catch-all /library/artifacts/{ref:path} so the literal suffix wins.

def _evidence_artifact(ref: str):
    """(artifact, uuid, error_response) for an evidence request. ``ref`` is a record UUID (or an
    alias, resolved here — packet 085 U3f); error_response is a JSONResponse to return as-is or None."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return None, "", err
    meta = backend.get_artifact_meta(uuid)
    if meta is None:
        return None, "", JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    if not getattr(meta, "is_schema", False):
        return None, "", JSONResponse(
            {"ok": False, "error": "This artifact carries no parsed schema — nothing to inspect."},
            status_code=400)
    try:
        return backend.load_artifact(uuid), uuid, None
    except Exception as exc:  # noqa: BLE001
        return None, "", JSONResponse({"ok": False, "error": f"Could not load artifact: {exc}"}, status_code=500)


@router.get("/library/artifacts/{ref:path}/objects", dependencies=[Depends(require_auth)])
def artifact_objects(ref: str, q: str = "", limit: int = 30) -> JSONResponse:
    """Search schema objects in one artifact (the Evidence-tab object picker). Case-insensitive
    substring on name / item_id; folders excluded; query-time only."""
    art, _uuid, err = _evidence_artifact(ref)
    if err is not None:
        return err
    ql = (q or "").strip().lower()
    limit = max(1, min(100, int(limit)))
    matches = []
    for it in art.items.values():
        if getattr(it, "is_folder", False):
            continue
        name = it.name or ""
        if ql and ql not in name.lower() and ql not in it.item_id.lower():
            continue
        matches.append({"item_id": it.item_id, "section": it.section, "name": name})
    matches.sort(key=lambda o: (o["section"], (o["name"] or o["item_id"]).lower()))
    return JSONResponse({"ok": True, "objects": matches[:limit],
                         "truncated": len(matches) > limit, "match_count": len(matches)})


@router.get("/library/artifacts/{ref:path}/evidence", dependencies=[Depends(require_auth)])
def artifact_object_evidence(ref: str, object: str = "", section: str = "",
                             limit: int = 20) -> JSONResponse:
    """Neutral, query-time evidence for ONE object — object_evidence + change_impact_evidence + a
    copy-ready markdown brief. Reuses core/evidence.py (no browser logic). Never a verdict."""
    from corpusfm.core import evidence as ev
    obj = (object or "").strip()
    if not obj:
        return JSONResponse({"ok": False, "error": "Select an object first."}, status_code=400)
    art, uuid, err = _evidence_artifact(ref)
    if err is not None:
        return err
    item = ev.find_artifact_item(art, obj, section=(section or None))
    if item is None:
        return JSONResponse({"ok": False, "error": f"No object matched {obj!r}."}, status_code=404)
    lim = max(1, min(50, int(limit)))
    obj_ev = ev.object_evidence(art, item, limit=lim)
    impact = ev.change_impact_evidence(art, item, limit=lim)
    label = art.identity.file_name if getattr(art, "identity", None) else uuid
    brief = (ev.format_object_markdown(label, obj_ev) + "\n\n---\n\n"
             + ev.format_change_impact_markdown(label, impact))
    return JSONResponse({"ok": True, "object": obj_ev.to_dict(),
                         "impact": impact.to_dict(), "brief": brief})


@router.get("/library/artifacts/{ref:path}/attention-signals", dependencies=[Depends(require_auth)])
def artifact_attention(ref: str, section: str = "", limit: int = 8) -> JSONResponse:
    """Neutral artifact-WIDE triage signals (same core as the get_artifact_attention_signals MCP
    tool) for the Evidence tab's "what to look at first" section — objects grouped under neutral
    signal kinds, each pointing back to concrete objects + their counts. A reason to look, never a
    verdict. Query-time only, nothing stored."""
    from corpusfm.core import evidence as ev
    art, _uuid, err = _evidence_artifact(ref)
    if err is not None:
        return err
    lim = max(1, min(25, int(limit)))
    res = ev.artifact_attention_signals(art, limit=lim, section=(section or None))
    return JSONResponse({"ok": True, **res.to_dict()})


def _display_file_name(meta) -> str:
    """The real FM file name for display. meta.file_name is the archive DIRECTORY name,
    and addon snapshots carry an internal '_addon' storage suffix to keep them separate
    from the SaveAsXML dir — that suffix is NOT part of the file name, so strip it for
    AddonXML. The .fmp12 suffix (the actual file extension) is always kept."""
    fn = meta.file_name or ""
    if getattr(meta, "artifact_type", "") == "AddonXML" and fn.endswith("_addon"):
        fn = fn[:-len("_addon")]
    return fn


def _resolve_job_name(job_uuid: str) -> str:
    """The current name of the job with this uuid, for DISPLAY only. '' if none (deleted/none)."""
    if not job_uuid:
        return ""
    try:
        from corpusfm.server.jobs.store import find_job_by_id
        job = find_job_by_id(job_uuid)
        return job.name if job is not None else ""
    except Exception:
        return ""


@router.get("/library/artifacts/{ref:path}", dependencies=[Depends(require_auth)])
def artifact_detail(ref: str) -> JSONResponse:
    """Full artifact-record/1 for one artifact (no usage/action history). ``ref`` is a record
    UUID (or a human alias, resolved here — packet 085 U3f).

    ONE record read serves the whole payload (audit #1 FETCH-ONCE): meta, provenance,
    merge-parent refs, and the projected analyzer status all ride the same jor — the
    same-record re-fetches and the common-case blob download are gone."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.storage.artifact_record import meta_from_jor
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return err
    record = _raw_record(backend, uuid)
    if record:
        meta = meta_from_jor(record, uuid=uuid)
    else:
        meta = backend.get_artifact_meta(uuid)   # test doubles without load_record_jor
    if meta is None or not meta.file_name:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    return JSONResponse({
        "uuid":        meta.uuid,
        "name":        meta.name or "",
        "type":        meta.artifact_type,
        "origin":      meta.origin,
        "description": meta.description,
        "memory":      meta.memory,
        # Artifact→Job is a UUID link; the name is resolved live for DISPLAY only (never stored
        # or matched on). Empty if the job was renamed-away/deleted — the uuid link still holds.
        "job_uuid":    getattr(meta, "job_uuid", "") or "",
        "run_uuid":    getattr(meta, "run_uuid", "") or "",
        "job_name":    _resolve_job_name(getattr(meta, "job_uuid", "") or ""),
        "identity": {
            "file_name":  _display_file_name(meta),
            "root_uuid":  meta.root_uuid,
            "fm_version": meta.fm_version,
            "timestamp":  meta.timestamp,
        },
        "provenance":  _provenance_from_record(record),
        "content": {
            "artifact_type": getattr(meta, "artifact_type", ""),   # drives the raw-download button (packet 1034)
            "is_schema":     getattr(meta, "is_schema", False),
            "indexable":     is_indexable_type(getattr(meta, "artifact_type", "")),  # packet 1042
            "has_name_map":  getattr(meta, "has_name_map", False),
            "has_summaries": getattr(meta, "has_summaries", False),
            "summarizable_count": getattr(meta, "summarizable_count", 0),
            "has_source":    getattr(meta, "has_source", False),   # (packet 059)
            "xml_bytes":     getattr(meta, "xml_bytes", 0),
        },
        "merge_parents": _merge_parents(backend, uuid, meta, record=record),
        "analysis": _gap_analysis(backend, uuid, meta, record=record),
    })


def _merge_parent_refs(backend, uuid: str, record: "dict | None" = None) -> list:
    """The two source parents of a MergedXML as [{uuid}] — read from the CHEAP record key stamped
    at merge time. [] if the record carries none.

    Packet 1216 removed the blob fallback: parent identity used to be duplicated into the merged
    artifact as MergeProvenance so it could be recovered from a downloaded blob. A parent link is a
    fact about a record in THIS catalog, and an artifact travels — so the link now lives only on the
    record, for the life of the record. A pre-1216 merge whose record was never stamped shows no
    parents rather than inventing them from a hash."""
    raw = record if record is not None else _raw_record(backend, uuid)
    # One canonical stored key: MergeParentRefs (the PascalCase jor schema; update_record maps the
    # app-side `merge_parent_refs` onto it). Packet 085 U3d retired the lowercase/`MergeParents`
    # dual reads — a fresh-install-only build carries no legacy-shaped records.
    refs = raw.get("MergeParentRefs")
    if isinstance(refs, str):
        import json
        try:
            refs = json.loads(refs)
        except Exception:
            refs = None
    if refs:
        return [r for r in refs if isinstance(r, dict)]
    return []


def _merge_parents(backend, uuid: str, meta, record: "dict | None" = None) -> list:
    """For a MergedXML record, its two source artifacts as {uuid, name, type, exists}, so the
    detail can link back. Each parent is addressed by its RECORD UUID. A parent no longer in the
    catalog comes back exists=False and the link renders inert — including the case where the
    parent was REIMPORTED, which makes it a new record with a new UUID. That is the honest outcome
    of packet 1216's rule, not a regression to work around. [] for non-merged records."""
    if getattr(meta, "artifact_type", "") != "MergedXML":
        return []
    refs = _merge_parent_refs(backend, uuid, record=record)
    if not refs:
        return []

    out = []
    for ref in refs:
        pu = (ref.get("uuid") or "").strip()
        pm = None
        if pu:
            try:
                pm = backend.get_artifact_meta(pu)
            except Exception:
                pm = None
        out.append({
            "uuid":     pu,
            "name":     (pm.name or pm.file_name) if pm else "(unknown)",
            "type":     pm.artifact_type if pm else "",
            "exists":   pm is not None,
        })
    return out


def _gap_analysis(backend, uuid: str, meta, record: "dict | None" = None) -> dict:
    """Gap analysis for the Health tab. The analyzer status (packet 072-D: "analyzed clean" vs
    "analyzer crashed") is PROJECTED into the record at ingest (`analyzer_failed`, audit #1
    NO-BLOB) — so the common clean case (`gap_issues == 0`) never downloads the artifact blob.
    Only a FLAGGED record loads the profile, to recount fresh (absent sections suppressed; the
    real unmapped step IDs / reference types / sections listed)."""
    out = {"gap_issues": meta.gap_issues, "gap_unmapped": list(meta.gap_unmapped or []),
           "gap_step_ids": [], "gap_ref_types": [],
           "clip_gaps": [], "clip_elements_checked_ids": [], "clip_inferred_fm_form": "",
           "is_clip": False,
           "analyzer_incomplete": [], "analysis_ok": True}
    if not getattr(meta, "is_schema", False):
        # packet 1080 §4 — a stored clip carries its OWN gap signal (packet 1079), and an incoming clip
        # is the only FMXML that comes toward us, so it is the first place clip-format drift is
        # observable. It was populated at ingest but only validate_clip ever showed it; someone browsing
        # the catalog met a blank Health tab. Same 072-D honesty as the schema path below: a crashed
        # analyzer must read "couldn't analyze", never a false "Clean".
        if getattr(meta, "artifact_type", "") == ArtifactType.CLIPBOARD_XML.value:
            from corpusfm.artifact.types import GAP_COUNT_VERSION
            out["is_clip"] = True
            stale = int(getattr(meta, "gap_count_version", 0) or 0) < GAP_COUNT_VERSION
            try:
                _art = backend.load_artifact(uuid)
                prof = getattr(_art, "completeness_profile", None)
                if prof is None:
                    raise ValueError("no profile")
                failed = list(getattr(prof, "analyzer_failed", []) or [])
                out["clip_gaps"] = list(getattr(prof, "clip_gaps", []) or [])
                out["clip_elements_checked_ids"] = list(getattr(prof, "clip_elements_checked_ids", []) or [])
                out["clip_inferred_fm_form"] = getattr(prof, "clip_inferred_fm_form", "") or ""
                out["gap_step_ids"] = list(getattr(prof, "unknown_step_ids", []) or [])
                # packet 1121 — a clip record stored BEFORE clip_gaps was persisted reloads with
                # clip_gaps==[]. For a stale-versioned clip whose reloaded profile carries no clip_gaps,
                # re-analyze the raw clip bytes so the Health tab + the healed badge are authoritative — a
                # BOUNDED per-open correction (one blob), not a list-time scan. A profile that DOES carry
                # clip_gaps (new-format) is trusted as-is; only the badge version is re-stamped below.
                if stale and not out["clip_gaps"]:
                    try:
                        from corpusfm.ingestion.clip import _analyze_clip_gaps
                        raw = backend.load_deliverable_xml(uuid)
                        if not raw:
                            # uploaded clips are stored as full Artifacts (store_artifact) — reconstruct the
                            # clip body from the loaded items rather than a deliverable blob.
                            raw = ('<fmxmlsnippet type="FMObjectList">'
                                   + "".join(s.xml for it in _art.items.values() for s in it.xml_sources)
                                   + "</fmxmlsnippet>").encode("utf-8")
                        g = _analyze_clip_gaps(raw)
                        failed = list(g.failed)
                        out["clip_gaps"] = list(g.unknown_enum_values) + list(g.unknown_elements)
                        out["clip_elements_checked_ids"] = [str(i) for i in g.elements_checked_ids]
                        out["clip_inferred_fm_form"] = g.inferred_fm_form or ""
                        out["gap_step_ids"] = list(g.unknown_step_ids)
                    except Exception:
                        pass
                out["analyzer_incomplete"] = failed
                out["analysis_ok"] = not failed
                out["gap_issues"] = len(out["clip_gaps"]) + len(out["gap_step_ids"])
                if stale:
                    # self-heal + stamp the version so re-opening does not reload/re-analyze this blob again.
                    try:
                        backend.update_record(uuid, {"gap_issues": out["gap_issues"],
                                                     "gap_count_version": GAP_COUNT_VERSION})
                        from corpusfm.server.tags_store import invalidate_record_views
                        invalidate_record_views()
                    except Exception:
                        pass
            except Exception:
                # Can't read the profile ⇒ we do NOT know it's clean. Say so rather than imply health.
                out["analyzer_incomplete"] = ["clip_gap_profile_unreadable"]
                out["analysis_ok"] = False
        return out
    raw = record if record is not None else _raw_record(backend, uuid)
    failed = list(raw.get("analyzer_failed", []) or [])
    out["analyzer_incomplete"] = failed
    out["analysis_ok"] = not failed
    if not meta.gap_issues:
        return out
    try:
        prof = getattr(backend.load_artifact(uuid), "completeness_profile", None)
        if prof is not None:
            failed = list(getattr(prof, "analyzer_failed", []) or [])
            out["analyzer_incomplete"] = failed
            out["analysis_ok"] = not failed
            g = prof.actionable_gaps()
            out.update(gap_issues=g["issues"], gap_unmapped=g["sections"],
                       gap_step_ids=g["step_ids"], gap_ref_types=g["reference_types"])
    except Exception:
        pass   # fall back to the stored meta count if the artifact can't be loaded
    return out


@router.patch("/library/artifacts/{ref:path}/name", dependencies=[Depends(require_auth)])
def edit_artifact_name(ref: str, body: dict) -> JSONResponse:
    return _edit_field(ref, "name", body)


@router.patch("/library/artifacts/{ref:path}/description", dependencies=[Depends(require_auth)])
def edit_artifact_description(ref: str, body: dict) -> JSONResponse:
    return _edit_field(ref, "description", body)


@router.patch("/library/artifacts/{ref:path}/memory", dependencies=[Depends(require_auth)])
def edit_artifact_memory(ref: str, body: dict) -> JSONResponse:
    # Memory is normally tool-written (set_artifact_memory / MCP); the detail pop-over lets a
    # human edit it behind an explicit Edit gate.
    return _edit_field(ref, "memory", body)


def _edit_field(ref: str, field: str, body: dict) -> JSONResponse:
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return err
    if backend.get_artifact_meta(uuid) is None:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    value = "" if body is None else body.get(field, "")
    backend.update_record(uuid, {field: value})
    # The catalog list is snapshot-served (audit #2) and name/description/memory show on the
    # card — bust so the edit is visible on the next list read, not after the TTL.
    from corpusfm.server.tags_store import invalidate_record_views
    invalidate_record_views()
    return JSONResponse({"ok": True})


@router.post("/artifact/{ref:path}/reingest", dependencies=[Depends(require_auth)])
async def reingest_artifact_route(ref: str, request: Request) -> JSONResponse:
    """Queue an atomic re-ingest-and-replace for ONE artifact (packet 1062): re-run the canonical
    pipeline on its retained source XML and replace the record IN PLACE (same identity), preserving the
    enrichment it originally had. Eligible only for a SCHEMA artifact WITH retained source; a
    deliverable or a `delete_source`d artifact is refused (re-upload to refresh). Non-blocking — the
    QUEUE drains it."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.server.queue_handlers import enqueue_reingest, reingest_eligible
    from corpusfm.app.web.auth import current_user
    from corpusfm.app.web.routes.api.upload import _offload
    backend = get_backend()
    uuid, err = resolve_ref(backend, ref)
    if err is not None:
        return err
    meta = backend.get_artifact_meta(uuid)
    if meta is None:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    if not reingest_eligible(meta):
        return JSONResponse({"ok": False, "error": (
            "This artifact can't be re-ingested — re-ingest needs a schema artifact with retained "
            "source XML. Re-upload the file to refresh it."
        )}, status_code=409)
    me = current_user(request)
    owner = f"user:{me.username}" if me else "reingest"
    qid = await _offload(enqueue_reingest, backend, uuid, owner=owner)
    if not qid:
        return JSONResponse({"ok": True, "queued": False,
                             "message": "A re-ingest for this artifact is already in the queue."})
    return JSONResponse({"ok": True, "queued": True, "id": qid,
                         "message": "Re-ingest queued — see Queue."})


@router.post("/artifacts/reingest-bulk", dependencies=[Depends(require_auth)])
async def reingest_bulk_route(request: Request) -> JSONResponse:
    """Queue an atomic re-ingest for each ELIGIBLE artifact in a selection (packet 1062). Body:
    ``{"refs": [<ref>, …]}``. Only schema artifacts with retained source are enqueued; deliverables and
    `delete_source`d artifacts are skipped and reported. Returns ``{queued, skipped, already}``. No
    browser wall (server-side enqueue, not a download)."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    from corpusfm.server.queue_handlers import enqueue_reingest, reingest_eligible
    from corpusfm.app.web.auth import current_user
    try:
        body = await request.json()
    except Exception:
        body = {}
    refs = [r for r in (body.get("refs") or []) if isinstance(r, str) and r.strip()]
    if not refs:
        return JSONResponse({"ok": False, "error": "No artifacts selected."}, status_code=400)
    backend = get_backend()
    me = current_user(request)
    owner = f"user:{me.username}" if me else "reingest"

    def _work():
        queued, skipped, already = [], [], []
        for ref in refs:
            uuid, err = resolve_ref(backend, ref)
            if err is not None:
                skipped.append(ref)
                continue
            meta = backend.get_artifact_meta(uuid)
            if not reingest_eligible(meta):
                skipped.append(uuid)
                continue
            qid = enqueue_reingest(backend, uuid, owner=owner)
            (queued if qid else already).append(uuid)
        return {"ok": True, "queued": len(queued), "skipped": len(skipped),
                "already": len(already)}

    from corpusfm.app.web.routes.api.upload import _offload
    return JSONResponse(await _offload(_work))


@router.post("/library/artifacts/{ref:path}/git-export", dependencies=[Depends(require_auth)])
def git_export_artifact(ref: str, body: dict) -> JSONResponse:
    """Per-artifact git export — the Export tab's action. Exports into the credential's per-repo
    local history and pushes to the (possibly overridden) repo. The chosen {registration, repo}
    is persisted as the artifact's own git target so the next export defaults to it."""
    registration_name = "" if body is None else (body.get("registration_name") or "").strip()
    repo = "" if body is None else (body.get("repo") or "").strip()
    if not registration_name:
        return JSONResponse({"ok": False, "error": "registration_name required"}, status_code=400)
    try:
        from corpusfm.app.web.artifact_ref import resolve_ref
        from corpusfm.storage import get_backend
        from corpusfm.core.git_formatter import export_artifact_to_registration, get_registration
        from corpusfm.server import git_targets
        backend = get_backend()
        uuid, err = resolve_ref(backend, ref)
        if err is not None:
            return err
        artifact = backend.load_artifact(uuid)
        # A deploy-key credential's repo is fixed — never honour a caller override.
        try:
            reg = get_registration(registration_name)
            if getattr(reg, "cred_type", "pat") == "deploy_key":
                repo = reg.repo
        except Exception:
            pass
        result = export_artifact_to_registration(artifact, registration_name, repo=repo, push=True)
        git_targets.set_target(uuid, registration_name, repo)
        return JSONResponse({"ok": True, "commit_sha": result.commit_sha,
                             "files_written": result.files_written,
                             "files_deleted": result.files_deleted,
                             "push_ok": result.push_ok, "push_msg": result.push_msg})
    except FileNotFoundError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=404)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/library/artifacts/{ref:path}", dependencies=[Depends(require_auth)])
def delete_artifact(ref: str) -> JSONResponse:
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    try:
        backend = get_backend()
        uuid, err = resolve_ref(backend, ref)
        if err is not None:
            return err
        # The full removal cascade (record + history, tag/lineage cache-bust, vector deindex,
        # latest repromotion) lives in ONE place so retention pruning can't drift from it (pkt 1054).
        from corpusfm.server.artifact_delete import delete_artifact_fully
        if not delete_artifact_fully(backend, uuid):
            return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/library/artifacts/{ref:path}/delete-source",
             dependencies=[Depends(require_auth)])
def delete_artifact_source(ref: str) -> JSONResponse:
    """Packet 059 — the User election: drop the retained compressed source XML to reclaim space. The
    derived artifact is untouched; this is irreversible (no re-upload recovery)."""
    from corpusfm.app.web.artifact_ref import resolve_ref
    from corpusfm.storage import get_backend
    try:
        backend = get_backend()
        uuid, err = resolve_ref(backend, ref)
        if err is not None:
            return err
        meta = backend.get_artifact_meta(uuid)
        if meta is None:
            return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
        removed = bool(backend.delete_source(uuid))
        if removed:
            # has_source rides the snapshot-served catalog rows (audit #2)
            from corpusfm.server.tags_store import invalidate_record_views
            invalidate_record_views()
        return JSONResponse({"ok": True, "removed": removed})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)
