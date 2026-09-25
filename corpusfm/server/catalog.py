"""The Artifact catalog — ONE persistent, dynamically updated, process-wide in-memory model.

Packet 1361-01, final persistent-catalog architecture (2026-09-02 rulings). This supersedes the
immutable-generation design that preceded it *and* every staleness ruling attached to it. What was
discarded, and why it is not coming back:

* **generations** — an immutable snapshot rebuilt in full, published atomically, and aged. It made
  every read a question about freshness and every writer a publisher of a whole new map;
* **generation age / `current` / `stale` / `refreshing` / `initializing`** — four caller-visible
  states describing the read model's own bookkeeping. Ordinary synchronization is not news. The one
  thing a consumer is entitled to know is that a database read genuinely FAILED;
* **leader readers** — the first read past the reconciliation age paid a full three-table read
  inline. A reader now never initiates and never waits for synchronization;
* **apply chunks and per-write full-map copies** — artefacts of publishing a new immutable map.

What replaces them:

**One persistent model.** ``_Catalog`` holds every raw ``STORAGE``, ``TAG`` and ``STORAGELINK``
record, keyed ``(table, uuid)``, for the life of the process. It is built ONCE, synchronously, at
startup — before requests, queue workers, the scheduler or any database-mutating background work may
begin — and from then on it is *updated*, never rebuilt-and-replaced.

**A background validation pass** reconciles memory with the database — every 15 s
(:data:`SYNC_INTERVAL_S`), backing off to 60 s (:data:`SYNC_MAX_INTERVAL_S`) only after three
successful unchanged passes, and requesting an immediate confirmation pass whenever a scan leaves a
deletion candidate (packet 1388-03, :class:`_Synchronizer`). Each entry carries two private flags,
``old`` and ``deleted``, invisible to every reader:

1. one opening memory traversal — if the PREVIOUS pass completed, drop entries still marked ``old``
   (a completed read did not return them, so they are gone); drop entries marked ``deleted``; mark
   every survivor ``old``;
2. complete, paginated, **unfiltered** reads of all three tables. A row for an entry still marked
   ``old`` replaces its raw value only if it changed and clears the mark; a row for an entry that is
   already unmarked lost the race to a newer confirmed application write and is ignored; a row for
   an entry that is absent is added, unmarked, unless a ``deleted`` tombstone covers it;
3. on success there is NO closing sweep — the reap is the next pass's opening traversal. If any
   confirmed write landed during the pass, another complete pass starts immediately, and keeps
   starting until one completes with none;
4. on failure nothing is ever removed. The model and its indexes survive intact behind a failure
   latch, and validation restarts from the beginning.

**Confirmed application writes go straight into the model**, from what the substrate returned, with
incremental index updates and no map copy. They clear ``old``/``deleted`` so a slower scan row
cannot overwrite or resurrect them, and they raise the pass's coalesced ``write_during_pass``
boolean (a boolean, never a counter).

**Raw is retained, always.** Every ``JSONOfRecord`` string is kept exactly as the substrate returned
it. A record whose JSON is unusable participates in no derived index but is never quarantined,
re-reported, rewritten or deleted; a syntactically valid but wrong-shaped document contributes the
fields that ARE usable and is not discarded for the ones that are not. A later confirmed write
replaces the raw value and the parse/index state rebuilds itself. There is no ``IsValidJSON``
projection and no narrowed read: the synchronization read asks for every row of every table, so a
structurally bad record needs no escape hatch to stay reachable.

**When parsing actually happens, stated precisely** (corrected 2026-09-02 — the docstring used to say
"parsing is lazy" without qualification, which is true of the artifact projection and NOT of the raw
document):

* the raw JSON is parsed **EAGERLY, ONCE, when a raw value enters or changes** — a scan row that
  differs, or a confirmed write. It has to be: the derived indexes are built from the document, so
  there is nothing to defer. The parse is performed OFF the model lock and swapped in, which is what
  keeps an eager parse cheap;
* its outcome — success **or failure** — is cached per raw value, so a malformed record costs one
  failed parse and is never retried;
* **an unchanged raw is never reparsed.** A scan row byte-identical to memory keeps the existing
  entry, its cached document and its projection. Measured: a steady pass over ~4,100 rows costs
  ~1 ms and rebuilds nothing;
* the **artifact/UI projection** (``record_from_jor`` → ``ArtifactMeta``) stays genuinely LAZY and
  cached — built the first time a reader asks for that record and not before.

**The only condition a consumer sees is an actual failed database read.** It sets a latch, the
catalog-dependent UI freezes and explains itself, the records stay intact behind the freeze, and the
latch clears only after one complete successful pass.

**Memory and scale — the accepted disposition (developer, 2026-09-02).** The model holds every row of
three tables for the life of the process and there is **no cap, no eviction, no partial catalog and
no fold redesign**. Measured on this development machine at 2,000 STORAGE + 2,130 TAG/STORAGELINK
records carrying ~5 KB icons: 12.3 MB of raw JSON resident as ~38 MB, an initial build of 0.017 s, a
steady pass of ~1 ms, a worst-case all-changed pass of 0.020 s, and reader latency of p50 0.28 ms
(max 2.0 ms) while a pass streamed. That is already beyond expected user scale, so nothing is
optimized against it. Live private validation will measure the real FileMaker scan duration, reader
latency and memory on a box; ``PassStats`` records the numbers and the MCP ``get_health`` tool
surfaces them.

Nothing here is written to disk, SQLite, Redis or a cache table; FileMaker remains the sole durable
authority. No secret, credential, container blob, artifact body or source XML enters the model — the
admitted payload is exactly ``UUID`` + ``JSONOfRecord`` (``icon_b64`` rides inside that document and
is admitted with it).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Optional

logger = logging.getLogger(__name__)

# ── The synchronization cycle ─────────────────────────────────────────────────────────────────────
# INTERNAL, not an administrator setting: there is no operator who can price this number. It is a
# module attribute rather than a constant so live measurement on a real box can guide reducing it
# (the healthy target for one complete three-table scan is ~2 s or less) and so a test can drive the
# synchronizer without sleeping. Nothing in the product reads it from configuration.
SYNC_INTERVAL_S = 15.0
# Packet 1388-03: the IDLE ceiling. After this many consecutive successful passes that changed
# nothing, the cycle waits SYNC_MAX_INTERVAL_S instead; any change, failure, concurrent or
# unpublishable write, deletion candidate or resume returns it to SYNC_INTERVAL_S. Same status as
# the fast interval: internal, never configuration.
SYNC_MAX_INTERVAL_S = 60.0
SYNC_BACKOFF_AFTER = 3
_SYNC_JOIN_TIMEOUT_S = 5.0
# Test seams for one synchronizer generation: an injected monotonic clock, an injected
# `wait(condition, timeout)`, and a callback run after each pass and before the cadence decision.
_sync_clock = None
_sync_wait = None
_sync_on_pass_done = None

# ── The required read boundary ────────────────────────────────────────────────────────────────────
TABLE_STORAGE = "STORAGE"
TABLE_TAG = "TAG"
TABLE_LINK = "STORAGELINK"
REQUIRED_TABLES = (TABLE_STORAGE, TABLE_TAG, TABLE_LINK)

# STORAGELINK is the GENERIC current-state relationship surface. Every link row is synchronized and
# retained; only these two Types are INTERPRETED, and every other one is kept raw and ignored.
USER_TAG_LINK = "User Tag"
LATEST_LINK = "Latest Artifact"

# A write response missing UUID/JSONOfRecord is a real deployment signal, but it can arrive on every
# write. Warn at most this often.
_WRITE_WARN_INTERVAL_S = 60.0


def _now() -> float:
    """The monotonic clock every duration reads. Named so a test can drive it without patching the
    global `time` module out from under the interpreter."""
    return time.monotonic()


def _freeze(value):
    """Recursively immutable view of a parsed JSONOfRecord document.

    The retained payload must not be mutable by a request. Mappings become ``MappingProxyType`` and
    sequences become tuples, which every consumer path already tolerates: ``record_from_jor`` /
    ``meta_from_jor`` only ``.get()`` and copy out (``list(...)`` on the list-valued keys, so a tuple
    arrives as a fresh list). Built OUTSIDE the model lock, always."""
    if isinstance(value, dict):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _parse_raw(raw):
    """The opaque raw value as a JSON object, or ``None`` when it does not yield one.

    Wider than "json.loads threw", deliberately: valid JSON that is not an object (``[]``, ``null``,
    ``42``, a bare string) is just as unusable as a syntax error, and collapsing either into ``{}``
    would turn a malformed record into an empty-but-valid one."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def _text(value) -> str:
    """A per-FIELD type check, and deliberately only that.

    A syntactically valid but wrong-shaped document is not discarded: each index input is validated
    independently, so a bad optional field yields the empty string and costs that record its place in
    ONE index while every other field it does carry still contributes (ruling 4)."""
    return value if isinstance(value, str) else ""


_UNSET = object()


class _Entry:
    """One retained raw record: ``(table, uuid)`` + the ``JSONOfRecord`` value exactly as returned.

    Externally immutable in everything a reader can see. ``old`` and ``deleted`` are the validation
    pass's private bookkeeping and are never exposed; ``idx`` is the record's own derived index
    membership, kept so a removal is O(1) and needs no re-parse.

    The raw JSON is parsed ONCE per raw value and the outcome — success or failure — is cached. The
    parse is EAGER on the way in (the caller performs it OUTSIDE the model lock before the entry is
    swapped in) because the derived indexes are built from the document; what stays lazy is
    :meth:`projection`, the artifact/UI shape a reader may never ask for. An UNCHANGED raw keeps its
    entry and therefore both caches. ``document()`` answers ``None`` when the raw value has no usable
    object; the entry is retained regardless, because it exists in the database and saying otherwise
    would be a lie the catalog is not entitled to tell.
    """

    __slots__ = ("table", "uuid", "raw", "old", "deleted", "idx",
                 "_doc", "_projection", "_lock")

    def __init__(self, table: str, uuid: str, raw) -> None:
        self.table = table
        self.uuid = uuid
        self.raw = raw
        self.old = False
        self.deleted = False
        self.idx: dict = {}
        self._doc = _UNSET
        self._projection = _UNSET
        self._lock = threading.Lock()

    # -- lazy, cached parse ----------------------------------------------------------------------

    def document(self):
        """The parsed, recursively frozen document, or ``None`` when the raw value is unusable.

        Parsed at most once per raw value; the failure is cached exactly like the success. Callers
        that are about to index an entry call this BEFORE taking the model lock — the parse is eager
        in practice, and deliberately so."""
        if self._doc is _UNSET:
            with self._lock:
                if self._doc is _UNSET:
                    parsed = _parse_raw(self.raw)
                    self._doc = _freeze(parsed) if parsed is not None else None
        return self._doc

    @property
    def parsed(self) -> bool:
        return self.document() is not None

    @property
    def raw_bytes(self) -> int:
        return len(self.raw) if isinstance(self.raw, str) else 0

    @property
    def ident(self) -> tuple:
        return (self.table, self.uuid)

    def projection(self) -> Optional[dict]:
        """The ``record_from_jor`` lineage/identity projection — derived, disposable, built at most
        once per raw value. ``None`` when the document is unusable."""
        if self._projection is _UNSET:
            doc = self.document()
            with self._lock:
                if self._projection is _UNSET:
                    if doc is None:
                        self._projection = None
                    else:
                        from corpusfm.storage.artifact_record import record_from_jor
                        try:
                            self._projection = record_from_jor(self.uuid, doc)
                        except Exception:
                            logger.debug("catalog: projection failed for %s/%s",
                                         self.table, self.uuid, exc_info=True)
                            self._projection = None
        return self._projection

    def __repr__(self) -> str:            # pragma: no cover - diagnostics only
        return f"_Entry({self.table}/{self.uuid}, {self.raw_bytes}B, ok={self.parsed})"


@dataclass(frozen=True)
class PassStats:
    """What one validation pass cost. Identities, counts and sizes only — never a JSON value, a
    response body, a credential or a secret."""

    ok: bool = False
    duration_s: float = 0.0
    counts: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))
    raw_bytes: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))
    added: int = 0
    replaced: int = 0
    reaped: int = 0
    # Entries a COMPLETE scan did not return and that therefore stay marked `old`: the first half
    # of the two-pass deletion confirmation, counted from memory after the scan (packet 1388-03).
    missing_candidates: int = 0
    at_utc: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {"ok": self.ok,
                "duration_s": round(self.duration_s, 4),
                "counts": dict(self.counts),
                "raw_bytes": dict(self.raw_bytes),
                "added": self.added,
                "replaced": self.replaced,
                "reaped": self.reaped,
                "missing_candidates": self.missing_candidates,
                "at_utc": self.at_utc,
                "error": self.error}


class _Index:
    """Every derived view of the persistent model, maintained INCREMENTALLY.

    An entry's membership is derived once, when its raw value is added or replaced, and recorded on
    the entry itself (``entry.idx``) so removal costs no second parse. Marking an entry ``old``
    changes nothing here — ``old`` is a validation-pass concern, and a record that is merely awaiting
    confirmation is still a record. A ``deleted`` entry leaves every index immediately.

    Fault containment, stated once: a record whose raw JSON yields no object appears in no derived
    index. It is not removed, not repaired and not reported — it stays a retained raw record.

    Two derived views are CACHED rather than maintained: the newest-first order and the latest-set.
    Both are pure functions of state this class already keys, both are wanted only by a reader, and
    both are invalidated in O(1) by the writes that could change them.
    """

    __slots__ = ("storage", "by_type", "by_origin", "by_job", "by_run", "by_root", "by_file",
                 "stamps", "search_text", "name_text",
                 "tag_names", "links_by_tag", "links_by_storage", "user_links",
                 "promo_by_job", "promo_link_job",
                 "_order", "_latest", "_assigned", "_groups")

    def __init__(self) -> None:
        self.storage: dict = {}            # uuid -> _Entry  (VISIBLE, parsed STORAGE only)
        self.by_type: dict = {}            # type.lower() -> set(uuid)
        self.by_origin: dict = {}
        self.by_job: dict = {}             # job uuid ("" for job-less) -> set(uuid)
        self.by_run: dict = {}
        self.by_root: dict = {}
        self.by_file: dict = {}
        self.stamps: dict = {}             # uuid -> ArtifactTimestamp
        self.search_text: dict = {}
        self.name_text: dict = {}
        self.tag_names: dict = {}          # tag record uuid -> name
        self.links_by_tag: dict = {}       # tag uuid -> set(link uuid)
        self.links_by_storage: dict = {}   # storage uuid -> set(link uuid)
        self.user_links: dict = {}         # link uuid -> (tag uuid, storage uuid)
        self.promo_by_job: dict = {}       # job uuid -> {link uuid: target uuid}
        self.promo_link_job: dict = {}     # link uuid -> job uuid
        self._order = None                 # cached newest-first uuid tuple
        self._latest = None                # cached frozenset of latest uuids
        self._assigned = None              # cached {storage uuid: (tag, …)}
        self._groups = None                # cached {tag name: (storage uuid, …)}

    # -- cache invalidation ----------------------------------------------------------------------

    def _drop_order(self) -> None:
        self._order = None

    def _drop_latest(self) -> None:
        self._latest = None

    def _drop_tags(self) -> None:
        self._assigned = None
        self._groups = None

    # -- membership ------------------------------------------------------------------------------

    def add(self, entry: _Entry) -> None:
        """Derive and record this entry's index membership. The document parse has already happened
        (off-lock, by the caller); this is pure dict work."""
        doc = entry.document()
        if doc is None:
            return                                  # retained raw, in no derived index
        table = entry.table
        if table == TABLE_STORAGE:
            self._add_storage(entry, doc)
        elif table == TABLE_TAG:
            self._add_tag(entry, doc)
        elif table == TABLE_LINK:
            self._add_link(entry, doc)

    def remove(self, entry: _Entry) -> None:
        """Undo exactly what :meth:`add` recorded for this entry."""
        idx = entry.idx
        if not idx:
            return
        kind = idx.get("kind")
        if kind == TABLE_STORAGE:
            self._remove_storage(entry, idx)
        elif kind == TABLE_TAG:
            self._remove_tag(entry, idx)
        elif kind == TABLE_LINK:
            self._remove_link(entry, idx)
        entry.idx = {}

    # -- STORAGE ---------------------------------------------------------------------------------

    def _add_storage(self, entry: _Entry, doc) -> None:
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        atype = _text(doc.get("Type"))
        if atype not in VISIBLE_TYPES:
            return                                  # retained raw, outside the catalog's own fence
        u = entry.uuid
        origin = _text(doc.get("Origin")).lower() or "import"
        job = _text(doc.get("UUIDJob"))
        run = _text(doc.get("RunUUID"))
        root = _text(doc.get("RootUUID"))
        fname = _text(doc.get("FileName"))
        ts = _text(doc.get("ArtifactTimestamp"))
        # `meta_from_jor` falls back to the TIMESTAMP when there is no PrimaryName, and the enriched
        # row's `name` is that meta value — so the search text carries the same fallback or an
        # index-narrowed request would drop a row the un-narrowed filter used to return.
        pname = _text(doc.get("PrimaryName")) or ts

        self.storage[u] = entry
        self.by_type.setdefault(atype.lower(), set()).add(u)
        self.by_origin.setdefault(origin, set()).add(u)
        self.by_job.setdefault(job, set()).add(u)
        if run:
            self.by_run.setdefault(run, set()).add(u)
        if root:
            self.by_root.setdefault(root, set()).add(u)
        if fname:
            self.by_file.setdefault(fname, set()).add(u)
        self.stamps[u] = ts
        self.name_text[u] = f"{pname}\n{fname}".lower()
        self.search_text[u] = "\n".join(
            (fname, pname, _text(doc.get("Description")), _text(doc.get("Memory")))).lower()
        entry.idx = {"kind": TABLE_STORAGE, "type": atype.lower(), "origin": origin,
                     "job": job, "run": run, "root": root, "file": fname}
        self._drop_order()
        self._drop_latest()
        # A record entering or leaving visibility changes which of its links are live memberships.
        if self.links_by_storage.get(u):
            self._drop_tags()

    def _remove_storage(self, entry: _Entry, idx: dict) -> None:
        u = entry.uuid
        if self.storage.get(u) is entry:
            self.storage.pop(u, None)
        _discard(self.by_type, idx.get("type"), u)
        _discard(self.by_origin, idx.get("origin"), u)
        _discard(self.by_job, idx.get("job"), u)
        _discard(self.by_run, idx.get("run"), u)
        _discard(self.by_root, idx.get("root"), u)
        _discard(self.by_file, idx.get("file"), u)
        self.stamps.pop(u, None)
        self.name_text.pop(u, None)
        self.search_text.pop(u, None)
        self._drop_order()
        self._drop_latest()
        if self.links_by_storage.get(u):
            self._drop_tags()

    # -- TAG -------------------------------------------------------------------------------------

    def _add_tag(self, entry: _Entry, doc) -> None:
        name = _text(doc.get("Name")).strip().lower()
        if not name:
            return                                  # an unnamed TAG row names nothing
        self.tag_names[entry.uuid] = name
        entry.idx = {"kind": TABLE_TAG, "name": name}
        self._drop_tags()

    def _remove_tag(self, entry: _Entry, idx: dict) -> None:
        self.tag_names.pop(entry.uuid, None)
        self._drop_tags()

    # -- STORAGELINK -----------------------------------------------------------------------------

    def _add_link(self, entry: _Entry, doc) -> None:
        ltype = _text(doc.get("Type"))
        if ltype == USER_TAG_LINK:
            tag_uuid = _text(doc.get("UUIDTag"))
            art_uuid = _text(doc.get("UUIDStorage"))
            self.user_links[entry.uuid] = (tag_uuid, art_uuid)
            if tag_uuid:
                self.links_by_tag.setdefault(tag_uuid, set()).add(entry.uuid)
            if art_uuid:
                self.links_by_storage.setdefault(art_uuid, set()).add(entry.uuid)
            entry.idx = {"kind": TABLE_LINK, "link": USER_TAG_LINK,
                         "tag": tag_uuid, "art": art_uuid}
            self._drop_tags()
        elif ltype == LATEST_LINK:
            job = _text(doc.get("UUIDJob"))
            if not job:
                return
            target = _text(doc.get("UUIDStorage"))
            self.promo_by_job.setdefault(job, {})[entry.uuid] = target
            self.promo_link_job[entry.uuid] = job
            entry.idx = {"kind": TABLE_LINK, "link": LATEST_LINK, "job": job}
            self._drop_latest()
        # Any other link type is retained raw and interpreted by nothing here.

    def _remove_link(self, entry: _Entry, idx: dict) -> None:
        if idx.get("link") == USER_TAG_LINK:
            self.user_links.pop(entry.uuid, None)
            _discard(self.links_by_tag, idx.get("tag"), entry.uuid)
            _discard(self.links_by_storage, idx.get("art"), entry.uuid)
            self._drop_tags()
        elif idx.get("link") == LATEST_LINK:
            job = idx.get("job") or ""
            bucket = self.promo_by_job.get(job)
            if bucket is not None:
                bucket.pop(entry.uuid, None)
                if not bucket:
                    self.promo_by_job.pop(job, None)
            self.promo_link_job.pop(entry.uuid, None)
            self._drop_latest()

    # -- derived, cached -------------------------------------------------------------------------

    def order(self) -> tuple:
        """Every visible record's uuid, newest-first by ``ArtifactTimestamp``."""
        if self._order is None:
            self._order = tuple(sorted(self.storage,
                                       key=lambda u: (self.stamps.get(u, ""), u), reverse=True))
        return self._order

    def promotions(self) -> dict:
        """``{job uuid: target uuid}``. A lineage carrying more than one promotion row is a repair
        question for ``server.latest`` at startup, not a read-time verdict: pick deterministically
        and carry on."""
        out = {}
        for job, bucket in self.promo_by_job.items():
            target = ""
            for t in bucket.values():
                if t and t > target:
                    target = t
            out[job] = target
        return out

    def latest(self) -> frozenset:
        """The uuids that read as current.

        A job-less artifact is latest; a promotion resolving to a live artifact makes exactly that
        one latest; a promotion that is missing, blank or unresolvable makes the WHOLE lineage
        temporarily latest, because "we cannot tell which one is current" must never render as
        "none of them"."""
        if self._latest is None:
            promos = self.promotions()
            out: set = set()
            for job, members in self.by_job.items():
                if not job:
                    out |= members
                    continue
                target = promos.get(job, "")
                if target and target in self.storage:
                    out.add(target)
                else:
                    out |= members
            self._latest = frozenset(out)
        return self._latest

    def _fold_tags(self) -> None:
        """The user-tag membership fold. A link is an active membership only when BOTH endpoints
        resolve — a named tag row and a visible STORAGE record. A link that does not resolve is
        simply not a membership fact; it is neither reported nor repaired from here."""
        assigned: dict = {}
        groups: dict = {name: set() for name in self.tag_names.values()}
        for tag_uuid, art_uuid in self.user_links.values():
            name = self.tag_names.get(tag_uuid, "")
            if not name or art_uuid not in self.storage:
                continue
            assigned.setdefault(art_uuid, set()).add(name)
            groups.setdefault(name, set()).add(art_uuid)
        self._assigned = {u: tuple(sorted(ns)) for u, ns in assigned.items()}
        self._groups = {n: tuple(sorted(ms)) for n, ms in groups.items()}

    def assigned(self) -> dict:
        if self._assigned is None:
            self._fold_tags()
        return self._assigned

    def groups(self) -> dict:
        if self._groups is None:
            self._fold_tags()
        return self._groups


def _discard(mapping: dict, key, value) -> None:
    """Drop ``value`` from ``mapping[key]``, dropping an emptied bucket with it."""
    if key is None:
        return
    bucket = mapping.get(key)
    if bucket is None:
        return
    bucket.discard(value)
    if not bucket:
        mapping.pop(key, None)


def _copy_record(record: dict, *, is_latest: bool) -> dict:
    """A derived record safe to hand to one caller: the dict, plus a fresh ``ArtifactMeta`` whose
    mutable fields are copied, plus the ``is_latest`` verdict the promotion index owns.

    The copy reaches the NESTED level on purpose. A shallow ``dict(r)`` still handed every consumer
    the same mutable ``ArtifactMeta``, so one consumer touching ``meta.description`` or appending to
    ``meta.gap_unmapped`` would alter what a LATER read returns."""
    from dataclasses import fields as _fields
    from dataclasses import replace as _replace

    out = dict(record)
    out["is_latest"] = is_latest
    meta = out.get("meta")
    if meta is not None and hasattr(meta, "__dataclass_fields__"):
        mutable = {}
        for f in _fields(meta):
            v = getattr(meta, f.name, None)
            if isinstance(v, list):
                mutable[f.name] = list(v)
            elif isinstance(v, dict):
                mutable[f.name] = dict(v)
            elif isinstance(v, set):
                mutable[f.name] = set(v)
        out["meta"] = _replace(meta, **mutable) if mutable else _replace(meta)
    return out


class CatalogView:
    """One consumer's handle on the persistent model.

    It is NOT a snapshot and carries no freshness vocabulary: the model behind it is the same one
    every other reader sees, and reading it never initiates or waits for synchronization. The single
    condition it exposes is :attr:`failed` — an actual incomplete or failed database read, latched
    until one complete pass succeeds.

    Every collection handed out is a per-read copy or an immutable value, so a consumer mutating what
    it was given can never change catalog state.
    """

    __slots__ = ("_cat", "_failed")

    def __init__(self, catalog: "_Catalog", failed: bool) -> None:
        self._cat = catalog
        self._failed = failed

    # -- the one exposed condition ---------------------------------------------------------------

    @property
    def failed(self) -> bool:
        """True only while a database read genuinely failed and has not yet been recovered."""
        return self._failed

    @property
    def servable(self) -> bool:
        """The model is always readable; this answers "should a surface RENDER these rows".

        It is False only under the failure latch, where the honest answer is "we cannot tell you"
        rather than a set of rows nobody can vouch for."""
        return not self._failed

    # -- whole-catalog views ---------------------------------------------------------------------

    @property
    def records(self) -> list:
        """Every visible, projectable STORAGE record's derived projection, newest-first."""
        return self.select()

    @property
    def has_records(self) -> bool:
        with self._cat.lock:
            return bool(self._cat.index.storage)

    @property
    def file_names(self) -> list:
        with self._cat.lock:
            return sorted(self._cat.index.by_file)

    @property
    def tags(self) -> dict:
        """``{record_uuid: [tag, …]}`` — active user-tag membership, strictly per record."""
        with self._cat.lock:
            return {u: list(ns) for u, ns in self._cat.index.assigned().items()}

    @property
    def tag_names(self) -> list:
        """Every USER tag name, INCLUDING named-but-empty tags (a TAG row with no live link)."""
        with self._cat.lock:
            return sorted(self._cat.index.groups())

    @property
    def tag_groups(self) -> dict:
        """``{tag_name: [record_uuid, …]}`` — includes named-but-empty tags, with an empty list."""
        with self._cat.lock:
            return {n: list(ms) for n, ms in self._cat.index.groups().items()}

    @property
    def latest_uuids(self) -> frozenset:
        with self._cat.lock:
            return self._cat.index.latest()

    def tags_for(self, uuid: str) -> list:
        with self._cat.lock:
            return list(self._cat.index.assigned().get(uuid, ()))

    def is_latest(self, uuid: str) -> bool:
        with self._cat.lock:
            return uuid in self._cat.index.latest()

    def promotion_target(self, job_uuid: str) -> str:
        with self._cat.lock:
            return self._cat.index.promotions().get(job_uuid, "")

    # -- narrowing: intersect identities, THEN copy ------------------------------------------------

    def candidate_uuids(self, *, file: str = "", job_uuid: str = "", type: str = "",
                        origin: str = "", root_uuid: str = "", run_uuid: str = "",
                        tag: str = "", latest_only: bool = False,
                        search: str = "", exclude_uuid: str = "") -> set:
        """The identities matching every supplied narrowing.

        Each named argument is an INDEX lookup and the sets are intersected before a single record is
        projected or copied, so a filtered request costs what its result costs rather than what the
        catalog costs."""
        idx = self._cat.index
        out: Optional[set] = None

        def _narrow(ids) -> None:
            nonlocal out
            out = set(ids) if out is None else (out & set(ids))

        with self._cat.lock:
            if file:
                _narrow(idx.by_file.get(file, ()))
            if job_uuid:
                _narrow(idx.by_job.get(job_uuid, ()))
            if type:
                _narrow(idx.by_type.get(type.lower(), ()))
            if origin:
                _narrow(idx.by_origin.get(origin.lower(), ()))
            if root_uuid:
                _narrow(idx.by_root.get(root_uuid, ()))
            if run_uuid:
                _narrow(idx.by_run.get(run_uuid, ()))
            if tag:
                _narrow(idx.groups().get(tag.lower(), ()))
            if latest_only:
                _narrow(idx.latest())
            if out is None:
                out = set(idx.storage)
            if search:
                needle = search.strip().lower()
                if needle:
                    out = {u for u in out if needle in idx.search_text.get(u, "")}
        if exclude_uuid:
            out.discard(exclude_uuid)
        return out

    def order_of(self, uuids) -> list:
        """``uuids`` in the model's newest-first timestamp order."""
        want = set(uuids)
        with self._cat.lock:
            order = self._cat.index.order()
        return [u for u in order if u in want]

    def projections_of(self, uuids) -> list:
        """Per-read projection copies for ``uuids``, newest-first. Unprojectable records are
        omitted; nothing else is."""
        want = set(uuids)
        with self._cat.lock:
            order = self._cat.index.order()
            entries = [self._cat.index.storage.get(u) for u in order if u in want]
            latest = self._cat.index.latest()
        # Projection (and therefore the lazy parse) happens OUTSIDE the model lock.
        out = []
        for e in entries:
            if e is None:
                continue
            proj = e.projection()
            if proj is not None:
                out.append(_copy_record(proj, is_latest=e.uuid in latest))
        return out

    def select(self, **narrowing) -> list:
        """``candidate_uuids`` + ``projections_of`` — the one call a surface normally wants."""
        return self.projections_of(self.candidate_uuids(**narrowing))

    def files_of(self, uuids) -> list:
        want = set(uuids)
        with self._cat.lock:
            return sorted(f for f, members in self._cat.index.by_file.items() if members & want)

    def matches_name(self, uuid: str, needle: str) -> bool:
        """Substring match on the picker's narrower search surface (primary name + file name)."""
        with self._cat.lock:
            return needle in self._cat.index.name_text.get(uuid, "")

    def timestamp(self, uuid: str) -> str:
        with self._cat.lock:
            return self._cat.index.stamps.get(uuid, "")

    # -- single-record lookups -------------------------------------------------------------------

    def projection(self, uuid: str) -> Optional[dict]:
        """ONE visible STORAGE record's derived projection, as a per-read copy. ``None`` when the
        catalog does not hold it, or holds it unprojectably."""
        with self._cat.lock:
            entry = self._cat.index.storage.get(uuid)
            latest = self._cat.index.latest()
        if entry is None:
            return None
        proj = entry.projection()
        return None if proj is None else _copy_record(proj, is_latest=uuid in latest)

    def same_root(self, root_uuid: str, *, exclude_uuid: str = "") -> list:
        """Every OTHER visible record sharing this FM file's root UUID, as per-read copies.

        An empty ``root_uuid`` matches nothing rather than everything — a record with no root has no
        lineage, and a missing key must never widen into the whole catalog."""
        if not root_uuid:
            return []
        return self.projections_of(
            self.candidate_uuids(root_uuid=root_uuid, exclude_uuid=exclude_uuid))

    def document(self, table: str, uuid: str):
        """The retained record's parsed document, or ``None`` when the catalog does not hold it or
        cannot parse it. Raw retention is a property of the model, not of this answer."""
        with self._cat.lock:
            entry = self._cat.entries.get((table, uuid))
            if entry is not None and entry.deleted:
                entry = None
        return None if entry is None else entry.document()

    def raw(self, table: str, uuid: str):
        """The retained raw ``JSONOfRecord`` value exactly as the substrate returned it, or ``None``
        when the catalog does not hold the record. A malformed document still answers here — that is
        what "retained" means."""
        with self._cat.lock:
            entry = self._cat.entries.get((table, uuid))
            if entry is not None and entry.deleted:
                entry = None
        return None if entry is None else entry.raw


def store_key(backend) -> tuple:
    """Store identity. One model per store, so a re-pointed backend (and parallel test backends)
    never read one another's records."""
    return (type(backend).__name__,
            str(getattr(backend, "archive_dir", "") or ""),
            str(getattr(backend, "host", "") or ""),
            str(getattr(backend, "database", "") or ""))


class _Catalog:
    """The one persistent model, plus the validation pass that keeps it honest.

    ``lock`` is a SHORT state lock. It guards ``entries`` and ``index`` and is **never** held across
    substrate I/O, across a JSON parse, or across a projection build.
    """

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.entries: dict = {}
        self.index = _Index()
        self.key: Optional[tuple] = None
        self.built = False
        self._failed = False               # the failure latch
        self._last_pass_ok = False
        self._pass_active = False
        self._write_during_pass = False
        self._pass_lock = threading.Lock()  # one validation pass at a time
        self._build_lock = threading.Lock()
        self._stats = PassStats()
        self._sync: Optional["_Synchronizer"] = None
        self._last_write_warn_at = 0.0

    # ── reading ──────────────────────────────────────────────────────────────────────────────────

    def _view_now(self, backend) -> CatalogView:
        """The persistent model for one consumer — memory only, under the readiness gate.

        A reader NEVER constructs the model and never waits for a pass. The request-triggered build
        fallback this used to carry is REMOVED (packet 1361-01, availability correction): it made a
        request thread the recovery mechanism on the exact failure the design exists to expose, and
        a late build that succeeded left the process serving a model with no synchronizer behind it.
        Construction is now deliberate — the boot path, the recovery coordinator, and a test that
        asks for it — and nothing else.

        The condition a reader sees is the PROCESS state, not the catalog's private bookkeeping: a
        paused process reports unavailable even when the retained records are intact, because while
        paused CORPUSfm does not operate from memory it cannot vouch for.
        """
        from corpusfm.server import availability
        key = store_key(backend)
        paused = not availability.is_open()
        with self.lock:
            if self.built and self.key == key:
                return CatalogView(self, self._failed or paused)
            return CatalogView(_EMPTY_MODEL, True)

    def view(self, backend) -> CatalogView:
        """The persistent model, for one consumer. Never constructs, never reads, never waits."""
        return self._view_now(backend)

    def peek(self, backend) -> CatalogView:
        """The same memory-only read, under the name a non-catalog surface asks for it by.

        A download or a bundle uses this: it is not a catalog surface, it is a best-effort tag
        round-trip riding beside one, and it must never provoke a read. It once differed from
        ``view`` by lacking the construction fallback; the fallback is gone from both, and the name
        is kept because a caller that must never provoke a read should say so at the call site."""
        return self._view_now(backend)

    def failed(self) -> bool:
        with self.lock:
            return self._failed

    def is_built(self, backend) -> bool:
        with self.lock:
            return bool(self.built and self.key == store_key(backend))

    # ── construction and synchronization ─────────────────────────────────────────────────────────

    def build_initial(self, backend) -> dict:
        """The BOOT build: one complete validation, synchronously, idempotent for a given store.

        Returns the pass result. ``ok`` False means the initial complete read did not succeed, so the
        process stays PAUSED — which is what holds the queue workers, every database-mutating
        background task and every database-dependent surface off the box until recovery succeeds."""
        with self.lock:
            if self.built and self.key == store_key(backend):
                return self._stats.as_dict()
        return self.validate_now(backend)

    def validate_now(self, backend) -> dict:
        """ONE complete validation, marking the model built and OPENING the readiness gate on success.

        The boot build and every recovery attempt are the SAME operation (packet 1361-01, availability
        correction): startup loss and runtime loss share one state machine, so there is one place that
        decides "the database answered completely" and one place that reopens the process. It does not
        rerun the boot-once prerequisite MUTATIONS — those are conversions, not recovery work.
        """
        from corpusfm.server import availability
        key = store_key(backend)
        with self._build_lock:
            with self.lock:
                if self.key != key:
                    # A different store: this process is being re-pointed (tests, a CLI switching
                    # archives). Start from nothing rather than mixing two corpora.
                    self.entries = {}
                    self.index = _Index()
                    self.key = key
                    self.built = False
                    self._last_pass_ok = False
                    self._failed = False
            res = self.run_validation_pass(backend)
            with self.lock:
                if res.get("ok"):
                    self.built = True
        if res.get("ok"):
            availability.open_on_complete_validation()
        return res

    def run_validation_pass(self, backend) -> dict:
        """ONE complete validation pass, plus the immediate follow-ups a concurrent write demands.

        Serialized by ``_pass_lock``: one pass at a time, whatever calls it (the synchronizer, the
        startup build, the recovery coordinator, a test). Never raises — a failed pass latches and
        returns.

        A complete success on a BUILT model reopens the readiness gate. That is what makes runtime
        loss and startup loss one state machine: whichever component happens to complete the first
        good pass — the synchronizer that kept running, or the recovery coordinator — is the one that
        resumes the process, and the gate's own edge guard makes it happen exactly once."""
        with self._pass_lock:
            res = self._one_pass(backend)
            follow_up = False
            # "If any confirmed application write occurred during the pass, immediately begin one
            # additional complete pass" — and keep going until one completes with none.
            while res.get("ok") and res.get("write_during_pass"):
                follow_up = True
                res = self._one_pass(backend)
        # The final pass always reports `write_during_pass` False on success, so the CALL-level fact
        # the cadence needs is accumulated here rather than inferred from it (packet 1388-03).
        res["follow_up_due_to_write"] = follow_up
        if res.get("ok"):
            with self.lock:
                built = self.built
            if built:
                from corpusfm.server import availability
                availability.open_on_complete_validation()
        return res

    def _one_pass(self, backend) -> dict:
        started = _now()
        counts: dict = {}
        raw_bytes: dict = {}
        added = replaced = 0
        # ── 1. the ONE opening memory traversal ───────────────────────────────────────────────────
        reaped = self._open_pass()
        engine = getattr(backend, "engine", None)
        if engine is None:
            return self._fail_pass(started, counts, raw_bytes, added, replaced, reaped,
                                   "catalog synchronization requires a storage engine")
        # ── 2. complete, paginated, UNFILTERED reads of all three tables ──────────────────────────
        try:
            for table in REQUIRED_TABLES:
                n = 0
                nbytes = 0
                for uuid, raw in engine.iter_raw(table):
                    if not uuid:
                        continue
                    n += 1
                    nbytes += len(raw) if isinstance(raw, str) else 0
                    a, r = self._apply_scan_row(table, uuid, raw)
                    added += a
                    replaced += r
                counts[table] = n
                raw_bytes[table] = nbytes
        except Exception as exc:                                    # noqa: BLE001
            logger.warning("catalog validation pass failed on a database read (%s); the persistent "
                           "records are kept and validation restarts from the beginning",
                           type(exc).__name__, exc_info=True)
            return self._fail_pass(started, counts, raw_bytes, added, replaced, reaped,
                                   f"{type(exc).__name__}: {exc}")
        # ── 3. success: NO closing sweep. The reap is the next pass's opening traversal. ──────────
        with self.lock:
            self._pass_active = False
            self._last_pass_ok = True
            self._failed = False
            wrote = self._write_during_pass
            # Still `old` after a COMPLETE read = not returned by it. Memory only; no second read.
            missing = sum(1 for e in self.entries.values() if e.old and not e.deleted)
            self._stats = PassStats(
                ok=True, duration_s=_now() - started,
                counts=MappingProxyType(dict(counts)), raw_bytes=MappingProxyType(dict(raw_bytes)),
                added=added, replaced=replaced, reaped=reaped, missing_candidates=missing,
                at_utc=datetime.now(timezone.utc).isoformat())
            stats = self._stats
        logger.debug("catalog validation pass ok in %.3fs: %s (%s raw bytes), %d added, "
                     "%d replaced, %d reaped", stats.duration_s, dict(counts), dict(raw_bytes),
                     added, replaced, reaped)
        out = stats.as_dict()
        out["write_during_pass"] = wrote
        return out

    def _open_pass(self) -> int:
        """The single opening traversal: reap, discard tombstones, mark everything ``old``."""
        reaped = 0
        with self.lock:
            reap_old = self._last_pass_ok
            for ident, entry in list(self.entries.items()):
                if entry.deleted or (reap_old and entry.old):
                    self.index.remove(entry)
                    self.entries.pop(ident, None)
                    if not entry.deleted:
                        reaped += 1
                    continue
                entry.old = True
            self._pass_active = True
            self._write_during_pass = False
        return reaped

    def _apply_scan_row(self, table: str, uuid: str, raw) -> tuple:
        """Apply ONE scanned row. Returns ``(added, replaced)``.

        Three rules, each load-bearing:

        * **still marked old** → the database result replaces it if the raw value CHANGED, and the
          mark is cleared. An unchanged raw keeps the existing entry, so its cached parse and
          projection are never rebuilt;
        * **already unmarked** → a newer confirmed application write reached memory after this pass
          began. The scan row was read before that write landed, so applying it would resurrect a
          stale document. Ignore it;
        * **absent** → add it, unmarked, unless a ``deleted`` tombstone from a confirmed removal
          covers it.

        The entry construction and its lazy parse happen OUTSIDE the model lock; the lock is taken
        only for the state transition itself.
        """
        ident = (table, uuid)
        with self.lock:
            entry = self.entries.get(ident)
            if entry is not None:
                if entry.deleted:
                    return (0, 0)                  # a confirmed removal outranks an older scan row
                if not entry.old:
                    return (0, 0)                  # a newer confirmed write already applied
                if entry.raw == raw:
                    entry.old = False
                    return (0, 0)
        fresh = _Entry(table, uuid, raw)
        fresh.document()                            # lazy parse, cached — deliberately off-lock
        with self.lock:
            current = self.entries.get(ident)
            if current is not None:
                if current.deleted or not current.old:
                    return (0, 0)                  # raced by a confirmed write; leave it alone
                self.index.remove(current)
                self.entries[ident] = fresh
                self.index.add(fresh)
                return (0, 1)
            self.entries[ident] = fresh
            self.index.add(fresh)
            return (1, 0)

    def _fail_pass(self, started, counts, raw_bytes, added, replaced, reaped, error: str) -> dict:
        """A failed or incomplete database read.

        Nothing is ever removed on this path. The model and its indexes stay intact behind the
        failure latch; ``_last_pass_ok`` False is what makes the NEXT opening traversal mark
        everything ``old`` again without reaping, which is "restart validation from the beginning".

        An incomplete three-table read IS a genuine database availability/read failure, so it PAUSES
        the whole process (packet 1361-01, availability correction) — the gate is closed outside the
        model lock, because closing it may start the recovery coordinator and a thread start has no
        business happening under the lock every reader takes."""
        with self.lock:
            self._pass_active = False
            self._last_pass_ok = False
            self._failed = True
            self._stats = PassStats(
                ok=False, duration_s=_now() - started,
                counts=MappingProxyType(dict(counts)), raw_bytes=MappingProxyType(dict(raw_bytes)),
                added=added, replaced=replaced, reaped=reaped,
                at_utc=datetime.now(timezone.utc).isoformat(), error=error)
            out = self._stats.as_dict()
        from corpusfm.server import availability
        availability.close("storage", error)
        out["write_during_pass"] = False
        return out

    # ── the background synchronizer ──────────────────────────────────────────────────────────────

    def start_synchronizer(self, backend) -> bool:
        """Start the adaptive validation cycle. Only ever started AFTER the initial model is built.

        The whole start happens under ONE lock acquisition (packet 1361-01, availability correction).
        It used to release the lock between the liveness check and the thread assignment, so two
        concurrent callers could each create a stop event, each start a thread, and leave the first
        one unstoppable — a leaked thread validating against a backend nothing could stop it reading.
        Two callers now produce exactly one synchronizer, which is what lets the readiness gate's
        resume callback be reached from more than one edge and still be safe.

        A call that finds the generation alive is the reopen edge (packet 1388-03): it returns the
        live cycle to the fast interval and requests nothing else — it never itself causes a read.
        """
        with self.lock:
            sync = self._sync
            if sync is not None and sync.thread.is_alive():
                sync.reset_cadence()
                return False
            sync = _Synchronizer(self, backend)
            self._sync = sync
            sync.thread.start()
        return True

    def stop_synchronizer(self, timeout: float = None) -> bool:
        """Stop and JOIN the current generation. Returns whether it exited within ``timeout``."""
        with self.lock:
            sync = self._sync
            self._sync = None
        if sync is None:
            return True
        return sync.stop(_SYNC_JOIN_TIMEOUT_S if timeout is None else timeout)

    # ── confirmed application writes ─────────────────────────────────────────────────────────────
    #
    # Every entry point below runs AFTER the substrate confirmed the write. Three properties hold for
    # all of them, and each is a protected invariant rather than a convenience:
    #
    # 1. **They never raise.** A publication failure may only cost freshness; it can never undo a
    #    confirmed write or surface to the caller as a rollback.
    # 2. **They take only the SHORT model lock**, never held across I/O or a parse — so a thread that
    #    has already committed cannot be stalled behind the validation pass.
    # 3. **They update the persistent model in place**, incrementally, with no map copy.

    @staticmethod
    def _visible(table: str, entry: _Entry) -> bool:
        """The STORAGE visibility fence. A record whose document is unusable is admitted regardless:
        it exists, and refusing it would be the "pretend it was deleted" lie."""
        if table != TABLE_STORAGE:
            return True
        doc = entry.document()
        if doc is None:
            return True
        from corpusfm.artifact.capabilities import VISIBLE_TYPES
        return doc.get("Type") in VISIBLE_TYPES

    def publish_batch(self, backend, upserts=(), removals=()) -> None:
        """Apply one operation's confirmed changes to the persistent model, ONCE, atomically.

        A multi-record application operation (a tag edit, a bulk tag adjustment) collects its
        confirmed upserts and deletions and calls this a single time, after the whole operation
        succeeded. The application is one short critical section over the persistent model — never a
        copy of it, and never a per-row publication that would let a reader see half an operation."""
        if not upserts and not removals:
            return
        try:
            key = store_key(backend)
            with self.lock:
                if not self.built or self.key != key:
                    return              # nothing to update; the model is not this store's
            # Build (and lazily parse) every incoming entry OFF-lock.
            prepared = []
            for table, uuid, raw in upserts:
                if not uuid:
                    continue
                entry = _Entry(table, uuid, raw)
                entry.document()
                prepared.append((table, uuid, entry, self._visible(table, entry)))
            with self.lock:
                active = self._pass_active
                for table, uuid, entry, visible in prepared:
                    ident = (table, uuid)
                    current = self.entries.get(ident)
                    if current is not None and not current.deleted and current.raw == entry.raw:
                        # Unchanged raw: keep the existing entry (and its cached parse and
                        # projection). The write still CLEARS the pass flags and still counts as a
                        # concurrent write (packet 1361-01, correction 4): "the returned document is
                        # byte-identical to what memory already held" is a statement about the
                        # DOCUMENT, not about whether an application write landed during the pass.
                        # Treating it as a non-event let the pass complete with
                        # `write_during_pass` False and skip the immediate follow-up the ruling
                        # requires — a real write that memory never accounted for.
                        current.old = False
                        if active:
                            self._write_during_pass = True
                        continue
                    if visible:
                        if current is not None:
                            self.index.remove(current)
                        self.entries[ident] = entry
                        self.index.add(entry)
                    else:
                        # A confirmed write whose Type is outside the visible artifact types is NOT a
                        # deletion, and must not be recorded as one (packet 1361-01, correction 3).
                        # The record exists in FileMaker; what changed is that the catalog no longer
                        # shows it. So the returned raw is RETAINED as a first-class entry with its
                        # derived visible membership removed, `old` and `deleted` both cleared — and
                        # an older in-flight scan row cannot overwrite it, because an unmarked entry
                        # is exactly what `_apply_scan_row` refuses to touch. `deleted` is reserved
                        # for a confirmed record DELETION and nothing else; using it here made the
                        # next opening traversal discard a row the database still holds, so the raw
                        # had to be re-read to come back.
                        if current is not None:
                            self.index.remove(current)
                        entry.old = False
                        entry.deleted = False
                        self.entries[ident] = entry
                        self.index.add(entry)       # a no-op membership: the visibility fence refuses it
                    if active:
                        self._write_during_pass = True
                for table, uuid in removals:
                    if not uuid:
                        continue
                    ident = (table, uuid)
                    current = self.entries.get(ident)
                    if current is not None:
                        self.index.remove(current)
                    if active:
                        # The tombstone is what stops an in-flight scan from resurrecting a row
                        # deleted after that scan read it. The next opening traversal discards it.
                        tomb = current if current is not None else _Entry(table, uuid, "")
                        tomb.deleted = True
                        tomb.old = False
                        self.entries[ident] = tomb
                        self._write_during_pass = True
                    else:
                        self.entries.pop(ident, None)
        except Exception:
            logger.debug("catalog publication failed; the next validation pass reconciles",
                         exc_info=True)

    def publish(self, backend, table: str, uuid: str, raw) -> None:
        self.publish_batch(backend, [(table, uuid, raw)], ())

    def publish_removed(self, backend, table: str, uuid: str) -> None:
        self.publish_batch(backend, (), [(table, uuid)])

    def note_unpublishable_write(self, table: str, uuid: str, operation: str) -> None:
        """A confirmed database write whose response could not be published.

        The write STANDS — this is never a rollback. Nothing is published (in particular never the
        REQUEST document), and the ordinary validation cycle brings memory back into line. Warned at
        most once per interval because it can arrive on every write.

        It also asks the ONE synchronizer for a prompt pass without blocking the writer (packet
        1388-03). While a pass is active the existing coalesced follow-up already covers the write,
        so the wake is requested only when none is: both branches are decided under the model lock
        that `_open_pass` and the pass's success block also take, so no write falls between them."""
        try:
            now = _now()
            with self.lock:
                warn = (now - self._last_write_warn_at) >= _WRITE_WARN_INTERVAL_S
                if warn:
                    self._last_write_warn_at = now
                active = self._pass_active
                if active:
                    self._write_during_pass = True
                sync = self._sync
            if warn:
                logger.warning(
                    "catalog: %s on %s/%s returned no publishable record; the write stands and the "
                    "catalog reconciles on its next validation pass.", operation, table, uuid)
            if sync is not None and not active:
                sync.request_pass("unpublishable_write")
        except Exception:                          # pragma: no cover - bookkeeping must never raise
            pass

    # ── diagnostics / lifecycle ──────────────────────────────────────────────────────────────────

    def diagnostics(self) -> dict:
        """Cheap facts only: identity counts, sizes and timings. It builds no index and reads no
        JSON value, so asking for it costs nothing and leaks nothing."""
        with self.lock:
            sync = self._sync
            out = {
                "built": self.built,
                "failed": self._failed,
                "records": len(self.entries),
                "visible_storage": len(self.index.storage),
                "pass_active": self._pass_active,
                "sync_interval_s": SYNC_INTERVAL_S,
                "sync_max_interval_s": SYNC_MAX_INTERVAL_S,
                "synchronizer_running": bool(sync is not None and sync.thread.is_alive()),
                "last_pass": self._stats.as_dict(),
            }
        out["synchronizer"] = sync.snapshot() if sync is not None else {"state": "stopped"}
        from corpusfm.server import availability
        out["readiness"] = availability.diagnostics()
        return out

    def reset(self) -> None:
        """Drop the model entirely — process shutdown semantics, and the test seam."""
        self.stop_synchronizer()
        with self.lock:
            self.entries = {}
            self.index = _Index()
            self.key = None
            self.built = False
            self._failed = False
            self._last_pass_ok = False
            self._pass_active = False
            self._write_during_pass = False
            self._stats = PassStats()
            self._last_write_warn_at = 0.0


class _Synchronizer:
    """ONE generation of the background validation cycle (packet 1388-03).

    Its thread, wake condition and pending state live and die together, so stopping a generation can
    never consume a signal meant for its successor. Every signal is STATE under the condition's lock
    — a pending reason, the unchanged streak, the deadline — and is consumed only by the decision made
    under that same lock immediately before a pass. A signal raised during a pass, between a pass and
    the wait, or during the wait is therefore seen by the next decision; there is no `wait(); clear()`
    window to lose it in, and repeated signals coalesce into one pending reason.

    Cadence: ``SYNC_INTERVAL_S`` after start, resume, failure, any change, a concurrent or
    unpublishable write, or a deletion candidate; ``SYNC_MAX_INTERVAL_S`` only after
    ``SYNC_BACKOFF_AFTER`` consecutive successful passes that changed nothing. A pass leaving deletion
    candidates requests ONE immediate confirmation pass, whose opening traversal is the existing reap.
    """

    def __init__(self, catalog: "_Catalog", backend) -> None:
        self._cat = catalog
        self._backend = backend
        self._clock = _sync_clock or _now
        self._wait = _sync_wait or (lambda cond, timeout: cond.wait(timeout))
        self._on_pass_done = _sync_on_pass_done
        self._cond = threading.Condition(threading.Lock())
        self._stopping = False
        self._pending = ""
        self._streak = 0
        self._interval = SYNC_INTERVAL_S
        self._deadline = self._clock() + SYNC_INTERVAL_S
        self._state = "starting"
        self._passes = 0
        self._resets = 0
        self._last: dict = {}
        self.thread = threading.Thread(target=self._run, name="cfm-catalog-sync", daemon=True)

    # -- signals (any thread; never blocks on a pass) ----------------------------------------------

    def request_pass(self, reason: str) -> None:
        with self._cond:
            if self._stopping:
                return
            if not self._pending:
                self._pending = reason
            self._streak = 0
            self._interval = SYNC_INTERVAL_S
            self._cond.notify_all()

    def reset_cadence(self) -> None:
        """Fast cadence again, WITHOUT requesting a pass: the reopen edge follows a complete
        validation, so the next read waits for the fast deadline."""
        with self._cond:
            if self._stopping:
                return
            self._streak = 0
            self._interval = SYNC_INTERVAL_S
            self._deadline = min(self._deadline, self._clock() + SYNC_INTERVAL_S)
            self._resets += 1
            self._cond.notify_all()

    def stop(self, timeout: float) -> bool:
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
        if self.thread is threading.current_thread() or self.thread.ident is None:
            return not self.thread.is_alive()
        self.thread.join(timeout)
        return not self.thread.is_alive()

    def snapshot(self) -> dict:
        with self._cond:
            return {"state": self._state,
                    "fast_interval_s": SYNC_INTERVAL_S,
                    "max_interval_s": SYNC_MAX_INTERVAL_S,
                    "current_interval_s": self._interval,
                    "unchanged_streak": self._streak,
                    "missing_candidates": self._last.get("missing_candidates", 0),
                    "pending_pass": bool(self._pending),
                    "pending_reason": self._pending,
                    "resets": self._resets,
                    "passes": self._passes,
                    "last_cycle": dict(self._last)}

    # -- the loop ----------------------------------------------------------------------------------

    def _run(self) -> None:
        from corpusfm.server import availability
        while True:
            gate_open = availability.is_open()
            with self._cond:
                if self._stopping:
                    self._state = "stopped"
                    return
                now = self._clock()
                if not gate_open:
                    # THE ORDINARY SYNCHRONIZER PERFORMS NO DATABASE OPERATION WHILE PAUSED (packet
                    # 1361-01, round 3): the recovery coordinator is the only component allowed to
                    # contact FileMaker then. One persistent thread re-checks the gate on the fast
                    # cadence; a pending signal is KEPT, not consumed, until the gate reopens.
                    self._state = "paused"
                    if self._deadline <= now:
                        self._deadline = now + SYNC_INTERVAL_S
                    self._wait(self._cond, self._deadline - now)
                    continue
                if not self._pending and now < self._deadline:
                    self._state = "waiting"
                    self._wait(self._cond, self._deadline - now)
                    continue
                reason = self._pending or "interval"
                self._pending = ""
                self._state = "validating"
            try:
                res = self._cat.run_validation_pass(self._backend)
            except Exception:                       # pragma: no cover - the pass never raises
                logger.debug("catalog synchronizer cycle failed", exc_info=True)
                res = {"ok": False}
            if self._on_pass_done is not None:
                self._on_pass_done(self, res)
            with self._cond:
                self._settle(res, reason)

    def _settle(self, res: dict, reason: str) -> None:
        """The cadence decision, from the completed pass result alone. Called under ``_cond``."""
        ok = bool(res.get("ok"))
        missing = int(res.get("missing_candidates") or 0) if ok else 0
        changed = bool(res.get("added") or res.get("replaced") or res.get("reaped")
                       or res.get("follow_up_due_to_write") or missing)
        confirmation = reason == "missing_candidates"
        self._passes += 1
        if not ok or changed or self._pending:
            self._streak = 0
        else:
            self._streak += 1
        self._interval = (SYNC_MAX_INTERVAL_S if self._streak >= SYNC_BACKOFF_AFTER
                          else SYNC_INTERVAL_S)
        if missing and not confirmation and not self._pending:
            self._pending = "missing_candidates"
        self._deadline = self._clock() + self._interval
        self._last = {"ok": ok, "reason": reason, "changed": changed,
                      "missing_candidates": missing, "confirmation": confirmation,
                      "follow_up_due_to_write": bool(res.get("follow_up_due_to_write"))}


_catalog = _Catalog()
# A permanently-empty model, so a `peek()` with nothing built hands back a usable (failed) view
# instead of `None` for every consumer to guard.
_EMPTY_MODEL = _Catalog()

# ── Module surface ────────────────────────────────────────────────────────────────────────────────

view = _catalog.view
peek = _catalog.peek
failed = _catalog.failed
is_built = _catalog.is_built
build_initial = _catalog.build_initial
validate_now = _catalog.validate_now
run_validation_pass = _catalog.run_validation_pass
start_synchronizer = _catalog.start_synchronizer
stop_synchronizer = _catalog.stop_synchronizer
publish = _catalog.publish
publish_removed = _catalog.publish_removed
publish_batch = _catalog.publish_batch
note_unpublishable_write = _catalog.note_unpublishable_write
diagnostics = _catalog.diagnostics


def reset() -> None:
    """Test seam / shutdown: drop the model, stop the synchronizer, and return the process to the
    startup state — PAUSED, unsupervised, with no recovery coordinator (packet 1361-01)."""
    from corpusfm.server import availability
    _catalog.reset()
    availability.reset()


def failed_view() -> CatalogView:
    """A view that reports the catalog condition without holding any records — for a caller whose
    backend could not even be resolved, which is the same claim as a failed database read."""
    return CatalogView(_EMPTY_MODEL, True)


def publish_write(backend, table: str, uuid: str, written, *, operation: str = "write") -> None:
    """Publish ONE confirmed write from what the substrate RETURNED, or record why it could not.

    ``written`` is the engine's :class:`~corpusfm.storage.engine.WriteRow` — ``UUID`` plus the opaque
    ``JSONOfRecord``, narrowed at the transport boundary. ``None`` means the response carried no
    publishable record:

    * it is **not** a database failure. The write is already confirmed and is never rolled back or
      reported as failed;
    * nothing is published — in particular never the REQUEST document, which would make a document we
      composed indistinguishable from one FileMaker committed;
    * the next validation pass brings the durable state into memory.

    Never raises. A publication problem may cost freshness and nothing else.
    """
    try:
        if written is None:
            note_unpublishable_write(table, uuid, operation)
            return
        publish(backend, table, written.key, written.raw)
    except Exception:
        logger.debug("catalog: %s publication failed for %s/%s", operation, table, uuid,
                     exc_info=True)


def publish_deleted(backend, table: str, uuid: str) -> None:
    """Publish one confirmed deletion. Never raises."""
    try:
        publish_removed(backend, table, uuid)
    except Exception:
        logger.debug("catalog: removal publication failed for %s/%s", table, uuid, exc_info=True)
