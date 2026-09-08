"""Edge address resolution (packet 085 U3f) — record UUID is the canonical artifact address.

``PrimaryName`` / ``FileName`` / tag name are human *aliases*, resolved to a record UUID HERE, at
the web/MCP edge, so the rest of the app only ever addresses a record by its (rename-stable) UUID.

Rules (ratified, design note §7):
  1. Exactly-a-UUID (RFC 4122 36-char form) → a direct engine-key hit; miss = not found.
  2. Else an alias, matched in order: PrimaryName (exact, case-insensitive) → FileName (exact,
     case-insensitive; ``ensure_fmp12`` applied as the XML-name normalizer only) → tag name
     (returns the tag's members).
  3. ``FileName/Timestamp`` rel_paths are NOT accepted — retired outright, no alias shim.

**An alias is not a primary key.** A single match resolves to its UUID. Several matches are ALL
returned as candidates — never silently collapsed to one, and never resolved by an automatic
latest/newest rule. Each candidate carries ``is_latest`` from the persistent catalog's normalized
promotion verdict, and the list is ordered latest-first then newest-timestamp so the caller sees the
likely answer at the top while still being told there was more than one. Under the approved
semantics several candidates may legitimately be latest at once — job-less artifacts are always
latest, and a lineage whose promotion is missing or unresolvable is latest as a whole.

Everything downstream of this module — every operation, every stored relationship — remains
UUID-addressed. This is an address-resolution surface, not an identity.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

_STORAGE = "STORAGE"
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def is_uuid(ref: str) -> bool:
    return bool(ref) and bool(_UUID_RE.match(ref.strip()))


@dataclass(frozen=True)
class Candidate:
    uuid: str
    primary_name: str
    file_name: str
    type: str
    timestamp: str
    is_latest: bool = False

    def to_dict(self) -> dict:
        return {"uuid": self.uuid, "primary_name": self.primary_name,
                "file_name": self.file_name, "type": self.type, "timestamp": self.timestamp,
                "is_latest": self.is_latest}


@dataclass
class Resolution:
    """The outcome of resolving one address ref. ``found`` = a single unambiguous UUID; ``ambiguous``
    = the alias matched >1 record (``candidates`` carries them); neither = not found."""
    uuid: str = ""
    ambiguous: bool = False
    candidates: list = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.uuid) and not self.ambiguous


def _cand(row, *, is_latest: bool = False) -> Candidate:
    j = row.jor
    return Candidate(row.key, j.get("PrimaryName", ""), j.get("FileName", ""),
                     j.get("Type", ""), j.get("ArtifactTimestamp", ""), is_latest)


def _latest_uuids(backend) -> frozenset:
    """The normalized promotion verdict, from the persistent catalog — never a per-record flag.

    A paused process or an unbuilt model answers with the empty set, which costs the ANNOTATION and
    the ordering, never the candidate list: this module's job is to say which records an alias names,
    and it can still do that when the catalog cannot say which of them is current.
    """
    try:
        from corpusfm.server import catalog
        view = catalog.view(backend)
        return frozenset() if view.failed else view.latest_uuids
    except Exception:
        return frozenset()


def _narrow(rows, backend=None) -> Resolution:
    """One record → resolved; many → EVERY candidate, latest-first then newest; none → not found.

    An alias that names several records is genuinely ambiguous and is reported that way (packet
    1361-01, correction 5). Two things it does NOT do, deliberately:

    * it does not pick one. The retired `IsLatest` rule silently resolved a multi-snapshot FileName
      to whichever row carried the flag, which made an alias behave like a primary key;
    * it does not rank by timestamp alone. `is_latest` comes from the catalog's normalized promotion
      index, so the ordering reflects what the product means by "current" rather than what the clock
      says. Several candidates may legitimately be latest — job-less artifacts always are, and an
      unresolved promotion makes a whole lineage latest — so this is an ANNOTATION and an ORDERING,
      never a tie-break that would collapse the list.
    """
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    rows = [r for r in rows if r.jor.get("Type", "") in VISIBLE_TYPES]
    if not rows:
        return Resolution()
    if len(rows) == 1:
        return Resolution(uuid=rows[0].key)
    latest = _latest_uuids(backend) if backend is not None else frozenset()
    pool = sorted(rows, key=lambda r: (r.key in latest, r.jor.get("ArtifactTimestamp", "")),
                  reverse=True)
    return Resolution(ambiguous=True,
                      candidates=[_cand(r, is_latest=r.key in latest).to_dict() for r in pool])


def _tag_members(eng, name: str) -> list:
    """Every STORAGE row assigned the user tag ``name`` (lowercased), via TAG→STORAGELINK→STORAGE.
    A tag alias is inherently multi-record; the caller surfaces candidates."""
    try:
        tag_rows = eng.get_many("TAG", "Name", [name.lower()])
        tag_uuids = [r.key for r in tag_rows]
        if not tag_uuids:
            return []
        links = eng.get_many("STORAGELINK", "UUIDTag", tag_uuids)
        art_uuids = [r.jor.get("UUIDStorage", "") for r in links if r.jor.get("UUIDStorage")]
        return eng.get_by_keys(_STORAGE, art_uuids) if art_uuids else []
    except Exception:
        return []


def resolve(backend, ref: str) -> Resolution:
    """Resolve one address ref (UUID or alias) to a record UUID. See module docstring for the rules."""
    eng = getattr(backend, "engine", None)
    ref = (ref or "").strip()
    if not ref or eng is None:
        return Resolution()

    # 1. A bare UUID is the canonical address — a direct engine-key hit (rename-stable).
    if is_uuid(ref):
        try:
            rows = eng.get_by_keys(_STORAGE, [ref])
        except Exception:
            rows = []
        return Resolution(uuid=ref) if rows else Resolution()

    # 2. Alias: PrimaryName → FileName (ensure_fmp12-normalized) → tag name. get_many lowercases
    #    the comparand (both engines), so the match is case-insensitive.
    try:
        res = _narrow(eng.get_many(_STORAGE, "PrimaryName", [ref]), backend)
        if res.found or res.ambiguous:
            return res
        from corpusfm.core.filenames import ensure_fmp12
        res = _narrow(eng.get_many(_STORAGE, "FileName", [ensure_fmp12(ref)]), backend)
        if res.found or res.ambiguous:
            return res
        return _narrow(_tag_members(eng, ref), backend)
    except Exception:
        return Resolution()


def resolve_uuid(backend, ref: str) -> Optional[str]:
    """The resolved UUID, or None (ambiguity + miss both → None). For internal call sites that
    want a plain 'best-effort address', not the candidate payload."""
    r = resolve(backend, ref)
    return r.uuid if r.found else None
