"""Edge address resolution (packet 085 U3f) — record UUID is the canonical artifact address.

``PrimaryName`` / ``FileName`` / tag name are human *aliases*, resolved to a record UUID HERE, at
the web/MCP edge, so the rest of the app only ever addresses a record by its (rename-stable) UUID.

Rules (ratified, design note §7):
  1. Exactly-a-UUID (RFC 4122 36-char form) → a direct engine-key hit; miss = not found.
  2. Else an alias, matched in order: PrimaryName (exact, case-insensitive) → FileName (exact,
     case-insensitive; ``ensure_fmp12`` applied as the XML-name normalizer only) → tag name
     (returns the tag's members).
  3. ``FileName/Timestamp`` rel_paths are NOT accepted — retired outright, no alias shim.

A single match resolves; multiple matches are **latest-preferred** (an ``IsLatest`` member of the
match set), and if still ambiguous the candidates are returned — never a guess.
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

    def to_dict(self) -> dict:
        return {"uuid": self.uuid, "primary_name": self.primary_name,
                "file_name": self.file_name, "type": self.type, "timestamp": self.timestamp}


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


def _cand(row) -> Candidate:
    j = row.jor
    return Candidate(row.key, j.get("PrimaryName", ""), j.get("FileName", ""),
                     j.get("Type", ""), j.get("ArtifactTimestamp", ""))


def _narrow(rows) -> Resolution:
    """One record → resolved; many → latest-preferred, else candidates; none → not found."""
    from corpusfm.artifact.capabilities import VISIBLE_TYPES
    rows = [r for r in rows if r.jor.get("Type", "") in VISIBLE_TYPES]
    if not rows:
        return Resolution()
    if len(rows) == 1:
        return Resolution(uuid=rows[0].key)
    latest = [r for r in rows if r.jor.get("IsLatest") in (True, 1, "1", "true")]
    if len(latest) == 1:
        return Resolution(uuid=latest[0].key)
    pool = latest or rows
    if len(pool) == 1:
        return Resolution(uuid=pool[0].key)
    pool = sorted(pool, key=lambda r: r.jor.get("ArtifactTimestamp", ""), reverse=True)
    return Resolution(ambiguous=True, candidates=[_cand(r).to_dict() for r in pool])


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
        res = _narrow(eng.get_many(_STORAGE, "PrimaryName", [ref]))
        if res.found or res.ambiguous:
            return res
        from corpusfm.core.filenames import ensure_fmp12
        res = _narrow(eng.get_many(_STORAGE, "FileName", [ensure_fmp12(ref)]))
        if res.found or res.ambiguous:
            return res
        return _narrow(_tag_members(eng, ref))
    except Exception:
        return Resolution()


def resolve_uuid(backend, ref: str) -> Optional[str]:
    """The resolved UUID, or None (ambiguity + miss both → None). For internal call sites that
    want a plain 'best-effort address', not the candidate payload."""
    r = resolve(backend, ref)
    return r.uuid if r.found else None
