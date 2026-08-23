"""Recent diff history — rolling JSONL store of recently compared artifact pairs.

Stores only the two archive paths and labels, not the diff output itself.
The diff is always recomputed from stored XMLs on demand.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_lock = threading.Lock()

# Number of diff-history records retained. Hard-coded (not user-configurable):
# history is a convenience trail, not data — a fixed small cap keeps the file
# bounded and the grooming cheap.
MAX_DIFF_HISTORY = 50


def _archive_dir() -> Optional[Path]:
    try:
        from corpusfm.storage import get_backend
        backend = get_backend()
        if hasattr(backend, "archive_dir"):
            return backend.archive_dir
    except Exception:
        pass
    return None


def default_diff_history_path() -> Path:
    d = _archive_dir()
    if d is not None:
        return d / "_diff_history.jsonl"
    return Path(__file__).parent.parent.parent / "diff_history.jsonl"


@dataclass
class DiffHistoryEntry:
    ts: str
    artifact_a: str
    artifact_b: str
    label_a: str
    label_b: str
    history_id: str = ""

    def __post_init__(self) -> None:
        if not self.history_id:
            self.history_id = str(uuid.uuid4())

    def artifacts_exist(self, archive_dir: Path) -> bool:
        """Local-disk existence check. Prefer entry_artifacts_exist(), which is
        backend-agnostic (the FM backend keeps artifacts in a container, not on
        disk, so this returns False for everything on the server)."""
        def _exists(rel_path: str) -> bool:
            p = Path(rel_path)
            if p.is_absolute():
                return p.exists()
            return (archive_dir / rel_path).exists()
        return _exists(self.artifact_a) and _exists(self.artifact_b)

    def to_dict(self) -> dict:
        return {
            "history_id": self.history_id,
            "ts": self.ts,
            "artifact_a": self.artifact_a,
            "artifact_b": self.artifact_b,
            "label_a": self.label_a,
            "label_b": self.label_b,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DiffHistoryEntry":
        entry = cls(
            ts=d["ts"],
            artifact_a=d.get("artifact_a") or d.get("snapshot_a", ""),
            artifact_b=d.get("artifact_b") or d.get("snapshot_b", ""),
            label_a=d.get("label_a", "A"),
            label_b=d.get("label_b", "B"),
            history_id=d.get("history_id", "") or d.get("ts", ""),
        )
        return entry


def append_diff_history(
    entry: DiffHistoryEntry,
    limit: Optional[int] = None,
    path: Optional[Path] = None,
) -> None:
    """Append an entry. Optionally prune to limit (newest first)."""
    p = path or default_diff_history_path()
    with _lock:
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")
        if limit is not None:
            _prune(p, limit)


def _prune(path: Path, limit: int) -> None:
    existing = _read_all(path)
    if len(existing) > limit:
        _write_all(path, existing[:limit])


def _read_all(path: Path) -> list[DiffHistoryEntry]:
    if not path.exists():
        return []
    results = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(DiffHistoryEntry.from_dict(json.loads(line)))
        except Exception:
            continue
    results.sort(key=lambda e: e.ts, reverse=True)
    return results


def _write_all(path: Path, entries: list[DiffHistoryEntry]) -> None:
    path.write_text(
        "\n".join(json.dumps(e.to_dict()) for e in entries) + "\n",
        encoding="utf-8",
    )


def load_diff_history(
    limit: Optional[int] = 200,
    path: Optional[Path] = None,
) -> list[DiffHistoryEntry]:
    """Load diff history, newest first."""
    p = path or default_diff_history_path()
    with _lock:
        entries = _read_all(p)
    if limit is not None:
        entries = entries[:limit]
    return entries


def delete_diff_history_entry(history_id: str, path: Optional[Path] = None) -> bool:
    p = path or default_diff_history_path()
    with _lock:
        entries = _read_all(p)
        new_entries = [e for e in entries if e.history_id != history_id and e.ts != history_id]
        if len(new_entries) == len(entries):
            return False
        _write_all(p, new_entries)
    return True


def record_diff(
    artifact_a: str,
    artifact_b: str,
    label_a: str,
    label_b: str,
    path: Optional[Path] = None,
) -> None:
    entry = DiffHistoryEntry(
        ts=datetime.now(timezone.utc).isoformat(),
        artifact_a=artifact_a,
        artifact_b=artifact_b,
        label_a=label_a,
        label_b=label_b,
    )
    append_diff_history(entry, limit=MAX_DIFF_HISTORY, path=path)


def existing_artifact_paths(backend=None, candidates=None) -> set:
    """The record UUIDs the backend currently holds (packet 085 U3f — history references artifacts
    by their canonical UUID address now). With ``candidates`` (the bounded set of UUIDs a history
    page references), resolution is ONE indexed ``get_by_keys`` read (audit #7) — never a full
    STORAGE scan. Without candidates (or on an engine-less backend) it falls back to the listing.
    Backend-agnostic (name kept for the diff/explore-history callers)."""
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    if candidates is not None:
        wanted = [c for c in candidates if c]
        eng = getattr(backend, "engine", None)
        if eng is not None:
            try:
                return {r.key for r in eng.get_by_keys("STORAGE", wanted)}
            except Exception:
                pass   # fall through to the full listing
    paths: set = set()
    try:
        for m in backend.iter_artifact_metas():
            if getattr(m, "uuid", ""):
                paths.add(m.uuid)
    except Exception:
        pass
    return paths


def _path_exists(ref: str, existing: set, archive_dir: Optional[Path]) -> bool:
    """True when the record UUID ``ref`` is among the currently-held ``existing`` set (085 U3f)."""
    return bool(ref) and ref in existing


def entry_artifacts_exist(entry: DiffHistoryEntry, backend=None,
                          existing: Optional[set] = None) -> bool:
    """True when both of an entry's artifacts still exist (backend-agnostic).
    Pass a pre-built `existing` set when checking many entries to avoid repeated
    backend listing."""
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    if existing is None:
        existing = existing_artifact_paths(
            backend, candidates={entry.artifact_a, entry.artifact_b})
    archive_dir = getattr(backend, "archive_dir", None)
    return (_path_exists(entry.artifact_a, existing, archive_dir)
            and _path_exists(entry.artifact_b, existing, archive_dir))


def groom_diff_history(backend=None, path=None) -> dict:
    """Drop history records whose artifacts no longer exist. Returns
    {kept, removed, entries}. Run when the Diff History page is opened."""
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    archive_dir = getattr(backend, "archive_dir", None)
    p = path or default_diff_history_path()
    with _lock:
        entries = _read_all(p)
        existing = existing_artifact_paths(
            backend,
            candidates={e.artifact_a for e in entries} | {e.artifact_b for e in entries})
        kept = [e for e in entries
                if _path_exists(e.artifact_a, existing, archive_dir)
                and _path_exists(e.artifact_b, existing, archive_dir)]
        removed = len(entries) - len(kept)
        if removed:
            _write_all(p, kept)
    return {"kept": len(kept), "removed": removed, "entries": kept}
