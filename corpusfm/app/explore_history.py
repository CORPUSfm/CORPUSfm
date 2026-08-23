"""Recent Explorer history — rolling JSONL store of recently explored artifact sets.

Stores only the archive paths + labels of each Explorer launch (a session may span
several artifacts), not the generated HTML. The Explorer is always regenerated on demand.
Mirrors diff_history.py; reuses its backend-agnostic existence helpers.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from corpusfm.app.diff_history import existing_artifact_paths, _path_exists

_lock = threading.Lock()

# Convenience trail, not data — a fixed small cap keeps the file bounded.
MAX_EXPLORE_HISTORY = 20


def _archive_dir() -> Optional[Path]:
    try:
        from corpusfm.storage import get_backend
        backend = get_backend()
        if hasattr(backend, "archive_dir"):
            return backend.archive_dir
    except Exception:
        pass
    return None


def default_explore_history_path() -> Path:
    d = _archive_dir()
    if d is not None:
        return d / "_explore_history.jsonl"
    return Path(__file__).parent.parent.parent / "explore_history.jsonl"


@dataclass
class ExploreHistoryEntry:
    ts: str
    artifacts: list = field(default_factory=list)   # rel_paths
    labels: list = field(default_factory=list)       # display labels (parallel to artifacts)
    history_id: str = ""

    def __post_init__(self) -> None:
        if not self.history_id:
            self.history_id = str(uuid.uuid4())

    def to_dict(self) -> dict:
        return {
            "history_id": self.history_id,
            "ts": self.ts,
            "artifacts": list(self.artifacts),
            "labels": list(self.labels),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ExploreHistoryEntry":
        return cls(
            ts=d.get("ts", ""),
            artifacts=list(d.get("artifacts") or []),
            labels=list(d.get("labels") or []),
            history_id=d.get("history_id", "") or d.get("ts", ""),
        )


def _read_all(path: Path) -> list:
    if not path.exists():
        return []
    results = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(ExploreHistoryEntry.from_dict(json.loads(line)))
        except Exception:
            continue
    results.sort(key=lambda e: e.ts, reverse=True)
    return results


def _write_all(path: Path, entries: list) -> None:
    path.write_text(
        ("\n".join(json.dumps(e.to_dict()) for e in entries) + "\n") if entries else "",
        encoding="utf-8",
    )


def _prune(path: Path, limit: int) -> None:
    existing = _read_all(path)
    if len(existing) > limit:
        _write_all(path, existing[:limit])


def load_explore_history(limit: Optional[int] = MAX_EXPLORE_HISTORY,
                         path: Optional[Path] = None) -> list:
    p = path or default_explore_history_path()
    with _lock:
        entries = _read_all(p)
    if limit is not None:
        entries = entries[:limit]
    return entries


def record_explore(artifacts: list, labels: list, path: Optional[Path] = None) -> None:
    """Record an Explorer launch (one or more artifacts). No-op on empty input."""
    artifacts = [a for a in (artifacts or []) if a]
    if not artifacts:
        return
    entry = ExploreHistoryEntry(
        ts=datetime.now(timezone.utc).isoformat(),
        artifacts=artifacts,
        labels=list(labels or [])[:len(artifacts)],
    )
    p = path or default_explore_history_path()
    with _lock:
        with open(p, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")
    _prune(p, MAX_EXPLORE_HISTORY)


def delete_explore_history_entry(history_id: str, path: Optional[Path] = None) -> bool:
    p = path or default_explore_history_path()
    with _lock:
        entries = _read_all(p)
        kept = [e for e in entries if e.history_id != history_id and e.ts != history_id]
        if len(kept) == len(entries):
            return False
        _write_all(p, kept)
    return True


def groom_explore_history(backend=None, path=None) -> dict:
    """Drop records where any artifact no longer exists. Returns {kept, removed, entries}."""
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    archive_dir = getattr(backend, "archive_dir", None)
    p = path or default_explore_history_path()
    with _lock:
        entries = _read_all(p)
        existing = existing_artifact_paths(
            backend, candidates={a for e in entries for a in (e.artifacts or [])})
        kept = [e for e in entries
                if e.artifacts and all(_path_exists(a, existing, archive_dir) for a in e.artifacts)]
        removed = len(entries) - len(kept)
        if removed:
            _write_all(p, kept)
    return {"kept": len(kept), "removed": removed, "entries": kept}
