"""Aggregated discovery log — unknown FM structural vocabulary across all ingestions.

Appends one JSON line per ingestion to discovery.jsonl when unknown step IDs or
reference types are found. Each entry carries enough context (FM version, file
identity, root UUID) to identify what FM build or file introduced the pattern.

The log accumulates across all ingestions and is the evidence base for promoting
unknown patterns to known types in mappings.yaml / structure_catalog.yaml.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()


def append_discovery(artifact, log_path: Path) -> None:
    """Append an entry to the discovery log if the artifact has any unknowns.

    No-ops when there is nothing to record. Thread-safe for concurrent ingestions.
    """
    profile = artifact.completeness_profile
    unknown_steps = list(profile.unknown_step_ids or [])
    unknown_refs = list(profile.unknown_reference_types or [])

    if not unknown_steps and not unknown_refs:
        return

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "file": artifact.identity.file_name,
        "fm_version": artifact.identity.fm_version,
        "root_uuid": artifact.identity.root_uuid,
        "unknown_step_ids": unknown_steps,
        "unknown_reference_types": unknown_refs,
    }
    with _lock:
        # Create the dir HERE, at the write, not when someone merely reads `backend.archive_dir` —
        # that getter used to mkdir as a side effect, which is how a network-free unit test ended up
        # writing into the developer's home directory (2026-07-15).
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def read_discovery_log(log_path: Path) -> list[dict]:
    """Return all entries from the discovery log, newest-first.

    Returns an empty list when the file does not exist.
    """
    if not log_path.exists():
        return []
    entries = []
    with log_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return list(reversed(entries))
