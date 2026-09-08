"""Per-artifact git export target — the credential selection an artifact carries.

An artifact receives `{registration, repo}` at ingest (copied from the Job that spawned it,
when that job had a git export), then **owns it independently**: the Job→Artifact link is
history, not a live binding, so the Export tab can later point the artifact at a different
registration or repo with no effect on the job. The credential's character still governs what
may be set (a deploy-key registration's repo is fixed; a PAT's is free).

**Storage (packet 1009/S3): the target rides the owning STORAGE record's own JSONOfRecord** under a
`git_target` key, keyed by the record UUID (the canonical artifact address, packet 085 U3f). It is
NON-secret and never queried/`$filter`ed, so it needs no slot and no container — it is a plain jor
field that travels with the artifact and is scoped strictly to that one record. (This replaced the
former SETTING-singleton `git_targets` map, which put per-artifact state in the app-settings blob.)

Read/written engine-direct via the storage backend (both backends expose `.engine`, exactly as
`storage.artifact_store` uses it): a `set` reads the record's full jor, merges/removes the
`git_target` key, and writes the full jor back (the engine update is a full-jor replace; the
FM auto-enter CF re-derives every slot to the same values, so nothing else on the record changes).

Public API (the key is the record UUID):
    get_target(record_uuid) -> dict            # {"registration": str, "repo": str} (empty if none)
    set_target(record_uuid, registration, repo) -> dict
    clear_target(record_uuid) -> None
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_STORAGE = "STORAGE"
_EMPTY = {"registration": "", "repo": ""}


def _backend():
    """The storage backend, or None when unavailable."""
    try:
        from corpusfm.storage import get_backend
        return get_backend()
    except Exception:
        return None


def _engine():
    """The storage engine, or None when unavailable (mirrors artifact_store's access)."""
    return getattr(_backend(), "engine", None)


def _coerce(value) -> dict:
    if not isinstance(value, dict):
        return dict(_EMPTY)
    return {
        "registration": str(value.get("registration", "") or ""),
        "repo": str(value.get("repo", "") or ""),
    }


def get_target(record_uuid: str) -> dict:
    """The artifact's git target, or {"registration": "", "repo": ""} if unset."""
    eng = _engine()
    if not record_uuid or eng is None:
        return dict(_EMPTY)
    rows = eng.get_by_keys(_STORAGE, [record_uuid])
    if not rows:
        return dict(_EMPTY)
    return _coerce(rows[0].jor.get("git_target"))


def set_target(record_uuid: str, registration: str, repo: str = "") -> dict:
    """Set (or clear, when registration is blank) the artifact's git target. Returns the new value."""
    eng = _engine()
    if not record_uuid or eng is None:
        return dict(_EMPTY)
    rows = eng.get_by_keys(_STORAGE, [record_uuid])
    if not rows:
        return dict(_EMPTY)
    jor = dict(rows[0].jor)
    registration = (registration or "").strip()
    repo = (repo or "").strip()
    if registration:
        jor["git_target"] = {"registration": registration, "repo": repo}
    else:
        jor.pop("git_target", None)
    committed = eng.update(_STORAGE, record_uuid, jor)
    # `git_target` rides in the canonical JSONOfRecord, which IS the persistent catalog's
    # authoritative payload (packet 1361-01, ruling D5) — so this writer owes a publication even
    # though the field itself is invisible to every catalog projection today.
    try:
        from corpusfm.server import catalog
        catalog.publish_write(_backend(), catalog.TABLE_STORAGE, record_uuid, committed,
                              operation="set_git_target")
    except Exception:
        logger.debug("catalog publication failed for git target %s", record_uuid, exc_info=True)
    return _coerce(jor.get("git_target"))


def clear_target(record_uuid: str) -> None:
    set_target(record_uuid, "", "")
