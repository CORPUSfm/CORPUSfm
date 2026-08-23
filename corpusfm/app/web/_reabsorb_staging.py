"""Reabsorb staging — a LOCAL temp area for validated `.artifact` bytes between inspect and commit.

The human import flow is single-upload: inspect uploads the whole `.artifact`, validates it, and
writes the validated bytes here under an unguessable uuid token; commit reads the staged file by
token (no re-upload), stores it, and deletes it. Staging is the LOCAL FILESYSTEM only — NEVER the
database (the dev's rule: the token model is fine only if it doesn't touch the DB). Same category as
the Explorer/Diff preview temp dirs + the JSONL debug aid: a runtime dir under the system temp.

Disk bound: each staged file is at most the per-upload cap (MAX_UPLOAD_BYTES, 1 GB) and a batch
stages each file once; abandoned tokens are TTL-swept and the whole dir is cleared at startup, so the
steady-state footprint is bounded by the in-flight batch. On an FMS box this is fine.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DIR_NAME = "corpusfm_reabsorb_staging"

# Abandoned tokens (inspected but never committed/cancelled) are swept after this age.
STAGING_TTL_SECONDS = 6 * 3600


def staging_dir() -> Path:
    from corpusfm.core.secure_fs import secure_dir
    return secure_dir(Path(tempfile.gettempdir()) / _DIR_NAME)


def _is_valid_token(token: str) -> bool:
    """A token must be exactly the uuid4 hex we mint — never a client-supplied path component."""
    if not token or len(token) != 32:
        return False
    try:
        return uuid.UUID(hex=token).version == 4
    except ValueError:
        return False


def _path_for(token: str) -> Optional[Path]:
    if not _is_valid_token(token):
        return None
    return staging_dir() / f"{token}.artifact"


def stage(data: bytes) -> str:
    """Write validated `.artifact` bytes under a fresh uuid token; return the token.
    Raises StagingSpaceError if the box is low on disk / the staging dir is over budget (packet 056)."""
    from corpusfm.app.web._staging_guard import ensure_space
    ensure_space(staging_dir(), len(data))
    token = uuid.uuid4().hex
    path = staging_dir() / f"{token}.artifact"
    from corpusfm.core.secure_fs import write_bytes_private
    write_bytes_private(path, data)
    return token


def read(token: str) -> Optional[bytes]:
    """Bytes for a staged token, or None if the token is invalid/missing."""
    path = _path_for(token)
    if path is None:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def discard(token: str) -> None:
    """Delete a staged file (on commit, on a pre-commit dup exclusion, or on cancel). Never raises."""
    path = _path_for(token)
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.debug("reabsorb staging: could not remove %s", path, exc_info=True)


def sweep(max_age_seconds: "float | None" = None) -> int:
    """Remove staged files. ``None`` clears ALL (startup — every token is orphaned once the
    process restarts, the token map being request-scoped). Otherwise only those older than the
    age (TTL sweep of abandoned tokens). Never raises. Returns the count removed."""
    try:
        d = staging_dir()
    except Exception:
        return 0
    now = time.time()
    removed = 0
    try:
        entries = list(d.glob("*.artifact"))
    except Exception:
        return 0
    for entry in entries:
        try:
            if max_age_seconds is not None and (now - entry.stat().st_mtime) < max_age_seconds:
                continue
            entry.unlink(missing_ok=True)
            removed += 1
        except Exception:
            logger.debug("reabsorb staging sweep: could not remove %s", entry, exc_info=True)
    if removed:
        logger.info("reabsorb staging sweep removed %d staged file(s)%s", removed,
                    "" if max_age_seconds is None else f" older than {int(max_age_seconds)}s")
    return removed
