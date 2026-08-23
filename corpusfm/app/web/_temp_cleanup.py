"""Cleanup of generated preview temp artifacts (Explorer/Diff HTML, patch JSON).

Explorer and Diff generate a SELF-CONTAINED HTML file into ``/tmp/corpusfm_{explorer,diff}_*``
and serve it via ``/api/preview/{task_id}`` (a plain ``FileResponse``). The task→path map is
*in-memory*, so once the browser has loaded the page it needs nothing further from the server,
and on a restart EVERY existing temp dir is orphaned (no task points to it → the preview URL
404s anyway). Nothing previously removed them, so they accumulated (70+ dirs, several GB).

This sweeps them safely:
  * ALL on startup — they're provably orphaned once the in-memory task map resets.
  * by AGE during uptime (default 6 h) — far longer than anyone views/reloads a preview; a
    reload after that just regenerates.
"""
from __future__ import annotations

import logging
import shutil
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Prefixes used by the generators (explorer.py / diff.py / generate.py patch temp).
_PREFIXES = ("corpusfm_explorer_", "corpusfm_diff_", "corpusfm_patch_")

# Uptime age threshold — older preview artifacts are swept on the next generation.
PREVIEW_TTL_SECONDS = 6 * 3600


def sweep_preview_temp(max_age_seconds: "float | None" = None) -> int:
    """Remove generated preview temp artifacts from the system temp dir.

    ``max_age_seconds=None`` removes ALL of them (startup — they're orphaned once the
    in-memory task map resets). Otherwise only those whose mtime is older than the age.
    Never raises. Returns the number removed.
    """
    tmp = Path(tempfile.gettempdir())
    now = time.time()
    removed = 0
    try:
        entries = list(tmp.glob("corpusfm_*"))
    except Exception:
        return 0
    for entry in entries:
        if not entry.name.startswith(_PREFIXES):
            continue
        try:
            if max_age_seconds is not None and (now - entry.stat().st_mtime) < max_age_seconds:
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink(missing_ok=True)
            removed += 1
        except Exception:
            logger.debug("preview temp sweep: could not remove %s", entry, exc_info=True)
    if removed:
        logger.info("preview temp sweep removed %d artifact(s)%s", removed,
                    "" if max_age_seconds is None else f" older than {int(max_age_seconds)}s")
    return removed
