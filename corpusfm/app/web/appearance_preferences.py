"""Standalone appearance preferences.

Server mode stores these values on the USER record.  Standalone has no USER, so its one local user
gets a small state-dir record.  This module is deliberately limited to presentation preferences.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from corpusfm.extensions.export.syntax_palettes import resolve_selection


def _path() -> Path:
    from corpusfm.lifecycle import app_paths
    return app_paths.state_dir() / "appearance_preferences.json"


def load() -> dict[str, str]:
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError, TypeError):
        data = {}
    selected = resolve_selection(data)
    return {"calculation_palette": selected.calculation, "script_palette": selected.script}


def save(body: dict) -> dict[str, str]:
    selected = resolve_selection(body)
    data = {"calculation_palette": selected.calculation, "script_palette": selected.script}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return data
