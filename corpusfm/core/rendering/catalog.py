"""Load the rendering.yaml catalog via the schema registry."""

from __future__ import annotations

from typing import Optional

from corpusfm.core.schemas.registry import load_rendering_catalog as _load_raw


def load_catalog(version: str) -> tuple[dict, Optional[str]]:
    """Return ({step_id_int: entry_dict}, warning | None) for the given FM XML version."""
    raw, warning = _load_raw(version)
    steps_raw = raw.get("script_steps", {})
    catalog = {int(k): v for k, v in steps_raw.items()}
    return catalog, warning
