"""Elevation check for lifecycle mutations (packet 1246-01, deliverable 2).

Only two lifecycle objects need this: the locator (root-owned `/etc/corpusfm` file, machine-wide
HKLM key) and, through it, the decision to publish or remove an installation's identity. Everything
else in this package is authorized by holding the lifecycle lock, which is a stronger and more
precise statement than "the caller happens to be root".

Kept as one tiny module so tests can substitute the answer at a single seam rather than patching a
platform call in five places.
"""

from __future__ import annotations

import os

from .errors import ElevationRequired


def is_elevated() -> bool:
    """True when this process can write machine-wide lifecycle state."""
    if os.name == "nt":  # pragma: no cover - platform-specific
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def require_elevation(action: str) -> None:
    """Raise ``ElevationRequired`` unless this process is elevated."""
    if not is_elevated():
        raise ElevationRequired(
            f"{action} requires administrator privilege; re-run the elevated CORPUSfm installer"
        )
