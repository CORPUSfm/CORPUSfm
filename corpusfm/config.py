"""Deployment mode detection for corpusfm.

Production: reads ~/.corpusfm/install.yaml written by the installer.
Development: falls back to CORPUSFM_MODE environment variable so existing
             dev workflows (CORPUSFM_MODE=server) are unchanged.

Public API:
    is_server_mode() -> bool
"""

from __future__ import annotations

import os


def is_server_mode() -> bool:
    """True when the install marker (or dev env var) indicates server mode."""
    from corpusfm.install import read_install_mode
    mode = read_install_mode()
    if mode is not None:
        return mode == "server"
    # Development fallback — no marker file present
    return os.environ.get("CORPUSFM_MODE", "").strip().lower() == "server"
