"""The composition edge — `build_context()` (inbox packet 006, runtime-composition refactor).

This is the ONE function a surface calls at startup to build its `AppContext`. Keeping the
construction in a single place is the point of the refactor: runtime mode / storage / config are
resolved here (or overridden for tests), not rediscovered at every call site.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from corpusfm.runtime.context import AppContext


def build_context(*, archive_dir: Optional[Path] = None, mode: Optional[str] = None) -> AppContext:
    """Compose the runtime graph for a surface.

    `mode` ("server" | "local") and `archive_dir` override the resolvers — pass them for tests
    or explicit composition; omit them in production and they resolve from `~/.corpusfm/install.yaml`
    (+ the `CORPUSFM_MODE` dev fallback) and the configured archive dir.
    """
    return AppContext(archive_dir=archive_dir, mode=mode)
