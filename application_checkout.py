"""Resolve the application checkout used by cross-repository installer verification."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


INSTALLER_ROOT = Path(__file__).resolve().parent


def _default_application_root() -> Path:
    """The consolidated public root, or the one sibling application checkout in development."""
    if (INSTALLER_ROOT / "corpusfm" / "__init__.py").is_file():
        return INSTALLER_ROOT
    candidates = sorted(
        path for path in INSTALLER_ROOT.parent.iterdir()
        if path.is_dir() and (path / "corpusfm" / "__init__.py").is_file()
    )
    if len(candidates) == 1:
        return candidates[0]
    ranked = []
    for path in candidates:
        result = subprocess.run(
            ("git", "-C", str(path), "rev-list", "--count", "HEAD"),
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip().isdigit():
            ranked.append((int(result.stdout.strip()), path))
    ranked.sort(reverse=True)
    if ranked and (len(ranked) == 1 or ranked[0][0] > ranked[1][0]):
        return ranked[0][1]
    raise RuntimeError(
        "Set CORPUSFM_APPLICATION_CHECKOUT to the complete CORPUSfm application checkout; "
        f"found {len(candidates)} sibling candidates"
    )


_DEFAULT_APPLICATION_ROOT = _default_application_root()
APPLICATION_ROOT = Path(
    os.environ.get("CORPUSFM_APPLICATION_CHECKOUT", _DEFAULT_APPLICATION_ROOT)
).expanduser().resolve()

if not (APPLICATION_ROOT / "corpusfm" / "__init__.py").is_file():
    raise RuntimeError(
        "Set CORPUSFM_APPLICATION_CHECKOUT to a complete CORPUSfm application checkout; "
        f"none was found at {APPLICATION_ROOT}"
    )
