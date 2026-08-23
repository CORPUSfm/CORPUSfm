"""Runtime version/build stamp.

``corpusfm.__version__`` is ``0.{build}``. A published tree declares that build in the tracked root
``release-build.txt``; a private development checkout without that file falls back to its git commit
count. To keep the running
service from depending on ``git`` being on its PATH at runtime — the ``0.0`` class of bug (a service
whose PATH lacks git, a repo git refuses for dubious-ownership, a tree mid-swap, a slow git) — the
installer and the in-app updater WRITE the build number to ``corpusfm/_build.txt``. ``__init__`` reads
that stamp first and only shells out to git as a DEV fallback.

This module is the shared writer/reader used by the installer (Linux writes it in shell; Windows in
PowerShell), the in-app updater (after a successful pull), and the tests. The stamp file is gitignored
(it is generated per deploy; an untracked runtime file the clean-tree upgrade check already ignores).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional

# corpusfm/_build.txt — sits beside this module, inside the deployed package.
STAMP_PATH = Path(__file__).resolve().parent / "_build.txt"
RELEASE_BUILD_NAME = "release-build.txt"


def declared_build_number(repo_dir: Optional[Path] = None) -> Optional[str]:
    """The public tree's explicit stable release identity, or ``None`` when absent/invalid."""
    repo = Path(repo_dir) if repo_dir else Path(__file__).resolve().parent.parent
    try:
        value = (repo / RELEASE_BUILD_NAME).read_text(encoding="utf-8").strip()
        return value if value.isdigit() and int(value) > 0 else None
    except Exception:
        return None


def git_build_number(repo_dir: Optional[Path] = None, timeout: float = 10) -> Optional[str]:
    """The git commit count for ``repo_dir`` (default: the repo root above this package), or None if
    git can't be run. ``safe.directory='*'`` avoids git's dubious-ownership refusal when the caller
    differs from the checkout owner. ``timeout`` is short at import time (the dev fallback must not
    block startup) and generous for the writer."""
    repo = Path(repo_dir) if repo_dir else Path(__file__).resolve().parent.parent
    # Non-interactive ALWAYS (packet 065, the codified invariant): git shelled from a request/import path
    # must FAIL FAST, never block on an unanswerable prompt (a broken .git/config or hook could otherwise
    # hang this up to `timeout` at import time). Mirrors updater._run_git.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "Never"}
    try:
        r = subprocess.run(
            ["git", "-c", "safe.directory=*", "rev-list", "--count", "HEAD"],
            cwd=str(repo), capture_output=True, text=True, timeout=timeout, env=env,
        )
        if r.returncode == 0 and r.stdout.strip().isdigit():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def source_build_number(repo_dir: Optional[Path] = None, timeout: float = 10) -> Optional[str]:
    """Published release identity first; private-development git count second."""
    return declared_build_number(repo_dir) or git_build_number(repo_dir, timeout=timeout)


def read_stamp() -> Optional[str]:
    """The build number from the written stamp, or None if absent/invalid."""
    try:
        n = STAMP_PATH.read_text(encoding="utf-8").strip()
        return n if n.isdigit() else None
    except Exception:
        return None


def write_stamp(repo_dir: Optional[Path] = None) -> Optional[str]:
    """Compute the build number from git and persist it to ``_build.txt``. Returns the number on
    success, else None (and the existing stamp, if any, is left untouched). Best-effort — callers
    treat a None as "stamp not updated; runtime will fall back to git"."""
    n = source_build_number(repo_dir)
    if not n:
        return None
    try:
        STAMP_PATH.write_text(n + "\n", encoding="utf-8")
        # Verify the readback (packet 065): a partial/corrupt write must never leave a stale or garbled
        # number that the service then reports forever (the "version won't advance" class).
        if read_stamp() != n:
            raise OSError("stamp readback did not match")
        return n
    except Exception:
        # Remove a possibly-stale/partial stamp so runtime falls back to git cleanly rather than serving
        # an out-of-date version indefinitely.
        try:
            STAMP_PATH.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return None
