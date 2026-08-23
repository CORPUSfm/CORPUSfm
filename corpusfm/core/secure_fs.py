"""Restrictive-permission filesystem helpers for sensitive local files.

Sensitive local artifacts (the session-signing secret, the app/server encryption keys
`corpus.key`/`machine.key`, staged `.artifact` bytes) must not be world-readable. These helpers
write files 0600 under a 0700 parent. On Windows POSIX modes are advisory — chmod is a no-op
there — so every call is best-effort and never raises on a chmod failure.
"""

from __future__ import annotations

import os
from pathlib import Path


def secure_dir(path: "str | Path") -> Path:
    """Create ``path`` (and parents) and tighten it to 0700. Best-effort chmod (no-op on Windows)."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


def write_text_private(path: "str | Path", data: str, *, encoding: str = "utf-8",
                       secure_parent: bool = True) -> None:
    """Write text to ``path`` as 0600, parent dir 0700. Best-effort chmod (no-op on Windows).

    ``secure_parent=False`` skips the parent-dir tightening — for a private file that lives in
    a directory whose mode is owned elsewhere (e.g. ``.mcp_env`` in the 755 install root, which
    the installer perms deliberately)."""
    write_bytes_private(path, data.encode(encoding), secure_parent=secure_parent)


def write_bytes_private(path: "str | Path", data: bytes, *, secure_parent: bool = True) -> None:
    """Write bytes to ``path`` as 0600, parent dir 0700. Best-effort chmod (no-op on Windows)."""
    p = Path(path)
    if secure_parent:
        secure_dir(p.parent)
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except PermissionError:
        # unlink needs WRITE ON THE PARENT DIR, which the service may not have (e.g. .mcp_env
        # lives in the root-owned 0755 install root). The service still owns the FILE, so fall
        # back to truncating it in place and re-asserting 0600 — create-at-0600 still holds
        # everywhere the dir allows creation; this branch only runs for a pre-existing file.
        fd = os.open(str(p), os.O_WRONLY | os.O_TRUNC)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
