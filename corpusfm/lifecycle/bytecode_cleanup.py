"""Retire installer-created Python bytecode from a deployed source checkout.

The services suppress bytecode writes, but an older Windows installer imported the deployed source
without doing so.  The privileged updater correctly treats ignored importable content as unclean.
This narrow migration removes only ordinary ``.pyc`` files inside ordinary ``__pycache__``
directories.  A link, reparse point, nested directory, or any other entry refuses before deletion.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path


class BytecodeCleanupRefused(Exception):
    """The cache set is not the disposable shape this migration owns."""


def _linklike(info: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(reparse and attributes & reparse)


def retire(repo: Path | str) -> int:
    """Remove the exact safe cache set beneath *repo* and return the directory count."""
    root = Path(repo).resolve(strict=True)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or _linklike(root_info):
        raise BytecodeCleanupRefused("the source root is not an ordinary directory")

    targets: list[tuple[Path, tuple[int, int], dict[str, tuple[int, int]]]] = []
    for current, directories, _files in os.walk(root, topdown=True, followlinks=False):
        for name in list(directories):
            path = Path(current, name)
            info = path.lstat()
            if name == ".git":
                directories.remove(name)
                continue
            if name != "__pycache__":
                if _linklike(info):
                    directories.remove(name)
                continue
            directories.remove(name)
            if not stat.S_ISDIR(info.st_mode) or _linklike(info):
                raise BytecodeCleanupRefused(f"{path} is a link or reparse point")
            entries: dict[str, tuple[int, int]] = {}
            with os.scandir(path) as scan:
                for entry in scan:
                    entry_info = entry.stat(follow_symlinks=False)
                    if (not entry.name.endswith(".pyc") or
                            not stat.S_ISREG(entry_info.st_mode) or _linklike(entry_info)):
                        raise BytecodeCleanupRefused(
                            f"{path} contains something other than ordinary .pyc files"
                        )
                    entries[entry.name] = (entry_info.st_dev, entry_info.st_ino)
            targets.append((path, (info.st_dev, info.st_ino), entries))

    # Re-read every target immediately before mutation. A substituted directory or child is left
    # untouched; the installer must never turn a check-then-swap race into recursive deletion.
    for path, identity, expected in targets:
        info = path.lstat()
        if (_linklike(info) or not stat.S_ISDIR(info.st_mode) or
                (info.st_dev, info.st_ino) != identity):
            raise BytecodeCleanupRefused(f"{path} changed after inspection")
        actual: dict[str, tuple[int, int]] = {}
        with os.scandir(path) as scan:
            for entry in scan:
                entry_info = entry.stat(follow_symlinks=False)
                if _linklike(entry_info) or not stat.S_ISREG(entry_info.st_mode):
                    raise BytecodeCleanupRefused(f"{path} changed after inspection")
                actual[entry.name] = (entry_info.st_dev, entry_info.st_ino)
        if actual != expected:
            raise BytecodeCleanupRefused(f"{path} changed after inspection")

    for path, _identity, entries in targets:
        for name in entries:
            Path(path, name).unlink()
        path.rmdir()
    return len(targets)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(json.dumps({"ok": False, "detail": "usage: bytecode_cleanup <source-root>"}))
        return 2
    try:
        removed = retire(args[0])
    except (BytecodeCleanupRefused, OSError) as exc:
        print(json.dumps({"ok": False, "detail": str(exc)}))
        return 1
    print(json.dumps({"ok": True, "removed_directories": removed}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
