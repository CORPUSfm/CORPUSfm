#!/usr/bin/env python3
"""Deterministic ZIP construction for the installer packages (packet 1380-03).

WHY THIS EXISTS. `zip -X` records each member's mtime, and signed adoption rewrites the signed
scripts at finalization time. Finalizing one frozen signed tree twice therefore produced two
different `installer-runtime.zip` files, and that difference propagated into `installer-files.sha256`
and `installer-manifest.json` - so the same inputs did not yield the same package. 1380-03's
load-bearing constraint 6 requires that repacking one frozen tree be reproducible. Normalizing at
packaging time is the only place that can guarantee it: the builder owns the archive, and touching
files beforehand cannot survive `adopt` rewriting them.

THE RULE, and every part of it is a decision rather than an inherited default:

  * ORDER      - members are sorted by their archive path as BYTES (C order), never by directory
                 enumeration or shell glob order, which vary by filesystem and locale.
  * TIME       - every member carries 1980-01-01 00:00:00, the earliest timestamp the ZIP format can
                 represent. It is a constant, so it is timezone-independent and needs no clock. A
                 source-derived epoch was considered and rejected: finalization legitimately runs
                 from a candidate that carries no repository to read a commit date from.
  * MODE       - 0755 when any execute bit is set, 0644 otherwise, recorded as a Unix mode. The
                 executable SEMANTICS the package depends on are preserved exactly; the umask of
                 whoever happened to run the build is not.
  * SHAPE      - regular files only, no directory entries, no extra fields, no comments - matching
                 what `zip -X` produced for these archives.
  * COMPRESSION- deflate at COMPRESS_LEVEL, but STORED when that is not smaller, which is the shape
                 `zip` produced for already-compressed members such as the nested archives. The level
                 is passed explicitly to the write, so the measurement that chooses between deflate
                 and stored and the encoder that produces the bytes are the same one.

BOUNDARY: this makes the bytes reproducible for one toolchain. Two different zlib versions may encode
the same data differently, so identity is claimed for repeated runs on the same interpreter and zlib,
not across arbitrary environments. The archive CONTENTS (member names, bytes and modes) are
reproducible regardless.

Nothing here reads, rewrites or inspects member CONTENT: the bytes written are the bytes given, so a
signed script is stored exactly as adoption placed it.
"""
from __future__ import annotations

import argparse
import sys
import zipfile
import zlib
from pathlib import Path, PurePosixPath

# The earliest timestamp representable in a ZIP entry. Constant, hence clock- and timezone-free.
EPOCH = (1980, 1, 1, 0, 0, 0)
COMPRESS_LEVEL = 9


def member_mode(path: Path) -> int:
    """0755 or 0644: the executable semantics, stated rather than inherited from the umask."""
    executable = bool(path.stat().st_mode & 0o111)
    return 0o100755 if executable else 0o100644


def _deflated_size(data: bytes) -> int:
    """The size the write below will store, computed with the SAME level it is written at.

    The level has to be stated in both places. A `ZipInfo` built here carries no level of its own, so
    `writestr` would otherwise compress at zlib's default while this measurement used COMPRESS_LEVEL -
    two different encoders deciding one archive's bytes.
    """
    compressor = zlib.compressobj(COMPRESS_LEVEL, zlib.DEFLATED, -15)
    return len(compressor.compress(data)) + len(compressor.flush())


def write_archive(archive: Path, members: list[tuple[str, Path]]) -> None:
    """Write `members` - (archive path, source file) - as a deterministic ZIP."""
    ordered = sorted(members, key=lambda entry: entry[0].encode())
    names = [name for name, _ in ordered]
    if len(set(names)) != len(names):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        raise SystemExit(f"Refusing: duplicate archive members {duplicates}")
    with zipfile.ZipFile(archive, "w", compresslevel=COMPRESS_LEVEL) as bundle:
        for name, source in ordered:
            data = source.read_bytes()
            info = zipfile.ZipInfo(name, date_time=EPOCH)
            info.external_attr = member_mode(source) << 16
            info.create_system = 3  # Unix, so the recorded mode is the mode that is read back.
            # `zip` stores what deflate cannot shrink; mirror that, decided before writing.
            info.compress_type = (zipfile.ZIP_DEFLATED if _deflated_size(data) < len(data)
                                  else zipfile.ZIP_STORED)
            bundle.writestr(info, data, compresslevel=COMPRESS_LEVEL)


def relative_members(base: Path, names: list[str]) -> list[tuple[str, Path]]:
    members = []
    for name in names:
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"Refusing: unsafe archive member {name!r}")
        source = base / relative
        if not source.is_file() or source.is_symlink():
            raise SystemExit(f"Refusing: {name!r} is not a regular file under {base}")
        members.append((relative.as_posix(), source))
    return members


def tree_members(base: Path, root: str, exclude_dirs: tuple[str, ...], exclude_suffixes: tuple[str, ...]):
    members = []
    for path in (base / root).rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(base)
        if set(relative.parts) & set(exclude_dirs) or path.suffix in exclude_suffixes:
            continue
        members.append((relative.as_posix(), path))
    return members


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a deterministic ZIP")
    parser.add_argument("archive", type=Path)
    parser.add_argument("--base", type=Path, help="directory the named members are relative to")
    parser.add_argument("--member", action="append", default=[], help="member path relative to --base")
    parser.add_argument("--all", action="store_true", help="every regular file directly under --base")
    parser.add_argument("--flat", action="append", default=[], type=Path,
                        help="file added under its own basename")
    parser.add_argument("--tree", help="directory under --base added recursively")
    parser.add_argument("--exclude-dir", action="append", default=[])
    parser.add_argument("--exclude-suffix", action="append", default=[])
    args = parser.parse_args(argv)

    members: list[tuple[str, Path]] = []
    if args.all:
        members += [(path.name, path) for path in args.base.iterdir()
                    if path.is_file() and not path.is_symlink()]
    if args.member:
        members += relative_members(args.base, args.member)
    if args.tree:
        members += tree_members(args.base, args.tree, tuple(args.exclude_dir), tuple(args.exclude_suffix))
    members += [(path.name, path) for path in args.flat]
    if not members:
        raise SystemExit("Refusing: no archive members were selected")
    write_archive(args.archive, members)
    return 0


if __name__ == "__main__":
    sys.exit(main())
