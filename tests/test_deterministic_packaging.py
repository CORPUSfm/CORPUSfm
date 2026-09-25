"""Repacking one frozen tree must produce the same bytes (packet 1380-03, constraint 6).

MEASURED FAILURE (1380-03, disabled-handoff-finalization batch). The same frozen SYNTHETIC signed
tree finalized twice produced two different packages: `zip -X` records each member's mtime, signed
adoption rewrites the signed scripts at finalization time, and the difference propagated from the
nested `installer-runtime.zip` into `installer-files.sha256` and `installer-manifest.json`. Only the
builder can fix that - a pre-packaging `touch` cannot survive `adopt` rewriting the members.

These guards assert the PROPERTY, not the constants: an archive of one tree is the same bytes no
matter when it is built, under which umask, in which timezone, or in which order the members were
listed - while the member bytes, names and executable semantics are exactly what was handed in.

Same-toolchain boundary: byte identity is claimed for repeated runs on one interpreter and zlib.
Member names, bytes and modes are reproducible regardless.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
import time
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "installer/package-installer.sh"
WRITER = ROOT / "installer/zip_deterministic.py"

sys.path.insert(0, str(ROOT / "installer"))
import zip_deterministic as writer  # noqa: E402


SIGNED_SCRIPT = (b"Write-Host 'signed'\r\n"
                 b"# SIG # Begin signature block\r\n# SYNTHETIC\r\n# SIG # End signature block\r\n")


def _tree(base: Path) -> list[tuple[str, Path]]:
    """A frozen tree shaped like a runtime: nested paths, mixed modes, CRLF, incompressible bytes."""
    (base / "installer/windows").mkdir(parents=True)
    (base / "installer/linux").mkdir(parents=True)
    members = {
        "installer/windows/uninstall.ps1": (SIGNED_SCRIPT, 0o644),
        "installer/windows/_cfm_lib.ps1": (SIGNED_SCRIPT, 0o644),
        "installer/linux/uninstall.sh": (b"#!/bin/bash\nexit 0\n", 0o755),
        "installer/linux/_cfm_lib.sh": (b"# library\n", 0o644),
        "installer/requirements.txt": (b"corpusfm\n" * 400, 0o644),
        "payload.bin": (bytes(range(256)) * 40, 0o644),
    }
    for name, (data, mode) in members.items():
        path = base / name
        path.write_bytes(data)
        path.chmod(mode)
    return [(name, base / name) for name in members]


def _write(archive: Path, members, cwd: Path, *, umask: int = 0o022, tz: str = "UTC",
           mtime: float | None = None) -> bytes:
    """Write the archive in a subprocess, so umask and timezone really differ between runs."""
    if mtime is not None:
        for _, path in members:
            os.utime(path, (mtime, mtime))
    script = textwrap.dedent(f"""
        import os, sys
        os.umask({umask})
        sys.path.insert(0, {str(ROOT / "installer")!r})
        import zip_deterministic as w
        from pathlib import Path
        members = [(name, Path(source)) for name, source in {[(n, str(p)) for n, p in members]!r}]
        w.write_archive(Path({str(archive)!r}), members)
    """)
    environment = dict(os.environ, TZ=tz)
    subprocess.run([sys.executable, "-c", script], cwd=cwd, env=environment, check=True)
    return archive.read_bytes()


def test_one_frozen_tree_packs_to_the_same_bytes_whenever_it_is_packed(tmp_path):
    """The defect that was measured: a later build differed only because the members were newer."""
    base = tmp_path / "tree"
    base.mkdir()
    members = _tree(base)
    first = _write(tmp_path / "a.zip", members, tmp_path, mtime=946_684_800)  # 2000-01-01
    time.sleep(2.1)  # longer than the ZIP timestamp resolution, which is two seconds
    second = _write(tmp_path / "b.zip", members, tmp_path, mtime=time.time())
    assert first == second


def test_the_bytes_do_not_depend_on_umask_timezone_or_listing_order(tmp_path):
    base = tmp_path / "tree"
    base.mkdir()
    members = _tree(base)
    reference = _write(tmp_path / "a.zip", members, tmp_path, umask=0o022, tz="UTC")
    other = _write(tmp_path / "b.zip", list(reversed(members)), tmp_path, umask=0o077,
                   tz="Pacific/Kiritimati")
    assert reference == other


def test_member_bytes_names_and_executable_semantics_are_preserved(tmp_path):
    base = tmp_path / "tree"
    base.mkdir()
    members = _tree(base)
    archive = tmp_path / "a.zip"
    _write(archive, members, tmp_path)
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        assert [i.filename for i in entries] == sorted(name for name, _ in members)
        assert not [i for i in entries if i.filename.endswith("/")], "no directory entries"
        for name, source in members:
            assert bundle.read(name) == source.read_bytes(), name
            recorded = (bundle.getinfo(name).external_attr >> 16) & 0o7777
            expected = 0o755 if source.stat().st_mode & 0o111 else 0o644
            assert recorded == expected, name
            assert bundle.getinfo(name).create_system == 3
        # CRLF and the signature block survive byte for byte.
        assert bundle.read("installer/windows/uninstall.ps1") == SIGNED_SCRIPT
        assert {i.compress_type for i in entries} <= {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def test_incompressible_members_are_stored_rather_than_grown(tmp_path):
    base = tmp_path / "tree"
    base.mkdir()
    (base / "already.zip").write_bytes(os.urandom(4096))
    archive = tmp_path / "a.zip"
    writer.write_archive(archive, [("already.zip", base / "already.zip")])
    with zipfile.ZipFile(archive) as bundle:
        info = bundle.getinfo("already.zip")
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.compress_size == info.file_size


@pytest.mark.parametrize(("members", "reason"), [
    ([("a.txt", "a.txt"), ("a.txt", "b.txt")], "duplicate archive members"),
    ([("../escape.txt", "a.txt")], "unsafe archive member"),
])
def test_unsafe_or_duplicate_members_are_refused(tmp_path, members, reason):
    base = tmp_path / "tree"
    base.mkdir()
    for name in {source for _, source in members}:
        (base / name).write_text("x")
    if reason == "duplicate archive members":
        prepared = [(name, base / source) for name, source in members]
        with pytest.raises(SystemExit, match=reason):
            writer.write_archive(tmp_path / "a.zip", prepared)
    else:
        with pytest.raises(SystemExit, match=reason):
            writer.relative_members(base, [name for name, _ in members])


def test_the_builder_packs_through_the_deterministic_writer():
    """Every shipped archive goes through the rule; none is built by a plain `zip` call again."""
    script = BUILDER.read_text(encoding="utf-8")
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    assert not re.search(r"^\s*\(?\s*(cd [^&]+&&\s*)?zip\s", code, re.M), "a shipped archive is built by `zip`"
    for archive in ('"$CANDIDATE/payload/corpusfm-recovery-source.zip"', '"$runtime_zip"',
                    '"$BUILD_DIR/release/$zip_name"'):
        assert f'zip_deterministic.py" {archive}' in code, archive
    # The digest inventory the manifest covers is enumerated in C order, not the builder's locale.
    assert 'LC_ALL=C sort' in code


# Codex finding: the deflate/stored choice was MEASURED at COMPRESS_LEVEL while `writestr` compressed
# at zlib's default, because a ZipInfo built by hand carries no level. On most inputs both encoders
# agree, so the fixture below is chosen to be one where they do NOT.
def _level_sensitive_payload() -> bytes:
    """Deterministic bytes whose deflate output differs between the default level and level 9."""
    import hashlib
    chunk = hashlib.sha256(b"b").digest()
    blob = bytearray()
    while len(blob) < 64_000:
        chunk = hashlib.sha256(chunk).digest()
        blob += chunk.hex().encode()[:48]
        if len(blob) % 997 < 60:
            blob += b"corpusfm-installer-runtime-member-boundary-marker "
    return bytes(blob[:64_000])


def _deflate_size(data: bytes, level: int) -> int:
    import zlib
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return len(compressor.compress(data)) + len(compressor.flush())


def test_the_fixture_really_distinguishes_the_levels():
    """Control: without this, the guard below could pass on an input both encoders treat alike."""
    payload = _level_sensitive_payload()
    assert _deflate_size(payload, writer.COMPRESS_LEVEL) < _deflate_size(payload, -1)


def test_entries_are_written_at_the_level_the_choice_was_measured_at(tmp_path):
    payload = _level_sensitive_payload()
    source = tmp_path / "payload.txt"
    source.write_bytes(payload)
    archive = tmp_path / "a.zip"
    writer.write_archive(archive, [("payload.txt", source)])
    with zipfile.ZipFile(archive) as bundle:
        info = bundle.getinfo("payload.txt")
        assert info.compress_type == zipfile.ZIP_DEFLATED
        assert info.compress_size == _deflate_size(payload, writer.COMPRESS_LEVEL)
        assert info.compress_size != _deflate_size(payload, -1), "written at zlib's default level"
        assert bundle.read("payload.txt") == payload, "the member's bytes are unchanged"
