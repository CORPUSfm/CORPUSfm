#!/usr/bin/env python3
"""Build the Series 2 runtime asset payload from the pinned application materialization.

THE ASSETS ARE APPLICATION CONTENT (packet 1380-04 asset-authority correction). They are tracked in
the application repository at `assets/`, and they arrive here inside the SAME clean, detached
materialization of the ONE pinned application commit that already supplies the source tree, the Git
bundle and the version number. There is no second repository, no second pin, no second checkout and
no second credential: one commit selects the product, and the product includes its assets.

That is why this script takes a DIRECTORY and a COMMIT rather than repositories and pins. It reads
nothing else — not a sibling checkout, not the caller's working tree, not a remote — and it proves
the directory it was handed really is the pinned materialization's `assets/` before reading a byte
of it. An asset change is therefore an ordinary application change: it lands on application `main`,
it advances the commit count, and it advances the version.

Output:
  corpusfm-assets.zip   db/CORPUSfm_DB.fmp12          the storage database FMS hosts
                        db/CORPUSfm_DB.artifact       wrapped seed
                        addon/CORPUSfm_ADDON.fmaddon  the package FileMaker installs
                        addon/CORPUSfm_ADDON/…        the tracked add-on folder
                        addon/CORPUSfm_ADDON_{SaveAsXML,AddonXML,MergedXML}.artifact  wrapped seeds
  assets.json           the application commit, every source path, and every source/output digest

The `.xml` exports and the add-on's own `.fmp12` are evidence, not runtime, and are deliberately
excluded. `.DS_Store` is macOS desktop state: it is untracked in the application repository, and a
source one found here is EXCLUDED from the payload rather than refused - it is not product content,
so its presence in a source tree is not by itself a fault. What is refused is a `.DS_Store` reaching
the payload: `add()` will not write one, which is a backstop on the exclusion rather than a second
rule.

Every tracked entry under `assets/` must be a regular file. See `refuse_non_regular_entries`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Deterministic ZIP fields: the same pinned commit -> the same payload bytes, so a package can be
# digest-compared instead of trusted.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644 << 16

FULL_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")

# The only Git modes that are a regular file's own bytes. 120000 is a symlink, whose blob holds a
# TARGET PATH rather than content; 160000 is a gitlink. Neither is content this repository committed.
REGULAR_BLOB_MODES = frozenset({"100644", "100755"})

# Desktop state, never product content. Named once so every exclusion below is the same rule.
IGNORED_NAMES = frozenset({".DS_Store"})

# (path under assets/, payload entry) — copied byte for byte.
VERBATIM = (
    ("db/CORPUSfm_DB.fmp12", "db/CORPUSfm_DB.fmp12"),
    ("addon/CORPUSfm_ADDON.fmaddon", "addon/CORPUSfm_ADDON.fmaddon"),
)

# (path under assets/, payload entry) — a bare JSON document wrapped into the ZIP envelope the
# importer accepts, the envelope member named exactly as the file.
WRAPPED = (
    ("db/CORPUSfm_DB.artifact", "db/CORPUSfm_DB.artifact"),
    ("addon/CORPUSfm_ADDON_SaveAsXML.artifact", "addon/CORPUSfm_ADDON_SaveAsXML.artifact"),
    ("addon/CORPUSfm_ADDON_AddonXML.artifact", "addon/CORPUSfm_ADDON_AddonXML.artifact"),
    ("addon/CORPUSfm_ADDON_MergedXML.artifact", "addon/CORPUSfm_ADDON_MergedXML.artifact"),
)

# The paired add-on construction: the `.fmaddon` FileMaker installs and, beside it, the tracked
# folder the download serves. Both must be present; one without the other is not a shippable add-on.
ADDON_FOLDER = "addon/CORPUSfm_ADDON"
ADDON_FOLDER_ENTRY = "addon/CORPUSfm_ADDON"

EXCLUDED_EVIDENCE_ONLY = ("db/CORPUSfm_DB.xml", "addon/CORPUSfm_ADDON.xml",
                          "addon/CORPUSfm_ADDON.fmp12")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def refuse(message: str) -> None:
    raise SystemExit(f"Refusing: {message}")


def verify_pinned_materialization(assets_dir: Path, commit: str) -> None:
    """Prove `assets_dir` is the pinned application materialization's own `assets/`.

    The packager hands over `$APP_MATERIALIZED/assets`, but "the caller said so" is not the same
    claim as "these bytes are that commit's". So the repository containing the directory is asked
    its own HEAD, and its `assets/` path is required to be clean — which is what makes "the payload
    came from a DIFFERENT materialization" and "the assets changed after staging" refusals rather
    than silent substitutions.
    """
    if not FULL_COMMIT.match(commit):
        refuse(f"APPLICATION_COMMIT must be exactly 40 lowercase hex characters, got {commit!r}")
    if not assets_dir.is_dir():
        refuse(f"the pinned application materialization carries no assets directory at {assets_dir}")

    repo = assets_dir.parent
    try:
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        refuse(f"{repo} is not a git materialization, so its assets have no provenance")
    if head != commit:
        refuse(f"the asset source is materialization {head}, not the pinned commit {commit}")

    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--",
                            assets_dir.name],
                           check=True, capture_output=True, text=True).stdout.strip()
    if dirty:
        refuse(f"the materialized assets are not clean at {commit}: {dirty.splitlines()[0]}")

    refuse_non_regular_entries(repo, commit, assets_dir.name)


def refuse_non_regular_entries(repo: Path, commit: str, assets_root: str) -> None:
    """Every tracked entry under `assets/` must be a REGULAR blob in the pinned commit.

    A CLEAN TREE DOES NOT PROVE THE BYTES ARE THE COMMIT'S. Git stores a symlink as mode 120000
    whose blob is the TARGET PATH, not the target's content. So a tracked symlink is perfectly
    committed and perfectly clean while the bytes it resolves to live wherever the target points -
    outside the repository, off the machine's product tree, anywhere. Reading through it packages
    those bytes and records their digest as if the commit had supplied them, which is precisely the
    provenance claim this builder exists to make honestly.

    Measured, not hypothetical: a mode-120000 `assets/db/CORPUSfm_DB.fmp12` pointing at a file
    outside the repository produced a payload carrying the outside bytes and exited 0.

    This is asked of GIT rather than of the filesystem on purpose: `Path.is_symlink()` answers a
    question about a checkout, and the question here is what the COMMIT contains.

    And it is asked of the commit TREE rather than of the index, so it stands on its own. The index
    and HEAD do agree by the time this runs - the cleanliness check above has just established that
    - but a guard that is correct only because of the check before it is one refactor away from
    being correct by accident.
    """
    listing = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "-z", commit,
                              "--", assets_root],
                             check=True, capture_output=True, text=True).stdout
    offenders = []
    for row in listing.split("\0"):
        if not row:
            continue
        meta, path = row.split("\t", 1)
        mode = meta.split()[0]
        if mode not in REGULAR_BLOB_MODES:
            offenders.append(f"{path} (mode {mode})")
    if offenders:
        refuse(f"every tracked entry under {assets_root}/ must be a regular file, so that its bytes "
               f"are the pinned commit's own; refusing {', '.join(sorted(offenders))}")


def add(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
    if Path(arcname).name in IGNORED_NAMES:
        refuse(f"{arcname} is desktop state and must never be packaged")
    info = zipfile.ZipInfo(arcname, date_time=FIXED_DATE_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = FILE_MODE
    info.create_system = 0
    zf.writestr(info, data)


def wrap_seed(raw: bytes, name: str) -> bytes:
    """A bare JSON document -> the ZIP envelope the importer accepts, member named as the file.

    The retired `<base>.artifact.json` member name is NOT produced and the parser was not broadened
    to accept it (packet 1253's decision stands); the shipped bytes move to the current contract.
    """
    buf = tempfile.SpooledTemporaryFile(max_size=1 << 30)
    with zipfile.ZipFile(buf, "w") as z:
        add(z, name, raw)
    buf.seek(0)
    return buf.read()


def read_required(assets_dir: Path, rel: str) -> bytes:
    path = assets_dir / rel
    if not path.is_file():
        refuse(f"required asset assets/{rel} is missing from the pinned application materialization")
    return path.read_bytes()


def main() -> int:
    out_zip = Path(os.environ["ASSETS_ZIP"])
    build_dir = Path(os.environ["BUILD_DIR"])
    assets_dir = Path(os.environ["ASSET_SOURCE_DIR"])
    commit = os.environ["APPLICATION_COMMIT"]

    verify_pinned_materialization(assets_dir, commit)

    assets_root = assets_dir.name          # `assets`, the tracked directory name
    sources: dict[str, str] = {}           # assets/<path>            -> digest of the source byte
    outputs: dict[str, str] = {}           # <payload entry>          -> digest of the shipped byte
    source_of: dict[str, str] = {}         # <payload entry>          -> assets/<path>

    def record(rel: str, entry: str, raw: bytes, shipped: bytes) -> None:
        sources[f"{assets_root}/{rel}"] = sha256(raw)
        outputs[entry] = sha256(shipped)
        source_of[entry] = f"{assets_root}/{rel}"

    with out_zip.open("wb") as buf, zipfile.ZipFile(buf, "w") as z:
        for rel, entry in VERBATIM:
            raw = read_required(assets_dir, rel)
            add(z, entry, raw)
            record(rel, entry, raw, raw)

        folder = assets_dir / ADDON_FOLDER
        if not folder.is_dir():
            refuse(f"required asset folder assets/{ADDON_FOLDER} is missing from the "
                   "pinned application materialization")
        members = sorted(p for p in folder.rglob("*")
                         if p.is_file() and p.name not in IGNORED_NAMES)
        if not members:
            refuse(f"required asset folder assets/{ADDON_FOLDER} carries no files")
        for p in members:
            rel_in_folder = p.relative_to(folder).as_posix()
            raw = p.read_bytes()
            entry = f"{ADDON_FOLDER_ENTRY}/{rel_in_folder}"
            add(z, entry, raw)
            record(f"{ADDON_FOLDER}/{rel_in_folder}", entry, raw, raw)

        for rel, entry in WRAPPED:
            raw = read_required(assets_dir, rel)
            wrapped = wrap_seed(raw, Path(rel).name)
            add(z, entry, wrapped)
            record(rel, entry, raw, wrapped)

    manifest = {
        "schema_version": 2,
        "provenance": {
            # ONE materialization, named truthfully: the commit that was packaged and the tracked
            # paths the bytes were read from. No repository/commit pair exists to record, because
            # no second repository is consulted.
            "source": "application",
            "application_commit": commit,
            "assets_root": assets_root,
            "source_paths": source_of,
        },
        "source_digests": sources,
        "payload_digests": outputs,
        "payload_sha256": sha256(out_zip.read_bytes()),
        "excluded_evidence_only": [f"{assets_root}/{rel}" for rel in EXCLUDED_EVIDENCE_ONLY],
    }
    (build_dir / "assets.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                           encoding="utf-8")
    print(f"  + asset payload {manifest['payload_sha256'][:12]}… "
          f"({len(outputs)} entries from {assets_root}/ at {commit[:7]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
