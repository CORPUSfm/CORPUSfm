#!/usr/bin/env python3
"""Build the Series 2 runtime asset payload from reviewed stable asset trees.

In the consolidated public repository, the asset trees are tracked by the same exact public commit
as the application and installer. Private development can instead nominate two source repositories
and pinned commits; those are detached-materialized before use. The installer runtime never clones an
asset source — acquisition happens only at package construction.

Output:
  corpusfm-assets.zip   db/CORPUSfm_DB.fmp12          the storage database FMS hosts
                        db/CORPUSfm_DB.artifact       wrapped seed
                        addon/CORPUSfm_ADDON.fmaddon  the package FileMaker installs
                        addon/CORPUSfm_ADDON/…        the committed add-on folder
                        addon/CORPUSfm_ADDON_{SaveAsXML,AddonXML,MergedXML}.artifact  wrapped seeds
  assets.json           the pins and every source/output digest, for the release record

The `.xml` exports are evidence, not runtime, and are deliberately excluded.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Deterministic ZIP fields: same pinned inputs -> same payload bytes, so a package can be
# digest-compared instead of trusted.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644 << 16

BARE_SEEDS = ("CORPUSfm_DB.artifact", "CORPUSfm_ADDON_SaveAsXML.artifact",
              "CORPUSfm_ADDON_AddonXML.artifact", "CORPUSfm_ADDON_MergedXML.artifact")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def materialize(repo: str, commit: str, dest: Path) -> str:
    """`git archive <commit>` into dest. Resolves the pin to a full id and never touches the tree."""
    full = subprocess.run(["git", "-C", repo, "rev-parse", f"{commit}^{{commit}}"],
                          check=True, capture_output=True, text=True).stdout.strip()
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryFile() as tar_fh:
        subprocess.run(["git", "-C", repo, "archive", full], check=True, stdout=tar_fh)
        tar_fh.seek(0)
        with tarfile.open(fileobj=tar_fh) as tf:
            tf.extractall(dest)      # noqa: S202 — content is a pinned, reviewed source commit
    return full


def add(zf: zipfile.ZipFile, arcname: str, data: bytes) -> None:
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


def main() -> int:
    out_zip = Path(os.environ["ASSETS_ZIP"])
    build_dir = Path(os.environ["BUILD_DIR"])
    work = Path(tempfile.mkdtemp())
    try:
        public_db = os.environ.get("ASSET_DB_DIR", "")
        public_addon = os.environ.get("ASSET_ADDON_DIR", "")
        if public_db or public_addon:
            if not public_db or not public_addon:
                raise SystemExit("both ASSET_DB_DIR and ASSET_ADDON_DIR are required")
            db_dir, addon_dir = Path(public_db), Path(public_addon)
            revision = os.environ["ASSET_TREE_REVISION"]
            db_source, addon_source = "public-release-tree:installer/assets/db", \
                "public-release-tree:installer/assets/addon"
            db_commit = addon_commit = revision
        else:
            db_dir, addon_dir = work / "db", work / "addon"
            db_commit = materialize(os.environ["ASSET_DB_REPO"], os.environ["ASSET_DB_COMMIT"], db_dir)
            addon_commit = materialize(os.environ["ASSET_ADDON_REPO"],
                                       os.environ["ASSET_ADDON_COMMIT"], addon_dir)
            db_source, addon_source = "reviewed-stable-db-asset", "reviewed-stable-addon-asset"

        sources: dict[str, str] = {}
        outputs: dict[str, str] = {}
        buf = out_zip.open("wb")
        with zipfile.ZipFile(buf, "w") as z:
            fmp12 = (db_dir / "CORPUSfm_DB.fmp12").read_bytes()
            sources["CORPUSfm_DB.fmp12"] = sha256(fmp12)
            add(z, "db/CORPUSfm_DB.fmp12", fmp12)
            outputs["db/CORPUSfm_DB.fmp12"] = sha256(fmp12)

            fmaddon = (addon_dir / "CORPUSfm_ADDON.fmaddon").read_bytes()
            sources["CORPUSfm_ADDON.fmaddon"] = sha256(fmaddon)
            add(z, "addon/CORPUSfm_ADDON.fmaddon", fmaddon)
            outputs["addon/CORPUSfm_ADDON.fmaddon"] = sha256(fmaddon)

            folder = addon_dir / "CORPUSfm_ADDON"
            for p in sorted(folder.rglob("*")):
                if p.is_file():
                    rel = p.relative_to(folder).as_posix()
                    add(z, f"addon/CORPUSfm_ADDON/{rel}", p.read_bytes())

            for name in BARE_SEEDS:
                src = (db_dir if name.startswith("CORPUSfm_DB") else addon_dir) / name
                raw = src.read_bytes()
                sources[name] = sha256(raw)
                wrapped = wrap_seed(raw, name)
                sub = "db" if name.startswith("CORPUSfm_DB") else "addon"
                add(z, f"{sub}/{name}", wrapped)
                outputs[f"{sub}/{name}"] = sha256(wrapped)
        buf.close()

        manifest = {
            "schema_version": 1,
            "pins": {
                "db": {"source": db_source, "revision": db_commit},
                "addon": {"source": addon_source, "revision": addon_commit},
            },
            "source_digests": sources,
            "payload_digests": outputs,
            "payload_sha256": sha256(out_zip.read_bytes()),
            "excluded_evidence_only": ["CORPUSfm_DB.xml", "CORPUSfm_ADDON.xml",
                                       "CORPUSfm_ADDON.fmp12"],
        }
        (build_dir / "assets.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                                               encoding="utf-8")
        print(f"  + asset payload {manifest['payload_sha256'][:12]}… "
              f"(db {db_commit[:7]} / addon {addon_commit[:7]})")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
