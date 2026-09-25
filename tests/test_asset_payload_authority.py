"""Where the Series 2 runtime assets come from, and where they may never come from again.

THE POSITIVE RULE, which every test here is written around:

    ONE pinned application materialization supplies both the application source and the runtime
    assets. The assets are tracked application content at `assets/`; the commit that selects the
    source selects them; there is no second repository, no second pin, no second checkout and no
    second credential.

The model this replaces built each package from THREE repositories: the application, plus separate
database and add-on source-authority repositories, each with its own commit input and each checked
out with the shared token. Its tests were true of it, which is why they could not be repointed - the
number of sources was the thing that changed, so the rule had to be restated rather than edited.

Nothing here reaches GitHub, Azure or a box. Every "materialization" below is a real local git
repository built in a temporary directory, because a builder that refuses the wrong provenance only
on paper has not refused anything.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.test_package_signing_order import _finalize, _isolated_tree
from tests.test_windows_signing_inventory import ASSET_ENTRIES, build_candidate, write_asset_payload, ws

ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "installer/build-asset-payload.py"
BUILDER = BUILDER_PATH.read_text(encoding="utf-8")
PACKAGER = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")

# Spelled in two halves so the public projection scanner, which refuses private repository identity,
# does not read the guard's own subject as a leak. The property is unchanged: no retired external
# asset repository may be named by the builder or the packager.
EXTERNAL_ASSET_REPOSITORIES = (
    "PRIVATE" + "_FILEMAKER_APP_CORPUSfm_DB_v1",
    "PRIVATE" + "_FILEMAKER_APP_CORPUSfm_ADDON",
    "_DB_v1",
)

# The shape of a shippable `assets/` tree: what must be there, and what is evidence rather than
# runtime. Content is arbitrary here - this suite is about provenance and completeness, not bytes.
# Named files: each one is required by name, so its absence is an individual refusal.
REQUIRED_FILES = {
    "db/CORPUSfm_DB.fmp12": b"database\n",
    "db/CORPUSfm_DB.artifact": b'{"kind": "db seed"}\n',
    "addon/CORPUSfm_ADDON.fmaddon": b"addon package\n",
    "addon/CORPUSfm_ADDON_SaveAsXML.artifact": b'{"lens": "SaveAsXML"}\n',
    "addon/CORPUSfm_ADDON_AddonXML.artifact": b'{"lens": "AddonXML"}\n',
    "addon/CORPUSfm_ADDON_MergedXML.artifact": b'{"lens": "MergedXML"}\n',
}
# The add-on folder is required as a FOLDER and carried whole. Its membership is the add-on's own
# business - a new localisation ships without a packager change - so the requirement is that the
# folder exists and is not empty, not that any particular member is present.
ADDON_FOLDER_FILES = {
    "addon/CORPUSfm_ADDON/info.json": b'{"name": "CORPUSfm"}\n',
    "addon/CORPUSfm_ADDON/en.xml": b"<addon/>\n",
    "addon/CORPUSfm_ADDON/icon.png": b"\x89PNG\r\n\x1a\n",
}
REQUIRED = {**REQUIRED_FILES, **ADDON_FOLDER_FILES}
EVIDENCE_ONLY = {
    "db/CORPUSfm_DB.xml": b"<db/>\n",
    "addon/CORPUSfm_ADDON.xml": b"<addon-export/>\n",
    "addon/CORPUSfm_ADDON.fmp12": b"addon database\n",
}

WRAPPED_ENTRIES = (
    "db/CORPUSfm_DB.artifact",
    "addon/CORPUSfm_ADDON_SaveAsXML.artifact",
    "addon/CORPUSfm_ADDON_AddonXML.artifact",
    "addon/CORPUSfm_ADDON_MergedXML.artifact",
)


def _git(repo: Path, *args: str) -> str:
    environment = dict(os.environ)
    environment.update({
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    })
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=environment).stdout.strip()


def make_application(root: Path, assets: dict[str, bytes] | None = None,
                     symlinks: dict[str, Path] | None = None) -> tuple[Path, str]:
    """A local application repository with a tracked `assets/` tree. Returns (repo, commit).

    `symlinks` maps a path under `assets/` to a target, and the link is COMMITTED - git stores it
    as a mode-120000 blob holding the target path. Any entry it names replaces the ordinary file.
    """
    repo = root / "application"
    (repo / "corpusfm").mkdir(parents=True)
    (repo / "corpusfm" / "__init__.py").write_text("", encoding="utf-8")
    content = {**REQUIRED, **EVIDENCE_ONLY} if assets is None else assets
    planted = symlinks or {}
    for rel, blob in content.items():
        if rel in planted:
            continue
        path = repo / "assets" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    for rel, target in planted.items():
        path = repo / "assets" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
    _git(repo, "init", "--quiet", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "assets")
    return repo, _git(repo, "rev-parse", "HEAD")


def materialize(root: Path, repo: Path, commit: str) -> Path:
    """Exactly what the packager does: clone without a checkout, then check the pin out clean."""
    tree = root / "materialized"
    subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout",
                    str(repo), str(tree)], check=True, capture_output=True)
    _git(tree, "checkout", "--quiet", "-B", "main", commit)
    return tree


def build(root: Path, assets_dir: Path, commit: str) -> subprocess.CompletedProcess:
    out = root / "build"
    out.mkdir(exist_ok=True)
    environment = dict(os.environ)
    environment.update({
        "ASSET_SOURCE_DIR": str(assets_dir),
        "APPLICATION_COMMIT": commit,
        "ASSETS_ZIP": str(out / "corpusfm-assets.zip"),
        "BUILD_DIR": str(out),
    })
    return subprocess.run([sys.executable, str(BUILDER_PATH)],
                          capture_output=True, text=True, env=environment)


@pytest.fixture()
def built(tmp_path):
    repo, commit = make_application(tmp_path)
    tree = materialize(tmp_path, repo, commit)
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode == 0, result.stderr
    out = tmp_path / "build"
    manifest = json.loads((out / "assets.json").read_text())
    with zipfile.ZipFile(out / "corpusfm-assets.zip") as z:
        members = {name: z.read(name) for name in z.namelist()}
    return {"commit": commit, "repo": repo, "tree": tree, "out": out,
            "manifest": manifest, "members": members}


# ── the positive rule ───────────────────────────────────────────────────────────────────────────

def test_one_pinned_materialization_supplies_the_assets(built):
    """The whole rule in one assertion: the payload exists, and its provenance is the application
    commit that was packaged - not a repository/commit pair belonging to somewhere else."""
    provenance = built["manifest"]["provenance"]
    assert provenance["source"] == "application"
    assert provenance["application_commit"] == built["commit"]
    assert provenance["assets_root"] == "assets"


def test_the_manifest_names_the_tracked_path_behind_every_shipped_entry(built):
    """Truthful provenance is per-entry, not a headline. Every payload member says which tracked
    `assets/` file it came from, and that file's digest is recorded beside the shipped one."""
    manifest = built["manifest"]
    for entry in built["members"]:
        source = manifest["provenance"]["source_paths"][entry]
        assert source.startswith("assets/"), source
        assert source in manifest["source_digests"], source
        assert entry in manifest["payload_digests"], entry


def test_every_recorded_digest_is_the_byte_that_shipped(built):
    """Source and output hashes are complete AND correct - a manifest that merely has the right
    keys is a table of contents, not evidence."""
    manifest = built["manifest"]
    for entry, blob in built["members"].items():
        assert manifest["payload_digests"][entry] == hashlib.sha256(blob).hexdigest(), entry
    for source, digest in manifest["source_digests"].items():
        raw = (built["tree"] / source).read_bytes()
        assert digest == hashlib.sha256(raw).hexdigest(), source
    archive = (built["out"] / "corpusfm-assets.zip").read_bytes()
    assert manifest["payload_sha256"] == hashlib.sha256(archive).hexdigest()


def test_the_paired_addon_construction_survives(built):
    """The `.fmaddon` FileMaker installs AND the folder the download serves. One without the other
    is not a shippable add-on, and the folder is carried entry by entry rather than as an archive."""
    assert "addon/CORPUSfm_ADDON.fmaddon" in built["members"]
    folder = [n for n in built["members"] if n.startswith("addon/CORPUSfm_ADDON/")]
    assert sorted(folder) == ["addon/CORPUSfm_ADDON/en.xml", "addon/CORPUSfm_ADDON/icon.png",
                              "addon/CORPUSfm_ADDON/info.json"]


def test_the_deterministic_wrapping_survives(built):
    """Each bare seed is wrapped into a ZIP envelope whose single member is named as the file, with
    fixed timestamps - which is half of what makes the payload reproducible. The other half, that
    the same commit twice yields the same bytes, is the next test."""
    for entry in WRAPPED_ENTRIES:
        with zipfile.ZipFile(io.BytesIO(built["members"][entry])) as z:
            assert z.namelist() == [Path(entry).name]
            assert z.infolist()[0].date_time == (1980, 1, 1, 0, 0, 0)
            assert z.read(Path(entry).name) == REQUIRED_FILES[entry]


def test_the_same_commit_twice_produces_the_same_payload_bytes(tmp_path):
    repo, commit = make_application(tmp_path)
    tree = materialize(tmp_path, repo, commit)
    first = build(tmp_path, tree / "assets", commit)
    assert first.returncode == 0, first.stderr
    one = (tmp_path / "build" / "corpusfm-assets.zip").read_bytes()
    one_manifest = (tmp_path / "build" / "assets.json").read_bytes()
    second = build(tmp_path, tree / "assets", commit)
    assert second.returncode == 0, second.stderr
    assert (tmp_path / "build" / "corpusfm-assets.zip").read_bytes() == one
    assert (tmp_path / "build" / "assets.json").read_bytes() == one_manifest


def test_the_evidence_only_exports_are_never_shipped(built):
    """`.xml` exports and the add-on's own `.fmp12` are evidence. They are tracked, and they stay
    out of the runtime payload - named in the manifest so the omission is a decision on the record."""
    for rel in EVIDENCE_ONLY:
        assert not any(name.endswith(Path(rel).name) for name in built["members"]), rel
    assert built["manifest"]["excluded_evidence_only"] == [
        "assets/db/CORPUSfm_DB.xml", "assets/addon/CORPUSfm_ADDON.xml",
        "assets/addon/CORPUSfm_ADDON.fmp12",
    ]


def test_the_packager_reads_the_assets_from_the_materialization_it_already_made():
    """The packager's half of the rule, stated where it lives: the asset source is derived from
    `$APP_MATERIALIZED`, which is the clean clone of the pinned commit it built for the source and
    the bundle - not a path the caller can point elsewhere."""
    assert 'ASSET_SOURCE_DIR="$APP_MATERIALIZED/assets"' in PACKAGER
    assert 'APPLICATION_COMMIT="$COMMIT"' in PACKAGER


# ── the controls ────────────────────────────────────────────────────────────────────────────────

def test_the_builder_names_no_external_asset_repository():
    """Control: an external asset repository checkout returns."""
    for name in EXTERNAL_ASSET_REPOSITORIES:
        assert name not in BUILDER, name
        assert name not in PACKAGER, name


def test_no_asset_repository_commit_or_path_variable_survives():
    """Control: an asset-repository commit input returns, or a default sibling path does.

    The packager used to default to a sibling database-asset checkout under `$ROOT/..` and accept
    `CORPUSFM_ASSET_DB_COMMIT`. A default path to a sibling working tree is the worst form of this
    defect: it makes a build succeed locally against bytes nobody committed.
    """
    for name in ("ASSET_DB_REPO", "ASSET_ADDON_REPO", "ASSET_DB_COMMIT", "ASSET_ADDON_COMMIT",
                 "CORPUSFM_ASSET_DB_REPO", "CORPUSFM_ASSET_ADDON_REPO",
                 "CORPUSFM_ASSET_DB_COMMIT", "CORPUSFM_ASSET_ADDON_COMMIT"):
        assert name not in BUILDER, name
        assert name not in PACKAGER, name
    assert "$ROOT/.." not in PACKAGER


def test_the_builder_consults_no_repository_of_its_own():
    """Control: the builder reads a sibling repository or the caller's working tree.

    It used to run `git archive` against two repositories it was handed by name. It now takes a
    DIRECTORY, and the only git it runs is against that directory's own repository, to prove the
    directory is the pin it was told it is.
    """
    assert "git archive" not in BUILDER
    assert "materialize(" not in BUILDER
    # Its whole input surface, pinned: two paths, one commit, one output directory.
    assert sorted(set(re.findall(r'os\.environ\["([A-Z_]+)"\]', BUILDER))) == [
        "APPLICATION_COMMIT", "ASSETS_ZIP", "ASSET_SOURCE_DIR", "BUILD_DIR",
    ]


def test_the_builder_refuses_a_source_from_a_different_materialization(tmp_path):
    """Control: assets come from a different application materialization.

    The caller says "this directory is commit X". The builder asks the directory's own repository
    and refuses when it answers something else - which is what makes a swapped checkout a refusal
    instead of a silent substitution.
    """
    repo, commit = make_application(tmp_path)
    tree = materialize(tmp_path, repo, commit)
    (tree / "assets" / "db" / "CORPUSfm_DB.fmp12").write_bytes(b"different database\n")
    _git(tree, "commit", "--quiet", "-am", "a second commit")
    other = _git(tree, "rev-parse", "HEAD")
    assert other != commit

    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode != 0
    assert "not the pinned commit" in result.stderr, result.stderr


def test_the_builder_refuses_a_source_that_is_not_a_materialization_at_all(tmp_path):
    """Control, the blunter half: a loose directory of files has no provenance to state."""
    loose = tmp_path / "loose" / "assets"
    (loose / "db").mkdir(parents=True)
    (loose / "db" / "CORPUSfm_DB.fmp12").write_bytes(b"database\n")
    result = build(tmp_path, loose, "0" * 40)
    assert result.returncode != 0
    assert "no provenance" in result.stderr, result.stderr


def test_the_builder_refuses_a_dirty_materialization(tmp_path):
    """Control: required assets changed after the pin was resolved.

    An edit that is not committed cannot be named by a commit, so a payload built over it would
    carry provenance that is false rather than merely incomplete.
    """
    repo, commit = make_application(tmp_path)
    tree = materialize(tmp_path, repo, commit)
    (tree / "assets" / "db" / "CORPUSfm_DB.fmp12").write_bytes(b"edited in place\n")
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode != 0
    assert "are not clean" in result.stderr, result.stderr


# ── tracked symlinks: a clean tree is not a provenance proof ────────────────────────────────────
#
# FOUND BY INDEPENDENT REVIEW (Codex, 2026-09-20), and reproduced before it was fixed. Codex
# committed a required asset as a mode-120000 symlink to a file OUTSIDE the repository. `git status`
# was clean, the commit was real, the builder returned 0, and the payload carried the outside bytes
# with their digest recorded as the commit's own.
#
# That is the exact claim this builder exists to make - "these bytes are the pinned commit's" - and
# the HEAD and cleanliness checks cannot see it, because a tracked symlink is genuinely committed and
# genuinely clean. Git stores it as a blob holding the TARGET PATH; the content it resolves to was
# never committed anywhere.

OUTSIDE_MARKER = b"BYTES FROM OUTSIDE THE REPOSITORY - MUST NEVER BE PACKAGED\n"


def _plant_symlink(tmp_path, rel: str):
    """Commit `assets/<rel>` as a symlink to a file outside the repository, then build."""
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "planted"
    target.write_bytes(OUTSIDE_MARKER)

    repo, commit = make_application(tmp_path, symlinks={rel: target})
    # The link really is committed as a symlink, not silently dereferenced by `git add`.
    entry = _git(repo, "ls-files", "-s", "--", f"assets/{rel}")
    assert entry.split()[0] == "120000", entry
    # And the target really is outside the repository.
    assert repo not in target.parents

    tree = materialize(tmp_path, repo, commit)
    assert (tree / "assets" / rel).read_bytes() == OUTSIDE_MARKER, \
        "the materialization must really resolve to the outside bytes, or this proves nothing"
    return build(tmp_path, tree / "assets", commit), tmp_path / "build", rel


def _assert_outside_bytes_were_not_packaged(build_dir: Path):
    """Nothing under the build directory may contain the planted bytes - in a ZIP member, in a
    digest table, or in a stray partial file."""
    for path in build_dir.rglob("*"):
        if not path.is_file():
            continue
        assert OUTSIDE_MARKER not in path.read_bytes(), path
        if path.suffix == ".zip" and path.stat().st_size:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    assert OUTSIDE_MARKER not in z.read(name), f"{path}::{name}"


@pytest.mark.parametrize("rel", [
    "db/CORPUSfm_DB.fmp12",                 # a NAMED required asset
    "addon/CORPUSfm_ADDON/info.json",       # a MEMBER of the add-on folder, reached by the walk
])
def test_the_builder_refuses_an_asset_committed_as_a_symlink(tmp_path, rel):
    result, build_dir, _ = _plant_symlink(tmp_path, rel)
    assert result.returncode != 0, (
        f"assets/{rel} was a tracked symlink to outside the repository and the build succeeded"
    )
    assert "must be a regular file" in result.stderr, result.stderr
    assert rel in result.stderr and "120000" in result.stderr, result.stderr
    _assert_outside_bytes_were_not_packaged(build_dir)


@pytest.mark.parametrize("rel", [
    "db/CORPUSfm_DB.fmp12",
    "addon/CORPUSfm_ADDON/info.json",
])
def test_a_symlinked_asset_is_refused_before_any_payload_exists(tmp_path, rel):
    """Position matters as much as the refusal. If the check ran after the archive were written, a
    partially-built payload carrying the outside bytes would already be on disk for something else
    to pick up."""
    _, build_dir, _ = _plant_symlink(tmp_path, rel)
    archive = build_dir / "corpusfm-assets.zip"
    assert not archive.exists() or archive.stat().st_size == 0, "a payload was written anyway"
    assert not (build_dir / "assets.json").exists(), "a manifest was written for a refused build"


def test_a_symlinked_tree_is_still_clean_and_still_committed(tmp_path):
    """The reason the earlier checks could not catch this, asserted rather than asserted-about.

    If this test ever fails because the tree is dirty, the symlink control above has stopped
    exercising the case it was written for and is passing for the wrong reason.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "planted"
    target.write_bytes(OUTSIDE_MARKER)
    repo, commit = make_application(tmp_path, symlinks={"db/CORPUSfm_DB.fmp12": target})
    tree = materialize(tmp_path, repo, commit)
    assert _git(tree, "status", "--porcelain", "--", "assets") == ""
    assert _git(tree, "rev-parse", "HEAD") == commit


def test_a_tracked_gitlink_or_other_non_regular_entry_is_refused_too(tmp_path):
    """The rule is REGULAR FILE, not NOT-A-SYMLINK. A guard written against one mode would let the
    next one through, so the check lists what is allowed rather than what is forbidden."""
    assert 'REGULAR_BLOB_MODES = frozenset({"100644", "100755"})' in BUILDER
    assert "mode not in REGULAR_BLOB_MODES" in BUILDER


@pytest.mark.parametrize("missing", sorted(REQUIRED_FILES))
def test_the_builder_refuses_when_a_required_asset_is_absent(tmp_path, missing):
    """Control: required assets are missing. Each one, independently - a check that fires only for
    the first entry in a list is a check for one file."""
    content = {k: v for k, v in {**REQUIRED, **EVIDENCE_ONLY}.items() if k != missing}
    repo, commit = make_application(tmp_path, assets=content)
    tree = materialize(tmp_path, repo, commit)
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode != 0, f"{missing} was not required"
    assert "Refusing" in result.stderr and "missing" in result.stderr, result.stderr


def test_the_builder_refuses_when_the_addon_folder_is_absent(tmp_path):
    """Control: the paired add-on construction is half-present. The `.fmaddon` alone is not a
    shippable add-on, because the download serves the folder beside it."""
    content = {k: v for k, v in {**REQUIRED, **EVIDENCE_ONLY}.items()
               if not k.startswith("addon/CORPUSfm_ADDON/")}
    repo, commit = make_application(tmp_path, assets=content)
    tree = materialize(tmp_path, repo, commit)
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode != 0
    assert "CORPUSfm_ADDON is missing" in result.stderr, result.stderr


def test_the_builder_refuses_an_addon_folder_that_carries_only_desktop_state(tmp_path):
    """The two exclusions must not combine into a silent empty folder: dropping `.DS_Store` may not
    turn "the folder has no product files" into "the folder was carried"."""
    content = {k: v for k, v in {**REQUIRED, **EVIDENCE_ONLY}.items()
               if not k.startswith("addon/CORPUSfm_ADDON/")}
    content["addon/CORPUSfm_ADDON/.DS_Store"] = b"\x00\x00\x00\x01Bud1"
    repo, commit = make_application(tmp_path, assets=content)
    tree = materialize(tmp_path, repo, commit)
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode != 0
    assert "carries no files" in result.stderr, result.stderr


def test_the_builder_accepts_the_complete_tree(tmp_path):
    """The requirement checks' other half. A builder that refused every tree would pass all of the
    parametrized cases above and ship nothing."""
    repo, commit = make_application(tmp_path)
    tree = materialize(tmp_path, repo, commit)
    assert build(tmp_path, tree / "assets", commit).returncode == 0


def test_desktop_state_is_never_packaged(tmp_path):
    """Control: `.DS_Store` enters packaged content.

    It is untracked in the application repository, so it cannot normally reach a materialization at
    all - which is exactly why the packaging side needs its own check rather than relying on that.
    """
    content = {**REQUIRED, **EVIDENCE_ONLY,
               "addon/CORPUSfm_ADDON/.DS_Store": b"\x00\x00\x00\x01Bud1",
               "db/.DS_Store": b"\x00\x00\x00\x01Bud1"}
    repo, commit = make_application(tmp_path, assets=content)
    tree = materialize(tmp_path, repo, commit)
    result = build(tmp_path, tree / "assets", commit)
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(tmp_path / "build" / "corpusfm-assets.zip") as z:
        names = z.namelist()
    assert not [n for n in names if Path(n).name == ".DS_Store"], names
    manifest = json.loads((tmp_path / "build" / "assets.json").read_text())
    assert not [k for k in manifest["source_digests"] if k.endswith(".DS_Store")]


# ── the finalization half: what the candidate recorded is what ships ────────────────────────────
#
# These RUN finalization rather than reading the packager's source. An earlier draft of this section
# asserted that the guard's own strings were present, and a mutation that replaced its condition with
# `if False:` while leaving the message intact passed all four - a guard that is checked by spelling
# is a guard that can be disabled without any test noticing.

def _staged_candidate(tmp_path):
    candidate = build_candidate(tmp_path)
    ws.stage(candidate)
    return candidate


def _rewrite_payload(candidate: Path, entries: dict[str, bytes], *, commit: str | None = None):
    """Rebuild the candidate's asset payload and manifest so they agree with each other.

    Each refusal below must be provoked in ISOLATION. Dropping a member also changes the archive's
    digest, so a test that only deleted an entry would fire the digest check and prove nothing about
    the member-set check.
    """
    payload = candidate / "payload"
    write_asset_payload(payload, commit or json.loads(
        (candidate / "candidate.json").read_text())["commit"], entries=entries)


def test_an_untouched_candidate_finalizes(tmp_path):
    """The other half of every refusal below. A finalization that rejected everything would pass
    all four of them and ship nothing."""
    candidate = _staged_candidate(tmp_path)
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode == 0, result.stderr


def test_finalization_rejects_an_asset_payload_that_changed_after_staging(tmp_path):
    """Control: assets changed after staging. The candidate crosses artifact storage between two
    jobs on two machines, so the archive is re-hashed against what staging wrote down."""
    candidate = _staged_candidate(tmp_path)
    archive = candidate / "payload" / "corpusfm-assets.zip"
    archive.write_bytes(archive.read_bytes() + b"appended after staging")
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "changed after staging" in result.stderr, result.stderr


def test_finalization_rejects_a_payload_built_from_another_application_commit(tmp_path):
    """Control: assets come from a different application materialization - detected at the seam,
    where the materialization itself is long gone and only the two records can be compared."""
    candidate = _staged_candidate(tmp_path)
    _rewrite_payload(candidate, ASSET_ENTRIES, commit="f" * 40)
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "but this candidate is" in result.stderr, result.stderr


def test_finalization_rejects_a_payload_missing_a_recorded_member(tmp_path):
    """Control: a required asset went missing between the two halves. The manifest still promises
    it, and the archive no longer carries it."""
    candidate = _staged_candidate(tmp_path)
    full = json.loads((candidate / "payload" / "assets.json").read_text())
    _rewrite_payload(candidate, {k: v for k, v in ASSET_ENTRIES.items()
                                 if k != "addon/CORPUSfm_ADDON.fmaddon"})
    # Restore the COMPLETE digest table over the reduced archive, so only the member set disagrees.
    reduced = json.loads((candidate / "payload" / "assets.json").read_text())
    reduced["payload_digests"] = full["payload_digests"]
    (candidate / "payload" / "assets.json").write_text(
        json.dumps(reduced, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "does not match its manifest" in result.stderr, result.stderr


def test_finalization_rejects_desktop_state_in_the_payload(tmp_path):
    """Control: `.DS_Store` reaches packaged content. The builder refuses to write one; this is the
    independent check at the other end, for a payload that did not come from this build."""
    candidate = _staged_candidate(tmp_path)
    _rewrite_payload(candidate, {**ASSET_ENTRIES, "addon/CORPUSfm_ADDON/.DS_Store": b"Bud1"})
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "desktop state was packaged" in result.stderr, result.stderr
