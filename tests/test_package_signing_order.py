"""The packager's signing seam, and what may happen on each side of it (public closure).

1380-04 section 4 states one order and one prohibition:

    materialize every final Windows member -> sign and timestamp -> rebuild the
    nested runtime ZIP -> only then the payload digest file, manifest, outer ZIP, sidecar and
    release.json.  Signing an earlier representation and then rewriting it is forbidden.

The static tests below assert the SHAPE that makes that order possible - a staging phase that stops
before anything is archived, and a finalization phase that reads the candidate rather than the
repository. The end-to-end test at the bottom actually runs finalization against a synthetic
candidate, because a phase split that is merely well described is a phase split nobody has run.

Nothing here reaches Azure, GitHub or a box. The signed bytes are simulated by appending the comment
block Authenticode appends, which is the whole of what it does to a `.ps1`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.test_windows_signing_inventory import (
    SERIES,
    VERSION,
    WINDOWS_RUNTIME_MEMBERS,
    build_candidate,
    sign_all,
    ws,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGER_PATH = ROOT / "installer/package-installer.sh"
PACKAGER = PACKAGER_PATH.read_text(encoding="utf-8")


def _section(start: str, end: str | None = None) -> str:
    begin = PACKAGER.index(start)
    return PACKAGER[begin:] if end is None else PACKAGER[begin:PACKAGER.index(end, begin)]


# ── the shape of the seam ───────────────────────────────────────────────────────────────────────

def test_the_builder_offers_both_halves_of_the_seam():
    """A signer that cannot be handed a paused build has to be given a finished one instead."""
    assert "--stage-signing-candidate" in PACKAGER
    assert "--finalize-signing-candidate" in PACKAGER
    assert "--signed-members" in PACKAGER


def test_staging_stops_before_anything_is_archived():
    """THE ORDER. If staging archived first, the signature would be over bytes that are already
    inside a ZIP nobody can amend without rewriting it - which is the forbidden case."""
    staging = _section('if [[ "$PHASE" == stage ]]; then',
                       "fi  # ── end MATERIALIZE")
    assert "exit 0" in staging
    # Every outer/runtime archive is built by `build_platform`, and that function is defined and
    # called only after the staging exit.
    assert PACKAGER.index("build_platform() {") > PACKAGER.index('if [[ "$PHASE" == stage ]]; then')
    assert PACKAGER.index("build_platform linux") > PACKAGER.index("windows_signing.py\" stage")


def test_the_inventory_is_written_while_the_members_are_still_loose_files():
    """The inventory has to describe the final bytes, and it can only do that before assembly."""
    assert PACKAGER.index('windows_signing.py" stage') < PACKAGER.index("build_platform() {")
    assert PACKAGER.index("stage_platform windows") < PACKAGER.index('windows_signing.py" stage')


def test_signed_members_are_adopted_before_the_first_archive_is_written():
    """`adopt` places signed bytes into every occurrence. An archive built first would carry the
    unsigned ones, and the later copy would be a post-signing rewrite of the package."""
    assert PACKAGER.index('windows_signing.py" adopt') < PACKAGER.index("build_platform linux")


def test_the_finished_package_is_reopened_and_verified_last():
    """Build ORDER is a claim; opening the shipped archive is evidence. The verify call must come
    after the release directory is published, or it is inspecting something else."""
    assert PACKAGER.index('windows_signing.py" verify') > PACKAGER.index('mv "$BUILD_DIR/release"')
    verify = _section('windows_signing.py" verify')
    assert "$OUT_DIR/corpusfm-installer-windows-$VER.zip" in verify
    # D14: there is no standalone bootstrap to verify, because none is built or published.
    assert "--standalone" not in verify


def test_finalization_holds_no_credential_and_no_application_checkout():
    """No credential exists in the public build at all, and finalization must not need one either.

    Finalization runs where signed bytes are assembled. It must not need a token, a source of truth
    it could disagree with, or the asset repositories - so a compromise of that step reaches nothing.
    """
    finalize = _section('if [[ "$PHASE" == finalize ]]; then', "echo \"Published")
    for forbidden in ("PAT_FILE", "APP_ROOT", "APP_MATERIALIZED", "build-asset-payload.py",
                      "github_pat_", "api.github.com"):
        assert forbidden not in finalize, forbidden


def test_finalization_ships_the_candidate_bytes_and_never_re_reads_the_repository():
    """The rewrite this forbids is subtle: re-copying `installer/windows/*.ps1` during assembly
    would silently replace signed members with unsigned working-tree bytes, and every digest the
    build computed afterwards would agree with itself."""
    build = _section("build_platform() {", "build_platform linux")
    assert '"$CANDIDATE/$platform/outer"' in build
    assert '"$CANDIDATE/$platform/runtime"' in build
    assert '$SRC/' not in build
    assert "installer/windows/" not in build


def test_the_recorded_member_list_and_the_staged_tree_must_agree():
    """A file dropped from the candidate between staging and finalization would ship as a smaller
    runtime that still passes its own digest file."""
    guard = _section("the one the candidate RECORDED", "build_platform() {")
    assert "runtime_members" in guard
    assert "does not match the recorded member list" in guard


def test_the_ordinary_unsigned_build_still_runs_both_halves():
    """The local development build must exercise the released assembly path, not a second one.

    If `all` skipped either half, the signed release would be the only time that code ever ran.
    """
    assert "PHASE=all" in PACKAGER
    assert 'if [[ "$PHASE" != finalize ]]; then' in PACKAGER
    assert 'if [[ "$PHASE" == stage ]]; then' in PACKAGER
    # and `all` is what an invocation with neither flag selects
    assert PACKAGER.index("PHASE=all") < PACKAGER.index('"--finalize-signing-candidate"')


def test_no_credential_is_materialized_into_any_member_on_either_side_of_the_seam():
    """The public package is acquired anonymously. A credential seam filled before signing would
    ship inside signed bytes, and one filled after would invalidate them - so neither may exist."""
    for forbidden in ("materialize_pat_seam", "PAT_FILE", "--pat-file", "EMBEDDED_PAT",
                      "EmbeddedPat", "github_pat_", "api.github.com"):
        assert forbidden not in PACKAGER, forbidden


# ── the seam, actually run ──────────────────────────────────────────────────────────────────────

def _isolated_tree(tmp_path: Path) -> Path:
    """A throwaway ROOT. `package-installer.sh` resolves its root from its own location and writes
    `outputs/` beside it, so running the real script against a copy keeps the repository's own build
    output untouched.
    """
    root = tmp_path / "tree"
    (root / "installer").mkdir(parents=True)
    for name in ("package-installer.sh", "windows_signing.py", "zip_deterministic.py"):
        shutil.copyfile(ROOT / "installer" / name, root / "installer" / name)
    (root / "installer/package-installer.sh").chmod(0o755)
    return root


def _finalize(root: Path, candidate: Path, signed: Path | None):
    command = ["bash", str(root / "installer/package-installer.sh"),
               "--finalize-signing-candidate", str(candidate)]
    if signed is not None:
        command += ["--signed-members", str(signed)]
    # The script calls `python3` from PATH. The suite's own interpreter is put in front of it so the
    # build under test runs on a known interpreter rather than on whatever the developer host
    # happens to expose - on macOS that is an Xcode shim whose state is not this test's subject.
    environment = dict(os.environ)
    environment["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{environment['PATH']}"
    return subprocess.run(command, capture_output=True, text=True, env=environment)


@pytest.fixture()
def staged(tmp_path):
    candidate = build_candidate(tmp_path)
    ws.stage(candidate)
    return candidate


def test_finalization_produces_a_release_whose_windows_members_are_the_signed_bytes(tmp_path,
                                                                                   staged):
    """The end-to-end claim of this packet, run rather than described."""
    root = _isolated_tree(tmp_path)
    signed = sign_all(staged, tmp_path / "signed")
    result = _finalize(root, staged, signed)
    assert result.returncode == 0, result.stderr

    out = root / f"outputs/server/{SERIES}/releases/{VERSION}"
    package = out / f"corpusfm-installer-windows-{VERSION}.zip"
    assert package.is_file()
    assert (out / f"corpusfm-installer-linux-{VERSION}.zip").is_file()
    assert json.loads((out / "release.json").read_text())["installer_version"] == VERSION
    assert (root / f"outputs/server/{SERIES}/latest.json").is_file()

    # Every Windows occurrence inside the FINISHED archives is the byte stream that was signed.
    recorded = {row["stream"]: row["signed_sha256"] for row in ws.read_inventory(staged)["streams"]}
    assert all(recorded.values())
    report = json.loads((out / "windows-signature-map.json").read_text())
    assert report["signed"] is True
    assert len(report["occurrences"]) == 11

    with zipfile.ZipFile(package) as outer:
        assert ws.SIG_BEGIN in outer.read("install.ps1")
        assert ws.SIG_BEGIN in outer.read("_cfm_lib.ps1")
        nested = zipfile.ZipFile(__import__("io").BytesIO(outer.read("installer-runtime.zip")))
        for member in WINDOWS_RUNTIME_MEMBERS:
            data = nested.read(member)
            assert (ws.SIG_BEGIN in data) == member.endswith(".ps1"), member
        # The one library, signed once, in both positions.
        assert outer.read("_cfm_lib.ps1") == nested.read("installer/windows/_cfm_lib.ps1")

    # D14: nothing standalone is written beside the release, signed or otherwise.
    assert not (root / "outputs/server/bootstrap").exists()
    assert not (root / "dist").exists()


def test_the_linux_peer_is_built_and_stays_unsigned(tmp_path, staged):
    """1380-04 section 4, last sentence. Signing Linux would be a scope change nobody asked for,
    and an unsigned Linux peer that quietly stopped being built would be a missing release half."""
    root = _isolated_tree(tmp_path)
    result = _finalize(root, staged, sign_all(staged, tmp_path / "signed"))
    assert result.returncode == 0, result.stderr
    package = (root / f"outputs/server/{SERIES}/releases/{VERSION}"
               / f"corpusfm-installer-linux-{VERSION}.zip")
    with zipfile.ZipFile(package) as outer:
        for name in outer.namelist():
            if name.endswith((".sh", ".txt", ".json")):
                assert ws.SIG_BEGIN not in outer.read(name), name


def test_an_unsigned_finalization_still_builds_and_still_verifies(tmp_path, staged):
    """The ordinary development build. It runs the same assembly and the same verification, so the
    released path is rehearsed locally instead of being exercised for the first time under Azure."""
    root = _isolated_tree(tmp_path)
    result = _finalize(root, staged, None)
    assert result.returncode == 0, result.stderr
    report = json.loads(
        (root / f"outputs/server/{SERIES}/releases/{VERSION}/windows-signature-map.json").read_text()
    )
    assert report["signed"] is False
    assert len(report["occurrences"]) == 11


def test_finalization_refuses_when_the_copy_that_was_signed_is_not_the_copy_it_holds(tmp_path,
                                                                                    staged):
    """The candidate crosses storage the signing job does not own.

    The signing job consumed `sign/`; finalization holds its own copy. If the two disagree, the
    signature that came back is a signature over bytes this build is not about to ship - and every
    digest computed downstream would still agree with itself.
    """
    root = _isolated_tree(tmp_path)
    signed = sign_all(staged, tmp_path / "signed")
    (staged / ws.SIGN_DIRNAME / "outer-install.ps1").write_bytes(b"# something else\r\n")
    result = _finalize(root, staged, signed)
    assert result.returncode != 0
    assert "no longer matches its recorded digest" in result.stderr


def test_an_unsigned_finalization_still_catches_a_member_edited_after_staging(tmp_path, staged):
    """The final verification is not only about signatures.

    With no signed members the inventory still records what staging measured, so a candidate member
    edited between approval and assembly is caught by opening the finished archive. That keeps the
    development build a real rehearsal rather than a path with the checks switched off.
    """
    root = _isolated_tree(tmp_path)
    (staged / "windows/outer/install.ps1").write_bytes(b"# something else\r\n")
    result = _finalize(root, staged, None)
    assert result.returncode != 0
    assert "install.ps1" in result.stderr and "not the staged" in result.stderr


def test_finalization_refuses_to_overwrite_an_existing_release(tmp_path, staged):
    """A release directory is immutable. Re-running a finalize over one would silently replace
    bytes an operator may already have downloaded and approved."""
    root = _isolated_tree(tmp_path)
    assert _finalize(root, staged, sign_all(staged, tmp_path / "signed")).returncode == 0

    second = build_candidate(tmp_path / "again")
    ws.stage(second)
    result = _finalize(root, second, sign_all(second, tmp_path / "signed-again"))
    assert result.returncode != 0
    assert "immutable installer release already exists" in result.stderr
