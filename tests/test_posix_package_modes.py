"""The executable bit has to survive the stage -> artifact -> finalize seam.

FOUND ON A LIVE BOX (packet 1380-04, 2026-09-20). The signed 0.2979 candidate installed fine as a
FRESH install but could not UPGRADE a 0.2818 predecessor:

    + Installer bundle verified: series-2 / 0.2979 / aad51931e760
    x Bootstrap handoff refused: verifier is missing or not executable
    LINUX UPGRADE EXIT: 2

`installer/linux/install.sh` guards the protocol-1 handoff with `[[ -x "$_handoff_verifier" ]]`, and
the shipped `cfm-verify-bootstrap-handoff.sh` had arrived at mode 0644. Measured against the
published predecessor, which had it at 0755 - so this was a regression, not a standing gap.

WHY IT COULD NOT HAPPEN BEFORE. The signing seam splits the build across two jobs, and the candidate
travels between them through GitHub Actions artifact storage, which does not preserve the executable
bit. A one-pass local build never crossed that boundary. `build_platform` inherited the extracted
modes and stated only the entry point's, so `install.sh` survived and everything else did not - in
the nested runtime archive too, where SIX members lost it.

The rule these tests defend: every mode the package needs is STATED at final assembly from a record
written while the modes were still true, and nothing is inherited from the extraction.
"""
from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.test_package_signing_order import _finalize, _isolated_tree
from tests.test_windows_signing_inventory import SERIES, VERSION, build_candidate, ws

ROOT = Path(__file__).resolve().parents[1]
PACKAGER = (ROOT / "installer/package-installer.sh").read_text(encoding="utf-8")
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")

# Derived from the INVOCATION PATHS, not assumed:
#   install.sh                        -- the entry point; `bash "$WORK/bundle/install.sh"` in the
#                                        installed bootstrap, and the mode a human unzipping the
#                                        package expects.
#   cfm-verify-bootstrap-handoff.sh   -- install.sh:`[[ -x "$_handoff_verifier" ]]` REQUIRES it.
# Deliberately NOT executable, because each is invoked through `bash` and guarded by `-f` only:
#   cfm-verify-installer-bundle.sh, _cfm_lib.sh
LINUX_OUTER_EXECUTABLE = {"install.sh", "cfm-verify-bootstrap-handoff.sh"}
LINUX_OUTER_NON_EXECUTABLE = {"cfm-verify-installer-bundle.sh", "_cfm_lib.sh"}


def zip_modes(data: bytes) -> dict[str, int]:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: (i.external_attr >> 16) & 0o7777 for i in z.infolist()}


# ── the audit, asserted rather than trusted ─────────────────────────────────────────────────────

def test_the_handoff_verifier_is_the_member_whose_contract_requires_the_bit():
    """If this guard ever moves, the executable set above has to be re-derived."""
    assert '[[ -x "$_handoff_verifier" ]]' in INSTALL_SH
    assert "verifier is missing or not executable" in INSTALL_SH


def test_the_bundle_verifier_is_guarded_only_by_existence():
    """Which is why it may stay 0644 - it is run through `bash`, never executed directly."""
    assert '[[ -f "$_bundle_verifier" ]]' in INSTALL_SH
    assert 'bash "$_bundle_verifier"' in INSTALL_SH


def test_git_tracks_the_required_members_as_executable():
    """The record the packager writes at staging is only as good as the checkout it reads."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-s", "installer/"],
                         check=True, capture_output=True, text=True).stdout
    modes = {}
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        modes[path] = meta.split()[0]
    assert modes["installer/linux/install.sh"] == "100755"
    assert modes["installer/linux/cfm-verify-bootstrap-handoff.sh"] == "100755"
    assert modes["installer/linux/cfm-verify-installer-bundle.sh"] == "100644"
    assert modes["installer/linux/_cfm_lib.sh"] == "100644"


# ── the seam, exercised end to end ──────────────────────────────────────────────────────────────

def flatten_modes(tree: Path) -> None:
    """What GitHub Actions artifact storage does to the candidate: every file becomes 0644."""
    for p in tree.rglob("*"):
        if p.is_file():
            p.chmod(0o644)


def stage_with_modes(tmp_path, mutate_record=None):
    """A candidate whose executable records are written BEFORE `stage`, as the packager does.

    Order matters and is the point of the seal: the real packager writes `candidate.json` and only
    then runs `windows_signing.py stage`, so the record is inside the staged digest. A fixture that
    edited it afterwards would be doing exactly what the Codex finding describes.
    """
    candidate = build_candidate(tmp_path)
    for name in LINUX_OUTER_EXECUTABLE:
        f = candidate / "linux" / "outer" / name
        if f.exists():
            f.chmod(0o755)
    for name in ("installer/linux/uninstall.sh", "installer/linux/cfm-proxy-exec.sh"):
        f = candidate / "linux" / "runtime" / name
        if f.exists():
            f.chmod(0o755)

    record = json.loads((candidate / "candidate.json").read_text())
    for platform in ("linux", "windows"):
        for slot, sub in (("executable_outer", "outer"), ("executable_runtime", "runtime")):
            base = candidate / platform / sub
            record["platforms"][platform][slot] = sorted(
                q.relative_to(base).as_posix()
                for q in base.rglob("*") if q.is_file() and os.access(q, os.X_OK)
            ) if base.is_dir() else []
    if mutate_record is not None:
        mutate_record(record)
    (candidate / "candidate.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    ws.stage(candidate)               # the seal closes over candidate.json here
    return candidate


@pytest.fixture()
def flattened(tmp_path):
    """A candidate staged with correct modes, then transported - i.e. flattened to 0644."""
    candidate = stage_with_modes(tmp_path)
    record = json.loads((candidate / "candidate.json").read_text())["platforms"]["linux"]
    outer, runtime = record["executable_outer"], record["executable_runtime"]
    flatten_modes(candidate)          # <- the transport
    return candidate, outer, runtime


def test_the_transport_really_does_flatten_the_candidate(flattened):
    """The control for the control. If flattening stopped happening, every test below would pass
    for the wrong reason."""
    candidate, outer, _ = flattened
    assert outer, "the fixture staged no executable outer member"
    for rel in outer:
        assert not os.access(candidate / "linux" / "outer" / rel, os.X_OK), rel


def test_the_finalized_linux_package_states_every_required_mode(tmp_path, flattened):
    candidate, outer, runtime = flattened
    root = _isolated_tree(tmp_path)
    result = _finalize(root, candidate, None)
    assert result.returncode == 0, result.stderr

    pkg = (root / f"outputs/server/{SERIES}/releases/{VERSION}"
           / f"corpusfm-installer-linux-{VERSION}.zip")
    modes = zip_modes(pkg.read_bytes())

    for name in sorted(set(outer)):
        assert modes[name] & stat.S_IXUSR, f"{name} shipped non-executable ({oct(modes[name])})"
    assert modes["install.sh"] == 0o755

    with zipfile.ZipFile(pkg) as z:
        nested = zip_modes(z.read("installer-runtime.zip"))
    for rel in runtime:
        assert nested[rel] & stat.S_IXUSR, f"runtime {rel} shipped non-executable"


def test_the_handoff_verifier_specifically_ships_0755(tmp_path, flattened):
    """The exact member whose 0644 broke the live upgrade."""
    candidate, _, _ = flattened
    root = _isolated_tree(tmp_path)
    assert _finalize(root, candidate, None).returncode == 0
    pkg = (root / f"outputs/server/{SERIES}/releases/{VERSION}"
           / f"corpusfm-installer-linux-{VERSION}.zip")
    modes = zip_modes(pkg.read_bytes())
    assert modes["cfm-verify-bootstrap-handoff.sh"] == 0o755


def test_intentionally_non_executable_members_stay_0644(tmp_path, flattened):
    """The other half. A fix that chmod-ed every .sh would pass the tests above and quietly widen
    the package's contract."""
    candidate, _, _ = flattened
    root = _isolated_tree(tmp_path)
    assert _finalize(root, candidate, None).returncode == 0
    pkg = (root / f"outputs/server/{SERIES}/releases/{VERSION}"
           / f"corpusfm-installer-linux-{VERSION}.zip")
    modes = zip_modes(pkg.read_bytes())
    for name in LINUX_OUTER_NON_EXECUTABLE:
        if name in modes:
            assert not (modes[name] & stat.S_IXUSR), f"{name} became executable ({oct(modes[name])})"


def test_the_packager_does_not_chmod_every_shell_file():
    """Stated structurally, so the narrow fix cannot be widened into a blanket one later."""
    assert "chmod 755 *.sh" not in PACKAGER
    assert 'chmod -R 755' not in PACKAGER
    assert "restore_modes" in PACKAGER


# ── the refusal itself, run against the real shipped logic ──────────────────────────────────────

def test_a_0644_handoff_verifier_reproduces_the_live_refusal(tmp_path):
    """The real guard from the real `install.sh`, executed - not a paraphrase of it.

    The guard is lifted verbatim out of the shipped script so this test fails if the product ever
    stops checking, and the refusal text is the one the live box printed.
    """
    begin = INSTALL_SH.index('    _handoff_verifier="$SCRIPT_DIR/cfm-verify-bootstrap-handoff.sh"')
    end = INSTALL_SH.index("    }", INSTALL_SH.index("verifier is missing or not executable")) + 5
    guard = INSTALL_SH[begin:end]
    assert "-x" in guard

    script = tmp_path / "guard.sh"
    script.write_text('SCRIPT_DIR="$1"\n' + guard + '\nprintf "ACCEPTED\\n"\n', encoding="utf-8")

    verifier = tmp_path / "cfm-verify-bootstrap-handoff.sh"
    verifier.write_text("#!/bin/bash\nprintf 'x\\n'\n", encoding="utf-8")

    verifier.chmod(0o644)
    refused = subprocess.run(["bash", str(script), str(tmp_path)], capture_output=True, text=True)
    assert refused.returncode == 2, refused.stdout
    assert "verifier is missing or not executable" in refused.stderr

    verifier.chmod(0o755)
    accepted = subprocess.run(["bash", str(script), str(tmp_path)], capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
    assert "ACCEPTED" in accepted.stdout


# ── the staging half ────────────────────────────────────────────────────────────────────────────
#
# The fixture above injects the executable record into `candidate.json`, because it stages a
# synthetic candidate rather than running the packager's own staging phase. That proves FINALIZE
# restores from the record; it cannot prove STAGING writes one. These two close that gap.

def test_staging_records_the_executable_set_for_both_platforms():
    assert "def executables(root):" in PACKAGER
    assert "os.access(q, os.X_OK)" in PACKAGER, "the record must be read from real modes"
    for platform in ("linux", "windows"):
        assert f'executables(Path(os.environ["CANDIDATE"], "{platform}", "outer"))' in PACKAGER
        assert f'executables(Path(os.environ["CANDIDATE"], "{platform}", "runtime"))' in PACKAGER


def test_finalization_writes_the_record_back_out_for_assembly():
    assert 'for slot, sub in (("executable_outer", "outer"), ("executable_runtime", "runtime")):' in PACKAGER
    assert 'restore_modes "$runtime_tree" "$BUILD_DIR/$platform-executable-runtime.txt"' in PACKAGER
    assert 'restore_modes "$stage" "$BUILD_DIR/$platform-executable-outer.txt"' in PACKAGER


def test_restore_modes_refuses_a_recorded_member_that_vanished(tmp_path):
    """A member that was executable at staging and is absent at assembly is a broken candidate.
    Skipping it quietly would ship the package the live box refused."""
    fn = PACKAGER[PACKAGER.index("restore_modes() {"):PACKAGER.index("build_platform() {")]
    script = tmp_path / "rm.sh"
    script.write_text("set -euo pipefail\n" + fn + '\nrestore_modes "$1" "$2"\n', encoding="utf-8")
    tree = tmp_path / "tree"; tree.mkdir()
    listing = tmp_path / "list.txt"; listing.write_text("gone.sh\n", encoding="utf-8")
    r = subprocess.run(["bash", str(script), str(tree), str(listing)], capture_output=True, text=True)
    assert r.returncode != 0
    assert "was executable at staging but is absent" in r.stderr


# ── the record is an AUTHORITY, so it is sealed ─────────────────────────────────────────────────
#
# FOUND BY CODEX REVIEW of the fix above. `candidate.json` decides which shipped members become
# 0755, but it sits at the candidate ROOT and the non-signable digest walk only covered the four
# subtrees. Editing that one file - and nothing else - made finalization ship `_cfm_lib.sh`
# executable and exit 0. The record was trusted because it was written by the build, which is the
# same reasoning the seam had already invalidated for file modes.

def _tamper_after_staging(candidate: Path, change) -> None:
    """Edit candidate.json AFTER the seal has closed over it - the exact reproduction."""
    record = json.loads((candidate / "candidate.json").read_text())
    change(record)
    (candidate / "candidate.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_making_a_member_executable_by_editing_only_candidate_json_is_refused(tmp_path):
    """The reproduction, end to end: nothing but candidate.json changes, and the package must not
    be assembled."""
    candidate = stage_with_modes(tmp_path)
    _tamper_after_staging(candidate, lambda r: r["platforms"]["linux"]["executable_outer"].append(
        "_cfm_lib.sh"))
    flatten_modes(candidate)

    root = _isolated_tree(tmp_path)
    result = _finalize(root, candidate, None)
    assert result.returncode != 0, "a tampered candidate.json was accepted"
    assert "candidate.json changed after staging" in result.stderr, result.stderr

    built = root / f"outputs/server/{SERIES}/releases/{VERSION}"
    assert not built.exists(), "the release was assembled despite the refusal"


def test_the_seal_covers_candidate_json_at_the_candidate_root():
    """Stated where it is easy to lose: the root file list, not only the tree walk."""
    ws_src = (ROOT / "installer/windows_signing.py").read_text(encoding="utf-8")
    assert 'NON_SIGNABLE_ROOT_FILES = ("candidate.json",)' in ws_src
    assert "for name in NON_SIGNABLE_ROOT_FILES:" in ws_src


def test_the_seal_is_checked_on_the_unsigned_path_too(tmp_path):
    """`adopt` re-digests the non-signable set, but the unsigned development build never calls it -
    and it reaches the same records. An untampered candidate still finalizes."""
    assert "assert-records-sealed" in PACKAGER
    candidate = stage_with_modes(tmp_path)
    flatten_modes(candidate)
    assert _finalize(_isolated_tree(tmp_path), candidate, None).returncode == 0


@pytest.mark.parametrize("bad", [
    # These escape the tree AND resolve to a real regular file, so only the component check can
    # refuse them. Without such a case the existence check would mask it, and the mutation that
    # deletes the component check would pass unnoticed - which is what happened on the first run.
    "../runtime/installer/linux/uninstall.sh",
    "../../linux/outer/install.sh",
    # These are refused by shape alone.
    "../outside.sh",
    "linux/../../escape.sh",
    "/etc/passwd",
    "nested/./odd.sh",
    "",
])
def test_an_unsafe_executable_entry_is_refused(tmp_path, bad):
    """Control: path traversal and malformed entries. The record is sealed, so this is a shape
    check - a stale or malformed entry must fail before it becomes a chmod target."""
    def change(record):
        record["platforms"]["linux"]["executable_outer"] = [bad]
    candidate = stage_with_modes(tmp_path, mutate_record=change)
    flatten_modes(candidate)
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0, f"{bad!r} was accepted"
    assert "Refusing:" in result.stderr and "executable_outer" in result.stderr, result.stderr


def test_an_entry_naming_an_absent_member_is_refused(tmp_path):
    """Control: the record names something the tree does not carry."""
    def change(record):
        record["platforms"]["linux"]["executable_outer"] = ["not-shipped.sh"]
    candidate = stage_with_modes(tmp_path, mutate_record=change)
    flatten_modes(candidate)
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "does not name a present regular member" in result.stderr, result.stderr


def test_a_duplicated_entry_is_refused(tmp_path):
    def change(record):
        record["platforms"]["linux"]["executable_outer"] = ["install.sh", "install.sh"]
    candidate = stage_with_modes(tmp_path, mutate_record=change)
    flatten_modes(candidate)
    result = _finalize(_isolated_tree(tmp_path), candidate, None)
    assert result.returncode != 0
    assert "repeats" in result.stderr, result.stderr


def test_a_well_formed_record_still_finalizes(tmp_path):
    """The other half of every refusal above."""
    candidate = stage_with_modes(tmp_path)
    flatten_modes(candidate)
    assert _finalize(_isolated_tree(tmp_path), candidate, None).returncode == 0
