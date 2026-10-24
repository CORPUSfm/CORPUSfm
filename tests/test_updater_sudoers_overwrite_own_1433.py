"""Packet 1433 overwrite-and-own (developer decision, October 24): an updater grant already standing
at `/etc/sudoers.d/corpusfm-update` no longer blocks a fresh install. The installer replaces it with
the canonical, visudo-validated rule, records the write truthfully as an OVERWRITE (present before),
and owns it, so a supported uninstall removes it and the next fresh install needs no cleanup.

Real: the exact attempt-record writer from install.sh against a temporary root, read back by the
application's classifier; the exact grant block and helper-snapshot loop from install.sh in bash.
Doubled: root ownership (the test uid), visudo and the installing command. Signed installed flows
remain the live proof.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

from corpusfm.lifecycle import install_attempt as ia
from corpusfm.lifecycle import uninstall_plan as up
from corpusfm.lifecycle.schema import OwnershipEntry

from tests.test_linux_install_attempt import SH, TEXT, Box, box  # noqa: F401 - fixture

LEGACY = "corpusfm ALL=(root) NOPASSWD: /usr/bin/systemctl start corpusfm-update.service\n"


def _grant(b):
    return b.root / "etc" / "sudoers.d" / "corpusfm-update"


def _place(path, text="x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_a_regular_legacy_grant_does_not_refuse_the_fresh_install(box):
    _place(_grant(box), LEGACY)
    ok = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert ok.returncode == 0 and ok.stdout == ""


def test_a_link_or_directory_at_the_grant_path_still_refuses(box, tmp_path):
    other = tmp_path / "unrelated"
    other.write_text("not ours")
    _grant(box).parent.mkdir(parents=True)
    _grant(box).symlink_to(other)
    linked = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert linked.returncode == 3 and str(_grant(box)) in linked.stdout
    _grant(box).unlink()
    _grant(box).mkdir()
    as_dir = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert as_dir.returncode == 3 and str(_grant(box)) in as_dir.stdout


def test_no_other_refuse_first_resource_is_relaxed(box):
    _place(box.root / "etc" / "sudoers.d" / "corpusfm-db-helper")
    refused = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert refused.returncode == 3 and "corpusfm-db-helper" in refused.stdout
    box.begin()
    step = box.run("step", box.container, os.getuid(), "file", "ensure", "-",
                   box.root / "etc" / "sudoers.d" / "corpusfm-db-helper", check=False)
    assert step.returncode != 0 and "REFUSE-FIRST" in step.stderr


def test_the_overwrite_is_ledgered_truthfully_and_owned(box):
    _place(_grant(box), LEGACY)
    box.begin()
    seqs = box.step("file", "ensure", "-", _grant(box))
    entry = box.raw()["ledger"][seqs[0] - 1]
    assert entry["intent"] == "overwrite", "an overwritten file is never reported as created"
    assert entry["prior"]["exists"] is True and entry["prior"]["type"] == "file"
    _grant(box).write_text(LEGACY)
    box.result("done", "-", seqs)
    assert box.run("wrote", box.container, os.getuid(), "file", _grant(box)).stdout.strip() == "true"
    assert box.run("created", box.container, os.getuid(), "file", _grant(box)).stdout.strip() == "false"
    record = box.record()
    assert ia.classify_target(record, str(_grant(box)), "file")[0] == ia.CLASS_MODIFIED
    assert ia.overwrote_updater_grant(record, str(_grant(box)))


def test_an_interrupted_attempt_that_overwrote_the_grant_may_remove_it(box):
    """Window B: the published manifest owns the overwritten grant; the filter keeps that removal."""
    db = box.root / "etc" / "sudoers.d" / "corpusfm-db-helper"
    _place(_grant(box), LEGACY)
    box.begin()
    s1 = box.step("file", "ensure", "-", db)
    db.write_text("rule\n")
    box.result("done", "-", s1)
    s2 = box.step("file", "ensure", "-", _grant(box))
    box.result("done", "-", s2)
    record = box.record()
    manifest = SimpleNamespace(services=(), ownership=tuple(
        OwnershipEntry("exact_resource", "privilege_helper_path", str(p)) for p in (db, _grant(box))))
    owed = {"sudoers_helpers": up.Decision(up.REMOVE, up.RECORDED, "test")}
    assert ia.attempt_filter(record, owed, manifest)["sudoers_helpers"].decision == up.REMOVE


def test_another_path_overwritten_is_not_attempt_owned(box):
    """Only the updater grant: an overwrite ledgered for any other file confers nothing."""
    other = box.root / "opt" / "elsewhere.conf"
    _place(other)
    box.begin()
    seqs = box.step("file", "ensure", "-", other)
    box.result("done", "-", seqs)
    record = box.record()
    assert box.raw()["ledger"][seqs[0] - 1]["intent"] == "overwrite"
    assert not ia.overwrote_updater_grant(record, str(other))


def _run_block(tmp_path, *, legacy, link=False, wrote=True, valid=True):
    text = TEXT
    begin = text.index('UPDATER_SRC="$CFM_RUNTIME_ROOT/installer/linux/corpusfm-update.sh"')
    block = text[begin:text.index("# ═══ PHASE 11", begin)]
    begin = text.index("        _lc_helpers=()")
    snapshot = text[begin:text.index('        _lc_helpers_json=', begin)]
    root = tmp_path / "root"
    dst = root / "etc" / "sudoers.d" / "corpusfm-update"
    dst.parent.mkdir(parents=True)
    if link:
        (tmp_path / "unrelated").write_text("not ours")
        dst.symlink_to(tmp_path / "unrelated")
    elif legacy:
        dst.write_text("anything an older installer or an operator left here\n")
    (tmp_path / "runtime/installer/linux").mkdir(parents=True)
    (tmp_path / "runtime/installer/linux/corpusfm-update.sh").write_text("template")
    block = block.replace("/etc/sudoers.d/corpusfm-update", str(dst))
    snapshot = snapshot.replace("/etc/sudoers.d/corpusfm-update", str(dst))
    harness = f'''
set -e
visudo() {{ {"true" if valid else "false"}; }}
warn() {{ :; }}
die() {{ echo "DIE: $*"; exit 9; }}
la_do() {{ while [[ "$1" != -- ]]; do shift; done; shift; [[ "$1 $2 $3 $4 $5 $6 $7" == "install -m 0440 -o root -g root" ]]; cp "$8" "$9"; chmod 0440 "$9"; }}
la_created() {{ false; }}
la_wrote() {{ {"true" if wrote else "false"}; }}
'''
    env = dict(os.environ, CFM_RUNTIME_ROOT=str(tmp_path / "runtime"), SERVICE_USER="corpusfm")
    proc = subprocess.run(["bash", "-c", harness + block + snapshot +
                           '\nprintf "OWNED:%s\\n" "${_lc_helpers[*]}"\n'],
                          env=env, text=True, capture_output=True)
    return proc, dst


def test_the_grant_block_replaces_existing_contents_with_the_canonical_rule_and_owns_it(tmp_path):
    proc, dst = _run_block(tmp_path, legacy=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert dst.read_text() == LEGACY and not dst.is_symlink()
    assert f"OWNED:{dst}" in proc.stdout


def test_the_missing_file_case_creates_and_owns_it(tmp_path):
    proc, dst = _run_block(tmp_path, legacy=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert dst.read_text() == LEGACY and f"OWNED:{dst}" in proc.stdout


def test_the_grant_block_refuses_to_write_through_a_link(tmp_path):
    proc, dst = _run_block(tmp_path, legacy=False, link=True)
    assert proc.returncode == 9 and "DIE:" in proc.stdout
    assert (tmp_path / "unrelated").read_text() == "not ours"


def test_a_leftover_grant_that_cannot_be_rewritten_stops_the_install(tmp_path):
    proc, dst = _run_block(tmp_path, legacy=True, valid=False)
    assert proc.returncode == 9 and "DIE:" in proc.stdout
    assert "OWNED:" not in proc.stdout


def test_an_update_asks_publish_installer_to_own_the_grant_it_wrote():
    begin = TEXT.index("_lc_req=\"$(lc_request publish-installer")
    req = TEXT[begin:TEXT.index('composition publish-installer --request', begin)]
    assert '"own_updater_sudoers":%s' in req and '"$UPDATER_SUDOERS_READY"' in req
