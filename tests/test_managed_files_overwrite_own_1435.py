"""Packet 1435 M2: the other fixed whole-content Linux files join the 1433 updater grant.

`/usr/local/bin/corpusfm`, `/etc/sudoers.d/corpusfm-db-helper` and `/etc/tmpfiles.d/corpusfm.conf`
left by older software no longer block a fresh install. Each regular file is replaced in place with
the installer's canonical content, ledgered truthfully as an OVERWRITE, and owned only once the write
completed; a link or non-regular object is refused and nothing is written through it. An update asks
publish-installer to own exactly the files it wrote.

Real: the attempt-record writer from install.sh against a temporary root, read back by the
application's classifier and attempt plan; the exact install.sh blocks in bash. Doubled: root
ownership, visudo, fmsadmin and `install`. Signed installed flows remain the live proof.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

from corpusfm.lifecycle import install_attempt as ia
from corpusfm.lifecycle import uninstall_plan as up
from corpusfm.lifecycle.schema import OwnershipEntry

from tests.test_linux_install_attempt import TEXT, _Layout, box  # noqa: F401 - fixture

NAMES = {"cli_shim": ("usr", "local", "bin", "corpusfm"),
         "db_helper_sudoers": ("etc", "sudoers.d", "corpusfm-db-helper"),
         "tmpfiles": ("etc", "tmpfiles.d", "corpusfm.conf")}


def _path(b, name):
    return b.root.joinpath(*NAMES[name])


def _place(path, text="left by an older installer\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# ── refuse-first and the write-ahead ledger ───────────────────────────────────────


@pytest.mark.parametrize("name", sorted(NAMES))
def test_a_regular_leftover_does_not_refuse_the_fresh_install(box, name):
    _place(_path(box, name))
    ok = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert ok.returncode == 0 and ok.stdout == ""


@pytest.mark.parametrize("name", sorted(NAMES))
def test_a_link_or_directory_still_refuses(box, tmp_path, name):
    other = tmp_path / "unrelated"
    other.write_text("not ours")
    target = _path(box, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(other)
    linked = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert linked.returncode == 3 and str(target) in linked.stdout
    target.unlink()
    target.mkdir()
    as_dir = box.run("refuse-check", json.dumps(box.paths), "false", check=False)
    assert as_dir.returncode == 3 and str(target) in as_dir.stdout
    assert other.read_text() == "not ours"


def _overwrite(box, name, state):
    seqs = box.step("file", "ensure", "-", _path(box, name))
    if state != "intended":
        box.result(state, "-", seqs)
    return seqs


@pytest.mark.parametrize("name", sorted(NAMES))
def test_the_overwrite_is_ledgered_truthfully_and_owned_once_written(box, name):
    _place(_path(box, name))
    box.begin()
    seqs = _overwrite(box, name, "done")
    entry = box.raw()["ledger"][seqs[0] - 1]
    assert entry["intent"] == "overwrite", "an overwritten file is never reported as created"
    assert entry["prior"]["exists"] is True and entry["prior"]["type"] == "file"
    assert box.run("wrote", box.container, os.getuid(), "file", _path(box, name)).stdout.strip() == "true"
    assert box.run("created", box.container, os.getuid(), "file", _path(box, name)).stdout.strip() == "false"
    record = box.record()
    assert ia.classify_target(record, str(_path(box, name)), "file")[0] == ia.CLASS_MODIFIED
    assert ia.overwrote_managed_file(record, str(_path(box, name)))
    assert not ia.overwrote_updater_grant(record, str(_path(box, name)))


def _plan(box):
    view, decisions = ia.attempt_plan(box.record(), _Layout(box.root))
    return {(e.kind, e.identifier) for e in view.ownership}, decisions


@pytest.mark.parametrize("state", ["intended", "done"])
def test_an_interrupted_overwrite_is_removable_by_discard_and_still_reads_as_an_overwrite(box, state):
    """Interrupted before (intended) or after (done) the write: the attempt owns what it replaces."""
    for name in NAMES:
        _place(_path(box, name))
    box.begin()
    for name in NAMES:
        _overwrite(box, name, state)
    owned, decisions = _plan(box)
    assert ("cli_shim_path", str(_path(box, "cli_shim"))) in owned
    for name in ("db_helper_sudoers", "tmpfiles"):
        assert ("privilege_helper_path", str(_path(box, name))) in owned
    assert decisions["cli_shim"].decision == up.REMOVE
    assert decisions["sudoers_helpers"].decision == up.REMOVE
    assert all(e["intent"] == "overwrite" and e["prior"]["exists"] is True
               for e in box.raw()["ledger"] if e["kind"] == "file")
    manifest = SimpleNamespace(services=(), ownership=tuple(
        OwnershipEntry("exact_resource", kind, ident) for kind, ident in sorted(owned)))
    narrowed = ia.attempt_filter(box.record(), decisions, manifest)
    assert narrowed["cli_shim"].decision == up.REMOVE
    assert narrowed["sudoers_helpers"].decision == up.REMOVE


def test_a_failed_overwrite_confers_no_ownership(box):
    for name in NAMES:
        _place(_path(box, name))
    box.begin()
    for name in NAMES:
        _overwrite(box, name, "failed")
    record = box.record()
    assert not any(ia.overwrote_managed_file(record, str(_path(box, n))) for n in NAMES)
    owned, decisions = _plan(box)
    assert owned == set()
    assert decisions["cli_shim"].decision == up.PRESERVE
    assert decisions["sudoers_helpers"].decision == up.PRESERVE
    for name in NAMES:
        assert box.run("wrote", box.container, os.getuid(), "file",
                       _path(box, name)).stdout.strip() == "false"


def test_a_missing_file_is_created_as_before(box):
    box.begin()
    seqs = box.step("file", "ensure", "-", _path(box, "tmpfiles"))
    _place(_path(box, "tmpfiles"), "rule\n")
    box.result("done", "-", seqs)
    entry = [e for e in box.raw()["ledger"] if e["kind"] == "file"][0]
    assert entry["intent"] == "create" and entry["prior"] == {"exists": False}
    assert box.run("created", box.container, os.getuid(), "file",
                   _path(box, "tmpfiles")).stdout.strip() == "true"


def test_an_attempt_record_written_before_m2_still_reads(box):
    """A 1433-era attempt (only the updater grant overwritten, the rest created) plans as before."""
    grant = box.root / "etc" / "sudoers.d" / "corpusfm-update"
    _place(grant)
    box.begin()
    for name in NAMES:
        seqs = box.step("file", "ensure", "-", _path(box, name))
        _place(_path(box, name), "new\n")
        box.result("done", "-", seqs)
    box.result("done", "-", box.step("file", "ensure", "-", grant))
    owned, decisions = _plan(box)
    assert ("privilege_helper_path", str(grant)) in owned
    assert ("cli_shim_path", str(_path(box, "cli_shim"))) in owned
    assert decisions["sudoers_helpers"].decision == up.REMOVE


# ── the exact install.sh blocks ────────────────────────────────────────────────────


_STUBS = '''
set -euo pipefail
die() { echo "DIE: $*"; exit 9; }
ok() { :; }; warn() { echo "WARN: $*"; }; info() { :; }
la_begin() { LA_SEQS=""; }
la_end() { echo "LA_END:$1"; return "$1"; }
install() { :; }
# The Mac running this is not root: the owner change is recorded, never performed.
chown() { echo "CHOWN:$*"; [[ -z "${CFM_TEST_CHOWN_FAILS:-}" ]]; }
la_do() {
    local args=() ; while [[ "$1" != -- ]]; do args+=("$1"); shift; done; shift
    if [[ "${args[0]} ${args[1]}" == "file ensure" ]]; then cp "$8" "$9"; chmod 0440 "$9"; fi
}
'''


def _helper(text):
    begin = text.index("cfm_replaceable_file() {")
    return text[begin:text.index("\n}\n", begin) + 3]


def _bash(tmp_path, body, *, fmsadmin=True, valid=True, chown_fails=False):
    harness = _STUBS + _helper(TEXT) + (
        "fmsadmin() { :; }\n" if fmsadmin else "") + (
        "visudo() { %s; }\n" % ("true" if valid else "false"))
    (tmp_path / "runtime/installer/linux").mkdir(parents=True, exist_ok=True)
    (tmp_path / "runtime/installer/linux/cfm-db-helper.sh").write_text("helper")
    env = dict(os.environ, CFM_RUNTIME_ROOT=str(tmp_path / "runtime"), SERVICE_USER="corpusfm",
               INSTALL_DIR=str(tmp_path / "opt"), HOSTING_DIR=str(tmp_path / "hosted"),
               FM_DB_DIR=str(tmp_path / "db"))
    if chown_fails:
        env["CFM_TEST_CHOWN_FAILS"] = "1"
    return subprocess.run(["bash", "-c", harness + body], env=env, text=True, capture_output=True)


def _block(start, end, real, fake):
    begin = TEXT.index(start)
    return TEXT[begin:TEXT.index(end, begin)].replace(real, fake)


def _shim_block(dst):
    return _block('info "Installing /usr/local/bin/corpusfm..."', '# ── Installed uninstaller',
                  "/usr/local/bin/corpusfm", str(dst))


def _tmpfiles_block(dst):
    return _block('info "Installing /etc/tmpfiles.d/corpusfm.conf..."',
                  "# ── Updater sudoers ownership", "/etc/tmpfiles.d/corpusfm.conf", str(dst)
                  ).replace("systemd-tmpfiles --create", ": ")


def _db_block(dst):
    return _block("DB_HELPER_SUDOERS_READY=false", "# ── Retire the storage-swap",
                  "/etc/sudoers.d/corpusfm-db-helper", str(dst)).replace(
                      "/var/lib/corpusfm/handoff", "/nonexistent/handoff")


def _target(tmp_path, kind, how):
    dst = tmp_path / "root" / kind
    dst.parent.mkdir(parents=True, exist_ok=True)
    if how == "leftover":
        dst.write_text("anything an older installer or an operator left here\n")
    elif how == "link":
        (tmp_path / "unrelated").write_text("not ours")
        dst.symlink_to(tmp_path / "unrelated")
    return dst


@pytest.mark.parametrize("how", ["leftover", "missing"])
def test_the_shim_and_tmpfiles_blocks_write_canonical_content(tmp_path, how):
    shim, rule = _target(tmp_path, "shim", how), _target(tmp_path, "rule", how)
    proc = _bash(tmp_path, _shim_block(shim) + _tmpfiles_block(rule)
                 + '\necho "FLAGS:$CLI_SHIM_WRITTEN:$TMPFILES_WRITTEN"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FLAGS:true:true" in proc.stdout
    assert shim.read_text().startswith("#!/usr/bin/env bash\n# CORPUSfm CLI wrapper")
    assert f"exec {tmp_path / 'opt'}/venv/bin/python -m corpusfm.server.cli" in shim.read_text()
    assert os.access(shim, os.X_OK)
    assert rule.read_text().startswith("# CORPUSfm") and "d /run/corpusfm 0750" in rule.read_text()


def test_a_loose_leftover_is_normalized_to_the_canonical_owner_and_mode(tmp_path):
    """1435 M4: `cat >` keeps the inode, so a regular leftover kept its owner and mode. The blocks
    now request root:root and set 0755 / 0644 after the canonical content."""
    shim, rule = _target(tmp_path, "shim", "leftover"), _target(tmp_path, "rule", "leftover")
    shim.chmod(0o666)
    rule.chmod(0o666)
    proc = _bash(tmp_path, _shim_block(shim) + _tmpfiles_block(rule)
                 + '\necho "FLAGS:$CLI_SHIM_WRITTEN:$TMPFILES_WRITTEN"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"CHOWN:root:root {shim}\n" in proc.stdout and f"CHOWN:root:root {rule}\n" in proc.stdout
    assert stat.S_IMODE(shim.stat().st_mode) == 0o755
    assert stat.S_IMODE(rule.stat().st_mode) == 0o644
    assert shim.read_text().startswith("#!/usr/bin/env bash\n# CORPUSfm CLI wrapper")
    assert "FLAGS:true:true" in proc.stdout


@pytest.mark.parametrize("which", ["shim", "rule"])
def test_a_failed_owner_change_stops_before_the_written_flag(tmp_path, which):
    """A file whose metadata could not be made canonical is never reported written, so the
    foundation and the update request never claim it."""
    dst = _target(tmp_path, which, "leftover")
    block, flag = {"shim": (_shim_block, "CLI_SHIM_WRITTEN"),
                   "rule": (_tmpfiles_block, "TMPFILES_WRITTEN")}[which]
    proc = _bash(tmp_path, block(dst) + f'\necho "REACHED:${{{flag}:-unset}}"\n', chown_fails=True)
    assert proc.returncode != 0 and "REACHED" not in proc.stdout, proc.stdout + proc.stderr
    assert f"CHOWN:root:root {dst}" in proc.stdout
    assert "LA_END:0" not in proc.stdout and "LA_END:" in proc.stdout, "the ledger result is not failed"


@pytest.mark.parametrize("which", ["shim", "rule", "db"])
def test_no_block_writes_through_a_link(tmp_path, which):
    dst = _target(tmp_path, which, "link")
    body = {"shim": _shim_block, "rule": _tmpfiles_block, "db": _db_block}[which](dst)
    proc = _bash(tmp_path, body + '\necho REACHED\n')
    assert proc.returncode == 9 and "DIE:" in proc.stdout and "REACHED" not in proc.stdout
    assert (tmp_path / "unrelated").read_text() == "not ours"


@pytest.mark.parametrize("how", ["leftover", "missing"])
def test_the_db_helper_block_replaces_the_grant_with_the_validated_rule(tmp_path, how):
    dst = _target(tmp_path, "db", how)
    proc = _bash(tmp_path, _db_block(dst) + '\necho "READY:$DB_HELPER_SUDOERS_READY"\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "READY:true" in proc.stdout
    assert dst.read_text() == f"corpusfm ALL=(root) NOPASSWD: {tmp_path / 'opt'}/bin/cfm-db-helper\n"


@pytest.mark.parametrize("fmsadmin, valid", [(True, False), (False, True)])
def test_a_leftover_grant_that_cannot_be_rewritten_stops_the_install(tmp_path, fmsadmin, valid):
    dst = _target(tmp_path, "db", "leftover")
    proc = _bash(tmp_path, _db_block(dst) + '\necho REACHED\n', fmsadmin=fmsadmin, valid=valid)
    assert proc.returncode == 9 and "DIE:" in proc.stdout and "REACHED" not in proc.stdout
    assert dst.read_text().startswith("anything an older installer")


def test_no_grant_and_no_validation_stays_the_old_warning(tmp_path):
    dst = _target(tmp_path, "db", "missing")
    proc = _bash(tmp_path, _db_block(dst) + '\necho "READY:$DB_HELPER_SUDOERS_READY"\n', valid=False)
    assert proc.returncode == 0 and "READY:false" in proc.stdout
    assert "DB helper NOT enabled" in proc.stdout and not dst.exists()


def _snapshot(wrote):
    begin = TEXT.index("        _lc_helpers=()")
    body = TEXT[begin:TEXT.index('        _lc_helpers_json=', begin)]
    return (f'la_created() {{ false; }}\nla_wrote() {{ case "$2" in {wrote}) true;; *) false;; esac; }}\n'
            + body + '\nprintf "OWNED:%s\\n" "${_lc_helpers[*]}"\n')


def test_the_fresh_foundation_owns_exactly_the_helpers_whose_write_completed(tmp_path):
    proc = _bash(tmp_path, _snapshot("/etc/sudoers.d/corpusfm-db-helper|/etc/tmpfiles.d/corpusfm.conf"))
    assert proc.returncode == 0, proc.stderr
    assert "OWNED:/etc/sudoers.d/corpusfm-db-helper /etc/tmpfiles.d/corpusfm.conf\n" in proc.stdout
    none = _bash(tmp_path, _snapshot("/nothing"))
    assert "OWNED:\n" in none.stdout


def _backfill(flags):
    begin = TEXT.index("    _lc_managed=()")
    body = TEXT[begin:TEXT.index('    _lc_req="$(lc_request publish-installer', begin)]
    return flags + "\n" + _block("lc_json_array() {", "\n}\n", "", "") + "\n}\n" + body \
        + '\necho "MANAGED:$_lc_managed_json"\n'


@pytest.mark.parametrize("flags, expected", [
    ("CLI_SHIM_WRITTEN=true; DB_HELPER_SUDOERS_READY=true; TMPFILES_WRITTEN=true",
     ["cli_shim", "db_helper_sudoers", "tmpfiles"]),
    ("CLI_SHIM_WRITTEN=true; DB_HELPER_SUDOERS_READY=false; TMPFILES_WRITTEN=true",
     ["cli_shim", "tmpfiles"]),
])
def test_an_update_asks_publish_installer_to_own_only_what_it_wrote(tmp_path, flags, expected):
    proc = _bash(tmp_path, _backfill(flags))
    assert proc.returncode == 0, proc.stderr
    line = [l for l in proc.stdout.splitlines() if l.startswith("MANAGED:")][0]
    assert json.loads(line[len("MANAGED:"):]) == expected
    begin = TEXT.index('_lc_req="$(lc_request publish-installer')
    req = TEXT[begin:TEXT.index("composition publish-installer --request", begin)]
    assert '"own_managed_files":%s' in req and '"$_lc_managed_json"' in req
    assert '"own_updater_sudoers":%s' in req and '"$UPDATER_SUDOERS_READY"' in req
