"""The updater grant must exist in the attempt ledger when foundation snapshots ownership.

These are local shell/ordering regressions, not installed uninstall proof; the signed Linux
fresh-install → uninstall → fresh-install gate remains required.
"""
import os
from pathlib import Path
import subprocess

import pytest

SCRIPT = Path(os.environ.get("CFM_INSTALLER_SH", Path(__file__).resolve().parents[1] /
                              "installer/linux/install.sh"))


def test_grant_is_ledgered_before_foundation_takes_helper_ownership():
    text = SCRIPT.read_text()
    grant = "la_do file ensure - /etc/sudoers.d/corpusfm-update -- install"
    snapshot = 'la_created file "$_lc_h" && _lc_helpers+=("$_lc_h")'
    assert text.count(grant) == 1
    assert text.index(grant) < text.index(snapshot), (
        "foundation misses the later updater grant, so uninstall leaves it behind")
    # The actual updater renderer still needs the published foundation.
    assert text.index("composition foundation --request") < text.index("from corpusfm.lifecycle.update_boundary import render_linux_updater")


@pytest.mark.parametrize("template,valid", [(True, True), (True, False), (False, True)])
def test_staged_grant_and_foundation_snapshot_agree(tmp_path, template, valid):
    text = SCRIPT.read_text()
    # Run the production grant block and exact production helper-snapshot loop, with privileged
    # installation/ledger commands replaced by observations. No root files are written.
    begin = text.index('UPDATER_SRC="$CFM_RUNTIME_ROOT/installer/linux/corpusfm-update.sh"')
    end = text.index("# ═══ PHASE 11", begin)
    block = text[begin:end]
    begin = text.index("        _lc_helpers=()")
    end = text.index('        _lc_helpers_json=', begin)
    snapshot = text[begin:end]
    src = tmp_path / "runtime/installer/linux"
    src.mkdir(parents=True)
    if template:
        (src / "corpusfm-update.sh").write_text("template")
    env = dict(os.environ, CFM_RUNTIME_ROOT=str(tmp_path / "runtime"),
               SERVICE_USER="corpusfm", VALID="true" if valid else "false")
    harness = r'''
set -e
created=""
visudo() { "$VALID"; }
warn() { :; }
la_do() {
    [[ "$1 $2 $3 $4 $5" == "file ensure - /etc/sudoers.d/corpusfm-update --" ]]
    [[ "$6 $7 $8 $9 ${10} ${11} ${12} ${14}" == "install -m 0440 -o root -g root /etc/sudoers.d/corpusfm-update" ]]
    cat "${13}"
    created="$4"
}
la_created() { [[ "$1" == file && "$2" == "$created" ]]; }
'''
    # Non-matches are ordinary decisions in the production for loop, not shell failures.
    proc = subprocess.run(["bash", "-c", harness + block + snapshot +
                           '\nprintf "OWNED:%s\\n" "${_lc_helpers[*]}"\n'],
                          env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stderr
    owned = "OWNED:/etc/sudoers.d/corpusfm-update" in proc.stdout
    assert owned == (template and valid)
    if owned:
        assert "corpusfm ALL=(root) NOPASSWD: /usr/bin/systemctl start corpusfm-update.service" in proc.stdout
