"""The Linux package-manager boundary precedes every CORPUSfm installation-tree write."""

from pathlib import Path
import subprocess


INSTALLER = (Path(__file__).resolve().parent.parent / "installer" / "linux" / "install.sh")


def test_an_apt_failure_cannot_strand_an_unpublished_install_tree():
    source = INSTALLER.read_text(encoding="utf-8")
    apt = source.index('info "Checking apt packages..."')

    first_layout_write = min(
        source.index("install -d -m 0755 -o root -g root /etc/corpusfm"),
        source.index('install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" '
                     '"$INSTALL_DIR/.corpusfm/update-inbox"'),
        source.index('mkdir -p "$INSTALL_DIR"'),
    )

    assert apt < first_layout_write
    assert source.index("apt-get update -qq", apt) < first_layout_write
    assert source.index('ok "System dependencies satisfied"', apt) < first_layout_write


def test_an_apt_failure_cannot_move_a_foreign_selected_root(tmp_path):
    source = INSTALLER.read_text(encoding="utf-8")
    apt = source.index("apt-get update -qq")
    prepare = source.index(
        'prepare_install_root "$INSTALL_DIR" "$PUBLISHED_HERE" "$REPLACE_EXISTING_INSTALL"',
        apt,
    )
    foreign = tmp_path / "CORPUSfm"
    foreign.mkdir()
    payload = foreign / "administrator-owned.txt"
    payload.write_bytes(b"foreign bytes")

    # The executed failure boundary: admit the replacement read-only, fail where apt runs, and prove
    # the mutating re-observation is unreachable.
    functions = source[source.index("install_root_state()"):
                       source.index("\n\n\n# ═══ PHASE 2")]
    script = functions + """
warn() { :; }
die() { exit 97; }
check_install_root "$1" false true
exit 100
prepare_install_root "$1" false true
"""
    result = subprocess.run(
        ["bash", "-c", script, "test", str(foreign)], cwd=tmp_path, check=False)

    assert result.returncode == 100
    assert apt < prepare
    assert payload.read_bytes() == b"foreign bytes"
    assert not list(tmp_path.glob("CORPUSfm.replaced-*"))


def test_the_post_apt_reobservation_refuses_newly_ambiguous_material(tmp_path):
    source = INSTALLER.read_text(encoding="utf-8")
    functions = source[source.index("install_root_state()"):
                       source.index("\n\n\n# ═══ PHASE 2")]
    selected = tmp_path / "CORPUSfm"
    script = functions + """
warn() { :; }
die() { exit 97; }
check_install_root "$1" false false
# Models material appearing while the external package-manager step ran.
mkdir -p "$1/src"
printf poison > "$1/src/foreign"
prepare_install_root "$1" false false
"""

    result = subprocess.run(
        ["bash", "-c", script, "test", str(selected)], cwd=tmp_path, check=False)

    assert result.returncode == 97
    assert (selected / "src" / "foreign").read_text() == "poison"
    assert not list(tmp_path.glob("CORPUSfm.replaced-*"))
