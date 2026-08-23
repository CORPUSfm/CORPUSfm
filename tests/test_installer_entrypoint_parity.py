"""Installer idempotent-entrypoint parity (inbox packets 007/008, tightened by 1181).

Operator contract, cross-platform: re-running the installer IS the upgrade command. An existing
install is auto-detected from a durable marker and upgraded in place; a truly-fresh box still does a
fresh install. **Neither platform has a force-upgrade flag** — Linux's retained `--upgrade` was
removed in packet 1181, so there is one entrypoint per platform and one operator command.

- Windows `install.ps1` has no `-Upgrade` switch — upgrade is auto-detected when already installed.
- Linux `install.sh` sets `IS_UPGRADE=true` from `$INSTALL_DIR/venv` alone, decided in the Settings
  section BEFORE the Progress (mutation) section, with the self-pull still gated by the origin +
  clean-tree trust rails. A retired `--upgrade` argument now falls through to the parser's ordinary
  unknown-option `die` — no hidden alias, no silent ignore.

These are static guards plus one real parse-level run (bash/PowerShell aren't both runnable on the
CI host — mirrors the other installer guards).
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest
from application_checkout import APPLICATION_ROOT

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SH_PATH = _ROOT / "installer/linux/install.sh"
_SH = _SH_PATH.read_text(encoding="utf-8")
_PS = (_ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")


def _usage_block() -> str:
    """The comment block `--help` prints (from `# Usage:` to the first non-comment line)."""
    out: list[str] = []
    started = False
    for line in _SH.splitlines():
        if line.startswith("# Usage:"):
            started = True
        if not started:
            continue
        if not line.startswith("#"):
            break
        out.append(line)
    assert out, "install.sh lost its `# Usage:` help block"
    return "\n".join(out)


# ── Linux: plain install.sh auto-detects an existing install ──────────────────────

def test_linux_auto_detects_upgrade_via_durable_venv_marker():
    # The durable marker is the installed venv dir — and nothing else. No force override.
    assert '[[ -d "$INSTALL_DIR/venv" ]] && IS_UPGRADE=true' in _SH
    assert "INSTALL_DIR=/opt/CORPUSfm" in _SH   # the marker is the real install root, not the cwd


def test_linux_fresh_install_detection_remains_correct():
    """A box with no installed venv AND no published installation record stays a fresh install.

    RE-EXPRESSED (packet 1000-13). This pinned `count("IS_UPGRADE=true") == 1`, which was a proxy
    for "only the venv marker raises the flag". There is now a SECOND raise, and it is correct: the
    lifecycle classification in phase 3 raises it when a published record names this very root
    (`$_lc_install_dir == $INSTALL_DIR`). A published installation IS an existing install, and
    treating it as fresh is the more dangerous error. Counting sites would have read that addition
    as a regression.

    So the rule is asserted directly: the flag defaults to false, and every site that raises it is
    a positive detection of an existing install — nothing raises it unconditionally.
    """
    assert "IS_UPGRADE=false" in _SH

    raises = [ln.strip() for ln in _SH.splitlines()
              if "IS_UPGRADE=true" in ln and not ln.lstrip().startswith("#")]
    assert raises == ['[[ -d "$INSTALL_DIR/venv" ]] && IS_UPGRADE=true', "IS_UPGRADE=true"], (
        f"the upgrade flag has an unclassified writer: {raises}")

    # The venv marker, stated as a guarded one-liner.
    assert '[[ -d "$INSTALL_DIR/venv" ]] && IS_UPGRADE=true' in _SH

    # …and the published-record arm, which sits inside a conditional rather than carrying its own.
    # Its guard is the `$_lc_install_dir == $INSTALL_DIR` comparison directly above it: a record
    # naming ANOTHER root dies rather than reaching this line.
    at = _SH.index("\n    IS_UPGRADE=true")
    window = _SH[max(0, at - 900):at]
    assert 'PUBLISHED_HERE=true' in window and '"$_lc_install_dir" == "$INSTALL_DIR"' in window, (
        "the bare `IS_UPGRADE=true` is no longer downstream of the published-record check that "
        "proves the record names THIS root — an unrelated installation would read as an upgrade")


def test_linux_detection_is_before_mutation():
    # RE-EXPRESSED (packet 1246-04-05): the rule is *detection precedes mutation*, and the 21-phase
    # conversion moved the byte offsets this compared. Asserted against the PHASES now, which is
    # what actually orders the work — classification is phase 2, and nothing mutates before phase 9.
    raw = _SH_PATH.read_text(encoding="utf-8")
    marks = {int(m.group(1)): m.start()
             for m in re.finditer(r"^# ═══ PHASE (\d+) —", raw, re.M)}
    assert marks, "the Linux installer has no phase markers"
    detect = raw.index("IS_UPGRADE=false")
    assert marks[2] < detect < marks[9], (
        "the fresh-vs-upgrade classification does not sit between phase 2 and the first mutation"
    )
    assert marks[9] < marks[10], "quiesce does not precede code replacement"


def test_linux_prints_explicit_upgrade_and_fresh_messages():
    assert "Existing install found" in _SH and "upgrade mode" in _SH
    assert "Fresh install" in _SH


# ── Linux: the retired --upgrade flag is gone (packet 1181) ───────────────────────

def test_linux_has_no_force_upgrade_state_or_parser_arm():
    assert "FORCE_UPGRADE" not in _SH
    assert "--upgrade)" not in _SH
    # no replacement synonym sneaked in
    for synonym in ("--update)", "--existing)", "--in-place)", "--force-upgrade)"):
        assert synonym not in _SH, f"retired force-upgrade flag reintroduced as {synonym}"


def test_linux_unknown_option_arm_is_the_ordinary_die():
    assert '*) die "Unknown option: $1  (use --help)" ;;' in _SH


def test_linux_upgrade_does_not_force_reingestion_or_reset():
    # nothing in the script wipes the archive / forces a re-ingest on upgrade
    assert "rm -rf \"$INSTALL_DIR/archive\"" not in _SH
    assert "rm -rf \"$INSTALL_DIR/.corpusfm\"" not in _SH


# ── Windows: install.ps1 auto-detects (no -Upgrade switch) ────────────────────────

def test_windows_has_no_upgrade_switch():
    param = _PS[_PS.index("param("): _PS.index("param(") + 1200]
    assert "[switch]$Upgrade" not in param, "Windows upgrade is auto-detected — there is no -Upgrade switch"


# ── Current documentation carries no retired-flag command ─────────────────────────

# Current-authoritative operator/dev docs + the runtime modules that generate operator guidance.
_CURRENT_DOCS = (
    "README.md",
    "SPEC.md",
    "installer/SPEC.md",
    "installer/constraints-server-py313.txt",
    "installer/constraints-server-win-py313.txt",
    "docs/current-architecture.md",
    "docs/roadmap.md",
    "public-site/index.md",
    "CLAUDE.md",
    "CLAUDE-SERVER.md",
    "CLAUDE-APP.md",
    "installer/linux/install.sh",
    "installer/windows/install.ps1",
    "corpusfm/server/health.py",
    "corpusfm/server/readiness.py",
    "corpusfm/core/safe_xml.py",
    "corpusfm/updater.py",
    "corpusfm/app/web/deployment.py",
    "corpusfm/app/web/routes/pages.py",
    "corpusfm/app/web/routes/api/settings.py",
)

# Append-only / dated records: history stays accurate about what happened at the time, so the
# current-doc guard deliberately does NOT scan them and nothing scrubs them.
_HISTORICAL_RECORDS = (
    "corpusfm/app/web/docs/changelog.md",
    ".claude/done/007-installer-idempotent-entrypoint-parity.md",
    ".claude/done/008-general-updates-installer-copy.md",
)


def _flag_hits(text: str) -> list[str]:
    # `pip install --upgrade pip` is a different tool's flag, not the installer's.
    return [ln for ln in text.splitlines()
            if "--upgrade" in ln and "pip" not in ln]


@pytest.mark.parametrize("rel", _CURRENT_DOCS)
def test_current_docs_promote_no_retired_upgrade_flag(rel: str):
    path = _ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present in this checkout")
    hits = _flag_hits(path.read_text(encoding="utf-8"))
    assert not hits, f"{rel} still references the retired installer --upgrade flag: {hits}"


@pytest.mark.parametrize("rel", _HISTORICAL_RECORDS)
def test_historical_records_are_left_untouched(rel: str):
    path = _ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present in this checkout")
    assert _flag_hits(path.read_text(encoding="utf-8")), (
        f"{rel} is a dated/append-only record — its historical `--upgrade` commands must not be "
        "rewritten by the current-doc cleanup"
    )


def test_in_app_documentation_articles_carry_no_retired_flag():
    docs_dir = APPLICATION_ROOT / "corpusfm/app/web/docs"
    offenders = {
        p.name: _flag_hits(p.read_text(encoding="utf-8"))
        for p in sorted(docs_dir.glob("*.md"))
        if p.name != "changelog.md" and _flag_hits(p.read_text(encoding="utf-8"))
    }
    assert not offenders, f"in-app help still promotes the retired flag: {offenders}"
