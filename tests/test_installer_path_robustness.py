"""Packet 017: installer path robustness.

- Windows operator guidance must use resolved paths ($Py / sys.executable), not a hard-coded
  C:\\CORPUSfm — a custom -InstallRoot (e.g. D:\\Apps\\CORPUSfm) must be honored.
- The Windows uninstaller must prompt for the FMS admin username (not assume 'admin'), step out of
  the install tree before deleting it, and only ever target CORPUSfm's own storage DB.
- FMS root is overridable: Windows -FmsRoot (Find-FmsBin), Linux --fms-root (DB dir).
- The Linux CORPUSfm install root stays a FIXED /opt/CORPUSfm invariant.
"""
from __future__ import annotations

from contextlib import contextmanager
import re
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
import pytest
from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
INSTALL_PS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")
UNINSTALL_PS = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="utf-8")
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
UNINSTALL_SH = (ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8")
LOGIN_HTML = (APPLICATION_ROOT / "corpusfm/app/web/templates/login.html").read_text(encoding="utf-8")
PAGES_PY = (APPLICATION_ROOT / "corpusfm/app/web/routes/pages.py").read_text(encoding="utf-8")


# ── Windows custom install-root guidance uses resolved paths ─────────────────────

def test_install_ps1_admin_guidance_uses_resolved_py_not_literal():
    # The first-admin warnings + Next-steps must build the command from $Py (= InstallRoot\python),
    # never a hard-coded C:\CORPUSfm\python that would be wrong on a custom -InstallRoot.
    assert "C:\\CORPUSfm\\python\\python.exe -m corpusfm.server.cli" not in INSTALL_PS
    assert '$Py + " -m corpusfm.server.cli users create <name> --admin"' in INSTALL_PS


def test_login_page_command_is_server_resolved_not_hardcoded():
    # The no-users login page renders {{ admin_cli }} (resolved from sys.executable), not a literal path.
    assert "{{ admin_cli }}" in LOGIN_HTML
    assert "C:\\CORPUSfm\\python\\python.exe" not in LOGIN_HTML


def test_pages_admin_cli_derives_from_sys_executable():
    assert "admin_cli" in PAGES_PY
    assert "sys').executable" in PAGES_PY or "sys.executable" in PAGES_PY
    assert 'corpusfm users create <name> --admin' in PAGES_PY   # Linux shim branch


# ── login page behavioral: posix host → shim command, no Windows literal ─────────

@contextmanager
def _server_login(tmp_path, monkeypatch):
    # Users live in the USER table (packet 1007): a fresh temp LocalBackend has none → the no-users page.
    from corpusfm.core import crypto
    from corpusfm.storage.local import LocalBackend
    monkeypatch.setattr(crypto, "_CORPUS_KEY_FILE", tmp_path / "corpus.key")
    monkeypatch.setattr(crypto, "_MACHINE_KEY_FILE", tmp_path / "machine.key")
    crypto._clear_key_cache()
    _be = LocalBackend(tmp_path / "store")
    monkeypatch.setattr("corpusfm.storage.get_backend", lambda: _be)
    monkeypatch.setenv("CORPUSFM_MODE", "server")
    import corpusfm.app.web.routes.pages  # make the split route module addressable to mock.patch
    ctx = [patch("corpusfm.config.is_server_mode", return_value=True),
           patch("corpusfm.app.web.routes.pages.is_server_mode", return_value=True),
           patch("corpusfm.storage.storage_migration.gate_active", return_value=False),
           patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=False)]
    for c in ctx:
        c.start()
    from corpusfm.app.web.app import create_app
    try:
        yield TestClient(create_app())
    finally:
        for c in ctx:
            c.stop()


def test_no_users_page_shows_resolved_command_no_windows_literal(tmp_path, monkeypatch):
    pytest.importorskip("jinja2", reason="application template runtime is not installed")
    with _server_login(tmp_path, monkeypatch) as c:
        body = c.get("/login").text
        assert "corpusfm users create &lt;name&gt; --admin" in body  # posix host → the shim form
        assert "C:\\CORPUSfm" not in body                            # no hard-coded Windows path


# ── Windows uninstaller robustness ───────────────────────────────────────────────

def test_the_UNINSTALLER_asks_only_after_the_plan_proves_a_credential_is_owed():
    """Current uninstallers may prompt, but only from a typed plan/continuation result.

    The credential remains transient and no option or environment value can supply it.
    """
    for text in (UNINSTALL_PS, UNINSTALL_SH):
        assert "credential_transport" in text, "it declares a TRANSPORT and never a value"
        assert "credential_required" in text
        assert "used for this run only" in text


def test_the_UNINSTALLER_has_NO_REMOVAL_ROOT_to_make_safe():
    """**Packet 1236 finding 1, closed by construction rather than by validation.**

    `-InstallRoot` and `-ConfigHome` were free-form argv reaching a recursive `Remove-Item`:
    `-ConfigHome C:\\` on an elevated uninstall would attempt to delete most of a volume, and a typo
    was enough. `Assert-SafeRemovalPath` was the guard, and a guard is what you need when a caller
    can still name a target.

    **The RC5 is gone because the capability is gone.** The launcher removes nothing and names no
    path; every target comes from what the installation recorded, and the executor re-proves each one
    immediately before acting. So the assertion is not that the validator is present and correct — it
    is that there is nothing left for it to validate.
    """
    for text in (UNINSTALL_PS, UNINSTALL_SH):
        assert "Remove-Tree" not in text
        assert "Assert-SafeRemovalPath" not in text, (
            "a removal-path validator in the launcher means the launcher removes something")
    # And the retired options are REFUSED rather than merely unused: an option silently ignored
    # reports success on terms it never honoured.
    assert "Unknown option(s)" in UNINSTALL_PS
    assert "Unknown option:" in UNINSTALL_SH


def test_the_UNINSTALLER_names_NO_DATABASE_and_so_VALIDATES_none():
    """**Packet 1236 finding 2, closed the same way.** `fm_database` came off a file on disk and
    steered a `close`, a filesystem path and a recursive deletion filter, so it had to be validated
    as a bare stem before it could steer anything. The launcher reads no marker, knows no database
    name, and issues no close — the storage removal is one atomic executor operation against the
    exact recorded path, with an unhosted proof it performs itself."""
    for text in (UNINSTALL_PS, UNINSTALL_SH):
        assert "CORPUSfm_DB" not in text and "fm_database" not in text
        assert "install.yaml" not in text


def test_KEEP_DATA_IS_RETIRED_ON_BOTH_PLATFORMS_and_refused_by_name():
    """**The cross-platform discipline this rule was written for, applied to its retirement.**

    The original rule was *a flag that means "keep the data" must keep the data on every platform
    that offers it* — written cross-platform because the Linux defect (packet 1230 wired `--keep-data`
    into the tree and the service user but not the DB step, so the flag deleted the one thing it
    exists to preserve) survived a Windows-only guard.

    `keep-data` is now retired on both, and for a reason bigger than that defect: it left an
    installation the installer then REFUSED to reinstall over (§H, RC3), so the flag's real effect was
    to strand the box. Retiring it removes the state, not merely the flag — and the same
    cross-platform discipline applies to the retirement, or one platform quietly keeps it.
    """
    assert "-KeepData" in UNINSTALL_PS, "declared so PowerShell cannot bind it silently"
    assert "$retired += '-KeepData'" in UNINSTALL_PS, "and REFUSED by name"
    assert "--keep-data)" not in UNINSTALL_SH, "no case arm: the catch-all refuses it as unknown"


# ── FMS root overridable both platforms ──────────────────────────────────────────

def test_windows_uses_fmsroot():
    assert "Find-FmsBin $FmsRoot" in INSTALL_PS
    # The UNINSTALLER no longer takes one: `-FmsRoot` is declared only so it can be refused. The
    # FileMaker Server root the uninstall observes is the one the MANIFEST recorded, and the
    # executor opens it itself — a launcher-supplied root is a launcher-supplied target.
    assert "$retired += " in UNINSTALL_PS and "-FmsRoot" in UNINSTALL_PS


def test_linux_has_fms_root_override():
    assert "--fms-root)" in INSTALL_SH
    assert 'FMS_ROOT="${FMS_ROOT:-/opt/FileMaker/FileMaker Server}"' in INSTALL_SH
    assert 'FM_DB_DIR="$FMS_ROOT/Data/Databases"' in INSTALL_SH


# ── PowerShell installer scripts must be ASCII-only ──────────────────────────────
# Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI (CP1252), so a non-ASCII char (em dash,
# arrows, box-drawing) corrupts the parser — an em dash inside a string once broke uninstall.ps1
# entirely (the trailing 0x94 byte read as a `"`), so the whole uninstall refused to run.

def test_powershell_installers_are_ascii_only():
    for rel in ("installer/windows/install.ps1", "installer/windows/uninstall.ps1",
                "installer/windows/_cfm_lib.ps1",
                "installer/windows/cfm-proxy-exec.ps1", "installer/windows/corpusfm-proxy.ps1"):
        p = ROOT / rel
        if not p.exists():
            continue
        raw = p.read_bytes()
        bad = [(i, b) for i, b in enumerate(raw) if b > 0x7F]
        assert not bad, f"{rel}: {len(bad)} non-ASCII byte(s) (first at offset {bad[0][0]}, 0x{bad[0][1]:02x}) — PS 5.1 BOM-less parse hazard"


# ── Linux CORPUSfm root is a FIXED invariant (not configurable) ──────────────────

def test_linux_install_root_is_fixed_opt_corpusfm():
    assert "INSTALL_DIR=/opt/CORPUSfm" in INSTALL_SH
    # no flag turns the CORPUSfm install root into a variable (FMS root is overridable; app root is not)
    assert "--install-root" not in INSTALL_SH
    assert "--config-home" not in INSTALL_SH
