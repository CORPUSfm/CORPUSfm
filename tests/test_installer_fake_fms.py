"""Packet 022: installer decision paths against the fake FMS substrate (no live FileMaker Server).

Uses tests/installer_sim/fake_fms.py: a fake `fmsadmin` (scripted list-files / cred accept-reject /
close) and a requests-level fake Admin API. Each test reduces a previously live-only installer risk.
"""
from __future__ import annotations

import os
from pathlib import Path
from application_checkout import APPLICATION_ROOT

import pytest
import urllib3

from tests.installer_sim.harness import make_fake_bin, extract_sh_func, run_bash
from tests.installer_sim.fake_fms import (
    make_fake_fmsadmin, FakeFmsHttp, auth_ok_routes, auth_rejected_routes,
)

ROOT = Path(__file__).resolve().parent.parent


# ── fake fmsadmin: credential accept/reject is by EXIT CODE, not output (the pkt-020 lesson) ───────

def test_fmsadmin_creds_distinguished_by_exit_code(tmp_path):
    log = tmp_path / "fmlog"
    make_fake_fmsadmin(tmp_path / "bin", hosted=("CORPUSfm_DB.fmp12", "CORPUSfm_Playground1.fmp12"),
                       good_pass="admin")
    env = {"FAKE_FMSADMIN_LOG": str(log)}
    good = run_bash('fmsadmin -u admin -p admin list files; echo "EXIT=$?"', env, tmp_path / "bin")
    bad = run_bash('fmsadmin -u admin -p wrongpw list files; echo "EXIT=$?"', env, tmp_path / "bin")
    assert "EXIT=0" in good.stdout and "CORPUSfm_DB.fmp12" in good.stdout
    # wrong password → exit 9 + EMPTY stdout (the trap: a `| grep CORPUSfm_DB` would misread this as "absent")
    assert "EXIT=9" in bad.stdout
    assert "CORPUSfm_DB" not in bad.stdout.split("EXIT=")[0]
    assert "Permission denied" in bad.stderr


# ── the two uninstall shell-step tests MOVED (packet 1000-14) ──────────────────────────────────────
#
# `test_uninstall_step_remove_db_targets_only_corpusfm_db` and
# `test_uninstall_unit_removal_is_idempotent_when_absent` extracted `step_remove_db` and
# `step_remove_units` out of `installer/linux/uninstall.sh`. The 1246 rethread made that file a thin
# launcher that plans nothing and deletes nothing, so neither function exists and neither rule is
# this file's to hold any more. Both rules are re-expressed against the authority that now owns them,
# in `tests/test_uninstall_exec.py`:
#
#   * ONLY the recorded database goes and every orphaned sibling survives  →
#     `test_ONLY_the_recorded_database_goes_and_every_ORPHANED_SIBLING_survives`
#   * the removal is safe to re-apply on a box where it already ran        →
#     `test_RE_APPLYING_a_unit_removal_is_safe_and_then_has_no_authority`
#
# The fake `fmsadmin` above stays: the installer still has decision paths that need it.



# ── fake Admin API: PKI auth/register/deregister decisions, loopback verify_ssl, real errors surface ─

def test_pki_auth_token_on_200_and_raises_on_401(monkeypatch):
    from corpusfm.server import fms_admin_pki as pki
    FakeFmsHttp(auth_ok_routes("tokX")).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    assert pki.authenticate_basic("127.0.0.1", "admin", "admin", verify_ssl=False) == "tokX"
    FakeFmsHttp(auth_rejected_routes()).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    with pytest.raises(RuntimeError):   # a REAL auth failure surfaces, never silently swallowed
        pki.authenticate_basic("127.0.0.1", "admin", "wrong", verify_ssl=False)


def test_pki_register_ok_and_loopback_uses_verify_false(monkeypatch):
    from corpusfm.server import fms_admin_pki as pki
    fake = FakeFmsHttp(auth_ok_routes()).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    ok, msg = pki.register_public_key("127.0.0.1", "admin", "admin", pki._DEFAULT_KEY_NAME,
                                      b"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                                      verify_ssl=False)
    assert ok is True
    # every loopback call went out with verify=False (intentional self-signed internal TLS), not verify=True
    assert fake.verify_seen and all(v is False for v in fake.verify_seen)


def test_pki_register_is_idempotent_deletes_before_posting(monkeypatch):
    """The 1708 fix: a key under our name may survive a prior install (the Windows uninstaller doesn't
    deregister), so register_public_key must DELETE the name first, THEN POST ours — else FMS rejects
    the duplicate (1708) and a reinstall's PKI silently fails. Pin the DELETE→POST order over the fake
    Admin API (packet 028)."""
    from corpusfm.server import fms_admin_pki as pki
    fake = FakeFmsHttp(auth_ok_routes()).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    ok, _ = pki.register_public_key("127.0.0.1", "admin", "admin", pki._DEFAULT_KEY_NAME,
                                    b"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
                                    verify_ssl=False)
    assert ok is True
    key_calls = [m for (m, u) in fake.record if "pkipublickey" in u]
    assert key_calls[:2] == ["DELETE", "POST"], \
        f"register must deregister-before-register (DELETE then POST); saw {key_calls}"


def test_pki_deregister_best_effort_never_raises(monkeypatch):
    from corpusfm.server import fms_admin_pki as pki
    # success path → (True, …)
    FakeFmsHttp(auth_ok_routes()).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    ok, _ = pki.deregister_local_key("admin", "admin", verify_ssl=False)
    assert ok is True
    # a server-side failure (500 on the key endpoint) → (False, …) but NEVER an exception (uninstall must proceed)
    routes = dict(auth_ok_routes())
    routes["/fmi/admin/api/v2/server/config/pkipublickey"] = (500, {"messages": [{"code": "1708"}]})
    FakeFmsHttp(routes).install(monkeypatch, "corpusfm.server.fms_admin_pki")
    ok2, _ = pki.deregister_local_key("admin", "admin", verify_ssl=False)
    assert ok2 is False


def test_loopback_quiet_does_not_swallow_real_connectivity_failures(monkeypatch):
    # The intentional loopback verify_ssl=False / InsecureRequestWarning suppression (covered for the
    # installer snippets by test_installer_loopback_tls_quiet) must NOT extend to swallowing genuine
    # failures: an unreachable Admin API / OData still propagates as an error, never a silent success.
    # the module silences the loopback warning at the source (static — pytest resets filter STATE per-test)
    src = (APPLICATION_ROOT / "corpusfm/server/fms_admin_pki.py").read_text()
    assert "disable_warnings(urllib3.exceptions.InsecureRequestWarning)" in src
    from corpusfm.server import fms_admin_pki as pki
    import requests

    def boom(url, **kw):
        raise ConnectionError("OData/Admin API unreachable")
    monkeypatch.setattr(requests, "post", boom)
    with pytest.raises(Exception):   # …yet a real failure is NOT silenced
        pki.authenticate_basic("127.0.0.1", "admin", "admin", verify_ssl=False)
