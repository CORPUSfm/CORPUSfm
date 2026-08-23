"""POST /api/settings/apply-update — the route, after the privileged boundary (1246-03-03).

**Eight tests were deleted here.** They drove the route through `apply()`'s self-pull — non-git
checkout, pull failure, import-probe rollback, restart scheduling, schema and installer blocking —
and every one of those verdicts now belongs to the elevated side, which the service cannot reach
into and must not simulate. The route's own behaviour (it calls `apply()` and returns its verdict)
is re-expressed below; what `apply()` decides is tested in `test_privileged_update_trigger.py`, and
what the updater decides in `test_privileged_updater_behaviour.py`.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace
from unittest.mock import patch


def _make_client():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from corpusfm.app.web.routes.api.settings import router
    from corpusfm.app.web.auth import require_auth
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.dependency_overrides[require_auth] = lambda: None
    return TestClient(app)


def _completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=["git"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def test_upgrade_handoff_names_the_focused_installer_repo():
    from corpusfm.app.web.routes.api import settings as s
    handoff = s._upgrade_command()
    assert (
        "github.com/CORPUSfm/CORPUSfm/releases" in handoff
    )
    assert "installer/" not in handoff and "install.ps1" not in handoff


def test_recorded_linux_installer_entry_becomes_a_copy_paste_command():
    from corpusfm.server import update_service as us

    assert us._command_for_installer_entry(
        "/opt/CORPUSfm/bin/corpusfm-installer", windows=False
    ) == "sudo /opt/CORPUSfm/bin/corpusfm-installer"


def test_recorded_windows_installer_entry_becomes_a_copy_paste_command():
    from corpusfm.server import update_service as us

    assert us._command_for_installer_entry(
        r"C:\Program Files\CORPUSfm\bin\corpusfm-installer.ps1", windows=True
    ) == (
        "powershell -ExecutionPolicy Bypass -File "
        "'C:\\Program Files\\CORPUSfm\\bin\\corpusfm-installer.ps1'"
    )


def _published(monkeypatch, entry):
    """`operator_command()` reads the FAÇADE now (packet 1276 — the lifecycle app fence caught its
    `ManifestStore` import), so these tests fix the façade's answer, not a manifest store."""
    from corpusfm.lifecycle import published

    monkeypatch.setattr(published, "read_published_installation",
                        lambda: SimpleNamespace(installer_entry_point=entry))


def test_operator_handoff_reads_the_published_installer_entry(monkeypatch):
    from corpusfm.server import update_service as us

    _published(monkeypatch, "/opt/CORPUSfm/bin/corpusfm-installer")
    assert us.operator_command() == "sudo /opt/CORPUSfm/bin/corpusfm-installer"


def test_operator_handoff_is_generic_for_an_older_manifest(monkeypatch):
    """An older manifest recorded no entry point — the façade answers None, never a guessed path."""
    from corpusfm.server import update_service as us

    _published(monkeypatch, None)
    assert (
        "github.com/CORPUSfm/CORPUSfm/releases"
        in us.operator_command()
    )


def test_operator_handoff_is_generic_when_nothing_is_published(monkeypatch):
    """An unpublished or unreadable state RAISES inside the façade; the handoff falls back to the
    generic instruction rather than inventing a launcher path."""
    from corpusfm.lifecycle import published
    from corpusfm.server import update_service as us

    def _raise():
        raise published.InstallationNotPublished("no locator")

    monkeypatch.setattr(published, "read_published_installation", _raise)
    assert (
        "github.com/CORPUSfm/CORPUSfm/releases"
        in us.operator_command()
    )


def test_windows_entry_with_a_quote_is_still_safely_quoted():
    from corpusfm.server import update_service as us

    cmd = us._command_for_installer_entry(r"C:\O'Brien\run.ps1", windows=True)
    assert "''" in cmd and cmd.startswith("powershell -ExecutionPolicy Bypass -File ")


def test_the_route_returns_what_apply_decided(monkeypatch):
    """The route's own job, and all of it: call `apply()` and report the verdict unchanged.

    Re-expressed from the deleted success/refusal pair. It asserts the wiring rather than any
    update verdict, because the route no longer reaches a verdict of its own.
    """
    from corpusfm.server import update_service as us

    seen = {}

    def fake_apply(**kw):
        seen.update(kw)
        return us.ApplyResult(True, "ok", 200, message="applied", request_id="upd_x")

    monkeypatch.setattr(us, "apply", fake_apply)
    client = _make_client()
    r = client.post("/api/settings/apply-update")
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert seen, "the route did not delegate to apply()"


def test_the_route_passes_a_refusal_through_unchanged(monkeypatch):
    """CLEAN CONTROL: a refusal must not be reshaped into a generic error by the route."""
    from corpusfm.server import update_service as us

    monkeypatch.setattr(us, "apply", lambda **kw: us.ApplyResult(
        False, "privileged_updater_unavailable", 409,
        message="Update refused — run the installer on the server."))
    client = _make_client()
    r = client.post("/api/settings/apply-update")
    assert r.json()["ok"] is False
    assert "installer" in r.json().get("message", "") + r.json().get("error", "")
