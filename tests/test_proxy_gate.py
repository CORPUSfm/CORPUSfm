"""The deployment gate: an un-migrated server install is locked to /needs-upgrade."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from corpusfm.app.web.app import create_app
    # gate_active() (DB schema) must be False so we isolate the proxy gate
    with patch("corpusfm.storage.storage_migration.gate_active", return_value=False):
        app = create_app()
        with TestClient(app, follow_redirects=False) as c:
            yield c


def test_unmigrated_server_is_gated(client):
    with patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=True):
        r = client.get("/artifacts")
    assert r.status_code == 302
    assert r.headers["location"] == "/needs-upgrade"


def test_gate_allows_the_warning_page_and_static(client):
    with patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=True):
        assert client.get("/needs-upgrade").status_code == 200
        assert client.get("/login").status_code in (200, 302)  # login renders or redirects
        # static is allowlisted (not redirected to the warning)
        assert client.get("/static/style.css").status_code in (200, 404)


def test_migrated_server_not_gated(client):
    with patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=False):
        r = client.get("/needs-upgrade")
    assert r.status_code == 200  # page still reachable, but nothing forces you there


@pytest.mark.parametrize("page", ["/needs-upgrade", "/build-mismatch"])
def test_gate_pages_render_the_focused_installer_handoff(client, page):
    body = client.get(page).text
    assert "github.com/CORPUSfm/CORPUSfm/releases" in body
    assert "installer/linux/install.sh" not in body


_TEMPLATES = ["needs_upgrade.html", "build_mismatch.html"]


@pytest.mark.parametrize("tmpl", _TEMPLATES)
def test_gate_template_has_no_hardcoded_linux_literal(tmpl):
    # The hardcoded Linux command is gone from the template source — it now renders {{ upgrade_command }}.
    from pathlib import Path
    import corpusfm.app.web.routes.pages as p
    src = (Path(p.__file__).parent.parent / "templates" / tmpl).read_text()
    assert "installer/linux/install.sh" not in src
    assert "{{ upgrade_command }}" in src
