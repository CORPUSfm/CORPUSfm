"""The deployment gate: an un-migrated server install is locked to /needs-upgrade."""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from corpusfm.app.web.app import create_app
    # The DB-schema lock that used to share this middleware is retired (packet 1361-01, round 12),
    # so the proxy gate is the only one here and needs no isolating.
    app = create_app()
    with TestClient(app, follow_redirects=False) as c:
        # Inlined from the private tree's shared test fixtures. The consolidated public repository
        # runs the application and installer suites in ONE pytest process, so it deliberately carries
        # no `tests/conftest.py`: that module's autouse fixtures reach the installer tests and break
        # their development-layout teardown. A serving box is this test's precondition (1361-01 r7).
        import time as _time

        from corpusfm.server import availability as _availability

        _availability.await_first_attempt(5.0)
        _deadline = _time.monotonic() + 5.0
        while not _availability.is_open() and _time.monotonic() < _deadline:
            _time.sleep(0.01)
        assert _availability.is_open(), (
            f"the box never finished initializing: {_availability.diagnostics()}")
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


def test_gate_page_renders_the_focused_installer_handoff(client):
    """`/build-mismatch` is GONE (packet 1361-01, round 12), so `/needs-upgrade` is the only gate
    page left. A proven build mismatch pauses the process before any route can be reached, and the
    local paused supervisory page owns that guidance now."""
    body = client.get("/needs-upgrade").text
    assert "github.com/CORPUSfm/CORPUSfm/releases" in body
    assert "installer/linux/install.sh" not in body


def test_the_retired_build_mismatch_ROUTE_IS_GONE(client):
    """It is not merely unreachable — it does not exist. A dead route that still renders is a second
    place the guidance can drift.

    Asserted against the ROUTE TABLE first, because a status code cannot prove absence: a gate
    redirect answers 302 for a path that exists and for one that does not alike, which is exactly
    what a full-suite run produced when leaked deployment state left the proxy gate active. The 404
    below is then measured with every gate explicitly inactive, so it means what it says.
    """
    def _paths(routes, prefix=""):
        # Starlette 1.3.x does not flatten `include_router` into `app.routes` — an included router
        # is an `_IncludedRouter` whose real routes hang off `include_context` (the same walk
        # `test_api_gate_conformance._walk_routes` documents).
        out = set()
        for r in routes:
            inc = getattr(r, "include_context", None)
            if inc is not None and getattr(inc, "included_router", None) is not None:
                out |= _paths(inc.included_router.routes, prefix + (getattr(inc, "prefix", "") or ""))
            elif hasattr(r, "routes"):
                out |= _paths(r.routes, prefix + (getattr(r, "path", "") or ""))
            else:
                out.add(prefix + getattr(r, "path", ""))
        return out

    routes = _paths(client.app.routes)
    assert "/build-mismatch" not in routes
    assert "/needs-upgrade" in routes, "the surviving gate page vanished; this test proves nothing"

    with patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=False), \
         patch("corpusfm.app.web.blob_conversion.is_running", return_value=False):
        assert client.get("/build-mismatch").status_code == 404

    from pathlib import Path
    import corpusfm.app.web.routes.pages as p
    assert "build-mismatch" not in Path(p.__file__).read_text().replace(
        "build-mismatch page it also", "")
    assert not (Path(p.__file__).parent.parent / "templates" / "build_mismatch.html").exists()


_TEMPLATES = ["needs_upgrade.html"]


@pytest.mark.parametrize("tmpl", _TEMPLATES)
def test_gate_template_has_no_hardcoded_linux_literal(tmpl):
    # The hardcoded Linux command is gone from the template source — it now renders {{ upgrade_command }}.
    from pathlib import Path
    import corpusfm.app.web.routes.pages as p
    src = (Path(p.__file__).parent.parent / "templates" / tmpl).read_text()
    assert "installer/linux/install.sh" not in src
    assert "{{ upgrade_command }}" in src
