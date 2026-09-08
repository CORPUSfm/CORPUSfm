"""Upgrade supply-chain integrity (hardening surface #1).

Before a privileged self-pull, the box must verify it is pulling the intended code from the
intended remote onto a clean tree. These lock the shared Python guards (corpusfm.updater) and the
in-app apply-update route that uses them. The installer enforces the same in bash (install.sh:
normalize_remote / assert_origin / assert_clean_tree) — covered by test_script_conformance + manual
box validation, not importable here.
"""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest

CANON = "github.com/corpusfm/corpusfm"


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def _init_repo(tmp_path, origin_url):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "remote", "add", "origin", origin_url)
    (repo / "f.txt").write_text("x")
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init")
    return repo


# ── canonical_remote: form-independent identity ───────────────────────────────

@pytest.mark.parametrize("url", [
    "https://github.com/CORPUSfm/CORPUSfm.git",
    "git@github.com:CORPUSfm/CORPUSfm.git",
    "https://x-access-token:ghp_ABC@github.com/CORPUSfm/CORPUSfm.git",
    "ssh://git@github.com/CORPUSfm/CORPUSfm",
    "https://github.com/CORPUSfm/CORPUSfm/",
])
def test_canonical_remote_accepts_legit_forms(url):
    from corpusfm.updater import canonical_remote, EXPECTED_ORIGIN
    assert canonical_remote(url) == EXPECTED_ORIGIN == CANON


@pytest.mark.parametrize("url", [
    "https://github.com/evil/CORPUSfm.git",      # wrong org
    "https://gitlab.com/CORPUSfm/CORPUSfm.git",  # wrong host
    "https://github.com/blconstructs/other.git",                       # wrong repo
    "https://github.com.evil.com/CORPUSfm/CORPUSfm.git",  # lookalike host
    "",
])
def test_canonical_remote_rejects_wrong_remote(url):
    from corpusfm.updater import canonical_remote, EXPECTED_ORIGIN
    assert canonical_remote(url) != EXPECTED_ORIGIN


# ── verify_origin / is_dirty against a real temp repo ─────────────────────────

def test_verify_origin_matches(tmp_path):
    from corpusfm.updater import verify_origin
    repo = _init_repo(tmp_path, "https://github.com/CORPUSfm/CORPUSfm.git")
    ok, actual = verify_origin(repo)
    assert ok and "CORPUSfm" in actual


def test_verify_origin_rejects_foreign_remote(tmp_path):
    from corpusfm.updater import verify_origin
    repo = _init_repo(tmp_path, "https://github.com/evil/CORPUSfm.git")
    ok, _ = verify_origin(repo)
    assert not ok


def test_is_dirty_tracks_modified_code_but_ignores_untracked(tmp_path):
    from corpusfm.updater import is_dirty
    repo = _init_repo(tmp_path, "https://github.com/CORPUSfm/CORPUSfm.git")
    assert is_dirty(repo) is False
    (repo / "f.txt").write_text("modified")       # modified tracked file → dirty (tamper signal)
    assert is_dirty(repo) is True
    _git(repo, "checkout", "--", "f.txt")
    assert is_dirty(repo) is False
    # Untracked runtime data (e.g. users.yaml on a real box) must NOT count — else every upgrade
    # would falsely refuse over app-written files in the checkout.
    (repo / "users.yaml").write_text("- runtime data")
    assert is_dirty(repo) is False


# ── in-app apply-update route refuses redirected origin / dirty tree ───────────

@contextmanager
def _admin_client():
    from fastapi.testclient import TestClient
    from corpusfm.app.web.app import create_app
    user = SimpleNamespace(username="a", has_gate=lambda g: True)
    with patch("corpusfm.config.is_server_mode", return_value=True), \
         patch("corpusfm.app.web.deployment.needs_proxy_migration", return_value=False), \
         patch("corpusfm.app.web.auth.is_server_mode", return_value=True), \
         patch("corpusfm.app.web.auth.current_user", return_value=user):
        app = create_app()
        with TestClient(app) as c:
            c.cookies.set("corpusfm_csrf", "t"); c.headers["x-csrf-token"] = "t"  # 073-A CSRF
            yield c


# The two apply-ROUTE tests that lived here are RETIRED (Codex scope ruling, packet 1276 §1).
# They preserved the pre-1246-03 design in which the unprivileged service itself ran the origin and
# dirty-tree checks during apply. The current `update_service.apply()` refuses an unpublished layout
# outright and otherwise delegates to the fixed privileged updater, which independently re-fetches,
# re-resolves and enforces both trust rails (installer repository: `corpusfm-update`, and its
# `tests/test_privileged_update_build_stamp.py`). The POLICY units above — `verify_origin`,
# `canonical_remote`, `is_dirty` — still exercise current application code and stay. What the route
# owes now is the successor rule below.


def test_the_service_apply_holds_no_trust_check_of_its_own():
    """The service may not carry its own origin/dirty verdicts on the apply path — those rails are
    the privileged updater's, evaluated on the tip IT resolves. A service-side copy would be a
    second authority that can disagree with the enforcing one."""
    import ast
    import inspect

    from corpusfm.server import update_service as us

    tree = ast.parse(inspect.getsource(us.apply))
    called = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
              for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not called & {"verify_origin", "is_dirty", "write_stamp"}, sorted(called)
