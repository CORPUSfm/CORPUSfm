"""Tests for corpusfm.updater — git-only version check (the Releases-API fallback was retired 1009)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from corpusfm.updater import (
    UpdateResult,
    _parse_version,
    check_for_update,
)


# ── _parse_version ─────────────────────────────────────────────────────────────

def test_parse_version_with_v_prefix():
    assert _parse_version("v2.6.0") == (2, 6, 0)


def test_parse_version_without_prefix():
    assert _parse_version("2.6.0") == (2, 6, 0)


def test_parse_version_two_parts():
    assert _parse_version("v3.0") == (3, 0)


def test_parse_version_empty():
    assert _parse_version("") == (0,)


def test_parse_version_non_numeric():
    assert _parse_version("vfoo") == (0,)


# ── git path (uses the installed private-repository credential) ───────────────

def _git_dir(tmp_path):
    (tmp_path / ".git").mkdir()
    return tmp_path


def _completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=["git"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


@patch("corpusfm.__version__", "0.250")
def test_git_update_available(tmp_path):
    repo = _git_dir(tmp_path)

    def fake(_repo, *args, **kw):
        if args[:3] == ("remote", "get-url", "origin"):
            return _completed("https://github.com/CORPUSfm/CORPUSfm.git\n")
        if args[0] == "fetch":
            return _completed()
        if args[:2] == ("rev-list", "--count") and args[2] == "HEAD..origin/main":
            return _completed("3\n")
        if args[:2] == ("rev-list", "--count") and args[2] == "origin/main":
            return _completed("253\n")
        return _completed()

    with patch("corpusfm.updater._run_git", side_effect=fake):
        r = check_for_update(repo_dir=repo)
    assert r.source == "git"
    assert r.update_available is True
    assert r.behind == 3
    assert r.latest_version == "0.253"
    assert r.current_version == "0.250"
    assert r.checked is True


@patch("corpusfm.__version__", "0.253")
def test_git_up_to_date(tmp_path):
    repo = _git_dir(tmp_path)

    def fake(_repo, *args, **kw):
        if args[:3] == ("remote", "get-url", "origin"):
            return _completed("https://github.com/CORPUSfm/CORPUSfm.git\n")
        if args[0] == "fetch":
            return _completed()
        if args[:2] == ("rev-list", "--count") and args[2] == "HEAD..origin/main":
            return _completed("0\n")
        if args[:2] == ("rev-list", "--count") and args[2] == "origin/main":
            return _completed("253\n")
        return _completed()

    with patch("corpusfm.updater._run_git", side_effect=fake):
        r = check_for_update(repo_dir=repo)
    assert r.update_available is False
    assert r.behind == 0
    assert r.checked is True


def _fetch_fails_with(tmp_path, stderr):
    """check_for_update against a git checkout whose `fetch` fails with the given stderr."""
    repo = _git_dir(tmp_path)

    def fake(_repo, *args, **kw):
        if args[:3] == ("remote", "get-url", "origin"):
            return _completed("https://github.com/CORPUSfm/CORPUSfm.git\n")
        if args[0] == "fetch":
            return _completed(returncode=1, stderr=stderr)
        return _completed()

    with patch("corpusfm.updater._run_git", side_effect=fake):
        return check_for_update(repo_dir=repo)


def test_git_fetch_failure_reports_error(tmp_path):
    # A GENERIC (unclassified) failure keeps the specific "git fetch failed — <tail>" text.
    r = _fetch_fails_with(tmp_path, "fatal: the remote end hung up unexpectedly")
    assert r.source == "git"
    assert r.update_available is False
    assert "git fetch failed" in r.error
    assert r.error_class == ""


# ── Credential-missing / network classification (friendly, non-actionable UX) ─────

def test_fetch_missing_credentials_is_classified_and_friendly(tmp_path):
    # The exact GIT_TERMINAL_PROMPT=0 signature on a credential-less https remote.
    r = _fetch_fails_with(
        tmp_path,
        "fatal: could not read Username for 'https://github.com': terminal prompts disabled")
    assert r.error_class == "credentials"
    assert r.error == "Updates unavailable: git credentials are not configured for this install."
    assert r.update_available is False and r.checked is False
    assert "could not read Username" in r.error_detail   # raw kept as a diagnostic, not the headline


def test_fetch_ssh_publickey_is_credentials(tmp_path):
    r = _fetch_fails_with(tmp_path, "git@github.com: Permission denied (publickey).")
    assert r.error_class == "credentials"


def test_fetch_network_failure_is_classified(tmp_path):
    r = _fetch_fails_with(
        tmp_path, "fatal: unable to access '...': Could not resolve host: github.com")
    assert r.error_class == "network"
    assert r.error.startswith("Updates unavailable")


def test_classify_git_error_units():
    from corpusfm.updater import classify_git_error
    assert classify_git_error("could not read Password for 'https://...'")[0] == "credentials"
    assert classify_git_error("fatal: Authentication failed for 'https://...'")[0] == "credentials"
    assert classify_git_error("Operation timed out after 15000 ms")[0] == "network"
    assert classify_git_error("fatal: the remote end hung up unexpectedly") == ("", "")
    assert classify_git_error("") == ("", "")


# ── no-checkout path (the retired Releases-API fallback, packet 1009) ─────────────

def test_no_git_checkout_reports_cannot_check(tmp_path):
    # A run with no .git checkout (not a shipped shape — both installers clone) no longer falls back
    # to the GitHub Releases API; it reports it couldn't check. Retired in packet 1009.
    result = check_for_update(repo_dir=tmp_path)     # tmp_path has no .git
    assert result.update_available is False
    assert result.source == "git"
    assert "checkout" in result.error.lower()


# ── _run_git non-interactivity (freeze fix) ──────────────────────────────────────
# A git remote with no stored credential must FAIL FAST, never block on an unanswerable prompt.
# Regression guard: the update-check ran git on the web event loop; a blocking prompt froze the app.

def test_run_git_disables_terminal_prompt(tmp_path):
    from corpusfm.updater import _run_git
    with patch("corpusfm.updater.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        _run_git(tmp_path, "fetch", "--quiet")
    env = run.call_args.kwargs["env"]
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_ASKPASS"] == ""        # no GUI/helper askpass either
    assert env["GCM_INTERACTIVE"] == "Never"


def test_WINDOWS_git_is_the_installation_recorded_binary_not_ambient_PATH(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from corpusfm import updater

    repo = tmp_path / "install" / "src"
    repo.mkdir(parents=True)
    git = repo.parent / "git" / "cmd" / "git.exe"
    git.parent.mkdir(parents=True)
    git.write_bytes(b"")
    monkeypatch.setattr(updater, "os", SimpleNamespace(name="nt", environ={}))
    with patch("corpusfm.updater.subprocess.run") as run:
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        updater._run_git(repo, "rev-parse", "HEAD")
    assert run.call_args.args[0][0] == str(git)


def test_update_routes_run_off_the_event_loop():
    """check_update / apply_update shell out to git; they must be sync `def` so FastAPI runs them in
    the threadpool and a slow remote can never block the single web event loop."""
    import asyncio
    from corpusfm.app.web.routes.api import settings as s
    assert not asyncio.iscoroutinefunction(s.check_update)
    assert not asyncio.iscoroutinefunction(s.apply_update)
