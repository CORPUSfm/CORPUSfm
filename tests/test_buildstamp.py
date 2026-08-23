"""Runtime version stamp (packet: fix post-upgrade version 0.0).

`__version__` must read the installer/updater-written stamp first and only fall back to git in dev —
so a service whose PATH lacks git never reports 0.0.
"""
from __future__ import annotations

import corpusfm
from corpusfm import buildstamp


# ── buildstamp writer/reader ─────────────────────────────────────────────────────

def test_read_stamp_absent_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(buildstamp, "STAMP_PATH", tmp_path / "_build.txt")
    assert buildstamp.read_stamp() is None


def test_read_stamp_invalid_returns_none(tmp_path, monkeypatch):
    p = tmp_path / "_build.txt"; p.write_text("not-a-number\n")
    monkeypatch.setattr(buildstamp, "STAMP_PATH", p)
    assert buildstamp.read_stamp() is None


def test_write_then_read_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(buildstamp, "STAMP_PATH", tmp_path / "_build.txt")
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: "1234")
    assert buildstamp.write_stamp() == "1234"
    assert buildstamp.read_stamp() == "1234"
    assert (tmp_path / "_build.txt").read_text().strip() == "1234"


def test_write_stamp_noop_when_source_identity_unavailable(tmp_path, monkeypatch):
    p = tmp_path / "_build.txt"
    monkeypatch.setattr(buildstamp, "STAMP_PATH", p)
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: None)
    assert buildstamp.write_stamp() is None
    assert not p.exists()   # an existing stamp would be left untouched; none here


# ── __version__ / _build_number precedence ───────────────────────────────────────

def test_build_number_prefers_stamp_over_git(monkeypatch):
    monkeypatch.setattr(buildstamp, "read_stamp", lambda: "777")
    monkeypatch.setattr(buildstamp, "git_build_number", lambda *a, **k: "999")
    assert corpusfm._build_number() == "777"


def test_build_number_falls_back_to_git_without_stamp(monkeypatch):
    monkeypatch.setattr(buildstamp, "read_stamp", lambda: None)
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: "999")
    assert corpusfm._build_number() == "999"


def test_build_number_zero_when_neither(monkeypatch):
    monkeypatch.setattr(buildstamp, "read_stamp", lambda: None)
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: None)
    assert corpusfm._build_number() == "0"


def test_version_not_zero_when_git_absent_but_stamp_present(monkeypatch):
    """The fix: git unavailable (PATH/ownership/etc.) but the stamp is written → real version, not 0.0."""
    monkeypatch.setattr(buildstamp, "read_stamp", lambda: "1002")
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: None)
    assert corpusfm._build_number() == "1002"
    assert f"0.{corpusfm._build_number()}" == "0.1002"


# ── Packet 065: stamp truthfulness + non-interactive git ──────────────────────────

def test_write_stamp_deletes_stale_on_write_failure(tmp_path, monkeypatch):
    """A write that can't be verified must clear any stale stamp (fall back to git), never serve a
    wrong/old number forever."""
    p = tmp_path / "_build.txt"
    p.write_text("0001\n")                       # a stale existing stamp
    monkeypatch.setattr(buildstamp, "STAMP_PATH", p)
    monkeypatch.setattr(buildstamp, "source_build_number", lambda *a, **k: "1234")

    def _boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(buildstamp.Path, "write_text", _boom, raising=False)
    assert buildstamp.write_stamp() is None
    assert not p.exists()                          # stale stamp removed → runtime falls back to git


def test_git_build_number_is_non_interactive(monkeypatch):
    captured = {}

    def _fake_run(cmd, **kw):
        captured["env"] = kw.get("env") or {}
        import subprocess as _sp
        return _sp.CompletedProcess(cmd, 0, stdout="4242\n", stderr="")
    monkeypatch.setattr(buildstamp.subprocess, "run", _fake_run)
    assert buildstamp.git_build_number() == "4242"
    assert captured["env"].get("GIT_TERMINAL_PROMPT") == "0"
    assert captured["env"].get("GIT_ASKPASS") == ""


def test_public_release_identity_wins_over_short_public_git_history(tmp_path, monkeypatch):
    (tmp_path / "release-build.txt").write_text("2564\n", encoding="utf-8")
    monkeypatch.setattr(buildstamp, "git_build_number", lambda *a, **k: "4")
    assert buildstamp.source_build_number(tmp_path) == "2564"


def test_private_development_checkout_without_release_identity_keeps_git_count(tmp_path, monkeypatch):
    monkeypatch.setattr(buildstamp, "git_build_number", lambda *a, **k: "2566")
    assert buildstamp.source_build_number(tmp_path) == "2566"


def test_invalid_release_identity_never_masks_development_fallback(tmp_path, monkeypatch):
    (tmp_path / "release-build.txt").write_text("not-a-build\n", encoding="utf-8")
    monkeypatch.setattr(buildstamp, "git_build_number", lambda *a, **k: "2566")
    assert buildstamp.source_build_number(tmp_path) == "2566"
