"""The git export credential model: registration cred_type, per-repo local history,
artifact git-target store, and the Job/Artifact decoupling.

The credential (registration) is the mandate: a PAT reaches many repos (the Job/Artifact may
override the repo), a deploy key is bound to one (overrides ignored). An artifact receives the
job's selection at ingest, then owns it independently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from corpusfm.core.git_formatter.registrations import (
    RegistrationConfig, add_registration, get_registration, is_valid_registration_name,
    resolve_local_path, effective_repo, verify_registration, push_registration,
)


# ── Name validation (the name is a URL path segment in verify/push/delete) ────────

def test_is_valid_registration_name():
    assert is_valid_registration_name("test-repo-1")
    assert is_valid_registration_name("CORPUSfm-git")
    assert is_valid_registration_name("a.b_c-1")
    # the bug: a repo-shaped name with a slash breaks the {name} route (404, undeletable)
    assert not is_valid_registration_name("blconstructs/PRIVATE_TEST_REPO_1")
    assert not is_valid_registration_name("has space")
    assert not is_valid_registration_name("")


def test_add_registration_rejects_unsafe_name(_reg_backend):
    from corpusfm.core.git_formatter import list_registrations
    bad = RegistrationConfig(name="blconstructs/REPO", cred_type="pat",
                             repo="https://github.com/blconstructs/REPO")
    with pytest.raises(ValueError, match="slashes or spaces"):
        add_registration(bad)
    # nothing written
    assert list_registrations() == []
    # the same credential with a slash-free name saves fine
    add_registration(RegistrationConfig(name="repo", cred_type="pat",
                                        repo="https://github.com/blconstructs/REPO"))
    assert get_registration("repo").repo.endswith("/REPO")


# ── Credential model ────────────────────────────────────────────────────────────

def test_registration_roundtrip_with_cred_fields(_reg_backend):
    reg = RegistrationConfig(name="team", cred_type="pat",
                             repo="https://github.com/o/r.git", username="bot",
                             token_enc="enc:abc", branch="main")
    add_registration(reg)
    got = get_registration("team")
    assert got.cred_type == "pat"
    assert got.token_enc == "enc:abc"
    assert got.username == "bot"
    assert got.repo == "https://github.com/o/r.git"


def test_effective_repo_pat_allows_override():
    pat = RegistrationConfig(name="p", cred_type="pat", repo="https://h/default.git")
    assert effective_repo(pat, "https://h/other.git") == "https://h/other.git"
    assert effective_repo(pat, "") == "https://h/default.git"


def test_effective_repo_deploy_key_is_bound():
    dk = RegistrationConfig(name="d", cred_type="deploy_key", repo="git@h:bound.git")
    # A deploy key ignores any downstream override — it is bound to its own repo.
    assert effective_repo(dk, "https://h/whatever.git") == "git@h:bound.git"


def test_resolve_local_path_per_repo_under_default_base():
    reg = RegistrationConfig(name="team", cred_type="pat")
    base = resolve_local_path(reg, "")
    a = resolve_local_path(reg, "https://github.com/o/a.git")
    b = resolve_local_path(reg, "https://github.com/o/b.git")
    assert a != b                       # each repo its own diffable history
    assert a.parent == base and b.parent == base


def test_resolve_local_path_explicit_is_pinned(tmp_path):
    reg = RegistrationConfig(name="team", repo="https://h/r.git", local_path=str(tmp_path))
    # An explicit path is honoured as-is (no per-repo subdir).
    assert resolve_local_path(reg, "https://h/r.git") == tmp_path


def test_verify_and_push_need_a_secret():
    pat = RegistrationConfig(name="p", cred_type="pat", repo="https://h/r.git")
    ok, msg = verify_registration(pat)
    assert ok is False and "token" in msg.lower()
    ok2, msg2 = push_registration(pat, "/tmp/nope")
    assert ok2 is False and "token" in msg2.lower()


def test_verify_needs_a_repo():
    pat = RegistrationConfig(name="p", cred_type="pat", token_enc="enc:x")
    ok, msg = verify_registration(pat, "")
    assert ok is False and "repo" in msg.lower()


# ── Job-level repo ───────────────────────────────────────────────────────────────

def test_job_git_export_repo_roundtrip():
    from corpusfm.server.jobs.config import JobConfig, JobSource, JobProcess, JobGitExport, JobTrigger
    job = JobConfig(
        name="j", source=JobSource(type="fms_save_to_documents", databases=["F"]),
        process=JobProcess(git_export=JobGitExport(registrations=["team"], repo="https://h/r.git")),
        triggers=[JobTrigger(type="manual")], file="F")
    d = job.to_dict()
    assert d["process"]["git_export"]["repo"] == "https://h/r.git"
    back = JobConfig.from_dict(d)
    assert back.process.git_export.repo == "https://h/r.git"


# ── Artifact git-target store ─────────────────────────────────────────────────────
# The per-artifact git target now rides the owning STORAGE record's jor (packet 1009/S3), not a
# yaml/SETTING side map — covered in tests/test_git_targets.py against a real backend engine.


# ── Settings routes (encrypt at rest, preserve-on-blank, verify) ─────────────────

def _settings_client():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from corpusfm.app.web.routes.api.settings import router
    from corpusfm.app.web.auth import require_auth
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.dependency_overrides[require_auth] = lambda: None
    return TestClient(app)


@pytest.fixture
def _reg_backend(tmp_path, monkeypatch):
    # Registrations live in the FM DB now (packet 1009/S1-B/C) — point get_backend at a tmp backend.
    from corpusfm.storage import get_backend
    b = get_backend(tmp_path / "archive")
    monkeypatch.setattr("corpusfm.storage.get_backend", lambda *a, **k: b)
    return b


def test_settings_git_add_encrypts_and_preserves(_reg_backend):
    import corpusfm.core.git_formatter.registrations as regs
    client = _settings_client()
    # Add a PAT with a token → stored encrypted (enc: marker), never plaintext.
    r = client.post("/api/settings/git/add", json={
        "name": "team", "cred_type": "pat", "repo": "https://h/r.git", "token": "ghp_SECRET"})
    assert r.json()["ok"] is True
    saved = regs.get_registration("team")
    assert saved.token_enc.startswith("enc:") and "ghp_SECRET" not in saved.token_enc
    # Edit with a blank token preserves the stored secret.
    r2 = client.post("/api/settings/git/add", json={
        "name": "team", "cred_type": "pat", "repo": "https://h/r2.git", "token": ""})
    assert r2.json()["ok"] is True
    saved2 = regs.get_registration("team")
    assert saved2.token_enc == saved.token_enc and saved2.repo == "https://h/r2.git"


def test_settings_smtp_password_is_write_only(tmp_path, monkeypatch):
    # packet 1009/S1-E: the SMTP password is write-only — a save with a BLANK password preserves the
    # stored one (the GET only ever exposes `smtp_pass_set`), and the value is encrypted on disk.
    import corpusfm.server.monitor.config as mc
    monkeypatch.setattr(mc, "default_monitor_config_path", lambda: tmp_path / "monitor.yaml")
    client = _settings_client()
    r = client.post("/api/settings/notifications", json={
        "smtp_host": "smtp.example.com", "smtp_user": "u", "smtp_pass": "s3cret", "smtp_to": "a@b.c"})
    assert r.json()["ok"] is True
    assert mc.load_monitor_config().email["password"] == "s3cret"
    # Re-save with a BLANK password (other fields changed) → the stored password is preserved.
    r2 = client.post("/api/settings/notifications", json={
        "smtp_host": "smtp.example.com", "smtp_user": "u2", "smtp_pass": "", "smtp_to": "a@b.c"})
    assert r2.json()["ok"] is True
    reloaded = mc.load_monitor_config()
    assert reloaded.email["password"] == "s3cret"     # preserved, not blanked
    assert reloaded.email["username"] == "u2"          # other fields still updated
    assert "s3cret" not in (tmp_path / "monitor.yaml").read_text()   # encrypted on disk


def test_settings_git_verify_route(_reg_backend):
    import corpusfm.core.git_formatter.registrations as regs
    regs.add_registration(RegistrationConfig(name="team", cred_type="pat", repo="https://h/r.git"))
    client = _settings_client()
    r = client.post("/api/settings/git/team/verify", json={"repo": "https://h/r.git"})
    d = r.json()
    assert d["ok"] is False and "token" in d["msg"].lower()  # no secret stored → honest fail


# ── Deploy-key keygen (in-app) ───────────────────────────────────────────────────

def test_generate_ssh_keypair_is_valid_openssh():
    from corpusfm.core.git_formatter.registrations import generate_ssh_keypair
    priv, pub = generate_ssh_keypair(comment="corpusfm-x")
    assert priv.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert pub.startswith("ssh-ed25519 ") and pub.endswith(" corpusfm-x")
    assert generate_ssh_keypair()[0] != priv  # each generation is unique


def test_settings_generate_deploy_key_route(_reg_backend):
    import corpusfm.core.git_formatter.registrations as regs
    client = _settings_client()
    r = client.post("/api/settings/git/generate-deploy-key",
                    json={"name": "dkey", "repo": "git@github.com:o/r.git"})
    d = r.json()
    assert d["ok"] is True and d["ssh_pubkey"].startswith("ssh-ed25519 ")
    saved = regs.get_registration("dkey")
    assert saved.cred_type == "deploy_key"
    assert saved.repo == "git@github.com:o/r.git"
    assert saved.ssh_key_enc.startswith("enc:")        # private key stored encrypted
    assert saved.ssh_pubkey == d["ssh_pubkey"]         # public key persisted
    assert "PRIVATE KEY" not in r.text                 # private key never returned to the client


def test_settings_generate_deploy_key_validates(_reg_backend):
    from corpusfm.core.git_formatter import list_registrations
    client = _settings_client()
    bad_name = client.post("/api/settings/git/generate-deploy-key",
                           json={"name": "o/r", "repo": "git@github.com:o/r.git"})
    assert bad_name.status_code == 400 and bad_name.json()["ok"] is False
    no_repo = client.post("/api/settings/git/generate-deploy-key", json={"name": "dkey", "repo": ""})
    assert no_repo.status_code == 400 and no_repo.json()["ok"] is False
    assert list_registrations() == []  # nothing persisted on rejection


# ── Library routes (per-artifact git target, decoupled) ──────────────────────────

def _library_client():
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from corpusfm.app.web.routes.api.library import router
    from corpusfm.app.web.auth import require_auth
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.dependency_overrides[require_auth] = lambda: None
    return TestClient(app)


def test_library_git_target_get_put(tmp_path, monkeypatch):
    # The git target now rides the STORAGE record's jor (packet 1009/S3): store a real artifact and
    # address it by its canonical record UUID through the library routes.
    from pathlib import Path
    from corpusfm.storage import get_backend
    from corpusfm.storage import artifact_store as AS
    from corpusfm.ingestion import ingest
    b = get_backend(tmp_path / "archive")
    monkeypatch.setattr("corpusfm.storage.get_backend", lambda *a, **k: b)
    xml = (Path(__file__).parent / "fixtures" / "minimal.xml").read_bytes()
    uuid = AS.store_artifact(b, ingest(xml, "Minimal"), xml_bytes=xml, label="Minimal").uuid
    client = _library_client()
    assert client.get(f"/api/library/artifacts/{uuid}/git-target").json() == {"registration": "", "repo": ""}
    r = client.put(f"/api/library/artifacts/{uuid}/git-target",
                   json={"registration": "team", "repo": "https://h/r.git"})
    assert r.json() == {"registration": "team", "repo": "https://h/r.git"}
    assert client.get(f"/api/library/artifacts/{uuid}/git-target").json()["registration"] == "team"


def test_library_git_registrations_exposes_cred_type(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(
        "corpusfm.core.git_formatter.list_registrations",
        lambda: [SimpleNamespace(name="dk", cred_type="deploy_key", repo="git@h:r.git", branch="main")])
    regs = _library_client().get("/api/library/git-registrations").json()["registrations"]
    assert regs[0]["cred_type"] == "deploy_key" and regs[0]["repo_locked"] is True


# ── PAT secret handling: token stays out of argv; git resolves it from env (packet 1000 re-sweep) ──

def test_pat_git_creds_keeps_token_out_of_argv():
    from corpusfm.core.git_formatter.registrations import _pat_git_creds
    token = "ghp_SECRET_never_in_argv"
    cargs, env = _pat_git_creds(token, "x-access-token")
    full_argv = ["git"] + cargs + ["ls-remote", "--", "https://example.invalid/r.git"]
    assert not any(token in a for a in full_argv)          # secret absent from every argv element
    assert any("$CFM_GIT_TOKEN" in a for a in cargs)       # helper references it by NAME
    assert env["CFM_GIT_TOKEN"] == token                   # secret rides the child env only
    assert env["CFM_GIT_USER"] == "x-access-token"


def test_pat_git_creds_helper_resolves_token(tmp_path):
    # Prove git actually reads the token via the inline helper (offline — `git credential fill`).
    import subprocess
    from corpusfm.core.git_formatter.registrations import _pat_git_creds
    token = "ghp_SECRET_resolved_by_git"
    cargs, env = _pat_git_creds(token, "x-access-token")
    r = subprocess.run(["git"] + cargs + ["credential", "fill"],
                       input="protocol=https\nhost=example.invalid\n\n",
                       capture_output=True, text=True, env=env, timeout=15)
    assert f"password={token}" in r.stdout
    assert "username=x-access-token" in r.stdout


def test_redact_scrubs_token_from_git_output():
    from corpusfm.core.git_formatter.registrations import _redact
    tok = "ghp_LEAK"
    msg = f"fatal: could not read Password for 'https://x-access-token:{tok}@host'"
    out = _redact(msg, tok)
    assert tok not in out and "***" in out
    assert _redact("", tok) == ""
