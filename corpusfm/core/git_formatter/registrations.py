"""Named git export registration store.

Registrations live in the FileMaker DB (the GITREG logical table — packet 1009/S1-B/C) so they are
PORTABLE: they survive a reinstall / restore / db-move and travel with the corpus, instead of the old
per-name YAML files on disk. Each credential is one GITREG record keyed by its NAME (a validated
single URL segment). The NON-secret config rides the record's ``JSONOfRecord``; the SECRETS
(``token_enc`` / ``ssh_key_enc``) ride the Corpus-Key-encrypted ``SecretData`` container, never jor (the
table-wide no-secret-in-jor fence, packet 1007). Multiple jobs can share one registration; one job
can target multiple registrations. Both credential types are kept: PAT (HTTPS token) + deploy-key (SSH).

Public API:
    add_registration(cfg, overwrite=False) -> None
    get_registration(name) -> RegistrationConfig        # raises KeyError if absent
    list_registrations() -> list[RegistrationConfig]     # sorted by name
    remove_registration(name) -> bool
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import uuid as _uuidlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from corpusfm.core.crypto import decrypt_secret
from corpusfm.core.git_formatter._renderer import ALL_SECTIONS, DEFAULT_LARGE_THRESHOLD

_GITREG = "GITREG"
# The non-secret RegistrationConfig fields persisted to the record jor. token_enc / ssh_key_enc are
# SECRETS → the SecretData container (never jor).
_JOR_FIELDS = ("name", "cred_type", "repo", "branch", "username", "ssh_pubkey",
               "modes", "sections", "show_hidden", "large_content_threshold", "group", "local_path")

_PROJECT_ROOT = Path(__file__).parent.parent.parent
_SAFE_NAME = re.compile(r"[^\w._-]")


@dataclass
class RegistrationConfig:
    name: str
    cred_type: str = "pat"            # "pat" (HTTPS token, many repos) | "deploy_key" (SSH, one bound repo)
    repo: str = ""                    # PAT: optional default repo (Job/Artifact may override). D-Key: the bound repo (fixed).
    branch: str = "main"
    username: str = ""                # PAT: optional git username (GitHub ignores it; default "x-access-token")
    token_enc: str = ""               # PAT: at-rest-encrypted personal access token ("enc:..." via core.crypto)
    ssh_key_enc: str = ""             # D-Key: at-rest-encrypted SSH private key
    ssh_pubkey: str = ""              # D-Key: public key (shown to paste as the repo's deploy key)
    modes: list = field(default_factory=lambda: ["structured", "rendered"])
    sections: list = field(default_factory=lambda: list(ALL_SECTIONS))
    show_hidden: bool = True
    large_content_threshold: int = DEFAULT_LARGE_THRESHOLD
    group: Optional[str] = None
    local_path: Optional[str] = None  # if None, defaults to {project_root}/git_exports/{name}/[{repo}]


def resolve_local_path(reg: RegistrationConfig, repo: str = "") -> Path:
    """Local git clone path for an export. An explicit ``local_path`` is honoured as-is (the
    operator pinned the directory). Otherwise the default base ``git_exports/{name}`` gets a
    PER-REPO subdir so each repo under the one credential accrues its own clean, diffable
    history. ``repo`` is the effective target (Job/Artifact override > registration default)."""
    if reg.local_path:
        return Path(reg.local_path)
    base = _PROJECT_ROOT / "git_exports" / _safe_filename(reg.name)
    target_repo = (repo or reg.repo or "").strip()
    if target_repo:
        return base / _safe_filename(target_repo)
    return base


def effective_repo(reg: RegistrationConfig, repo: str = "") -> str:
    """The repo this push targets: a PAT may be overridden downstream; a deploy key is
    bound to its own repo regardless of what a Job/Artifact tried to set."""
    if reg.cred_type == "deploy_key":
        return (reg.repo or "").strip()
    return (repo or reg.repo or "").strip()


def _pat_git_creds(token: str, username: str = ""):
    """Return (extra_git_args, env) that authenticate an https fetch/push with a PAT **without the
    token ever entering argv**.

    The token used to be injected into the repo URL (``https://user:token@host/…``) and passed as a
    positional git argument — visible in ``ps`` / ``/proc/<pid>/cmdline`` to any local user for the
    life of the (short) git call, and liable to be echoed back inside a git transport error. That is
    the exact exposure the deploy-key path already avoids (packet 1009/C). Here the token rides only
    the child **environment** (``/proc/<pid>/environ`` — owner+root, not ``ps``-listable): git's
    inline credential helper reads it by variable NAME, so argv carries the literal ``$CFM_GIT_TOKEN``
    text, never the secret. The empty ``credential.helper=`` first resets any system/global helper so
    only ours answers. The URL is passed clean (no credentials)."""
    import os
    helper = ('!f() { test "$1" = get && printf '
              "'username=%s\\npassword=%s\\n' "
              '"${CFM_GIT_USER:-x-access-token}" "$CFM_GIT_TOKEN"; }; f')
    args = ["-c", "credential.helper=", "-c", f"credential.helper={helper}"]
    env = dict(os.environ)
    env["CFM_GIT_TOKEN"] = token
    if username:
        env["CFM_GIT_USER"] = username
    return args, env


def _redact(text: str, *secrets: str) -> str:
    """Scrub any secret substring from a git message before it reaches the UI / logs (defence in
    depth — the token no longer rides the URL, but a git version could still surface it)."""
    out = text or ""
    for s in secrets:
        if s:
            out = out.replace(s, "***")
    return out


def _run_git(args: list[str], env: Optional[dict] = None, timeout: int = 60):
    # Non-interactive ALWAYS (the updater invariant): a rejected/missing credential must fail
    # fast, never block on a terminal prompt for the full timeout.
    import os
    merged = dict(env if env is not None else os.environ)
    merged.update({"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "Never"})
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=merged)


def _no_leading_dash(value: str, label: str) -> None:
    """Reject an operator-config value that would be parsed as a git option (leading '-').
    Defence-in-depth: argv already uses '--' separators; this refuses the value outright."""
    if value.startswith("-"):
        raise ValueError(f"Invalid {label}: must not start with '-'.")


def _deploy_key_env(reg: RegistrationConfig):
    """Return (env, cleanup) for an SSH deploy-key push, or (None, noop) if not applicable.

    The decrypted private key is written 0600 inside a per-call ``mkdtemp`` directory (mode 0700,
    service-owned) rather than a bare file directly in world-listable ``/tmp`` (packet 1009/C) — the
    key is never even *listable* by another local user. The whole dir is removed on cleanup."""
    key = decrypt_secret(reg.ssh_key_enc)
    if not key:
        return None, (lambda: None)
    import os
    import shutil
    d = tempfile.mkdtemp(prefix="cfm_dkey_")            # 0700 dir — not world-listable
    path = os.path.join(d, "key")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (key if key.endswith("\n") else key + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    env = dict(os.environ)
    env["GIT_SSH_COMMAND"] = (
        f"ssh -i {path} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes"
    )
    return env, (lambda: shutil.rmtree(d, ignore_errors=True))


def verify_registration(reg: RegistrationConfig, repo: str = "") -> tuple[bool, str]:
    """Prove the credential can reach the target repo (auth'd ls-remote). Never raises."""
    repo_url = effective_repo(reg, repo)
    if not repo_url:
        return False, "Set a repo to test against."
    try:
        _no_leading_dash(repo_url, "repo URL")
        if reg.cred_type == "deploy_key":
            env, cleanup = _deploy_key_env(reg)
            if env is None:
                return False, "No SSH key stored for this deploy key."
            try:
                r = _run_git(["git", "ls-remote", "--", repo_url], env=env, timeout=30)
            finally:
                cleanup()
        else:
            token = decrypt_secret(reg.token_enc)
            if not token:
                return False, "No token stored for this PAT credential."
            cargs, cenv = _pat_git_creds(token, reg.username)
            r = _run_git(["git"] + cargs + ["ls-remote", "--", repo_url], env=cenv, timeout=30)
        if r.returncode == 0:
            return True, "Credential verified — repo reachable."
        return False, _redact((r.stderr or "git ls-remote failed").strip(), locals().get("token", ""))[:300]
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:300]


def push_registration(reg: RegistrationConfig, local_dir, repo: str = "",
                      branch: str = "") -> tuple[bool, str]:
    """Push a local export clone to the credential's effective repo URL. Never raises."""
    repo_url = effective_repo(reg, repo)
    if not repo_url:
        return False, "No repo set for this export."
    target_branch = (branch or reg.branch or "main").strip() or "main"
    refspec = f"HEAD:{target_branch}"
    try:
        _no_leading_dash(repo_url, "repo URL")
        _no_leading_dash(target_branch, "branch")
        if reg.cred_type == "deploy_key":
            env, cleanup = _deploy_key_env(reg)
            if env is None:
                return False, "No SSH key stored for this deploy key."
            try:
                r = _run_git(["git", "-C", str(local_dir), "push", "--", repo_url, refspec], env=env)
            finally:
                cleanup()
        else:
            token = decrypt_secret(reg.token_enc)
            if not token:
                return False, "No token stored for this PAT credential."
            cargs, cenv = _pat_git_creds(token, reg.username)
            r = _run_git(["git", "-C", str(local_dir)] + cargs + ["push", "--", repo_url, refspec], env=cenv)
        if r.returncode == 0:
            return True, f"Pushed to {repo_url} ({target_branch})."
        return False, _redact((r.stderr or "git push failed").strip(), locals().get("token", ""))[:300]
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)[:300]


def generate_ssh_keypair(comment: str = "") -> tuple[str, str]:
    """Generate an ed25519 SSH keypair for a deploy-key credential, in-process (no ssh-keygen
    subprocess). Returns (private_openssh, public_openssh): the private key in OpenSSH format so
    ``ssh -i`` accepts it (see _deploy_key_env), the public key as the single-line
    ``ssh-ed25519 AAAA… comment`` form to paste as a repo deploy key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode()
    if comment:
        pub = f"{pub} {comment}"
    return priv, pub


def is_valid_registration_name(name: str) -> bool:
    """A registration name must be usable as a single URL path segment — it appears in the
    verify/push/delete routes as ``{name}``. A '/' (or space, etc.) splits the path and the
    route 404s, which also makes the credential undeletable from the UI. Restrict to the same
    safe set already used for the on-disk filename."""
    return bool(name) and _SAFE_NAME.search(name) is None


def _safe_filename(name: str) -> str:
    return _SAFE_NAME.sub("_", name)


# ── FM-DB storage (GITREG table; secrets in the SecretData container) ─────────────

def _engine():
    """The storage engine (both backends expose it), or None when unavailable."""
    try:
        from corpusfm.storage import get_backend
        return getattr(get_backend(), "engine", None)
    except Exception:
        return None


def _cfg_to_jor(cfg: RegistrationConfig) -> dict:
    d = asdict(cfg)
    return {k: d[k] for k in _JOR_FIELDS}


def _cfg_from(jor: dict, secret: dict) -> RegistrationConfig:
    fields = RegistrationConfig.__dataclass_fields__
    data = {k: v for k, v in jor.items() if k in fields}
    data["token_enc"] = secret.get("token_enc", "") or ""
    data["ssh_key_enc"] = secret.get("ssh_key_enc", "") or ""
    return RegistrationConfig(**data)


def _find(eng, name: str):
    """The GITREG row whose indexed ``name`` slot matches (case-insensitive, like USER.Username), or
    None. Records are keyed by a uuid4 (NOT the name) — so key-addressed FM OData ops (delete) work
    exactly like every other table; the name is a slot we look up on."""
    return eng.get_one(_GITREG, name=name) if name else None


def _load_secret(eng, key: str) -> dict:
    from corpusfm.core.crypto import decode_blob, decompress
    try:
        raw = eng.blob_get(_GITREG, key, "SecretData")
        if not raw:
            return {}
        return json.loads(decompress(decode_blob(raw)).decode("utf-8"))
    except Exception:
        return {}


def _save_secret(eng, key: str, cfg: RegistrationConfig) -> None:
    from corpusfm.core.crypto import compress, encode_blob
    secret = {"token_enc": cfg.token_enc or "", "ssh_key_enc": cfg.ssh_key_enc or ""}
    blob = encode_blob(
        compress(json.dumps(secret, ensure_ascii=False).encode("utf-8")),
        encrypt_on=True)   # ALWAYS Corpus-Key-encrypted — a credential secret is never a plaintext blob
    eng.blob_put(_GITREG, key, "SecretData", blob)


def add_registration(cfg: RegistrationConfig, overwrite: bool = False) -> None:
    """Store a registration in the GITREG table (config in jor, secrets in the SecretData container).

    Raises ValueError if the name is invalid, or if it already exists and overwrite=False.
    """
    if not is_valid_registration_name(cfg.name):
        raise ValueError(
            "Credential name may only contain letters, digits, dot, dash, and underscore "
            "(no slashes or spaces) — it is used in the credential's web address. "
            "Name it for the credential, not the repo (the repo URL is a separate field)."
        )
    eng = _engine()
    if eng is None:
        raise RuntimeError("No storage backend available to store the credential.")
    existing = _find(eng, cfg.name)
    if existing is not None and not overwrite:
        raise ValueError(f"Registration '{cfg.name}' already exists. Pass overwrite=True to replace.")
    key = existing.key if existing is not None else str(_uuidlib.uuid4())
    jor = _cfg_to_jor(cfg)
    if existing is not None:
        eng.update(_GITREG, key, jor)
    else:
        eng.create(_GITREG, key, jor)
    _save_secret(eng, key, cfg)


def get_registration(name: str) -> RegistrationConfig:
    """Load a RegistrationConfig by name. Raises KeyError if it does not exist."""
    eng = _engine()
    if eng is None:
        raise KeyError(f"Registration '{name}' not found (no storage backend).")
    row = _find(eng, name)
    if row is None:
        raise KeyError(f"Registration '{name}' not found.")
    return _cfg_from(row.jor, _load_secret(eng, row.key))


def list_registrations() -> list[RegistrationConfig]:
    """Return all registrations sorted by name. Returns [] if the backend is unavailable."""
    eng = _engine()
    if eng is None:
        return []
    try:
        out = [_cfg_from(r.jor, _load_secret(eng, r.key)) for r in eng.list_all(_GITREG)]
    except Exception:
        return []
    return sorted(out, key=lambda c: c.name)


def remove_registration(name: str) -> bool:
    """Delete the named registration. True if it existed, else False.

    Deleting the record removes ALL its fields, INCLUDING the SecretData container — so there is no
    separate blob_delete. A prior blob_delete was not only redundant but left the FM record delete
    returning a spurious 404 while the record was actually removed (box-verified: a bare record delete
    succeeds; blob_delete-then-delete 404s though the row is gone)."""
    eng = _engine()
    if eng is None:
        return False
    row = _find(eng, name)
    if row is None:
        return False
    eng.delete(_GITREG, row.key)
    return True
