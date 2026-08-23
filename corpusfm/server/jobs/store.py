"""Job config file storage.

One YAML file per job in the jobs/ directory. A valid YAML file = active job.
No separate activation step.

Public API:
    default_jobs_dir()
    save_job(cfg, jobs_dir, overwrite)
    load_job(name, jobs_dir) -> JobConfig
    list_jobs(jobs_dir) -> list[tuple[JobConfig | None, str | None]]
    delete_job(name, jobs_dir) -> bool
    generate_token() -> str
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Optional

from corpusfm.server.jobs.config import JobConfig

_PROJECT_ROOT = Path(__file__).parent.parent.parent

TOKEN_BYTES = 16  # 32 hex chars


def _repo():
    """The JobsRepo on a server (fm_odata) install, else None (local dev/test = YAML files).
    Jobs are a server feature, so the gate is the INSTALL MODE, not engine presence — the
    repo just carries the entity logic over whichever engine the live backend exposes."""
    # THE SILENT FALLBACK THIS CLOSES (packet 1246-08 §11.2 row 5): returning None on a published
    # box sends Jobs to local YAML files while the corpus sits there unused, and nothing reports it.
    from corpusfm.lifecycle import runtime_storage

    active = runtime_storage.fm_storage_active()
    if active is None:                        # nothing published — the dev/test path, unchanged
        from corpusfm.install import read_install_config
        if read_install_config().get("storage_backend") != "fm_odata":
            return None
    elif not active:
        raise RuntimeError(
            "this installation is published but has composed no corpus; refusing to serve Jobs "
            "from local files while its storage authority is incomplete.")
    from corpusfm.storage import get_backend
    from corpusfm.storage.repos import jobs_repo
    r = jobs_repo(get_backend())
    if r is None:
        raise RuntimeError(
            "storage_backend is fm_odata but FileMakerODataBackend could not be loaded."
        )
    return r


def _jrepo():
    """The JobsRepo over the live backend's ENGINE (not install-mode gated). Per-job credentials
    + verification live in the JOB record's CredentialData container + jor flags, which are an
    engine feature — they work on FileMakerODataBackend (server) AND the LocalBackend SQLite
    mirror (dev/test). A job that isn't an engine record (a pure local-YAML dev job) simply has
    no credential — jobs are a server feature. Returns None only for an engine-less backend."""
    from corpusfm.storage import get_backend
    from corpusfm.storage.repos import jobs_repo
    return jobs_repo(get_backend())


# ── per-job credential + verification (packet 085 U3b) ─────────────────────────

def set_job_credential(name: str, account: str, password: str) -> bool:
    r = _jrepo()
    return bool(r and r.set_credential(name, account, password))


def get_job_credential(name: str) -> "Optional[dict]":
    r = _jrepo()
    return r.get_credential(name) if r is not None else None


def has_job_credential(name: str) -> bool:
    r = _jrepo()
    return bool(r and r.has_credential(name))


def job_account_name(name: str) -> str:
    r = _jrepo()
    return r.account_name(name) if r is not None else ""


def delete_job_credential(name: str) -> bool:
    r = _jrepo()
    return bool(r and r.delete_credential(name))


def set_job_verified(name: str, verified: bool, reason: str = "") -> None:
    r = _jrepo()
    if r is not None:
        r.set_verified(name, verified, reason)


def job_verify_state(name: str) -> "tuple[bool, str]":
    r = _jrepo()
    return r.verify_state(name) if r is not None else (False, "")


def _published_state_dir():
    """The published writable state directory, or `None` when nothing is published.

    THE SOURCE TREE IS NOT WRITABLE (packet 1246-10-04). `_PROJECT_ROOT` is `/opt/CORPUSfm/src` on
    an installed box — root-owned 0750 and inside the systemd sandbox's read-only world — so a
    default that puts mutable job, history or archive material there is a scheduler that cannot
    run. The published `state_dir` is the authority the unit already grants (`ReadWritePaths`), and
    a tree that publishes no installation keeps `_PROJECT_ROOT`.
    """
    from corpusfm.lifecycle import app_paths

    try:
        return app_paths.state_dir()
    except Exception:  # noqa: BLE001 - nothing published: the development tree, unchanged
        return None


def default_jobs_dir() -> Path:
    state = _published_state_dir()
    return (state if state is not None else _PROJECT_ROOT) / "jobs"


def default_history_dir() -> Path:
    state = _published_state_dir()
    return (state if state is not None else _PROJECT_ROOT) / "history"


def generate_token() -> str:
    """Generate a secure random webhook token."""
    return secrets.token_hex(TOKEN_BYTES)


def _safe_name(name: str) -> str:
    """Injective, filesystem-safe base filename for a job name (dev/test YAML path only — the
    server install keys jobs by uuid). Percent-encodes every char outside the always-safe set
    (alphanumerics + ``._-``), INCLUDING ``/`` and ``%`` itself, so distinct names never collide —
    unlike the old lossy ``[^\\w._-] -> _`` map where ``"a b"`` and ``"a_b"`` shared one file.
    Backward-compatible for ASCII: a name of only ASCII safe chars is returned unchanged, so
    pre-existing ``<name>.yaml`` / ``<name>.state`` files still resolve without migration. A pre-1056
    name containing NON-ASCII word chars (the old ``\\w`` validator accepted e.g. ``café``, stored
    verbatim) now percent-encodes and would not resolve its legacy file — accepted, dev/test YAML path
    only (the server install keys jobs by uuid, not by name)."""
    from urllib.parse import quote
    return quote(name, safe="._-")


def _job_path(name: str, jobs_dir: Path) -> Path:
    return jobs_dir / f"{_safe_name(name)}.yaml"


def save_job(
    cfg: JobConfig,
    jobs_dir: Path = None,
    overwrite: bool = False,
) -> None:
    """Write a job config. Raises ValueError if name exists and overwrite=False."""
    r = _repo()
    if r is not None:
        r.save(cfg, overwrite=overwrite)
        return
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    jobs_dir.mkdir(parents=True, exist_ok=True)
    path = _job_path(cfg.name, jobs_dir)
    if path.exists() and not overwrite:
        raise ValueError(f"Job '{cfg.name}' already exists. Pass overwrite=True to replace.")
    path.write_text(cfg.to_yaml(), encoding="utf-8")


def load_job(name: str, jobs_dir: Path = None) -> JobConfig:
    """Load a job by name. Raises KeyError if not found."""
    r = _repo()
    if r is not None:
        return r.load(name)
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    path = _job_path(name, jobs_dir)
    if not path.exists():
        raise KeyError(f"Job '{name}' not found in {jobs_dir}.")
    return JobConfig.from_yaml(path.read_text(encoding="utf-8"))


def find_job_by_id(job_id: str, jobs_dir: Path = None) -> Optional[JobConfig]:
    """Resolve a job by its stable uuid (for DISPLAY — e.g. naming the job that spawned an
    artifact). Returns None if no job carries that id. Never used as a link key itself."""
    if not job_id:
        return None
    for cfg, _err in list_jobs(jobs_dir):
        if cfg is not None and getattr(cfg, "id", None) == job_id:
            return cfg
    return None


def list_jobs(
    jobs_dir: Path = None,
) -> list[tuple[Optional[JobConfig], Optional[str]]]:
    """Return all jobs as (JobConfig | None, error_str | None) pairs, sorted by name.

    Invalid records are included with config=None and an error string.
    """
    r = _repo()
    if r is not None:
        return r.list()
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    if not jobs_dir.exists():
        return []
    result = []
    for path in sorted(jobs_dir.glob("*.yaml")):
        try:
            cfg = JobConfig.from_yaml(path.read_text(encoding="utf-8"))
            result.append((cfg, None))
        except Exception as exc:
            result.append((None, f"{path.name}: {exc}"))
    return result


def list_jobs_with_state(jobs_dir: Path = None) -> list:
    """(JobConfig, JobState) for every VALID job — from ONE store read on a server install
    (audit #4: the state fields ride the same JOBS records the config parse already reads; the
    old per-job ``read_state`` re-fetch was an N+1 on the 10s notifications poll). Local mode
    reads the cheap sidecar files as before."""
    r = _repo()
    if r is not None:
        return [(cfg, state) for cfg, state in r.list_with_state() if cfg is not None]
    from corpusfm.server.jobs.state import read_state
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    return [(cfg, read_state(cfg.name, jobs_dir))
            for cfg, _err in list_jobs(jobs_dir) if cfg is not None]


def delete_job(name: str, jobs_dir: Path = None) -> bool:
    """Delete a job. Returns True if it existed."""
    r = _repo()
    if r is not None:
        return r.delete(name)
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    path = _job_path(name, jobs_dir)
    state_path = jobs_dir / f"{_safe_name(name)}.state"
    existed = path.exists()
    if existed:
        path.unlink()
    if state_path.exists():
        state_path.unlink()
    return existed
