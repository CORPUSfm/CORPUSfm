"""Job storage — UUID-addressed (packet 1372-02).

A job is identified by its UUID and by nothing else. Names are editable labels that may collide,
including by case; no operation here resolves a job from one. On a server install the store is the
JOB table keyed by that UUID; on the unpublished dev/test path it is one `<job_uuid>.yaml` per job in
the jobs/ directory, with the name inside the document. A valid YAML file = active job; no separate
activation step.

Public API:
    default_jobs_dir()
    save_job(cfg, jobs_dir, overwrite)          # creates at cfg.id; refuses a missing/invalid id
    load_job(job_uuid, jobs_dir) -> JobConfig
    find_job_by_id(job_uuid, jobs_dir)          # O(1) on the server path
    list_jobs(jobs_dir) -> list[tuple[JobConfig | None, str | None]]
    delete_job(job_uuid, jobs_dir) -> bool
    generate_token() -> str
    assert_job_work_permitted()                 # the ProjectionVersion 2 gate
"""

from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Optional

from corpusfm.server.jobs.config import JobConfig

_PROJECT_ROOT = Path(__file__).parent.parent.parent

TOKEN_BYTES = 16  # 32 hex chars


class JobsStoreUnavailable(RuntimeError):
    """Jobs cannot be served, for a reason CORPUSfm itself states in product prose.

    Typed so a caller can tell it apart from a third-party failure and show it verbatim: the message
    is ours, an administrator can act on it, and it carries no response body, URL or credential
    (packet 1369).
    """


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
        raise JobsStoreUnavailable(
            "this installation is published but has composed no corpus; refusing to serve Jobs "
            "from local files while its storage authority is incomplete.")
    from corpusfm.storage import get_backend
    from corpusfm.storage.repos import jobs_repo
    r = jobs_repo(get_backend())
    if r is None:
        raise JobsStoreUnavailable(
            "storage_backend is fm_odata but FileMakerODataBackend could not be loaded."
        )
    return r


class JobWorkUnavailable(RuntimeError):
    """This corpus has not reached the projection version this build requires (packet 1372-02).

    Typed so a surface can show it verbatim: the message is ours, an administrator can act on it, and
    it carries no response body, URL or credential. Distinct from `JobsStoreUnavailable`, which is
    about storage authority rather than data readiness.
    """


def assert_job_work_permitted() -> None:
    """Refuse BEFORE any JOB write or enqueue until `ProjectionVersion == 2` reads back.

    **This is the whole of R8's cutover discipline in one call.** Until startup has strictly read
    back version 2, the JOB table may still be keyed the old way, and this build addresses it only by
    UUID — so a mutation or an enqueue would either fail confusingly or, worse, write a row (a
    blank-`UUIDJob` Job Run) that then blocks the very conversion that would fix it. Read-only
    administration and diagnosis stay available; writing and running do not.

    The read is strict: absent, behind, malformed and unreadable are all "not permitted", and an
    unsupported backend is the dev path with nothing to convert. `projections.conversion_complete`
    owns that judgement so there is exactly one place it is made.
    """
    from corpusfm.storage import get_backend, projections
    try:
        permitted = projections.conversion_complete(get_backend())
    except Exception as exc:
        raise JobWorkUnavailable(
            "Jobs are unavailable: this installation's storage could not be read "
            f"({type(exc).__name__}), so whether its job identities have been converted cannot be "
            "determined. See the CORPUSfm server log.") from exc
    if not permitted:
        raise JobWorkUnavailable(
            "Jobs are unavailable: this corpus has not completed the job-identity conversion this "
            "version of CORPUSfm requires. Restart CORPUSfm to run it; the server log names any "
            "record that refused. Viewing existing jobs still works.")


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

def set_job_credential(job_uuid: str, account: str, password: str) -> bool:
    """Set or replace a job's credential. A blank half is refused by the repo."""
    assert_job_work_permitted()
    r = _jrepo()
    return bool(r and r.set_credential(job_uuid, account, password))


def get_job_credential(job_uuid: str) -> "Optional[dict]":
    r = _jrepo()
    return r.get_credential(job_uuid) if r is not None else None


def has_job_credential(job_uuid: str) -> bool:
    r = _jrepo()
    return bool(r and r.has_credential(job_uuid))


def job_account_name(job_uuid: str) -> str:
    r = _jrepo()
    return r.account_name(job_uuid) if r is not None else ""


# `delete_job_credential` is RETIRED (packet 1372-02): no retained job may be left without the
# credential it needs to do the one thing it exists for. Replace it, or delete the job.


def set_job_verified(job_uuid: str, verified: bool, reason: str = "") -> None:
    """Record a verification verdict on the JOB record — a JOB mutation, so it takes the gate.

    Its only caller is the gated verify route, so this is defence in depth rather than the
    enforcement point. It is here because the rule is "every JOB mutation refuses before writing",
    and a mutator that is an exception to it is the one a later route reaches without noticing.
    """
    assert_job_work_permitted()
    r = _jrepo()
    if r is not None:
        r.set_verified(job_uuid, verified, reason)


def job_verify_state(job_uuid: str) -> "tuple[bool, str]":
    r = _jrepo()
    return r.verify_state(job_uuid) if r is not None else (False, "")


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


# `_safe_name` is RETIRED (packet 1372-02). It existed to turn a user-chosen name into a filename,
# which is the local half of the identity defect this cutover removes: two jobs whose names differed
# only by case shared one file, and renaming a job orphaned its state sidecar. Local files are now
# named by the job's UUID, with the name inside the document where it belongs.
# `corpusfm migrate job-identity --jobs-dir <dir>` converts a developer's existing fixtures.


def _job_path(job_uuid: str, jobs_dir: Path) -> Path:
    return jobs_dir / f"{job_uuid}.yaml"


def save_job(
    cfg: JobConfig,
    jobs_dir: Path = None,
    overwrite: bool = False,
) -> None:
    """Write a job config AT ITS OWN ID. Raises if the id is missing or already present."""
    assert_job_work_permitted()
    from corpusfm.storage.repos import JobIdentityInvalid, _SOUND_UUID
    r = _repo()
    if r is not None:
        r.save(cfg, overwrite=overwrite)
        return
    job_uuid = (getattr(cfg, "id", "") or "").strip()
    if not _SOUND_UUID.match(job_uuid):
        raise JobIdentityInvalid(
            f"job {cfg.name!r} carries id {getattr(cfg, 'id', None)!r}, which is not a UUID.")
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    jobs_dir.mkdir(parents=True, exist_ok=True)
    path = _job_path(job_uuid, jobs_dir)
    if path.exists() and not overwrite:
        raise ValueError(f"A job with id {job_uuid} already exists. Pass overwrite=True to replace.")
    path.write_text(cfg.to_yaml(), encoding="utf-8")


def load_job(job_uuid: str, jobs_dir: Path = None) -> JobConfig:
    """Load a job by its UUID. Raises KeyError if not found."""
    r = _repo()
    if r is not None:
        return r.load(job_uuid)
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    path = _job_path(job_uuid, jobs_dir)
    if not path.exists():
        raise KeyError(f"No job with id {job_uuid!r} in {jobs_dir}.")
    return JobConfig.from_yaml(path.read_text(encoding="utf-8"))


def find_job_by_id(job_uuid: str, jobs_dir: Path = None) -> Optional[JobConfig]:
    """A job by its UUID, or None. **O(1) now** — it is a direct key read, not a scan.

    It used to enumerate every job and compare ids in Python, because the id was not the record's
    address. It is, so this is `load_job` with a miss returned instead of raised.
    """
    if not job_uuid:
        return None
    try:
        return load_job(job_uuid, jobs_dir)
    except KeyError:
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


def list_jobs_with_state(jobs_dir: Path = None, *, strict: bool = False) -> list:
    """(JobConfig, JobState) for every VALID job — from ONE store read on a server install
    (audit #4: the state fields ride the same JOBS records the config parse already reads; the
    old per-job ``read_state`` re-fetch was an N+1 on the 10s notifications poll). Local mode
    reads the cheap sidecar files as before.

    ``strict=True`` asks the engine read to raise `JobReadUnavailable` rather than degrade an
    unreadable JOB table to an empty list — for a caller that paints the list and must not present
    a failed read as "there are none" (packet 1369). Opt-in: the poll/monitor callers keep the
    degraded render they were built for.
    """
    r = _repo()
    if r is not None:
        return [(cfg, state) for cfg, state in r.list_with_state(strict=strict) if cfg is not None]
    from corpusfm.server.jobs.state import read_state
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    return [(cfg, read_state(getattr(cfg, "id", "") or "", jobs_dir))
            for cfg, _err in list_jobs(jobs_dir) if cfg is not None]


def _overlay_by_reread(job_uuid: str) -> dict:
    """The credential/verification overlay for ONE job, by indexed re-read — the local dev/test path.

    Kept because the YAML enumeration has no `JSONOfRecord` to project from: on an unpublished tree
    the configs come from files while credential state still lives in the LocalBackend engine
    (`_jrepo()` is not install-mode gated). Projecting from jor is valid only when the enumeration
    itself came from the engine (packet 1368).
    """
    verified, reason = job_verify_state(job_uuid)
    return {"has_credential": has_job_credential(job_uuid), "account": job_account_name(job_uuid),
            "verified": verified, "verify_reason": reason}


def list_jobs_with_overlay(jobs_dir: Path = None, *, strict: bool = False) -> list:
    """(JobConfig, JobState, overlay) for every VALID job — the ONE derivation the Jobs surfaces use.

    ``overlay`` is ``{has_credential, account, verified, verify_reason}``. On a server install it is
    projected from the same `JSONOfRecord` the config and state already came from, so a file list no
    longer costs three indexed JOB re-reads per job. The secret never appears: only its presence
    flag, the display account and the verification verdict live in jor at all.

    A pure projection over the enumerated rows on purpose — a later read model can reuse the
    derivation instead of growing a second one.
    """
    r = _repo()
    if r is not None:
        return [(cfg, state, cred) for cfg, state, cred in r.list_with_overlay(strict=strict)
                if cfg is not None]
    return [(cfg, state, _overlay_by_reread(getattr(cfg, "id", "") or ""))
            for cfg, state in list_jobs_with_state(jobs_dir, strict=strict)]


def delete_job(job_uuid: str, jobs_dir: Path = None) -> bool:
    """Delete a job by its UUID, with its state sidecar. Returns True if it existed."""
    assert_job_work_permitted()
    r = _repo()
    if r is not None:
        return r.delete(job_uuid)
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    path = _job_path(job_uuid, jobs_dir)
    state_path = jobs_dir / f"{job_uuid}.state"
    existed = path.exists()
    if existed:
        path.unlink()
    if state_path.exists():
        state_path.unlink()
    return existed
