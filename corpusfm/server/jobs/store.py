"""Job storage — UUID-addressed, ENGINE-BACKED, and nothing else (packet 1372-02 / 1361-01).

A job is identified by its UUID and by nothing else. Names are editable labels that may collide,
including by case; no operation here resolves a job from one. The store is the JOB table keyed by
that UUID, over whichever engine the live backend exposes — FileMaker OData on a server install, the
SQLite mirror in development.

**The `<job_uuid>.yaml` file store is REMOVED (packet 1361-01).** It was the storage half of a job
model the product does not support: filesystem-selected jobs, archives and history, executed
directly. CORPUSfm's Jobs pull XML from HOSTED FileMaker files, store artifacts internally, and may
export to GitHub — none of which a directory of YAML files is part of. Keeping it as a "dev path"
meant development exercised a store production never uses, and the fallback could silently take a
misconfigured box with it. Development now uses the same engine-backed JOB table through the SQLite
mirror. There is no compatibility path and no migration: the model is unsupported, not deprecated.

Public API:
    save_job(cfg, overwrite)                    # creates at cfg.id; refuses a missing/invalid id
    load_job(job_uuid) -> JobConfig
    find_job_by_id(job_uuid)                    # O(1) — a direct key read
    list_jobs() -> list[tuple[JobConfig | None, str | None]]
    delete_job(job_uuid) -> bool
    generate_token() -> str
    assert_job_work_permitted()                 # the ProjectionVersion 2 gate
"""

from __future__ import annotations

import re
import secrets
from typing import Optional

from corpusfm.server.jobs.config import JobConfig

TOKEN_BYTES = 16  # 32 hex chars


class JobsStoreUnavailable(RuntimeError):
    """Jobs cannot be served, for a reason CORPUSfm itself states in product prose.

    Typed so a caller can tell it apart from a third-party failure and show it verbatim: the message
    is ours, an administrator can act on it, and it carries no response body, URL or credential
    (packet 1369).
    """


def _repo(backend=None):
    """The JobsRepo over a backend's engine. NEVER None — there is no second store.

    ``backend`` lets a caller that already holds one supply it (packet 1361-01), instead of this
    resolving a fresh one through the global `get_backend()`.

    The install-mode gate that used to sit here existed to choose between the JOB table and a
    directory of YAML files. With the file store removed (packet 1361-01) there is nothing to choose:
    every install and every development tree reads and writes the same JOB table, so the only failure
    left is a backend that exposes no engine at all, which is a refusal rather than a fallback.

    The published-but-uncomposed check survives, because it says something the engine cannot: an
    installation that has published authority but composed no corpus must refuse Jobs rather than
    serve them from somewhere else (packet 1246-08 §11.2 row 5).
    """
    from corpusfm.lifecycle import runtime_storage

    try:
        active = runtime_storage.fm_storage_active()
    except Exception:
        active = None
    if active is False:
        raise JobsStoreUnavailable(
            "this installation is published but has composed no corpus; refusing to serve Jobs "
            "while its storage authority is incomplete.")
    from corpusfm.storage.repos import jobs_repo
    if backend is None:
        from corpusfm.storage import get_backend
        backend = get_backend()
    r = jobs_repo(backend)
    if r is None:
        raise JobsStoreUnavailable(
            "the active storage backend exposes no engine, so the JOB table cannot be read.")
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


def generate_token() -> str:
    """Generate a secure random webhook token."""
    return secrets.token_hex(TOKEN_BYTES)


# `_safe_name` is RETIRED (packet 1372-02). It existed to turn a user-chosen name into a filename,
# which is the local half of the identity defect this cutover removes: two jobs whose names differed
# only by case shared one file, and renaming a job orphaned its state sidecar. Local files are now
# named by the job's UUID, with the name inside the document where it belongs.
# There is nothing left to convert: the local file store itself is gone (packet 1361-01), and with
# it `corpusfm migrate job-identity --jobs-dir`.


def save_job(cfg: JobConfig, overwrite: bool = False) -> None:
    """Write a job config AT ITS OWN ID into the JOB table. Raises if the id is missing or present."""
    assert_job_work_permitted()
    _repo().save(cfg, overwrite=overwrite)


def load_job(job_uuid: str) -> JobConfig:
    """Load a job by its UUID. Raises KeyError if not found."""
    return _repo().load(job_uuid)


def find_job_by_id(job_uuid: str) -> Optional[JobConfig]:
    """A job by its UUID, or None. O(1) — a direct key read, not a scan."""
    if not job_uuid:
        return None
    try:
        return load_job(job_uuid)
    except KeyError:
        return None


def list_jobs() -> list[tuple[Optional[JobConfig], Optional[str]]]:
    """Every job as (JobConfig | None, error_str | None) pairs, sorted by name.

    Invalid records are included with config=None and an error string.
    """
    return _repo().list()


def list_jobs_with_state(*, strict: bool = False, backend=None) -> list:
    """(JobConfig, JobState) for every VALID job — from ONE store read.

    The state fields ride the same JOB records the config parse already reads, so this costs one
    enumeration rather than the per-job ``read_state`` re-fetch it replaced (an N+1 on the 10s
    notifications poll).

    ``strict=True`` asks the read to raise `JobReadUnavailable` rather than degrade an unreadable JOB
    table to an empty list — for a caller that paints the list and must not present a failed read as
    "there are none" (packet 1369). Opt-in: the poll/monitor callers keep the degraded render they
    were built for.
    """
    return [(cfg, state) for cfg, state in _repo(backend).list_with_state(strict=strict)
            if cfg is not None]


def list_jobs_with_overlay(*, strict: bool = False) -> list:
    """(JobConfig, JobState, overlay) for every VALID job — the ONE derivation the Jobs surfaces use.

    ``overlay`` is ``{has_credential, account, verified, verify_reason}``, projected from the same
    ``JSONOfRecord`` the config and state already came from, so a job list costs no extra indexed
    re-reads. The secret never appears: only its presence flag, the display account and the
    verification verdict live in jor at all.
    """
    return [(cfg, state, cred) for cfg, state, cred in _repo().list_with_overlay(strict=strict)
            if cfg is not None]


def delete_job(job_uuid: str) -> bool:
    """Delete a job by its UUID. Returns True if it existed."""
    assert_job_work_permitted()
    return _repo().delete(job_uuid)
