"""Job runner — executes one job run end-to-end.

Flow:
    1. Load and validate job config
    2. Load credentials (if FMS source — no-op for local_file)
    3. For each database in source.databases (or once for local_file):
       a. Pull XML bytes from source
       b. Parse XML → ParseResult
       c. Store to archive
       d. AI summaries (optional)
       e. Vector index (optional)
       f. Git export (optional)
    4. Record run in history and update state sidecar

Public API:
    run_job(job_uuid, jobs_dir, archive_dir, history_dir, trigger)
        -> RunRecord
"""

from __future__ import annotations

import dataclasses
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("corpusfm.server.jobs.runner")

from corpusfm.server.jobs.config import JobConfig, JobSource, effective_export_timeout_s
from corpusfm.server.jobs.history import RunRecord, default_history_dir, record_run
from corpusfm.server.jobs.sources import pull_source
from corpusfm.server.jobs.state import update_state
from corpusfm.server.jobs.store import default_jobs_dir, load_job, save_job
from corpusfm.server.jobs.validator import validate_job
from corpusfm.storage import get_backend
from corpusfm.app.app_config import load_app_config


def resolve_job_credentials(job: "JobConfig") -> dict:
    """The OData/pull credentials for a job (packet 1142 — extracted from ``run_job`` so the QUEUE
    ``acquire`` handler and the direct ``run_job`` path resolve them identically). A FileMaker job
    uses its per-job CredentialData; transport supplies only TLS posture. Unsupported pre-file jobs
    do not fall through to a named registry or environment group. Raises ``ValueError`` with a
    user-facing message when no usable credential is stored; returns ``{}`` for a source that needs
    none (local_file)."""
    if job.file:
        from corpusfm.server.jobs.store import get_job_credential
        c = get_job_credential(getattr(job, "id", "") or "")
        if not c or not c.get("account") or not c.get("password"):
            raise ValueError(f"No usable credential stored for job '{job.name}' — set it on the job")
        from corpusfm.server.fms_transport import for_server_ref
        transport = for_server_ref(job.source.server_ref)
        return {"username": c["account"], "password": c["password"],
                "verify_ssl": "true" if transport.verify_ssl else "false"}
    if job.source.type != "local_file":
        raise ValueError(
            f"Job {job.name!r} has no tracked file and is not supported by the current job model")
    return {}


def run_job(
    job_uuid: str,
    jobs_dir: Path = None,
    archive_dir: Path = None,
    history_dir: Path = None,
    trigger: str = "manual",
    on_stored=None,
    run_id: str = None,
) -> RunRecord:
    """Execute one job run synchronously, addressed BY UUID; returns a RunRecord (ok or error).

    Packet 086: this is the executor — in production the ``pull`` QUEUE worker calls it (the run is a
    ``[pull]`` laundry-list record; the single pull worker IS the mutual exclusion, so the old
    ``run_claim`` wait/takeover is gone). Tests + the pull handler call it directly. Triggers
    (scheduler / web / MCP) ENQUEUE a run record (``queue_handlers.enqueue_job_run``) rather than
    calling this inline.

    ``run_id`` (packet 1058 P0-A): the PRE-ALLOCATED run identity, threaded in by the pull worker from
    the ``[pull]`` record's payload so ONE authoritative id spans enqueue → runner → produced artifact
    → HISTORY (and, for a push, the trigger→POST→land close). Direct callers (tests, webhook, CLI) may
    omit it — one is minted here for compatibility; production enqueue paths always supply it.

    ``job_uuid`` (packet 1149): the job identity as the QUEUE row already knows it, so a run that fails
    BEFORE its config loads still writes a job-scoped HISTORY row. Without it such a run lands with a
    blank UUIDJob and is invisible to every job-scoped read — permanently, since MCP history is the only
    durable account of a failure once the queue row is cleared.

    ``on_stored(uuid)`` (packet 1002/B) is an optional hook the pull worker passes to ANCHOR the
    produced artifact on its QUEUE record right after the store commits — so a crash-recovery re-claim
    can detect 'this record already produced its artifact' and skip a duplicate snapshot."""
    if jobs_dir is None:
        jobs_dir = default_jobs_dir()
    if history_dir is None:
        history_dir = default_history_dir()
    backend = get_backend(archive_dir)

    start = datetime.now(timezone.utc)
    # THE EXECUTOR ITSELF TAKES THE GATE (packet 1372-02, R8). The QUEUE workers reach this through
    # a boot gate and the routes through their own, but `corpusfm jobs run` and the unlaunched
    # webhook call it DIRECTLY — so an unconverted corpus could still be made to pull a file and
    # write a STORAGE artifact while the box was meant to be paused. Gating the executor covers
    # every caller, including ones added later.
    from corpusfm.server.jobs.store import assert_job_work_permitted
    assert_job_work_permitted()

    log.info("job %s starting — trigger=%s", job_uuid, trigger)

    run_id = run_id or str(uuid.uuid4())
    return _run_job_body(
        job_uuid, jobs_dir, history_dir, trigger, backend, start, run_id,
        on_stored=on_stored,
    )


def _run_job_body(
    job_uuid: str,
    jobs_dir: Path,
    history_dir: Path,
    trigger: str,
    backend,
    start: datetime,
    run_id: str,
    on_stored=None,
) -> RunRecord:

    # Load config BY UUID. The caller's uuid is the run's identity whether or not the config loads,
    # so a failure is still attributable (packet 1149 — a run row without it is reachable only by
    # exact run_id, and so invisible on the Runs page, /api/alerts and the zero-diff alert forever).
    try:
        job = load_job(job_uuid, jobs_dir)
    except KeyError as exc:
        return _record_error(job_uuid, jobs_dir, history_dir, str(exc), start, trigger, backend,
                             run_id=run_id)

    # Validate
    errors = validate_job(job)
    if errors:
        msg = "Config invalid: " + "; ".join(errors)
        return _record_error(job_uuid, jobs_dir, history_dir, msg, start, trigger, backend,
                             run_id=run_id, job_name=job.name)

    # THE LAZY ID BACKFILL IS GONE (packet 1372-02). It assigned an id and re-saved with
    # `overwrite=False`, which both engines refused because the name was already present — a repair
    # that never once repaired anything, and whose failure was swallowed. A job now cannot exist
    # without an id: `save()` refuses one, and packet 1372-01 gave every existing record its own.

    # Mutual exclusion is the single pull QUEUE worker (packet 086 — run_claim retired): runs execute
    # one at a time by construction, so there is no per-file claim/wait/takeover here any more.

    # fms_push (packet 1015): mint a one-time token, enqueue the PENDING push QUEUE record, fire the
    # remote PostToServer trigger over OData, and return. FM POSTs the DDR back to /api/upload, which
    # resolves the pending record by the token and lands it (the land step closes the exact run).
    if job.source.type == "fms_push":
        return _run_fms_push_trigger(job, jobs_dir, history_dir, start, trigger, backend,
                                     run_id=run_id)

    # One file, one artifact per run (packet 086 / F5 file-centric). The pull target IS the job's
    # OWNER FILE (`job.file`) — there is no stored database list. `job.source.databases` is a derived
    # runtime carrier (= [job.file], set on load); a job can't run against a file it doesn't own.
    # (local_file reads a filesystem path and has no hosted owner.)
    if job.source.type == "local_file":
        source_list = [job.source]
    else:
        target = job.file or (job.source.databases or [None])[0]
        if not target:
            return _record_error(
                job_uuid, jobs_dir, history_dir,
                "This job has no owner file — it can't pull a hosted database.",
                start, trigger, backend, run_id=run_id, job_name=job.name,
            )
        source_list = [dataclasses.replace(job.source, databases=[target])]

    # Per-job credential (packet 085 U3b / 1142): resolved by the shared helper the QUEUE acquire step
    # also uses. "The security price of making a job is knowing the credentials."
    try:
        credentials = resolve_job_credentials(job)
    except ValueError as exc:
        return _record_error(
            job_uuid, jobs_dir, history_dir, str(exc), start, trigger, backend,
            run_id=run_id, job_name=job.name,
        )
    except Exception as exc:
        return _record_error(
            job_uuid, jobs_dir, history_dir, f"Credential load failed: {exc}", start, trigger, backend,
            run_id=run_id, job_name=job.name,
        )

    all_metas = []
    all_git_commits: list[str] = []
    pull_errors: list[str] = []

    _app_cfg = load_app_config()
    _keep_source_xml = _app_cfg.keep_source_xml

    for single_source in source_list:
        db_label = (single_source.databases or [None])[0] or job.name

        # Pull XML
        try:
            xml_bytes = pull_source(
                single_source, credentials,
                timeout=effective_export_timeout_s(job.source),
            )
        except (NotImplementedError, FileNotFoundError, ValueError, OSError) as exc:
            pull_errors.append(f"{db_label}: {exc}")
            continue
        except Exception as exc:
            pull_errors.append(f"{db_label}: Source pull failed: {exc}")
            continue

        # Ingest → Artifact and store
        try:
            from corpusfm.ingestion.pipeline import ingest
            from corpusfm.core.filenames import primary_name_from_filename
            artifact = ingest(xml_bytes, db_label, source_type="job")
            # Naming doctrine: the PRIMARY name is the FMS file's name, suffix dropped.
            meta = backend.store_artifact(
                artifact, xml_bytes=xml_bytes, label=primary_name_from_filename(db_label),
                origin="Job", job_uuid=job.id, run_uuid=run_id, keep_source_xml=_keep_source_xml,
            )
            all_metas.append(meta)
            # Anchor the produced artifact on the caller's QUEUE record BEFORE the downstream
            # tags/latest/git work (packet 1002/B) — the earliest the uuid exists, so a crash after
            # the commit still leaves the record able to skip a re-pull instead of duplicating.
            if on_stored is not None and getattr(meta, "uuid", ""):
                try:
                    on_stored(meta.uuid)
                except Exception:
                    log.debug("on_stored anchor hook failed for '%s'", db_label, exc_info=True)
            log.debug("Artifact stored for %s/%s", meta.rel_path, db_label)
            if hasattr(backend, "archive_dir"):
                try:
                    from corpusfm.tools.discovery_log import append_discovery
                    append_discovery(artifact, backend.archive_dir / "discovery.jsonl")
                except Exception:
                    pass
            # Tag v2 (FM backend only; never fails the job): copy the prior version's USER tags
            # forward + union the JOB's configured artifact tags (packet 085 U3b: per-file
            # propagation tags moved onto the job). System tags (type:/origin:/fm:) are computed
            # at read time, not stamped (packet 085 U3e).
            try:
                from corpusfm.server import tags_store
                if tags_store.tables_available(backend):
                    applied = tags_store.copy_forward_on_run(
                        backend, job_uuid=job.id,
                        new_timestamp=getattr(meta, "timestamp", ""),
                        job_tags=list(job.tags or []),
                    )
                    if applied:
                        log.debug("Tags applied to %s/%s: %s", db_label, meta.timestamp, applied)
            except Exception:
                log.debug("tag tagging failed for '%s'", db_label, exc_info=True)
            # Latest-version flag: demote the prior version in this job's lineage (job_uuid alone,
            # packet 086 / Ruling A). The just-stored record is already IsLatest=true.
            try:
                from corpusfm.server import latest as _latest
                if _latest.latest_available(backend):
                    _latest.mark_latest_on_store(
                        backend, job_uuid=job.id,
                        new_uuid=getattr(meta, "uuid", "") or "")
            except Exception:
                log.debug("latest-flag update failed for '%s'", db_label, exc_info=True)
        except Exception as exc:
            pull_errors.append(f"{db_label}: Ingest/store failed: {exc}")
            continue

        # Enrichment (AI summaries + vector index) now funnels through the server queue (packet 052)
        # like every other enrichment path — so a scheduled summarize shows on the Queue page and runs
        # one-at-a-time with the rest, instead of inline here (10–30 min would otherwise block the run).
        # Owner = job:<name>. The run completes on pull→store; enrichment drains afterward.
        if artifact is not None and getattr(meta, "uuid", None):
            try:
                from corpusfm.server import enrichment, queue_handlers
                from corpusfm.storage.queue_record import INDEX, SUMMARIZE
                owner = f"job:{getattr(job, 'name', '') or 'scheduled'}"
                do_summarize = job.process.summarize_on_ingest and enrichment.provider_ready()
                do_index = job.process.index_on_ingest and enrichment.embedder_ready()
                steps = [SUMMARIZE if do_summarize else None, INDEX if do_index else None]
                if any(steps):
                    queue_handlers.enqueue_enrichment_steps(backend, meta.uuid, steps, owner=owner)
            except Exception:
                log.debug("Enqueue enrichment failed for '%s'", db_label, exc_info=True)

        # Artifact retention limit (optional — errors never fail the job). Prunes through the full
        # delete cascade (deindex + history + cache-bust + repromote), never a raw backend delete
        # (packet 1054).
        if job.process.enable_artifact_limit and job.process.max_artifacts > 0:
            try:
                from corpusfm.server.artifact_delete import prune_job_artifacts
                pruned = prune_job_artifacts(backend, job.id, job.process.max_artifacts)
                if pruned:
                    log.debug("Pruned %d artifact(s) for job '%s' (limit=%d)", pruned, job.name, job.process.max_artifacts)
            except Exception:
                log.debug("Artifact pruning failed for job '%s'", job.name, exc_info=True)

        # Git export (optional — errors here do not fail the job). The job's repo overrides
        # each registration's default (a deploy-key credential ignores it — bound repo). Each
        # produced artifact is STAMPED with its job's credential selection, then owns it
        # independently (git_targets, keyed by the record UUID — stored on the record's own jor).
        if job.process and job.process.git_export and job.process.git_export.registrations:
            from corpusfm.core.git_formatter import export_artifact_to_registration
            _job_repo = getattr(job.process.git_export, "repo", "") or ""
            _job_modes = getattr(job.process.git_export, "modes", None) or None
            if artifact is not None:
                for reg_name in job.process.git_export.registrations:
                    try:
                        er = export_artifact_to_registration(
                            artifact, reg_name,
                            repo=_job_repo, push=True, modes=_job_modes,
                        )
                        tag = er.commit_sha[:8] if er.commit_sha else "no-change"
                        if er.push_ok is False:
                            tag += f" (push failed: {er.push_msg})"
                        all_git_commits.append(tag)
                    except Exception as exc:
                        all_git_commits.append(f"ERROR:{exc}")
                # Stamp the artifact's own git target from the job's selection (first registration).
                try:
                    from corpusfm.server import git_targets
                    git_targets.set_target(
                        meta.uuid, job.process.git_export.registrations[0], _job_repo)
                except Exception:
                    log.debug("git-target stamp failed for '%s'", db_label, exc_info=True)

    if not all_metas:
        msg = "; ".join(pull_errors) or "All database pulls failed"
        return _record_error(job_uuid, jobs_dir, history_dir, msg, start, trigger, backend,
                             run_id=run_id, job_name=job.name)

    end = datetime.now(timezone.utc)
    duration = round((end - start).total_seconds(), 2)

    last_meta = all_metas[-1]
    run = RunRecord(
        ts=end.isoformat(timespec="seconds"),
        status="ok",
        trigger=trigger,
        duration_s=duration,
        archive_path=last_meta.uuid,   # the run's produced-artifact address (packet 085 U3f: record UUID)
        git_commits=all_git_commits if all_git_commits else None,
        run_id=run_id,
        job_uuid=job.id,
    )
    log.info("job '%s' (%s) completed in %.1fs (%d database(s))", job.name, job_uuid, duration,
             len(all_metas))
    _record_run(job_uuid, jobs_dir, history_dir, run, backend)
    return run


def _run_fms_push_trigger(
    job: JobConfig,
    jobs_dir: "Path",
    history_dir: "Path",
    start: "datetime",
    trigger: str,
    backend=None,
    run_id: str = None,
) -> "RunRecord":
    """Fire an fms_push run from a DIRECT ``run_job`` caller (CLI / webhook) by ENQUEUEING the unified
    ``[acquire, ingest, …]`` QUEUE record (packet 1142 — the run IS the acquire). The trigger is no
    longer fired here: the acquire worker mints the one-time token, stamps its hash on the record, fires
    ``PostToServer``, blocks, reads the verdict, and (on ``ok``) advances to ingest — which writes the
    closing RunRecord. This function just enqueues and returns a ``triggered`` in-memory record; the
    queue owns the run's real outcome. (The scheduler / web / MCP triggers call ``enqueue_job_run``
    directly and never reach here.)"""
    from corpusfm.server import queue_handlers

    job_name = job.name                    # display label for the log lines below
    _je = job.id or ""   # this job's uuid — carried onto every early-error RunRecord (packet 1058)
    file_name = job.file or (job.source.databases or [None])[0] or ""
    if not file_name:
        return _record_error(_je, jobs_dir, history_dir,
                             "This fms_push job has no owner file to pull.", start, trigger, backend,
                             run_id=run_id, job_name=job_name)
    try:
        queue_handlers.enqueue_job_run(backend, job_name=job_name, job_uuid=_je,
                                       file_name=file_name, trigger=trigger, run_id=run_id or "")
    except Exception as exc:
        return _record_error(_je, jobs_dir, history_dir,
                             f"fms_push: could not enqueue the run: {exc}",
                             start, trigger, backend, run_id=run_id, job_name=job_name)

    end = datetime.now(timezone.utc)
    run = RunRecord(
        ts=end.isoformat(timespec="seconds"),
        status="triggered",
        trigger=trigger,
        duration_s=round((end - start).total_seconds(), 2),
        run_id=run_id or None,
        job_uuid=_je or None,
    )
    log.info("job '%s' fms_push enqueued as a unified acquire run; the acquire worker fires the trigger",
             job_name)
    return run


def _record_error(
    job_uuid: str,
    jobs_dir: Path,
    history_dir: Path,
    message: str,
    start: datetime,
    trigger: str,
    backend=None,
    run_id: str = None,
    job_name: str = "",
) -> RunRecord:
    """An error RunRecord, scoped by the job's UUID.

    `job_name` is the DISPLAY label and is optional: a run that fails before its config loads has no
    name to show, and stamping the uuid there instead would put an identity in a field readers treat
    as prose. Empty is the honest answer; the run is still findable, because it is found by uuid.
    """
    log.error("job %s failed: %s", job_uuid, message)
    end = datetime.now(timezone.utc)
    duration = round((end - start).total_seconds(), 2)
    # Carry the run identity + job uuid onto the error RunRecord (packet 1058 P0-A) so a failed run is
    # queryable by exact run_id — and so a Restart's later success overwrites this row in place rather
    # than being masked by it (record_run upserts by run_id).
    run = RunRecord(
        ts=end.isoformat(timespec="seconds"),
        status="error",
        trigger=trigger,
        duration_s=duration,
        error=message,
        run_id=run_id or None,
        job_uuid=job_uuid or None,
        job_name=job_name or "",
    )
    _record_run(job_uuid or "", jobs_dir, history_dir, run, backend)
    return run


def _record_run(
    job_uuid: str,
    jobs_dir: Path,
    history_dir: Path,
    run: RunRecord,
    backend=None,
) -> None:
    # HISTORY Type=Run is the single system of record for run outcomes on both backends
    # (085 U3c — no FM-RUNS/JSONL dual path). record_run is best-effort; a run that fails
    # *because* FM is down can't record (accepted loss).
    # Freeze the label (packet 1149): every run row carries the job's name AS AT RUN TIME, so no read
    # surface has to borrow it from live config. This is the single chokepoint every runner-side writer
    # passes through, which is why it is stamped here rather than at each construction site.
    if not getattr(run, "job_uuid", None):
        run.job_uuid = job_uuid or None
    if backend is not None:
        record_run(backend, run)
    # The JOB record's "last run" summary, addressed BY UUID (packet 1372-02). It was addressed by
    # name, so a run belonging to one of two same-named jobs updated whichever the lookup found —
    # and a deleted job's run silently updated a survivor that happened to share its label.
    try:
        update_state(job_uuid, run, jobs_dir)
    except Exception:
        pass
