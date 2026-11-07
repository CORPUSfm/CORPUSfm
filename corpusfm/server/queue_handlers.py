"""Producer step handlers + enqueue helpers for the QUEUE workspace (packet 086 brick 4).

The framework (``queue_workers``) claims records and dispatches by ``Type``; this module holds the
handlers that DO each step and the enqueue helpers the producers call. Everything routes through the
queue — nothing enriches or lands off-queue.

Every Job Run is ONE unified record (packet 1142 — the run IS the acquire):
- **job run** — a self-initiated ``[acquire, ingest, git_export?, summarize?, index?]`` record. The
  ``acquire`` step makes the blocking FM export call (push: PostToServer + a mid-call POST to
  ``/api/upload`` that deposits into this same record, resolved by its one-time token hash; else:
  ``pull_source`` returns the bytes), stages the source, and advances to ``ingest`` — which stores the
  artifact and writes the run's closing RunRecord (:func:`_close_run_record`). ``git_export`` /
  ``summarize`` / ``index`` are their own downstream compartments. This replaces BOTH the old
  single-stop ``[pull]`` record and the push's second ``[upload, land, …]`` record — one row per run.
- **import** — a client-driven ``[upload, ingest, summarize?, index?]`` record: the browser stores the
  source (the ``upload`` step, no worker), the server advances ``upload``→``ingest``, the ``ingest``
  handler runs the shared 077-E landing (``ingest_import_bytes`` → ``land_artifact``), then the record
  walks its enrichment tail. Enrichment steps are baked into the list at enqueue only when opted-in AND
  configured, so a step never parks for a provider the user never asked for.
- **enrichment** — ``summarize`` / ``index`` steps (``deindex`` folds into ``index`` via a Payload op
  flag). SEPARATE workers drain them (packet 1170 — the slow LLM summary lane must not block fast
  indexing); each step does ONE artifact and parks on failure (try-once).

``register_all()`` wires the handlers into the framework at boot.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid as _uuidlib
from datetime import datetime, timezone

from corpusfm.core.filenames import primary_name_from_filename
from corpusfm.server import enrichment
from corpusfm.server import queue_workers as W
from corpusfm.storage import queue_record as Q

log = logging.getLogger("corpusfm.queue_handlers")


def _repo(backend):
    from corpusfm.storage.repos import queue_repo
    repo = queue_repo(backend)
    if repo is None:
        raise RuntimeError("no storage engine — cannot use the QUEUE workspace")
    return repo


# ── import: enqueue (the client-performed upload) ────────────────────────────────

def enqueue_import(backend, raw: bytes, *, filename: str, name: str = "", locale: str = "",
                   summarize: bool = False, index: bool = False, owner: str = "",
                   origin: str = "", keep_source_xml: bool = False) -> str:
    """Stage one import as a QUEUE ``[upload, land, summarize?, index?]`` record: create the record
    (``Type=upload``), store the source bytes into its ``SourceXML`` container (the client-performed
    upload), then advance ``upload``→``land``. Enrichment steps are appended only when the opt-in AND
    the provider are both present. Returns the record UUID. Blocking (FM POST + blob) — call off the
    event loop.

    ``origin`` (packet 1167/1169) is the ingesting CHANNEL carried in the payload for the ingest handler
    to stamp on the landed record: a human web import leaves it empty (the handler defaults to
    ``"WebUI"``); an AI import passes ``"MCP"``. It is NOT the artifact ``owner`` — that is a separate
    param (identity vs provenance)."""
    from corpusfm.core.crypto import compress, encode_blob
    repo = _repo(backend)
    summarize_ok = bool(summarize) and enrichment.provider_ready()
    index_ok = bool(index) and enrichment.embedder_ready()
    steps = [Q.UPLOAD, Q.INGEST,
             Q.SUMMARIZE if summarize_ok else None,
             Q.INDEX if index_ok else None]        # build() drops the falsy entries
    payload = {"filename": filename or "import", "name": name or "", "locale": locale or "",
               "origin": origin or "", "keep_source_xml": bool(keep_source_xml)}
    qid = repo.enqueue(steps, payload=payload, owner=owner or "")
    backend.engine.blob_put("QUEUE", qid, "SourceXML",
                            encode_blob(compress(raw), encrypt_on=backend._encrypt_blobs()))
    repo.advance_or_delete(qid)     # upload → ingest (single POST = the final bytes)
    return qid


# ── enrichment: enqueue helpers (catalog UI / MCP / jobs) ────────────────────────

def _in_flight(repo, step_type: str, uuid: str) -> bool:
    """A non-failed record already sitting on ``step_type`` for this target — a light per-(type,target)
    dedup so a double-click / re-request doesn't stack redundant multi-minute work. (The rare
    import-tail race — a fresh Index while the import is still landing — is idempotent upsert, so it's
    left uncaught.)"""
    if any(r.jor.get("UUIDStorage", "") == uuid for r in repo.list_by_type(step_type)):
        return True
    # A live record that still plans this step for the target, such as a re-ingest's later stages.
    for r in repo.list_all():
        steps = r.jor.get("Steps") or []
        cursor = r.jor.get("Type", "")
        if (r.jor.get("UUIDStorage", "") == uuid and not Q.is_failed(r.jor) and cursor in steps
                and step_type in steps[steps.index(cursor) + 1:]):
            return True
    return False


def enqueue_enrichment_steps(backend, uuid: str, steps, *, owner: str = "") -> str:
    """Enqueue ONE enrichment record ``[summarize?, index?]`` for an existing artifact (target =
    ``UUIDStorage``). Deduped on the entry step; returns the record UUID, or ``""`` if deduped/empty.
    Blocking (FM read + write) — call off the event loop."""
    steps = [s for s in (steps or []) if s]
    if not steps:
        return ""
    repo = _repo(backend)
    if _in_flight(repo, steps[0], uuid):
        return ""
    qid = repo.enqueue(steps, owner=owner or "", uuid_storage=uuid)
    W.poke(steps[0])
    return qid


#: The explicit Job Run discriminator (packet 1372-02, R4). Four paths used to ask "does this row's
#: payload carry a `job_name`?", which made a DISPLAY LABEL load-bearing control flow: a job whose
#: name was somehow blank stopped being a Job Run. `kind` says what the row is; the name is a frozen
#: snapshot from the moment it was enqueued.
JOB_RUN = "job_run"


def is_job_run(row_or_payload) -> bool:
    """True for a Job Run row.

    Two signals, never a name. `kind` is what everything enqueued from now on carries. The second
    covers a row that was ALREADY on the queue when the update landed — it has a `UUIDJob` (every
    Job Run has carried one since packet 1142) **and** a `Payload.job_name` (every Job Run has
    carried that too).

    **Both halves are required, deliberately.** "A non-blank `UUIDJob` means Job Run" on its own is
    an implicit discriminator of exactly the kind this packet exists to delete: today
    `enqueue_job_run` is the only caller that sets `uuid_job=`, but nothing enforces that, and a
    future job-scoped deindex or enrichment row would then have its tags copied forward, a
    fabricated closing `ok` RunRecord written, and its artifacts pruned for something that never ran.
    Requiring the legacy shape's OTHER field costs nothing and keeps the accident out.
    """
    jor = getattr(row_or_payload, "jor", None)
    if jor is not None:
        payload = jor.get("Payload", {}) or {}
        if (jor.get("UUIDJob") or "").strip() and (payload.get("job_name") or "").strip():
            return True
    else:
        payload = row_or_payload or {}
    return (payload or {}).get("kind") == JOB_RUN


def enqueue_job_run(backend, *, job_name: str, job_uuid: str = "", file_name: str = "",
                    trigger: str = "manual", run_id: str = "") -> "tuple[str, str]":
    """Enqueue a Job Run as ONE unified QUEUE record (packet 1142 — the run IS the acquire): a
    ``[acquire, ingest, git_export?, summarize?, index?]`` laundry list. The acquire worker fires the
    blocking FM export script (push: PostToServer + /api/upload deposit; else: pull_source), stages the
    source, and advances to ``ingest`` — which stores the artifact + writes the run's HISTORY record.
    The enrichment/git tail is baked per readiness + the job's config, so a step never parks for work
    the job never asked for. Replaces the old single-stop ``[pull]`` record AND the push's second
    ``[upload, land, …]`` record — one row per run.

    No dedup here — the caller decides (the scheduler skips a fire while a run is in-flight; a manual run
    always enqueues). Packet 1058 P0-A: the run identity is PRE-ALLOCATED here and rides the payload
    (``Payload.run_id``) so one authoritative id spans enqueue → acquire → ingest → produced artifact →
    HISTORY. Returns ``(queue_record_uuid, run_id)``. ``UUIDJob`` carries the job identity so 'is this
    job running?' is an indexed read AND every step resolves its own job by uuid (packet 1142 §F₀);
    ``job_name`` rides the payload as a FROZEN display label; ``file_name`` rides it for the Jobs-page
    running badge.

    **`UUIDJob` IS MANDATORY (packet 1372-02, R4).** A Job Run with no job identity is unrunnable by
    UUID-only code and, worse, is exactly the record the identity conversion refuses to attribute —
    so one enqueued now would block the next startup. It is refused here, before the write, rather
    than discovered later. `Payload.kind` is the explicit discriminator that replaces "does this row
    have a `job_name`?"; the name is a frozen label from this point on."""
    repo = _repo(backend)
    run_id = run_id or str(_uuidlib.uuid4())
    job_uuid = (job_uuid or "").strip()
    if not job_uuid:
        raise ValueError(
            "a Job Run must carry the UUID of the job it runs; refusing to enqueue an "
            "unattributable run.")
    # Resolve the job to decide the enrichment/git tail (baked at enqueue, per readiness + config —
    # mirroring enqueue_import). BY UUID ONLY: the name is not identity and may collide.
    job = None
    try:
        from corpusfm.server.jobs.store import find_job_by_id
        job = find_job_by_id(job_uuid)
    except Exception:
        job = None
    summarize_ok = bool(getattr(getattr(job, "process", None), "summarize_on_ingest", True)) \
        and enrichment.provider_ready()
    ge = getattr(getattr(job, "process", None), "git_export", None) if job else None
    git_ok = bool(ge and ge.registrations)
    index_ok = bool(getattr(getattr(job, "process", None), "index_on_ingest", False)) \
        and enrichment.embedder_ready()
    steps = [Q.ACQUIRE, Q.INGEST,
             Q.GIT_EXPORT if git_ok else None,
             Q.SUMMARIZE if summarize_ok else None,
             Q.INDEX if index_ok else None]        # build() drops the falsy entries
    # The ingest step routes by FILENAME EXTENSION (ingest_import_bytes) — a job run ALWAYS delivers
    # SaveAsXML, so the record's filename must end in .xml or ingest rejects it as "unsupported file
    # type". The real artifact name is still derived from the XML's own File= attribute (routing-only).
    _fn = file_name or job_name or "run"
    ingest_filename = _fn if _fn.lower().endswith(".xml") else f"{_fn}.xml"
    qid = repo.enqueue(steps,
                       payload={"kind": JOB_RUN, "job_name": job_name, "trigger": trigger,
                                "file_name": file_name or "", "run_id": run_id,
                                "filename": ingest_filename},
                       owner=f"job:{job_name}", uuid_job=job_uuid or "")
    W.poke(Q.ACQUIRE)
    return qid, run_id


def find_run_in_queue(backend, run_id: str):
    """The live QUEUE row for a pre-allocated ``run_id`` (packet 1058 P0-B), or ``None``. The active
    phase of ``get_job_run``: the run's unified ``[acquire, ingest, …]`` record still exists while the
    run is queued/running/failed, keyed in its payload by ``run_id``. A scan of the SMALL live queue
    rather than a projected column — chosen because the live queue is small, NOT because the substrate
    forbids the column: projection slots are ours to change (``fm_registry.SLOTS``) and cost no FM file
    edit. Returns the first match (run ids are unique)."""
    if not run_id:
        return None
    repo = _repo_or_none(backend)
    if repo is None:
        return None
    for row in repo.list_all():
        if (row.jor.get("Payload", {}) or {}).get("run_id") == run_id:
            return row
    return None


def _resolve_run_job(row):
    """Resolve the JobConfig behind a run record BY UUID, and only by UUID (packet 1372-02).

    The name fallback is gone. It could only ever fire for a row with no `UUIDJob` — which
    `enqueue_job_run` now refuses to create — and it resolved a job from a label that may legitimately
    belong to several. Returns the JobConfig, or None when the job no longer exists.
    """
    uuid = row.jor.get("UUIDJob", "") or ""
    if not uuid:
        return None
    try:
        from corpusfm.server.jobs.store import find_job_by_id
        return find_job_by_id(uuid)
    except Exception:
        return None


def _source_server(job, host: str) -> dict:
    """The FileMaker server one acquire attempt contacts, as frozen non-secret facts (packet 1438).

    ``host`` is the address the attempt ACTUALLY uses — a pull reads the host saved on its job, a
    push the live SERVER/co-located transport — so it is passed in, never re-derived from the ref.
    ``name`` is the SERVER record's name as it is now, or "" when that record is gone; it is never
    guessed. ``ref`` keeps two servers that share a name (after a rename) distinguishable."""
    import re
    ref = (getattr(job.source, "server_ref", None) or "").strip() or "local"
    name = "Local"
    if ref != "local":
        try:
            from corpusfm.server import remote_servers
            srv = remote_servers.get_server_by_id(ref)
        except Exception:
            srv = None
        name = getattr(srv, "name", "") or ""
    return {"ref": ref, "name": name,
            "host": re.sub(r"^https?://", "", (host or "").strip()).rstrip("/")}


def _pull_host(job) -> str:
    """The host a pull method contacts. ``fms_local`` drives the local fmsadmin CLI, so its host is the
    co-located transport; the OData pulls use the host saved on the job's source."""
    if (job.source.type or "").strip() == "fms_local":
        try:
            from corpusfm.server.fms_transport import colocated
            return colocated().host
        except Exception:
            return ""
    return job.source.server or ""


def _record_run_error(row, message: str, source_server: "dict | None" = None) -> None:
    """Write an ``error`` RunRecord to HISTORY for a failed Job Run step (packet 1142 — parity with the
    old ``runner._record_error``: a failed acquire must still show on the Runs page and resolve via
    ``get_job_run`` after the queue row is cleared). Keyed by ``run_id``, so a later Restart's success
    overwrites this error in place. Best-effort — never blocks the step's own failure."""
    p = row.jor.get("Payload", {}) or {}
    if not is_job_run(row):
        return
    try:
        from datetime import datetime, timezone
        from corpusfm.storage import get_backend
        from corpusfm.server.jobs.history import RunRecord
        from corpusfm.server.jobs.runner import _record_run
        now = datetime.now(timezone.utc)
        created = row.jor.get("created_at") or ""
        dur = 0.0
        if created:
            try:
                dur = round((now - datetime.fromisoformat(created)).total_seconds(), 2)
            except Exception:
                dur = 0.0
        run = RunRecord(
            ts=now.isoformat(timespec="seconds"), status="error",
            trigger=p.get("trigger") or "schedule", duration_s=max(0.0, dur), error=message,
            run_id=p.get("run_id") or None, job_uuid=row.jor.get("UUIDJob", "") or None,
            job_name=p.get("job_name") or "", source_server=source_server or None)
        _record_run(row.jor.get("UUIDJob", "") or "", run, get_backend())
    except Exception:
        log.debug("acquire: error run-record write failed", exc_info=True)


def git_export_handler(repo, row) -> W.StepResult:
    """Git-export one LANDED run artifact to its Job's configured registrations, and VERIFY it completed
    (packet 1142 §F₁ — the model: a step advances only when its outcome is real). The old handler
    returned ``W.ok()`` on THREE unverified absences (job unresolvable, artifact unloadable, a
    per-registration failure), so a deleted job / a read blip / a failed export all read as 'no git
    work'. Now distinguished:
      - job resolvable, NO registrations → a genuine no-op, ``W.ok()``;
      - job UNRESOLVABLE → ``W.fail`` (an unanswered question, not 'nothing to do');
      - artifact unloadable → ``W.fail`` (cannot confirm the export);
      - a registration that did not export (raised, or its push failed) → ``W.fail`` (the outcome was
        not achieved) — Restartable, rather than logged-and-continued."""
    from corpusfm.storage import get_backend
    be = get_backend()
    uuid = row.jor.get("UUIDStorage", "")
    if not uuid:
        return W.fail("git_export target missing (ingest did not anchor an artifact).")
    job = _resolve_run_job(row)
    if job is None:
        return W.fail("git_export: the job could not be resolved by uuid — cannot confirm its git "
                      "targets (it may have been deleted mid-run).")
    ge = getattr(getattr(job, "process", None), "git_export", None)
    if not ge or not ge.registrations:
        return W.ok()   # genuinely no git work — the ONLY W.ok()-on-absence that is honest
    try:
        artifact = be.load_artifact(uuid)
    except Exception as exc:
        return W.fail(f"git_export: could not load the landed artifact {uuid} to export it: {exc}")
    from corpusfm.core.git_formatter import export_artifact_to_registration
    from corpusfm.server import git_targets
    job_repo = getattr(ge, "repo", "") or ""
    job_modes = getattr(ge, "modes", None) or None
    failures: list[str] = []
    for reg_name in ge.registrations:
        try:
            er = export_artifact_to_registration(artifact, reg_name, repo=job_repo, push=True,
                                                 modes=job_modes)
            W.note_progress()
            if getattr(er, "push_ok", None) is False:
                failures.append(f"{reg_name}: push failed ({getattr(er, 'push_msg', '') or 'unknown'})")
        except Exception as exc:
            failures.append(f"{reg_name}: {exc}")
    if failures:
        return W.fail("git_export did not complete for: " + "; ".join(failures))
    try:
        git_targets.set_target(uuid, ge.registrations[0], job_repo)
    except Exception:
        log.debug("git_export: git-target stamp failed for %s", uuid, exc_info=True)
    return W.ok()


# ── acquire: the run IS the blocking FM export call (packet 1142) ────────────────────

def acquire_handler(repo, row) -> W.StepResult:
    """The self-initiated first step of a Job Run — the run IS the acquire. Resolve the job BY UUID,
    set the worker's no-progress deadline from the job's effective export bound (§H), then make the ONE
    blocking fetch (dev decision B — script call + read in one step):
      - fms_push  → fire PostToServer, block; FM POSTs the DDR to /api/upload DURING the block (the
        record carries the token hash); read the script verdict.
      - otherwise → ``pull_source`` (fmsadmin / SaveToDocuments / SaveToFilePath) returns the bytes,
        which we stage.
    Success stages the source on the record → advance to ``ingest``. Failure parks the step (Restart) AND
    writes an error RunRecord (parity with the old ``run_job``); CLEANUP discards any deposited bytes so a
    Restart produces one artifact, not two."""
    from corpusfm.storage import get_backend
    backend = get_backend()
    job = _resolve_run_job(row)
    if job is None:
        msg = "This job no longer exists — its run cannot acquire a source."
        _record_run_error(row, msg)
        return W.fail(msg)
    from corpusfm.server.jobs.config import effective_export_timeout_s
    bound = effective_export_timeout_s(job.source)
    # File-producing pulls may spend up to 60s observing the file or attempting
    # best-effort FM-owned cleanup after the bounded export call returns. Keep the
    # watchdog outside that documented post-call work too.
    post_call_margin = 90.0 if (job.source.type or "").strip() in {
        "fms_local", "fms_save_to_documents", "fms_save_to_file_path",
    } else 30.0
    W.set_step_deadline(bound + post_call_margin)
    if (job.source.type or "").strip() == "fms_push":
        return _acquire_push(repo, backend, row, job, bound)
    return _acquire_pull(repo, backend, row, job, bound)


def _acquire_pull(repo, backend, row, job, bound) -> W.StepResult:
    """Acquire for a non-push method: ``pull_source`` makes the blocking call + reads the produced file,
    returning bytes we stage. A failure discards nothing to clean (pull_source either returns bytes or
    raises) and parks the step Restartable."""
    import dataclasses
    from corpusfm.core.crypto import compress, encode_blob
    from corpusfm.server.jobs.runner import resolve_job_credentials
    from corpusfm.server.jobs.sources import pull_source
    qid = row.key
    try:
        creds = resolve_job_credentials(job)
    except ValueError as exc:
        _record_run_error(row, str(exc))
        return W.fail(str(exc))
    # The pull target IS the owner file (packet 086). Every source pulls from a hosted file — the
    # `local_file` branch that read a path off disk went with the source type (packet 1361-01).
    target = job.file or (job.source.databases or [None])[0]
    if not target:
        msg = "This job has no owner file — it can't pull a hosted database."
        _record_run_error(row, msg)
        return W.fail(msg)
    source = dataclasses.replace(job.source, databases=[target])
    origin_server = _source_server(job, _pull_host(job))
    repo.set_source_server(qid, origin_server)
    try:
        xml_bytes = pull_source(source, creds, timeout=bound)
    except Exception as exc:
        repo.clear_source(qid)
        msg = f"Acquire failed: {exc}"
        _record_run_error(row, msg, origin_server)
        return W.fail(msg)
    backend.engine.blob_put("QUEUE", qid, "SourceXML",
                            encode_blob(compress(xml_bytes), encrypt_on=backend._encrypt_blobs()))
    return W.ok()


def _acquire_push(repo, backend, row, job, bound) -> W.StepResult:
    """Acquire for fms_push: mint a one-time token, stamp its hash on THIS record (so /api/upload
    resolves it mid-call), fire PostToServer, and BLOCK. FM POSTs the DDR to /api/upload during the
    block (depositing into this record). Then interpret the script verdict — ``ok`` (bytes present →
    advance), ``error: N`` / ``""`` (unconfigured) → fail — reporting which side ended the call for a
    timeout/reset (§H). CLEANUP: discard deposited bytes + spend the token on any failure."""
    import dataclasses
    from corpusfm.server import push_tokens, remote_servers
    from corpusfm.server.fms_client import (
        FMSError, FMSPushConnectionReset, FMSPushTimeout, trigger_fms_push,
    )
    from corpusfm.app.web.deployment import external_base, local_base_url, validate_callback_url
    from corpusfm.core.addon.scripts import POST_TO_SERVER
    from corpusfm.server.jobs.store import get_job_credential
    qid = row.key
    p = row.jor.get("Payload", {}) or {}

    file_name = job.file or (job.source.databases or [None])[0] or p.get("file_name") or ""
    if not file_name:
        msg = "This fms_push job has no owner file to pull."
        _record_run_error(row, msg)
        return W.fail(msg)
    script = job.source.script or POST_TO_SERVER
    server_ref = getattr(job.source, "server_ref", None) or ""
    is_remote = bool(server_ref) and server_ref != "local"
    srv = remote_servers.get_server_by_id(server_ref) if is_remote else None
    if is_remote and srv is None:
        msg = "This job targets a remote server that no longer exists."
        _record_run_error(row, msg)
        return W.fail(msg)
    c = get_job_credential(getattr(job, "id", "") or "") or {}
    if not c.get("account") or not c.get("password"):
        msg = f"No usable credential stored for job '{job.name}' — set it on the job"
        _record_run_error(row, msg)
        return W.fail(msg)
    try:
        # Callback resolution (packet 1219): a REMOTE push uses the callback stored on ITS OWN SERVER
        # record — the address from that peer's perspective, so two remote servers on different
        # networks can each be right. It falls back to the install's asserted address when the record
        # carries none, and fails before firing when neither exists (never posts the schema + a
        # one-time token to nowhere). A LOCAL co-located push keeps the loopback base; local traffic
        # stays local, and a single machine has no From/To to state.
        if is_remote:
            resolved_cb = (getattr(srv, "callback_url", "") or "").strip()
            if not resolved_cb:
                eb = external_base()
                if not eb.value:
                    raise ValueError(
                        eb.error or f"no callback address for remote server '{getattr(srv, 'name', '')}' "
                        "— set one on the server, or set this install's address on Settings → MCP")
                resolved_cb = eb.value
        else:
            resolved_cb = local_base_url()
        callback = validate_callback_url(resolved_cb, require_public=is_remote)
    except ValueError as exc:
        msg = f"fms_push: {exc}"
        _record_run_error(row, msg)
        return W.fail(msg)
    if srv is not None:
        server_url = f"https://{srv.host.rstrip('/')}"
        verify_ssl = bool(srv.verify_ssl)
    else:
        try:
            from corpusfm.server.fms_transport import colocated
            transport = colocated()
            verify_ssl = transport.verify_ssl
            server_url = f"https://{transport.host.rstrip('/')}"
        except Exception as exc:
            raise FMSError(f"Installed FileMaker transport unavailable: {exc}") from exc
    creds = {"username": c["account"], "password": c["password"],
             "verify_ssl": "true" if verify_ssl else "false"}
    source = dataclasses.replace(job.source, server=server_url, databases=[file_name], script=script)
    # Stamped BEFORE firing: FileMaker deposits the bytes into this record during the blocking call.
    origin_server = _source_server(job, server_url)
    repo.set_source_server(qid, origin_server)

    # Mint the one-time token and stamp its HASH on THIS record BEFORE firing, so FM's mid-call POST to
    # /api/upload resolves the exact acquiring record (find_pending_push: Type=acquire + hash).
    raw, token_hash = push_tokens.mint_push_token()
    repo.set_push_token(qid, token_hash)

    def _cleanup():
        repo.clear_source(qid)      # discard any bytes /api/upload deposited before the failure
        repo.set_push_token(qid, "")  # spend the token — a later POST cannot re-resolve this record

    try:
        verdict = trigger_fms_push(source, creds, callback, push_token=raw, timeout=bound)
    except FMSPushTimeout as exc:
        _cleanup()
        msg = f"Acquire timed out — {exc}"
        _record_run_error(row, msg, origin_server)
        return W.fail(msg)
    except FMSPushConnectionReset as exc:
        _cleanup()
        msg = f"Acquire ended by the server — {exc}"
        _record_run_error(row, msg, origin_server)
        return W.fail(msg)
    except FMSError as exc:
        _cleanup()
        msg = f"Acquire trigger failed: {exc}"
        _record_run_error(row, msg, origin_server)
        return W.fail(msg)

    v = (verdict or "").strip()
    if v == "ok":
        # FM reported success — its POST to /api/upload should have deposited the DDR during the block.
        if backend.load_staged_source(qid) is None:
            _cleanup()
            msg = "FileMaker reported success but no schema was received at /api/upload."
            _record_run_error(row, msg, origin_server)
            return W.fail(msg)
        repo.set_push_token(qid, "")   # spent; the record now advances acquire→ingest
        return W.ok()
    # A non-ok verdict: an "error: N" the script returned, or "" from an unconfigured target whose
    # security-guard Exit Script fired first. Both are failures WITH the verdict in hand (the model:
    # the acquire step's outcome is the verdict).
    _cleanup()
    reason = (f"FileMaker returned: {v}" if v.startswith("error")
              else "The export target is not configured (the script's security-guard Exit Script is "
                   "still enabled)." if not v else f"FileMaker returned an unexpected result: {v!r}")
    _record_run_error(row, reason, origin_server)
    return W.fail(reason)


def enqueue_deindex(backend, file_name: str, *, owner: str = "") -> str:
    """Enqueue a de-index record (Type=``index`` with a ``deindex`` op flag; target = the FM file
    name). Returns the record UUID."""
    repo = _repo(backend)
    qid = repo.enqueue([Q.INDEX], payload={"op": "deindex", "file_name": file_name},
                       owner=owner or "")
    W.poke(Q.INDEX)
    return qid


def enqueue_summary_index(backend, uuid: str, *, owner: str = "") -> str:
    """Enqueue a SUMMARY-layer index record (Type=``index`` with an ``index_summaries`` op flag;
    packet 1006). Builds only the additive summary layer — never a full raw reindex. Deduped against
    an in-flight summary-index for the same target; returns the record UUID or ``""`` if deduped.
    Blocking (FM read) — call off the event loop."""
    repo = _repo(backend)
    for r in repo.list_by_type(Q.INDEX):
        p = r.jor.get("Payload", {}) or {}
        if p.get("op") == "index_summaries" and r.jor.get("UUIDStorage", "") == uuid:
            return ""
    qid = repo.enqueue([Q.INDEX], payload={"op": "index_summaries"},
                       owner=owner or "", uuid_storage=uuid)
    W.poke(Q.INDEX)
    return qid


def reingest_eligible(meta) -> bool:
    """A record can be re-ingested iff it is a SCHEMA artifact WITH retained source XML (packet 1062).
    Deliverables and ``delete_source``d artifacts are not re-ingestable (advisory re-upload)."""
    if meta is None:
        return False
    return bool(getattr(meta, "is_schema", False) and getattr(meta, "has_source", False))


def _planned_enrichment(was_indexed, was_summarized) -> list:
    """The enrichment a re-ingest requeues (packet 1462): what the artifact already had, whatever the
    providers' state now — the Queue owns whether each stage succeeds. A prior index → a fresh raw index
    (unknown is attempted); prior summaries → fresh summarization, whose success queues their summary
    index. Nothing is created that the artifact didn't have."""
    return ([Q.INDEX] if was_indexed is not False else []) + ([Q.SUMMARIZE] if was_summarized else [])


def enqueue_reingest(backend, uuid: str, *, owner: str = "", was_indexed=None) -> str:
    """Enqueue ONE atomic re-ingest-and-replace record (``[reingest]``, target = ``UUIDStorage``) for a
    source-retained schema artifact (packet 1062). Captures the artifact's CURRENT enrichment state
    (indexed? summarized?) into the payload NOW, so the handler re-enqueues only the enrichment it
    originally had (never silently indexing what the user chose not to). Deduped against an in-flight
    re-ingest for the same target; returns the record UUID, or ``""`` if deduped. Blocking — call off
    the event loop.

    The whole plan is on this ONE record (packet 1452), so the Queue shows the operation rather than a
    row per stage. Index comes before summarize: a slow summary mustn't hold up search (packet 1170).

    ``was_indexed`` may be passed explicitly by a caller that already measured the artifact's index
    state; when None, it is read from the stored index here — True, False, or None when an index exists
    but cannot be read.

    An index that existed is ALWAYS planned for refresh (packet 1460), whatever the embedder's state:
    a refresh that cannot run must fail visibly rather than leave old vectors reading as current. An
    unreadable index keeps the stage too, and the handler settles it once the content has committed."""
    repo = _repo(backend)
    if _in_flight(repo, Q.REINGEST, uuid):
        return ""
    if was_indexed is None:
        was_indexed = enrichment.index_membership(uuid)
    was_summarized = False
    try:
        m = backend.get_artifact_meta(uuid)
        was_summarized = bool(getattr(m, "has_summaries", False))
    except Exception:
        pass
    tail = _planned_enrichment(was_indexed, was_summarized)
    qid = repo.enqueue([Q.REINGEST] + tail,
                       payload={"was_indexed": was_indexed, "was_summarized": was_summarized},
                       owner=owner or "", uuid_storage=uuid)
    W.poke(Q.REINGEST)
    return qid


# ── handlers ─────────────────────────────────────────────────────────────────────

def ingest_handler(repo, row) -> W.StepResult:
    """Ingest one ``ingest``-step record — parse + store the staged source into a STORAGE artifact (the
    step's outcome). Three kinds share the step:
    - a **Job Run** (``Payload.kind == "job_run"``, with a mandatory ``UUIDJob``) → the 077-E landing, then the run's durable
      side effects the old monolithic ``run_job`` did at store: copy-forward tags, the closing RunRecord,
      artifact pruning (git + enrichment are their OWN downstream steps);
    - a browser **import** → the landing + its baked enrichment tail (no job side effects);
    - a **deliverable** (patch/clip/fmScript/fmCalc over MCP — ``Payload.deliverable``) → a degenerate
      ``store_deliverable`` write with a pre-supplied ``record_uuid``.
    The staged source is guaranteed present (acquire/upload completed before ingest); a missing source is
    a genuine failure. (Renamed from ``land_handler``; the persisted step value is now ``ingest``.)"""
    from corpusfm.storage import get_backend
    backend = get_backend()
    qid = row.key
    p = row.jor.get("Payload", {}) or {}
    raw = backend.load_staged_source(qid)
    if raw is None:
        return W.fail("Staged source was never stored, or is unreadable.")
    if p.get("deliverable"):
        return _land_deliverable(backend, raw, p)
    from corpusfm.app.web._import_ingest import ingest_import_bytes
    # Origin = the ingesting CHANNEL (packet 1169): a job run passes "Import" so land_artifact promotes it
    # to "Job" from the queue row's UUIDJob; an AI/MCP import carries its channel in the payload; a human
    # web import is "WebUI". The promotion only fires while origin == "Import", so WebUI/MCP flow through.
    origin = "Import" if is_job_run(row) else (p.get("origin") or "WebUI")
    outcome = ingest_import_bytes(
        raw, p.get("filename") or "import",
        name=p.get("name") or "", locale=p.get("locale") or "",
        backend=backend, land_from=qid, origin=origin,
        keep_source_xml=bool(p.get("keep_source_xml")))
    if not outcome.ok:
        return W.fail(outcome.error or "Import failed.")
    _demote_prior_latest(backend, row, getattr(outcome, "uuid", "") or "")
    _apply_run_side_effects(backend, row, outcome)
    return W.ok()


def _apply_run_side_effects(backend, row, outcome) -> None:
    """For a JOB RUN, apply the durable outcome the old monolithic ``run_job`` wrote at store —
    copy-forward tags, the closing OK RunRecord, artifact pruning. A browser import / MCP deliverable
    is a no-op. Discriminated by ``Payload.kind``, not by whether a display label happens to be set. Best-effort: none of these fail the ingest step — the run's
    real outcome is the STORED artifact, already committed; these are its bookkeeping."""
    p = row.jor.get("Payload", {}) or {}
    if not is_job_run(row):
        return
    job = _resolve_run_job(row)
    meta = getattr(outcome, "meta", None)
    new_uuid = getattr(outcome, "uuid", "") or row.jor.get("UUIDStorage", "") or ""
    job_uuid = row.jor.get("UUIDJob", "") or (getattr(job, "id", "") if job else "")
    try:
        from corpusfm.server import tags_store
        if job is not None and tags_store.tables_available(backend):
            tags_store.copy_forward_on_run(
                backend, job_uuid=job_uuid,
                new_timestamp=getattr(meta, "timestamp", "") if meta is not None else "",
                job_tags=list(job.tags or []))
    except Exception:
        log.debug("ingest: tag copy-forward failed", exc_info=True)
    _close_run_record(backend, row, new_uuid)
    try:
        if job is not None and job.process.enable_artifact_limit and job.process.max_artifacts > 0:
            from corpusfm.server.artifact_delete import prune_job_artifacts
            prune_job_artifacts(backend, job_uuid, job.process.max_artifacts)
    except Exception:
        log.debug("ingest: artifact pruning failed", exc_info=True)


def _demote_prior_latest(backend, row, new_uuid: str) -> None:
    """PROMOTE the just-landed record in this job's lineage (packet 1145 / 1361-01).

    There is nothing to demote any more: promotion is one ``STORAGELINK`` row per job at a
    deterministic key, so pointing it at the new artifact IS the whole operation. Job-less imports
    carry no ``UUIDJob`` and are always-latest singletons — ``mark_latest_on_store`` returns
    immediately. Never fails the step."""
    job_uuid = row.jor.get("UUIDJob", "") or ""
    if not job_uuid:
        return
    try:
        from corpusfm.server import latest as _latest
        if _latest.latest_available(backend):
            _latest.mark_latest_on_store(backend, job_uuid=job_uuid, new_uuid=new_uuid)
    except Exception:
        log.debug("promotion update failed after land", exc_info=True)


def _close_run_record(backend, row, uuid_storage: str) -> None:
    """Write the ONE closing ``ok`` RunRecord for a Job Run at ingest (packet 1142 — ingest is every
    run's real completion, push or pull). Generalizes the old ``_maybe_close_push_run``: the trigger is
    read from the payload (manual/schedule/push/webhook), not hard-coded to ``push``. Best-effort; a
    browser import is a no-op (by ``Payload.kind``). Keyed by ``run_id``, so a Restart after an earlier error
    RunRecord overwrites it in place. Git + enrichment are downstream steps (their own compartments)."""
    p = row.jor.get("Payload", {}) or {}
    if not is_job_run(row):
        return
    try:
        from datetime import datetime, timezone
        from corpusfm.server.jobs.history import RunRecord
        from corpusfm.server.jobs.runner import _record_run
        now = datetime.now(timezone.utc)
        duration = 0.0
        created = row.jor.get("created_at") or ""
        if created:
            try:
                duration = round((now - datetime.fromisoformat(created)).total_seconds(), 2)
            except Exception:
                duration = 0.0
        # The produced artifact's UUID: prefer the just-landed uuid; fall back to the row's freshly
        # anchored UUIDStorage (ingest_import_bytes → land_artifact anchors it during the store).
        us = uuid_storage or row.jor.get("UUIDStorage", "") or ""
        if not us:
            fresh = _repo_or_none(backend)
            fr = fresh.get(row.key) if fresh is not None else None
            us = fr.jor.get("UUIDStorage", "") if fr is not None else us
        run_id = p.get("run_id") or str(_uuidlib.uuid4())
        run = RunRecord(
            ts=now.isoformat(timespec="seconds"), status="ok", trigger=p.get("trigger") or "schedule",
            duration_s=max(0.0, duration), archive_path=us,
            run_id=run_id, job_uuid=row.jor.get("UUIDJob", "") or None,
            job_name=p.get("job_name") or "", source_server=p.get("source_server") or None)
        _record_run(row.jor.get("UUIDJob", "") or "", run, backend)
    except Exception:
        log.debug("run-record write failed at ingest", exc_info=True)


def _land_deliverable(backend, raw: bytes, p: dict) -> W.StepResult:
    """Store one deliverable (patch/clip/script/calc) at its pre-supplied ``record_uuid`` (packet 086
    — deliverable saves route through the queue instead of an inline store). Records the HISTORY
    patch event (for PatchXML) and, for an acceptance case, its ``AcceptanceCase`` metadata.

    **The step is complete only when the record, its container AND its supplemental metadata have
    all succeeded (packet 1361-01).** Anything less is a `fail`, so the row rests for a restart
    rather than reporting a half-built case as done.

    A restart OVERWRITES the same anchored STORAGE uuid — the record uuid is pre-supplied and stable,
    so `store_deliverable` replaces its own prior attempt rather than minting a second artifact for
    the same case. It is deliberately not a resume: the source bytes are durable in this queue row's
    own `SourceXML` container, so redoing the store is cheap and correct, and detecting "which half
    already landed" would be machinery for no outcome (ruling 11)."""
    record_uuid = p.get("record_uuid") or ""
    try:
        backend.store_deliverable(
            raw, artifact_type=p.get("artifact_type") or "fmClip", origin=p.get("origin") or "MCP",
            name=p.get("name") or "", description=p.get("description") or "",
            memory=p.get("memory") or "", record_uuid=record_uuid)
    except Exception as exc:
        return W.fail(f"Deliverable save failed: {exc}")
    case = p.get("acceptance_case")
    if isinstance(case, dict) and case:
        # Supplemental metadata is REQUIRED work for this item, not a best-effort tail: a stored
        # acceptance clip with no case record is invisible to `evaluate_acceptance_return` and to
        # its own batch, which is worse than an obvious failed queue row.
        try:
            from corpusfm.server import acceptance_ops
            acceptance_ops.write_case(backend, record_uuid, case)
        except Exception as exc:
            return W.fail(f"Acceptance metadata write failed: {exc}")
    if p.get("artifact_type") == "PatchXML":
        try:
            from corpusfm.server.history import record_patch
            record_patch(backend, record_uuid, p.get("source_uuid") or "", "",
                         label=p.get("name") or "")
        except Exception:
            log.debug("record_patch failed for deliverable %s", record_uuid, exc_info=True)
    return W.ok()


def enqueue_deliverable(backend, xml_bytes: bytes, *, artifact_type: str, origin: str = "MCP",
                        owner: str = "", name: str = "", description: str = "", memory: str = "",
                        source_uuid: str = "", record_uuid: str = "",
                        acceptance_case: dict = None) -> dict:
    """Stage one deliverable and enqueue it — WITHOUT waiting. Returns {queue_id, uuid}.

    The fast deliverable lane (packet 086) with no poll loop: an acceptance BATCH is many cases, and
    blocking each one behind the ingest worker turned a batch into a serialized wait whose only
    outcome was a timeout message (packet 1361-01). One queue item per case, each linked by the
    batch id inside its own acceptance metadata, each anchored on its pre-generated record uuid so a
    retry resumes that artifact instead of duplicating it."""
    import uuid as _uuidlib
    from corpusfm.core.crypto import compress, encode_blob
    repo = _repo(backend)
    record_uuid = record_uuid or str(_uuidlib.uuid4())
    payload = {"deliverable": True, "artifact_type": artifact_type, "origin": origin or "MCP",
               "name": name or "", "description": description or "", "memory": memory or "",
               "record_uuid": record_uuid, "source_uuid": source_uuid or ""}
    if acceptance_case:
        payload["acceptance_case"] = acceptance_case
    # Two-state stage (mirror enqueue_import): start on UPLOAD — which no worker drains — stage the
    # source, THEN advance upload→ingest, so the ingest worker only ever claims a record whose
    # SourceXML is already present.
    qid = repo.enqueue([Q.UPLOAD, Q.INGEST], payload=payload, owner=owner or origin or "MCP",
                       uuid_storage=record_uuid)
    backend.engine.blob_put("QUEUE", qid, "SourceXML",
                            encode_blob(compress(xml_bytes), encrypt_on=backend._encrypt_blobs()))
    repo.advance_or_delete(qid)      # upload → ingest (source now guaranteed present)
    W.poke(Q.INGEST)
    return {"queue_id": qid, "uuid": record_uuid}


def enqueue_deliverable_and_wait(backend, xml_bytes: bytes, *, artifact_type: str, origin: str = "MCP",
                                 owner: str = "", name: str = "", description: str = "", memory: str = "",
                                 source_uuid: str = "", timeout: float = 120.0,
                                 poll: float = 0.25) -> dict:
    """Save a deliverable THROUGH the queue and WAIT for it (packet 086 — nothing competes with the
    queue; even an MCP save serializes behind the ingest worker). Pre-generates the record UUID (so the
    produced address is known without a post-delete lookup), stages the XML, enqueues a ``[upload,
    ingest]`` deliverable record, pokes the ingest worker, then polls to completion. Returns
    {status: ok|failed|timeout, uuid, error}. Blocking — call off the event loop.

    ``owner`` is IDENTITY (who saved it) and is kept SEPARATE from ``origin`` (provenance) — packet 1168.
    An MCP caller passes ``owner=_mcp_actor()`` so the real user can cancel/own the record and audit
    attributes correctly; when ``owner`` is empty it defaults to ``origin`` for back-compat (a non-MCP
    caller — e.g. a job — that legitimately wants owner==origin is unchanged)."""
    import time
    import uuid as _uuidlib
    from corpusfm.core.crypto import compress, encode_blob
    repo = _repo(backend)
    record_uuid = str(_uuidlib.uuid4())
    payload = {"deliverable": True, "artifact_type": artifact_type, "origin": origin or "MCP",
               "name": name or "", "description": description or "", "memory": memory or "",
               "record_uuid": record_uuid, "source_uuid": source_uuid or ""}
    # Two-state stage (mirror enqueue_import): start on UPLOAD — which no worker drains — stage the
    # source, THEN advance upload→ingest, so the ingest worker only ever claims a record whose SourceXML
    # is already present. A bare [ingest] enqueue is claimable before its blob lands (a source-less
    # claim race under load); this closes it deterministically.
    qid = repo.enqueue([Q.UPLOAD, Q.INGEST], payload=payload, owner=owner or origin or "MCP")
    backend.engine.blob_put("QUEUE", qid, "SourceXML",
                            encode_blob(compress(xml_bytes), encrypt_on=backend._encrypt_blobs()))
    repo.advance_or_delete(qid)      # upload → ingest (source now guaranteed present)
    W.poke(Q.INGEST)
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        row = repo.get(qid)
        if row is None:
            return {"status": "ok", "uuid": record_uuid, "error": ""}
        if Q.is_failed(row.jor):
            return {"status": "failed", "uuid": record_uuid, "error": row.jor.get("Outcome", "")}
        time.sleep(poll)
    return {"status": "timeout", "uuid": record_uuid,
            "error": "The save is still processing — it will appear in the catalog shortly."}


def summarize_handler(repo, row) -> W.StepResult:
    """Summarize one artifact (target = ``UUIDStorage``). Raises → parked (try-once). On success,
    if an embedder is configured, enqueue a SUMMARY-LAYER index step only — never a full raw reindex
    (packet 1006: summaries are additive; generating them must not stale/replace the raw search
    substrate). If no embedder is configured, we simply stored the summaries."""
    from corpusfm.storage import get_backend
    be = get_backend()
    uuid = row.jor.get("UUIDStorage", "")
    if not uuid:
        return W.fail("summarize target missing (no UUIDStorage).")
    # packet 1155: summarize is cooperatively cancelable — generate_summaries polls should_cancel per
    # object. Capture whether the poll actually STOPPED it (a cancel racing in after the last object
    # doesn't reach here). Partial summaries are additive/valid, so they're KEPT (no undo, unlike index).
    stopped_early = {"v": False}
    def _should_cancel() -> bool:
        if W.cancel_requested():
            stopped_early["v"] = True
            return True
        return False
    produced = enrichment.summarize_one(be, uuid, on_progress=lambda *a, **k: W.note_progress(),
                                        should_cancel=_should_cancel)
    if produced == 0 and not stopped_early["v"] and Q.REINGEST in (row.jor.get("Steps") or []):
        # A re-ingest removed the old summary layer; a run that produced nothing must not let the old
        # saved summaries be indexed as this content's (packet 1462). Its own visible outcome.
        return W.fail("No summaries were produced; check the AI provider.")
    # Summaries never change raw index membership, and the `summarized` badge is per-record.
    if stopped_early["v"]:
        return W.fail(_INTERRUPTED)   # partial summaries kept; no summary-layer index chained
    if row.key not in _whole_cancels:     # a stop that landed after the last object still means no more work
        _maybe_index_summary_layer(be, row)
    return W.ok()


def index_handler(repo, row) -> W.StepResult:
    """Index (or de-index) one target (packet 1006). ``Payload.op``:
    - ``deindex``          → remove the FM file's entries (all layers);
    - ``index_summaries``  → build the additive summary layer at ``UUIDStorage`` (no raw touch);
    - otherwise            → build/refresh the RAW search layer at ``UUIDStorage``.
    Raises → parked (try-once)."""
    from corpusfm.storage import get_backend
    be = get_backend()
    p = row.jor.get("Payload", {}) or {}
    op = p.get("op")
    if op == "deindex":
        fn = p.get("file_name", "")
        if not fn:
            return W.fail("de-index target missing (no file_name).")
        enrichment.deindex_one(fn)
    elif op == "index_summaries":
        uuid = row.jor.get("UUIDStorage", "")
        if not uuid:
            return W.fail("summary-index target missing (no UUIDStorage).")
        enrichment.index_summaries_one(be, uuid, on_progress=lambda: W.note_progress())
    else:
        uuid = row.jor.get("UUIDStorage", "")
        if not uuid:
            return W.fail("index target missing (no UUIDStorage).")
        # Record whether the cancel actually STOPPED the indexer at a batch boundary — not merely
        # whether a cancel was requested. A cancel that arrives after the final batch never fires this
        # callback again, so a COMPLETE index is kept instead of being discarded (packet 1000 re-sweep:
        # the old post-hoc `cancel_requested()` check de-indexed a just-finished valid index in that race).
        stopped_early = {"v": False}
        def _should_cancel() -> bool:
            if W.cancel_requested():
                stopped_early["v"] = True
                return True
            return False
        enrichment.index_one(be, uuid, on_progress=lambda: W.note_progress(),
                             should_cancel=_should_cancel)
        if stopped_early["v"]:
            # Reached ONLY when the poll fired at a batch boundary — the indexer genuinely stopped mid-run,
            # so THIS artifact's raw index is PARTIAL. De-index just this artifact (by uuid — never the
            # whole file / siblings) to keep its per-artifact `indexed` badge honest (its old complete
            # slice was already dropped at reindex start — no good state to preserve). Park failed so it
            # stays visible + Restartable. (A cancel that raced in after the final batch does NOT reach
            # here — the index completed and is kept.)
            enrichment.deindex_artifact_one(uuid)
            return W.fail("Interrupted by user.")
    # No in-process badge-cache bust (packet 1415): the vector index publishes its membership
    # generation, which the next Artifacts request observes; a trailing bust here could discard a
    # result a concurrent request had already refreshed for that generation.
    return W.ok()


def reingest_handler(repo, row) -> W.StepResult:
    """Re-ingest one artifact IN PLACE from its retained source XML (packet 1062). Target = ``UUIDStorage``.

    A source or parse failure leaves the OLD record untouched; a failed write is reported and may have
    replaced the content blob without the record (the accepted blob-first boundary of
    ``reingest_artifact``). Either way the step parks, Restartable. On success its requeued enrichment
    stays on this record (packets 1452/1462) and the Queue owns each stage's outcome: no stage is dropped for a provider's state. Every old layer is removed
    first, so a stage that cannot run fails visibly instead of old vectors reading as current. An index
    unknown at enqueue and confirmed absent now is not created.
    """
    from corpusfm.storage import get_backend
    from corpusfm.storage.artifact_store import reingest_artifact
    from corpusfm.app.app_config import load_app_config
    from corpusfm.storage.queue_record import INDEX as _INDEX, SUMMARIZE as _SUMMARIZE
    be = get_backend()
    uuid = row.jor.get("UUIDStorage", "")
    if not uuid:
        return W.fail("re-ingest target missing (no UUIDStorage).")
    p = dict(row.jor.get("Payload", {}) or {})
    if not p.get("reingest_committed"):
        cfg = load_app_config()
        res = reingest_artifact(be, uuid, keep_source_xml=cfg.keep_source_xml)
        if not res.ok:
            return W.fail(res.error or "re-ingest failed.")     # summaries are only cleared after a success
        # Restart after a later failure here resumes past the re-ingest instead of repeating it.
        p["reingest_committed"] = True
        repo.rewrite(row.key, {**(repo.get(row.key) or row).jor, "Payload": p})
    row = repo.get(row.key) or row
    steps = row.jor.get("Steps") or [Q.REINGEST]
    # One rule for every record: the plan follows what the artifact had (its payload). A record queued
    # before 1452 — one step, its enrichment never on the record — is normalised into the same plan here.
    if len(steps) == 1:
        tail = _planned_enrichment(p.get("was_indexed", False), bool(p.get("was_summarized")))
    else:
        tail = [s for s in steps[1:] if s in (_INDEX, _SUMMARIZE)]
    if _INDEX in tail and p.get("was_indexed") is None and enrichment.index_membership(uuid) is False:
        tail.remove(_INDEX)     # unknown at enqueue, confirmed absent now: no new index
    if tail != steps[1:]:
        repo.retain_steps(row.key, [Q.REINGEST] + tail)
    _note_reingest_committed(be, row, [Q.REINGEST] + tail)
    if tail:
        # Same-UUID content changed (or may have) → every layer goes before the requeued work rebuilds
        # it, so neither old raw text nor old summaries read as this content's.
        try:
            enrichment.deindex_artifact_one(uuid)
        except Exception:
            log.warning("reingest: could not remove the old index for %s", uuid, exc_info=True)
    # Summaries are disposable (packet 1463): any saved ones describe the content just replaced, so they
    # go without being read, and the requeued summarisation writes fresh ones. A failure is reported as
    # what it is — committed, old summaries still stored — and Restart retries only this removal.
    try:
        be.clear_summaries(uuid)
    except Exception as exc:
        log.warning("reingest: could not remove the old summaries for %s", uuid, exc_info=True)
        return W.fail(f"Re-ingest committed, but its old summaries could not be removed ({type(exc).__name__}). "
                      "Restart retries the removal.")
    return W.ok()


# ── Finished re-ingests ───────────────────────────────────────────────────────────────────────────────
# A record that finishes is deleted, so nothing durable says it succeeded. This keeps a short, in-memory
# account for the Queue and artifact detail: lost on restart, and never a source of truth about the artifact.
_RECENT_REINGEST_SECONDS = 3600
_RECENT_REINGEST_MAX = 50
_recent_reingests: dict = {}
_recent_lock = threading.Lock()


def _note_reingest_committed(backend, row, steps: list) -> None:
    target = _target_name(backend, row.jor.get("UUIDStorage", "")) or "artifact"
    with _recent_lock:
        _recent_reingests[row.key] = {
            "id": row.key, "uuid": row.jor.get("UUIDStorage", ""), "owner": row.jor.get("owner", "unknown"),
            "target": target, "steps": list(steps),
            "committed_at": datetime.now(timezone.utc).isoformat(), "finished_at": "", "_at": time.monotonic()}
        # Only ever a finished account: one still running must be there when it finishes.
        finished = [k for k, e in _recent_reingests.items() if e["finished_at"]]
        for key in sorted(finished, key=lambda k: _recent_reingests[k]["_at"])[:max(0, len(_recent_reingests) - _RECENT_REINGEST_MAX)]:
            del _recent_reingests[key]


def _summaries_missing(uuid: str) -> bool:
    # A provider error for every object still ends the step well, with nothing stored.
    from corpusfm.storage import get_backend
    try:
        return not getattr(get_backend().get_artifact_meta(uuid), "has_summaries", True)
    except Exception:
        return False


def _reingest_record_finished(row) -> None:
    with _recent_lock:
        entry = _recent_reingests.get(row.key)
    if entry is None:
        return
    _whole_cancels.discard(row.key)
    _stage_skips.discard(row.key)
    skipped = list((row.jor.get("Payload") or {}).get("stage_skipped") or [])
    cancelled = bool(entry.get("cancelled"))
    summary_empty = (Q.SUMMARIZE in entry["steps"] and Q.SUMMARIZE not in skipped and not cancelled
                     and _summaries_missing(entry["uuid"]))
    with _recent_lock:
        entry["skipped"] = skipped
        if summary_empty:
            entry["summaries_empty"] = True
        if summary_empty or skipped or cancelled:
            entry["finished_at"] = ""
            entry["ended"] = True
        else:
            entry["finished_at"] = datetime.now(timezone.utc).isoformat()
        entry["_at"] = time.monotonic()


# ── A re-ingest's optional stages run independently (packet 1453) ─────────────────────────────────────
# One record carries the operation, but one optional stage's failure mustn't cost the others. A failure is
# noted and the record moves on; when the last stage ends, completed stages sort first and the record parks
# on the first failed one, so Restart repeats only what failed. Cancel means the whole operation: nothing
# further starts. Skip means this stage: the next one still runs. These two sets say which a stop was; they
# live only as long as the running step that reads them.
_INTERRUPTED = "Interrupted by user."
_whole_cancels: set = set()
_stage_skips: set = set()


def _run_optional_stage(repo, row, handler) -> W.StepResult:
    qid, step = row.key, row.jor.get("Type", "")
    # A stop that landed after the previous stage had finished was meant for what comes next.
    _stage_skips.discard(qid)
    if qid in _whole_cancels:
        _whole_cancels.discard(qid)
        return W.fail(_INTERRUPTED)
    try:
        result = handler(repo, row)
    except Exception as exc:
        log.warning("queue: re-ingest stage '%s' raised on %s: %s", step, qid, exc, exc_info=True)
        result = W.fail(f"{step} failed: {exc}")
    whole, skip = qid in _whole_cancels, qid in _stage_skips
    _whole_cancels.discard(qid)
    _stage_skips.discard(qid)
    fresh = repo.get(qid)
    if fresh is None or fresh.jor.get("Type") != step:
        return W.StepResult(ok=result.ok, outcome=result.outcome, settled=True)   # cancelled or skipped while claimed
    jor = fresh.jor
    steps = list(jor.get("Steps") or [])
    later = steps[steps.index(step) + 1:]
    if whole:
        if not result.ok:
            return result
        if later:       # it finished before the stop landed; the remaining stages still don't start
            steps = steps[:steps.index(step) + 1]
            later = []
            with _recent_lock:
                if qid in _recent_reingests:
                    _recent_reingests[qid]["cancelled"] = True
    payload = dict(jor.get("Payload") or {})
    failures = dict(payload.get("stage_failures") or {})
    skipped = list(payload.get("stage_skipped") or [])
    if result.ok:
        failures.pop(step, None)
    elif skip and later and result.outcome == _INTERRUPTED:
        failures.pop(step, None)
        skipped.append(step)
    else:
        failures[step] = result.outcome or f"{step} failed"
    payload.update(stage_failures=failures, stage_skipped=skipped)
    if later or not failures:
        repo.rewrite(qid, {**jor, "Steps": steps, "Payload": payload})
        return W.ok()
    held = [s for s in steps[1:] if s in failures]
    # In one write: a record resting on a stage with no failure mark would be claimable by that stage's lane.
    repo.rewrite(qid, Q.failed({**jor, "Payload": payload, "Type": held[0],
                                "Steps": steps[:1] + [s for s in steps[1:] if s not in failures] + held},
                               failures[held[0]]))
    return W.StepResult(ok=False, outcome=failures[held[0]], settled=True)


def _stuck_optional_stage(repo, qid: str, outcome: str) -> bool:
    """A timed-out optional stage doesn't hold back the next one: the process restarts into it."""
    row = repo.get(qid)
    if row is None or Q.REINGEST not in (row.jor.get("Steps") or []) or row.jor.get("Type") == Q.REINGEST \
            or not _later_stages(row.jor):
        return False
    payload = dict(row.jor.get("Payload") or {})
    payload["stage_failures"] = {**(payload.get("stage_failures") or {}), row.jor["Type"]: outcome}
    repo.rewrite(qid, {**row.jor, "Payload": payload})
    repo.advance_or_delete(qid)
    return True


def _optional_stage(handler):
    def run(repo, row) -> W.StepResult:
        if Q.REINGEST in (row.jor.get("Steps") or []):
            return _run_optional_stage(repo, row, handler)
        return handler(repo, row)
    return run


def _later_stages(jor) -> list:
    steps = jor.get("Steps") or []
    cursor = jor.get("Type", "")
    return steps[steps.index(cursor) + 1:] if cursor in steps else []


def _can_skip_stage(jor, running: bool) -> bool:
    if Q.REINGEST not in (jor.get("Steps") or []) or jor.get("Type") == Q.REINGEST or not _later_stages(jor):
        return False
    return _is_cancelable_step(jor) if running else True


def skip_stage_record(backend, qid: str, actor: str, is_admin: bool) -> "tuple[bool, int, str]":
    """Skip a re-ingest's current optional stage and carry on with the next (owner-or-admin)."""
    repo = _repo_or_none(backend)
    if repo is None:
        return False, 500, "No storage engine."
    row = repo.get(qid)
    if row is None:
        return False, 404, "No such queued job."
    if not _authorized(row, actor, is_admin):
        return False, 403, "Only the owner or an admin can skip this stage."
    running = qid in W.current_ids()
    if not _can_skip_stage(row.jor, running):
        return False, 409, "This stage can't be skipped."
    if running:
        _stage_skips.add(qid)
        if W.request_cancel(qid):
            return True, 200, "Skipping this stage…"
        _stage_skips.discard(qid)
        return False, 409, "This stage just finished — nothing to skip."
    step = row.jor.get("Type", "")
    payload = dict(row.jor.get("Payload") or {})
    failures = dict(payload.get("stage_failures") or {})
    failures.pop(step, None)
    payload.update(stage_failures=failures, stage_skipped=list(payload.get("stage_skipped") or []) + [step])
    repo.rewrite(qid, {**row.jor, "Payload": payload})
    nxt = repo.advance_or_delete(qid)
    if nxt:
        W.poke(nxt)
    return True, 200, "Skipped."


def recent_reingests(live_records: list, *, observed: bool = True) -> list:
    """Re-ingests that committed and have no live Queue row, newest first. ``state`` is ``done`` when every
    planned stage ran; ``partial`` when the record left the Queue before its optional stages finished.

    ``observed`` False means the Queue read failed, so an absent row says nothing: only an account already
    known to have ended is reported, and none expires. A record still live never expires."""
    live = {r.get("id") for r in live_records}
    now = time.monotonic()
    with _recent_lock:
        if observed:
            for key in [k for k, e in _recent_reingests.items()
                        if k not in live and now - e["_at"] > _RECENT_REINGEST_SECONDS]:
                del _recent_reingests[key]
        rows = [dict(e) for k, e in _recent_reingests.items()
                if k not in live and (observed or e["finished_at"] or e.get("ended"))]
    rows.sort(key=lambda e: e.pop("_at"), reverse=True)
    for entry in rows:
        entry["state"] = "done" if entry["finished_at"] else "partial"
        entry.pop("ended", None)
    return rows


def _maybe_index_summary_layer(be, row) -> None:
    """After summaries complete, add the additive summary index layer when an embedder is configured
    (packet 1006). Never a full raw reindex — the raw substrate is untouched. No-op without an
    embedder (summaries are simply stored)."""
    try:
        if not enrichment.embedder_ready():
            return
        uuid = row.jor.get("UUIDStorage", "")
        if uuid:
            enqueue_summary_index(be, uuid, owner=row.jor.get("owner", "unknown"))
    except Exception:
        log.debug("summary-layer index hook failed", exc_info=True)


# ── Queue-page views ──────────────────────────────────────────────────────────────

def _target_name(backend, uuid: str) -> str:
    """A queued target's DISPLAY label, from the memory-only catalog projection (packet 1410).

    Never a STORAGE read: a decorative label polled every few seconds must not add FileMaker pressure, so
    an unservable catalog or a missing projection is honestly labelled with the record UUID instead.
    ``enrichment.index_key`` stays the authority for the summarize/index operations themselves."""
    if not uuid:
        return ""
    try:
        from corpusfm.server import catalog
        view = catalog.peek(backend)
        proj = view.projection(uuid) if view.servable else None
    except Exception:
        return uuid
    if not proj:
        return uuid
    return proj.get("name") or proj.get("file_name") or uuid


def _kinds_and_target(backend, jor) -> "tuple[list[str], str]":
    """The friendly pipeline KIND TAGS + a display target — derived from the WHOLE laundry list (``Steps``),
    not the current cursor, so a record's identity is stable from enqueue to delete (packet 1018). That's
    what makes an import that opts into enrichment read as ONE row instead of hopping sections.

    Returns a LIST of compact, single-CamelCase tags so the Queue can render them like the artifact page's
    system-tag badges (``SaveAsXML``/``Indexed``). Usually one tag; an enrichment record that BOTH
    summarizes and indexes carries both, in step order."""
    p = jor.get("Payload", {}) or {}
    steps = jor.get("Steps") or []
    if p.get("deliverable"):
        return ["Deliverable"], (p.get("name") or p.get("artifact_type") or "deliverable")
    if p.get("op") == "deindex":
        return ["Deindex"], (p.get("file_name") or "")
    if Q.ACQUIRE in steps:                        # a self-initiated run (push OR pull) — the acquire IS the run
        return ["JobRun"], (p.get("job_name") or "job")   # display label only
    if Q.REINGEST in steps:
        return ["Reingest"], (_target_name(backend, jor.get("UUIDStorage", "")) or "artifact")
    if Q.UPLOAD in steps or Q.INGEST in steps:    # a non-deliverable, client-supplied upload/ingest pipeline is an import
        # Same precedence the LANDING uses (_import_ingest: explicit name → filename stem), so the row
        # reads as the artifact it becomes. Queue never parses the staged XML, so identity can't be the
        # third rung here — "import" is the honest floor.
        return ["Import"], ((p.get("name") or "").strip()
                            or primary_name_from_filename(p.get("filename") or "")
                            or "import")
    if steps and all(s in (Q.SUMMARIZE, Q.INDEX) for s in steps):
        uuid = jor.get("UUIDStorage", "")
        labels = {Q.SUMMARIZE: "Summarize", Q.INDEX: "Index"}
        tags: list[str] = []
        for s in steps:                            # step order; an enrichment record can carry both
            if s in labels and labels[s] not in tags:
                tags.append(labels[s])
        return (tags or ["Enrichment"]), (_target_name(backend, uuid) or uuid)
    # any other pipeline (e.g. a parked git_export scaffolding record) — surface it honestly by its
    # current step rather than mislabelling it, so it can never become invisible (packet 1018).
    return [(jor.get("Type", "") or "queued").replace("_", " ").title().replace(" ", "")], ""


def workspace_view(backend) -> list:
    """The record-centric Queue view (packet 1018): EVERY live QUEUE record as one row showing its whole
    step pipeline (``Steps``) with the cursor (``Type``) as the current step — replacing the old
    kind-sliced import/enrichment/job-run views. One record is one row through its whole life.

    Each row: {id, kinds, target, steps, current, status, cancelable, uuid, owner, error, created_at,
    job_name, file_name}.
    ``cancelable`` marks a raw-index step (the one a RUNNING row can stop mid-run). ``status`` is
    ``failed`` (Outcome set) · ``running`` (a worker holds it now) · ``queued``. Ordered running →
    queued → failed, FIFO (``created_at``) within each. ``uuid`` (UUIDStorage) is the catalog
    pending-overlay key for enrichment records."""
    repo = _repo_or_none(backend)
    if repo is None:
        return []
    cur = W.current_ids()
    out = []
    for row in repo.list_all():
        j = row.jor
        steps = list(j.get("Steps") or ([j["Type"]] if j.get("Type") else []))
        kinds, target = _kinds_and_target(backend, j)
        if Q.is_failed(j):
            status = "failed"
        elif row.key in cur:
            status = "running"
        else:
            status = "queued"
        p = j.get("Payload", {}) or {}
        out.append({
            "id": row.key,
            "kinds": kinds,
            "target": target,
            "steps": steps,
            "current": j.get("Type", ""),
            "status": status,
            "cancelable": _is_cancelable_step(j),   # a running raw-index OR summarize can be stopped mid-run
            # packet 1158: the index op ("" raw · "deindex" · "index_summaries") so the Queue can
            # distinguish an index_summaries record from a raw index (both are Type=index). Display-only
            # extra field; kinds/vocabulary untouched.
            "index_op": p.get("op", ""),
            "uuid": j.get("UUIDStorage", ""),
            "owner": j.get("owner", "unknown"),
            "error": j.get("Outcome", "") if status == "failed" else "",
            # A re-ingest's optional stages (packet 1453): what failed or was skipped along the way.
            "stage_failures": p.get("stage_failures") or {},
            "stage_skipped": p.get("stage_skipped") or [],
            "committed": bool(p.get("reingest_committed")),
            "can_skip_stage": _can_skip_stage(j, status == "running"),
            "created_at": j.get("created_at", ""),
            # JobRun fold (packet 1136 Stage 1, R4): the running-badge data (job identity + FM file)
            # rides the ONE row so the unified activity feed makes /api/jobs/running a redundant
            # re-derivation. Empty for non-job records — additive keys, ignored by the Queue page.
            #
            # `job_uuid` is what the badge JOINS on (packet 1372-02). The row has always carried it;
            # it simply was not surfaced, so the browser fell back to joining on the display NAME —
            # which lights every job sharing a label the moment one of them runs.
            "job_uuid": j.get("UUIDJob", "") or "",
            "job_name": p.get("job_name", "") or "",
            "file_name": p.get("file_name", "") or "",
        })
    _rank = {"running": 0, "queued": 1, "failed": 2}
    out.sort(key=lambda r: (_rank.get(r["status"], 3), r["created_at"]))
    return out


def failed_count(backend) -> int:
    """Indexed count of parked failures across the workspace — the red nav badge."""
    repo = _repo_or_none(backend)
    return repo.failed_count() if repo is not None else 0


# ── Queue-page controls (owner-or-admin; work on ANY queue record) ───────────────

def _authorized(row, actor: str, is_admin: bool) -> bool:
    return bool(is_admin) or (row.jor.get("owner", "") == actor)


def _is_cancelable_step(jor) -> bool:
    """A RUNNING step we can stop cleanly at a cooperative checkpoint (packet 1155):
    - a RAW index (the indexer polls between embedding batches), and
    - a SUMMARIZE (generate_summaries polls should_cancel between objects; partials are kept).
    A de-index / summary-layer index / acquire / ingest / any other step has no checkpoint (or nothing
    to gain), so it is not mid-run cancelable."""
    t = jor.get("Type")
    if t == Q.SUMMARIZE:
        return True
    return (t == Q.INDEX
            and (jor.get("Payload") or {}).get("op") not in ("deindex", "index_summaries"))


def cancel_record(backend, qid: str, actor: str, is_admin: bool) -> "tuple[bool, int, str]":
    """Cancel a record (owner-or-admin). A QUEUED record is removed outright. A RUNNING raw-index record
    is cancelled cooperatively — the worker stops at the next batch boundary, cleans up the partial
    index, and parks it as failed ('Interrupted by user'). Any other running step is refused (409 — no
    checkpoint). Returns (ok, http_status, message)."""
    repo = _repo_or_none(backend)
    if repo is None:
        return False, 500, "No storage engine."
    row = repo.get(qid)
    if row is None:
        return False, 404, "No such queued job."
    if not _authorized(row, actor, is_admin):
        return False, 403, "Only the owner or an admin can cancel this job."
    if qid in W.current_ids():
        if not _is_cancelable_step(row.jor):
            return False, 409, "This job is processing and can't be cancelled mid-run."
        _whole_cancels.add(qid)
        if W.request_cancel(qid):
            return True, 200, "Cancelling the running step…"
        _whole_cancels.discard(qid)
        return False, 409, "This job just finished — nothing to cancel."
    repo.delete(qid)
    return True, 200, "Removed from the queue."


def restart_record(backend, qid: str, actor: str, is_admin: bool) -> "tuple[bool, int, str]":
    """Restart a parked failure (owner-or-admin): clear the failure so the worker re-runs the current
    step. Returns (ok, http_status, message)."""
    repo = _repo_or_none(backend)
    if repo is None:
        return False, 500, "No storage engine."
    row = repo.get(qid)
    if row is None:
        return False, 404, "No such job."
    if not Q.is_failed(row.jor):
        return False, 409, "That job is not in a failed state."
    if not _authorized(row, actor, is_admin):
        return False, 403, "Only the owner or an admin can restart this job."
    _whole_cancels.discard(qid)
    _stage_skips.discard(qid)
    repo.restart(qid)
    W.poke(row.jor.get("Type", ""))
    return True, 200, "Re-queued."


def clear_failed_records(backend, actor: str, is_admin: bool) -> int:
    """Delete every parked failure the actor may remove (own, or all if admin). Returns the count."""
    repo = _repo_or_none(backend)
    if repo is None:
        return 0
    removed = 0
    for row in repo.list_failed():
        if _authorized(row, actor, is_admin):
            repo.delete(row.key)
            removed += 1
    return removed


def _repo_or_none(backend):
    from corpusfm.storage.repos import queue_repo
    return queue_repo(backend)


# ── registration (called at boot) ────────────────────────────────────────────────

def register_all() -> None:
    """Wire the producer handlers into the framework. Idempotent."""
    W.register(Q.ACQUIRE, acquire_handler)
    W.register(Q.INGEST, ingest_handler)
    W.register(Q.SUMMARIZE, _optional_stage(summarize_handler))
    W.register(Q.INDEX, _optional_stage(index_handler))
    W.register(Q.GIT_EXPORT, git_export_handler)
    W.register(Q.REINGEST, reingest_handler)
    W.on_record_finished("reingest", _reingest_record_finished)
    W.on_step_stuck(_stuck_optional_stage)
