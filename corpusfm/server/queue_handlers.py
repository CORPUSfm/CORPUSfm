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
import uuid as _uuidlib

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
    return any(r.jor.get("UUIDStorage", "") == uuid for r in repo.list_by_type(step_type))


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


def _record_run_error(row, message: str) -> None:
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
            job_name=p.get("job_name") or "")
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
    try:
        xml_bytes = pull_source(source, creds, timeout=bound)
    except Exception as exc:
        repo.clear_source(qid)
        msg = f"Acquire failed: {exc}"
        _record_run_error(row, msg)
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
        _record_run_error(row, msg)
        return W.fail(msg)
    except FMSPushConnectionReset as exc:
        _cleanup()
        msg = f"Acquire ended by the server — {exc}"
        _record_run_error(row, msg)
        return W.fail(msg)
    except FMSError as exc:
        _cleanup()
        msg = f"Acquire trigger failed: {exc}"
        _record_run_error(row, msg)
        return W.fail(msg)

    v = (verdict or "").strip()
    if v == "ok":
        # FM reported success — its POST to /api/upload should have deposited the DDR during the block.
        if backend.load_staged_source(qid) is None:
            _cleanup()
            msg = "FileMaker reported success but no schema was received at /api/upload."
            _record_run_error(row, msg)
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
    _record_run_error(row, reason)
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


def enqueue_reingest(backend, uuid: str, *, owner: str = "", was_indexed=None) -> str:
    """Enqueue ONE atomic re-ingest-and-replace record (``[reingest]``, target = ``UUIDStorage``) for a
    source-retained schema artifact (packet 1062). Captures the artifact's CURRENT enrichment state
    (indexed? summarized?) into the payload NOW, so the handler re-enqueues only the enrichment it
    originally had (never silently indexing what the user chose not to). Deduped against an in-flight
    re-ingest for the same target; returns the record UUID, or ``""`` if deduped. Blocking — call off
    the event loop.

    ``was_indexed`` may be passed explicitly by a caller that already measured the artifact's index
    state; when None, it is read from the live index here."""
    repo = _repo(backend)
    if _in_flight(repo, Q.REINGEST, uuid):
        return ""
    if was_indexed is None:
        was_indexed = uuid in enrichment.indexed_uuids()
    was_indexed = bool(was_indexed)
    was_summarized = False
    try:
        m = backend.get_artifact_meta(uuid)
        was_summarized = bool(getattr(m, "has_summaries", False))
    except Exception:
        pass
    qid = repo.enqueue([Q.REINGEST],
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
            job_name=p.get("job_name") or "")
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
    enrichment.summarize_one(be, uuid, on_progress=lambda *a, **k: W.note_progress(),
                             should_cancel=_should_cancel)
    enrichment.bust_indexed_badge_cache()
    if stopped_early["v"]:
        return W.fail("Interrupted by user.")   # partial summaries kept; no summary-layer index chained
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
            enrichment.bust_indexed_badge_cache()
            return W.fail("Interrupted by user.")
    enrichment.bust_indexed_badge_cache()
    return W.ok()


def reingest_handler(repo, row) -> W.StepResult:
    """Re-ingest one artifact IN PLACE from its retained source XML (packet 1062), then re-enqueue only
    the enrichment it originally had. Target = ``UUIDStorage``; the payload carries the captured
    ``was_indexed``/``was_summarized`` flags.

    On a re-ingest failure the OLD record is left untouched (the atomic op guarantees it) and the step
    parks (Restartable). On success:
      - was_indexed + an embedder configured → DEINDEX (stale same-UUID vectors) then enqueue a fresh
        INDEX (content changed → vectors must be rebuilt, never left pointing at old text);
      - was_summarized + a provider configured → enqueue SUMMARIZE (the fresh blob carries no summaries).
    Enrichment the artifact never had is left off (respect the user's choice)."""
    from corpusfm.storage import get_backend
    from corpusfm.storage.artifact_store import reingest_artifact
    from corpusfm.app.app_config import load_app_config
    from corpusfm.storage.queue_record import INDEX as _INDEX, SUMMARIZE as _SUMMARIZE
    be = get_backend()
    uuid = row.jor.get("UUIDStorage", "")
    if not uuid:
        return W.fail("re-ingest target missing (no UUIDStorage).")
    cfg = load_app_config()
    res = reingest_artifact(be, uuid, keep_source_xml=cfg.keep_source_xml)
    if not res.ok:
        return W.fail(res.error or "re-ingest failed.")
    p = row.jor.get("Payload", {}) or {}
    owner = row.jor.get("owner", "") or "reingest"
    if p.get("was_indexed") and enrichment.embedder_ready():
        # Same-UUID content changed → the old vectors MUST be cleared before re-indexing or search is
        # polluted with stale text. Deindex synchronously here, then queue the fresh index.
        try:
            enrichment.deindex_artifact_one(uuid)
        except Exception:
            log.debug("reingest: pre-index deindex failed for %s", uuid, exc_info=True)
        enqueue_enrichment_steps(be, uuid, [_INDEX], owner=owner)
    if p.get("was_summarized") and enrichment.provider_ready():
        enqueue_enrichment_steps(be, uuid, [_SUMMARIZE], owner=owner)
    enrichment.bust_indexed_badge_cache()
    return W.ok()


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
    if not uuid:
        return ""
    try:
        _fn, _ts, name = enrichment.index_key(backend, uuid)
        return name or uuid
    except Exception:
        return uuid


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
        if W.request_cancel(qid):
            return True, 200, "Cancelling the running step…"
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
    W.register(Q.SUMMARIZE, summarize_handler)
    W.register(Q.INDEX, index_handler)
    W.register(Q.GIT_EXPORT, git_export_handler)
    W.register(Q.REINGEST, reingest_handler)
