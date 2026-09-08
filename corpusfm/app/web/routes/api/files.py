"""Files API — the file-centric tracking surface (Stage 4 over Stages 1-3 backend).

The co-located server's hosted files are the canvas: discover them, set a per-file
credential, prove reachability (the export probe), and toggle tracking. See
docs/jobs-per-file-plan.md.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth
from corpusfm.core import servertime

router = APIRouter()


# Callback-URL validation is shared with the runner's default path (packet 1022) — the UI save route
# was the only guard, so a stored/manual/FM-DB job record or an env/install override could still route
# a token + schema over off-box cleartext http. One validator, two trust boundaries.
from corpusfm.app.web.deployment import validate_callback_url as _validate_callback_url


@router.get("/remote-servers", dependencies=[Depends(require_auth)])
def remote_servers_list(request: Request) -> JSONResponse:
    """The registered remote servers, for the Jobs-page HEADER server dropdown (packet 1015). Each is
    {id, name}; full CRUD lives on the Settings page. ``callback_default`` is the URL a remote FM POSTs a
    push back to — pre-fills the PostToServer method field (editable). Prefer the persisted External
    CORPUSfm address; when none is configured, fall back to the request-detected URL so the UI never
    suggests an unreachable loopback (packet 1055/1180)."""
    try:
        from corpusfm.server import remote_servers
        from corpusfm.app.web.deployment import external_base_url, public_callback_url_from_request
        # The one shared External CORPUSfm address (never loopback); when none is configured, suggest
        # the request-detected URL so the UI never proposes an unreachable loopback (packet 1055/1180).
        default = external_base_url() or (public_callback_url_from_request(request) or "")
        return JSONResponse({
            "servers": [{"id": s.id, "name": s.name, "callback_url": s.callback_url or ""}
                        for s in remote_servers.list_servers()],
            "callback_default": default,
        })
    except Exception:
        return JSONResponse({"servers": [], "callback_default": ""})


def _fmt_ts(iso: str) -> str:
    """ISO timestamp → 'YYYY-MM-DD HH:MM' (trim seconds/zone for the card)."""
    return (iso or "").replace("T", " ")[:16]


def _server_display_name(server_ref) -> str:
    """A job's target-server label (packet 1015): 'Local' for the co-located pull, else the remote
    SERVER record's name (falling back to the ref if the server was removed)."""
    ref = (server_ref or "").strip()
    if not ref or ref == "local":
        return "Local"
    try:
        from corpusfm.server import remote_servers
        srv = remote_servers.get_server_by_id(ref)
        return srv.name if srv is not None else ref
    except Exception:
        return ref


def _next_run(trigger):
    """Next fire time for a trigger, in SERVER-LOCAL time, or None.

    Server-local because that is the clock the scheduler matches against (packet 1185). It used to
    be computed in UTC and rendered with no zone at all, so on any box that is not on UTC the Jobs
    card advertised a time the job would not run at — and gave the reader nothing to notice it by.

    It also goes through the SAME engine the scheduler uses. A preview computed by a second
    implementation is a promise the scheduler never made.
    """
    from corpusfm.server.scheduler import next_fire
    return next_fire(trigger)


def _schedule_fields(cfg) -> dict:
    """The job form's view of a schedule: the structured parts, plus what it currently IS."""
    from corpusfm.server.jobs import schedule as sched
    t = cfg.trigger
    s = t.resolved_schedule() if t is not None else None
    if s is None:
        return {"server_time": "", "weekdays": [], "schedule_summary": "",
                "schedule_needs_update": False, "legacy_cron": ""}
    return {
        "server_time": s.server_time,
        "weekdays": list(s.weekdays),
        "schedule_summary": sched.summary(s),
        "schedule_needs_update": s.needs_update,
        # Shown so a user can see what they had before the model changed. Never interpreted.
        "legacy_cron": s.legacy_cron,
    }


@router.post("/schedule-preview", dependencies=[Depends(require_auth)])
async def schedule_preview(request: Request) -> JSONResponse:
    """The authoritative clock envelope and preview for the job form (packet 1185, Stage E).

    The browser must NOT implement recurrence itself. A second implementation is a second opinion,
    and the one the user reads would be the one that is wrong. So the form asks the server what a
    schedule means and what it will do next, and renders the answer.

    Also carries the server's own clock, because a schedule is meaningless without knowing which
    wall clock it refers to — including, honestly, when that clock is the UTC fallback.
    """
    from corpusfm.server.jobs import schedule as sched
    body = await request.json()
    now = servertime.local_now()
    info = servertime.clock_info()

    days = [str(d).strip().lower() for d in (body.get("weekdays") or []) if str(d).strip()]
    s = sched.Schedule(
        server_time=(body.get("server_time") or "").strip(),
        weekdays=tuple(d for d in sched.WEEKDAYS if d in days),
    )
    errors = sched.validate(s)
    upcoming = [] if errors else sched.next_matches(s, now, count=3)
    return JSONResponse({
        "server_now_text": now.strftime("%Y-%m-%d %H:%M"),
        "server_zone_label": servertime.short_label(info),
        # True only when the box could not tell us its own zone. The form says so in words rather
        # than quietly presenting UTC as if it were local (decision 4).
        "server_time_fallback": info.source == servertime.SOURCE_UTC_FALLBACK,
        "summary": "" if errors else sched.summary(s),
        "errors": errors,
        "next": [{"text": d.strftime("%Y-%m-%d %H:%M"),
                  "label": servertime.short_label(at=d),
                  "iso": d.isoformat()} for d in upcoming],
    })


def _schedule_trigger_from_body(body: dict, job_uuid: str):
    """Build a schedule trigger from a save request. Returns (trigger, errors).

    THE SERVER OWNS `revision` AND `effective_after`, and a client value for either is discarded
    without comment. A client that could author `effective_after` could make its own schedule
    effective in the past and fire during the very save that created it, which is exactly what
    decision 7 ("saving is not running") forbids.

    A schedule whose user-visible parts are UNCHANGED keeps its existing revision. Decision 8: an
    unrelated edit — a tag, a timeout, a Git registration — must not silently restart the schedule's
    clock, which would push the next run out by a day for someone who only renamed a tag.
    """
    from corpusfm.server.jobs import schedule as sched
    from corpusfm.server.jobs.config import JobTrigger
    from corpusfm.server.jobs.store import load_job

    days = [str(d).strip().lower() for d in (body.get("weekdays") or []) if str(d).strip()]
    incoming = sched.Schedule(
        server_time=(body.get("server_time") or "").strip(),
        weekdays=tuple(d for d in sched.WEEKDAYS if d in days),
    )
    errors = sched.validate(incoming)
    if errors:
        return None, errors

    previous = None
    try:
        existing = load_job(job_uuid)
        previous = existing.trigger.resolved_schedule() if existing.trigger is not None else None
    except Exception:
        previous = None

    # `previous.effective_after` must actually EXIST to be worth preserving. A schedule migrated
    # from cron carries neither field, so an unchanged save would have kept those blanks — and a
    # schedule with no `effective_after` is effective always, including the minute the save landed
    # in. The one job most likely to be opened and saved unchanged is exactly the migrated one
    # (found by review).
    unchanged = previous is not None and previous.effective_after and (
        (previous.server_time, tuple(previous.weekdays))
        == (incoming.server_time, tuple(incoming.weekdays)))

    if unchanged:
        final = replace(incoming, revision=previous.revision,
                        effective_after=previous.effective_after)
    else:
        final = replace(incoming, revision=uuid.uuid4().hex,
                        effective_after=datetime.now(timezone.utc).isoformat())
    return JobTrigger(type="schedule", schedule=final), []


def _trigger_of(row: dict):
    """Rebuild a Schedule from an already-composed job row, so the card's "next run" and the
    scheduler's decision come from one engine rather than two that agree today.

    `revision` and `effective_after` are deliberately absent: every candidate here is strictly in
    the future, and `effective_after` can only ever suppress the minute a save landed in. Carrying
    server-authored metadata out to a card that has no use for it would be the worse trade.
    """
    from corpusfm.server.jobs import schedule as sched
    return sched.Schedule(
        server_time=row.get("server_time") or "",
        weekdays=tuple(row.get("weekdays") or ()),
        legacy_cron=row.get("legacy_cron") or "",
    )


def _job_server_ref(cfg) -> str:
    """A job's server context as the canonical ref: 'local' for the co-located pull, else the SERVER
    record uuid. None/'' normalize to 'local' (packet 1015)."""
    return (getattr(cfg.source, "server_ref", None) or "local")


class JobsProjectionUnavailable(RuntimeError):
    """The JOB/Queue projection behind the Jobs gallery could not be read (packet 1369).

    Its message is bounded on purpose: an administrator sees what failed and where to look, never a
    third-party response body, URL or traceback. The full detail goes to the server log.
    """


def _jobs_by_file(server_ref: str = "local") -> dict[str, list]:
    """Map file_name -> its jobs for ONE server context (packet 1015: jobs are keyed by (server, file);
    the Jobs page shows one server at a time). Includes only jobs whose server_ref matches. One
    list_jobs() read grouped + a credential/verify overlay. A file is 'automated' when non-empty.

    Each job carries a `running` flag from its in-flight [pull] QUEUE record (packet 086).

    RAISES `JobsProjectionUnavailable` when the JOB or QUEUE read fails. It used to swallow every
    exception into `{}`, which the whole page above it then read as "this server has no automated
    files" — an authoritative-looking empty gallery standing in for a storage outage, and for the
    deliberate published-install refusal too (packet 1369).
    """
    from corpusfm.server.jobs.store import JobsStoreUnavailable
    from corpusfm.storage.repos import JobReadUnavailable

    out: dict[str, list] = {}
    try:
        from corpusfm.server.jobs.store import list_jobs_with_overlay
        from corpusfm.server.jobs.run_queue import active_runs
        from corpusfm.storage import get_backend
        # JOIN BY UUID (packet 1372-02): duplicate names are ordinary now, and a name join lit
        # every same-named job when one ran.
        running_uuids = {m.get("job_uuid", "") for m in active_runs(get_backend()) if m.get("job_uuid")}
        for cfg, st, cred in list_jobs_with_overlay(strict=True):
            if not cfg.file:
                continue
            if _job_server_ref(cfg) != server_ref:
                continue
            t = cfg.trigger
            p = cfg.process
            out.setdefault(cfg.file, []).append({
                "id": getattr(cfg, "id", "") or "",     # the job's identity; every row action uses it
                "name": cfg.name,
                "uuid": getattr(cfg, "id", "") or "",   # kept: existing JS reads `uuid` (packet 1143)
                "trigger_summary": _trigger_summary(cfg),
                "trigger_type": t.type if t else "",
                **_schedule_fields(cfg),
                "index_on_ingest": p.index_on_ingest,
                "summarize_on_ingest": p.summarize_on_ingest,
                "export_timeout_s": cfg.source.export_timeout_s,
                "enable_artifact_limit": p.enable_artifact_limit,
                "max_artifacts": p.max_artifacts,
                "git_regs": list(p.git_export.registrations) if p.git_export else [],
                "tags": list(cfg.tags or []),
                "has_credential": cred["has_credential"],
                "account": cred["account"],
                "verified": cred["verified"],
                "verify_reason": cred["verify_reason"],
                "last_run_ts": st.last_run_ts or "",
                "last_status": st.last_status or "",
                "running": (getattr(cfg, "id", "") or "") in running_uuids,
            })
    except (JobsStoreUnavailable, JobReadUnavailable) as exc:
        # CORPUSfm's own prose, already bounded and already administrator-facing ("this installation
        # is published but has composed no corpus"). It carries nothing from a third party, so it
        # travels verbatim — losing that refusal was the worst case of the swallow.
        raise JobsProjectionUnavailable(str(exc)) from exc
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error(
            "Jobs projection read failed for server_ref=%r", server_ref, exc_info=True)
        raise JobsProjectionUnavailable(
            "The job list could not be read from storage "
            f"({type(exc).__name__}). See the CORPUSfm server log for detail.") from exc
    return out


def _discover_for_server(server_ref: str) -> dict:
    """The live hosted-file INVENTORY for a server context, keyed by bare name (no .fmp12).

    ``{name: closed}`` where ``closed`` is True / False / **None when FMS reported no runtime status**
    (packet 1330). None is not closed: an absent status asserts nothing rather than painting a live
    file gray. Local → the co-located Admin API PKI (``discover_files``); a remote SERVER record → its
    fmsadmin Admin-API list (packet 1015). Raises on failure (bad creds / unreachable / no PKI) so the
    caller can distinguish 'scan failed' from 'host empty'. One authenticate/list/logout either way —
    no additional Admin API session."""
    if server_ref in ("", "local"):
        from corpusfm.server.file_discovery import discover_files
        return {d.name: d.closed for d in discover_files()}
    from corpusfm.server import remote_servers
    from corpusfm.server.fms_client import list_admin_hosted_databases
    from corpusfm.server.file_discovery import strip_ext
    srv = remote_servers.get_server_by_id(server_ref)
    if srv is None:
        raise RuntimeError("Unknown remote server.")
    inventory = {}
    for rec in list_admin_hosted_databases(srv.host, srv.account, srv.password,
                                           verify_ssl=srv.verify_ssl):
        name = strip_ext(rec.filename)
        if not name:
            continue
        inventory[name] = None if rec.open is None else (not rec.open)
    return inventory


def _base_file_rows(*, live: bool, server_ref: str = "local",
                    jobs_by_file: "dict[str, list] | None" = None) -> "tuple[list[dict], str]":
    """The Jobs-page base rows for ONE server context (packet 1015). Returns (rows, error).
    ``live=False`` (page load, NO Admin API): the files that have jobs on this server, from the JOBS
    read. ``live=True`` (Refresh): the live hosted-file list (local PKI or the remote server's fmsadmin
    Admin API) unioned with the job-having files. is_self is a local-only, name-derived label.

    ``jobs_by_file`` is the request's already-built projection. Both this and `_attach_jobs` used to
    call `_jobs_by_file()` for themselves, so one response rebuilt it twice (packet 1368)."""
    from corpusfm.server.file_discovery import is_self_name
    is_local = server_ref in ("", "local")
    #: name -> (missing, closed). The two are INDEPENDENT facts, composed only on a successful live
    #: scan: `missing` means a job target is absent from the inventory, `closed` means a present
    #: record reported a non-open runtime status. A missing row is never also inferred closed, and a
    #: page-load or failed-scan row asserts neither (packet 1330).
    names: dict = {}
    for fn in (_jobs_by_file(server_ref) if jobs_by_file is None else jobs_by_file):
        names.setdefault(fn, (False, None))  # page load: presence unknown → assume present (no Admin API)
    err = ""
    if live:
        # Distinguish a scan that SUCCEEDED (even if it returned zero files → the host genuinely has
        # nothing) from one that FAILED (Admin API down / bad creds → unknown). A *successful* scan is
        # authoritative: a job-having file not in it is `missing`. A failed scan leaves status
        # unasserted (don't false-flag missing on a blip) but surfaces the reason to the user.
        scan_ok = False
        discovered: dict = {}
        try:
            discovered = _discover_for_server(server_ref)
            scan_ok = True     # a scan that RAN — even if it returned zero files (host genuinely empty)
        except Exception as exc:
            err = str(exc)     # bad fmsadmin creds / unreachable / no PKI — tell the user
        if scan_ok:
            for n, closed in discovered.items():
                names[n] = (False, closed)
            for n in list(names):
                if n not in discovered:
                    names[n] = (True, None)   # not hosted → missing, and never also inferred closed
    rows = sorted(
        ({"name": n, "missing": missing, "closed": bool(closed),
          "is_self": (is_local and is_self_name(n))}
         for n, (missing, closed) in names.items()),
        key=lambda r: r["name"].lower())
    return rows, err


def _aggregate_job_tags(jobs: list[dict]) -> list[dict]:
    """The deduplicated UNION of a file's job features, as passive {label, kind} tags —
    one tag per distinct feature across ALL the file's jobs (never one-per-job). Purely
    informational; the card renders them as non-interactive colored badges."""
    tags: list[dict] = []
    triggers = {j.get("trigger_type") for j in jobs}
    for t in ("schedule", "webhook", "manual"):          # canonical order
        if t in triggers:
            tags.append({"label": t, "kind": "trigger"})
    if any(j.get("index_on_ingest") for j in jobs):
        tags.append({"label": "index", "kind": "process"})
    keeps = {j.get("max_artifacts") for j in jobs if j.get("enable_artifact_limit")}
    if keeps:
        tags.append({"label": f"keep {next(iter(keeps))}" if len(keeps) == 1 else "retention",
                     "kind": "process"})
    seen: list[str] = []
    for j in jobs:
        for rname in (j.get("git_regs") or []):
            if rname and rname not in seen:
                seen.append(rname)
    for rname in seen:
        tags.append({"label": f"git: {rname}", "kind": "git"})
    return tags


def _attach_jobs(rows: list[dict], server_ref: str = "local",
                 jobs_by_file: "dict[str, list] | None" = None) -> list[dict]:
    """Fold each file's job count + summary + aggregate feature tags + credential/verify summary
    + last/next-run onto its row (packet 085 U3b: credential/verify are per-JOB — the file card
    shows the summary across its jobs), scoped to ONE server context (packet 1015).

    ``jobs_by_file`` is the request's already-built projection (packet 1368)."""
    by_file = _jobs_by_file(server_ref) if jobs_by_file is None else jobs_by_file
    for r in rows:
        jobs = by_file.get(r["name"], [])
        r["job_count"] = len(jobs)
        r["job_tags"] = _aggregate_job_tags(jobs)
        r["running"] = any(j.get("running") for j in jobs)
        # Credential/verify are per-job now: the file is "ready" when it has jobs and every one
        # is verified; "needs credentials" when any job lacks one.
        r["has_credential"] = bool(jobs) and all(j.get("has_credential") for j in jobs)
        r["needs_credential"] = any(not j.get("has_credential") for j in jobs)
        r["all_verified"] = bool(jobs) and all(j.get("verified") for j in jobs)
        if not jobs:
            r["job_summary"] = ""
        elif len(jobs) == 1:
            r["job_summary"] = jobs[0]["trigger_summary"]
        else:
            r["job_summary"] = f"{len(jobs)} jobs"
        # Most recent run across the file's jobs.
        runs = [j for j in jobs if j["last_run_ts"]]
        if runs:
            latest = max(runs, key=lambda j: j["last_run_ts"])
            r["last_run"] = _fmt_ts(latest["last_run_ts"])
            r["last_status"] = latest["last_status"]
        else:
            r["last_run"] = ""
            r["last_status"] = ""
        # Soonest upcoming scheduled run across the file's jobs.
        nexts = [n for n in (_next_run(_trigger_of(j)) for j in jobs
                             if j["trigger_type"] == "schedule") if n]
        # Labelled with the server's clock. This one string is not converted to browser-local like
        # the rest of the UI: it is a SCHEDULE, and the server's wall clock is what it means. The
        # label is taken AT that future instant, not now — a summer box previewing a December run
        # would otherwise stamp "PDT" on a time that will happen in PST.
        if nexts:
            soonest = min(nexts)
            r["next_run"] = (f"{soonest.strftime('%Y-%m-%d %H:%M')} "
                             f"{servertime.short_label(at=soonest)}")
        else:
            r["next_run"] = ""
    return rows


def _server_ref_param(request: Request) -> str:
    """The Jobs-page server context from the query string (packet 1015). '' / 'local' → co-located."""
    return (request.query_params.get("server_ref") or "local").strip() or "local"


@router.get("/files", dependencies=[Depends(require_auth)])
async def list_files_route(request: Request) -> JSONResponse:
    """The Jobs page composition for ONE server context (packet 1015; ``?server_ref=``). READ-ONLY —
    no live discovery (the FMS Admin API session pool is small, error 956): the files CORPUSfm knows
    are the ones with jobs on this server (the JOBS read), each overlaid with its job/credential/verify
    state. Use POST /api/files/refresh to also pull the live hosted-file list."""
    try:
        ref = _server_ref_param(request)
        by_file = _jobs_by_file(ref)      # built ONCE per request (packet 1368)
        rows, err = _base_file_rows(live=False, server_ref=ref, jobs_by_file=by_file)
        return JSONResponse({"files": _attach_jobs(rows, ref, jobs_by_file=by_file),
                             **({"error": err} if err else {})})
    except Exception as exc:
        return JSONResponse({"files": [], "error": str(exc)}, status_code=200)


@router.post("/files/refresh", dependencies=[Depends(require_auth)])
async def refresh_files_route(request: Request) -> JSONResponse:
    """Live-discover hosted files for the selected server (``?server_ref=``): local → the co-located
    Admin API PKI; a remote server → its fmsadmin Admin API (packet 1015). Unioned with the job-having
    files, each overlaid with its job state. User-initiated (Refresh); nothing is persisted."""
    try:
        ref = _server_ref_param(request)
        by_file = _jobs_by_file(ref)      # built ONCE per request (packet 1368)
        rows, err = _base_file_rows(live=True, server_ref=ref, jobs_by_file=by_file)
        return JSONResponse({"files": _attach_jobs(rows, ref, jobs_by_file=by_file),
                             **({"error": err} if err else {})})
    except Exception as exc:
        return JSONResponse({"files": [], "error": str(exc)}, status_code=200)


def _job_gate():
    """`None` when JOB work may proceed; a 503 JSONResponse when it may not (packet 1372-02, R8).

    Every JOB mutation and execution route calls this BEFORE it writes or enqueues. Until startup
    has strictly read back `ProjectionVersion == 2`, the JOB table may still be keyed the old way and
    this build addresses it only by UUID — so a write would either fail confusingly or land a row
    (a blank-`UUIDJob` Job Run) that then blocks the very conversion that would fix it.

    Reading stays available: the job list, the detail pop-over and the catalog are all unaffected.
    503 rather than 409 because this is a temporary service condition an administrator resolves by
    restarting, not a conflict with the request.
    """
    from corpusfm.server.jobs.store import JobWorkUnavailable, assert_job_work_permitted
    try:
        assert_job_work_permitted()
    except JobWorkUnavailable as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=503)
    return None


@router.post("/jobs/{job_uuid}/tags", dependencies=[Depends(require_auth)])
async def set_job_tags_route(job_uuid: str, request: Request) -> JSONResponse:
    """Set a JOB's configured artifact tags — applied at landing to every artifact the job produces.

    **The path used to be `/files/{name}/tags` and `{name}` was really a JOB NAME** (packet 085 U3b
    moved the tags onto the job and the URL was kept "for stability"). A path that says one thing and
    means another is exactly what this cutover removes, so it now names what it addresses.
    """
    from corpusfm.server.jobs.store import load_job, save_job
    body = await request.json()
    tags = body.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    tags = [t for t in (str(x).strip() for x in tags) if t]
    guard = _job_gate()
    if guard is not None:
        return guard
    try:
        cfg = load_job(job_uuid)
    except KeyError:
        return JSONResponse({"ok": False, "error": f"No job with id {job_uuid}."}, status_code=404)
    cfg.tags = tags or None
    save_job(cfg, overwrite=True)
    return JSONResponse({"ok": True, "tags": tags})


@router.post("/jobs/{job_uuid}/credential", dependencies=[Depends(require_auth)])
async def set_job_credential_route(job_uuid: str, request: Request) -> JSONResponse:
    """Store or REPLACE a JOB's own FileMaker account + password (per-job, encrypted in the JOB
    record's CredentialData container — never a shared or per-file secret).

    **There is no delete route any more (packet 1372-02).** A retained job may not be left without
    the credential it needs to do the one thing it exists for; replacement is always available, and
    deleting the job cascades the container.
    """
    from corpusfm.server.jobs.store import set_job_credential
    body = await request.json()
    account = (body.get("account") or "").strip()
    password = body.get("password") or ""
    if not account or not password:
        return JSONResponse({"ok": False, "error": "account and password are required"},
                            status_code=400)
    guard = _job_gate()
    if guard is not None:
        return guard
    if not set_job_credential(job_uuid, account, password):
        return JSONResponse({"ok": False, "error": f"No job with id {job_uuid}."}, status_code=404)
    return JSONResponse({"ok": True})


@router.post("/jobs/{job_uuid}/verify", dependencies=[Depends(require_auth)])
async def verify_job_route(job_uuid: str) -> JSONResponse:
    """Run the readiness probe for one JOB (its own credential against its file) and record the
    verdict on the JOB record (IsVerified)."""
    from corpusfm.server.file_readiness import verify_job
    guard = _job_gate()
    if guard is not None:
        return guard
    return JSONResponse(verify_job(job_uuid))


# ── Jobs attached to a tracked file ───────────────────────────────────────────
# A file's automation: each job is a stored JobConfig with .file == the file, one
# trigger, the co-located pull derived (credential inherited from the file store).

import threading
import uuid as _uuid

_run_tasks: dict[str, dict] = {}
_run_lock = threading.Lock()


def _trigger_summary(cfg) -> str:
    t = cfg.trigger
    if t is None:
        return "no trigger"
    if t.type == "schedule":
        from corpusfm.server.jobs import schedule as sched
        s = t.resolved_schedule()
        return sched.summary(s) if s is not None else "no schedule"
    return t.type


@router.get("/jobs/locate", dependencies=[Depends(require_auth)])
async def job_locate(job_uuid: str = "") -> JSONResponse:
    """Where does this job live? → ``{ok, file, name, server_ref}`` (packet 1143).

    The Jobs page is organised by FILE, so a link that knows only a job's uuid — the Runs page's
    "Job" button — needs the file to open. Resolving by uuid rather than name is the whole point:
    a name can be reused by a later job, a uuid cannot."""
    ju = (job_uuid or "").strip()
    if not ju:
        return JSONResponse({"ok": False, "error": "job_uuid is required"}, status_code=400)
    try:
        from corpusfm.server.jobs.store import list_jobs
        for cfg, _err in list_jobs():
            if cfg is not None and (getattr(cfg, "id", "") or "") == ju:
                return JSONResponse({"ok": True, "file": cfg.file or "", "name": cfg.name,
                                     "server_ref": _job_server_ref(cfg)})
        return JSONResponse({"ok": False, "error": "No job with that id — it may have been deleted."},
                            status_code=404)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/files/{name}/jobs", dependencies=[Depends(require_auth)])
async def file_jobs_list(name: str, request: Request) -> JSONResponse:
    """List the jobs attached to one file, scoped to the selected server context (``?server_ref=``,
    packet 1015 — jobs are keyed by (server, file)), with last-run state + each job's export method.

    Reads through packet 1368's `list_jobs_with_overlay()` — the SAME projection the two file-list
    endpoints take, not a second one. Every matching job used to be read back three more times
    (`job_verify_state` / `has_job_credential` / `job_account_name`) for four values the enumeration
    had already returned in its `JSONOfRecord`, costing `3 + 3J` reads for `J` attached jobs; it is a
    flat 3 now (packet 1371).

    Deliberately NOT `strict=True`. Packet 1369 made the strict read opt-in and took it for the Jobs
    gallery alone; this endpoint keeps the degraded-empty render it already had, because changing
    that would change this response."""
    try:
        from corpusfm.server.jobs.store import list_jobs_with_overlay
        from corpusfm.server.jobs.config import content_for_modes, default_method
        from corpusfm.server.jobs.run_queue import active_runs
        from corpusfm.storage import get_backend
        ref = _server_ref_param(request)
        is_remote = ref not in ("", "local")
        # JOIN BY UUID (packet 1372-02). It used to join on `job_name`, so two jobs sharing a name
        # both lit up when one ran — and duplicate names are now ordinary.
        running_uuids = {m.get("job_uuid", "") for m in active_runs(get_backend()) if m.get("job_uuid")}
        rows = []
        for cfg, st, cred in list_jobs_with_overlay():
            if cfg.file != name or _job_server_ref(cfg) != ref:
                continue
            t = cfg.trigger
            rows.append({
                "id": cfg.id,
                "name": cfg.name,
                "trigger_type": t.type if t else "",
                **_schedule_fields(cfg),
                "trigger_summary": _trigger_summary(cfg),
                "index_on_ingest": cfg.process.index_on_ingest,
                "summarize_on_ingest": cfg.process.summarize_on_ingest,
                "export_timeout_s": cfg.source.export_timeout_s,
                "enable_artifact_limit": cfg.process.enable_artifact_limit,
                "max_artifacts": cfg.process.max_artifacts,
                "git_regs": ", ".join(cfg.process.git_export.registrations) if cfg.process.git_export else "",
                "git_reg": (cfg.process.git_export.registrations[0]
                            if cfg.process.git_export and cfg.process.git_export.registrations else ""),
                "git_repo": getattr(cfg.process.git_export, "repo", "") if cfg.process.git_export else "",
                "git_content": content_for_modes(getattr(cfg.process.git_export, "modes", None))
                               if cfg.process.git_export else "both",
                "server_ref": _job_server_ref(cfg),
                "server_name": _server_display_name(getattr(cfg.source, "server_ref", None)),
                # Export method (the addon script) + its method-specific option, for the job editor.
                "script": getattr(cfg.source, "script", None) or default_method(is_remote),
                "file_path": getattr(cfg.source, "file_path", None) or "",
                "webhook_token": cfg.webhook_token or "",
                "tags": list(cfg.tags or []),
                "has_credential": cred["has_credential"],
                "account": cred["account"],
                "verified": cred["verified"],
                "verify_reason": cred["verify_reason"],
                "last_run": (st.last_run_ts.replace("T", " ")[:19] + " UTC") if st.last_run_ts else "",
                "last_status": st.last_status or "",
                "last_error": st.last_error or "",
                "running": (cfg.id or "") in running_uuids,
            })
        rows.sort(key=lambda r: r["name"].lower())
        return JSONResponse({"jobs": rows})
    except Exception as exc:
        return JSONResponse({"jobs": [], "error": str(exc)}, status_code=200)


@router.post("/files/{name}/jobs", dependencies=[Depends(require_auth)])
async def file_job_save(name: str, request: Request) -> JSONResponse:
    """Create or update a job attached to a tracked file. The source is derived
    (co-located pull against this file); the credential is inherited from the file store."""
    try:
        body = await request.json()
        from corpusfm.server.jobs.store import save_job, generate_token, load_job
        from corpusfm.server.jobs.config import (
            JobConfig, JobProcess, JobGitExport, JobTrigger, JobSource,
            modes_for_content, default_method, source_type_for_method,
            LOCAL_METHODS, REMOTE_METHODS, _coerce_timeout,
        )

        job_name = (body.get("name") or "").strip()
        if not job_name:
            return JSONResponse({"ok": False, "error": "job name is required"}, status_code=400)
        # IDENTITY COMES FROM THE BODY, NOT THE NAME (packet 1372-02). A create omits `id` and
        # receives the server-minted one; an edit carries the id it is editing, and that id is
        # immutable — there is no rename problem to solve any more, because a name is not identity.
        submitted_id = (body.get("id") or "").strip()
        is_new = not submitted_id
        guard = _job_gate()
        if guard is not None:
            return guard

        # THE JOB'S UUID. A create mints one; an edit uses the submitted id and must resolve it.
        #
        # The old code looked the job up by the SUBMITTED NAME, so a changed name missed, minted a
        # fresh uuid and wrote a SECOND record — orphaning the original's credential, history and
        # artifacts. It closed that by forbidding renames outright. **Renaming is now ordinary**:
        # identity is the id in the body, the name is a label, and two jobs may share one.
        import uuid as _uuid
        if is_new:
            job_id = str(_uuid.uuid4())
        else:
            job_id = submitted_id
            try:
                load_job(job_id)
            except KeyError:
                return JSONResponse({"ok": False, "error": f"No job with id {job_id}."},
                                    status_code=404)


        # Server context (packet 1015): the Jobs-page HEADER selection, carried on the job as
        # ``server_ref``. "local" (or unset) = the co-located server; a SERVER record uuid = a remote
        # server. The host is derived (co-located config, or the SERVER record) — never entered here.
        server_ref = (body.get("server_ref") or "").strip() or "local"
        is_remote = server_ref != "local"
        if is_remote:
            from corpusfm.server import remote_servers
            srv = remote_servers.get_server_by_id(server_ref)
            if srv is None:
                return JSONResponse({"ok": False, "error": "Unknown remote server."}, status_code=400)
            host = srv.host
        else:
            try:
                from corpusfm.server.fms_transport import colocated
                host = colocated().host
            except Exception as exc:
                return JSONResponse({"ok": False, "error": f"Installed FileMaker transport unavailable: {exc}"},
                                    status_code=409)

        # Export method (the addon script) — must be one valid for the server context; else the default.
        method = (body.get("script") or "").strip()
        allowed = REMOTE_METHODS if is_remote else LOCAL_METHODS
        if method not in allowed:
            method = default_method(is_remote)
        stype = source_type_for_method(method, is_remote=is_remote)
        # A remote PostToServer job (stype fms_push) POSTs its schema + a one-time token back to us, so
        # its callback MUST be public — validate the EFFECTIVE callback (the field, else the deployment
        # default) with require_public and reject a loopback result AT SAVE (packet 1055), not silently at
        # the next run. A blank field is kept blank (derived at run time) only when the default is public.
        # A remote PostToServer job POSTs its schema + a one-time token back to us, so a usable
        # callback must exist BEFORE the job can be saved — rejected here, not silently at the next
        # run. The callback itself lives on the SERVER record (packet 1219): it is the address from
        # that peer's perspective, so two remote servers on different networks can each be right.
        is_remote_push = is_remote and stype == "fms_push"
        if is_remote_push:
            try:
                from corpusfm.server import remote_servers
                from corpusfm.app.web.deployment import external_base
                srv = remote_servers.get_server_by_id(server_ref) if server_ref else None
                eff = (getattr(srv, "callback_url", "") or "").strip()
                if eff:
                    _validate_callback_url(eff, require_public=True)
                else:
                    eb = external_base()
                    if not eb.value:
                        raise ValueError(
                            eb.error or "this remote server has no callback address — set one on the "
                            "server under Settings, or set this install's address on Settings → MCP")
            except ValueError as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        source = JobSource(
            type=stype, server=host, databases=[name], script=method, server_ref=server_ref,
            file_path=((body.get("file_path") or "").strip() or None),
            export_timeout_s=_coerce_timeout(body.get("export_timeout_s")),   # packet 1154
        )

        ttype = (body.get("trigger_type") or "manual").strip()
        if ttype == "schedule":
            trigger, sched_errors = _schedule_trigger_from_body(body, job_id)
            if sched_errors:
                return JSONResponse({"ok": False, "error": "; ".join(sched_errors)}, status_code=400)
        else:
            trigger = JobTrigger(type=ttype)

        token = None
        if ttype == "webhook":
            try:
                existing = None if is_new else load_job(job_id)
            except KeyError:
                existing = None
            token = (existing.webhook_token if existing and existing.webhook_token else generate_token())

        git_export = None
        # Single-registration model: prefer git_reg; fall back to the legacy comma list.
        single = (body.get("git_reg") or "").strip()
        regs = [single] if single else [r.strip() for r in (body.get("git_regs") or "").split(",") if r.strip()]
        if regs:
            git_export = JobGitExport(
                registrations=regs,
                repo=(body.get("git_repo") or "").strip(),
                modes=modes_for_content(body.get("git_content")),
            )

        _tags = body.get("tags") or []
        if isinstance(_tags, str):
            _tags = [t.strip() for t in _tags.split(",") if t.strip()]
        _tags = [t for t in (str(x).strip() for x in _tags) if t]

        cfg = JobConfig(
            name=job_name,
            id=job_id,
            file=name,
            source=source,
            process=JobProcess(
                git_export=git_export,
                index_on_ingest=bool(body.get("index_on_ingest", True)),
                summarize_on_ingest=bool(body.get("summarize_on_ingest", True)),
                enable_artifact_limit=bool(body.get("enable_artifact_limit", False)),
                max_artifacts=int(body.get("max_artifacts", 10)),
            ),
            triggers=[trigger],
            webhook_token=token,
            description=(body.get("description") or "").strip() or None,
            tags=_tags or None,
        )
        from corpusfm.server.jobs.validator import validate_job
        verrs = validate_job(cfg)
        if verrs:
            return JSONResponse({"ok": False, "error": "; ".join(verrs)}, status_code=400)

        # A CREDENTIALLESS JOB IS A VALID INCOMPLETE DRAFT (developer ruling, packet 1372
        # waterfall correction). An earlier draft of 1372-02 refused to create one, on the reasoning
        # that "the security price of making a job is knowing the credentials". That made a job the
        # user was still assembling impossible to save, and it is not this route's call to make: a
        # credential is required where it is USED — verification and execution — and each of those
        # refuses clearly on its own behalf.
        #
        # Half a credential is still a mistake worth naming, and naming it HERE is right: this route
        # is the entry boundary, and the entry boundary is where data is policed. The storage adapter
        # underneath stores what it is given and describes what it holds.
        account = (body.get("account") or "").strip()
        password = body.get("password") or ""
        if bool(account) != bool(password):
            return JSONResponse(
                {"ok": False, "error": "supply both an account and a password, or neither to keep "
                                       "the existing credential"}, status_code=400)

        save_job(cfg, overwrite=not is_new)
        if account and password:
            from corpusfm.server.jobs.store import set_job_credential
            try:
                set_job_credential(job_id, account, password)
            except Exception as exc:
                # The job is KEPT. A credential that would not store no longer leaves a forbidden
                # state — it leaves a draft, which is a state the product now supports — and deleting
                # the job the user just asked for would destroy more than it repaired. Say what
                # happened instead, and leave the job to be completed.
                return JSONResponse(
                    {"ok": False, "id": job_id,
                     "error": f"the job was created, but its credential could not be stored ({exc}). "
                              "It is saved without one; add the credential to run it."},
                    status_code=500)
        return JSONResponse({"ok": True, "id": job_id})
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.delete("/jobs/{job_uuid}", dependencies=[Depends(require_auth)])
async def job_delete(job_uuid: str) -> JSONResponse:
    guard = _job_gate()
    if guard is not None:
        return guard
    try:
        from corpusfm.server.jobs.store import delete_job
        # `delete_job` answers whether the job EXISTED. Discarding that made "Delete all jobs"
        # report success for rows it had not deleted, which is the shape of report that hides a
        # partial failure behind a green banner.
        if not delete_job(job_uuid):
            return JSONResponse({"ok": False, "error": f"No job with id {job_uuid}."},
                                status_code=404)
        return JSONResponse({"ok": True})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.post("/jobs/{job_uuid}/run", dependencies=[Depends(require_auth)])
async def job_run(job_uuid: str) -> JSONResponse:
    """Run a job now: enqueue a Job Run QUEUE record and return its id as the task_id the UI polls.

    A manual run never dedups — it always enqueues, queueing behind any in-flight run of the same
    file. **It resolves the job FIRST and enqueues with that job's UUID**, so no path here can
    produce a Queue row with a blank `UUIDJob`: an unresolvable id is a 404 before anything is
    written, and the gate above refuses before that.
    """
    from starlette.concurrency import run_in_threadpool

    guard = _job_gate()
    if guard is not None:
        return guard

    def _enqueue():
        from corpusfm.server import queue_handlers
        from corpusfm.server.jobs.store import load_job
        from corpusfm.storage import get_backend
        cfg = load_job(job_uuid)          # KeyError -> 404 below, nothing written
        qid, run_id = queue_handlers.enqueue_job_run(
            get_backend(), job_name=cfg.name, job_uuid=cfg.id,
            file_name=getattr(cfg, "file", "") or "", trigger="manual")
        with _run_lock:
            # The durable run id is what makes the outcome resolvable after this process restarts
            # (packet 1149); the in-memory entry is only a fast path.
            _run_tasks[qid] = {"job_uuid": job_uuid, "name": cfg.name, "run_id": run_id}
        return qid, run_id

    try:
        qid, run_id = await run_in_threadpool(_enqueue)
        return JSONResponse({"ok": True, "task_id": qid, "run_id": run_id})
    except KeyError:
        return JSONResponse({"ok": False, "error": f"No job with id {job_uuid}."}, status_code=404)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)


@router.get("/files/jobs/run-status/{task_id}", dependencies=[Depends(require_auth)])
async def file_job_run_status(task_id: str, run_id: str = "") -> JSONResponse:
    """Poll a manual run by its QUEUE record id. present+non-failed → running; present+failed →
    error (Outcome); gone → resolve the DURABLE run record.

    Packet 1149: a gone queue row used to fall back to a process-local dict, and to ``{"status":
    "ok"}`` when that dict had no entry — so a web restart mid-run made every finished run report
    success, including one that errored. The queue row is also gone after a *deletion*, not only a
    success. Never infer an outcome from an absence: the run_id carried in the payload resolves the
    HISTORY row, which spans both the live and terminal phases."""
    from starlette.concurrency import run_in_threadpool

    def _status() -> dict:
        from corpusfm.storage import get_backend
        from corpusfm.storage import queue_record as Q
        from corpusfm.storage.repos import queue_repo
        backend = get_backend()
        repo = queue_repo(backend)
        row = repo.get(task_id) if repo is not None else None
        if row is not None:
            if Q.is_failed(row.jor):
                return {"status": "error", "error": row.jor.get("Outcome", "")}
            return {"status": "running"}
        with _run_lock:
            entry = _run_tasks.get(task_id) or {}
        rid = run_id or entry.get("run_id", "")
        if rid:
            from corpusfm.server.history import get_run_record
            rec = get_run_record(backend, rid)
            if rec is not None:
                return {"status": rec.status or "ok", "error": rec.error or ""}
        job_uuid = entry.get("job_uuid", "")
        if not job_uuid:
            return {"status": "unknown", "error": "This run could not be resolved."}
        from corpusfm.server.jobs.state import read_state
        st = read_state(job_uuid)
        return {"status": st.last_status or "ok", "error": st.last_error or ""}

    return JSONResponse(await run_in_threadpool(_status))
