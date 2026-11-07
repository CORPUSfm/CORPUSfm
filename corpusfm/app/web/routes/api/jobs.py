"""Runs history API.

Job *creation/editing* moved to the file-centric model: jobs are authored in the Files
(Jobs) page pop-over via /api/files/{file}/jobs. The old hand-authored-job endpoints
(save/detail/list/run/duplicate/trigger) were retired with that page. This module now
serves only the run-history ledger that the Runs page reads.
"""

from __future__ import annotations

import base64
import json
import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()
logger = logging.getLogger(__name__)

_RUNS_UNAVAILABLE = "Unable to load run history"
_RUNNING_UNAVAILABLE = "Unable to read running jobs"


def _acquire_backend():
    """Reaching storage is the storage layer's outcome, so any failure here classifies as unavailable."""
    from corpusfm.server.history import RunHistoryUnavailable
    from corpusfm.storage import get_backend
    try:
        return get_backend()
    except Exception as exc:
        raise RunHistoryUnavailable(f"storage could not be acquired ({type(exc).__name__})") from exc


_RUNS_MAX_PER_PAGE = 100


def _encode_position(position) -> str:
    if not position:
        return ""
    raw = json.dumps(list(position), separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_position(token: str):
    """A position this route handed out, or None when absent. A malformed one raises ValueError."""
    if not token:
        return None
    value = json.loads(base64.urlsafe_b64decode(token.encode("ascii")))
    if not (isinstance(value, list) and len(value) == 2 and all(isinstance(v, str) for v in value)):
        raise ValueError("not a run position")
    return tuple(value)


def _artifact_types(backend, refs: list):
    """``{uuid: Type}`` for the refs that exist, or None if neither read could answer. Keyed read first;
    the persistent catalog answers when that fails. Only an action asks this, never the list."""
    refs = sorted({r for r in refs if r})
    if not refs:
        return {}
    eng = getattr(backend, "engine", None)
    if eng is not None:
        try:
            return {r.key: r.jor.get("Type", "") for r in eng.get_by_keys("STORAGE", refs)}
        except Exception:
            logger.warning("Run action keyed artifact lookup failed", exc_info=True)
    try:
        from corpusfm.server import catalog
        view = catalog.view(backend)
        if view.failed:
            return None
        wanted = set(refs)
        found = {}
        for rec in view.records:
            m = rec.get("meta")
            if m is not None and getattr(m, "uuid", "") in wanted:
                found[m.uuid] = getattr(m, "artifact_type", "") or ""
        return found
    except Exception:
        logger.warning("Run action could not check which artifacts exist", exc_info=True)
        return None


def _catalog_file_names(backend, refs: list) -> dict:
    """``{uuid: FM file name}`` for the row subtitle, from the catalog's memory: no storage read. A
    display nicety, so anything short of an answer simply leaves the subtitle off."""
    try:
        from corpusfm.server import catalog
        view = catalog.view(backend)
        if view.failed:
            return {}
        return {m.uuid: getattr(m, "file_name", "")
                for m in (rec.get("meta") for rec in view.projections_of(refs)) if m is not None}
    except Exception:
        return {}


def _job_options(backend) -> list:
    """Live jobs plus any job that only exists in history now. Page-one only, so Next costs nothing
    here. A failure omits the list, and the page keeps the one it has: the rows are still true."""
    from corpusfm.server.history import run_job_options
    from corpusfm.server.jobs.store import list_jobs
    options: dict = {}
    for cfg, _e in list_jobs():
        if cfg is not None and getattr(cfg, "id", ""):
            options[cfg.id] = cfg.name
    for uuid, name in run_job_options(backend).items():
        options.setdefault(uuid, name)
    return sorted(({"uuid": u, "name": n} for u, n in options.items() if u and n),
                  key=lambda j: j["name"].lower())


@router.get("/runs/list", dependencies=[Depends(require_auth)])
def runs_list(
    request: Request,
    page: int = 1,
    per_page: int = 50,
    job_uuid: str = "",
    status: str = "",
    trigger: str = "",
    after: str = "",
    as_of: str = "",
) -> JSONResponse:
    """One page read from storage. `after` and `as_of` are the continuation the previous page handed
    out; Next and Prev use them, so a newer run can't shift what the next page shows. `page` alone is a
    plain offset for a caller holding no continuation.

    A failure is an error status, never an empty 200: the page cannot tell an empty list from one
    it could not read. A storage read answers 503 and anything else 500, with the detail in the server
    log. No outage header: a real outage reaches the shell through its own poll, and one unreadable
    table must not tell the whole app it can't reach CORPUSfm."""
    from corpusfm.server.history import RunHistoryUnavailable, page_runs
    from corpusfm.server.jobs.store import JobsStoreUnavailable
    try:
        try:
            after_position, as_of_position = _decode_position(after), _decode_position(as_of)
        except (ValueError, TypeError, UnicodeError):
            return JSONResponse({"error": _RUNS_UNAVAILABLE}, status_code=400)
        page = max(1, page)
        per_page = max(1, min(per_page, _RUNS_MAX_PER_PAGE))
        backend = _acquire_backend()
        result = page_runs(backend, job_uuid=job_uuid, status=status, trigger=trigger, per_page=per_page,
                           after=after_position, as_of=as_of_position,
                           skip=0 if after_position else (page - 1) * per_page)

        file_names = _catalog_file_names(backend, [run.archive_path for _k, run in result.items if run.archive_path])
        all_rows: list[dict] = []
        for key, run in result.items:
            all_rows.append({
                "key":              key,
                "job_name":         run.job_name or "",
                "job_uuid":         run.job_uuid or "",
                "run_id":           run.run_id or key,
                "ts":               run.ts,
                "ts_display":       run.ts.replace("T", " ")[:16] + " UTC",
                "status":           run.status,
                "trigger":          run.trigger or "",
                "duration_s":       round(run.duration_s, 1),
                "archive_path":     run.archive_path or "",   # the produced record's UUID (085 U3f)
                "file_name":        file_names.get(run.archive_path or "", ""),
                "error":            run.error or "",
                "source_server":    dict(run.source_server or {}),
            })

        body = {
            "runs":      all_rows,
            "total":     result.total,
            "page":      page,
            "per_page":  per_page,
            "pages":     max(1, (result.total + per_page - 1) // per_page),
            "has_next":  result.has_next,
            "next_after": _encode_position(result.next_after) if result.has_next else "",
            "as_of":     _encode_position(result.as_of),
        }
        if page == 1 and not after_position:
            try:
                body["jobs"] = _job_options(backend)
                # `job_names` is DISPLAY ONLY (packet 1372-02): two jobs may share a label.
                body["job_names"] = sorted({j["name"] for j in body["jobs"]})
            except JobsStoreUnavailable:
                raise
            except Exception:
                logger.warning("Run history could not list its jobs", exc_info=True)
        return JSONResponse(body)
    except (RunHistoryUnavailable, JobsStoreUnavailable):
        logger.error("Run history could not be read from storage", exc_info=True)
        return JSONResponse({"error": _RUNS_UNAVAILABLE}, status_code=503)
    except Exception:
        logger.error("Run history could not be built", exc_info=True)
        return JSONResponse({"error": _RUNS_UNAVAILABLE}, status_code=500)


def _action_refusal(status: int, reason: str, error: str) -> JSONResponse:
    return JSONResponse({"ok": False, "reason": reason, "error": error}, status_code=status)


_LOOKUP_FAILED = "Could not check this run's artifacts just now. Try again."


@router.get("/runs/resolve", dependencies=[Depends(require_auth)])
def run_resolve(request: Request, key: str = "", action: str = "") -> JSONResponse:
    """What a Runs row's Explore or Diff button acts on, resolved when it is clicked and never before.
    Every outcome the page has to tell apart gets its own reason, and the message is written here, so
    no exception text reaches the client. Opening the result still goes through the generate routes,
    which keep their own permission."""
    from corpusfm.artifact.capabilities import DELIVERABLE_TYPES
    from corpusfm.server.history import RunHistoryUnavailable, find_run_predecessor, read_run
    if action not in ("explore", "diff") or not key:
        return _action_refusal(400, "invalid", "That action could not be understood.")
    try:
        backend = _acquire_backend()
        run = read_run(backend, key)
        if run is None:
            return _action_refusal(404, "run_missing", "This run is no longer in the history. Refresh the list.")
        if not run.archive_path:
            return _action_refusal(404, "no_artifact", "This run did not record an artifact.")
        types = _artifact_types(backend, [run.archive_path])
        if types is None:
            return _action_refusal(503, "lookup_failed", _LOOKUP_FAILED)
        if run.archive_path not in types:
            return _action_refusal(404, "artifact_missing", "This run's artifact no longer exists.")
        if types[run.archive_path] in DELIVERABLE_TYPES:
            return _action_refusal(422, "unsupported", "This run's artifact can't be opened this way.")
        if action == "explore":
            return JSONResponse({"ok": True, "artifact": run.archive_path})
        if not run.job_uuid:
            return _action_refusal(422, "no_job_identity",
                                   "This run has no job identity, so no earlier run can be paired with it.")
        def present(refs):
            found = _artifact_types(backend, refs)
            return None if found is None else set(found)
        outcome, earlier, searched = find_run_predecessor(backend, key, run, present)
        if outcome == "found":
            return JSONResponse({"ok": True, "artifact_a": earlier, "artifact_b": run.archive_path})
        if outcome == "none":
            return _action_refusal(404, "no_predecessor", "No earlier successful run of this job has an artifact to compare.")
        if outcome == "incomplete":
            return _action_refusal(422, "search_incomplete", f"The {searched} nearest earlier runs of this job have no "
                                   "artifact left, and the search stopped there. An older one may still exist.")
        return _action_refusal(503, "lookup_failed", _LOOKUP_FAILED)
    except RunHistoryUnavailable:
        logger.error("A run action could not read history", exc_info=True)
        return _action_refusal(503, "lookup_failed", _LOOKUP_FAILED)
    except Exception:
        logger.error("A run action failed", exc_info=True)
        return _action_refusal(500, "failed", "This action failed. See the server log for detail.")


@router.get("/jobs/running", dependencies=[Depends(require_auth)])
def jobs_running(request: Request) -> JSONResponse:
    """The set of currently-active runs — in-flight ``[pull]`` QUEUE records (packet 086).

    Cross-process by design: a scheduled run's pull record is written in the scheduler process while
    this route is served by the web process; both read the same records. Each record's payload carries
    its job_name + file_name, so the Jobs-page (file-centric) cards flip a "Running" badge without a
    second JOBS read.

    SYNC `def` (packet-061/078 invariant): the row read is a bounded indexed engine call."""
    try:
        from corpusfm.server.jobs.run_queue import active_runs
        active = active_runs(_acquire_backend())
        job_names = sorted({m.get("job_name", "") for m in active if m.get("job_name")})
        file_names = sorted({m.get("file_name", "") for m in active if m.get("file_name")})
        return JSONResponse({"running": active, "job_names": job_names, "file_names": file_names})
    except Exception:
        logger.error("Running jobs could not be read", exc_info=True)
        return JSONResponse({"error": _RUNNING_UNAVAILABLE}, status_code=503)
