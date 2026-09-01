"""Runs history API.

Job *creation/editing* moved to the file-centric model: jobs are authored in the Files
(Jobs) page pop-over via /api/files/{file}/jobs. The old hand-authored-job endpoints
(save/detail/list/run/duplicate/trigger) were retired with that page. This module now
serves only the run-history ledger that the Runs page reads.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from corpusfm.app.web.auth import require_auth

router = APIRouter()


@router.get("/runs/list", dependencies=[Depends(require_auth)])
def runs_list(
    request: Request,
    page: int = 1,
    per_page: int = 50,
    job_uuid: str = "",
    status: str = "",
    trigger: str = "",
) -> JSONResponse:
    try:
        from corpusfm.server.jobs.store import list_jobs, default_jobs_dir
        from corpusfm.server.history import list_all_runs
        from corpusfm.storage import get_backend

        jobs_dir    = default_jobs_dir()
        backend     = get_backend()

        pairs = list_jobs(jobs_dir)

        # Enumerate RUNS, not live job configs (packet 1149). Iterating configs silently dropped the
        # history of a deleted job even though its HISTORY rows were intact — and a deleted job's
        # failures are exactly what someone comes here to find. Each run carries its own frozen
        # job_name, so no run needs its job to still exist in order to render.
        runs = list_all_runs(backend, limit=2000)

        # Record UUIDs whose artifact is actually present (packet 085 U3f — a run's archive_path
        # is now the produced record's UUID), backend-agnostic: on the FM backend artifacts live
        # in a container (nothing on disk), so a disk probe would hide the Diff button on every
        # run. Keyed off the runs' OWN archive_paths rather than the live job list, so a deleted
        # job's surviving artifacts still resolve.
        present_artifacts: set = set()
        uuid_to_file: dict = {}   # record UUID → FM FileName, for the run row's display name
        refs = [r.archive_path for r in runs if r.archive_path]
        eng = getattr(backend, "engine", None)
        resolved = False
        if eng is not None and refs:
            try:
                for r in eng.get_by_keys("STORAGE", sorted(set(refs))):
                    present_artifacts.add(r.key)
                    uuid_to_file[r.key] = r.jor.get("FileName", "")
                resolved = True
            except Exception:
                present_artifacts = set()
                uuid_to_file = {}
        if not resolved:
            try:
                for m in backend.iter_artifact_metas():
                    if getattr(m, "is_schema", False) and getattr(m, "uuid", ""):
                        present_artifacts.add(m.uuid)
                        uuid_to_file[m.uuid] = getattr(m, "file_name", "")
            except Exception:
                pass

        # Dropdown options: live jobs PLUS any job that only exists in history now. Carried as
        # (uuid, name) pairs because the page filters on the uuid — a name is a label, and two
        # jobs can share one (packet 1144).
        job_opts: dict = {}
        for cfg, _e in pairs:
            if cfg is not None:
                job_opts.setdefault(getattr(cfg, "id", "") or "", cfg.name)
        for r in runs:
            if r.job_name:
                job_opts.setdefault(r.job_uuid or "", r.job_name)
        # `job_names` is DISPLAY ONLY and the `job=` name filter is gone (packet 1372-02): two jobs
        # may share a label, so filtering on one would have shown both jobs' runs as one job's.
        job_names: list[str] = [n for n in job_opts.values() if n]

        by_job: dict = {}
        for r in runs:
            by_job.setdefault(r.job_uuid or "", []).append(r)

        all_rows: list[dict] = []
        for ju, group in by_job.items():
            if job_uuid and ju != job_uuid:
                continue
            for i, run in enumerate(group):
                # Closest older successful run OF THE SAME JOB whose artifact is still present.
                prev_path = ""
                for older in group[i + 1:]:
                    if older.status == "ok" and older.archive_path in present_artifacts:
                        prev_path = older.archive_path
                        break

                archive_exists = bool(
                    run.archive_path and run.archive_path in present_artifacts
                )
                all_rows.append({
                    "job_name":         run.job_name or "",
                    "job_uuid":         ju,
                    "ts":               run.ts,
                    "ts_display":       run.ts.replace("T", " ")[:16] + " UTC",
                    "status":           run.status,
                    "trigger":          run.trigger or "",
                    "duration_s":       round(run.duration_s, 1),
                    "archive_path":     run.archive_path or "",   # the produced record's UUID (085 U3f)
                    "file_name":        uuid_to_file.get(run.archive_path or "", ""),
                    "archive_exists":   archive_exists,
                    "prev_archive_path": prev_path,
                    "error":            run.error or "",
                })

        all_rows.sort(key=lambda x: x["ts"], reverse=True)

        if status:
            all_rows = [r for r in all_rows if r["status"] == status]
        if trigger:
            all_rows = [r for r in all_rows if r["trigger"] == trigger]

        total = len(all_rows)
        start = (page - 1) * per_page
        return JSONResponse({
            "runs":      all_rows[start : start + per_page],
            "total":     total,
            "page":      page,
            "per_page":  per_page,
            "pages":     max(1, (total + per_page - 1) // per_page),
            "job_names": sorted(set(job_names)),
            "jobs": sorted(({"uuid": u, "name": n} for u, n in job_opts.items() if u and n),
                           key=lambda j: j["name"].lower()),
        })
    except Exception as exc:
        return JSONResponse({"runs": [], "total": 0, "page": 1, "pages": 1,
                             "job_names": [], "error": str(exc)})


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
        from corpusfm.storage import get_backend
        active = active_runs(get_backend())
        job_names = sorted({m.get("job_name", "") for m in active if m.get("job_name")})
        file_names = sorted({m.get("file_name", "") for m in active if m.get("file_name")})
        return JSONResponse({"running": active, "job_names": job_names, "file_names": file_names})
    except Exception as exc:
        return JSONResponse({"running": [], "job_names": [], "file_names": [], "error": str(exc)})
