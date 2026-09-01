"""CLI: corpusfm storage maintenance subcommands.

  migrate-storage : RETIRED no-op. Packet 085 is fresh-install-only — there is no
                    in-place storage-schema migration. A DB behind the shipped schema
                    is handled by the in-app build-mismatch gate ("fresh install
                    required"), not by carrying data across a schema change. Kept as a
                    green no-op so the installer's upgrade step stays stable.
  backfill-latest : reconcile STORAGE.IsLatest across every lineage.
  backfill-storage-projections : assert the FM-side index-projection contract.
  migrate job-identity : the JOB identity conversion (packet 1372-01) as a DIAGNOSIS
                    and RECOVERY surface. Moves every job to its own UUID so the JOB
                    record key, JobConfig.id and the related UUIDJob are one value. Not
                    a schema migration — the FileMaker file, the projection map and
                    db_schema_build.txt are untouched; what changes is which key a job
                    record lives at. ACTIVATION is the SETTING.ProjectionVersion 1 -> 2
                    transition the web service performs at startup; this command never
                    stamps it.

See corpusfm/storage/storage_migration.py (the surviving build-mismatch gate) and
corpusfm/storage/job_identity_conversion.py (the conversion planner/executor).
"""

from __future__ import annotations

import json


def add_parser(subparsers) -> None:
    ps = subparsers.add_parser(
        "migrate-storage",
        help="Retired no-op (085 is fresh-install-only; no in-place storage migration)",
        description="Retired. Packet 085 is fresh-install-only — there is no in-place "
                    "storage-schema migration; a DB behind the shipped schema is handled by "
                    "the in-app build-mismatch gate. Kept as a green no-op for the installer.",
    )
    ps.set_defaults(func=run_storage)

    pl = subparsers.add_parser(
        "backfill-latest",
        help="Reconcile the STORAGE.IsLatest flag across every lineage (job+file)",
        description="Set IsLatest on the newest artifact per (job, file) lineage; manual "
                    "uploads are singletons (always latest). Idempotent.",
    )
    pl.set_defaults(func=run_backfill_latest)

    pp = subparsers.add_parser(
        "backfill-storage-projections",
        help="Assert the FM-side index-projection contract (push the map + re-project every record)",
        description="Push the index-projection map into SETTING and re-project every record so the "
                    "FM-side auto-enter CF derives (and lowercases) every indexed slot from the "
                    "current map. The app no longer writes slot fields — FileMaker owns projection. "
                    "Idempotent. The app also asserts this on every startup; this command lets the "
                    "installer/an admin assert it out of band.",
    )
    pp.set_defaults(func=run_backfill_storage_projections)

    pm = subparsers.add_parser(
        "migrate",
        help="Application data migrations (diagnosis and recovery)",
        description="Application DATA migrations. These are not schema migrations: no FileMaker "
                    "schema, projection-map or db_schema_build change is involved. Activation "
                    "happens at web startup through the SETTING.ProjectionVersion transition; "
                    "these commands inspect and repair, and do not advance the version.",
    )
    msub = pm.add_subparsers(dest="migration")
    pj = msub.add_parser(
        "job-identity",
        help="Move every job to its own UUID (JOB key == JobConfig.id == UUIDJob)",
        description="Idempotent conversion. Plans the complete change before the first write, "
                    "refuses any ambiguous record rather than guessing by name, copies each "
                    "credential ciphertext byte-for-byte, and verifies each replacement before "
                    "deleting the record it replaces. It does NOT advance the projection version: "
                    "the web service does that at startup, once this conversion and the incumbent "
                    "projection refresh have both succeeded.",
    )
    pj.add_argument("--jobs-dir", default=None,
                    help="Convert a local development jobs directory instead of the storage "
                         "backend (developer fixtures).")
    pj.add_argument("--check", action="store_true",
                    help="Report the stored projection version and exit; write nothing. Exit 0 "
                         "only when the corpus is at the version this build requires.")
    pj.add_argument("--plan", action="store_true",
                    help="Classify every job and report the plan; write nothing.")
    pj.set_defaults(func=run_job_identity)


# Outcome exit codes — a contract an operator or a script may branch on:
#   0  the conversion is complete (it ran now, or the corpus was already converted)
#   1  REFUSED before any write — correct the reported condition and re-run
#   2  INCOMPLETE — a write or its verification failed part-way; re-run to resume
#   3  UNAVAILABLE — the JOB table or the stored version could not be read at all
_EXIT = {"ok": 0, "refused": 1, "incomplete": 2, "unavailable": 3}


def _emit(payload: dict) -> None:
    """One machine-readable line, always, so an operator and a script read the same words."""
    print(json.dumps(payload, sort_keys=True))


def run_job_identity(args) -> int:
    """Diagnose or repair the JOB identity conversion out of band.

    THIS IS NOT THE ACTIVATION MECHANISM and deliberately does not stamp the version. Activation is
    the `SETTING.ProjectionVersion` 1 -> 2 transition, which the web service performs at startup and
    which requires the conversion AND the incumbent projection refresh to succeed together. A
    command that stamped the version after doing only half of that would report a corpus as
    converted while its index projections were still mid-transition.

    What it is for: reading the plan before a restart, seeing exactly which record refuses, and
    re-running the idempotent conversion after fixing one. The next web startup then finds the
    conversion `already_current`, completes the refresh, and stamps. `backfill-storage-projections`
    remains the out-of-band way to run the whole assertion.
    """
    from corpusfm.storage import job_identity_conversion as conv
    from corpusfm.storage import fm_registry as reg
    from corpusfm.storage import projections

    jobs_dir = getattr(args, "jobs_dir", None)

    # -- developer fixture directory ------------------------------------------------
    if jobs_dir:
        if getattr(args, "check", False):
            _emit({"result": conv.UNAVAILABLE, "scope": "jobs_dir",
                   "detail": "a local jobs directory carries no projection version; there is "
                             "nothing to check. --check applies to the storage backend."})
            return _EXIT["unavailable"]
        try:
            if getattr(args, "plan", False):
                # THE SAME PLANNER THE RUN USES. An earlier version reported `planned` and exit 0
                # without opening the directory at all, and its replacement had a simplified
                # classification of its own that still disagreed with the run — reporting `planned`
                # for documents `convert_jobs_dir` then refused. One planner, one answer.
                classified = conv.plan_jobs_dir(jobs_dir)
                _emit({"result": "planned", "scope": "jobs_dir", "jobs_dir": str(jobs_dir),
                       "exists": classified["exists"], "jobs": len(classified["paths"]),
                       "actions": {conv.ADOPT: classified["adopt"],
                                   conv.CURRENT: classified["current"]}})
                return _EXIT["ok"]
            out = conv.convert_jobs_dir(jobs_dir)
        except conv.ConversionRefused as exc:
            _emit({"result": conv.REFUSED, "scope": "jobs_dir", "detail": str(exc)})
            return _EXIT["refused"]
        except conv.ConversionIncomplete as exc:
            _emit({"result": conv.INCOMPLETE, "scope": "jobs_dir", "detail": str(exc)})
            return _EXIT["incomplete"]
        out["scope"] = "jobs_dir"
        _emit(out)
        return _EXIT["ok"]

    # -- the storage backend --------------------------------------------------------
    from corpusfm.storage import get_backend
    backend = get_backend()
    stored = projections.stored_projection_version(backend)

    if getattr(args, "check", False):
        # The strict read, reported. `stored` is None for absent, malformed AND unreadable — three
        # different facts that share one consequence, so the word here is deliberately "not
        # current" rather than a guess about which of them it was.
        current = projections.conversion_complete(backend)
        _emit({"result": "ok" if current else conv.REFUSED, "scope": "backend",
               "required_projection_version": reg.PROJECTION_VERSION,
               "stored_projection_version": stored,
               "supported": projections.supported(backend)})
        return _EXIT["ok"] if current else _EXIT["refused"]

    engine = getattr(backend, "engine", None)
    if engine is None:
        _emit({"result": conv.UNAVAILABLE, "scope": "backend",
               "detail": f"{type(backend).__name__} exposes no storage engine to convert."})
        return _EXIT["unavailable"]

    try:
        plan = conv.plan(engine)
    except conv.JobStoreUnreadable as exc:
        _emit({"result": conv.UNAVAILABLE, "scope": "backend", "detail": str(exc)})
        return _EXIT["unavailable"]

    if plan.blocked:
        _emit({"result": conv.REFUSED, "scope": "backend", "jobs": plan.total,
               "blocking": list(plan.blocking),
               "stored_projection_version": stored})
        return _EXIT["refused"]

    if getattr(args, "plan", False):
        _emit({"result": "planned", "scope": "backend", "jobs": plan.total,
               "stored_projection_version": stored,
               "required_projection_version": reg.PROJECTION_VERSION,
               "actions": {a: sum(1 for e in plan.entries if e.action == a)
                           for a in (conv.CURRENT, conv.ADOPT, conv.REKEY, conv.RESUME)}})
        return _EXIT["ok"]

    try:
        out = conv.convert(engine, plan_=plan)
    except conv.ConversionRefused as exc:
        _emit({"result": conv.REFUSED, "scope": "backend", "detail": str(exc)})
        return _EXIT["refused"]
    except conv.ConversionIncomplete as exc:
        _emit({"result": conv.INCOMPLETE, "scope": "backend", "detail": str(exc)})
        return _EXIT["incomplete"]
    except Exception as exc:                                   # noqa: BLE001
        _emit({"result": conv.INCOMPLETE, "scope": "backend",
               "detail": f"{type(exc).__name__}: {exc}"})
        return _EXIT["incomplete"]

    out["scope"] = "backend"
    out["stored_projection_version"] = projections.stored_projection_version(backend)
    out["required_projection_version"] = reg.PROJECTION_VERSION
    out["activation"] = ("the projection version is advanced by the web service at startup; "
                         "restart CORPUSfm to activate")
    _emit(out)
    return _EXIT["ok"]


def run_backfill_storage_projections(args) -> int:
    from corpusfm.storage import get_backend
    from corpusfm.storage import projections
    backend = get_backend()
    if not projections.supported(backend):
        # On a SERVER install this is a real problem (storage should be fm_odata), not "nothing to do":
        # name the config path, whether it was found, and the storage_backend value so the operator can
        # see WHY the active backend is LocalBackend (usually fm_odata was never activated in install.yaml).
        from corpusfm.config import is_server_mode
        if is_server_mode():
            try:
                from corpusfm.install import read_install_config, marker_path
                cfg = read_install_config()
                mp = marker_path()
                sb = cfg.get("storage_backend")
                print(f"skip: the active storage backend is {type(backend).__name__}, not the FM OData "
                      "backend — projections cannot be backfilled.")
                print(f"  install.yaml: {mp} (exists={mp.exists()})")
                print(f"  storage_backend: {sb!r} (expected 'fm_odata')")
                if sb != "fm_odata":
                    print("  => FM OData storage is NOT activated. Re-run the installer with FM admin "
                          "credentials to (re)bootstrap, or activate it in Settings -> Connections, "
                          "then re-run this command.")
                return 0
            except Exception as exc:
                print(f"skip: projection backfill needs the FM OData backend; diagnostic failed ({exc}).")
                return 0
        print("skip: projection backfill needs the FM OData backend (LocalBackend dev/test path — "
              "nothing to do here).")
        return 0
    res = projections.assert_projection(backend)
    if not res.get("ok"):
        print(f"error: projection assert failed ({res.get('reason', 'see log')}) - will retry.")
        return 1
    if res.get("skipped"):
        print(f"projection assert: {res.get('reason', 'skipped')}.")
    elif res.get("wrote") == "none":
        print("projection assert: index projections already match - no change.")
    else:
        what = "wrote default template" if res.get("wrote") == "default_template" else "updated index projections"
        via = res.get("refreshed") or "no refresh"
        print(f"projection assert: {what}, refreshed ({via}).")
    return 0


def run_backfill_latest(args) -> int:
    from corpusfm.storage import get_backend
    from corpusfm.server import latest as _latest
    backend = get_backend()
    if not _latest.latest_available(backend):
        print("error: the IsLatest schema isn't live (FM backend + new schema required).")
        return 1
    res = _latest.backfill_latest(backend)
    print(f"reconciled IsLatest: {res['updated']} flag(s) flipped across {res['artifacts']} artifact(s)")
    return 0


def run_storage(args) -> int:
    # Retired (packet 085, fresh-install-only): no in-place migration exists. The in-app
    # build-mismatch gate handles a DB behind the shipped schema. Green no-op so the
    # installer's upgrade step stays stable without shelling to a removed engine.
    print("no-op: in-place storage migration is retired (085 is fresh-install-only); "
          "a DB behind the shipped schema is handled by the in-app build-mismatch gate.")
    return 0
