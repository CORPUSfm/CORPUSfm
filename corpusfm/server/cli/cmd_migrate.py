"""CLI: corpusfm storage maintenance subcommands.

  migrate-storage : RETIRED no-op. Packet 085 is fresh-install-only — there is no
                    in-place storage-schema migration. A DB behind the shipped schema
                    is handled by the in-app build-mismatch gate ("fresh install
                    required"), not by carrying data across a schema change. Kept as a
                    green no-op so the installer's upgrade step stays stable.
  backfill-latest : reconcile STORAGE.IsLatest across every lineage.
  backfill-storage-projections : assert the FM-side index-projection contract.

See corpusfm/storage/storage_migration.py (the surviving build-mismatch gate).
"""

from __future__ import annotations


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
