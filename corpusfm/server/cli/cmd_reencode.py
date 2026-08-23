"""CLI: corpusfm reencode — bulk re-encode stored blobs to plaintext or encrypted.

Synchronous (blocking) counterpart to the in-app Settings "Save & Convert" toggle: it backs the
encrypt_blobs setting and sets the config flag to match. Tier 1 (storage) must be up.

(The old --migrate-db decrypt-for-transport usage is RETIRED. Blobs stay encrypted wherever the
database goes and only the Corpus Key travels, in a Recovery File — so no bulk decrypt pass is
needed. This command remains solely for the encrypt-blobs toggle.)
"""

from __future__ import annotations


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "reencode",
        help="Bulk re-encode stored blobs (--on encrypt / --off decrypt) + set the config flag",
        description="Synchronous blob re-encode. Tier 1 (storage) must be reachable.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--on", action="store_true", help="Encrypt all stored blobs")
    g.add_argument("--off", action="store_true", help="Decrypt all stored blobs")
    p.set_defaults(func=run)


def run(args) -> int:
    from corpusfm.app.app_config import load_app_config, save_app_config
    from corpusfm.runtime import build_context

    target = bool(args.on)  # required group -> exactly one of --on/--off
    cfg = load_app_config()
    backend = build_context().storage()   # the active backend, via the composed runtime (S7)
    try:
        n = backend.reencode_all_blobs(target)
    except Exception as exc:  # surface clearly; the installer keys off rc + stderr
        # The setting is deliberately NOT saved here. It would claim a store that does not exist —
        # and this path is the worst place for that claim, because the installer reads the exit
        # code and moves on. Before packet 1208 the backend could not fail: a listing failure or
        # every upload failing still returned normally, so this printed "0 blob(s)" and rc 0.
        print(f"reencode failed: {exc}")
        print("The encryption setting was NOT changed — it still describes the blobs as they are.")
        return 1
    cfg.encrypt_blobs = target
    save_app_config(cfg)
    print(f"reencode complete: {n} blob(s) -> encrypt_blobs={target}")
    return 0
