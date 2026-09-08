"""CLI: corpusfm ingest <file> — scripted ingest, ASYNCHRONOUS and durable (packet 1361-01).

Hand a local **SaveAsXML** (`.xml`), a pasted **clip** (`.xml`) or an **addon** (`.fmaddon`) export
to the same QUEUE every other ingestion path uses, then exit. The command no longer parses, stores
or waits: it uploads the bytes into a durable QUEUE record, prints the queue id, and returns.

**Why it stopped waiting.** A CLI ingest is the one path that used to build a whole artifact in the
caller's own process and store it directly, which meant a `Ctrl-C`, a dropped SSH session or a
CI timeout could kill the write half-way with nothing anchoring the attempt. Enqueuing makes the
work survive the client: the record is durable, the worker owns it, and a failure rests on the row
for a human instead of vanishing with the terminal.

    corpusfm ingest export.xml
    corpusfm ingest MyFile.xml --name "My File"
    corpusfm ingest PTLaunchPad.fmaddon --locale en
    corpusfm ingest export.xml --keep-source-xml
    corpusfm ingest-status <queue-id>          # state · position · outcome · artifact uuid
    corpusfm ingest-status                     # everything currently in the ingestion queue
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest",
        help="Queue a local SaveAsXML (.xml) or addon (.fmaddon) export for ingestion",
        description=(
            "Upload a FileMaker schema export into the ingestion queue and exit. Accepts a "
            "SaveAsXML .xml, a pasted-clip .xml, or a .fmaddon archive. The ingest itself runs in "
            "the server's queue worker; use `corpusfm ingest-status` to follow it."
        ),
    )
    p.add_argument("path", help="Path to a .xml schema export or a .fmaddon archive")
    p.add_argument("--name", default="", help="Display label (defaults to the schema's own file name)")
    p.add_argument("--locale", default="", help=".fmaddon: locale for name resolution (default: config / en)")
    p.add_argument("--keep-source-xml", action="store_true",
                   help="Retain the encrypted raw XML alongside the artifact")
    p.add_argument("--json", action="store_true", dest="json_output", help="Emit the result as JSON")
    p.set_defaults(func=run)

    s = subparsers.add_parser(
        "ingest-status",
        help="Show queued ingestion work: state, position, failure outcome, artifact uuid",
        description=(
            "Report one queued ingestion (by queue id) or every ingestion record currently in the "
            "queue. A record that has completed is GONE from the queue — deletion is the only "
            "success — so an unknown id means either 'finished' or 'never existed', and the "
            "report says exactly that rather than guessing."
        ),
    )
    s.add_argument("queue_id", nargs="?", default="", help="Queue record id (from `corpusfm ingest`)")
    s.add_argument("--json", action="store_true", dest="json_output", help="Emit the result as JSON")
    s.set_defaults(func=run_status)


def _default_locale() -> str:
    try:
        from corpusfm.app.app_config import load_app_config, system_locale_code
        return load_app_config().preferred_addon_locale or system_locale_code() or "en"
    except Exception:
        return "en"


def run(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists() or not path.is_file():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 1
    suffix = path.suffix.lower()
    if suffix not in (".xml", ".fmaddon"):
        print(f"ERROR: unsupported file type '{suffix}'. Use a .xml export or a .fmaddon archive.",
              file=sys.stderr)
        return 1

    try:
        from corpusfm.runtime import build_context
        from corpusfm.server import queue_handlers as QH
        from corpusfm.server import queue_workers as W
        from corpusfm.storage import queue_record as Q

        backend = build_context().storage()   # the active backend, via the composed runtime (S7)
        raw = path.read_bytes()
        # Every kind check the worker will make is the worker's to make; the CLI only refuses what
        # it can tell from the bytes in hand and would otherwise queue work certain to fail.
        head = raw[:1024]
        if suffix == ".xml" and b"<FMPReport" in head:
            print("ERROR: FMPReport (Database Design Report) is not supported. Export a "
                  "Schema XML instead (File -> Save a Copy as XML -> include analysis details).",
                  file=sys.stderr)
            return 1
        if suffix == ".xml" and b"<FMAdd_on" in head:
            print("ERROR: this is an addon XML — ingest the .fmaddon archive instead "
                  "(it carries locale names, metadata, icons).", file=sys.stderr)
            return 1

        qid = QH.enqueue_import(
            backend, raw, filename=path.name, name=(args.name or "").strip(),
            locale=args.locale or _default_locale(), owner="cli", origin="CLI",
            keep_source_xml=bool(args.keep_source_xml))
        try:
            W.poke(Q.INGEST)          # nudge the in-process worker when there is one
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "json_output", False):
        print(json.dumps({"ok": True, "queued": True, "queue_id": qid, "file": path.name}))
    else:
        print(f"Queued {path.name} for ingestion.")
        print(f"  queue id: {qid}")
        print("  state:    in queue")
        print(f"  follow:   corpusfm ingest-status {qid}")
    return 0


def _view(row, position: int, depth: int) -> dict:
    from corpusfm.storage import queue_record as Q
    jor = row.jor if isinstance(row.jor, dict) else {}
    payload = jor.get("Payload") or {}
    failed = Q.is_failed(jor)
    return {
        "queue_id": row.key,
        "state": "failed" if failed else Q.current_step(jor),
        "failed": failed,
        "outcome": jor.get("Outcome", "") if failed else "",
        "filename": payload.get("filename", "") if isinstance(payload, dict) else "",
        "artifact_uuid": jor.get("UUIDStorage", "") or "",
        "position": position,
        "queue_depth": depth,
    }


def run_status(args: argparse.Namespace) -> int:
    try:
        from corpusfm.runtime import build_context
        from corpusfm.storage import queue_record as Q
        from corpusfm.storage.repos import queue_repo

        repo = queue_repo(build_context().storage())
        if repo is None:
            print("ERROR: storage is not available.", file=sys.stderr)
            return 1
        rows = [r for r in repo.list_all()
                if (r.jor or {}).get("Type") in (Q.UPLOAD, Q.INGEST, Q.ACQUIRE)
                or Q.is_failed(r.jor or {})]
        # FIFO by creation stamp — the same order the worker claims in, so "position" is a real
        # position and not a rendering artefact.
        rows.sort(key=lambda r: (r.jor or {}).get("created_at", ""))
        waiting = [r for r in rows if not Q.is_failed(r.jor or {})]
        depth = len(waiting)
        order = {r.key: i + 1 for i, r in enumerate(waiting)}
        views = [_view(r, order.get(r.key, 0), depth) for r in rows]
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    wanted = (args.queue_id or "").strip()
    if wanted:
        one = next((v for v in views if v["queue_id"] == wanted), None)
        if one is None:
            msg = {"ok": True, "queue_id": wanted, "state": "not in queue",
                   "note": "a completed record is deleted from the queue — this id has either "
                           "finished or never existed"}
            print(json.dumps(msg) if getattr(args, "json_output", False)
                  else f"{wanted}: not in queue (a completed record is deleted; it has either "
                       "finished or never existed).")
            return 0
        if getattr(args, "json_output", False):
            print(json.dumps({"ok": True, **one}))
        else:
            print(f"{one['queue_id']}  {one['filename'] or '(no filename)'}")
            print(f"  state:    {one['state']}")
            if one["position"]:
                print(f"  position: {one['position']} of {one['queue_depth']}")
            if one["artifact_uuid"]:
                print(f"  artifact: {one['artifact_uuid']}")
            if one["failed"]:
                print(f"  outcome:  {one['outcome']}")
        return 0

    if getattr(args, "json_output", False):
        print(json.dumps({"ok": True, "queue_depth": len(views), "items": views}))
        return 0
    if not views:
        print("Ingestion queue is empty.")
        return 0
    print(f"{len(views)} ingestion record(s):")
    for v in views:
        pos = f"[{v['position']}/{v['queue_depth']}] " if v["position"] else "[failed] "
        tail = f"  artifact={v['artifact_uuid']}" if v["artifact_uuid"] else ""
        tail += f"  outcome={v['outcome']}" if v["failed"] and v["outcome"] else ""
        print(f"  {pos}{v['queue_id']}  {v['state']:<10} {v['filename']}{tail}")
    return 0
