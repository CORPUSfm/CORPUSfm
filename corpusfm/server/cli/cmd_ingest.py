"""CLI: corpusfm ingest <file> — scripted one-off ingest into the catalog.

Ingest a local **SaveAsXML** (`.xml`) or **addon** (`.fmaddon`) export straight into the
active storage backend — the same pipeline the Upload page and Jobs use. For CI / scripted
batch loads where there is no browser. (``corpusfm compare`` reads raw XML but does not
store; this stores.)

Examples:
    corpusfm ingest export.xml
    corpusfm ingest MyFile.xml --name "My File"
    corpusfm ingest PTLaunchPad.fmaddon --locale en
    corpusfm ingest export.xml --keep-source-xml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest",
        help="Ingest a local SaveAsXML (.xml) or addon (.fmaddon) export into the catalog",
        description=(
            "Parse and store a FileMaker schema export into the active storage backend. "
            "Accepts a SaveAsXML .xml, a pasted-clip .xml, or a .fmaddon archive."
        ),
    )
    p.add_argument("path", help="Path to a .xml schema export or a .fmaddon archive")
    p.add_argument("--name", default="", help="Display label (defaults to the schema's own file name)")
    p.add_argument("--locale", default="", help=".fmaddon: locale for name resolution (default: config / en)")
    p.add_argument("--keep-source-xml", action="store_true",
                   help="Retain the encrypted raw XML alongside the artifact")
    p.add_argument("--json", action="store_true", dest="json_output", help="Emit the result as JSON")
    p.set_defaults(func=run)


def _safe_label(raw: str) -> str:
    return "".join(c if c.isalnum() or c in " ._-" else "_" for c in (raw or "")).strip(" ._-")


def _label_from_identity(artifact) -> str:
    return _safe_label(getattr(getattr(artifact, "identity", None), "file_name", "") or "")


def run(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists() or not path.is_file():
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 1

    suffix = path.suffix.lower()
    name = (args.name or "").strip()
    addon_package = None

    try:
        from corpusfm.runtime import build_context
        from corpusfm.ingestion.pipeline import ingest
        backend = build_context().storage()   # the active backend, via the composed runtime (S7)

        if suffix == ".fmaddon":
            from corpusfm.core.addon.package import parse_addon_xar
            locale = args.locale or _default_locale()
            addon_package = parse_addon_xar(path, locale=locale)
            xml_bytes = addon_package.xml_bytes
            label = name or path.stem
        elif suffix == ".xml":
            raw = path.read_bytes()
            from corpusfm.ingestion.clip import detect_clip, ingest_clip
            if detect_clip(raw):
                label = name or path.stem
                clip = ingest_clip(raw, label)
                meta = backend.store_artifact(clip, label=label, origin="Import")
                return _report(meta, clip, "fmClip", args)
            head = raw[:1024]
            if b"<FMAdd_on" in head:
                print("ERROR: this is an addon XML — ingest the .fmaddon archive instead "
                      "(it carries locale names, metadata, icons).", file=sys.stderr)
                return 1
            if b"<FMPReport" in head:
                print("ERROR: FMPReport (Database Design Report) is not supported. Export a "
                      "Schema XML instead (File -> Save a Copy as XML -> include analysis details).",
                      file=sys.stderr)
                return 1
            xml_bytes = raw
            label = name or path.stem
        else:
            print(f"ERROR: unsupported file type '{suffix}'. Use a .xml export or a .fmaddon archive.",
                  file=sys.stderr)
            return 1

        name_map = addon_package.name_map if addon_package else {}
        artifact = ingest(xml_bytes, label, source_type="manual", name_map=name_map)
        label = name or _label_from_identity(artifact) or label
        meta = backend.store_artifact(
            artifact, xml_bytes=xml_bytes, label=label,
            addon_package=addon_package, keep_source_xml=args.keep_source_xml,
        )
        return _report(meta, artifact, getattr(artifact.type, "value", str(artifact.type)), args)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def _default_locale() -> str:
    try:
        from corpusfm.app.app_config import load_app_config, system_locale_code
        return load_app_config().preferred_addon_locale or system_locale_code() or "en"
    except Exception:
        return "en"


def _report(meta, artifact, artifact_type: str, args) -> int:
    ref = getattr(meta, "uuid", "")   # canonical record address (packet 085 U3f)
    items = len(getattr(artifact, "items", {}) or {})
    if getattr(args, "json_output", False):
        import json
        print(json.dumps({"ok": True, "uuid": ref, "type": artifact_type, "items": items}))
    else:
        print(f"Ingested {artifact_type}: {meta.name if hasattr(meta, 'name') else ref}")
        print(f"  stored: {ref}")
        print(f"  items:  {items}")
    return 0
