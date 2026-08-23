"""CLI: corpusfm diff-companion <addon> <saveas>

A/B the rendered text of the SAME solution exported two ways — an addon
(.fmaddon / FMAdd_on XML) and its SaveAsXML companion. Because they describe the
same schema, every shared object should render identically; a divergence is
either a renderer bug (one path mis-renders) or a known-faithful FM difference
(built-in function-name casing, e.g. CurrentTimeStamp vs CurrentTimestamp).

This is the discovery net that surfaced most of the addon rendering bugs by hand;
it classifies each divergence as REVIEW (likely a bug) or faithful (casing only),
and exits non-zero when anything needs review.

Usage:
    corpusfm diff-companion addon.fmaddon solution.xml
    corpusfm diff-companion addon.fmaddon solution.xml --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "diff-companion",
        help="A/B rendered text of an addon vs its SaveAsXML companion to find renderer divergences",
        description=(
            "Ingest two exports of the same solution and compare rendered text per object. "
            "Reports divergences classified as REVIEW (likely a renderer bug) or faithful "
            "(case-only, e.g. FM built-in function name casing)."
        ),
    )
    p.add_argument("file_a", help="First export (.fmaddon or .xml)")
    p.add_argument("file_b", help="Second export (.fmaddon or .xml)")
    p.add_argument("--json", action="store_true", dest="json_output", help="Emit JSON")
    p.add_argument("--max", type=int, default=40, help="Max REVIEW items to print (default 40)")
    p.set_defaults(func=run)


def _load(path: Path):
    from corpusfm.ingestion import ingest
    if path.suffix.lower() == ".fmaddon":
        from corpusfm.core.addon.package import parse_addon_xar
        pkg = parse_addon_xar(path)
        return ingest(pkg.xml_bytes, path.stem, source_type="AddonXML", name_map=pkg.name_map)
    data = path.read_bytes()
    from corpusfm.core.parser import sanitize_xml
    head = sanitize_xml(data[:4000]) if data else ""
    is_addon = "<FMAdd_on" in head
    return ingest(data, path.stem, source_type="AddonXML" if is_addon else "SaveAsXML")


def _by_key(art) -> dict:
    return {(it.section, it.name): (it.rendered_text or "")
            for it in art.items.values() if not it.is_folder}


def _casing_only(a: str, b: str) -> bool:
    """True if a and b differ ONLY by case (the faithful FM function-casing class)."""
    return a != b and a.lower() == b.lower()


def _first_diff_line(a: str, b: str) -> tuple:
    la, lb = a.splitlines(), b.splitlines()
    for x, y in zip(la, lb):
        if x != y:
            return x.strip(), y.strip()
    if len(la) != len(lb):
        return (f"<{len(la)} lines>", f"<{len(lb)} lines>")
    return ("", "")


def run(args: argparse.Namespace) -> int:
    pa, pb = Path(args.file_a), Path(args.file_b)
    for p in (pa, pb):
        if not p.exists():
            print(f"Error: file not found: {p}", file=sys.stderr)
            return 2

    art_a, art_b = _load(pa), _load(pb)
    ka, kb = _by_key(art_a), _by_key(art_b)
    common = ka.keys() & kb.keys()

    identical_n = casing_n = 0
    review: list = []
    for key in sorted(common):
        a, b = ka[key], kb[key]
        if a == b:
            identical_n += 1
        elif _casing_only(a, b):
            casing_n += 1
        else:
            da, db = _first_diff_line(a, b)
            review.append({"object": f"{key[0]}/{key[1]}", "a": da, "b": db})

    only_a = sorted(f"{s}/{n}" for (s, n) in (ka.keys() - kb.keys()))
    only_b = sorted(f"{s}/{n}" for (s, n) in (kb.keys() - ka.keys()))
    root_match = art_a.identity.root_uuid == art_b.identity.root_uuid and bool(art_a.identity.root_uuid)

    result = {
        "a": {"label": art_a.identity.file_name, "type": art_a.type.value},
        "b": {"label": art_b.identity.file_name, "type": art_b.type.value},
        "root_uuid_match": root_match,
        "common": len(common),
        "identical": identical_n,
        "faithful_casing": casing_n,
        "review": review,
        "only_in_a": only_a,
        "only_in_b": only_b,
    }

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Companion diff: {result['a']['label']} ({result['a']['type']}) "
              f"vs {result['b']['label']} ({result['b']['type']})")
        print(f"  root UUID match: {'yes' if root_match else 'NO — not the same solution?'}")
        print(f"  common objects:  {len(common)}")
        print(f"  identical:       {identical_n}")
        print(f"  faithful (case-only, e.g. function-name casing): {casing_n}")
        print(f"  REVIEW (likely renderer divergence): {len(review)}")
        for r in review[: args.max]:
            print(f"    {r['object']}")
            print(f"      A: {r['a'][:120]}")
            print(f"      B: {r['b'][:120]}")
        if len(review) > args.max:
            print(f"    … +{len(review) - args.max} more")
        if only_a:
            print(f"  only in A: {len(only_a)} (e.g. {', '.join(x.split('/')[0] for x in only_a[:5])})")
        if only_b:
            print(f"  only in B: {len(only_b)} (e.g. {', '.join(x.split('/')[0] for x in only_b[:5])})")

    return 1 if review else 0
