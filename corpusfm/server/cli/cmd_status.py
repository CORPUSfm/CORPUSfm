"""CLI: corpusfm status — the readiness/diagnostic report.

Read-only, needs no PKI/fmsadmin — the always-available Tier-0 way for an admin to see what's
configured and what's missing (and the next step for each). Mirrors the UI status surface; both
read the one `corpusfm.server.readiness` module.
"""

from __future__ import annotations

import json

_TIER_LABEL = {
    0: "Tier 0 — status / setup (always)",
    1: "Tier 1 — storage + SETTINGS (catalog/read)",
    2: "Tier 2 — PKI + tool + helper (apply / jobs)",
    3: "Tier 3 — embedder (semantic search)",
}
_MARK = {True: "OK ", False: "-- "}


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "status",
        help="Show the readiness/diagnostic report (tiers + per-capability status)",
        description="Diagnose what's configured. Read-only; no PKI/fmsadmin needed.",
    )
    p.add_argument("--json", action="store_true", help="Emit the raw report as JSON")
    p.set_defaults(func=run)


def run(args) -> int:
    from corpusfm.server import readiness
    rep = readiness.report(force=True)

    if getattr(args, "json", False):
        print(json.dumps(rep, indent=2))
        return 0

    t = rep["tier"]
    print(f"CORPUSfm readiness — reached {_TIER_LABEL.get(t, 'Tier ' + str(t))}")
    print(f"  Tier 1 {'ready' if rep['tier1_ready'] else 'NOT ready'} · "
          f"Tier 2 {'ready' if rep['tier2_ready'] else 'NOT ready'} · "
          f"Tier 3 {'ready' if rep['tier3_ready'] else 'NOT ready'}")
    if rep.get("storage_default_cred"):
        print("  ! storage is on the DEFAULT password — startup will rotate it off")
    print()
    # group capabilities by tier for readable boundaries
    caps = sorted(rep["capabilities"], key=lambda c: (c["tier"], c["key"]))
    last_tier = None
    for c in caps:
        if c["tier"] != last_tier:
            print(_TIER_LABEL.get(c["tier"], f"Tier {c['tier']}"))
            last_tier = c["tier"]
        line = f"  {_MARK[c['ok']]}{c['label']:22} {c['detail']}"
        print(line.rstrip())
        if not c["ok"] and c.get("fix"):
            print(f"         -> {c['fix']}")
    return 0 if rep["tier1_ready"] else 1
