"""CLI: corpusfm registrations list|add|remove

Manage named git export registrations.
"""

from __future__ import annotations

import argparse
import sys


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "registrations",
        aliases=["regs"],
        help="Manage named git export registrations",
        description="List, add, and remove named git export registrations.",
    )
    sub = p.add_subparsers(dest="regs_cmd", required=True)

    # list
    sub.add_parser("list", help="List all registrations")

    # add
    p_add = sub.add_parser("add", help="Add a new registration")
    p_add.add_argument("name", help="Registration name (e.g. team-archive)")
    p_add.add_argument("repo", help="Git remote URL")
    p_add.add_argument("--branch", default="main")
    p_add.add_argument("--modes", default="structured,rendered",
                       help="Comma-separated modes (default: structured,rendered)")
    p_add.add_argument("--group", default=None, help="Optional group name")
    p_add.add_argument("--local-path", default=None, help="Override local clone path")
    p_add.add_argument("--no-hidden", action="store_true", help="Disable hidden character marking")
    p_add.add_argument("--overwrite", action="store_true", help="Overwrite existing registration")

    # remove
    p_rm = sub.add_parser("remove", aliases=["rm"], help="Remove a registration")
    p_rm.add_argument("name", help="Registration name")

    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    from corpusfm.core.git_formatter import (
        RegistrationConfig, add_registration,
        list_registrations, remove_registration, resolve_local_path,
    )

    # ── list ──────────────────────────────────────────────────────────────────
    if args.regs_cmd == "list":
        regs = list_registrations()
        if not regs:
            print("No registrations configured.")
            return 0
        for reg in regs:
            local = resolve_local_path(reg)
            modes_str = ", ".join(reg.modes)
            group_str = f"  group: {reg.group}" if reg.group else ""
            print(f"  {reg.name}")
            print(f"    repo:   {reg.repo} ({reg.branch})")
            print(f"    modes:  {modes_str}{group_str}")
            print(f"    local:  {local}")
        return 0

    # ── add ───────────────────────────────────────────────────────────────────
    if args.regs_cmd == "add":
        modes = [m.strip() for m in args.modes.split(",") if m.strip()]
        cfg = RegistrationConfig(
            name=args.name,
            repo=args.repo,
            branch=args.branch,
            modes=modes,
            show_hidden=not args.no_hidden,
            group=args.group,
            local_path=args.local_path,
        )
        try:
            add_registration(cfg, overwrite=args.overwrite)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        local = resolve_local_path(cfg)
        print(f"Registration '{cfg.name}' added.")
        print(f"  repo:  {cfg.repo} ({cfg.branch})")
        print(f"  local: {local}")
        return 0

    # ── remove ────────────────────────────────────────────────────────────────
    if args.regs_cmd in ("remove", "rm"):
        removed = remove_registration(args.name)
        if removed:
            print(f"Registration '{args.name}' removed.")
        else:
            print(f"Registration '{args.name}' not found.", file=sys.stderr)
            return 1
        return 0

    return 0
