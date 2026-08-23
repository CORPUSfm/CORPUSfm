"""CLI: corpusfm users — on-box user administration.

The web **Users** tab (Settings -> admin) is the normal surface; this is the headless
one — reset a forgotten password, re-grant gates when someone is locked out of the web
UI, or re-create an admin if the USER table was emptied. It operates on the USER table in
the storage DB directly (packet 1007; no auth/session needed), so run it as the **service
user** to keep the box key (the Corpus Key) accessible.

**Needs the storage DB reachable, so it is NOT a remedy for a storage outage** — it writes
to the very table an outage makes unreadable. It was once labelled "break-glass", which
promised exactly the one thing it cannot do (packet 1201). The first admin is created by
the installer; when storage itself is down the repair is the FileMaker file, via its local
[Full Access] account.

Passwords are always PROMPTED (getpass) or read from the ``CORPUSFM_USER_PASSWORD`` environment
variable for non-interactive installer/test contexts — NEVER taken on argv (a shell-history /
process-list exposure; packet 1008/B).

Examples:
    corpusfm users list
    corpusfm users create alice --admin
    corpusfm users create bob --gates automation,library_mcp
    corpusfm users set-password alice
    corpusfm users set-gates bob --gates library_mcp,patching
    corpusfm users deactivate bob
    corpusfm users delete bob
    corpusfm users mint-mcp-token alice --name first-client

**First contact for MCP lives here (packet 1258).** A fresh box has no server-wide token — there is
no such thing any more — so the first MCP client is connected by minting a NAMED token for a real
account with ``mint-mcp-token``. That is the out-of-band bootstrap channel the Unknowable-Install
Principle requires: it needs a shell on the box, not a browser session the administrator may not yet
be able to reach. Everything it mints is an ordinary per-user token, identical to one minted at
Library -> MCP, and deleted the same way.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

_PW_ENV = "CORPUSFM_USER_PASSWORD"   # non-interactive password source (installer/test); never argv


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "users",
        help="On-box user administration (create / reset password / gates)",
        description=(
            "Headless administration of the USER table — create a user, reset a password, or "
            "re-grant gates. Run as the service user. Needs the storage DB reachable, so it "
            "cannot repair a storage outage; the installer creates the first admin."
        ),
    )
    sub = p.add_subparsers(dest="users_command")

    lp = sub.add_parser("list", help="List users (gates, active, admin)")
    lp.set_defaults(func=_list)

    cp = sub.add_parser("create", help="Create a user")
    cp.add_argument("username")
    cp.add_argument("--gates", default="", help="comma-separated: " + ", ".join(_gate_names()))
    cp.add_argument("--admin", action="store_true", help="grant ALL gates (full admin)")
    cp.add_argument("--display-name", default="")
    cp.set_defaults(func=_create)

    sp = sub.add_parser("set-password", help="Reset a user's password")
    sp.add_argument("username")
    sp.set_defaults(func=_set_password)

    gp = sub.add_parser("set-gates", help="Replace a user's gates")
    gp.add_argument("username")
    gp.add_argument("--gates", default="", help="comma-separated: " + ", ".join(_gate_names()))
    gp.add_argument("--admin", action="store_true", help="grant ALL gates (full admin)")
    gp.set_defaults(func=_set_gates)

    ap = sub.add_parser("activate", help="Activate a user")
    ap.add_argument("username")
    ap.set_defaults(func=_activate)

    dp = sub.add_parser("deactivate", help="Deactivate a user")
    dp.add_argument("username")
    dp.set_defaults(func=_deactivate)

    rp = sub.add_parser("delete", help="Delete a user")
    rp.add_argument("username")
    rp.set_defaults(func=_delete)

    mp = sub.add_parser(
        "mint-mcp-token",
        help="Mint a named MCP token for a user and print it ONCE (first-contact bootstrap)",
        description=(
            "Mint an ordinary per-user MCP token and print it once. Use it to connect the first MCP "
            "client on a fresh box, before anyone can reach the web UI. The token carries that "
            "user's CURRENT gates and nothing more; revoke it by deleting it at Library -> MCP."
        ),
    )
    mp.add_argument("username")
    mp.add_argument("--name", default="", help="token name (default: cli-bootstrap)")
    mp.set_defaults(func=_mint_mcp_token)

    p.set_defaults(func=lambda a: (p.print_help() or 0))


# ── helpers ──────────────────────────────────────────────────────────────────

def _gate_names():
    from corpusfm.app.web.users import GATES
    return GATES


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _resolve_gates(args):
    """Gate set from --admin (all) or a --gates comma list. Raises ValueError on an unknown gate."""
    from corpusfm.app.web.users import GATES
    if getattr(args, "admin", False):
        return set(GATES)
    raw = [g.strip() for g in (args.gates or "").split(",") if g.strip()]
    bad = [g for g in raw if g not in GATES]
    if bad:
        raise ValueError(f"unknown gate(s): {', '.join(bad)} — valid: {', '.join(GATES)}")
    return set(raw)


def _read_password() -> str:
    """Password for create/set-password: the CORPUSFM_USER_PASSWORD env var (non-interactive
    installer/test) if set, else an interactive getpass prompt (confirmed). NEVER read from argv —
    a password on the command line leaks into shell history and the process list."""
    env = os.environ.get(_PW_ENV, "")
    if env:
        return env
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Confirm password: "):
        raise ValueError("passwords did not match")
    if not pw:
        raise ValueError("password may not be empty")
    return pw


def _find(username: str):
    from corpusfm.app.web.users import get_user
    u = get_user(username)
    if u is None:
        raise ValueError(f"user '{username}' not found")
    return u


# ── subcommands ──────────────────────────────────────────────────────────────

def _list(args) -> int:
    from corpusfm.app.web.users import load_users
    users = load_users()
    if not users:
        print("(no users — create one with: corpusfm users create <name> --admin)")
        return 0
    for u in sorted(users, key=lambda x: x.username.lower()):
        flags = []
        if u.is_admin:
            flags.append("admin")
        if not u.active:
            flags.append("INACTIVE")
        tail = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  {u.username:20} gates: {', '.join(sorted(u.gates)) or '(none)'}{tail}")
    return 0


def _create(args) -> int:
    from corpusfm.app.web.users import create_user, users_exist
    try:
        gates = _resolve_gates(args)
        if not users_exist() and "settings" not in gates:
            print("! the first user is normally an admin — consider --admin", file=sys.stderr)
        pw = _read_password()
        u = create_user(args.username, pw, gates, display_name=args.display_name,
                        created_by="cli", now=_now())
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Created '{u.username}' with gates: {', '.join(sorted(u.gates)) or '(none)'}")
    return 0


def _set_password(args) -> int:
    from corpusfm.app.web.users import set_user_password
    try:
        u = _find(args.username)
        pw = _read_password()
        set_user_password(u.id, pw)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Password reset for '{u.username}'.")
    return 0


def _set_gates(args) -> int:
    from corpusfm.app.web.users import update_user_gates
    try:
        u = _find(args.username)
        gates = _resolve_gates(args)
        update_user_gates(u.id, gates)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Gates for '{u.username}' set to: {', '.join(sorted(gates)) or '(none)'}")
    return 0


def _mint_mcp_token(args) -> int:
    """Mint a per-user MCP token on the box and print it once.

    Deliberately NOT a special credential: it is the same record `mint` writes for the web UI, owned
    by a named user, carrying that user's live gates, revoked by deleting it. The one thing this verb
    adds is REACH — it works over a shell before the administrator can reach any in-app surface.

    It needs the storage DB, like every other verb here, and says so plainly when the store is
    unreachable rather than implying a credential could be issued without one: with MCP access
    user-account-centric, a storage outage means no MCP access at all, by design (packet 1258).
    """
    from corpusfm.app.web import mcp_tokens
    try:
        u = _find(args.username)
        if not u.active:
            raise ValueError(f"user '{u.username}' is deactivated — activate it first")
        if "library_mcp" not in u.gates:
            print(f"! '{u.username}' does not hold the library_mcp gate; the token will authenticate "
                  f"but see almost no tools", file=sys.stderr)
        raw = mcp_tokens.mint(u.id, (args.name or "cli-bootstrap"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print("The storage database must be reachable to mint a token — there is no credential "
              "outside it.", file=sys.stderr)
        return 1
    print(f"MCP token for '{u.username}' (shown ONCE — copy it now):")
    print()
    print(f"  {raw}")
    print()
    print(f"  gates: {', '.join(sorted(u.gates)) or '(none)'}")
    print("  connect: point your MCP client at https://<this-host>/corpusfm/mcp "
          "over HTTP transport,")
    print("           sending  Authorization: Bearer <token>")
    return 0


def _activate(args) -> int:
    return _set_active(args, True)


def _deactivate(args) -> int:
    return _set_active(args, False)


def _set_active(args, active: bool) -> int:
    from corpusfm.app.web.users import set_user_active
    try:
        u = _find(args.username)
        set_user_active(u.id, active)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"'{u.username}' is now {'active' if active else 'inactive'}.")
    return 0


def _delete(args) -> int:
    from corpusfm.app.web.users import delete_user
    try:
        u = _find(args.username)
        delete_user(u.id)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Deleted '{u.username}'.")
    return 0
