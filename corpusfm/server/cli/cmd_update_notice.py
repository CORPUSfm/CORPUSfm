"""CLI: corpusfm update-notice — publish and print the informational post-update notice.

The installer calls this as its FINAL line after restarting the service, so a CLI install reports the
update without anyone opening a browser. It prints the DURABLE narrative — version, release lines and
any recommendation — which since packet 1359 is deliberately NOT what the transient web toast shows:
that toast carries the recommendation sentence alone, and appears only when there is one. The stable
command is retained as an installer contract; it performs no storage, index, queue or migration work.
"""
from __future__ import annotations


def add_parser(subparsers) -> None:
    p = subparsers.add_parser(
        "update-notice",
        help="Publish and print the informational post-update notice",
        description="Publish and print this build's informational notice. Idempotent per version.",
    )
    p.add_argument("--json", action="store_true", help="Emit the raw flow result as JSON")
    p.set_defaults(func=run)


def run(args) -> int:
    from corpusfm.server import update_notice
    result = update_notice.run_update_flow()

    if getattr(args, "json", False):
        import json
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("ok") else 1

    if not result.get("ok"):
        # stdout is intentional: shipped installer callers suppress stderr and ignore this command's
        # status, so the operator must still see that notice publication was indeterminate/failed.
        print("WARNING: CORPUSfm update notice could not be published: "
              + (result.get("error") or result.get("reason") or "unknown failure"))
        return 1

    notice = result.get("notice") or ""
    if not notice:
        stored = update_notice.about_notice()
        notice = stored.get("text") or ""
    # Windows-console-safe (cp1252): the installer runs this on WS boxes.
    print(notice or f"CORPUSfm is up to date (v{_version()}).")
    return 0


def _version() -> str:
    try:
        import corpusfm
        return str(corpusfm.__version__)
    except Exception:
        return "?"
