"""The one boundary that publishes an update outcome (packet 1246-03-03, N2).

Both elevated updaters used to build the outcome JSON themselves — a heredoc in bash, an ordered
hashtable in PowerShell — and neither passed anywhere near `secret_guard`. The structural fence
1246-01 built for lifecycle records was therefore absent from the one record written by root, and the
only alternative on offer was transliterating a dozen regular expressions into two shells and keeping
three copies in step. That is not a fence; it is three fences that will disagree.

So the shells now COLLECT fields and this collects nothing: it validates the field names against
`update_boundary.OUTCOME_FIELDS`, builds an `UpdateOutcome` (which validates the state), and hands it
to `update_boundary.write_outcome`, which runs `secret_guard.assert_no_secrets` and performs the
atomic 0644 write. A refusal publishes **nothing** and says why on stderr — redacted, because the
thing being refused is by definition something that reads like a secret.

**Where its code comes from.** This runs as `InstallDir/bin/publish_outcome.py`, and it loads
`corpusfm` from `InstallDir/lib` — resolved from this file's own location, never from `PYTHONPATH`,
`cwd` or the checkout. The record it writes is root's word about the tree being judged; loading the
fence that validates it out of that same tree is R7b wearing a different hat. Run with `-I` so
nothing in the environment contributes either.
"""

from __future__ import annotations

import sys
from pathlib import Path

LIBRARY_DIRNAME = "lib"


class PublicationRefused(Exception):
    """Nothing was published. The message is safe to log."""


def library_root(entry_file: str) -> Path:
    """`InstallDir/lib`, derived from where this file actually is.

    `resolve()` first: a symlinked entry point that resolved to its *link* location would put the
    library root somewhere the administrator never installed.
    """
    return Path(entry_file).resolve().parent.parent / LIBRARY_DIRNAME


def install_library_root(entry_file: str) -> None:
    """Put the administrator-owned library first, or refuse. Never falls back to the ambient path."""
    root = library_root(entry_file)
    if not (root / "corpusfm" / "lifecycle").is_dir():
        raise PublicationRefused(
            f"the administrator-owned library at {root} does not hold corpusfm/lifecycle; refusing "
            "to publish an update outcome through code loaded from anywhere else"
        )
    sys.path.insert(0, str(root))


def parse_fields(pairs) -> dict:
    """`name=value` arguments → a validated field mapping.

    Every name must be one `UpdateOutcome` declares. An unknown one is REFUSED, not ignored: a
    secret-shaped *field name* is one of the two ways a secret arrives, and a parser that drops what
    it does not recognise hands the fence a record the fence cannot fail.
    """
    from corpusfm.lifecycle.update_boundary import OUTCOME_FIELDS

    fields: dict[str, object] = {}
    for pair in pairs:
        name, sep, value = str(pair).partition("=")
        if not sep:
            raise PublicationRefused(f"{name!r} is not a name=value field")
        if name not in OUTCOME_FIELDS:
            raise PublicationRefused(f"{name!r} is not a field of the update outcome record")
        if name in fields:
            raise PublicationRefused(f"{name!r} was supplied twice")
        if name == "rolled_back":
            if value not in ("true", "false"):
                raise PublicationRefused("rolled_back must be exactly 'true' or 'false'")
            fields[name] = value == "true"
        elif name == "privileged_classes":
            fields[name] = tuple(p for p in value.split(",") if p)
        else:
            fields[name] = value
    for required in ("operation_id", "trigger_id", "state"):
        if required not in fields:
            raise PublicationRefused(f"the outcome record has no {required}")
    return fields


def publish(state_dir: str, pairs) -> Path:
    """Validate and write, or raise. The ONLY route by which an outcome record comes into existence."""
    from corpusfm.lifecycle.errors import LifecycleError
    from corpusfm.lifecycle.update_boundary import UpdateOutcome, write_outcome

    fields = parse_fields(pairs)
    try:
        outcome = UpdateOutcome(**fields)  # type: ignore[arg-type]
        return write_outcome(state_dir, outcome)
    except LifecycleError as exc:
        raise PublicationRefused(str(exc)) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise PublicationRefused(f"the update outcome could not be written: {exc}") from exc


def _safe(message: str) -> str:
    """Redact the refusal itself. It quotes what was refused, and what was refused reads like a
    secret often enough that the log line is the last place to leak it."""
    try:
        from corpusfm.lifecycle.secret_guard import redact

        return redact(message)
    except Exception:  # pragma: no cover - the library is exactly what failed to load
        return "the update outcome was refused and the refusal could not be rendered safely"


def main(argv: list[str] | None = None, *, entry_file: str | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        install_library_root(entry_file or __file__)
    except PublicationRefused as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if len(args) < 2:
        print("usage: publish_outcome <state_dir> name=value ...", file=sys.stderr)
        return 2
    try:
        publish(args[0], args[1:])
    except PublicationRefused as exc:
        print(_safe(str(exc)), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
