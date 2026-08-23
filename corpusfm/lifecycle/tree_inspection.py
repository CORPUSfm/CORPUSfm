"""Deciding whether the deployed checkout is clean enough to update (packet 1246-03, R7).

**Why this is Python and not shell.** The shell version parsed `git status --porcelain` in a `while
read` loop, which meant handling arbitrary filesystem pathnames in shell variables: quoted spellings,
embedded newlines, non-UTF-8 bytes. Two reviews found real defects in it and each fix produced a
subtler one. Git pathnames are not a shell datatype.

**What it inspects, and what the previous versions missed:**

- `--ignored`, because `.gitignore` covers `archive/`, `__pycache__/` and `corpusfm/_build.txt` — so
  a planted `archive/__init__.py` never even reached the old allowlist. An ignored importable file
  is the *most* interesting thing here, not the least.
- **Exact equality only.** Prefix matching let `corpusfm/_build.txt.suffix` through, and a
  *directory* named `corpusfm/_build.txt` containing files through as well.
- **No directory prefixes at all.** After the ruled cutover, runtime data lives under
  `/var/lib/corpusfm`; `archive/`, `logs/`, `jobs/` and `history/` do not belong in the checkout, so
  there is nothing left to justify allowlisting them.
- **Non-UTF-8 names are rejected, not guessed at**, and reported by their escaped form so the
  message itself is always valid JSON.

It reads NUL-delimited porcelain, so nothing is ever quoted or split on whitespace. It takes the
repository as an argument and reads **no environment**: an elevated updater that could be pointed at
another tree by a variable is the hole item 6 closed, and this must not reopen it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# The ONLY untracked or ignored paths a deployed checkout may hold, matched by exact equality.
# `_build.txt` is the version stamp the running app READS; the installer writes it. It is data, it
# is not importable, and there is exactly one of it.
ALLOWED_EXACT: frozenset[str] = frozenset({"corpusfm/_build.txt"})

# ── the git invocation, and why none of it is inherited ───────────────────────────────
#
# R7a: this ran bare `git` with the whole ambient environment. Every one of the following decides
# which repository git reads, or what code it runs, and every one is settable by whoever can set an
# environment variable on the elevated process:
#
#   PATH            which `git` binary
#   GIT_DIR         which repository, regardless of -C
#   GIT_WORK_TREE   which files that repository is compared against
#   GIT_INDEX_FILE  which index the comparison uses
#   GIT_CONFIG_*    arbitrary config, including `core.fsmonitor` and alias definitions, which
#                   execute commands
#   IFS             word splitting in anything that later shells out
#
# So the binary is an absolute path from a fixed list and the environment is BUILT, not filtered:
# an allowlist of what git needs, and nothing else. Filtering a denylist means keeping a list of
# every variable git has ever honoured, which is the kind of list that is wrong the moment it is
# written.

GIT_CANDIDATES: tuple[str, ...] = ("/usr/bin/git", "/bin/git", "/usr/local/bin/git",
                                   "/opt/homebrew/bin/git")

#: The Windows installer-owned MinGit, relative to the installation root.  The inspected checkout
#: is the fixed ``<install>/src`` published by the updater, so this is derived from that checkout
#: rather than accepted from argv, the environment, or PATH.
WINDOWS_GIT_RELATIVE: tuple[str, ...] = ("git", "cmd", "git.exe")

#: The only environment entries the inspector passes on. `HOME` is set to the repository so a
#: stray `~/.gitconfig` cannot contribute either — git reads one whether or not we point at it.
_GIT_ARGS = ("-c", "safe.directory=*", "-c", "core.fsmonitor=false", "-c", "protocol.ext.allow=never")


class GitUnavailable(Exception):
    """No git binary at any known absolute location. Refused rather than resolved through PATH."""


def git_executable(candidates: tuple[str, ...] = GIT_CANDIDATES) -> str:
    """An absolute git, chosen from a fixed list — never `PATH`, never `shutil.which`."""
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise GitUnavailable(
        "no git executable was found at any known absolute location "
        f"({', '.join(candidates)}); refusing to resolve one through PATH"
    )


def _platform_name() -> str:
    """A tiny measured seam: production answers the host, tests can model the other host."""
    return os.name


def _git_for_repo(repo: Path) -> str:
    """Return the one platform-owned Git for this fixed deployed checkout.

    Windows has no system Git contract: ``install.ps1`` owns MinGit beside ``src``.  Deriving it
    from the checkout keeps the helper's one-argument CLI and introduces no nominated executable.
    POSIX retains its fixed system candidate list exactly.
    """
    if _platform_name() != "nt":
        return git_executable()
    candidate = repo.parent.joinpath(*WINDOWS_GIT_RELATIVE)
    if candidate.is_file():
        return str(candidate)
    raise GitUnavailable(
        f"the installation-owned git was not found at {candidate}; refusing to resolve one "
        "through PATH"
    )


def sanitised_environment(repo: Path) -> dict:
    """Built from nothing. Anything not named here does not reach git."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(repo),
        "LC_ALL": "C",
        "LANG": "C",
        "IFS": " \t\n",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_ALLOW_PROTOCOL": "",
    }


class TreeUnclean(Exception):
    """The deployed checkout holds something an update must not build on."""


def _porcelain(repo: Path) -> list[bytes]:
    """NUL-delimited records, as bytes. Never decoded before we know we can."""
    # The environment deliberately suppresses system Git configuration.  Pin the one checkout
    # conversion rule that therefore disappears with it: MinGit checks out CRLF, POSIX Git LF.
    # Without this, freshly advanced Windows files are falsely reported modified even though the
    # ordinary checkout is clean.  This is a fixed platform property, not ambient configuration.
    autocrlf = "true" if _platform_name() == "nt" else "false"
    result = subprocess.run(
        [_git_for_repo(repo), "-c", f"core.autocrlf={autocrlf}", *_GIT_ARGS,
         "-C", str(repo), "status", "--porcelain", "-z",
         "--untracked-files=all", "--ignored=matching"],
        capture_output=True, timeout=120,
        env=sanitised_environment(repo), cwd=str(repo),
    )
    if result.returncode != 0:
        raise TreeUnclean(
            "the deployed checkout could not be inspected: "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    return [record for record in result.stdout.split(b"\0") if record]


def _describe(raw: bytes) -> str:
    """A safe display form. A name we cannot decode is shown escaped, never dropped."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "backslashreplace")


def inspect(repo: Path | str) -> list[str]:
    """Return the problems, most specific first. Empty means the tree may be updated."""
    repo = Path(repo)
    problems: list[str] = []
    for record in _porcelain(repo):
        if len(record) < 4:
            continue
        status, raw_path = record[:2], record[3:]
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(
                f"a path whose name is not valid UTF-8: {_describe(raw_path)}"
            )
            continue
        if status.startswith(b"??") or status.startswith(b"!!"):
            if path in ALLOWED_EXACT:
                continue
            kind = "ignored" if status.startswith(b"!!") else "untracked"
            problems.append(f"{kind} content that is not an installer artifact: {path}")
        else:
            problems.append(f"modified tracked file: {path}")
    return problems


def main(argv: list[str] | None = None) -> int:
    """`python -m corpusfm.lifecycle.tree_inspection <repo>` → JSON on stdout, exit 1 if unclean.

    JSON so the shell never has to parse a pathname, and `json.dumps` so every control character —
    carriage returns included — is encoded rather than embedded raw in a record somebody later
    fails to parse.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(json.dumps({"ok": False, "problems": ["usage: tree_inspection <repo>"]}))
        return 2
    try:
        problems = inspect(args[0])
    except (TreeUnclean, GitUnavailable) as exc:
        print(json.dumps({"ok": False, "problems": [str(exc)]}))
        return 1
    print(json.dumps({"ok": not problems, "problems": problems}, ensure_ascii=True))
    return 0 if not problems else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
