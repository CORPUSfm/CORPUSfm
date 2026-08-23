"""Check for a newer app version.

**git only.** Every supported deployment runs from a git working tree (both installers are
git-clone-only), so we compare HEAD against origin/main. A direct check may fetch using the
administrator-installed read-only PAT; on Windows the unprivileged service instead classifies refs
fetched by the fixed privileged updater and never receives that credential. No GitHub API token is
involved. The version scheme is ``0.{git-rev-count}``, so "behind by N commits" is exactly the next
versions.
(The former GitHub-Releases-API fallback for packaged no-``.git`` standalone builds was retired in
packet 1009 — standalone is archived and no shipped install lacks a checkout.)

check_for_update() never raises — it returns an UpdateResult carrying the
current/latest versions and, when it could not determine an answer, a short
human-readable `error` explaining why.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import corpusfm

REPO = "CORPUSfm/CORPUSfm"
RELEASES_PAGE_URL = f"https://github.com/{REPO}/releases"
_REMOTE_BRANCH = "origin/main"


@dataclass
class UpdateResult:
    update_available: bool
    latest_version: Optional[str] = None
    current_version: Optional[str] = None
    releases_url: str = RELEASES_PAGE_URL
    checked: bool = False          # True only when the source answered authoritatively
    error: Optional[str] = None    # why the check could not complete (human-readable)
    source: str = "github"         # "git" (PAT-backed HTTPS) or "github" (Releases API)
    behind: int = 0                # commits behind origin/main (git path only)
    schema_change: bool = False    # the incoming update bumps the storage DB schema
                                   # (db_schema_build.txt) → needs a full install, not an
                                   # in-app pull (the service can't migrate the DB itself)
    installer_change: bool = False  # canonical lifecycle classifier requires the installer
    installer_reason: str = ""     # named privileged class and an example path ('' if none)
    error_class: str = ""           # machine class of a FAILED check: "credentials" / "network" / ""
                                    # (generic). Lets the UI show a friendly, non-actionable state
                                    # instead of raw git plumbing.
    error_detail: str = ""          # raw diagnostic (git stderr tail) — kept OUT of the primary UI
                                    # message; available for logs / a diagnostic field.


def _parse_version(tag: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", tag.lstrip("v"))
    return tuple(int(p) for p in parts) if parts else (0,)


# ── git path (direct fetch or already-fetched refs; no GitHub API token) ──

def _repo_root() -> Path:
    return Path(corpusfm.__file__).resolve().parent.parent


def _run_git(repo_dir: Path, *args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    # -c safe.directory=<repo>: trust this checkout regardless of who owns it. On a
    # dist/rsync deploy src/ is root-owned while the service runs as corpusfm, which
    # otherwise makes git refuse with "dubious ownership" and the Updates check fails.
    #
    # Non-interactive ALWAYS: a remote with no stored credential must FAIL FAST, never block on an
    # unanswerable username/password prompt. GIT_TERMINAL_PROMPT=0 (+ a no-op askpass and a
    # non-interactive credential manager) guarantee git returns instead of waiting on stdin. This is
    # load-bearing: the update check runs `git fetch` and a blocking prompt here once froze the whole
    # web app — the route ran on the event loop and git sat waiting the full timeout every poll.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "GCM_INTERACTIVE": "Never"}
    git = "git"
    if os.name == "nt":
        # Services deliberately carry no ambient PATH.  The Windows installation records MinGit at
        # this fixed sibling of ``src`` and the privileged updater uses the same executable; a
        # check that falls back to PATH is a different authority and failed on the first live gate.
        installed = repo_dir.parent / "git" / "cmd" / "git.exe"
        if installed.is_file():
            git = str(installed)
    return subprocess.run(
        [git, "-c", f"safe.directory={repo_dir}", "-C", str(repo_dir), *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def classify_git_error(stderr: str) -> tuple[str, str]:
    """Map a failed git invocation's stderr to ``(error_class, operator-readable message)``.

    Credential- and network-class failures get a friendly, NON-actionable message; everything else
    returns ``("", "")`` so the caller keeps its own specific text. This is what lets the Settings
    Updates panel show "Updates unavailable: git credentials are not configured for this install."
    instead of raw git plumbing (`fatal: could not read Username … terminal prompts disabled`) — the
    expected state on a deploy whose checkout has no stored PAT credential."""
    s = (stderr or "").lower()
    credential_signals = (
        "could not read username", "could not read password", "authentication failed",
        "terminal prompts disabled", "permission denied (publickey)", "invalid username or password",
        "could not read credential",
    )
    network_signals = (
        "could not resolve host", "could not resolve proxy", "operation timed out",
        "connection timed out", "failed to connect", "could not connect to server",
        "network is unreachable", "temporary failure in name resolution",
    )
    if any(k in s for k in credential_signals):
        return ("credentials", "Updates unavailable: git credentials are not configured for this install.")
    if any(k in s for k in network_signals):
        return ("network", "Updates unavailable: could not reach the update source (network).")
    return ("", "")


# ── Supply-chain guards: origin identity + clean tree ─────────────────────────
# A privileged upgrade pulls code that then runs as root/service. Before any fetch/pull we verify
# the checkout points at the expected CORPUSfm repo (not a redirected remote) and that the deployed
# tree has no local modifications (a red flag for tampered-in-place code). Shared by the in-app
# apply route and the read-only update check; the installer enforces the same in bash.
EXPECTED_ORIGIN = f"github.com/{REPO}".lower()


def canonical_remote(url: str) -> str:
    """Normalize a git remote URL to ``github.com/<org>/<repo>`` (lowercased), stripping scheme,
    embedded credentials (``x-access-token:TOKEN@``), scp-style ``host:path`` colons, and a trailing
    ``.git`` — so origin identity compares equal regardless of https/ssh/PAT-in-URL form."""
    u = (url or "").strip()
    if u.endswith(".git"):
        u = u[:-4]
    u = u.rstrip("/")
    for scheme in ("https://", "http://", "ssh://", "git://"):
        if u.startswith(scheme):
            u = u[len(scheme):]
            break
    if u.startswith("git@"):
        u = u[len("git@"):]
    u = u.replace("github.com:", "github.com/")  # scp-style host:path → host/path
    if "@" in u:
        u = u.split("@", 1)[1]                    # strip any remaining userinfo
    return u.lower()


def verify_origin(repo_dir: Path) -> tuple[bool, Optional[str]]:
    """(True, raw_origin) when the checkout's ``origin`` is the expected CORPUSfm repo; (False,
    raw_or_None) otherwise. Refuse to pull from an unexpected remote."""
    r = _run_git(repo_dir, "remote", "get-url", "origin")
    if r.returncode != 0:
        return False, None
    actual = (r.stdout or "").strip()
    return canonical_remote(actual) == EXPECTED_ORIGIN, actual


def is_dirty(repo_dir: Path) -> bool:
    """True if any TRACKED file has staged/unstaged modifications — i.e. deployed code changed in
    place, which a privileged upgrade should surface rather than silently pull over. Untracked files
    are deliberately ignored: runtime data legitimately exists beside the tracked application and is
    not a code-tamper signal."""
    r = _run_git(repo_dir, "status", "--porcelain", "--untracked-files=no")
    return r.returncode == 0 and bool((r.stdout or "").strip())


def _changed_paths(repo_dir: Path) -> List[str]:
    """The set of files that differ between HEAD and origin/main (whole tree, not just installer/)."""
    try:
        d = _run_git(repo_dir, "diff", "--name-only", f"HEAD..{_REMOTE_BRANCH}")
        if d.returncode != 0:
            return []
        return [p.strip() for p in (d.stdout or "").splitlines() if p.strip()]
    except Exception:
        return []


@dataclass
class ChangeClassification:
    """Service projection of the canonical lifecycle classification."""
    paths: List[str] = field(default_factory=list)
    installer_required: bool = False
    schema_change: bool = False
    reason: str = ""


def classify_incoming_changes(repo_dir: Path) -> ChangeClassification:
    """Delegate to the same classifier used by the elevated updater."""
    from corpusfm.lifecycle.update_boundary import classify

    paths = _changed_paths(repo_dir)
    verdict = classify(paths)
    return ChangeClassification(
        paths=paths,
        installer_required=verdict.requires_installer,
        schema_change="manifest_schema" in verdict.privileged_classes,
        reason=verdict.reason(),
    )


def _git_update(repo_dir: Path, *, fetch_remote: bool = True) -> Optional[UpdateResult]:
    """Update status from a git checkout, or None if this isn't one."""
    if not (repo_dir / ".git").exists():
        return None
    current = corpusfm.__version__
    ok_origin, actual = verify_origin(repo_dir)
    if not ok_origin:
        return UpdateResult(False, current_version=current, source="git",
                            error=f"Update check skipped — checkout origin is not the expected "
                                  f"CORPUSfm repository (got: {actual or 'unknown'}).")
    try:
        if fetch_remote:
            fetch = _run_git(repo_dir, "fetch", "--quiet")
            if fetch.returncode != 0:
                tail = (fetch.stderr.strip().splitlines() or ["check the PAT credential / network"])[-1]
                cls, friendly = classify_git_error(fetch.stderr)
                return UpdateResult(False, current_version=current, source="git",
                                    error=friendly or f"git fetch failed — {tail}",
                                    error_class=cls, error_detail=tail)
        behind = _run_git(repo_dir, "rev-list", "--count", f"HEAD..{_REMOTE_BRANCH}")
        remote = _run_git(repo_dir, "rev-list", "--count", _REMOTE_BRANCH)
        if behind.returncode != 0 or remote.returncode != 0:
            return UpdateResult(False, current_version=current, source="git",
                                error=f"Could not compare with {_REMOTE_BRANCH}.")
        n_behind = int((behind.stdout or "0").strip() or "0")
        latest = f"0.{(remote.stdout or '').strip()}"
        cls = classify_incoming_changes(repo_dir) if n_behind > 0 else ChangeClassification()
        return UpdateResult(
            update_available=n_behind > 0,
            latest_version=latest,
            current_version=current,
            checked=True,
            source="git",
            behind=n_behind,
            schema_change=cls.schema_change,
            installer_change=cls.installer_required,
            installer_reason=cls.reason,
        )
    except Exception:
        return UpdateResult(False, current_version=current, source="git",
                            error="Could not run git to check for updates.")


def check_for_update(repo_dir: Optional[Path] = None) -> UpdateResult:
    """Return an UpdateResult. Never raises.

    git-only: every supported deployment is a source checkout (both installers clone), so the update
    check is a ``git fetch`` + HEAD-vs-origin/main compare over the deploy's own PAT-backed HTTPS
    credential — no GitHub API token. A run without a ``.git`` checkout (not a shipped shape) simply
    reports it couldn't check.
    """
    git_res = _git_update(Path(repo_dir) if repo_dir is not None else _repo_root())
    if git_res is not None:
        return git_res
    return UpdateResult(False, current_version=corpusfm.__version__, source="git",
                        error="No git checkout found — cannot check for updates.")
