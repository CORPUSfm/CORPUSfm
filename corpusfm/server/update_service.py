"""The service's side of the privileged update (packets 1124, 1246-03-03).

ONE importable server-side authority, called by BOTH the Settings → Updates route and the four stable
MCP update tools (``server_capabilities`` / ``update_check`` / ``update_apply`` / ``update_status``).
The route does not call MCP over HTTP and MCP does not call the route over HTTP — they share this
module in-process (the current folded web+MCP topology).

**This module performs no update.** It resolves installation authority, writes a correlation id and
the administrator's authorized tip to a fixed root-owned inbox, starts one fixed elevated operation
that takes no arguments, and reads the outcome record root wrote back. It cannot nominate a ref,
repository, path, helper or executable, and there is no second route: an absent or unprobeable
one-shot refuses rather than falling back to anything.

``expected_head`` is a **refusal-only consent precondition**. The elevated side resolves
``origin/main`` for itself and compares; a value that differs can only produce a refusal, and a real
older reachable commit is refused rather than selected.

The in-service fetch/pull/rollback/restart sequence, the ``ORIG_HEAD`` rollback, the build-stamp
repair and every reason code belonging to them were **deleted** by 1246-03-03, along with the
unpublished-installation branch that was their last caller. On an installed Windows box, a check
asks the fixed privileged task to fetch with impossible consent, then reads only the refs that task
left behind. The service never receives the private-repository credential and never fetches itself.

What this module still owns:
  - a process-wide single-flight lock (a concurrent Settings/MCP apply refuses ``update_in_progress``
    rather than triggering the elevated operation twice);
  - a durable, privacy-safe update-request record (an atomic mode-0600 JSON file under the CORPUSfm
    runtime dir) so a client that reconnects after the restart can prove which update actually landed;
  - one audit entry per *outcome*, with the real web / MCP actor.

Stable reason codes (part of the tool compatibility surface — do not rename):
  ``installation_state_unclear`` · ``not_a_published_installation`` · ``update_in_progress`` ·
  ``consent_required`` · ``invalid_expected_head`` · ``privileged_updater_unavailable`` ·
  ``outcome_authority_unproven`` · ``request_not_written`` · ``trigger_failed`` ·
  ``update_execution_timeout`` · ``no_matching_outcome`` · ``ok``, plus whatever reason code root
  recorded in its outcome (``origin_mismatch``, ``unclean_tree``, ``not_fast_forward``,
  ``needs_installer``, ``target_changed``, ``import_probe_failed``, …), which is passed through
  verbatim rather than re-derived here.

Durable-record states: ``applying`` · ``restart_scheduled`` · ``restarted`` · ``refused`` ·
  ``rolled_back`` · ``failed`` · ``head_mismatch``.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

#: How an update observation was obtained. Part of the reported state (packet 1251).
OBSERVATION_OBSERVED = "observed"
OBSERVATION_CLASSIFIED = "classified"
OBSERVATION_DIRECT = "direct"

#: The elevated refusals that prove the fetch ALREADY HAPPENED, so the refs on disk are fresh and
#: worth classifying. Both are decided after `git fetch` in the installed executor, and both leave
#: HEAD untouched.
#:
#: `not_fast_forward` is post-fetch too and is deliberately NOT here (developer ruling D3,
#: 2026-08-12): a divergent checkout fails closed rather than being classified into an ordinary
#: "update available". `unclean_tree` and `origin_mismatch` are refused BEFORE the fetch, so there is
#: nothing fresh to read after them.
_POST_FETCH_REFUSALS = frozenset({"target_changed", "needs_installer"})

# The toolset / control-plane revision. A SHORT opaque string that changes when the update-tool
# contract (the four stable names, their arguments, the record format) changes — so a client can
# tell whether it is talking to the control plane it expects. Bump on a contract change, not on an
# ordinary code release.
CONTROL_PLANE_REVISION = "cp-1"

# The exact four stable public MCP tool names (the compatibility promise; guarded).
STABLE_TOOL_NAMES = ("server_capabilities", "update_check", "update_apply", "update_status")

_RECORD_FORMAT = 1

# Process-wide single-flight: one apply at a time across the route AND the MCP tool (same process).
_UPDATE_LOCK = threading.Lock()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── durable update-request record (atomic, mode 0600, privacy-safe) ──────────────────

def request_record_path() -> Path:
    """The box-local update-request record file. Override with ``CORPUSFM_UPDATE_REQUEST`` (tests /
    non-standard installs).

    Lives in the installation's STATE directory, not beside the marker (packet 1246-03). It used to
    sit next to `install.yaml`, which was the same directory back when everything was under
    `~/.corpusfm`. Once a layout is published they are different directories with different owners:
    config is root-owned and the service cannot write it, while state is exactly the place the
    service owns. This file is written BY the service and read by the elevated updater, so state is
    the only correct home for it.
    """
    override = os.environ.get("CORPUSFM_UPDATE_REQUEST")
    if override:
        return Path(override)
    from corpusfm.lifecycle import app_paths
    return app_paths.state_dir() / "update_request.json"


def _write_record(rec: dict) -> None:
    """Atomically persist the record with mode 0600 (never world/group readable — it names the actor and
    heads, though never a token). A UNIQUE per-write temp name (not a fixed ``.tmp``): the ``status()``
    reconciliation write runs OUTSIDE the single-flight lock, so a fixed temp could be truncated/clobbered
    mid-write by a concurrent writer (a second poller, or apply vs status) → a corrupt record on disk
    (packet 1000 Phase 2). ``os.replace`` stays atomic; a failed write cleans up its own temp."""
    import secrets
    p = request_record_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.parent / (p.name + "." + secrets.token_hex(6) + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, json.dumps(rec, indent=2).encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def read_record() -> Optional[dict]:
    """The latest persisted update-request record, or None if there is none/unreadable."""
    try:
        return json.loads(request_record_path().read_text(encoding="utf-8")) or None
    except Exception:
        return None


# ── git head helpers ────────────────────────────────────────────────────────────────

_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _rev_parse(repo: Path, ref: str) -> Optional[str]:
    """The commit SHA for ``ref`` in ``repo`` (via the updater's bounded git), or None."""
    from corpusfm import updater
    r = updater._run_git(repo, "rev-parse", ref)
    if r.returncode != 0:
        return None
    sha = (r.stdout or "").strip()
    return sha or None


def _looks_like_commit(value: str) -> bool:
    return bool(value) and bool(_SHA_RE.match(value.strip()))


def head_build_version(repo: Path) -> Optional[str]:
    """The build version (``0.{count}``) derived from the EXACT current git HEAD, INDEPENDENT of the
    runtime stamp. REPORTED by ``check()``; nothing here acts on it."""
    from corpusfm.buildstamp import source_build_number
    n = source_build_number(repo)
    return f"0.{n}" if n else None


def is_stamp_stale(repo: Path, running_version: Optional[str], current_head: Optional[str],
                   target_head: Optional[str], update_available: bool,
                   checked: bool) -> tuple[bool, Optional[str]]:
    """A read-only OBSERVATION reported by ``check()`` and the Settings route. **Nothing repairs it.**

    Returns ``(stale, head_build_version)``. ``stale`` is True when the checkout is CURRENT yet the
    RUNNING version — read from ``_build.txt`` — differs from the git-derived build for that exact
    HEAD: git advanced without ``buildstamp.write_stamp()`` re-running, so the runtime serves a stale
    version at a current checkout.

    It is reported so a reader is not told "up to date" while the runtime says otherwise. **There is
    no in-app repair for it**: the repair path was a service-side write to the deployed checkout and
    went with the rest of that privilege (packet 1246-03-03). An installer run rewrites the stamp."""
    hb = head_build_version(repo)
    stale = bool(
        checked and not update_available
        and current_head and target_head and current_head == target_head
        and hb and running_version and running_version != hb)
    return stale, hb


# ── check ────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    current_version: Optional[str] = None
    current_head: Optional[str] = None
    target_version: Optional[str] = None
    target_head: Optional[str] = None
    head_build_version: Optional[str] = None   # git-derived build for the EXACT HEAD (stamp-independent)
    stamp_repair: bool = False                 # OBSERVED: current checkout, stale runtime stamp. Reported only.
    behind: int = 0
    update_available: bool = False
    schema_change: bool = False
    installer_change: bool = False
    installer_reason: str = ""
    dirty: bool = False
    is_git: bool = True
    apply_allowed: bool = False
    apply_blocked_reason: str = ""        # stable reason code when NOT apply_allowed (else "")
    operator_command: str = ""            # canonical installer handoff when elevated work is required
    control_plane_revision: str = CONTROL_PLANE_REVISION
    checked: bool = False
    error: Optional[str] = None
    error_class: str = ""
    #: HOW this result was obtained (packet 1251). `observed` — the fixed privileged updater just
    #: performed its refusal-only observation and these are the refs it left behind. `classified` —
    #: the refs already on disk, read without any fetch and without triggering anything; it may be
    #: as old as the last observation. `direct` — an explicitly selected development or
    #: caller-supplied repository fetched in this process. A reader that cannot tell a fresh
    #: observation from a cached one cannot tell "up to date" from "nobody has looked lately".
    observation: str = OBSERVATION_CLASSIFIED
    #: A divergent checkout: `origin/main` is not a descendant of HEAD. Distinct from "behind" on
    #: purpose (developer ruling D3, 2026-08-12) — it fails closed rather than being offered as an
    #: ordinary update.
    diverged: bool = False
    #: Kept for the Settings response shape; deliberately NOT in `to_public_dict`, which excludes
    #: raw git tails.
    source: str = "git"
    error_detail: str = ""

    def to_public_dict(self) -> dict:
        """Privacy-safe view for the MCP ``update_check`` result — the classification booleans + the
        exact heads + the operator handoff, WITHOUT raw git tails / diagnostic detail."""
        return {
            "current_version": self.current_version,
            "current_head": self.current_head,
            "target_version": self.target_version,
            "target_head": self.target_head,
            "head_build_version": self.head_build_version,
            "stamp_repair": self.stamp_repair,
            "behind": self.behind,
            "update_available": self.update_available,
            "schema_change": self.schema_change,
            "installer_change": self.installer_change,
            "installer_reason": self.installer_reason,
            "dirty_tree": self.dirty,
            "apply_allowed": self.apply_allowed,
            "apply_blocked_reason": self.apply_blocked_reason,
            "operator_command": self.operator_command,
            "control_plane_revision": self.control_plane_revision,
            "checked": self.checked,
            "error": self.error,
            "error_class": self.error_class,
            # Additive (packet 1251): existing keys keep their names and meanings, so a client built
            # against the previous contract is unaffected.
            "observation": self.observation,
            "diverged": self.diverged,
        }


def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    """Is `ancestor` reachable from `descendant`? The same question the elevated updater asks.

    **Git's contract is three-valued and this reads all three.** Exit 0 is "yes, an ancestor"; exit
    **1** is the real "no"; anything else — 128 for an unreadable repository or an object that does
    not exist, or an exception — is a probe that could not run. Only exit 1 is evidence of
    divergence.

    A failed probe therefore answers **True** ("not diverged") deliberately: this predicate exists to
    ADD a refusal, and a git invocation that never ran is not evidence of anything. Collapsing 128
    into "diverged" was the first version of this function and it turned every unreadable checkout
    into a confident, wrong verdict — caught by a test whose fake heads are not real objects. The
    elevated side re-runs the real check before anything is applied.
    """
    from corpusfm import updater

    try:
        probe = updater._run_git(repo, "merge-base", "--is-ancestor", ancestor, descendant)
    except Exception:
        return True
    return probe.returncode != 1


def _assembled_check(r, repo_dir: Path) -> CheckResult:
    """Add the service-facing exact-head and applicability fields to one Git observation."""
    from corpusfm import updater

    is_git = (repo_dir / ".git").exists()

    res = CheckResult(
        current_version=r.current_version,
        target_version=r.latest_version,
        behind=r.behind,
        update_available=r.update_available,
        schema_change=r.schema_change,
        installer_change=r.installer_change,
        installer_reason=r.installer_reason,
        is_git=is_git,
        checked=r.checked,
        error=r.error,
        error_class=r.error_class,
        source=getattr(r, "source", "git") or "git",
        error_detail=getattr(r, "error_detail", "") or "",
    )
    if is_git:
        res.current_head = _rev_parse(repo_dir, "HEAD")
        res.target_head = _rev_parse(repo_dir, updater._REMOTE_BRANCH)
        try:
            res.dirty = updater.is_dirty(repo_dir)
        except Exception:
            res.dirty = False
        # INDEPENDENT comparison: the running (stamp-derived) version vs the git-derived build for the
        # exact HEAD. A same-head mismatch is a stale runtime build stamp, not a git update.
        res.stamp_repair, res.head_build_version = is_stamp_stale(
            repo_dir, res.current_version, res.current_head, res.target_head,
            res.update_available, res.checked)

    # A DIVERGENT checkout is not an update (developer ruling D3, 2026-08-12). `behind` counts the
    # commits reachable from origin/main and not from HEAD, which is non-zero for a tree that has
    # diverged as well as for one that is merely behind — and the elevated updater refuses the first
    # with `not_fast_forward` after its own merge-base check. Offering it here as an ordinary
    # available update would invite an authorization that can only be refused, and would describe a
    # broken checkout as a routine upgrade. So it is named, and it fails closed.
    if is_git and res.checked and res.current_head and res.target_head \
            and res.current_head != res.target_head:
        res.diverged = not _is_ancestor(repo_dir, res.current_head, res.target_head)
        if res.diverged:
            res.update_available = False
            res.error_class = "not_fast_forward"
            res.error = (res.error or
                         "The deployed checkout has diverged from origin/main — the remote tip is "
                         "not a descendant of the deployed commit, so this is not an update. The "
                         "privileged updater refuses a divergent tree.")

    # apply_allowed + why-not, using the SAME predicates the mutating path enforces.
    blocked = ""
    if not is_git:
        blocked = "not_git_deployment"
    elif not res.checked:
        blocked = "check_failed"
    elif res.diverged:
        blocked = "not_fast_forward"
    elif not res.update_available:
        # Distinguished from already_current so the reader is not told "up to date" while the
        # runtime serves a stale version. Both are refusals — neither is an action offered here.
        blocked = "stamp_repair" if res.stamp_repair else "already_current"
    elif res.schema_change or res.installer_change:
        blocked = "needs_installer"
    elif res.dirty:
        blocked = "dirty_tree"
    res.apply_blocked_reason = blocked
    # apply_allowed is this read-only view's opinion about whether an update is worth authorizing.
    # It is not permission: the elevated operation re-decides every one of these for itself.
    res.apply_allowed = blocked == ""

    if res.schema_change or res.installer_change:
        res.operator_command = operator_command()
    return res


def _observation_route(repo: Optional[Path]) -> tuple[str, str, str]:
    """`(route, reason_code, message)` — who may look, and how (packet 1251).

    `route` is `"privileged"`, `"direct"` or `"refuse"`. The old test was `os.name == "nt"`, which
    said nothing about the installation and left Linux fetching from the web process into
    administrator-owned Git metadata it cannot write. The question is not the platform; it is whether
    this process is an installed service (delegate) or an explicitly selected development tree (look
    for itself). Both installers ship the same fixed one-shot, and the POSIX trigger has always been
    the sudoers-granted `systemctl start corpusfm-update.service`.

    An indeterminate installation REFUSES. There is no third route, and falling back to a direct
    fetch is precisely the behaviour this packet removes — it would ask an unprivileged identity to
    write a checkout it must never own.
    """
    from corpusfm.lifecycle import app_paths

    if repo is not None:
        return "direct", "", ""          # a caller-supplied repository: a test seam, never production
    try:
        if app_paths.development_layout_active():
            return "direct", "", ""      # explicitly selected development, preserved deliberately
    except Exception as exc:             # noqa: BLE001 - an unanswerable probe is not a yes
        return "refuse", "installation_state_unclear", (
            f"The installation layout could not be determined ({exc}), so this box cannot say "
            "whether it may check for updates.")
    try:
        published = app_paths.is_published()
    except Exception as exc:             # noqa: BLE001 - InstallationStateUnclear and anything else
        return "refuse", "installation_state_unclear", (
            f"This installation's own record could not be read ({exc}). Update checks refuse rather "
            "than guess which checkout they are looking at.")
    if not published:
        return "refuse", "not_a_published_installation", (
            "This process is neither a published installation nor an explicitly selected development "
            "tree, so it has no authority to inspect a deployed checkout.")

    state = privileged_updater_state()
    if state == PRIVILEGED_PRESENT:
        return "privileged", "", ""
    if state == PRIVILEGED_ABSENT:
        return "refuse", "privileged_updater_unavailable", (
            f"The fixed privileged updater ({PRIVILEGED_UNIT}) is not installed, and the web service "
            f"may not fetch into the deployed checkout itself. Re-run the installer on the server.")
    return "refuse", "privileged_updater_unavailable", (
        f"Whether {PRIVILEGED_UNIT} is installed could not be determined. Refusing rather than "
        "reporting an installation without a privileged updater.")


def check(repo: Optional[Path] = None, *, refresh: bool = False) -> CheckResult:
    """Resolve the update state, and say HOW it was resolved.

    `refresh=False` is the passive read (developer ruling D2, 2026-08-12): classify the refs already
    on disk, trigger nothing and fetch nothing. That is what the all-users sidebar poll and an
    ordinary Updates page load ask for, and it is why they no longer start a root one-shot with a
    network fetch per browser — under the single-flight lock that also turned two concurrent polls
    into an `update_in_progress` error.

    `refresh=True` is the explicit *Check for updates* action and MCP `update_check`: the fixed
    privileged updater performs its refusal-only observation — an impossible all-zero consent SHA can
    never authorize a checkout — and this process then classifies only the refs that operation left
    behind, with no second network call. The service never fetches and never writes `.git`.

    The returned `observation` field distinguishes the two, so "up to date" is never confused with
    "nobody has looked lately".
    """
    from corpusfm import updater

    repo_dir = Path(repo) if repo is not None else updater._repo_root()
    route, reason, message = _observation_route(repo)

    if route == "refuse":
        return CheckResult(
            current_head=_rev_parse(repo_dir, "HEAD") if (repo_dir / ".git").exists() else None,
            checked=False, error=message, error_class=reason,
            observation=OBSERVATION_CLASSIFIED,
        )

    if route == "direct":
        res = _assembled_check(updater.check_for_update(repo), repo_dir)
        res.observation = OBSERVATION_DIRECT
        return res

    if not refresh:
        # No trigger, no fetch — only what is already on disk.
        res = _assembled_check(updater._git_update(repo_dir, fetch_remote=False), repo_dir)
        res.observation = OBSERVATION_CLASSIFIED
        return res

    if not _UPDATE_LOCK.acquire(blocking=False):
        return CheckResult(checked=False, error="An update operation is already in progress.",
                           error_class="update_in_progress",
                           observation=OBSERVATION_CLASSIFIED)
    try:
        observed = _trigger_privileged_update(expected_head="0" * 40,
                                              actor="update_check",
                                              audit_outcome=False)
    finally:
        _UPDATE_LOCK.release()
    if observed.reason_code in _POST_FETCH_REFUSALS:
        # The elevated operation fetched and classified before comparing consent.  It could not
        # have changed the checkout: all-zero is not a Git object id and exact equality is the
        # sole path past the consent gate.
        res = _assembled_check(updater._git_update(repo_dir, fetch_remote=False), repo_dir)
        if observed.reason_code == "needs_installer":
            classes = tuple(observed.extra.get("privileged_classes") or ())
            res.installer_change = True
            res.installer_reason = (
                "this update changes " + ", ".join(classes)
                if classes else (observed.message or "the elevated updater requires the installer"))
            res.apply_allowed = False
            res.apply_blocked_reason = "needs_installer"
            res.operator_command = operator_command()
        res.observation = OBSERVATION_OBSERVED
        return res
    return CheckResult(
        current_version=None,
        current_head=_rev_parse(repo_dir, "HEAD") if (repo_dir / ".git").exists() else None,
        checked=False, error=observed.message or "The privileged update observation failed.",
        error_class=observed.reason_code,
        observation=OBSERVATION_CLASSIFIED,
    )


_GENERIC_INSTALLER_HANDOFF = (
    "Acquire and run the current verified Series 2 package from "
    "https://github.com/CORPUSfm/CORPUSfm/releases"
)


def _command_for_installer_entry(entry_point: str, *, windows: bool) -> str:
    """Format the one recorded launcher path without giving the application execution authority."""
    if windows:
        quoted = "'" + entry_point.replace("'", "''") + "'"
        return f"powershell -ExecutionPolicy Bypass -File {quoted}"
    import shlex
    return f"sudo {shlex.quote(entry_point)}"


def operator_command() -> str:
    """The canonical installer handoff shared by Settings, gate pages and MCP.

    New Series 2 packages publish the protected bootstrap they installed. Older manifests carry no
    such field and retain the honest generic handoff; the application never guesses a path from the
    checkout or from the directory where an administrator happened to extract a package.
    """
    try:
        # Through the read façade, not `ManifestStore` — application code may not reach the
        # lifecycle write API (the 1246-01 fence; this function was its one violation, packet 1276).
        # The façade validates locator+manifest agreement itself; an unreadable or unpublished
        # state raises and lands on the generic handoff below.
        from corpusfm.lifecycle.published import read_published_installation

        entry = read_published_installation().installer_entry_point
        if not entry:
            return _GENERIC_INSTALLER_HANDOFF
        return _command_for_installer_entry(entry, windows=(os.name == "nt"))
    except Exception:
        return _GENERIC_INSTALLER_HANDOFF


# ── apply ──────────────────────────────────────────────────────────────────────────

@dataclass
class ApplyResult:
    ok: bool
    reason_code: str                       # "ok" on success, else a stable refusal/error code
    http_status: int                       # the status the Settings route should return
    message: str = ""
    request_id: str = ""
    old_head: Optional[str] = None
    old_version: Optional[str] = None
    applied_head: Optional[str] = None
    target_version: Optional[str] = None
    restart_scheduled: bool = False
    restart_mode: str = "none"             # "server" / "standalone" / "none"
    rolled_back: bool = False
    operator_command: str = ""
    # NEVER POPULATED SINCE 1246-03-03, and kept only because the Settings route and the MCP result
    # still read them. Every one belonged to the deleted in-service pull: there is no build-stamp
    # repair, no locally computed classification and no pull output on this side any more — the
    # elevated operation does that work and reports a reason code. They stay at their defaults so a
    # consumer sees "nothing to report" rather than a value this module cannot honestly produce.
    stamp_repair: bool = False
    schema_change: bool = False
    installer_change: bool = False
    installer_reason: str = ""
    pull_output: str = ""
    extra: dict = field(default_factory=dict)


# ── the privileged one-shot (packet 1246-03) ──────────────────────────────────────────

def _default_restart_scheduler(supervised: bool) -> None:
    """Restart this web process shortly after its successful response has had time to flush.

    The privileged updater restarts the scheduler and proves its result, but deliberately leaves
    the calling web process alive long enough to read the root-owned outcome.  Restarting that
    caller inside the one-shot made a completed Linux update report ``trigger_failed``.  The web
    process owns this final supervised restart, as it did before the privileged updater split.
    """
    import signal
    import sys
    import time

    def _restart() -> None:
        time.sleep(1.0)
        if supervised:
            os.kill(os.getpid(), signal.SIGTERM)
            return
        try:
            os.execv(sys.executable, [sys.executable, "-m", "corpusfm.app.web", *sys.argv[1:]])
        except Exception:
            os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_restart, daemon=True).start()

PRIVILEGED_UNIT = "corpusfm-update.service"
PRIVILEGED_UNIT_PATH = Path("/etc/systemd/system") / PRIVILEGED_UNIT
PRIVILEGED_TASK = "CORPUSfm Update"

PRIVILEGED_PRESENT = "present"
PRIVILEGED_ABSENT = "absent"
PRIVILEGED_UNKNOWN = "unknown"


def privileged_updater_state() -> str:
    """`present` · `absent` · `unknown`. Three answers, because two of them are not the same.

    A bool would fold a *failed probe* into "absent", and "absent" is the answer that has to refuse
    loudly: there is no second route to fall back to, so a subprocess that merely timed out must not
    be reported as an installation without a privileged updater. Unknown is not absent.
    """
    if os.environ.get("CORPUSFM_NO_PRIVILEGED_UPDATER", "").strip():
        return PRIVILEGED_ABSENT
    if os.name == "nt":  # pragma: no cover - platform-specific
        try:
            import subprocess as _sp
            probe = _sp.run(["schtasks", "/Query", "/TN", PRIVILEGED_TASK],
                            capture_output=True, text=True, timeout=15)
        except Exception:
            return PRIVILEGED_UNKNOWN
        if probe.returncode == 0:
            return PRIVILEGED_PRESENT
        # schtasks says "cannot find" for a genuinely absent task; anything else is a probe we could
        # not interpret, and interpreting it generously is what this function exists not to do.
        text = ((probe.stderr or "") + (probe.stdout or "")).lower()
        return PRIVILEGED_ABSENT if "cannot find" in text or "does not exist" in text else PRIVILEGED_UNKNOWN
    try:
        return PRIVILEGED_PRESENT if PRIVILEGED_UNIT_PATH.exists() else PRIVILEGED_ABSENT
    except OSError:
        return PRIVILEGED_UNKNOWN


def privileged_updater_installed() -> bool:
    """Kept for callers that only need the positive case. Never use it to decide a FALLBACK."""
    return privileged_updater_state() == PRIVILEGED_PRESENT


def _outcome_result(outcome, request_id: str, *, actor: str = "unknown",
                    audit_outcome: bool = True) -> "ApplyResult":
    """One place that turns root's record into our result, so every caller reports it identically.

    There are three ways to arrive here — the ordinary poll, a nonzero exit that turns out to be a
    recorded refusal, and a late outcome after a client-side timeout — and before this existed each
    formatted its own message, which is how a refusal reason ends up rendered three different ways.
    """
    ok = outcome.state == "completed"
    detail = outcome.detail or ("Update applied." if ok else "The update did not complete.")
    if outcome.log_path:
        detail = f"{detail} Log: {outcome.log_path}"
    # AUDIT THE OUTCOME, not the trigger. The deleted route recorded `UPDATE_APPLIED` when the
    # pull succeeded; on this side the service does not perform the update, so the event it can
    # honestly record is what root reported back. Without this a successful privileged update left
    # no audit trail at all, while every refusal left one — an asymmetry that reads as "updates
    # never succeed".
    if audit_outcome:
        from corpusfm.server import audit as _audit

        _audit.record(_audit.UPDATE_APPLIED, actor=actor,
                      outcome="ok" if outcome.state == "completed" else "denied",
                      meta={"reason": outcome.reason_code, "via": "privileged_updater",
                            "operation_id": outcome.operation_id,
                            "resulting_head": outcome.resulting_head})
    return ApplyResult(
        ok, outcome.reason_code or ("ok" if ok else "failed"), 200 if ok else 409,
        request_id=request_id, old_head=outcome.observed_head or None,
        applied_head=outcome.resulting_head or None, rolled_back=outcome.rolled_back,
        restart_scheduled=ok, restart_mode="server" if ok else "none",
        operator_command="" if ok else operator_command(), message=detail,
        extra={"privileged_classes": list(getattr(outcome, "privileged_classes", ()) or ())},
    )


# Starting the one-shot is a handoff, not the work: `systemctl start` returns as soon as systemd has
# accepted the unit. This bounds only that handoff.
_TRIGGER_TIMEOUT_SECONDS = 30

# After a NONZERO exit, how long to look for root's own record before calling it a failed trigger.
# The one-shot exits 1 when it REFUSES and writes a perfectly good outcome saying why, so reading
# first turns "systemctl returned 1" into the actual reason.
_REFUSAL_GRACE_SECONDS = 10

# How long the service waits for root's outcome record, and how often it looks. The trigger returns
# a verdict rather than "started", so these bound a user-facing request: long enough for a real
# fast-forward, restart and health check, short enough that a wedged one-shot is reported instead of
# hanging. A late outcome is still read on the next status call.
_OUTCOME_TIMEOUT_SECONDS = 300
_OUTCOME_POLL_SECONDS = 0.5


def _await_outcome(trigger_id: str, *, deadline_seconds: int):
    """Poll for the outcome record bearing OUR trigger id, or give up and say so.

    Stale records are ignored rather than reported: an outcome whose `trigger_id` is not ours
    belongs to a different operation, and the whole reason root writes that field is so this side
    can tell them apart instead of reading the newest file and hoping.
    """
    import time

    from corpusfm.lifecycle import app_paths, update_boundary

    deadline = time.monotonic() + deadline_seconds
    while True:
        try:
            outcome = update_boundary.read_outcome(app_paths.state_dir())
        except Exception:
            outcome = None
        if outcome is not None and outcome.trigger_id == trigger_id:
            return outcome
        if time.monotonic() >= deadline:
            return None
        time.sleep(_OUTCOME_POLL_SECONDS)


def _trigger_privileged_update(*, expected_head: str, actor: str,
                               audit_outcome: bool = True) -> ApplyResult:
    """Write the request, start the one fixed unit, and report what root recorded.

    The service passes **no** path, ref, command or environment — only its own correlation id and the
    tip the administrator authorized, both of which the elevated side re-validates. It cannot even
    name the unit differently: the sudoers grant is that one command.
    """
    import subprocess as _sp

    from corpusfm.lifecycle import app_paths, update_boundary

    request_id = _new_request_id()
    if not _looks_like_commit(expected_head or ""):
        return ApplyResult(False, "invalid_expected_head", 400,
                           message="Update refused — expected_head is not a commit SHA. Read it "
                                   "from update_check and pass it verbatim.")

    # BEFORE triggering: prove the outcome location is one we could not have written ourselves.
    # An outcome is evidence only if its filesystem authority says root wrote it; a trigger id
    # inside the JSON is correlation, never authentication.
    try:
        update_boundary.assert_outcome_authority(app_paths.state_dir())
    except update_boundary.OutcomeAuthorityUnproven as exc:
        return ApplyResult(False, "outcome_authority_unproven", 409, request_id=request_id,
                           operator_command=operator_command(),
                           message=f"Update refused — {exc}. Run the installer on the server: "
                                   f"{operator_command()}")
    try:
        path = update_boundary.request_path(app_paths.state_dir())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"trigger_id": request_id,
                                    "expected_head": expected_head.strip().lower(),
                                    "actor": actor}), encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:
        return ApplyResult(False, "request_not_written", 500, request_id=request_id,
                           message=f"Could not record the update request: {exc}")

    cmd = (["schtasks", "/Run", "/TN", PRIVILEGED_TASK] if os.name == "nt"
           else ["sudo", "-n", "/usr/bin/systemctl", "start", PRIVILEGED_UNIT])
    try:
        started = _sp.run(cmd, capture_output=True, text=True, timeout=_TRIGGER_TIMEOUT_SECONDS)
    except _sp.TimeoutExpired:
        # The unit may still be running. Saying "could not start" would be false, and would invite
        # a retry that collides with an operation already in flight.
        late = _await_outcome(request_id, deadline_seconds=_OUTCOME_TIMEOUT_SECONDS)
        if late is not None:
            return _outcome_result(late, request_id, actor=actor,
                                   audit_outcome=audit_outcome)
        return ApplyResult(False, "update_execution_timeout", 504, request_id=request_id,
                           message="The privileged update operation is taking longer than "
                                   f"{_TRIGGER_TIMEOUT_SECONDS}s and has not recorded an outcome. "
                                   "It may still be running; call update_status shortly.")
    except Exception as exc:
        return ApplyResult(False, "trigger_failed", 500, request_id=request_id,
                           message=f"Could not start the privileged update operation: {exc}")
    # A NONZERO EXIT IS NOT NECESSARILY A FAILED TRIGGER. The one-shot exits 1 when it REFUSES —
    # and it writes a perfectly good outcome saying why. Reading the outcome first turns "systemctl
    # returned 1" into the actual reason (`dirty_tree`, `target_changed`, …) instead of a generic
    # trigger failure that tells the administrator nothing.
    if started.returncode != 0:
        refusal = _await_outcome(request_id, deadline_seconds=_REFUSAL_GRACE_SECONDS)
        if refusal is not None:
            return _outcome_result(refusal, request_id, actor=actor,
                                   audit_outcome=audit_outcome)
        tail = (started.stderr or started.stdout or "").strip().splitlines()
        return ApplyResult(False, "trigger_failed", 500, request_id=request_id,
                           message="The privileged update operation could not be started"
                                   + (f" — {tail[-1]}" if tail else "")
                                   + ". Run the installer on the server.")

    # WAIT FOR OUR OWN OUTCOME. `schtasks /Run` returns as soon as the task is *started*, not when
    # it finishes, so reading the record immediately would have read whatever was there before —
    # most often the PREVIOUS operation's, which correlates to a different trigger and would have
    # been reported as this one's failure. `systemctl start` for a Type=oneshot blocks until the
    # unit finishes, so on Linux the first poll usually succeeds; the loop is correct either way and
    # does not depend on which behaviour the platform gives us.
    outcome = _await_outcome(request_id, deadline_seconds=_OUTCOME_TIMEOUT_SECONDS)
    if outcome is None:
        # A FOREIGN outcome is not evidence that OUR operation is running — it is evidence about
        # somebody else's. The first version reported `update_still_running` on seeing one, which
        # reads as reassurance and would be equally true if our operation had died immediately.
        # Both cases are the same fact: no matching outcome inside the deadline.
        return ApplyResult(False, "no_matching_outcome", 504, request_id=request_id,
                           message="The privileged update operation recorded no outcome for this "
                                   f"request within {_OUTCOME_TIMEOUT_SECONDS}s. It may still be "
                                   "running, or may have failed before writing; call update_status "
                                   "and check the server log.")
    return _outcome_result(outcome, request_id, actor=actor,
                           audit_outcome=audit_outcome)


def apply(*, expected_head: Optional[str] = None, actor: str = "unknown") -> ApplyResult:
    """Trigger the one fixed elevated update operation and report what root recorded.

    **The service does not update anything.** It resolves installation authority, requires a
    published installation, requires the elevated one-shot, requires the administrator's exact
    authorized tip, writes a correlation id and that tip to a fixed root-owned path, starts one
    fixed unit, and reads root's outcome record.

    `expected_head` is a **refusal-only** consent precondition: the elevated side resolves
    `origin/main` itself and refuses if it differs. It cannot select a ref, and it cannot make an
    otherwise-ineligible update eligible.

    There is no `repo`, `allow_restart` or `restart_scheduler` parameter: restarting is root's, and
    there is no repository for a caller to name.
    """
    from corpusfm.lifecycle import app_paths
    from corpusfm.lifecycle.errors import LifecycleError
    from corpusfm.server import audit

    # No correlation id is minted here. `_trigger_privileged_update` mints the one that is actually
    # written to the inbox and matched against root's outcome; a second id in this frame was carried
    # by nothing and returned in nothing, which reads as a contract the refusals above do not have.
    #
    # INSTALLATION AUTHORITY FIRST, before anything reads a path or probes an operation. A box
    # whose record cannot be read is not an unpublished box (packet 1246-03-01): `is_published()`
    # raises there, and that refusal is the answer rather than something to recover from.
    try:
        published = app_paths.is_published()
    except LifecycleError as exc:
        audit.record(audit.UPDATE_APPLIED, actor=actor, outcome="denied",
                     meta={"reason": "installation_state_unclear", "via": "update_service"})
        return ApplyResult(
            False, "installation_state_unclear", 409, operator_command=operator_command(),
            message=f"Update refused — this installation's own record could not be read ({exc}). "
                    f"Run the installer on the server: {operator_command()}")
    if not published:
        return ApplyResult(
            False, "not_a_published_installation", 409, operator_command=operator_command(),
            message="Update refused — in-app update applies only to an installed CORPUSfm. "
                    "Update a development checkout with git.")

    if not _UPDATE_LOCK.acquire(blocking=False):
        return ApplyResult(False, "update_in_progress", 409,
                           message="An update is already in progress — try again shortly.")
    try:
        # PRIVILEGE BOUNDARY (packet 1246-03). On an installed box the service does not touch the
        # checkout at all — it could not if it wanted to, because that tree is root-owned. There is
        # no other branch: the service triggers the one fixed elevated operation or it refuses.
        state = privileged_updater_state()
        if state == PRIVILEGED_PRESENT:
            if expected_head is None:
                return ApplyResult(
                    False, "consent_required", 400,
                    message="This update needs the exact origin/main tip you inspected. Call "
                            "update_check and authorize that commit.")
            result = _trigger_privileged_update(expected_head=expected_head, actor=actor)
            if result.ok:
                _default_restart_scheduler(True)
            return result

        # No second route, and nothing below this line to fall through to. The one-shot is the ONLY
        # way an installed CORPUSfm advances its own code, so an absent or unprobeable one refuses
        # here: a service that can rewrite its own code has the privilege of whoever can reach it.
        reason = ("could not be probed" if state == PRIVILEGED_UNKNOWN else "is not installed")
        audit.record(audit.UPDATE_APPLIED, actor=actor, outcome="denied",
                     meta={"reason": "privileged_updater_unavailable", "state": state,
                           "via": "update_service"})
        return ApplyResult(
            False, "privileged_updater_unavailable", 409,
            operator_command=operator_command(),
            message=f"Update refused — the privileged update operation {reason} on this "
                    f"installation, and an installed CORPUSfm never updates itself from the "
                    f"service. Run the installer on the server: {operator_command()}")
    finally:
        _UPDATE_LOCK.release()


def _new_request_id() -> str:
    import secrets
    return "upd_" + secrets.token_hex(8)


def _record(request_id: str, *, actor: str, state: str, reason_code: str,
            old_head: Optional[str] = None, old_version: Optional[str] = None,
            expected_head: Optional[str] = None, applied_head: Optional[str] = None,
            applied_version: Optional[str] = None, completed: bool = False,
            restart_mode: str = "none", detail: str = "") -> None:
    """Persist (or update) the single durable request record. Best-effort — a record failure never
    blocks the update. NEVER carries a token, credential-helper output, remote URL, or raw stdout/err."""
    prior = read_record() or {}
    started = prior.get("started_utc") if prior.get("request_id") == request_id else None
    rec = {
        "format": _RECORD_FORMAT,
        "request_id": request_id,
        "actor": str(actor or "unknown")[:200],
        "started_utc": started or _utc_now_iso(),
        "completed_utc": _utc_now_iso() if completed else None,
        "old_head": old_head,
        "old_version": old_version,
        "expected_head": (expected_head or None),
        "applied_head": applied_head,
        "applied_version": applied_version,
        "state": state,
        "reason_code": reason_code,
        "detail": str(detail or "")[:300],
        "restart_mode": restart_mode,
        "control_plane_revision": CONTROL_PLANE_REVISION,
    }
    try:
        _write_record(rec)
    except Exception:
        logger.debug("update_service: could not persist request record", exc_info=True)


# ── status (durable read + lazy restart reconciliation) ──────────────────────────────

@dataclass
class StatusResult:
    ok: bool
    reason_code: str            # "ok" when a record was found/reconciled, else e.g. "no_request"/"unknown_request"
    record: Optional[dict] = None
    message: str = ""


def status(request_id: str = "") -> StatusResult:
    """Read the durable update-request record and lazily reconcile a scheduled restart.

    Empty ``request_id`` → the latest record. An explicit id that does not match the latest record
    refuses clearly (the record store keeps only the most recent attempt). Reconciliation compares the
    RUNNING process's in-memory version (``corpusfm.__version__`` — set at THIS process's import, so a
    fresh post-restart process reads the new stamp while the old one still holds the old value) against
    the applied version: a match promotes ``restart_scheduled`` → ``restarted``; still-old means the
    restart has not landed yet (left ``restart_scheduled``); anything else is a named ``head_mismatch``,
    never a silent success. Status reads never fetch/pull/restart or mutate the repository."""
    rec = read_record()
    if rec is None:
        return StatusResult(False, "no_request", message="No update request has been recorded on this "
                                                          "server yet.")
    if request_id and request_id != rec.get("request_id"):
        return StatusResult(False, "unknown_request", message=f"No update request with id {request_id!r} "
                                                              "— only the most recent attempt is retained.")

    if rec.get("state") == "restart_scheduled":
        import corpusfm as _cfm
        running = _cfm.__version__
        applied_v = rec.get("applied_version")
        old_v = rec.get("old_version")
        if applied_v and running == applied_v:
            rec["state"] = "restarted"
            rec["completed_utc"] = _utc_now_iso()
            rec["detail"] = "Restart confirmed — the running version matches the applied update."
            try:
                _write_record(rec)
            except Exception:
                logger.debug("update_service: could not persist reconciled record", exc_info=True)
        elif old_v and running == old_v:
            # Still the pre-restart process (the supervised SIGTERM has not landed yet). Leave the
            # record as restart_scheduled; a later poll reconciles once the new process serves it.
            pass
        else:
            rec["state"] = "head_mismatch"
            rec["detail"] = (f"Running version {running} matches neither the applied "
                             f"({applied_v}) nor the previous ({old_v}) version.")
            try:
                _write_record(rec)
            except Exception:
                logger.debug("update_service: could not persist mismatch record", exc_info=True)

    return StatusResult(True, "ok", record=rec)
