"""The privilege boundary around the in-app code update (packet 1246-03, E4/E5).

The web service **triggers** one fixed elevated operation and passes it exactly one value; the
elevated side does all the deciding. The service holds no route of its own to the checkout, to git,
or to any ref — there is no in-process update path for it to fall back to.

**`expected_head` is a consent precondition, not a code selector (developer ruling, 2026-08-02).**
The re-scope first proposed removing it, reasoning that a caller-supplied SHA is a caller choosing
code. That was wrong, and the distinction is worth stating precisely because it is the whole design:

    a ref the elevated side CHECKS OUT          → the caller chose the code.  Forbidden.
    a SHA the elevated side REFUSES TO DIFFER FROM → the caller consented to code it already saw.

The elevated side fetches and resolves `origin/main` itself. `expected_head` is compared against that
independently resolved tip and can produce exactly one outcome: a refusal. It cannot name a branch,
cannot reach an older commit, and — because every other gate is evaluated on the resolved tip, never
on the supplied value — **cannot make an otherwise ineligible update eligible**. `assert_consent`
below is written so that its only reachable effect is `raise`.

**Classification decides whether the in-app path is allowed at all.** Installation tools live in a
separate repository, so this module classifies only application-repository paths. Lifecycle, PKI and
proxy-policy application changes remain privileged; an `installer/` path has no special meaning in
this repository after the Series 2 separation.

**A package upgrade publishes one coherent Git observation.** Once the installer advances a
deployed checkout to its independently verified package commit, both ``HEAD`` and the cached
``origin/main`` tracking ref must identify that commit. Leaving the old tracking ref beside the new
checkout makes the read-only update classifier report a false divergence immediately after a valid
upgrade. Packet 1270 changes the installer-owned transaction and changes this privileged policy text
in the same application release so that release cannot be applied through the code-only updater.
"""

from __future__ import annotations

import json
from typing import Protocol
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import LifecycleError

_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")

# Change classes that require the elevated installer. Named rather than boolean so a refusal can say
# WHICH kind of change it saw — an administrator reading "needs the installer" deserves the reason.
CLASS_SERVICE = "service"
CLASS_DEPENDENCY_RUNTIME = "dependency_runtime"
CLASS_LAYOUT = "layout"
CLASS_MANIFEST_SCHEMA = "manifest_schema"
CLASS_PROXY = "proxy"
CLASS_PKI = "pki"
CLASS_HELPER = "helper"
CLASS_CODE_ONLY = "code_only"

PRIVILEGED_CLASSES: tuple[str, ...] = (
    CLASS_SERVICE,
    CLASS_DEPENDENCY_RUNTIME,
    CLASS_LAYOUT,
    CLASS_MANIFEST_SCHEMA,
    CLASS_PROXY,
    CLASS_PKI,
    CLASS_HELPER,
)

# Prefix → class. Longest match wins, so a more specific rule beats a general one.
_PRIVILEGED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("corpusfm/lifecycle/", CLASS_LAYOUT),
    ("corpusfm/install.py", CLASS_LAYOUT),
    ("corpusfm/storage/db_schema_build.txt", CLASS_MANIFEST_SCHEMA),
    ("corpusfm/server/fms_admin_pki.py", CLASS_PKI),
    ("corpusfm/server/cli/cmd_pki.py", CLASS_PKI),
)

_PRIVILEGED_EXACT: dict[str, str] = {
    "requirements.txt": CLASS_DEPENDENCY_RUNTIME,
    # Packet 1246-07's five lifecycle modules. WITHOUT these rows they fall through the
    # ("corpusfm/lifecycle/", CLASS_LAYOUT) prefix above and classify as CLASS_LAYOUT. Both classes
    # are privileged, so nothing is weakened either way — the rows make the class NAME its subject,
    # which is what a reader of an update refusal sees. `fms_admin_pki.py` already has its own
    # CLASS_PKI prefix row and needs no change.
    "corpusfm/lifecycle/admin_identity.py": CLASS_PKI,
    "corpusfm/lifecycle/admin_identity_store.py": CLASS_PKI,
    "corpusfm/lifecycle/admin_identity_ops.py": CLASS_PKI,
    "corpusfm/lifecycle/admin_identity_adapter.py": CLASS_PKI,
    "corpusfm/lifecycle/admin_identity_recovery.py": CLASS_PKI,
}

class UpdateRefused(LifecycleError):
    """The in-app update path may not carry this change, or this consent."""


class ConsentMismatch(UpdateRefused):
    """`origin/main` is not the tip the administrator authorized."""


@dataclass(frozen=True)
class PathVerdict:
    path: str
    change_class: str

    @property
    def privileged(self) -> bool:
        return self.change_class in PRIVILEGED_CLASSES


@dataclass
class Classification:
    verdicts: tuple[PathVerdict, ...] = ()

    @property
    def privileged_classes(self) -> tuple[str, ...]:
        seen: list[str] = []
        for v in self.verdicts:
            if v.privileged and v.change_class not in seen:
                seen.append(v.change_class)
        return tuple(seen)

    @property
    def requires_installer(self) -> bool:
        return bool(self.privileged_classes)

    def reason(self) -> str:
        if not self.requires_installer:
            return ""
        classes = ", ".join(self.privileged_classes)
        example = next(v.path for v in self.verdicts if v.privileged)
        return f"this update changes {classes} (for example {example})"


def classify_path(path: str) -> PathVerdict:
    """One path's class. **Unknown under a privileged tree is privileged.**

    The conservative default applies to the application's privileged lifecycle tree. Installer
    source is not an application-repository namespace in Series 2.
    """
    normalised = str(path).replace("\\", "/").strip().lstrip("./")
    if normalised in _PRIVILEGED_EXACT:
        return PathVerdict(path=path, change_class=_PRIVILEGED_EXACT[normalised])
    best: tuple[str, str] | None = None
    for prefix, klass in _PRIVILEGED_PREFIXES:
        if normalised.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, klass)
    if best is not None:
        return PathVerdict(path=path, change_class=best[1])
    return PathVerdict(path=path, change_class=CLASS_CODE_ONLY)


def classify(paths) -> Classification:
    return Classification(verdicts=tuple(classify_path(p) for p in paths))


def assert_code_only(paths) -> Classification:
    """Refuse the in-app path for a privileged change, naming the elevated installer."""
    result = classify(paths)
    if result.requires_installer:
        raise UpdateRefused(
            f"this update needs the elevated CORPUSfm installer — {result.reason()}. "
            "The in-application update applies ordinary code only."
        )
    return result


# ── consent ───────────────────────────────────────────────────────────────────────────

def assert_consent(expected_head: str, resolved_head: str) -> None:
    """Refuse unless the independently resolved tip is the one the administrator authorized.

    **This function can do exactly one thing: raise.** It returns `None` on success and its result is
    never used to choose anything, which is the mechanical form of "a precondition, not a selector".
    `resolved_head` is what the elevated side fetched for itself; `expected_head` is only ever
    compared to it.
    """
    if not isinstance(resolved_head, str) or not _SHA_RE.match(resolved_head.strip().lower()):
        raise UpdateRefused(
            "the elevated updater could not resolve origin/main to a commit; refusing to proceed"
        )
    supplied = (expected_head or "").strip().lower()
    if not supplied:
        raise ConsentMismatch(
            "this update was not authorized against a specific origin/main tip. Read the current "
            "tip with update_check and authorize that exact commit."
        )
    if not _SHA_RE.match(supplied):
        raise ConsentMismatch(
            "the authorized tip is not a commit SHA. Read it from update_check and pass it verbatim."
        )
    resolved = resolved_head.strip().lower()
    # EXACT equality, not a prefix match (ruling O2: "the exact tip the administrator authorized").
    #
    # The first version accepted an abbreviation that prefixed the resolved tip, reasoning that this
    # could not widen consent because a longer supplied value never matches a shorter resolved one.
    # That reasoning was about the wrong axis. An abbreviation authorizes EVERY commit sharing the
    # prefix, so `expected_head="a60d5c7"` consents in advance to a tip nobody has seen — which is
    # exactly the case where equality would refuse and the administrator would re-read. Codex found
    # it; `update_check` returns a full SHA, so requiring the whole thing costs the caller nothing.
    if resolved != supplied:
        raise ConsentMismatch(
            f"origin/main is now {resolved[:12]}, but this update was authorized for "
            f"{supplied[:12]}. Re-run update_check and authorize the current tip."
        )


# ── outcome record (developer ruling O4) ──────────────────────────────────────────────

# TWO DIRECTORIES, TWO AUTHORITIES (developer ruling, 2026-08-03).
#
# The request inbox is written by the service, so it is service-writable. The outcome is written by
# ROOT and must not be forgeable: the first version put both in one service-writable state
# directory, which meant a service could author an outcome naming its own known trigger id and have
# it read back as root's verdict. Correlation is not authentication.
#
# So the outcome lives in its own root-owned directory the service may traverse and read and may not
# create, delete or rename entries in — directory authority is what makes the file's protection
# mean anything, on NTFS and POSIX alike.
INBOX_DIRNAME = "update-inbox"
OUTCOME_DIRNAME = "update-outcome"
REQUEST_FILENAME = "update_request.json"
OUTCOME_FILENAME = "update_outcome.json"

OUTCOME_STATES: tuple[str, ...] = (
    "started",
    "refused",
    "failed",
    "rolled_back",
    "completed",
)


@dataclass
class UpdateOutcome:
    """What the elevated operation did, written by root and read by the service.

    The service cannot write this — that is the point. Without it the service cannot tell its own
    trigger from one already running, a fresh result from a stale one, or which head actually landed.
    Carries no secret: paths and SHAs only, and the log LOCATION rather than the log.
    """

    operation_id: str
    trigger_id: str
    state: str
    requested_head: str = ""
    observed_head: str = ""
    resulting_head: str = ""
    started_utc: str = ""
    ended_utc: str = ""
    reason_code: str = ""
    detail: str = ""
    log_path: str = ""
    rolled_back: bool = False
    privileged_classes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        if self.state not in OUTCOME_STATES:
            raise LifecycleError(f"unknown update outcome state {self.state!r}")
        return {
            "operation_id": self.operation_id,
            "trigger_id": self.trigger_id,
            "state": self.state,
            "requested_head": self.requested_head,
            "observed_head": self.observed_head,
            "resulting_head": self.resulting_head,
            "started_utc": self.started_utc,
            "ended_utc": self.ended_utc,
            "reason_code": self.reason_code,
            "detail": self.detail,
            "log_path": self.log_path,
            "rolled_back": self.rolled_back,
            "privileged_classes": list(self.privileged_classes),
        }

    @staticmethod
    def from_dict(data: object) -> "UpdateOutcome":
        if not isinstance(data, dict):
            raise LifecycleError("an update outcome record must be a JSON object")
        state = data.get("state")
        if state not in OUTCOME_STATES:
            raise LifecycleError(f"unknown update outcome state {state!r}")
        return UpdateOutcome(
            operation_id=str(data.get("operation_id") or ""),
            trigger_id=str(data.get("trigger_id") or ""),
            state=str(state),
            requested_head=str(data.get("requested_head") or ""),
            observed_head=str(data.get("observed_head") or ""),
            resulting_head=str(data.get("resulting_head") or ""),
            started_utc=str(data.get("started_utc") or ""),
            ended_utc=str(data.get("ended_utc") or ""),
            reason_code=str(data.get("reason_code") or ""),
            detail=str(data.get("detail") or ""),
            log_path=str(data.get("log_path") or ""),
            rolled_back=bool(data.get("rolled_back")),
            privileged_classes=tuple(data.get("privileged_classes") or ()),
        )


#: The exact field names the outcome record may carry. A name outside this set is refused rather
#: than dropped — a *field name* is one of the shapes a secret arrives in, and silently ignoring an
#: unknown key means the fence never sees it.
OUTCOME_FIELDS: tuple[str, ...] = tuple(UpdateOutcome.__dataclass_fields__)


def inbox_dir(state_dir: Path | str) -> Path:
    return Path(state_dir) / INBOX_DIRNAME


def outcome_dir(state_dir: Path | str) -> Path:
    return Path(state_dir) / OUTCOME_DIRNAME


def request_path(state_dir: Path | str) -> Path:
    return inbox_dir(state_dir) / REQUEST_FILENAME


def outcome_path(state_dir: Path | str) -> Path:
    return outcome_dir(state_dir) / OUTCOME_FILENAME


class WindowsOutcomeAcl(Protocol):
    """The platform calls the Windows outcome check makes.

    Declared here so the policy can be exercised against a double on any machine, and so
    `effective_rights` is part of the contract rather than something an implementation may omit —
    which is exactly how the previous version came to stop at "protected".
    """

    def sid(self, account: str) -> object: ...
    def dacl_is_protected(self, path) -> bool: ...
    def effective_rights(self, path, trustee: object) -> int: ...


#: NTFS rights that would let their holder place or alter a file in the outcome directory. A reader
#: that can write its own evidence is not reading evidence.
OUTCOME_WRITE_AUTHORITY = 0x0002 | 0x0004 | 0x0040 | 0x00010000 | 0x00040000 | 0x00080000 \
    | 0x40000000 | 0x10000000


def _assert_windows_outcome_authority(directory, *, service_accounts=(), api=None) -> None:
    """Read the real DACL AND the effective rights. Any doubt is a refusal.

    **R4.** The previous version stopped at "the DACL is protected" and said so in a comment — that
    inheritance is disabled says nothing about what the DACL itself grants, so a directory
    explicitly granting the service Modify passed. Non-inheritance and non-authority are two
    different properties and only the second one is the guarantee.
    """
    try:
        acl = api if api is not None else _real_windows_outcome_acl()
        if not acl.dacl_is_protected(directory):
            raise OutcomeAuthorityUnproven(
                f"{directory} inherits its permissions, so whatever its parent grants reaches it; "
                "an outcome read from here is not evidence of what the privileged operation did"
            )
        for account in service_accounts:
            held = int(acl.effective_rights(directory, acl.sid(account)))
            if held & OUTCOME_WRITE_AUTHORITY:
                raise OutcomeAuthorityUnproven(
                    f"{directory} grants {account} write authority (0x{held:08x}); the outcome "
                    "record would be forgeable by its own reader"
                )
    except OutcomeAuthorityUnproven:
        raise
    except Exception as exc:
        raise OutcomeAuthorityUnproven(
            f"the permissions on {directory} could not be established ({exc}); refusing to treat "
            "anything read from it as root's word"
        ) from exc


def _real_windows_outcome_acl():  # pragma: no cover - exercised only on Windows
    from .protection import _RealWindowsAclApi

    return _RealWindowsAclApi()


class OutcomeAuthorityUnproven(LifecycleError):
    """The outcome location is not protected, so nothing read from it is root's word."""


#: The Windows service identities whose rights over the outcome directory must be checked. Empty is
#: not a safe default — a check that queries no trustee proves nothing about any of them — so the
#: caller cannot silently supply none.
#:
#: `NT SERVICE\corpusfm-scheduler` is GONE (packet 1361-01, round 3), and its removal is a FIX, not
#: only tidying. That service is retired, so on a current installation the virtual account has no
#: SID at all — `acl.sid()` refuses with error 1332, the helper below turns any exception into
#: `OutcomeAuthorityUnproven`, and every privileged update on a fresh Windows box would have refused
#: because a trustee that does not exist could not be shown not to have write.
DEFAULT_SERVICE_ACCOUNTS: tuple = ("NT SERVICE\\corpusfm-web",)


def assert_outcome_authority(state_dir: Path | str, *, service_uid: int | None = None,
                            admin_uid: int = 0, service_accounts=None, windows_acl=None,
                            _force_windows: bool = False) -> None:
    """Prove the outcome location cannot be written by the service, before trusting anything in it.

    Checked at TRIGGER time rather than assumed from the installer having run: an outcome is only
    evidence if the place it came from is one the reader could not have written. On POSIX that means
    the directory is not owned by, and not group/other-writable to, the service; on Windows the
    equivalent ACL check belongs to the installer, which establishes and reports it (a Python
    directory is not owned by, and not group/other-writable to, the service; on Windows it means the
    DACL is protected AND grants no service trustee write authority — read back through the
    platform, not inferred from the fact that inheritance is off.
    """
    import os
    import stat as _stat

    directory = outcome_dir(state_dir)
    try:
        info = os.stat(directory)
    except FileNotFoundError as exc:
        raise OutcomeAuthorityUnproven(
            f"{directory} does not exist; the privileged updater has not been installed"
        ) from exc
    except OSError as exc:
        raise OutcomeAuthorityUnproven(f"{directory} could not be inspected: {exc}") from exc

    if os.name == "nt" or _force_windows:  # pragma: no cover - platform branch
        # Windows CHECKS rather than returning. The first version returned unconditionally, which
        # made the whole guarantee a Linux-only one while reading as cross-platform. Effective
        # rights need the platform API, so this asks it: the directory must be protected (not
        # inheriting from a parent the service can write) and must not grant this identity write.
        accounts = DEFAULT_SERVICE_ACCOUNTS if service_accounts is None else service_accounts
        if not accounts:
            raise OutcomeAuthorityUnproven(
                f"no service identity was named for the {directory} rights check; a check that "
                "queries no trustee establishes nothing about any of them"
            )
        _assert_windows_outcome_authority(directory, service_accounts=accounts, api=windows_acl)
        return
    mode = _stat.S_IMODE(info.st_mode)
    if mode & (_stat.S_IWGRP | _stat.S_IWOTH):
        raise OutcomeAuthorityUnproven(
            f"{directory} is group- or other-writable ({mode:04o}); an outcome read from it is not "
            "evidence of what the privileged operation did"
        )
    effective = os.geteuid() if service_uid is None else service_uid
    if info.st_uid == effective and effective != admin_uid:
        raise OutcomeAuthorityUnproven(
            f"{directory} is owned by the identity that reads it (uid {effective}); the outcome "
            "record would be forgeable by its own reader"
        )
    # "Not the service" is not the requirement. A third identity — some other daemon, a stray
    # account — can write the outcome just as well, and the record's whole value is that only the
    # elevated operation could have produced it. So the owner must be the ADMINISTRATOR, named
    # rather than written as the literal 0 so a test can exercise the rule without root.
    if info.st_uid != admin_uid:
        raise OutcomeAuthorityUnproven(
            f"{directory} is owned by uid {info.st_uid}, not the installing administrator "
            f"({admin_uid}); an outcome read from it is not evidence of what the privileged "
            "operation did"
        )


def write_outcome(state_dir: Path | str, outcome: UpdateOutcome) -> Path:
    """Root writes this. Goes through the lifecycle's atomic writer, world-readable by design —
    it holds no secret and the service must be able to read it as an ordinary user."""
    from .atomic import atomic_write_text
    from .secret_guard import assert_no_secrets

    payload = outcome.to_dict()
    assert_no_secrets(payload, what="update outcome record")
    path = outcome_path(state_dir)
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True), mode=0o644)
    return path


def read_outcome(state_dir: Path | str) -> UpdateOutcome | None:
    path = outcome_path(state_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise LifecycleError(f"the update outcome record at {path} could not be read: {exc}") from exc
    return UpdateOutcome.from_dict(raw)


# ── rendering the updaters from resolved authority ────────────────────────────────────
#
# Deliverable 3 / R4-Linux, and N1. The updater artifacts carry fixed locations by design — an
# environment override inside a root script that rewrites the box's code is authority in a variable.
# But the values that get FIXED were install-time literals: the Linux updater rendered
# `$INSTALL_DIR/.corpusfm` while the application resolved `/var/lib/corpusfm/state`, so root and the
# service disagreed about where the request and outcome lived.
#
# The first fix took a `ResolvedPaths` and CHECKED the caller's install/checkout/interpreter/git
# against it. That is a boundary the caller draws: whoever calls it still names four of the seven
# values, and a check performed on a caller's own input is only ever as good as the caller. So there
# is now **nothing to pass**. This module resolves the published locator and its agreeing manifest
# itself, derives every path from the manifest plus one fixed installed layout, and resolves git
# through the same fixed absolute candidate list the inspector uses. Indeterminate, development,
# missing or contradictory authority refuses before anything is rendered.

HELPER_DIRNAME = "bin"
HELPER_FILENAME = "tree_inspection.py"
PUBLISHER_FILENAME = "publish_outcome.py"

#: The administrator-owned Python library root. NOT the checkout: the classifier and the outcome
#: fence are both judgments ABOUT the checkout, so loading them from it is R7b one module over.
LIBRARY_DIRNAME = "lib"
#: The deployed checkout, relative to the install directory. Fixed by the new-format layout — the
#: manifest records the installation's directories, not its internal furniture.
CHECKOUT_DIRNAME = "src"

#: `@@VENV_PY@@` is the spelling the two shipped templates carry, and renaming it means editing
#: `installer/{linux,windows}/corpusfm-update.{sh,ps1}` — a wider change than this correction. The
#: NAME is stale on Windows; the VALUE behind it is the platform's real interpreter, below.
LINUX_PLACEHOLDERS = ("@@INSTALL_DIR@@", "@@STATE_DIR@@", "@@LOG_DIR@@", "@@SRC_DIR@@",
                      "@@VENV_PY@@", "@@HELPER@@", "@@PUBLISHER@@", "@@LIB_DIR@@", "@@GIT@@")
WINDOWS_PLACEHOLDERS = LINUX_PLACEHOLDERS


class UpdaterPathsUnresolved(LifecycleError):
    """A rendered updater path is not one the installation's own record accounts for."""


class UpdaterAuthorityUnresolved(UpdaterPathsUnresolved):
    """There is no published installation to render an updater for, or its record disagrees."""


def helper_path(install_dir: Path | str) -> Path:
    """Where the tree inspector is invoked FROM.

    `InstallDir/bin/tree_inspection.py` — administrator-owned, protected like the updater script
    itself, and **outside the checkout being judged**. R7b: both updaters used to put the checkout
    on `PYTHONPATH` and run `-m corpusfm.lifecycle.tree_inspection`, so a modified helper inside a
    modified tree declared that tree clean. The helper imports only the standard library precisely
    so it can live here as a plain file with nothing to resolve.
    """
    return Path(install_dir) / HELPER_DIRNAME / HELPER_FILENAME


def publisher_path(install_dir: Path | str) -> Path:
    """Where the outcome record is WRITTEN from — the same administrator-owned location, for the
    same reason (N2). The shell and PowerShell artifacts collect fields; this boundary validates
    them against `UpdateOutcome` and `secret_guard.assert_no_secrets` and performs the atomic write,
    so the secret patterns exist once, in Python, rather than transliterated into two shells."""
    return Path(install_dir) / HELPER_DIRNAME / PUBLISHER_FILENAME


def library_path(install_dir: Path | str) -> Path:
    return Path(install_dir) / LIBRARY_DIRNAME


def interpreter_relative(flavour: str) -> str:
    """The interpreter each platform's installer actually places, relative to the install directory.

    **The two are not one layout spelled twice, and treating them as one was a real defect.** Linux
    builds a venv from the bundled python-build-standalone CPython, so its interpreter is
    `venv/bin/python`. Windows extracts the python.org embeddable distribution and treats *that* as
    the isolated environment — an embeddable build ships no `ensurepip`, `install.ps1` therefore
    creates no venv at all, and the interpreter is `python\\python.exe`.

    This module used to hold a `_VENV_INTERPRETER` table whose two entries were `bin/python` and
    `Scripts/python.exe` under a shared `venv/`. The name asserted the wrong thing and the Windows
    value followed it: `<install_dir>\\venv\\Scripts\\python.exe` is a path the shipped Windows
    installer never creates, rendered into the one artifact that runs as SYSTEM.

    The spelling is READ from `service_identity`, which is where the service definitions get theirs,
    so the elevated updater and the units the box runs cannot come to disagree about which
    interpreter exists.
    """
    from .service_identity import POSIX_INTERPRETER, WINDOWS_INTERPRETER

    try:
        return {"posix": POSIX_INTERPRETER, "windows": WINDOWS_INTERPRETER}[flavour]
    except KeyError as exc:
        raise UpdaterAuthorityUnresolved(
            f"the installation records {flavour!r} paths, which names no interpreter layout; "
            "refusing to guess one"
        ) from exc


#: Where `install.ps1` extracts MinGit, relative to the install directory. Measured from the shipped
#: installer (`$Git = Join-Path $InstallDir 'git\cmd\git.exe'`), not assumed.
WINDOWS_GIT_RELATIVE = r"git\cmd\git.exe"


def _windows_git_path(install_dir) -> str:
    """The git the WINDOWS installation owns, derived from its own record.

    `tree_inspection.GIT_CANDIDATES` is four POSIX paths — `/usr/bin/git` and friends. It has no
    Windows entry and never could sensibly have one, because the Windows box's git is not at a fixed
    system location: `install.ps1` downloads MinGit and extracts it INSIDE the install directory.
    So on Windows the fixed absolute list is the wrong instrument, and the installation's own record
    is the right one — the same reasoning that gives this module every other path it renders.

    The rule the candidate list exists to enforce is unchanged and is enforced here: one absolute
    location, decided before the elevated script runs, never `PATH` and never `where.exe`. Existence
    is required for the same reason `git_executable` requires it — rendering `@@GIT@@` to a path
    with nothing at it produces a root script that fails at its first command.
    """
    parts = [p for p in WINDOWS_GIT_RELATIVE.split("\\") if p]
    #: PROBED with the host's own path semantics and RENDERED with the target's. On the only machine
    #: that renders a Windows updater — a Windows one — `Path` *is* `WindowsPath` and the two are the
    #: same string; the distinction exists so the probe is a real file test wherever this runs,
    #: rather than a lookup of a backslash-spelled name on a POSIX filesystem.
    rendered = str(_pure("windows", str(install_dir)).joinpath(*parts))
    if not Path(install_dir).joinpath(*parts).is_file():
        raise UpdaterAuthorityUnresolved(
            f"this installation records no git at {rendered}; the elevated updater will not be "
            "rendered with a git resolved through PATH, so it is not rendered at all"
        )
    return rendered


def _interpreter_path(flavour: str, install_dir) -> str:
    """The absolute interpreter, joined with the TARGET platform's separator.

    Joined through `_pure` rather than `Path` so a Windows installation renders `\\` even when the
    derivation runs somewhere else — the same reason every other check in this module takes a
    flavour.
    """
    parts = [p for p in re.split(r"[\\/]", interpreter_relative(flavour)) if p]
    return str(_pure(flavour, str(install_dir)).joinpath(*parts))


@dataclass(frozen=True)
class InstalledUpdaterAuthority:
    """One published installation, read once, with everything the updaters are rendered from."""

    install_dir: Path
    paths: object
    flavour: str
    source: str


def resolve_updater_authority() -> InstalledUpdaterAuthority:
    """The published locator and its agreeing manifest, or a refusal. **It takes nothing.**

    An earlier version kept 03-01's `layout` / `locator` injection seams "for tests". They were a
    real seam in the production signature: a caller supplying a locator that named any
    schema-consistent manifest chose the install root, and every derived path with it — the
    containment check then only proved the derived files sat beneath the root that caller had
    picked. A boundary the caller draws is not a boundary.

    So there is no parameter. Production and tests take the same route: `platform_layout()` and
    `locator_for()`, resolved here. A test redirects them by patching those two module functions
    **in its own process** and publishing a real temporary locator and manifest — which changes what
    the operating system appears to hold, not what this function will accept from a caller. No argv,
    environment variable, request field, installer flag or public parameter reaches this.
    """
    from . import app_paths
    from .layout import platform_layout
    from .locator import locator_for
    from .manifest import ManifestStore
    from .schema import assert_identity_agrees, path_flavour

    lay = platform_layout()
    try:
        adapter = locator_for(lay)
        present = adapter.exists()
    except Exception as exc:
        raise UpdaterAuthorityUnresolved(
            f"the CORPUSfm installation record for {lay.describe_locator()} could not be examined "
            f"({exc}); refusing to render an elevated updater against a layout we had to guess"
        ) from exc
    if not present:
        raise UpdaterAuthorityUnresolved(
            f"there is no published CORPUSfm installation at {lay.describe_locator()}; the elevated "
            "updater is an installed artifact and is not rendered for anything else"
        )
    try:
        record = adapter.read()
        store = ManifestStore(Path(record.install_dir), record.manifest_relative_path)
        manifest = store.read()
        assert_identity_agrees(record, manifest, manifest_path=str(store.path))
    except Exception as exc:
        raise UpdaterAuthorityUnresolved(
            f"the installation record at {lay.describe_locator()} is unreadable or contradictory "
            f"({exc}); a published installation that cannot be read is not an unpublished one"
        ) from exc

    paths = app_paths.resolve()
    if paths.state != app_paths.PUBLISHED:
        raise UpdaterAuthorityUnresolved(
            f"this installation resolves as {paths.describe()}; the elevated updater is rendered "
            "only for a published installation"
        )
    install_dir = Path(manifest.paths.install_dir)
    return InstalledUpdaterAuthority(
        install_dir=install_dir,
        paths=paths,
        flavour=path_flavour(manifest.paths.install_dir),
        source=lay.describe_locator(),
    )


def updater_substitutions() -> dict:
    """Every value the rendered updater will carry, derived from the installation's own record.

    **It takes nothing.** The install directory comes from the manifest, the checkout / interpreter
    / helper / publisher / library from the fixed installed layout beneath it, the state and log
    directories from 03-01's resolver, and git from the fixed absolute candidate list — resolved
    through `tree_inspection.git_executable`, looked up on the module so a test can point it at a
    temporary binary without any production argument, request field or environment variable existing
    that could select one.

    Git is the one value with a per-flavour source, and it is not an exception to the rule. That
    candidate list is four POSIX system paths; a Windows box's git is the MinGit `install.ps1`
    extracts INSIDE the install directory, so on Windows it comes from the installation's record
    like everything else. Both routes settle one absolute location before the elevated script runs,
    which is the whole of what the rule asks.
    """
    from . import tree_inspection

    authority = resolve_updater_authority()
    install_dir, paths = authority.install_dir, authority.paths

    src_dir = install_dir / CHECKOUT_DIRNAME
    interpreter = _interpreter_path(authority.flavour, install_dir)
    helper = helper_path(install_dir)
    publisher = publisher_path(install_dir)
    library = library_path(install_dir)
    if authority.flavour == "windows":
        git = _windows_git_path(install_dir)
    else:
        try:
            git = tree_inspection.git_executable()
        except tree_inspection.GitUnavailable as exc:
            raise UpdaterAuthorityUnresolved(
                f"no git executable is available at a known absolute location ({exc}); the elevated "
                "updater will not be rendered with one resolved through PATH"
            ) from exc

    values = {
        "@@INSTALL_DIR@@": str(install_dir),
        "@@STATE_DIR@@": str(paths.state_dir),
        "@@LOG_DIR@@": str(paths.log_dir),
        "@@SRC_DIR@@": str(src_dir),
        "@@VENV_PY@@": interpreter,
        "@@HELPER@@": str(helper),
        "@@PUBLISHER@@": str(publisher),
        "@@LIB_DIR@@": str(library),
        "@@GIT@@": str(git),
    }
    _assert_under(install_dir, (src_dir, interpreter, helper, publisher, library),
                  what="the install directory", flavour=authority.flavour)
    # The git rule answers BEFORE the generic one: both would refuse `git`, but only this message
    # says why a relative git is a different kind of mistake from a relative log directory.
    if not _pure(authority.flavour, str(git)).is_absolute():
        raise UpdaterPathsUnresolved(
            f"the git executable {str(git)!r} is not an absolute path; resolving it through "
            "PATH is exactly what the elevated side must not do"
        )
    _assert_absolute(values, flavour=authority.flavour)
    return values


def _pure(flavour: str, value: str):
    from pathlib import PurePosixPath, PureWindowsPath

    return PureWindowsPath(value) if flavour == "windows" else PurePosixPath(value)


def _collapsed(flavour: str, value: str):
    """`..` and `.` removed with the TARGET platform's semantics, before any containment test.

    `PurePath.relative_to` does not collapse anything, so `/opt/CORPUSfm/../../tmp/x` compares as
    contained — the defect 03-02 was corrected on, in the module next door.
    """
    pure = _pure(flavour, value)
    parts: list[str] = []
    for part in pure.parts[1:] if pure.anchor else pure.parts:
        if part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return _pure(flavour, pure.anchor).joinpath(*parts)


def _assert_under(root: Path, candidates, *, what: str, flavour: str) -> None:
    collapsed_root = _collapsed(flavour, str(root))
    for candidate in candidates:
        collapsed = _collapsed(flavour, str(candidate))
        if not collapsed.is_relative_to(collapsed_root):
            raise UpdaterPathsUnresolved(
                f"{candidate} is not inside {what} ({root}); every path the elevated updater uses "
                "comes from the installation's own record"
            )


def _assert_absolute(values: dict, *, flavour: str) -> None:
    for name, value in values.items():
        if not _pure(flavour, value).is_absolute():
            raise UpdaterPathsUnresolved(f"{name} rendered {value!r}, which is not an absolute path")


# ── the production rendering entry points ─────────────────────────────────────────────
#
# There are exactly two. The focused installer supplies the template bytes from its verified private
# runtime; this application derives every installation-specific substitution and performs the
# platform-specific rendering. Supplying bytes grants no write or execution authority.
#
# The public `render_updater(template, substitutions, ...)` they replace was the last seam. Removing
# `layout=`/`locator=` from the authority resolver closed the front door while that one stood open:
# a caller could hand-build a substitution dict naming any install directory, checkout, interpreter,
# helper, library or git binary and render a perfectly valid elevated artifact from it. The
# derivation being airtight is worth nothing if the renderer accepts values that never went through
# it.

@dataclass(frozen=True)
class _UpdaterPlan:
    """One resolved rendering. Built here and nowhere else; not a caller-facing type."""

    template: str
    values: dict
    placeholders: tuple
    quoting: str


def _plan_from_authority(template: str, placeholders, quoting: str) -> _UpdaterPlan:
    if not isinstance(template, str) or not template.strip():
        raise UpdaterPathsUnresolved("the focused installer supplied no updater template bytes")
    return _UpdaterPlan(template=template, values=updater_substitutions(),
                        placeholders=tuple(placeholders), quoting=quoting)


def render_linux_updater(template: str) -> str:
    """Render verified focused-installer bytes with this installation's own record."""
    return _substitute(_plan_from_authority(template, LINUX_PLACEHOLDERS, "none"))


def render_windows_updater(template: str) -> str:
    """Render verified focused-installer bytes with this installation's own record."""
    return _substitute(
        _plan_from_authority(template, WINDOWS_PLACEHOLDERS, "powershell"))


def _substitute(plan: "_UpdaterPlan") -> str:
    """The mechanical half, private and plan-only. **Not a production entry point.**

    Substitute, then prove nothing is left. A placeholder that survives is a path the script would
    use literally — `@@STATE_DIR@@/update-inbox` is a real directory name.

    `quoting="powershell"` doubles apostrophes, because the Windows artifact carries these values
    inside single-quoted literals: one `'` in an installation path ends the literal and the rest of
    the path becomes PowerShell. Raw replacement into a quoted context is the rendering escape this
    family has already been caught by once.
    """
    template, substitutions = plan.template, plan.values
    placeholders, quoting = plan.placeholders, plan.quoting
    missing = [p for p in placeholders if p not in substitutions]
    if missing:
        raise UpdaterPathsUnresolved(f"no value was derived for {', '.join(missing)}")
    if quoting not in ("none", "powershell"):
        raise UpdaterPathsUnresolved(f"unknown quoting {quoting!r}")
    rendered = template
    for name, value in substitutions.items():
        if quoting == "powershell":
            if "\x00" in value or "\n" in value or "\r" in value:
                raise UpdaterPathsUnresolved(
                    f"{name} rendered a value containing a line break or NUL, which no quoting "
                    "makes safe inside a PowerShell literal"
                )
            value = value.replace("'", "''")
        rendered = rendered.replace(name, value)
    left = [p for p in placeholders if p in rendered]
    if left:
        raise UpdaterPathsUnresolved(
            f"the rendered updater still contains {', '.join(left)}; it would use the placeholder "
            "as a literal path"
        )
    return rendered
