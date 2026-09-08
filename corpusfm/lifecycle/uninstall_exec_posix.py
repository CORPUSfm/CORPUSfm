"""Executing the typed pending operations — the boundary, and the POSIX half (1246-09 stage 4).

**The caller never supplies a target.** That sentence is the whole design, and it is the correction
§X made after reproducing seven failures against the retired executor: the pending record handed
over a string, so everything an operation actually needed — an install directory, a database name, a
fingerprint, a proof that something else happened first — arrived from the caller, and *a caller that
supplies the target authority is a caller that could supply any target*.

So:

* **one construction path.** `for_installation(layout, lock=…)` reads the record from its **fixed**
  location under a held, matching lifecycle lock. The bare constructor refuses — §X.1 #1 is exactly
  what a second entry point costs, and "only `for_installation` enforces provenance" was not a
  guarantee while `__init__` was public;
* **no record and no `install_dir` argument.** Both are read from the fixed evidence, every time;
* **a reread before EVERY operation, and between the substeps of one.** A checkpoint immediately
  revokes authority (§X.1 #3): the executor holds `operation_id` and `installation_id` and nothing
  else, so an operation that was checkpointed away between two substeps stops the rest of the work;
* **public methods take a resource NAME and operational collaborators only** — an FMS adapter, an
  admin API client, a proxy engine, a credential lease, a subprocess runner. Never a path, never a
  service name, never a fingerprint;
* **the executor enforces its own preconditions and read-backs.** A storage removal proves the
  database unhosted *inside* the same method; a service removal requires the stop to have succeeded
  before a definition is touched.

**Two exit modes, and the difference is deliberate.** An `ExecutorRefused` means the *authority*
could not be established — no record, a foreign one, a resource that is not owed or already
checkpointed, a duplicate, the wrong kind, the wrong platform. Nothing was attempted and there is
nothing to report about the box. Everything else returns an `Outcome`: the authority was good and
this is what the box did, including a `refused` when the box disagrees with the record.

**`checkpointable` is never derived from a return code.** It is set by the handler, and only after
the *entire* typed resource reached its terminal state **and that state was read back**. A successful
`systemctl`, `sc`, `schtasks`, PATCH or DELETE is an account of a command, not an observation of a
resource.

**Where the base class lives.** Stage 4 adds exactly two modules, so the platform-neutral
`UninstallExecutor` sits here beside the POSIX subclass and `uninstall_exec_windows` imports it.
Nothing in the base is POSIX-specific: the exact-path, storage, proxy, PKI and patch-slot handlers
are identical on both platforms, and the two subclasses supply only the managed-unit and account
behaviour — which is the whole of the difference between them.
"""

from __future__ import annotations

import ntpath
import errno
import os
import posixpath
import stat as _stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import fms_folders as ff
from . import service_control as sc
from . import uninstall_pending as pending
from .errors import LifecycleError
from .layout import POSIX, WINDOWS
from .lock import LockNotHeld, require_lock
from .service_identity import REMOVABLE_SERVICE_ROLES, UNIT_KIND_SERVICE

# ── the closed outcome vocabulary ─────────────────────────────────────────────

EXEC_COMPLETED = "completed"
EXEC_ALREADY_ABSENT = "already_absent"
EXEC_REFUSED = "refused"
EXEC_FAILED = "failed_unknown"
EXEC_STATES: tuple = (EXEC_COMPLETED, EXEC_ALREADY_ABSENT, EXEC_REFUSED, EXEC_FAILED)

#: The only two results a handler may pair with `checkpointable=True`. A refusal changed nothing and
#: a failure does not know what it changed, so neither may retire pending authority.
EXEC_TERMINAL: frozenset = frozenset({EXEC_COMPLETED, EXEC_ALREADY_ABSENT})

#: The early-quiesce operation's name. It is NOT a pending resource — it removes nothing and is
#: never checkpointed — so it is named here rather than borrowed from the record.
STOP_SERVICES = "stop_app_services"

#: Named refusals, so a caller can branch on the reason without parsing prose.
REFUSE_CONTROL_PLANE = "control_plane_path_inside_target"
REFUSE_LINK = "recorded_path_is_a_link"
REFUSE_MOUNT = "entry_on_another_volume"
REFUSE_SUBSTITUTED = "entry_replaced_between_read_and_open"
REFUSE_NOT_A_DIRECTORY = "recorded_path_is_not_what_the_record_says"
REFUSE_SUPPORT_NOT_EMPTY = "support_directory_is_not_empty"
REFUSE_CONJUNCTION = "service_conjunction_disagrees"
REFUSE_FINGERPRINT = "recorded_fingerprint_disagrees"
REFUSE_SLOT = "slot_holds_another_path"
REFUSE_COMPARTMENT_NOT_EMPTY = "hosting_directory_is_not_empty"
REFUSE_VIRTUAL_ACCOUNT = "windows_service_identity_is_virtual"
REFUSE_STORAGE_NEEDS_FMS = "storage_removal_requires_an_fms_observation"
REFUSE_FMS_ROOT_PRESENT = "recorded_filemaker_server_root_is_present"
REFUSE_FMS_ROOT_UNUSABLE = "recorded_filemaker_server_root_is_not_observable"
REFUSE_IDENTITY_UNUSABLE = "recorded_identity_store_is_not_usable"
REFUSE_IDENTITY_MISMATCH = "stored_identity_names_another_registration"
#: **The tree being removed holds the process removing it** (packet 1000-14). The retired Windows
#: uninstaller stepped its working directory out of the install root before deleting it; the
#: deletion moved here and the guard did not come with it. It covers the half that guard never did
#: as well — the EXECUTING IMAGE — and it is a refusal rather than an attempt because a platform
#: that cannot unlink a running interpreter discovers that *part-way through* a tree it has already
#: begun to delete, which is durable pending evidence on a box with nothing left able to read it.
REFUSE_SELF_RUNTIME = "target_holds_this_running_uninstall"
REFUSE_READONLY_AUTHORITY = "read_only_retry_authority_unproven"

# ── WINDOWS-SPECIFIC refusal reasons, defined HERE and not in the Windows module ──────────────
#
# **These are emitted by the shared boundary, so they belong to it.** `REFUSE_NO_QUIESCE_PRIMITIVE`
# lived only in this module while only the Windows executor raised it, which is a reason code with
# no home: a caller switching on it had to import it from the platform that does not use it. A
# reason travels with the layer that defines the vocabulary, not with the one platform that happens
# to emit it today.
REFUSE_NO_QUIESCE_PRIMITIVE = "no_stop_only_primitive_on_this_platform"
REFUSE_SERVICE_NOT_STOPPED = "recorded_service_did_not_reach_stopped"
REFUSE_SERVICE_UNREADABLE = "recorded_service_registration_unreadable"
REFUSE_SERVICE_ABSENT = "recorded_service_registration_absent"
REFUSE_RECORDED_FRONT_UNUSABLE = "recorded_proxy_front_is_not_usable"
REFUSE_PROXY_COMPONENT = "the_proxy_component_refused"
REFUSE_AMBIGUOUS_REGISTRATION = "more_than_one_registration_carries_the_recorded_name"
REFUSE_QUIESCE_INCOMPLETE = "an_early_quiesce_target_refused"
#: **The one refusal a launcher is allowed to act on** (packet 1246-09 stage 6). The recorded proxy
#: removal needs an FMS administrator credential to take effect and none was supplied — established
#: from the real plan's activation mechanism, BEFORE the editor, the activation or the engine has
#: run. It is not a rejected credential (that one was supplied and refused, and is `failed_unknown`),
#: and it is never inferred from a resource name or from prose.
REFUSE_CREDENTIAL_REQUIRED = "credential_required"

#: Every reason this boundary may emit. A refusal carrying anything else is a refusal nobody
#: defined, and `Outcome.__post_init__` says so.
REFUSAL_REASONS: frozenset = frozenset({
    REFUSE_CONTROL_PLANE, REFUSE_LINK, REFUSE_MOUNT, REFUSE_SUBSTITUTED, REFUSE_NOT_A_DIRECTORY,
    REFUSE_SUPPORT_NOT_EMPTY,
    REFUSE_CONJUNCTION, REFUSE_FINGERPRINT, REFUSE_SLOT, REFUSE_COMPARTMENT_NOT_EMPTY,
    REFUSE_VIRTUAL_ACCOUNT, REFUSE_STORAGE_NEEDS_FMS, REFUSE_FMS_ROOT_PRESENT,
    REFUSE_FMS_ROOT_UNUSABLE, REFUSE_IDENTITY_UNUSABLE, REFUSE_SELF_RUNTIME,
    REFUSE_IDENTITY_MISMATCH, REFUSE_NO_QUIESCE_PRIMITIVE,
    REFUSE_SERVICE_NOT_STOPPED, REFUSE_SERVICE_UNREADABLE, REFUSE_SERVICE_ABSENT,
    REFUSE_RECORDED_FRONT_UNUSABLE, REFUSE_PROXY_COMPONENT, REFUSE_AMBIGUOUS_REGISTRATION,
    REFUSE_QUIESCE_INCOMPLETE, REFUSE_CREDENTIAL_REQUIRED,
})

# ── the five-part conjunction, as ONE implementation with two callers ─────────
#
# **The executors re-prove this before every service removal, and the PLANNER now needs the same
# answer before it decides anything** (packet 1246-09 stage 6). It used to live only inside
# `_prove_conjunction`, which takes a typed pending operation — an object that exists only *after*
# the plan that needed the answer was already made. That circularity is what made `service_binding` a
# request field no launcher could produce.
#
# So the proof is a module-level pure function per platform, and `_prove_conjunction` is a thin
# adapter over it. **The classification is what the observer needs and the executor does not**: three
# parts fail in ways that mean different things to the planner, and a fourth — unreadable — is not a
# drift finding at all. The executor collapses all four to "there is drift" exactly as before.
CONJ_OK = ""
CONJ_DEFINITION = "definition"
CONJ_EXECUTABLE = "executable"
CONJ_IDENTITY = "identity"
CONJ_UNREADABLE = "unreadable"
CONJ_PARTS: tuple = (CONJ_DEFINITION, CONJ_EXECUTABLE, CONJ_IDENTITY, CONJ_UNREADABLE)


class ExecutorRefused(LifecycleError):
    """The executor has no authority to act on what it was asked for. Nothing was attempted."""


class PathRemovalRefused(LifecycleError):
    """A removal was aimed at something the walker will not touch.

    It carries its own `reason` rather than leaving the caller to recognise the refusal from its
    prose. A caller that read `"link" in str(exc)` would silently start reporting the wrong reason
    the first time somebody improved the wording — which is the class of bug the named reasons exist
    to prevent, so the reason travels with the refusal.
    """

    def __init__(self, message: str, *, reason: str):
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class Outcome:
    """What one typed operation did, and the observation that decided it.

    `checkpointable` is an argument rather than a property because the *handler* is the only thing
    that knows whether every substep of a multi-part resource reached its terminal state. A property
    derived from `result` would let a partial storage removal — closed, unhosted, file gone, one RC
    path left — call itself finished on the strength of the last thing that worked.
    """

    resource: str
    operation: str
    result: str
    checkpointable: bool = False
    detail: str = ""
    reason: str = ""
    observations: tuple = field(default_factory=tuple)

    def __post_init__(self):
        if self.result not in EXEC_STATES:
            raise ExecutorRefused(f"result must be one of {EXEC_STATES}, got {self.result!r}")
        if self.checkpointable and self.result not in EXEC_TERMINAL:
            raise ExecutorRefused(
                f"a {self.result!r} outcome may never be checkpointable; only a resource that "
                "reached its terminal state and was read back there may retire pending authority")
        # **A refusal must carry a reason from the closed vocabulary.** Without this, blanking a
        # `reason=` was invisible: the detail text carried the meaning while the machine-readable
        # field nobody asserted quietly became `""`, and a caller switching on it fell through every
        # branch. Found by a mutation that survived the first stage-4 suite.
        if self.result == EXEC_REFUSED and self.reason not in REFUSAL_REASONS:
            raise ExecutorRefused(
                f"a refusal must name a reason from {sorted(REFUSAL_REASONS)}, got "
                f"{self.reason!r}")
        if self.reason and self.reason not in REFUSAL_REASONS:
            raise ExecutorRefused(f"unknown refusal reason {self.reason!r}")

    def to_dict(self) -> dict:
        return {"resource": self.resource, "operation": self.operation, "result": self.result,
                "checkpointable": self.checkpointable, "detail": self.detail,
                "reason": self.reason, "observations": list(self.observations)}


# ── path comparison, one rule per platform ────────────────────────────────────


def _normalise(value, *, flavour: str) -> str:
    if flavour == WINDOWS:
        return ntpath.normpath(str(value).replace("/", "\\")).rstrip("\\").lower()
    return posixpath.normpath(str(value)).rstrip("/") or "/"


def _same_path(left, right, *, flavour: str) -> bool:
    return _normalise(left, flavour=flavour) == _normalise(right, flavour=flavour)


def _within(child, parent, *, flavour: str) -> bool:
    """Strictly beneath — the same directory is not *inside* it."""
    a, b = _normalise(child, flavour=flavour), _normalise(parent, flavour=flavour)
    separator = "\\" if flavour == WINDOWS else "/"
    return a != b and a.startswith(b.rstrip(separator) + separator)


def _touches(candidate, other, *, flavour: str) -> bool:
    """Either path contains the other, or they are the same path."""
    return (_same_path(candidate, other, flavour=flavour)
            or _within(candidate, other, flavour=flavour)
            or _within(other, candidate, flavour=flavour))


# ── this process's own runtime, read through seams ────────────────────────────
#
# **Two reads, not two constants**, because the guard that uses them is only worth having if it can
# be driven: the whole point is what happens when the interpreter and the working directory are
# inside the tree about to be removed, and that state cannot be reached by a test that reads
# `sys.executable` and `os.getcwd()` directly. The retired protection was a `Set-Location` in the
# Windows launcher, pinned by a test whose own docstring said it could not run.


def _inside_or_is(child, parent, *, flavour: str) -> bool:
    """`child` goes when `parent` goes. **Not `_touches`**: an ANCESTOR of the target survives the
    removal, so a working directory above it is not in danger and a directory above it is exactly
    where a step-out lands."""
    return (_same_path(child, parent, flavour=flavour)
            or _within(child, parent, flavour=flavour))


def _process_executable() -> str:
    return sys.executable or ""


def _process_cwd() -> str:
    try:
        return os.getcwd()
    except OSError:
        # A working directory that has already been removed. There is nothing to step out of.
        return ""


def _stand_off_directory(target, *, flavour: str) -> str:
    """A directory outside `target` for this process to hold while `target` is removed.

    The temporary directory first — it is what the retired launcher chose, and it is writable on
    every supported box — then the target's own filesystem anchor, which is an ancestor of anything
    recorded and therefore always survives. A candidate INSIDE the target is skipped: stepping from
    one doomed directory into another is not stepping out.
    """
    for candidate in (tempfile.gettempdir(), Path(str(target)).anchor):
        if candidate and not _inside_or_is(candidate, target, flavour=flavour):
            return str(candidate)
    return ""


# ── the exact-path walker ─────────────────────────────────────────────────────
#
# **No glob, no recursive filename search, no shell.** Every entry removed is one the walker read
# out of a directory it opened itself, and the only paths it is ever aimed at come from the typed
# operation. `lstat` rather than `stat` is the load-bearing choice: a symlink is reported as a link
# and unlinked as a link, so the walker removes the name and never the target.
#
# Where the platform supports directory descriptors the walk uses them, and holds TWO independent
# TOCTOU guards. They are each sufficient alone, which is exactly why the regression asserts the
# PAIR: a test pinning one would keep passing while the other silently disappeared.
#
#   1. `O_NOFOLLOW` on every descent, so a directory swapped for a symlink between the read and the
#      open fails to open rather than being followed;
#   2. an identity comparison — `(st_dev, st_ino)` from the `lstat` against the `fstat` of the
#      descriptor actually opened — so the thing we descended into is the thing we looked at.

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

#: Whether this platform lets the walk hold a directory open and act relative to it.
_DIR_FD = {os.open, os.stat, os.unlink, os.rmdir} <= os.supports_dir_fd


def _stat_at(name, dir_fd):
    """`lstat` semantics, relative to an open directory. A seam, so a test can fake a volume."""
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _fstat(fd):
    """A seam for the same reason. A fake that moves one of these must move both — a fake that is
    inconsistent silently exercises the identity check instead of the mount check (§W)."""
    return os.fstat(fd)


def _lstat_or_none(path):
    try:
        return os.lstat(str(path))
    except FileNotFoundError:
        return None


def _is_link(st) -> bool:
    if _stat.S_ISLNK(st.st_mode):
        return True
    # Windows reparse points are not `S_IFLNK`; a junction is the local substitution hazard there.
    attributes = getattr(st, "st_file_attributes", 0)
    return bool(attributes & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _is_windows_readonly(st) -> bool:
    """The one Windows attribute this remover is allowed to change after ACCESS_DENIED."""
    attributes = getattr(st, "st_file_attributes", 0)
    return bool(attributes & getattr(_stat, "FILE_ATTRIBUTE_READONLY", 0x1))


def _remove_recorded_empty_scaffolding(paths: tuple[str, ...]) -> None:
    """Attempt ``rmdir`` on exact recorded scaffolding paths; never enumerate or recurse."""
    for raw in paths:
        path = Path(raw)
        observed = _lstat_or_none(path)
        if observed is None:
            continue
        if _is_link(observed) or not _stat.S_ISDIR(observed.st_mode):
            raise PathRemovalRefused(
                f"{path} is not the recorded empty directory scaffolding",
                reason=REFUSE_SUBSTITUTED)
        try:
            os.rmdir(str(path))
        except OSError as exc:
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise


def _windows_readonly_authority_refusal(child: Path, root: Path, *, authority_api=None) -> str:
    """Prove ordinary principals cannot substitute ``child`` during the path-only Windows retry.

    Windows lacks this walk's POSIX directory descriptors.  Its stated safety boundary is therefore
    the protected recorded root plus every descendant DACL down to the entry: SYSTEM/the invoking
    administrator may write; any other named trustee must have measured read-only rights.  A
    privileged actor can always race a privileged installer, and is inside the accepted authority
    set; service and ambient principals are not.
    """
    from .protection import (DIRECTORY_AUTHORITY, FILE_WRITE_AUTHORITY,
                             real_windows_file_authority)

    api = authority_api or real_windows_file_authority()
    try:
        allowed = set(api.invoking_owner_sids()) | {api.system_sid_text()}
    except Exception as exc:  # pragma: no cover - real Windows failure
        return f"the invoking Windows identity could not be read ({type(exc).__name__})"
    targets = [child]
    current = child.parent
    while True:
        targets.append(current)
        if _normalise(current, flavour=WINDOWS) == _normalise(root, flavour=WINDOWS):
            break
        parent = current.parent
        if parent == current or not _within(current, root, flavour=WINDOWS):
            return f"{child} is not beneath the recorded removal root {root}"
        current = parent
    for index, target in enumerate(targets):
        try:
            authority = api.authority_of_path(str(target))
        except Exception as exc:
            return f"{target} authority could not be read ({type(exc).__name__})"
        if _same_path(target, root, flavour=WINDOWS) and (
                not authority.protected or authority.inherited):
            return f"{root} is not a protected authority root"
        if authority.owner not in allowed:
            return f"{target} is owned outside the invoking administrator/SYSTEM authority"
        forbidden = FILE_WRITE_AUTHORITY if index == 0 else DIRECTORY_AUTHORITY
        masks: dict[str, int] = {}
        for trustee, mask in authority.grants:
            masks[trustee] = masks.get(trustee, 0) | mask
        for trustee in authority.trustees:
            if trustee in allowed:
                continue
            if trustee not in masks or masks[trustee] & forbidden:
                return f"{target} grants write or unknown authority to {trustee}"
    return ""


def _ancestors(paths, root, *, flavour: str) -> set:
    """Every directory that must survive because something kept lives underneath it."""
    survivors = set()
    for kept in paths:
        current = _normalise(kept, flavour=flavour)
        stop = _normalise(root, flavour=flavour)
        while current and current != stop:
            survivors.add(current)
            parent = (ntpath if flavour == WINDOWS else posixpath).dirname(current)
            if parent == current:
                break
            current = parent
    survivors.add(_normalise(root, flavour=flavour))
    return survivors


class _Purge:
    """One removal, aimed once. It holds the root's volume and the set of paths that must survive."""

    def __init__(self, root: Path, *, keep, flavour: str):
        self.root = Path(root)
        self.flavour = flavour
        self.keep = {_normalise(k, flavour=flavour) for k in keep}
        self.survivors = _ancestors(keep, root, flavour=flavour) if keep else set()
        self.device = None

    def _protected(self, path) -> bool:
        norm = _normalise(path, flavour=self.flavour)
        return norm in self.keep or norm in self.survivors

    def _must_recurse(self, path) -> bool:
        """A directory holding something kept is descended into but never removed."""
        norm = _normalise(path, flavour=self.flavour)
        return norm in self.survivors and norm not in self.keep

    def _unlink_path(self, child: Path, observed) -> None:
        """Unlink one already-observed entry; Windows gets one bounded read-only retry.

        Git legitimately marks some checkout objects read-only.  Windows then rejects ``unlink``
        with ``ERROR_ACCESS_DENIED`` even though the recorded installation owns the exact tree.
        ``chmod`` on Windows changes only that attribute; it does not grant ACL authority.  The
        retry is therefore Windows-only, proves the full path is non-writable by ordinary
        principals, and re-identifies the entry before and after changing it.
        """
        try:
            os.unlink(str(child))
            return
        except PermissionError as exc:
            if self.flavour != WINDOWS:
                raise
            denied = exc
        current = os.lstat(str(child))
        if _is_link(current) or (current.st_dev, current.st_ino) != (
                observed.st_dev, observed.st_ino):
            raise PathRemovalRefused(
                f"{child} was replaced after its first removal attempt; the replacement is left "
                "untouched", reason=REFUSE_SUBSTITUTED)
        if not _is_windows_readonly(current):
            # ACCESS_DENIED from an ACL, a running image, or anything else is not permission to
            # alter the entry. Only the measured checkout attribute gets the bounded retry.
            raise denied
        authority_refusal = _windows_readonly_authority_refusal(child, self.root)
        if authority_refusal:
            raise PathRemovalRefused(
                f"{child} is read-only but its bounded retry is not authorized: "
                f"{authority_refusal}", reason=REFUSE_READONLY_AUTHORITY)
        os.chmod(str(child), _stat.S_IWRITE)
        current = os.lstat(str(child))
        if _is_link(current) or (current.st_dev, current.st_ino) != (
                observed.st_dev, observed.st_ino):
            raise PathRemovalRefused(
                f"{child} was replaced while its read-only attribute was cleared; the replacement "
                "is not deleted", reason=REFUSE_SUBSTITUTED)
        os.unlink(str(child))

    def _rmdir_path(self, child: Path, observed) -> None:
        """Remove one empty directory; Windows gets the same bounded read-only retry as files.

        Windows marks some shell-facing directories (observed directly as the installed
        ``ProgramData\\CORPUSfm\\Documents`` directory) read-only.  Administrators still own the
        DACL, but ``rmdir`` returns ACCESS_DENIED until that attribute is cleared.  This is an
        attribute retry only: the complete descendant-to-root authority proof and identity
        re-check remain mandatory, exactly as for a read-only file.
        """
        try:
            os.rmdir(str(child))
            return
        except PermissionError as exc:
            if self.flavour != WINDOWS:
                raise
            denied = exc
        current = os.lstat(str(child))
        if (_is_link(current) or not _stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino)):
            raise PathRemovalRefused(
                f"{child} was replaced after its first removal attempt; the replacement is left "
                "untouched", reason=REFUSE_SUBSTITUTED)
        if not _is_windows_readonly(current):
            raise denied
        authority_refusal = _windows_readonly_authority_refusal(child, self.root)
        if authority_refusal:
            raise PathRemovalRefused(
                f"{child} is read-only but its bounded retry is not authorized: "
                f"{authority_refusal}", reason=REFUSE_READONLY_AUTHORITY)
        os.chmod(str(child), _stat.S_IWRITE)
        current = os.lstat(str(child))
        if (_is_link(current) or not _stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino)):
            raise PathRemovalRefused(
                f"{child} was replaced while its read-only attribute was cleared; the replacement "
                "is not deleted", reason=REFUSE_SUBSTITUTED)
        os.rmdir(str(child))

    # -- the two walks ---------------------------------------------------------

    def _walk_fd(self, path: Path, fd: int) -> None:
        for name in os.listdir(fd):
            child = path / name
            if self._protected(child) and not self._must_recurse(child):
                continue
            st = _stat_at(name, fd)
            if self.device is not None and st.st_dev != self.device:
                raise PathRemovalRefused(
                    f"{child} is on volume {st.st_dev} and the recorded tree is on {self.device}; "
                    "a removal never crosses a mount point", reason=REFUSE_MOUNT)
            if _stat.S_ISDIR(st.st_mode):
                child_fd = os.open(name, os.O_RDONLY | _NOFOLLOW | _DIRECTORY, dir_fd=fd)
                try:
                    opened = _fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                        raise PathRemovalRefused(
                            f"{child} was replaced between reading it and opening it; the walk "
                            "acts only on the directory it looked at", reason=REFUSE_SUBSTITUTED)
                    self._walk_fd(child, child_fd)
                finally:
                    os.close(child_fd)
                if not self._must_recurse(child):
                    os.rmdir(name, dir_fd=fd)
                continue
            # Everything else — a file, a socket, a device, and a SYMLINK, which `lstat` reported as
            # itself. `unlink` removes the name; the target is never touched.
            os.unlink(name, dir_fd=fd)

    def _walk_path(self, path: Path) -> None:
        """The fallback for a platform with no directory descriptors. Same decisions, weaker
        guarantee: there is no `O_NOFOLLOW` and no descriptor to compare against, so the link check
        is done on the `lstat` and the descent is by path. Stated rather than implied."""
        for name in os.listdir(str(path)):
            child = path / name
            if self._protected(child) and not self._must_recurse(child):
                continue
            st = os.lstat(str(child))
            if self.device is not None and st.st_dev != self.device:
                raise PathRemovalRefused(
                    f"{child} is on volume {st.st_dev} and the recorded tree is on {self.device}; "
                    "a removal never crosses a mount point", reason=REFUSE_MOUNT)
            if _is_link(st):
                # A link is removed as a name and never chmoded: clearing attributes through a
                # substituted name is precisely what the retry above refuses.
                os.unlink(str(child))
                continue
            if _stat.S_ISDIR(st.st_mode):
                self._walk_path(child)
                if not self._must_recurse(child):
                    self._rmdir_path(child, st)
                continue
            self._unlink_path(child, st)

    def run(self, *, remove_root: bool) -> None:
        st = _lstat_or_none(self.root)
        if st is None:
            return
        if _is_link(st):
            raise PathRemovalRefused(
                f"{self.root} is a link, and the record names a tree — following it would remove "
                "somebody else's directory", reason=REFUSE_LINK)
        if not _stat.S_ISDIR(st.st_mode):
            raise PathRemovalRefused(f"{self.root} is not a directory; a tree removal needs one",
                                     reason=REFUSE_NOT_A_DIRECTORY)
        self.device = st.st_dev
        if _DIR_FD:
            fd = os.open(str(self.root), os.O_RDONLY | _NOFOLLOW | _DIRECTORY)
            try:
                opened = _fstat(fd)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    raise PathRemovalRefused(
                        f"{self.root} was replaced between reading it and opening it",
                        reason=REFUSE_SUBSTITUTED)
                self._walk_fd(self.root, fd)
            finally:
                os.close(fd)
        else:
            self._walk_path(self.root)
        if remove_root:
            if self.flavour == WINDOWS:
                self._rmdir_path(self.root, st)
            else:
                os.rmdir(str(self.root))


def _remove_exact_file(path: Path) -> bool:
    """The exact recorded file. Returns whether anything was removed.

    A link is refused rather than unlinked: the record names a FILE this installation wrote, and a
    link standing where that file should be is a substitution, not the file.
    """
    st = _lstat_or_none(path)
    if st is None:
        return False
    if _is_link(st):
        raise PathRemovalRefused(
            f"{path} is a link and the record names a file this installation wrote",
            reason=REFUSE_LINK)
    if _stat.S_ISDIR(st.st_mode):
        raise PathRemovalRefused(f"{path} is a directory and the record names a file",
                                 reason=REFUSE_NOT_A_DIRECTORY)
    os.unlink(str(path))
    return True


# ── the recorded FileMaker Server root, observed HERE (1246-09 stage 5, ruling 1) ─────────────
#
# **The one thing that may permit a storage removal with no FileMaker Server call is FileMaker Server
# not being there** — and the executor establishes that itself, at the exact path the installation
# recorded, exactly as `run_pki` reads its identity from the recorded `secrets_dir`. The alternative
# was a caller saying *FMS is absent*, which is F3's defect one layer along: every other proof in
# `run_storage` is about WHICH DATABASE, and this one is about WHETHER ANYTHING CAN HOST IT. A caller
# that could assert that could get a live hosted database deleted, which is the §X RC5.
#
# **Only ABSENT permits.** Present, a link or reparse point, a non-directory, an unreadable path and
# one substituted between the read and the open all refuse — none of them is evidence of absence,
# and the honest answer to "I cannot tell" is not "no".

FMS_ROOT_ABSENT = "absent"
FMS_ROOT_PRESENT = "present"
FMS_ROOT_UNUSABLE = "unusable"


def _observe_recorded_fms_root(path, *, flavour: str = POSIX, windows_authority=None) -> tuple:
    """`(state, detail)` for the exact recorded root. Reads; touches nothing.

    POSIX closes the read/substitution boundary with an ``O_DIRECTORY|O_NOFOLLOW`` descriptor.
    Windows does not permit Python's ``os.open(path, O_RDONLY)`` on a directory. There the existing
    Windows file-authority API reads the directory's security descriptor by path, bracketed by two
    ``lstat`` identity reads. The descriptor is not required to carry any CORPUSfm ACL here — it is
    only the independent read that proves the recorded directory is observable without inventing a
    POSIX operation Windows cannot perform.
    """
    target = Path(path)
    try:
        st = os.lstat(str(target))
    except FileNotFoundError:
        return FMS_ROOT_ABSENT, f"{target} does not exist"
    except OSError as exc:
        # NotADirectoryError, a permission failure, a dead mount: every one of them means the root
        # could not be observed, and none of them means it is not there.
        return FMS_ROOT_UNUSABLE, f"{target} could not be read: {exc}"
    if _is_link(st):
        return FMS_ROOT_UNUSABLE, (f"{target} is a link or reparse point; a substitution standing "
                                   "where the recorded root should be is not an observation of it")
    if not _stat.S_ISDIR(st.st_mode):
        return FMS_ROOT_UNUSABLE, f"{target} is not a directory and the record names a root"
    if flavour == WINDOWS:
        try:
            if windows_authority is None:
                from .protection import real_windows_file_authority
                windows_authority = real_windows_file_authority()
            windows_authority.authority_of_path(str(target))
            reread = os.lstat(str(target))
        except OSError as exc:
            return FMS_ROOT_UNUSABLE, f"{target} could not be read back: {exc}"
        except Exception as exc:                                      # noqa: BLE001
            return FMS_ROOT_UNUSABLE, f"{target} could not be read back: {exc}"
        if _is_link(reread) or not _stat.S_ISDIR(reread.st_mode):
            return FMS_ROOT_UNUSABLE, f"{target} changed while it was being observed"
        if (reread.st_dev, reread.st_ino) != (st.st_dev, st.st_ino):
            return FMS_ROOT_UNUSABLE, f"{target} was replaced while it was being observed"
        return FMS_ROOT_PRESENT, f"{target} is present"
    try:
        fd = os.open(str(target), os.O_RDONLY | _NOFOLLOW | _DIRECTORY)
    except OSError as exc:
        return FMS_ROOT_UNUSABLE, f"{target} could not be opened: {exc}"
    try:
        opened = _fstat(fd)
        if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
            return FMS_ROOT_UNUSABLE, (f"{target} was replaced between reading it and opening it")
    finally:
        os.close(fd)
    return FMS_ROOT_PRESENT, f"{target} is present"


# ── the installed Admin-API identity, from the RECORDED secrets directory ─────


class _RecordedSecretsLocation:
    """A layout describing ONE location: the secrets directory this installation recorded.

    `admin_identity_store` validates a supplied directory against a layout, and its ordinary layout
    is the platform's fixed one. That is the right authority for the *running application*, which
    must never be pointed at a caller-chosen key location. It is the wrong one here for a reason
    worth stating: an uninstall executes against the installation the pending record describes, and
    the record — not `platform_os_layout()` — is this executor's evidence about where that
    installation put things. The store's own single-location branch exists for exactly this shape.

    **What is given up, and what is not.** The lexical-equality half of the validation is trivially
    satisfied, because the recorded directory is the one being validated. Everything that actually
    defends the read survives: the non-following `lstat` of the directory name, the
    `O_DIRECTORY|O_NOFOLLOW` open, the device/inode agreement between the name and the descriptor,
    and the `O_NOFOLLOW` read of the store file itself. The authority still comes from installed
    evidence; it has simply moved from a platform constant to the record.
    """

    __slots__ = ("secrets_dir",)

    def __init__(self, secrets_dir):
        self.secrets_dir = Path(secrets_dir)


def _installed_identity(secrets_dir):
    """The stored Admin-API identity, or `None` — absent, unreadable, foreign, or undecryptable.

    One return value for every unusable case on purpose: the caller's only correct response to any
    of them is to refuse without contacting anything, and distinguishing them here would invite a
    branch that treats one of them as *nearly* good enough.
    """
    from . import admin_identity_store as ais

    try:
        identity = ais.load(secrets_dir, layout=_RecordedSecretsLocation(secrets_dir))
    except Exception:                                                     # noqa: BLE001
        return None
    if identity is None or not identity.private_pem or not identity.host:
        return None
    return identity


# ── the executor ──────────────────────────────────────────────────────────────

_CONSTRUCTION = object()


class UninstallExecutor:
    """Typed pending operations, executed against the box. Platform-neutral."""

    FLAVOUR: str = ""

    #: **Whether this platform can remove a tree THIS process is running from.** POSIX can: an
    #: unlinked image keeps its mapping until the process exits, and a directory that is somebody's
    #: working directory still `rmdir`s. Windows cannot — the image section and the working
    #: directory are open handles the file system honours, so the removal fails on them.
    #:
    #: Keyed to the EXECUTOR and not to the live `os.name`, deliberately. A Windows record is only
    #: ever executed by `WindowsExecutor` (`_assert_platform`), so the two agree on a real box; and
    #: reading the live platform would make this branch unreachable anywhere except a Windows box,
    #: which is exactly how the protection it replaces came to be unexercised.
    SELF_RUNTIME_IS_REMOVABLE: bool = True

    #: tag -> the ONE method that executes it. Read by the coverage gate: a typed operation the
    #: planner can emit and this table does not name cannot be executed at all, and a handler naming
    #: a tag the planner never emits is an orphan.
    HANDLERS: dict = {
        pending.OP_EXACT_PATH: "run_exact_path",
        pending.OP_MANAGED_UNIT: "run_managed_unit",
        pending.OP_STORAGE: "run_storage",
        pending.OP_PROXY: "run_proxy",
        pending.OP_PKI: "run_pki",
        pending.OP_PATCH_SLOT: "run_patch_slot",
        pending.OP_ACCOUNT: "run_account",
    }

    def __init__(self, layout, *, lock, operation_id: str, installation_id: str, _token=None):
        if _token is not _CONSTRUCTION:
            raise ExecutorRefused(
                "an executor is built by `for_installation(layout, lock=…)` and by nothing else; a "
                "second construction path is how a fabricated record came to aim a deletion")
        self._layout = layout
        self._lock = lock
        self._operation_id = operation_id
        self._installation_id = installation_id

    # -- construction ---------------------------------------------------------

    @classmethod
    def for_installation(cls, layout, *, lock) -> "UninstallExecutor":
        """THE construction path: the fixed record, under a held lock for THIS machine's state."""
        held = require_lock(lock, "executing the pending uninstall")
        if held.layout != layout:
            raise LockNotHeld(
                f"executing the pending uninstall requires the lifecycle lock for "
                f"{layout.lock_file}, not {held.layout.lock_file}")
        record = pending.read(layout)
        if record is None:
            raise ExecutorRefused(
                f"there is no pending record at {pending.pending_path(layout)}; an executor has no "
                "authority of its own and never invents one")
        executor = cls(layout, lock=lock, operation_id=record.operation_id,
                       installation_id=record.installation_id, _token=_CONSTRUCTION)
        executor._assert_platform(record)
        return executor

    def _assert_platform(self, record) -> None:
        flavours = {getattr(op, "flavour", None) for op in record.remaining} - {None}
        if flavours - {self.FLAVOUR}:
            raise ExecutorRefused(
                f"the pending record describes {sorted(flavours)} and this executor is "
                f"{self.FLAVOUR!r}")

    # -- authority, reread every time -----------------------------------------

    def _record(self):
        """The record, from its FIXED path, checked against the identity this executor was built on.

        Read afresh for every operation and between the substeps of one. The executor keeps two
        identifiers and no operations, so a checkpoint that lands between two reads immediately
        revokes the authority for whatever it retired — which is §X.1 #3, and the reason a cached
        record is not an optimisation.
        """
        require_lock(self._lock, "executing the pending uninstall")
        if self._lock.layout != self._layout:
            raise LockNotHeld("the held lock is for another installation's lifecycle state")
        record = pending.read(self._layout)
        if record is None:
            raise ExecutorRefused(
                "the pending record is gone; every operation reads it again, and an executor whose "
                "authority has been retired stops rather than acting from memory")
        if record.installation_id != self._installation_id:
            raise ExecutorRefused(
                f"the pending record now belongs to installation {record.installation_id}, not "
                f"{self._installation_id}")
        if record.operation_id != self._operation_id:
            raise ExecutorRefused(
                f"the pending record now belongs to operation {record.operation_id}, not "
                f"{self._operation_id}")
        self._assert_platform(record)
        return record

    def _operation(self, resource: str, tag: str):
        """The ONE authorized operation for this resource, or a refusal. No caller data enters."""
        record = self._record()
        matches = [op for op in record.remaining if op.resource == resource]
        if not matches:
            raise ExecutorRefused(
                f"{resource!r} is not in the remaining set; it was never owed, or it has already "
                "been checkpointed, and either way there is no authority to act on it")
        if len(matches) != 1:
            raise ExecutorRefused(f"{resource!r} appears {len(matches)} times; the target is ambiguous")
        operation = matches[0]
        if operation.tag != tag:
            raise ExecutorRefused(
                f"{resource!r} is a {operation.tag!r} operation and was asked to run as {tag!r}")
        flavour = getattr(operation, "flavour", None)
        if flavour is not None and flavour != self.FLAVOUR:
            raise ExecutorRefused(
                f"{resource!r} is recorded for {flavour!r} and this executor is {self.FLAVOUR!r}")
        return operation

    def _still(self, resource: str, expected):
        """Between two substeps of ONE operation: the record must still owe the SAME operation.

        Equality, not presence. A matching operation replaced by a foreign one — same resource
        name, different target — is exactly the substitution a mid-operation reread exists to catch.
        """
        current = self._operation(resource, expected.tag)
        if current != expected:
            raise ExecutorRefused(
                f"the pending operation for {resource!r} changed while it was being executed; the "
                "remaining substeps are abandoned and the operation stays owed")
        return current

    # -- the live control plane, derived ---------------------------------------

    def control_plane(self) -> frozenset:
        """The lifecycle paths a running uninstall still needs, from THIS executor's own layout.

        Derived from the layout the executor holds, never from the flavour alone: deriving from the
        flavour always answers for the DEFAULT machine root, so an executor on any other root
        protected paths that were not the ones it was about to delete — and deleted the directory
        holding the lock it was holding (§W B3).

        **What actually protects this set: every path is read from `self._layout`'s own fields**, so
        an executor built on any root protects that root's control plane and not some other one.
        `lock_file.parent` is the run directory because `paired_layouts()` refuses to hand back a
        pair whose lock is not under `run` — that relationship is what makes reading the parent
        legitimate instead of hand-listing a sixth constant.

        *(A `paired_layouts(flavour=…)` call used to sit here, and a blind review showed it did
        nothing: it takes no root, so it validated the DEFAULT-rooted pair — whose consistency is
        true by construction — and discarded the result. `LifecycleLayout` records no root, so
        there is nothing here that could validate `self._layout`. The comment claimed a protection
        the line could not provide, which is worse than no line, so the line is gone and the claim
        with it.)*
        """
        protected = {
            Path(pending.pending_path(self._layout)),
            Path(self._layout.journal_file),
            Path(self._layout.lock_file),
            Path(self._layout.lock_file).parent,          # run_dir: preserved, never cleaned
        }
        if self._layout.locator_file is not None:
            protected.add(Path(self._layout.locator_file))
        return frozenset(protected)

    # -- this invocation's own runtime -----------------------------------------

    def _guard_self_runtime(self, target) -> tuple:
        """`(refusal_detail, observations)` — the uninstall is never inside the tree it deletes.

        The recorded install root holds the bundled interpreter, the package, and — when an operator
        ran the launcher from inside the installation, which is the only place it runs from — this
        process's working directory. Two distinct holds, and the uninstaller that shipped before the
        lifecycle rethread guarded exactly one of them, on one platform, in shell.

        * **the working directory is STEPPED OUT OF**, on both platforms and before anything is
          removed. It costs nothing where it is not needed and it is the whole of the protection
          where it is.
        * **the executing image is REFUSED**, and only where the platform cannot unlink one. There
          is no stepping out of an image: a run that tried would delete the package and the CLI, fail
          on `python.exe`, and leave a pending record on a box with nothing able to resume it. So the
          refusal comes first, before a single entry is removed, and it says what a human must do.
        """
        observations = []
        executable = _process_executable()
        if (executable and not self.SELF_RUNTIME_IS_REMOVABLE
                and _inside_or_is(Path(executable), target, flavour=self.FLAVOUR)):
            return (f"{target} holds the interpreter running this uninstall ({executable}) and this "
                    "platform cannot remove a running image; nothing in it was touched, so the "
                    f"record stays resumable. Delete {target} once this process has exited."), ()
        cwd = _process_cwd()
        if cwd and _inside_or_is(Path(cwd), target, flavour=self.FLAVOUR):
            stand_off = _stand_off_directory(target, flavour=self.FLAVOUR)
            try:
                if not stand_off:
                    raise OSError("no directory outside the target could be found to step into")
                os.chdir(stand_off)
            except OSError as exc:
                if not self.SELF_RUNTIME_IS_REMOVABLE:
                    return (f"{target} is this process's working directory and it could not be "
                            f"stepped out of ({exc}); on this platform that alone stops the "
                            "removal. Nothing in it was touched."), ()
                observations.append(
                    f"working directory {cwd} is inside {target} and could not be moved ({exc}); "
                    "this platform removes it anyway")
            else:
                observations.append(
                    f"stepped out of {cwd} into {stand_off} before removing {target}")
        return "", tuple(observations)

    # -- 1. exact paths --------------------------------------------------------

    def run_exact_path(self, resource: str) -> Outcome:
        """The exact recorded file or tree, or a clean of a tree that holds the control plane."""
        operation = self._operation(resource, pending.OP_EXACT_PATH)
        target = Path(operation.path)
        protected = self.control_plane()

        if operation.action in (pending.PATH_ACTION_REMOVE_FILE, pending.PATH_ACTION_REMOVE_TREE,
                                pending.PATH_ACTION_REMOVE_EMPTY_DIR):
            collisions = sorted(str(p) for p in protected
                                if _touches(p, target, flavour=self.FLAVOUR))
            if collisions:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=REFUSE_CONTROL_PLANE,
                    detail=f"{target} holds or is the live control plane ({', '.join(collisions)}); "
                           "the operation still needs it and it is preserved")
        else:
            required = sorted(str(p) for p in protected
                              if _within(p, target, flavour=self.FLAVOUR))
            recorded = {_normalise(k, flavour=self.FLAVOUR) for k in operation.keep}
            missing = [p for p in required if _normalise(p, flavour=self.FLAVOUR) not in recorded]
            if missing:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=REFUSE_CONTROL_PLANE,
                    detail=f"the live control plane holds {missing} inside {target} and the record "
                           "does not preserve them; the record and the box disagree about what is "
                           "still in use")

        # **After the control-plane judgement and before the first deletion.** The control plane is
        # about the record and the box; this is about the process holding both.
        conflict, stepped = self._guard_self_runtime(target)
        if conflict:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_SELF_RUNTIME, detail=conflict)

        existed = [str(k) for k in operation.keep if _lstat_or_none(Path(k)) is not None]
        try:
            if operation.action == pending.PATH_ACTION_REMOVE_FILE:
                removed = _remove_exact_file(target)
            elif operation.action == pending.PATH_ACTION_REMOVE_TREE:
                removed = _lstat_or_none(target) is not None
                _Purge(target, keep=(), flavour=self.FLAVOUR).run(remove_root=True)
            elif operation.action == pending.PATH_ACTION_REMOVE_EMPTY_DIR:
                observed = _lstat_or_none(target)
                if observed is None:
                    return Outcome(resource=resource, operation=operation.tag,
                                   result=EXEC_ALREADY_ABSENT, checkpointable=True,
                                   detail=f"{target} is already gone")
                if _is_link(observed) or not _stat.S_ISDIR(observed.st_mode):
                    raise PathRemovalRefused(
                        f"{target} is not the recorded empty directory",
                        reason=REFUSE_NOT_A_DIRECTORY)
                if os.listdir(str(target)):
                    return Outcome(resource=resource, operation=operation.tag,
                                   result=EXEC_REFUSED,
                                   reason=REFUSE_SUPPORT_NOT_EMPTY,
                                   detail=f"{target} is no longer empty and is preserved")
                os.rmdir(str(target))
                removed = True
            else:
                if _lstat_or_none(target) is None:
                    return Outcome(resource=resource, operation=operation.tag,
                                   result=EXEC_ALREADY_ABSENT, checkpointable=True,
                                   detail=f"{target} is already gone; a clean of an absent tree "
                                          "leaves nothing owed")
                removed = True
                _Purge(target, keep=operation.keep, flavour=self.FLAVOUR).run(remove_root=False)
        except PathRemovalRefused as exc:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=exc.reason, detail=str(exc))
        except OSError as exc:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"{target} could not be removed: {exc}")

        # THE READ-BACK. Not "the calls returned" — what is there now.
        if operation.action == pending.PATH_ACTION_CLEAN_TREE:
            if _lstat_or_none(target) is None:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{target} was cleaned and is now gone; the directory itself "
                                      "is preserved by a clean")
            survived = [k for k in existed if _lstat_or_none(Path(k)) is None]
            if survived:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"the clean removed preserved paths {survived}")
            # **Only the paths kept INSIDE the tree exempt anything.** A `keep` naming the tree
            # itself means *remove the contents, keep the directory* — the ordinary Windows case,
            # where no control-plane path lives under `config` — and matching leftovers against it
            # would exempt every child, leaving the read-back with nothing to check.
            inside = [Path(k) for k in operation.keep
                      if _within(Path(k), target, flavour=self.FLAVOUR)]
            leftover = sorted(name for name in os.listdir(str(target))
                              if not any(_touches(target / name, k, flavour=self.FLAVOUR)
                                         for k in inside))
            if leftover:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{target} still holds {leftover} after the clean")
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_COMPLETED,
                           checkpointable=True,
                           detail=f"{target} holds only its preserved control-plane paths",
                           observations=stepped + tuple(existed))
        if _lstat_or_none(target) is not None:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"{target} is still present after the removal reported success",
                           observations=stepped)
        return Outcome(
            resource=resource, operation=operation.tag,
            result=EXEC_COMPLETED if removed else EXEC_ALREADY_ABSENT, checkpointable=True,
            detail=f"{target} is absent", observations=stepped)

    # -- 2. managed units ------------------------------------------------------

    def run_managed_unit(self, resource: str, *, runner=None) -> Outcome:
        """Re-prove O4's five parts against the RECORDED facts, then act, then read back."""
        operation = self._operation(resource, pending.OP_MANAGED_UNIT)
        return self._remove_managed_unit(operation, runner=runner)

    def _remove_managed_unit(self, operation, *, runner) -> Outcome:      # pragma: no cover - base
        raise NotImplementedError

    def _prove_conjunction(self, operation) -> str:
        """`""` when all five parts agree, otherwise why they do not.

        Five parts, from O4: the ROLE and the NAME are recorded; the DEFINITION exists at the exact
        recorded path and the recorded name is the one it registers; the EXECUTABLE it names is
        canonically beneath the RECORDED install directory — never a constructor argument, which is
        §X.1 #2 — and the IDENTITY it runs as agrees with the recorded one.
        """
        raise NotImplementedError                                        # pragma: no cover - base

    def _remove_definition(self, operation) -> tuple:
        """The exact recorded definition file. Returns `(removed, refusal_or_empty)`."""
        path = Path(operation.definition_path)
        try:
            removed = _remove_exact_file(path)
        except PathRemovalRefused as exc:
            return False, str(exc)
        if _lstat_or_none(path) is not None:
            return False, f"{path} is still present after the removal reported success"
        return removed, ""

    # -- 3. storage: ONE indivisible operation ---------------------------------

    def run_storage(self, resource: str, *, fms) -> Outcome:
        """close → observe CLOSED → prove not serving → remove file → prove → RCs → prove.

        **A caller cannot omit or reorder a substep**, because there is nothing to call in between.
        §X deleted a live hosted database by not calling `close` and `verify`, which were separate
        methods; they are steps of this one now, and the sequence is the executor's obligation.

        **The first two substeps are conditional on the database still being there, and that is what
        makes the operation resumable (F1).** The operation is one indivisible unit of authority but
        it is *not* one instant: a crash after the file is unlinked and before the last RC path is
        removed leaves a record that still owes everything. Unconditionally closing a database that
        no longer exists makes that retry fail on the one fact that proves progress was made — the
        file is gone — and an operation that can only fail after a partial run is an RC4 the
        installation has no way out of.

        So the close and the CLOSED observation are asked of a database that is PRESENT. **The
        not-serving proof is not conditional on anything**: FileMaker keeps a CLOSED registration
        in its database list, so a matching row is safe only when its protocol status is CLOSED. An
        absent file whose matching row is open or whose status is unreadable may be served from
        somewhere this record does not describe, and its remote-container paths are not touched.
        Present-but-open, absent-but-open, an unreadable server and a database that reappears
        mid-flight all retain the whole operation.

        **The second admissible proof: there is no FileMaker Server (stage 5, ruling 1).** With no
        collaborator, the executor observes the EXACT RECORDED `fms_root` itself. An observably
        absent root means nothing on this box can serve anything, so the not-serving proof is complete
        without a call — and only that. A present, substituted or unobservable root refuses. The
        caller supplies neither the root nor a verdict about it: there is no argument for either, so
        `present` and `unreadable` cannot be turned into `absent` from outside.
        """
        operation = self._operation(resource, pending.OP_STORAGE)
        seen = []
        if fms is None:
            state, detail = _observe_recorded_fms_root(
                operation.fms_root, flavour=self.FLAVOUR)
            if state != FMS_ROOT_ABSENT:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=(REFUSE_FMS_ROOT_PRESENT if state == FMS_ROOT_PRESENT
                            else REFUSE_FMS_ROOT_UNUSABLE),
                    observations=(f"fms_root={state}",),
                    detail=f"the recorded database is removed only with a not-serving proof, and the "
                           f"two proofs are an FMS observation or an absent FileMaker Server: "
                           f"{detail}")
            seen.append(f"recorded FileMaker Server root {operation.fms_root} is absent")
        database = Path(operation.database_path)
        present = _lstat_or_none(database) is not None
        if fms is not None:
            try:
                if present:
                    try:
                        fms.close_database(operation.database_name)
                    except Exception:                                   # noqa: BLE001
                        # FileMaker returns 409 when a prior attempt already closed the database.
                        # The registry read below is authoritative: CLOSED or absent may continue;
                        # every other answer retains the file.
                        seen.append("close request did not complete; checking current status")
                    else:
                        seen.append(f"close_database({operation.database_name})")
                        if not fms.await_status(operation.database_name, "CLOSED"):
                            return Outcome(resource=resource, operation=operation.tag,
                                           result=EXEC_FAILED,
                                           detail=f"{operation.database_name} did not reach CLOSED",
                                           observations=tuple(seen))
                        seen.append("observed CLOSED")
                else:
                    # A retry after the file was already removed. There is nothing to close, and
                    # asking anyway is how the retry would fail on the evidence of its own progress.
                    seen.append(f"{database} was already absent; no close was issued")
                rows = fms.list_databases()
            except Exception as exc:                                      # noqa: BLE001
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"FileMaker Server could not be read or driven: {exc}",
                               observations=tuple(seen))
            wanted = ff.database_stem(operation.database_name)
            for row in rows:
                if not isinstance(row, dict):
                    return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                                   detail="the hosted-database list could not be read; unreadable "
                                          "is not proof that the database is not serving",
                                   observations=tuple(seen))
                filename = row.get("filename")
                if not isinstance(filename, str) or not filename.strip():
                    return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                                   detail="the hosted-database list carries an unreadable filename; "
                                          "absence cannot be proved from it",
                                   observations=tuple(seen))
                if ff.database_stem(filename) == wanted:
                    if not ff.database_row_is_closed(row):
                        return Outcome(
                            resource=resource, operation=operation.tag, result=EXEC_FAILED,
                            detail=f"{operation.database_name} is still serving or its status "
                                   "could not be proved CLOSED; the database file is retained",
                            observations=tuple(seen))
                    seen.append("matching FileMaker registration is CLOSED")
            seen.append("proved not serving")

        if present:
            operation = self._still(resource, operation)
            database = Path(operation.database_path)
            try:
                _remove_exact_file(database)
            except PathRemovalRefused as exc:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                               reason=exc.reason, detail=str(exc), observations=tuple(seen))
            except OSError as exc:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{database} could not be removed: {exc}",
                               observations=tuple(seen))
            if _lstat_or_none(database) is not None:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_FAILED,
                    detail=f"{database} is still present after its removal reported success",
                    observations=tuple(seen))
        seen.append(f"{database} absent")

        for rc_path in operation.rc_paths:
            operation = self._still(resource, operation)
            if _lstat_or_none(Path(operation.database_path)) is not None:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail="the database file reappeared; its remote-container paths are "
                                      "removed only after it is gone",
                               observations=tuple(seen))
            rc = Path(rc_path)
            try:
                if _lstat_or_none(rc) is not None:
                    st = os.lstat(str(rc))
                    if _stat.S_ISDIR(st.st_mode) and not _is_link(st):
                        _Purge(rc, keep=(), flavour=self.FLAVOUR).run(remove_root=True)
                    else:
                        _remove_exact_file(rc)
            except PathRemovalRefused as exc:
                # **Forward the exception's OWN reason.** This hardcoded `REFUSE_LINK`, so an RC
                # directory spanning a mount point or swapped mid-walk was reported as a symlink —
                # the exact mislabelling `PathRemovalRefused`'s docstring says it exists to prevent,
                # committed by the one site that did not forward. Every other site already did.
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                               reason=exc.reason, detail=str(exc), observations=tuple(seen))
            except OSError as exc:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{rc} could not be removed: {exc}",
                               observations=tuple(seen))
            if _lstat_or_none(rc) is not None:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{rc} is still present after its removal reported success",
                               observations=tuple(seen))
            seen.append(f"{rc} absent")

        # A fresh install creates this exact FMS database container and its RC_Data_FMS wrapper.
        # Remove those directories only when empty; rmdir preserves any foreign content.
        database_parent = database.parent
        recorded_fms_root = Path(operation.fms_root)
        # ``paths.fms_root`` names FileMaker's executable-bearing ``Database Server`` directory,
        # not the enclosing ``FileMaker Server`` installation root.  The old expression appended
        # ``Data/Databases`` directly to that directory, so the live layout could never agree and
        # a fresh uninstall left the now-empty CORPUSfm/RC_Data_FMS scaffolding behind while
        # reporting completion.  Keep accepting the enclosing-root spelling for old records and
        # tests, but interpret the published contract when its final component says what it is.
        installation_root = (recorded_fms_root.parent
                             if recorded_fms_root.name.casefold() == "database server"
                             else recorded_fms_root)
        canonical_parent = installation_root / "Data" / "Databases" / "CORPUSfm"
        if _same_path(database_parent, canonical_parent, flavour=self.FLAVOUR):
            scaffolding = []
            for rc_path in operation.rc_paths:
                rc_parent = Path(rc_path).parent
                if rc_parent.parent == database_parent and rc_parent not in scaffolding:
                    scaffolding.append(rc_parent)
            for directory in (*scaffolding, database_parent):
                try:
                    directory.rmdir()
                except FileNotFoundError:
                    pass
                except OSError:
                    seen.append(f"{directory} retained because it is not empty")
                else:
                    seen.append(f"{directory} absent")
        return Outcome(resource=resource, operation=operation.tag, result=EXEC_COMPLETED,
                       checkpointable=True, observations=tuple(seen),
                       detail="closed, proved not serving, and every recorded path read back absent")

    # -- 4. proxy --------------------------------------------------------------

    def run_proxy(self, resource: str, *, observe, engine, lease=None, credential=None) -> Outcome:
        """Every recorded front, through the proxy component's own removal callable.

        The fronts and the policy are built from the typed operation and from nothing else, so the
        fingerprint the removal compares against is the one the installation recorded. `observe`,
        `engine` and `lease` are operational collaborators — the box reader, the bounded executor and
        the admin credential — and none of them names a target.

        **`credential` is a PROVIDER, not a value** (packet 1246-09 stage 6). It is called at most
        once, and only after the observed fronts and the real plan say an FMS restart is required —
        so a Windows box, whose front publishes without activating, never asks for one and never
        prompts. When it is required and nothing can supply it, the component answers
        `credential_required` before the editor, the activation or the engine has run, and this
        reports that word: a launcher branches on it and on nothing else.

        **Partial removal retains the WHOLE operation.** A record that owes `proxy_edits` owes every
        front in it, and checkpointing on a majority would leave routing in place with nothing left
        that knows about it.
        """
        from . import proxy_transaction as pt
        from .proxy_policy import MANAGED, ProxyPolicyView
        from .schema import ProxyPolicyEntry

        operation = self._operation(resource, pending.OP_PROXY)
        try:
            fronts = tuple(pt.RecordedFront(proxy_type=f.proxy_type,
                                            config_location=f.config_location,
                                            config_fingerprint=f.config_fingerprint)
                           for f in operation.fronts)
        except pt.ProxyRefused as exc:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_RECORDED_FRONT_UNUSABLE,
                           detail=f"a recorded front is not usable: {exc}")
        policy = ProxyPolicyView(entries={
            f.proxy_type: ProxyPolicyEntry(policy=MANAGED, detected=True,
                                           config_location=f.config_location,
                                           config_fingerprint=f.config_fingerprint)
            for f in operation.fronts})
        try:
            results = pt.remove_owned_routing(fronts=fronts, policy=policy, observe=observe,
                                              engine=engine, lease=lease, credential=credential)
        except pt.ProxyRefused as exc:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_PROXY_COMPONENT, detail=str(exc))
        seen = tuple(f"{r.proxy_type}={r.state}" for r in results)
        unfinished = [r for r in results if not r.may_checkpoint]
        if unfinished:
            # **Checked FIRST, and never mixed.** `credential_required` is a pre-action state: the
            # component returns it for every front and nothing was touched. A run that also carries a
            # fingerprint refusal or a failure is not one of these, and reporting the credential word
            # there would send a launcher to acquire a credential that was never the obstacle.
            needed = all(r.state == pt.REMOVAL_CREDENTIAL_REQUIRED for r in unfinished)
            refused = all(r.state == pt.REMOVAL_REFUSED for r in unfinished)
            if needed:
                reason, result = REFUSE_CREDENTIAL_REQUIRED, EXEC_REFUSED
            elif refused:
                reason, result = REFUSE_FINGERPRINT, EXEC_REFUSED
            else:
                reason, result = "", EXEC_FAILED
            return Outcome(
                resource=resource, operation=operation.tag, result=result, reason=reason,
                observations=seen,
                detail="; ".join(f"{r.proxy_type}: {r.detail}" for r in unfinished))
        completed = any(r.state == pt.REMOVAL_COMPLETED for r in results)
        return Outcome(resource=resource, operation=operation.tag,
                       result=EXEC_COMPLETED if completed else EXEC_ALREADY_ABSENT,
                       checkpointable=True, observations=seen,
                       detail="every recorded front re-observed without its owned block")

    # -- 5. PKI ----------------------------------------------------------------

    def run_pki(self, resource: str, *, admin_api, credential=None) -> Outcome:
        """Observe the exact registration AND its fingerprint, delete only on exact agreement.

        **The caller supplies no host and no key.** It used to supply both, and `host` was defended
        as a credential rather than a target — which is wrong, and is the F3 RC5: the fingerprint
        comparison proves *which registration* is deleted but says nothing about *which server* the
        deletion is aimed at, so a caller holding an otherwise perfectly valid recorded authority
        could point it at another FileMaker Server that happens to carry the same registration.

        Both now come from the recorded secrets directory: the installed identity store, loaded
        through its own strict validation, supplies the endpoint and the private key. A store that is
        absent, unreadable, foreign or undecryptable **refuses before any request is made**.

        A recorded identity can legitimately be unable to authenticate when its exact registration
        is already absent.  That is not evidence of absence: an administrator credential is then
        requested lazily and may only observe/delete/read back the same record-derived endpoint,
        name and fingerprint.  The credential supplies no target and is never acquired while the
        installed identity still works.
        """
        from .admin_identity_store import fingerprint_of_public_pem

        operation = self._operation(resource, pending.OP_PKI)
        name = operation.registration_name
        identity = _installed_identity(operation.secrets_dir)
        if identity is None:
            return Outcome(
                resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                reason=REFUSE_IDENTITY_UNUSABLE,
                detail=f"the identity store under the recorded {operation.secrets_dir} is absent, "
                       "unreadable or unusable; the endpoint and the key for this deletion come from "
                       "there and from nowhere else, so nothing is contacted")
        if identity.registration_name != name:
            return Outcome(
                resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                reason=REFUSE_IDENTITY_MISMATCH,
                detail=f"the stored identity authenticates as {identity.registration_name!r} and "
                       f"this operation is recorded against {name!r}; two disagreeing authorities "
                       "are not one authority")
        host, private_pem = identity.host, identity.private_pem
        use_admin = False
        try:
            ok, entries, message = admin_api.get_public_keys_as_identity(host, name, private_pem)
        except Exception:                                                 # noqa: BLE001
            ok, entries, message = False, (), "identity authentication failed"
        if not ok:
            lease = credential() if credential is not None else None
            if lease is None:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=REFUSE_CREDENTIAL_REQUIRED,
                    detail="the recorded identity could not read the registration list; an FMS "
                           "administrator credential is required to prove whether its exact "
                           "registration is already absent")
            use_admin = True
            try:
                ok, entries, message = admin_api.get_public_keys(
                    host, lease.user, lease.password)
            except Exception as exc:                                      # noqa: BLE001
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"the administrator could not read the registration list: "
                                      f"{type(exc).__name__}")
            if not ok:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"the administrator could not read the registration list: "
                                      f"{message}; unreadable is not absence")
        matches = [e for e in entries if str(e.get("name") or "") == name]
        if not matches:
            return Outcome(resource=resource, operation=operation.tag,
                           result=EXEC_ALREADY_ABSENT, checkpointable=True,
                           detail=f"FileMaker Server holds no registration named {name!r}")
        if len(matches) != 1:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_AMBIGUOUS_REGISTRATION,
                           detail=f"{len(matches)} registrations are named {name!r}")
        try:
            observed = fingerprint_of_public_pem(matches[0].get("publicKey") or "")
        except Exception as exc:                                          # noqa: BLE001
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_FINGERPRINT,
                           detail=f"the registered key could not be fingerprinted ({exc}); a key "
                                  "we cannot compare is a key we do not delete")
        if observed != operation.public_fingerprint:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_FINGERPRINT,
                           detail=f"{name!r} presents {observed!r} and this installation recorded "
                                  f"{operation.public_fingerprint!r}; the registration is somebody "
                                  "else's and is preserved")
        try:
            if use_admin:
                ok, message = admin_api.delete_public_key_exact(
                    host, lease.user, lease.password, name)
            else:
                ok, message = admin_api.delete_public_key_exact_as_identity(
                    host, name, private_pem, name)
        except Exception as exc:                                          # noqa: BLE001
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the deletion failed: {exc}")
        if not ok:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the deletion was refused: {message}")
        try:
            if use_admin:
                ok, entries, message = admin_api.get_public_keys(
                    host, lease.user, lease.password)
            else:
                ok, entries, message = admin_api.get_public_keys_as_identity(
                    host, name, private_pem)
        except Exception as exc:                                          # noqa: BLE001
            if not use_admin:
                # Deleting the registration can invalidate the exact credential that performed
                # the deletion.  The mutation returned success, but that credential can no longer
                # prove its own absence; continue through the already-existing administrator
                # transport on the next call.  Nothing is checkpointed until that independent
                # read-back says the exact registration is gone.
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=REFUSE_CREDENTIAL_REQUIRED,
                    detail="the recorded identity deleted its registration and can no longer "
                           "read it back; an FMS administrator credential is required to prove "
                           "the exact registration is absent")
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the read-back failed: {exc}")
        if not ok:
            if not use_admin:
                return Outcome(
                    resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                    reason=REFUSE_CREDENTIAL_REQUIRED,
                    detail="the recorded identity deleted its registration and can no longer "
                           "read it back; an FMS administrator credential is required to prove "
                           "the exact registration is absent")
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the read-back could not be read: {message}; a deletion is "
                                  "complete when the registration is observably gone")
        if any(str(e.get("name") or "") == name for e in entries):
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"{name!r} is still registered after the deletion returned ok")
        return Outcome(resource=resource, operation=operation.tag, result=EXEC_COMPLETED,
                       checkpointable=True, detail=f"{name!r} is absent from the registration list")

    # -- 6. the patch folder slot ---------------------------------------------

    def run_patch_slot(self, resource: str, *, folders) -> Outcome:
        """Deregister the exact recorded slot — never clear one holding somebody else's path."""
        operation = self._operation(resource, pending.OP_PATCH_SLOT)
        try:
            slots = ff.read_slots(folders, flavour=self.FLAVOUR)
        except Exception as exc:                                          # noqa: BLE001
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the folder slots could not be read: {exc}")
        current = [s for s in slots if s.index == operation.slot]
        if len(current) != 1:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"FileMaker Server reported {len(current)} slots numbered "
                                  f"{operation.slot!r}")
        slot = current[0]
        if not slot.enabled:
            # **Deregistered means NOT ENABLED.** FileMaker Server documents no clearing semantics
            # for the path field — `slot_restore_body` says so and deliberately sends only the
            # enable flag — so a disabled slot may legitimately still report the path it last held.
            # Requiring the path to be gone as well would call every successful deregistration a
            # failure.
            return Outcome(resource=resource, operation=operation.tag,
                           result=EXEC_ALREADY_ABSENT, checkpointable=True,
                           detail=f"slot {operation.slot} is not enabled")
        if not ff.paths_equal(slot.local_path, operation.hosting_dir, flavour=self.FLAVOUR):
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                           reason=REFUSE_SLOT,
                           detail=f"slot {operation.slot} holds {slot.fms_path!r} and this "
                                  f"installation recorded {operation.hosting_dir!r}")
        hosting = Path(operation.hosting_dir)
        st = _lstat_or_none(hosting)
        if st is not None:
            if _is_link(st):
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                               reason=REFUSE_LINK,
                               detail=f"{hosting} is a link; the recorded compartment is a directory")
            try:
                _remove_recorded_empty_scaffolding(operation.scaffolding)
                content = sorted(os.listdir(str(hosting)))
            except PathRemovalRefused as exc:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                               reason=exc.reason, detail=str(exc))
            except OSError as exc:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                               detail=f"{hosting} could not be read: {exc}")
            if content:
                return Outcome(resource=resource, operation=operation.tag, result=EXEC_REFUSED,
                               reason=REFUSE_COMPARTMENT_NOT_EMPTY,
                               detail=f"{hosting} still holds {content}; a slot serving content is "
                                      "not deregistered")
        try:
            folders.patch_additional_db_folder(ff.slot_restore_body(
                operation.slot, ff.SlotRecord(index=operation.slot, fms_path=None, local_path=None,
                                              enabled=False)))
            after = ff.read_slots(folders, flavour=self.FLAVOUR)
        except Exception as exc:                                          # noqa: BLE001
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"the slot could not be deregistered or re-read: {exc}")
        freed = [s for s in after if s.index == operation.slot]
        if len(freed) != 1 or freed[0].enabled:
            return Outcome(resource=resource, operation=operation.tag, result=EXEC_FAILED,
                           detail=f"slot {operation.slot} still reads back enabled after the "
                                  "deregistration returned")
        return Outcome(resource=resource, operation=operation.tag, result=EXEC_COMPLETED,
                       checkpointable=True, detail=f"slot {operation.slot} reads back free")

    # -- 7. the service account ------------------------------------------------

    def run_account(self, resource: str, *, runner=None) -> Outcome:
        operation = self._operation(resource, pending.OP_ACCOUNT)
        return self._remove_account(operation, runner=runner)

    def _remove_account(self, operation, *, runner) -> Outcome:          # pragma: no cover - base
        raise NotImplementedError

    # -- 8. early quiesce ------------------------------------------------------

    def stop_services(self, *, runner=None) -> Outcome:
        """The planner's `stop_app_services`, over the CURRENT typed managed units.

        It stops the recorded web and scheduler services and does nothing else: it removes no
        definition, deregisters nothing, and **never checkpoints** — those belong to the managed-unit
        operations, whose own five-part conjunction needs the registration still to be there.

        **Scheduled tasks are not application services.** The updater is a managed unit and it is not
        something an early quiesce brings down; treating it as one would stop a privileged one-shot
        that is not running and call that progress.

        Authority is re-established immediately before EACH stop, so a unit checkpointed away
        mid-quiesce is skipped rather than acted on from the list this method started with.
        """
        record = self._record()
        planned = [op for op in record.remaining
                   if isinstance(op, pending.ManagedUnitOperation)
                   # REMOVABLE, not rendered (packet 1361-01, round 3): a box installed by an
                   # earlier build still carries the retired `corpusfm-scheduler` service, and this
                   # quiesce must stop it. `SERVICE_ROLES` is now the RENDERED set and would skip it.
                   and op.unit_kind == UNIT_KIND_SERVICE
                   and op.role in REMOVABLE_SERVICE_ROLES]
        seen = []
        failures = []
        refusals = []

        # **PROVE THEM ALL BEFORE TOUCHING ANY** (packet 1246-09 stage 6, Codex disposition).
        # Drifted services are owed work now rather than preserved, so a record can carry a unit that
        # binds beside one that does not — and quiescing them one at a time stopped the healthy ones
        # before discovering the drift, leaving a half-stopped installation on a run that then
        # refused and changed nothing else. An invocation that cannot bring the whole set down brings
        # none of it down. The per-target proof below stays exactly where it is: this decides whether
        # to begin, and that one is the TOCTOU guard immediately before each act.
        # A target the record no longer describes is not decided here — the loop below re-reads it
        # and reports it in its own vocabulary. This pass answers one question: does anything the
        # record STILL describes fail its conjunction?
        current_targets = []
        for target in planned:
            try:
                current = self._still(target.resource, target)
            except ExecutorRefused:
                continue
            if self._quiesce_already_absent(current, runner=runner):
                continue
            current_targets.append(current)
        drifted = [(op, self._prove_conjunction(op)) for op in current_targets]
        blocking = [(op, drift) for op, drift in drifted if drift]
        if blocking:
            return Outcome(
                resource=STOP_SERVICES, operation=STOP_SERVICES, result=EXEC_REFUSED,
                reason=REFUSE_QUIESCE_INCOMPLETE,
                observations=tuple(f"{op.resource}={EXEC_REFUSED}:{REFUSE_CONJUNCTION}"
                                   for op, _drift in blocking),
                detail="; ".join(f"{op.resource}: {REFUSE_CONJUNCTION}: {drift}"
                                 for op, drift in blocking))
        for target in planned:
            try:
                current = self._still(target.resource, target)
            except ExecutorRefused as exc:
                seen.append(f"{target.resource}=skipped")
                refusals.append(f"{target.resource}: {exc}")
                continue
            # A prior invocation may have stopped the service, removed its exact definition and
            # then died before checkpointing the managed-unit operation.  If BOTH the definition
            # and the manager registration now positively read absent, there is nothing to
            # quiesce; leave the operation to its own already-absent/residual read-back below.
            # Recheck here as well as in the all-target preflight so a changed box never acts on a
            # stale exemption.
            if self._quiesce_already_absent(current, runner=runner):
                seen.append(f"{current.resource}={EXEC_ALREADY_ABSENT}")
                continue
            result = self._quiesce(current, runner=runner)
            # The per-service REASON travels with its observation. Aggregating into prose alone
            # loses the machine-readable code exactly where a caller would want to branch on which
            # service refused and why.
            seen.append(f"{current.resource}={result.result}"
                        + (f":{result.reason}" if result.reason else ""))
            if result.result == EXEC_REFUSED:
                refusals.append(f"{current.resource}: {result.reason}: {result.detail}")
            elif result.result not in EXEC_TERMINAL:
                failures.append(f"{current.resource}: {result.detail}")
        if failures:
            return Outcome(resource=STOP_SERVICES, operation=STOP_SERVICES, result=EXEC_FAILED,
                           observations=tuple(seen), detail="; ".join(failures))
        if refusals:
            return Outcome(resource=STOP_SERVICES, operation=STOP_SERVICES, result=EXEC_REFUSED,
                           reason=REFUSE_QUIESCE_INCOMPLETE,
                           observations=tuple(seen), detail="; ".join(refusals))
        # NEVER checkpointable: `stop_app_services` is not a pending resource, it retires nothing,
        # and the services it quiesced are still owed by their own managed-unit operations.
        return Outcome(resource=STOP_SERVICES, operation=STOP_SERVICES, result=EXEC_COMPLETED,
                       checkpointable=False, observations=tuple(seen),
                       detail=f"{len(planned)} recorded application service(s) quiesced")

    def _quiesce(self, operation, *, runner) -> Outcome:                 # pragma: no cover - base
        raise NotImplementedError

    def _quiesce_already_absent(self, operation, *, runner) -> bool:
        """Whether this platform positively proves there is no service left to stop."""
        return False


# ── shared helpers for the platform subclasses ────────────────────────────────


def _run(argv, *, runner=None) -> sc.CommandRun:
    """One subprocess rule for the whole package: an absolute executable and an argv LIST.

    Delegated to `service_control` rather than reimplemented — two implementations of *never a
    shell, never a joined string* is two rules, and only one of them stays right.
    """
    return sc._run_argv(list(argv), runner=runner)


def _canonical(value, *, flavour: str) -> str:
    """Absolute, `..`-free, and on POSIX link-resolved — the same rule `service_identity` applies.

    Lexical canonicalization alone leaves `install_dir -> /` looking like containment, which is the
    substitution the conjunction is supposed to catch.
    """
    text = _normalise(value, flavour=flavour)
    if flavour == POSIX and os.name != "nt":
        return os.path.realpath(text)
    return text


class _PosixUnitFacts:
    """`ExecStart=` and `User=`, read out of a systemd unit."""

    def __init__(self, text: str):
        self.exec_start = ""
        self.user = ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("ExecStart=") and not self.exec_start:
                self.exec_start = stripped.split("=", 1)[1].strip()
            elif stripped.startswith("User=") and not self.user:
                self.user = stripped.split("=", 1)[1].strip()

    @property
    def executable(self) -> str:
        value = self.exec_start.lstrip("-@+!:").strip()
        if value.startswith('"'):
            closing = value.find('"', 1)
            return value[1:closing] if closing > 0 else value[1:]
        return value.split()[0] if value.split() else ""

    @property
    def identity(self) -> str:
        """systemd's own default is root, so an ABSENT `User=` is an observation OF root — not an
        absence of one. A web unit that lost its `User=` therefore still disagrees with the recorded
        `corpusfm` and refuses, which is the regression §W added; and the updater, recorded as
        `root`, agrees without a special case."""
        return self.user or "root"


def posix_conjunction(*, definition_path, name: str, install_dir, expected_identity: str) -> tuple:
    """`(part, detail)` — systemd's half of the five-part conjunction. Pure; reads one file.

    `part` is `CONJ_OK` when the recorded definition binds, and otherwise names WHICH part failed,
    because the planner and the executor want different things from the same proof: the executor
    needs only *is there drift*, and the observer needs *what kind*, so that a hand-edited `User=`
    and a unit that is simply not there produce the decisions they each already have.
    """
    definition = Path(definition_path)
    if _lstat_or_none(definition) is None:
        return CONJ_DEFINITION, f"the recorded definition {definition} is not there"
    if _is_link(os.lstat(str(definition))):
        return CONJ_DEFINITION, f"the recorded definition {definition} is a link, not a unit file"
    expected = f"{name}.service"
    if definition.name != expected:
        return CONJ_DEFINITION, (
            f"the recorded definition is {definition.name!r} and the recorded name is "
            f"{name!r}, which systemd would read from {expected!r}")
    try:
        facts = _PosixUnitFacts(definition.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        # **Unreadable is not drift.** The executor treats it as a refusal either way, but an
        # observer that called this "the definition is gone" would report ownership drift on the
        # evidence of a permission error.
        return CONJ_UNREADABLE, f"{definition} could not be read: {exc}"
    if not facts.executable:
        return CONJ_DEFINITION, f"{definition} names no ExecStart"
    root = _canonical(install_dir, flavour=POSIX)
    candidate = _canonical(facts.executable, flavour=POSIX)
    if not (candidate == root or _within(candidate, root, flavour=POSIX)):
        return CONJ_EXECUTABLE, (
            f"{definition} runs {facts.executable!r}, which is not beneath the recorded "
            f"install directory {install_dir!r}")
    if facts.identity != expected_identity:
        return CONJ_IDENTITY, (
            f"{definition} runs as {facts.identity!r} and this installation recorded "
            f"{expected_identity!r}; somebody has been editing our unit")
    return CONJ_OK, ""


class PosixExecutor(UninstallExecutor):
    """systemd units, a POSIX account, and the shared operations."""

    FLAVOUR = POSIX

    #: The account tool. Absolute, from a fixed constant — never resolved through `PATH`.
    USERDEL = "/usr/sbin/userdel"

    # -- the five-part conjunction --------------------------------------------

    def _prove_conjunction(self, operation) -> str:
        return posix_conjunction(
            definition_path=operation.definition_path, name=operation.name,
            install_dir=operation.install_dir,
            expected_identity=operation.expected_identity)[1]

    def _quiesce_already_absent(self, operation, *, runner) -> bool:
        if _lstat_or_none(Path(operation.definition_path)) is not None:
            return False
        observed, _probe = sc.posix_unit_state(
            f"{operation.name}.service", runner=runner)
        return observed == sc.ABSENT

    # -- removal ---------------------------------------------------------------

    def _remove_managed_unit(self, operation, *, runner) -> Outcome:
        unit = f"{operation.name}.service"
        registered, probe = sc.posix_unit_state(unit, runner=runner)
        definition_there = _lstat_or_none(Path(operation.definition_path)) is not None
        if registered == sc.UNREADABLE:
            # Unreadable is not absence, and it is not residual state either. Nothing is decided
            # from a manager that could not be asked.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"{unit}=unreadable",),
                           detail=f"systemd could not be read: {probe.stderr or probe.stdout!r}")
        if not definition_there:
            if registered == sc.ABSENT:
                return Outcome(resource=operation.resource, operation=operation.tag,
                               result=EXEC_ALREADY_ABSENT, checkpointable=True,
                               observations=(f"{unit}=absent",),
                               detail="systemd does not know the unit and its definition is gone")
            # **RESIDUAL STATE — the F2 RC4.** The definition is gone and systemd still lists the
            # unit, which is precisely what a crash between the removal and the reload leaves. The
            # five-part conjunction cannot be re-proved from a definition that no longer exists, so
            # requiring it here made the retry REFUSE on the evidence of its own progress and left
            # the box with a phantom unit and a pending record nothing could retire.
            #
            # Only the reload is owed, and only the reload is done: no stop, no disable, and no
            # second path removal. The unit's definition has already been removed by an earlier run —
            # removing anything else now would be acting on authority this branch cannot re-prove.
            reload_result = sc.posix_reload_and_observe(unit, runner=runner)
            observations = (f"{unit}={registered}", "definition_already_removed",
                            f"reload_observe={reload_result.state}")
            if reload_result.state != sc.COMPLETED:
                return Outcome(resource=operation.resource, operation=operation.tag,
                               result=EXEC_FAILED, observations=observations,
                               detail=reload_result.detail)
            # Checkpointable only because systemd was asked again and answered ABSENT.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_COMPLETED, checkpointable=True, observations=observations,
                           detail=f"{unit}'s definition was already gone; the reload completed the "
                                  "removal and systemd no longer knows the unit")
        drift = self._prove_conjunction(operation)
        if drift:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_CONJUNCTION, detail=drift)
        control = sc.posix_stop_and_disable(unit, runner=runner)
        if not control.substep_succeeded:
            # THE §X.1 #7 FENCE. A failed stop never reaches a definition removal, and it never
            # reports completion: the service is still running, and deleting its definition would
            # leave nothing on the box able to stop it.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"stop_disable={control.state}",),
                           detail=control.detail)
        # BETWEEN THE SUBSTEPS. The stop and the definition removal are two acts, and the record is
        # read again between them: an operation swapped for a foreign one — same resource, a
        # different definition path — must not have its new target unlinked by this run.
        operation = self._still(operation.resource, operation)
        removed, refusal = self._remove_definition(operation)
        if refusal:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"stop_disable={control.state}",),
                           detail=refusal)
        # THE ORDER THAT MEANS SOMETHING: stop and disable · remove the definition · reload ·
        # observe. A reload taken before the removal re-reads a unit that is still there.
        reload_result = sc.posix_reload_and_observe(unit, runner=runner)
        observations = (f"stop_disable={control.state}", f"removed_definition={removed}",
                        f"reload_observe={reload_result.state}")
        if reload_result.state != sc.COMPLETED:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=observations,
                           detail=reload_result.detail)
        return Outcome(resource=operation.resource, operation=operation.tag,
                       result=EXEC_COMPLETED, checkpointable=True, observations=observations,
                       detail=f"{unit} is absent and its definition is gone")

    def _remove_account(self, operation, *, runner) -> Outcome:
        """The exact recorded account, with a read-back. Never a lookup by a familiar name.

        The runtime root is intentionally owned by this account while the services run.  Reclaim
        that one fixed root *before* deleting the account: the launcher may cross a credential
        boundary after this operation, and a later lifecycle invocation can no longer resolve the
        deleted name to prove that the numeric owner was ours.  Chown-before-userdel also makes an
        interruption between the account checkpoint and terminal cleanup safely resumable.
        """
        before = _posix_account_exists(operation.account)
        if before is None:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED,
                           detail="the account database could not be read; unreadable is not absence")
        if before is False:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_ALREADY_ABSENT, checkpointable=True,
                           detail=f"{operation.account!r} does not resolve")
        reclaim_refusal = _reclaim_posix_runtime_before_account_removal(
            self._layout, operation.account)
        if reclaim_refusal:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, detail=reclaim_refusal)
        run = _run([self.USERDEL, operation.account], runner=runner)
        after = _posix_account_exists(operation.account)
        if after is None:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"userdel={run.returncode}",),
                           detail="the account database could not be read back")
        if after:
            return Outcome(
                resource=operation.resource, operation=operation.tag, result=EXEC_FAILED,
                observations=(f"userdel={run.returncode}",),
                detail=f"{operation.account!r} still resolves after userdel exited "
                       f"{run.returncode}; pending authority is unchanged")
        return Outcome(resource=operation.resource, operation=operation.tag,
                       result=EXEC_COMPLETED, checkpointable=True,
                       observations=(f"userdel={run.returncode}",),
                       detail=f"{operation.account!r} no longer resolves")

    def _quiesce(self, operation, *, runner) -> Outcome:
        """Stop and disable — and nothing else. The definition stays, which is what makes the
        managed-unit operation's conjunction still provable afterwards."""
        drift = self._prove_conjunction(operation)
        if drift:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_CONJUNCTION, detail=drift)
        control = sc.posix_stop_and_disable(f"{operation.name}.service", runner=runner)
        if not control.substep_succeeded:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, detail=control.detail)
        return Outcome(resource=operation.resource, operation=operation.tag,
                       result=EXEC_COMPLETED, checkpointable=False, detail=control.detail)


def _posix_account_exists(account: str):
    """`True` · `False` · `None` for *the account database could not be read*. A seam for tests."""
    try:
        import pwd

        pwd.getpwnam(account)
        return True
    except KeyError:
        return False
    except Exception:                                                     # noqa: BLE001
        return None


def _reclaim_posix_runtime_before_account_removal(layout, account: str) -> str:
    """Return an empty string after root reclaims the fixed run root, else a refusal detail.

    The lifecycle layout supplies the path; the typed account operation supplies the name.  No
    caller supplies either target.  The terminal helper performs the inode/link/mode/owner checks
    and the chown read-back used by final cleanup, so the two boundaries cannot drift apart.
    """
    run_root = Path(layout.lock_file).parent
    st = _lstat_or_none(run_root)
    if st is None:
        return f"the fixed runtime root {run_root} is absent while its lifecycle lock is held"
    if st.st_uid == 0:
        return ""
    try:
        import pwd
        service_uid = pwd.getpwnam(account).pw_uid
    except KeyError:
        return f"{account!r} stopped resolving before its runtime root could be reclaimed"
    except Exception as exc:                                              # noqa: BLE001
        return f"the account database could not identify {account!r}: {type(exc).__name__}"
    try:
        # Delayed to avoid a module-load cycle: uninstall_terminal imports the POSIX purge
        # primitives from this module, while this operation reuses its one authority transition.
        from .uninstall_terminal import _claim_posix_run_root
        _claim_posix_run_root(run_root, st, service_uid=service_uid)
    except LifecycleError as exc:
        return str(exc)
    return ""


__all__ = [
    "EXEC_ALREADY_ABSENT", "EXEC_COMPLETED", "EXEC_FAILED", "EXEC_REFUSED", "EXEC_STATES",
    "EXEC_TERMINAL", "ExecutorRefused", "Outcome", "PathRemovalRefused", "PosixExecutor",
    "STOP_SERVICES", "UninstallExecutor",
]
