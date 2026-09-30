"""Cleanup authority for a failed fresh-install attempt (packet 1398).

A fresh install that fails part-way leaves resources nothing else owns. This module is the ONE place
the protected record of such an attempt is read, validated, classified and turned into typed uninstall
authority. It never executes anything itself: deletion still happens only through the existing pending
record, operations and executors, now in the version-5 `install_attempt` form.

The contract, in the order a reader needs it (the packet is the authority; this is its code):

* **The container** (§2.1) is a dedicated protected directory OUTSIDE every product root. It holds
  `attempt.json`, and during a discard the v5 `pending.json` and `journal.json`. Nothing a service can
  write ever directs a deletion from here.
* **The write-ahead ledger** (§2.4) is the only ownership evidence. A target is removable only when an
  entry recorded it ABSENT immediately before an intended creation, published before that creation.
  A target recorded PRESENT is never removable, whatever happened afterwards.
* **The frozen plan** (§6.1) is written into `attempt.json` before any v5 pending record exists, and
  every dispatch re-proves the pending operations are an unaltered suffix of it.
* **Nothing here publishes a foundation, a locator or a manifest** (ruling 3).
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
import stat as _stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from . import result as R
from .errors import LifecycleError, RecordInvalid
from .layout import POSIX, WINDOWS
from .schema import JOURNAL_RESOLVED, PathsBlock, canonical_path, same_path, utc_now_iso

RECORD_SCHEMA_VERSION = 1

POSIX_CONTAINER_NAME = "corpusfm-attempt"
WINDOWS_CONTAINER_NAME = "CORPUSfm-Attempt"
RECORD_FILENAME = "attempt.json"
PENDING_FILENAME = "pending.json"
JOURNAL_FILENAME = "journal.json"
CONTAINER_FILES = frozenset({RECORD_FILENAME, PENDING_FILENAME, JOURNAL_FILENAME})
#: The protected writers' own staging names. Residue of a write that never replaced, never authority.
_STAGING = re.compile(r"^\.(attempt|pending|journal)\.json\..+\.tmp$")

PHASE_INSTALLING = "installing"
PHASE_DISCARDING = "discarding"
PHASE_TERMINAL_PENDING = "terminal_pending"
PHASE_TERMINAL_DONE = "terminal_done"
PHASES = (PHASE_INSTALLING, PHASE_DISCARDING, PHASE_TERMINAL_PENDING, PHASE_TERMINAL_DONE)

STATE_INTENDED = "intended"
STATE_DONE = "done"
STATE_FAILED = "failed"
ENTRY_STATES = (STATE_INTENDED, STATE_DONE, STATE_FAILED)

CLASS_CREATED = "created"
CLASS_UNTOUCHED = "untouched"
CLASS_MODIFIED = "modified"
CLASS_UNOWNED = "unowned"
CLASS_UNEXPLAINED = "unexplained"

# ── named refusals ────────────────────────────────────────────────────────────
REFUSE_CONTAINER = "install_attempt_container_invalid"
REFUSE_RECORD_UNPROTECTED = "install_attempt_record_unprotected"
REFUSE_RECORD_INVALID = "install_attempt_record_invalid"
REFUSE_PHASE_INVALID = "install_attempt_phase_invalid"
REFUSE_PLAN_MISMATCH = "install_attempt_plan_mismatch"
REFUSE_BINDING_MISMATCH = "install_attempt_binding_mismatch"
REFUSE_UNDECIDABLE = "install_attempt_undecidable"
REFUSE_FORCE = "install_attempt_discard_does_not_accept_force"

# ── attempt states, as a router reads them ─────────────────────────────────────
STATE_NONE = "none"
STATE_LEFTOVER_EMPTY = "leftover_empty_container"
STATE_PRE_FOUNDATION = "pre_foundation"
STATE_FOUNDATION_WINDOW = "foundation_window"
STATE_POST_FOUNDATION = "post_foundation"
STATE_DISCARDING = "discarding"
STATE_TERMINAL_PENDING = "terminal_pending"
STATE_TERMINAL_DONE = "terminal_done"
STATE_BOOKKEEPING = "bookkeeping_only"
STATE_STALE_COMPLETE = "complete_stale_record"

#: The states in which a discard may begin or continue under the lifecycle lock.
DISCARDABLE = frozenset({STATE_PRE_FOUNDATION, STATE_FOUNDATION_WINDOW, STATE_POST_FOUNDATION,
                         STATE_DISCARDING})
#: The states finished OUTSIDE the lifecycle lock, because terminal retirement removes the lock's
#: own directory (the same boundary the ordinary CLI keeps for `uninstall_terminal.retire`).
OUTSIDE_LOCK = frozenset({STATE_TERMINAL_PENDING, STATE_TERMINAL_DONE, STATE_BOOKKEEPING})

PATH_KEYS = ("install_dir", "patch_hosting_dir", "fms_root", "fms_database_dir", "config_dir",
             "state_dir", "secrets_dir", "log_dir", "run_dir", "storage_target", "support_dir")
_PATHS_BLOCK_KEYS = ("install_dir", "patch_hosting_dir", "fms_root", "config_dir", "state_dir",
                     "secrets_dir", "log_dir", "run_dir")
_FIXED_LAYOUT_KEYS = ("config_dir", "state_dir", "secrets_dir", "log_dir", "run_dir")
_PROVENANCE_CLAIMS = frozenset({"self_consistent", "channel_authenticated_bundle",
                                "installation_series_bound"})
_PACKAGE_OBSERVED_KEYS = ("installer_series", "installer_version", "application_commit",
                          "installer_source_commit", "payload_digest_sha256")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MODE = re.compile(r"^0[0-7]{3}$")

#: The account the Linux installer creates, and the system paths it owns when it creates them.
POSIX_SERVICE_ACCOUNT = "corpusfm"
_POSIX_SYSTEM_FILES = {
    "cli_shim": ("usr", "local", "bin", "corpusfm"),
    "db_helper_sudoers": ("etc", "sudoers.d", "corpusfm-db-helper"),
    "update_sudoers": ("etc", "sudoers.d", "corpusfm-update"),
    "tmpfiles": ("etc", "tmpfiles.d", "corpusfm.conf"),
}


class AttemptRefused(LifecycleError):
    """A named refusal. Nothing was written and nothing was removed."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


# ── where it lives, and what protected means ──────────────────────────────────


@dataclass(frozen=True)
class Protection:
    """What a protected container and its files must look like.

    `posix_owner_uid` is root in production; a suite rooted in a temporary directory names its own
    uid, exactly as the executors' tests redirect `privilege.is_elevated`. `windows_authority` is the
    `protection.real_windows_file_authority()` shape, or a double.
    """

    posix_owner_uid: int = 0
    windows_authority: object = None


@dataclass(frozen=True)
class AttemptPaths:
    flavour: str
    container: Path

    @property
    def record(self) -> Path:
        return self.container / RECORD_FILENAME

    @property
    def pending(self) -> Path:
        return self.container / PENDING_FILENAME

    @property
    def journal(self) -> Path:
        return self.container / JOURNAL_FILENAME


def attempt_paths(layout) -> AttemptPaths:
    """Derived from the lifecycle layout, never from a caller.

    POSIX: `/etc/corpusfm-attempt`, the sibling of the locator directory. Windows:
    `C:\\ProgramData\\CORPUSfm-Attempt`, the sibling of the product root. Both are outside every root
    terminal retirement purges, so the record survives the cleanup it authorizes.
    """
    if layout.kind == POSIX:
        return AttemptPaths(POSIX, Path(layout.locator_dir).parent / POSIX_CONTAINER_NAME)
    return AttemptPaths(WINDOWS,
                        Path(layout.journal_file).parent.parent.parent / WINDOWS_CONTAINER_NAME)


def system_paths(layout) -> dict:
    """The fixed Linux system files the installer may create, from the layout's own root."""
    if layout.kind != POSIX:
        return {}
    root = Path(layout.locator_dir).parent.parent
    return {name: str(root.joinpath(*parts)) for name, parts in _POSIX_SYSTEM_FILES.items()}


def _lstat(path) -> os.stat_result | None:
    try:
        return os.lstat(str(path))
    except FileNotFoundError:
        return None


def _is_link(st) -> bool:
    if _stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0)
                & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _windows_api(protection: Protection):
    if protection.windows_authority is not None:
        return protection.windows_authority
    from .protection import real_windows_file_authority      # pragma: no cover - Windows only

    return real_windows_file_authority()                     # pragma: no cover


def container_refusal(paths: AttemptPaths, protection: Protection) -> str:
    """`""` when the existing container has the protected shape, otherwise why not."""
    st = _lstat(paths.container)
    if st is None:
        return f"{paths.container} does not exist"
    if _is_link(st):
        return f"{paths.container} is a link or reparse point"
    if not _stat.S_ISDIR(st.st_mode):
        return f"{paths.container} is not a directory"
    if paths.flavour == POSIX:
        if st.st_uid != protection.posix_owner_uid:
            return f"{paths.container} is owned by uid {st.st_uid}"
        if st.st_mode & 0o077:
            return f"{paths.container} is accessible to accounts other than its owner"
        parent = _lstat(paths.container.parent)
        if parent is None or _is_link(parent) or not _stat.S_ISDIR(parent.st_mode):
            return f"{paths.container.parent} is not a plain directory"
        if parent.st_uid not in (0, protection.posix_owner_uid):
            return f"{paths.container.parent} is not owned by root"
        if parent.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
            return f"{paths.container.parent} is writable by other accounts"
        return ""
    api = _windows_api(protection)
    try:
        authority = api.authority_of_path(str(paths.container))
        allowed = set(api.invoking_owner_sids()) | {api.system_sid_text()}
    except Exception as exc:  # noqa: BLE001 - unreadable authority is not authority
        return f"{paths.container} authority could not be read ({type(exc).__name__})"
    if not authority.protected or authority.inherited:
        return f"{paths.container} does not carry a protected, non-inherited DACL"
    if authority.owner not in allowed:
        return f"{paths.container} is owned outside the administrator/SYSTEM authority"
    extra = [t for t in authority.trustees if t not in allowed]
    if extra:
        return f"{paths.container} grants access to {', '.join(sorted(extra))}"
    return ""


CONTAINER_ABSENT = "absent"
CONTAINER_EMPTY = "empty"
CONTAINER_POPULATED = "populated"


def container_state(paths: AttemptPaths, protection: Protection) -> str:
    """`absent` · `empty` · `populated`; anything unrecognised REFUSES rather than reading absent."""
    if _lstat(paths.container) is None:
        return CONTAINER_ABSENT
    refusal = container_refusal(paths, protection)
    if refusal:
        raise AttemptRefused(REFUSE_CONTAINER, refusal)
    try:
        names = os.listdir(str(paths.container))
    except OSError as exc:
        raise AttemptRefused(REFUSE_CONTAINER, f"{paths.container} could not be listed: {exc}")
    unknown = sorted(n for n in names if n not in CONTAINER_FILES and not _STAGING.match(n))
    if unknown:
        raise AttemptRefused(
            REFUSE_CONTAINER,
            f"{paths.container} holds content this build does not recognise: {unknown}")
    return CONTAINER_POPULATED if any(n in CONTAINER_FILES for n in names) else CONTAINER_EMPTY


def read_protected(paths: AttemptPaths, path: Path, protection: Protection) -> bytes | None:
    """The bytes of one container file, judged on the OPEN descriptor, or `None` when absent."""
    refusal = container_refusal(paths, protection)
    if refusal:
        raise AttemptRefused(REFUSE_CONTAINER, refusal)
    observed = _lstat(path)
    if observed is None:
        return None
    if _is_link(observed) or not _stat.S_ISREG(observed.st_mode):
        raise AttemptRefused(REFUSE_RECORD_UNPROTECTED, f"{path} is not a plain file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AttemptRefused(REFUSE_RECORD_UNPROTECTED, f"{path} could not be opened: {exc}")
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (observed.st_dev,
                                                                          observed.st_ino):
            raise AttemptRefused(REFUSE_RECORD_UNPROTECTED, f"{path} changed while it was opened")
        if paths.flavour == POSIX:
            if st.st_uid != protection.posix_owner_uid:
                raise AttemptRefused(REFUSE_RECORD_UNPROTECTED,
                                     f"{path} is owned by uid {st.st_uid}")
            if st.st_mode & (_stat.S_IWGRP | _stat.S_IWOTH):
                raise AttemptRefused(REFUSE_RECORD_UNPROTECTED,
                                     f"{path} is writable by other accounts")
        else:
            api = _windows_api(protection)
            try:
                authority = api.authority_of(fd)
                allowed = set(api.invoking_owner_sids()) | {api.system_sid_text()}
            except Exception as exc:  # noqa: BLE001
                raise AttemptRefused(REFUSE_RECORD_UNPROTECTED,
                                     f"{path} authority could not be read ({type(exc).__name__})")
            if authority.owner not in allowed or any(t not in allowed
                                                     for t in authority.trustees):
                raise AttemptRefused(REFUSE_RECORD_UNPROTECTED,
                                     f"{path} names an account outside administrator/SYSTEM")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_protected(paths: AttemptPaths, path: Path, payload: bytes,
                    protection: Protection) -> None:
    """Stage in the container, fsync, replace, fsync the container, then prove the bytes landed."""
    refusal = container_refusal(paths, protection)
    if refusal:
        raise AttemptRefused(REFUSE_CONTAINER, refusal)
    fd, staged = tempfile.mkstemp(dir=str(paths.container), prefix=f".{path.name}.", suffix=".tmp")
    try:
        written = 0
        while written < len(payload):
            count = os.write(fd, payload[written:])
            if count <= 0:
                raise AttemptRefused(REFUSE_RECORD_INVALID, f"{path} could not be written")
            written += count
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(staged)
        except OSError:
            pass
        raise
    os.close(fd)
    if paths.flavour == POSIX:
        os.chmod(staged, 0o600)
    os.replace(staged, str(path))
    _fsync_dir(paths.container)
    landed = read_protected(paths, path, protection)
    if landed is None or hashlib.sha256(landed).digest() != hashlib.sha256(payload).digest():
        raise AttemptRefused(REFUSE_RECORD_INVALID, f"{path} did not read back as written")


def unlink_protected(paths: AttemptPaths, path: Path, protection: Protection) -> None:
    refusal = container_refusal(paths, protection)
    if refusal:
        raise AttemptRefused(REFUSE_CONTAINER, refusal)
    try:
        os.unlink(str(path))
    except FileNotFoundError:
        return
    _fsync_dir(paths.container)


def remove_empty_container(paths: AttemptPaths, protection: Protection) -> bool:
    """Remove the container when it holds nothing but staging residue. Never recursive."""
    if container_state(paths, protection) != CONTAINER_EMPTY:
        return False
    for name in os.listdir(str(paths.container)):
        if _STAGING.match(name):
            os.unlink(str(paths.container / name))
    os.rmdir(str(paths.container))
    return True


def create_container(paths: AttemptPaths, protection: Protection) -> None:
    """POSIX creation in the protected shape (the installers own creation on their platform)."""
    if paths.flavour != POSIX:
        raise AttemptRefused(REFUSE_CONTAINER,
                             "the Windows container is created by the installer with its DACL")
    if _lstat(paths.container) is None:
        previous = os.umask(0o077)
        try:
            os.mkdir(str(paths.container), 0o700)
        finally:
            os.umask(previous)
        os.chmod(str(paths.container), 0o700)
    refusal = container_refusal(paths, protection)
    if refusal:
        raise AttemptRefused(REFUSE_CONTAINER, refusal)


def _fsync_dir(directory: Path) -> None:
    from .atomic import _fsync_dir as fsync

    fsync(directory)


# ── the closed record ─────────────────────────────────────────────────────────


def _fail(detail: str):
    raise RecordInvalid(detail)


def _exact(raw: object, keys, what: str) -> dict:
    if not isinstance(raw, dict):
        _fail(f"{what} must be a JSON object")
    if set(raw) != set(keys):
        _fail(f"{what} must have exactly {sorted(keys)}, got {sorted(raw)}")
    return raw


def _bool(value, what):
    if not isinstance(value, bool):
        _fail(f"{what} must be a boolean")
    return value


def _int(value, what, *, minimum=None):
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(f"{what} must be an integer")
    if minimum is not None and value < minimum:
        _fail(f"{what} must be at least {minimum}")
    return value


def _str(value, what, *, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value):
        _fail(f"{what} must be a non-empty string")
    return value


def _uuid(value, what):
    if not isinstance(value, str) or not _UUID.match(value):
        _fail(f"{what} must be a canonical lowercase UUID")
    return value


def _hex64(value, what):
    if not isinstance(value, str) or not _HEX64.match(value):
        _fail(f"{what} must be a lowercase sha256")
    return value


def _path(value, what, platform):
    canonical = canonical_path(value, field_name=what)
    flavour = WINDOWS if re.match(r"^[A-Za-z]:\\|^\\\\", canonical) else POSIX
    if flavour != platform:
        _fail(f"{what} is a {flavour} path on a {platform} record")
    return canonical


def _word(value, what):
    if value not in R.RESULT_VOCABULARY:
        _fail(f"{what} must be a lifecycle result word")
    return value


def _filesystem_state(raw, what, platform, *, kind):
    if not isinstance(raw, dict) or "exists" not in raw:
        _fail(f"{what} must be an object with 'exists'")
    if raw["exists"] is False:
        _exact(raw, ("exists",), what)
        return
    _bool(raw["exists"], f"{what}.exists")
    authority = ("owner", "mode") if platform == POSIX else ("sddl",)
    if kind == "dir":
        _exact(raw, ("exists", "type") + authority, what)
        if raw["type"] != "dir":
            _fail(f"{what}.type must be 'dir'")
    else:
        _exact(raw, ("exists", "type", "size", "sha256") + authority, what)
        if raw["type"] != "file":
            _fail(f"{what}.type must be 'file'")
        _int(raw["size"], f"{what}.size", minimum=0)
        # A null digest is legal only for the attempt's storage target; the record binds it there.
        if raw["sha256"] is not None:
            _hex64(raw["sha256"], f"{what}.sha256")
    if platform == POSIX:
        _str(raw["owner"], f"{what}.owner")
        if not isinstance(raw["mode"], str) or not _MODE.match(raw["mode"]):
            _fail(f"{what}.mode must look like 0755")
    else:
        _str(raw["sddl"], f"{what}.sddl")


def _dir_state(raw, what, platform, *, moved=False):
    if moved and isinstance(raw, dict) and "moved_to" in raw:
        _exact(raw, ("exists", "moved_to"), what)
        if raw["exists"] is not False:
            _fail(f"{what}: a moved directory no longer exists at its source")
        _path(raw["moved_to"], f"{what}.moved_to", platform)
        return
    _filesystem_state(raw, what, platform, kind="dir")


def _present_or_absent(fields):
    def check(raw, what, platform):
        if not isinstance(raw, dict) or "exists" not in raw:
            _fail(f"{what} must be an object with 'exists'")
        if raw["exists"] is False:
            _exact(raw, ("exists",), what)
            return
        _bool(raw["exists"], f"{what}.exists")
        _exact(raw, ("exists",) + tuple(fields), what)
        for name, kind in fields.items():
            if kind == "int":
                _int(raw[name], f"{what}.{name}", minimum=0)
            elif kind == "hex":
                _hex64(raw[name], f"{what}.{name}")
            else:
                _str(raw[name], f"{what}.{name}")
    return check


def _package_set(raw, what, platform):
    raw = _exact(raw, ("packages",), what)
    if not isinstance(raw["packages"], dict):
        _fail(f"{what}.packages must be an object")
    for name, installed in raw["packages"].items():
        _str(name, f"{what}.packages key")
        _bool(installed, f"{what}.packages[{name}]")


def _git_config(raw, what, platform):
    raw = _exact(raw, ("file", "exists", "sha256", "values"), what)
    _path(raw["file"], f"{what}.file", platform)
    _bool(raw["exists"], f"{what}.exists")
    if raw["sha256"] is not None:
        _hex64(raw["sha256"], f"{what}.sha256")
    if not isinstance(raw["values"], list) or not all(isinstance(v, str) for v in raw["values"]):
        _fail(f"{what}.values must be a list of strings")


def _journal_prior(raw, what, platform):
    raw = _exact(raw, ("mode", "subsystem", "state", "installation_id"), what)
    if raw["mode"] != "fresh_install" or raw["subsystem"] is not None or raw["state"] != "open":
        _fail(f"{what} must describe an open fresh_install foundation journal with no subsystem")
    _uuid(raw["installation_id"], f"{what}.installation_id")


def _journal_post(raw, what, platform):
    raw = _exact(raw, ("state",), what)
    if raw["state"] != "discarded":
        _fail(f"{what}.state must be 'discarded'")


def _result_post(extra: dict):
    def check(raw, what, platform):
        raw = _exact(raw, ("result",) + tuple(extra), what)
        _word(raw["result"], f"{what}.result")
        for name, spec in extra.items():
            spec(raw[name], f"{what}.{name}")
    return check


def _nullable_int(value, what):
    if value is not None:
        _int(value, what, minimum=1)


def _str_list(value, what):
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        _fail(f"{what} must be a list of non-empty strings")


def _slot_before(value, what):
    if value is None:
        return
    raw = _exact(value, ("fms_path", "enabled"), what)
    if raw["fms_path"] is not None:
        _str(raw["fms_path"], f"{what}.fms_path", allow_empty=True)
    _bool(raw["enabled"], f"{what}.enabled")


def _prior_family(value, what):
    if not isinstance(value, dict):
        _fail(f"{what} must be an object")
    for proxy_type, facts in value.items():
        _str(proxy_type, f"{what} key")
        facts = _exact(facts, ("pool_existed", "app_existed", "marker_state", "include_present"),
                       f"{what}[{proxy_type}]")
        _bool(facts["pool_existed"], f"{what}[{proxy_type}].pool_existed")
        _bool(facts["app_existed"], f"{what}[{proxy_type}].app_existed")
        _str(facts["marker_state"], f"{what}[{proxy_type}].marker_state")
        _bool(facts["include_present"], f"{what}[{proxy_type}].include_present")


def _obj(spec: dict):
    def check(raw, what, platform):
        raw = _exact(raw, tuple(spec), what)
        for name, validator in spec.items():
            validator(raw[name], f"{what}.{name}")
    return check


def _const(expected):
    def check(value, what):
        if value is not expected and value != expected:
            _fail(f"{what} must be {expected!r}")
    return check


def _one_of(*words):
    def check(value, what):
        if value not in words:
            _fail(f"{what} must be one of {words}")
    return check


def _blocks(value, what):
    if not isinstance(value, dict):
        _fail(f"{what} must be an object")
    for proxy_type, state in value.items():
        _str(proxy_type, f"{what} key")
        if state not in ("BLOCK_ABSENT", "BLOCK_CURRENT"):
            _fail(f"{what}[{proxy_type}] must be BLOCK_ABSENT or BLOCK_CURRENT")


def _unit_enablement(raw, what, platform):
    """Ruling 6: `enable`/`disable` carry the enabled state beside the unit-file facts."""
    raw = _exact(raw, ("exists", "sha256", "enabled"), what)
    _bool(raw["exists"], f"{what}.exists")
    if raw["exists"]:
        _hex64(raw["sha256"], f"{what}.sha256")
    elif raw["sha256"] is not None:
        _fail(f"{what}.sha256 must be null for an absent unit file")
    _bool(raw["enabled"], f"{what}.enabled")


def _only_on(platform_required, check):
    def guarded(raw, what, platform):
        if platform != platform_required:
            _fail(f"{what}: this kind is recorded only on {platform_required}")
        check(raw, what, platform)
    return guarded


def _firewall_rule(raw, what, platform):
    raw = _exact(raw, ("rule", "exists"), what)
    _str(raw["rule"], f"{what}.rule")
    _bool(raw["exists"], f"{what}.exists")


def _iis_proxy_setting(raw, what, platform):
    raw = _exact(raw, ("enabled",), what)
    _bool(raw["enabled"], f"{what}.enabled")


_B = _bool
#: kind -> {intent: (target_kind, prior validator, post validator)}. CLOSED (rulings 5 and 6).
_PATH_TARGET = "path"
_NAME_TARGET = "name"
#: Ruling 6: the one IIS setting the Windows installer changes, named exactly. Not generic authority.
IIS_ARR_PROXY_TARGET = "system.webServer/proxy"
_IIS_TARGET = "iis_arr_proxy"
#: Ruling 6: kinds that classify nothing and never enter a plan, a restore or a manual command.
REPORT_ONLY_KINDS = frozenset({"provider_op", "journal", "package_set", "git_config_entry",
                               "firewall_rule", "iis_setting"})
STORAGE_ROUTE_INTENTS = {"bootstrap": "storage_bootstrap", "adopt": "storage_adopt"}
LEDGER_VOCABULARY: dict = {
    "dir": {
        intent: (_PATH_TARGET, lambda r, w, p: _dir_state(r, w, p),
                 (lambda r, w, p, moved=(intent == "move_aside"): _dir_state(r, w, p, moved=moved)))
        for intent in ("create", "set_owner_mode", "set_acl", "move_aside")
    },
    "file": {
        intent: (_PATH_TARGET,
                 lambda r, w, p: _filesystem_state(r, w, p, kind="file"),
                 lambda r, w, p: _filesystem_state(r, w, p, kind="file"))
        for intent in ("create", "overwrite", "append", "delete")
    },
    "account": {"create": (_NAME_TARGET, _present_or_absent({"uid": "int", "gid": "int"}),
                           _present_or_absent({"uid": "int", "gid": "int"}))},
    "service": {"create": (_NAME_TARGET, _present_or_absent({"binary_path": "str"}),
                           _present_or_absent({"binary_path": "str"}))},
    "task": {"create": (_NAME_TARGET, _present_or_absent({"task_path": "str"}),
                        _present_or_absent({"task_path": "str"}))},
    "unit": {**{intent: (_PATH_TARGET, _present_or_absent({"sha256": "hex"}),
                         _present_or_absent({"sha256": "hex"}))
                for intent in ("create", "delete")},
             **{intent: (_PATH_TARGET, _unit_enablement, _unit_enablement)
                for intent in ("enable", "disable")}},
    "firewall_rule": {"delete": (_NAME_TARGET, _only_on(POSIX, _firewall_rule),
                                 _only_on(POSIX, _firewall_rule))},
    "iis_setting": {"enable_arr_proxy": (_IIS_TARGET, _only_on(WINDOWS, _iis_proxy_setting),
                                         _only_on(WINDOWS, _iis_proxy_setting))},
    "package_set": {"install_packages": (_NAME_TARGET, _package_set, _package_set)},
    "git_config_entry": {intent: (_PATH_TARGET, _git_config, _git_config)
                         for intent in ("append", "unset")},
    "journal": {"abandon_foundation": (_PATH_TARGET, _journal_prior, _journal_post)},
    "provider_op": {
        "foundation": (_NAME_TARGET,
                       _obj({"locator": _const(False), "manifest": _const(False)}),
                       _result_post({"generation": _nullable_int})),
        "provision_keys": (_NAME_TARGET,
                           _obj({"corpus_key": _B, "machine_key": _B, "session_secret": _B}),
                           _result_post({"generated": _str_list, "reused": _str_list})),
        "admin_identity_reconcile": (
            _NAME_TARGET, _obj({"observe": _one_of("NOT_INSTALLED", "LOCAL_ONLY", "WORKING")}),
            _result_post({"committed": _B})),
        "patch_apply": (
            _NAME_TARGET, _obj({"hosting_dir_seq": lambda v, w: _int(v, w, minimum=1)}),
            _result_post({"settled": _B, "slot_touched": _B, "slot_before": _slot_before,
                          "directory_created_by_this_run": _B, "sandbox_existed": _B})),
        "proxy_reconcile": (_NAME_TARGET, _obj({"blocks": _blocks}),
                            _result_post({"prior_family": _prior_family})),
        "storage_bootstrap": (
            _NAME_TARGET,
            _obj({"observe": _str, "route": _str, "target_seq": lambda v, w: _int(v, w, minimum=1)}),
            _result_post({})),
        "storage_adopt": (
            _NAME_TARGET,
            _obj({"observe": _str, "route": _str, "target_seq": lambda v, w: _int(v, w, minimum=1)}),
            _result_post({})),
        "create_first_admin": (_NAME_TARGET, _obj({"users_exist": _const(False)}),
                               _result_post({"created": _B})),
        "retire_scheduler_authority": (_NAME_TARGET, _obj({}), _result_post({})),
        "backfill_storage_projections": (
            _NAME_TARGET,
            _obj({"target_seq": lambda v, w: _int(v, w, minimum=1),
                  "route": _one_of(*STORAGE_ROUTE_INTENTS)}),
            _result_post({})),
    },
}


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    target: str
    kind: str
    intent: str
    prior: Mapping[str, Any]
    state: str
    post: Mapping[str, Any] | None
    intent_utc: str
    result_utc: str | None

    def to_dict(self) -> dict:
        return {"seq": self.seq, "target": self.target, "kind": self.kind, "intent": self.intent,
                "prior": self.prior, "state": self.state, "post": self.post,
                "intent_utc": self.intent_utc, "result_utc": self.result_utc}

    @staticmethod
    def from_dict(raw: object, platform: str) -> "LedgerEntry":
        raw = _exact(raw, ("seq", "target", "kind", "intent", "prior", "state", "post",
                           "intent_utc", "result_utc"), "ledger entry")
        seq = _int(raw["seq"], "ledger seq", minimum=1)
        kind, intent = raw["kind"], raw["intent"]
        if kind not in LEDGER_VOCABULARY:
            _fail(f"ledger entry {seq}: unknown kind {kind!r}")
        if intent not in LEDGER_VOCABULARY[kind]:
            _fail(f"ledger entry {seq}: intent {intent!r} is not allowed for kind {kind!r}")
        target_kind, prior_check, post_check = LEDGER_VOCABULARY[kind][intent]
        if target_kind == _PATH_TARGET:
            target = _path(raw["target"], f"ledger entry {seq} target", platform)
        elif target_kind == _IIS_TARGET:
            target = raw["target"]
            if target != IIS_ARR_PROXY_TARGET:
                _fail(f"ledger entry {seq}: an iis_setting entry names only {IIS_ARR_PROXY_TARGET}")
        else:
            target = _str(raw["target"], f"ledger {seq} target")
        prior_check(raw["prior"], f"ledger entry {seq} prior", platform)
        state = raw["state"]
        if state not in ENTRY_STATES:
            _fail(f"ledger entry {seq}: state must be one of {ENTRY_STATES}")
        _str(raw["intent_utc"], f"ledger entry {seq} intent_utc")
        if state == STATE_INTENDED:
            if raw["post"] is not None or raw["result_utc"] is not None:
                _fail(f"ledger entry {seq}: an intended entry carries no post or result_utc")
        else:
            if raw["post"] is None:
                _fail(f"ledger entry {seq}: a {state} entry requires post")
            post_check(raw["post"], f"ledger entry {seq} post", platform)
            _str(raw["result_utc"], f"ledger entry {seq} result_utc")
            if kind == "firewall_rule" and raw["post"]["rule"] != raw["prior"]["rule"]:
                _fail(f"ledger entry {seq}: the post-observation names a different rule")
        return LedgerEntry(seq=seq, target=target, kind=kind, intent=intent, prior=raw["prior"],
                           state=state, post=raw["post"], intent_utc=raw["intent_utc"],
                           result_utc=raw["result_utc"])


def canonical_operations(operations) -> list:
    return [op.to_dict() if hasattr(op, "to_dict") else dict(op) for op in operations]


def plan_digest(operation_dicts) -> str:
    material = json.dumps(list(operation_dicts), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DiscardPlan:
    operation_id: str
    manifest_generation: int | None
    operations: tuple
    plan_sha256: str

    def to_dict(self) -> dict:
        return {"operation_id": self.operation_id,
                "manifest_generation": self.manifest_generation,
                "operations": [dict(op) for op in self.operations],
                "plan_sha256": self.plan_sha256}

    @staticmethod
    def from_dict(raw: object) -> "DiscardPlan":
        from .uninstall_pending import parse_operation

        raw = _exact(raw, ("operation_id", "manifest_generation", "operations", "plan_sha256"),
                     "discard")
        _uuid(raw["operation_id"], "discard.operation_id")
        _nullable_int(raw["manifest_generation"], "discard.manifest_generation")
        if not isinstance(raw["operations"], list):
            _fail("discard.operations must be a list")
        for index, op in enumerate(raw["operations"]):
            parse_operation(op)
        _hex64(raw["plan_sha256"], "discard.plan_sha256")
        return DiscardPlan(operation_id=raw["operation_id"],
                           manifest_generation=raw["manifest_generation"],
                           operations=tuple(raw["operations"]), plan_sha256=raw["plan_sha256"])


@dataclass(frozen=True)
class AttemptRecord:
    attempt_id: str
    installation_id: str
    platform: str
    created_utc: str
    paths: Mapping[str, str]
    package: Mapping[str, Any] | None
    ledger: tuple
    discard: DiscardPlan | None
    phase: str

    def to_dict(self) -> dict:
        return {"schema_version": RECORD_SCHEMA_VERSION, "attempt_id": self.attempt_id,
                "installation_id": self.installation_id, "platform": self.platform,
                "created_utc": self.created_utc, "paths": dict(self.paths),
                "package": self.package, "ledger": [e.to_dict() for e in self.ledger],
                "discard": None if self.discard is None else self.discard.to_dict(),
                "phase": self.phase}

    @staticmethod
    def from_dict(data: object) -> "AttemptRecord":
        raw = _exact(data, ("schema_version", "attempt_id", "installation_id", "platform",
                            "created_utc", "paths", "package", "ledger", "discard", "phase"),
                     "the attempt record")
        if raw["schema_version"] != RECORD_SCHEMA_VERSION:
            _fail(f"the attempt record declares schema_version {raw['schema_version']!r}")
        attempt_id = _uuid(raw["attempt_id"], "attempt_id")
        installation_id = _uuid(raw["installation_id"], "installation_id")
        platform = raw["platform"]
        if platform not in (POSIX, WINDOWS):
            _fail("platform must be posix or windows")
        _str(raw["created_utc"], "created_utc")
        paths = _exact(raw["paths"], PATH_KEYS, "paths")
        canonical = {key: _path(paths[key], f"paths.{key}", platform) for key in PATH_KEYS}
        PathsBlock.from_dict({key: canonical[key] for key in _PATHS_BLOCK_KEYS})
        module = ntpath if platform == WINDOWS else posixpath
        if not same_path(canonical["storage_target"],
                         module.join(canonical["fms_database_dir"], "CORPUSfm",
                                     "CORPUSfm_DB.fmp12")):
            _fail("paths.storage_target is not derived from paths.fms_database_dir")
        if not same_path(canonical["support_dir"],
                         module.join(canonical["fms_database_dir"], "CORPUSfm-Support")):
            _fail("paths.support_dir is not derived from paths.fms_database_dir")
        package = raw["package"]
        if package is not None:
            package = _exact(package, ("observed", "provenance"), "package")
            observed = _exact(package["observed"], _PACKAGE_OBSERVED_KEYS, "package.observed")
            for key in _PACKAGE_OBSERVED_KEYS:
                if observed[key] is not None:
                    _str(observed[key], f"package.observed.{key}")
            if (not isinstance(package["provenance"], list)
                    or not set(package["provenance"]) <= _PROVENANCE_CLAIMS):
                _fail(f"package.provenance must be a subset of {sorted(_PROVENANCE_CLAIMS)}")
        if not isinstance(raw["ledger"], list):
            _fail("ledger must be a list")
        ledger = tuple(LedgerEntry.from_dict(e, platform) for e in raw["ledger"])
        for index, entry in enumerate(ledger, start=1):
            if entry.seq != index:
                _fail(f"ledger seq must run 1..n without gaps; entry {index} has {entry.seq}")
        for entry in ledger:
            if entry.kind == "provider_op" and entry.intent == "backfill_storage_projections":
                _check_backfill_binding(entry, ledger, canonical["storage_target"])
            if entry.kind == "file":
                _check_undigested_binding(entry, canonical["storage_target"])
        phase = raw["phase"]
        if phase not in PHASES:
            raise RecordInvalid(f"{REFUSE_PHASE_INVALID}: phase must be one of {PHASES}, "
                                f"got {phase!r}")
        discard = None if raw["discard"] is None else DiscardPlan.from_dict(raw["discard"])
        if (phase == PHASE_INSTALLING) != (discard is None):
            raise RecordInvalid(
                f"{REFUSE_PHASE_INVALID}: phase {phase!r} "
                + ("must not carry a frozen plan" if phase == PHASE_INSTALLING
                   else "requires a frozen discard plan"))
        return AttemptRecord(attempt_id=attempt_id, installation_id=installation_id,
                             platform=platform, created_utc=raw["created_utc"],
                             paths=canonical, package=package, ledger=ledger,
                             discard=discard, phase=phase)


def _check_backfill_binding(entry: LedgerEntry, ledger: tuple, storage_target: str) -> None:
    """Ruling 6: a projection backfill names the attempt's own storage target entry and route."""
    target_seq, route = entry.prior["target_seq"], entry.prior["route"]
    if target_seq >= entry.seq:
        _fail(f"ledger entry {entry.seq}: target_seq must name an earlier entry")
    target = ledger[target_seq - 1]
    if target.kind != "file" or not same_path(target.target, storage_target):
        _fail(f"ledger entry {entry.seq}: target_seq {target_seq} is not the storage_target entry")
    storage = [e for e in ledger[:entry.seq - 1] if e.kind == "provider_op"
               and e.intent in STORAGE_ROUTE_INTENTS.values()]
    if not storage:
        _fail(f"ledger entry {entry.seq}: no storage provider entry precedes the backfill")
    last = storage[-1]
    if (last.intent != STORAGE_ROUTE_INTENTS[route] or last.prior["route"] != route
            or last.prior["target_seq"] != target_seq):
        _fail(f"ledger entry {entry.seq}: the backfill route and target disagree with entry "
              f"{last.seq}")


def _check_undigested_binding(entry: LedgerEntry, storage_target: str) -> None:
    """Only the storage target may be observed without a content digest.

    Once FileMaker Server hosts it, the database is a live file the server holds open (on Windows,
    with a sharing mode that refuses a read), so its bytes are neither readable nor ownership
    evidence. Nothing consumes a file entry's digest: ownership is `prior.exists`, the create intent
    and the observed object type, and the storage executor re-proves the database through FMS.
    """
    for side in ("prior", "post"):
        observed = getattr(entry, side)
        if (observed is not None and observed.get("exists") is True
                and observed.get("sha256") is None
                and not same_path(entry.target, storage_target)):
            _fail(f"ledger entry {entry.seq}: {side}.sha256 may be null only for the storage target")


def _serialize(record: AttemptRecord) -> bytes:
    return json.dumps(record.to_dict(), indent=2, sort_keys=True).encode("utf-8") + b"\n"


def read_record(layout, protection: Protection) -> AttemptRecord | None:
    paths = attempt_paths(layout)
    payload = read_protected(paths, paths.record, protection)
    if payload is None:
        return None
    try:
        record = AttemptRecord.from_dict(json.loads(payload.decode("utf-8")))
    except RecordInvalid as exc:
        reason = (REFUSE_PHASE_INVALID if str(exc).startswith(REFUSE_PHASE_INVALID)
                  else REFUSE_RECORD_INVALID)
        raise AttemptRefused(reason, f"{paths.record}: {exc}") from exc
    except ValueError as exc:
        raise AttemptRefused(REFUSE_RECORD_INVALID, f"{paths.record} is not JSON: {exc}") from exc
    if record.platform != paths.flavour:
        raise AttemptRefused(REFUSE_RECORD_INVALID,
                             f"{paths.record} describes {record.platform} on a {paths.flavour} box")
    return record


def write_record(layout, record: AttemptRecord, protection: Protection) -> AttemptRecord:
    validated = AttemptRecord.from_dict(json.loads(_serialize(record)))
    paths = attempt_paths(layout)
    write_protected(paths, paths.record, _serialize(validated), protection)
    return validated


# ── the pending-record authority object (the protocol `uninstall_pending` consumes) ──


@dataclass(frozen=True)
class PendingAuthority:
    """Where a v5 pending record lives and how it is read and written — nothing else."""

    layout: object
    attempt_id: str
    installation_id: str
    protection: Protection

    @property
    def paths(self) -> AttemptPaths:
        return attempt_paths(self.layout)

    @property
    def pending_path(self) -> Path:
        return self.paths.pending

    @property
    def journal_path(self) -> Path:
        return self.paths.journal

    def read_bytes(self, path: Path) -> bytes | None:
        return read_protected(self.paths, path, self.protection)

    def write_bytes(self, path: Path, payload: bytes) -> None:
        write_protected(self.paths, path, payload, self.protection)

    def validate(self, pending_record) -> None:
        """Before every dispatch: the protected frozen plan still authorizes this record."""
        record = read_record(self.layout, self.protection)
        if record is None:
            raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                                 "the attempt record is gone; the v5 pending record has no authority")
        if record.attempt_id != self.attempt_id or record.installation_id != self.installation_id:
            raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                                 "the attempt record names a different attempt or installation")
        validate_pending_against_plan(record, pending_record)


def validate_pending_against_plan(record: AttemptRecord, pending_record) -> None:
    from .uninstall_pending import SOURCE_INSTALL_ATTEMPT

    plan = record.discard
    if plan is None:
        raise AttemptRefused(REFUSE_PLAN_MISMATCH, "the attempt record holds no frozen plan")
    if plan_digest(plan.operations) != plan.plan_sha256:
        raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                             "the frozen operations do not hash to the recorded plan_sha256")
    if pending_record is None:
        return
    if (pending_record.source != SOURCE_INSTALL_ATTEMPT
            or pending_record.attempt_id != record.attempt_id
            or pending_record.installation_id != record.installation_id
            or pending_record.operation_id != plan.operation_id
            or pending_record.manifest_generation != plan.manifest_generation):
        raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                             "the pending record's identity does not match the frozen plan")
    remaining = canonical_operations(pending_record.remaining)
    frozen = [dict(op) for op in plan.operations]
    if len(remaining) > len(frozen) or frozen[len(frozen) - len(remaining):] != remaining:
        raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                             "the pending operations are not an unaltered suffix of the frozen plan")


def freeze_plan(record: AttemptRecord, *, operation_id: str, manifest_generation, operations
                ) -> AttemptRecord:
    dicts = canonical_operations(operations)
    if manifest_generation is None:
        from .uninstall_pending import OP_ACCOUNT, OP_EXACT_PATH

        locator_bound = [op["operation"] for op in dicts
                         if op["operation"] not in (OP_EXACT_PATH, OP_ACCOUNT)]
        if locator_bound:
            raise AttemptRefused(REFUSE_PLAN_MISMATCH,
                                 f"a plan with no published generation may not hold {locator_bound}")
    plan = DiscardPlan(operation_id=operation_id, manifest_generation=manifest_generation,
                       operations=tuple(dicts), plan_sha256=plan_digest(dicts))
    return replace(record, discard=plan, phase=PHASE_DISCARDING)


# ── ledger classification (§2.4) ─────────────────────────────────────────────


def _canon(target: str, platform: str) -> str:
    if platform == WINDOWS:
        return target.replace("/", "\\").rstrip("\\").lower()
    return target.rstrip("/") or "/"


def _inside(child: str, parent: str, platform: str) -> bool:
    c, p = _canon(child, platform), _canon(parent, platform)
    sep = "\\" if platform == WINDOWS else "/"
    return c != p and c.startswith(p + sep)


def default_observer(target: str, kind: str) -> str:
    """`absent` · `match` · `mismatch` for the current state of one recorded target."""
    if kind in ("dir", "file", "unit"):
        st = _lstat(target)
        if st is None:
            return "absent"
        if _is_link(st):
            return "mismatch"
        if kind == "dir":
            return "match" if _stat.S_ISDIR(st.st_mode) else "mismatch"
        return "match" if _stat.S_ISREG(st.st_mode) else "mismatch"
    if kind == "account":
        try:
            import pwd
        except ImportError:                                        # pragma: no cover - Windows
            return "mismatch"
        try:
            pwd.getpwnam(target)
        except KeyError:
            return "absent"
        return "match"
    # Services and tasks are re-proved by the executor's own conjunction before anything acts; the
    # class only decides whether an operation may be BUILT, and presence is not deletion authority.
    return "match"


def classify_target(record: AttemptRecord, target: str, kind: str, *, observer=default_observer
                    ) -> tuple[str, str]:
    """`(class, detail)` from the write-ahead ledger alone — never from observation alone."""
    platform = record.platform
    key = _canon(target, platform) if kind in ("dir", "file", "unit") else target
    entries = [e for e in record.ledger if e.kind == kind
               and (_canon(e.target, platform) if kind in ("dir", "file", "unit") else e.target) == key]
    # A completed move-aside ends the life of the object that stood at this path; what happens there
    # afterwards is a new object with its own first entry.
    last_move = max((i for i, e in enumerate(entries)
                     if e.intent == "move_aside" and e.state == STATE_DONE), default=None)
    considered = entries[last_move + 1:] if last_move is not None else entries
    if last_move is not None and not considered:
        return CLASS_UNOWNED, "moved aside; nothing the attempt created stands at this path"
    if not considered:
        if kind in ("dir", "file", "unit"):
            for parent in record.ledger:
                if (parent.kind == "dir" and parent.intent == "create"
                        and parent.prior.get("exists") is False
                        and _inside(target, parent.target, platform)):
                    return CLASS_CREATED, f"contained in {parent.target}, created by the attempt"
        return CLASS_UNOWNED, "no ledger entry records it"
    first = considered[0]
    if first.prior.get("exists") is not False and first.kind in (
            "dir", "file", "unit", "account", "service", "task"):
        if any(e.state in (STATE_DONE, STATE_INTENDED) for e in considered):
            return CLASS_MODIFIED, f"present before entry {first.seq}; never removable"
        return CLASS_UNTOUCHED, f"present before entry {first.seq}; never removable"
    if first.intent != "create":
        return CLASS_UNEXPLAINED, f"entry {first.seq} records an absent target without a create"
    observed = observer(target, kind)
    if observed == "mismatch":
        return CLASS_UNEXPLAINED, f"created per entry {first.seq}, but what stands there differs"
    return CLASS_CREATED, (f"absent before entry {first.seq} and "
                           + ("now gone" if observed == "absent" else "created by the attempt"))


def _moved_before(record, entry) -> bool:
    return False


def provider_entries(record: AttemptRecord, intent: str) -> list:
    return [e for e in record.ledger if e.kind == "provider_op" and e.intent == intent]


def storage_adopted(record: AttemptRecord) -> bool:
    return bool(provider_entries(record, "storage_adopt"))


# ── plan sources (§6.2) ───────────────────────────────────────────────────────


def _decision(verdict: str, because: str):
    from .uninstall_plan import RECORDED, Decision, PRESERVE

    return Decision(verdict, RECORDED if verdict != PRESERVE else None, because)


def attempt_plan(record: AttemptRecord, layout, *, observer=default_observer) -> tuple:
    """Window A — nothing published. `(view, decisions)` for `remaining_from_plan`."""
    from .schema import OwnershipEntry
    from .uninstall_plan import PRESERVE, REMOVE

    p = record.paths
    decisions: dict = {}
    ownership: list = []

    def dir_class(key):
        return classify_target(record, p[key], "dir", observer=observer)

    for resource, key in (("install_dir", "install_dir"), ("config_dir", "config_dir"),
                          ("state_dir", "state_dir"), ("secrets_dir", "secrets_dir"),
                          ("patch_dir", "patch_hosting_dir")):
        cls, detail = dir_class(key)
        decisions[resource] = (_decision(REMOVE, f"install_attempt: {detail}")
                               if cls == CLASS_CREATED
                               else _decision(PRESERVE, f"install_attempt: {cls}: {detail}"))
    decisions["log_dir"] = _decision(PRESERVE, "install_attempt: logs are always preserved")
    decisions["run_dir"] = _decision(PRESERVE, "the lifecycle coordination footprint")

    cls, detail = dir_class("support_dir")
    if cls == CLASS_CREATED:
        ownership.append(OwnershipEntry("shared_conditional", "support_directory_path",
                                        p["support_dir"]))
        decisions["support_dir"] = _decision(REMOVE, f"install_attempt: {detail}")
    else:
        decisions["support_dir"] = _decision(PRESERVE, f"install_attempt: {cls}: {detail}")

    if record.platform == POSIX:
        cls, detail = classify_target(record, POSIX_SERVICE_ACCOUNT, "account", observer=observer)
        if cls == CLASS_CREATED:
            ownership.append(OwnershipEntry("exact_resource", "service_account",
                                            POSIX_SERVICE_ACCOUNT))
            decisions["service_account"] = _decision(REMOVE, f"install_attempt: {detail}")
        else:
            decisions["service_account"] = _decision(PRESERVE, f"install_attempt: {cls}")
        files = system_paths(layout)
        cls, detail = classify_target(record, files["cli_shim"], "file", observer=observer)
        if cls == CLASS_CREATED:
            ownership.append(OwnershipEntry("exact_resource", "cli_shim_path", files["cli_shim"]))
            decisions["cli_shim"] = _decision(REMOVE, f"install_attempt: {detail}")
        else:
            decisions["cli_shim"] = _decision(PRESERVE, f"install_attempt: {cls}")
        helpers = [files[name] for name in ("db_helper_sudoers", "update_sudoers", "tmpfiles")
                   if classify_target(record, files[name], "file", observer=observer)[0]
                   == CLASS_CREATED]
        for helper in helpers:
            ownership.append(OwnershipEntry("exact_resource", "privilege_helper_path", helper))
        decisions["sudoers_helpers"] = (
            _decision(REMOVE, "install_attempt: helpers the attempt created") if helpers
            else _decision(PRESERVE, "install_attempt: no helper was created"))

    view = SimpleNamespace(
        paths=PathsBlock.from_dict({key: p[key] for key in _PATHS_BLOCK_KEYS}),
        ownership=tuple(ownership), services=(), proxy_policy={},
        patch=SimpleNamespace(folder_slot=None, registered=None, verified=None, sandbox_file=None),
        storage=SimpleNamespace(database_name=None), pki=SimpleNamespace(registration_name=None,
                                                                         public_fingerprint=None))
    return view, decisions


def attempt_filter(record: AttemptRecord, decisions: dict, manifest, *, observer=default_observer
                   ) -> dict:
    """Window B — the existing plan, with every removal the ledger does not prove turned to PRESERVE.

    It only ever narrows: a decision is replaced by PRESERVE, never added, never widened.
    """
    from .uninstall_plan import DEREGISTER_ONLY, PRESERVE, RECORDED, REMOVE, UNAVAILABLE

    p = record.paths
    platform = record.platform

    def created(target, kind):
        return classify_target(record, target, kind, observer=observer)[0] == CLASS_CREATED

    patch = provider_entries(record, "patch_apply")
    patch_post = patch[-1].post if patch and patch[-1].post is not None else None
    patch_unsettled = patch_post is not None and patch_post["settled"] is False
    proxy = provider_entries(record, "proxy_reconcile")
    proxy_post = proxy[-1].post if proxy and proxy[-1].post is not None else None
    proxy_clean = proxy_post is not None and not any(
        f["pool_existed"] or f["app_existed"] for f in proxy_post["prior_family"].values())
    identity = provider_entries(record, "admin_identity_reconcile")
    storage_boot = provider_entries(record, "storage_bootstrap")
    services = {entry.role: entry for entry in getattr(manifest, "services", ())}

    def unit_created(role):
        entry = services.get(role)
        if entry is None:
            return False
        names = {entry.unit, entry.name}
        for e in record.ledger:
            if e.kind in ("service", "task", "unit") and any(
                    n and (_canon(e.target, platform) == _canon(n, platform)) for n in names):
                return classify_target(record, e.target, e.kind, observer=observer)[0] \
                    == CLASS_CREATED
        return False

    def ownership(kind):
        return [e.identifier for e in manifest.ownership if e.kind == kind]

    rules = {
        "install_dir": lambda: created(p["install_dir"], "dir"),
        "config_dir": lambda: created(p["config_dir"], "dir"),
        "state_dir": lambda: created(p["state_dir"], "dir"),
        "secrets_dir": lambda: created(p["secrets_dir"], "dir") and not storage_adopted(record),
        "log_dir": lambda: False,
        "run_dir": lambda: False,
        "support_dir": lambda: created(p["support_dir"], "dir"),
        # The hosting folder is removable whenever the write-ahead ledger proves THIS attempt created
        # it — never conditioned on a patch_apply result (packet 1398 ruling, deviation 1). An
        # interruption before the patch provider ran (window B) still created it, and the remove-if-
        # empty executor decides the rest: empty → removed, non-empty → preserved/refused, prior-present
        # → never a C class here so never removed. The slot and sandbox remain governed by patch_apply.
        "patch_dir": lambda: created(p["patch_hosting_dir"], "dir"),
        "patch_slot": lambda: patch_unsettled,
        "sandbox": lambda: patch_unsettled and patch_post["sandbox_existed"] is False,
        "sandbox_rc": lambda: patch_unsettled and patch_post["sandbox_existed"] is False,
        "storage_db": lambda: bool(storage_boot) and not storage_adopted(record)
        and created(p["storage_target"], "file"),
        "storage_rc": lambda: bool(storage_boot) and not storage_adopted(record)
        and created(p["storage_target"], "file"),
        "pki": lambda: bool(identity)
        and identity[-1].prior["observe"] in ("NOT_INSTALLED", "LOCAL_ONLY"),
        "proxy_edits": lambda: proxy_clean,
        "service_account": lambda: platform == POSIX and created(POSIX_SERVICE_ACCOUNT, "account"),
        "cli_shim": lambda: bool(ownership("cli_shim_path"))
        and all(created(path, "file") for path in ownership("cli_shim_path")),
        "sudoers_helpers": lambda: bool(ownership("privilege_helper_path"))
        and all(created(path, "file") for path in ownership("privilege_helper_path")),
        "web_service": lambda: unit_created("web"),
        "updater_task": lambda: unit_created("updater"),
    }
    narrowed = dict(decisions)
    for resource, decision in decisions.items():
        owed = decision.decision in (REMOVE, DEREGISTER_ONLY) or (
            decision.decision == UNAVAILABLE and decision.authority == RECORDED)
        if not owed:
            continue
        rule = rules.get(resource)
        if rule is None or not rule():
            narrowed[resource] = _decision(
                PRESERVE, "install_attempt: the ledger does not prove the attempt created it")
    return narrowed


# ── the phase table (§2.3) and the attempt state (§3) ─────────────────────────


@dataclass(frozen=True)
class AttemptState:
    kind: str
    record: AttemptRecord | None = None
    pending: object = None
    journal: object = None
    detail: str = ""


def _read_container_pending(layout, record, protection):
    from .uninstall_pending import PendingRecordRefused, read

    if record is None:
        return None
    try:
        return read(layout, attempt=PendingAuthority(layout, record.attempt_id,
                                                     record.installation_id, protection))
    except PendingRecordRefused as exc:
        raise AttemptRefused(REFUSE_UNDECIDABLE, str(exc)) from exc


def _read_pending_without_record(layout, protection):
    """Bookkeeping-only reading: the file is still judged, but no attempt id is known to match."""
    from .uninstall_pending import PendingRecord, SOURCE_INSTALL_ATTEMPT

    paths = attempt_paths(layout)
    payload = read_protected(paths, paths.pending, protection)
    if payload is None:
        return None
    try:
        pending = PendingRecord.from_dict(json.loads(payload.decode("utf-8")))
    except (ValueError, RecordInvalid) as exc:
        raise AttemptRefused(REFUSE_UNDECIDABLE, f"{paths.pending} is malformed: {exc}") from exc
    if pending.source != SOURCE_INSTALL_ATTEMPT:
        raise AttemptRefused(REFUSE_UNDECIDABLE, f"{paths.pending} is not an install-attempt record")
    return pending


def _read_container_journal(layout, protection):
    from .journal import Journal

    paths = attempt_paths(layout)
    if read_protected(paths, paths.journal, protection) is None:
        return None
    try:
        return Journal(layout, path=paths.journal).read()
    except RecordInvalid as exc:
        raise AttemptRefused(REFUSE_UNDECIDABLE, f"{paths.journal}: {exc}") from exc


def _locator_present(layout, locator_adapter=None) -> bool:
    from .locator import locator_for

    adapter = locator_adapter if locator_adapter is not None else locator_for(layout)
    try:
        return adapter.exists()
    except OSError:
        return True


def check_phase(record: AttemptRecord, *, pending, journal, locator_present: bool) -> None:
    """The §2.3 phase table. Any other combination is undecidable and refuses by name."""
    def refuse(why):
        raise AttemptRefused(REFUSE_PHASE_INVALID, f"phase {record.phase!r}: {why}")

    def bound(obj):
        return (obj is not None and obj.installation_id == record.installation_id
                and record.discard is not None and obj.operation_id == record.discard.operation_id)

    if record.phase == PHASE_INSTALLING:
        if record.discard is not None:
            refuse("an installing record may not hold a frozen plan")
        if pending is not None or journal is not None:
            refuse("an installing record may not have a discard pending record or journal")
        return
    if record.discard is None:
        refuse("a frozen discard plan is required")
    if record.phase == PHASE_DISCARDING:
        if pending is not None and not bound(pending):
            refuse("the pending record is not bound to the frozen plan")
        if journal is not None and not bound(journal):
            refuse("the container journal is not bound to the frozen plan")
        return
    # terminal_pending and terminal_done share every precondition.
    if pending is None or not bound(pending) or pending.remaining:
        refuse("requires a bound pending record with no remaining operations")
    if journal is None or not bound(journal) or journal.state != JOURNAL_RESOLVED:
        refuse("requires the matching container journal, resolved")
    if locator_present:
        refuse("requires that no locator exists")


def classify(layout, protection: Protection, *, locator_adapter=None) -> AttemptState:
    """What the protected container says about this box, before anything acts on it."""
    from . import uninstall_inventory as inv
    from .journal import Journal
    from .manifest import ManifestStore

    paths = attempt_paths(layout)
    state = container_state(paths, protection)
    if state == CONTAINER_ABSENT:
        return AttemptState(STATE_NONE)
    if state == CONTAINER_EMPTY:
        return AttemptState(STATE_LEFTOVER_EMPTY)
    record = read_record(layout, protection)
    if record is None:
        pending = _read_pending_without_record(layout, protection)
        journal = _read_container_journal(layout, protection)
        if pending is not None and pending.remaining:
            raise AttemptRefused(REFUSE_UNDECIDABLE,
                                 "no attempt record, and the pending record still owes work")
        if journal is None or journal.state != JOURNAL_RESOLVED:
            raise AttemptRefused(REFUSE_UNDECIDABLE,
                                 "no attempt record, and no resolved container journal")
        if pending is not None and (pending.operation_id != journal.operation_id
                                    or pending.installation_id != journal.installation_id):
            raise AttemptRefused(REFUSE_UNDECIDABLE,
                                 "the pending record and container journal describe different work")
        return AttemptState(STATE_BOOKKEEPING, pending=pending, journal=journal)

    pending = _read_container_pending(layout, record, protection)
    journal = _read_container_journal(layout, protection)
    locator_present = _locator_present(layout, locator_adapter)
    check_phase(record, pending=pending, journal=journal, locator_present=(
        locator_present if record.phase in (PHASE_TERMINAL_PENDING, PHASE_TERMINAL_DONE)
        else False))
    if record.phase == PHASE_DISCARDING:
        return AttemptState(STATE_DISCARDING, record, pending, journal)
    if record.phase == PHASE_TERMINAL_PENDING:
        return AttemptState(STATE_TERMINAL_PENDING, record, pending, journal)
    if record.phase == PHASE_TERMINAL_DONE:
        return AttemptState(STATE_TERMINAL_DONE, record, pending, journal)

    if locator_present:
        locator_state, manifest_state, manifest = inv.observe_locator_and_manifest(
            layout, locator_adapter=locator_adapter)
        if (manifest is not None and manifest.last_result is not None
                and manifest.last_result.operation_id == record.attempt_id
                and manifest.installation_id == record.installation_id):
            return AttemptState(STATE_STALE_COMPLETE, record,
                                detail="the manifest carries this attempt's completion stamp")
        return AttemptState(STATE_POST_FOUNDATION, record)
    store = ManifestStore(Path(record.paths["install_dir"]), layout=layout)
    try:
        exists = store.exists()
    except OSError as exc:
        raise AttemptRefused(REFUSE_UNDECIDABLE, f"the install directory is unreadable: {exc}")
    if not exists:
        return AttemptState(STATE_PRE_FOUNDATION, record)
    try:
        manifest = store.read()
        ordinary = Journal(layout).read()
    except (RecordInvalid, OSError) as exc:
        raise AttemptRefused(REFUSE_UNDECIDABLE, f"the unpublished foundation is unreadable: {exc}")
    if (manifest.installation_id != record.installation_id or manifest.generation != 1
            or manifest.last_result is not None):
        raise AttemptRefused(REFUSE_UNDECIDABLE,
                             "an unpublished manifest stands in the install directory and it is not "
                             "this attempt's generation-1 foundation")
    abandoned = [e for e in record.ledger if e.kind == "journal" and e.intent == "abandon_foundation"
                 and e.prior.get("installation_id") == record.installation_id]
    bound = (ordinary is not None and ordinary.mode == "fresh_install"
             and ordinary.current_subsystem is None
             and ordinary.installation_id == record.installation_id)
    if bound and ordinary.state == "open":
        return AttemptState(STATE_FOUNDATION_WINDOW, record, journal=ordinary)
    if bound and ordinary.state == JOURNAL_RESOLVED and abandoned:
        return AttemptState(STATE_FOUNDATION_WINDOW, record, journal=ordinary)
    if ordinary is None and abandoned:
        return AttemptState(STATE_FOUNDATION_WINDOW, record)
    raise AttemptRefused(
        REFUSE_UNDECIDABLE,
        "an unpublished manifest stands in the install directory without the open foundation "
        "journal, bound by installation_id, that ties it to this attempt")


# ── binding checks (§6.3) ─────────────────────────────────────────────────────


def bind(state: AttemptState, layout, *, installation_id: str, locator_adapter=None) -> object:
    """Every binding the kind of state requires. Returns the manifest for window B, else `None`."""
    from . import uninstall_inventory as inv
    from .os_layout import os_layout_for_lifecycle

    record = state.record

    def refuse(why):
        raise AttemptRefused(REFUSE_BINDING_MISMATCH, why)

    if record is None:
        return None
    if record.installation_id != str(installation_id).lower():
        refuse(f"the request names {installation_id} and the attempt is {record.installation_id}")
    osl = os_layout_for_lifecycle(layout)
    for key in _FIXED_LAYOUT_KEYS:
        if not same_path(record.paths[key], str(getattr(osl, key))):
            refuse(f"paths.{key} {record.paths[key]} is not this platform's fixed layout")
    if state.kind != STATE_POST_FOUNDATION:
        return None
    locator_state, manifest_state, manifest = inv.observe_locator_and_manifest(
        layout, expected_installation_id=record.installation_id, locator_adapter=locator_adapter)
    if locator_state != inv.LOCATOR_VALID or manifest_state != inv.MANIFEST_VALID:
        refuse(f"the locator is {locator_state} and the manifest is {manifest_state}")
    from .locator import locator_for

    locator = (locator_adapter if locator_adapter is not None else locator_for(layout)).read()
    if not (same_path(locator.install_dir, record.paths["install_dir"])
            and same_path(manifest.paths.install_dir, record.paths["install_dir"])):
        refuse("the locator, manifest and attempt record name different install directories")
    for key in _PATHS_BLOCK_KEYS:
        recorded = getattr(manifest.paths, key)
        if recorded is None or not same_path(recorded, record.paths[key]):
            refuse(f"manifest paths.{key} is {recorded} and the attempt recorded "
                   f"{record.paths[key]}")
    observed = (record.package or {}).get("observed") if record.package else None
    installer = getattr(manifest, "installer", None)
    if observed is None:
        if installer is not None and installer.source != "development":
            refuse("a development attempt may only bind a development installation record")
    else:
        if installer is None or (installer.series != observed["installer_series"]
                                 or installer.version != observed["installer_version"]):
            refuse("the manifest installer identity differs from the attempt's observed package")
        if observed["application_commit"] and manifest.build.commit != observed["application_commit"]:
            refuse("the manifest application commit differs from the attempt's observed package")
    if manifest.last_result is not None and manifest.last_result.operation_id == record.attempt_id:
        refuse("the manifest carries this attempt's completion stamp")
    return manifest


# ── terminal retirement under record authority (§6.6 step 3b) ──────────────────


def terminal_plan(record: AttemptRecord, os_layout, *, observer=default_observer) -> tuple:
    """`((root, remove_root, keep), ...)` for `uninstall_terminal.retire`'s attempt form.

    A root the attempt created is removed whole, except the log tree. Any other root keeps
    everything the ledger does not prove the attempt created — its logs above all.
    """
    from .uninstall_terminal import _roots

    platform = record.platform
    log_dir = str(os_layout.log_dir)
    plan = []
    for root in _roots(os_layout):
        root_text = str(root)
        if same_path(root_text, log_dir):
            continue
        cls, _detail = classify_target(record, root_text, "dir", observer=observer)
        keep = [log_dir] if _inside(log_dir, root_text, platform) else []
        if cls == CLASS_CREATED and not keep:
            plan.append((root_text, True, ()))
            continue
        try:
            children = os.listdir(root_text)
        except FileNotFoundError:
            continue
        for name in children:
            child = str(Path(root_text) / name)
            if same_path(child, log_dir):
                continue
            kind = "dir" if os.path.isdir(child) and not os.path.islink(child) else "file"
            if classify_target(record, child, kind, observer=observer)[0] != CLASS_CREATED:
                keep.append(child)
        plan.append((root_text, cls == CLASS_CREATED and not keep, tuple(keep)))
    return tuple(plan)


def manual_commands(record: AttemptRecord, layout, *, observer=default_observer) -> tuple:
    """§7.1 — the bounded filesystem fallback, for a record the CALLER has already proved protected,
    valid and fully bound.

    Only `dir`/`file` targets whose FIRST ledger entry is a published `prior: absent` create, that
    still stand, and that are not the log tree. Never a provider or system-authority resource, never
    anything recorded present. Reverse creation order, then the attempt record itself.
    """
    platform = record.platform
    log_dir = record.paths["log_dir"]
    seen = set()
    commands = []
    for entry in sorted(record.ledger, key=lambda e: e.seq, reverse=True):
        if entry.kind not in ("dir", "file") or entry.intent != "create":
            continue
        key = _canon(entry.target, platform)
        if key in seen:
            continue
        seen.add(key)
        if same_path(entry.target, log_dir) or _inside(entry.target, log_dir, platform) \
                or _inside(log_dir, entry.target, platform):
            continue
        cls, _detail = classify_target(record, entry.target, entry.kind, observer=observer)
        if cls != CLASS_CREATED or observer(entry.target, entry.kind) != "match":
            continue
        commands.append(_remove_command(entry.target, entry.kind, platform))
    paths = attempt_paths(layout)
    commands.append(_remove_command(str(paths.record), "file", platform))
    return tuple(commands)


def _remove_command(target: str, kind: str, platform: str) -> str:
    if platform == WINDOWS:
        quoted = "'" + target.replace("'", "''") + "'"
        return (f"Remove-Item -LiteralPath {quoted} -Recurse -Force" if kind == "dir"
                else f"Remove-Item -LiteralPath {quoted} -Force")
    quoted = "'" + target.replace("'", "'\\''") + "'"
    return f"rm -rf -- {quoted}" if kind == "dir" else f"rm -f -- {quoted}"


def status_summary(layout, protection: Protection) -> dict | None:
    """For `status --json`: present only when a container exists, so ordinary status is unchanged."""
    paths = attempt_paths(layout)
    if _lstat(paths.container) is None:
        return None
    try:
        state = classify(layout, protection)
    except AttemptRefused as exc:
        return {"state": "undecidable", "reason": exc.reason, "detail": exc.detail}
    summary = {"state": state.kind}
    if state.record is not None:
        summary.update({"attempt_id": state.record.attempt_id,
                        "installation_id": state.record.installation_id,
                        "phase": state.record.phase})
    elif state.journal is not None:
        # Bookkeeping only: the installer needs the id its uninstall request must name.
        summary["installation_id"] = state.journal.installation_id
    return summary


def complete_fresh_install(layout, *, lock, installation_id: str, attempt_id: str,
                           protection: Protection, users_exist, locator_adapter=None) -> dict:
    """§3 — the authoritative completion boundary. The last lifecycle mutation of a fresh install.

    Order: every check, the compare-and-swap stamp `last_result.operation_id = attempt_id`, THEN the
    record is unlinked and the empty container removed. A crash between the stamp and the unlink
    leaves the stale-complete state, which any later run retires; it never reads as a failed attempt.
    """
    from . import uninstall_inventory as inv
    from .journal import Journal
    from .locator import locator_for
    from .manifest import ManifestStore
    from .schema import LastResultBlock

    def refuse(reason, why):
        raise AttemptRefused(reason, why)

    paths = attempt_paths(layout)
    state = classify(layout, protection, locator_adapter=locator_adapter)
    if state.kind not in (STATE_POST_FOUNDATION, STATE_STALE_COMPLETE):
        refuse(REFUSE_PHASE_INVALID, f"completion requires a published attempt, not {state.kind}")
    record = state.record
    if record.attempt_id != attempt_id or record.installation_id != str(installation_id).lower():
        refuse(REFUSE_BINDING_MISMATCH, "the request names a different attempt or installation")
    locator_state, manifest_state, manifest = inv.observe_locator_and_manifest(
        layout, expected_installation_id=record.installation_id, locator_adapter=locator_adapter)
    if locator_state != inv.LOCATOR_VALID or manifest_state != inv.MANIFEST_VALID:
        refuse(REFUSE_BINDING_MISMATCH,
               f"the locator is {locator_state} and the manifest is {manifest_state}")
    locator = (locator_adapter if locator_adapter is not None else locator_for(layout)).read()
    if not (same_path(locator.install_dir, record.paths["install_dir"])
            and same_path(manifest.paths.install_dir, record.paths["install_dir"])):
        refuse(REFUSE_BINDING_MISMATCH, "the install directories do not agree")
    stamped = (manifest.last_result is not None
               and manifest.last_result.operation_id == record.attempt_id)
    generation = manifest.generation
    if not stamped:
        ordinary = Journal(layout).read()
        if ordinary is not None and ordinary.state != JOURNAL_RESOLVED:
            refuse(REFUSE_PHASE_INVALID, "a lifecycle operation is unresolved")
        if not manifest.storage.database_name:
            refuse(REFUSE_PHASE_INVALID, "the storage block is not recorded")
        try:
            exists = users_exist()
        except Exception as exc:  # noqa: BLE001 - an outage is UNKNOWN, never "no users"
            refuse(REFUSE_PHASE_INVALID,
                   f"whether an administrator exists could not be read ({type(exc).__name__})")
        if exists is not True:
            refuse(REFUSE_PHASE_INVALID, "no CORPUSfm administrator exists yet")
        stamp = LastResultBlock(mode="fresh_install", result=R.COMPLETED,
                                operation_id=record.attempt_id, completed_utc=utc_now_iso())
        written = ManifestStore(Path(record.paths["install_dir"]), layout=layout).write(
            replace(manifest, last_result=stamp), lock=lock, expected_generation=generation)
        generation = written.generation
    unlink_protected(paths, paths.record, protection)
    remove_empty_container(paths, protection)
    return {"result": R.NO_CHANGE if stamped else R.COMPLETED, "attempt_id": record.attempt_id,
            "installation_id": record.installation_id, "generation": generation,
            "detail": ("the completion stamp was already present; the stale record was retired"
                       if stamped else "the fresh installation is complete")}


def inspect(layout, protection: Protection, *, installation_id: str) -> dict:
    """What §7's Inspect shows, read-only. Manual commands appear ONLY for a protected, valid,
    fully bound record (§7.1); anything else yields its finding and no command."""
    try:
        state = classify(layout, protection)
    except AttemptRefused as exc:
        return {"state": "undecidable", "reason": exc.reason, "detail": exc.detail,
                "manual_commands": []}
    summary = {"state": state.kind, "manual_commands": []}
    record = state.record
    if record is None:
        return summary
    summary.update({"attempt_id": record.attempt_id, "installation_id": record.installation_id,
                    "phase": record.phase, "package": record.package,
                    "ledger": [{"seq": e.seq, "target": e.target, "kind": e.kind,
                                "intent": e.intent, "state": e.state,
                                "class": (classify_target(record, e.target, e.kind)[0]
                                          if e.kind not in REPORT_ONLY_KINDS else None)}
                               for e in record.ledger]})
    try:
        bind(state, layout, installation_id=installation_id)
    except AttemptRefused as exc:
        summary.update({"reason": exc.reason, "detail": exc.detail})
        return summary
    summary["manual_commands"] = list(manual_commands(record, layout))
    return summary


def utc() -> str:
    return utc_now_iso()


__all__ = [
    "AttemptPaths", "AttemptRecord", "AttemptRefused", "AttemptState", "DiscardPlan",
    "LedgerEntry", "PendingAuthority", "Protection", "attempt_filter", "attempt_paths",
    "attempt_plan", "bind", "check_phase", "classify", "classify_target", "container_state",
    "freeze_plan", "plan_digest", "read_record", "status_summary", "terminal_plan",
    "validate_pending_against_plan", "write_record",
]
