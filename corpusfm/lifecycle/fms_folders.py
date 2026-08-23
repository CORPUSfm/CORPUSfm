"""The FileMaker Server Additional Database Folder adapter (packet 1246-05-01).

One place that knows the Admin API's folder vocabulary, so `patch_compartment` can reason about
slots without also knowing that slot 2's enable flag is spelled `UseOtherDatabaseRoot3`.

**The API is required.** There is no capability negotiation and no degraded return: every method
raises, and the one construction path returns `None` when authority is absent so the caller can
answer with a report instead of a traceback.

**The prefix conversion is one function.** `local_path_from_fms` is the only place an FMS folder
string becomes a comparable local path, because two implementations of "is this the same folder"
drift and the drift is invisible until a conversion refuses on a box nobody tested.
"""

from __future__ import annotations

import ntpath
import posixpath
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Protocol

from .errors import LifecycleError
from .layout import POSIX, WINDOWS

# Claris documents 255 characters and a trailing slash on every accepted form.
FMS_PATH_LIMIT = 255
_PREFIXES = ("filewin:/", "filemac:/", "filelinux:/")

# THE API HAS TWO VOCABULARIES AND THEY ARE NOT THE SAME. Reading one with the other's names is a
# silent failure — every slot reads back empty, the exact readback can never match, and the
# before-image a rollback restores from is blank.
#
#   WRITE (PATCH /server/config/additionaldbfolder): UseOtherDatabaseRoot / DatabaseRootPath,
#         and the second slot is spelled "3".
#   READ  paths   (GET /server/additionaldbpath):    additionalDatabaseFolderPath[2]
#   READ  enabled (GET /server/currentfoldersettings): additionalDatabaseFolder[2]. Claris
#         documents null before enablement; FMS 2026 also returns ["disabled"] for an inactive,
#         configured slot, so recognised status words take precedence over mere presence.

# (index, PATCH enable field, PATCH path field). Ordered: lowest free slot wins.
SLOT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("1", "UseOtherDatabaseRoot", "DatabaseRootPath"),
    ("2", "UseOtherDatabaseRoot3", "DatabaseRootPath3"),
)

# (index, additionaldbpath path field, currentfoldersettings enabled field).
SLOT_READ_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("1", "additionalDatabaseFolderPath", "additionalDatabaseFolder"),
    ("2", "additionalDatabaseFolderPath2", "additionalDatabaseFolder2"),
)

# The remote-container fields as the PATCH names them. NEVER sent — packet §8. Listed so the
# omission can be asserted against the exact names a body would have to carry.
PATCH_RC_FIELDS: tuple[str, ...] = (
    "UseDatabaseRoot1_RC", "DatabaseRootPath1_RC", "backupDatabaseRoot1_RC",
    "UseDatabaseRoot3_RC", "DatabaseRootPath3_RC", "backupDatabaseRoot3_RC",
)

# The remote-container fields as currentfoldersettings REPORTS them. Captured and compared to prove
# they are unchanged — a different vocabulary from the one above, deliberately kept apart.
READ_RC_FIELDS: tuple[str, ...] = (
    "additionalRemoteContainerFolder", "additionalRemoteContainerFolder2",
)

_FOLDER_SETTINGS = "/server/currentfoldersettings"
_ADDITIONAL_PATHS = "/server/additionaldbpath"
_PATCH_FOLDER = "/server/config/additionaldbfolder"
_DATABASES = "/databases"


class FmsFolderError(LifecycleError):
    """An Admin API folder operation failed. Never swallowed into a False."""


class CompartmentApiUnavailable(FmsFolderError):
    """No usable Admin API authority. A refusal, never a fallback."""


class FmsPathRefused(FmsFolderError):
    """A path FileMaker Server cannot accept as an Additional Database Folder."""


@dataclass(frozen=True)
class SlotRecord:
    index: str
    fms_path: str | None
    local_path: Path | None
    enabled: bool


def database_stem(name: str) -> str:
    """A comparable database name. FileMaker is loose about the suffix; `ensure_fmp12` normalises UP
    for display and matching, and this is its inverse for the one place that needs a bare stem."""
    from corpusfm.core.filenames import ensure_fmp12

    return ensure_fmp12(name)[: -len(".fmp12")].lower() if name else ""


def fms_prefix_for(flavour: str) -> str:
    if flavour == WINDOWS:
        return "filewin:/"
    if flavour == POSIX:
        return "filelinux:/"
    raise FmsPathRefused(f"no FileMaker path prefix is defined for flavour {flavour!r}")


def fms_path_for(path: Path | str, *, flavour: str) -> str:
    """Local path -> the FMS folder form, validated against Claris's stated rules."""
    text = str(path)
    if not text:
        raise FmsPathRefused("an empty path is not an Additional Database Folder")
    if text.startswith("\\\\") or text.startswith("//"):
        raise FmsPathRefused(f"a UNC path is not accepted as a database folder: {text!r}")
    # The prefix already ends in the separator, and a POSIX path already begins with one. Joining
    # them naively yields `filelinux://opt/...`, which is not the form Claris documents and not the
    # form the installer writes (`install.sh:1595`).
    body = text.replace("\\", "/").strip("/")
    rendered = f"{fms_prefix_for(flavour)}{body}/"
    if len(rendered) > FMS_PATH_LIMIT:
        raise FmsPathRefused(
            f"the FileMaker folder form is {len(rendered)} characters; the limit is "
            f"{FMS_PATH_LIMIT}"
        )
    return rendered


def local_path_from_fms(value: str, *, flavour: str) -> Path:
    """FMS folder value -> local path, FOR EQUALITY ONLY.

    Strips exactly one recognised prefix (an unrecognised one is refused, never guessed), drops the
    trailing slash the FMS form requires, and collapses `.`/`..` with TARGET-PLATFORM semantics —
    `PurePath.relative_to` and friends do not collapse, and comparing uncollapsed paths is how a
    traversal gets called equal to the thing it escapes.

    Case folding is the caller's, via `paths_equal`: Windows compares case-insensitively with the
    drive letter normalised, POSIX compares case-sensitively.
    """
    if not isinstance(value, str) or not value:
        raise FmsPathRefused("an empty value is not an FMS folder path")
    for prefix in _PREFIXES:
        if value.lower().startswith(prefix):
            body = value[len(prefix):]
            break
    else:
        raise FmsPathRefused(
            f"{value!r} carries no recognised FileMaker path prefix "
            f"({', '.join(_PREFIXES)}) — refusing to guess one"
        )
    body = body.rstrip("/").rstrip("\\")
    if not body:
        raise FmsPathRefused(f"{value!r} names no folder after its prefix")
    if flavour == WINDOWS:
        collapsed = ntpath.normpath(body.replace("/", "\\"))
        return Path(PureWindowsPath(collapsed).as_posix().replace("/", "\\"))
    collapsed = posixpath.normpath("/" + body.lstrip("/"))
    return Path(PurePosixPath(collapsed))


def paths_equal(left: Path | str | None, right: Path | str | None, *, flavour: str) -> bool:
    """Compartment equality: platform-correct case rules, drive letter normalised on Windows."""
    if left is None or right is None:
        return False
    a, b = str(left), str(right)
    if flavour == WINDOWS:
        a = ntpath.normpath(a.replace("/", "\\")).rstrip("\\")
        b = ntpath.normpath(b.replace("/", "\\")).rstrip("\\")
        return a.lower() == b.lower()
    a = posixpath.normpath(a).rstrip("/") or "/"
    b = posixpath.normpath(b).rstrip("/") or "/"
    return a == b


class FmsFolderAdapter(Protocol):
    def current_folder_settings(self) -> dict: ...
    def additional_db_paths(self) -> tuple[str | None, str | None]: ...
    def patch_additional_db_folder(self, body: dict) -> dict: ...
    def list_databases(self) -> tuple[dict, ...]: ...
    def open_database(self, name: str) -> None: ...
    def close_database(self, name: str) -> None: ...
    def await_status(self, name: str, target: str) -> bool: ...


class PkiFolderAdapter:
    """Every call through `fms_admin_pki.admin_api_request`; every failure raised."""

    def __init__(self, *, host: str, key_name: str, private_pem: bytes, verify_ssl: bool = False):
        self._host = host
        self._key_name = key_name
        self._pem = private_pem
        self._verify = verify_ssl

    def _request(self, method: str, path: str, *, json_body: dict | None = None) -> dict:
        from corpusfm.server import fms_admin_pki as pki

        ok, status, body = pki.admin_api_request(
            self._host, self._key_name, self._pem, method, path,
            json_body=json_body, verify_ssl=self._verify,
        )
        if not ok:
            raise FmsFolderError(
                f"Admin API {method} {path} failed with status {status}"
            )
        return body if isinstance(body, dict) else {}

    @staticmethod
    def _response(body: dict) -> dict:
        inner = body.get("response")
        return inner if isinstance(inner, dict) else {}

    def current_folder_settings(self) -> dict:
        return self._response(self._request("GET", _FOLDER_SETTINGS))

    def additional_db_paths(self) -> tuple[str | None, str | None]:
        data = self._response(self._request("GET", _ADDITIONAL_PATHS))
        return (
            data.get("additionalDatabaseFolderPath") or None,
            data.get("additionalDatabaseFolderPath2") or None,
        )

    def patch_additional_db_folder(self, body: dict) -> dict:
        return self._response(self._request("PATCH", _PATCH_FOLDER, json_body=body))

    def list_databases(self) -> tuple[dict, ...]:
        data = self._response(self._request("GET", _DATABASES))
        rows = data.get("databases")
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise FmsFolderError("the Admin API database list is malformed")
        return tuple(rows)

    def _database_id(self, name: str) -> int:
        want = database_stem(name)
        for row in self.list_databases():
            if database_stem(str(row.get("filename") or "")) == want:
                return int(row["id"])
        raise FmsFolderError(f"FileMaker Server does not list a database named {name!r}")

    def open_database(self, name: str) -> None:
        self._request("PATCH", f"{_DATABASES}/{self._database_id(name)}",
                      json_body={"status": "OPENED"})

    def close_database(self, name: str) -> None:
        self._request("PATCH", f"{_DATABASES}/{self._database_id(name)}",
                      json_body={"status": "CLOSED"})

    def await_status(self, name: str, target: str) -> bool:
        from corpusfm.server import fms_admin_pki as pki

        return bool(pki.wait_until_status(
            self._host, self._key_name, self._pem, name, target, verify_ssl=self._verify,
        ))


def database_row_is_closed(row: dict) -> bool:
    """Whether an Admin API database-registry row proves the database is not serving.

    FileMaker keeps a successfully closed database in its database list.  Presence in that list is
    therefore not an open/hosted verdict; the row's protocol status is.  Keep this interpretation
    centralized so an uninstall never falls back to message text or treats an absent/unknown status
    as safe.
    """
    status = row.get("status")
    return isinstance(status, str) and status.strip().upper() == "CLOSED"


def build_adapter() -> FmsFolderAdapter | None:
    """The ONE construction path, from the CANONICAL identity — not the retired PKI file.

    It used to read ``fms_admin_pki.load_admin_pki_for_apply()``, which resolves
    ``src/fms_admin_pki.yaml``. That file was written by an inline installer block that minted a
    SECOND keypair after the admin-identity provider had already published one, so the compartment
    could authenticate with a key the manifest does not name. Both the file and that block are
    retired (ruling, 2026-08-08).

    Three things this now insists on, and each closes a way the old path could be wrong:

    * **The secrets directory comes from THE PUBLISHED RECORD**, never from a caller. There is
      exactly one location for this installation's identity, and a supplied path could only ever
      disagree with it. It is read here through ``published.read_published_installation()`` — the
      locator → manifest → identity-agreement chain — rather than ``app_paths.secrets_dir()``, whose
      answer is a per-process cache of "where is the layout" (packet 1000-07). The outcome is
      unchanged on every box: the fingerprint check below already required a published manifest, so
      an unpublished or unreadable installation produced no adapter before and produces none now.
    * **The store and the MANIFEST must agree** on registration name *and* public fingerprint. A
      store holding an identity the manifest does not name is not this installation's authority —
      it is a leftover, a restored backup, or a second key — and using it would authenticate as
      something the published record does not claim to be.
    * **Returns None, never raises.** Missing or disagreeing authority is a reportable preflight
      result; every caller gets a ``CompartmentReport`` rather than a traceback and an invented
      state.

    **All three now live in ONE place** (developer ruling D4, 2026-08-12; packet 1247).
    ``admin_identity_runtime.resolve_published_identity`` performs the published-record read, the
    store load and the manifest agreement, and the running application resolves through the same
    function — so the patch compartment and Jobs/Health can no longer form different opinions about
    which key is this installation's. What used to be inline here (the published read for
    ``secrets_dir``, ``admin_identity_store.load``, and a local ``_published_pki`` that reached
    ``app_paths._adapter_for`` / ``_read_manifest``) is that function's body now, with
    the manifest's ``pki`` block projected onto the read façade instead of read through private
    ``app_paths`` helpers. The rule is unchanged: same secrets location, same two-field agreement,
    same ``None``.
    """
    from .admin_identity_runtime import resolve_published_identity

    resolution = resolve_published_identity()
    if not resolution.available:
        return None
    identity = resolution.identity
    return PkiFolderAdapter(host=identity.host, key_name=identity.registration_name,
                            private_pem=identity.private_pem)


def capture_folder_state(adapter: FmsFolderAdapter) -> tuple[tuple[str | None, str | None], dict]:
    """ONE fetch of each resource, returned for every parser to share.

    `fms_admin_pki` warns twice that the FMS session pool is small (error 956) and each
    `admin_api_request` opens and releases its own session, so "one capture" must mean one call per
    resource — not one call per question asked of it.
    """
    return adapter.additional_db_paths(), adapter.current_folder_settings()


def _setting_enabled(value: object, *, fms_path: str | None, field: str) -> bool:
    """Interpret the two FMS enablement shapes without turning malformed evidence into authority.

    Current FMS returns arrays containing ``enabled`` or ``disabled``. Older documented responses
    used a nonempty array carrying the configured path. Nothing else is guessed: booleans, mappings,
    conflicting words, foreign strings and an enabled setting with no path are contradictory server
    evidence and must stop before slot selection or rollback planning.
    """
    if value is None:
        return False
    if not isinstance(value, (list, tuple)):
        raise FmsFolderError(f"{field} is not an array or null")
    if not value:
        return False
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise FmsFolderError(f"{field} contains a non-text or empty value")

    tokens = tuple(item.strip() for item in value)
    lowered = {item.lower() for item in tokens}
    statuses = lowered & {"enabled", "disabled"}
    if len(statuses) > 1:
        raise FmsFolderError(f"{field} reports both enabled and disabled")
    foreign = tuple(item for item in tokens if item.lower() not in {"enabled", "disabled"})
    if foreign:
        if len(foreign) != 1 or fms_path is None or foreign[0] != fms_path:
            raise FmsFolderError(f"{field} carries an unrecognised enablement value")
    enabled = "enabled" in statuses or bool(foreign)
    if enabled and not fms_path:
        raise FmsFolderError(f"{field} reports enabled but the slot carries no path")
    return enabled


def parse_slots(paths: tuple[str | None, str | None], settings: dict, *,
                flavour: str) -> tuple[SlotRecord, ...]:
    """BOTH slots, always — a before-image that holds one slot cannot restore the other.

    Two endpoints, because the API splits the answer: `additionaldbpath` returns the paths and
    `currentfoldersettings` reports enablement.  Claris documents a null value before enablement,
    but FMS 2026 also returns ``["disabled"]`` for a configured, inactive slot.  Presence alone
    therefore is not enablement.  Recognised status words are authoritative; older nonempty array
    forms without a status word retain the documented presence semantics.
    """
    records = []
    for position, (index, _path_field, enabled_field) in enumerate(SLOT_READ_FIELDS):
        fms_path = paths[position] or None
        local = None
        if fms_path:
            try:
                local = local_path_from_fms(fms_path, flavour=flavour)
            except FmsPathRefused:
                local = None          # a path FMS holds that we cannot parse is still recorded
        enabled = _setting_enabled(
            settings.get(enabled_field), fms_path=fms_path, field=enabled_field)
        records.append(SlotRecord(
            index=index,
            fms_path=fms_path,
            local_path=local,
            enabled=enabled,
        ))
    return tuple(records)


def read_slots(adapter: FmsFolderAdapter, *, flavour: str) -> tuple[SlotRecord, ...]:
    """Convenience for a caller that wants only the slots. Captures once."""
    paths, settings = capture_folder_state(adapter)
    return parse_slots(paths, settings, flavour=flavour)


def read_rc_fields(settings: dict) -> dict:
    """Verbatim, for comparison only. Never written back — packet §8. Parses an already-captured
    response rather than fetching one."""
    return {field: settings.get(field) for field in READ_RC_FIELDS}


def slot_restore_body(index: str, original: SlotRecord) -> dict:
    """Put a slot back to exactly what was captured.

    A slot captured as FREE is restored by DISABLING it and nothing else. The first draft sent
    `DatabaseRootPath: ""` alongside, which is a write the API documents no clearing semantics for —
    restoring a slot that held nothing must not be the packet's first untested write against a live
    server.
    """
    for candidate, enable_field, path_field in SLOT_FIELDS:
        if candidate != index:
            continue
        if not original.fms_path:
            return {enable_field: False}
        return {enable_field: bool(original.enabled), path_field: original.fms_path}
    raise FmsFolderError(f"{index!r} is not a slot; FileMaker Server has exactly 1 and 2")


def slot_patch_body(index: str, *, fms_path: str, enable: bool = True) -> dict:
    """The PATCH body for one slot, with NO remote-container field.

    The API's own rule: to enable, the path must be in the SAME request; to change the path, the
    enable flag must already be on. Sending both together satisfies it in either direction.
    """
    for candidate, enable_field, path_field in SLOT_FIELDS:
        if candidate == index:
            return {enable_field: bool(enable), path_field: fms_path}
    raise FmsFolderError(f"{index!r} is not a slot; FileMaker Server has exactly 1 and 2")
