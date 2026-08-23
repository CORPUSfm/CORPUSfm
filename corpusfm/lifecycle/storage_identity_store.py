"""The ONE canonical automation access record (packet 1246-08 §4.2, §9.1).

One file, beneath the VALIDATED fixed secrets directory, protected with the Machine Key. Three
properties, each with a reason:

1. **Machine Key, not Corpus Key.** This secret is box-local and this component rotates it. The
   Corpus Key is irreplaceable (``crypto.py`` ``get_corpus_key``); making it a precondition for
   repairing FileMaker access would invert the recovery order — you would need the key you are
   trying to protect in order to reach the data it protects.
2. **The path is DERIVED, never supplied.** A module constant beneath the validated fixed
   ``secrets_dir``. No caller-selected record path exists, so there is nothing to point elsewhere.
3. **Service-readable, service-UNWRITABLE.** No installed secret is runtime-writable — the single
   former exception (``.mcp_env``) went with the server-wide MCP token (packet 1258). Rotation is a
   privileged lifecycle operation, always.

The secrets-directory validation and the pinned descriptor come from ``admin_identity_store``
(packet 1246-07) rather than being written a second time. That module is not modified: only
``validated_secrets_dir`` and ``pinned_secrets_dir`` are imported, both of which are path-level and
carry no identity semantics. A second implementation of "is this really the fixed directory" is
exactly the drift 1246-05 warned about when it found two HTTP clients for one endpoint.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import LifecycleError
from .admin_identity_store import (  # the ONE implementation of both, unmodified
    PinnedSecretsDir,
    SecretsDirRefused,
    pinned_secrets_dir,
    validated_secrets_dir,
)
from .storage_identity import AUTOMATION_ACCOUNT, LocalMaterial

#: The canonical record. `access` rather than `credential`: 1246-01's secret fence denies the token
#: `credential` in any structured payload, and a filename that cannot be named in a result is a
#: filename that gets renamed later under pressure.
STORE_FILENAME = "storage_access.json"
STAGED_FILENAME = "storage_access.staged"
BACKUP_SUFFIX = ".prior"

STORE_FILE_MODE = 0o600
RECORD_VERSION = 1


class StorageStoreError(LifecycleError):
    """The record is missing, substituted, wrongly protected, or did not land intact."""


@dataclass(frozen=True)
class StorageAccess:
    """What the record holds.

    NOT held: host, database name, or any path. Those are manifest facts; duplicating them here
    would create a second authority that can disagree with the first.
    """

    account: str
    secret: str
    corpus_id: str | None
    proven_utc: str
    version: int = RECORD_VERSION

    def redacted(self) -> dict[str, Any]:
        """Everything except the secret. For diagnostics that must never carry the value."""
        return {
            "account": self.account,
            "corpus_id": self.corpus_id,
            "proven_utc": self.proven_utc,
            "version": self.version,
        }


def store_path(secrets_dir: Path | str, *, layout=None) -> Path:
    return validated_secrets_dir(secrets_dir, layout=layout) / STORE_FILENAME


def staged_path(secrets_dir: Path | str, *, layout=None) -> Path:
    return validated_secrets_dir(secrets_dir, layout=layout) / STAGED_FILENAME


def backup_path(secrets_dir: Path | str, operation_id: str, *, layout=None) -> Path:
    """Operation-bound, so two operations cannot overwrite each other's way back."""
    _assert_operation_id(operation_id)
    return validated_secrets_dir(secrets_dir, layout=layout) / f"{operation_id}{BACKUP_SUFFIX}"


def _assert_operation_id(operation_id: str) -> None:
    # The id becomes a FILENAME. A traversal or separator in it would select a file outside the
    # pinned directory, which is the class of defect the pinned descriptor exists to prevent —
    # so it is refused here rather than relied on to be well formed.
    if not operation_id or not all(c.isalnum() or c in "-_" for c in operation_id):
        raise StorageStoreError(
            f"refusing operation id {operation_id!r}: it names a file in the secrets directory and "
            "must be alphanumeric with - and _ only"
        )


def _encode(access: StorageAccess) -> bytes:
    from corpusfm.core.crypto import encrypt_machine

    payload = json.dumps(
        {
            "version": access.version,
            "account": access.account,
            "corpus_id": access.corpus_id,
            "proven_utc": access.proven_utc,
            "secret": access.secret,
        },
        sort_keys=True,
    )
    # `encrypt_machine` takes and returns BYTES (`crypto.py:315-322`).
    return encrypt_machine(payload.encode("utf-8"))


def _decode(raw: bytes) -> StorageAccess:
    from corpusfm.core.crypto import decrypt_machine

    text = decrypt_machine(raw).decode("utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise StorageStoreError("the access record did not decode to an object")
    version = data.get("version")
    if version != RECORD_VERSION:
        raise StorageStoreError(f"access record version {version!r}; this build reads {RECORD_VERSION}")
    account = data.get("account")
    secret = data.get("secret")
    proven = data.get("proven_utc")
    corpus_id = data.get("corpus_id")
    # Strict. `bool("false")` is True and `str(None)` is "None"; a record parsed loosely turns a
    # missing field into a plausible value, which is how an ABSENT thing becomes a PRESENT one.
    if not isinstance(account, str) or not account:
        raise StorageStoreError("access record: account must be a non-empty string")
    if not isinstance(secret, str) or not secret:
        raise StorageStoreError("access record: secret must be a non-empty string")
    if not isinstance(proven_utc_ok := proven, str):
        raise StorageStoreError("access record: proven_utc must be a string")
    if corpus_id is not None and not isinstance(corpus_id, str):
        raise StorageStoreError("access record: corpus_id must be a string or null")
    return StorageAccess(
        account=account, secret=secret, corpus_id=corpus_id,
        proven_utc=proven_utc_ok, version=version,
    )


def _refuse_if_link_or_shared(pinned: PinnedSecretsDir, filename: str) -> None:
    """A symlink aims the write elsewhere; a hard link makes it land in two places.

    Both are checked on the object actually opened, never on the path — a path-based check is the
    TOCTOU this exists to close.
    """
    name = filename if pinned.fd is not None else str(pinned.path / filename)
    kwargs = {"dir_fd": pinned.fd} if pinned.fd is not None else {}
    try:
        st = os.lstat(name, **kwargs)
    except (FileNotFoundError, NotADirectoryError):
        return
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode):
        raise StorageStoreError(
            f"refusing {filename}: a symlink is present where the access record must be"
        )
    if st.st_nlink > 1:
        raise StorageStoreError(
            f"refusing {filename}: the access record has {st.st_nlink} links, so a write would "
            "land in more than one place"
        )


def exists(secrets_dir: Path | str, *, layout=None) -> bool:
    """Whether a record FILE is there. Says nothing about whether it can be decrypted."""
    try:
        with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
            return pinned.exists(STORE_FILENAME)
    except (FileNotFoundError, SecretsDirRefused):
        return False


def staged_exists(secrets_dir: Path | str, *, layout=None) -> bool:
    try:
        with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
            return pinned.exists(STAGED_FILENAME)
    except (FileNotFoundError, SecretsDirRefused):
        return False


def classify_local(secrets_dir: Path | str, *, machine_key_ready: bool, layout=None) -> str:
    """The ``LocalMaterial`` axis.

    ``UNCLASSIFIED`` when the Machine Key authority is not yet established: before it, "no record
    is stored" and "the record cannot be decrypted yet" are indistinguishable, and reporting either
    would be a guess. Nothing is read or written in that case.
    """
    if not machine_key_ready:
        return LocalMaterial.UNCLASSIFIED.value
    if not exists(secrets_dir, layout=layout):
        return LocalMaterial.ABSENT.value
    try:
        load(secrets_dir, layout=layout)
    except Exception:  # noqa: BLE001 — every failure to read it back is the same axis value
        return LocalMaterial.UNUSABLE.value
    return LocalMaterial.USABLE.value


def load(secrets_dir: Path | str, *, layout=None) -> StorageAccess | None:
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(STORE_FILENAME):
            return None
        _refuse_if_link_or_shared(pinned, STORE_FILENAME)
        return _decode(pinned.read_bytes(STORE_FILENAME))


def load_staged(secrets_dir: Path | str, *, layout=None) -> StorageAccess | None:
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(STAGED_FILENAME):
            return None
        _refuse_if_link_or_shared(pinned, STAGED_FILENAME)
        return _decode(pinned.read_bytes(STAGED_FILENAME))


def load_backup(secrets_dir: Path | str, operation_id: str, *, layout=None) -> StorageAccess | None:
    _assert_operation_id(operation_id)
    name = f"{operation_id}{BACKUP_SUFFIX}"
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(name):
            return None
        _refuse_if_link_or_shared(pinned, name)
        return _decode(pinned.read_bytes(name))


def stage(secrets_dir: Path | str, access: StorageAccess, *, layout=None) -> Path:
    """Write the candidate BESIDE the promoted record. The promoted one is untouched.

    Staging happens before FileMaker is touched, so a crash in the FileMaker call leaves a box whose
    promoted secret still works and whose candidate is recoverable.
    """
    with pinned_secrets_dir(secrets_dir, layout=layout, create=True) as pinned:
        _refuse_if_link_or_shared(pinned, STAGED_FILENAME)
        pinned.write_private(STAGED_FILENAME, _encode(access))
        _establish_privacy(pinned, STAGED_FILENAME)
        _verify_readback(pinned, STAGED_FILENAME, access)
        return pinned.path / STAGED_FILENAME


def back_up_promoted(secrets_dir: Path | str, operation_id: str, *, layout=None) -> Path | None:
    """Copy the promoted record to an operation-bound backup, so an abort has a way back.

    Returns None when there is nothing promoted — a fresh install, where the way back is removing
    the file this operation placed.
    """
    _assert_operation_id(operation_id)
    name = f"{operation_id}{BACKUP_SUFFIX}"
    with pinned_secrets_dir(secrets_dir, layout=layout, create=True) as pinned:
        if not pinned.exists(STORE_FILENAME):
            return None
        _refuse_if_link_or_shared(pinned, STORE_FILENAME)
        _refuse_if_link_or_shared(pinned, name)
        pinned.write_private(name, pinned.read_bytes(STORE_FILENAME))
        # The operation-bound backup holds the same secret as the record it copies, so it carries
        # the same protection — and is verified, not assumed.
        _establish_privacy(pinned, name)
        _assert_privacy(pinned, name)
        return pinned.path / name


def promote(secrets_dir: Path | str, *, layout=None) -> StorageAccess:
    """Make the staged candidate the promoted record, then READ IT BACK before saying so.

    An in-place or renamed write that half-landed reports success at the syscall and lies; the
    read-back is what turns "the call returned" into "the record is there".
    """
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(STAGED_FILENAME):
            raise StorageStoreError("nothing is staged; there is no candidate to promote")
        _refuse_if_link_or_shared(pinned, STAGED_FILENAME)
        _refuse_if_link_or_shared(pinned, STORE_FILENAME)
        staged = _decode(pinned.read_bytes(STAGED_FILENAME))
        pinned.replace(STAGED_FILENAME, STORE_FILENAME)
        # PROMOTION PRESERVES AND REVERIFIES IT. A rename carries the source's DACL, but "carried"
        # is an expectation and this establishes the fact.
        _establish_privacy(pinned, STORE_FILENAME)
        _verify_readback(pinned, STORE_FILENAME, staged)
        return staged


def save(secrets_dir: Path | str, access: StorageAccess, *, layout=None) -> Path:
    """Stage then promote, as one call, for the case with no prior record to preserve."""
    stage(secrets_dir, access, layout=layout)
    promote(secrets_dir, layout=layout)
    return store_path(secrets_dir, layout=layout)


def restore_from_backup(secrets_dir: Path | str, operation_id: str, *, layout=None) -> bool:
    """Put the operation's prior record back. Returns False when there is no backup."""
    _assert_operation_id(operation_id)
    name = f"{operation_id}{BACKUP_SUFFIX}"
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(name):
            return False
        _refuse_if_link_or_shared(pinned, name)
        prior = _decode(pinned.read_bytes(name))
        pinned.write_private(STORE_FILENAME, pinned.read_bytes(name))
        _establish_privacy(pinned, STORE_FILENAME)
        _verify_readback(pinned, STORE_FILENAME, prior)
        return True


def discard_staged(secrets_dir: Path | str, *, layout=None) -> bool:
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(STAGED_FILENAME):
            return False
        pinned.unlink(STAGED_FILENAME)
        return True


def discard_backup(secrets_dir: Path | str, operation_id: str, *, layout=None) -> bool:
    _assert_operation_id(operation_id)
    name = f"{operation_id}{BACKUP_SUFFIX}"
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(name):
            return False
        pinned.unlink(name)
        return True


def remove_local(secrets_dir: Path | str, *, layout=None) -> bool:
    """Uninstall's removal of the promoted record. Never called by any other verb."""
    with pinned_secrets_dir(secrets_dir, layout=layout) as pinned:
        if not pinned.exists(STORE_FILENAME):
            return False
        pinned.unlink(STORE_FILENAME)
        return True


def _establish_privacy(pinned: PinnedSecretsDir, filename: str) -> None:
    """Make this artifact private in the terms the PLATFORM actually enforces.

    POSIX needs nothing here: `write_private` creates at 0600 and `_assert_privacy` checks it.

    WINDOWS DOES. `os.chmod` there only toggles the read-only attribute, so a writable file always
    stats as 0666 and the mode assertion below could never pass — measured on winfms2026,
    2026-08-09, where a completed adoption rotated the credential, wrote its candidate, and then
    refused its own read-back with "storage_access.staged landed with mode 0666, not 0600". A mode
    is not access authority on NTFS; the DACL is. So the artifact is protected through the
    protection module that already owns this vocabulary — SYSTEM and Administrators, full control,
    inheritance disabled — rather than through a second ACL implementation here.

    NO SERVICE ACCESS IS GRANTED HERE. The final layout-protection phase remains the sole authority
    that later gives the registered services read-only access to the promoted record.
    """
    if os.name != "nt":                            # pragma: no cover - POSIX writes 0600 directly
        return
    from .protection import ADMINISTRATORS_SID_TEXT, FILE_ALL_ACCESS, real_windows_acl_api

    api = real_windows_acl_api()
    target = pinned.path / filename
    try:
        api.set_protected_dacl(target, api.system_sid(),
                               ((api.administrators_sid(), FILE_ALL_ACCESS),))
    except Exception as exc:                       # noqa: BLE001
        raise StorageStoreError(
            f"{filename} could not be made private ({type(exc).__name__}); nothing may be reported "
            "as stored") from exc
    assert ADMINISTRATORS_SID_TEXT                  # the policy is the module's, not this file's


def _assert_privacy(pinned: PinnedSecretsDir, filename: str) -> None:
    """Read the privacy back — the platform's own answer, never the call that intended it."""
    if os.name != "nt":
        mode = os.stat(
            filename if pinned.fd is not None else str(pinned.path / filename),
            follow_symlinks=False,
            **({"dir_fd": pinned.fd} if pinned.fd is not None else {}),
        ).st_mode & 0o777
        if mode != STORE_FILE_MODE:
            raise StorageStoreError(
                f"{filename} landed with mode {mode:04o}, not {STORE_FILE_MODE:04o}"
            )
        return

    from .protection import (                       # pragma: no cover - platform-specific
        ADMINISTRATORS_SID_TEXT, FILE_ALL_ACCESS, SYSTEM_SID_TEXT, real_windows_acl_api,
    )

    api = real_windows_acl_api()
    target = pinned.path / filename
    try:
        protected = api.dacl_is_protected(target)
        entries = tuple(api.dacl_entries(target))
    except Exception as exc:                       # noqa: BLE001
        raise StorageStoreError(
            f"the access control on {filename} could not be read ({type(exc).__name__}); an "
            "unreadable DACL is not evidence of privacy") from exc
    if not protected:
        raise StorageStoreError(f"{filename} inherits access from its parent directory")
    allowed = {SYSTEM_SID_TEXT, ADMINISTRATORS_SID_TEXT}
    named = {str(sid) for sid, _mask in entries}
    foreign = named - allowed
    if foreign:
        raise StorageStoreError(
            f"{filename} grants access to {', '.join(sorted(foreign))}; a stored credential is "
            "SYSTEM and Administrators only")
    missing = allowed - named
    if missing:
        raise StorageStoreError(
            f"{filename} does not name {', '.join(sorted(missing))}; an administrator must be able "
            "to repair what the installer protected")
    for sid, mask in entries:
        if int(mask) & FILE_ALL_ACCESS != FILE_ALL_ACCESS:
            raise StorageStoreError(
                f"{filename} grants {sid} 0x{int(mask):08x}, not full control")


def _verify_readback(pinned: PinnedSecretsDir, filename: str, expected: StorageAccess) -> None:
    read = _decode(pinned.read_bytes(filename))
    if read.secret != expected.secret or read.account != expected.account:
        raise StorageStoreError(
            f"{filename} did not read back as it was written; nothing may be reported as stored"
        )
    _assert_privacy(pinned, filename)


__all__ = [
    "BACKUP_SUFFIX",
    "RECORD_VERSION",
    "STAGED_FILENAME",
    "STORE_FILENAME",
    "STORE_FILE_MODE",
    "StorageAccess",
    "StorageStoreError",
    "back_up_promoted",
    "backup_path",
    "classify_local",
    "discard_backup",
    "discard_staged",
    "exists",
    "load",
    "load_backup",
    "load_staged",
    "promote",
    "remove_local",
    "restore_from_backup",
    "save",
    "stage",
    "staged_exists",
    "staged_path",
    "store_path",
]
