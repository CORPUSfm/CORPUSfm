"""Remove the fixed lifecycle containers after a completed uninstall.

This is deliberately not an uninstall operation and accepts no target path.  The ordinary
operations need the journal, pending record and lock that live inside these containers; only the
CLI, after the driver has finalized and released that lock, may call this tail with the paired
machine layout.  A failure is reported rather than turning a completed product removal into a
claim that the machine is clean.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import LifecycleError, RecordInvalid
from .layout import POSIX, WINDOWS
from .locator import locator_for
from .os_layout import OsLayout
from .uninstall_exec_posix import (
    PathRemovalRefused,
    _Purge,
    _is_link,
    _lstat_or_none,
)
from .uninstall_pending import read as read_pending


class TerminalCleanupRefused(LifecycleError):
    """The fixed product containers could not safely be retired."""


def _roots(os_layout: OsLayout) -> tuple[Path, ...]:
    if os_layout.flavour == WINDOWS:
        parents = {path.parent for path in os_layout.all_dirs()}
        if len(parents) != 1:
            raise RecordInvalid("the Windows mutable directories do not share one product root")
        return (parents.pop(),)
    if os_layout.flavour == POSIX:
        # state and secrets are siblings under the one exclusive /var/lib/corpusfm container.
        if os_layout.state_dir.parent != os_layout.secrets_dir.parent:
            raise RecordInvalid(
                "the POSIX state and secrets directories do not share a product root")
        return (os_layout.config_dir, os_layout.state_dir.parent,
                os_layout.log_dir, os_layout.run_dir)
    raise RecordInvalid(f"unknown platform flavour {os_layout.flavour!r}")


def _posix_root_refusal(path: Path, st) -> str:
    if st.st_uid != 0:
        return f"{path} is not root-owned"
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return f"{path} is group- or world-writable"
    return ""


def _claim_posix_run_root(path: Path, st, *, service_uid: int | None):
    """Revoke the service's intentional runtime-directory authority before terminal removal."""
    if service_uid is None or st.st_uid != service_uid:
        raise TerminalCleanupRefused(f"{path} is not root-owned")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise TerminalCleanupRefused(f"{path} is group- or world-writable")
    identity = (st.st_dev, st.st_ino)
    try:
        os.chown(path, 0, 0)
    except OSError as exc:
        raise TerminalCleanupRefused(f"{path} could not be reclaimed by root: {exc}") from exc
    claimed = _lstat_or_none(path)
    if (claimed is None or _is_link(claimed) or not stat.S_ISDIR(claimed.st_mode)
            or (claimed.st_dev, claimed.st_ino) != identity or claimed.st_uid != 0):
        raise TerminalCleanupRefused(f"{path} changed while root authority was being established")
    return claimed


def _windows_root_refusal(path: Path, *, authority_api=None) -> str:
    from .protection import DIRECTORY_AUTHORITY, real_windows_file_authority

    api = authority_api or real_windows_file_authority()
    try:
        authority = api.authority_of_path(str(path))
        allowed = set(api.invoking_owner_sids()) | {api.system_sid_text()}
    except Exception as exc:  # pragma: no cover - exercised through a platform double
        return f"{path} authority could not be read ({type(exc).__name__})"
    if not authority.protected or authority.inherited:
        return f"{path} is not a protected authority root"
    if authority.owner not in allowed:
        return f"{path} is owned outside the invoking administrator/SYSTEM authority"
    masks: dict[str, int] = {}
    for trustee, mask in authority.grants:
        masks[trustee] = masks.get(trustee, 0) | mask
    for trustee in authority.trustees:
        if trustee in allowed:
            continue
        if trustee not in masks or masks[trustee] & DIRECTORY_AUTHORITY:
            return f"{path} grants write or unknown authority to {trustee}"
    return ""


def retire(layout, os_layout: OsLayout, *, windows_authority=None, posix_service_uid=None,
           locator_adapter=None) -> tuple[str, ...]:
    """Remove only the platform-fixed CORPUSfm containers and read back their absence.

    The driver has already removed the locator and pending record before returning ``finalized``.
    The CLI calls here only after leaving the lifecycle-lock context.  Those three facts are checked
    again because deleting a live control plane is never an admissible cleanup shortcut.
    """
    if os_layout.flavour != layout.kind:
        raise TerminalCleanupRefused("the OS and lifecycle layouts name different platforms")
    adapter = locator_adapter if locator_adapter is not None else locator_for(layout)
    if adapter.exists():
        raise TerminalCleanupRefused("the installation locator still exists")
    if read_pending(layout) is not None:
        raise TerminalCleanupRefused("the uninstall pending record still exists")
    if Path(layout.journal_file).exists():
        raise TerminalCleanupRefused("the lifecycle journal still exists")

    removed = []
    for root in _roots(os_layout):
        st = _lstat_or_none(root)
        if st is None:
            continue
        if _is_link(st):
            raise TerminalCleanupRefused(f"{root} is a link or reparse point")
        if not stat.S_ISDIR(st.st_mode):
            raise TerminalCleanupRefused(f"{root} is not a directory")
        if (os_layout.flavour == POSIX and root == os_layout.run_dir and st.st_uid != 0):
            st = _claim_posix_run_root(root, st, service_uid=posix_service_uid)
        refusal = (_windows_root_refusal(root, authority_api=windows_authority)
                   if os_layout.flavour == WINDOWS else _posix_root_refusal(root, st))
        if refusal:
            raise TerminalCleanupRefused(refusal)
        try:
            _Purge(root, keep=(), flavour=os_layout.flavour).run(remove_root=True)
        except (OSError, PathRemovalRefused) as exc:
            raise TerminalCleanupRefused(f"{root} could not be retired: {exc}") from exc
        if _lstat_or_none(root) is not None:
            raise TerminalCleanupRefused(f"{root} is still present after terminal cleanup")
        removed.append(str(root))
    return tuple(removed)


__all__ = ["TerminalCleanupRefused", "retire"]
