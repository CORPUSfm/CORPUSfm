"""Who owns a Recovery File, and what stops anyone else reading it (packet 1246-02).

**Developer ruling, 2026-08-02:** *a Recovery File belongs to the administrator who invoked
`corpusfm-recovery create`, not to the elevated process identity.*

The reasoning is the artifact's whole purpose. A Recovery File exists to be **carried away** — to a
USB stick, a backup share, a safe. An elevated command that leaves a root-owned file behind has
produced something the person who asked for it cannot read, copy or move without a second privileged
step, and the failure only shows up on the day it is needed. So the process identity that happened to
be required in order to *create* it is not the identity that should *own* it.

**Why this is 1246-02's and not 1246-03's.** Installed key-directory ACLs are 1246-03's — those live
at a location the installer chooses and controls. A Recovery File's destination is **external and
arbitrary**: the administrator names it, CORPUSfm has never seen it, and it may be a shared folder,
removable media, or a directory with permissive inherited ACLs. Protection of the artifact itself
therefore travels with the artifact, and belongs to the packet that creates it.

**POSIX mode is not evidence of Windows protection.** `0600` means nothing on NTFS; `os.chmod` there
is close to a no-op and inherited ACEs decide who can read the file. Reporting "0600" on Windows
would be reporting a number that does not govern anything. So protection is described per-platform,
and what is reported is what was actually verified.

**Four rules the implementation follows:**

1. **Establish before publishing.** Ownership and protection are applied to the staged temporary, and
   the replace happens afterwards. A file published first and secured second is readable by whoever
   arrives in between.
2. **Validate the claimed identity.** `SUDO_UID` is an environment variable — it is *evidence*, not
   authority. It is checked against the real account database, and cross-checked against `SUDO_USER`
   when that is present, before anything is handed to it.
3. **Never touch the parent.** The administrator's directory is theirs. Nothing here chmods,
   chowns or re-ACLs it.
4. **Restore protection, not just bytes.** A failed replacement puts back the previous file's owner
   and access protection as well as its contents. Bytes with the wrong owner are not the file that
   was there.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol

from .errors import LifecycleError

POSIX = "posix"
WINDOWS = "windows"


class OwnershipUnavailable(LifecycleError):
    """The invoking identity could not be established, so nothing was assumed."""


class ProtectionNotEstablished(LifecycleError):
    """Ownership or access protection could not be applied to the staged artifact."""


@dataclass(frozen=True)
class Identity:
    """Who the artifact should belong to, and how that was decided."""

    flavour: str                    # posix | windows
    label: str = ""                 # human-readable owner name
    uid: Optional[int] = None
    gid: Optional[int] = None
    sid: Optional[str] = None
    source: str = ""                # invoking_user | sudo_user | elevated_process
    warning: Optional[str] = None   # stated plainly when the answer is not the ideal one

    def describe(self) -> str:
        return self.label or (str(self.uid) if self.uid is not None else (self.sid or "unknown"))


@dataclass(frozen=True)
class Protection:
    """What actually governs access to the file, expressed in the platform's own terms."""

    flavour: str
    owner: str
    detail: str
    raw: Any = None                 # what `restore` needs; never rendered

    def describe(self) -> str:
        return f"owner {self.owner}, {self.detail}"


class OwnershipBackend(Protocol):
    """The platform-specific half, injectable so the Windows path is testable off Windows."""

    flavour: str

    def invoking_identity(self) -> Identity: ...
    def apply(self, path: Path, identity: Identity) -> None: ...
    def describe(self, path: Path) -> Protection: ...
    def capture(self, path: Path) -> Protection: ...
    def restore(self, path: Path, protection: Protection) -> None: ...


# ── POSIX ────────────────────────────────────────────────────────────────────────────

class PosixOwnership:
    """`sudo` tells us who called, and we check that it is telling the truth."""

    flavour = POSIX

    def __init__(self, environ=None):
        self._environ = os.environ if environ is None else environ

    def invoking_identity(self) -> Identity:
        import pwd

        euid = os.geteuid()
        if euid != 0:
            # Not elevated: the file is already going to belong to this account.
            return Identity(flavour=POSIX, label=_posix_name(euid), uid=euid, gid=os.getegid(),
                            source="invoking_user")

        raw_uid = (self._environ.get("SUDO_UID") or "").strip()
        raw_gid = (self._environ.get("SUDO_GID") or "").strip()
        if not raw_uid:
            # Direct root invocation. Root keeps it, and we SAY so — an administrator who logged in
            # as root gets a root-owned artifact and needs to know that before they go looking for
            # it from another account.
            return Identity(
                flavour=POSIX, label="root", uid=0, gid=0, source="elevated_process",
                warning=(
                    "this command was run directly as root rather than through sudo, so the "
                    "Recovery File belongs to root. Another account will not be able to read it "
                    "without elevation — copy it to its final home now, or re-run under sudo."
                ),
            )

        try:
            uid = int(raw_uid)
            gid = int(raw_gid) if raw_gid else pwd.getpwuid(uid).pw_gid
        except (TypeError, ValueError) as exc:
            raise OwnershipUnavailable(
                f"SUDO_UID/SUDO_GID are not numeric ({raw_uid!r}/{raw_gid!r}); refusing to guess "
                "who this Recovery File belongs to"
            ) from exc
        except KeyError as exc:
            raise OwnershipUnavailable(
                f"SUDO_UID {raw_uid} is not a real account on this machine; refusing to assign the "
                "Recovery File to it"
            ) from exc

        # An environment variable is EVIDENCE, not authority. Check it against the real account
        # database before handing an artifact to it.
        try:
            entry = pwd.getpwuid(uid)
        except KeyError as exc:
            raise OwnershipUnavailable(
                f"SUDO_UID {uid} is not a real account on this machine; refusing to assign the "
                "Recovery File to it"
            ) from exc
        if uid == 0:
            return Identity(
                flavour=POSIX, label="root", uid=0, gid=0, source="elevated_process",
                warning=(
                    "sudo reports root as the invoking account, so the Recovery File belongs to "
                    "root and another account cannot read it without elevation."
                ),
            )
        claimed = (self._environ.get("SUDO_USER") or "").strip()
        if claimed and claimed != entry.pw_name:
            raise OwnershipUnavailable(
                f"SUDO_USER says {claimed!r} but SUDO_UID {uid} is {entry.pw_name!r}; these "
                "disagree, so the invoking account is not established"
            )
        self._assert_group_is_claimable(entry, gid)
        return Identity(flavour=POSIX, label=entry.pw_name, uid=uid, gid=gid, source="sudo_user")

    @staticmethod
    def _assert_group_is_claimable(entry, gid: int) -> None:
        """`SUDO_GID` gets the same treatment as `SUDO_UID`, and for the same reason.

        Parsing it as an integer only proves it is a number. An unvalidated gid can name a group
        that does not exist — leaving a file with an orphan numeric group — or one the invoking
        account is not in, which would hand read access to a group of people who never asked for it
        and were never checked. Both are silent; neither is acceptable on an artifact whose entire
        job is to be the only copy of a key.
        """
        import grp

        try:
            group = grp.getgrgid(gid)
        except KeyError as exc:
            raise OwnershipUnavailable(
                f"SUDO_GID {gid} is not a real group on this machine; refusing to assign the "
                "Recovery File to it"
            ) from exc
        if gid == entry.pw_gid:
            return                       # the account's own primary group
        if entry.pw_name in group.gr_mem:
            return                       # a supplementary group the account genuinely belongs to
        raise OwnershipUnavailable(
            f"SUDO_GID {gid} is group {group.gr_name!r}, which {entry.pw_name!r} does not belong "
            "to; refusing to give the Recovery File to a group the invoking account is not in"
        )

    def apply(self, path: Path, identity: Identity) -> None:
        if identity.uid is None:
            raise ProtectionNotEstablished("no POSIX identity to assign")
        try:
            os.chown(str(path), identity.uid, identity.gid if identity.gid is not None else -1)
        except PermissionError as exc:
            # Unelevated and already ours is fine; anything else is not.
            if os.stat(str(path)).st_uid == identity.uid:
                pass
            else:
                raise ProtectionNotEstablished(
                    f"could not give the Recovery File to {identity.describe()}: {exc}"
                ) from exc
        except OSError as exc:
            raise ProtectionNotEstablished(
                f"could not give the Recovery File to {identity.describe()}: {exc}"
            ) from exc
        try:
            os.chmod(str(path), 0o600)
        except OSError as exc:
            raise ProtectionNotEstablished(f"could not restrict the Recovery File: {exc}") from exc

    def describe(self, path: Path) -> Protection:
        stat = os.stat(str(path))
        return Protection(flavour=POSIX, owner=_posix_name(stat.st_uid),
                          detail=f"mode {stat.st_mode & 0o777:04o}",
                          raw=(stat.st_uid, stat.st_gid, stat.st_mode & 0o777))

    def capture(self, path: Path) -> Protection:
        return self.describe(path)

    def restore(self, path: Path, protection: Protection) -> None:
        uid, gid, mode = protection.raw
        try:
            os.chown(str(path), uid, gid)
        except OSError:
            pass                       # unelevated restore of a file already ours
        try:
            os.chmod(str(path), mode)
        except OSError:
            pass


def _posix_name(uid: int) -> str:
    import pwd
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


# ── Windows ──────────────────────────────────────────────────────────────────────────

class WindowsOwnership:
    """Owner SID plus a **protected** owner-only DACL. `0600` governs nothing here.

    Elevation on Windows does not change the account the way `sudo` does — an elevated process runs
    as the same administrator with a fuller token — so the invoking identity is simply the token's
    user. What has to be built deliberately is the DACL: a file inheriting its parent's ACEs on a
    shared folder is readable by whoever that folder lets in, which on an arbitrary administrator-
    chosen destination is exactly the case this exists for.

    The DACL is **protected** (inheritance blocked) and holds two entries: the owner, and SYSTEM.
    SYSTEM stays because the OS needs it — backup, indexing, defragmentation — and removing it makes
    a file that fights the platform. Ordinary users and unrelated administrators are absent, which is
    the point: membership in Administrators does not by itself grant access through this DACL, only
    the ability to take ownership, which is a deliberate, auditable act rather than an inheritance.
    """

    flavour = WINDOWS

    def __init__(self, api=None):
        self._api = api                        # injected on non-Windows for testing

    def _win(self):
        if self._api is not None:
            return self._api
        try:
            import win32security                # noqa: F401
            import ntsecuritycon                # noqa: F401
        except ImportError as exc:              # pragma: no cover - Windows-only dependency
            raise OwnershipUnavailable(
                "pywin32 is required to establish Windows ownership of a Recovery File"
            ) from exc
        return _RealWindowsApi()

    def invoking_identity(self) -> Identity:
        api = self._win()
        sid, name = api.current_user()
        return Identity(flavour=WINDOWS, label=name, sid=sid, source="invoking_user")

    def apply(self, path: Path, identity: Identity) -> None:
        if not identity.sid:
            raise ProtectionNotEstablished("no Windows identity to assign")
        api = self._win()
        try:
            api.set_owner(str(path), identity.sid)
            api.set_protected_owner_only_dacl(str(path), identity.sid)
        except Exception as exc:
            raise ProtectionNotEstablished(
                f"could not protect the Recovery File for {identity.describe()}: {exc}"
            ) from exc

    def describe(self, path: Path) -> Protection:
        api = self._win()
        owner_sid, owner_name = api.get_owner(str(path))
        trustees = api.dacl_trustees(str(path))
        protected = api.dacl_is_protected(str(path))
        if not protected:
            raise ProtectionNotEstablished(
                f"{path} inherits access from its parent directory; owner-only protection was not "
                "established"
            )
        unexpected = [t for t in trustees if t not in (owner_sid, api.system_sid())]
        if unexpected:
            raise ProtectionNotEstablished(
                f"{path} grants access to {unexpected} besides its owner and SYSTEM"
            )
        return Protection(
            flavour=WINDOWS, owner=owner_name,
            detail="protected owner-only ACL (inheritance blocked; SYSTEM retained)",
            raw=(owner_sid, api.security_descriptor(str(path))),
        )

    def capture(self, path: Path) -> Protection:
        api = self._win()
        owner_sid, owner_name = api.get_owner(str(path))
        # Whether the file WAS protected is part of its state, and restoring has to reproduce it.
        return Protection(
            flavour=WINDOWS, owner=owner_name, detail="captured",
            raw=(owner_sid, api.security_descriptor(str(path)),
                 api.dacl_is_protected(str(path))),
        )

    def restore(self, path: Path, protection: Protection) -> None:
        """Put the file back as it was — including whether its DACL inherited.

        The first version always restored PROTECTED. A file that had been inheriting from its parent
        came back protected, which is a *different file* from the one that was there: it no longer
        tracks the directory's ACLs, and nobody was told. Restoring must reproduce the prior state,
        not impose the state we happen to prefer.
        """
        api = self._win()
        owner_sid, descriptor, was_protected = protection.raw
        api.set_owner(str(path), owner_sid)
        api.set_security_descriptor(str(path), descriptor, protected=was_protected)


class _RealWindowsApi:                          # pragma: no cover - exercised only on Windows
    """The thin pywin32 shim. Kept behind the injectable seam so the policy above is testable."""

    def current_user(self):
        import win32api
        import win32security
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return win32security.ConvertSidToStringSid(sid), f"{domain}\\\\{name}"

    def system_sid(self):
        import win32security
        return win32security.ConvertSidToStringSid(
            win32security.CreateWellKnownSid(win32security.WinLocalSystemSid))

    def _sid(self, text):
        import win32security
        return win32security.ConvertStringSidToSid(text)

    def set_owner(self, path, sid):
        import win32security
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION,
            self._sid(sid), None, None, None)

    def set_protected_owner_only_dacl(self, path, sid):
        import ntsecuritycon
        import win32security
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, self._sid(sid))
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS,
            self._sid(self.system_sid()))
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None)

    def get_owner(self, path):
        import win32security
        sd = win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION)
        sid = sd.GetSecurityDescriptorOwner()
        name, domain, _ = win32security.LookupAccountSid(None, sid)
        return win32security.ConvertSidToStringSid(sid), f"{domain}\\\\{name}"

    def dacl_trustees(self, path):
        import win32security
        sd = win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        out = []
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            out.append(win32security.ConvertSidToStringSid(ace[2]))
        return out

    def dacl_is_protected(self, path):
        import win32security
        sd = win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        control, _ = sd.GetSecurityDescriptorControl()
        return bool(control & win32security.SE_DACL_PROTECTED)

    def security_descriptor(self, path):
        import win32security
        return win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)

    def set_security_descriptor(self, path, descriptor, protected=True):
        import win32security
        flag = (win32security.PROTECTED_DACL_SECURITY_INFORMATION if protected
                else win32security.UNPROTECTED_DACL_SECURITY_INFORMATION)
        win32security.SetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | flag,
            None, None, descriptor.GetSecurityDescriptorDacl(), None)


def ownership_backend(environ=None, api=None) -> OwnershipBackend:
    """The backend for this platform. `api` injects a Windows double on a non-Windows host."""
    if api is not None or sys.platform == "win32":
        return WindowsOwnership(api=api)
    return PosixOwnership(environ=environ)
