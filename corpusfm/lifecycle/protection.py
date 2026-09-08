"""Establishing and PROVING the fixed layout's ownership and access (packet 1246-03, step 6).

Two reviews found the same defect at different levels: an ACL was *issued* and nobody checked what
it *effected*. First a `/grant (R)` sat beside an inherited Modify and changed nothing; then the
per-file protection was correct and the parent directory still let the service delete the file and
put its own there. Both times the tests asserted the command string.

So this module has two halves and the second is the point:

    apply()   establish ownership and access. Every failure is fatal.
    verify()  report what is TRUE of the filesystem now, as a list of problems.

`verify()` returns findings rather than raising, so a caller can report all of them at once — an
administrator fixing permissions wants the whole list, not the first one.

**Parent authority is checked, not just file authority.** A secrets directory the service can create
and delete entries in makes every mode inside it decorative, which is exactly the hole the developer
ruled out on 2026-08-03.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .errors import LifecycleError
from .os_layout import OsLayout

# Secrets the runtime READS and must never be able to rewrite.
#
# Provider records join the keys here when the runtime must consume them without being able to
# rewrite them. Their providers correctly create them private for the installer; this final policy
# pass grants the installed service read-only access (root:<service> 0640 on POSIX, the equivalent
# protected ACL on Windows).
READ_ONLY_SECRETS: tuple[str, ...] = (
    "corpus.key", "machine.key", "secret.key", "server.key", "session_secret",
    "storage_access.json", "admin_identity.yaml",
)

# NTFS access-mask bits, named here rather than imported so this module states its own policy and
# can be reasoned about (and tested) on a machine that has no pywin32.
FILE_WRITE_DATA = 0x0002       # on a directory the same bit means FILE_ADD_FILE
FILE_APPEND_DATA = 0x0004      # on a directory, FILE_ADD_SUBDIRECTORY
FILE_DELETE_CHILD = 0x0040
DELETE = 0x00010000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_WRITE = 0x40000000
GENERIC_ALL = 0x10000000

#: Authority over a *directory* that would let its holder replace what is inside it. This is R2 in
#: one constant: per-file protection is decorative while any of these is granted on the parent.
DIRECTORY_AUTHORITY = (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_DELETE_CHILD | DELETE
                       | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

#: Authority over a *file* that changes it or who may change it.
FILE_WRITE_AUTHORITY = (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER
                        | GENERIC_WRITE | GENERIC_ALL)

#: Full control, and the two well-known SIDs named as SIDs rather than as account names. This is
#: not decoration: `LookupAccountName` is exactly what fails at phase 12 (error 1332, measured on
#: winfms2026 2026-08-08), and a well-known SID needs no lookup and no localised group name.
FILE_ALL_ACCESS = 0x001F01FF
SYSTEM_SID_TEXT = "S-1-5-18"
ADMINISTRATORS_SID_TEXT = "S-1-5-32-544"

#: How the group is NAMED in a problem report — never how it is resolved. The group is localised on
#: a non-English Windows, so this string is not a lookup key and must never be used as one.
ADMINISTRATORS_NAME = "BUILTIN\\Administrators"

#: ACE inheritance flags. `C:\ProgramData\CORPUSfm` is a SHARED LAYOUT ROOT, not a secret: `state`,
#: `logs`, `run`, `update-inbox` and `update-outcome` get SYSTEM and Administrators from it by
#: inheritance and hold no such ACE of their own. A DACL written there with no inheritance flags
#: therefore takes that authority away from all of them — measured on winfms2026, 2026-08-09 at
#: generation 26, where `state`, `logs` and `run` were left holding one ACE
#: (`NT SERVICE\corpusfm-web:(OI)(CI)(M)`), `update-inbox` became unreadable to the elevated
#: installer, and the run died on `icacls …\update-inbox: Access is denied`.
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
INHERIT_BOTH = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE

def describe_rights(mask: int) -> str:
    """Name the bits, because `0x40000000` in a problem report tells an administrator nothing."""
    names = [
        (GENERIC_ALL, "GENERIC_ALL"), (GENERIC_WRITE, "GENERIC_WRITE"),
        (WRITE_OWNER, "WRITE_OWNER"), (WRITE_DAC, "WRITE_DAC"), (DELETE, "DELETE"),
        (FILE_DELETE_CHILD, "FILE_DELETE_CHILD"), (FILE_APPEND_DATA, "FILE_APPEND_DATA/ADD_SUBDIR"),
        (FILE_WRITE_DATA, "FILE_WRITE_DATA/ADD_FILE"),
    ]
    held = [name for bit, name in names if mask & bit]
    return "+".join(held) if held else f"0x{mask:08x}"


#: The modes the POSIX protector establishes, as data rather than literals inside `apply()`. Named
#: because a test that re-states them is a test-owned mirror: it passes while `apply()` changes
#: underneath it, which is the failure mode the mutation battery exists to catch.
SERVICE_WRITABLE_MODE = 0o750
ADMIN_OWNED_DIR_MODE = 0o755
READ_ONLY_SECRET_MODE = 0o640
def intended_modes(layout: OsLayout) -> dict:
    """Path → mode, exactly as `apply()` sets them. One statement of the policy, two readers."""
    modes = {layout.state_dir: SERVICE_WRITABLE_MODE, layout.log_dir: SERVICE_WRITABLE_MODE,
             layout.run_dir: SERVICE_WRITABLE_MODE,
             layout.config_dir: ADMIN_OWNED_DIR_MODE, layout.secrets_dir: ADMIN_OWNED_DIR_MODE}
    for name in READ_ONLY_SECRETS:
        modes[layout.secrets_dir / name] = READ_ONLY_SECRET_MODE
    return modes


def describe_inheritance(flags: int) -> str:
    """Name the inheritance flags an ACE carries, for a report an administrator can act on."""
    held = [name for bit, name in ((OBJECT_INHERIT_ACE, "OBJECT_INHERIT"),
                                   (CONTAINER_INHERIT_ACE, "CONTAINER_INHERIT")) if flags & bit]
    return "+".join(held) if held else "no inheritance"


def shared_container_problems(api, path: Path, *, service_sids: "tuple[str, ...]" = ()) -> list[str]:
    """What a protected SHARED LAYOUT ROOT must carry — judged from its ACEs, not its intent.

    Stated once and used by both Windows protectors, because they protect the same container at
    two different moments and a rule written twice is a rule that drifts. It is deliberately about
    the ACEs rather than effective rights: `effective_rights` answers what a principal holds HERE,
    and the whole defect this rule exists for is about what the container passes DOWN.

    - SYSTEM and Administrators: Full Control, **with both OBJECT_INHERIT and CONTAINER_INHERIT**.
      A correct mask without the flags is exactly the state that stranded the layout.
    - The service identities, when they are named at all: no inheritance. Traverse and read HERE is
      not traverse and read over `state`, `logs`, `run` and the update compartment.
    - Nobody else is named.
    """
    try:
        entries = tuple(api.dacl_entries_ex(path))
    except Exception as exc:                               # noqa: BLE001
        return [f"the DACL on {path} could not be read: {exc}"]

    problems: list[str] = []
    services = tuple(str(s) for s in service_sids)
    allowed = {SYSTEM_SID_TEXT, ADMINISTRATORS_SID_TEXT} | set(services)
    foreign = {str(sid) for sid, _mask, _flags in entries} - allowed
    if foreign:
        problems.append(
            f"{path} names {', '.join(sorted(foreign))}; the shared layout root names SYSTEM, "
            "Administrators and the registered services only")

    for sid_text, who in ((SYSTEM_SID_TEXT, "SYSTEM"), (ADMINISTRATORS_SID_TEXT, ADMINISTRATORS_NAME)):
        aces = [(mask, flags) for sid, mask, flags in entries if str(sid) == sid_text]
        if not aces:
            problems.append(
                f"{path} does not name {who}; every fixed-layout directory beneath it inherits "
                "its access from here and holds none of its own")
            continue
        inheriting = [(mask, flags) for mask, flags in aces if flags & INHERIT_BOTH == INHERIT_BOTH]
        if not inheriting:
            missing = " and ".join(
                name for bit, name in ((OBJECT_INHERIT_ACE, "OBJECT_INHERIT"),
                                       (CONTAINER_INHERIT_ACE, "CONTAINER_INHERIT"))
                if not any(flags & bit for _mask, flags in aces))
            problems.append(
                f"{path} grants {who} {describe_inheritance(aces[0][1])}, missing {missing}; "
                "the fixed-layout directories beneath it would lose that access entirely")
        elif not any(mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS for mask, _flags in inheriting):
            problems.append(
                f"{path} passes {who} {describe_rights(inheriting[0][0])} down, not full control; "
                "a later elevated lifecycle operation could not repair what it inherits")

    for sid, _mask, flags in entries:
        if str(sid) in services and flags & INHERIT_BOTH:
            problems.append(
                f"{path} grants {sid} {describe_inheritance(flags)}; a service's traverse and read "
                "on the shared root must not descend into the state, log and update directories")
    return problems


class ProtectionFailed(LifecycleError):
    """An ownership or access change did not take. Never a warning."""


class LayoutProtector(Protocol):
    def apply(self, layout: OsLayout, *, stage: str) -> None: ...
    def verify(self, layout: OsLayout) -> list[str]: ...


class WindowsAclApi(Protocol):
    """The platform calls the Windows protector makes.

    Declared here, in the module whose policy depends on it, so the policy can be exercised against
    a double on any machine — and so `effective_rights` is part of the contract rather than an
    optional extra some implementation might not provide.
    """

    def sid(self, account: str) -> object: ...
    def sid_text(self, account: str) -> str: ...
    def system_sid(self) -> object: ...
    def administrators_sid(self) -> object: ...
    def dacl_entries(self, path: Path) -> "tuple[tuple[str, int], ...]": ...
    def dacl_entries_ex(self, path: Path) -> "tuple[tuple[str, int, int], ...]": ...
    def set_protected_owner_only_dacl(self, path: Path, sid: object) -> None: ...
    def set_protected_dacl(self, path: Path, owner: object,
                           grants: "tuple[tuple[object, int], ...]") -> None: ...
    def set_protected_dacl_preserve_owner(
            self, path: Path, grants: "tuple[tuple[object, int], ...]") -> None: ...
    def set_protected_shared_container_dacl(
            self, path: Path, owner: object,
            inheritable: "tuple[tuple[object, int], ...]",
            grants: "tuple[tuple[object, int], ...]") -> None: ...
    def dacl_is_protected(self, path: Path) -> bool: ...
    def effective_rights(self, path: Path, trustee: object) -> int: ...


class PosixLayoutProtector:
    """Owners and modes, checked after they are set.

    `service_uid`/`service_gid` are the identity the services run as. Directories the service writes
    are owned by it; the secrets directory is **root-owned and not group-writable**, so the service
    can traverse and read but cannot create, delete or rename anything inside it — which is what
    makes the per-file modes below mean something.
    """

    def __init__(self, *, service_uid: int, service_gid: int, admin_uid: int = 0,
                 admin_gid: int = 0):
        self._uid = service_uid
        self._gid = service_gid
        # The identity that OWNS the installation, as opposed to the one that runs it. Named and
        # defaulted to root rather than written as the literal `0` at each site: the rule is "not
        # the service", and stating it as a parameter is what lets a test exercise the rule without
        # root — which is the only way this policy gets tested at all before the live lane.
        self._admin_uid = admin_uid
        self._admin_gid = admin_gid

    def apply(self, layout: OsLayout, *, stage: str) -> None:
        modes = intended_modes(layout)
        for directory in (layout.state_dir, layout.log_dir, layout.run_dir):
            self._own(directory, self._uid, self._gid, modes[directory])
        # Administrator-owned, service-traversable, NOT service-writable.
        for directory in (layout.config_dir, layout.secrets_dir):
            self._own(directory, self._admin_uid, self._admin_gid, modes[directory])

        for name in READ_ONLY_SECRETS:
            path = layout.secrets_dir / name
            if path.exists():
                self._own(path, self._admin_uid, self._admin_gid, modes[path], group=self._gid)

    def _own(self, path: Path, uid: int, gid: int, mode: int, *, group: int | None = None) -> None:
        try:
            os.chown(path, uid, gid if group is None else group)
            os.chmod(path, mode)
        except OSError as exc:
            raise ProtectionFailed(f"could not protect {path}: {exc}") from exc

    def verify(self, layout: OsLayout) -> list[str]:
        problems: list[str] = []

        def info(path: Path):
            try:
                return os.stat(path)
            except OSError as exc:
                problems.append(f"{path} could not be inspected: {exc}")
                return None

        secrets = info(layout.secrets_dir)
        if secrets is not None:
            if secrets.st_uid != self._admin_uid:
                problems.append(
                    f"{layout.secrets_dir} is owned by uid {secrets.st_uid}, not the installing "
                    f"administrator ({self._admin_uid}) — the service could delete a protected key "
                    "and replace it"
                )
            if stat.S_IMODE(secrets.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                problems.append(
                    f"{layout.secrets_dir} is group- or other-writable "
                    f"({stat.S_IMODE(secrets.st_mode):04o}); parent authority defeats every mode "
                    "inside it"
                )

        for name in READ_ONLY_SECRETS:
            path = layout.secrets_dir / name
            if not path.exists():
                continue
            entry = info(path)
            if entry is None:
                continue
            if entry.st_uid == self._uid:
                problems.append(f"{path} is owned by the service identity and must not be")
            if stat.S_IMODE(entry.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                problems.append(f"{path} is writable beyond its owner")

        for directory in (layout.state_dir, layout.log_dir, layout.run_dir):
            entry = info(directory)
            if entry is not None and entry.st_uid != self._uid:
                problems.append(
                    f"{directory} is owned by uid {entry.st_uid}; the service cannot write its own "
                    "state"
                )

        # The parent of the protected directory, which is one level further out than R2 reached.
        # A root-owned `secrets/` inside a service-writable `/var/lib/corpusfm` is not protected:
        # the service renames the directory aside, creates its own, and every mode inside the
        # original becomes irrelevant without a single permission being changed.
        problems.extend(self._parent_problems(layout.secrets_dir, info))
        problems.extend(self._parent_problems(layout.config_dir, info))
        return problems

    def _parent_problems(self, directory: Path, info) -> list[str]:
        parent = directory.parent
        if parent == directory:
            return []
        entry = info(parent)
        if entry is None:
            return []
        found: list[str] = []
        if entry.st_uid == self._uid:
            found.append(
                f"{parent} is owned by the service identity, so the service can rename "
                f"{directory.name} aside and put its own there; protecting the contents does not "
                "survive that"
            )
        if stat.S_IMODE(entry.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
            mode = stat.S_IMODE(entry.st_mode)
            if not (mode & stat.S_ISVTX):
                found.append(
                    f"{parent} is group- or other-writable ({mode:04o}) with no sticky bit; "
                    f"{directory.name} can be replaced wholesale"
                )
        return found


FILE_READ_DATA = 0x0001
FILE_EXECUTE = 0x0020
READ_CONTROL = 0x00020000
SYNCHRONIZE = 0x00100000

#: Traverse and read a directory's entries — everything a service needs in `secrets/`, and nothing
#: that lets it add, remove or rename anything there.
DIRECTORY_TRAVERSE_READ = FILE_READ_DATA | FILE_EXECUTE | READ_CONTROL | SYNCHRONIZE
#: Read one file.
FILE_READ = FILE_READ_DATA | READ_CONTROL | SYNCHRONIZE
#: Read and rewrite one file's contents, with no authority over its existence.


class WindowsLayoutProtector:
    """The NTFS half, behind the same two-method contract.

    **What this is evidence of, stated plainly:** the policy, exercised through an injected API. It
    is NOT proof that Windows enforces the result — that needs a real box and is 1246-10's lane.
    The distinction is load-bearing here because the defect being fixed was precisely a test that
    proved a *command* and called it a *state*.

    Two corrections over the previous version, both from review round 4:

    - **The secrets DIRECTORY is protected and verified**, not only the files inside it (R2). A
      service holding `FILE_ADD_FILE` or `FILE_DELETE_CHILD` on the parent can replace any secret
      no matter how the file itself is permissioned, so a protector that inspected only files
      reported success over exactly that hole.
    - **Effective rights are read back for each trustee** (R3), rather than inferring the outcome
      from the fact that a call returned without error. `set_protected_dacl` is an intent;
      `effective_rights` is a state, and only the second one can contradict the first.
    """

    def __init__(self, *, web_sid: str, scheduler_sid: str | None = None, api=None):
        self._web = web_sid
        # OPTIONAL, AND NORMALLY ABSENT (packet 1361-01, round 3). The standalone
        # `corpusfm-scheduler` service is retired — scheduling is a background component of the web
        # process — so a current installation registers ONE service and has one virtual account.
        # A virtual account whose service does not exist has no SID at all, and naming it here would
        # make `LookupAccountName` refuse (error 1332) on every fresh box. It stays accepted because
        # an installation that still carries the retired service is still protected correctly while
        # the upgrade that removes it runs.
        self._sched = scheduler_sid or ""
        self._api = api

    def _subjects(self) -> tuple:
        """The service trustees this protector actually grants to, ``(label, account)`` each."""
        pairs = [("web", self._web)]
        if self._sched:
            pairs.append(("scheduler", self._sched))
        return tuple(pairs)

    def _win(self):
        if self._api is not None:
            return self._api
        return _RealWindowsAclApi()  # pragma: no cover - platform-specific

    def apply(self, layout: OsLayout, *, stage: str) -> None:
        api = self._win()
        system = api.system_sid()
        admins = api.administrators_sid()
        service_sids = tuple(api.sid(account) for _who, account in self._subjects())

        # ADMINISTRATORS KEEP FULL CONTROL, EXPLICITLY (developer ruling, 2026-08-09). SYSTEM owns
        # these, and an owner-only DACL locked the elevated installer out of the very directory it
        # must re-permission: phase 20 died on `icacls C:\ProgramData\CORPUSfm\secrets: Access is
        # denied` because the pre-service protection had already made it SYSTEM's alone, and the
        # installer runs as Administrators. Measured on winfms2026, 2026-08-09, at generation 20.
        # Every future elevated lifecycle operation needs this grant; it is policy, not a fallback.
        for_admins = (admins, FILE_ALL_ACCESS)

        # The directory first, and deliberately: protecting the files inside a directory the service
        # can rewrite is the shape of the original defect. Its OWN parent comes first again for the
        # same reason one level out — replacement authority there renames `secrets` aside and puts
        # another one in its place, and nothing inside `secrets` has changed.
        parent = layout.secrets_dir.parent
        if parent != layout.secrets_dir:
            # THE SHARED LAYOUT ROOT, NOT A SECRET. `state`, `logs`, `run`, `update-inbox` and
            # `update-outcome` live under it and hold no SYSTEM or Administrators ACE of their own —
            # they inherit both from here. Protecting this container against replacement is right;
            # writing it with no inheritance flags took that authority away from all of them.
            api.set_protected_shared_container_dacl(
                parent, system,
                ((system, FILE_ALL_ACCESS), (admins, FILE_ALL_ACCESS)),
                tuple((sid, DIRECTORY_TRAVERSE_READ) for sid in service_sids),
            )
        api.set_protected_dacl(
            layout.secrets_dir, system,
            (for_admins,) + tuple((sid, DIRECTORY_TRAVERSE_READ) for sid in service_sids),
        )
        for name in READ_ONLY_SECRETS:
            path = layout.secrets_dir / name
            if path.exists():
                api.set_protected_dacl(
                    path, system,
                    (for_admins,) + tuple((sid, FILE_READ) for sid in service_sids))

    def verify(self, layout: OsLayout) -> list[str]:
        api = self._win()
        problems: list[str] = []

        def rights(path: Path, who: str, trustee: object | None = None) -> int | None:
            """`who` NAMES the trustee in the message; `trustee` is the already-resolved SID.

            A SID **string** is not an account name. `api.sid()` is `LookupAccountName`, which
            answers error 1332 for `"S-1-5-32-544"` — measured on winfms2026, 2026-08-09, where the
            Administrators read-back refused six subjects while the DACL it was reading was
            correct. Well-known trustees resolve through their own converter and are passed in;
            only real account names go through the lookup.
            """
            try:
                subject = api.sid(who) if trustee is None else trustee
                return int(api.effective_rights(path, subject))
            except Exception as exc:
                problems.append(f"effective rights for {who} on {path} could not be read: {exc}")
                return None

        def protected(path: Path) -> None:
            try:
                if not api.dacl_is_protected(path):
                    problems.append(f"{path} still inherits permissions from its parent")
            except Exception as exc:
                problems.append(f"{path} could not be inspected: {exc}")

        # ── the parent, which is R2 — and ITS parent, which R2 did not reach ──
        secrets = layout.secrets_dir
        containers = [secrets]
        if secrets.parent != secrets:
            containers.append(secrets.parent)
            # The shared layout root answers for what it passes DOWN as well; the service checks
            # below still answer for what it grants HERE.
            service_sids = []
            for _who, account in self._subjects():
                try:
                    service_sids.append(api.sid_text(account))
                except Exception as exc:                    # noqa: BLE001
                    problems.append(f"the SID for {account} could not be resolved: {exc}")
            problems.extend(shared_container_problems(api, secrets.parent,
                                                      service_sids=tuple(service_sids)))
        for directory in containers:
            protected(directory)
            for who, sid_text in self._subjects():
                held = rights(directory, sid_text)
                if held is None:
                    continue
                offending = held & DIRECTORY_AUTHORITY
                if offending:
                    problems.append(
                        f"{directory} grants the {who} service {describe_rights(offending)}; with "
                        "authority over that directory it can replace what is inside it regardless "
                        "of how the contents are permissioned"
                    )

        # ── ADMINISTRATORS, OBSERVED — not assumed from the grant that was issued ──
        # Resolved the way `apply` resolves it, through the well-known-SID converter. Once, and
        # named, because failing to resolve the group at all is a different problem from a subject
        # whose rights are wrong, and reporting it six times says nothing more than reporting it.
        try:
            admins = api.administrators_sid()
        except Exception as exc:
            admins = None
            problems.append(f"{ADMINISTRATORS_NAME} could not be resolved: {exc}")
        for subject in ([] if admins is None else
                        containers + [secrets / n for n in READ_ONLY_SECRETS
                                      if (secrets / n).exists()]):
            held = rights(subject, ADMINISTRATORS_NAME, admins)
            if held is None:
                continue
            if held & FILE_ALL_ACCESS != FILE_ALL_ACCESS:
                problems.append(
                    f"{subject} grants {ADMINISTRATORS_NAME} {describe_rights(held)}, not full "
                    "control; a later elevated lifecycle operation could not re-permission it")

        # ── the read-only secrets ──
        for name in READ_ONLY_SECRETS:
            path = secrets / name
            if not path.exists():
                continue
            protected(path)
            for who, sid_text in self._subjects():
                held = rights(path, sid_text)
                if held is None:
                    continue
                offending = held & FILE_WRITE_AUTHORITY
                if offending:
                    problems.append(
                        f"{path} grants the {who} service {describe_rights(offending)}; every "
                        "installed secret is read-only to the runtime, without exception"
                    )

        return problems


class _RealWindowsAclApi:  # pragma: no cover - exercised only on Windows
    """pywin32 behind `WindowsAclApi`. Imported lazily so this module loads anywhere."""

    def _win(self):
        import ntsecuritycon
        import win32security

        return win32security, ntsecuritycon

    def sid(self, account: str):
        win32security, _ = self._win()
        return win32security.LookupAccountName(None, account)[0]

    def sid_text(self, account: str) -> str:
        """The same trustee as `sid`, spelled the way a DACL reads back."""
        win32security, _ = self._win()
        return win32security.ConvertSidToStringSid(self.sid(account))

    def system_sid(self):
        win32security, _ = self._win()
        return win32security.ConvertStringSidToSid(SYSTEM_SID_TEXT)

    def administrators_sid(self):
        win32security, _ = self._win()
        return win32security.ConvertStringSidToSid(ADMINISTRATORS_SID_TEXT)

    def dacl_entries(self, path: Path):
        """The DACL as it IS: every ACE's trustee and mask, read back from the file.

        `effective_rights` answers "what does THIS principal hold", which can never answer "and
        nobody else is named here" — the question the pre-service mode has to answer.
        """
        win32security, _ = self._win()
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return ()
        out = []
        for i in range(dacl.GetAceCount()):
            _header, mask, sid = dacl.GetAce(i)
            out.append((win32security.ConvertSidToStringSid(sid), int(mask)))
        return tuple(out)

    def dacl_entries_ex(self, path: Path):
        """The DACL with each ACE's INHERITANCE FLAGS, which `dacl_entries` cannot express.

        A shared layout root is judged on what it passes DOWN as well as what it grants here, and
        those are different facts: `SYSTEM:(F)` and `SYSTEM:(OI)(CI)(F)` have the same mask and
        opposite consequences for every child that holds no ACE of its own.
        """
        win32security, _ = self._win()
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return ()
        out = []
        for i in range(dacl.GetAceCount()):
            header, mask, sid = dacl.GetAce(i)
            out.append((win32security.ConvertSidToStringSid(sid), int(mask), int(header[1])))
        return tuple(out)

    def set_protected_shared_container_dacl(self, path: Path, owner, inheritable, grants) -> None:
        """ONE whole DACL for a container the rest of the fixed layout inherits from.

        The same single-call discipline as `set_protected_dacl` — never `/reset` then `/grant`,
        which leaves a window with no authority at all — and the same protection against
        replacement. What differs is the one thing this container needs and a secret must not have:
        the SYSTEM and Administrators entries are written with `AddAccessAllowedAceEx` carrying
        OBJECT_INHERIT and CONTAINER_INHERIT, so children that hold no ACE of their own keep
        theirs. The service grants stay explicit and non-inheritable: traverse and read HERE is not
        traverse and read over everything below.

        `ACL_REVISION_DS` is required for `AddAccessAllowedAceEx`; the ACEs themselves are ordinary
        allow entries.
        """
        win32security, _ = self._win()
        dacl = win32security.ACL()
        for trustee, mask in inheritable:
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, INHERIT_BOTH, int(mask),
                                       trustee)
        for trustee, mask in grants:
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, 0, int(mask), trustee)
        sd = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorOwner(owner, False)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sd.SetSecurityDescriptorControl(
            win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
        try:
            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
                sd)
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            if code is None and getattr(exc, "args", ()):
                code = exc.args[0]
            if code != 1307:
                raise
            # An ordinary elevated Administrator can protect this DACL but need not hold the
            # privilege Windows requires to assign SYSTEM as owner. Keep the creation-time owner
            # and still establish the complete protected SYSTEM/Administrators access policy.
            win32security.SetFileSecurity(
                str(path), win32security.DACL_SECURITY_INFORMATION, sd)

    def set_protected_owner_only_dacl(self, path: Path, sid) -> None:
        self.set_protected_dacl(path, sid, ())

    def set_protected_dacl(self, path: Path, owner, grants) -> None:
        win32security, ntsecuritycon = self._win()
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, owner)
        for trustee, mask in grants:
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, int(mask), trustee)
        sd = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorOwner(owner, False)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sd.SetSecurityDescriptorControl(
            win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
        try:
            win32security.SetFileSecurity(
                str(path),
                win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION,
                sd)
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            if code is None and getattr(exc, "args", ()):
                code = exc.args[0]
            if code != 1307:
                raise
            win32security.SetFileSecurity(
                str(path), win32security.DACL_SECURITY_INFORMATION, sd)

    def set_protected_dacl_preserve_owner(self, path: Path, grants) -> None:
        """Replace and protect only the DACL; retain the creation-time owner.

        A freshly-created staging leaf is already owned by the elevated caller. Assigning SYSTEM
        as its owner requires a token privilege an ordinary elevated Administrator need not hold
        (Windows error 1307). Ownership is not being repaired here: the caller created the leaf,
        and the independent authority read-back accepts only that invoking owner or SYSTEM. The
        operation therefore writes exactly the SYSTEM/Administrators access policy without asking
        Windows to assign a different owner.
        """
        win32security, _ = self._win()
        dacl = win32security.ACL()
        for trustee, mask in grants:
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, int(mask), trustee)
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sd.SetSecurityDescriptorControl(
            win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
        win32security.SetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION, sd)

    def dacl_is_protected(self, path: Path) -> bool:
        win32security, _ = self._win()
        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        return bool(sd.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED)

    def effective_rights(self, path: Path, trustee) -> int:
        """What the trustee can ACTUALLY do, resolved by Windows rather than read off the ACEs.

        `GetEffectiveRightsFromAcl` is the whole point of R3: it accounts for inheritance, group
        membership and deny entries, none of which are visible in the ACE list the previous version
        inspected.
        """
        import win32security

        sd = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            # A NULL DACL is not "no permissions" — Windows reads it as unrestricted access for
            # everyone. Returning 0 here reported a wide-open object as clean, which is the same
            # class of error as trusting an apply(): an absent answer read as a safe one.
            return GENERIC_ALL | DIRECTORY_AUTHORITY | FILE_WRITE_AUTHORITY
        return int(dacl.GetEffectiveRightsFromAcl({
            "TrusteeForm": win32security.TRUSTEE_IS_SID,
            "TrusteeType": win32security.TRUSTEE_IS_UNKNOWN,
            "Identifier": trustee,
        }))


@dataclass(frozen=True)
class FileAuthority:
    """Who owns an open file and who may write it — the Windows answer to "root-owned, 0600".

    Owner and trustees are SID STRINGS so the policy that consumes them is testable against a
    double on any machine, exactly as `WindowsAclApi` already is.
    """

    owner: str
    trustees: tuple[str, ...]
    protected: bool
    inherited: bool
    # Explicit ACCESS_ALLOWED ACE masks, keyed by SID.  `trustees` deliberately remains the
    # complete named-principal answer used by privileged-input policy; the executor boundary is
    # the narrower consumer that distinguishes harmless read/traverse from replacement authority.
    # An empty answer means the caller has no mask evidence and must retain the old fail-closed
    # treatment of every unexplained trustee.
    grants: tuple[tuple[str, int], ...] = ()


class WindowsFileAuthorityApi(Protocol):
    """The seam the privileged-request check uses. Injectable, so the POLICY is exercised without
    pywin32 and without a real Windows box."""

    def authority_of(self, fd: int) -> FileAuthority: ...
    def authority_of_path(self, path: str) -> FileAuthority: ...
    def system_sid_text(self) -> str: ...
    def invoking_owner_sids(self) -> tuple[str, ...]: ...


class _RealWindowsFileAuthority:  # pragma: no cover - exercised only on Windows
    """pywin32 behind `WindowsFileAuthorityApi`, beside the other pywin32 work in this module.

    Not a third ACL implementation: it reads the same descriptors `_RealWindowsAclApi` writes, in
    the module that already owns the import, and answers in the same SID vocabulary.
    """

    def _win(self):
        import win32security

        return win32security

    def authority_of(self, fd: int) -> FileAuthority:
        import msvcrt

        win32security = self._win()
        handle = msvcrt.get_osfhandle(fd)
        sd = win32security.GetSecurityInfo(
            handle, win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        return self._from_descriptor(sd)

    def authority_of_path(self, path: str) -> FileAuthority:
        """The same answer, BY PATH — which is the only way to ask it about a DIRECTORY.

        `os.open(dir, O_RDONLY)` is a POSIX idiom; on Windows opening a directory that way fails,
        so a descriptor-based check applied to `<InstallDir>/bin` could never run there. Files that
        are already open keep the descriptor form, because for those the descriptor is what closes
        the TOCTOU the check exists to close.
        """
        win32security = self._win()
        sd = win32security.GetNamedSecurityInfo(
            path, win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
        return self._from_descriptor(sd)

    def _from_descriptor(self, sd) -> FileAuthority:
        win32security = self._win()
        owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return FileAuthority(owner=owner, trustees=("<null-dacl>",), protected=False,
                                 inherited=True)
        trustees, grants, inherited = [], [], False
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            try:
                ace_type, ace_flags = ace[0]
            except (IndexError, TypeError, ValueError):
                # An unparseable ACE is authority we cannot classify, never evidence that an
                # unexplained trustee is read-only.
                trustees.append(f"<unreadable-ace-{index}>")
                continue
            if ace_flags & win32security.INHERITED_ACE:
                inherited = True
            # CORPUSfm writes simple allow ACEs. Object/callback ACEs have different tuple shapes;
            # partially parsing one could omit a write-capable grant and turn incomplete evidence
            # into permission. Keep every other form visible as unexplained authority instead.
            if len(ace) != 3 or ace_type not in (
                    win32security.ACCESS_ALLOWED_ACE_TYPE,
                    win32security.ACCESS_DENIED_ACE_TYPE):
                trustees.append(f"<unsupported-ace-{ace_type}-{index}>")
                continue
            mask, sid = ace[1], ace[2]
            sid_text = win32security.ConvertSidToStringSid(sid)
            trustees.append(sid_text)
            if ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE:
                grants.append((sid_text, int(mask)))
        control = sd.GetSecurityDescriptorControl()[0]
        protected = bool(control & win32security.SE_DACL_PROTECTED)
        return FileAuthority(owner=owner, trustees=tuple(trustees), protected=protected,
                             inherited=inherited, grants=tuple(grants))

    def system_sid_text(self) -> str:
        return "S-1-5-18"

    def invoking_owner_sids(self) -> tuple[str, ...]:
        win32security = self._win()
        import win32api

        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                               win32security.TOKEN_QUERY)
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        owner = win32security.GetTokenInformation(token, win32security.TokenOwner)
        return tuple(dict.fromkeys(
            win32security.ConvertSidToStringSid(s) for s in (user, owner)))


def real_windows_file_authority() -> WindowsFileAuthorityApi:  # pragma: no cover - platform
    """The one public way to reach it, matching `real_windows_acl_api()`."""
    return _RealWindowsFileAuthority()


def security_descriptor_of(path: Path) -> str | None:  # pragma: no cover - platform-specific
    """The SDDL string for `path`, or None when it cannot be read.

    Lives here, beside the other pywin32 work, so a second subject that needs to CAPTURE Windows
    security for restoration does not grow its own `win32security` import. None is a real answer —
    a snapshot that could not be taken must not masquerade as one that found nothing to record.
    """
    try:
        import win32security

        wanted = (win32security.OWNER_SECURITY_INFORMATION
                  | win32security.GROUP_SECURITY_INFORMATION
                  | win32security.DACL_SECURITY_INFORMATION)
        sd = win32security.GetFileSecurity(str(path), wanted)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, wanted)
    except Exception:
        return None


class WindowsPreServiceProtector:
    """Windows secret protection BEFORE either service exists (packet 1246-10-04).

    A virtual `NT SERVICE\\<name>` account has no SID until its service is registered, and
    registration is phase 20 — eight phases after the keys are provisioned. So the ordinary
    protector could never have run at phase 12: `LookupAccountName` refused with error 1332 and key
    provisioning failed on a box whose keys were already on disk, unprotected. Measured on
    winfms2026, 2026-08-08.

    This mode protects them immediately with the two principals that DO exist — SYSTEM and
    BUILTIN\\Administrators, named by well-known SID so no name lookup is involved at all — and
    grants no service principal anything. The final Windows ACL pass, which runs after both
    services are registered and before either starts, is what resolves the two service accounts and
    applies the least-privilege runtime grants: read for both services, write for neither.

    It is selected EXPLICITLY, by a request that asks for it. Falling into it by omitting a SID is
    the shape of defect where a secret ends up unprotected because nobody said which mode they
    meant, so a partially-supplied service identity refuses instead.
    """

    def __init__(self, *, api=None):
        self._api = api

    def _win(self):
        if self._api is not None:
            return self._api
        return _RealWindowsAclApi()  # pragma: no cover - platform-specific

    def _shared_parent(self, layout: OsLayout) -> Path | None:
        """The layout root the secrets directory sits in — shared with `state`, `logs` and `run`."""
        secrets = layout.secrets_dir
        return None if secrets.parent == secrets else secrets.parent

    def _subjects(self, layout: OsLayout) -> list[Path]:
        """The SECRETS, which are this mode's own least-privilege subjects. The shared parent is
        NOT one of them — it is protected by the shared-container operation instead, because the
        rest of the fixed layout inherits its authority from it."""
        secrets = layout.secrets_dir
        subjects = [secrets]
        for name in READ_ONLY_SECRETS:
            path = secrets / name
            if path.exists():
                subjects.append(path)
        return subjects

    def apply(self, layout: OsLayout, *, stage: str) -> None:
        api = self._win()
        system = api.system_sid()
        admins = api.administrators_sid()
        parent = self._shared_parent(layout)
        if parent is not None:
            # PHASE 12 IS WHERE THE LAYOUT ROOT IS FIRST PROTECTED, so it is also where inheritable
            # authority has to survive: `update-inbox`, `update-outcome`, `state`, `logs` and `run`
            # are consumed later in the same run and hold no ACE of their own.
            api.set_protected_shared_container_dacl(
                parent, system, ((system, FILE_ALL_ACCESS), (admins, FILE_ALL_ACCESS)), ())
        grants = ((admins, FILE_ALL_ACCESS),)
        for path in self._subjects(layout):
            api.set_protected_dacl(path, system, grants)

    def verify(self, layout: OsLayout) -> list[str]:
        api = self._win()
        problems: list[str] = []
        allowed = {SYSTEM_SID_TEXT, ADMINISTRATORS_SID_TEXT}
        parent = self._shared_parent(layout)
        if parent is not None:
            try:
                if not api.dacl_is_protected(parent):
                    problems.append(f"{parent} still inherits permissions from its parent")
            except Exception as exc:                  # noqa: BLE001
                problems.append(f"{parent} could not be inspected: {exc}")
            problems.extend(shared_container_problems(api, parent))
        for path in self._subjects(layout):
            try:
                if not api.dacl_is_protected(path):
                    problems.append(f"{path} still inherits permissions from its parent")
            except Exception as exc:              # noqa: BLE001
                problems.append(f"{path} could not be inspected: {exc}")
                continue
            try:
                entries = tuple(api.dacl_entries(path))
            except Exception as exc:              # noqa: BLE001
                problems.append(f"the DACL on {path} could not be read: {exc}")
                continue
            named = {str(sid) for sid, _mask in entries}
            foreign = named - allowed
            if foreign:
                problems.append(
                    f"{path} names {', '.join(sorted(foreign))}; before the services exist the "
                    "fixed secrets are SYSTEM and Administrators only")
            missing = allowed - named
            if missing:
                problems.append(
                    f"{path} does not name {', '.join(sorted(missing))}; an administrator must be "
                    "able to repair what the installer protected")
            for sid, mask in entries:
                if str(sid) in allowed and int(mask) & FILE_ALL_ACCESS != FILE_ALL_ACCESS:
                    problems.append(
                        f"{path} grants {sid} 0x{int(mask):08x}, not full control")
        return problems


def real_windows_acl_api() -> WindowsAclApi:
    """The one public way to reach the pywin32 `WindowsAclApi`.

    Exists so a second subject needing effective rights — the patch compartment — reuses this
    implementation instead of growing its own SID/DACL code. Two of those drift, and the newer is
    the one nobody exercises on a real box.
    """
    return _RealWindowsAclApi()  # pragma: no cover - platform-specific


def platform_protector(*, service_uid: int | None = None, service_gid: int | None = None,
                       web_sid: str | None = None, scheduler_sid: str | None = None,
                       pre_service: bool = False):
    if os.name == "nt":  # pragma: no cover - platform-specific
        if pre_service:
            # Explicit, and it refuses to be half of itself: a request that asks for pre-service
            # protection while also naming a service account is describing two different moments.
            if web_sid or scheduler_sid:
                raise ProtectionFailed(
                    "pre-service protection was requested together with a service account; the "
                    "service SIDs do not exist yet and this mode grants none")
            return WindowsPreServiceProtector()
        if not web_sid:
            # ONE service, one SID (packet 1361-01, round 3). It used to require both; the
            # standalone scheduler service is retired, so demanding its SID would refuse every
            # current installation. `scheduler_sid` stays accepted for a box that still carries the
            # retired service while the upgrade that removes it runs.
            raise ProtectionFailed("the Windows protector needs the web service SID")
        return WindowsLayoutProtector(web_sid=web_sid, scheduler_sid=scheduler_sid)
    if service_uid is None or service_gid is None:
        raise ProtectionFailed("the POSIX protector needs the service uid and gid")
    return PosixLayoutProtector(service_uid=service_uid, service_gid=service_gid)
