"""The stable machine-wide locator, on both platforms (packet 1246-01, deliverable 2).

The locator answers one question — *is a CORPUSfm installed on this machine, and where is its
manifest* — from a place a caller does not have to already know. That is exactly what today's
`install.yaml` cannot do: Linux keeps it under `INSTALL_DIR` and Windows under a selectable
`ConfigHome`, so finding it requires knowing the path it exists to supply.

**Ownership is enforced here, not deferred.** Deliverable 2 gives this child "administrator-only
atomic file" and "write/delete requires elevation", so this module refuses the conditions that would
make those words false rather than assuming a well-behaved filesystem: a symlinked locator directory
or file, a directory owned by someone else, a group- or world-writable directory, and a failure to
establish the required mode. 1246-03 owns the OS layout those paths sit in; it does not own whether
this file is safe to trust, and an earlier draft that silently ignored a failed `chmod` was writing a
security claim it had not checked.

**Publication is ordered, and the order is a rule, not a habit.** A locator is published only after
its manifest exists, validates, and agrees with it — read back here, not taken on a caller's word. A
locator pointing at nothing converts "not installed" into "installed and broken". It is removed last,
after everything it could help find is gone.

**Two generations on Windows, because one is not a crash boundary.** A registry key holds several
values and `winreg` offers no transaction across them (the KTM APIs are deprecated). Clearing a
single commit sentinel before overwriting — the first attempt — turned a crash from "missing" into
"invalid", which is honest but still loses the last-known-good locator. So a record is written into
the *unused* one of two numbered slots, and commitment moves by rewriting one `committed_slot` value.
Until that single write lands, the previous generation is complete and still committed; after it, the
new one is. There is no instant at which neither is readable.
"""

from __future__ import annotations

import json
import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol

from .atomic import atomic_write_text
from .errors import LockNotHeld, RecordInvalid, RecordMissing
from .layout import POSIX, WINDOWS, LifecycleLayout
from .lock import require_lock
from .privilege import require_elevation
from .schema import LocatorRecord, assert_identity_agrees
from .secret_guard import assert_no_secrets

LOCATOR_FILE_MODE = 0o644
LOCATOR_DIR_MODE = 0o755

COMMITTED_SLOT_VALUE = "committed_slot"
SLOTS: tuple[str, str] = ("0", "1")


class LocatorAdapter(ABC):
    """Read/publish/remove one machine's locator. Two implementations, one contract."""

    def __init__(self, layout: LifecycleLayout):
        self._layout = layout

    @property
    def layout(self) -> LifecycleLayout:
        return self._layout

    @abstractmethod
    def exists(self) -> bool: ...

    @abstractmethod
    def read(self) -> LocatorRecord:
        """Return the record, or raise ``RecordMissing`` / ``RecordInvalid``."""

    @abstractmethod
    def _write(self, record: LocatorRecord) -> None: ...

    @abstractmethod
    def _remove(self) -> None: ...

    @abstractmethod
    def describe(self) -> str: ...

    def _authority(self, lock: object, action: str):
        """Accept only a held lock for THIS machine's lifecycle state."""
        held = require_lock(lock, action)
        if held.layout != self._layout:
            raise LockNotHeld(
                f"{action} requires the lifecycle lock for {self._layout.lock_file}, "
                f"not {held.layout.lock_file}"
            )
        return held

    def publish(self, record: LocatorRecord, *, lock: object) -> LocatorRecord:
        """Publish the locator — only after reading back the manifest it names.

        Takes the held lifecycle lock like every other mutator: publishing races an installer or
        uninstaller working on the same installation otherwise, and D5's "one lifecycle" means one
        lock across all of them, not one per object.

        The first draft took the caller's word for durability (``manifest_is_durable: bool``). An
        independent review was right that this left the ordering rule *asserted* rather than
        *enforced*: a caller passing ``True`` too early would publish a locator pointing at nothing.
        The record already carries everything needed to check it, so it is checked.
        """
        self._authority(lock, "publishing the CORPUSfm locator")
        record = record.validated()
        assert_no_secrets(record.to_dict(), what="the lifecycle locator")
        self._verify_manifest(record)
        require_elevation("publishing the CORPUSfm locator")
        self._write(record)
        return record

    def remove(self, *, lock: object) -> None:
        """Remove the locator. The LAST step of a removal, and the caller owns proving that.

        Whether nothing else remains is 1246-09's question — it owns the ownership inventory and the
        pending-uninstall record. This layer enforces what it can see: the lock and elevation.
        """
        self._authority(lock, "removing the CORPUSfm locator")
        require_elevation("removing the CORPUSfm locator")
        self._remove()

    @staticmethod
    def _verify_manifest(record: LocatorRecord) -> None:
        from .manifest import ManifestStore

        store = ManifestStore(record.install_dir, record.manifest_relative_path)
        try:
            manifest = store.read()
        except RecordMissing as exc:
            raise RecordInvalid(
                f"refusing to publish a locator before its manifest is durable: nothing at "
                f"{store.path}"
            ) from exc
        assert_identity_agrees(record, manifest, manifest_path=str(store.path))


class PosixFileLocator(LocatorAdapter):
    def __init__(self, layout: LifecycleLayout):
        super().__init__(layout)
        if layout.locator_dir is None:
            raise RecordInvalid("a posix layout must name its locator directory")
        self._dir = Path(layout.locator_dir)
        self._file = self._dir / "locator.json"

    def describe(self) -> str:
        return str(self._file)

    def exists(self) -> bool:
        return self._file.exists()

    def read(self) -> LocatorRecord:
        try:
            raw = self._file.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise RecordMissing(f"no CORPUSfm locator at {self._file}") from exc
        except OSError as exc:
            raise RecordInvalid(f"locator at {self._file} is unreadable: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise RecordInvalid(f"locator at {self._file} is not valid JSON: {exc}") from exc
        return LocatorRecord.from_dict(data)

    def _assert_safe_location(self) -> None:
        """Refuse to write a locator into a place that cannot carry its ownership claim.

        Each refusal answers a way the file could exist and still not mean what the rest of this
        package assumes it means. A symlinked directory or file redirects an elevated write
        somewhere the attacker chose; a directory owned by someone else, or writable by group or
        other, means a non-administrator can replace the record after we have written it.
        """
        if self._dir.is_symlink():
            raise RecordInvalid(
                f"refusing to publish: the locator directory {self._dir} is a symlink"
            )
        if self._dir.exists():
            if not self._dir.is_dir():
                raise RecordInvalid(
                    f"refusing to publish: {self._dir} exists and is not a directory"
                )
            info = os.stat(self._dir, follow_symlinks=False)
            if info.st_uid != os.geteuid():
                raise RecordInvalid(
                    f"refusing to publish: the locator directory {self._dir} is owned by uid "
                    f"{info.st_uid}, not by the administrator performing this operation"
                )
            if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RecordInvalid(
                    f"refusing to publish: the locator directory {self._dir} is writable by group "
                    "or other, so the record it holds is not administrator-only"
                )
        if self._file.is_symlink():
            raise RecordInvalid(
                f"refusing to publish: the locator {self._file} is a symlink"
            )
        if self._file.exists():
            info = os.stat(self._file, follow_symlinks=False)
            if info.st_uid != os.geteuid():
                raise RecordInvalid(
                    f"refusing to publish: the existing locator {self._file} is owned by uid "
                    f"{info.st_uid}, not by the administrator performing this operation"
                )

    def _assert_established_permissions(self) -> None:
        """Verify what was actually established. A `chmod` that failed is not a mode that holds."""
        info = os.stat(self._file, follow_symlinks=False)
        actual = stat.S_IMODE(info.st_mode)
        if actual != LOCATOR_FILE_MODE:
            raise RecordInvalid(
                f"refusing to publish: the locator {self._file} ended up mode {actual:o}, not "
                f"{LOCATOR_FILE_MODE:o}; its permissions could not be established"
            )
        dir_mode = stat.S_IMODE(os.stat(self._dir, follow_symlinks=False).st_mode)
        if dir_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RecordInvalid(
                f"refusing to publish: the locator directory {self._dir} ended up mode "
                f"{dir_mode:o}, writable beyond its owner"
            )

    def _write(self, record: LocatorRecord) -> None:
        self._assert_safe_location()
        atomic_write_text(
            self._file,
            json.dumps(record.to_dict(), indent=2, sort_keys=True) + "\n",
            mode=LOCATOR_FILE_MODE,
            dir_mode=LOCATOR_DIR_MODE,
        )
        try:
            self._assert_established_permissions()
        except RecordInvalid:
            # A locator whose permissions we could not establish must not survive as an
            # authoritative record; leaving it would publish exactly the claim we just disproved.
            try:
                self._file.unlink()
            except OSError:
                pass
            raise

    def _remove(self) -> None:
        try:
            self._file.unlink()
        except FileNotFoundError:
            return
        try:
            os.rmdir(self._dir)
        except OSError:
            pass


class RegistryBackend(Protocol):
    """The slice of the registry this package needs, so the Windows path is testable off-Windows."""

    def read_values(self, root: str, subkey: str) -> dict[str, Any] | None: ...

    def write_values(self, root: str, subkey: str, values: dict[str, Any]) -> None: ...

    def flush(self, root: str, subkey: str) -> None: ...

    def delete_key(self, root: str, subkey: str) -> None: ...

    def delete_empty_key(self, root: str, subkey: str) -> None: ...


class InMemoryRegistry:
    """A registry double. Records the ORDER of writes, which is what the slot switch needs proved."""

    def __init__(self) -> None:
        self.keys: dict[tuple[str, str], dict[str, Any]] = {}
        self.flushes: list[tuple[str, str]] = []
        self.write_log: list[tuple[str, str, tuple[str, ...]]] = []

    def read_values(self, root: str, subkey: str) -> dict[str, Any] | None:
        found = self.keys.get((root, subkey))
        return dict(found) if found is not None else None

    def write_values(self, root: str, subkey: str, values: dict[str, Any]) -> None:
        self.keys.setdefault((root, subkey), {}).update(values)
        self.write_log.append((root, subkey, tuple(values)))

    def flush(self, root: str, subkey: str) -> None:
        self.flushes.append((root, subkey))

    def delete_key(self, root: str, subkey: str) -> None:
        self.keys.pop((root, subkey), None)

    def delete_empty_key(self, root: str, subkey: str) -> None:
        values = self.keys.get((root, subkey))
        prefix = subkey.rstrip("\\") + "\\"
        has_children = any(r == root and k.startswith(prefix) for r, k in self.keys)
        if values == {} and not has_children:
            self.keys.pop((root, subkey), None)


class WinRegBackend:  # pragma: no cover - exercised only on Windows boxes
    """The real HKLM backend. Kept trivial; the behaviour under test lives in the adapter."""

    def _hive(self, root: str):
        import winreg

        return getattr(winreg, root)

    def read_values(self, root: str, subkey: str) -> dict[str, Any] | None:
        import winreg

        try:
            handle = winreg.OpenKey(self._hive(root), subkey, 0, winreg.KEY_READ)
        except FileNotFoundError:
            return None
        values: dict[str, Any] = {}
        with handle:
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(handle, index)
                except OSError:
                    break
                values[name] = value
                index += 1
        return values

    def write_values(self, root: str, subkey: str, values: dict[str, Any]) -> None:
        import winreg

        with winreg.CreateKeyEx(self._hive(root), subkey, 0, winreg.KEY_WRITE) as handle:
            for name, value in values.items():
                kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
                winreg.SetValueEx(handle, name, 0, kind, value)

    def flush(self, root: str, subkey: str) -> None:
        import winreg

        with winreg.OpenKey(self._hive(root), subkey, 0, winreg.KEY_WRITE) as handle:
            winreg.FlushKey(handle)

    def delete_key(self, root: str, subkey: str) -> None:
        import winreg

        try:
            winreg.DeleteKey(self._hive(root), subkey)
        except FileNotFoundError:
            return

    def delete_empty_key(self, root: str, subkey: str) -> None:
        """Remove only a key that has neither values nor children.

        ``RegDeleteKey`` would also remove values held directly by the key, so an ordinary
        ``delete_key`` after a best-effort read is too broad for the parent namespace. Inspect both
        dimensions first; a foreign value or subkey makes this a deliberate no-op.
        """
        import winreg

        try:
            with winreg.OpenKey(self._hive(root), subkey, 0, winreg.KEY_READ) as handle:
                subkeys, values, _modified = winreg.QueryInfoKey(handle)
        except FileNotFoundError:
            return
        if subkeys or values:
            return
        try:
            winreg.DeleteKey(self._hive(root), subkey)
        except (FileNotFoundError, OSError):
            # A concurrent child makes the key non-empty; retaining it is the fail-safe outcome.
            return


class WindowsRegistryLocator(LocatorAdapter):
    """HKLM with two numbered generation slots and one committed pointer."""

    def __init__(self, layout: LifecycleLayout, backend: RegistryBackend):
        super().__init__(layout)
        if layout.registry_root is None or layout.registry_subkey is None:
            raise RecordInvalid("a windows layout must name its registry root and subkey")
        self._root = layout.registry_root
        self._subkey = layout.registry_subkey
        self._backend = backend

    def describe(self) -> str:
        return f"{self._root}\\{self._subkey}"

    def _slot_key(self, slot: str) -> str:
        return f"{self._subkey}\\{slot}"

    def exists(self) -> bool:
        if self._backend.read_values(self._root, self._subkey) is not None:
            return True
        return any(
            self._backend.read_values(self._root, self._slot_key(s)) is not None for s in SLOTS
        )

    def committed_slot(self) -> str | None:
        values = self._backend.read_values(self._root, self._subkey) or {}
        slot = values.get(COMMITTED_SLOT_VALUE)
        return str(slot) if slot is not None and str(slot) in SLOTS else None

    def read(self) -> LocatorRecord:
        slot = self.committed_slot()
        if slot is None:
            if self.exists():
                raise RecordInvalid(
                    f"locator at {self.describe()} has no committed generation — a publication was "
                    "interrupted; re-run the elevated installer rather than trusting it"
                )
            raise RecordMissing(f"no CORPUSfm locator at {self.describe()}")
        values = self._backend.read_values(self._root, self._slot_key(slot))
        if not values:
            raise RecordInvalid(
                f"locator at {self.describe()} points at generation slot {slot}, which is empty"
            )
        return LocatorRecord.from_dict(values)

    def read_slot(self, slot: str) -> LocatorRecord:
        """Read one generation directly. Exists so a test can prove the other one survived."""
        values = self._backend.read_values(self._root, self._slot_key(slot))
        if not values:
            raise RecordMissing(f"generation slot {slot} is empty")
        return LocatorRecord.from_dict(values)

    def _write(self, record: LocatorRecord) -> None:
        current = self.committed_slot()
        target = SLOTS[1] if current == SLOTS[0] else SLOTS[0]
        # Stage the complete new generation in the slot that is NOT committed. Nothing observable
        # changes yet: `committed_slot` still names the previous generation, and it stays fully
        # readable throughout.
        self._backend.write_values(self._root, self._slot_key(target), record.to_dict())
        self._backend.flush(self._root, self._slot_key(target))
        # One value write moves commitment. Before it, the old generation is authoritative; after
        # it, the new one is. There is no state in between.
        self._backend.write_values(self._root, self._subkey, {COMMITTED_SLOT_VALUE: int(target)})
        self._backend.flush(self._root, self._subkey)

    def _remove(self) -> None:
        for slot in SLOTS:
            self._backend.delete_key(self._root, self._slot_key(slot))
        self._backend.delete_key(self._root, self._subkey)
        # Creating ``SOFTWARE\CORPUSfm\Installation`` also creates its CORPUSfm parent. It is part
        # of the locator's footprint, but only while empty: another value or child is foreign and
        # must survive. Measured after a complete Windows uninstall as an otherwise-empty key.
        parent = self._subkey.rsplit("\\", 1)[0] if "\\" in self._subkey else ""
        if parent:
            self._backend.delete_empty_key(self._root, parent)


def locator_for(
    layout: LifecycleLayout, *, registry: RegistryBackend | None = None
) -> LocatorAdapter:
    """Build the locator adapter this layout calls for."""
    if layout.kind == WINDOWS:
        backend = registry if registry is not None else WinRegBackend()
        return WindowsRegistryLocator(layout, backend)
    if layout.kind == POSIX:
        return PosixFileLocator(layout)
    raise RecordInvalid(f"unknown layout kind {layout.kind!r}")
