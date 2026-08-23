"""The authoritative installation manifest and its generations (packet 1246-01, deliverable 3).

Three properties, each with a failure it exists to prevent:

**Durable replacement.** ``validate → guard → stage → fsync → keep previous → replace → fsync dir``.
A crash at any point leaves either the complete old manifest or the complete new one, and never a
truncated file that validates far enough to be believed.

**One retained generation.** The manifest before this operation stays on disk as ``.prev`` until the
operation *commits*. That is what makes a lifecycle rollback possible without re-deriving policy
from a machine that is halfway through being changed. ``commit()`` drops it; ``rollback()`` restores
it.

**Compare-and-swap.** ``write`` takes the generation the caller believes is current and refuses if
the on-disk manifest has moved. Two lifecycle tools can both produce a complete valid manifest from
the same starting point; without the token, the second silently discards the first one's policy —
which is precisely the drift D2 exists to stop.

The application gets ``read_view()``: a deeply read-only mapping. It cannot reach a write path at
all, because every mutator here demands a **held** ``LifecycleLock`` that application code has no way
to be holding.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .atomic import _fsync_dir, atomic_write_bytes, atomic_write_text
from .errors import GenerationConflict, LockNotHeld, RecordInvalid, RecordMissing
from .layout import LifecycleLayout
from .lock import require_lock
from .schema import (
    DEFAULT_MANIFEST_RELPATH,
    InstallationManifest,
    canonical_relative_path,
    same_path,
)
from .secret_guard import assert_no_secrets

MANIFEST_FILE_MODE = 0o644
MANIFEST_DIR_MODE = 0o755
PREV_SUFFIX = ".prev"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


class ManifestStore:
    """Reads and writes one installation's manifest inside its ``InstallDir``."""

    def __init__(
        self,
        install_dir: Path | str,
        relative_path: str = DEFAULT_MANIFEST_RELPATH,
        *,
        layout: LifecycleLayout | None = None,
    ):
        """``layout`` is the machine this store belongs to, and it is what makes a write possible.

        A store opened WITHOUT one is a reader: ``read``/``read_view``/``generation`` work, every
        mutator refuses. That is deliberate — the CLI and the locator's verification step open
        stores by path alone and must never gain a write path by doing so, while a real lifecycle
        operation always has the layout in hand.
        """
        self._layout = layout
        self._install_dir = Path(install_dir)
        self._relative = canonical_relative_path(
            relative_path, field_name="manifest_relative_path"
        )
        self._path = self._install_dir / self._relative
        self._prev = self._path.with_name(self._path.name + PREV_SUFFIX)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def previous_path(self) -> Path:
        return self._prev

    @property
    def relative_path(self) -> str:
        return self._relative

    def exists(self) -> bool:
        return self._path.exists()

    def _authority(self, lock: object, action: str):
        """Accept only a held lock for THIS machine's lifecycle state.

        ``require_lock`` proves a lock is held, never that it is the right one. A direct probe
        confirmed the gap an independent review named: a lock rooted under some other tree
        authorized writing this manifest and publishing this locator. Binding closes it.
        """
        if self._layout is None:
            raise LockNotHeld(
                f"{action} requires a ManifestStore opened with its LifecycleLayout; "
                "this one was opened read-only"
            )
        held = require_lock(lock, action)
        if held.layout != self._layout:
            raise LockNotHeld(
                f"{action} requires the lifecycle lock for {self._layout.lock_file}, "
                f"not {held.layout.lock_file}"
            )
        return held

    def has_previous_generation(self) -> bool:
        return self._prev.exists()

    def _load(self, path: Path) -> InstallationManifest:
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise RecordMissing(f"no CORPUSfm manifest at {path}") from exc
        except OSError as exc:
            raise RecordInvalid(f"manifest at {path} is unreadable: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise RecordInvalid(f"manifest at {path} is not valid JSON: {exc}") from exc
        return InstallationManifest.from_dict(data)

    def read(self) -> InstallationManifest:
        return self._load(self._path)

    def read_previous(self) -> InstallationManifest:
        return self._load(self._prev)

    def read_view(self) -> Mapping[str, Any]:
        """The application's window onto lifecycle state: deeply read-only, no write path."""
        return _freeze(self.read().to_dict())

    def generation(self) -> int:
        """The current on-disk generation, or ``0`` when no manifest exists yet."""
        try:
            return self.read().generation
        except RecordMissing:
            return 0

    def write(
        self,
        manifest: InstallationManifest,
        *,
        lock: object,
        expected_generation: int,
    ) -> InstallationManifest:
        """Validate, stage, retain the previous generation, then atomically replace.

        ``expected_generation`` is ``0`` for the first write of a new installation.
        """
        self._authority(lock, "writing the installation manifest")
        current = self.generation()
        if current != expected_generation:
            raise GenerationConflict(
                f"manifest generation moved: expected {expected_generation}, on disk {current}. "
                "Another lifecycle operation wrote this manifest; re-read before writing."
            )
        proposed = manifest.with_generation(expected_generation + 1)
        proposed = proposed.validated()
        self._assert_addresses_this_store(proposed)
        self._assert_identity_is_immutable(proposed)
        payload = proposed.to_dict()
        assert_no_secrets(payload, what="the installation manifest")

        # Retain the generation this OPERATION started from, not the previous WRITE. An operation
        # that writes twice would otherwise leave `.prev` holding its own intermediate state, and
        # a rollback would restore the half-done thing it was supposed to undo.
        #
        # Published ATOMICALLY, not copied. `shutil.copy2` writes straight onto `.prev`; a planted
        # failure mid-copy left `.prev` holding `{partial`, and because the file then EXISTED every
        # later write preserved that poisoned rollback target. The retained generation needs the
        # same stage-flush-replace treatment as the manifest it is a rollback for.
        if self._path.exists() and not self._prev.exists():
            atomic_write_bytes(
                self._prev,
                self._path.read_bytes(),
                mode=MANIFEST_FILE_MODE,
                dir_mode=MANIFEST_DIR_MODE,
            )

        atomic_write_text(
            self._path,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            mode=MANIFEST_FILE_MODE,
            dir_mode=MANIFEST_DIR_MODE,
        )
        return proposed

    def _assert_addresses_this_store(self, manifest: InstallationManifest) -> None:
        """The manifest must describe the tree it lives in.

        A store is addressed BY its install directory, so a manifest naming a different one is
        either a copy from another box or a relocation that was never allowed (paths are immutable
        after installation, parent load-bearing constraint 2).
        """
        if not same_path(manifest.paths.install_dir, str(self._install_dir)):
            raise RecordInvalid(
                f"manifest declares install_dir {manifest.paths.install_dir} but lives under "
                f"{self._install_dir}; a lifecycle record must describe its own installation"
            )

    def _assert_identity_is_immutable(self, proposed: InstallationManifest) -> None:
        """An installation's ID and software root never change under a published locator.

        Compare-and-swap alone only proves nobody else wrote in between; it does not stop THIS
        writer from replacing the record with a different installation's, which would leave the
        published locator pointing at a manifest that contradicts it.
        """
        try:
            existing = self.read()
        except (RecordMissing, RecordInvalid):
            return
        if existing.installation_id != proposed.installation_id:
            raise RecordInvalid(
                f"refusing to change installation_id {existing.installation_id} -> "
                f"{proposed.installation_id}; relocation requires uninstall and reinstall"
            )
        if not same_path(existing.paths.install_dir, proposed.paths.install_dir):
            raise RecordInvalid(
                f"refusing to change install_dir {existing.paths.install_dir} -> "
                f"{proposed.paths.install_dir}; installation paths are immutable"
            )

    def commit(self, *, lock: object) -> None:
        """End the operation: the retained previous generation is no longer needed."""
        self._authority(lock, "committing the installation manifest")
        try:
            self._prev.unlink()
        except FileNotFoundError:
            return
        _fsync_dir(self._path.parent)

    def rollback(self, *, lock: object) -> InstallationManifest:
        """Restore the retained previous generation and return it."""
        self._authority(lock, "rolling back the installation manifest")
        if not self._prev.exists():
            raise RecordMissing(
                f"no retained generation at {self._prev}; nothing to roll back to"
            )
        restored = self.read_previous()
        atomic_write_text(
            self._path,
            json.dumps(restored.to_dict(), indent=2, sort_keys=True) + "\n",
            mode=MANIFEST_FILE_MODE,
            dir_mode=MANIFEST_DIR_MODE,
        )
        os.unlink(str(self._prev))
        _fsync_dir(self._path.parent)
        return restored
