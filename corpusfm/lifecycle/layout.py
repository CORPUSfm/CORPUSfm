"""Where machine-wide lifecycle state lives (packet 1246-01, parent decisions D2 and D3).

This module NAMES locations. It does not create them, chown them or ACL them — the OS filesystem
layout, the service identities and the ACLs that make those locations correct belong to 1246-03, and
creating them here would be that child's cutover done early and in the wrong place.

**There is no environment or argv override, deliberately.** A lifecycle record whose location can be
redirected by a variable is not machine-wide authority; an unprivileged process that can set an
environment variable could point a later elevated operation at a record it wrote itself. The API
takes a ``LifecycleLayout`` so tests can supply their own; ``platform_layout()`` builds the real one
and reads nothing from the environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

POSIX = "posix"
WINDOWS = "windows"

LOCATOR_FILENAME = "locator.json"
LOCK_FILENAME = "lifecycle.lock"
JOURNAL_FILENAME = "lifecycle-journal.json"

WINDOWS_REGISTRY_ROOT = "HKEY_LOCAL_MACHINE"
WINDOWS_REGISTRY_SUBKEY = r"SOFTWARE\CORPUSfm\Installation"


@dataclass(frozen=True)
class LifecycleLayout:
    """The three machine-wide lifecycle locations, plus which locator adapter serves them."""

    kind: str
    lock_file: Path
    journal_file: Path
    locator_dir: Path | None = None
    registry_root: str | None = None
    registry_subkey: str | None = None

    @property
    def locator_file(self) -> Path | None:
        return None if self.locator_dir is None else self.locator_dir / LOCATOR_FILENAME

    def describe_locator(self) -> str:
        if self.kind == WINDOWS:
            return f"{self.registry_root}\\{self.registry_subkey}"
        return str(self.locator_file)


def posix_layout(root: Path | str = Path("/")) -> LifecycleLayout:
    """The Linux layout. ``root`` exists so a test can build the same shape under a temp dir."""
    base = Path(root)
    return LifecycleLayout(
        kind=POSIX,
        locator_dir=base / "etc" / "corpusfm",
        lock_file=base / "run" / "corpusfm" / LOCK_FILENAME,
        journal_file=base / "var" / "lib" / "corpusfm" / "state" / JOURNAL_FILENAME,
    )


def windows_layout(program_data: Path | str = Path(r"C:\ProgramData")) -> LifecycleLayout:
    """The Windows layout: HKLM for the locator, fixed ProgramData for lock and journal.

    The lock lives under ``run\\`` and the journal under ``state\\`` — the same split as POSIX. It
    was originally both under ``state\\`` (packet 1246-01), which read fine in isolation and became
    wrong once 1246-03 recorded these as *distinct* manifest fields: ``PathsBlock`` requires
    pairwise-disjoint paths, so one directory serving as both the run and state location cannot be
    recorded at all. Safe to change — no installer has ever created either path.
    """
    base = Path(program_data) / "CORPUSfm"
    return LifecycleLayout(
        kind=WINDOWS,
        registry_root=WINDOWS_REGISTRY_ROOT,
        registry_subkey=WINDOWS_REGISTRY_SUBKEY,
        lock_file=base / "run" / LOCK_FILENAME,
        journal_file=base / "state" / JOURNAL_FILENAME,
    )


def platform_layout() -> LifecycleLayout:
    """The real layout for this machine. Reads no configuration and accepts no override."""
    if os.name == "nt":  # pragma: no cover - platform-specific
        return windows_layout()
    return posix_layout()
