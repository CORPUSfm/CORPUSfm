"""The fixed operating-system locations an installation uses (packet 1246-03, decision E1).

`layout.py` names the three *machine-wide lifecycle* locations — locator, lock, journal. This module
names the larger set the **application** needs: config, state, secrets, logs, run. They are the same
roots, and that is not a coincidence to be maintained by hand: `assert_agrees_with_lifecycle_layout`
proves it, so a change to one that forgets the other fails the build rather than drifting.

**No environment override, no argv override**, for exactly the reason `layout.py` gives: a location an
unprivileged process can redirect is not machine-wide authority. The functions take an explicit root
so a test can build the same shape under a temp dir, which is a parameter, not an override — nothing
reads it from the outside world.

These are *derived OS locations*, never a second selectable `ConfigHome` (parent D3). `InstallDir` is
the one selected software root; everything here follows from the platform, not from a choice.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import RecordInvalid
from .layout import POSIX, WINDOWS, LifecycleLayout, posix_layout, windows_layout

# The InstallDir subtrees (parent D3). Administrator-owned, not runtime-writable.
INSTALL_SUBTREES: tuple[str, ...] = ("app", "runtime", "bin", "installer", "manifest")

DEFAULT_POSIX_INSTALL_DIR = "/opt/CORPUSfm"
DEFAULT_WINDOWS_INSTALL_DIR = r"C:\Program Files\CORPUSfm"


@dataclass(frozen=True)
class OsLayout:
    """Where an installation's mutable state lives, by operating-system convention."""

    flavour: str
    config_dir: Path
    state_dir: Path
    secrets_dir: Path
    log_dir: Path
    run_dir: Path

    def as_paths_fields(self) -> dict[str, str]:
        """The subset of `schema.PathsBlock` this layout supplies, ready to record."""
        return {
            "config_dir": str(self.config_dir),
            "state_dir": str(self.state_dir),
            "secrets_dir": str(self.secrets_dir),
            "log_dir": str(self.log_dir),
            "run_dir": str(self.run_dir),
        }

    def all_dirs(self) -> tuple[Path, ...]:
        return (self.config_dir, self.state_dir, self.secrets_dir, self.log_dir, self.run_dir)


def posix_os_layout(root: Path | str = Path("/")) -> OsLayout:
    base = Path(root)
    return OsLayout(
        flavour=POSIX,
        config_dir=base / "etc" / "corpusfm",
        state_dir=base / "var" / "lib" / "corpusfm" / "state",
        secrets_dir=base / "var" / "lib" / "corpusfm" / "secrets",
        log_dir=base / "var" / "log" / "corpusfm",
        run_dir=base / "run" / "corpusfm",
    )


def windows_os_layout(program_data: Path | str = Path(r"C:\ProgramData")) -> OsLayout:
    base = Path(program_data) / "CORPUSfm"
    return OsLayout(
        flavour=WINDOWS,
        config_dir=base / "config",
        state_dir=base / "state",
        secrets_dir=base / "secrets",
        log_dir=base / "logs",
        run_dir=base / "run",
    )


def platform_os_layout() -> OsLayout:
    """The real layout for this machine. Reads no configuration and accepts no override."""
    if os.name == "nt":  # pragma: no cover - platform-specific
        return windows_os_layout()
    return posix_os_layout()


def assert_agrees_with_lifecycle_layout(
    os_layout: OsLayout, lifecycle: LifecycleLayout
) -> None:
    """The lifecycle locations must sit inside the OS locations that describe the same machine.

    Two modules naming the same directories in two sets of literals is a drift generator. This turns
    the relationship into something checkable: the journal belongs under `state`, the lock under
    `run`, and on POSIX the locator under `config`. Windows keeps its locator in HKLM, so there is no
    directory to compare — that asymmetry is real and is stated rather than papered over.
    """
    if os_layout.flavour != lifecycle.kind:
        raise RecordInvalid(
            f"os layout is {os_layout.flavour} but the lifecycle layout is {lifecycle.kind}"
        )
    if lifecycle.journal_file.parent != os_layout.state_dir:
        raise RecordInvalid(
            f"the lifecycle journal at {lifecycle.journal_file} is not inside the state directory "
            f"{os_layout.state_dir}"
        )
    if lifecycle.lock_file.parent != os_layout.run_dir:
        raise RecordInvalid(
            f"the lifecycle lock at {lifecycle.lock_file} is not inside the run directory "
            f"{os_layout.run_dir}"
        )
    if os_layout.flavour == POSIX:
        if lifecycle.locator_dir != os_layout.config_dir:
            raise RecordInvalid(
                f"the POSIX locator directory {lifecycle.locator_dir} is not the config directory "
                f"{os_layout.config_dir}"
            )


def paired_layouts(*, flavour: str, root: Path | str | None = None
                   ) -> tuple[OsLayout, LifecycleLayout]:
    """Both layouts for one flavour, already proven to agree. The pair a caller should want."""
    if flavour == POSIX:
        os_l = posix_os_layout(Path("/") if root is None else root)
        life = posix_layout(Path("/") if root is None else root)
    elif flavour == WINDOWS:
        base = Path(r"C:\ProgramData") if root is None else root
        os_l = windows_os_layout(base)
        life = windows_layout(base)
    else:
        raise RecordInvalid(f"unknown platform flavour {flavour!r}")
    assert_agrees_with_lifecycle_layout(os_l, life)
    return os_l, life


def os_layout_for_lifecycle(lifecycle: LifecycleLayout) -> OsLayout:
    """Reconstruct the paired OS layout from a lifecycle layout, including test roots."""
    if lifecycle.kind == POSIX:
        if lifecycle.locator_dir is None:
            raise RecordInvalid("a POSIX lifecycle layout has no locator directory")
        root = lifecycle.locator_dir.parent.parent
    elif lifecycle.kind == WINDOWS:
        # <ProgramData>/CORPUSfm/run/lifecycle.lock
        root = lifecycle.lock_file.parent.parent.parent
    else:
        raise RecordInvalid(f"unknown platform flavour {lifecycle.kind!r}")
    os_l, paired = paired_layouts(flavour=lifecycle.kind, root=root)
    if paired != lifecycle:
        raise RecordInvalid("the lifecycle layout is not the canonical paired machine layout")
    return os_l


def default_install_dir(flavour: str) -> str:
    if flavour == POSIX:
        return DEFAULT_POSIX_INSTALL_DIR
    if flavour == WINDOWS:
        return DEFAULT_WINDOWS_INSTALL_DIR
    raise RecordInvalid(f"unknown platform flavour {flavour!r}")
