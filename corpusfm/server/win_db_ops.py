"""Windows direct-filesystem DB ops — the LocalSystem equivalent of the Linux cfm-db-helper.

On Linux the unprivileged ``corpusfm`` service cannot write the fmserver-owned Databases dir, so a
scoped sudo broker (``cfm-db-helper``) performs the privileged file moves. On Windows the CORPUSfm
services run as **LocalSystem**, which has ``FullControl`` on the FMS Databases dir (probed live
2026-06-25, WS2022 + FMS 2025) — so the same copy-out / place / remove operations are plain
filesystem calls, no broker and no sudoers.

This module is therefore the Windows arm of the platform split in ``db_helper`` — same (ok, msg)
contract, never raises. ``place`` does a **same-volume atomic swap** (copy beside the target, then
``os.replace``) so an interrupted write never leaves a partial hosted file, and it works even when
the caller staged on a different volume.

STORAGE-DB-GUARDED backstop: the copy-out / place / remove ops always refuse the CORPUSfm storage DB
(``_gate``), so an FS op can never touch it even if a caller skipped the up-front check. The apply
POLICY (which non-storage targets are allowed) is NOT decided here — it lives in the unified
``db_helper.check_apply_target`` compartment gate (packet 1066), checked once before the DB is closed.
The old Windows name-allowlist (``windows_apply_allowlist`` + the playground defaults) was RETIRED by
1066 (option A): folder-scoped on both platforms when the restriction is on, any-non-storage when off.
A stale ``windows_apply_allowlist`` in install.yaml is ignored (logged once as superseded).
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

log = logging.getLogger("corpusfm.win_db_ops")
_warned_superseded_allowlist = False


def is_windows() -> bool:
    return os.name == "nt"


def _norm(name: str) -> str:
    """Canonical compare form for a DB name: trimmed, .fmp12-insensitive, lower-cased — matching
    install.is_storage_database's normalization so the two guards agree."""
    n = (name or "").strip()
    return (n[:-6] if n.lower().endswith(".fmp12") else n).lower()


def _note_superseded_allowlist() -> None:
    """One-time back-compat notice: a ``windows_apply_allowlist`` left in install.yaml no longer gates
    anything (packet 1066 retired it in favor of the folder-scoped compartment). Log once so an admin
    who relied on it learns it's ignored, without spamming every apply."""
    global _warned_superseded_allowlist
    if _warned_superseded_allowlist:
        return
    try:
        from corpusfm.install import read_install_config
        if read_install_config().get("windows_apply_allowlist"):
            log.info("windows_apply_allowlist in install.yaml is SUPERSEDED by the apply compartment "
                     "gate (packet 1066) and is ignored — apply targets are scoped by folder, not name.")
    except Exception:
        pass
    _warned_superseded_allowlist = True


def databases_dir() -> "Path | None":
    """Locate the FMS Databases directory. Override with CORPUSFM_FMS_DATABASES_DIR (tests/ops).

    Derived from fmsadmin's location: ``<FMS root>\\Database Server\\fmsadmin.exe`` →
    ``<FMS root>\\Data\\Databases``. Returns None when it can't be resolved.
    """
    override = os.environ.get("CORPUSFM_FMS_DATABASES_DIR")
    if override:
        p = Path(override)
        return p if p.is_dir() else None
    try:
        from corpusfm.server.patch_apply import find_fmsadmin
        fa = find_fmsadmin()
    except Exception:
        fa = None
    if fa is None:
        return None
    cand = Path(fa).resolve().parent.parent / "Data" / "Databases"
    return cand if cand.is_dir() else None


def available() -> bool:
    """True when the Windows direct-FS path is usable: the FMS Databases dir resolves. The actual
    write capability is the LocalSystem service identity's FullControl on that dir (probed); we do
    NOT write a probe file here (readiness polls this, and the Databases dir is FMS-scanned). Only
    consulted from platform-gated branches (db_helper / readiness on Windows)."""
    return databases_dir() is not None


def _find_hosted(db_name: str) -> "Path | None":
    """On-disk path of a hosted ``<db_name>.fmp12`` — top level or one subfolder deep (FMS scans
    and hosts subfolders by name). None if not present."""
    root = databases_dir()
    if root is None:
        return None
    direct = root / f"{db_name}.fmp12"
    if direct.is_file():
        return direct
    try:
        for sub in root.iterdir():
            if sub.is_dir():
                cand = sub / f"{db_name}.fmp12"
                if cand.is_file():
                    return cand
    except Exception:
        pass
    return None


def _gate(db_name: str) -> "tuple[bool, str] | None":
    """FS-op backstop: None if the op may proceed, else the (False, reason) refusal. Refuses the
    storage DB ALWAYS — an FS op must never touch CORPUSfm's own data even if a caller skipped the
    up-front check. The compartment POLICY (which non-storage targets are allowed) is decided once,
    up front, by db_helper.check_apply_target (packet 1066) — not re-litigated per FS op, mirroring
    the Linux broker which also doesn't re-check the compartment. It DOES reject a non-basename name
    (path separators / ``..``) as defense-in-depth: retiring the name-allowlist removed the only db_name
    validation, and ``_find_hosted``/``place`` build ``root / f"{db_name}.fmp12"`` with no confinement,
    so a ``..\\`` name could escape the Databases dir and write as LocalSystem (packet 1000/1066 finding
    2). The unified db_helper gate rejects it up front; this backstop can't be skipped."""
    _note_superseded_allowlist()
    n = (db_name or "").strip()
    if not n or "/" in n or "\\" in n or ".." in n:
        return (False, f"refused: '{db_name}' is not a valid database name (no path separators or '..').")
    try:
        from corpusfm.install import is_storage_database
        if is_storage_database(db_name):
            return (False, f"refused: '{db_name}' is the CORPUSfm storage database — never a target")
    except Exception:
        pass
    return None


def check_apply_target(db_name: str) -> tuple[bool, str]:
    """Back-compat thin wrapper: the storage-DB FS backstop as an (ok, reason) pair. The real
    apply POLICY is db_helper.check_apply_target (the unified compartment gate, packet 1066) — this
    stays only so any legacy Windows caller gets the storage refusal; it is not the policy authority."""
    g = _gate(db_name)
    return (True, "") if g is None else g


def copy_out(db_name: str, dest: "str | Path") -> tuple[bool, str]:
    """Copy a hosted DB's .fmp12 OUT to a caller-owned dest so the service can read/patch it."""
    g = _gate(db_name)
    if g is not None:
        return g
    src = _find_hosted(db_name)
    if src is None:
        return False, f"no such hosted database: '{db_name}'"
    try:
        shutil.copy2(str(src), str(dest))
        return True, f"copied '{db_name}' -> {dest}"
    except Exception as exc:
        return False, f"copy-out failed: {exc}"


def place(src: "str | Path", db_name: str) -> tuple[bool, str]:
    """Place a (patched) .fmp12 INTO the Databases dir as the hosted db_name, via a same-volume
    atomic swap (copy beside the target, then os.replace). Targets the file's existing location
    (subfolder honored); a brand-new name lands top-level."""
    g = _gate(db_name)
    if g is not None:
        return g
    root = databases_dir()
    if root is None:
        return False, "FMS Databases dir not found"
    src = Path(src)
    if not src.is_file():
        return False, f"no such source file: '{src}'"
    target = _find_hosted(db_name) or (root / f"{db_name}.fmp12")
    tmp = target.with_name(f".{target.stem}.cfmswap.{os.getpid()}")
    try:
        shutil.copy2(str(src), str(tmp))     # same dir as target → guaranteed same volume
        os.replace(str(tmp), str(target))    # atomic on Windows when source+dest share a volume
        return True, f"placed '{db_name}'"
    except Exception as exc:
        try:
            tmp.unlink()
        except Exception:
            pass
        return False, f"place failed: {exc}"


def remove(db_name: str) -> tuple[bool, str]:
    """Remove db_name.fmp12 from the Databases dir (sandbox/playground teardown)."""
    g = _gate(db_name)
    if g is not None:
        return g
    p = _find_hosted(db_name)
    if p is None:
        return True, f"'{db_name}' not present"
    try:
        p.unlink()
        return True, f"removed '{db_name}'"
    except Exception as exc:
        return False, f"remove failed: {exc}"
