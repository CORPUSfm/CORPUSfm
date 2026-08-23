"""Discover hosted FileMaker files on the co-located server.

Stage 1 of the file-centric jobs model (see docs/jobs-per-file-plan.md). The FMS
Admin API PKI `list_databases` returns every hosted `.fmp12`. We normalize the
names (strip the extension) and flag exactly ONE file: CORPUSfm's storage backend
database — the one named in Settings (`install.yaml` `fm_database`). That file is
shown like any other but badged, because the patch tooling refuses it (it holds
CORPUSfm's own data; see `install.is_storage_database`). Every other file —
including the playground/sandbox siblings and the FileMaker samples — is a normal,
unflagged file.

Grounded against the live server (36 hosted files): names arrive WITH `.fmp12`
while the rest of the code (server_configs, OData paths) uses the bare name, and
real filenames contain spaces (e.g. "Admin API Tool", "SSH Keys & JWT").

Public API:
    discover_files() -> list[DiscoveredFile]   # live: PKI → list → classify
    discover_hosted_files() -> list[str]        # live: raw filenames
    classify_all(filenames, *, self_names) -> list[DiscoveredFile]  # pure
    is_self_name(name) -> bool                            # is this the storage DB?
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

logger = logging.getLogger(__name__)


class FileDiscoveryUnavailable(RuntimeError):
    """Live discovery could not be PERFORMED (e.g. no admin PKI key configured). Distinct from a
    successful scan that returned zero files — callers must NOT treat this as 'the host is empty'
    (that would false-flag every tracked file as `missing`, e.g. on a Tier-1 box)."""


@dataclass
class DiscoveredFile:
    name: str        # bare name, no .fmp12 — the identity used everywhere else
    filename: str    # exactly as FMS returned it (may carry .fmp12)
    is_self: bool     # the storage backend DB (from Settings) — shown, badged, patch-guarded


def strip_ext(filename: str) -> str:
    return filename[:-6] if filename.lower().endswith(".fmp12") else filename


def classify(filename: str, *, self_names: set[str]) -> DiscoveredFile:
    bare = strip_ext(filename)
    is_self = bare.lower() in {s.lower() for s in self_names}
    return DiscoveredFile(name=bare, filename=filename, is_self=is_self)


def is_self_name(name: str) -> bool:
    """Pure: is this (bare) file CORPUSfm's storage backend database (the one in Settings)?
    The single flagged file — recomputed from the name so the read-only view needs no live
    discovery. Same authority as the patch guard (`install.is_storage_database`)."""
    try:
        from corpusfm.install import is_storage_database
        return is_storage_database(name)
    except Exception:
        return False


def classify_all(filenames: Iterable[str], *, self_names: set[str]) -> list[DiscoveredFile]:
    """Normalize + classify a list of FMS filenames; skip blanks; sort by name."""
    out = [classify(f, self_names=self_names) for f in filenames if f and f.strip()]
    return sorted(out, key=lambda d: d.name.lower())


def _self_names() -> set[str]:
    """The bare name of the storage backend DB (from Settings), or empty — the only flag."""
    try:
        from corpusfm.install import storage_database_name
        sdb = storage_database_name()
        return {strip_ext(sdb)} if sdb else set()
    except Exception:
        return set()


def discover_hosted_files() -> list[str]:
    """Live: PKI-auth → list_databases → logout. Returns raw filenames (with .fmp12).

    Raises FileDiscoveryUnavailable when this installation's Admin API identity cannot be used —
    carrying the resolver's own REASON, so "none was published", "it is there and unreadable" and
    "the store disagrees with the manifest" reach the operator as different facts (packet 1247).
    A scan that was not performed is never an empty host. Pairs every auth with a logout (FMS caps
    concurrent Admin API sessions — error 956).

    *(The former `path` parameter is gone: it pointed at the retired checkout-local
    `fms_admin_pki.yaml`, which no published installation has and no production caller passed.)*
    """
    from corpusfm.server import fms_admin_pki as pki
    from corpusfm.server.admin_api_identity import admin_api_identity

    identity = admin_api_identity()
    if not identity.available:
        logger.info("file_discovery: Admin API identity unavailable (%s) — cannot list files",
                    identity.state)
        raise FileDiscoveryUnavailable(identity.reason)
    cfg = identity.config
    host = cfg["host"]
    token = pki.authenticate(host, cfg["name"], cfg["private_pem"])
    try:
        return pki.list_databases(host, token)
    finally:
        pki.logout(host, token)


def discover_files() -> list[DiscoveredFile]:
    """Live discovery: hosted files, normalized + classified (the storage DB flagged)."""
    return classify_all(discover_hosted_files(), self_names=_self_names())
