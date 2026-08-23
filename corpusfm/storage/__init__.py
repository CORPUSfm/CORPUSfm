"""Storage package — use get_backend() to obtain the active backend instance.

All route handlers, MCP tools, and job runners call get_backend() instead of
importing functions directly from corpusfm.storage.local. This keeps all callers
backend-agnostic and positions the codebase for the FileMaker OData backend.

Backend selection (in priority order):
  1. FileMakerODataBackend — when install.yaml has storage_backend: fm_odata
     and the required FM connection fields (fm_host, fm_database, fm_user, fm_password)
  2. LocalBackend — all other cases (default)
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Union


class StagedSourceUnavailable(Exception):
    """A backend's ``load_staged_source`` could not READ the staged source bytes due to a transient
    transport error (FMS blip / timeout), as opposed to the source being genuinely absent (which
    returns ``None``). The ingest worker keeps the QUEUE row for retry rather than deleting it —
    a transient read must never destroy a durable import (packet 077-B; renamed in 085 U3a)."""


def get_backend(
    archive_dir: Optional[Path] = None,
) -> "Union[LocalBackend, FileMakerODataBackend]":
    """Return the active storage backend.

    Reads install.yaml to determine whether to return FileMakerODataBackend
    (storage_backend: fm_odata) or LocalBackend (default).

    On an fm_odata install the FM backend ALWAYS wins — even when an archive_dir
    is passed. This keeps every caller (job runner, scheduler, webhook, MCP tools)
    storing to FileMaker on a server install; a stray local archive_dir (which
    callers pass for local scratch like git registrations / discovery logs) must
    not silently divert artifact storage to the local filesystem.

    archive_dir only selects a specific LocalBackend directory on NON-fm_odata
    installs (standalone / local).
    """
    # THE PUBLISHED INSTALLATION ANSWERS FIRST, AND FINALLY (packet 1246-10-04). A box with a
    # published record resolves its corpus through the manifest and the held credential; it never
    # reads `install.yaml` for storage and never falls through to LocalBackend, because substituting
    # local storage for a corpus that exists is a silent split-brain — the pages render and the
    # artifacts go somewhere else. `None` means nothing is published at all (a development tree),
    # and only then does the legacy path below apply.
    from corpusfm.lifecycle import runtime_storage

    published = runtime_storage.published_installation()
    if published is not None:
        return runtime_storage.resolve().backend()

    from corpusfm.install import read_install_config

    config = read_install_config()
    if config.get("storage_backend") == "fm_odata":
        host = config.get("fm_host", "")
        database = config.get("fm_database", "")
        username = config.get("fm_user", "")
        password = config.get("fm_password", "")
        if host and database and username and password:
            from corpusfm.storage.fm_odata import FileMakerODataBackend
            return FileMakerODataBackend(
                host=host,
                database=database,
                username=username,
                password=password,
                verify_ssl=bool(config.get("fm_verify_ssl", False)),
            )

    from corpusfm.storage.local import default_archive_dir, load_settings, LocalBackend

    # Not fm_odata: honor an explicit archive_dir, else the configured default.
    if archive_dir is not None:
        return LocalBackend(archive_dir)
    settings = load_settings()
    resolved = Path(settings.get("archive_dir", str(default_archive_dir())))
    return LocalBackend(resolved)
