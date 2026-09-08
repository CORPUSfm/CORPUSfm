"""FM XML source dispatch for job runner.

Public API:
    pull_source(source, credentials, *, timeout=300) -> bytes — raw FM DDR XML bytes

Every source pulls from a HOSTED FileMaker file. `local_file` — "read XML from a filesystem path" —
is REMOVED (packet 1361-01): it made a Job out of something that is not a Job. Ordinary direct-file
ingestion is still fully supported; it is INGESTION (upload, drop, paste, `corpusfm ingest`), which
lands an artifact without inventing a scheduled automation unit, a credential exemption and a pull
method around a path on disk.

`source.path` survives and is unrelated: it is where `fms_local`'s fmsadmin export WRITES, which the
co-located CORPUSfm then reads. That is a mechanism detail of a hosted pull, not a source.

Implemented sources:
    fms_local     — fmsadmin CLI on same host, reads from local path
    fms_save_to_documents — co-located zero-admin pull: FM SaveToDocumentsFolder
                    script writes XML to FM's Documents folder and returns its path
                    (no result-size cap); CORPUSfm reads the local file
    fms_push      — FM pushes XML to /api/upload; use trigger_fms_push() to
                    initiate; pull_source() is not applicable for this type
"""

from __future__ import annotations

from corpusfm.server.jobs.config import JobSource


def pull_source(source: JobSource, credentials: dict, *, timeout: float = 300.0) -> bytes:
    """Pull FM DDR XML bytes from the configured source.

    Args:
        source:      JobSource describing where to pull from.
        credentials: Resolved target-file account and password.
        timeout:     Bound for a blocking FileMaker export operation.

    Returns:
        Raw FM DDR XML bytes (UTF-16 encoded, ready for parser.load_file()).

    Raises:
        FMSError:   for FMS API errors.
        ValueError: for unknown source type or missing config.
    """
    stype = (source.type or "").strip()

    if stype == "fms_local":
        from corpusfm.server.fms_client import pull_fms_local
        return pull_fms_local(source, credentials, timeout=timeout)

    if stype == "fms_save_to_documents":
        from corpusfm.server.fms_client import pull_fms_save_to_documents_job
        return pull_fms_save_to_documents_job(source, credentials, timeout=timeout)

    if stype == "fms_save_to_file_path":
        from corpusfm.server.fms_client import pull_fms_save_to_file_path
        return pull_fms_save_to_file_path(source, credentials, timeout=timeout)

    if stype == "fms_push":
        raise ValueError(
            "fms_push jobs receive data via FM pushing to /api/upload — "
            "use POST /api/jobs/{name}/trigger to send the trigger to FM"
        )

    raise ValueError(
        f"Unknown source type: '{stype}'. Valid types: fms_local, fms_save_to_documents, "
        "fms_save_to_file_path, fms_push"
    )
