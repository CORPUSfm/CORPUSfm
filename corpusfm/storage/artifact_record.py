"""Canonical artifact-record/2 — the ONE jor schema + reader both backends store and read.

The catalog record's ``JSONOfRecord`` (FM) / ``jor`` (SQLite) is this shape, in the PascalCase key
schema the registry slots project from (packet 085 seven-table model). ``build_record`` derives it
from an Artifact + store params; ``meta_from_jor`` reads it back into ``ArtifactMeta``. One source,
so FM and the local SQLite store never drift. The addon icon rides in the jor as ``icon_b64`` — a
record field, not a sidecar file.

record/2 vs record/1 (superseded by 085, then by 1216 which removed the hash entirely; the line
below is kept only so a reader of an OLD record understands the key it carries):
never dedup); ``PrimaryName`` is the single editable human identity (absorbs ``Name`` and
``addon_title``); ``UUIDJob`` replaces ``JobUUID``; ``HasSummaries`` replaces jor-only
``has_summaries``; ``has_artifact`` is gone — Type membership in ``capabilities.SCHEMA_TYPES``
is the truth.
"""
from __future__ import annotations

import base64
from pathlib import Path
from typing import Optional

from corpusfm.storage.local import ArtifactMeta, _safe_dir_name


def build_record(artifact, *, timestamp: str, label: str = "", origin: str = "Import",
                 job_uuid: str = "", run_uuid: str = "", addon_package=None,
                 xml_bytes: Optional[bytes] = None, keep_source_xml: bool = False) -> dict:
    """The canonical artifact-record/2 jor. Every newly-stored artifact is IsLatest at creation."""
    from corpusfm.artifact.types import GAP_COUNT_VERSION, count_summarizable

    identity = getattr(artifact, "identity", None)
    provenance = getattr(artifact, "provenance", None)
    profile = getattr(artifact, "completeness_profile", None)
    art_type = getattr(artifact, "type", None)

    file_name = _safe_dir_name(artifact)

    gap_issues, gap_unmapped = 0, []
    analyzer_failed: list = []
    if profile is not None:
        # packet 1121 — the persisted badge counts schema gaps PLUS incoming-clip gaps (clip_gaps), so an
        # enum-/element-only clip gets the same warning badge as a schema gap without a blob reload at list time.
        g = profile.actionable_gaps()
        gap_issues, gap_unmapped = profile.gap_badge_count(), g["sections"]
        analyzer_failed = list(getattr(profile, "analyzer_failed", []) or [])

    has_name_map = False
    addon_version = addon_locale = ""
    icon_b64 = ""
    primary_name = label or getattr(identity, "file_name", "") or file_name
    if addon_package is not None:
        has_name_map = bool(addon_package.name_map)
        if addon_package.icon_bytes:
            icon_b64 = base64.b64encode(addon_package.icon_bytes).decode("ascii")
        # An addon's PrimaryName is its title (absorbed the retired addon_title slot).
        primary_name = addon_package.addon_title or primary_name
        addon_version = addon_package.addon_version
        addon_locale = addon_package.addon_locale
    # PrimaryName is the extensionless human identity; export filenames derive from it.
    if primary_name.lower().endswith(".fmp12"):
        primary_name = primary_name[: -len(".fmp12")]

    return {
        "Type": art_type.value if art_type else "SaveAsXML",
        "PrimaryName": primary_name,
        "FileName": file_name,
        "Origin": origin,
        "UUIDJob": job_uuid,
        "RootUUID": getattr(identity, "root_uuid", "") or "",
        "ArtifactTimestamp": timestamp,
        "IsLatest": True,
        "HasSummaries": False,
        "Description": "",
        "Memory": "",
        "RunUUID": run_uuid,
        "FMVersion": getattr(identity, "fm_version", "") or "",
        "schema_version": getattr(provenance, "catalog_version", "") or "",
        # Detail-pop-over provenance + analyzer status ride the record (audit #1 NO-BLOB):
        # immutable ingest-time facts, JOR-only (no slot; never filtered).
        "created_at": getattr(provenance, "ingested_at", "") or "",
        "corpusfm_build": getattr(provenance, "corpusfm_build", "") or "",
        "catalog_version": getattr(provenance, "catalog_version", "") or "",
        "analyzer_failed": analyzer_failed,
        "addon_version": addon_version,
        "addon_locale": addon_locale,
        "has_name_map": has_name_map,
        "has_source": bool(keep_source_xml and xml_bytes),
        "summarizable_count": count_summarizable(artifact),
        "gap_issues": gap_issues,
        "gap_count_version": GAP_COUNT_VERSION,
        "gap_unmapped": gap_unmapped,
        "xml_bytes": len(xml_bytes) if xml_bytes else 0,
        "icon_b64": icon_b64,
    }


def record_from_jor(record_uuid: str, jor: dict) -> dict:
    """The lineage/identity record dict the latest-flag + tag layers consume, from one canonical
    jor. One converter for both backends (the FM backend and the engine-read paths), so the
    record shape never drifts. Carries the full canonical ``meta`` from the same parse (free)."""
    return {
        "uuid": record_uuid,
        "root_uuid": jor.get("RootUUID", ""),
        "file_name": jor.get("FileName", ""),
        "job_uuid": jor.get("UUIDJob", ""),
        "run_uuid": jor.get("RunUUID", ""),
        "timestamp": jor.get("ArtifactTimestamp", ""),
        "artifact_type": jor.get("Type", ""),
        "origin": jor.get("Origin", "Import"),
        "fm_version": jor.get("FMVersion", ""),
        "is_latest": bool(jor.get("IsLatest", False)),
        "name": jor.get("PrimaryName", ""),
        "meta": meta_from_jor(jor, uuid=record_uuid),
    }


def meta_from_jor(jor: dict, uuid: str = "") -> ArtifactMeta:
    """ArtifactMeta from the canonical jor (both backends read through this). ``uuid`` is the
    engine record key — the canonical address (packet 085 U3f); callers holding a Row pass
    ``row.key`` so the meta carries its address, empty only for keyless jor-only reads."""
    fn, ts = jor.get("FileName", ""), jor.get("ArtifactTimestamp", "")
    return ArtifactMeta(
        uuid=uuid,
        file_name=fn, timestamp=ts, path=Path(f"{fn}/{ts}"),
        name=jor.get("PrimaryName", ts), schema_version=jor.get("schema_version", ""),
        fm_version=jor.get("FMVersion", ""), origin=jor.get("Origin", "Import"),
        description=jor.get("Description", ""), memory=jor.get("Memory", ""),
        gap_issues=int(jor.get("gap_issues", 0) or 0),
        gap_count_version=int(jor.get("gap_count_version", 0) or 0),
        gap_unmapped=list(jor.get("gap_unmapped", [])),
        xml_bytes=int(jor.get("xml_bytes", 0) or 0), enc_bytes=0,
        job_uuid=jor.get("UUIDJob", ""), run_uuid=jor.get("RunUUID", ""),
        artifact_type=jor.get("Type", ""),
        addon_version=jor.get("addon_version", ""), addon_locale=jor.get("addon_locale", ""),
        has_name_map=bool(jor.get("has_name_map", False)),
        has_icon=bool(jor.get("icon_b64", "")),
        has_source=bool(jor.get("has_source", False)),
        has_summaries=bool(jor.get("HasSummaries", False)),
        summarizable_count=int(jor.get("summarizable_count", 0) or 0),
        root_uuid=jor.get("RootUUID", ""),
        analyzer_failed=list(jor.get("analyzer_failed", []) or []),
        # packet 1121 — surface the acceptance OBSERVATION state + batch id as cheap scalars derived from the
        # additive AcceptanceCase JOR record, so the card/facets project them without a blob reload.
        acceptance_state=(jor.get("AcceptanceCase") or {}).get("acceptance_state", "") or "",
        acceptance_batch=(jor.get("AcceptanceCase") or {}).get("batch_id", "") or "")
