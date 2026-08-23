"""Shared STORAGE-container download resolver (packet 1166).

ONE place maps a logical STORAGE container name → its typed loader, presence flag, and
content-type/extension. Used by BOTH the HTTP download route (``artifact-download``) and the
``download_container_data`` MCP tool, so the two never drift (mirrors how ``_compartment_path`` is
the single resolver for the apply path).

Hard fences (from the dev — do not soften):
- **VISIBLE_TYPES only.** A typeless / mid-landing / QUEUE row is structurally invisible — never serve
  it. ``is_visible(meta)`` is the gate; callers check it BEFORE serving.
- **Read-only.** Nothing here mutates a record, a container, or the queue.
- **Empty slot is normal, not an error.** ``present(meta, container)`` false means the slot legitimately
  has no content (a non-addon record has no name-map; a Seed record retains no source) — report
  skipped-with-reason, never a failure.

``ArtifactData`` is dual-meaning, keyed on ``artifact_type ∈ DELIVERABLE_TYPES``: a deliverable's
``ArtifactData`` is its raw file (``load_deliverable_xml``); a schema artifact's is the parsed
``.artifact`` document (``load_artifact(...).to_json()``). Getting this wrong yields silent empty/garbage —
the same trap the 709fbfde loader-rename fix addressed.

**That trap is now ENFORCED, not merely warned about** (packet 1224, audited + guarded 2026-07-31).
Every call site outside ``corpusfm/storage`` establishes the type before loading, and
``tests/test_deliverable_loader_is_type_gated.py`` fails the build if a new one does not. The paragraph
above describes a real hazard and a closed one — do not read it as a live defect.
"""

from __future__ import annotations

import json
from typing import Optional

from corpusfm.artifact.capabilities import DELIVERABLE_EXT, DELIVERABLE_TYPES, VISIBLE_TYPES

# The addressable containers. `container=` is the SOLE selector on the signed path (packet 1166 A3-auth).
CONTAINER_NAMES: tuple[str, ...] = ("SourceXML", "ArtifactData", "SummariesData", "NameMapData", "icon")

# A sensible default set for the MCP tool — the AI opts into Summaries / NameMap / icon explicitly.
DEFAULT_CONTAINERS: tuple[str, ...] = ("SourceXML", "ArtifactData")


def is_visible(meta) -> bool:
    """The VISIBLE_TYPES fence: only a stable catalog record (schema or deliverable) is servable."""
    return meta is not None and getattr(meta, "artifact_type", "") in VISIBLE_TYPES


def present(meta, container: str) -> bool:
    """Whether ``container`` legitimately holds content for this record (the has_* flags; ArtifactData
    is always the record's payload). A false result is NORMAL — report skipped-with-reason, never fail."""
    if container == "ArtifactData":
        return True
    if container == "SourceXML":
        return bool(getattr(meta, "has_source", False))
    if container == "SummariesData":
        return bool(getattr(meta, "has_summaries", False))
    if container == "NameMapData":
        return bool(getattr(meta, "has_name_map", False))
    if container == "icon":
        return bool(getattr(meta, "has_icon", False))
    return False


def absent_reason(container: str) -> str:
    """A human reason for an absent slot (skipped, not failed)."""
    return {
        "SourceXML":    "source XML was not retained for this record",
        "SummariesData": "no AI summaries stored for this record",
        "NameMapData":  "no addon name-map (not an addon record)",
        "icon":         "no addon icon on this record",
    }.get(container, "container has no content")


def is_zipped(container: str, meta) -> bool:
    """Does this container's download arrive as a zip? (packet 1226; deliverables added on the
    developer's ruling 2026-07-31.)

    The two payloads that are the artifact's own CONTENT — the retained source XML and a
    deliverable's raw file — are zipped. The source is the hundreds-of-MB case; deliverables joined
    it for consistency, so "downloads are compressed" has no exceptions to remember.

    Summaries, name-maps and the addon icon are not: they are small derived sidecars, and a PNG is
    already compressed.

    ONE definition, because three surfaces have to agree — the HTTP route serves it, and the MCP
    manifest tells an AI what will land. A second copy of this rule is a second chance to disagree.
    """
    if container == "SourceXML":
        return True
    return container == "ArtifactData" and getattr(meta, "artifact_type", "") in DELIVERABLE_TYPES


def content_type_and_ext(container: str, meta) -> "tuple[str, str]":
    """(media_type, file-extension) for one container's decoded payload."""
    atype = getattr(meta, "artifact_type", "")
    if container == "SourceXML":
        return ("application/xml", "xml")
    if container in ("SummariesData", "NameMapData"):
        return ("application/json", "json")
    if container == "icon":
        return ("image/png", "png")
    if container == "ArtifactData":
        if atype in DELIVERABLE_TYPES:
            return ("application/xml", DELIVERABLE_EXT.get(atype, "xml"))
        return ("application/json", "artifact")
    return ("application/octet-stream", "bin")


def load_container(backend, uuid: str, container: str, meta=None) -> Optional[bytes]:
    """DECODED bytes for one container, or None when absent/unreadable. Call only after ``present``.

    ArtifactData is dual-meaning (deliverable file vs parsed artifact.json), keyed on DELIVERABLE_TYPES.
    Summaries / NameMap are re-serialized to canonical JSON bytes (the loaders return dicts)."""
    if meta is None:
        meta = backend.get_artifact_meta(uuid)
    if meta is None:
        return None
    atype = getattr(meta, "artifact_type", "")
    if container == "SourceXML":
        return backend.load_raw_xml(uuid)
    if container == "SummariesData":
        s = backend.load_summaries(uuid)
        return json.dumps(s or {}, ensure_ascii=False, indent=2).encode("utf-8")
    if container == "NameMapData":
        nm = backend.load_name_map(uuid)
        return json.dumps(nm or {}, ensure_ascii=False, indent=2).encode("utf-8")
    if container == "icon":
        return getattr(backend, "load_icon", lambda _u: None)(uuid)
    if container == "ArtifactData":
        if atype in DELIVERABLE_TYPES:
            return backend.load_deliverable_xml(uuid)
        try:
            return backend.load_artifact(uuid).to_json().encode("utf-8")
        except Exception:
            return None
    return None
