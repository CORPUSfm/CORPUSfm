"""corpusfm.artifact — canonical AI-facing reference document.

The Artifact is what the ingestion pipeline produces and all extensions consume.
Explorer, Diff, git formatter, MCP tools, and AI harnesses all read from it.

Public API:
    ARTIFACT_VERSION          str constant "1.0"
    ArtifactType              SaveAsXML | AddonXML | MergedXML
    ArtifactIdentity          root_uuid, file_name, fm_version
    ArtifactProvenance        ingested_at, catalog_version, source
    XmlSource                 catalog, xml
    ArtifactItem              per-item record with xml_sources, rendered_text, xref ids
    XRefRecord                one directed edge in the cross-reference graph
    CompletenessProfile       what the pipeline knew, skipped, and left unresolved
    StructureCatalogSnapshot  FM structural vocabulary observed at ingestion
    Artifact                  top-level envelope; serializes to artifact.json.gz

    make_item_id(section, fm_uuid, name) -> str
"""
from corpusfm.artifact.types import (
    ARTIFACT_VERSION,
    ArtifactType,
    ArtifactIdentity,
    ArtifactProvenance,
    XmlSource,
    ArtifactItem,
    XRefRecord,
    CompletenessProfile,
    StructureCatalogSnapshot,
    Artifact,
    make_item_id,
)
from corpusfm.artifact.capabilities import (
    capabilities_for,
    has_capability,
    is_known_type,
    known_types,
    capability_matrix,
)

__all__ = [
    "ARTIFACT_VERSION",
    "ArtifactType",
    "ArtifactIdentity",
    "ArtifactProvenance",
    "XmlSource",
    "ArtifactItem",
    "XRefRecord",
    "CompletenessProfile",
    "StructureCatalogSnapshot",
    "Artifact",
    "make_item_id",
    "capabilities_for",
    "has_capability",
    "is_known_type",
    "known_types",
    "capability_matrix",
]
