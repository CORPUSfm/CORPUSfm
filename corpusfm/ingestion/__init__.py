"""corpusfm.ingestion — FM XML bytes → Artifact.

Public API:
    ingest(xml_bytes, label, *, source_type, name_map, keep_source_xml) -> Artifact
    PipelineState  (exposed for testing only)
"""
from corpusfm.ingestion.pipeline import ingest, PipelineState

__all__ = ["ingest", "PipelineState"]
