"""Cross-file analysis: what one FM file references in its siblings, and the reconstruction
of a missing file's external interface from everything its siblings ask of it.

Deterministic, on-demand (not stored on the
artifact) — the substrate the cross-file reconstruction trial drives over MCP.
"""

from ._types import (
    ExternalDataSource, ExternalRef, ExternalReferenceSet, NameCandidate,
    ReconstructedField, ReconstructedTable, ReconstructedScript, ReconstructedInterface,
    ExternalDataSourceEntry, ExternalDataSourceIndex, ExternalResolution,
    RESOLUTION_CATALOG_ABSENT, RESOLUTION_REFERENCE_UNRESOLVED, RESOLUTION_NON_FILEMAKER,
    RESOLUTION_RESOLVED_UNVERIFIED, RESOLUTION_CURRENT_FILE,
    KIND_TABLE, KIND_KEY_FIELD, KIND_CALC_FIELD, KIND_VL_FIELD, KIND_LAYOUT_FIELD, KIND_SCRIPT,
)
from ._extract import extract_external_references, build_external_data_source_index
from ._reconstruct import reconstruct_interface, infer_field_type
from ._render import render_reference_set, render_interface
from ._emit import (
    build_schema_stub, render_stub_plan, render_stub_ddl, render_stub_saveasxml,
    SchemaStub, StubTable, StubField,
)

__all__ = [
    "ExternalDataSource", "ExternalRef", "ExternalReferenceSet", "NameCandidate",
    "ReconstructedField", "ReconstructedTable", "ReconstructedScript", "ReconstructedInterface",
    "ExternalDataSourceEntry", "ExternalDataSourceIndex", "ExternalResolution",
    "RESOLUTION_CATALOG_ABSENT", "RESOLUTION_REFERENCE_UNRESOLVED", "RESOLUTION_NON_FILEMAKER",
    "RESOLUTION_RESOLVED_UNVERIFIED", "RESOLUTION_CURRENT_FILE",
    "KIND_TABLE", "KIND_KEY_FIELD", "KIND_CALC_FIELD", "KIND_VL_FIELD",
    "KIND_LAYOUT_FIELD", "KIND_SCRIPT",
    "extract_external_references", "build_external_data_source_index",
    "reconstruct_interface", "infer_field_type",
    "render_reference_set", "render_interface",
    "build_schema_stub", "render_stub_plan", "render_stub_ddl", "render_stub_saveasxml",
    "SchemaStub", "StubTable", "StubField",
]
