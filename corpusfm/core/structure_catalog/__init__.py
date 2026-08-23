"""FM Internal Structure Catalog.

Public API:
    mine(step_xml, fields_section_xml, catalog) -> StructureCatalogSnapshot
    sanitize_step_xml(xml_str) -> str | None

Types:
    StructureCatalog
    StructureCatalogSnapshot
    StepEntry
"""

from .types import StepEntry, StructureCatalog, StructureCatalogSnapshot
from .miner import mine
from .sanitizer import sanitize_step_xml

__all__ = [
    "StepEntry",
    "StructureCatalog",
    "StructureCatalogSnapshot",
    "mine",
    "sanitize_step_xml",
]
