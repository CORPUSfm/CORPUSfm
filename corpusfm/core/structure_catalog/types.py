"""FM Internal Structure Catalog — data types.

StructureCatalog     — in-memory representation loaded from structure_catalog.yaml.
StructureCatalogSnapshot — compact observation record embedded in each Artifact.

Privacy: these types capture FM's own vocabulary (step IDs, element names,
type codes). They carry no user content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Catalog (full, loaded from YAML)
# ---------------------------------------------------------------------------

@dataclass
class StepEntry:
    """One entry from the script_steps section of structure_catalog.yaml."""
    step_id: int
    name: str
    param_types: list        # list[str] — Parameter @type values used
    block_role: Optional[str]    # "opener" | "continue" | "closer" | None
    fm_version_first_seen: str
    xml_template: Optional[str] = None  # sanitized XML template with typed placeholders


@dataclass
class StructureCatalog:
    """Full catalog loaded from structure_catalog.yaml for a given schema version."""
    schema_version: str
    steps: dict              # {int: StepEntry} — keyed by step_id
    field_types: dict        # {str: dict} — type code → {label}
    field_result_types: dict # {str: dict}
    layout_object_types: dict  # {str: dict}
    script_trigger_names: dict # {str: dict}
    relationship_operators: dict  # {str: dict}
    parameter_types: list    # list[str] — all known Parameter @type values
    container_grammar: dict = field(default_factory=dict)  # FM folder open/close grammar

    def step_ids(self) -> set:
        return set(self.steps.keys())

    def step_name(self, step_id: int) -> Optional[str]:
        e = self.steps.get(step_id)
        return e.name if e else None

    def to_dict(self) -> dict:
        """JSON-safe form, for embedding in the externalized artifact document (packet 1226).

        Step IDs become string keys because JSON has no integer keys — the same convention
        `StructureCatalogSnapshot.steps_templates` already uses.
        """
        return {
            "schema_version": self.schema_version,
            "script_steps": {
                str(sid): {
                    "name": e.name,
                    "param_types": list(e.param_types),
                    "block_role": e.block_role,
                    "fm_version_first_seen": e.fm_version_first_seen,
                    "xml_template": e.xml_template,
                }
                for sid, e in sorted(self.steps.items())
            },
            "field_types": dict(self.field_types),
            "field_result_types": dict(self.field_result_types),
            "layout_object_types": dict(self.layout_object_types),
            "script_trigger_names": dict(self.script_trigger_names),
            "relationship_operators": dict(self.relationship_operators),
            "parameter_types": list(self.parameter_types),
            "container_grammar": dict(self.container_grammar),
        }


# ---------------------------------------------------------------------------
# Snapshot (compact, embedded in Artifact)
# ---------------------------------------------------------------------------

@dataclass
class StructureCatalogSnapshot:
    """Compact record of structure catalog observations for one artifact.

    Embedded in every Artifact at ingestion time.  Records what FM structural
    vocabulary was encountered in this specific file, and includes sanitized
    XML construction templates for every step observed in the file's scripts.

    steps_templates is a dict keyed by step_id (as str for JSON compat) whose
    values are sanitized XML template strings.  Templates are sourced first from
    the curated catalog YAML, then supplemented by mined observations from this
    file's actual step XML.

    The full catalog for a given schema_version can be loaded from
    load_structure_catalog(schema_version) when richer data is needed.
    """
    schema_version: str           # catalog version used at ingestion (e.g. "2.2.3.0")
    steps_in_catalog: int         # total known step IDs in catalog at ingestion time
    steps_observed: list          # list[int] — step IDs seen in this file's scripts
    steps_unknown: list           # list[int] — step IDs in file but not in catalog
    field_types_observed: list    # list[str] — field type codes seen in this file
    steps_templates: dict = field(default_factory=dict)  # {str(step_id): template_xml}

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "steps_in_catalog": self.steps_in_catalog,
            "steps_observed": self.steps_observed,
            "steps_unknown": self.steps_unknown,
            "field_types_observed": self.field_types_observed,
            "steps_templates": self.steps_templates,
        }

    @classmethod
    def from_dict(cls, d: dict) -> StructureCatalogSnapshot:
        return cls(
            schema_version=d.get("schema_version", ""),
            steps_in_catalog=d.get("steps_in_catalog", 0),
            steps_observed=d.get("steps_observed", []),
            steps_unknown=d.get("steps_unknown", []),
            field_types_observed=d.get("field_types_observed", []),
            steps_templates=d.get("steps_templates", {}),
        )

    @classmethod
    def empty(cls, schema_version: str = "") -> StructureCatalogSnapshot:
        return cls(
            schema_version=schema_version,
            steps_in_catalog=0,
            steps_observed=[],
            steps_unknown=[],
            field_types_observed=[],
            steps_templates={},
        )
