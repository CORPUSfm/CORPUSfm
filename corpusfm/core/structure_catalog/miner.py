"""FM Internal Structure Catalog — miner.

Extracts structural observations from FM XML during ingestion:
  mine(step_xml, fields_section_xml, catalog) -> StructureCatalogSnapshot

Observations recorded:
  steps_observed     — step IDs seen in StepsForScripts XML
  steps_unknown      — step IDs seen but absent from the catalog
  field_types_observed — field type codes seen in FieldsForTables XML
  steps_templates    — sanitized XML templates keyed by str(step_id);
                       populated first from catalog.yaml, then from
                       mined observations for steps lacking a curated template

Privacy guarantee: only FM's own structural vocabulary is extracted.
User content (field names, calculation text, script names, etc.) is
replaced by typed placeholders via the sanitizer before storage.
"""

from __future__ import annotations

import logging
from corpusfm.core import safe_xml as ET
from typing import Optional

from .sanitizer import sanitize_step_xml
from .types import StructureCatalog, StructureCatalogSnapshot

logger = logging.getLogger(__name__)


def _collect_step_ids(step_xml: dict) -> list[int]:
    """Return sorted list of unique step IDs across all script step XML strings.

    step_xml is {script_name: xml_str} where xml_str is a <Script> element
    containing <Step id="N" ...> children from StepsForScripts.
    """
    seen: set[int] = set()
    for xml_str in step_xml.values():
        if not xml_str:
            continue
        try:
            root = ET.fromstring(xml_str)
            for elem in root.iter("Step"):
                id_str = elem.get("id", "")
                if id_str.isdigit():
                    seen.add(int(id_str))
        except ET.ParseError as exc:
            logger.debug("step_xml parse error: %s", exc)
    return sorted(seen)


def _collect_field_types(section_xml: dict) -> list[str]:
    """Return sorted unique field type codes from FieldsForTables section XML.

    section_xml is the FieldsForTables sub-dict from result.section_xml:
    {key: xml_str} where xml_str contains <Field type="Normal|..."> elements.
    """
    seen: set[str] = set()
    for xml_str in section_xml.values():
        if not xml_str:
            continue
        try:
            root = ET.fromstring(xml_str)
            for elem in root.iter("Field"):
                ft = elem.get("fieldType", "") or elem.get("type", "")
                if ft:
                    seen.add(ft)
        except ET.ParseError as exc:
            logger.debug("field_type parse error: %s", exc)
    return sorted(seen)


def _extract_step_elements(step_xml: dict) -> dict[int, str]:
    """Return {step_id: first_raw_xml_str} for one representative <Step> per ID.

    Only the first occurrence of each step ID is retained — sufficient to
    derive a structural template; the user-content differs per occurrence
    but the element structure is identical for the same step type.
    """
    first_seen: dict[int, str] = {}
    for xml_str in step_xml.values():
        if not xml_str:
            continue
        try:
            root = ET.fromstring(xml_str)
            for elem in root.iter("Step"):
                id_str = elem.get("id", "")
                if not id_str.isdigit():
                    continue
                sid = int(id_str)
                if sid not in first_seen:
                    first_seen[sid] = ET.tostring(elem, encoding="unicode")
        except ET.ParseError as exc:
            logger.debug("step element extraction error: %s", exc)
    return first_seen


def _build_templates(
    step_ids_observed: list[int],
    step_elements: dict[int, str],
    catalog: StructureCatalog,
) -> dict[str, str]:
    """Build {str(step_id): template_xml} for all observed step IDs.

    Priority:
      1. Curated template from catalog.yaml (xml_template on StepEntry) — preferred
      2. Mined template from sanitizing the first observed raw Step XML

    Step IDs with no catalog entry and no observed XML get no template.
    """
    templates: dict[str, str] = {}
    for sid in step_ids_observed:
        key = str(sid)
        # 1. Try curated template from the catalog YAML
        entry = catalog.steps.get(sid)
        if entry and entry.xml_template:
            templates[key] = entry.xml_template
            continue
        # 2. Mine from observed raw XML
        raw = step_elements.get(sid)
        if raw:
            sanitized = sanitize_step_xml(raw)
            if sanitized:
                templates[key] = sanitized
    return templates


def mine(
    step_xml: dict,
    fields_section_xml: dict,
    catalog: StructureCatalog,
) -> StructureCatalogSnapshot:
    """Produce a StructureCatalogSnapshot from raw FM XML data.

    Args:
        step_xml:           {script_name: xml_str} from ParseResult.step_xml
        fields_section_xml: section_xml["FieldsForTables"] or {} when absent
        catalog:            loaded StructureCatalog for this schema version

    Returns:
        StructureCatalogSnapshot with observations and templates filled in.
    """
    step_ids_observed = _collect_step_ids(step_xml)
    known_ids = catalog.step_ids()
    steps_unknown = sorted(sid for sid in step_ids_observed if sid not in known_ids)

    field_types_observed = _collect_field_types(fields_section_xml)

    step_elements = _extract_step_elements(step_xml)
    steps_templates = _build_templates(step_ids_observed, step_elements, catalog)

    return StructureCatalogSnapshot(
        schema_version=catalog.schema_version,
        steps_in_catalog=len(known_ids),
        steps_observed=step_ids_observed,
        steps_unknown=steps_unknown,
        field_types_observed=field_types_observed,
        steps_templates=steps_templates,
    )
