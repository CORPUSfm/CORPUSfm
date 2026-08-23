"""Gap analyzer — compares an InspectorResult against a loaded mappings.yaml config.

Three categories of findings:
  unmapped      — catalog keys present in the XML but absent from mappings.yaml
                  (and not in non_mapped). These may need a new catalog entry.
  stale         — catalog keys declared in mappings.yaml but not found in the XML.
                  Schema may have changed or the element was removed.
  attribute_drift — for each mapped catalog: the declared name_attr is missing from
                  item elements, or item elements expose attributes not in noise_attrs
                  and not accounted for by name_attr (potential new meaningful attrs).

Public API:
    analyze(inspector_result, config) -> GapReport
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from corpusfm.tools.xml_inspector import InspectorResult


@dataclass
class AttributeDriftEntry:
    catalog_key: str
    item_xpath: str          # e.g. "BaseTableCatalog/BaseTable"
    missing_name_attr: bool  # declared name_attr not found on any item element
    declared_name_attr: str
    new_attrs: list[str]     # attrs in XML, not name_attr, not noise_attrs


@dataclass
class GapReport:
    version: str
    unmapped: list[str]                    # catalog keys: in XML, not in YAML
    stale: list[str]                       # catalog keys: in YAML, not in XML
    attribute_drift: list[AttributeDriftEntry]
    unknown_reference_types: list[str] = field(default_factory=list)  # *Reference elements not in catalog
    # Summary counts
    total_issues: int = field(init=False)

    def __post_init__(self):
        self.total_issues = (
            len(self.unmapped) + len(self.stale)
            + len(self.attribute_drift) + len(self.unknown_reference_types)
        )

    def to_dict(self) -> dict:
        """Serialisable representation — used as Claude API input."""
        return {
            "version": self.version,
            "unmapped": self.unmapped,
            "stale": self.stale,
            "attribute_drift": [
                {
                    "catalog_key": e.catalog_key,
                    "item_xpath": e.item_xpath,
                    "missing_name_attr": e.missing_name_attr,
                    "declared_name_attr": e.declared_name_attr,
                    "new_attrs": e.new_attrs,
                }
                for e in self.attribute_drift
            ],
            "unknown_reference_types": self.unknown_reference_types,
            "total_issues": self.total_issues,
        }


def analyze(inspector: InspectorResult, config: dict) -> GapReport:
    """Compare InspectorResult against a loaded mappings.yaml config dict.

    Args:
        inspector: result of xml_inspector.inspect()
        config:    dict loaded from mappings.yaml (via registry.load_mapping_config)

    Returns:
        GapReport with unmapped, stale, and attribute_drift findings.
    """
    noise_attrs: set[str] = set(config.get("noise_attrs", []))

    # Collect all "known" top-level catalog keys from the YAML
    catalog_cfgs: list[dict] = config.get("catalogs", [])
    known_yaml_keys: set[str] = {c["key"] for c in catalog_cfgs}

    # optional: true catalogs are legitimately absent in many FM files (e.g. files
    # that don't define custom menu sets). Exclude them from the stale check so they
    # don't generate false-positive warnings.
    optional_keys: set[str] = {c["key"] for c in catalog_cfgs if c.get("optional")}

    # Pick up any *_catalog special section (fields_catalog, steps_catalog,
    # calcs_catalog, options_catalog, etc.) that has a catalog_element key.
    for cfg_val in config.values():
        if isinstance(cfg_val, dict) and "catalog_element" in cfg_val:
            elem = cfg_val["catalog_element"]
            known_yaml_keys.add(elem)
            if cfg_val.get("optional"):
                optional_keys.add(elem)
    known_yaml_keys.discard("")

    non_mapped: set[str] = set(config.get("non_mapped", []))

    xml_top: set[str] = set(inspector.top_level_catalogs)

    # --- unmapped ---
    unmapped = sorted(xml_top - known_yaml_keys - non_mapped)

    # --- stale (exclude optional catalogs absent from this file) ---
    stale = sorted(known_yaml_keys - xml_top - optional_keys)

    # --- attribute drift (regular catalogs only) ---
    drift: list[AttributeDriftEntry] = []

    for cat_cfg in catalog_cfgs:
        key = cat_cfg["key"]
        item_tag = cat_cfg.get("item_element", "")
        name_attr = cat_cfg.get("name_attr", "")
        if not item_tag or key not in xml_top:
            continue

        # compare_content: true means all attrs are already captured in the
        # content fingerprint — no drift to report.
        if cat_cfg.get("compare_content", False):
            continue

        item_xpath = f"{key}/{item_tag}"
        xml_attrs = set(inspector.xpaths.get(item_xpath, []))

        if not xml_attrs:
            # item elements not seen at all (possibly wrapped differently)
            continue

        known_attrs: set[str] = set(cat_cfg.get("known_attrs", []))
        missing_name_attr = bool(name_attr and name_attr not in xml_attrs)
        new_attrs = sorted(xml_attrs - noise_attrs - {name_attr} - known_attrs)

        if missing_name_attr or new_attrs:
            drift.append(AttributeDriftEntry(
                catalog_key=key,
                item_xpath=item_xpath,
                missing_name_attr=missing_name_attr,
                declared_name_attr=name_attr,
                new_attrs=new_attrs,
            ))

    # --- unknown reference types ---
    # Scan all XPath components for element names ending in "Reference"; compare
    # against the reference_types list in the YAML config.
    known_ref_types: set[str] = set(config.get("reference_types", []))
    found_ref_types: set[str] = set()
    for path in inspector.xpaths:
        for component in path.split("/"):
            if component.endswith("Reference"):
                found_ref_types.add(component)
    unknown_reference_types = sorted(found_ref_types - known_ref_types)

    return GapReport(
        version=inspector.version,
        unmapped=unmapped,
        stale=stale,
        attribute_drift=drift,
        unknown_reference_types=unknown_reference_types,
    )
