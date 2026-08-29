"""In-memory candidate-YAML overlay + re-analysis — the breakage-safeguard for
agent-proposed schema-YAML adjustments (the MCP gap-resolution path).

When the gap analyzer flags unknown FM vocabulary (a new script-step ID, a new
reference type, a new catalog section), an agent proposes additions to the shipped
``mappings.yaml`` / ``structure_catalog.yaml``. This module lets that candidate be
tested SAFELY: the candidate is deep-merged ON TOP of the shipped config for the
artifact's schema version, **in memory only** — the shipped YAML is never written —
and the relevant analyzers re-run against the artifact's own sampled XML. It reports
whether each previously-unknown item now resolves, and whether the candidate would
CLOBBER an existing entry (the breakage signal). A human commits a clean candidate.

The shipped YAML is the only place a real change ever lands, and only a human makes
it — so nothing the agent does here can break ingestion in production.
"""
from __future__ import annotations

from typing import Optional

import yaml

from corpusfm.core.schemas.registry import (
    _deep_merge, _load_schema_yaml, build_structure_catalog, load_mapping_config,
)


def parse_candidate(text_or_dict) -> dict:
    """Parse a candidate YAML string (or accept a dict). Raises ValueError on malformed
    YAML or a non-mapping top level."""
    if isinstance(text_or_dict, dict):
        return text_or_dict
    if not text_or_dict:
        return {}
    try:
        parsed = yaml.safe_load(text_or_dict)
    except yaml.YAMLError as exc:
        raise ValueError(f"candidate is not valid YAML: {exc}") from exc
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("candidate YAML must be a mapping (a top-level dict of keys)")
    return parsed


def clobbered_keys(base: dict, candidate: dict, _path: str = "") -> list[str]:
    """Keys where the candidate would REPLACE existing config rather than ADD to it —
    the breakage signal. Adding a new key/step/ref is safe; changing an existing scalar,
    or dropping items from an existing list, is not. A list replaced by a SUPERSET (pure
    addition) is safe; a list that loses members is flagged."""
    out: list[str] = []
    for k, v in (candidate or {}).items():
        path = f"{_path}.{k}" if _path else str(k)
        if k not in base:
            continue  # pure addition — safe
        bv = base[k]
        if isinstance(bv, dict) and isinstance(v, dict):
            out.extend(clobbered_keys(bv, v, path))
        elif isinstance(bv, list) and isinstance(v, list):
            dropped = [x for x in bv if x not in v]
            if dropped:
                out.append(f"{path} (drops {', '.join(map(str, dropped))})")
        elif bv != v:
            out.append(f"{path} ({bv!r} → {v!r})")
    return out


def _gap_report(xml_bytes: bytes, mapping_config: dict):
    from corpusfm.tools.xml_inspector import inspect as xml_inspect
    from corpusfm.tools.gap_analyzer import analyze
    inspector = xml_inspect(xml_bytes)
    if inspector.error:
        return None
    return analyze(inspector, mapping_config)


def _steps_unknown(result, structure_raw: dict, version: str) -> list:
    from corpusfm.core.structure_catalog.miner import mine
    catalog = build_structure_catalog(structure_raw, version)
    fields_section = (result.section_xml or {}).get("FieldsForTables", {})
    snap = mine(step_xml=(result.step_xml_by_identity or result.step_xml or {}),
                fields_section_xml=fields_section, catalog=catalog)
    return list(snap.steps_unknown)


def try_candidate(xml_bytes: bytes, *, mappings=None, structure=None,
                  label: str = "candidate-tryout") -> dict:
    """Overlay candidate ``mappings.yaml`` / ``structure_catalog.yaml`` additions on the
    shipped config and re-analyze ``xml_bytes``. Returns a report (never raises for a bad
    candidate — the error is reported)."""
    report: dict = {"ok": False, "schema_version": "", "errors": [], "clobbered": [],
                    "mappings": None, "structure": None, "resolved_all": None}
    try:
        cand_map = parse_candidate(mappings)
        cand_struct = parse_candidate(structure)
    except ValueError as exc:
        report["errors"].append(str(exc))
        return report

    if not cand_map and not cand_struct:
        report["errors"].append("no candidate provided (give mappings and/or structure YAML)")
        return report

    from corpusfm.core.parser import load_file
    try:
        result = load_file(xml_bytes, label)
    except Exception as exc:
        report["errors"].append(f"the sample XML failed to parse: {exc}")
        return report
    version = result.schema_version or ""
    report["schema_version"] = version

    resolved_flags: list[bool] = []

    if cand_map:
        try:
            base_map, _ = load_mapping_config(version)
            report["clobbered"].extend(clobbered_keys(base_map, cand_map))
            before = _gap_report(xml_bytes, base_map)
            after = _gap_report(xml_bytes, _deep_merge(base_map, cand_map))
            if before is not None and after is not None:
                b_refs, a_refs = set(before.unknown_reference_types), set(after.unknown_reference_types)
                b_sec, a_sec = set(before.unmapped), set(after.unmapped)
                report["mappings"] = {
                    "ref_types_resolved": sorted(b_refs - a_refs),
                    "ref_types_still_unknown": sorted(a_refs),
                    "sections_resolved": sorted(b_sec - a_sec),
                    "sections_still_unknown": sorted(a_sec),
                }
                resolved_flags.append(not a_refs and not a_sec if (b_refs or b_sec) else True)
        except Exception as exc:
            report["errors"].append(f"mappings overlay failed: {exc}")

    if cand_struct:
        try:
            base_struct, _ = _load_schema_yaml(version, "structure_catalog.yaml")
            report["clobbered"].extend(clobbered_keys(base_struct, cand_struct))
            before = _steps_unknown(result, base_struct, version)
            after = _steps_unknown(result, _deep_merge(base_struct, cand_struct), version)
            report["structure"] = {
                "steps_resolved": sorted(set(before) - set(after)),
                "steps_still_unknown": sorted(after),
            }
            resolved_flags.append(not after if before else True)
        except Exception as exc:
            report["errors"].append(f"structure overlay failed: {exc}")

    report["ok"] = not report["errors"]
    if resolved_flags:
        report["resolved_all"] = all(resolved_flags)
    return report


def try_candidate_against_gaps(version: str, *, unknown_steps=(), unknown_refs=(),
                               mappings=None, structure=None) -> dict:
    """Validate a candidate against an artifact's STORED actionable gaps (the unknown step
    IDs / reference types from its CompletenessProfile) — no source XML required, so it works
    on every artifact. Overlays the candidate on the shipped config for ``version`` and checks
    each previously-unknown item is now KNOWN, plus the same clobber safeguard."""
    report: dict = {"ok": False, "schema_version": version, "errors": [], "clobbered": [],
                    "mappings": None, "structure": None, "resolved_all": None}
    try:
        cand_map = parse_candidate(mappings)
        cand_struct = parse_candidate(structure)
    except ValueError as exc:
        report["errors"].append(str(exc))
        return report
    if not cand_map and not cand_struct:
        report["errors"].append("no candidate provided (give mappings and/or structure YAML)")
        return report

    flags: list[bool] = []
    if cand_struct or unknown_steps:
        try:
            base_struct, _ = _load_schema_yaml(version, "structure_catalog.yaml")
            report["clobbered"].extend(clobbered_keys(base_struct, cand_struct))
            known = build_structure_catalog(_deep_merge(base_struct, cand_struct), version).step_ids()
            resolved = [s for s in unknown_steps if int(s) in known]
            still = [s for s in unknown_steps if int(s) not in known]
            report["structure"] = {"steps_resolved": sorted(resolved, key=int),
                                   "steps_still_unknown": sorted(still, key=int)}
            flags.append(not still if unknown_steps else True)
        except Exception as exc:
            report["errors"].append(f"structure overlay failed: {exc}")
    if cand_map or unknown_refs:
        try:
            base_map, _ = load_mapping_config(version)
            report["clobbered"].extend(clobbered_keys(base_map, cand_map))
            known_refs = set(_deep_merge(base_map, cand_map).get("reference_types", []))
            resolved = sorted(r for r in unknown_refs if r in known_refs)
            still = sorted(r for r in unknown_refs if r not in known_refs)
            report["mappings"] = {"ref_types_resolved": resolved, "ref_types_still_unknown": still,
                                  "sections_resolved": [], "sections_still_unknown": []}
            flags.append(not still if unknown_refs else True)
        except Exception as exc:
            report["errors"].append(f"mappings overlay failed: {exc}")

    report["ok"] = not report["errors"]
    if flags:
        report["resolved_all"] = all(flags)
    return report
