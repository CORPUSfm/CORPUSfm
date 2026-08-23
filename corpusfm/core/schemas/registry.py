"""Schema version detection and YAML file loader.

Public API:
    detect_version(xml_path)              -> (version_str, root_attrs)
    load_mapping_config(version_str)      -> (config_dict, warning_str | None)
    load_rendering_catalog(version_str)   -> (config_dict, warning_str | None)
    resolve_parser_config(xml_path)       -> (config_dict, version_str, warning_str | None)
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
import yaml
from pathlib import Path
from typing import Optional

_SCHEMAS_DIR = Path(__file__).parent

EXPECTED_ROOT = "FMSaveAsXML"
ADDON_ROOT = "FMAdd_on"
_VALID_ROOTS = frozenset({EXPECTED_ROOT, ADDON_ROOT})


def detect_version(xml_path) -> tuple[str, dict]:
    """Read only the root element of xml_path via iterparse and return (version, attrs).

    Uses iterparse so we never load the full file into memory just to read version.
    Accepts both FMSaveAsXML (DDR export) and FMAdd_on (addon XML) roots.
    attrs always contains "_root" with the actual root tag name.
    Raises FileNotFoundError if the path does not exist.
    Raises ValueError if the root element is not a recognised FM XML root.
    """
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"XML file not found: {xml_path}")

    with open(xml_path, "rb") as fh:
        for event, elem in ET.iterparse(fh, events=("start",)):
            tag = elem.tag
            attrs = dict(elem.attrib)
            attrs["_root"] = tag
            if tag not in _VALID_ROOTS:
                raise ValueError(
                    f"Unexpected root element <{tag}> in {xml_path.name}. "
                    f"Expected <{EXPECTED_ROOT}> (DDR export) or <{ADDON_ROOT}> (addon XML)."
                )
            version = attrs.get("version", "")
            if not version and tag == EXPECTED_ROOT:
                raise ValueError(
                    f"Root element <{EXPECTED_ROOT}> has no 'version' attribute "
                    f"in {xml_path.name}."
                )
            return version, attrs

    raise ValueError(f"Empty or unreadable XML file: {xml_path.name}")


def _version_tuple(v: str) -> tuple[int, ...]:
    """Convert '2.2.3.0' to (2, 2, 3, 0) for numeric comparison."""
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def _available_versions(schema_filename: str = "mappings.yaml") -> list[str]:
    """Return all version strings found in schemas/ subdirectories, sorted ascending."""
    versions = []
    for d in _SCHEMAS_DIR.iterdir():
        if d.is_dir() and d.name.startswith("v") and (d / schema_filename).exists():
            versions.append(d.name[1:])  # strip leading 'v'
    return sorted(versions, key=_version_tuple)


def _registered_versions() -> set:
    """Versions that have a schema directory with at least one YAML file.

    A version is "registered" once a maintainer creates its directory — even if that dir
    overrides only SOME schema files (e.g. v2.3.0.0 ships only its own mappings.yaml and
    inherits rendering.yaml / structure_catalog.yaml unchanged from v2.2.3.0). Inheriting a
    sibling file for a registered version is deliberate, so it is SILENT — distinct from
    guessing a schema across an unverified version gap, which still warns.
    """
    out = set()
    for d in _SCHEMAS_DIR.iterdir():
        if d.is_dir() and d.name.startswith("v") and any(d.glob("*.yaml")):
            out.add(d.name[1:])
    return out


def _deep_merge(base, delta):
    """Recursively overlay `delta` onto `base`. Dicts merge key-by-key (delta wins / adds);
    scalars and lists are replaced by `delta`. Used for version-delta schema inheritance —
    a child version's `script_steps` (etc.) extend the parent's instead of replacing them."""
    if not isinstance(base, dict) or not isinstance(delta, dict):
        return delta
    out = dict(base)
    for k, v in delta.items():
        out[k] = _deep_merge(out[k], v) if (k in out and isinstance(out[k], dict)
                                            and isinstance(v, dict)) else v
    return out


def _load_version_file(version: str, filename: str) -> dict:
    """Read schemas/v{version}/{filename}; if it declares `inherits: <ver>`, deep-merge it
    onto the resolved parent file (recursively). So a new version dir can ship a SMALL delta
    (e.g. v2.3.0.0/structure_catalog.yaml = just the new FM2026 steps) instead of cloning the
    whole file — the parent supplies everything the delta doesn't override."""
    with open(_SCHEMAS_DIR / f"v{version}" / filename, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    parent = raw.pop("inherits", None) if isinstance(raw, dict) else None
    if not parent:
        return raw
    base, _ = _load_schema_yaml(str(parent), filename)   # parent resolves (own inherits/fallback)
    return _deep_merge(base, raw)


def _load_schema_yaml(version: str, filename: str) -> tuple[dict, Optional[str]]:
    """Load a named YAML file from the versioned schema directory with fallback.

    Resolution order:
    1. Exact match     → schemas/v{version}/{filename}, no warning
    2. Nearest ≤ found → load it; silent if {version} is a registered dir, else warn
    3. Older than all  → use oldest available, return warning

    A loaded file declaring `inherits: <ver>` is deep-merged onto its parent (delta override).
    Raises ValueError if no version directories containing filename exist.
    """
    available = _available_versions(filename)
    if not available:
        raise ValueError(
            f"No schema version directories with {filename} found under schemas/."
        )

    if version in available:
        return _load_version_file(version, filename), None

    registered = _registered_versions()
    target = _version_tuple(version)
    candidates = [v for v in available if _version_tuple(v) <= target]
    if candidates:
        best = candidates[-1]  # sorted ascending → last is highest ≤ target
        config = _load_version_file(best, filename)
        # A registered version inheriting a sibling file it chose not to override is silent;
        # guessing a schema for an unknown FM version still warns.
        warning = None if version in registered else (
            f"Using schema v{best} for FM XML version {version}. "
            f"Results may be incomplete if the schema changed between versions."
        )
        return config, warning

    oldest = available[0]
    config = _load_version_file(oldest, filename)
    warning = (
        f"FM XML version {version} predates all known schemas. "
        f"Using oldest available schema v{oldest}. Results may be inaccurate."
    )
    return config, warning


def load_mapping_config(version: str) -> tuple[dict, Optional[str]]:
    """Load mappings.yaml for version. Returns (config_dict, warning_str | None)."""
    return _load_schema_yaml(version, "mappings.yaml")


def load_rendering_catalog(version: str) -> tuple[dict, Optional[str]]:
    """Load rendering.yaml for version. Returns (config_dict, warning_str | None)."""
    return _load_schema_yaml(version, "rendering.yaml")


def load_structure_catalog(version: str) -> tuple["StructureCatalog", Optional[str]]:
    """Load structure_catalog.yaml for version. Returns (StructureCatalog, warning | None).

    Builds a typed StructureCatalog from the raw YAML dict.
    Uses nearest-version fallback identical to load_mapping_config.
    """
    raw, warning = _load_schema_yaml(version, "structure_catalog.yaml")
    return build_structure_catalog(raw, version), warning


def build_structure_catalog(raw: dict, version: str) -> "StructureCatalog":
    """Build a typed StructureCatalog from a raw structure_catalog.yaml dict. Shared by
    the loader and by the in-memory candidate-overlay path (tools/yaml_tryout)."""
    from corpusfm.core.structure_catalog.types import StepEntry, StructureCatalog

    steps_raw = raw.get("script_steps", {})
    steps: dict = {}
    for k, v in steps_raw.items():
        try:
            sid = int(k)
        except (ValueError, TypeError):
            continue
        steps[sid] = StepEntry(
            step_id=sid,
            name=v.get("name", ""),
            param_types=list(v.get("param_types") or []),
            block_role=v.get("block_role"),
            fm_version_first_seen=str(v.get("fm_version_first_seen", "")),
            xml_template=v.get("xml_template") or None,
        )

    return StructureCatalog(
        schema_version=str(raw.get("schema_version", version)),
        steps=steps,
        field_types=dict(raw.get("field_types") or {}),
        field_result_types=dict(raw.get("field_result_types") or {}),
        layout_object_types=dict(raw.get("layout_object_types") or {}),
        script_trigger_names=dict(raw.get("script_trigger_names") or {}),
        relationship_operators=dict(raw.get("relationship_operators") or {}),
        parameter_types=list(raw.get("parameter_types") or []),
        container_grammar=dict(raw.get("container_grammar") or {}),
    )


def resolve_parser_config(xml_path) -> tuple[dict, str, Optional[str]]:
    """Convenience: detect version then load config.

    Returns (config_dict, version_str, warning_str | None).
    """
    version, _ = detect_version(xml_path)
    config, warning = load_mapping_config(version)
    return config, version, warning
