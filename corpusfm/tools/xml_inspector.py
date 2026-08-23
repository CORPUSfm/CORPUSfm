"""Structural fingerprint tool for FMSaveAsXML DDR exports.

Walks the XML tree and records every distinct XPath (relative to AddAction)
and every attribute name seen at that path. Content-agnostic — never reads
text or attribute values, only names.

Public API:
    inspect(xml_bytes: bytes) -> InspectorResult
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InspectorResult:
    version: str
    # XPath relative to AddAction → sorted list of distinct attribute names seen
    xpaths: dict[str, list[str]]
    # Top-level catalog element names found as direct children of AddAction, in discovery order
    top_level_catalogs: list[str]
    # Root element attributes (File, Source, version, …)
    root_attrs: dict[str, str]
    error: Optional[str] = None


def _walk(elem: ET.Element, path: str, path_attrs: dict[str, set]) -> None:
    """Recursively collect XPaths and attribute names below an AddAction child."""
    attrs = path_attrs.setdefault(path, set())
    attrs.update(elem.attrib.keys())
    for child in elem:
        _walk(child, f"{path}/{child.tag}", path_attrs)


def inspect(xml_bytes: bytes) -> InspectorResult:
    """Return a structural fingerprint of a FMSaveAsXML DDR export.

    Accepts raw bytes (UTF-16 encoded, as produced by FM's Save As XML).
    Never reads attribute values or text content — structure and attribute
    names only.

    Returns InspectorResult with .error set (and other fields empty) if the
    file cannot be parsed or is not a FMSaveAsXML document.
    """
    from corpusfm.core.parser import sanitize_xml

    try:
        text = sanitize_xml(xml_bytes)
        root = ET.fromstring(text)
    except Exception as exc:
        return InspectorResult(
            version="", xpaths={}, top_level_catalogs=[], root_attrs={},
            error=f"XML parse error: {exc}",
        )

    if root.tag != "FMSaveAsXML":
        return InspectorResult(
            version="", xpaths={}, top_level_catalogs=[], root_attrs=dict(root.attrib),
            error=(
                f"Not a FMSaveAsXML file: root element is <{root.tag}>. "
                "Only FMSaveAsXML DDR exports are supported."
            ),
        )

    version = root.attrib.get("version", "unknown")
    root_attrs = dict(root.attrib)

    path_attrs: dict[str, set] = {}
    seen_top: set[str] = set()
    top_level_catalogs: list[str] = []

    for action_node in root.findall("./Structure/"):
        for child in action_node:
            if child.tag not in seen_top:
                seen_top.add(child.tag)
                top_level_catalogs.append(child.tag)
            _walk(child, child.tag, path_attrs)

    xpaths = {path: sorted(attrs) for path, attrs in sorted(path_attrs.items())}
    return InspectorResult(
        version=version,
        xpaths=xpaths,
        top_level_catalogs=top_level_catalogs,
        root_attrs=root_attrs,
    )
