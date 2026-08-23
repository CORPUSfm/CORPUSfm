"""FM Step XML sanitizer — strips user content, preserves FM structural vocabulary.

Public API:
    sanitize_step_xml(xml_str) -> str

Purpose: produce a reusable XML construction template from a raw `<Step>` element
extracted from StepsForScripts.  The template retains FM's internal element and
attribute names (structural vocabulary); user-authored content — field names,
calculation formulas, script names, variable names, layout names, comment text,
etc. — is replaced with typed placeholders.

Privacy invariant:
  The returned string contains ONLY FM's own vocabulary.  No user content survives.

Placeholder naming convention:
  {field_name}        field name in a FieldReference
  {to_name}           table occurrence name
  {script_name}       script name
  {layout_name}       layout name
  {data_source_name}  external data source / file name
  {base_table_name}   base table name
  {value_list_name}   value list name
  {cf_name}           custom function name
  {menu_set_name}     custom menu set name
  {table_name}        table name (generic reference)
  {variable_name}     FileMaker variable name ($var or $$var)
  {calculation}       formula / calculation text
  {comment_text}      comment body text
  {_hash}             ChunkList hash (FM-computed, opaque to callers)
  {_id}               FM internal integer ID on reference elements
  {_key}              FM internal keyValue attribute
  {_uuid}             UUID text content
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from typing import Optional


# ---------------------------------------------------------------------------
# Reference element tags whose 'name' attribute is user content
# ---------------------------------------------------------------------------

_REF_NAME_PLACEHOLDER: dict[str, str] = {
    "FieldReference": "{field_name}",
    "TableOccurrenceReference": "{to_name}",
    "ScriptReference": "{script_name}",
    "LayoutReference": "{layout_name}",
    "DataSourceReference": "{data_source_name}",
    "BaseTableReference": "{base_table_name}",
    "ValueListReference": "{value_list_name}",
    "CustomFunctionReference": "{cf_name}",
    "CustomMenuSetReference": "{menu_set_name}",
    "TableReference": "{table_name}",
}

# Reference elements that also carry FM internal IDs which need redaction
_REF_ID_ELEMENTS: frozenset[str] = frozenset(_REF_NAME_PLACEHOLDER.keys())


def _sanitize_elem(elem: ET.Element) -> None:
    """Recursively sanitize a Step element tree in-place."""
    tag = elem.tag

    # ── Reference elements: name is user content; id/keyValue are FM internals ──
    if tag in _REF_NAME_PLACEHOLDER:
        if "name" in elem.attrib:
            elem.set("name", _REF_NAME_PLACEHOLDER[tag])
        if "id" in elem.attrib:
            elem.set("id", "{_id}")
        if "keyValue" in elem.attrib:
            elem.set("keyValue", "{_key}")
        if "fileIndex" in elem.attrib:
            elem.set("fileIndex", "{_id}")

    # ── Variable Name: value is the variable name ($var / $$var) ──
    elif tag == "Name" and "value" in elem.attrib:
        elem.set("value", "{variable_name}")

    # ── Target Variable: value is a variable name ──
    elif tag == "Variable" and "value" in elem.attrib:
        elem.set("value", "{variable_name}")

    # ── Comment text ──
    elif tag == "Comment" and "value" in elem.attrib:
        elem.set("value", "{comment_text}")

    # ── UUID element ──
    elif tag == "UUID":
        if elem.text:
            elem.text = "{_uuid}"

    # ── Calculation text (formula content) ──
    elif tag == "Text":
        if elem.text is not None:
            elem.text = "{calculation}"

    # ── Chunk content (calculation fragments) ──
    elif tag == "Chunk":
        if elem.text is not None:
            elem.text = "{_chunk}"

    # ── ChunkList hash (FM-computed opaque value) ──
    elif tag == "ChunkList":
        if "hash" in elem.attrib:
            elem.set("hash", "{_hash}")

    for child in elem:
        _sanitize_elem(child)


def sanitize_step_xml(xml_str: str) -> Optional[str]:
    """Return a sanitized XML template for the given `<Step>` element string.

    User-authored content is replaced with typed placeholders (see module
    docstring).  FM structural vocabulary (element names, attribute names,
    Boolean/enum values) is preserved verbatim.

    Returns None if xml_str is empty or unparseable.
    """
    if not xml_str:
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None
    _sanitize_elem(root)
    return ET.tostring(root, encoding="unicode")
