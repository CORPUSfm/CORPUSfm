"""Plain-text renderer for git_formatter.

Independent of the rendering/ package. Produces plain text optimized for
git diff and AI consumption.

show_hidden=True  marks hidden characters: NBSP, trailing whitespace, control chars.
show_hidden=False outputs raw text, clean for human reading.
"""

from __future__ import annotations

import hashlib
import re
from corpusfm.core import safe_xml as ET
from typing import Optional

DEFAULT_LARGE_THRESHOLD = 512 * 1024  # 512K bytes

ALL_SECTIONS = [
    "scripts",
    "custom_functions",
    "tables",
    "layouts",
    "value_lists",
    "relationships",
    "addons",
]

CATALOG_TO_FOLDER = {
    "ScriptCatalog":           "scripts",
    "CustomFunctionsCatalog":  "custom_functions",
    "BaseTableCatalog":        "tables",
    "LayoutCatalog":           "layouts",
    "ValueListCatalog":        "value_lists",
    "RelationshipCatalog":     "relationships",
    "BaseDirectoryCatalog":    "addons",
}


# ── Hidden character marking ──────────────────────────────────────────────────

_NBSP = " "
_SAFE_CONTROL = frozenset("\t\n\r")


def _mark_hidden(text: str) -> str:
    """Mark NBSP, trailing whitespace per line, and control characters."""
    text = text.replace(_NBSP, "[NBSP]")
    lines = text.split("\n")
    marked = []
    for line in lines:
        stripped = line.rstrip(" \t")
        tail = line[len(stripped):]
        visible = "".join("·" if c == " " else "→" for c in tail)
        marked.append(stripped + visible)
    text = "\n".join(marked)
    result = []
    for ch in text:
        cp = ord(ch)
        if (cp < 0x20 and ch not in _SAFE_CONTROL) or cp == 0x7F:
            result.append(f"[U+{cp:04X}]")
        else:
            result.append(ch)
    return "".join(result)


def _apply_hidden(text: str, show_hidden: bool) -> str:
    return _mark_hidden(text) if show_hidden else text


# ── Large content threshold ───────────────────────────────────────────────────

def large_marker(data: bytes) -> str:
    """`[LARGE_CONTENT: <size>, SHA256: <16 hex>]` for oversized content, measured and hashed
    over the exact UTF-8 bytes. Public: the Explorer and Diff presentation caps (packet 1282)
    share this vocabulary so one marker reads identically across all three surfaces."""
    size = len(data)
    if size >= 1024 * 1024:
        label = f"{size / (1024 * 1024):.1f}MB"
    else:
        label = f"{size // 1024}KB"
    sha = hashlib.sha256(data).hexdigest()[:16]
    return f"[LARGE_CONTENT: {label}, SHA256: {sha}]"


_large_marker = large_marker


def _maybe_truncate(text: str, threshold: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= threshold:
        return text
    return _large_marker(encoded)


# ── Slugification ─────────────────────────────────────────────────────────────

_UNSAFE = re.compile(r'[/\\:*?"<>|]')


def slugify(name: str) -> str:
    """Return a filesystem-safe slug. Same name always yields same result."""
    s = _UNSAFE.sub("", name)
    s = s.replace(" ", "_")
    s = s.strip("._")
    return s or "unnamed"


# ── File label ────────────────────────────────────────────────────────────────

def make_file_label(fm_file_name: str, job_name: Optional[str] = None) -> str:
    """Derive the top-level folder name for a git export.

    With a job:         {job_slug}_{fm_slug}
    Standalone (no job): manual_{fm_slug}
    """
    fm_slug = slugify(fm_file_name.replace(".fmp12", ""))
    if job_name:
        return f"{slugify(job_name)}_{fm_slug}"
    return f"manual_{fm_slug}"


# ── Item filename helpers ─────────────────────────────────────────────────────

def item_filename(item_id: str, name: str) -> str:
    """Build a .txt filename: {id}_{slug}.txt, or {slug}.txt if no id."""
    slug = slugify(name)
    if item_id:
        return f"{item_id}_{slug}.txt"
    return f"{slug}.txt"


def relationship_filename(rel_id: str, xml_str: str) -> str:
    """Build filename for a relationship: {id}_{left}_{right}.txt."""
    try:
        elem = ET.fromstring(xml_str)

        def _tname(tag: str) -> str:
            side = elem.find(tag)
            if side is None:
                return "unknown"
            ref = side.find("TableOccurrenceReference")
            return slugify(ref.get("name", "unknown")) if ref is not None else "unknown"

        left = _tname("LeftTable")
        right = _tname("RightTable")
        return f"{rel_id}_{left}_{right}.txt"
    except ET.ParseError:
        return f"{rel_id}.txt"


# ── Step rendering (own implementation, no rendering/ dependency) ─────────────

def _render_step(step_elem: ET.Element, show_hidden: bool, threshold: int) -> str:
    """Render one FM script Step element as a plain-text line."""
    name = step_elem.get("name", "")
    disabled = step_elem.get("enable", "True") == "False"

    parts = []
    seen: set[str] = set()

    # Calculation formulas
    for calc in step_elem.findall(".//Calculation"):
        t = (calc.findtext("Text") or "").strip()
        if t and t not in seen:
            t = _apply_hidden(t, show_hidden)
            t = _maybe_truncate(t, threshold)
            parts.append(t)
            seen.add(t)

    # Direct Text elements (dialog messages, labels, etc.)
    for text_elem in step_elem.findall(".//Text"):
        t = (text_elem.text or "").strip()
        if t and t not in seen:
            t = _apply_hidden(t, show_hidden)
            t = _maybe_truncate(t, threshold)
            parts.append(t)
            seen.add(t)

    # Field references
    for ref in step_elem.findall(".//FieldReference"):
        fname = ref.get("name", "")
        tname = ref.get("tableName", "")
        if fname:
            ref_str = f"{tname}::{fname}" if tname else fname
            if ref_str not in seen:
                parts.append(ref_str)
                seen.add(ref_str)

    # Script references (include cross-file source when DataSourceReference is present)
    parent_map = {child: parent for parent in step_elem.iter() for child in parent}
    for ref in step_elem.findall(".//ScriptReference"):
        sname = ref.get("name", "")
        if not sname:
            continue
        parent = parent_map.get(ref)
        ds = parent.find("DataSourceReference") if parent is not None else None
        file_prefix = f'"{ds.get("name")}" :: ' if ds is not None and ds.get("name") else ""
        marker = f"-> {file_prefix}{sname}"
        if marker not in seen:
            parts.append(marker)
            seen.add(marker)

    content = " ; ".join(parts)
    prefix = "[disabled] " if disabled else ""
    return f"{prefix}{name} [ {content} ]" if content else f"{prefix}{name}"


def render_script_steps(
    script_xml: str,
    show_hidden: bool = True,
    threshold: int = DEFAULT_LARGE_THRESHOLD,
) -> str:
    """Render all steps in a Script element as plain text. Returns multi-line string."""
    try:
        root = ET.fromstring(script_xml)
    except ET.ParseError:
        return "(parse error)"
    lines = [_render_step(step, show_hidden, threshold) for step in root.findall(".//Step")]
    return "\n".join(lines)


# ── Per-section renderers ─────────────────────────────────────────────────────

def render_script_structured(name: str, xml_str: str, step_xml: str = "") -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    is_folder = elem.get("isFolder") == "True"
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if is_folder:
        lines.append("Type: Folder")
    elif step_xml:
        try:
            step_root = ET.fromstring(step_xml)
            count = sum(1 for _ in step_root.findall(".//Step"))
            lines.append(f"StepCount: {count}")
        except ET.ParseError:
            pass
    return "\n".join(lines)


def render_script_rendered(
    name: str,
    xml_str: str,
    step_xml: str = "",
    show_hidden: bool = True,
    threshold: int = DEFAULT_LARGE_THRESHOLD,
) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    is_folder = elem.get("isFolder") == "True"
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if is_folder:
        lines.append("Type: Folder")
        return "\n".join(lines)
    lines.append("")
    if step_xml:
        lines.append(render_script_steps(step_xml, show_hidden=show_hidden, threshold=threshold))
    return "\n".join(lines)


def render_cf_structured(name: str, xml_str: str, calc_xml_str: str = "") -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    params = [p.get("name", "?") for p in elem.findall(".//Parameter")]
    lines = [f"Name: {name}", f"ID: {item_id}"]
    lines.append(f"Parameters: {', '.join(params)}" if params else "Parameters: (none)")
    return "\n".join(lines)


def render_cf_rendered(
    name: str,
    xml_str: str,
    calc_xml_str: str = "",
    show_hidden: bool = True,
    threshold: int = DEFAULT_LARGE_THRESHOLD,
) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    is_folder = elem.get("isFolder") == "True"
    params = [p.get("name", "?") for p in elem.findall(".//Parameter")]
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if is_folder:
        lines.append("Type: Folder")
        return "\n".join(lines)
    lines.append(f"Parameters: {', '.join(params)}" if params else "Parameters: (none)")
    if calc_xml_str:
        try:
            calc_root = ET.fromstring(calc_xml_str)
            formula = (calc_root.findtext("./Calculation/Text") or "").strip()
            if formula:
                formula = _apply_hidden(formula, show_hidden)
                formula = _maybe_truncate(formula, threshold)
                lines.append("")
                lines.append("Formula:")
                for fl in formula.splitlines():
                    lines.append(f"  {fl}")
        except ET.ParseError:
            pass
    return "\n".join(lines)


def render_table_structured(name: str, xml_str: str, field_names: list = None) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if field_names is not None:
        lines.append(f"FieldCount: {len(field_names)}")
    return "\n".join(lines)


def render_table_rendered(name: str, xml_str: str, field_names: list = None) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    comment = elem.get("comment", "").strip()
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if comment:
        lines.append(f"Comment: {comment}")
    if field_names:
        lines.append(f"Fields ({len(field_names)}):")
        for fname in field_names:
            lines.append(f"  {fname}")
    else:
        lines.append("Fields: (none)")
    return "\n".join(lines)


def render_layout_structured(name: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    is_folder = elem.get("isFolder") == "True"
    lines = [f"Name: {name}", f"ID: {item_id}"]
    if is_folder:
        lines.append("Type: Folder")
    return "\n".join(lines)


def render_layout_rendered(name: str, xml_str: str) -> str:
    # LayoutCatalog compare_content=false — only presence tracked, no body content.
    return render_layout_structured(name, xml_str)


def render_valuelist_structured(name: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    src = elem.find("Source")
    src_type = src.get("value", "Unknown") if src is not None else "Unknown"
    return "\n".join([f"Name: {name}", f"ID: {item_id}", f"Source: {src_type}"])


def render_valuelist_rendered(name: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)
    item_id = elem.get("id", "")
    src = elem.find("Source")
    src_type = src.get("value", "Unknown") if src is not None else "Unknown"
    source_label = {"Custom": "Custom (static values)", "FromField": "Field values (dynamic)"}.get(
        src_type, src_type
    )
    return "\n".join([f"Name: {name}", f"ID: {item_id}", f"Source: {source_label}"])


def render_relationship_structured(rel_id: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)

    def _tname(tag: str) -> str:
        side = elem.find(tag)
        if side is None:
            return "?"
        ref = side.find("TableOccurrenceReference")
        return ref.get("name", "?") if ref is not None else "?"

    left = _tname("LeftTable")
    right = _tname("RightTable")
    jp_list = elem.find("JoinPredicateList")
    pred_count = len(jp_list.findall("JoinPredicate")) if jp_list is not None else 0
    return "\n".join([
        f"ID: {rel_id}",
        f"Tables: {left}  <->  {right}",
        f"PredicateCount: {pred_count}",
    ])


def render_relationship_rendered(rel_id: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)

    def _tname(tag: str) -> str:
        side = elem.find(tag)
        if side is None:
            return "?"
        ref = side.find("TableOccurrenceReference")
        return ref.get("name", "?") if ref is not None else "?"

    left = _tname("LeftTable")
    right = _tname("RightTable")
    lines = [f"ID: {rel_id}", f"Tables: {left}  <->  {right}"]

    jp_list = elem.find("JoinPredicateList")
    if jp_list is not None:
        for jp in jp_list.findall("JoinPredicate"):
            pred_type = jp.get("type", "")
            lf = jp.find("./LeftField/FieldReference")
            rf = jp.find("./RightField/FieldReference")
            lf_name = lf.get("name", "?") if lf is not None else "?"
            rf_name = rf.get("name", "?") if rf is not None else "?"
            op = "=" if pred_type == "Equal" else pred_type
            lines.append(f"  {left}::{lf_name}  {op}  {right}::{rf_name}")

    for side_tag, side_label in [("LeftTable", "left"), ("RightTable", "right")]:
        side_elem = elem.find(side_tag)
        if side_elem is not None:
            cc = "Yes" if side_elem.get("cascadeCreate") == "True" else "No"
            cd = "Yes" if side_elem.get("cascadeDelete") == "True" else "No"
            lines.append(f"  {side_label}  cascade create={cc}  delete={cd}")

    return "\n".join(lines)


def render_addon_structured(name: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)
    source_uuid = elem.findtext("SourceUUID", "").strip()
    lines = [f"Name: {name}"]
    if source_uuid:
        lines.append(f"PackageUUID: {source_uuid}")
    return "\n".join(lines)


def render_addon_rendered(name: str, xml_str: str) -> str:
    elem = ET.fromstring(xml_str)
    source_uuid = elem.findtext("SourceUUID", "").strip()
    display_name = name.rstrip("/")
    lines = [f"Name: {display_name}"]
    if source_uuid:
        lines.append(f"PackageUUID: {source_uuid}")
        lines.append("Type: Official FM addon package")
    else:
        lines.append("Type: Internal base directory (no package UUID)")
    return "\n".join(lines)
