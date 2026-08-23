"""Generate a self-contained HTML Explorer for a stored FM snapshot.

Public API:
    generate_explorer_html(inputs: list[Artifact]) -> Path

The returned Path is a temp file; caller opens it with webbrowser.open().
All rendering happens in Python at export time — the HTML is pure display.
"""

from __future__ import annotations

import html as _html  # aliased: `html` is used as a local var name in generate_explorer_html
import hashlib
import json
import tempfile
from collections import defaultdict
from corpusfm.core import safe_xml as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import corpusfm
from corpusfm.app.sections import SECTION_ORDER
from corpusfm.core.filenames import ensure_fmp12
from corpusfm.core.git_formatter._renderer import DEFAULT_LARGE_THRESHOLD, large_marker
from corpusfm.core.layout_objects import extract_layout_objects

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact

_VENDOR_DIR = Path(__file__).parent / "vendor"
_ASSETS_DIR = Path(__file__).parent / "assets"
_LONG_PARAMETER_CHARS = 2000


# ── Data builder ───────────────────────────────────────────────────────────────

def _load_vendor(name: str) -> str:
    p = _VENDOR_DIR / name
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _load_asset(name: str) -> str:
    p = _ASSETS_DIR / name
    content = p.read_text(encoding="utf-8") if p.exists() else ""
    if content.startswith("<?xml"):
        content = content[content.index("?>") + 2:].lstrip()
    return content


def _fmt_ts(ts: str) -> str:
    try:
        d, t = ts.split("_", 1)
        return f"{d} {t[:2]}:{t[2:4]}"
    except Exception:
        return ts


def _render_script_steps(
    step_xml: str,
    schema_version: str,
    *,
    include_display_parts: bool = False,
) -> tuple[list[dict], str]:
    """Return (steps_list, body_string) for a script.

    steps_list — structured step dicts for interactive rendering in the Explorer.
    body_string — plain text fallback for search indexing and step counting.
    """
    if not step_xml:
        return [], "(no steps)"
    try:
        from corpusfm.core.rendering.step_renderer import render_script
        from corpusfm.core.rendering.catalog import load_catalog
        catalog, _ = load_catalog(schema_version)
        elem = ET.fromstring(step_xml)
        rendered = render_script(elem, catalog, show_hidden=False)
        steps = [
            {
                "one_line":   rs.one_line,
                "full_text":  rs.full_text,
                "depth":      rs.depth,
                "block_id":   rs.block_id,
                "block_role": rs.block_role,
                "disabled":   rs.disabled,
                "partial":    rs.partial,
                "step_id":    rs.step_id,
                "step_name":  rs.step_name,
                **({"display_parts": rs.display_parts} if include_display_parts else {}),
            }
            for rs in rendered
        ]
        body = "\n".join(("// " if rs.disabled else "   ") + rs.full_text for rs in rendered)
        return steps, body
    except Exception as exc:
        return [], f"(render error: {exc})"


def _format_value_size(byte_count: int) -> str:
    if byte_count < 1024:
        return f"{byte_count} B"
    if byte_count < 1024 * 1024:
        return f"{byte_count / 1024:.1f} KB"
    return f"{byte_count / (1024 * 1024):.1f} MB"


def _pool_long_step_parameters(steps: list[dict], pool: dict[str, str]) -> str:
    """Replace proven long parameter values with references and return bounded body text."""
    body_lines: list[str] = []
    for step in steps:
        parts = step.get("display_parts") or []
        if not parts or "".join(p.get("text", "") for p in parts) != step.get("full_text", ""):
            step.pop("display_parts", None)
            text = step.get("full_text", "")
            body_lines.append(("// " if step.get("disabled") else "   ") + text)
            continue

        pooled_parts: list[dict] = []
        bounded_parts: list[str] = []
        has_long = False
        for part in parts:
            text = part.get("text", "")
            if part.get("kind") == "parameter" and len(text) > _LONG_PARAMETER_CHARS:
                raw = text.encode("utf-8")
                digest = hashlib.sha256(raw).hexdigest()
                pool.setdefault(digest, text)
                marker = f"[Long text · {_format_value_size(len(raw))} · SHA256: {digest[:16]}]"
                pooled_parts.append({
                    "kind": "long", "name": part.get("name", ""), "ref": digest,
                    "marker": marker, "bytes": len(raw), "chars": len(text),
                })
                bounded_parts.append(marker)
                has_long = True
            else:
                pooled_parts.append(part)
                bounded_parts.append(text)

        if has_long:
            step["display_parts"] = pooled_parts
            step["has_long_values"] = True
            step.pop("full_text", None)
            body_text = "".join(bounded_parts)
        else:
            # Ordinary steps remain byte-for-byte compatible and need no structured payload.
            step.pop("display_parts", None)
            step["parameter_safe_inline"] = True
            body_text = step.get("full_text", "")
        body_lines.append(("// " if step.get("disabled") else "   ") + body_text)
    return "\n".join(body_lines)


def _pretty_xml(xml_str: str) -> str:
    """Return indented XML, XML declaration stripped.

    Parsed through safe_xml (entity-expansion/XXE blocked) — a reabsorbed artifact's baked
    xml_sources reach here un-re-parsed, so a raw minidom parse would be a billion-laughs vector.
    """
    if not xml_str:
        return ""
    try:
        elem = ET.fromstring(xml_str)
        ET.indent(elem, space="  ")
        pretty = ET.tostring(elem, encoding="unicode")
        return "\n".join(l for l in pretty.splitlines() if l.strip())
    except Exception:
        return xml_str


def _find_cross_file_calls(step_xml_str: str, this_fm_key: str) -> list:
    """Return [{file, script}] for cross-file Perform Script calls.

    In FMSaveAsXML, a cross-file Perform Script step contains a DataSourceReference
    element with the external file's name and a ScriptReference with the script name.
    Intra-file calls have only a ScriptReference with no DataSourceReference sibling.
    """
    if not step_xml_str:
        return []
    calls: list = []
    seen: set = set()
    try:
        root = ET.fromstring(step_xml_str)
        for step in root.iter("Step"):
            ds_ref = step.find(".//DataSourceReference")
            if ds_ref is None:
                continue
            file_name = ds_ref.get("name", "")
            if not file_name:
                continue
            # A cross-file Perform Script target is a known FM file → canonical .fmp12 form,
            # so it matches this file's key and the loaded-file list regardless of FM looseness.
            file_name = ensure_fmp12(file_name)
            if file_name == ensure_fmp12(this_fm_key):
                continue
            for sr in step.findall(".//ScriptReference"):
                script_name = sr.get("name", "")
                if script_name:
                    key = (file_name, script_name)
                    if key not in seen:
                        seen.add(key)
                        calls.append({"file": file_name, "script": script_name})
    except Exception:
        pass
    return calls


import re as _re

_RGBA_RE = _re.compile(
    r'rgba\(\s*([\d.]+)(%?)\s*,\s*([\d.]+)(%?)\s*,\s*([\d.]+)(%?)\s*,\s*([\d.]+)\s*\)'
)


def _rgba_to_hex(m: _re.Match) -> str | None:
    def _ch(v, pct): return min(255, round(float(v) * 255 / 100 if pct else float(v)))
    r, g, b = _ch(m.group(1), m.group(2)), _ch(m.group(3), m.group(4)), _ch(m.group(5), m.group(6))
    if float(m.group(7)) < 0.05:
        return None
    return f"#{r:02x}{g:02x}{b:02x}"


def _css_rule_bg(rule_body: str) -> str | None:
    """Extract background-color hex from a CSS rule body string, or None."""
    bg = _re.search(r'background-color\s*:\s*(rgba\([^)]+\))', rule_body)
    if not bg:
        return None
    m = _RGBA_RE.search(bg.group(1))
    return _rgba_to_hex(m) if m else None


def _build_style_colors(css_text: str) -> dict[str, str]:
    """Parse ThemeCatalog CSS; return {class_name → hex_bg_color} for :normal .self rules."""
    out: dict[str, str] = {}
    for rm in _re.finditer(
        r'([A-Za-z][A-Za-z0-9_-]*):normal\s+\.self\s*\{([^}]+)\}', css_text
    ):
        bg = _css_rule_bg(rm.group(2))
        if bg:
            out.setdefault(rm.group(1), bg)
    return out


def _extract_wireframe(xml_str: str, style_colors: dict | None = None) -> dict | None:
    """Extract structural wireframe data from a LayoutCatalog XML entry.

    DDR layout XML structure (FMSaveAsXML):
      <Layout width="N" ...>
        <PartsList>
          <Part type="Body" ...>
            <Definition absolute="Y" size="H"/>
            <ObjectList membercount="N">
              <LayoutObject type="Field|Button|..." name="...">
                <Bounds top="..." left="..." bottom="..." right="..."/>
                <LocalCSS name="FM-UUID" displayName="style name">CDATA</LocalCSS>
                <Portal><ObjectList><LayoutObject .../></ObjectList></Portal>  <!-- portal children -->
              </LayoutObject>
            </ObjectList>
          </Part>
        </PartsList>
      </Layout>
    """
    if not xml_str:
        return None
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    try:
        width = int(root.get("width", "0") or "0")
    except (ValueError, TypeError):
        width = 0
    if width <= 0:
        return None

    parts:   list = []
    objects: list = []
    height = 0

    def _b(el):
        b = el.find("Bounds")
        if b is None:
            return None
        try:
            return (int(float(b.get("top", "0"))), int(float(b.get("left", "0"))),
                    int(float(b.get("bottom", "0"))), int(float(b.get("right", "0"))))
        except (ValueError, TypeError):
            return None

    def _collect(obj_list_elem, part_type: str, dx: int = 0, dy: int = 0):
        if obj_list_elem is None:
            return
        for obj in obj_list_elem.findall("LayoutObject"):
            obj_type = obj.get("type", "Unknown")
            obj_name = obj.get("name", "")
            b = _b(obj)
            if b is None:
                continue
            top, left, bottom, right = b[0] + dy, b[1] + dx, b[2] + dy, b[3] + dx
            obj_entry: dict = {
                "type": obj_type, "name": obj_name,
                "top": top, "left": left, "bottom": bottom, "right": right,
                "part": part_type,
            }
            local_css = obj.find("LocalCSS")
            if local_css is not None:
                style_class   = local_css.get("name", "")
                style_display = local_css.get("displayName", "")
                if style_display:
                    obj_entry["style"] = style_display
                fill = None
                local_cdata = (local_css.text or "").strip()
                if local_cdata:
                    lm = _re.search(
                        r'self(?:\.[A-Za-z][A-Za-z0-9_-]*)?:normal\s+\.self\s*\{([^}]+)\}',
                        local_cdata
                    )
                    if lm:
                        fill = _css_rule_bg(lm.group(1))
                if fill is None and style_class and style_colors:
                    fill = style_colors.get(style_class)
                if fill:
                    obj_entry["fill"] = fill
            objects.append(obj_entry)
            # Portal children: bounds are relative to portal top-left
            if obj_type == "Portal":
                _collect(obj.find(".//Portal/ObjectList"), part_type, dx=left, dy=top)
            # Tab/slide panel children: absolute coords (no offset)
            elif obj_type == "TabControl":
                tab_list = obj.find(".//TabControl/TabPanelList")
                if tab_list is not None:
                    for panel in tab_list.findall("TabPanel"):
                        _collect(panel.find("ObjectList"), part_type, dx=dx, dy=dy)
            elif obj_type == "SlideControl":
                panel_list = obj.find(".//SlideControl/PanelControlObjList")
                if panel_list is not None:
                    for panel in panel_list.findall("PanelControlObj"):
                        _collect(panel.find("ObjectList"), part_type, dx=dx, dy=dy)
            elif obj_type == "GroupObject":
                _collect(obj.find("ObjectList"), part_type, dx=dx, dy=dy)

    part_list = root.find("PartsList")
    if part_list is None:
        return None
    for part in part_list.findall("Part"):
        part_type = part.get("type", "Unknown")
        defn = part.find("Definition")
        if defn is None:
            continue
        try:
            absolute = int(defn.get("absolute", "0") or "0")
            size     = int(defn.get("size",     "0") or "0")
        except (ValueError, TypeError):
            continue
        part_bottom = absolute + size
        height = max(height, part_bottom)
        parts.append({
            "type": part_type,
            "top": absolute, "left": 0, "bottom": part_bottom, "right": width,
        })
        _collect(part.find("ObjectList"), part_type)

    if not parts:
        return None
    return {"width": width, "height": max(height, 1), "parts": parts, "objects": objects}


# Matches FM addon UUID keys in two forms:
#   com.fmi.<segments>.<32hexUUID>                       — script, layout, etc.
#   com.fmi.<segments>.<32hexUUID>::<32hexUUID>           — basetable field (hex::hex)
#   com.fmi.<segments>.<readable_name>::<32hexUUID>       — tableoccurrence field (name::hex)
_FM_UUID_KEY_PAT = _re.compile(
    r'com\.fmi\.'           # prefix
    r'(?:[a-zA-Z]+\.)*'     # category segments, e.g. "script." or "basetable.field."
    r'(?:'
        r'[0-9A-Fa-f]{32}(?:::[0-9A-Fa-f]{32})?'          # 32-hex UUID, optionally ::32-hex
        r'|[A-Za-z0-9_|!.]+::(?:text\.)?[0-9A-Fa-f]{32}'  # readable-name(::text.)?::32-hex
    r')'
)


def _resolve_uuids(text: str, name_map: dict[str, str]) -> str:
    """Replace FM addon UUID keys in rendered text with their resolved names."""
    if not name_map or not text:
        return text

    def _sub(m: _re.Match) -> str:
        key = m.group(0)
        resolved = name_map.get(key)
        if resolved is not None:
            return resolved
        # Comment/text refs use compound form TABLE::text.UUID; name_map stores
        # the text as com.fmi.calculation.text.UUID
        if "::text." in key:
            text_uuid = key.rsplit("::text.", 1)[-1]
            resolved = name_map.get(f"com.fmi.calculation.text.{text_uuid}")
            if resolved is not None:
                return resolved
        return key

    return _FM_UUID_KEY_PAT.sub(_sub, text)


def _split_rendered_text(rendered_text: str, fallback_name: str) -> tuple[str, str]:
    """Return (summary_line, body) from rendered_text. Summary = first non-empty line."""
    if not rendered_text:
        return fallback_name, ""
    lines = rendered_text.split("\n")
    for i, line in enumerate(lines):
        if line.strip():
            rest = "\n".join(lines[i + 1:]).strip()
            return line.strip(), rest
    return fallback_name, ""


# ── Sidebar sort keys (precomputed at export; the client only reorders) ─────────

def _created_key(attrs: dict):
    """FM creation order = the numeric item id. None when absent (sorts last)."""
    _id = attrs.get("id", "")
    return int(_id) if isinstance(_id, str) and _id.isdigit() else None


def _field_type_group(attrs: dict) -> str:
    """Group label for the field-type sort — mirrors FM's Manage Database labels
    (Text / Number / Calculation - Text / Summary …)."""
    dt = attrs.get("dataType") or attrs.get("datatype") or ""
    ft = attrs.get("fieldType") or attrs.get("fieldtype") or "Normal"
    if ft == "Normal":
        return dt or "—"
    if ft == "Calculated":
        return f"Calculation - {dt}" if dt else "Calculation"
    if ft == "Summary":
        return "Summary"
    return ft


def _vl_source_group(xml: str) -> str:
    """Value-list source group: Custom Values vs From Field (FM's <Source value>)."""
    try:
        src = ET.fromstring(xml).find("Source")
    except ET.ParseError:
        return "—"
    v = src.get("value", "") if src is not None else ""
    return {"Custom": "Custom Values", "FromField": "From Field"}.get(v, v or "—")


def _cf_signature(xml: str, base: str) -> str:
    """Render a custom function as its signature: Func ( param ; param )."""
    try:
        params = [p.get("name", "") for p in ET.fromstring(xml).findall(".//Parameter")]
    except ET.ParseError:
        return base
    params = [p for p in params if p]
    return f"{base} ( {' ; '.join(params)} )" if params else base


def _cf_avail_group(xml: str) -> str:
    """Custom-function availability group from the <CustomFunction access=…> attr."""
    try:
        acc = ET.fromstring(xml).get("access", "")
    except ET.ParseError:
        return "All accounts"
    return {"All": "All accounts", "Private": "Full access only"}.get(acc, acc or "All accounts")


def _cf_formula_text(xml_sources, name_map: dict | None = None) -> str:
    """The custom-function formula, from its CalcsForCustomFunctions source —
    isolated so it can render as a line-numbered block (line 1 = calc start)."""
    src = next((s for s in xml_sources if s.catalog == "CalcsForCustomFunctions"), None)
    if src is None:
        return ""
    try:
        t = ET.fromstring(src.xml).findtext(".//Calculation/Text") or ""
    except ET.ParseError:
        return ""
    t = t.strip()
    if t and name_map:
        t = _resolve_uuids(t, name_map)
    return t


_FIELD_CALC_HEADER_LABELS = {"Formula:", "Auto-enter formula:", "Validation formula:"}


def _strip_calc_lines(body: str) -> str:
    """Remove the formula blocks (Formula / Auto-enter formula / Validation formula)
    from a rendered field body — they move into line-numbered field_calcs blocks, so
    keeping them in the body would duplicate. Each is a `  X:` header followed by
    4-space-indented continuation lines; a blank line precedes the calc/auto-enter ones.
    Matched strip-insensitively since _split_rendered_text de-indents the first body line."""
    lines = body.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        if lines[i].strip() in _FIELD_CALC_HEADER_LABELS:
            if out and out[-1] == "":
                out.pop()  # drop the blank line render_field put before the header
            i += 1
            while i < n and lines[i].startswith("    "):  # formula continuation lines
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out).strip()


def _build_folder_children_from_artifact(
    section_items: list,
    item_data: dict,
) -> dict[str, list[str]]:
    """Reconstruct folder_children from artifact item.folder_path data.

    Folders are identified by (name, tuple(folder_path)) — unambiguous even
    when two folders share the same name at different nesting depths.
    """
    folder_key_to_id: dict = {}
    for item in section_items:
        if item.is_folder:
            key = (item.name, tuple(item.folder_path))
            folder_key_to_id[key] = item.item_id

    result: dict[str, list[str]] = {}
    for item in section_items:
        if item.is_folder:
            result.setdefault(item.item_id, [])
        if item_data.get(item.item_id, {}).get("is_marker"):
            continue
        if item.folder_path:
            parent_name = item.folder_path[-1]
            parent_fp = tuple(item.folder_path[:-1])
            parent_id = folder_key_to_id.get((parent_name, parent_fp))
            if parent_id is not None:
                result.setdefault(parent_id, []).append(item.item_id)
    return result


_GRAPH_PALETTE = [
    "#4e9eff", "#50c878", "#ff6b6b", "#ffd700",
    "#da70d6", "#40e0d0", "#ff9500", "#87ceeb",
    "#ff69b4", "#7fffd4", "#ffa07a", "#b0c4de",
    "#98fb98", "#dda0dd", "#f0e68c", "#7ec8e3",
]


def _build_graph_data_from_artifact(artifact: "Artifact") -> dict:
    """Extract TO positions and relationship edges from artifact items."""
    to_items = [
        item for item in artifact.items.values()
        if item.section == "TableOccurrenceCatalog" and not item.is_folder and item.xml_sources
    ]
    rel_items = [
        item for item in artifact.items.values()
        if item.section == "RelationshipCatalog" and not item.is_folder and item.xml_sources
    ]
    if not to_items:
        return {"nodes": [], "edges": []}

    nodes: list = []
    node_id_map: dict = {}

    for item in to_items:
        try:
            elem = ET.fromstring(item.xml_sources[0].xml)
        except ET.ParseError:
            continue
        to_id   = elem.get("id", "")
        to_name = elem.get("name", item.name)
        coord = elem.find("CoordRect")
        if coord is None:
            continue
        try:
            top    = int(float(coord.get("top",    "0")))
            left   = int(float(coord.get("left",   "0")))
            bottom = int(float(coord.get("bottom", "60")))
            right  = int(float(coord.get("right",  "120")))
        except ValueError:
            continue
        src_ref    = elem.find("BaseTableSourceReference")
        external   = False
        base_table = to_name
        if src_ref is not None:
            ref_type = src_ref.get("type", "")
            if ref_type == "BaseTableReference":
                bt_ref = src_ref.find("BaseTableReference")
                if bt_ref is not None:
                    base_table = bt_ref.get("name", to_name)
            elif ref_type == "ExternalDataSourceReference":
                external = True
                ds_ref = src_ref.find("DataSourceReference")
                if ds_ref is not None:
                    base_table = ds_ref.get("name", to_name)
            elif ref_type == "ODBCDataSourceReference":   # External SQL Source (ESS) — SQL table target
                external = True
                sql_src = src_ref.find("Source")
                if sql_src is not None and sql_src.get("tableName"):
                    base_table = sql_src.get("tableName")
        col_elem = elem.find("Color")
        if col_elem is not None:
            r = min(255, max(0, int(float(col_elem.get("red",   "120")))))
            g = min(255, max(0, int(float(col_elem.get("green", "120")))))
            b = min(255, max(0, int(float(col_elem.get("blue",  "120")))))
            fm_color = f"#{r:02x}{g:02x}{b:02x}"
        else:
            r = g = b = 120
            fm_color = "#787878"
        if r == g == b:
            color = _GRAPH_PALETTE[hash(base_table) % len(_GRAPH_PALETTE)]
        else:
            color = fm_color
        node = {
            "id": to_id, "name": to_name, "base_table": base_table,
            "external": external,
            "x": left, "y": top,
            "w": max(1, right - left), "h": max(1, bottom - top),
            "color": color,
        }
        nodes.append(node)
        node_id_map[to_id] = node

    edges: list = []
    for item in rel_items:
        try:
            elem = ET.fromstring(item.xml_sources[0].xml)
        except ET.ParseError:
            continue
        left_elem  = elem.find("LeftTable")
        right_elem = elem.find("RightTable")
        if left_elem is None or right_elem is None:
            continue
        lt_ref = left_elem.find("TableOccurrenceReference")
        rt_ref = right_elem.find("TableOccurrenceReference")
        if lt_ref is None or rt_ref is None:
            continue
        from_id   = lt_ref.get("id",   "")
        to_id     = rt_ref.get("id",   "")
        from_name = lt_ref.get("name", "")
        to_name   = rt_ref.get("name", "")
        jp_list    = elem.find("JoinPredicateList")
        predicates: list = []
        edge_type  = "equal"
        if jp_list is not None:
            for jp in jp_list.findall("JoinPredicate"):
                pred_type = jp.get("type", "")
                if pred_type == "CartesianProduct":
                    edge_type = "cartesian"
                    predicates.append("× Cartesian product")
                elif pred_type == "Equal":
                    lf = jp.find(".//LeftField/FieldReference")
                    rf = jp.find(".//RightField/FieldReference")
                    lf_name = lf.get("name", "?") if lf is not None else "?"
                    rf_name = rf.get("name", "?") if rf is not None else "?"
                    predicates.append(f"{from_name}::{lf_name} = {to_name}::{rf_name}")
                else:
                    predicates.append(pred_type)
        if from_id not in node_id_map or to_id not in node_id_map:
            continue
        edges.append({
            "from_id": from_id, "to_id": to_id,
            "type": edge_type, "predicates": predicates,
        })

    # Degree = relationships touching each TO; drives hub emphasis in the graph.
    degree: dict = {}
    for e in edges:
        degree[e["from_id"]] = degree.get(e["from_id"], 0) + 1
        degree[e["to_id"]] = degree.get(e["to_id"], 0) + 1
    for n in nodes:
        n["degree"] = degree.get(n["id"], 0)

    return {"nodes": nodes, "edges": edges}


# A field's inbound reference is categorised by the SOURCE object's section, NOT by
# the edge-type name.  A script step that reads a field emits a "FieldReference"-typed
# edge (as does a field's own calc), so grouping by type mislabels scripts and field
# calcs as custom functions and drops layouts entirely.  from_id is "<Section>/<id>".
_FIELD_XREF_SECTIONS: dict = {
    "ScriptCatalog":          "used_in_scripts",
    "CustomFunctionsCatalog": "used_in_cfs",
    "LayoutCatalog":          "used_in_layouts",
    "RelationshipCatalog":    "used_in_relationships",
    "FieldsForTables":        "used_in_field_calcs",
}


def _field_inbound_xref(records: list) -> dict:
    """Group a field's inbound xref edges into panel buckets by source section,
    one entry per source object (a field hit in many steps lists its script once)."""
    buckets: dict = {}
    seen: set = set()
    for r in records:
        if r.from_id in seen:
            continue
        seen.add(r.from_id)
        key = _FIELD_XREF_SECTIONS.get(r.from_id.split("/", 1)[0])
        if key is not None:
            buckets.setdefault(key, []).append({"id": r.from_id, "name": r.from_name})
    return buckets


def _uniq_refs(refs: list) -> list:
    """Order-preserving dedup of xref panel entries by (id, name). The xref graph
    emits one edge per reference site, so a field used in several steps repeats."""
    seen: set = set()
    out: list = []
    for r in refs:
        k = (r.get("id"), r.get("name"))
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


# ── Object xref panel — dispatch by (owner section, edge type, direction) (packet 1132) ──
# The object xref panel used to hand-pick a few edge types per section in a big if/elif,
# silently dropping the rest — a `.type` could be surfaced for one object family/direction
# and vanish for another (e.g. a layout showed the scripts it *calls* but not the scripts
# that *open* it). This table makes coverage explicit and per-(section, type, direction):
# direction "from" = this object is the edge SOURCE (other end = edge target, r.to);
# "to" = this object is the edge TARGET (other end = edge source, r.from_id).
# EVERY (owner section, type, direction) that can reach a handled object is either given a
# surfaced group here OR listed in _XREF_HIDDEN with a reason — the coverage guard
# (tests/test_explorer_xref_coverage.py) fails the build on any unaccounted combo, so a new
# edge type can never again silently disappear per-family/per-direction. (Field objects use
# the separate section-keyed _field_inbound_xref path.)
_XREF_DISPATCH: dict[tuple, tuple] = {
    ("ScriptCatalog", "ScriptReference", "from"):        ("calls", "Calls"),
    ("ScriptCatalog", "ScriptReference", "to"):          ("called_by", "Called by"),
    ("ScriptCatalog", "FieldReference", "from"):         ("uses_fields", "Uses fields"),
    ("CustomFunctionsCatalog", "CustomFunctionField", "from"): ("uses_fields", "Uses fields"),
    # CF callers + outbound CF calls (packet 1283). Packet 1132 parked these in _XREF_HIDDEN as
    # "surfaced via evidence", but evidence tools are MCP-only — the human panel showed a CF as
    # used (the unused badge reads these same edges) while refusing to show by what. Group keys
    # reuse the existing panel blocks (used_in_* vocabulary matches the field panel's buckets);
    # only used_in_menus is a new block in the template.
    ("CustomFunctionsCatalog", "CustomFunctionReference", "to"):   ("used_in_cfs", "Used in custom functions"),
    ("CustomFunctionsCatalog", "CustomFunctionReference", "from"): ("calls_cfs", "Calls custom functions"),
    ("CustomFunctionsCatalog", "FieldCFCall", "to"):     ("used_in_field_calcs", "Used in field calculations"),
    ("CustomFunctionsCatalog", "LayoutCFCall", "to"):    ("used_in_layouts", "Used in layouts"),
    ("CustomFunctionsCatalog", "MenuCFCall", "to"):      ("used_in_menus", "Used in custom menus"),
    ("TableOccurrenceCatalog", "RelationshipTO", "from"): ("related_tos", "Related table occurrences"),
    ("LayoutCatalog", "LayoutScript", "from"):           ("calls_scripts", "Calls scripts"),
    ("LayoutCatalog", "LayoutField", "from"):            ("uses_fields", "Uses fields"),
    ("LayoutCatalog", "LayoutCalculation", "from"):      ("uses_fields", "Uses fields"),
    ("LayoutCatalog", "LayoutValueList", "from"):        ("uses_value_lists", "Uses value lists"),
    ("LayoutCatalog", "LayoutCFCall", "from"):           ("calls_cfs", "Calls custom functions"),
    ("LayoutCatalog", "ScriptNavigate", "to"):           ("opened_by_scripts", "Opened by scripts"),
    ("ValueListCatalog", "LayoutValueList", "to"):       ("used_in_layouts", "Used in layouts"),
    ("ValueListCatalog", "FieldValidation", "to"):       ("validates_fields", "Validates fields"),
    ("ValueListCatalog", "RelationshipSort", "to"):      ("used_in_relationships", "Used in relationships"),
    ("ValueListCatalog", "ScriptSort", "to"):            ("used_in_scripts", "Used in scripts"),
}

# Combinations that reach a handled object but are intentionally NOT shown in its xref panel,
# each with the reason (usually: surfaced on another, more natural surface). Keeping them here —
# rather than dropping them silently — is what lets the coverage guard prove nothing leaks.
_XREF_HIDDEN: dict[tuple, str] = {
    ("ScriptCatalog", "SQLQuery", "from"):          "SQL table refs surfaced via workflows/evidence, not the object panel",
    ("ScriptCatalog", "DynamicDispatch", "from"):   "dynamic dispatch is an honest-limit note with no resolved target to link",
    ("ScriptCatalog", "ScriptNavigate", "from"):    "surfaced on the destination layout as 'Opened by scripts'",
    ("ScriptCatalog", "ScriptNavigateTO", "from"):  "TO navigation surfaced via structural shortcuts / workflows",
    ("ScriptCatalog", "TriggerCascade", "from"):    "trigger cascade surfaced via workflows",
    ("ScriptCatalog", "TriggerCascade", "to"):      "trigger cascade surfaced via workflows",
    ("ScriptCatalog", "LayoutScript", "to"):        "layout/button trigger surfaced via workflows",
    ("ScriptCatalog", "MenuScript", "to"):          "custom-menu trigger surfaced via workflows",
    ("ScriptCatalog", "FileScript", "to"):          "file-level trigger surfaced via workflows",
    ("ScriptCatalog", "PrivilegeAccess", "to"):     "access surfaced on the security page",
    ("ScriptCatalog", "ScriptSort", "from"):        "value list used in a sort step surfaced on that value list",
    ("CustomFunctionsCatalog", "PrivilegeAccess", "to"):         "access surfaced on the security page",
    ("LayoutCatalog", "PrivilegeAccess", "to"):     "access surfaced on the security page",
    ("ValueListCatalog", "PrivilegeAccess", "to"):  "access surfaced on the security page",
    ("RelationshipCatalog", "RelationshipJoin", "from"): "join fields surfaced via structural shortcuts",
    ("RelationshipCatalog", "RelationshipSort", "from"): "value list sort surfaced on that value list",
    # RelationshipTO edges connect two TableOccurrenceCatalog item ids (via = the relationship);
    # they reach the TO object, never the relationship object. The relationship's two-way emission
    # means each neighbour appears once as 'from' (surfaced above) and once as 'to' (its mirror).
    ("TableOccurrenceCatalog", "RelationshipTO", "to"):  "reciprocal duplicate of the surfaced adjacency",
    ("TableOccurrenceCatalog", "ScriptNavigateTO", "to"): "Go to Related Record navigation surfaced via evidence",
}


def _build_object_xref_groups(owner_section: str, froms: list, tos: list) -> dict:
    """Group a non-field object's xref edges into named panel buckets via _XREF_DISPATCH.
    Generic replacement for the old per-section if/elif: an unaccounted (section, type,
    direction) combo is dropped here and caught by the coverage guard, never silently
    surfaced or lost. Cross-file panels (cross_calls/cross_files, derived from XML rather
    than edges) are handled by the caller, not here."""
    groups: dict = {}
    for direction, records in (("from", froms), ("to", tos)):
        for r in records:
            spec = _XREF_DISPATCH.get((owner_section, r.type, direction))
            if spec is None:
                continue
            ref = ({"id": r.to, "name": r.to_name} if direction == "from"
                   else {"id": r.from_id, "name": r.from_name})
            if getattr(r, "via", ""):   # trigger event / "button" (LayoutScript), nav kind, … — kept for callers
                ref["via"] = r.via
            groups.setdefault(spec[0], []).append(ref)
    return {k: _uniq_refs(v) for k, v in groups.items()}


def _inject_structural_shortcuts(sections: dict, artifact: "Artifact", name_map: dict) -> None:  # noqa: C901
    """Bake one-way structural nav shortcuts onto TableOccurrence + Relationship items.

    Resolves EVERY target in Python against the structures actually generated above
    (the finished ``sections`` dict + the artifact items). A target that resolves bakes
    a concrete clickable target (item id / field-folder key + its section); a target that
    does NOT resolve bakes an INERT placeholder (``ok: False``, no target) — the template
    emits no navigate binding for it, so a wrong target can never dead-link to a blank pane.

    Invariant (asserted in the tests): every ``ok: True`` link points at a real key in its
    section's ``item_data``; everything else is the placeholder.
    """
    to_sec  = sections.get("TableOccurrenceCatalog")
    rel_sec = sections.get("RelationshipCatalog")
    if not to_sec and not rel_sec:
        return

    bt_sec  = sections.get("BaseTableCatalog")
    fld_sec = sections.get("FieldsForTables")

    # base-table name -> BaseTableCatalog item id (real generated keys)
    bt_id_by_name: dict[str, str] = {}
    if bt_sec:
        for _iid, _d in bt_sec["item_data"].items():
            if not _d.get("is_folder") and not _d.get("is_marker") and not _d.get("is_separator"):
                bt_id_by_name.setdefault(_d.get("display_name", ""), _iid)

    # the synthetic field-folder keys that ACTUALLY exist (_FLD_<base table name>),
    # plus (base table name, bare field name) -> field item id for match keys
    fld_folder_keys: set[str] = set()
    fld_id_by_table_field: dict[tuple, str] = {}
    if fld_sec:
        fld_data = fld_sec["item_data"]
        for _k, _d in fld_data.items():
            if _k.startswith("_FLD_") and _d.get("is_folder"):
                fld_folder_keys.add(_k)
        for _k in fld_sec.get("folder_children", {}):
            if _k in fld_folder_keys:
                tname = fld_data.get(_k, {}).get("display_name", "")
                for _child in fld_sec["folder_children"][_k]:
                    _cd = fld_data.get(_child, {})
                    bare = (_cd.get("display_name") or "")
                    if bare:
                        fld_id_by_table_field.setdefault((tname, bare), _child)

    # TO name -> (TO item id, base-table name) read off the real TO XML
    to_id_by_name: dict[str, str] = {}
    to_basetable_by_name: dict[str, str] = {}
    for _item in artifact.items.values():
        if _item.section != "TableOccurrenceCatalog" or _item.is_folder:
            continue
        if _item.attributes.get("isFolder") == "Marker":
            continue
        _toname = _item.name
        to_id_by_name.setdefault(_toname, _item.item_id)
        if _item.xml_sources:
            try:
                _te = ET.fromstring(_item.xml_sources[0].xml)
                _bref = _te.find("BaseTableSourceReference/BaseTableReference")
                if _bref is not None:
                    _btn = _bref.get("name", "")
                    if name_map:
                        _btn = name_map.get(_btn, _btn)
                    to_basetable_by_name[_toname] = _btn
            except ET.ParseError:
                pass

    def _resolve_name(raw: str) -> str:
        return name_map.get(raw, raw) if name_map else raw

    def _folder_link(base_table_name: str) -> dict:
        key = f"_FLD_{base_table_name}"
        if key in fld_folder_keys:
            return {"kind": "fields", "label": f"Fields · {base_table_name}",
                    "ok": True, "target": key, "section": "FieldsForTables"}
        return {"kind": "fields", "label": f"Fields · {base_table_name}",
                "ok": False, "reason": f"no field folder for base table “{base_table_name}” ({key})"}

    def _basetable_link(base_table_name: str) -> dict:
        iid = bt_id_by_name.get(base_table_name)
        if iid:
            return {"kind": "base_table", "label": f"Base table · {base_table_name}",
                    "ok": True, "target": iid, "section": "BaseTableCatalog"}
        return {"kind": "base_table", "label": f"Base table · {base_table_name}",
                "ok": False, "reason": f"no BaseTableCatalog item named “{base_table_name}”"}

    def _to_link(to_name: str) -> dict:
        iid = to_id_by_name.get(to_name)
        if iid:
            return {"kind": "table_occurrence", "label": f"Table occurrence · {to_name}",
                    "ok": True, "target": iid, "section": "TableOccurrenceCatalog"}
        return {"kind": "table_occurrence", "label": f"Table occurrence · {to_name}",
                "ok": False, "reason": f"no TableOccurrenceCatalog item named “{to_name}”"}

    def _matchkey_link(to_name: str, field_name: str) -> dict:
        label = f"{to_name}::{field_name}"
        btn = to_basetable_by_name.get(to_name)
        iid = fld_id_by_table_field.get((btn, field_name)) if btn else None
        if iid:
            return {"kind": "match_key", "label": label,
                    "ok": True, "target": iid, "section": "FieldsForTables"}
        reason = (f"no field “{field_name}” under base table “{btn}”"
                  if btn else f"base table for occurrence “{to_name}” unknown")
        return {"kind": "match_key", "label": label, "ok": False, "reason": reason}

    # ── #10 — Table occurrence → field folder + base table ───────────────────
    _tos_by_basetable: dict[str, list[str]] = {}
    if to_sec:
        for _item in artifact.items.values():
            if _item.section != "TableOccurrenceCatalog" or _item.is_folder:
                continue
            if _item.attributes.get("isFolder") == "Marker":
                continue
            entry = to_sec["item_data"].get(_item.item_id)
            if entry is None:
                continue
            btn = to_basetable_by_name.get(_item.name)
            links: list[dict] = []
            if btn:
                links.append(_folder_link(btn))
                links.append(_basetable_link(btn))
                _tos_by_basetable.setdefault(btn, []).append(_item.name)
            else:
                links.append({"kind": "base_table", "label": "Base table",
                              "ok": False,
                              "reason": f"occurrence “{_item.name}” has no resolvable base table"})
            if links:
                entry["struct_links"] = links

    # ── Base table → its table occurrences (packet 1285) — the reverse of #10 ──
    # Built from the same walk, so every listed TO resolved a base table above; _to_link
    # re-resolves the target id and bakes the inert placeholder if it somehow cannot.
    if bt_sec and _tos_by_basetable:
        for _item in artifact.items.values():
            if _item.section != "BaseTableCatalog" or _item.is_folder:
                continue
            if _item.attributes.get("isFolder") == "Marker":
                continue
            entry = bt_sec["item_data"].get(_item.item_id)
            if entry is None:
                continue
            to_names = _tos_by_basetable.get(entry.get("display_name", _item.name))
            if to_names:
                entry["struct_links"] = [_to_link(n) for n in sorted(set(to_names))]

    # ── #11 — Relationship → match keys + per-side field folders + TOs + base tables ─
    if rel_sec:
        for _item in artifact.items.values():
            if _item.section != "RelationshipCatalog" or _item.is_folder:
                continue
            if _item.attributes.get("isFolder") == "Marker" or not _item.xml_sources:
                continue
            entry = rel_sec["item_data"].get(_item.item_id)
            if entry is None:
                continue
            try:
                _re = ET.fromstring(_item.xml_sources[0].xml)
            except ET.ParseError:
                continue

            side_tos: list[str] = []
            for _tag in ("LeftTable", "RightTable"):
                _ref = _re.find(f"{_tag}/TableOccurrenceReference")
                if _ref is not None:
                    side_tos.append(_resolve_name(_ref.get("name", "")))

            mk_links: list[dict] = []
            for _jp in _re.findall("JoinPredicateList/JoinPredicate"):
                for _ftag in ("LeftField", "RightField"):
                    _fr = _jp.find(f"{_ftag}/FieldReference")
                    if _fr is None:
                        continue
                    _fn = _resolve_name(_fr.get("name", ""))
                    _to_ref = _fr.find("TableOccurrenceReference")
                    _ton = _resolve_name(_to_ref.get("name", "")) if _to_ref is not None else ""
                    if _fn and _ton:
                        mk_links.append(_matchkey_link(_ton, _fn))

            folder_links: list[dict] = []
            to_links: list[dict] = []
            bt_links: list[dict] = []
            _seen_btn: set[str] = set()
            for _ton in side_tos:
                if not _ton:
                    continue
                to_links.append(_to_link(_ton))
                btn = to_basetable_by_name.get(_ton)
                if btn:
                    if btn in _seen_btn:
                        continue
                    _seen_btn.add(btn)
                    folder_links.append(_folder_link(btn))
                    bt_links.append(_basetable_link(btn))
                else:
                    # base table for this occurrence is unknown — surface it as inert
                    # placeholders for both target kinds (per-target visibility).
                    reason = f"base table for occurrence “{_ton}” unknown"
                    folder_links.append({"kind": "fields", "label": f"Fields · {_ton}",
                                         "ok": False, "reason": reason})
                    bt_links.append({"kind": "base_table", "label": f"Base table · {_ton}",
                                     "ok": False, "reason": reason})

            groups = {}
            if mk_links:     groups["match_keys"]   = _dedup_struct(mk_links)
            if folder_links: groups["field_folders"] = _dedup_struct(folder_links)
            if to_links:     groups["table_occurrences"] = _dedup_struct(to_links)
            if bt_links:     groups["base_tables"]    = _dedup_struct(bt_links)
            if groups:
                entry["struct_groups"] = groups


def _dedup_struct(links: list[dict]) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for l in links:
        k = (l.get("kind"), l.get("target"), l.get("label"), l.get("ok"))
        if k not in seen:
            seen.add(k)
            out.append(l)
    return out


def _link_object_field_ids(obj_dicts: list, uses_fields: list) -> None:
    """packet 1156: resolve each layout object's field binding (``TO::field``) to the field's Explorer
    item_id, using the layout's ALREADY-RESOLVED ``uses_fields`` xref (``[{id, name}]`` with name =
    ``TO::field``). Mutates obj_dicts in place, setting ``field_item_id`` on a resolvable binding — so the
    Objects tab links fields by id exactly like the xref panel. An unresolvable binding (external/unknown
    TO, or a layout with no uses_fields) gets no id and the template renders it as plain text, never a
    dead link. Scripts are unaffected (they resolve by their unique name)."""
    uf = {e.get("name"): e.get("id") for e in (uses_fields or []) if e.get("id")}
    if not uf:
        return
    for od in obj_dicts:
        f, fto = od.get("field"), od.get("field_to")
        if f and fto:
            fid = uf.get(f"{fto}::{f}")
            if fid:
                od["field_item_id"] = fid


def _relabel_relationship_xrefs(sections: dict) -> None:
    """packet 1157: FileMaker relationships have no name (keyed by id), so the xref *Used in
    relationships* group listed them by numeric id (``2``, ``3``, ``5``). Remap each entry's display
    name to the relationship item's composed ``Left → Right`` display_name (built during the item pass),
    so the xref reads like a name AND matches the relationship item title it links to. Navigation stays
    by id — display only."""
    rel_sec = sections.get("RelationshipCatalog")
    if not rel_sec:
        return
    name_by_id = {iid: d.get("display_name")
                  for iid, d in (rel_sec.get("item_data") or {}).items()
                  if d.get("display_name") and not d.get("is_folder")}
    if not name_by_id:
        return
    for sec in sections.values():
        if not isinstance(sec, dict):
            continue
        for d in (sec.get("item_data") or {}).values():
            for entry in ((d.get("xref") or {}).get("used_in_relationships") or []):
                nm = name_by_id.get(entry.get("id"))
                if nm:
                    entry["name"] = nm


def _build_sections_from_artifact(artifact: "Artifact") -> dict:  # noqa: C901
    """Build per-file Explorer data dict from an Artifact (ingestion-based path)."""
    identity  = artifact.identity
    provenance = artifact.provenance
    # Prefer the server-injected sidecar map, else the self-contained map baked into
    # the artifact at ingest (Artifact.name_map). Without the fallback, addon UUID
    # references (comments, script/field refs) render unresolved when the artifact
    # carries its own map but no sidecar was injected.
    _nm: dict = getattr(artifact, "_name_map", None) or getattr(artifact, "name_map", None) or {}
    _schema_ver: str = provenance.catalog_version

    ingested_at = provenance.ingested_at or ""
    ts_display = ingested_at[:16].replace("T", " ") if ingested_at else ""
    ts_str = ingested_at.replace("-", "").replace(":", "").replace("T", "_")[:15]

    metadata = {
        "fm_key":            identity.file_name,
        "timestamp":         ts_str,
        "timestamp_display": ts_display,
        "label":             identity.file_name,
        "schema_version":    provenance.catalog_version,
        "fm_version":        identity.fm_version,
        "generated_at":      datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "app_version":       corpusfm.__version__,
        # Ingest build = the version that BAKED this artifact's xref + rendered_text
        # (neither fully self-heals — xref not at all). If it lags the app version,
        # the baked layers may be stale → re-import. render_version stamps the heal layer.
        "ingest_build":      provenance.corpusfm_build or "?",
        "render_version":    getattr(artifact, "render_version", ""),
        "is_addon":          artifact.type.value == "AddonXML",
        "has_name_map":      any(
            i.xml_key != i.name
            for i in artifact.items.values()
            if i.section == "ScriptCatalog" and not i.is_folder
        ) if artifact.type.value == "AddonXML" else False,
    }

    # Build style_colors from ThemeCatalog items
    style_colors: dict[str, str] = {}
    for _item in artifact.items.values():
        if _item.section == "ThemeCatalog" and not _item.is_folder:
            for _src in _item.xml_sources:
                try:
                    _te = ET.fromstring(_src.xml)
                    _css = _te.find("CSS")
                    if _css is not None and _css.text:
                        style_colors.update(_build_style_colors(_css.text))
                except ET.ParseError:
                    pass

    # Group items by section in document order (dict preserves insertion order)
    sections_items: dict[str, list] = {}
    for _item in artifact.items.values():
        sections_items.setdefault(_item.section, []).append(_item)

    # External TO map for cross-file link detection
    external_tos_map: dict[str, str] = {}
    for _item in sections_items.get("TableOccurrenceCatalog", []):
        if not _item.is_folder and _item.xml_sources:
            try:
                _te = ET.fromstring(_item.xml_sources[0].xml)
                _src_ref = _te.find("BaseTableSourceReference")
                if _src_ref is not None and _src_ref.get("type") == "ExternalDataSourceReference":
                    _ds_ref = _src_ref.find("DataSourceReference")
                    ext_name = _ds_ref.get("name", _item.name) if _ds_ref is not None else _item.name
                    external_tos_map[_item.name] = ext_name
            except ET.ParseError:
                pass

    sections: dict = {}
    search_index: list = []
    long_values: dict[str, str] = {}
    dead_count_by_section: dict[str, int] = {}

    _is_addon_xml = artifact.type.value == "AddonXML"

    # O(1) xref lookups (packet 1132). artifact.xrefs_from/to linear-scan the whole
    # xref_map on every call; the panel builder calls them once per object, so the old
    # code was O(objects × edges) — ~27 s of pure lookup on a ~10k-object solution.
    # Index once here (single pass), then every per-object lookup is O(1).
    _from_idx: dict = defaultdict(list)
    _to_idx: dict = defaultdict(list)
    for _r in artifact.xref_map:
        _from_idx[_r.from_id].append(_r)
        _to_idx[_r.to].append(_r)

    for section_key, section_label in SECTION_ORDER:
        # BaseDirectoryCatalog is FM's internal package registry — meaningful only
        # in SaveAsXML (host file), not in the addon XML itself.
        if section_key == "BaseDirectoryCatalog" and _is_addon_xml:
            continue
        items_in_section = sections_items.get(section_key, [])

        # ── FieldsForTables: virtual table-folder entries ─────────────────────
        if section_key == "FieldsForTables":
            tables: dict[str, list] = {}
            for _item in items_in_section:
                if not _item.is_folder and _item.attributes.get("isFolder") != "Marker":
                    if _item.folder_path:
                        tname = _item.folder_path[0]
                    elif "::" in _item.xml_key:
                        tname = _item.xml_key.split("::", 1)[0]
                    else:
                        tname = "Unknown"
                    tables.setdefault(tname, []).append(_item)

            total_field_count = sum(len(v) for v in tables.values())
            if not tables or total_field_count == 0:
                continue

            item_data: dict = {}
            folder_children: dict = {}
            item_names_fft: list = []

            for tname in sorted(tables.keys()):
                vkey = f"_FLD_{tname}"
                fc_count = len(tables[tname])
                item_data[vkey] = {
                    "display_name": tname,
                    "summary": f"📁 {tname}",
                    "body": f"{fc_count} field{'s' if fc_count != 1 else ''}",
                    "is_folder": True, "is_separator": False, "is_marker": False,
                    "xref": {}, "xml_sources": [], "xml": "", "dead_end": False,
                }
                item_names_fft.append(vkey)
                children: list = []
                for _item in sorted(tables[tname], key=lambda it: it.name.split("::", 1)[-1].lower()):
                    summary, body = _split_rendered_text(_item.rendered_text, _item.name)
                    xref_f: dict = _field_inbound_xref(_to_idx.get(_item.item_id, ()))
                    xml_srcs = [{"catalog": s.catalog, "xml": _pretty_xml(s.xml)} for s in _item.xml_sources]
                    _fld_entry: dict = {
                        "display_name": _item.name.split("::", 1)[-1],  # bare field name for the sidebar; filter_text keeps TABLE::FIELD
                        "filter_text":  _item.name,
                        "summary": summary, "body": body,
                        "is_folder": False, "is_separator": False, "is_marker": False,
                        "xref": xref_f,
                        "xml_sources": xml_srcs,
                        "xml": xml_srcs[0]["xml"] if xml_srcs else "",
                        "attrs": _item.attributes,
                        "dead_end": _item.dead_end,
                    }
                    _ck = _created_key(_item.attributes)
                    if _ck is not None:
                        _fld_entry["sort_created"] = _ck
                    _fld_entry["sort_type"] = _field_type_group(_item.attributes)
                    if _item.xml_sources:
                        try:
                            _fe = ET.fromstring(_item.xml_sources[0].xml)
                            _ft = _fe.get("fieldType") or _fe.get("fieldtype", "Normal")
                            _field_calcs: list[dict] = []

                            def _xcalc(el: ET.Element) -> str:
                                # Descendant search (.//): FM nests auto-enter calcs as
                                # AutoEnter/Calculated/Calculation/Text, not a direct child.
                                # Mirrors render_field's _calc_text — no _ADDON_CMT_LF_PAT:
                                # the resolved comment fragment carries its own trailing
                                # newline, so re-inserting one double-spaced the line.
                                t = el.find(".//Calculation/Text")
                                if t is not None and t.text:
                                    return t.text.strip()
                                c = el.find(".//Calculation")
                                if c is not None and c.text:
                                    return c.text.strip()
                                return ""

                            if _ft == "Calculated":
                                _f = _xcalc(_fe)
                                if _f:
                                    if _nm: _f = _resolve_uuids(_f, _nm)
                                    _field_calcs.append({"label": "Formula", "text": _f})

                            # FM encodes the auto-enter kind in AutoEnter@type (the old
                            # `calculation="True"` read was dead — see render_field).
                            _auto = _fe.find("AutoEnter")
                            if _auto is not None and _auto.get("type") == "Calculated" and _ft != "Calculated":
                                _f = _xcalc(_auto)
                                if _f:
                                    if _nm: _f = _resolve_uuids(_f, _nm)
                                    _field_calcs.append({"label": "Auto-enter formula", "text": _f})

                            _val = _fe.find("Validation")
                            if _val is not None:
                                _f = _xcalc(_val)
                                if _f:
                                    if _nm: _f = _resolve_uuids(_f, _nm)
                                    _field_calcs.append({"label": "Validation formula", "text": _f})

                            if _field_calcs:
                                _fld_entry["field_calcs"] = _field_calcs
                                # Formulas now live in line-numbered blocks — drop them
                                # from the body so they aren't shown twice.
                                _fld_entry["body"] = _strip_calc_lines(_fld_entry["body"])
                        except ET.ParseError:
                            pass
                    item_data[_item.item_id] = _fld_entry
                    item_names_fft.append(_item.item_id)
                    children.append(_item.item_id)
                    search_index.append({
                        "section": section_key, "item": _item.item_id,
                        "display_name": _item.name,
                        "text": f"{tname}::{_item.name}\n{_item.rendered_text}",
                        "summary": summary,
                    })
                    if _item.dead_end:
                        dead_count_by_section[section_key] = dead_count_by_section.get(section_key, 0) + 1
                folder_children[vkey] = children

            sections[section_key] = {
                "label": section_label,
                "item_names": item_names_fft,
                "item_data": item_data,
                "folder_children": folder_children,
                "default_collapsed": True,
                "display_count": total_field_count,
            }
            continue

        if not items_in_section:
            continue

        item_data = {}

        for _item in items_in_section:
            is_marker    = _item.attributes.get("isFolder") == "Marker"
            is_separator = _item.attributes.get("isSeparatorItem") == "True"
            is_fldr      = _item.is_folder

            if is_marker:
                item_data[_item.item_id] = {
                    "display_name": _item.name, "summary": "", "body": "",
                    "is_folder": False, "is_separator": False, "is_marker": True,
                    "xref": {}, "xml_sources": [], "xml": "", "dead_end": False,
                }
                continue

            summary, body = _split_rendered_text(_item.rendered_text, _item.name)
            search_rendered = _item.rendered_text
            xml_srcs = [{"catalog": s.catalog, "xml": _pretty_xml(s.xml)} for s in _item.xml_sources]
            primary_xml = xml_srcs[0]["xml"] if xml_srcs else ""

            xref_item: dict = {}
            if not is_fldr and not is_separator:
                froms = _from_idx.get(_item.item_id, ())
                tos   = _to_idx.get(_item.item_id, ())

                # Generic, dispatch-driven grouping (packet 1132) — replaces the old
                # per-section if/elif cherry-pick; coverage is pinned per (section, type,
                # direction) by _XREF_DISPATCH + the coverage guard.
                xref_item.update(_build_object_xref_groups(section_key, froms, tos))

                # Cross-file panels are derived from XML (not xref edges), so they stay as
                # per-section special cases alongside the generic groups.
                if section_key == "ScriptCatalog":
                    step_src = next((s for s in _item.xml_sources if s.catalog != section_key), None)
                    if step_src is None and _item.xml_sources:
                        step_src = _item.xml_sources[0]
                    if step_src:
                        cross = _find_cross_file_calls(step_src.xml, identity.file_name)
                        if cross:
                            xref_item["cross_calls"] = cross

                elif section_key == "RelationshipCatalog":
                    if external_tos_map and _item.xml_sources:
                        try:
                            _cross: list[dict] = []
                            _seen_ext: set[str] = set()
                            _xml_e = ET.fromstring(_item.xml_sources[0].xml)
                            for _side_tag in ("LeftTable", "RightTable"):
                                _side = _xml_e.find(_side_tag)
                                if _side is not None:
                                    _to_ref = _side.find("TableOccurrenceReference")
                                    if _to_ref is not None:
                                        _to_name = _to_ref.get("name", "")
                                        if _to_name in external_tos_map:
                                            _ef = external_tos_map[_to_name]
                                            if _ef not in _seen_ext:
                                                _seen_ext.add(_ef)
                                                _cross.append({"file": _ef})
                            if _cross:
                                xref_item["cross_files"] = _cross
                        except ET.ParseError:
                            pass

                elif section_key == "ValueListCatalog":
                    if external_tos_map and _item.xml_sources and len(_item.xml_sources) > 1:
                        try:
                            _cross: list[dict] = []
                            _seen_ext: set[str] = set()
                            _opts_e = ET.fromstring(_item.xml_sources[1].xml)
                            for _fref in _opts_e.findall(".//FieldReference"):
                                _to_ref2 = _fref.find("TableOccurrenceReference")
                                if _to_ref2 is not None:
                                    _to_name2 = _to_ref2.get("name", "")
                                    if _to_name2 in external_tos_map:
                                        _ef2 = external_tos_map[_to_name2]
                                        if _ef2 not in _seen_ext:
                                            _seen_ext.add(_ef2)
                                            _cross.append({"file": _ef2})
                            if _cross:
                                xref_item["cross_files"] = _cross
                        except ET.ParseError:
                            pass

            entry: dict = {
                "display_name": _item.name,
                "summary": summary, "body": body,
                "is_folder": is_fldr, "is_separator": is_separator, "is_marker": False,
                "xref": xref_item,
                "xml_sources": xml_srcs,
                "xml": primary_xml,
                "attrs": _item.attributes,
                "dead_end": _item.dead_end,
            }
            _ck = _created_key(_item.attributes)
            if _ck is not None:
                entry["sort_created"] = _ck
            if section_key == "LayoutCatalog" and not is_fldr and not is_separator:
                _layout_xml = _item.xml_sources[0].xml if _item.xml_sources else ""
                wf = _extract_wireframe(_layout_xml, style_colors)
                if wf:
                    entry["wireframe"] = wf
                objs = extract_layout_objects(_layout_xml)
                if objs:
                    obj_dicts = [o.to_dict() for o in objs]
                    _link_object_field_ids(obj_dicts, xref_item.get("uses_fields"))
                    entry["objects"] = obj_dicts

            if section_key == "ScriptCatalog" and not is_fldr and not is_separator:
                step_src = next((s for s in _item.xml_sources if s.catalog == "StepsForScripts"), None)
                if step_src:
                    # Parse the UNRESOLVED step XML — resolving addon UUIDs into the XML
                    # first can inject XML-special chars (a calc like " <= ?" has a raw
                    # '<'), breaking ET.fromstring and silently dropping the whole steps
                    # list (no line numbers, no highlighting). Resolve the rendered
                    # strings instead, mirroring the pipeline's rendered_text path.
                    steps_list, _ = _render_script_steps(
                        step_src.xml, _schema_ver, include_display_parts=True,
                    )
                    if _nm:
                        for _s in steps_list:
                            _s["full_text"] = _resolve_uuids(_s["full_text"], _nm)
                            for _part in _s.get("display_parts") or []:
                                _part["text"] = _resolve_uuids(_part["text"], _nm)
                            ol = _resolve_uuids(_s["one_line"], _nm)
                            # one_line truncates each param at 100 chars BEFORE resolution,
                            # which can cut an addon UUID in half (it then won't resolve).
                            # When that happened, collapse the resolved full_text instead.
                            if "com.fmi." in ol:
                                ol = _s["full_text"].replace("\r\n", "\n").replace("\r", "\n").replace("\n", "¶")
                            _s["one_line"] = ol
                    bounded_steps_body = _pool_long_step_parameters(steps_list, long_values)
                    # Oversize presentation cap (packet 1282) — annotated AFTER every full_text
                    # transformation, so the marker's size/SHA describe the exact bytes the
                    # "Show anyway" control reveals. The template's oversize branch renders the
                    # marker and never hands this text to the highlighter.
                    for _s in steps_list:
                        _ft_bytes = _s.get("full_text", "").encode("utf-8")
                        if len(_ft_bytes) > DEFAULT_LARGE_THRESHOLD:
                            _s["oversize"] = large_marker(_ft_bytes)
                    if steps_list:
                        entry["steps"] = steps_list
                        entry["body"] = bounded_steps_body
                        search_rendered = bounded_steps_body

            if section_key == "RelationshipCatalog" and not is_fldr and not is_separator and _item.xml_sources:
                try:
                    _rel_elem = ET.fromstring(_item.xml_sources[0].xml)
                    _lt = _rel_elem.find("LeftTable/TableOccurrenceReference")
                    _rt = _rel_elem.find("RightTable/TableOccurrenceReference")
                    if _lt is not None and _rt is not None:
                        _ln = _lt.get("name", "")
                        _rn = _rt.get("name", "")
                        if _nm:
                            _ln = _nm.get(_ln, _ln)
                            _rn = _nm.get(_rn, _rn)
                        if _ln and _rn:
                            entry["display_name"] = f"{_ln} → {_rn}"
                            entry["sort_left"]  = _ln   # sort-by-left-side-name
                            entry["sort_right"] = _rn   # sort-by-right-side-name
                            # Structured predicates so the sidebar/header can flip a
                            # relationship's sides client-side (op inverted for non-=).
                            _preds = []
                            _jpl = _rel_elem.find("JoinPredicateList")
                            if _jpl is not None:
                                for _jp in _jpl.findall("JoinPredicate"):
                                    _pt = _jp.get("type", "")
                                    _lf = _jp.find("./LeftField/FieldReference")
                                    _rf = _jp.find("./RightField/FieldReference")
                                    _lfn = _lf.get("name", "") if _lf is not None else ""
                                    _rfn = _rf.get("name", "") if _rf is not None else ""
                                    if _nm:
                                        _lfn = _nm.get(_lfn, _lfn)
                                        _rfn = _nm.get(_rfn, _rfn)
                                    _preds.append({"lf": _lfn,
                                                   "op": "=" if _pt == "Equal" else _pt,
                                                   "rf": _rfn})
                            entry["rel"] = {"l": _ln, "r": _rn, "preds": _preds}
                except ET.ParseError:
                    pass

            if section_key == "ThemeCatalog" and not is_fldr and not is_separator and _item.xml_sources:
                try:
                    _disp = ET.fromstring(_item.xml_sources[0].xml).get("Display", "")
                    if _disp:
                        entry["display_name"] = _disp  # FileMaker's theme name; internal id stays in the body
                except ET.ParseError:
                    pass

            if section_key == "ValueListCatalog" and not is_fldr and not is_separator and _item.xml_sources:
                entry["sort_source"] = _vl_source_group(_item.xml_sources[0].xml)

            if section_key == "CustomFunctionsCatalog" and not is_fldr and not is_separator and _item.xml_sources:
                entry["display_name"] = _cf_signature(_item.xml_sources[0].xml, _item.name)  # Func ( param ; param )
                entry["sort_avail"]   = _cf_avail_group(_item.xml_sources[0].xml)
                _cf_f = _cf_formula_text(_item.xml_sources, _nm)
                if _cf_f:
                    # Isolate the formula into a line-numbered block; the body keeps
                    # the Parameters/Access header (everything before the blank line).
                    entry["field_calcs"] = [{"label": "Formula", "text": _cf_f}]
                    entry["body"] = (body or "").split("\n\n", 1)[0]

            item_data[_item.item_id] = entry

            if not is_separator:
                search_index.append({
                    "section": section_key, "item": _item.item_id,
                    "display_name": _item.name,
                    "text": f"{_item.name}\n{search_rendered}",
                    "summary": summary,
                })
                if _item.dead_end and not is_fldr:
                    dead_count_by_section[section_key] = dead_count_by_section.get(section_key, 0) + 1

        fc = _build_folder_children_from_artifact(items_in_section, item_data)
        item_names = [
            _item.item_id for _item in items_in_section
            if not item_data.get(_item.item_id, {}).get("is_marker")
        ]
        sections[section_key] = {
            "label": section_label,
            "item_names": item_names,
            "item_data": item_data,
            "folder_children": fc,
        }

    # Structural nav shortcuts (#10/#11) — resolved here against the FINISHED sections
    # so every clickable target provably exists; unresolvable targets become inert
    # placeholders (no nav binding). One-way only; no new canonical xref edges.
    _inject_structural_shortcuts(sections, artifact, _nm)
    _relabel_relationship_xrefs(sections)   # packet 1157: xref lists relationships by NAME, not id

    section_order = [
        [k, v["label"], v.get("display_count", len(v["item_names"])),
         dead_count_by_section.get(k, 0)]
        for k, v in sections.items()
    ]

    # The derived AI-oriented perspectives (workflows / security / structure / ai_usage)
    # are NO LONGER injected into the Explorer data blob — their human-UI overlays were
    # removed (inbox packet 002, Batch 2). Explorer is the human artifact-inspection lens;
    # those compressed perspectives are reachable over MCP instead. The builder functions
    # (core.workflows / core.structure_intent / core.ai_usage and the local
    # _build_security_from_artifact) are intentionally kept for MCP + Diff + tests.

    # About data = the baked completeness profile, but recompute the deterministic
    # render diagnostics FRESH so an artifact stored before this existed still shows
    # them (rendered_text self-heals; the profile's lists do not).
    _about = artifact.completeness_profile.to_dict()
    try:
        from corpusfm.core.render_diagnostics import scan as _scan_render
        _fresh = _scan_render(artifact.items.values(), bool(_nm), _schema_ver)
        _about["unresolved_in_render"] = _fresh["unresolved_in_render"]
        _about["empty_renders"] = _fresh["empty_renders"]
    except Exception:
        pass

    return {
        "file_key":       identity.file_name,
        "metadata":       metadata,
        "sections":       sections,
        "section_order":  section_order,
        "search_index":   search_index,
        "long_values":    long_values,
        "xref_available":  len(artifact.xref_map) > 0,
        "graph":           _build_graph_data_from_artifact(artifact),
        "artifact_type":   artifact.type.value,
        "about":           _about,
    }


def _build_security_from_artifact(artifact) -> dict:
    """Per privilege set, the objects it can reach (from PrivilegeAccess edges) + the
    accounts assigned to it (AccountPrivilege) — the security graph, browseable. The
    same edges the AI reads; nothing rendered, just regrouped for the human."""
    _SECMAP = {"LayoutCatalog": "layouts", "ScriptCatalog": "scripts",
               "ValueListCatalog": "value_lists", "BaseTableCatalog": "tables"}
    sets: dict = {}

    def _slot(name, item_id=""):
        slot = sets.setdefault(name, {
            "name": name, "item_id": "", "layouts": [], "scripts": [], "value_lists": [],
            "tables": [], "write_tables": [], "accounts": []})
        if item_id and not slot["item_id"]:
            slot["item_id"] = item_id      # the privilege set's own stable id, for agent drill-down
        return slot

    for r in artifact.xref_map:
        if r.type == "PrivilegeAccess":
            tgt = artifact.items.get(r.to)
            bucket = _SECMAP.get(tgt.section if tgt else "", "")
            if bucket:
                _slot(r.from_name, r.from_id)[bucket].append(r.to_name)
                if bucket == "tables" and r.mode == "write":
                    _slot(r.from_name, r.from_id)["write_tables"].append(r.to_name)
        elif r.type == "AccountPrivilege":
            _slot(r.to_name, r.to)["accounts"].append(r.from_name)

    for s in sets.values():
        for k in ("layouts", "scripts", "value_lists", "tables", "write_tables", "accounts"):
            s[k] = sorted(set(s[k]))
        s["reach"] = len(s["layouts"]) + len(s["scripts"]) + len(s["value_lists"]) + len(s["tables"])
    items = sorted(sets.values(), key=lambda s: (-s["reach"], s["name"]))
    return {"items": items}


# ── Template loader ───────────────────────────────────────────────────────────

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_template(name: str) -> str:
    return (_TEMPLATES_DIR / name).read_text(encoding="utf-8")


# The save-time marker (template line ~648): deliberately left literal in the output so the
# in-browser _savePage() can find `var appData = __CORPUSFM_APPDATA__;` inside the base64'd save
# template and re-inject the live data. It is NEVER a render kwarg — exempt from the strict check.
_APPDATA_MARKER = "__CORPUSFM_APPDATA__"


def _js_str(value: str) -> str:
    """A safe JS string literal for embedding in a <script> block: JSON-encode (neutralizes quotes,
    backslashes, newlines) and split any `</` so an FM-object name containing `</script>` can't close
    the element. The FM `File=` attribute reaches these sinks unsanitized — never interpolate it raw."""
    return json.dumps(value).replace("</", "<\\/")


def _render_template(template: str, **kwargs: str) -> str:
    # Fail-loud (packet 073-G): every __CORPUSFM_<KEY>__ placeholder in the template must have a
    # matching kwarg — EXCEPT the APPDATA save marker. A renamed/typo'd/new placeholder with no
    # value would otherwise ship as a literal sentinel and silently corrupt the standalone HTML.
    present = set(_re.findall(r"__CORPUSFM_[A-Z0-9_]+__", template))
    provided = {f"__CORPUSFM_{k.upper()}__" for k in kwargs}
    unfilled = present - provided - {_APPDATA_MARKER}
    if unfilled:
        raise AssertionError(f"Explorer template placeholder(s) with no value: {sorted(unfilled)}")
    for key, value in kwargs.items():
        template = template.replace(f"__CORPUSFM_{key.upper()}__", value)
    return template



# ── Public API ─────────────────────────────────────────────────────────────────

def generate_explorer_html(inputs: "list[Artifact]", syntax_palettes: object = None) -> Path:
    """Build a self-contained Explorer HTML for one or more artifacts.

    inputs: list[Artifact] — produced by the ingestion pipeline.
    Returns a Path to a file in a system temp directory.
    Caller is responsible for opening it (e.g. webbrowser.open(str(path))).
    """
    from corpusfm.artifact import Artifact as _ArtifactCls
    if not inputs or not all(isinstance(a, _ArtifactCls) for a in inputs):
        raise TypeError("generate_explorer_html requires a non-empty list of Artifact objects")
    files = [_build_sections_from_artifact(art) for art in inputs]
    data = {"files": files, "multi_file": len(files) > 1}
    first_meta = data["files"][0]["metadata"]

    if data["multi_file"]:
        keys = "_".join(f["file_key"] for f in data["files"])
        out_name = f"{keys}_{first_meta['timestamp']}_explorer.html"
        title = "CorpusFM Explorer — " + " + ".join(f["file_key"] for f in data["files"])
    else:
        out_name = f"{first_meta['fm_key']}_{first_meta['timestamp']}_explorer.html"
        title = f"CorpusFM Explorer — {first_meta['fm_key']}"

    import base64 as _base64
    data_json_str = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")

    # Build a save template: full HTML with appData replaced by a sentinel.
    # _savePage decodes this and re-injects JSON.stringify(appData) at save time,
    # avoiding the outerHTML approach which bakes in Alpine's runtime DOM mutations.
    from corpusfm.extensions.export.syntax_palettes import palette_css, resolve_selection
    selected = resolve_selection(syntax_palettes)
    _tpl      = _load_template("explorer.html")
    _css      = _load_template("explorer.css") + "\n" + palette_css(selected)
    _fmhl_js  = _load_template("explorer_highlight.js")
    _graph_js = _load_template("explorer_graph.js")
    _common = dict(
        # title lands in <title>…</title> (HTML), filename in `var filename = …;` (JS in <script>).
        # Both derive from the FM `File=` attribute — escape per-context or a crafted name is stored XSS.
        title=_html.escape(title),
        css=_css,
        alpine_js=_load_vendor("alpine.min.js"),
        fuse_js=_load_vendor("fuse.min.js"),
        filename=_js_str(out_name),
        fmhl_js=_fmhl_js,
        graph_js=_graph_js,
        node_icon=_load_asset("corpusfm-wordmark-darkmode.svg"),
        hdr_wm_light=_load_asset("corpusfm-wordmark-lightmode.svg"),
        wordmark=_load_asset("wordmark.svg"),
        calc_palette=selected.calculation,
        script_palette=selected.script,
        palette_version=str(selected.as_dict()["version"]),
    )

    html_no_data = _render_template(_tpl, **_common, data_json=_APPDATA_MARKER, save_tpl_b64="")
    save_tpl_b64 = _base64.b64encode(html_no_data.encode("utf-8")).decode("ascii")

    html = _render_template(_tpl, **_common, data_json=data_json_str, save_tpl_b64=save_tpl_b64)

    # Fail-loud (packet 073-G): the "save as HTML" feature depends on the APPDATA marker surviving —
    # the save template (post-base64) must still carry the exact re-injection target, and the marker
    # must remain in the final HTML. A renamed sentinel would break save silently; catch it here.
    if f"var appData = {_APPDATA_MARKER};" not in html_no_data:
        raise AssertionError("Explorer save template lost its appData re-injection marker")
    if _APPDATA_MARKER not in html:
        raise AssertionError("Explorer save marker missing from rendered HTML")

    tmp_dir = Path(tempfile.mkdtemp(prefix="corpusfm_explorer_"))
    # Slugify the ON-DISK name only (packet 082): fm_key derives from the untrusted FM `File=`
    # attribute — a `/` or other path metacharacter must not steer the write outside tmp_dir.
    # The value embedded in the HTML (filename=…) is escaped separately above.
    from corpusfm.core.git_formatter._renderer import slugify as _slugify
    out_path = tmp_dir / _slugify(out_name)
    out_path.write_text(html, encoding="utf-8")
    return out_path
