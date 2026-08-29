"""Human-readable renderers for FM catalog section items.

Each renderer takes the raw XML string of one catalog element and returns
a RenderedItem with a one-line summary (expander header) and a multi-line
body (detail view).

Public API:
    render_section_item(section_key, name, xml_str, **kwargs) -> RenderedItem
"""

from __future__ import annotations

import re as _re
from collections import Counter

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field

# Renderer schema version, stamped into Artifact.render_version at ingestion. BUMP when a
# render change alters rendered_text — a stale stamp marks an artifact whose derived layers a
# explicit re-ingestion will refresh it; packet 1062 retired lazy self-heal.
#   1 — render_field auto-enter/validation/storage fix (the prior code matched 0 fields).
#   2 — addon field calc fidelity: resolve UUID refs before indenting the formula (multi-line
#       block comments align), and drop the now-redundant comment-LF reinsertion (it double-
#       spaced // comments once locale fragments stopped being stripped). FieldsForTables only.
#   3 — Perform Script [on Server [with Callback]]: render a script specified "by name" (a
#       <Calculation>) instead of an empty "", and surface "Wait for completion". ScriptCatalog.
#   4 — empty comment steps render as a blank line (no "# "), matching FileMaker. ScriptCatalog.
#   5 — Go to Layout "by calculation" renders the calc (not ""); Pause/Resume Script renders its
#       duration (the xpath was wrong). Both specify their target by <Calculation>. ScriptCatalog.
#   6 — Set Window Title (title under WindowReference/Rename) and Insert Text (text under
#       Parameter[type=Text], + target) had wrong xpaths → rendered empty. ScriptCatalog.
#   7 — step param xpaths ending in '/@attr' raised KeyError('@') in ElementTree, which the
#       per-script catch turned into a BLANK body for any script containing such a step
#       (e.g. Enable Touch Keyboard / Set Web Viewer / Go to Object — 8 specs). _extract now
#       supports the '/@attr' form and never raises. Surfaced by an FM2026 sample. ScriptCatalog.
#   8 — relationship sort: each side's <SortSpecification> (the order related records are
#       returned through the relationship) was never rendered. Now emits a "sort (left|right
#       TO): field asc/desc[, …]" line, incl. type=Custom "by value list" sorts. RelationshipCatalog.
#   9 — custom function formula: was emitted only from the supplemental CalcsForCustomFunctions
#       source, so when the formula lives in the PRIMARY CustomFunctionsCatalog <Calculation><Text>
#       (the FM2026/SaveAsXML case) the body was signature-only. Now reads the primary first,
#       falls back to the supplemental source. CustomFunctionsCatalog.
RENDER_VERSION = 11

@dataclass
class RenderedItem:
    name: str       # original lookup key (e.g. "TemplateTable", or "5" for a relationship)
    summary: str    # one-line human label — used as the expander header
    body: str       # multi-line body text shown inside the expander
    xml_str: str = field(default="", repr=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bool_flag(value: str) -> str:
    return "Yes" if value == "True" else "No"


# Auto-enter kinds keyed by the <AutoEnter type="..."> value (the FM 2.2.3.0 form,
# verified across all sample exports — FM 22.0.6). Serial/Calculated/Looked_up carry
# extra detail and are handled separately.
_AUTO_ENTER_LABELS = {
    "CreationDate": "creation date", "CreationTime": "creation time",
    "CreationTimestamp": "creation timestamp", "CreationName": "creation account",
    "CreationAccountName": "creation account", "ModificationDate": "mod date",
    "ModificationTime": "mod time", "ModificationTimestamp": "mod timestamp",
    "ModificationName": "mod account", "ModificationAccountName": "mod account",
    "ConstantData": "constant data", "LastVisited": "value from last visited record",
}

# Drift fallback: a hypothetical older/variant form that encoded auto-enter as boolean
# attributes (matched 0 fields across the FM 22.0.6 corpus, but kept so a version that
# DOES use it still renders rather than silently dropping the info).
_AUTO_ENTER_BOOL_FALLBACK = [
    ("creationTimestamp", "creation timestamp"), ("creationDate", "creation date"),
    ("creationAccountName", "creation account"), ("modificationTimestamp", "mod timestamp"),
    ("modificationDate", "mod date"), ("modificationAccountName", "mod account"),
]


def _vflag(validation, attr: str, child: str) -> bool:
    """A validation flag that may be an ATTRIBUTE (FM 2.2.3.0, verified) or a child
    element (a possible older/variant form) — drift-tolerant."""
    if validation.get(attr) == "True":
        return True
    c = validation.find(child)
    return c is not None and c.get("value", "True") != "False"


_FM_UUID_PAT = _re.compile(
    r'com\.fmi\.(?:[a-zA-Z]+\.)*'
    r'(?:[0-9A-Fa-f]{32}(?:::[0-9A-Fa-f]{32})?'
    r'|[A-Za-z0-9_|!.]+::(?:text\.)?[0-9A-Fa-f]{32})'
)


def _resolve_addon_uuids(text: str, name_map: "dict | None") -> str:
    """Resolve FM addon UUID refs in calc text to their locale values.

    The pipeline also resolves UUIDs in a post-pass over the whole item body,
    but a formula must be resolved HERE — before render_field/_cf split it into
    per-line-indented lines — so that a multi-line resolved value (a block
    comment or string fragment) inherits the formula's uniform indent instead of
    landing flush-left. That is what makes an addon calc read as FileMaker shows
    it. No-op for SaveAsXML (name_map is empty).
    """
    if not name_map or not text:
        return text
    def _sub(m: "_re.Match") -> str:
        key = m.group(0)
        r = name_map.get(key)
        if r is None and "::text." in key:
            r = name_map.get("com.fmi.calculation.text." + key.rsplit("::text.", 1)[-1])
        return r if r is not None else key
    return _FM_UUID_PAT.sub(_sub, text)


def _calc_text(root: ET.Element, name_map: "dict | None" = None) -> str:
    """Extract formula text from <Calculation><Text> (DDR_INFO) or <Calculation> text directly.

    For addons, resolve UUID refs against name_map. We do NOT apply
    _ADDON_CMT_LF_PAT here: that pattern re-inserts the newline that ends a
    //comment, but a resolved comment fragment already carries its own trailing
    newline (the locale keeps it), so adding another double-spaced the line and
    ate an indent tab. xref analysis (graph.py) still needs the pattern because
    it parses the UNRESOLVED text, where the fragment newline isn't present yet.
    """
    t = root.find(".//Calculation/Text")
    if t is not None and t.text:
        return _resolve_addon_uuids(t.text, name_map)
    c = root.find(".//Calculation")
    if c is not None and c.text:
        return _resolve_addon_uuids(c.text, name_map)
    return ""


def _field_ref_label(ref_elem: ET.Element, external_tos=None) -> str:
    """Return TO::Field from a FieldReference element, with [ext] if the TO is external."""
    if ref_elem is None:
        return "?"
    to = ref_elem.find("TableOccurrenceReference")
    to_name = to.get("name", "") if to is not None else ""
    fname = ref_elem.get("name", "?")
    ext = external_tos and to_name in external_tos
    to_label = f"{to_name} [ext]" if ext else to_name
    return f"{to_label}::{fname}" if to_name else fname


def _parse(xml_str: str) -> ET.Element:
    if not xml_str:
        raise ET.ParseError("no element found")
    return ET.fromstring(xml_str)


def is_folder(xml_str: str) -> bool:
    """Return True if the XML element represents a FileMaker UI folder (isFolder='True')."""
    if not xml_str:
        return False
    try:
        return _parse(xml_str).attrib.get("isFolder") == "True"
    except ET.ParseError:
        return False


def is_separator(xml_str: str) -> bool:
    """Return True if the element is a layout menu separator (isSeparatorItem='True')."""
    if not xml_str:
        return False
    try:
        return _parse(xml_str).attrib.get("isSeparatorItem") == "True"
    except ET.ParseError:
        return False


# ---------------------------------------------------------------------------
# Folder / separator renderers (shared across catalogs)
# ---------------------------------------------------------------------------

def render_folder(name: str, xml_str: str, **_) -> RenderedItem:
    """Render a FileMaker UI folder item (isFolder='True')."""
    return RenderedItem(
        name=name,
        summary=f"📁 {name}",
        body="  Folder — UI grouping only, not a real asset",
        xml_str=xml_str,
    )


def render_separator(name: str, xml_str: str, **_) -> RenderedItem:
    """Render a layout menu separator item (isSeparatorItem='True')."""
    return RenderedItem(
        name=name,
        summary="── separator ──",
        body="  Separator — layout menu divider, not a real layout",
        xml_str=xml_str,
    )


# ---------------------------------------------------------------------------
# Per-section renderers
# ---------------------------------------------------------------------------

def render_basetable(name: str, xml_str: str, field_names: list = None, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    comment = elem.attrib.get("comment", "").strip()
    lines = []
    if comment:
        lines.append(f"  Comment: {comment}")

    if field_names:
        lines.append(f"  Fields ({len(field_names)}):")
        for fname in field_names:
            lines.append(f"    {fname}")
    else:
        lines.append("  Fields: (none)")

    body = "\n".join(lines)
    return RenderedItem(name=name, summary=name, body=body, xml_str=xml_str)


def render_custom_function(name: str, xml_str: str, calc_xml_str: str = "", **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    display = elem.findtext("Display") or name
    summary = display

    params = [p.attrib.get("name", "?") for p in elem.findall(".//Parameter")]
    lines = []
    if params:
        lines.append(f"  Parameters: {', '.join(params)}")
    else:
        lines.append("  Parameters: (none)")

    access = elem.attrib.get("access", "")
    if access:
        lines.append(f"  Access: {access}")

    formula = _calc_text(elem).strip()
    if not formula and calc_xml_str:
        try:
            formula = _calc_text(_parse(calc_xml_str)).strip()
        except ET.ParseError:
            formula = ""
    if formula:
        lines.append("")
        for formula_line in formula.splitlines():
            lines.append(f"  {formula_line}")

    body = "\n".join(lines)
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


def render_relationship(name: str, xml_str: str, external_tos=None, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=f"Relationship {name}", body="(parse error)", xml_str=xml_str)

    def _to_name(side_tag: str) -> str:
        side = elem.find(side_tag)
        if side is None:
            return "?"
        ref = side.find("TableOccurrenceReference")
        return ref.attrib.get("name", "?") if ref is not None else "?"

    def _to_label(raw: str) -> str:
        return f"{raw} [ext]" if (external_tos and raw in external_tos) else raw

    left_raw  = _to_name("LeftTable")
    right_raw = _to_name("RightTable")
    left_to   = _to_label(left_raw)
    right_to  = _to_label(right_raw)

    predicates = []
    jp_list = elem.find("JoinPredicateList")
    if jp_list is not None:
        for jp in jp_list.findall("JoinPredicate"):
            pred_type = jp.attrib.get("type", "")
            lf = jp.find("./LeftField/FieldReference")
            rf = jp.find("./RightField/FieldReference")
            lf_name = lf.attrib.get("name", "?") if lf is not None else "?"
            rf_name = rf.attrib.get("name", "?") if rf is not None else "?"
            op = "=" if pred_type == "Equal" else pred_type
            predicates.append(f"{left_to}::{lf_name}  {op}  {right_to}::{rf_name}")

    if predicates:
        summary = predicates[0]
        if len(predicates) > 1:
            summary += f"  (+{len(predicates) - 1} more)"
    else:
        summary = f"{left_to}  ↔  {right_to}"

    lines = list(predicates) if predicates else [f"  {left_to}  ↔  {right_to}  (no predicates)"]

    # cascade flags
    left_elem = elem.find("LeftTable")
    right_elem = elem.find("RightTable")
    cascade_parts = []
    if left_elem is not None:
        cc = _bool_flag(left_elem.attrib.get("cascadeCreate", "False"))
        cd = _bool_flag(left_elem.attrib.get("cascadeDelete", "False"))
        cascade_parts.append(f"left  cascade create={cc}  delete={cd}")
    if right_elem is not None:
        cc = _bool_flag(right_elem.attrib.get("cascadeCreate", "False"))
        cd = _bool_flag(right_elem.attrib.get("cascadeDelete", "False"))
        cascade_parts.append(f"right  cascade create={cc}  delete={cd}")
    if cascade_parts:
        lines.append("  " + "  |  ".join(cascade_parts))

    # Relationship sort: each side may carry a SortSpecification that orders the
    # related records of that table occurrence when accessed through this
    # relationship. type Ascending/Descending sort by the field; type Custom
    # sorts the field by a value list's custom order.
    def _sort_line(side_tag: str, side_word: str, side_label: str) -> str | None:
        side = elem.find(side_tag)
        if side is None:
            return None
        spec = side.find("SortSpecification")
        if spec is None or spec.attrib.get("value", "False") != "True":
            return None
        sort_list = spec.find("SortList")
        if sort_list is None:
            return None
        parts = []
        for s in sort_list.findall("Sort"):
            stype = s.attrib.get("type", "")
            fref = s.find("./PrimaryField/FieldReference")
            fname = fref.attrib.get("name", "?") if fref is not None else "?"
            vl = s.find("ValueListReference")
            if stype == "Custom" and vl is not None:
                parts.append(f"{fname} by value list {vl.attrib.get('name', '?')}")
            elif stype in ("Ascending", "Descending"):
                parts.append(f"{fname} {stype.lower()}")
            else:
                parts.append(f"{fname} {stype}".strip())
        if not parts:
            return None
        suffix = "  (maintain order)" if spec.attrib.get("maintain", "False") == "True" else ""
        return f"  sort ({side_word} {side_label}): " + ", ".join(parts) + suffix

    for tag, word, label in (("LeftTable", "left", left_to), ("RightTable", "right", right_to)):
        sl = _sort_line(tag, word, label)
        if sl:
            lines.append(sl)

    body = "\n".join(lines)
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


def render_table_occurrence(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    to_type = elem.attrib.get("type", "")
    src_ref = elem.find("BaseTableSourceReference")

    if src_ref is None:
        return RenderedItem(name=name, summary=name, body="  (no source reference)", xml_str=xml_str)

    ref_type = src_ref.attrib.get("type", "")
    lines = []

    if ref_type == "BaseTableReference":
        bt_ref = src_ref.find("BaseTableReference")
        bt_name = bt_ref.attrib.get("name", "?") if bt_ref is not None else "?"
        summary = f"{name}  →  {bt_name}"
        lines.append(f"  Base table: {bt_name}  [local]")
    elif ref_type == "ExternalDataSourceReference":
        ds_ref = src_ref.find("DataSourceReference")
        ds_name = ds_ref.attrib.get("name", "?") if ds_ref is not None else "?"
        summary = f"{name}  →  {ds_name}  [external]"
        lines.append(f"  Data source: {ds_name}  [external]")
    elif ref_type == "ODBCDataSourceReference":
        # External SQL Source (ESS/ODBC): the target lives in a SQL database, not an FM file.
        # <Source schemaName catalogName tableName/> names the SQL table; <ODBCDataSourceReference
        # name dsn/> names the DSN (the connection the FM solution defines).
        odbc = src_ref.find("ODBCDataSourceReference")
        src = src_ref.find("Source")
        ds_name = odbc.attrib.get("name") if odbc is not None else None
        dsn = odbc.attrib.get("dsn") if odbc is not None else None
        sql_table = src.attrib.get("tableName") if src is not None else None
        target = ".".join(p for p in (src.attrib.get("catalogName") if src is not None else None,
                                      src.attrib.get("schemaName") if src is not None else None,
                                      sql_table) if p) if src is not None else (sql_table or "?")
        summary = f"{name}  →  {ds_name or target}  [ESS]"
        lines.append(f"  SQL source: {target or '?'}  [ESS]")
        if ds_name:
            lines.append(f"  Data source: {ds_name}" + (f"  (DSN: {dsn})" if dsn and dsn != ds_name else ""))
    else:
        summary = f"{name}  ({to_type})"
        lines.append(f"  Type: {to_type}")

    body = "\n".join(lines) if lines else "  (no detail)"
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


def _extract_css_classes(css_text: str) -> list[tuple[str, str]]:
    """Return [(class_name, hex_bg_or_empty)] for all :normal .self rules in theme CSS."""
    results = []
    for m in _re.finditer(r'([A-Za-z][A-Za-z0-9_-]*):normal\s+\.self\s*\{([^}]+)\}', css_text):
        cls = m.group(1)
        rule = m.group(2)
        bg = ""
        bg_m = _re.search(r'background-color\s*:\s*rgba\(\s*([\d.]+)%\s*,\s*([\d.]+)%\s*,\s*([\d.]+)%\s*,\s*([\d.]+)\s*\)', rule)
        if bg_m:
            r = round(float(bg_m.group(1)) * 255 / 100)
            g = round(float(bg_m.group(2)) * 255 / 100)
            b = round(float(bg_m.group(3)) * 255 / 100)
            a = float(bg_m.group(4))
            if a >= 0.05:
                bg = f"#{r:02x}{g:02x}{b:02x}"
        results.append((cls, bg))
    return results


def render_theme(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    display = elem.attrib.get("Display", name)
    group = elem.attrib.get("Group", "")
    version = elem.attrib.get("version", "")
    locale = elem.attrib.get("locale", "")

    summary = display
    lines = [f"  Internal name: {name}"]
    if group:
        lines.append(f"  Group: {group}")
    if version:
        lines.append(f"  Version: {version}")
    if locale:
        lines.append(f"  Locale: {locale}")

    css_elem = elem.find("CSS")
    if css_elem is not None and css_elem.text:
        classes = _extract_css_classes(css_elem.text)
        if classes:
            with_fill = [(c, bg) for c, bg in classes if bg]
            lines.append("")
            lines.append(f"  CSS styles: {len(classes)} classes, {len(with_fill)} with fill")
            if with_fill:
                lines.append("")
                for cls, bg in sorted(with_fill):
                    lines.append(f"  {cls:<40} {bg}")

    body = "\n".join(lines)
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


def render_value_list(name: str, xml_str: str, options_xml: str = "", external_tos=None, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    src = elem.find("Source")
    src_type = src.attrib.get("value", "Unknown") if src is not None else "Unknown"

    source_label = {
        "Custom": "Custom (static values)",
        "FromField": "Field values (dynamic)",
    }.get(src_type, src_type)

    lines = [f"  Source: {source_label}"]

    if options_xml:
        try:
            opts = _parse(options_xml)
            if src_type == "Custom":
                cv = opts.find(".//CustomValues/Text")
                if cv is not None and cv.text:
                    values = [v.strip() for v in cv.text.splitlines() if v.strip()]
                    lines.append(f"  Values ({len(values)}):")
                    for v in values:
                        lines.append(f"    {v}")
            elif src_type == "FromField":
                def _field_ref(tag: str) -> str:
                    fref = opts.find(f"./Field/{tag}/FieldReference")
                    if fref is None:
                        return "?"
                    return _field_ref_label(fref, external_tos)

                def _flag(tag: str, attr: str) -> str:
                    el = opts.find(f"./Field/{tag}")
                    return "Yes" if el is not None and el.get(attr) == "True" else "No"

                primary = _field_ref("PrimaryField")
                secondary = _field_ref("SecondaryField")
                lines.append(f"  Primary field:   {primary}")
                if secondary not in ("?", "?::?"):
                    lines.append(f"  Secondary field: {secondary}  show={_flag('SecondaryField', 'show')}  sort={_flag('SecondaryField', 'sort')}")
                show_related = opts.find("./Field/ShowRelated")
                if show_related is not None and show_related.get("value") == "True":
                    sr_to = show_related.find("TableOccurrenceReference")
                    if sr_to is not None:
                        to_name = sr_to.get("name", "?")
                        ext = external_tos and to_name in external_tos
                        label = f"{to_name} [ext]" if ext else to_name
                        lines.append(f"  Show related:    {label}")
        except ET.ParseError:
            pass

    body = "\n".join(lines)
    return RenderedItem(name=name, summary=name, body=body, xml_str=xml_str)


_ACC_SHORT: dict[str, str] = {
    "ReadWrite": "RW",
    "NoAccess":  "—",
    "ReadOnly":  "RO",
}


def _acc(val: str) -> str:
    return _ACC_SHORT.get(val, val or "?")


def _format_pivot(header: list[str], rows: list[list[str]], indent: str = "    ") -> list[str]:
    """Return aligned table lines: header row, separator, then data rows."""
    if not rows:
        return []
    all_rows = [header] + rows
    widths = [max(len(str(r[i])) for r in all_rows) for i in range(len(header))]
    lines: list[str] = []
    for i, row in enumerate(all_rows):
        line = "  ".join(str(cell).ljust(w) for cell, w in zip(row, widths))
        lines.append(indent + line.rstrip())
        if i == 0:
            lines.append(indent + "  ".join("-" * w for w in widths))
    return lines


def _priv_access_summary(child: ET.Element) -> str:
    """Return a short summary string for a Records/Layouts/ValueLists/Scripts element."""
    if child.get("Custom") == "True":
        obj_list = child.find(".//ObjectList")
        count = int(obj_list.get("membercount", "0")) if obj_list is not None else 0
        return f"Custom ({count} items)"
    view = child.get("View")
    if view:
        return view
    c = _bool_flag(child.get("Create", "False"))
    e = _bool_flag(child.get("Edit", "False"))
    d = _bool_flag(child.get("Delete", "False"))
    return f"Create={c}  Edit={e}  Delete={d}"


def _priv_records_pivot(child: ET.Element) -> list[str]:
    """Pivot table for Custom Records access: one row per base table."""
    COLS = ["View", "Edit", "Create", "Delete", "Fields"]
    rows: list[list[str]] = []
    obj_list = child.find(".//ObjectList")
    if obj_list is None:
        return []
    for table in obj_list:
        if table.tag != "Table":
            continue
        if table.get("type") == "New":
            tname = "[Any New Table]"
        else:
            btr = table.find("BaseTableReference")
            tname = btr.get("name", "?") if btr is not None else "?"
        vals = []
        for col in COLS:
            sub = table.find(col)
            vals.append(_acc(sub.get("access", "?") if sub is not None else "?"))
        rows.append([tname] + vals)
    return _format_pivot(["Table"] + COLS, rows)


def _priv_layouts_pivot(child: ET.Element) -> list[str]:
    """Pivot table for Custom Layouts access: one row per layout."""
    rows: list[list[str]] = []
    obj_list = child.find(".//ObjectList")
    if obj_list is None:
        return []
    for layout in obj_list:
        if layout.tag != "Layout":
            continue
        if layout.get("type") == "New":
            lname = "[Any New Layout]"
        else:
            lref = layout.find("LayoutReference")
            lname = lref.get("name", "?") if lref is not None else "?"
        rows.append([lname, _acc(layout.get("access", "?")), _acc(layout.get("records", "?"))])
    return _format_pivot(["Layout", "Design", "Records"], rows)


def _priv_scripts_pivot(child: ET.Element) -> list[str]:
    """Pivot table for Custom Scripts access: one row per script."""
    rows: list[list[str]] = []
    obj_list = child.find(".//ObjectList")
    if obj_list is None:
        return []
    for script in obj_list:
        if script.tag != "Script":
            continue
        if script.get("type") == "New":
            sname = "[Any New Script]"
        else:
            sref = script.find("ScriptReference")
            sname = sref.get("name", "?") if sref is not None else "?"
        rows.append([sname, _acc(script.get("access", "?"))])
    return _format_pivot(["Script", "Access"], rows)


_PRIV_PIVOT: dict = {
    "Records": _priv_records_pivot,
    "Layouts": _priv_layouts_pivot,
    "Scripts": _priv_scripts_pivot,
}


def render_privilege_set(
    name: str,
    xml_str: str,
    ext_privs_xml: dict | None = None,
    **_,
) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    ps_id = elem.get("id", "")
    desc = (elem.findtext("Description") or "").strip()
    access = elem.find("access")

    # ── Phase 1: compact summary block ───────────────────────────────────────
    lines: list[str] = []
    if desc:
        lines.append(f"  {desc}")

    ACCESS_SECTIONS = [
        ("Records",    "Records"),
        ("Layouts",    "Layouts"),
        ("ValueLists", "Value Lists"),
        ("Scripts",    "Scripts"),
    ]

    if access is not None:
        for tag, label in ACCESS_SECTIONS:
            child = access.find(tag)
            if child is not None:
                lines.append(f"  {label:<14}  {_priv_access_summary(child)}")

        other = access.find("Other")
        if other is not None:
            g = other.attrib.get
            print_f    = _bool_flag(g("Print",              "False"))
            export_f   = _bool_flag(g("Export",             "False"))
            cmds       = g("commands", "All")
            manage_db  = _bool_flag(g("manageDatabase",     "False"))
            manage_ac  = _bool_flag(g("manageAccounts",     "False"))
            manage_cm  = _bool_flag(g("manageCustomMenus",  "False"))
            manage_ep  = _bool_flag(g("manageExtPrivs",     "False"))
            override   = _bool_flag(g("allowOverride",      "False"))
            open_quick = _bool_flag(g("allowOpenQuickly",   "False"))
            disconnect = _bool_flag(g("disconnectIdle",     "False"))
            pwd = other.find("Password")
            pwd_note = ""
            if pwd is not None:
                prohibit = pwd.get("prohibitModification", "False") == "True"
                pwd_note = f"  Password change: {'Prohibited' if prohibit else 'Allowed'}"
            lines.append(
                f"  Other          Print={print_f}  Export={export_f}  Commands={cmds}"
            )
            lines.append(
                f"                 ManageDB={manage_db}  ManageAccounts={manage_ac}"
                f"  ManageCustomMenus={manage_cm}  ManageExtPrivs={manage_ep}"
            )
            lines.append(
                f"                 AllowOverride={override}  AllowOpenQuickly={open_quick}"
                f"  DisconnectIdle={disconnect}{pwd_note}"
            )

    # Resolve extended privilege membership for this privilege set.
    ep_rows: list[list[str]] = []
    if ext_privs_xml:
        for ep_name, ep_xml_str in sorted(ext_privs_xml.items()):
            try:
                ep_elem = _parse(ep_xml_str)
            except ET.ParseError:
                continue
            ep_desc = (ep_elem.findtext("Description") or "").strip()
            obj_list = ep_elem.find("ObjectList")
            is_enabled = False
            if obj_list is not None:
                for ref in obj_list.findall("PrivilegeSetReference"):
                    if ref.get("name") == name or (ps_id and ref.get("id") == ps_id):
                        is_enabled = True
                        break
            ep_rows.append([ep_name, ep_desc, "Yes" if is_enabled else "—"])

    # One-line extended privileges summary: just the enabled names.
    if ep_rows:
        enabled_names = [r[0] for r in ep_rows if r[2] == "Yes"]
        if enabled_names:
            lines.append(f"  Extended       {', '.join(enabled_names)}")
        else:
            lines.append("  Extended       (none)")

    # ── Phase 2: detail block (pivot tables + full ext-priv table) ───────────
    custom_tags = [
        tag for tag, _ in ACCESS_SECTIONS
        if access is not None
        and access.find(tag) is not None
        and access.find(tag).get("Custom") == "True"  # type: ignore[union-attr]
        and tag in _PRIV_PIVOT
    ]
    has_detail = bool(custom_tags or ep_rows)

    if has_detail:
        lines.append("")
        lines.append("  " + "─" * 58)

        for tag in custom_tags:
            child = access.find(tag)  # type: ignore[union-attr]
            label = next(lbl for t, lbl in ACCESS_SECTIONS if t == tag)
            ol = child.find(".//ObjectList")  # type: ignore[union-attr]
            count = ol.get("membercount", "?") if ol is not None else "?"
            lines.append("")
            lines.append(f"  {label}  ({count} items)")
            lines.extend(_PRIV_PIVOT[tag](child))  # type: ignore[arg-type]

        if ep_rows:
            lines.append("")
            lines.append("  Extended Privileges")
            name_w = max(len(r[0]) for r in ep_rows)
            desc_w = max(len(r[1]) for r in ep_rows)
            for ep_name, ep_desc, flag in ep_rows:
                lines.append(f"    {ep_name:<{name_w}}  {ep_desc:<{desc_w}}  {flag}")

    body = "\n".join(lines) if lines else "  (no detail)"
    return RenderedItem(name=name, summary=name, body=body, xml_str=xml_str)


def render_extended_privilege(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    desc = (elem.findtext("Description") or "").strip()
    summary = f"{name}  —  {desc}" if desc else name

    obj_list = elem.find("ObjectList")
    ps_refs = obj_list.findall("PrivilegeSetReference") if obj_list is not None else []
    ps_names = [r.get("name", "?") for r in ps_refs]

    lines: list[str] = []
    if desc:
        lines.append(f"  {desc}")
    if ps_names:
        lines.append(f"  Enabled for {len(ps_names)} privilege set{'s' if len(ps_names) != 1 else ''}:")
        for ps_name in ps_names:
            lines.append(f"    {ps_name}")
    else:
        lines.append("  Not enabled for any privilege set")

    return RenderedItem(name=name, summary=summary, body="\n".join(lines), xml_str=xml_str)


def render_custom_menu(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    item_list = elem.find("MenuItemList")
    count     = int(item_list.get("membercount", 0)) if item_list is not None else 0
    summary   = f"{name}  ({count} item{'s' if count != 1 else ''})"
    lines     = [f"  Items ({count}):"]

    if item_list is not None:
        for item in item_list.findall("CustomMenuItem"):
            if item.get("isSeparatorItem") == "True":
                lines.append("    ——")
                continue
            cmd = item.find("Command")
            if cmd is not None:
                lines.append(f"    {cmd.get('name', '?')}")
                continue
            ref = item.find("CustomMenuReference")
            if ref is not None:
                lines.append(f"    ▶ {ref.get('name', '?')}")
                continue
            lines.append("    (unknown item)")

    return RenderedItem(name=name, summary=summary, body="\n".join(lines), xml_str=xml_str)


def render_account(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    acct_type = elem.get("type", "Unknown")
    enabled   = elem.get("enable", "True") == "True"
    desc      = (elem.findtext("Description") or "").strip()
    priv_ref  = elem.find("PrivilegeSetReference")
    priv_name = priv_ref.get("name", "") if priv_ref is not None else ""

    status  = "Enabled" if enabled else "Disabled"
    summary = f"{name}  [{acct_type}]  {status}"

    lines = [
        f"  Type:          {acct_type}",
        f"  Status:        {status}",
    ]
    if priv_name:
        lines.append(f"  Privilege set: {priv_name}")
    if desc:
        lines.append(f"  Description:   {desc}")

    return RenderedItem(name=name, summary=summary, body="\n".join(lines), xml_str=xml_str)


def render_external_data_source(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    src_type = elem.get("type", "Unknown")
    summary  = f"{name}  [{src_type}]"
    lines    = [f"  Type: {src_type}"]

    if src_type == "FileMaker":
        raw_path = (elem.findtext("File/UniversalPathList") or "").strip()
        paths = [p.strip() for p in raw_path.splitlines() if p.strip()]
        if len(paths) == 1:
            lines.append(f"  File: {paths[0]}")
        elif len(paths) > 1:
            lines.append(f"  Files ({len(paths)}):")
            for p in paths:
                lines.append(f"    {p}")

    elif src_type == "ODBC":
        odbc = elem.find("ODBC")
        if odbc is not None:
            auth = odbc.find("Authentication")
            if auth is not None:
                auth_type = auth.get("type", "")
                username  = auth.get("UserName", "").strip('"')
                if auth_type:
                    lines.append(f"  Auth: {auth_type}")
                if username:
                    lines.append(f"  Username: {username}")
                # Password intentionally not shown
            filt = odbc.find("Filter")
            if filt is not None:
                exposed = [
                    label for attr, label in [
                        ("tables",      "Tables"),
                        ("views",       "Views"),
                        ("systemTable", "System tables"),
                    ]
                    if filt.get(attr) == "True"
                ]
                if exposed:
                    lines.append(f"  Expose: {', '.join(exposed)}")
                for attr, label in [
                    ("catalogName", "Catalog filter"),
                    ("schemaName",  "Schema filter"),
                    ("tableName",   "Table filter"),
                ]:
                    val = filt.get(attr, "").strip()
                    if val:
                        lines.append(f"  {label}: {val}")

    return RenderedItem(name=name, summary=summary, body="\n".join(lines), xml_str=xml_str)


def render_field(name: str, xml_str: str, **kwargs) -> RenderedItem:
    name_map = kwargs.get("name_map")
    if not xml_str:
        return RenderedItem(name=name, summary=name, body="(no detail)", xml_str=xml_str)
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    data_type  = elem.attrib.get("dataType", "") or elem.attrib.get("datatype", "")
    field_type = elem.attrib.get("fieldType") or elem.attrib.get("fieldtype", "Normal")
    comment    = elem.attrib.get("comment", "").strip()

    type_label = data_type if field_type == "Normal" else f"{data_type} ({field_type})"
    summary    = f"{name}  [{type_label}]" if type_label else name
    lines      = []

    if type_label:
        lines.append(f"  Type: {type_label}")
    if comment:
        lines.append(f"  Comment: {comment}")

    # Calculated field formula
    if field_type == "Calculated":
        formula = _calc_text(elem, name_map)
        if formula:
            lines.append("")
            lines.append("  Formula:")
            for fline in formula.strip().splitlines():
                lines.append(f"    {fline}")

    # Summary field
    if field_type == "Summary":
        st_elem = elem.find("SummaryType")
        if st_elem is not None:
            stype = st_elem.get("value") or st_elem.get("type", "?")
            fref = st_elem.find("FieldReference")
            if fref is not None:
                src = _field_ref_label(fref)
                lines.append(f"  Summary: {stype} {src}")
            else:
                lines.append(f"  Summary type: {stype}")

    # Auto-enter — driven by AutoEnter@type (the boolean-attr reads were dead code; FM
    # encodes the kind in `type`: SerialNumber / Calculated / Looked_up / Creation* /
    # Modification* / ConstantData …), with serial / calc / lookup detail.
    auto = elem.find("AutoEnter")
    if auto is not None:
        atype = auto.get("type", "")
        if atype == "SerialNumber":
            sn = auto.find("SerialNumber")
            nv = sn.get("nextvalue", "") if sn is not None else ""
            inc = sn.get("increment", "") if sn is not None else ""
            detail = (f" (next {nv}{', increment ' + inc if inc and inc != '1' else ''})"
                      if nv else "")
            lines.append(f"  Auto-enter: serial number{detail}")
        elif atype == "Calculated":
            formula = _calc_text(auto, name_map)
            if formula:
                lines.append("")
                lines.append("  Auto-enter formula:")
                for fline in formula.strip().splitlines():
                    lines.append(f"    {fline}")
            else:
                lines.append("  Auto-enter: calculated")
        elif atype == "Looked_up":
            fref = auto.find(".//FieldReference")
            lines.append(f"  Auto-enter lookup: {_field_ref_label(fref)}"
                         if fref is not None else "  Auto-enter: looked-up value")
        elif atype in _AUTO_ENTER_LABELS:
            lines.append(f"  Auto-enter: {_AUTO_ENTER_LABELS[atype]}")
        else:
            # Drift fallback: a form that used boolean attributes instead of @type.
            parts = [lbl for a, lbl in _AUTO_ENTER_BOOL_FALLBACK if auto.get(a) == "True"]
            if parts:
                lines.append(f"  Auto-enter: {', '.join(parts)}")

    # Validation — notEmpty / unique / existing are ATTRS on <Validation> in FM 2.2.3.0
    # (the child-element reads were dead code); _vflag also accepts the child form so a
    # version difference can't silently drop validation. Value list, max size, strict,
    # and the validation calc are children.
    validation = elem.find("Validation")
    if validation is not None:
        v_parts: list = []
        if _vflag(validation, "notEmpty", "NotEmpty"):
            v_parts.append("not empty")
        if _vflag(validation, "unique", "Unique"):
            v_parts.append("unique")
        if _vflag(validation, "existing", "Existing"):
            v_parts.append("existing value")
        vl_ref = validation.find("ValueListReference")
        if vl_ref is not None:
            v_parts.append(f"in value list '{vl_ref.get('name', '?')}'")
        maxsize = validation.find("MaximumSize")
        if maxsize is not None:
            sz = maxsize.get("value") or (maxsize.text or "").strip() or "?"
            v_parts.append(f"max {sz} chars")
        v_calc = _calc_text(validation, name_map)
        if v_calc:
            v_parts.append("by calculation")
        if v_parts:
            is_strict = validation.find("Strict") is not None or validation.get("strict") == "True"
            strict = " (strict)" if is_strict else ""
            lines.append(f"  Validation: {', '.join(v_parts)}{strict}")
            if v_calc:
                lines.append("  Validation formula:")
                for fline in v_calc.strip().splitlines():
                    lines.append(f"    {fline}")

    # Field storage options — these live on the <Storage> child (not the Field
    # element), with FM's own attribute names. Reading them off Field (the old code)
    # was silently dead, so a field's actual *nature* never rendered. The unstored-
    # calc flag is load-bearing: an unstored calc can't be indexed, found, or used as
    # a relationship match key, and recomputes on every access.
    storage = elem.find("Storage")
    if storage is not None:
        if storage.get("global") == "True":
            lines.append("  Storage: Global (per-session, not stored on disk)")
        if field_type == "Calculated":
            lines.append("  Storage: " + (
                "Stored (indexable)" if storage.get("storeCalculationResults") == "True"
                else "Unstored (recomputed on access — not indexable / can't be a match field)"))
        index = storage.get("index", "")
        if index and index != "None":
            lines.append(f"  Indexing: {index}")
        elif storage.get("autoIndex") == "True":
            lines.append("  Indexing: None (auto-created on demand)")
        reps = storage.get("maxRepetitions", "")
        if reps and reps not in ("", "1"):
            lines.append(f"  Repetitions: {reps}")

    body = "\n".join(lines) if lines else "  (no detail)"
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


#: Bounds for the rendered object block (packet 1339). This text is PERSISTED in
#: `ArtifactItem.rendered_text` and consumed by `git diff`, so its size must not track object count:
#: one real file carried 10,270 layout objects, and a per-object dump would bloat every artifact and
#: every export that embeds it.
_OBJ_MAX_TYPES = 8        # distinct type labels before an `other` remainder
_OBJ_MAX_DETAILS = 20     # meaningful binding/action lines
_OBJ_LABEL_WIDTH = 60     # per-line truncation


def _one_line(text: str) -> str:
    """Collapse embedded newlines/control whitespace — a calculation must not break the block."""
    return " ".join((text or "").split())


def _trunc(text: str) -> str:
    t = _one_line(text)
    return t if len(t) <= _OBJ_LABEL_WIDTH else t[:_OBJ_LABEL_WIDTH - 1] + "…"


def _layout_object_lines(xml_str: str) -> list:
    """What is ON the layout, bounded (packet 1339).

    `render_layout` used to read only layout-LEVEL metadata — context table, width, hidden, parts,
    menu set, theme, triggers, margins — and never `PartsList`. So `(no detail)` did not mean "nothing
    on this layout", it meant "no width or theme", and the 3,060 layouts that DID render said nothing
    about their content either.

    Geometry is deliberately absent: bounds, options, hide/conditional formulas belong to the
    wireframe and the Diff/AI views, and duplicating them here would inflate every stored artifact.
    """
    from corpusfm.core.layout_objects import scan_layout_objects
    scan = scan_layout_objects(xml_str)
    if scan.parse_error:
        return []
    if not scan.objects:
        # An UNKNOWN-ONLY layout is not an empty one. Returning [] here let a layout whose every
        # object is an unrecognised form render "(no detail)" — the exact confident-empty answer this
        # block exists to prevent (found by Codex review, 2026-08-26).
        if scan.unexamined:
            kinds = ", ".join(sorted({u["tag"] for u in scan.unexamined})[:3])
            return [f"  Object analysis incomplete: {len(scan.unexamined)} unrecognized ({kinds})"]
        return []

    lines = ["  Objects: %d" % len(scan.objects)]
    counts = Counter(o.type or "?" for o in scan.objects)
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    shown, remainder = ordered[:_OBJ_MAX_TYPES], ordered[_OBJ_MAX_TYPES:]
    parts = [f"{t} {n}" for t, n in shown]
    if remainder:
        parts.append(f"other {sum(n for _, n in remainder)}")
    lines.append("    " + ", ".join(parts))

    #: Deduplicated by semantic tuple, so 100 repeated fields do not consume the budget.
    seen: set = set()
    details: list = []
    for o in scan.objects:
        for text in _object_detail_lines(o):
            if text not in seen:
                seen.add(text)
                details.append(text)
    for text in details[:_OBJ_MAX_DETAILS]:
        lines.append("    " + text)
    if len(details) > _OBJ_MAX_DETAILS:
        lines.append(f"    … +{len(details) - _OBJ_MAX_DETAILS} more meaningful objects")
    if scan.unexamined:
        kinds = ", ".join(sorted({u["tag"] for u in scan.unexamined})[:3])
        lines.append(f"    Object analysis incomplete: {len(scan.unexamined)} unrecognized ({kinds})")
    return lines


def _object_detail_lines(o) -> list:
    """The bindings and actions that carry MEANING for one object. Geometry is not meaning."""
    out: list = []
    if o.field:
        out.append(f"field {_trunc(f'{o.field_to}::{o.field}' if o.field_to else o.field)}")
    if o.to and not o.field:
        out.append(f"{_trunc(o.type)} context {_trunc(o.to)}")
    if o.script:
        out.append(f"{_trunc(o.type)} runs {_trunc(o.script)}")
    for act in (o.actions or []):
        target = act.get("layout") or act.get("to") or act.get("script")
        if act.get("dynamic") or not target:
            out.append(f"{_trunc(act.get('step', '?'))} → (computed)")
        else:
            out.append(f"{_trunc(act.get('step', '?'))} → {_trunc(target)}")
    return out


def render_layout(name: str, xml_str: str, **_) -> RenderedItem:
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=name, body="(parse error)", xml_str=xml_str)

    width  = elem.attrib.get("width", "")
    lines  = []

    ctx_ref = elem.find("TableOccurrenceReference")
    if ctx_ref is not None:
        ctx_name = ctx_ref.attrib.get("name", "")
        if ctx_name:
            lines.append(f"  Context table: {ctx_name}")

    if width:
        lines.append(f"  Width: {width} px")

    opts = elem.find("Options")
    if opts is not None and opts.attrib.get("hidden") == "True":
        lines.append("  Hidden: Yes")

    parts = elem.find("PartsList")
    if parts is not None:
        count = parts.attrib.get("membercount", "")
        if count:
            lines.append(f"  Parts: {count}")

    menu_set = elem.find("MenuSet")
    if menu_set is not None:
        ms_name = menu_set.attrib.get("name", "").strip()
        if ms_name:
            lines.append(f"  Menu set: {ms_name}")

    theme_ref = elem.find("LayoutThemeReference")
    if theme_ref is not None:
        t_name = theme_ref.attrib.get("name", "").strip()
        if t_name:
            lines.append(f"  Theme: {t_name}")

    triggers = elem.find("ScriptTriggers")
    if triggers is not None:
        for trig in triggers.findall("ScriptTrigger"):
            event = trig.get("action") or trig.get("name") or trig.get("event", "?")
            active = trig.get("active", trig.get("enable", "True")) != "False"
            sr = trig.find("ScriptReference")
            script_name = sr.get("name", "?") if sr is not None else "?"
            disabled = " (disabled)" if not active else ""
            lines.append(f"  Trigger {event}: {script_name}{disabled}")

    margins = elem.find("FixedMargins")
    if margins is not None:
        t = margins.attrib.get("top", "")
        r = margins.attrib.get("right", "")
        b = margins.attrib.get("bottom", "")
        l = margins.attrib.get("left", "")
        if any([t, r, b, l]):
            lines.append(f"  Fixed margins: top={t}  right={r}  bottom={b}  left={l}")

    lines.extend(_layout_object_lines(xml_str))

    body = "\n".join(lines) if lines else "  (no detail)"
    return RenderedItem(name=name, summary=name, body=body, xml_str=xml_str)


def render_base_directory(name: str, xml_str: str, **_) -> RenderedItem:
    """Render a BaseDirectoryCatalog / BaseDirectory entry (installed addon / path alias)."""
    import posixpath as _pp
    raw_path = name.rstrip("/")
    # Extract a readable label from the last path component (strip extension)
    last = _pp.basename(raw_path.replace("\\", "/")) or raw_path
    label = last.rsplit(".", 1)[0] if "." in last else last
    summary = label or raw_path

    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=summary, body="(parse error)", xml_str=xml_str)

    source_uuid = elem.findtext("SourceUUID", "").strip()
    lines = [f"  Path: {raw_path}"]
    if source_uuid:
        lines.append(f"  Package UUID: {source_uuid}")

    return RenderedItem(name=name, summary=summary, body="\n".join(lines), xml_str=xml_str)


def render_library(name: str, xml_str: str, **_) -> RenderedItem:
    """Render a LibraryCatalog / BinaryData entry (installed FM addon package)."""
    summary = name
    try:
        elem = _parse(xml_str)
    except ET.ParseError:
        return RenderedItem(name=name, summary=summary, body="(parse error)", xml_str=xml_str)

    lib_ref = elem.find("LibraryReference")
    lines = []
    if lib_ref is not None:
        for attr in ("key", "version", "type"):
            val = lib_ref.get(attr, "").strip()
            if val:
                lines.append(f"  {attr.capitalize()}: {val}")

    body = "\n".join(lines) if lines else "(no details)"
    return RenderedItem(name=name, summary=summary, body=body, xml_str=xml_str)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_FOLDER_SECTIONS = frozenset({
    "ScriptCatalog",
    "LayoutCatalog",
    "CustomFunctionsCatalog",
})

_SEPARATOR_SECTIONS = frozenset({
    "LayoutCatalog",
})

_RENDERERS = {
    "AccountsCatalog":             render_account,
    "BaseDirectoryCatalog":        render_base_directory,
    "LibraryCatalog":              render_library,
    "BaseTableCatalog":            render_basetable,
    "CustomFunctionsCatalog":      render_custom_function,
    "CustomMenuCatalog":           render_custom_menu,
    "ExternalDataSourceCatalog":   render_external_data_source,
    "FieldsForTables":             render_field,
    "LayoutCatalog":               render_layout,
    "RelationshipCatalog":         render_relationship,
    "TableOccurrenceCatalog":      render_table_occurrence,
    "ThemeCatalog":                render_theme,
    "ValueListCatalog":            render_value_list,
    "PrivilegeSetsCatalog":        render_privilege_set,
    "ExtendedPrivilegesCatalog":   render_extended_privilege,
}


def render_section_item(
    section_key: str,
    name: str,
    xml_str: str,
    **kwargs,
) -> RenderedItem:
    """Dispatch to the appropriate renderer for a catalog section item.

    Folder items (isFolder='True') in Script/Layout/CustomFunction catalogs are
    rendered as folders regardless of section. Separator items (isSeparatorItem='True')
    in LayoutCatalog are rendered as separators. Extra kwargs (e.g. calc_xml_str
    for CustomFunctions) are forwarded to the section-specific renderer.
    """
    if section_key in _SEPARATOR_SECTIONS and is_separator(xml_str):
        return render_separator(name, xml_str)
    if section_key in _FOLDER_SECTIONS and is_folder(xml_str):
        return render_folder(name, xml_str)
    renderer = _RENDERERS.get(section_key)
    if renderer is None:
        return RenderedItem(name=name, summary=name, body="", xml_str=xml_str)
    return renderer(name, xml_str, **kwargs)
