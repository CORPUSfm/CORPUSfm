"""Render FM script Step XML elements to human-readable one-line strings.

Public API:
    render_step(step_elem, catalog, show_hidden=True)           -> RenderedStep
    render_script(script_elem, catalog, show_hidden=True)       -> list[RenderedStep]

RenderedStep fields:
    one_line    — collapsed display: single line, newlines replaced with ¶,
                  long param values truncated to ONE_LINE_PARAM_MAX chars + …
    full_text   — expanded display: full param values with newlines preserved
    partial     — True when the step ID is absent from the catalog (fallback used)
    disabled    — True when the step's enable attribute is "False"
    step_id     — integer step ID from the XML @id attribute
    step_name   — step name string from the XML @name attribute
    depth       — indentation level (0 = top-level); set by render_script()
    block_id    — shared integer across opener/body/closer of same block; None outside a block
    block_role  — "opener" | "continue" | "closer" | "body" | None
"""

from __future__ import annotations

import re
from string import Formatter
from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from typing import Optional

from corpusfm.core.rendering import hidden_chars

ONE_LINE_PARAM_MAX = 100  # truncate individual param values beyond this length

# Block classification (opener / continue / closer) is driven ENTIRELY by the structure catalog's
# per-step `block_role` (packet 072-A / 074) — the former hardcoded frozensets were retired. FM's
# schema is purely additive and fenced to [2.2.0.0, 2.3.0.0], so block roles are identical across
# the supported window; we load the map once from the latest structure catalog. A future FM block
# construct is supported by adding its step to structure_catalog.yaml — no code change, no drift
# guard to keep in sync. (The maintainer is the guard; a new nesting step absent from the YAML
# renders flat and self-signals the update, per the gap analyzer.)
_BLOCK_ROLE_CACHE: "dict[int, str] | None" = None


def _block_roles() -> "dict[int, str]":
    """{step_id: 'opener'|'continue'|'closer'} from the latest structure catalog (cached)."""
    global _BLOCK_ROLE_CACHE
    if _BLOCK_ROLE_CACHE is None:
        from corpusfm.core.schemas.registry import _available_versions, load_structure_catalog
        versions = _available_versions("structure_catalog.yaml")
        if not versions:
            raise RuntimeError("no structure_catalog.yaml available — cannot classify script blocks")
        cat, _ = load_structure_catalog(versions[-1])
        _BLOCK_ROLE_CACHE = {sid: e.block_role for sid, e in cat.steps.items() if e.block_role}
    return _BLOCK_ROLE_CACHE


class _DefaultingDict(dict):
    """format_map backing that yields '' for a missing key instead of raising KeyError."""
    def __missing__(self, key):  # noqa: D401
        return ""


def _safe_format(template: str, values: dict) -> str:
    """Render a step template tolerantly (packet 067). A template referencing a placeholder the params
    spec doesn't produce used to raise KeyError inside .format(), which the per-script catch turned into
    a BLANKED ENTIRE SCRIPT. Missing keys now render '' (isolated to this step); a hard malformed template
    degrades to the raw template rather than blanking. Well-formed templates render byte-identically."""
    try:
        return template.format_map(_DefaultingDict(values))
    except Exception:
        return template


@dataclass
class RenderedStep:
    one_line: str
    full_text: str
    partial: bool
    disabled: bool
    step_id: int
    step_name: str
    depth: int = 0
    block_id: Optional[int] = None
    block_role: Optional[str] = None
    # Exact literal/parameter boundaries for consumers that need to disclose one value without
    # parsing the flattened display string. Empty means the renderer could not prove a boundary.
    display_parts: list[dict[str, str]] = field(default_factory=list)


def _display_parts(template: str, values: dict[str, str]) -> list[dict[str, str]]:
    """Return exact literal/parameter parts for a simple catalog template.

    Catalog templates currently use named fields without conversions or format specifications.
    Refuse anything richer: a consumer must never guess a parameter span from flattened text.
    """
    parts: list[dict[str, str]] = []
    try:
        for literal, name, format_spec, conversion in Formatter().parse(template):
            if literal:
                parts.append({"kind": "literal", "text": literal})
            if name is None:
                continue
            if not name or format_spec or conversion or name not in values:
                return []
            parts.append({"kind": "parameter", "name": name, "text": values[name]})
    except (ValueError, KeyError):
        return []
    return parts


# ── Extraction helpers ────────────────────────────────────────────────────────


def _extract(elem: ET.Element, xpath: str, attr: Optional[str] = None) -> str:
    """Run xpath on elem; return attribute or text. Returns '' if not found.

    Robust to two things ElementTree's find() can't handle on its own:
      • a trailing '/@attr' in the xpath — ElementTree cannot select an attribute node, so
        find('.../List/@name') raises KeyError('@'). We split it into element-path + attr.
      • any other malformed/unsupported xpath — caught and degraded to '', so one bad param
        spec yields an empty value instead of raising and blanking the ENTIRE script body.
    """
    if attr is None and "/@" in xpath:
        xpath, _, attr = xpath.rpartition("/@")
    try:
        found = elem.find(xpath)
    except (KeyError, SyntaxError):
        return ""
    if found is None:
        return ""
    if attr:
        return found.get(attr) or ""
    return found.text or ""


def _extract_params(
    step_elem: ET.Element,
    params_spec: dict,
    single_line: bool,
) -> dict:
    """Extract all params from the step element and apply display mappings."""
    result = {}
    for key, spec in params_spec.items():
        if "alts" in spec:
            # First non-empty xpath wins, with its own prefix/suffix. Lets one param
            # render either of two mutually-exclusive forms — e.g. Perform Script's
            # target, which is a <ScriptReference> (specify from list) OR a
            # <Calculation> (specify "by name"); the old single xpath rendered the
            # by-name case as an empty "".
            value = ""
            for alt in spec["alts"]:
                raw = _extract(step_elem, alt["xpath"], alt.get("attr"))
                if raw:
                    value = alt.get("prefix", "") + raw + alt.get("suffix", "")
                    break
            result[key] = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "¶") if single_line else value
            continue
        raw = _extract(step_elem, spec["xpath"], spec.get("attr"))
        display = spec.get("display", {})
        value = display.get(raw, raw) if display else raw
        if value and "suffix" in spec:
            value = value + spec["suffix"]
        if single_line:
            # Collapse newlines to pilcrow and strip carriage returns
            value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "¶")
        result[key] = value
    return result


def _truncate(value: str, max_len: int = ONE_LINE_PARAM_MAX) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + "…"


# ── Fallback rendering ────────────────────────────────────────────────────────


def _fallback(step_elem: ET.Element) -> str:
    """Collect all Calculation/Text descendants and join as a summary."""
    texts = [
        t.strip()
        for t in (e.text or "" for e in step_elem.iter("Text"))
        if t.strip()
    ]
    if texts:
        combined = " ; ".join(texts)
        return combined
    return ""


# ── FM2026 native-AI steps: generic ParameterValues rendering ─────────────────
# The AI steps (Configure AI Account, Insert Embedding, Generate Response, …) all share one
# uniform shape: <ParameterValues><Parameter type="X">{Boolean|List|Calculation/Text|Variable}.
# Rather than hand-author per-step xpaths for 16 steps × up-to-15 params each, a catalog entry
# flagged `render: ai_params` renders that block generically. Grounded on a real 26.0.1 export
# (xmlsamples/DB_AI_ScriptSamples.xml). The Parameter@type IS the semantic slot name
# (LLMAccountName, LLMEmbeddingModel, ModelProvider, …) — humanized for display.

def _humanize(t: str) -> str:
    """`LLMAccountName` → `LLM Account Name`; `RAGSpaceID` → `RAG Space ID`. Keeps acronym
    runs (LLM/RAG/SQL/SSL/ID) intact, splits camelCase elsewhere."""
    if not t:
        return "Param"
    s = re.sub(r"\b(LLM|RAG)(API)", r"\1 \2", t)           # split stacked acronyms (LLMAPIKey)
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)          # camel boundary
    s = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", s)        # acronym→Word boundary
    return s.strip()


def _ai_param_pairs(p: ET.Element):
    """Yield (label, value) for one <Parameter> of an AI step. Handles the boolean toggle,
    enum (List), calc-text, variable, and nested-Parameter (e.g. LLMWebScript) forms."""
    ptype = p.get("type", "")
    b = p.find("Boolean")
    if b is not None:
        yield (b.get("type") or "Option", b.get("value") or "")
        return
    lst = p.find("List")
    if lst is not None:
        label = "Option" if ptype in ("List", "") else _humanize(ptype)
        yield (label, lst.get("name") or "")
        return
    var = p.find("Variable")
    if var is not None:
        yield (_humanize(ptype), var.get("value") or "")
        return
    nested = p.findall("Parameter")
    if nested:
        for np in nested:
            for lab, val in _ai_param_pairs(np):
                yield (f"{_humanize(ptype)} · {lab}", val)
        return
    t = p.find(".//Text")
    if t is not None and (t.text or "").strip():
        yield (_humanize(ptype), t.text.strip())


def _render_ai_params(step_elem: ET.Element, step_name: str, *, single_line: bool) -> str:
    """Render an AI step's ParameterValues as `Name [ label: value ; … ]` (one-line) or a
    multi-line block. Empty params are dropped."""
    pv = step_elem.find("ParameterValues")
    pairs = []
    if pv is not None:
        for p in pv.findall("Parameter"):
            for label, value in _ai_param_pairs(p):
                if (value or "").strip():
                    pairs.append((label, value.strip()))
    if not pairs:
        return step_name
    if single_line:
        body = " ; ".join(f"{lab}: {_truncate(val)}" for lab, val in pairs)
        return f"{step_name} [ {body} ]"
    body = "\n".join(f"    {lab}: {val}" for lab, val in pairs)
    return f"{step_name} [\n{body}\n]"


def _sort_fields(step_elem: ET.Element) -> list:
    """The fields a Sort Records step sorts by — which the base `[ With dialog: … ]` template
    hides (packet 1024 §6: the 'the rendered text lies' case that masked a real ordering bug).

    Reads the DDR SortSpecification/SortList: each `<Sort type="Ascending|Descending|Custom">`
    carries a PrimaryField/FieldReference (+ its TableOccurrenceReference) and, for a Custom sort,
    a ValueListReference. Tolerant of a `<PrimarySortField>`/`<SortOrder>` variant. Returns a list
    of display strings like `PO::PONumber ▲`, `Item::Grouping (custom: MyVL)`."""
    out: list = []
    for sl in step_elem.iter("SortList"):
        entries = sl.findall("Sort") or sl.findall("PrimarySortField") or sl.findall("PrimaryField")
        for e in entries or [sl]:
            fr = e.find(".//FieldReference")
            if fr is None:
                continue
            fname = fr.get("name") or ""
            to = fr.find("TableOccurrenceReference")
            toname = to.get("name") if to is not None else ""
            label = f"{toname}::{fname}" if toname else fname
            stype = (e.get("type") or "").strip()
            if not stype:
                so = e.find(".//SortOrder")
                stype = (so.get("value") if so is not None else "") or ""
            if stype == "Custom":
                vl = e.find(".//ValueListReference")
                vlname = vl.get("name") if vl is not None else ""
                out.append(f"{label} (custom{': ' + vlname if vlname else ''})")
            else:
                out.append(label + {"Ascending": " ▲", "Descending": " ▼"}.get(stype, ""))
    return out


def _restore_on(step_elem: ET.Element) -> bool:
    """True iff the step's `Restore` parameter is set (packet 1043 §4). A restore step re-applies a
    SAVED order/state (the stored sort order, a stored found set) rather than acting on the current
    one — the base `[ With dialog: … ]` template drops it, so a restore-based step reads as a no-op.
    DDR shape: `<Parameter type="Restore"><Restore value="True"/></Parameter>`."""
    r = step_elem.find(".//Parameter[@type='Restore']/Restore")
    return r is not None and r.get("value") == "True"


def _hidden_flags(step_elem: ET.Element) -> list:
    """Behaviour-bearing option flags the hand-authored base templates drop — the residual "the text
    lies" class (roadmap; same root as the invisible-Sort bug, packet 1024 §6). Read GENERICALLY from
    the DDR (no step-id list), so any base-template step that carries one surfaces it:

      • `Restore` — re-applies a SAVED state (a stored found set / import order / print setup) instead
        of acting on the current one. Carried by Perform Find, Import Records, Print / Print Setup,
        Save Records as PDF/Excel, Create/Print PDF, … `<Parameter type="Restore" value="True">`.
      • `Exit after last` — Go to Record/Request/Page [ Next/Previous ] that exits the loop on the
        last record (the difference between an infinite loop and a clean one). `<Boolean
        type="Exit after last" value="True">`, nested in the Records `<List>`.

    Sort Records surfaces Restore itself (its render mode), so it never reaches this generic path."""
    flags: list = []
    if _restore_on(step_elem):
        flags.append("Restore")
    if any(b.get("value") == "True"
           for b in step_elem.iter("Boolean") if b.get("type") == "Exit after last"):
        flags.append("Exit after last")
    return flags


def _append_flags(text: str, flags: list) -> str:
    """Merge hidden option flags into an already-rendered template string, honouring its shape:
    into an existing `Name [ … ]` bracket (single- or multi-line), else as a fresh `Name [ … ]`."""
    flags = [f for f in flags if f]
    if not flags:
        return text
    fs = " ; ".join(flags)
    if text.rstrip().endswith("]"):
        if "\n]" in text:                                 # multi-line block: insert before the "\n]"
            return text[:text.rindex("\n]")] + "\n    " + fs + "\n]"
        return text.rstrip()[:-1].rstrip() + " ; " + fs + " ]"   # single-line "Name [ inner ]"
    return f"{text} [ {fs} ]"                              # no bracket (e.g. "Perform Find")


# ── Render residue (packet 1140) ──────────────────────────────────────────────
# A step template's `params` block is a guideline for the READABLE part, not an inventory of what
# is worth showing — it became a de-facto allowlist without anyone choosing that, so any DDR value
# with no slot rendered nowhere (the `1/0` repetition operand that raises FM error 5 was the exhibit).
# Residue = every text-bearing node no param consumed. It is appended NEUTRALLY (`label: value`,
# never a `[n]` subscript): a <repetition> element is overloaded — a real index on Set Field, a
# script parameter on Install OnTimer Script, a criterion on Find Matching Records — so asserting
# "index" would lie. Naming the tag reports what the DDR holds and interprets nothing. This mirrors
# _hidden_flags/_append_flags (which already surface dropped Restore/Exit-after-last generically) and
# closes the inversion where an UNKNOWN step (via _fallback) rendered MORE faithfully than a known one.
# Scope: the plain-template path only — the measured residue census (packet 1140) excluded the special
# render modes (ai_params/sort_records/ref), which surface their own dropped content.
_RESIDUE_DENYLIST = frozenset({"UUID", "DDRREF", "SourceUUID", "Options"})   # machine identity / step bitmask
_RESIDUE_WRAPPERS = frozenset({"Text", "Calculation", "value"})   # calc-encoding wrappers carry no label


def _consumed_nodes(step_elem: ET.Element, params_spec: dict) -> set:
    """The elements a params-spec render reads (find(), first match) — mirrors _extract, so residue
    is exactly 'what rendering did NOT consume'. Every alts branch's target is marked, not just the
    winner, so a losing alternative never resurfaces as residue."""
    consumed: set = set()
    for spec in (params_spec or {}).values():
        if "alts" in spec:
            xpaths = [a.get("xpath", "") for a in spec["alts"]]
        elif "xpath" in spec:
            xpaths = [spec["xpath"]]
        else:
            xpaths = []
        for xp in xpaths:
            if "/@" in xp:
                xp = xp.rpartition("/@")[0]
            try:
                found = step_elem.find(xp)
            except (KeyError, SyntaxError):
                continue
            if found is not None:
                consumed.add(id(found))
    return consumed


def _residue_label(node: ET.Element, parents: dict) -> str:
    """Name a residue value by its nearest meaningful ancestor, skipping calc wrappers:
    repetition/Calculation/Calculation/Text → 'repetition'; Bounds/height/Calc/Calc/Text → 'height';
    Options/Close (text on Close itself) → 'Close'. A <Parameter> is named by its @type — the DDR's
    own semantic slot (Message/Title/Calculation/…) — not the bare tag; a value that climbs past a
    Parameter-less path to a structural container (ParameterValues/Step) keeps its own tag."""
    cur = node
    while cur is not None and cur.tag in _RESIDUE_WRAPPERS:
        cur = parents.get(cur)
    if cur is None or cur.tag in ("ParameterValues", "Step"):
        return node.tag
    if cur.tag == "Parameter":
        return cur.get("type") or "Parameter"
    return cur.tag


def _render_residue(step_elem: ET.Element, consumed: set) -> list:
    """[(label, raw_value)] for every text-bearing node no param consumed, minus the machine tags
    (denylist — a step's own <Options> bitmask leaf; a WindowReference/Options CONTAINER is skipped
    by tag but its meaningful children still surface) and the uninformative default repetition `1`
    (FileMaker itself hides a [1] subscript, so suppressing it keeps default output byte-identical)."""
    parents = {c: p for p in step_elem.iter() for c in p}
    out: list = []
    for node in step_elem.iter():
        if node is step_elem or id(node) in consumed or node.tag in _RESIDUE_DENYLIST:
            continue
        if not (node.text or "").strip():
            continue
        label = _residue_label(node, parents)
        if label == "repetition" and node.text.strip() == "1":
            continue
        out.append((label, node.text))
    return out


def _fmt_residue_value(value: str, single_line: bool, show_hidden: bool) -> str:
    if single_line:
        value = value.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "¶")
    return hidden_chars.apply(value) if show_hidden else value


def _render_sort_records(step_elem: ET.Element, *, single_line: bool) -> str:
    """Render Sort Records WITH its sort fields (base template drops them). Falls back to the
    plain `[ With dialog: … ]` form when a step carries no explicit sort list (sort-by-dialog).
    Surfaces the `Restore` flag (packet 1043 §4) when set — otherwise a restore-a-saved-sort step
    reads as an empty sort."""
    dlg_el = step_elem.find(".//Boolean[@type='With dialog']")
    dlg = {"True": "On", "False": "Off"}.get(dlg_el.get("value") if dlg_el is not None else "", "Off")
    restore = "Restore ; " if _restore_on(step_elem) else ""
    fields = _sort_fields(step_elem)
    if not fields:
        return f"Sort Records [ {restore}With dialog: {dlg} ]"
    if single_line:
        return f"Sort Records [ {restore}With dialog: {dlg} ; by: {_truncate(', '.join(fields))} ]"
    body = "\n".join(f"    {f}" for f in fields)
    return f"Sort Records [ {restore}With dialog: {dlg} ; by:\n{body}\n]"


# ── Reference-surfacing render modes (packet 1027) ────────────────────────────
# A class of steps rendered a bare name (or dropped a referenced object) because the hand-authored
# template had no slot for it — the "the text lies" case (packet 1024 §6 fixed the Sort instance;
# this closes more). Each is a catalog-driven `render:` mode (no hardcoded step-ids), mirroring
# _render_sort_records: surface the dropped FieldReference/LayoutReference/calc inline, tolerant of
# the no-param fallback. Two small shared extractors keep them faithful and terse.

def _readable_calc(container: "ET.Element | None") -> str:
    """The human-readable calc text under the first <Calculation> in `container` — the <Text> child
    of the innermost <Calculation> (skips the DDRREF/ChunkList internals). '' if none."""
    if container is None:
        return ""
    for calc in container.iter("Calculation"):
        t = calc.find("Text")
        if t is not None and (t.text or "").strip():
            return t.text.strip()
    return ""


def _fieldref_label(fr: "ET.Element | None") -> str:
    """`TO::Field` (or `Field`) from a <FieldReference>."""
    if fr is None:
        return ""
    fname = fr.get("name") or ""
    to = fr.find("TableOccurrenceReference")
    toname = to.get("name") if to is not None else ""
    return f"{toname}::{fname}" if (toname and fname) else fname


def _layout_of(container: "ET.Element | None") -> str:
    """A LayoutReferenceContainer's target: the LayoutReference name, or a layout-by-calc, or ''."""
    if container is None:
        return ""
    lr = container.find(".//LayoutReference")
    if lr is not None and lr.get("name"):
        return lr.get("name")
    return _readable_calc(container)


def _bracket(name: str, parts: list, *, single_line: bool) -> str:
    """`Name [ a ; b ]` (one-line, truncated) or a multi-line block; bare `Name` when empty."""
    parts = [p for p in parts if p]
    if not parts:
        return name
    if single_line:
        joined = " ; ".join(parts).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "¶")
        return f"{name} [ {_truncate(joined)} ]"
    body = "\n".join(f"    {p}" for p in parts)
    return f"{name} [\n{body}\n]"


def _render_new_window(step_elem: ET.Element, *, single_line: bool) -> str:
    """New Window WITH its target layout (a LayoutReference the base template dropped entirely),
    plus the window Style and calculated Name when present."""
    wr = step_elem.find(".//WindowReference")
    parts: list = []
    if wr is not None:
        style = wr.find("Style")
        if style is not None and style.get("name"):
            parts.append(f"Style: {style.get('name')}")
        nm = _readable_calc(wr.find("Name"))
        if nm:
            parts.append(f"Name: {nm}")
        lay = _layout_of(wr.find("LayoutReferenceContainer"))
        if lay:
            parts.append(f"Layout: {lay}")
    return _bracket("New Window", parts, single_line=single_line)


def _render_export_field_contents(step_elem: ET.Element, *, single_line: bool) -> str:
    """Export Field Contents WITH the source field (dropped by the bare template)."""
    fr = step_elem.find("./ParameterValues/Parameter[@type='FieldReference']/FieldReference")
    return _bracket("Export Field Contents",
                    [_fieldref_label(fr)] if fr is not None else [], single_line=single_line)


def _render_insert_file(step_elem: ET.Element, *, single_line: bool) -> str:
    """Insert File WITH the target field (dropped by the bare template)."""
    fr = step_elem.find("./ParameterValues/Parameter[@type='Target']/FieldReference")
    return _bracket("Insert File",
                    [_fieldref_label(fr)] if fr is not None else [], single_line=single_line)


def _render_insert_calc_result(step_elem: ET.Element, *, single_line: bool) -> str:
    """Insert Calculated Result — surface a FIELD target (base template only handled a Variable
    target, so a field destination rendered blank), plus the value calc."""
    tgt_p = step_elem.find("./ParameterValues/Parameter[@type='Target']")
    if tgt_p is not None:
        fr = tgt_p.find("FieldReference")
        var = tgt_p.find("Variable")
        target = _fieldref_label(fr) if fr is not None else (var.get("value") if var is not None else "")
    else:
        target = ""
    value = _readable_calc(step_elem.find("./ParameterValues/Parameter[@type='Calculation']"))
    return _bracket("Insert Calculated Result", [target, value], single_line=single_line)


def _render_insert_from_url(step_elem: ET.Element, *, single_line: bool) -> str:
    """Insert from URL WITH the target field (base template rendered only the URL calc)."""
    fr = step_elem.find("./ParameterValues/Parameter[@type='Target']/FieldReference")
    url = _readable_calc(step_elem.find("./ParameterValues/Parameter[@type='URL']/URL"))
    parts = [_fieldref_label(fr) if fr is not None else "", f"URL: {url}" if url else ""]
    return _bracket("Insert from URL", parts, single_line=single_line)


def _render_gtrr(step_elem: ET.Element, *, single_line: bool) -> str:
    """Go to Related Record — surface a layout specified BY CALCULATION (the base template only read
    a static LayoutReference name, dropping a calculated layout), alongside the related TO."""
    rel = step_elem.find("./ParameterValues/Parameter[@type='Related']")
    to = rel.find("TableOccurrenceReference") if rel is not None else None
    toname = to.get("name") if to is not None else ""
    layout = _layout_of(rel.find("LayoutReferenceContainer")) if rel is not None else ""
    parts = [f"From: {toname}" if toname else "", f"Layout: {layout}" if layout else ""]
    return _bracket("Go to Related Record", parts, single_line=single_line)


def _param_calc(step_elem: ET.Element, ptype: str) -> str:
    """Readable calc text under `<Parameter type="{ptype}">` — '' if absent."""
    return _readable_calc(step_elem.find(f"./ParameterValues/Parameter[@type='{ptype}']"))


def _render_enable_account(step_elem: ET.Element, *, single_line: bool) -> str:
    """Enable Account WITH the target account-name calc (base template rendered a bare name)."""
    acct = _param_calc(step_elem, "Calculation")
    return _bracket("Enable Account", [f"Account: {acct}" if acct else ""], single_line=single_line)


def _render_relogin(step_elem: ET.Element, *, single_line: bool) -> str:
    """Re-Login WITH the account-name calc (base template rendered a bare name). The password calc is
    intentionally NOT surfaced — it names where credentials come from and stays out of rendered text."""
    acct = _param_calc(step_elem, "Name")
    return _bracket("Re-Login", [f"Account: {acct}" if acct else ""], single_line=single_line)


def _render_execute_fmdapi(step_elem: ET.Element, *, single_line: bool) -> str:
    """Execute FileMaker Data API WITH the request calc + target variable (base template dropped both)."""
    var = step_elem.find("./ParameterValues/Parameter[@type='Target']/Variable")
    req = _param_calc(step_elem, "Calculation")
    parts = [f"Target: {var.get('value')}" if (var is not None and var.get("value")) else "",
             f"Request: {req}" if req else ""]
    return _bracket("Execute FileMaker Data API", parts, single_line=single_line)


def _render_perform_js_webviewer(step_elem: ET.Element, *, single_line: bool) -> str:
    """Perform JavaScript in Web Viewer WITH the web-viewer object + JS function (base template
    dropped both — an agent couldn't see what ran or where)."""
    obj = _param_calc(step_elem, "Name")
    fn = _param_calc(step_elem, "FunctionRef")
    parts = [f"Object: {obj}" if obj else "", f"Function: {fn}" if fn else ""]
    return _bracket("Perform JavaScript in Web Viewer", parts, single_line=single_line)


# ── List-encoded param render modes (packet 1150) ─────────────────────────────
# The operative value of these steps is a `<List name>` ATTRIBUTE, which packet 1140's text-only
# residue cannot reach. The base template either matched an unrelated Boolean (rendering the
# opposite of the step) or the wrong Parameter type (rendering nothing). Surfaced by evidence, not
# by a generic attribute sweep — see the packet for why the attribute space is 77% Perform-Script
# noise and needs per-step discrimination.

def _render_go_to_portal_row(step_elem: ET.Element, *, single_line: bool) -> str:
    """Go to Portal Row — the row target is `Parameter[@type='Portal']/List` @name
    (First/Last/Previous/Next/Select entry/By Calculation…). The By-Calculation… variant nests the
    row-number calc inside the List; surface it too. The `Boolean type="Select"` flag is out of
    scope (packet 1150)."""
    lst = step_elem.find("./ParameterValues/Parameter[@type='Portal']/List")
    if lst is None:
        return _bracket("Go to Portal Row", [], single_line=single_line)
    parts = [lst.get("name") or "", _readable_calc(lst)]
    return _bracket("Go to Portal Row", parts, single_line=single_line)


def _render_sort_records_by_field(step_elem: ET.Element, *, single_line: bool) -> str:
    """Sort Records by Field — add the sort direction (`Parameter[@type='List']/List` @name,
    Ascending/Descending) the base template dropped, and omit the `::`/field clause entirely when
    there is no FieldReference (the direction-only case rendered a misleading `[ :: ]`). packet 1150."""
    fr = step_elem.find("./ParameterValues/Parameter[@type='FieldReference']/FieldReference")
    lst = step_elem.find("./ParameterValues/Parameter[@type='List']/List")
    direction = lst.get("name") if lst is not None else ""
    parts = [_fieldref_label(fr) if fr is not None else "", direction or ""]
    return _bracket("Sort Records by Field", parts, single_line=single_line)


# {render-mode key: helper} — dispatched in render_step (mirrors sort_records/ai_params).
_REF_RENDER_MODES = {
    "new_window": _render_new_window,
    "export_field_contents": _render_export_field_contents,
    "insert_file": _render_insert_file,
    "insert_calc_result": _render_insert_calc_result,
    "insert_from_url": _render_insert_from_url,
    "gtrr": _render_gtrr,
    "enable_account": _render_enable_account,
    "relogin": _render_relogin,
    "execute_fmdapi": _render_execute_fmdapi,
    "perform_js_webviewer": _render_perform_js_webviewer,
    "go_to_portal_row": _render_go_to_portal_row,
    "sort_records_by_field": _render_sort_records_by_field,
}


# ── Public API ────────────────────────────────────────────────────────────────


def render_step(
    step_elem: ET.Element,
    catalog: dict,
    show_hidden: bool = True,
) -> RenderedStep:
    """Render one Step element.

    catalog: {step_id_int: entry_dict} as returned by load_catalog().
    """
    try:
        step_id = int(step_elem.get("id", "-1"))
    except ValueError:
        step_id = -1
    step_name = step_elem.get("name", "")
    disabled = step_elem.get("enable", "True") == "False"

    entry = catalog.get(step_id)
    partial = entry is None
    display_parts: list[dict[str, str]] = []

    if entry is not None and entry.get("render") == "ai_params":
        # FM2026 native-AI step — render its ParameterValues block generically.
        ol = _render_ai_params(step_elem, step_name, single_line=True)
        ft = _render_ai_params(step_elem, step_name, single_line=False)
        one_line = hidden_chars.apply(ol) if show_hidden else ol
        full_text = hidden_chars.apply(ft) if show_hidden else ft
    elif entry is not None and entry.get("render") == "sort_records":
        # Sort Records — surface the sort FIELDS the base template hides (packet 1024 §6).
        ol = _render_sort_records(step_elem, single_line=True)
        ft = _render_sort_records(step_elem, single_line=False)
        one_line = hidden_chars.apply(ol) if show_hidden else ol
        full_text = hidden_chars.apply(ft) if show_hidden else ft
    elif entry is not None and entry.get("render") in _REF_RENDER_MODES:
        # packet 1027 — surface a referenced object/calc the bare template dropped ("the text lies").
        fn = _REF_RENDER_MODES[entry["render"]]
        ol = fn(step_elem, single_line=True)
        ft = fn(step_elem, single_line=False)
        one_line = hidden_chars.apply(ol) if show_hidden else ol
        full_text = hidden_chars.apply(ft) if show_hidden else ft
    elif entry is not None:
        template: str = entry.get("template") or step_name
        params_spec: dict = entry.get("params") or {}

        # Build one_line: newlines → ¶, truncate, apply hidden chars to values
        ol_params = _extract_params(step_elem, params_spec, single_line=True)
        ol_values = {
            k: (hidden_chars.apply(_truncate(v)) if show_hidden else _truncate(v))
            for k, v in ol_params.items()
        }
        one_line = _safe_format(template, ol_values)

        # Build full_text: newlines preserved, apply hidden chars to values
        ft_params = _extract_params(step_elem, params_spec, single_line=False)
        ft_values = {
            k: (hidden_chars.apply(v) if show_hidden else v)
            for k, v in ft_params.items()
        }
        full_text = _safe_format(template, ft_values)
        display_parts = _display_parts(template, ft_values)

        # A step that renders blank when a named param is empty (an empty comment is
        # a blank line in FileMaker, not "# ").
        bwe = entry.get("blank_when_empty")
        if bwe and not (ft_params.get(bwe) or "").strip():
            one_line = full_text = ""
        else:
            # Surface behaviour-bearing flags the base template drops (Restore / Exit after last).
            flags = _hidden_flags(step_elem)
            if flags:
                one_line = _append_flags(one_line, flags)
                full_text = _append_flags(full_text, flags)
            # Append DDR content no param consumed (packet 1140) — a repetition operand, a stored
            # label, a criterion the template has no slot for stops being invisible. Neutral
            # `label: value`; suppressed for the default repetition `1`, so default output is
            # byte-identical to pre-packet.
            residue = _render_residue(step_elem, _consumed_nodes(step_elem, params_spec))
            if residue:
                ol_res = [f"{lbl}: {_truncate(_fmt_residue_value(v, True, show_hidden))}"
                          for lbl, v in residue]
                ft_res = [f"{lbl}: {_fmt_residue_value(v, False, show_hidden)}"
                          for lbl, v in residue]
                one_line = _append_flags(one_line, ol_res)
                full_text = _append_flags(full_text, ft_res)
    else:
        # Fallback: step name + extracted text summary
        summary = _fallback(step_elem)
        if show_hidden:
            summary = hidden_chars.apply(summary)
        if summary:
            one_line = f"{step_name} [ {_truncate(summary)} ]  ⚠ partial"
            full_text = f"{step_name} [ {summary} ]  ⚠ partial"
        else:
            one_line = f"{step_name}  ⚠ partial"
            full_text = one_line

    # Flags, residue, blanking, or a tolerant formatting fallback can change the flattened line.
    # Publish boundaries only when their exact concatenation still proves the final display.
    if "".join(part["text"] for part in display_parts) != full_text:
        display_parts = []

    return RenderedStep(
        one_line=one_line,
        full_text=full_text,
        partial=partial,
        disabled=disabled,
        step_id=step_id,
        step_name=step_name,
        display_parts=display_parts,
    )


def render_script(
    script_elem: ET.Element,
    catalog: dict,
    show_hidden: bool = True,
) -> list[RenderedStep]:
    """Render all Step children of a Script element with depth and block metadata."""
    results: list[RenderedStep] = []
    depth = 0
    next_block_id = 0
    # Stack of (block_id,) for currently open blocks; lets closers find their id.
    block_stack: list[int] = []
    roles = _block_roles()   # {step_id: 'opener'|'continue'|'closer'} from the structure catalog

    for step_elem in script_elem.iter("Step"):
        try:
            sid = int(step_elem.get("id", "-1"))
        except ValueError:
            sid = -1

        rs = render_step(step_elem, catalog, show_hidden=show_hidden)

        role = roles.get(sid)
        if role == "opener":
            bid = next_block_id
            next_block_id += 1
            block_stack.append(bid)
            rs.depth = depth
            rs.block_id = bid
            rs.block_role = "opener"
            depth += 1
        elif role == "continue":
            depth = max(0, depth - 1)
            bid = block_stack[-1] if block_stack else None
            rs.depth = depth
            rs.block_id = bid
            rs.block_role = "continue"
            depth += 1
        elif role == "closer":
            depth = max(0, depth - 1)
            bid = block_stack.pop() if block_stack else None
            rs.depth = depth
            rs.block_id = bid
            rs.block_role = "closer"
        else:
            rs.depth = depth
            rs.block_id = block_stack[-1] if block_stack else None
            rs.block_role = "body" if block_stack else None

        results.append(rs)

    return results
