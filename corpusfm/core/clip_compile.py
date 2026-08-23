"""Packet 1131 — structured AI-authored script → fmClip compiler (MVP).

The compiler is NOT a second emitter. It lowers a thin, name-based, FLAT AST into DDR ``<Step>`` XML — the
exact ``StepsForScripts`` step dialect a real SaveAsXML export carries — and hands that blob to the existing,
fenced ``clip_emit.emit_script_clip``. Everything downstream of the DDR step seam (permission, the
verified/experimental line, static validity, source-incomplete reporting, whole-script atomicity) is reused
unchanged. The compiler's whole job is: resolve names → ids/anchors against a selected target artifact, and
build the DDR steps a SaveAsXML would contain for the authored intent.

Governed by the fmClip product model (CLAUDE.md, packet-1086 epoch + the 2026-07-18 developer-final
direction): a generated clip is a legitimate, useful FileMaker starting point; FileMaker is the final
contextual editor; limitations travel in RESULT METADATA, never in the clip XML; a requested step or
reference is NEVER silently omitted or substituted — the compiler returns a complete script or withholds the
whole result (② taxonomy below).

MVP scope (widens later by ordinary evidence work, not by relaxing the fence):
  - vocabulary: 14 verified emitter ids (control flow, Set Field/Variable, Perform Script/Go to Layout,
    Show Custom Dialog, Comment) — anything else refuses as an unsupported step.
  - resolver: three reference kinds only — fields+table occurrences, layouts, current-file scripts.
    External-file resolution and Print Setup are explicitly OUT of the MVP.
  - flat AST only: control flow is explicit sequential steps (If/Else If/Else/End If, Loop/Exit Loop If/
    End Loop); no nested blocks. Block balance is validated over the flat list before lowering.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _dc_field

from corpusfm.core import safe_xml as ET
from corpusfm.core import acceptance
from corpusfm.core import clip_emit as ce


# ── MVP vocabulary ────────────────────────────────────────────────────────────────
# friendly canonical name → DDR step id. The friendly name is what the authoring agent writes; the DDR
# `name` attribute (which the emitter copies verbatim into the clip) may differ (Comment → "# (comment)").
MVP_STEP_IDS: "dict[str, str]" = {
    "If": "68", "Else If": "125", "Else": "69", "End If": "70",
    "Loop": "71", "Exit Loop If": "72", "End Loop": "73", "Exit Script": "103",
    "Set Field": "76", "Set Variable": "141",
    "Perform Script": "1", "Go to Layout": "6",
    "Show Custom Dialog": "87", "Comment": "89",
}
# id → the exact DDR/clip `name` attribute FileMaker uses (verified against the committed pairs).
_DDR_NAME: "dict[str, str]" = {
    "68": "If", "125": "Else If", "69": "Else", "70": "End If",
    "71": "Loop", "72": "Exit Loop If", "73": "End Loop", "103": "Exit Script",
    "76": "Set Field", "141": "Set Variable", "1": "Perform Script",
    "6": "Go to Layout", "87": "Show Custom Dialog", "89": "# (comment)",
}
# accept the friendly name, the DDR `name` spelling (incl. "# (comment)"), or the raw id as aliases.
_ALIASES: "dict[str, str]" = {n: n for n in MVP_STEP_IDS}
for _fn, _sid in MVP_STEP_IDS.items():
    _ALIASES[_sid] = _fn
    _ALIASES[_DDR_NAME[_sid]] = _fn

# block structure (over the flat list). openers push; the matching closer pops; continuers must sit inside
# the right open block; Exit Loop If must sit inside an open Loop.
_OPENERS = {"If", "Loop"}
_CLOSER_OF = {"End If": "If", "End Loop": "Loop"}
_CONTINUER_BLOCK = {"Else If": "If", "Else": "If"}
_INSIDE_LOOP = {"Exit Loop If"}

# Go to Layout destination modes (AST "mode" → LayoutReferenceContainer @value + payload kind).
_LAYOUT_MODES = {"original": "1", "name_by_calc": "3", "number_by_calc": "4", "layout": "5"}
# Loop flush modes (AST "flush" → <List name value>). Bounded; unknown refuses.
_LOOP_FLUSH = {"Always": "1", "Defer": "3", "Minimum": "2"}


# ── result / refusal types ─────────────────────────────────────────────────────────
class CompileRefusal(Exception):
    """A whole-script withhold. `code` is a stable machine reason; `detail` names the exact offending
    step/reference. Raised anywhere in validate/resolve/lower; the compiler converts it to a refusal
    result. Never carries private content beyond schema identifiers the user already sees (names)."""

    def __init__(self, code: str, detail: str, *, index: "int | None" = None):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.index = index


@dataclass
class CompileResult:
    ok: bool
    result_state: str                       # ratified vocabulary (generated_* / refused_known_hazard)
    script_name: str
    clip: str = ""                          # '' on refusal
    ddr_blob: str = ""                      # the lowered StepsForScripts blob (empty on refusal)
    step_count: int = 0
    # four SEPARATE metadata buckets (packet 1131 ②/Stage-2 contract)
    resolved_references: list = _dc_field(default_factory=list)   # COMPLETE — not a manual-edit list
    experimental_steps: list = _dc_field(default_factory=list)
    source_incomplete_steps: list = _dc_field(default_factory=list)
    manual_actions: list = _dc_field(default_factory=list)        # only GENUINE remaining FileMaker work
    # refusal
    refusal_code: str = ""
    refusal_detail: str = ""
    refusal_index: "int | None" = None

    def to_dict(self) -> dict:
        d = {"ok": self.ok, "result_state": self.result_state, "script_name": self.script_name,
             "step_count": self.step_count,
             "metadata": {"resolved_references": self.resolved_references,
                          "experimental_steps": self.experimental_steps,
                          "source_incomplete_steps": self.source_incomplete_steps,
                          "manual_actions": self.manual_actions}}
        if self.ok:
            d["clip"] = self.clip
        else:
            d["refusal"] = {"code": self.refusal_code, "detail": self.refusal_detail,
                            "index": self.refusal_index}
        return d


# ── reference resolver (MVP scope only: fields/TOs, layouts, current-file scripts) ──
class _Resolver:
    """Resolve NAMES against a loaded target artifact, reusing its parsed catalogs. Enforces the ② STRICT
    rule fail-loud: a name that resolves to 0 items is unresolved → withhold; >1 is ambiguous → withhold.
    No substitution, no omission — every failure raises CompileRefusal naming the reference."""

    def __init__(self, art):
        self.art = art
        self._resolved: list = []            # accumulates the resolved_references metadata bucket

    def _scan(self, section: str, name: str):
        matches = [it for it in self.art.items.values()
                   if it.section == section and not getattr(it, "is_folder", False)
                   and (it.name or "").casefold() == name.casefold()]
        return matches

    def _one(self, section: str, name: str, kind: str, index: int):
        matches = self._scan(section, name)
        if not matches:
            raise CompileRefusal(f"unresolved_{kind}",
                                 f"{kind} {name!r} does not resolve to any {section} entry in the target "
                                 f"artifact", index=index)
        if len(matches) > 1:
            raise CompileRefusal(f"ambiguous_{kind}",
                                 f"{kind} {name!r} is ambiguous — it matches {len(matches)} {section} "
                                 f"entries; withholding rather than guessing", index=index)
        return matches[0]

    def layout(self, name: str, index: int) -> "tuple[str, str]":
        it = self._one("LayoutCatalog", name, "layout", index)
        lid, lname = it.attributes.get("id", ""), it.name
        self._resolved.append({"kind": "layout", "requested": name, "resolved_id": lid, "resolved_name": lname})
        return lid, lname

    def script(self, name: str, index: int) -> "tuple[str, str]":
        it = self._one("ScriptCatalog", name, "script", index)
        sid, sname = it.attributes.get("id", ""), it.name
        self._resolved.append({"kind": "script", "requested": name, "resolved_id": sid, "resolved_name": sname})
        return sid, sname

    def field(self, spec: str, index: int) -> "tuple[str, str, str, str]":
        """`TO::Field` → (field id, field name, TO id, TO name). The left side is a TABLE OCCURRENCE; the
        field is looked up under the TO's BASE TABLE (a TO may be aliased, so its name ≠ the base name)."""
        if "::" not in spec:
            raise CompileRefusal("bad_field_reference",
                                 f"field reference {spec!r} must be 'TableOccurrence::Field'", index=index)
        to_name, field_name = spec.split("::", 1)
        to_name, field_name = to_name.strip(), field_name.strip()
        to_it = self._one("TableOccurrenceCatalog", to_name, "table_occurrence", index)
        base = self._base_table(to_it, index)
        fld = self._one("FieldsForTables", f"{base}::{field_name}", "field", index)
        fid, toid = fld.attributes.get("id", ""), to_it.attributes.get("id", "")
        self._resolved.append({"kind": "field", "requested": spec, "resolved_field_id": fid,
                               "resolved_field_name": field_name, "table_occurrence": to_it.name,
                               "base_table": base})
        return fid, field_name, toid, to_it.name

    def _base_table(self, to_item, index: int) -> str:
        src = next((s for s in (to_item.xml_sources or []) if s.catalog == "TableOccurrenceCatalog"), None)
        xml = src.xml if src is not None else (to_item.xml_sources[0].xml if to_item.xml_sources else None)
        if xml:
            try:
                root = ET.fromstring(xml.decode("utf-8", "replace") if isinstance(xml, bytes) else xml)
                bsr = root.find(".//BaseTableSourceReference")
                if bsr is not None:
                    ref = bsr.find("BaseTableReference")
                    if ref is not None and ref.get("name"):
                        return ref.get("name")
            except Exception:
                pass
        raise CompileRefusal("unresolved_table_occurrence",
                             f"table occurrence {to_item.name!r} has no resolvable base table (external or "
                             f"malformed) — withholding", index=index)


# ── lowering: AST node → DDR <Step> Element ─────────────────────────────────────────
def _step_el(sid: str) -> "ET.Element":
    return ET.Element("Step", {"id": sid, "name": _DDR_NAME[sid], "enable": "True"})


def _param_values(step: "ET.Element", *params) -> None:
    pv = ET.SubElement(step, "ParameterValues", {"membercount": str(len(params))})
    for p in params:
        pv.append(p)


def _calc_block(parent: "ET.Element", text: str, *, datatype: str = "1", position: str = "0") -> None:
    """Append the canonical DDR calc subtree (Form C: outer<Calculation>→inner<Calculation>→<Text>) — the
    exact grammar the emitter's `_inner_text`/`_calc_subtree_reason` read."""
    outer = ET.SubElement(parent, "Calculation", {"datatype": datatype, "position": position})
    inner = ET.SubElement(outer, "Calculation")
    ET.SubElement(inner, "Text").text = text


def _calc_param(ptype: str, text: str) -> "ET.Element":
    p = ET.Element("Parameter", {"type": ptype})
    _calc_block(p, text)
    return p


def _collapsed_boolean_param() -> "ET.Element":
    p = ET.Element("Parameter", {"type": "Boolean"})
    ET.SubElement(p, "Boolean", {"type": "Collapsed", "id": "33554432", "value": "False"})
    return p


def _require(node: dict, key: str, name: str, index: int):
    if key not in node or node[key] is None:
        raise CompileRefusal("missing_field", f"{name}: required '{key}' is missing", index=index)
    return node[key]


def _lower(node: dict, friendly: str, R: _Resolver, index: int) -> "ET.Element":
    sid = MVP_STEP_IDS[friendly]
    st = _step_el(sid)

    if friendly in ("If", "Else If"):
        # Real FileMaker always emits the Collapsed block-marker on If/Else If (confirmed against the
        # committed pairs AND a live FM 26.0.1 paste→re-export, packet 1131 Stage 3) — emit it so the
        # lowered DDR matches what a real SaveAsXML carries. (Exit Loop If, below, gets NO Collapsed.)
        _param_values(st, _collapsed_boolean_param(),
                      _calc_param("Calculation", str(_require(node, "calc", friendly, index))))
    elif friendly == "Else":
        # The committed pair carries EXACTLY two Collapsed Boolean block-markers (not a bare marker).
        _param_values(st, _collapsed_boolean_param(), _collapsed_boolean_param())
    elif friendly in ("End If", "End Loop"):
        pass  # bare marker (_emit_bare — DisableStepCollapsed only)
    elif friendly == "Loop":
        flush = node.get("flush", "Always")
        if flush not in _LOOP_FLUSH:
            raise CompileRefusal("loop_flush_unmapped",
                                 f"Loop flush mode {flush!r} not in {sorted(_LOOP_FLUSH)}", index=index)
        p = ET.Element("Parameter", {"type": "List"})
        ET.SubElement(p, "List", {"name": flush, "value": _LOOP_FLUSH[flush]})
        _param_values(st, _collapsed_boolean_param(), p)   # one Collapsed Boolean + the flush List
    elif friendly == "Exit Loop If":
        _param_values(st, _calc_param("Calculation", str(_require(node, "calc", friendly, index))))
    elif friendly == "Exit Script":
        if node.get("calc") is not None and str(node.get("calc")) != "":
            _param_values(st, _calc_param("Calculation", str(node["calc"])))
    elif friendly == "Comment":
        text = str(node.get("text", ""))
        p = ET.Element("Parameter", {"type": "Comment"})
        if text != "":
            ET.SubElement(p, "Comment", {"value": text})
        else:
            ET.SubElement(p, "Comment")
        _param_values(st, p)
    elif friendly == "Set Variable":
        _lower_set_variable(st, node, index)
    elif friendly == "Set Field":
        _lower_set_field(st, node, R, index)
    elif friendly == "Perform Script":
        _lower_perform_script(st, node, R, index)
    elif friendly == "Go to Layout":
        _lower_goto_layout(st, node, R, index)
    elif friendly == "Show Custom Dialog":
        _lower_show_dialog(st, node, R, index)
    else:  # unreachable — vocabulary is gated before lowering
        raise CompileRefusal("unsupported_step", f"{friendly} has no lowering", index=index)
    return st


def _lower_set_variable(st, node, index):
    name = str(_require(node, "name", "Set Variable", index))
    var = ET.Element("Parameter", {"type": "Variable"})
    val = ET.SubElement(var, "value")
    value_calc = node.get("value")
    if value_calc is not None and str(value_calc) != "":
        _calc_block(val, str(value_calc))          # populated → <value><Calculation>…
    # else: bare <value/> (packet 1129 — an empty value omits <Value> in the clip)
    ET.SubElement(var, "Name", {"value": name})
    rep = ET.SubElement(var, "repetition")
    _calc_block(rep, str(node.get("repetition", "1")))
    _param_values(st, var)


def _lower_set_field(st, node, R, index):
    fid, fname, toid, toname = R.field(str(_require(node, "field", "Set Field", index)), index)
    fref = ET.Element("Parameter", {"type": "FieldReference"})
    fr = ET.SubElement(fref, "FieldReference", {"id": fid, "name": fname})
    # A real FileMaker FieldReference always carries a repetition (default 1) — emit it so the lowered DDR
    # matches a real SaveAsXML (confirmed against the committed pair AND a live FM 26.0.1 re-export, Stage 3).
    rep_el = ET.SubElement(fr, "repetition")
    _calc_block(rep_el, str(node.get("repetition") or "1"))
    ET.SubElement(fr, "TableOccurrenceReference", {"id": toid, "name": toname})
    value = _calc_param("Calculation", str(node.get("value", "")))
    _param_values(st, fref, value)


def _lower_perform_script(st, node, R, index):
    sid, sname = R.script(str(_require(node, "script", "Perform Script", index)), index)
    lst = ET.Element("Parameter", {"type": "List"})
    lel = ET.SubElement(lst, "List", {"name": "From list", "value": "1"})
    ET.SubElement(lel, "ScriptReference", {"id": sid, "name": sname})
    par = ET.Element("Parameter", {"type": "Parameter"})
    inner = ET.SubElement(par, "Parameter")
    param = node.get("parameter")
    if param is not None and str(param) != "":
        _calc_block(inner, str(param))
    _param_values(st, lst, par)


def _lower_goto_layout(st, node, R, index):
    dest = node.get("destination")
    if not isinstance(dest, dict) or "mode" not in dest:
        raise CompileRefusal("missing_field",
                             "Go to Layout: 'destination' with a 'mode' is required", index=index)
    mode = dest["mode"]
    if mode not in _LAYOUT_MODES:
        raise CompileRefusal("layout_mode_unmapped",
                             f"Go to Layout destination mode {mode!r} not in {sorted(_LAYOUT_MODES)}",
                             index=index)
    lrc_param = ET.Element("Parameter", {"type": "LayoutReferenceContainer"})
    lrc = ET.SubElement(lrc_param, "LayoutReferenceContainer", {"value": _LAYOUT_MODES[mode]})
    if mode == "original":
        ET.SubElement(lrc, "Label").text = "original layout"
    elif mode in ("name_by_calc", "number_by_calc"):
        _calc_block(lrc, str(_require(dest, "calc", "Go to Layout", index)), position="5")
    elif mode == "layout":
        lid, lname = R.layout(str(_require(dest, "layout", "Go to Layout", index)), index)
        ET.SubElement(lrc, "LayoutReference", {"id": lid, "name": lname})
    anim_param = ET.Element("Parameter", {"type": "Animation"})
    anim = node.get("animation", "None") or "None"
    ET.SubElement(anim_param, "Animation", {"name": str(anim), "value": "0"})
    _param_values(st, lrc_param, anim_param)


def _lower_show_dialog(st, node, R, index):
    params = []
    title = node.get("title")
    if title is not None and str(title) != "":
        params.append(_calc_param("Title", str(title)))
    params.append(_calc_param("Message", str(_require(node, "message", "Show Custom Dialog", index))))
    buttons = node.get("buttons") or [{"label": "OK", "commit": True}]
    if not isinstance(buttons, list) or not (1 <= len(buttons) <= 3):
        raise CompileRefusal("dialog_buttons_invalid",
                             "Show Custom Dialog: 'buttons' must be a list of 1–3 buttons", index=index)
    for i in range(3):
        b = buttons[i] if i < len(buttons) else None
        attrs = {"type": f"Button{i + 1}"}
        if b and b.get("label") not in (None, ""):
            attrs["value"] = str(b["label"])
        bp = ET.Element("Parameter", attrs)
        commit = "True" if (b and b.get("commit")) else "False"
        ET.SubElement(bp, "Boolean", {"type": "Commit", "value": commit})
        params.append(bp)
    for i, slot in enumerate(node.get("inputs") or []):
        params.append(_dialog_input_slot(slot, i + 1, R, index))
    _param_values(st, *params)


def _dialog_input_slot(slot, n: int, R: _Resolver, index: int) -> "ET.Element":
    fp = ET.Element("Parameter", {"type": f"Field{n}"})
    target = ET.SubElement(fp, "Parameter", {"type": "Target"})
    if slot.get("variable"):
        var = ET.SubElement(target, "Variable", {"value": str(slot["variable"])})
        rep = ET.SubElement(var, "repetition")
        _calc_block(rep, str(slot.get("repetition", "1")))
    elif slot.get("field"):
        fid, fname, toid, toname = R.field(str(slot["field"]), index)
        fr = ET.SubElement(target, "FieldReference", {"id": fid, "name": fname})
        ET.SubElement(fr, "TableOccurrenceReference", {"id": toid, "name": toname})
    else:
        raise CompileRefusal("dialog_input_target_missing",
                             f"Show Custom Dialog input slot {n} needs a 'variable' or 'field' target",
                             index=index)
    if slot.get("password"):
        ET.SubElement(fp, "Boolean", {"type": "Password", "value": "True"})
    if slot.get("label") not in (None, ""):
        lp = ET.SubElement(fp, "Parameter", {"type": "Label"})
        _calc_block(lp, str(slot["label"]))
    return fp


# ── AST validation (vocabulary + flat block balance) ───────────────────────────────
def _canonical_step(node: dict, index: int) -> str:
    if not isinstance(node, dict):
        raise CompileRefusal("bad_ast_node", f"step {index} is not an object", index=index)
    raw = node.get("step")
    if raw is None:
        raise CompileRefusal("missing_step_kind", f"step {index} has no 'step'", index=index)
    friendly = _ALIASES.get(str(raw))
    if friendly is None:
        raise CompileRefusal("unsupported_step",
                             f"step {index}: {raw!r} is not in the MVP vocabulary "
                             f"{sorted(MVP_STEP_IDS)}", index=index)
    return friendly


def _validate_blocks(friendlies: "list[str]") -> None:
    stack: list = []
    for i, f in enumerate(friendlies):
        if f in _OPENERS:
            stack.append((f, i))
        elif f in _CLOSER_OF:
            need = _CLOSER_OF[f]
            if not stack or stack[-1][0] != need:
                raise CompileRefusal("unbalanced_blocks",
                                     f"step {i} {f!r} has no open {need!r}", index=i)
            stack.pop()
        elif f in _CONTINUER_BLOCK:
            need = _CONTINUER_BLOCK[f]
            if not stack or stack[-1][0] != need:
                raise CompileRefusal("unbalanced_blocks",
                                     f"step {i} {f!r} must sit inside an open {need!r}", index=i)
        elif f in _INSIDE_LOOP:
            if not any(s[0] == "Loop" for s in stack):
                raise CompileRefusal("unbalanced_blocks",
                                     f"step {i} {f!r} must sit inside an open Loop", index=i)
    if stack:
        f, i = stack[-1]
        raise CompileRefusal("unbalanced_blocks", f"step {i} {f!r} is never closed", index=i)


# ── public API ─────────────────────────────────────────────────────────────────────
def compile_script(art, ast, *, script_name: str, script_id: str = "", flavor: str = "xmsc",
                   strict: bool = False, context=None) -> CompileResult:
    """Compile a flat, name-based AST into an fmClip against a selected target artifact.

    `art` is a loaded Artifact (its parsed catalogs are the resolution authority). `ast` is a flat ordered
    list of step objects (or a `{"steps": [...]}` wrapper). Returns a CompileResult; on any unsupported
    step, unbalanced block, or unresolved/ambiguous reference the whole script is withheld (② taxonomy),
    never a partial clip. Mutates nothing — persistence is the MCP tool's concern (Stage 2)."""
    steps = ast.get("steps") if isinstance(ast, dict) else ast
    if not isinstance(steps, list) or not steps:
        return CompileResult(ok=False, result_state="refused_known_hazard", script_name=script_name,
                             refusal_code="empty_ast", refusal_detail="the AST has no steps")
    try:
        friendlies = [_canonical_step(n, i) for i, n in enumerate(steps)]
        _validate_blocks(friendlies)
        R = _Resolver(art)
        lowered = [_lower(n, f, R, i) for i, (n, f) in enumerate(zip(steps, friendlies))]
    except CompileRefusal as r:
        return CompileResult(ok=False, result_state="refused_known_hazard", script_name=script_name,
                             refusal_code=r.code, refusal_detail=r.detail, refusal_index=r.index)

    blob = _assemble_blob(lowered, script_name, script_id)
    clip, unsupported = ce.emit_script_clip(blob, script_name=script_name, script_id=script_id,
                                            flavor=flavor, strict=strict, context=context)
    if unsupported:
        # The MVP vocabulary is verified, but the emitter is the single authority — an option shape it
        # refuses (or strict=True on an experimental shape) withholds the whole script, honestly.
        u = unsupported[0]
        return CompileResult(ok=False, result_state="refused_known_hazard", script_name=script_name,
                             refusal_code="emitter_refused_shape",
                             refusal_detail=f"step index {u['index']} (id {u['id']} {u.get('name')}): "
                                            f"{u.get('reason')}",
                             refusal_index=u["index"], resolved_references=R._resolved)

    assessed = ce.scan_step_assessments(blob, strict=strict, context=context, flavor=flavor)
    si = [] if strict else ce.scan_source_incomplete(blob)
    experimental = [{"index": a["index"], "id": a["id"], "name": a["name"]}
                    for a in assessed if a["evidence"] == "experimental" and not a["blocked"]]
    source_incomplete = [{"index": s["index"], "id": s["id"], "name": s["name"],
                          "source_absent_for_target": s.get("source_absent_for_target", []),
                          "source_held_unimplemented": s.get("source_held_unimplemented", [])} for s in si]
    if source_incomplete:
        state = "generated_static_valid"
    elif experimental:
        state = "generated_experimental"
    else:
        state = "generated_verified"
    return CompileResult(ok=True, result_state=state, script_name=script_name, clip=clip, ddr_blob=blob,
                         step_count=len(lowered), resolved_references=R._resolved,
                         experimental_steps=experimental, source_incomplete_steps=source_incomplete,
                         manual_actions=[])


def _assemble_blob(lowered: "list[ET.Element]", script_name: str, script_id: str) -> str:
    """Wrap the lowered steps in a StepsForScripts-style <Script> — the exact form emit_script_clip and
    acceptance.step_shapes consume (both just iterate .//Step)."""
    root = ET.Element("Script", {"name": script_name, "id": str(script_id or "")})
    for s in lowered:
        root.append(s)
    return ET.tostring(root, encoding="unicode")


def ast_json_schema() -> dict:
    """The JSON schema the authoring agent targets — a flat ordered step list. Kept intentionally permissive
    on per-step fields (the compiler validates each shape fail-loud and the emitter is the final grammar
    authority); the schema pins the vocabulary + the flat-list contract."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "CORPUSfm fmClip compiler AST (MVP)",
        "type": "object",
        "required": ["steps"],
        "properties": {
            "steps": {
                "type": "array", "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["step"],
                    "properties": {
                        "step": {"enum": sorted(MVP_STEP_IDS)},
                        "calc": {"type": "string"},
                        "text": {"type": "string"},
                        "name": {"type": "string"},
                        "value": {"type": "string"},
                        "repetition": {"type": "string"},
                        "field": {"type": "string", "description": "TableOccurrence::Field"},
                        "script": {"type": "string", "description": "current-file script name"},
                        "parameter": {"type": "string"},
                        "flush": {"enum": sorted(_LOOP_FLUSH)},
                        "destination": {
                            "type": "object",
                            "properties": {
                                "mode": {"enum": sorted(_LAYOUT_MODES)},
                                "calc": {"type": "string"},
                                "layout": {"type": "string"},
                            },
                        },
                        "animation": {"type": "string"},
                        "title": {"type": "string"},
                        "message": {"type": "string"},
                        "buttons": {"type": "array", "items": {"type": "object"}},
                        "inputs": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
    }
