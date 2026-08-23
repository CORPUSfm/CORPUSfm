"""Deterministic structured edits on a FileMaker clipboard clip — packet 1024 §12 (patch_clip).

The field session that prompted this packet was, end to end, a *patch* operation: take an existing
clipboard clip (script steps the developer exported from FileMaker), apply a small structured edit,
hand it back paste-ready. That needs NO DDR→clipboard transpiler — the input is already the clipboard
dialect — so it is the tractable, high-value, low-risk half of the authoring loop, and the one the
real workflow actually used.

Ops (each resolved fresh against current order):
  set_enabled(selector, enabled)   — toggle a step's enable flag
  delete(selector)                 — remove the selected step(s)
  replace_calc(selector, calc)     — replace a step's primary <Calculation> text (whole calc)
  replace_calc_text(selector, find, replace, expected_matches=1)
                                   — replace an EXACT text fragment INSIDE the selected calc(s);
                                     fail-closed if the fragment count ≠ expected_matches (a positive
                                     int, or "all"). Surgical: leaves the rest of the calc untouched.
  insert(steps_xml, at)            — splice clip-dialect <Step>… before/after an anchor (or at end)
  move(selector, dest)             — move a contiguous run to before/after an anchor

Any op may carry expected_matches (a positive int, or "all") to assert its SELECTOR match count
before mutating — a fail-closed guard for newly authored calls; omit it for the legacy first-match
behavior. replace_calc_text's expected_matches asserts the FRAGMENT count and defaults to 1.

Selectors (a dict {by, value}):
  index  — 0-based position in the step list
  name   — step name (e.g. "Set Field"); first match unless all=True
  banner — a comment step whose text contains value (scripts here are banner-delimited — a stable,
           human-meaningful anchor)
  var    — a Set Variable whose Name equals value
  calc   — any step whose calc text contains value

Operates on the step list wherever it lives: a bare-step XMSS clip (steps under <fmxmlsnippet>) or a
single whole-script XMSC clip (steps under its <Script>). Multi-script / foldered clips are a v1
boundary — patch one script at a time. Pure functions over clip XML; never raises on a bad op, it
records the failure in the report and leaves that op un-applied.
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from corpusfm.ingestion.clip import _strip_xml_decl


class ClipPatchError(Exception):
    pass


def _step_container(root: ET.Element) -> ET.Element:
    """The element whose direct <Step> children are the editable step list."""
    if any(c.tag == "Step" for c in root):
        return root
    for el in root.iter():
        if el is not root and any(c.tag == "Step" for c in el):
            return el
    raise ClipPatchError("no <Step> list found in clip (not a script/steps clip)")


def _calc_text_of(step: ET.Element) -> str:
    c = step.find(".//Calculation")
    return "".join(c.itertext()) if c is not None else ""


def _var_name_of(step: ET.Element) -> str:
    n = step.find("Name")
    return (n.text or "").strip() if n is not None else ""


def _banner_text_of(step: ET.Element) -> str:
    if step.get("name") != "# (comment)":
        return ""
    t = step.find("Text")
    return (t.text or "") if t is not None else ""


def _resolve(steps: list, selector: dict) -> list:
    """Return the [indices] a selector matches (in order). Empty when nothing matches."""
    by = selector.get("by")
    val = selector.get("value")
    take_all = bool(selector.get("all"))
    hits = []
    for i, s in enumerate(steps):
        ok = False
        if by == "index":
            ok = (i == int(val))
        elif by == "name":
            ok = (s.get("name") == val)
        elif by == "banner":
            ok = (str(val) in _banner_text_of(s))
        elif by == "var":
            ok = (_var_name_of(s) == val)
        elif by == "calc":
            ok = (str(val) in _calc_text_of(s))
        else:
            raise ClipPatchError(f"unknown selector 'by': {by!r}")
        if ok:
            hits.append(i)
            if not take_all and by != "index":
                break
    return hits


def _one(steps: list, selector: dict) -> int:
    hits = _resolve(steps, selector)
    if not hits:
        raise ClipPatchError(f"selector matched nothing: {selector}")
    return hits[0]


def _check_expected(count: int, expected, what: str) -> None:
    """Fail-closed assertion, run BEFORE any mutation: raise unless `count` satisfies `expected`
    (a positive int, or the string "all" meaning ≥1). A wrong selector/fragment count therefore
    writes nothing."""
    if expected == "all":
        if count < 1:
            raise ClipPatchError(f"{what}: expected ≥1 match, found 0")
        return
    try:
        exp = int(expected)
    except (TypeError, ValueError):
        raise ClipPatchError(f"{what}: expected_matches must be a positive integer or 'all', "
                             f"got {expected!r}")
    if exp < 1:
        raise ClipPatchError(f"{what}: expected_matches must be ≥1, got {exp}")
    if count != exp:
        raise ClipPatchError(f"{what}: expected {exp} match(es), found {count}")


def _step_label(step: ET.Element) -> str:
    """A human anchor for a step in the review: its name, plus the Set Variable name when present."""
    nm = step.get("name") or "?"
    v = _var_name_of(step)
    return f"{nm} [{v}]" if v else nm


def _anchor_index(steps: list, at: dict) -> tuple:
    """(index, side) for an insert/move destination: {after|before: selector} or {end:true}."""
    if at.get("end"):
        return len(steps), "before"
    if "after" in at:
        return _one(steps, at["after"]), "after"
    if "before" in at:
        return _one(steps, at["before"]), "before"
    raise ClipPatchError(f"insert/move needs after/before/end: {at}")


def apply_clip_patch(clip_xml: str, ops: list) -> tuple:
    """Apply ops to a clip. Returns (new_clip_xml, report).

    report = {applied:[str…], failed:[str…], ops:[dict…]}. The `ops` list is the structured,
    per-operation review (index, selector, matched step indices+labels, before/after calc text when
    applicable, replacement count, status/error) — one entry per op, applied or failed."""
    text = clip_xml.decode("utf-8", "replace") if isinstance(clip_xml, bytes) else clip_xml
    root = ET.fromstring(_strip_xml_decl(text))
    container = _step_container(root)
    report = {"applied": [], "failed": [], "ops": []}

    def steps():
        return [c for c in container if c.tag == "Step"]

    def guarded(cur, op):
        """Resolve a selector and, when the op carries expected_matches, assert its match count
        fail-closed before the caller mutates."""
        hits = _resolve(cur, op["selector"])
        if "expected_matches" in op:
            _check_expected(len(hits), op["expected_matches"], f"selector {op['selector']}")
        return hits

    for n, op in enumerate(ops):
        kind = op.get("op")
        entry = {"n": n, "op": kind, "selector": op.get("selector"), "matched": [],
                 "labels": [], "before": None, "after": None, "replacements": None,
                 "status": "applied", "error": None}
        try:
            cur = steps()
            if kind == "set_enabled":
                targets = guarded(cur, op)
                if not targets:
                    raise ClipPatchError(f"selector matched nothing: {op['selector']}")
                for i in targets:
                    cur[i].set("enable", "True" if op.get("enabled", True) else "False")
                entry["matched"] = targets
                report["applied"].append(f"[{n}] set_enabled {op['selector']} → {op.get('enabled', True)}")
            elif kind == "delete":
                targets = guarded(cur, op)
                if not targets:
                    raise ClipPatchError(f"selector matched nothing: {op['selector']}")
                entry["matched"] = targets
                entry["labels"] = [_step_label(cur[i]) for i in targets]
                for i in sorted(targets, reverse=True):
                    container.remove(cur[i])
                report["applied"].append(f"[{n}] delete {op['selector']} ({len(targets)} step(s))")
            elif kind == "replace_calc":
                hits = guarded(cur, op)
                if not hits:
                    raise ClipPatchError(f"selector matched nothing: {op['selector']}")
                i = hits[0]
                c = cur[i].find(".//Calculation")
                if c is None:
                    raise ClipPatchError(f"step {i} ({cur[i].get('name')}) has no <Calculation> to replace")
                entry["before"] = "".join(c.itertext())
                for ch in list(c):
                    c.remove(ch)
                c.text = op["calc"]
                entry["after"] = op["calc"]
                entry["matched"] = [i]
                entry["labels"] = [_step_label(cur[i])]
                report["applied"].append(f"[{n}] replace_calc {op['selector']}")
            elif kind == "replace_calc_text":
                find, repl = op.get("find"), op.get("replace")
                if find is None or repl is None:
                    raise ClipPatchError("replace_calc_text needs both 'find' and 'replace'")
                if find == "":
                    raise ClipPatchError("replace_calc_text 'find' must be a non-empty fragment")
                targets = _resolve(cur, op["selector"])
                if not targets:
                    raise ClipPatchError(f"selector matched nothing: {op['selector']}")
                nodes, total = [], 0
                for i in targets:
                    c = cur[i].find(".//Calculation")
                    if c is None:
                        raise ClipPatchError(f"step {i} ({cur[i].get('name')}) has no <Calculation>")
                    txt = "".join(c.itertext())
                    nodes.append((i, c, txt))
                    total += txt.count(find)
                _check_expected(total, op.get("expected_matches", 1), f"fragment {find!r}")
                # fail-closed passed → mutate every occurrence in the selected calc(s)
                for i, c, txt in nodes:
                    if find in txt:
                        for ch in list(c):
                            c.remove(ch)
                        c.text = txt.replace(find, repl)
                i0, _c0, t0 = nodes[0]
                entry["matched"] = targets
                entry["labels"] = [_step_label(cur[i]) for i in targets]
                entry["before"], entry["after"] = t0, t0.replace(find, repl)
                entry["replacements"] = total
                report["applied"].append(
                    f"[{n}] replace_calc_text {op['selector']} ({total} replacement(s))")
            elif kind == "insert":
                new_steps = _parse_steps(op["steps_xml"])
                idx, side = _anchor_index(cur, op["at"])
                pos = _container_pos(container, cur, idx, side)
                for k, ns in enumerate(new_steps):
                    container.insert(pos + k, ns)
                report["applied"].append(f"[{n}] insert {len(new_steps)} step(s) at {op['at']}")
            elif kind == "move":
                targets = guarded(cur, op)
                if not targets:
                    raise ClipPatchError(f"selector matched nothing: {op['selector']}")
                entry["matched"] = targets
                moving = [cur[i] for i in targets]
                for m in moving:
                    container.remove(m)
                cur2 = steps()
                idx, side = _anchor_index(cur2, op["dest"])
                pos = _container_pos(container, cur2, idx, side)
                for k, m in enumerate(moving):
                    container.insert(pos + k, m)
                report["applied"].append(f"[{n}] move {op['selector']} → {op['dest']} ({len(moving)} step(s))")
            else:
                raise ClipPatchError(f"unknown op: {kind!r}")
        except Exception as exc:
            entry["status"] = "failed"
            entry["error"] = str(exc)
            report["failed"].append(f"[{n}] {kind}: {exc}")
        report["ops"].append(entry)

    out = ET.tostring(root, encoding="unicode")
    if not out.lstrip().startswith("<?xml"):
        out = '<?xml version="1.0" encoding="UTF-8"?>\n' + out
    return out, report


def _container_pos(container: ET.Element, cur: list, step_index: int, side: str) -> int:
    """Translate a step-list index+side into a child position within the container element (which may
    hold non-Step children like a leading comment/Group)."""
    children = list(container)
    if step_index >= len(cur):
        return len(children)
    anchor = cur[step_index]
    base = children.index(anchor)
    return base + 1 if side == "after" else base


def _parse_steps(steps_xml: str) -> list:
    """Parse clip-dialect <Step>… (optionally wrapped) into a list of Step elements."""
    frag = _strip_xml_decl(steps_xml.strip())
    if not frag.lstrip().startswith("<Step"):
        # tolerate a wrapping element (e.g. a snippet the caller pasted)
        holder = ET.fromstring(frag)
        return [c for c in holder.iter("Step")]
    holder = ET.fromstring(f"<_ins>{frag}</_ins>")
    return [c for c in holder if c.tag == "Step"]
