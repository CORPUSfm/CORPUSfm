"""Render-layer diagnostics — the signals the gap analyzer can't see.

The gap analyzer catches INGEST-structure problems (unknown step IDs, unmapped
catalogs). This module catches RENDER problems: an addon reference that didn't
resolve, a known step that rendered empty because its xpath missed, and errors
that were caught-and-degraded rather than surfaced. The results feed the
Explorer About panel (and the CompletenessProfile) so a bad render is VISIBLE
instead of looking fine.

Deterministic from the artifact's own data (rendered_text + step XML), so the
pipeline bakes it at ingest AND the Explorer can recompute it fresh for an
artifact stored before this existed.
"""
from __future__ import annotations

import re as _re
from corpusfm.core import safe_xml as ET

# An addon reference that survived name resolution: com.fmi.<segments>.<32hex>.
# Its presence in RENDERED (post-resolution) text means a name was never found.
_UNRESOLVED_RE = _re.compile(r"com\.fmi\.[A-Za-z.]+\.[0-9A-Fa-f]{32}")

_CAP = 200  # max entries kept per list; the rest are summarised, never silently dropped


def _cap(items: list) -> list:
    if len(items) <= _CAP:
        return items
    return items[:_CAP] + [f"… +{len(items) - _CAP} more"]


def scan_unresolved_in_render(items, is_addon: bool) -> list:
    """Items whose rendered_text still carries an unresolved addon UUID reference.

    Only meaningful for addons (SaveAsXML has no UUID references). Each entry is
    'ItemName — ref1, ref2 …' so the About panel can point at the exact object.
    """
    if not is_addon:
        return []
    out: list = []
    for it in items:
        if getattr(it, "is_folder", False):
            continue
        refs = _UNRESOLVED_RE.findall(it.rendered_text or "")
        if refs:
            uniq = list(dict.fromkeys(refs))
            shown = ", ".join(uniq[:3]) + (" …" if len(uniq) > 3 else "")
            out.append(f"{it.name} — {shown}")
    return _cap(out)


def _step_has_real_content(step: ET.Element) -> bool:
    """True if the step carries param INPUT the renderer should have surfaced:
    a non-empty <Calculation>/<Text> or a *Reference with a name. (Animation /
    empty markers don't count — a blank render of those is legitimate.)"""
    pv = step.find("ParameterValues")
    if pv is None:
        return False
    for t in pv.iter("Text"):
        if (t.text or "").strip():
            return True
    for el in pv.iter():
        if el.tag.endswith("Reference") and (el.get("name") or "").strip():
            return True
    return False


def scan_empty_renders(items, schema_version: str) -> list:
    """Script steps that HAVE parameter content in the XML but rendered all-empty.

    The signal a renderer xpath missed a target — e.g. a 'Go to Layout' specified
    by calculation rendering 'Go to Layout [ "" ]'. Each entry is
    'ScriptName — step N (StepName)'. Conservative: only fires when the catalog
    expects params, the step XML has real input, and EVERY extracted value is empty.
    """
    from corpusfm.core.rendering.catalog import load_catalog
    from corpusfm.core.rendering.step_renderer import _extract_params
    try:
        catalog, _ = load_catalog(schema_version)
    except Exception:
        return []
    out: list = []
    for it in items:
        if it.section != "ScriptCatalog" or getattr(it, "is_folder", False):
            continue
        steps_xml = next((s.xml for s in it.xml_sources if s.catalog == "StepsForScripts"), "")
        if not steps_xml:
            continue
        try:
            root = ET.fromstring(steps_xml)
        except ET.ParseError:
            continue
        for idx, step in enumerate(root.iter("Step"), start=1):
            try:
                sid = int(step.get("id", "-1"))
            except ValueError:
                continue
            entry = catalog.get(sid)
            if not entry or not entry.get("params"):
                continue
            if not _step_has_real_content(step):
                continue
            vals = _extract_params(step, entry["params"], single_line=False)
            if vals and all(not (v or "").strip() for v in vals.values()):
                out.append(f"{it.name} — step {idx} ({step.get('name', '?')})")
    return _cap(out)


def scan(items, is_addon: bool, schema_version: str) -> dict:
    """Deterministic render diagnostics computed from the artifact's own data.

    Returns {"unresolved_in_render": [...], "empty_renders": [...]}. Render ERRORS
    (caught exceptions) are capture-time, not derivable here — the pipeline collects
    those separately and stores them on the profile.
    """
    items = list(items)
    return {
        "unresolved_in_render": scan_unresolved_in_render(items, is_addon),
        "empty_renders": scan_empty_renders(items, schema_version),
    }
