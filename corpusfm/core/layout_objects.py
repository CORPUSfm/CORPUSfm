"""Structured layout-object inventory — what's ON a layout, distilled from the XML.

The wireframe (Explorer) reads layout objects for *geometry*; this reads them for
*meaning*: each object's type, what it's bound to (field / script / portal TO), its
human label, and its display formatting. One shared distillation, consumed by both the
Explorer (the human's "what the user sees") and build_schema_context (the AI's view) —
per the completeness north star (surface everything relevant, both consumers).

Document order is z-order: a later object draws in front of an earlier one (the basis
for "that button is in front of the text"). Bounds give position + overlap.

Note on source fidelity: SaveAsXML is the abridged *analysis* export (it drops e.g.
resize/anchoring); the AddonXML/Merged artifact is the faithful *reconstruction* source.
This reads whatever the artifact carries — richest from a merged/addon artifact.

Public API:
    extract_layout_objects(layout_xml: str) -> list[LayoutObjectInfo]
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field as _dcfield  # `field` is also an attr name below
from typing import Optional

# Container objects nest other LayoutObjects; their own binding lookup would wrongly
# pick up a child's ref, so we record them as containers (type + name + the portal TO)
# and let their children appear as their own entries.
_CONTAINER_TYPES = {"Portal", "TabControl", "SlideControl", "PanelControl", "Popover"}


@dataclass
class LayoutObjectInfo:
    type: str                       # Field | Button | Text | Portal | TabControl | ...
    name: str = ""
    z: int = 0                      # document order = stacking order (higher = in front)
    bounds: Optional[tuple] = None  # (top, left, bottom, right)
    field: str = ""                 # bound field (FieldReference) for data objects
    field_to: str = ""              # the field's table-occurrence (FieldReference/TableOccurrenceReference)
                                    # — qualifies the bare field name to TO::field so it resolves + links
    script: str = ""                # script run (ScriptReference) for buttons/triggers
    to: str = ""                    # portal/object table-occurrence context
    label: str = ""                 # button label / displayed text (human-readable)
    fmt: str = ""                   # display formatting kind (e.g. NumFormat/DateFormat)
    # Behavior — what makes an object conditional / dynamic, not just where it sits:
    hide: str = ""                  # "Hide object when" condition formula
    placeholder: str = ""           # placeholder-text formula (empty-field prompt)
    tooltip: str = ""               # tooltip formula
    cond_format: int = 0            # number of conditional-formatting rules
    cond_format_calcs: list = _dcfield(default_factory=list)  # each rule's condition formula
    # Per-object FM layout-options bitmask (the <Options> int). FileMaker exports NO
    # named anchoring field — not in SaveAsXML, and not even in the faithful .fmaddon
    # (verified on PTLaunchPad, 3016 objects: no anchor/autoResize attr or element).
    # Autosize anchoring + other per-object flags are packed into this opaque integer.
    # The anchor bits live in the HIGH nibble (28-31) — decoded via decode_anchors().
    # The raw value is kept so non-anchor option CHANGES stay visible and diffable.
    options: int = 0

    @property
    def anchors(self) -> list:
        """Autosize anchor sides decoded from `options` (top/bottom/left/right order).
        Empty list = FM's implicit default (behaves top-left)."""
        return decode_anchors(self.options)

    def to_dict(self) -> dict:
        return {k: v for k, v in {
            "type": self.type, "name": self.name, "z": self.z,
            "bounds": list(self.bounds) if self.bounds else None,
            "field": self.field, "field_to": self.field_to, "script": self.script, "to": self.to,
            "label": self.label, "fmt": self.fmt,
            "hide": self.hide, "placeholder": self.placeholder,
            "tooltip": self.tooltip, "cond_format": self.cond_format,
            "cond_format_calcs": self.cond_format_calcs,
            "options": self.options,
            "anchors": self.anchors,
        }.items() if v not in ("", None, 0, []) or k == "type"}


# Autosize anchoring is packed into the HIGH nibble (bits 28-31) of the per-object
# <Options> integer. Mapping VERIFIED against FM-Pro ground truth (FM 2026 / schema
# 2.3.0.0): a layout of objects, each with a known Inspector anchor combination, was
# exported and correlated to its Options value, then cross-checked against window-resize
# behavior (the Top+Bottom object is the one that stretched vertically). The four single
# bits and three "Top + one other" pairs all decoded consistently.
_ANCHOR_BITS = (
    (0x10000000, "left"),    # bit 28
    (0x20000000, "top"),     # bit 29
    (0x40000000, "right"),   # bit 30
    (0x80000000, "bottom"),  # bit 31
)
_ANCHOR_ORDER = ("top", "bottom", "left", "right")


def decode_anchors(options: int) -> list:
    """Autosize anchor sides set in a layout object's <Options> bitmask.

    Returns the anchored side names in top/bottom/left/right reading order. An empty
    list means no anchor bits are set — FM's implicit default, which behaves as
    top-left (note: an *explicit* Top+Left is stored as both bits set, not as 0)."""
    try:
        opts = int(options)
    except (TypeError, ValueError):
        return []
    on = {name for mask, name in _ANCHOR_BITS if opts & mask}
    return [s for s in _ANCHOR_ORDER if s in on]


def _bounds(obj) -> Optional[tuple]:
    b = obj.find("Bounds")
    if b is None:
        return None
    try:
        return tuple(int(float(b.get(k, "0"))) for k in ("top", "left", "bottom", "right"))
    except (ValueError, TypeError):
        return None


def _clean_label(s: str) -> str:
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':   # a literal string label "Save" → Save
        s = s[1:-1]
    return s


def _find_own(obj, tag):
    """First <tag> belonging to `obj` itself — descends but prunes nested LayoutObjects
    so a container doesn't pick up a child object's hide/tooltip/etc."""
    for child in obj:
        if child.tag == "LayoutObject":
            continue
        if child.tag == tag:
            return child
        found = _find_own(child, tag)
        if found is not None:
            return found
    return None


def _own_calc(obj, tag) -> str:
    """The <tag>/Calculation/<Text> formula belonging to obj (hide/placeholder/tooltip)."""
    el = _find_own(obj, tag)
    if el is None:
        return ""
    t = el.find(".//Text")
    return (t.text or "").strip() if t is not None and t.text else ""


def extract_layout_objects(layout_xml: str) -> list:
    """Every object placed on a layout, with type / binding / label / formatting.

    z (document order) is the stacking order. Container objects (portals, tab panels)
    are recorded as containers; their children appear as their own entries."""
    if not layout_xml:
        return []
    try:
        root = ET.fromstring(layout_xml)
    except ET.ParseError:
        return []

    out: list = []
    for z, obj in enumerate(root.iter("LayoutObject")):
        info = LayoutObjectInfo(
            type=obj.get("type", "Unknown"), name=obj.get("name", ""),
            z=z, bounds=_bounds(obj),
        )
        # Behavior (its own, not a nested child's): what makes it conditional/dynamic.
        info.hide = _own_calc(obj, "Hide")
        info.placeholder = _own_calc(obj, "Placeholder")
        info.tooltip = _own_calc(obj, "Tooltip")
        conds = _find_own(obj, "Conditions")
        if conds is not None:
            for c in conds.iter("Condition"):
                info.cond_format += 1
                ct = c.find(".//Calculation//Text")
                if ct is None:
                    ct = c.find(".//Text")
                txt = (ct.text or "").strip() if ct is not None and ct.text else ""
                if txt:
                    info.cond_format_calcs.append(txt)
        # The object's OWN <Options> bitmask (direct child only — Button/Formatting
        # carry their own nested <Options> which must not be picked up here).
        opt_el = obj.find("Options")
        if opt_el is not None and (opt_el.text or "").strip().lstrip("-").isdigit():
            info.options = int(opt_el.text.strip())

        if info.type in _CONTAINER_TYPES:
            tor = obj.find(".//TableOccurrenceReference")
            if tor is not None:
                info.to = tor.get("name", "")
            out.append(info)
            continue

        fr = obj.find(".//FieldReference")
        if fr is not None:
            info.field = fr.get("name", "")
            tref = fr.find("TableOccurrenceReference")   # the field's TO context → TO::field (linkable)
            if tref is not None:
                info.field_to = tref.get("name", "")
        sr = obj.find(".//ScriptReference")
        if sr is not None:
            info.script = sr.get("name", "")
        lbl = obj.findtext(".//Label//Text") or obj.findtext(".//Text/Data")
        if lbl:
            info.label = _clean_label(lbl)
        fmt_el = obj.find(".//Formatting")
        if fmt_el is not None and len(fmt_el):
            info.fmt = list(fmt_el)[0].tag
        out.append(info)
    return out
