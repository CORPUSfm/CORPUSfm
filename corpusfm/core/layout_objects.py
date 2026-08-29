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

import re

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field as _dcfield  # `field` is also an attr name below
from typing import Optional

# Container objects nest other LayoutObjects; their own binding lookup would wrongly
# pick up a child's ref, so we record them as containers (type + name + the portal TO)
# and let their children appear as their own entries.
_CONTAINER_TYPES = {"Portal", "TabControl", "SlideControl", "PanelControl", "Popover"}

#: The element forms FileMaker uses for a placed object. All three are FULL definitions, not stubs
#: (packet 1338): `LayoutObjectReference` carries a `type`, a `hash` and its own `<Button><action>`;
#: `TableViewLayoutObject` is a Table View column and may carry no `<Bounds>` at all. Walking only
#: `LayoutObject` made both invisible to the Explorer wireframe AND to the AI schema context, which
#: share this one extraction — 62 references in one customer export, 434 table-view columns in another.
_OBJECT_TAGS = ("LayoutObject", "LayoutObjectReference", "TableViewLayoutObject")

#: A tag that LOOKS like a placed object but is not one we know. Reported, never dropped: a confidently
#: empty answer is the failure this packet exists to end (the analyzer-honesty rule, packet 072-D).
_OBJECT_FAMILY = re.compile(r"(?:^|[A-Za-z])LayoutObject(?:Reference)?$|^TableViewLayoutObject$")


def _looks_like_object_tag(tag: str) -> bool:
    return bool(_OBJECT_FAMILY.search(tag or "")) and tag not in _OBJECT_TAGS


@dataclass
class LayoutObjectScan:
    """The diagnostic form (packet 1338). `extract_layout_objects()` is the compatibility projection
    of `.objects`, so existing consumers keep their shape while 1337 can enforce completeness."""
    objects: list = _dcfield(default_factory=list)
    unexamined: list = _dcfield(default_factory=list)   # [{tag, position}] — object-like, unrecognized
    parse_error: str = ""                               # "" unless the XML would not parse

    @property
    def complete(self) -> bool:
        return not self.unexamined and not self.parse_error


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
    #: Static navigation/script steps this object's OWN button carries, in document order (packet
    #: 1339). Each is {step, script?, layout?, to?, dynamic?}. Default-empty so every existing
    #: consumer and `to_dict()` keep their shape. A computed/original/current destination is labelled
    #: dynamic rather than converted into a named target.
    actions: list = _dcfield(default_factory=list)

    @property
    def anchors(self) -> list:
        """Autosize anchor sides decoded from `options` (top/bottom/left/right order).
        Empty list = FM's implicit default (behaves top-left)."""
        return decode_anchors(self.options)

    def to_dict(self) -> dict:
        return {k: v for k, v in {
            "actions": list(self.actions),
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
        if child.tag in _OBJECT_TAGS:      # prune EVERY nested object form, or a container absorbs
            continue                       # a child's field/script/behaviour/options/label
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


#: Steps whose literal targets are worth naming on a rendered layout. Navigation plus the script call,
#: because "what does this button do" is answered by one of those two in almost every real layout.
_ACTION_STEPS = ("Go to Layout", "Go to Related Record", "New Window", "Perform Script")


def _own_actions(obj) -> list:
    """Static steps carried by this object's OWN button, in document order (packet 1339).

    Every button-bar segment is kept — not just the first descendant `<Step>` — and nested object
    forms are pruned, so a container never reports a child's action as its own."""
    out: list = []
    for step in _iter_own(obj, "Step"):
        name = step.get("name") or ""
        if name not in _ACTION_STEPS:
            continue
        entry = {"step": name}
        sr = step.find(".//ScriptReference")
        if sr is not None and sr.get("name"):
            entry["script"] = sr.get("name")
        lr = step.find(".//LayoutReference")
        if lr is not None and lr.get("name"):
            entry["layout"] = lr.get("name")
        field_to_ids = {id(t) for fr in step.iter("FieldReference")
                        for t in fr.iter("TableOccurrenceReference")}
        for tr in step.iter("TableOccurrenceReference"):
            if id(tr) not in field_to_ids and tr.get("name"):
                entry["to"] = tr.get("name")
                break
        # ONE reader decides this, shared with the script scan and the layout scan (packet 1357).
        # Deciding it here from the ABSENCE of a named target was wrong in both directions: a
        # Go to Related Record that keeps the original layout was called dynamic when its layout is
        # known, and a New Window whose only calculation names the WINDOW was called dynamic when its
        # layout is not computed at all.
        from corpusfm.core.xref.graph import step_navigation
        if step_navigation(step)["dynamic"]:
            entry["dynamic"] = True
        out.append(entry)
    return out


def _iter_own(obj, tag):
    """Every <tag> belonging to `obj` itself, in document order, pruning nested object forms."""
    for child in obj:
        if child.tag in _OBJECT_TAGS:
            continue
        if child.tag == tag:
            yield child
        yield from _iter_own(child, tag)


def _decode_object(obj, z: int) -> "LayoutObjectInfo":
    """One placed object -> its distillation. Shared by all three source forms (packet 1338)."""
    # A form that omits `type` gets a stable element-derived label, never the misleading "Unknown":
    # a Table View column IS a known thing, and calling it unknown would hide it from a reader.
    declared = obj.get("type") or ""
    # A recognized form that omits `type` gets a STABLE element-derived label. "Unknown" is only for
    # something we genuinely cannot name; calling a known form unknown hides it from a reader
    # (widened after Codex review, 2026-08-26 — only the table-view case was covered).
    default = {
        "TableViewLayoutObject": "TableViewField",
        "LayoutObjectReference": "PlacedObject",
        "LayoutObject": "PlacedObject",
    }.get(obj.tag, "Unknown")
    info = LayoutObjectInfo(
        type=declared or default, name=obj.get("name", ""),
        z=z, bounds=_bounds(obj),          # optional: table-view columns carry no <Bounds>
    )
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
    opt_el = obj.find("Options")
    if opt_el is not None and (opt_el.text or "").strip().lstrip("-").isdigit():
        info.options = int(opt_el.text.strip())

    if info.type in _CONTAINER_TYPES:
        tor = _find_own(obj, "TableOccurrenceReference")
        if tor is not None:
            info.to = tor.get("name", "")
        return info

    fr = _find_own(obj, "FieldReference")
    if fr is not None:
        info.field = fr.get("name", "")
        tref = fr.find("TableOccurrenceReference")   # the field's TO context → TO::field (linkable)
        if tref is not None:
            info.field_to = tref.get("name", "")
    sr = _find_own(obj, "ScriptReference")
    if sr is not None:
        info.script = sr.get("name", "")
    # `_find_own`, not `.//` — an unrestricted descendant search let a container absorb a NESTED
    # object's label, which is the one "own value" boundary the first pass missed (Codex review,
    # 2026-08-26). Every other lookup here already prunes the nested object forms.
    lbl_el = _find_own(obj, "Label")
    lbl = None
    if lbl_el is not None:
        t = lbl_el.find(".//Text")
        lbl = t.text if t is not None else None
    if not lbl:
        text_el = _find_own(obj, "Text")
        if text_el is not None:
            data = text_el.find("Data")
            lbl = data.text if data is not None else None
    if lbl:
        info.label = _clean_label(lbl)
    fmt_el = _find_own(obj, "Formatting")
    if fmt_el is not None and len(fmt_el):
        info.fmt = list(fmt_el)[0].tag
    info.actions = _own_actions(obj)
    return info


def scan_layout_objects(layout_xml: str) -> "LayoutObjectScan":
    """Every placed object, plus what the scan could NOT classify (packet 1338).

    ONE walk in document order over all three recognized forms, so `z` is a true stacking order
    rather than three concatenated lists. Every source element is emitted exactly once: the walk
    emits it, and `_find_own` prunes nested object forms so a container never absorbs a child.

    `LayoutObjectReference` carries a `hash`. It is **not** deduplicated by it: no evidence
    establishes that the hash is a placement identity, and two references can be distinct placements
    even with identical content. Erasing objects speculatively is worse than emitting a duplicate.
    """
    if not layout_xml:
        return LayoutObjectScan()
    try:
        root = ET.fromstring(layout_xml)
    except ET.ParseError as exc:
        return LayoutObjectScan(parse_error=str(exc))

    scan = LayoutObjectScan()
    z = 0
    for pos, el in enumerate(root.iter()):
        if el.tag in _OBJECT_TAGS:
            scan.objects.append(_decode_object(el, z))
            z += 1
        elif _looks_like_object_tag(el.tag):
            scan.unexamined.append({"tag": el.tag, "position": pos})
    return scan


def extract_layout_objects(layout_xml: str) -> list:
    """Every object placed on a layout, with type / binding / label / formatting.

    The compatibility projection of `scan_layout_objects(...).objects` — existing consumers (Explorer,
    AI schema context, layout-behaviour Diff) keep their exact shape. Use `scan_layout_objects` when
    the caller must know whether the answer is COMPLETE."""
    return scan_layout_objects(layout_xml).objects
