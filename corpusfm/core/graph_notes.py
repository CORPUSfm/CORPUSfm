"""Captured relationship-graph notes: reading them, and comparing two captures (packets 1448, 1451).

Notes live in TableOccurrenceCatalog/TableOccurrenceNotes and aren't catalog items. Artifact.graph_notes keeps
their source XML, and None there means the artifact was ingested before they were kept, so it says nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from corpusfm.core import safe_xml as ET

_CSS_RGBA = re.compile(r"rgba?\(\s*([\d.]+)(%?)\s*,\s*([\d.]+)(%?)\s*,\s*([\d.]+)(%?)\s*(?:,\s*([\d.]+)\s*)?\)")
# What read_note already reports, by path; anything else under a note is kept as `other` and compared.
_READ_TEXT = {"UUID", "Options", "Text/Options", "Text/StyledText/Data", "LocalCSS"}
_READ_ATTRS = {"Bounds": {"top", "left", "bottom", "right"}, "LocalCSS": {"type", "name", "displayName"}}
# Not edits of the note: FileMaker's own content hash and the UUID's edit-history attributes.
_NOISE_ATTRS = {"hash", "modifications", "userName", "accountName", "timestamp"}


def css_color(css: str, prop: str) -> list | None:
    """One color property from captured CSS as [r, g, b, a] numbers. Nothing else in that CSS is ever used."""
    decl = re.search(rf"(?:^|[;{{\s]){prop}\s*:\s*([^;}}]+)", css or "")
    match = _CSS_RGBA.search(decl.group(1)) if decl else None
    if not match:
        return None
    channels = []
    try:
        for value, percent in (match.group(1, 2), match.group(3, 4), match.group(5, 6)):
            number = float(value) * (2.55 if percent else 1)
            channels.append(max(0, min(255, round(number))))
        alpha = float(match.group(7)) if match.group(7) else 1.0
    except ValueError:
        return None
    return channels + [max(0.0, min(1.0, alpha))]


def _residue(elem, path: str) -> str:
    """Whatever under this element read_note doesn't report, in a form that ignores source formatting."""
    skip = _NOISE_ATTRS | _READ_ATTRS.get(path, set())
    attrs = "".join(f' {k}="{v}"' for k, v in sorted(elem.attrib.items()) if k not in skip)
    text = "" if path in _READ_TEXT else (elem.text or "").strip()
    inner = "".join(_residue(child, f"{path}/{child.tag}") for child in elem)
    return f"<{elem.tag}{attrs}>{text}{inner}</{elem.tag}>" if attrs or text or inner else ""


def read_note(xml: str) -> dict:
    """Every fact a note carries. Unreadable values stay None, and unparseable XML is kept whole in `other`."""
    note = {"id": None, "uuid": None, "text": "", "x": None, "y": None, "w": None, "h": None, "options": None,
            "collapsed": False, "background": None, "color": None, "text_options": None, "style": "", "attributes": "", "other": ""}
    try:
        elem = ET.fromstring(xml)
    except ET.ParseError:
        note["other"] = xml
        return note
    note["id"] = elem.get("id")
    note["uuid"] = (elem.findtext("UUID") or "").strip() or None
    note["text"] = elem.findtext("Text/StyledText/Data") or ""
    bounds = elem.find("Bounds")
    try:
        top, left, bottom, right = (int(float(bounds.get(k))) for k in ("top", "left", "bottom", "right"))
        note.update(x=left, y=top, w=max(1, right - left), h=max(1, bottom - top))
    except (AttributeError, TypeError, ValueError, OverflowError):
        pass
    options_text = (elem.findtext("Options") or "").strip()
    if options_text.isascii() and options_text.isdigit():
        note["options"] = int(options_text)
        note["collapsed"] = bool(note["options"] & 1)   # supported by one paired capture; every bit is kept
    note["text_options"] = (elem.findtext("Text/Options") or "").strip() or None
    css = elem.findtext("LocalCSS") or ""
    note["background"] = css_color(css, "background-color")
    note["color"] = css_color(css, "color")
    note["style"] = " ".join(css.split())
    note["attributes"] = " ".join(f'{k}="{v}"' for k, v in sorted(elem.attrib.items()) if k not in _NOISE_ATTRS | {"id"})
    note["other"] = " ".join(r for r in (_residue(child, child.tag) for child in elem) if r)
    return note


def note_identity(note: dict, index: int) -> str:
    """Stable identity within a file: the captured UUID, else the id. Position is a last resort."""
    if note["uuid"]:
        return "uuid:" + note["uuid"]
    return "id:" + note["id"] if note["id"] else f"position:{index}"


def note_label(note: dict, identity: str) -> str:
    first = next((line.strip() for line in note["text"].splitlines() if line.strip()), "")
    name = first if len(first) <= 60 else first[:59] + "…"
    return f"{name or '(empty note)'} [{identity.split(':', 1)[1][:8]}]"


def _color_text(color: list | None) -> str:
    if color is None:
        return "not captured"
    return f"rgba({color[0]}, {color[1]}, {color[2]}, {color[3]:g})"


def note_lines(note: dict, stacking: str | None = None) -> list[str]:
    """A note as readable lines; two notes differ in these lines exactly where they differ."""
    text = note["text"].replace("\r\n", "\n").replace("\r", "\n").split("\n")
    lines = ["Text: " + text[0]] + ["      " + line for line in text[1:]]
    if note["x"] is None:
        lines.append("Position: not captured")
    else:
        lines.append(f"Position: left {note['x']}, top {note['y']}")
        lines.append(f"Size: {note['w']} × {note['h']}")
    lines.append("Background: " + _color_text(note["background"]))
    if note["color"]:
        lines.append("Text color: " + _color_text(note["color"]))
    lines.append("State: " + ("Collapsed" if note["collapsed"] else "Expanded"))
    lines.append("Options: " + ("not captured" if note["options"] is None else str(note["options"])))
    if note["text_options"]:
        lines.append("Text options: " + note["text_options"])
    if note["style"]:
        lines.append("Style: " + note["style"])
    if note["attributes"]:
        lines.append("Attributes: " + note["attributes"])
    if note["other"]:
        lines.append("Other captured data: " + note["other"])
    if stacking:
        lines.append("Stacking: " + stacking)
    return lines


@dataclass
class NoteChange:
    identity: str
    label: str
    lines_a: list = field(default_factory=list)
    lines_b: list = field(default_factory=list)


@dataclass
class NoteComparison:
    added: list = field(default_factory=list)     # NoteChange, lines_b only
    removed: list = field(default_factory=list)   # NoteChange, lines_a only
    changed: list = field(default_factory=list)
    incomplete: str | None = None                 # why notes could not be compared


def uncaptured_message(graph_a, graph_b) -> str | None:
    sides = [s for s, g in (("A", graph_a), ("B", graph_b)) if g is None]
    if not sides:
        return None
    who = "Both sides were" if len(sides) == 2 else f"Side {sides[0]} was"
    return (f"Relationship graph notes not compared. {who} ingested before CORPUSfm kept them, so nothing is "
            "known about notes there. Re-ingest to compare them.")


def _overlap(a: dict, b: dict) -> bool:
    if None in (a["x"], b["x"]):
        return False
    return a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]


def _indexed(xmls: list) -> dict:
    out: dict = {}
    for index, xml in enumerate(xmls):
        note = read_note(xml)
        key = note_identity(note, index)
        while key in out:       # a duplicate identity must not hide a note
            key += "#"
        out[key] = (index, note)
    return out


def compare_notes(graph_a, graph_b) -> NoteComparison:
    """Added, removed and changed notes between two captures, by identity.

    Document order is the only stacking the source holds, and a swap matters only where the two notes overlap
    on either side: elsewhere it has no visible effect, so it is treated as incidental serialization order.
    """
    message = uncaptured_message(graph_a, graph_b)
    if message:
        return NoteComparison(incomplete=message)
    a, b = _indexed(graph_a), _indexed(graph_b)
    result = NoteComparison()
    common = [k for k in a if k in b]
    swapped: set = set()
    for i, k1 in enumerate(common):
        for k2 in common[i + 1:]:
            if (a[k1][0] < a[k2][0]) != (b[k1][0] < b[k2][0]) and (_overlap(a[k1][1], a[k2][1]) or _overlap(b[k1][1], b[k2][1])):
                swapped.update((k1, k2))
    for key, (_, note) in b.items():
        if key not in a:
            result.added.append(NoteChange(key, note_label(note, key), lines_b=note_lines(note)))
    for key, (_, note) in a.items():
        if key not in b:
            result.removed.append(NoteChange(key, note_label(note, key), lines_a=note_lines(note)))
    for key in common:
        (ia, na), (ib, nb) = a[key], b[key]
        stack_a = f"{ia + 1} of {len(a)}, later notes on top" if key in swapped else None
        stack_b = f"{ib + 1} of {len(b)}, later notes on top" if key in swapped else None
        la, lb = note_lines(na, stack_a), note_lines(nb, stack_b)
        if la != lb:
            result.changed.append(NoteChange(key, note_label(nb, key), lines_a=la, lines_b=lb))
    return result
