"""FMClip XML ingestion — fmxmlsnippet type="FMObjectList" → Artifact.

Clipboard XML is a fragment, not a full schema.  Stages skipped:
  dead-end analysis, XRef graph, gap analysis, structure mining.

Public API:
    detect_clip(xml_bytes) -> bool
    extract_clip_xml(text) -> str
    ingest_clip(xml_bytes, label, *, source_type) -> Artifact
"""

from __future__ import annotations

import hashlib
import logging
from corpusfm.core import safe_xml as ET
from datetime import datetime, timezone
from typing import Optional

from corpusfm.artifact import (
    ARTIFACT_VERSION,
    Artifact,
    ArtifactIdentity,
    ArtifactItem,
    ArtifactProvenance,
    ArtifactType,
    CompletenessProfile,
    XmlSource,
    make_item_id,
)

logger = logging.getLogger(__name__)

# Maps fmxmlsnippet child tag names to catalog section keys used throughout CORPUSfm.
_TAG_TO_SECTION: dict[str, str] = {
    "Script":        "ScriptCatalog",
    "Layout":        "LayoutCatalog",
    "BaseTable":     "BaseTableCatalog",
    "TableOccurrence": "TableOccurrenceCatalog",
    "CustomFunction": "CustomFunctionsCatalog",
    "ValueList":     "ValueListCatalog",
    "PrivilegeSet":  "PrivilegeSetsCatalog",
    "CustomMenuSet": "CustomMenuSetCatalog",
    "Field":         "FieldsForTables",
}


def detect_clip(xml_bytes: bytes) -> bool:
    """Return True when xml_bytes is an fmxmlsnippet FMObjectList clip."""
    head = xml_bytes[:512]
    return b"<fmxmlsnippet" in head and b"FMObjectList" in head


# The first element child of an FMObjectList determines what the clip IS, which maps to
# FileMaker's clipboard class code (what MBS Clipboard.SetFileMakerData / FmClipTools must
# set) and the paste target. Only well-established class codes are asserted; an unknown
# child reports its tag with no class so we never claim a code we haven't verified.
_CLIP_KIND: dict[str, tuple[str, str, str]] = {
    "Step":           ("script steps", "XMSS", "paste into a script"),
    "Script":         ("scripts", "XMSC", "paste into the Scripts list"),
    "Field":          ("fields", "XMFD", "paste into Manage Database → Fields"),
    "BaseTable":      ("tables", "XMTB", "paste into Manage Database → Tables"),
    "CustomFunction": ("custom functions", "XMFN", "paste into Manage → Custom Functions"),
    "ValueList":      ("value lists", "XMVL", "paste into Manage → Value Lists"),
    "Layout":         ("layout objects", "XMLO", "paste onto a layout"),
    "Object":         ("layout objects", "XMLO", "paste onto a layout"),
}


def classify_clip(xml_text: str) -> "dict | None":
    """Classify an FMObjectList clip by its first real object.

    Returns {kind, fm_class, paste_target, child} (fm_class "" when unverified), or None
    when the text isn't a parseable fmxmlsnippet. Used to label the clip item so a clipboard
    tool (MBS / FmClipTools) knows which FM class to set.

    A FOLDERED clip wraps its objects in <Group> (e.g. a script-folder tree), so the first
    child is the folder, not the object — descend through Group wrappers to the first real
    object before classifying (samples: SeedDBScripts.xml, severalcustomfunctions.xml)."""
    try:
        root = ET.fromstring(_strip_xml_decl(xml_text))
    except Exception:
        return None
    if root.tag != "fmxmlsnippet":
        return None
    for child in root:
        tag = child.tag
        if tag == "Group":
            inner = next((e for e in child.iter() if e.tag in _CLIP_KIND), None)
            if inner is not None:
                tag = inner.tag
        kind, cls, target = _CLIP_KIND.get(tag, (tag, "", ""))
        return {"kind": kind, "fm_class": cls, "paste_target": target, "child": tag}
    return None


def _strip_xml_decl(text: str) -> str:
    """Drop a leading <?xml …?> declaration. ElementTree refuses to parse a Unicode string that
    carries an `encoding=` declaration ("encoding declaration in Unicode string"), and FM clips
    sometimes declare utf-16 even when handed to us as text — so strip it before parsing a str."""
    import re as _re
    return _re.sub(r"^﻿?\s*<\?xml[^>]*\?>", "", text, count=1)


def extract_clip_xml(text: str) -> str:
    """Extract and validate a FileMaker FMObjectList clip from arbitrary text.

    Tolerates markdown fences / surrounding prose (an agent may wrap its output): finds the
    `<fmxmlsnippet …>…</fmxmlsnippet>` block, validates it is well-formed and carries
    type="FMObjectList", and returns it with an XML declaration. Raises ValueError otherwise.
    This is what `save_clip` validates an agent-authored clip against (the #5-removed in-app
    fmClip validator, minimal — ingestion stays via detect_clip/ingest_clip).
    """
    import re as _re

    if not text or not text.strip():
        raise ValueError("empty clip text")
    body = text.strip()
    # strip a leading ```xml / ``` fence pair if present
    if body.startswith("```"):
        body = _re.sub(r"^```[a-zA-Z]*\n?", "", body)
        body = _re.sub(r"\n?```$", "", body).strip()

    m = _re.search(r"<fmxmlsnippet\b.*?</fmxmlsnippet>", body, _re.DOTALL)
    if not m:
        raise ValueError("no <fmxmlsnippet>…</fmxmlsnippet> block found")
    snippet = m.group(0)

    try:
        root = ET.fromstring(snippet)
    except ET.ParseError as exc:
        raise ValueError(f"clip XML is not well-formed: {exc}") from exc
    if root.tag != "fmxmlsnippet":
        raise ValueError(f"root element is <{root.tag}>, expected <fmxmlsnippet>")
    if (root.get("type") or "") != "FMObjectList":
        raise ValueError('fmxmlsnippet type must be "FMObjectList"')

    if not snippet.lstrip().startswith("<?xml"):
        snippet = '<?xml version="1.0" encoding="UTF-8"?>\n' + snippet
    return snippet


def _analyze_clip_gaps(xml_bytes: bytes):
    """Run the clip gap analyzer, fail-SAFE (packet 1079).

    Drift detection must never break ingestion — a clip we can't analyse is still a clip worth storing,
    and refusing it would lose the very sample that proves the format moved. But a crash must not read
    as "clean" either (packet 072-D), so the failure is RECORDED in `analyzer_failed`. Imported lazily
    so clip ingestion doesn't pull the catalog on every call."""
    from corpusfm.core.clip_gap import analyze_clip, ClipGapReport
    try:
        return analyze_clip(xml_bytes)
    except Exception as exc:
        logger.warning("clip gap analyze failed: %s", exc)
        return ClipGapReport(failed=["clip_gap_analyze"])


def ingest_clip(
    xml_bytes: bytes,
    label: str,
    *,
    source_type: str = "manual",
) -> Artifact:
    """Parse an FMObjectList clip and return an Artifact of type fmClip."""
    root_uuid = "clip:" + hashlib.sha256(xml_bytes).hexdigest()[:16]

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid clip XML: {exc}") from exc

    items: dict[str, ArtifactItem] = {}
    sections_seen: list[str] = []

    for child in root:
        tag = child.tag
        section = _TAG_TO_SECTION.get(tag)
        if section is None:
            logger.debug("clip: unknown element <%s>, skipping", tag)
            continue

        name = child.get("name") or child.get("id") or tag
        fm_uuid = child.get("UUID") or ""
        attrs = dict(child.attrib)
        xml_str = ET.tostring(child, encoding="unicode")
        item_id = make_item_id(section, fm_uuid, name)

        # Deduplicate when the same item_id appears twice in a clip
        if item_id in items:
            item_id = f"{section}/{name}"

        rendered_text = _render_clip_item(section, name, xml_str, child)

        if section not in sections_seen:
            sections_seen.append(section)

        items[item_id] = ArtifactItem(
            item_id=item_id,
            section=section,
            name=name,
            xml_key=name,
            fm_uuid=fm_uuid,
            attributes=attrs,
            xml_sources=[XmlSource(catalog=section, xml=xml_str)],
            rendered_text=rendered_text,
            summary=None,
            is_folder=False,
            folder_path=[],
            dead_end=False,
        )

    # packet 1079 — the FMXML drift early-warning. An incoming clip is the ONLY FMXML that ever comes
    # toward us, so it is the only place clip-format drift is observable; storing it unanalysed threw
    # that signal away. Read-only: it records what we didn't recognise, and never rejects.
    gap = _analyze_clip_gaps(xml_bytes)

    # fm_version stays EMPTY, deliberately: it means the DECLARED FM build (SaveAsXML's Source="26.0.1"),
    # and a clip declares nothing. The inferred form is analysis output, not identity, so it lives on the
    # CompletenessProfile — "the record of what the pipeline knew". Putting a prose label in a version
    # field would misfeed fm_tag()'s dotted-major parse and print "FM FM2026-form (inferred)" in the CLI.
    identity = ArtifactIdentity(root_uuid=root_uuid, file_name=label, fm_version="")
    provenance = ArtifactProvenance(
        ingested_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        catalog_version="",
        source=source_type,
    )
    profile = CompletenessProfile(
        sections_present=sections_seen,
        sections_absent=[],
        absent_by_design=[],
        unknown_step_ids=gap.unknown_step_ids,
        unknown_reference_types=[],
        unresolved_uuids=[],
        # `gap_analyze` (the DDR analyzer) still doesn't apply — a clip is a fragment, not a schema. The
        # clip-specific analyzer is a DIFFERENT thing and is named distinctly, so "we skipped the DDR
        # analyzer" is never mistaken for "we analysed nothing".
        miner_skipped=["xref", "dead_ends", "gap_analyze", "structure_mine"],
        clip_gaps=gap.unknown_enum_values + gap.unknown_elements,
        clip_elements_checked_ids=[str(i) for i in gap.elements_checked_ids],
        clip_inferred_fm_form=gap.inferred_fm_form,
        analyzer_failed=list(gap.failed),
    )

    artifact = Artifact(
        artifact_version=ARTIFACT_VERSION,
        type=ArtifactType.CLIPBOARD_XML,
        identity=identity,
        provenance=provenance,
        sections=sections_seen,
        items=items,
        xref_map=[],
        completeness_profile=profile,
        structure_catalog=None,
    )
    return artifact


def _render_clip_item(section: str, name: str, xml_str: str, elem) -> str:
    """Return rendered text for a clip item. Falls back to name on any error."""
    if section == "ScriptCatalog":
        return _render_clip_script(name, elem)
    try:
        from corpusfm.core.rendering.section_renderer import render_section_item
        ri = render_section_item(section, name, xml_str)
        parts = [ri.summary or name]
        if ri.body:
            parts.append(ri.body)
        return "\n".join(parts)
    except Exception as exc:
        logger.debug("clip render error %s/%s: %s", section, name, exc)
        return name


def _render_clip_script(name: str, elem) -> str:
    """Render script steps from a clip element (steps are inline children)."""
    try:
        from corpusfm.core.rendering.step_renderer import render_script
        from corpusfm.core.rendering.catalog import load_catalog
        catalog, _ = load_catalog("")
        rendered_steps = render_script(elem, catalog, show_hidden=False)
        step_body = "\n".join(
            ("// " if rs.disabled else "   ") + rs.full_text
            for rs in rendered_steps
        )
        if step_body:
            return f"{name}\n--- Steps ---\n{step_body}"
    except Exception as exc:
        logger.debug("clip script render error %s: %s", name, exc)
    return name
