"""YAML-driven FM XML parser.

Public API:
    load_file(xml_path_or_bytes, label) -> ParseResult

ParseResult has the same logical shape as compare_fm.py's load_file() return value
so comparator.py can operate on either source interchangeably.
"""

from __future__ import annotations

import io
import re
from corpusfm.core import safe_xml as ET
from corpusfm.core.identity import (ID_KIND, UUID_KIND, identity_key,
                                    is_owner_ref_projection, owner_identities,
                                    owner_identity)
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from corpusfm.core.schemas.registry import resolve_parser_config


@dataclass
class ParseResult:
    label: str
    sections: dict        # {section_key: {item_name: fingerprint_or_name}}
    fields: dict          # {table_name: {field_name: fingerprint}}
    steps: dict           # {script_name: fingerprint}
    metadata: dict        # {File, Source, version, ...} from root element attrs
    schema_version: str
    schema_warning: Optional[str]
    step_xml: dict = field(default_factory=dict)    # {script_name: xml_str}
    # {identity_key: xml_str} for the SAME fragments as step_xml. FileMaker does not
    # require script names to be unique, so the name-keyed dict above silently drops a
    # duplicate-named script's body and hands its twin's steps to both — measured: 3 of
    # 620 fragments in MicroK12_dev and 3 of 405 in CMP_Operations_UI_rev2. Every
    # StepsForScripts fragment carries an owner <ScriptReference> with a UUID, so this
    # view loses nothing. step_xml is retained for callers that legitimately want a
    # name lookup; anything attributing a body to a script must use this one.
    step_xml_by_identity: dict = field(default_factory=dict)
    section_xml: dict = field(default_factory=dict) # {section_key: {item_name: xml_str}}
    calcs: dict = field(default_factory=dict)        # {cf_name: fingerprint}
    cf_xml: dict = field(default_factory=dict)       # {cf_name: xml_str}
    field_names: dict = field(default_factory=dict)  # {table_name: [field_name, ...]} for display
    options: dict = field(default_factory=dict)      # {vl_name: fingerprint} from OptionsForValueLists
    options_xml: dict = field(default_factory=dict)  # {vl_name: xml_str}
    # {identity_key: [xml_str, ...]} — the ModifyAction LAYOUT projections, kept beside
    # section_xml instead of overwriting it (packet 1353). The AddAction <Layout> is the
    # authoritative content; this projection is supplemental navigation evidence. Measured:
    # every navigation semantic these carry is already present in the body they name
    # (722/722 CMP_Operations_UI_rev2, 407/407 CMP_Operations, 34/34 MicroK12_dev, 1/1
    # TechFest_dev, through step_navigation()), so they are retained for the one thing the
    # body does NOT carry — a destination FileMaker computes at runtime, which the fragment
    # marks with `type="current"` on its LayoutReferenceContainer and the body serialises as
    # a <Label> the dynamic test does not read.
    layout_nav_xml: dict = field(default_factory=dict)
    is_addon: bool = False                           # True when parsed from FMAdd_on XML


def sanitize_xml(raw_bytes: bytes) -> str:
    """Decode FM export bytes and strip illegal XML control characters.

    FM <=2025 exports SaveAsXML as UTF-16 with a BOM; FM 2026 (schema 2.3.0.0)
    switched to UTF-8 with no BOM. Sniff the leading bytes so both decode.
    """
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw_bytes.decode("utf-16")          # UTF-16, endianness from BOM
    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
        text = raw_bytes.decode("utf-8-sig")        # UTF-8 with BOM
    elif raw_bytes[1:2] == b"\x00":
        text = raw_bytes.decode("utf-16-le")        # BOM-less UTF-16 LE
    elif raw_bytes[:1] == b"\x00":
        text = raw_bytes.decode("utf-16-be")        # BOM-less UTF-16 BE
    else:
        text = raw_bytes.decode("utf-8")            # FM 2026+ UTF-8, no BOM
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)


def _elem_fingerprint(elem: ET.Element, noise_attrs: frozenset, noise_tags: frozenset) -> str:
    """Stable, human-readable representation of an XML element with noise stripped."""
    buf = io.StringIO()

    def walk(e: ET.Element, indent: int = 0) -> None:
        if e.tag in noise_tags:
            return
        attribs = {k: v for k, v in sorted(e.attrib.items()) if k not in noise_attrs}
        buf.write("  " * indent + f"<{e.tag}")
        for k, v in sorted(attribs.items()):
            buf.write(f' {k}="{v}"')
        text = (e.text or "").strip()
        if text:
            buf.write(f">{text}</{e.tag}>\n")
        elif len(e):
            buf.write(">\n")
            for child in e:
                walk(child, indent + 1)
            buf.write("  " * indent + f"</{e.tag}>\n")
        else:
            buf.write("/>\n")

    walk(elem)
    return buf.getvalue()


def _resolve_item_source(catalog_elem: ET.Element, cat: dict) -> Optional[ET.Element]:
    """Return the element to iterate for items, handling optional item_container."""
    container = cat.get("item_container")
    if container:
        catalog_elem = catalog_elem.find(container)
    return catalog_elem


def _resolve_item_name(
    item: ET.Element,
    name_attr: str,
    name_child: Optional[str],
    name_text_path: Optional[str] = None,
) -> str:
    """Extract the item's lookup key.

    Resolution order:
    1. Direct attribute on the item element
    2. Attribute on a named child element (item_name_child)
    3. Text content at an XPath (item_name_text_path) — for deeply nested names
    """
    name = item.attrib.get(name_attr, "")
    if not name and name_child:
        child = item.find(name_child)
        if child is not None:
            name = child.attrib.get(name_attr, "")
    if not name and name_text_path:
        name = (item.findtext(name_text_path) or "").strip()
    return name or "<unnamed>"


def _extract_catalogs(
    action_node: ET.Element,
    catalog_configs: list,
    noise_attrs: frozenset,
    noise_tags: frozenset,
) -> tuple[dict, dict, dict]:
    """Extract all regular catalog sections from ONE action node.

    Returns (sections, section_xml, section_meta). The first two are
    {section_key: {item_name: value}}; the third is {section_key: {item_name:
    (identity_key, id_key, is_projection)}} and exists so `_merge_catalog_xml` can pair
    an entry across action nodes by the identity it asserts instead of by its display
    name. `id_key` is the item's `id` identity where it ALSO carries a UUID — the second
    address a reference may use. All three are computed here because the Element is in
    hand; recovering them later would mean re-parsing every stored string.
    """
    sections: dict[str, dict] = {}
    section_xml: dict[str, dict] = {}
    section_meta: dict[str, dict] = {}

    for cat in catalog_configs:
        key = cat["key"]
        item_tag = cat["item_element"]
        name_attr      = cat["name_attr"]
        name_child     = cat.get("item_name_child")
        name_text_path = cat.get("item_name_text_path")
        compare_content = cat.get("compare_content", False)

        catalog_elem = action_node.find(key)
        if catalog_elem is None:
            continue

        source = _resolve_item_source(catalog_elem, cat)
        if source is None:
            continue

        items = sections.setdefault(key, {})
        xmls = section_xml.setdefault(key, {})
        meta = section_meta.setdefault(key, {})

        for item in source:
            if item.tag != item_tag:
                continue
            name = _resolve_item_name(item, name_attr, name_child, name_text_path)
            if compare_content:
                items[name] = _elem_fingerprint(item, noise_attrs, noise_tags)
            else:
                items[name] = name
            # Structural items like folder markers ("--") and separators ("-") share the
            # same name across all occurrences. Disambiguate in section_xml so every item
            # keeps its document-order position for hierarchy reconstruction in the explorer.
            xml_key = name
            if xml_key in xmls:
                n = 2
                while f"{xml_key}__{n}" in xmls:
                    n += 1
                xml_key = f"{xml_key}__{n}"
            xmls[xml_key] = ET.tostring(item, encoding="unicode")
            idents = owner_identities(key, item)
            meta[xml_key] = (identity_key(idents[0] if idents else None),
                             identity_key(next((i for i in idents[1:] if i.kind == ID_KIND), None)),
                             is_owner_ref_projection(key, item))

    return sections, section_xml, section_meta


def _extract_fields(
    action_node: ET.Element,
    fields_cfg: dict,
    noise_attrs: frozenset,
    noise_tags: frozenset,
) -> dict:
    """Extract fields grouped by table."""
    fields: dict[str, dict] = {}
    catalog_elem = action_node.find(fields_cfg["catalog_element"])
    if catalog_elem is None:
        return fields

    table_tag = fields_cfg["table_element"]
    table_name_attr = fields_cfg["table_name_attr"]
    item_tag = fields_cfg.get("item_element")   # None / null means no tag filter
    item_name_attr = fields_cfg["item_name_attr"]
    compare_content = fields_cfg.get("compare_content", True)

    for table_elem in catalog_elem:
        if table_elem.tag != table_tag:
            continue
        tname = table_elem.attrib.get(table_name_attr, "<unnamed>")
        tfields = fields.setdefault(tname, {})
        for field_elem in table_elem:
            if item_tag and field_elem.tag != item_tag:
                continue
            fname = field_elem.attrib.get(item_name_attr, "<unnamed>")
            if compare_content:
                tfields[fname] = _elem_fingerprint(field_elem, noise_attrs, noise_tags)
            else:
                tfields[fname] = fname
    return fields


def _extract_steps(
    action_node: ET.Element,
    steps_cfg: dict,
    noise_attrs: frozenset,
    noise_tags: frozenset,
) -> tuple[dict, dict]:
    """Extract script step fingerprints and raw XML strings.

    Returns (fingerprints, {script_name: xml}, {identity_key: xml}). The third is the
    one that keeps every fragment — see ParseResult.step_xml_by_identity.
    """
    steps: dict[str, str] = {}
    step_xml: dict[str, str] = {}
    step_xml_by_identity: dict[str, str] = {}

    catalog_elem = action_node.find(steps_cfg["catalog_element"])
    if catalog_elem is None:
        return steps, step_xml, step_xml_by_identity

    source = _resolve_item_source(catalog_elem, steps_cfg)
    if source is None:
        return steps, step_xml, step_xml_by_identity

    item_tag = steps_cfg["item_element"]
    name_attr = steps_cfg["item_name_attr"]
    name_child = steps_cfg.get("item_name_child")

    for script_elem in source:
        if script_elem.tag != item_tag:
            continue
        sname = _resolve_item_name(script_elem, name_attr, name_child)
        xml_str = ET.tostring(script_elem, encoding="unicode")
        steps[sname] = _elem_fingerprint(script_elem, noise_attrs, noise_tags)
        step_xml[sname] = xml_str
        key = identity_key(owner_identity("ScriptCatalog", script_elem))
        if key:
            step_xml_by_identity[key] = xml_str
    return steps, step_xml, step_xml_by_identity


def _project_cf_calc(item: ET.Element) -> "Optional[ET.Element]":
    """A `CustomFunctionCalc`-shaped projection of an inline FM 2026 CustomFunction item:
    `CustomFunctionReference[id,name,UUID]` + the `Calculation` subtree — exactly what the
    retired `CalcsForCustomFunctions` record carried. CF folders carry no Calculation/Text
    and project to None (deliberate skip, never an <unnamed> entry)."""
    import copy as _copy

    name = item.get("name")
    calc = item.find("Calculation")
    if not name or calc is None or calc.find("Text") is None:
        return None
    proj = ET.Element("CustomFunctionCalc")
    ref = ET.SubElement(proj, "CustomFunctionReference")
    for attr in ("id", "name"):
        value = item.get(attr)
        if value is not None:
            ref.set(attr, value)
    uuid_el = item.find("UUID")
    if uuid_el is not None and (uuid_el.text or "").strip():
        ref.set("UUID", uuid_el.text.strip())
    proj.append(_copy.deepcopy(calc))
    return proj


def _project_vl_options(item: ET.Element) -> "Optional[ET.Element]":
    """A legacy-shaped `ValueList` projection of an inline FM 2026 ValueList item:
    `ValueListReference[id,name,UUID]` + only the Source / CustomValues / Field subtrees the
    retired `OptionsForValueLists` record owned."""
    import copy as _copy

    name = item.get("name")
    keep = [child for child in item if child.tag in ("Source", "CustomValues", "Field")]
    if not name or not keep:
        return None
    proj = ET.Element("ValueList")
    ref = ET.SubElement(proj, "ValueListReference")
    for attr in ("id", "name"):
        value = item.get(attr)
        if value is not None:
            ref.set(attr, value)
    uuid_el = item.find("UUID")
    if uuid_el is not None and (uuid_el.text or "").strip():
        ref.set("UUID", uuid_el.text.strip())
    for child in keep:
        proj.append(_copy.deepcopy(child))
    return proj


#: supplemental catalog → (primary catalog, inline item tag, legacy-shape projection)
_INLINE_SUPPLEMENTAL_HOMES: dict = {
    "CalcsForCustomFunctions": ("CustomFunctionsCatalog", "CustomFunction", _project_cf_calc),
    "OptionsForValueLists": ("ValueListCatalog", "ValueList", _project_vl_options),
}


def _harvest_inline_supplemental(
    action_node: ET.Element,
    supplemental_name: str,
    noise_attrs: frozenset,
    noise_tags: frozenset,
) -> tuple[dict, dict]:
    """The FM 2026 read path for a retired supplemental catalog (see _extract_calcs).

    Keys, fingerprints and XML strings are computed from the legacy-shaped PROJECTION, so
    every consumer of the join (xref graph, dead-ends, item renders, git export) keeps its
    paths and its change semantics; the primary item's own metadata never enters the
    fingerprint."""
    fps: dict[str, str] = {}
    xmls: dict[str, str] = {}
    home = _INLINE_SUPPLEMENTAL_HOMES.get(supplemental_name)
    if home is None:
        return fps, xmls
    primary_name, item_tag, project = home
    primary = action_node.find(primary_name)
    if primary is None:
        return fps, xmls
    for item in primary.iter(item_tag):
        proj = project(item)
        if proj is None:
            continue
        cname = item.get("name")
        fps[cname] = _elem_fingerprint(proj, noise_attrs, noise_tags)
        xmls[cname] = ET.tostring(proj, encoding="unicode")
    return fps, xmls


def _extract_calcs(
    action_node: ET.Element,
    calcs_cfg: dict,
    noise_attrs: frozenset,
    noise_tags: frozenset,
) -> tuple[dict, dict]:
    """Extract custom function formula fingerprints and raw XML strings.

    Returns (fingerprints, xml_strings) where both are {cf_name: str}.
    Analogous to _extract_steps for script bodies.
    """
    calcs: dict[str, str] = {}
    cf_xml: dict[str, str] = {}

    catalog_elem = action_node.find(calcs_cfg["catalog_element"])
    if catalog_elem is None:
        # FM 2026 (schema 2.3.0.0) RETIRED this supplemental catalog and folded its content
        # inline into the primary catalog — the first observed non-additive schema change
        # (measured on the same file exported from FM 2024/2025/2026). Absence-triggered only:
        # when the supplemental catalog is present (≤ FM 2025) this path never runs and
        # behavior is byte-identical. The harvest PROJECTS the legacy supplemental shape from
        # the inline item — never the whole primary item, whose UUID/tags/access metadata the
        # supplemental record did not own (a metadata edit must not read as a calc edit).
        return _harvest_inline_supplemental(
            action_node, calcs_cfg["catalog_element"], noise_attrs, noise_tags)

    source = _resolve_item_source(catalog_elem, calcs_cfg)
    if source is None:
        return calcs, cf_xml

    item_tag = calcs_cfg["item_element"]
    name_attr = calcs_cfg["item_name_attr"]
    name_child = calcs_cfg.get("item_name_child")

    for cf_elem in source:
        if cf_elem.tag != item_tag:
            continue
        cname = _resolve_item_name(cf_elem, name_attr, name_child)
        calcs[cname] = _elem_fingerprint(cf_elem, noise_attrs, noise_tags)
        cf_xml[cname] = ET.tostring(cf_elem, encoding="unicode")
    return calcs, cf_xml


def _collect_field_names(action_node: ET.Element) -> tuple[dict, dict]:
    """Return ({table_name: [field_name, ...]}, {"Table::Field": xml_str}).

    Display-only; does not affect fingerprinting or diff logic.
    """
    names: dict[str, list[str]] = {}
    xml_map: dict[str, str] = {}
    fft = action_node.find("FieldsForTables")
    if fft is None:
        return names, xml_map
    for catalog in fft:
        if catalog.tag != "FieldCatalog":
            continue
        bt_ref = catalog.find("BaseTableReference")
        if bt_ref is None:
            continue
        table_name = bt_ref.attrib.get("name", "")
        if not table_name:
            continue
        field_list: list[str] = []
        obj_list = catalog.find("ObjectList")
        if obj_list is not None:
            for f in obj_list:
                if f.tag == "Field":
                    fname = f.attrib.get("name", "")
                    if fname:
                        field_list.append(fname)
                        xml_map[f"{table_name}::{fname}"] = ET.tostring(f, encoding="unicode")
        names[table_name] = field_list
    return names, xml_map


def _merge(dest: dict, src: dict) -> None:
    """Merge nested dicts in-place (two-level: section → name → value)."""
    for key, items in src.items():
        if key not in dest:
            dest[key] = items
        else:
            dest[key].update(items)


#: Sections whose ModifyAction projection is supplemental rather than authoritative.
#: LayoutCatalog alone, and deliberately: its AddAction entry is the full layout body
#: while the ModifyAction entry is a navigation projection of it, so letting the second
#: land on the first destroys the layout. No other catalog was measured to behave that
#: way, and applying a body-wins rule blindly would silently discard real modifications
#: elsewhere (packet 1353, developer ruling 2).
_BODY_IS_AUTHORITATIVE = frozenset({"LayoutCatalog"})


def _pair_target(prior_meta: dict, xml_key: str, ident: str) -> Optional[str]:
    """The key of the entry from an EARLIER action node that this item identifies.

    UUID, else an unambiguous id, and never the display name — `core/identity.py`'s rule,
    applied to the parser's own catalog merge. `prior_meta` holds only earlier nodes'
    entries, which is what keeps the per-node `__N` disambiguation intact: two
    same-identity items inside ONE node are left alone.

    An item offering a UUID is matched on the UUID ALONE. A miss stays a miss and never
    falls through to the id, because an id belonging to a different object is a wrong
    answer rather than a weaker one. Several prior keys may carry one UUID — FileMaker
    projects a rename that way — and those are revisions of one object, not ambiguity.

    An item offering only an id is matched against EVERY prior claim on that id, whether
    the entry holds it as its own identity or as the second address of a UUID-bearing
    entry. Several claimants are unambiguous only when they are fragments of one logical
    object, which is to say they share a single UUID primary; two id-only entries sharing
    an id are two objects and pair with neither. This is `CatalogIndex.resolve`'s rule,
    restated here because this function answers the same question against the parser's
    own per-key metadata instead of against re-parsed XML — the two must not drift.

    Measured: no export in this repository exercises the id route, because every
    projection FileMaker emits carries a UUID. It exists because a reference may not.

    A name match breaks a tie between prior keys that legitimately coalesce, so the
    common case pairs exactly where it always did.
    """
    if not ident:
        return None
    if ident.startswith(f"{UUID_KIND}:"):
        hits = [k for k, m in prior_meta.items() if m[0] == ident]
    else:
        hits = [k for k, m in prior_meta.items() if ident in (m[0], m[1])]
        if len(hits) > 1:
            primaries = {prior_meta[k][0] for k in hits}
            if not (len(primaries) == 1
                    and next(iter(primaries)).startswith(f"{UUID_KIND}:")):
                return None
    if not hits:
        return None
    return xml_key if xml_key in hits else hits[0]


def _merge_catalog_xml(dest_xml: dict, dest_meta: dict, src_xml: dict, src_meta: dict,
                       nav_xml: dict) -> None:
    """Merge one action node's catalog XML into the accumulated view, BY IDENTITY.

    The name-keyed merge this replaces landed a ModifyAction fragment on whatever entry
    shared its display name. Measured on real exports: 4 catalog objects destroyed in
    CMP_Operations_UI_rev2 and 2 in CMP_Operations, and — because two of the four were
    folder-OPEN entries whose close markers still popped — 209 of 419 layouts left with
    a wrong folder path.

    Three rules, in order:
      * an item lands on the earlier-node entry asserting the SAME identity;
      * with no such entry it lands on its own name key, taking a `__N` suffix only when
        that key is already held by a DIFFERENT identity;
      * in `_BODY_IS_AUTHORITATIVE` a projection never displaces a body. It is routed to
        `nav_xml` under the BODY's identity instead, so nothing is discarded and the
        consumer finds it by the layout's own identity.
    """
    for section, items in src_xml.items():
        dest = dest_xml.setdefault(section, {})
        meta = dest_meta.setdefault(section, {})
        prior = dict(meta)                 # earlier nodes only — see _pair_target
        for xml_key, xml_str in items.items():
            ident, _id_key, is_projection = src_meta.get(section, {}).get(xml_key, ("", "", False))
            target = _pair_target(prior, xml_key, ident)
            if target is None:
                # No prior entry this item is known to BE. The name key is therefore
                # reusable only when neither side asserts an identity at all — markers
                # and separators, which are not objects. Comparing identity strings here
                # instead let an AMBIGUOUS id through: two id-only objects and a
                # projection all read `id:2`, pairing correctly refused, and the equality
                # test then handed the projection the first one anyway (Codex, 2026-08-27).
                target = xml_key
                if target in dest and not (
                        ident == "" and meta.get(target, ("", "", False))[0] == ""):
                    n = 2
                    while f"{xml_key}__{n}" in dest:
                        n += 1
                    target = f"{xml_key}__{n}"
            elif (section in _BODY_IS_AUTHORITATIVE
                  and is_projection and not meta[target][2]):
                # Keyed by the BODY's identity, not the projection's: a projection may
                # have reached it by id, and the consumer looks it up by the layout's own.
                nav_xml.setdefault(meta[target][0], []).append(xml_str)
                continue
            dest[target] = xml_str
            meta[target] = (ident, _id_key, is_projection)


# Strict schema-version fence (packet 074). CORPUSfm runs a tight, validated window — FileMaker's
# schema XML is NEAR-additive (FM 2026 retired two supplemental catalogs — packet 1284; see
# _harvest_inline_supplemental), so we support exactly the versions we've built + validated against
# and REJECT anything outside it (a partial parse that LOOKS complete is a user trap; a clean
# rejection is honest). When a new FileMaker version ships, we build support and release an update.
#   FLOOR  = FM 21 (FM 21.1.2 emits schema 2.2.2.0; kept generous at 2.2.x to cover every FM 21/22
#            point release — the <DDR_INFO> gate below is the real FM-21 floor for FM 17-20).
#   CEILING = FM 2026 (schema 2.3.0.0), the newest validated.
_SCHEMA_FLOOR = (2, 2, 0, 0)
_SCHEMA_CEILING = (2, 3, 0, 0)


def _check_version_fence(root: ET.Element, label: str) -> None:
    """Reject a schema version outside the validated [2.2.0.0, 2.3.0.0] window with a distinct,
    actionable message (too-new vs too-old), before we try to parse it."""
    from corpusfm.core.schemas.registry import _version_tuple
    ver = root.get("version", "")
    if not ver:
        return  # absence is handled elsewhere (detect_version raises; the bytes path fails on empty config)
    vt = _version_tuple(ver)
    if vt > _SCHEMA_CEILING:
        raise ValueError(
            f"'{label}' is from a newer FileMaker version than this CORPUSfm has been validated "
            f"against (schema {ver}, newer than 2.3.0.0). Update CORPUSfm to ingest this file."
        )
    if vt < _SCHEMA_FLOOR:
        raise ValueError(
            f"'{label}' is from a FileMaker version older than CORPUSfm supports "
            f"(schema {ver}, older than 2.2.0.0). FileMaker 21+ is required."
        )


def _validate_import(root: ET.Element, label: str) -> None:
    """Gate imported XML on root element, schema-version window, and FM version floor.

    Version fence (packet 074): the schema version must fall in the validated [2.2.0.0, 2.3.0.0]
    window — newer is rejected (not silently down-mapped), older than FM 21 is rejected.

    FMSaveAsXML (DDR): must carry Has_DDR_INFO="True" or a <DDR_INFO> child element,
    which FM 21+ always produces when "Include details for analysis tools" is checked.
    Files from FM 17-20 lack DDR_INFO and are hard-rejected here.

    FMAdd_on: Has_DDR_INFO="False" by design — DDR gate skipped, but the version fence still applies.

    Raises ValueError with a user-actionable message on any violation.
    """
    from corpusfm.core.schemas.registry import ADDON_ROOT, EXPECTED_ROOT, _VALID_ROOTS
    tag = root.tag
    if tag not in _VALID_ROOTS:
        raise ValueError(
            f"Unrecognised root element <{tag}> in '{label}'. "
            f"Expected <{EXPECTED_ROOT}> (DDR export) or <{ADDON_ROOT}> (addon XML)."
        )
    _check_version_fence(root, label)
    if tag == ADDON_ROOT:
        return  # Has_DDR_INFO="False" is expected; skip DDR version gate

    # DDR gate: FM 21+ required
    if root.get("Has_DDR_INFO") == "True":
        return
    if root.find("DDR_INFO") is not None:
        return
    raise ValueError(
        f"'{label}' was exported without analysis detail (Has_DDR_INFO missing or False). "
        "Re-export from FileMaker 21+ with 'Include details for analysis tools' checked."
    )


def load_file(xml_path_or_bytes, label: str) -> ParseResult:
    """Parse a FileMaker DDR export (FMSaveAsXML) or addon XML (FMAdd_on).

    Accepts:
        xml_path_or_bytes: pathlib.Path, str path, or raw bytes
        label:             display label for this file

    Returns:
        ParseResult; is_addon=True when source is FMAdd_on XML.
    """
    if isinstance(xml_path_or_bytes, (str, Path)):
        xml_path = Path(xml_path_or_bytes)
        config, schema_version, schema_warning = resolve_parser_config(xml_path)
        with open(xml_path, "rb") as fh:
            raw = fh.read()
    else:
        raw = xml_path_or_bytes
        text = sanitize_xml(raw)
        root_probe = ET.fromstring(text)
        version = root_probe.attrib.get("version", "")
        from corpusfm.core.schemas.registry import load_mapping_config
        config, schema_warning = load_mapping_config(version) if version else ({}, "No version attribute found")
        schema_version = version
        # Packet 067: a schema root that resolved to an EMPTY mapping (missing/garbled `version`) would
        # otherwise parse into a structurally-valid but EMPTY artifact and be stored as SUCCESS with no
        # diagnostic. Fail loudly instead — the file-path branch already raises via detect_version; the
        # bytes path (the ingestion path) must match. Empty catalogs ⟺ no usable mapping resolved.
        if root_probe.tag in ("FMSaveAsXML", "FMAdd_on") and not config.get("catalogs"):
            raise ValueError(
                f"Cannot parse this {root_probe.tag}: no schema mapping resolved "
                f"({'no version attribute on the root' if not version else 'unknown version ' + version}). "
                f"Re-export from FileMaker: File → Save a Copy as XML → Include details for analysis tools."
            )

    noise_attrs = frozenset(config.get("noise_attrs", []))
    noise_tags = frozenset(config.get("noise_tags", []))
    catalog_configs = config.get("catalogs", [])
    fields_cfg   = config.get("fields_catalog", {})
    steps_cfg    = config.get("steps_catalog", {})
    calcs_cfg    = config.get("calcs_catalog", {})
    options_cfg  = config.get("options_catalog", {})

    text = sanitize_xml(raw)
    root = ET.fromstring(text)
    _validate_import(root, label)
    is_addon = root.tag == "FMAdd_on"
    metadata = dict(root.attrib)

    sections: dict[str, dict] = {}
    section_xml: dict[str, dict] = {}
    section_meta: dict[str, dict] = {}   # {section: {xml_key: (identity_key, is_projection)}}
    layout_nav_xml: dict[str, list] = {}
    fields: dict[str, dict] = {}
    field_names: dict[str, list] = {}
    steps: dict[str, str] = {}
    step_xml: dict[str, str] = {}
    step_xml_by_identity: dict[str, str] = {}
    calcs: dict[str, str] = {}
    cf_xml: dict[str, str] = {}
    options: dict[str, str] = {}
    options_xml: dict[str, str] = {}

    for action_node in root.findall(config.get("structure_path", "./Structure/")):
        secs, sxmls, smeta = _extract_catalogs(action_node, catalog_configs, noise_attrs, noise_tags)
        _merge(sections, secs)
        _merge_catalog_xml(section_xml, section_meta, sxmls, smeta, layout_nav_xml)
        if fields_cfg:
            _merge(fields, _extract_fields(action_node, fields_cfg, noise_attrs, noise_tags))
        fn, fxml = _collect_field_names(action_node)
        # First-wins: AddAction has the complete field list per table.
        # ModifyAction entries are one-field-per-FieldCatalog and must not
        # overwrite the authoritative complete list from AddAction.
        for tname, fnames in fn.items():
            if tname not in field_names:
                field_names[tname] = fnames
        # fxml is keyed by Table::Field — _merge correctly updates individual
        # field XML with the latest version from any ModifyAction.
        _merge(section_xml, {"FieldsForTables": fxml})
        if steps_cfg:
            fps, xmls, by_identity = _extract_steps(action_node, steps_cfg, noise_attrs, noise_tags)
            steps.update(fps)
            step_xml.update(xmls)
            step_xml_by_identity.update(by_identity)
        if calcs_cfg:
            fps, xmls = _extract_calcs(action_node, calcs_cfg, noise_attrs, noise_tags)
            calcs.update(fps)
            cf_xml.update(xmls)
        if options_cfg:
            fps, xmls = _extract_calcs(action_node, options_cfg, noise_attrs, noise_tags)
            options.update(fps)
            options_xml.update(xmls)

    return ParseResult(
        label=label,
        sections=sections,
        fields=fields,
        steps=steps,
        metadata=metadata,
        schema_version=schema_version,
        schema_warning=schema_warning,
        step_xml=step_xml,
        step_xml_by_identity=step_xml_by_identity,
        section_xml=section_xml,
        calcs=calcs,
        cf_xml=cf_xml,
        field_names=field_names,
        options=options,
        options_xml=options_xml,
        layout_nav_xml=layout_nav_xml,
        is_addon=is_addon,
    )
