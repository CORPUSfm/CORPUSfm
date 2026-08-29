"""Structured-reference identity — UUID, else id. Never the display name.

FileMaker does not require display names to be unique WITHIN a catalog, and the
same name may also sit in several catalogs at once — layouts, scripts and value
lists all collide this way, and FileMaker manages them by id. A display name is
therefore not a reference, and an id is one only once a catalog is named with it:
`LayoutCatalog/id:7` and `ValueListCatalog/id:7` are unrelated objects (packet
1358; the earlier wording said only scripts and layouts).

This module is the one place that answers two questions for a STRUCTURED
reference — an XML element carrying `UUID`/`id` attributes:

  * what identity does this catalog item assert?   ``owner_identity``
  * which catalog item does this reference name?   ``CatalogIndex.resolve``

**The formula boundary is deliberately outside this module.** A CF call or a
field reference inside an auto-enter, validation or layout formula names its
target as text and nothing else — FileMaker puts no identifier there — so those
analyses stay name-matched by construction. They must not be re-scoped by the
rule here, and they must say that they are name-matched.

Resolution rules:

  * A reference carrying a non-empty UUID is looked up by UUID ONLY. A miss is
    a miss; it never falls through to the reference's id, because an id that
    belongs to a different object is a wrong answer, not a weaker one.
  * A reference with no UUID may be looked up by id.
  * Several catalog fragments sharing one UUID are REVISIONS of one logical
    object (FileMaker projects a rename as a second fragment), so they resolve
    together.
  * Several DISTINCT objects sharing an id resolve to nothing. Ambiguity
    refuses; it does not pick the first.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from corpusfm.core import safe_xml as ET

UUID_KIND = "uuid"
ID_KIND = "id"
MISSING = "missing"
AMBIGUOUS = "ambiguous"

#: Sections whose catalog element may assert its identity through a direct
#: child owner reference instead of a <UUID> child. FileMaker projects a
#: ModifyAction fragment that way: the root element carries no `name`, and its
#: first child is the section's own reference tag naming the object being
#: modified. Measured 2026-08-26: 22 such fragments in MicroK12_dev and 143 in
#: CMP_Operations_UI_rev2, every one with no root `name` and a child
#: `<LayoutReference>` whose name matched the catalog key.
_OWNER_REF_TAG: dict[str, str] = {
    "LayoutCatalog": "LayoutReference",
    "ScriptCatalog": "ScriptReference",
    "ValueListCatalog": "ValueListReference",
    "TableOccurrenceCatalog": "TableOccurrenceReference",
    "BaseTableCatalog": "BaseTableReference",
    "CustomMenuCatalog": "CustomMenuReference",
    "CustomMenuSetCatalog": "CustomMenuSetReference",
    "PrivilegeSetsCatalog": "PrivilegeSetReference",
}


@dataclass(frozen=True)
class CatalogIdentity:
    """What a catalog item asserts about which object it is."""

    section: str
    kind: str    # UUID_KIND | ID_KIND
    value: str


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving one structured reference against a catalog."""

    kind: str                    # UUID_KIND | ID_KIND | MISSING | AMBIGUOUS
    xml_keys: tuple[str, ...] = ()
    identity: CatalogIdentity | None = None
    reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.kind in (UUID_KIND, ID_KIND)


def owner_identity(section: str, el: ET.Element) -> CatalogIdentity | None:
    """Return the identity a catalog element asserts, or None.

    UUID first, in the two forms FileMaker uses; the element's own `id` last.
    """
    # Some element types carry the UUID as a root attribute; most store it as a
    # <UUID> child. Measured across every repository export: where the attribute is
    # present it never disagrees with the child form, so this order is safe.
    attr_uuid = (el.get("UUID") or "").strip()
    if attr_uuid:
        return CatalogIdentity(section, UUID_KIND, attr_uuid)

    uuid_el = el.find("UUID")
    if uuid_el is not None and uuid_el.text and uuid_el.text.strip():
        return CatalogIdentity(section, UUID_KIND, uuid_el.text.strip())

    ref_tag = _OWNER_REF_TAG.get(section)
    if ref_tag is not None and el.get("name") is None:
        ref = el.find(ref_tag)
        if ref is not None:
            uuid = (ref.get("UUID") or "").strip()
            if uuid:
                return CatalogIdentity(section, UUID_KIND, uuid)
            ref_id = (ref.get("id") or "").strip()
            if ref_id:
                return CatalogIdentity(section, ID_KIND, ref_id)

    own_id = (el.get("id") or "").strip()
    if own_id:
        return CatalogIdentity(section, ID_KIND, own_id)
    return None


def identity_key(identity: CatalogIdentity | None) -> str:
    """A flat, deterministic key for an identity — `"uuid:<v>"` / `"id:<v>"`, or `""`.

    Used where a dict has to be keyed by identity without carrying the dataclass,
    e.g. the parser's supplemental views on the ephemeral ParseResult.
    """
    return f"{identity.kind}:{identity.value}" if identity is not None else ""


def is_owner_ref_projection(section: str, el: ET.Element) -> bool:
    """True when this element identifies itself through a child owner reference rather
    than through its own `name` — the shape a ModifyAction fragment has.

    The AddAction entry carries the object's own attributes and its full body; the
    ModifyAction entry carries a bare root, a child `<...Reference>` naming the object,
    and a partial projection of it. Telling them apart STRUCTURALLY is what lets the
    parser keep the authoritative body when both describe one object. Size is not the
    rule: a fragment may be larger than the folder entry it names, and a body may be
    small.
    """
    ref_tag = _OWNER_REF_TAG.get(section)
    return (ref_tag is not None
            and el.get("name") is None
            and el.find(ref_tag) is not None)


def owner_identities(section: str, el: ET.Element) -> list[CatalogIdentity]:
    """EVERY identity a catalog item asserts — its UUID and its id, primary first.

    An item normally carries both, and a reference may name it by either: measured,
    a `<PrivilegeSetReference>` inside an Account offers only `id` while the
    `<PrivilegeSet>` it names carries a `<UUID>` child. Indexing the item under one
    identity alone made every such reference unresolvable.

    This does NOT weaken the reference-side rule: a reference offering a UUID is
    still looked up by UUID only and never falls through to an id.
    """
    primary = owner_identity(section, el)
    if primary is None:
        return []
    out = [primary]
    if primary.kind == UUID_KIND:
        own_id = (el.get("id") or "").strip()
        if not own_id:
            ref_tag = _OWNER_REF_TAG.get(section)
            if ref_tag is not None and el.get("name") is None:
                ref = el.find(ref_tag)
                if ref is not None:
                    own_id = (ref.get("id") or "").strip()
        if own_id:
            out.append(CatalogIdentity(section, ID_KIND, own_id))
    return out


def owner_identity_from_xml(section: str, xml_str: str) -> CatalogIdentity | None:
    if not xml_str:
        return None
    try:
        return owner_identity(section, ET.fromstring(xml_str))
    except ET.ParseError:
        return None


def reference_identity(section: str, ref: ET.Element) -> CatalogIdentity | None:
    """Return the identity a reference element offers, or None.

    A non-empty UUID wins outright. An empty or absent UUID may fall to `id` —
    the case the FM 2026 export exhibits, where `<LayoutReference UUID="" id="4">`
    names its target by id alone.
    """
    uuid = (ref.get("UUID") or "").strip()
    if uuid:
        return CatalogIdentity(section, UUID_KIND, uuid)
    ref_id = (ref.get("id") or "").strip()
    if ref_id:
        return CatalogIdentity(section, ID_KIND, ref_id)
    return None


class CatalogIndex:
    """Identity → catalog keys, for one section.

    Built once per section from the parser's `section_xml`, whose keys are
    already unique (a repeated display name gets a `__N` suffix).
    """

    def __init__(self, section: str, xml_section: dict[str, str]):
        self.section = section
        self._by_key: dict[str, CatalogIdentity] = {}
        self._by_uuid: dict[str, list[str]] = {}
        self._by_id: dict[str, list[str]] = {}
        for xml_key, xml_str in (xml_section or {}).items():
            if not xml_str:
                continue
            try:
                el = ET.fromstring(xml_str)
            except ET.ParseError:
                continue
            identities = owner_identities(section, el)
            if not identities:
                continue
            self._by_key[xml_key] = identities[0]
            for identity in identities:
                bucket = self._by_uuid if identity.kind == UUID_KIND else self._by_id
                bucket.setdefault(identity.value, []).append(xml_key)

    def identity_of(self, xml_key: str) -> CatalogIdentity | None:
        return self._by_key.get(xml_key)

    def keys_without_identity(self, xml_section: dict[str, str]) -> list[str]:
        return [k for k in (xml_section or {}) if k not in self._by_key]

    def resolve(self, identity: CatalogIdentity | None) -> Resolution:
        if identity is None:
            return Resolution(MISSING, reason="reference offers no UUID and no id")
        if identity.kind == UUID_KIND:
            keys = self._by_uuid.get(identity.value, [])
            if not keys:
                return Resolution(MISSING, identity=identity,
                                  reason="no catalog item carries this UUID")
            # Repeated UUID = revisions of one logical object, not ambiguity.
            return Resolution(UUID_KIND, tuple(keys), identity)
        keys = self._by_id.get(identity.value, [])
        if not keys:
            return Resolution(MISSING, identity=identity,
                              reason="no catalog item carries this id")
        if len(keys) > 1:
            # Fragments of ONE logical object share its id as well as its UUID, so an
            # id claimed by several keys is only unambiguous when they all resolve to
            # the same UUID. Two id-only items sharing an id are two objects.
            primaries = {self._by_key[k] for k in keys if k in self._by_key}
            coalesced = len(primaries) == 1 and next(iter(primaries)).kind == UUID_KIND
            if not coalesced:
                return Resolution(AMBIGUOUS, tuple(keys), identity,
                                  reason="several catalog items carry this id")
        return Resolution(ID_KIND, tuple(keys), identity)

    def resolve_reference(self, ref: ET.Element) -> Resolution:
        return self.resolve(reference_identity(self.section, ref))


def build_indexes(section_xml: dict, sections: Iterable[str]) -> dict[str, CatalogIndex]:
    return {s: CatalogIndex(s, (section_xml or {}).get(s, {})) for s in sections}
