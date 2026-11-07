"""One file's table occurrences, named by the identity a relationship end offers (packet 1448).

A relationship endpoint is a ``TableOccurrenceReference`` to an occurrence in the relationship's own
file, so the occurrence's own title names it, even when that occurrence's base table lives in another
file. Identity is the catalog's own rule (``CatalogIndex``: a reference's UUID first, else its id),
the same one XRef and Statistics use, so every consumer agrees on which occurrence an end is. An end
it cannot identify is MISSING (no definition in this capture) or AMBIGUOUS (several occurrences carry
the id it offers); either way the reference's own supplied name is the only honest title, and nothing
is attached to an occurrence the reference does not identify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from corpusfm.core import safe_xml as ET
from corpusfm.core.identity import AMBIGUOUS as _AMBIGUOUS, CatalogIndex

RESOLVED, MISSING, AMBIGUOUS = "", "missing", "ambiguous"
SECTION = "TableOccurrenceCatalog"


@dataclass(frozen=True)
class OccurrenceTitles:
    index: CatalogIndex
    titles: dict = field(default_factory=dict)   # catalog key → title

    def resolve(self, ref) -> tuple[str | None, str]:
        """(catalog key, state) for one ``TableOccurrenceReference``; the key is None unless RESOLVED."""
        if ref is None:
            return None, MISSING
        res = self.index.resolve_reference(ref)
        # Fragments of one occurrence resolve together; like the item, it takes the latest name.
        keys = [k for k in res.xml_keys if self.titles.get(k)] if res.resolved else []
        if keys:
            return keys[-1], RESOLVED
        return None, AMBIGUOUS if res.kind == _AMBIGUOUS else MISSING

    def endpoint(self, ref, name_map: "dict | None" = None) -> tuple[str, str]:
        """(title, state) for one end: its occurrence's title, else the reference's supplied name."""
        key, state = self.resolve(ref)
        if key is not None:
            return self.titles[key], state
        raw = ref.get("name", "") if ref is not None else ""
        return (name_map.get(raw, raw) if name_map else raw) or "?", state


def occurrence_titles(occurrences: Iterable[tuple[str, str, str]]) -> OccurrenceTitles:
    """Index ``(catalog key, occurrence XML, title)`` triples from ONE file."""
    xml_by_key, titles = {}, {}
    for key, xml, title in occurrences:
        xml_by_key[key] = xml
        titles[key] = title
    return OccurrenceTitles(CatalogIndex(SECTION, xml_by_key), titles)


def xml_occurrence_titles(section_xml: dict, name_map: "dict | None" = None) -> OccurrenceTitles:
    """The index straight from a file's occurrence XML (``{key: xml}``), each titled by its own
    ``name`` — through an add-on package's names when one is supplied."""
    def _name(xml: str) -> str:
        try:
            raw = ET.fromstring(xml).get("name", "")
        except ET.ParseError:
            return ""
        return name_map.get(raw, raw) if name_map else raw
    return occurrence_titles((k, x, _name(x)) for k, x in (section_xml or {}).items() if x)


def artifact_occurrence_titles(artifact) -> OccurrenceTitles:
    """The index for one stored artifact, keyed by item id: each occurrence item's own name, which
    already carries supported add-on name resolution."""
    return occurrence_titles(
        (item.item_id, item.xml_sources[0].xml, item.name) for item in artifact.items.values()
        if item.section == SECTION and not item.is_folder and item.xml_sources)
