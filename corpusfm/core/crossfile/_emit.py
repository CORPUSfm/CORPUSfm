"""Turn a reconstructed external interface into a BUILDABLE schema stub.

The reconstruction (reconstruct_interface) yields the recoverable external surface of a
missing file. This module renders that surface into something a developer can actually
execute to recreate the file's schema:

  • OData DDL  — POST FileMaker_Tables bodies that create each base table + its NAMED
    fields on a blank, hosted .fmp12 (the documented FM table-creation path).
  • a human creation plan — the same, annotated with origin/confidence/keys + the blind
    spots and the honest relink caveat.

Only NAMED fields are emitted as creatable (the recovered keys + any calc-named fields) —
we never fabricate a name for an id-only field. Id-only fields are reported as a count so
the developer knows the table has more fields to add by hand. This is a scaffold, not an
auto-relink: cross-file refs were stored by internal id with blank names (the file was
missing at export), so FM will not silently re-match a recreated field — the developer
recreates the schema from this stub and re-points/repairs the siblings' relationships
using the recovered KEY names. (The chair principle: we rebuild the interface; the human
supplies what only they can.)

Public API:
    build_schema_stub(iface) -> SchemaStub
    render_stub_plan(stub) -> str          # human-readable creation plan
    render_stub_ddl(stub) -> str           # JSON array of FileMaker_Tables create bodies
"""

from __future__ import annotations

import json
import uuid as _uuidlib
from dataclasses import dataclass, field
from xml.sax.saxutils import quoteattr

from ._reconstruct import _is_placeholder

# FM type → OData DDL column type (Claris OData "Modify schema" guide).
_ODATA_TYPE = {
    "Text": "varchar(255)", "Number": "numeric", "Date": "date", "Time": "time",
    "Timestamp": "timestamp", "Container": "blob", "unknown": "varchar(255)",
}

# FM inferred type → the word FM stores in a Field's @datatype (verified against real exports:
# container is "Binary", timestamp is "TimeStamp"). Unknown falls back to Text — the safe,
# always-creatable default; the stub already flags low-confidence types as guesses.
_FM_DATATYPE = {
    "Text": "Text", "Number": "Number", "Date": "Date", "Time": "Time",
    "Timestamp": "TimeStamp", "Container": "Binary", "unknown": "Text",
}


@dataclass
class StubField:
    name: str
    fm_type: str = "unknown"           # Text | Number | … | unknown
    odata_type: str = "varchar(255)"
    is_key: bool = False
    origin: str = "recovered"          # recovered (read from calc) | inferred (from join partner)
    field_id: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {"name": self.name, "fm_type": self.fm_type, "odata_type": self.odata_type,
                "is_key": self.is_key, "origin": self.origin, "field_id": self.field_id,
                "confidence": round(self.confidence, 2)}


@dataclass
class StubTable:
    name: str
    name_is_inferred: bool = False
    fields: list = field(default_factory=list)          # creatable (named) StubFields
    unnamed_field_ids: list = field(default_factory=list)  # referenced by id only — must be named by hand
    # field_id → [candidate dicts]: context-mined SUGGESTED names for an id-only field (#1b).
    unnamed_field_candidates: dict = field(default_factory=dict)
    from_tos: list = field(default_factory=list)
    merged_from: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "name_is_inferred": self.name_is_inferred,
                "fields": [f.to_dict() for f in self.fields],
                "unnamed_field_ids": list(self.unnamed_field_ids),
                "unnamed_field_candidates": {k: list(v) for k, v in self.unnamed_field_candidates.items()},
                "from_tos": sorted(set(self.from_tos)),
                "merged_from": sorted(set(self.merged_from))}


@dataclass
class SchemaStub:
    target_file: str
    tables: list = field(default_factory=list)          # list[StubTable]
    scripts: list = field(default_factory=list)         # external script names the file must publish
    contributing_files: list = field(default_factory=list)
    blind_spots: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"target_file": self.target_file,
                "tables": [t.to_dict() for t in self.tables],
                "scripts": list(self.scripts),
                "contributing_files": sorted(set(self.contributing_files)),
                "blind_spots": list(self.blind_spots)}


def build_schema_stub(iface) -> SchemaStub:
    """Project a ReconstructedInterface onto a creatable schema stub."""
    stub = SchemaStub(target_file=iface.target_file,
                      contributing_files=list(iface.contributing_files),
                      blind_spots=list(iface.blind_spots))
    for t in iface.tables:
        st = StubTable(name=t.name, name_is_inferred=t.name_is_inferred,
                       from_tos=list(t.from_tos), merged_from=list(t.merged_from))
        for f in t.fields:
            if _is_placeholder(f.name):
                if f.field_id:
                    st.unnamed_field_ids.append(f.field_id)
                    if f.candidate_names:
                        st.unnamed_field_candidates[f.field_id] = [c.to_dict() for c in f.candidate_names]
                continue
            st.fields.append(StubField(
                name=f.name, fm_type=f.inferred_type,
                odata_type=_ODATA_TYPE.get(f.inferred_type, "varchar(255)"),
                is_key=f.used_as_key,
                origin="inferred" if f.name_is_inferred else "recovered",
                field_id=f.field_id, confidence=f.confidence))
        stub.tables.append(st)
    stub.scripts = [s.name for s in iface.scripts]
    return stub


def render_stub_ddl(stub) -> str:
    """JSON array of FileMaker_Tables create bodies — one per table, NAMED fields only.

    Apply against a blank, hosted target file:
        POST /fmi/odata/v4/<NewFile>/FileMaker_Tables   (body = each array element)
    """
    bodies = []
    for t in stub.tables:
        cols = [{"name": f.name, "type": f.odata_type} for f in t.fields]
        bodies.append({"tableName": t.name, "fields": cols})
    return json.dumps(bodies, indent=2)


def _u() -> str:
    """A fresh upper-case FM-style UUID."""
    return str(_uuidlib.uuid4()).upper()


def _safe_fm_name(name: str, fallback: str) -> str:
    """A usable FM file/object name: strip a .fmp12 suffix and FM-illegal path chars."""
    n = (name or "").strip()
    if n.lower().endswith(".fmp12"):
        n = n[:-6]
    for ch in '/\\:*?"<>|':
        n = n.replace(ch, "_")
    n = n.strip() or fallback
    return n


def _uuid_el(indent: str) -> str:
    return f'{indent}<UUID>{_u()}</UUID>'


def render_stub_saveasxml(stub, *, file_name: str = "") -> str:
    """Render the reconstruction stub as a COMPLETE FMSaveAsXML that FMUpgradeTool 2026's
    `--generateDBFile` can materialize into a hostable .fmp12 (no FileMaker Pro).

    Emits the minimal-but-complete envelope an empty-data schema needs: a `<Structure><AddAction>`
    carrying a BaseTableCatalog (one BaseTable per recovered table), a TableOccurrenceCatalog
    (one Local TO per table, so the file has a usable relationship-graph anchor), and a
    FieldsForTables (one FieldCatalog per table with its NAMED fields). Only NAMED fields are
    emitted — id-only fields are never fabricated (the same scaffold contract as the plan/DDL).

    This is the origination path: feed the result to `generate_db_file(source_xml=...)`. The
    materialized file carries the recovered tables/fields with FRESH UUIDs — it does NOT
    re-link the siblings (cross-file refs were stored by internal id with blank names); the
    developer rewires the siblings by the recovered KEY names, exactly as the plan states.
    """
    fname = _safe_fm_name(file_name or stub.target_file, "Reconstructed")
    root_uuid = _u()
    bt_lines, to_lines, fft_lines = [], [], []
    bt_id, to_id = 129, 1065089

    for t in stub.tables:
        tname = t.name
        bt_uuid = _u()
        bt_lines += [
            '\t\t\t\t<SortOrder>1</SortOrder>',
            '\t\t\t\t<CustomOrderList>',
            f'\t\t\t\t\t<key>{bt_id}</key>',
            '\t\t\t\t</CustomOrderList>',
            _uuid_el('\t\t\t\t'),
            '\t\t\t\t<TagList></TagList>',
            f'\t\t\t\t<BaseTable id="{bt_id}" comment="" name={quoteattr(tname)}>',
            f'\t\t\t\t\t<UUID>{bt_uuid}</UUID>',
            '\t\t\t\t\t<TagList></TagList>',
            '\t\t\t\t</BaseTable>',
        ]
        to_lines += [
            '\t\t\t\t<CustomOrderList>',
            f'\t\t\t\t\t<key>{to_id}</key>',
            '\t\t\t\t</CustomOrderList>',
            _uuid_el('\t\t\t\t'),
            '\t\t\t\t<TagList></TagList>',
            f'\t\t\t\t<TableOccurrence View="Full" height="0" id="{to_id}" name={quoteattr(tname)} type="Local">',
            _uuid_el('\t\t\t\t\t'),
            '\t\t\t\t\t<BaseTableSourceReference type="BaseTableReference">',
            f'\t\t\t\t\t\t<BaseTableReference id="{bt_id}" name={quoteattr(tname)} UUID="{bt_uuid}"></BaseTableReference>',
            '\t\t\t\t\t</BaseTableSourceReference>',
            '\t\t\t\t\t<CoordRect top="0" left="0" bottom="0" right="0"></CoordRect>',
            '\t\t\t\t\t<Color red="119" green="119" blue="119" alpha="1.00"></Color>',
            '\t\t\t\t\t<TagList></TagList>',
            '\t\t\t\t</TableOccurrence>',
        ]
        # FieldsForTables: one FieldCatalog per table
        named = list(t.fields)
        fc = [
            '\t\t\t\t<FieldCatalog>',
            '\t\t\t\t\t<SortOrder>1</SortOrder>',
            '\t\t\t\t\t<CustomOrderList>',
        ]
        for k in range(1, len(named) + 1):
            fc.append(f'\t\t\t\t\t\t<key>{k}</key>')
        fc += [
            '\t\t\t\t\t</CustomOrderList>',
            _uuid_el('\t\t\t\t\t'),
            '\t\t\t\t\t<TagList></TagList>',
            f'\t\t\t\t\t<BaseTableReference id="{bt_id}" name={quoteattr(tname)} UUID="{bt_uuid}"></BaseTableReference>',
            f'\t\t\t\t\t<ObjectList membercount="{len(named)}">',
        ]
        for fi, f in enumerate(named, start=1):
            datatype = _FM_DATATYPE.get(f.fm_type, "Text")
            fc += [
                f'\t\t\t\t\t\t<Field id="{fi}" name={quoteattr(f.name)} fieldtype="Normal" datatype="{datatype}" comment="">',
                f'\t\t\t\t\t\t\t<UUID>{_u()}</UUID>',
                '\t\t\t\t\t\t\t<AutoEnter type="" prohibitModification="False"></AutoEnter>',
                '\t\t\t\t\t\t\t<Validation alwaysValidate="False" type="OnlyDuringDataEntry" allowOverride="True" notEmpty="False" unique="False" existing="False"></Validation>',
                '\t\t\t\t\t\t\t<Storage global="False" maxRepetitions="1"></Storage>',
                '\t\t\t\t\t\t\t<TagList></TagList>',
                '\t\t\t\t\t\t</Field>',
            ]
        fc += ['\t\t\t\t\t</ObjectList>', '\t\t\t\t</FieldCatalog>']
        fft_lines += fc
        bt_id += 1
        to_id += 1

    n_tables = len(stub.tables)
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<FMSaveAsXML version="2.2.3.0" Source="22.0.1" File="{_safe_fm_name(fname, "Reconstructed")}.fmp12" '
        f'UUID="{root_uuid}" locale="English" Has_DDR_INFO="True">',
        '\t<Structure membercount="1">',
        '\t\t<AddAction membercount="3">',
        f'\t\t\t<BaseTableCatalog membercount="{n_tables}">',
        *bt_lines,
        '\t\t\t</BaseTableCatalog>',
        f'\t\t\t<TableOccurrenceCatalog membercount="{n_tables}">',
        *to_lines,
        '\t\t\t</TableOccurrenceCatalog>',
        f'\t\t\t<FieldsForTables membercount="{n_tables}">',
        *fft_lines,
        '\t\t\t</FieldsForTables>',
        '\t\t</AddAction>',
        '\t</Structure>',
        '</FMSaveAsXML>',
    ]
    return "\n".join(parts)


def render_stub_plan(stub) -> str:
    """Human-readable creation plan for the missing file's recoverable schema."""
    d = stub.to_dict()
    lines = [
        f"BUILDABLE SCHEMA STUB: {d['target_file']}",
        f"(from siblings: {', '.join(d['contributing_files']) or '(none)'})",
        "",
        "Recreate this file by creating the tables + NAMED fields below (e.g. on a blank",
        "hosted .fmp12 via OData DDL — see the DDL output), then repair the siblings'",
        "relationships using the recovered KEY names. This is a scaffold: cross-file refs",
        "were stored by internal id with blank names, so FM will NOT auto-rematch a",
        "recreated field — the key names are what let you rewire by hand.",
        "",
    ]
    for t in d["tables"]:
        tag = " [name inferred from TO]" if t["name_is_inferred"] else ""
        lines.append(f"TABLE {t['name']}{tag}")
        if t["merged_from"]:
            lines.append(f"  (consolidated TO aliases: {', '.join(t['merged_from'])})")
        if not t["fields"]:
            lines.append("  (no NAMED fields recovered — only id-only references)")
        for f in t["fields"]:
            key = " ★KEY" if f["is_key"] else ""
            lines.append(
                f"  - {f['name']}{key}  {f['odata_type']}  "
                f"[{f['origin']}, conf {f['confidence']:.2f}]")
        if t["unnamed_field_ids"]:
            cands = t.get("unnamed_field_candidates", {})
            plain = [i for i in t["unnamed_field_ids"] if i not in cands]
            lines.append(f"  + {len(t['unnamed_field_ids'])} more field(s) referenced by id only "
                         f"(name by hand):")
            for fid in t["unnamed_field_ids"]:
                if fid in cands:
                    sugg = "; ".join(f"{c['name']} (conf {c['confidence']:.2f}, {c['source']})"
                                     for c in cands[fid][:3])
                    lines.append(f"      #{fid} — suggested: {sugg}")
            if plain:
                lines.append(f"      no name signal: {', '.join('#' + i for i in plain)}")
        lines.append("")
    if d["scripts"]:
        lines.append("SCRIPTS the file must publish (called cross-file — create as stubs):")
        for s in d["scripts"]:
            lines.append(f"  - {s}")
        lines.append("")
    lines.append("NOT RECOVERABLE (do not fabricate):")
    for b in d["blind_spots"]:
        lines.append(f"  • {b}")
    return "\n".join(lines)
