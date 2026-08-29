"""How would a caller reach ONE hosted file's data? (packet 1336)

The friction this removes is measured. To make a single working OData call against a file, a session
had to discover: the URL shape; that the file must be OPEN (a closed one answers `501`); that
`fmodata` must be enabled ON THAT FILE; the entity names; and the certificate posture. One of those is
effectively undiscoverable from the response — with `fmodata` disabled, a closed file, a wrong
password, a correct password and a non-existent file all return the identical `501` / FM `802`.

**NO RECORD, AND NO CREDENTIAL, PASSES THROUGH HERE.** The recipe is a map. The caller brings its own
account, and FileMaker's privilege model remains the only authority on what that account may read.

THREE AUTHORITY CORRECTIONS, from the Codex scope, each of which the framing had wrong:

* **Live inventory is a fresh read**, not state MCP already holds. Each call opens exactly one Admin
  API session, reads `/databases` once, and releases it in a `finally`. "Right now" would otherwise be
  backed by nothing.
* **The externally usable origin is NOT CORPUSfm's loopback storage transport.** `fms_transport`
  resolves to `localhost` with `verify_ssl=False` for the product's own private OData connection;
  neither fact is a usable or safe instruction for a remote caller. The origin comes from the
  installation's canonical external address, and normal TLS verification is the stated expectation.
* **Schema is a SNAPSHOT.** Inventory proves hosting, status and transport flags — never schema. The
  TO/field catalog comes from a stored artifact, whose identity and ingestion time are returned so the
  caller knows what it is looking at.
"""
from __future__ import annotations

from dataclasses import dataclass, field as _dcfield

#: FileMaker extended privileges that ARE data transports, mapped to what a caller would speak.
_TRANSPORTS = {"fmodata": "OData", "fmrest": "Data API (REST)", "fmxdbc": "ODBC/JDBC"}
#: Observed but not data transports. Reported as such, never as something this tool recommends.
_NON_TRANSPORT = {"fmwebdirect": "WebDirect", "fmapp": "FileMaker Pro/Go network access"}

MAX_LIMIT = 100


@dataclass
class Recipe:
    database: str = ""                       # the canonical FMS filename
    hosted: bool = False
    status: str = ""
    open: object = None                      # True / False / None when FMS reported no status
    transports: dict = _dcfield(default_factory=dict)
    other_privileges: list = _dcfield(default_factory=list)
    odata_base: str = ""
    verify_tls: bool = True
    blockers: list = _dcfield(default_factory=list)
    schema: dict = _dcfield(default_factory=dict)
    table_occurrences: list = _dcfield(default_factory=list)
    fields: list = _dcfield(default_factory=list)
    total: int = 0
    offset: int = 0
    returned: int = 0
    withheld: int = 0
    next_offset: object = None

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def map_transports(privileges) -> tuple:
    """`enabledExtPrivileges` → (data transports, other observed privileges).

    An unknown token is preserved in `other` rather than silently reclassified, so a future FMS value
    is visible instead of lost."""
    transports, other = {}, []
    for raw in privileges or ():
        token = str(raw).strip().lower()
        if not token:
            continue
        if token in _TRANSPORTS:
            transports[_TRANSPORTS[token]] = token
        else:
            other.append(_NON_TRANSPORT.get(token, token))
    return transports, other


def odata_base(external_base: str, database: str) -> str:
    """`scheme://authority` of the installation's EXTERNAL address + the encoded database segment.

    Never the loopback storage transport: that address is CORPUSfm's own private connection and is
    neither reachable nor safe as an instruction to a remote caller."""
    from urllib.parse import quote, urlsplit
    parts = urlsplit(external_base)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}/fmi/odata/v4/{quote(database, safe='')}"


def compose(record, *, external_base: str, artifact=None, artifact_meta=None,
            table_occurrence=None, limit: int = MAX_LIMIT, offset: int = 0) -> Recipe:
    """Build the recipe from facts already gathered. Pure — no network, no storage, no credential."""
    r = Recipe(database=record.filename, hosted=True, status=record.status, open=record.open)
    r.transports, r.other_privileges = map_transports(record.ext_privileges)

    if record.open is False:
        r.blockers.append(
            f"'{record.filename}' is closed on the FileMaker Server. A closed file answers no data "
            "request; an administrator must open it.")
    elif record.open is None:
        r.blockers.append("FileMaker Server reported no runtime status for this file, so whether it "
                          "is open is unknown. Nothing is assumed from that silence.")
    if "OData" not in r.transports:
        r.blockers.append(
            "OData is not enabled on this file. Enable 'Access via OData' in its extended privileges. "
            "Until then every request answers the same 501/802 regardless of credentials, which is "
            "indistinguishable from a closed file or a wrong password.")

    r.odata_base = odata_base(external_base, record.filename)
    if not r.odata_base:
        r.blockers.append("external_address_unavailable: this installation has no valid external "
                          "address, so no reachable OData URL can be constructed. Set it in Settings.")

    if artifact is None:
        r.blockers.append("schema_not_imported: no stored schema artifact matches this file, so no "
                          "table occurrences or fields can be listed.")
        return r
    if not getattr(artifact, "items", None):
        # A chosen artifact that will not load is a NAMED failure, not an absent import: "nothing was
        # imported" and "what was imported is unreadable" are different administrator actions.
        r.blockers.append("schema_unavailable: the stored schema artifact for this file could not be "
                          "read, so no table occurrences or fields can be listed.")
        return r

    r.schema = {"artifact_uuid": getattr(artifact_meta, "uuid", ""),
                "artifact_type": getattr(artifact_meta, "artifact_type", ""),
                "ingested_utc": getattr(artifact_meta, "timestamp", ""),
                "note": "a snapshot of a past import, not a claim about the live file"}

    tos = sorted({i.name for i in artifact.items.values()
                  if i.section == "TableOccurrenceCatalog" and not getattr(i, "is_folder", False)})
    if table_occurrence:
        match = [t for t in tos if t.lower() == table_occurrence.strip().lower()]
        if not match:
            r.blockers.append(f"table_occurrence_not_found: '{table_occurrence}' is not in this "
                              "artifact's table-occurrence catalog.")
            return r
        r.table_occurrences = match
        r.fields = _fields_for(artifact, match[0])
        r.total = r.returned = len(match)
        return r

    r.total = len(tos)
    page = tos[max(0, offset):max(0, offset) + max(1, min(limit, MAX_LIMIT))]
    r.table_occurrences = page
    r.offset, r.returned = offset, len(page)
    r.withheld = max(0, r.total - offset - len(page))
    r.next_offset = (offset + len(page)) if (offset + len(page)) < r.total else None
    return r


def _fields_for(artifact, to_name: str) -> list:
    """One TO's fields, with cost signals read from the primary field XML.

    `Storage` is nested SOURCE data and is not present in `ArtifactItem.attributes`, so the flags are
    parsed here. Deliberately absent: any "cheap" category — the schema cannot establish the supplied
    account's record-, table- or field-level privileges, and a calculation's complexity is not encoded
    by its type. This names schema-addressable fields and cost signals; access stays FileMaker's call.
    """
    from corpusfm.core import safe_xml as ET

    base = _base_table_for(artifact, to_name)
    if not base:
        # An external or unresolved BaseTableReference. `if base and ...` used to fall through and
        # admit EVERY field in the artifact — a false catalog presented as this TO's (found by Codex
        # review, 2026-08-26). An honest annotation beats a confident wrong answer.
        return [{"field_catalog_unavailable":
                 f"'{to_name}' has no resolvable base table in this artifact (external data source, "
                 "or a reference this snapshot does not carry), so its fields cannot be listed."}]
    out = []
    for item in artifact.items.values():
        if item.section != "FieldsForTables":
            continue
        table, _, fname = (item.name or "").partition("::")
        if table != base:
            continue
        entry = {"field": fname or item.name, "evaluation": "stored", "index": "unknown",
                 # The OBSERVED flags, not only the derived verdict: a reader checking our reasoning
                 # needs the evidence, and `unknown` must be visible as a state rather than implied.
                 "store_calculation_results": "unknown", "auto_index": "unknown"}
        try:
            el = ET.fromstring(getattr(item, "xml_str", "") or "")
        except Exception:
            out.append(entry)
            continue
        ftype = el.get("fieldType") or el.get("fieldtype") or ""
        storage = el.find("Storage")
        if storage is not None:
            stored = storage.get("storeCalculationResults")
            if stored is not None:
                entry["store_calculation_results"] = stored
            if ftype == "Calculated" and stored == "False":
                entry["evaluation"] = "per_record_on_read"
            if storage.get("autoIndex") is not None:
                entry["auto_index"] = storage.get("autoIndex")
            entry["index"] = storage.get("index") or (
                "auto" if storage.get("autoIndex") == "True" else "unknown")
        if entry["index"] == "None":
            entry["note"] = ("no stored index is declared; filtering may be expensive")
        out.append(entry)
    return out


def _base_table_for(artifact, to_name: str) -> str:
    """A TO's base table, via its `BaseTableReference`. An unresolved reference is honest, not fatal."""
    from corpusfm.core import safe_xml as ET
    for item in artifact.items.values():
        if item.section != "TableOccurrenceCatalog" or item.name != to_name:
            continue
        try:
            el = ET.fromstring(getattr(item, "xml_str", "") or "")
        except Exception:
            return ""
        ref = el.find(".//BaseTableReference")
        return ref.get("name", "") if ref is not None else ""
    return ""
