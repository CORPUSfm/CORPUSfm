"""Data shapes for cross-file analysis — external references and reconstructed interfaces.

A FileMaker solution is many .fmp12 files that reference each other. Each file declares
its outward dependencies in its OWN schema: external data sources (which sibling files it
opens), external table occurrences (tables it borrows), relationship/calc/layout/value-list
field references into those tables, and cross-file Perform Script calls. This module's types
carry (1) what one file references in its siblings, and (2) the reconstructed external
INTERFACE of a missing file, aggregated from everything its siblings ask of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ExternalDataSource:
    """One <ExternalDataSource> entry — a sibling file this file can open."""
    name: str                  # the data-source NAME used inside this file (an alias)
    ds_id: str = ""            # @id (referenced by DataSourceReference/@id)
    ds_type: str = "FileMaker" # "FileMaker" | "ODBC" | … — only FileMaker is a reconstructable sibling
    target_file: str = ""      # resolved sibling file name (basename of the path, .fmp12 stripped)
    paths: list = field(default_factory=list)  # raw UniversalPathList strings

    @property
    def is_filemaker(self) -> bool:
        return self.ds_type == "FileMaker" and bool(self.target_file)

    def to_dict(self) -> dict:
        return {"name": self.name, "ds_id": self.ds_id, "ds_type": self.ds_type,
                "target_file": self.target_file, "paths": list(self.paths)}


# ── External-data-source resolution authority (packet 1118) ────────────────────
#
# The single public authority for resolving a script step's external DataSourceReference against the
# SAME artifact's ExternalDataSourceCatalog. It reuses the existing parser (_iter_data_sources); it does
# NOT decide any target clip fact. Raw paths NEVER leave this layer — only a status, the alias/id, the
# source type, a path-alternative COUNT, and (labelled) the derived filename cross-file analysis already
# computes. `resolve()` is deterministic and refuses to guess: a reference resolves only when its id AND
# name agree on one unique FileMaker entry.

# Resolution statuses (packet 1118). None of these is permission — a resolved reference is still refused
# and the whole clip withheld until matched target captures arrive.
RESOLUTION_CATALOG_ABSENT = "catalog_absent"          # no ExternalDataSourceCatalog entry at all
RESOLUTION_REFERENCE_UNRESOLVED = "reference_unresolved"  # id/name missing/conflicting/duplicate/no-path
RESOLUTION_NON_FILEMAKER = "non_filemaker_source"     # matched entry is ODBC/other — not a FM sibling
RESOLUTION_RESOLVED_UNVERIFIED = "resolved_unverified"   # one FM entry + ordered paths; target UNVERIFIED
RESOLUTION_CURRENT_FILE = "current_file"              # id=0; existing behavior, not an external lookup


@dataclass(frozen=True)
class ExternalDataSourceEntry:
    """One immutable ExternalDataSourceCatalog entry, indexed by id AND name. `paths` (raw
    UniversalPathList alternatives) is INTERNAL — never surfaced in diagnostics; `target_file` is the
    DERIVED filename cross-file analysis already computes (clearly labelled derived by any consumer)."""
    ds_id: str
    name: str                      # the data-source alias
    ds_type: str                   # "FileMaker" | "ODBC" | other explicit value
    paths: tuple = ()              # raw UniversalPathList alternatives (order-preserving) — INTERNAL
    target_file: str = ""          # DERIVED sibling filename (as _resolve_target_file defines it)

    @property
    def is_filemaker(self) -> bool:
        return self.ds_type == "FileMaker"


@dataclass(frozen=True)
class ExternalResolution:
    """A privacy-safe resolution verdict for one external DataSourceReference. Reporting only — never
    permission. `path_alternative_count` is a COUNT, never the paths; `derived_target_file` is labelled
    derived and is NOT included in the MCP report subset (`to_report_dict`)."""
    status: str
    alias: str = ""                # the reference's data-source name (an alias, catalog-permitted metadata)
    ds_id: str = ""                # the reference's @id
    ds_type: str = ""              # matched entry source type (when matched)
    path_alternative_count: int = 0
    derived_target_file: str = ""  # INTERNAL/diagnostic; excluded from to_report_dict
    detail: str = ""               # structural only — never a path/credential/server name

    @property
    def resolved(self) -> bool:
        return self.status == RESOLUTION_RESOLVED_UNVERIFIED

    def to_report_dict(self) -> dict:
        """The bounded metadata safe to surface at the MCP boundary (packet 1118 §C): status, alias, id,
        source type, path-alternative count, structural detail. NO raw path, no derived filename."""
        return {"status": self.status, "alias": self.alias, "ds_id": self.ds_id,
                "ds_type": self.ds_type, "path_alternative_count": self.path_alternative_count,
                "detail": self.detail}


@dataclass(frozen=True)
class ExternalDataSourceIndex:
    """The single read-only authority indexing an artifact's ExternalDataSourceCatalog by id AND name.
    Built once (build_external_data_source_index); `resolve()` is pure and deterministic."""
    entries: tuple = ()            # tuple[ExternalDataSourceEntry] — every parsed entry, incl. duplicates

    def resolve(self, ref_id, ref_name) -> "ExternalResolution":
        """Resolve a step reference's (id, name) against the catalog. Resolves ONLY to one unique
        FileMaker entry that agrees on BOTH id and name — never prefers id over a conflicting name, never
        chooses the first duplicate, never coerces ODBC to FileMaker."""
        rid, rname = ref_id or "", ref_name or ""
        if not self.entries:
            return ExternalResolution(RESOLUTION_CATALOG_ABSENT, alias=rname, ds_id=rid,
                                      detail="the artifact declares no ExternalDataSourceCatalog entries")
        both = [e for e in self.entries if e.ds_id == rid and e.name == rname]
        if len(both) != 1:
            by_id = sum(1 for e in self.entries if e.ds_id == rid)
            by_name = sum(1 for e in self.entries if e.name == rname)
            if not both and (by_id or by_name):
                why = "id and name point to different catalog entries (conflict)" if (by_id and by_name) \
                    else "only the id agrees (name does not match its entry)" if by_id \
                    else "only the name agrees (id does not match its entry)"
            elif len(both) > 1:
                why = "the id and name are duplicated across more than one entry"
            else:
                why = "no catalog entry carries this id and name"
            return ExternalResolution(RESOLUTION_REFERENCE_UNRESOLVED, alias=rname, ds_id=rid,
                                      detail=f"the reference is not uniquely resolvable: {why}")
        e = both[0]
        if not e.is_filemaker:
            return ExternalResolution(RESOLUTION_NON_FILEMAKER, alias=e.name, ds_id=e.ds_id,
                                      ds_type=e.ds_type,
                                      detail="the matched catalog entry is a non-FileMaker source and "
                                             "cannot be a FileMaker sibling clip target")
        if not e.paths:
            return ExternalResolution(RESOLUTION_REFERENCE_UNRESOLVED, alias=e.name, ds_id=e.ds_id,
                                      ds_type=e.ds_type,
                                      detail="the matched FileMaker entry declares no path alternatives")
        return ExternalResolution(RESOLUTION_RESOLVED_UNVERIFIED, alias=e.name, ds_id=e.ds_id,
                                  ds_type=e.ds_type, path_alternative_count=len(e.paths),
                                  derived_target_file=e.target_file,
                                  detail="one FileMaker catalog entry and its ordered path list resolve; "
                                         "no matched external clip yet establishes the target projection")

    def single_external_path(self, ref_id, ref_name) -> "str | None":
        """The ONE raw UniversalPathList string for a reference that uniquely resolves to a FileMaker entry
        with EXACTLY one path alternative, else None (packet 1119 §B). This is the ONLY channel by which a
        raw path leaves this authority — for CLIP CONTENT on a successful external-file emission, never for
        reporting. It re-checks uniqueness independently (id AND name agree on one FileMaker entry; a single
        path); a multi-path, ambiguous, non-FileMaker, or absent entry returns None and never a chosen path."""
        rid, rname = ref_id or "", ref_name or ""
        both = [e for e in self.entries if e.ds_id == rid and e.name == rname]
        if len(both) != 1:
            return None
        e = both[0]
        if not e.is_filemaker or len(e.paths) != 1:
            return None
        return e.paths[0]


# Reference kinds — the channels through which one file reaches into another.
KIND_TABLE = "table"            # an external table occurrence (borrows a sibling's base table)
KIND_KEY_FIELD = "relationship_key"  # a field used as a join key (high-value: indexed, type-matchable)
KIND_CALC_FIELD = "calc_field"  # a field named in a calculation (TO::field)
KIND_VL_FIELD = "value_list_field"   # a field a value list draws from
KIND_LAYOUT_FIELD = "layout_field"   # a field placed on a layout
KIND_SCRIPT = "script"          # a cross-file Perform Script call


@dataclass
class ExternalRef:
    """One reference this file makes into a sibling file."""
    target_file: str            # resolved sibling file name
    data_source: str            # the data-source alias used
    kind: str                   # one of the KIND_* constants
    external_table: str = ""    # the external base table (when known); "" if not carried
    external_to: str = ""       # the external TO this ref reaches through (groups fields by table)
    external_field: str = ""    # the external field name — EMPTY for cross-file relationship/
                                # layout refs (FM stores those by id only; name leaks only via calc text)
    external_field_id: str = "" # the external field's internal id (the only field identity that
                                # survives in relationship/layout refs when the file is missing)
    external_script: str = ""   # the external script name (for script calls)
    via_section: str = ""       # the local section the reference was found in
    via_name: str = ""          # the local object making the reference
    local_join_field: str = ""  # for keys: the LOCAL field joined against (drives type inference)
    detail: str = ""            # free-form (join operator, etc.)
    # Naming HINT mined from the local context around an id-only reference (e.g. the text
    # label sitting beside the field on a sibling's layout). A CANDIDATE name, never asserted
    # as the field's identity — surfaced for a human/agent to accept or reject (#1b).
    name_hint: str = ""
    hint_source: str = ""       # layout_label | script_var (the kind of evidence)
    hint_evidence: str = ""     # human-readable provenance of the hint


@dataclass
class NameCandidate:
    """A SUGGESTED name for an id-only external field, mined from surrounding context.

    Distinct from a ReconstructedField's deterministic `name` (read from calc text, or
    inferred from a join partner). A candidate is a guess with a confidence and the evidence
    that produced it — material for a human/agent to confirm, never an assertion."""
    name: str
    confidence: float = 0.0
    source: str = ""            # join_partner | layout_label | calc | script_var (may be "a+b")
    evidence: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "confidence": round(self.confidence, 2),
                "source": self.source, "evidence": self.evidence}


@dataclass
class ExternalReferenceSet:
    """Everything one file references in its siblings."""
    source_file: str
    data_sources: list = field(default_factory=list)   # list[ExternalDataSource]
    refs: list = field(default_factory=list)           # list[ExternalRef]

    def by_target_file(self) -> dict:
        out: dict = {}
        for r in self.refs:
            out.setdefault(r.target_file, []).append(r)
        return out

    def target_files(self) -> list:
        """Distinct FileMaker sibling files this file references, sorted."""
        return sorted({r.target_file for r in self.refs if r.target_file})

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "data_sources": [d.to_dict() for d in self.data_sources],
            "refs": [vars(r) for r in self.refs],
        }


# ── Reconstruction (aggregate of many siblings' refs to one missing file) ──────

@dataclass
class ReconstructedField:
    name: str                        # field name — read from the export when present, else INFERRED
    field_id: str = ""               # the external field's internal id (its identity when name is gone)
    name_is_inferred: bool = False   # True when the name came from a join partner, not the export
    inferred_type: str = "unknown"   # Text | Number | Date | Time | Timestamp | Container | unknown
    confidence: float = 0.0          # 0..1
    rationale: str = ""              # WHY this type (honest, human-readable)
    used_as_key: bool = False        # appears in a relationship join predicate
    referenced_by: list = field(default_factory=list)  # ["File:context", …]
    candidate_names: list = field(default_factory=list)  # list[NameCandidate] — suggested names

    def to_dict(self) -> dict:
        return {"name": self.name, "field_id": self.field_id,
                "name_is_inferred": self.name_is_inferred,
                "inferred_type": self.inferred_type,
                "confidence": round(self.confidence, 2), "rationale": self.rationale,
                "used_as_key": self.used_as_key, "referenced_by": sorted(set(self.referenced_by)),
                "candidate_names": [c.to_dict() for c in self.candidate_names]}


@dataclass
class ReconstructedTable:
    name: str                          # external base table name (or inferred from the TO when not carried)
    name_is_inferred: bool = False     # True when only the TO name was available (no BaseTableReference)
    from_tos: list = field(default_factory=list)       # the external TO name(s) that mapped to this base table
    merged_from: list = field(default_factory=list)    # other inferred table-name(s) folded in (same table, different TO alias)
    fields: list = field(default_factory=list)         # list[ReconstructedField]
    referenced_by_files: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "name_is_inferred": self.name_is_inferred,
                "from_tos": sorted(set(self.from_tos)),
                "merged_from": sorted(set(self.merged_from)),
                "referenced_by_files": sorted(set(self.referenced_by_files)),
                "fields": [f.to_dict() for f in self.fields]}


@dataclass
class ReconstructedScript:
    name: str
    called_by_files: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "called_by_files": sorted(set(self.called_by_files))}


@dataclass
class ReconstructedInterface:
    """The external INTERFACE of a missing file, rebuilt from its siblings' references.

    This is the recoverable surface ONLY — the objects other files name. Everything a
    sibling never references (internal scripts, layouts, calc bodies, field options,
    unreferenced fields, CFs, value lists, privilege sets) is NOT in the data and is listed
    in `blind_spots`, never fabricated.
    """
    target_file: str
    tables: list = field(default_factory=list)         # list[ReconstructedTable]
    scripts: list = field(default_factory=list)        # list[ReconstructedScript]
    contributing_files: list = field(default_factory=list)  # siblings that referenced the target
    blind_spots: list = field(default_factory=list)    # explicit "not recoverable" notes

    @property
    def field_count(self) -> int:
        return sum(len(t.fields) for t in self.tables)

    def to_dict(self) -> dict:
        return {
            "target_file": self.target_file,
            "contributing_files": sorted(set(self.contributing_files)),
            "coverage": {"tables": len(self.tables), "fields": self.field_count,
                         "scripts": len(self.scripts),
                         "contributing_files": len(set(self.contributing_files))},
            "tables": [t.to_dict() for t in self.tables],
            "scripts": [s.to_dict() for s in self.scripts],
            "blind_spots": list(self.blind_spots),
        }
