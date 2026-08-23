"""Artifact dataclasses and serialization.

artifact_version = "1.0"

Four artifact types:
  SaveAsXML    — from FMSaveAsXML ingestion; full schema, human names
  AddonXML     — from FMAdd_on ingestion; UUID names resolved at ingestion
  MergedXML    — merge of SaveAsXML + AddonXML sharing the same root UUID;
                 richest form: resolved names, merged xref, accurate dead-ends
  fmClip       — from fmxmlsnippet FMObjectList clipboard paste; fragment only;
                 no UUID, no XRef, no dead-end analysis

Storage: artifact.json.gz (always), raw_xml.enc (optional cold storage).
Sidecar files (xref.json, dead_ends.json, gap_report.json, summaries.json)
are retired — all data is absorbed into the artifact envelope.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from corpusfm.artifact.readme import ARTIFACT_README


# The AUTHORITATIVE artifact-format version (packet 033, #1). Written on store, read on load; the
# single branch point for future heal / reabsorb / migrate decisions. Bump it when the artifact
# CONTRACT changes (a field's meaning, not a derived layer — those have their own per-layer stamps:
# render_version, gap_count_version, structure_intent["v"]). No migration logic yet by decision —
# this just makes the stamp the one place that gates "do we understand this artifact's shape?".
ARTIFACT_VERSION = "1.0"

# The version of the actionable_gaps() COUNTING logic (packet 014 #5). A record stamps the version
# its stored gap_issues was computed under; the catalog reloads a flagged row's body to recompute
# only when its stamp is behind this. BUMP this whenever actionable_gaps() changes what it counts,
# so historical rows re-heal once. (It tracks the counting logic, not the schema mappings — the
# stored CompletenessProfile is re-counted, never re-parsed.)
# v2 (packet 1121): the clip badge count now INCLUDES clip_gaps (unknown enum values + unknown elements),
# not just unknown step ids. Old clip rows re-heal once via the detail-open lazy correction.
GAP_COUNT_VERSION = 2


class ArtifactType(str, Enum):
    SAVE_AS_XML = "SaveAsXML"
    ADDON_XML = "AddonXML"
    MERGED_XML = "MergedXML"
    CLIPBOARD_XML = "fmClip"
    PATCH_XML = "PatchXML"            # FMUpgradeToolPatch deliverable — a degenerate artifact
                                      # (raw XML + metadata, no schema layers). ISV vs AI = origin.
    FMSCRIPT = "fmScript"             # a single FileMaker script as fmscript.org text (packet 033).
                                      # Low-fidelity tenant: store + view + export, no schema lenses.
    FMCALC = "fmCalc"                # a single FileMaker calculation as FM calc-expression text
                                      # (packet 033). Same low-fidelity profile as fmscript.


# ---------------------------------------------------------------------------
# Identity and provenance
# ---------------------------------------------------------------------------

@dataclass
class ArtifactIdentity:
    root_uuid: str
    file_name: str
    fm_version: str

    def to_dict(self) -> dict:
        return {
            "root_uuid": self.root_uuid,
            "file_name": self.file_name,
            "fm_version": self.fm_version,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ArtifactIdentity:
        return cls(
            root_uuid=d["root_uuid"],
            file_name=d["file_name"],
            fm_version=d["fm_version"],
        )


@dataclass
class ArtifactProvenance:
    ingested_at: str        # ISO 8601 timestamp
    catalog_version: str
    source: str             # "manual" | "job"
    corpusfm_build: str = ""  # the app build (0.{rev}) that INGESTED this — immutable birth
                              # mark, for diagnostics. NOT a heal trigger: it bumps on every
                              # commit, so it can't tell which derived layer is stale. The
                              # per-layer stamps (render_version, structure_intent["v"]) do that.

    def to_dict(self) -> dict:
        d = {
            "ingested_at": self.ingested_at,
            "catalog_version": self.catalog_version,
            "source": self.source,
        }
        if self.corpusfm_build:
            d["corpusfm_build"] = self.corpusfm_build
        return d

    @classmethod
    def from_dict(cls, d: dict) -> ArtifactProvenance:
        return cls(
            ingested_at=d["ingested_at"],
            catalog_version=d["catalog_version"],
            source=d["source"],
            corpusfm_build=d.get("corpusfm_build", ""),
        )


# ---------------------------------------------------------------------------
# Per-item structures
# ---------------------------------------------------------------------------

@dataclass
class XmlSource:
    """One excerpt of honest FM XML from a named catalog.

    xml_sources for an item are ordered primary catalog first (e.g. ScriptCatalog),
    then supplemental catalogs (e.g. StepsForScripts).  The XML is untouched
    source — UUID names in AddonXML remain as-is here; resolved names appear only
    in rendered_text and item.name.
    """
    catalog: str
    xml: str

    def to_dict(self) -> dict:
        return {"catalog": self.catalog, "xml": self.xml}

    @classmethod
    def from_dict(cls, d: dict) -> XmlSource:
        return cls(catalog=d["catalog"], xml=d["xml"])


@dataclass
class ArtifactItem:
    item_id: str            # "{section}/{fm_uuid}" or "{section}/{safe_name}"
    section: str            # e.g. "ScriptCatalog"
    name: str               # human-readable; resolved from name_map for addons
    xml_key: str            # FM XML key attribute value (may be UUID-based for addons)
    fm_uuid: str            # FM UUID of this object; empty string when absent
    attributes: dict        # pre-extracted from primary catalog entry at ingestion
    xml_sources: list       # list[XmlSource] — ordered primary-first
    rendered_text: str      # plain text; pre-computed at ingestion
    summary: Optional[str]  # AI one-liner; None until async summarization runs
    is_folder: bool
    folder_path: list       # list[str] — ancestor folder names, outermost first
    dead_end: bool          # True when not reachable from any trigger or caller
    has_calc: bool = False  # (packet 053) a field carrying a calc/auto-enter/validation formula —
                            # makes it a summarizable item; default False (only set for FieldsForTables)

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "section": self.section,
            "name": self.name,
            "xml_key": self.xml_key,
            "fm_uuid": self.fm_uuid,
            "attributes": self.attributes,
            "xml_sources": [s.to_dict() for s in self.xml_sources],
            "rendered_text": self.rendered_text,
            "summary": self.summary,
            "is_folder": self.is_folder,
            "folder_path": self.folder_path,
            "dead_end": self.dead_end,
            "has_calc": self.has_calc,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ArtifactItem:
        return cls(
            item_id=d["item_id"],
            section=d["section"],
            name=d["name"],
            xml_key=d.get("xml_key", ""),
            fm_uuid=d.get("fm_uuid", ""),
            attributes=d.get("attributes", {}),
            xml_sources=[XmlSource.from_dict(s) for s in d.get("xml_sources", [])],
            rendered_text=d.get("rendered_text", ""),
            summary=d.get("summary"),
            is_folder=d.get("is_folder", False),
            folder_path=d.get("folder_path", []),
            dead_end=d.get("dead_end", False),
            has_calc=d.get("has_calc", False),
        )


# ---------------------------------------------------------------------------
# Cross-reference graph
# ---------------------------------------------------------------------------

@dataclass
class XRefRecord:
    """One directed edge in the artifact cross-reference graph.

    JSON key for from_id is "from" (Python reserved word → renamed field).
    Both directions are queryable via Artifact.xrefs_from() / xrefs_to()
    without a separate reverse index.
    """
    from_id: str    # item_id of the source
    from_name: str
    to: str         # item_id of the target
    to_name: str
    type: str       # e.g. "ScriptReference", "FieldReference"
    # Optional edge annotations (default "" → backward-compatible with old artifacts):
    mode: str = ""  # data-flow direction for field edges: "read" | "write" | ""
    via: str = ""   # how the edge fires: a trigger event (e.g. "OnLayoutEnter"),
                    # "button", "sql", a dispatch note ("dynamic"), or a passed parameter
    cond: str = ""  # the nearest enclosing guard condition (control flow): this edge
                    # only fires when `cond` holds. "" = unconditional.

    def to_dict(self) -> dict:
        d = {
            "from": self.from_id,
            "from_name": self.from_name,
            "to": self.to,
            "to_name": self.to_name,
            "type": self.type,
        }
        if self.mode:
            d["mode"] = self.mode
        if self.via:
            d["via"] = self.via
        if self.cond:
            d["cond"] = self.cond
        return d

    @classmethod
    def from_dict(cls, d: dict) -> XRefRecord:
        return cls(
            from_id=d["from"],
            from_name=d["from_name"],
            to=d["to"],
            to_name=d["to_name"],
            type=d["type"],
            mode=d.get("mode", ""),
            via=d.get("via", ""),
            cond=d.get("cond", ""),
        )


# ---------------------------------------------------------------------------
# Completeness profile (absorbs gap report)
# ---------------------------------------------------------------------------

@dataclass
class CompletenessProfile:
    """Single record of what the ingestion pipeline knew, skipped, and left open.

    Absorbs the former gap_report.json sidecar.  Shown in Explorer About screen.
    gap_sections_unknown: catalog keys present in the imported XML but absent from
    mappings.yaml — the "unmapped" list from GapReport, used for the gap badge.
    """
    sections_present: list = field(default_factory=list)         # list[str]
    sections_absent: list = field(default_factory=list)          # list[str] — stale (non-optional)
    absent_by_design: list = field(default_factory=list)         # list[str]
    unknown_step_ids: list = field(default_factory=list)         # list[str]
    unknown_reference_types: list = field(default_factory=list)  # list[str]
    unresolved_uuids: list = field(default_factory=list)         # list[str]
    miner_skipped: list = field(default_factory=list)            # list[str]
    gap_sections_unknown: list = field(default_factory=list)     # list[str] — in XML, not in YAML
    # Render-layer diagnostics (see core/render_diagnostics.py) — what the gap
    # analyzer can't see: addon refs that didn't resolve in rendered text, known
    # steps that rendered empty (renderer xpath gap), and caught-then-degraded errors.
    unresolved_in_render: list = field(default_factory=list)     # list[str] — "Item — ref…"
    empty_renders: list = field(default_factory=list)            # list[str] — "Script — step N (Name)"
    render_errors: list = field(default_factory=list)            # list[str] — "Item: <exception>"
    # Analyzer-status (packet 072-D): names of forward-compat miners that CRASHED during ingestion
    # (e.g. "gap_analyze", "structure_mine"). A crashed miner leaves unknown_step_ids etc. EMPTY —
    # indistinguishable from "analyzed clean" unless we record it. Non-empty ⇒ "couldn't analyze",
    # NOT "clean": the gap lists are UNTRUSTWORTHY. Surfaced on the Health tab so a silent
    # fail-open can't masquerade as an all-clear.
    analyzer_failed: list = field(default_factory=list)          # list[str] — miner names
    # Clip-side drift (packet 1079) — fmClip artifacts only. An incoming clip is the ONLY FMXML that
    # comes toward us, so it is the only place clip-format drift is observable. Unknown enum values +
    # unknown elements found in a captured clip; unknown STEP IDS reuse `unknown_step_ids` above (same
    # meaning, same field — a clip's unknown id means FileMaker changed, since the clip is FM's own
    # output). `clip_elements_checked_ids` discloses that element coverage is PARTIAL by construction:
    # a shipped analyzer can only check the ids the catalog carries a skeleton for.
    clip_gaps: list = field(default_factory=list)                 # list[str]
    clip_elements_checked_ids: list = field(default_factory=list)  # list[str]
    # The clip's FM form, INFERRED from content (<DisableStepCollapsed> presence). It lives here and NOT
    # on identity.fm_version because that field means the DECLARED build (SaveAsXML's Source="26.0.1")
    # and a clip declares nothing — the FM2025/FM2026 envelopes are byte-identical. Keeping an inference
    # out of a declared-value field is the point: fm_tag() parses fm_version as a dotted version.
    clip_inferred_fm_form: str = ""

    def analysis_incomplete(self) -> bool:
        """True when a forward-compat analyzer crashed — the gap lists cannot be trusted as clean."""
        return bool(self.analyzer_failed)

    def gap_badge_count(self) -> int:
        """The persisted warning-badge count (packet 1121). Schema gaps (`actionable_gaps`) PLUS every stored
        `clip_gaps` entry (unknown enum values + unknown elements on an incoming fmClip). `clip_gaps` and
        `unknown_step_ids` are disjoint by construction (the analyzer emits step ids separately), so no double
        count. Analyzer FAILURE is a SEPARATE signal (`analysis_incomplete`), never folded into this number."""
        return self.actionable_gaps()["issues"] + len(self.clip_gaps or [])

    def actionable_gaps(self) -> dict:
        """Gaps an agent can ACT on — FM vocabulary PRESENT in the XML that the mappings/
        rendering YAML don't handle yet: unknown step IDs, unknown reference types, and
        unknown catalog sections that appear in the XML.

        ABSENT sections (``sections_absent`` — a file simply not using a feature, e.g. no
        scripts → no ScriptCatalog) are NOT gaps: that is perfectly valid XML and there is
        nothing to map. They are deliberately excluded from the count and the lists."""
        steps = list(self.unknown_step_ids or [])
        refs = list(self.unknown_reference_types or [])
        sections = list(self.gap_sections_unknown or [])
        return {
            "issues": len(steps) + len(refs) + len(sections),
            "step_ids": steps,
            "reference_types": refs,
            "sections": sections,
        }

    def to_dict(self) -> dict:
        return {
            "sections_present": self.sections_present,
            "sections_absent": self.sections_absent,
            "absent_by_design": self.absent_by_design,
            "unknown_step_ids": self.unknown_step_ids,
            "unknown_reference_types": self.unknown_reference_types,
            "unresolved_uuids": self.unresolved_uuids,
            "miner_skipped": self.miner_skipped,
            "gap_sections_unknown": self.gap_sections_unknown,
            "unresolved_in_render": self.unresolved_in_render,
            "empty_renders": self.empty_renders,
            "render_errors": self.render_errors,
            "analyzer_failed": self.analyzer_failed,
            # packet 1121 — the clip drift signal (fmClip only) must SURVIVE a store/reload round-trip; it was
            # omitted here, so a reloaded clip profile came back with clip_gaps == [] and the Health tab /
            # badge undercounted. Persist it (and its coverage disclosure) alongside the schema gaps.
            "clip_gaps": self.clip_gaps,
            "clip_elements_checked_ids": self.clip_elements_checked_ids,
            "clip_inferred_fm_form": self.clip_inferred_fm_form,
        }

    @classmethod
    def from_dict(cls, d: dict) -> CompletenessProfile:
        return cls(
            sections_present=d.get("sections_present", []),
            sections_absent=d.get("sections_absent", []),
            absent_by_design=d.get("absent_by_design", []),
            unknown_step_ids=d.get("unknown_step_ids", []),
            unknown_reference_types=d.get("unknown_reference_types", []),
            unresolved_uuids=d.get("unresolved_uuids", []),
            miner_skipped=d.get("miner_skipped", []),
            gap_sections_unknown=d.get("gap_sections_unknown", []),
            unresolved_in_render=d.get("unresolved_in_render", []),
            empty_renders=d.get("empty_renders", []),
            render_errors=d.get("render_errors", []),
            analyzer_failed=d.get("analyzer_failed", []),
            clip_gaps=d.get("clip_gaps", []),
            clip_elements_checked_ids=d.get("clip_elements_checked_ids", []),
            clip_inferred_fm_form=d.get("clip_inferred_fm_form", ""),
        )


# ---------------------------------------------------------------------------
# Structure catalog snapshot (embedded at ingestion)
# ---------------------------------------------------------------------------

@dataclass
class StructureCatalogSnapshot:
    """Compact record of FM structural vocabulary observed in this artifact.

    Embedded at ingestion time.  Records which step IDs appeared in this
    file's scripts, includes sanitized XML construction templates for those
    steps, and records the field type codes seen in base tables.

    steps_templates is keyed by str(step_id) (JSON-safe int key).  Values
    are sanitized XML template strings with typed placeholders for user
    content — the raw structure needed to construct valid fmClip XML for
    each step type that appears in this file.

    The full catalog for schema_version is loadable via
    load_structure_catalog(schema_version) when richer data is needed.
    """
    schema_version: str           # catalog version used at ingestion (e.g. "2.2.3.0")
    steps_in_catalog: int         # total known step IDs in catalog at ingestion time
    steps_observed: list          # list[int] — step IDs seen in this file's scripts
    steps_unknown: list           # list[int] — step IDs in file but not in catalog
    field_types_observed: list    # list[str] — field type codes seen in this file
    steps_templates: dict = field(default_factory=dict)  # {str(step_id): template_xml}

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "steps_in_catalog": self.steps_in_catalog,
            "steps_observed": self.steps_observed,
            "steps_unknown": self.steps_unknown,
            "field_types_observed": self.field_types_observed,
            "steps_templates": self.steps_templates,
        }

    @classmethod
    def from_dict(cls, d: dict) -> StructureCatalogSnapshot:
        return cls(
            schema_version=d.get("schema_version", ""),
            steps_in_catalog=d.get("steps_in_catalog", 0),
            steps_observed=d.get("steps_observed", []),
            steps_unknown=d.get("steps_unknown", []),
            field_types_observed=d.get("field_types_observed", []),
            steps_templates=d.get("steps_templates", {}),
        )

    @classmethod
    def empty(cls, schema_version: str = "") -> StructureCatalogSnapshot:
        return cls(
            schema_version=schema_version,
            steps_in_catalog=0,
            steps_observed=[],
            steps_unknown=[],
            field_types_observed=[],
            steps_templates={},
        )


# ---------------------------------------------------------------------------
# Artifact — top-level envelope
# ---------------------------------------------------------------------------

# Catalog sections whose items get an AI summary (packet 053/054). Lives here (the lowest layer) so
# the ingestion/storage layers can count summarizable objects without importing server.ai.summarize.
# Must match the KEYS of summarize._CATALOG_TO_FOLDER (guarded by a test). FieldsForTables is a special
# case — only calc-bearing fields count (see is_summarizable_item).
SUMMARY_SECTIONS = frozenset({
    "ScriptCatalog", "CustomFunctionsCatalog", "BaseTableCatalog", "LayoutCatalog",
    "ValueListCatalog", "RelationshipCatalog", "BaseDirectoryCatalog",
})


def is_summarizable_item(item) -> bool:
    """Whether an ArtifactItem gets summarized — a non-folder item in a summary section, or a
    calc-bearing field. Single source of truth for summarize.summarizable_items + the ingest count."""
    if getattr(item, "is_folder", False):
        return False
    section = getattr(item, "section", "")
    if section in SUMMARY_SECTIONS:
        return True
    return section == "FieldsForTables" and getattr(item, "has_calc", False)


def count_summarizable(artifact) -> int:
    """How many of an artifact's objects get summarized — stamped onto ArtifactMeta at store time
    (packet 054 F) so the detail can show it without re-counting."""
    try:
        return sum(1 for it in artifact.items.values() if is_summarizable_item(it))
    except Exception:
        return 0


def make_item_id(section: str, fm_uuid: str, name: str) -> str:
    """Build a stable item_id.

    Prefers UUID form: "{section}/{fm_uuid}".
    Falls back to name-derived form when fm_uuid is absent.
    """
    if fm_uuid:
        return f"{section}/{fm_uuid}"
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return f"{section}/{safe or 'unknown'}"


@dataclass
class Artifact:
    """Top-level artifact envelope.

    Produced by the ingestion pipeline; consumed by Explorer, Diff, git
    formatter, MCP tools, and AI harnesses.  Serialises to artifact.json.gz.

    Do not add render-time or session-level data here.  The artifact is
    written once at ingestion and read many times.  Wireframe geometry and
    graph visual positions stay in the extension that builds them.
    """
    artifact_version: str
    type: ArtifactType
    identity: ArtifactIdentity
    provenance: ArtifactProvenance
    sections: list              # list[str] — ordered section names present
    items: dict                 # dict[str, ArtifactItem] — keyed by item_id
    xref_map: list              # list[XRefRecord]
    completeness_profile: CompletenessProfile
    structure_catalog: Optional[StructureCatalogSnapshot] = None
    has_corpusfm_export: bool = False  # True when SaveToDocumentsFolder script detected at ingestion
    structure_intent: Optional[dict] = None  # rung-5 structural-intent block (see core/structure_intent)
    name_map: Optional[dict] = None     # {uuid_key: human_name} for addons; None for SaveAsXML.
                                        # Carried in the artifact so addon renders are self-contained
                                        # (no name_map.json sidecar dependency) and self-healable.
    render_version: int = 0             # stamp of the renderer that produced rendered_text; 0 = pre-stamp.
                                        # A stale stamp triggers a re-render from xml_sources (see refresh).
    # ------------------------------------------------------------------
    # Identity (packet 033, #1/#3)
    # ------------------------------------------------------------------

    def is_current_format(self) -> bool:
        """True iff this artifact's format version is the current one we fully understand.
        The branch point for heal/reabsorb/migrate (no migration logic yet)."""
        return self.artifact_version == ARTIFACT_VERSION

    # ------------------------------------------------------------------
    # XRef helpers
    # ------------------------------------------------------------------

    def xrefs_from(self, item_id: str) -> list:
        """All XRefRecords where item_id is the source."""
        return [r for r in self.xref_map if r.from_id == item_id]

    def xrefs_to(self, item_id: str) -> list:
        """All XRefRecords where item_id is the target."""
        return [r for r in self.xref_map if r.to == item_id]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        d = {
            # First key on purpose: the artifact serializes to one long line, so "first key" is
            # "first bytes" — what a reader meets before anything else. See artifact/readme.py for
            # why the text travels in the artifact rather than beside it.
            "README": ARTIFACT_README,
            "artifact_version": self.artifact_version,
            "type": self.type.value,
            "identity": self.identity.to_dict(),
            "provenance": self.provenance.to_dict(),
            "sections": self.sections,
            "items": {k: v.to_dict() for k, v in self.items.items()},
            "xref_map": [r.to_dict() for r in self.xref_map],
            "completeness_profile": self.completeness_profile.to_dict(),
        }
        if self.structure_catalog is not None:
            d["structure_catalog"] = self.structure_catalog.to_dict()
        if self.has_corpusfm_export:
            d["has_corpusfm_export"] = True
        if self.structure_intent is not None:
            d["structure_intent"] = self.structure_intent
        if self.name_map is not None:
            d["name_map"] = self.name_map
        if self.render_version:
            d["render_version"] = self.render_version
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Artifact:
        sc_raw = d.get("structure_catalog")
        return cls(
            artifact_version=d["artifact_version"],
            type=ArtifactType(d["type"]),
            identity=ArtifactIdentity.from_dict(d["identity"]),
            provenance=ArtifactProvenance.from_dict(d["provenance"]),
            sections=d["sections"],
            items={k: ArtifactItem.from_dict(v) for k, v in d["items"].items()},
            xref_map=[XRefRecord.from_dict(r) for r in d["xref_map"]],
            completeness_profile=CompletenessProfile.from_dict(d["completeness_profile"]),
            structure_catalog=StructureCatalogSnapshot.from_dict(sc_raw) if sc_raw else None,
            has_corpusfm_export=d.get("has_corpusfm_export", False),
            structure_intent=d.get("structure_intent"),
            name_map=d.get("name_map"),
            render_version=d.get("render_version", 0),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_json(cls, text: str) -> Artifact:
        return cls.from_dict(json.loads(text))

    def dump_gz(self, path: Path) -> None:
        """Write compressed artifact to path (artifact.json.gz)."""
        data = self.to_json().encode("utf-8")
        with gzip.open(path, "wb") as fh:
            fh.write(data)

    @classmethod
    def load_gz(cls, path: Path) -> Artifact:
        """Load artifact from a compressed artifact.json.gz file."""
        with gzip.open(path, "rb") as fh:
            return cls.from_json(fh.read().decode("utf-8"))
