"""Per-artifact-type capability map (packet 033, #5).

THE single source of truth for "what can this artifact type do?" — the home for the rules that
were previously scattered as inline ``artifact_type == / != 'X'`` checks across templates and
routes. Every surface (UI button gating, MCP type-awareness, reabsorb's "do we understand this
type?") should consult this map. Adding a new type = add one row here, not edit N call sites.

NOTE: distinct from ``corpusfm/extensions/export/capabilities.py`` (that is the FMUpgradeTool
*patch* capability ledger — a different concern).

Rules baked in (the 2026-06-29 framing session):
  - DOWNLOAD: every type — artifacts are loose containers; download is never gated.
  - Schema lenses (EXPLORER / DIFF / XREF / INDEX / GIT_EXPORT): the full-schema types.
  - DIFF is a same-type-only tool; this flag means "diffable against its own type".
  - MERGE: full-schema artifact types only, and NOT an already-merged one.
  - Low-fidelity tenants (fmclip / fmscript / fmcalc / patch): store + view (+ mcp-save), no
    schema lenses.
  - Unknown type → minimal {DOWNLOAD}; reabsorb's understandability gate decides accept/reject.
"""

from __future__ import annotations

# Capability vocabulary
DOWNLOAD = "download"
VIEW = "view"             # human "View" affordance (formatted/colorized text + copy/save)
INDEX = "index"           # vector / semantic search index
EXPLORER = "explorer"
DIFF = "diff"             # same-type-only comparison
MERGE = "merge"           # combine SaveAsXML + AddonXML → MergedXML
XREF = "xref"
GIT_EXPORT = "git_export"
PATCH_OPS = "patch_ops"   # ISV validate / encrypt / apply
MCP_SAVE = "mcp_save"     # agent-produced and stored via an MCP save tool

ALL_CAPABILITIES = (
    DOWNLOAD, VIEW, INDEX, EXPLORER, DIFF, MERGE, XREF, GIT_EXPORT, PATCH_OPS, MCP_SAVE,
)

# Keyed by the ArtifactType *value* (the string stored on records).
_CAPABILITIES: dict[str, set[str]] = {
    "SaveAsXML":    {DOWNLOAD, INDEX, EXPLORER, DIFF, MERGE, XREF, GIT_EXPORT},
    "AddonXML":     {DOWNLOAD, INDEX, EXPLORER, DIFF, MERGE, XREF},
    "MergedXML":    {DOWNLOAD, INDEX, EXPLORER, DIFF, XREF},
    "PatchXML":     {DOWNLOAD, VIEW, PATCH_OPS, MCP_SAVE},
    "fmClip":       {DOWNLOAD, VIEW, MCP_SAVE},
    "fmScript":     {DOWNLOAD, VIEW, MCP_SAVE},
    "fmCalc":       {DOWNLOAD, VIEW, MCP_SAVE},
}

_MINIMAL: set[str] = {DOWNLOAD}

# ── Type sets (packet 085) — the closed vocabulary that replaced has_artifact ──
# SCHEMA_TYPES carry full artifact layers (Explorer/Diff/XRef/git-export/enrichment);
# DELIVERABLE_TYPES are degenerate records (raw XML/text + metadata, view/download only).
# VISIBLE_TYPES is the catalog visibility fence: every catalog/picker/facet read filters
# `Type in VISIBLE_TYPES` — a row without a Type (mid-landing) or with an unknown Type is
# structurally invisible. No sentinel values, no exclusion chokepoints.
SCHEMA_TYPES: frozenset[str] = frozenset({"SaveAsXML", "AddonXML", "MergedXML"})
DELIVERABLE_TYPES: frozenset[str] = frozenset({"PatchXML", "fmClip", "fmScript", "fmCalc"})
VISIBLE_TYPES: frozenset[str] = SCHEMA_TYPES | DELIVERABLE_TYPES

# INDEXABLE_TYPES — types the vector index can ingest (packet 1035 backend / 1042 UI parity): schema
# artifacts PLUS the text-bearing deliverables (fmClip re-parsed per step, fmScript/fmCalc one doc).
# PatchXML is excluded (edit-ops, no searchable prose). This is the SINGLE source of truth for both the
# enqueue guard (_enqueue_sync) and the UI's `indexable` flag — the two must never drift.
INDEXABLE_TYPES: frozenset[str] = SCHEMA_TYPES | (DELIVERABLE_TYPES - frozenset({"PatchXML"}))

# The raw-file extension a deliverable downloads as (raw form) and the payload member name inside
# the portable `.artifact` envelope (packet 1034).
DELIVERABLE_EXT: dict = {"PatchXML": "patch", "fmClip": "fmclip", "fmScript": "fmscript", "fmCalc": "fmcalc"}


def is_schema_type(artifact_type) -> bool:
    """True iff this type carries full artifact layers (the old ``has_artifact`` truth)."""
    return _key(artifact_type) in SCHEMA_TYPES


def is_indexable_type(artifact_type) -> bool:
    """True iff the vector index can ingest this type (schema + fmClip/fmScript/fmCalc; NOT PatchXML).
    The one predicate behind both the enqueue guard and the UI `indexable` flag — keep them in lockstep."""
    return _key(artifact_type) in INDEXABLE_TYPES


def _key(artifact_type) -> str:
    """Accept an ArtifactType, its .value, or a bare string."""
    return getattr(artifact_type, "value", artifact_type) or ""


def capabilities_for(artifact_type) -> set[str]:
    """The capability set for a type. Unknown types get the minimal {DOWNLOAD}."""
    return set(_CAPABILITIES.get(_key(artifact_type), _MINIMAL))


def has_capability(artifact_type, capability: str) -> bool:
    return capability in capabilities_for(artifact_type)


def is_known_type(artifact_type) -> bool:
    """True iff this type is registered (the reabsorb understandability gate's first check)."""
    return _key(artifact_type) in _CAPABILITIES


def known_types() -> list[str]:
    return list(_CAPABILITIES.keys())


def capability_matrix() -> dict[str, list[str]]:
    """Serializable {type: sorted[capabilities]} for MCP / UI / data routes."""
    return {t: sorted(caps) for t, caps in _CAPABILITIES.items()}
