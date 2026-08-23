"""Object evidence — neutral, query-time signals about FM schema objects.

This is the Python half of the evidence workflow:

    Python finds evidence. MCP serves evidence. AI explains evidence. Human confirms meaning.

It reports only what the artifact already carries (xref edges, dead-end flags, names) — counts and
examples, never an interpretation. It deliberately does NOT label anything "important", "bad",
"obsolete", or "safe to delete": a misleading FM name does not reveal intent, so the conclusion is
the human's (or the agent's, with the human confirming), not Python's. Nothing here is written back
to the artifact; every signal is computed on demand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Neutral name-attention tokens — surfaced as `name_attention_token`, NOT as "bad name". A match is
# a reason to LOOK, not a verdict. Alpha tokens match on a word boundary (so "dev" doesn't fire on
# "device"); the two sigil markers (z_/zz) are FM "park it at the bottom of the list" conventions.
_ATTENTION_WORDS = ["temp", "tmp", "old", "backup", "bak", "copy", "test", "dev"]
_ATTENTION_WORD_RE = re.compile(r"(?<![a-z])(" + "|".join(_ATTENTION_WORDS) + r")(?![a-z])", re.IGNORECASE)

_DEAD_END_BONUS = 3
_ATTENTION_TOKEN_BONUS = 2


@dataclass
class EvidenceResult:
    item_id: str
    section: str
    name: str
    type: str
    dead_end: bool
    inbound_count: int
    outbound_count: int
    inbound_by_type: dict
    outbound_by_type: dict
    inbound_examples: list   # list[dict]: {section, name, id, type, via, cond}
    outbound_examples: list
    name_attention_tokens: list
    attention_score: int

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id, "section": self.section, "name": self.name,
            "type": self.type, "dead_end": self.dead_end,
            "inbound_count": self.inbound_count, "outbound_count": self.outbound_count,
            "inbound_by_type": self.inbound_by_type, "outbound_by_type": self.outbound_by_type,
            "inbound_examples": self.inbound_examples, "outbound_examples": self.outbound_examples,
            "name_attention_tokens": self.name_attention_tokens,
            "attention_score": self.attention_score,
        }


def _section_of(item_id: str) -> str:
    return item_id.split("/", 1)[0] if "/" in item_id else ""


def _item_type(item) -> str:
    """Best-effort object 'type' from pre-extracted attributes, else "" (the section already carries
    the kind). Never inferred — only what ingestion already pulled from the primary catalog entry."""
    attrs = getattr(item, "attributes", {}) or {}
    for k in ("type", "fieldType", "dataType", "scriptType"):
        v = attrs.get(k)
        if v:
            return str(v)
    return ""


def name_attention_tokens(name: str) -> list:
    """The neutral attention tokens present in a name (deduped, order-stable). Empty when none."""
    lowered = (name or "").lower()
    found: list[str] = []
    for m in _ATTENTION_WORD_RE.finditer(name or ""):
        tok = m.group(1).lower()
        if tok not in found:
            found.append(tok)
    if lowered.startswith("z_") and "z_" not in found:
        found.append("z_")
    if "zz" in lowered and "zz" not in found:
        found.append("zz")
    return found


def find_artifact_item(artifact, query: str, section: str | None = None):
    """Resolve a single ArtifactItem by id or name, or None.

    Match order: exact item_id → exact name → case-insensitive name. When `section` is given it
    scopes every match (and disambiguates same-name objects across catalogs)."""
    q = (query or "").strip()
    if not q:
        return None
    items = list(artifact.items.values())
    if section:
        items = [it for it in items if it.section == section]

    # exact item_id (id already encodes section, so it's unambiguous)
    for it in items:
        if it.item_id == q:
            return it
    # exact name
    for it in items:
        if it.name == q:
            return it
    # case-insensitive name
    ql = q.lower()
    for it in items:
        if (it.name or "").lower() == ql:
            return it
    return None


def _edge_examples(records, *, inbound: bool, limit: int) -> tuple[list, dict]:
    """(examples, by_type_counts) for a list of XRefRecords, from the perspective of the queried
    object. inbound → describe the SOURCE end; outbound → describe the TARGET end."""
    examples: list[dict] = []
    by_type: dict[str, int] = {}
    for r in records:
        by_type[r.type] = by_type.get(r.type, 0) + 1
        if len(examples) < limit:
            other_id = r.from_id if inbound else r.to
            other_name = r.from_name if inbound else r.to_name
            ex = {"section": _section_of(other_id), "name": other_name, "id": other_id, "type": r.type}
            if getattr(r, "via", ""):
                ex["via"] = r.via
            if getattr(r, "cond", ""):
                ex["cond"] = r.cond
            examples.append(ex)
    return examples, by_type


def object_evidence(artifact, item, limit: int = 20) -> EvidenceResult:
    """Neutral evidence for one object. Counts are full; examples are capped at `limit`."""
    inbound = artifact.xrefs_to(item.item_id)
    outbound = artifact.xrefs_from(item.item_id)
    in_ex, in_by = _edge_examples(inbound, inbound=True, limit=limit)
    out_ex, out_by = _edge_examples(outbound, inbound=False, limit=limit)
    tokens = name_attention_tokens(item.name)
    score = (len(inbound) + len(outbound)
             + (_DEAD_END_BONUS if item.dead_end else 0)
             + _ATTENTION_TOKEN_BONUS * len(tokens))
    return EvidenceResult(
        item_id=item.item_id, section=item.section, name=item.name, type=_item_type(item),
        dead_end=bool(item.dead_end), inbound_count=len(inbound), outbound_count=len(outbound),
        inbound_by_type=in_by, outbound_by_type=out_by,
        inbound_examples=in_ex, outbound_examples=out_ex,
        name_attention_tokens=tokens, attention_score=score,
    )


# ── change-impact evidence ──────────────────────────────────────────────────────
# "If I touch this object, what appears to depend on it?" — the SAME observed xref edges, seen
# through a blast-radius lens: DEPENDENTS (inbound — objects that reference this one, so they're
# affected if it changes/renames/disappears) and DEPENDENCIES (outbound — what this one relies on,
# affected if THOSE change). Still neutral: counts, channels, examples, and a per-edge provenance
# label (observed/inferred) — never "safe to change/delete". The conclusion is the human's.


def _edge_channel(via: str) -> str:
    """How a dependency edge fires, from its (already-extracted) `via` annotation. Neutral, factual:
    a trigger event → 'trigger'; 'button'/'sql'/'dynamic' as-is; empty → 'direct'; else 'other'."""
    v = (via or "").strip()
    if not v:
        return "direct"
    if v in ("button", "sql", "dynamic"):
        return v
    if v.startswith("On"):          # FM script-trigger events: OnLayoutEnter, OnObjectModify, …
        return "trigger"
    return "other"


def _edge_confidence(record) -> str:
    """Provenance of the edge, NOT a value judgement: 'inferred' for heuristically-derived linkages
    (ExecuteSQL parsing, dynamic 'Perform Script by Name' dispatch), else 'observed' (the schema
    records the reference explicitly). An unresolved reference yields no edge, so nothing is labelled
    'unknown' here — absence of an edge is reported as a zero count, not a guessed dependency."""
    return "inferred" if _edge_channel(getattr(record, "via", "")) in ("sql", "dynamic") else "observed"


def _impact_breakdown(records, *, inbound: bool, limit: int):
    """(examples, by_type, by_section, by_channel, confidence_counts) for a set of edges, described
    from the OTHER end (inbound → the source that depends on us; outbound → the target we depend on)."""
    examples: list[dict] = []
    by_type: dict[str, int] = {}
    by_section: dict[str, int] = {}
    by_channel: dict[str, int] = {}
    conf_counts: dict[str, int] = {}
    for r in records:
        other_id = r.from_id if inbound else r.to
        other_name = r.from_name if inbound else r.to_name
        sec = _section_of(other_id)
        chan = _edge_channel(getattr(r, "via", ""))
        conf = _edge_confidence(r)
        by_type[r.type] = by_type.get(r.type, 0) + 1
        by_section[sec] = by_section.get(sec, 0) + 1
        by_channel[chan] = by_channel.get(chan, 0) + 1
        conf_counts[conf] = conf_counts.get(conf, 0) + 1
        if len(examples) < limit:
            ex = {"section": sec, "name": other_name, "id": other_id, "type": r.type,
                  "channel": chan, "confidence": conf}
            if getattr(r, "mode", ""):
                ex["mode"] = r.mode
            if getattr(r, "via", ""):
                ex["via"] = r.via
            if getattr(r, "cond", ""):
                ex["cond"] = r.cond
            examples.append(ex)
    return examples, by_type, by_section, by_channel, conf_counts


@dataclass
class ChangeImpactResult:
    item_id: str
    section: str
    name: str
    type: str
    dependents_count: int          # inbound — objects affected if THIS changes/disappears
    dependencies_count: int        # outbound — objects THIS relies on (affected if THEY change)
    dependents_by_type: dict
    dependents_by_section: dict
    dependents_by_channel: dict
    dependencies_by_type: dict
    dependencies_by_section: dict
    dependents_examples: list
    dependencies_examples: list
    confidence_summary: dict       # {observed: n, inferred: m} across all edges shown

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id, "section": self.section, "name": self.name, "type": self.type,
            "dependents_count": self.dependents_count,
            "dependencies_count": self.dependencies_count,
            "dependents_by_type": self.dependents_by_type,
            "dependents_by_section": self.dependents_by_section,
            "dependents_by_channel": self.dependents_by_channel,
            "dependencies_by_type": self.dependencies_by_type,
            "dependencies_by_section": self.dependencies_by_section,
            "dependents_examples": self.dependents_examples,
            "dependencies_examples": self.dependencies_examples,
            "confidence_summary": self.confidence_summary,
        }


def change_impact_evidence(artifact, item, limit: int = 20) -> ChangeImpactResult:
    """Neutral change-impact evidence for one object: who depends on it (inbound) and what it depends
    on (outbound), from the SAME observed xref edges. Counts are full; examples capped at `limit`."""
    inbound = artifact.xrefs_to(item.item_id)
    outbound = artifact.xrefs_from(item.item_id)
    dep_ex, dep_by_t, dep_by_s, dep_by_c, dep_conf = _impact_breakdown(inbound, inbound=True, limit=limit)
    use_ex, use_by_t, use_by_s, _use_c, use_conf = _impact_breakdown(outbound, inbound=False, limit=limit)
    conf = {}
    for d in (dep_conf, use_conf):
        for k, v in d.items():
            conf[k] = conf.get(k, 0) + v
    return ChangeImpactResult(
        item_id=item.item_id, section=item.section, name=item.name, type=_item_type(item),
        dependents_count=len(inbound), dependencies_count=len(outbound),
        dependents_by_type=dep_by_t, dependents_by_section=dep_by_s, dependents_by_channel=dep_by_c,
        dependencies_by_type=use_by_t, dependencies_by_section=use_by_s,
        dependents_examples=dep_ex, dependencies_examples=use_ex,
        confidence_summary=conf,
    )


def artifact_attention_candidates(artifact, limit: int = 20, section: str | None = None) -> list:
    """Top objects by `attention_score`, descending. Triage only — NOT business importance. Folders
    are skipped (they aren't schema objects). `section` optionally restricts the scan."""
    results: list[EvidenceResult] = []
    for it in artifact.items.values():
        if getattr(it, "is_folder", False):
            continue
        if section and it.section != section:
            continue
        results.append(object_evidence(artifact, it, limit=3))
    results.sort(key=lambda e: (e.attention_score, e.inbound_count + e.outbound_count, e.name), reverse=True)
    return results[:limit]


# ── artifact-level attention signals ─────────────────────────────────────────────
# "What parts of this artifact deserve a human/AI look FIRST?" — a triage SCAN, not a verdict. It
# groups objects under a small set of NEUTRAL signal kinds, each derived purely from the evidence the
# artifact already carries (xref degree, reachability, names) and each pointing back to concrete
# objects + their numbers. Within a kind, entries are ranked by the numeric strength that DEFINES the
# kind (degree, token count, group size) — never by an inferred meaning. Nothing is "important",
# "unused", "obsolete", or "safe to delete": a signal is a reason to look, the conclusion is the
# human's. Query-time only; nothing is written back.

# FM "park it at the bottom of the list" naming sigils — a convention, not a status.
_SIGIL_TOKENS = ("z_", "zz")


def _dup_name_key(name: str) -> str:
    """Normalize a name for duplicate-looking detection: lowercased + trimmed, with an OBVIOUS
    duplication suffix removed (' (2)', ' copy', ' copy 2', '_copy', ' 2', '_2'). Conservative — only
    strips a clear copy/number tail, so 'Process Order' and 'Process Order copy 2' collide while
    distinct names stay distinct. Empty in → empty out (skipped by the caller)."""
    n = (name or "").strip().lower()
    n = re.sub(r"\s*\(\d+\)$", "", n)               # "x (2)"
    n = re.sub(r"[ _-]+copy(\s*\d+)?$", "", n)      # "x copy", "x copy 2", "x_copy"
    n = re.sub(r"[ _-]+\d+$", "", n)                # "x 2", "x_2"
    return n.strip()


@dataclass
class AttentionSignal:
    kind: str            # neutral signal id, e.g. "high_reference_count"
    description: str     # what the signal IS (factual), with the look-don't-conclude caveat
    items: list          # list[dict] — each points back to an object + its evidence numbers

    def to_dict(self) -> dict:
        return {"kind": self.kind, "description": self.description, "items": self.items}


@dataclass
class ArtifactAttentionResult:
    object_count: int           # non-folder objects scanned (after the optional section filter)
    section: str                # "" when whole-artifact
    signals: list               # list[AttentionSignal]

    def to_dict(self) -> dict:
        return {"object_count": self.object_count, "section": self.section,
                "signals": [s.to_dict() for s in self.signals]}


def artifact_attention_signals(artifact, limit: int = 10, section: str | None = None) -> ArtifactAttentionResult:
    """Neutral artifact-level triage signals (see the section comment above). `limit` caps EACH
    signal's entry list; `section` optionally restricts the scan. Folders are skipped."""
    rows: list[EvidenceResult] = []
    for it in artifact.items.values():
        if getattr(it, "is_folder", False):
            continue
        if section and it.section != section:
            continue
        rows.append(object_evidence(artifact, it, limit=0))   # counts only — no examples

    def _entry(e: EvidenceResult, **extra) -> dict:
        d = {"item_id": e.item_id, "section": e.section, "name": e.name,
             "inbound": e.inbound_count, "outbound": e.outbound_count}
        if e.dead_end:
            d["dead_end"] = True
        d.update(extra)
        return d

    signals: list[AttentionSignal] = []

    # 1. high_reference_count — the most-connected objects (total degree). The NEUTRAL framing of
    #    "important": a high reference count is a reason to look, not a statement of value. The
    #    inbound count travels in each entry, so blast radius is visible (per-object: change-impact).
    by_degree = sorted((e for e in rows if (e.inbound_count + e.outbound_count) > 0),
                       key=lambda e: (e.inbound_count + e.outbound_count, e.inbound_count, e.name),
                       reverse=True)[:limit]
    if by_degree:
        signals.append(AttentionSignal(
            "high_reference_count",
            "Objects with the most xref edges (inbound + outbound). A high reference count is a "
            "reason to look first; it is not a measure of value.",
            [_entry(e, degree=e.inbound_count + e.outbound_count) for e in by_degree]))

    # 2. no_observed_dependents — zero inbound xrefs. Orphan CANDIDATE, with the standing caveat that
    #    dynamic dispatch / plug-ins / external callers leave no recorded edge.
    orphans = sorted((e for e in rows if e.inbound_count == 0),
                     key=lambda e: (e.dead_end, e.outbound_count, e.name), reverse=True)[:limit]
    if orphans:
        signals.append(AttentionSignal(
            "no_observed_dependents",
            "Objects with zero inbound xrefs — nothing recorded references them. Dynamic dispatch, "
            "plug-ins, and external/Data-API callers leave no edge, so this is a prompt to check, "
            "not a conclusion.",
            [_entry(e) for e in orphans]))

    # 3. name_attention_token — names carrying a neutral attention token (temp/old/test/backup/…).
    tokened = [(e, name_attention_tokens(e.name)) for e in rows]
    tokened = sorted(((e, t) for e, t in tokened if t),
                     key=lambda p: (len(p[1]), p[0].inbound_count + p[0].outbound_count, p[0].name),
                     reverse=True)[:limit]
    if tokened:
        signals.append(AttentionSignal(
            "name_attention_token",
            "Objects whose name contains a neutral attention token (temp/tmp/old/backup/bak/copy/"
            "test/dev/z_/zz). A naming convention is a reason to look, never proof of intent.",
            [_entry(e, tokens=t) for e, t in tokened]))

    # 4. duplicate_looking_name — >=2 objects in the SAME section whose names match after trimming an
    #    obvious copy/number suffix. A near-duplicate name is a reason to look (it may be deliberate).
    groups: dict = {}
    for e in rows:
        key = _dup_name_key(e.name)
        if not key:
            continue
        groups.setdefault((e.section, key), []).append(e)
    dup_groups = sorted(((k, g) for k, g in groups.items() if len(g) >= 2),
                        key=lambda kg: (len(kg[1]), kg[0][0], kg[0][1]), reverse=True)[:limit]
    if dup_groups:
        dup_items = [{
            "section": sec, "normalized_name": key, "count": len(g),
            "members": [{"item_id": e.item_id, "name": e.name,
                         "inbound": e.inbound_count, "outbound": e.outbound_count} for e in g[:6]],
        } for (sec, key), g in dup_groups]
        signals.append(AttentionSignal(
            "duplicate_looking_name",
            "Sets of two or more objects in the same section whose names match after trimming an "
            "obvious copy/number suffix. A near-duplicate name is a reason to look; it may be "
            "intentional.",
            dup_items))

    # 5. sigil_named_with_dependencies — a 'park at the bottom' sigil (z_/zz) name that STILL has
    #    outbound dependencies (so it is not inert). The neutral form of "hidden/system-looking with
    #    dependencies": the sigil is a convention, not a status.
    sigil = sorted((e for e in rows
                    if any(t in _SIGIL_TOKENS for t in name_attention_tokens(e.name)) and e.outbound_count > 0),
                   key=lambda e: (e.outbound_count, e.name), reverse=True)[:limit]
    if sigil:
        signals.append(AttentionSignal(
            "sigil_named_with_dependencies",
            "Objects whose name carries a 'park at the bottom' sigil (z_/zz) yet still have outbound "
            "dependencies, i.e. not inert. Neutral: the sigil is a naming convention, not a status.",
            [_entry(e, tokens=[t for t in name_attention_tokens(e.name) if t in _SIGIL_TOKENS])
             for e in sigil]))

    return ArtifactAttentionResult(object_count=len(rows), section=section or "", signals=signals)


# ── markdown formatting (MCP ergonomics; regular enough for an agent to parse) ──

_GUIDANCE = ("Use this as evidence only. These are neutral signals (reference counts, a reachability "
             "flag, name tokens) — not conclusions. Do not infer intent, importance, or whether an "
             "object is unused/obsolete/safe to remove; confirm meaning with the human.")


def _fmt_by_type(by_type: dict) -> str:
    if not by_type:
        return "none"
    return ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))


def _fmt_examples(examples: list) -> list:
    if not examples:
        return ["  - (none)"]
    out = []
    for e in examples:
        extra = ""
        if e.get("via"):
            extra += f" via={e['via']}"
        if e.get("cond"):
            extra += f" when={e['cond']}"
        out.append(f"  - {e['section']}/{e['name'] or e['id']} -> {e['type']}{extra}")
    return out


def format_object_markdown(artifact_path: str, result: EvidenceResult) -> str:
    lines = [
        "# Object Evidence", "",
        f"Artifact: {artifact_path}",
        "Mode: selected object", "",
        "## Selected Object",
        f"- id: {result.item_id}",
        f"- section: {result.section}",
        f"- name: {result.name}",
        f"- type: {result.type or '(n/a)'}",
        f"- dead_end: {str(result.dead_end).lower()}", "",
        "## Direct Evidence",
        f"- inbound_xrefs: {result.inbound_count}",
        f"- outbound_xrefs: {result.outbound_count}",
        f"- inbound_by_type: {_fmt_by_type(result.inbound_by_type)}",
        f"- outbound_by_type: {_fmt_by_type(result.outbound_by_type)}", "",
        "## Neutral Signals",
        f"- name_attention_tokens: {', '.join(result.name_attention_tokens) or 'none'}",
        f"- attention_score: {result.attention_score}",
        f"- orphan_candidate: {str(result.inbound_count == 0).lower()}", "",
        "## Evidence Links",
        "- inbound:",
        *_fmt_examples(result.inbound_examples),
        "- outbound:",
        *_fmt_examples(result.outbound_examples), "",
        "## Agent Guidance",
        _GUIDANCE,
    ]
    return "\n".join(lines)


_IMPACT_GUIDANCE = (
    "Use this as evidence only. 'Dependents' are objects that REFERENCE this one (observed/inferred "
    "from the schema) — i.e. what could be AFFECTED if you rename, retype, or remove it; "
    "'dependencies' are what this object itself relies on. These are reference facts, NOT a verdict: "
    "they do not establish that a change is safe, breaking, or complete (dynamic dispatch, plug-ins, "
    "external/data-API callers, and runtime calc can reference an object without a recorded edge). "
    "Confirm impact and intent with the human before acting.")


def _fmt_impact_examples(examples: list) -> list:
    if not examples:
        return ["  - (none)"]
    out = []
    for e in examples:
        extra = f" [{e.get('confidence', 'observed')}]"
        if e.get("channel") and e["channel"] != "direct":
            extra += f" via={e['channel']}"
        if e.get("mode"):
            extra += f" mode={e['mode']}"
        if e.get("cond"):
            extra += f" when={e['cond']}"
        out.append(f"  - {e['section']}/{e['name'] or e['id']} ({e['type']}){extra}")
    return out


def format_change_impact_markdown(artifact_path: str, result: "ChangeImpactResult") -> str:
    lines = [
        "# Change-Impact Evidence", "",
        f"Artifact: {artifact_path}",
        "Question: if I change/rename/remove this object, what appears to depend on it?", "",
        "## Object",
        f"- id: {result.item_id}",
        f"- section: {result.section}",
        f"- name: {result.name}",
        f"- type: {result.type or '(n/a)'}", "",
        "## Dependents (inbound — affected if THIS changes)",
        f"- count: {result.dependents_count}",
        f"- by_type: {_fmt_by_type(result.dependents_by_type)}",
        f"- by_section: {_fmt_by_type(result.dependents_by_section)}",
        f"- by_channel: {_fmt_by_type(result.dependents_by_channel)}",
        f"- no_observed_dependents: {str(result.dependents_count == 0).lower()}",
        "- examples:",
        *_fmt_impact_examples(result.dependents_examples), "",
        "## Dependencies (outbound — this object relies on these)",
        f"- count: {result.dependencies_count}",
        f"- by_type: {_fmt_by_type(result.dependencies_by_type)}",
        f"- by_section: {_fmt_by_type(result.dependencies_by_section)}",
        "- examples:",
        *_fmt_impact_examples(result.dependencies_examples), "",
        "## Provenance",
        f"- edge_confidence: {_fmt_by_type(result.confidence_summary)}",
        "  (observed = the schema records the reference explicitly; inferred = heuristic, e.g. "
        "ExecuteSQL parsing or dynamic 'Perform Script by Name' dispatch)", "",
        "## Agent Guidance",
        _IMPACT_GUIDANCE,
    ]
    return "\n".join(lines)


def format_candidates_markdown(artifact_path: str, results: list) -> str:
    lines = [
        "# Object Evidence", "",
        f"Artifact: {artifact_path}",
        "Mode: artifact attention candidates", "",
        f"## Top {len(results)} by attention_score",
        "(triage signal only — reference activity + reachability + name tokens; NOT importance)", "",
    ]
    if not results:
        lines.append("- (no objects)")
    for e in results:
        toks = f" tokens={','.join(e.name_attention_tokens)}" if e.name_attention_tokens else ""
        dead = " dead_end" if e.dead_end else ""
        lines.append(
            f"- [{e.attention_score}] {e.section}/{e.name} "
            f"(in:{e.inbound_count} out:{e.outbound_count}{dead}{toks})")
    lines += ["", "## Agent Guidance", _GUIDANCE]
    return "\n".join(lines)


_SIGNALS_GUIDANCE = (
    "Use these as triage signals only — reasons to LOOK, ranked within each kind by the number that "
    "defines it (degree, token count, group size), NOT by any inferred meaning. They are computed "
    "from reference counts, reachability, and names; they do not establish that an object is "
    "important, unused, obsolete, or safe to remove. A zero-dependent or sigil-named object can still "
    "be reached by dynamic dispatch, plug-ins, or external/Data-API callers (no recorded edge). For "
    "the blast radius of a specific object use get_change_impact_evidence; confirm meaning with the "
    "human.")


def _fmt_signal_entry(it: dict) -> str:
    """One compact line per signal entry. Duplicate-name groups have their own shape (members)."""
    if "members" in it:                              # duplicate_looking_name group
        mem = ", ".join(m["name"] for m in it["members"])
        return f"  - [{it['count']}] {it['section']}/~{it['normalized_name']}: {mem}"
    extra = ""
    if "degree" in it:
        extra += f" degree={it['degree']}"
    extra += f" in:{it.get('inbound', 0)} out:{it.get('outbound', 0)}"
    if it.get("dead_end"):
        extra += " dead_end"
    if it.get("tokens"):
        extra += f" tokens={','.join(it['tokens'])}"
    return f"  - {it['section']}/{it['name'] or it['item_id']}{extra}"


def format_attention_signals_markdown(artifact_path: str, result: "ArtifactAttentionResult") -> str:
    scope = f" (section {result.section})" if result.section else ""
    lines = [
        "# Artifact Attention Signals", "",
        f"Artifact: {artifact_path}",
        "Question: what parts of this artifact deserve a look first?",
        f"Scope: {result.object_count} objects scanned{scope}", "",
        "Neutral triage — each kind is ranked by its own strength, not by claimed meaning.", "",
    ]
    if not result.signals:
        lines.append("- (no signals)")
    for s in result.signals:
        lines.append(f"## {s.kind} ({len(s.items)})")
        lines.append(s.description)
        for it in s.items:
            lines.append(_fmt_signal_entry(it))
        lines.append("")
    lines += ["## Agent Guidance", _SIGNALS_GUIDANCE]
    return "\n".join(lines)
