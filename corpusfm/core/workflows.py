"""Workflow extraction — what a FileMaker solution DOES, traced from the xref graph.

A workflow is a path through the dependency graph that starts where a USER acts: a
layout button/trigger or a custom-menu command that runs a script (the LayoutScript /
MenuScript entry edges the ingestion pipeline now captures). From each entry point we
walk the script→script call tree and collect the fields those scripts touch. The
result is the functional layer above raw structure — "rung 4": not what objects exist,
but what the solution lets a person do.

This is derived analysis over `Artifact.items` + `Artifact.xref_map` (cheap, ephemeral —
not stored). Two consumers, same canonical layer: a human-facing "what this solution
does" view, and `build_schema_context` so the AI's generated changes land near intent.

Public API:
    extract_workflows(artifact, *, max_depth=6, max_workflows=None) -> WorkflowReport
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact

_ENTRY_EDGE_TYPES = ("LayoutScript", "MenuScript", "FileScript")
_ENTRY_KIND = {"LayoutScript": "layout", "MenuScript": "menu", "FileScript": "file"}


@dataclass
class Workflow:
    entry_id: str               # item_id of the entry-point script
    entry_name: str
    invoked_from: list          # [(kind, name, via)] — the user surface + how it fires (trigger event/button)
    calls: list                 # script names reached transitively (the call tree, breadth-first order)
    sets_fields: list           # all fields referenced (union of writes ∪ reads) — backward-compatible
    writes: list                # fields the workflow WRITES (its data effect / blast radius)
    reads: list                 # fields the workflow READS (its data dependencies)
    sql_tables: list            # tables reached via ExecuteSQL (outside the relationship graph)
    dynamic: list               # opaque/runtime-computed dispatch points (honest limits)
    conditions: list            # distinct guard conditions the workflow branches on (control flow)
    triggers: list              # scripts fired indirectly via navigation triggers (cascades)
    script_count: int           # scripts involved (entry + transitively called)
    depth: int                  # deepest call level reached
    lands_in: list = field(default_factory=list)  # TO contexts the workflow navigates into (Go to Related Record)

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "entry_name": self.entry_name,
            "invoked_from": [{"kind": k, "name": n, "via": v} for k, n, v in self.invoked_from],
            "calls": self.calls,
            "sets_fields": self.sets_fields,
            "writes": self.writes,
            "reads": self.reads,
            "sql_tables": self.sql_tables,
            "dynamic": self.dynamic,
            "conditions": self.conditions,
            "triggers": self.triggers,
            "script_count": self.script_count,
            "depth": self.depth,
            "lands_in": self.lands_in,
        }


@dataclass
class WorkflowReport:
    workflows: list = field(default_factory=list)   # list[Workflow], richest first
    entry_point_count: int = 0                       # distinct user-invocable scripts
    has_scripted_ui: bool = False                    # any entry edges at all

    def to_dict(self) -> dict:
        return {
            "entry_point_count": self.entry_point_count,
            "has_scripted_ui": self.has_scripted_ui,
            "workflow_count": len(self.workflows),
            "workflows": [w.to_dict() for w in self.workflows],
        }


def extract_workflows(
    artifact: "Artifact",
    *,
    max_depth: int = 6,
    max_workflows: Optional[int] = None,
) -> WorkflowReport:
    """Trace user-action → script → call-tree workflows from the artifact graph."""
    items = artifact.items

    def _section(item_id: str) -> str:
        it = items.get(item_id)
        return it.section if it else ""

    def _name(item_id: str) -> str:
        it = items.get(item_id)
        return it.name if it else item_id

    calls: dict = defaultdict(list)          # script_id -> [called script_id]
    script_writes: dict = defaultdict(set)   # script_id -> {field written}
    script_reads: dict = defaultdict(set)    # script_id -> {field read}
    script_sql: dict = defaultdict(set)      # script_id -> {sql table}
    script_dyn: dict = defaultdict(set)      # script_id -> {dynamic note}
    entry_sources: dict = defaultdict(list)  # script_id -> [(kind, source name, via)]

    script_guards: dict = defaultdict(set)   # script_id -> {guard condition}
    script_triggers: dict = defaultdict(set)  # script_id -> {triggered script name (cascade)}
    script_lands: dict = defaultdict(set)     # script_id -> {TO context navigated into}
    for r in artifact.xref_map:
        if r.type == "ScriptReference":
            calls[r.from_id].append(r.to)
            if r.cond and r.cond not in ("if", "else if", "(else)"):
                script_guards[r.from_id].add(r.cond)
        elif r.type == "ScriptNavigateTO":
            script_lands[r.from_id].add(r.to_name)
        elif r.type == "TriggerCascade":
            # A navigation fires the destination's trigger — a hidden continuation;
            # fold it into the call tree so its effects join the workflow.
            calls[r.from_id].append(r.to)
            script_triggers[r.from_id].add(r.to_name)
        elif r.type in _ENTRY_EDGE_TYPES:
            entry_sources[r.to].append((_ENTRY_KIND[r.type], r.from_name, r.via))
        elif r.type == "FieldReference" and _section(r.from_id) == "ScriptCatalog":
            (script_writes if r.mode == "write" else script_reads)[r.from_id].add(r.to_name)
        elif r.type == "SQLQuery":
            script_sql[r.from_id].add(r.to_name)
        elif r.type == "DynamicDispatch":
            script_dyn[r.from_id].add(r.to_name)

    workflows: list = []
    for entry_id in entry_sources:
        # Breadth-first walk of the call tree (cycle- and depth-guarded).
        order: list = [(entry_id, 0)]
        seen = {entry_id}
        i = 0
        max_depth_reached = 0
        while i < len(order):
            sid, depth = order[i]
            i += 1
            max_depth_reached = max(max_depth_reached, depth)
            if depth >= max_depth:
                continue
            for nxt in calls.get(sid, []):
                if nxt not in seen:
                    seen.add(nxt)
                    order.append((nxt, depth + 1))

        tree_ids = [sid for sid, _ in order]
        called = [_name(sid) for sid, d in order if d > 0]
        writes = sorted({f for sid in tree_ids for f in script_writes.get(sid, ())})
        reads = sorted({f for sid in tree_ids for f in script_reads.get(sid, ())})
        sql = sorted({t for sid in tree_ids for t in script_sql.get(sid, ())})
        dyn = sorted({d for sid in tree_ids for d in script_dyn.get(sid, ())})
        conds = sorted({c for sid in tree_ids for c in script_guards.get(sid, ())})
        trigs = sorted({t for sid in tree_ids for t in script_triggers.get(sid, ())})
        lands = sorted({t for sid in tree_ids for t in script_lands.get(sid, ())})
        invoked = sorted(set(entry_sources[entry_id]))
        workflows.append(Workflow(
            entry_id=entry_id,
            entry_name=_name(entry_id),
            invoked_from=invoked,
            calls=called,
            sets_fields=sorted(set(writes) | set(reads)),
            writes=writes,
            reads=reads,
            sql_tables=sql,
            dynamic=dyn,
            conditions=conds,
            triggers=trigs,
            script_count=len(order),
            depth=max_depth_reached,
            lands_in=lands,
        ))

    # Richest first: a workflow that fans out to more scripts/surfaces/data effects is
    # the one a reader (or the AI) most wants to see first. Writes weigh heaviest —
    # they are what the workflow changes.
    workflows.sort(
        key=lambda w: (len(w.writes) * 2 + len(w.calls) + len(w.invoked_from)
                       + len(w.reads) + len(w.sql_tables), w.entry_name),
        reverse=True,
    )
    if max_workflows is not None:
        workflows = workflows[:max_workflows]

    return WorkflowReport(
        workflows=workflows,
        entry_point_count=len(entry_sources),
        has_scripted_ui=bool(entry_sources),
    )
