"""Neutral markdown formatters for the AI-oriented perspective MCP tools (inbox packet
002, Batch 3).

The human-UI overlays for these perspectives were removed (Batch 2); MCP is now their
home. Each formatter takes a builder's already-computed dict/report and renders compact,
factual markdown — observed/inferred provenance carried through, never a verdict
(nothing is "important", "unused", "obsolete", or "safe to delete"). They duplicate no
Explorer rendering and store nothing back to the artifact.
"""

from __future__ import annotations


def _cap(seq, n: int) -> tuple[list, int]:
    seq = list(seq or [])
    extra = max(0, len(seq) - n)
    return seq[:n], extra


def _join(seq, n: int = 12) -> str:
    shown, extra = _cap(seq, n)
    s = ", ".join(str(x) for x in shown)
    return s + (f" … (+{extra})" if extra else "") if s else "—"


def _wf_block(w, heading: str, mlim: int) -> list:
    """One workflow rendered as markdown lines. `mlim` caps each member list (the inline
    `… (+N)` from _join discloses the rest). Includes the entry's stable item_id for drill-down."""
    out = [heading]
    if getattr(w, "entry_id", ""):
        out.append(f"- id: `{w.entry_id}` (ScriptCatalog)")
    inv = [f"{s[0]}:{s[1]}" + (f" ({s[2]})" if s[2] else "") for s in (w.invoked_from or [])]
    if inv:
        out.append(f"- invoked from: {_join(inv, min(mlim, 8))}")
    if w.writes:
        out.append(f"- writes ({len(w.writes)}): {_join(w.writes, mlim)}")
    if w.reads:
        out.append(f"- reads ({len(w.reads)}): {_join(w.reads, mlim)}")
    if w.calls:
        out.append(f"- calls ({len(w.calls)}): {_join(w.calls, mlim)}")
    if w.sql_tables:
        out.append(f"- SQL tables (outside the relationship graph): {_join(w.sql_tables, mlim)}")
    if w.conditions:
        out.append(f"- branches on ({len(w.conditions)}): {_join(w.conditions, min(mlim, 8))}")
    if w.triggers:
        out.append(f"- triggers (via navigation): {_join(w.triggers, mlim)}")
    if w.lands_in:
        out.append(f"- lands in: {_join(w.lands_in, mlim)}")
    if w.dynamic:
        out.append(f"- ⚠ runtime-computed (no recorded edge): {_join(w.dynamic, min(mlim, 8))}")
    return out


def format_workflows_md(path: str, report, limit: int = 20) -> str:
    """`report` is a WorkflowReport (core.workflows.extract_workflows). The report is already
    capped to `limit` workflows by the caller; we surface the total so truncation is explicit."""
    wfs = list(report.workflows)[:limit]
    total = report.entry_point_count
    truncated = total > len(wfs)
    shown = (f"Showing {len(wfs)} of {total} (raise `limit`, or pass `entry` for one in full)."
             if truncated else f"Showing all {len(wfs)}.")
    out = [
        f"# Workflows — {path}",
        f"{total} entry point(s) (user-invocable scripts). Each entry → its "
        "call tree + the data each action touches, observed from the xref graph "
        "(button / trigger / script edges). Runtime-computed targets are flagged. Facts, not a "
        "verdict on importance.",
        shown,
        "",
    ]
    if not wfs:
        out.append("No workflows traced (no user-invocable entry points found).")
        return "\n".join(out)
    for w in wfs:
        out.extend(_wf_block(w, f"## {w.entry_name}  ({w.script_count} scripts, depth {w.depth})", 12))
        out.append("")
    if truncated:
        out.append(f"… {total - len(wfs)} more entry point(s) not shown "
                   "(raise `limit`, or pass `entry=<name>` for one in full).")
    return "\n".join(out).rstrip()


def format_one_workflow_md(path: str, w, member_limit: int = 40) -> str:
    """Focused single-workflow view — richer than the list row (higher member cap) but still
    bounded: each member list shows up to `member_limit` with an inline `… (+N)` for the rest."""
    out = [f"# Workflow: {w.entry_name} — {path}",
           f"{w.script_count} script(s), depth {w.depth}. Observed from the xref graph; facts, "
           "not a verdict.", ""]
    out.extend(_wf_block(w, f"## {w.entry_name}", member_limit))
    return "\n".join(out).rstrip()


def format_workflow_not_found_md(path: str, query: str, candidates: list) -> str:
    out = [f"No workflow entry matched `{query}` in {path}.",
           "An entry is a user-invocable script (run from a button / layout trigger / external "
           "call). Call get_workflows without `entry` to list them."]
    if candidates:
        out.append("")
        out.append("Closest entry names:")
        for name in candidates:
            out.append(f"- {name}")
    return "\n".join(out)


def format_workflow_ambiguous_md(path: str, query: str, matches: list) -> str:
    out = [f"`{query}` matched {len(matches)} entries case-insensitively in {path} — "
           "re-call with the exact name:"]
    for w in matches:
        eid = f" (id `{w.entry_id}`)" if getattr(w, "entry_id", "") else ""
        out.append(f"- {w.entry_name}{eid}")
    return "\n".join(out)


def format_security_md(path: str, sec: dict, limit: int = 50) -> str:
    """`sec` is {'items': [...]} from explorer._build_security_from_artifact."""
    items = (sec or {}).get("items", [])[:limit]
    out = [
        f"# Security reachability — {path}",
        "Per privilege set, the objects it can reach (from PrivilegeAccess edges) + the accounts "
        "assigned to it (AccountPrivilege). Observed from the schema; not a verdict on whether the "
        "access is correct or safe.",
        "",
    ]
    if not items:
        out.append("No privilege-set access edges found (e.g. an addon export omits security "
                   "catalogs by design).")
        return "\n".join(out)
    for p in items:
        out.append(f"## {p['name']}  (reaches {p['reach']} object(s))")
        if p.get("item_id"):
            out.append(f"- id: `{p['item_id']}` (PrivilegeSetsCatalog)")
        if p.get("accounts"):
            out.append(f"- accounts: {_join(p['accounts'])}")
        if p.get("write_tables"):
            out.append(f"- writes tables: {_join(p['write_tables'])}")
        if p.get("tables"):
            out.append(f"- tables (read): {_join(p['tables'])}")
        if p.get("layouts"):
            out.append(f"- layouts: {_join(p['layouts'])}")
        if p.get("scripts"):
            out.append(f"- scripts: {_join(p['scripts'])}")
        if p.get("value_lists"):
            out.append(f"- value lists: {_join(p['value_lists'])}")
        out.append("")
    return "\n".join(out).rstrip()


def format_data_model_md(path: str, structure: dict) -> str:
    """`structure` is structure_intent_dict(artifact)."""
    dm = (structure or {}).get("data_model") or {}
    edges = dm.get("edges", []) if isinstance(dm, dict) else []
    tables = dm.get("tables", []) if isinstance(dm, dict) else []
    out = [
        f"# Data model — {path}",
        f"The real table-to-table model under the TableOccurrence graph (TOs collapsed to base "
        f"tables): {len(tables)} table(s), {len(edges)} relationship(s). Deterministic facts by "
        "rule, not inferred purpose.",
        "",
    ]
    _CAP = 200
    if not edges:
        out.append("No table-to-table relationships resolved.")
    else:
        out.append("| Table | Cardinality | Table | Join keys |")
        out.append("|---|---|---|---|")
        for e in edges[:_CAP]:
            card = e.get("cardinality", "?")
            rc = e.get("relationships", 1)
            card_lbl = card + (f" ×{rc}" if rc > 1 else "")
            jk = e.get("join_keys") or []
            if card == "cross":
                jk_lbl = "(cartesian)"
            elif jk:
                jk_lbl = "; ".join(jk[:3]) + (f" (+{len(jk) - 3} more)" if len(jk) > 3 else "")
            else:
                jk_lbl = "—"
            if e.get("self_loop"):
                out.append(f"| {e['a']} | {card_lbl} (self) | ↺ | {jk_lbl} |")
            else:
                out.append(f"| {e['a']} | {card_lbl} | {e['b']} | {jk_lbl} |")
        if len(edges) > _CAP:
            out.append("")
            out.append(f"… {len(edges) - _CAP} more relationship(s) not shown (first {_CAP} of "
                       f"{len(edges)}; the mermaid below carries the full model).")
        out.append("")
    mermaid = (structure or {}).get("mermaid") or ""
    if mermaid:
        out.append("mermaid `erDiagram` (paste into any mermaid renderer):")
        out.append("```mermaid")
        out.append(mermaid)
        out.append("```")
    return "\n".join(out).rstrip()


def format_ai_usage_md(path: str, ai: dict, labels: dict) -> str:
    """`ai` is analyze_ai_usage(artifact).to_dict(); `labels` is CAPABILITY_LABELS."""
    out = [f"# AI usage — {path}"]
    if not ai.get("uses_ai"):
        out.append("uses_ai: false — no FileMaker native-AI steps or AI calc functions detected.")
        return "\n".join(out)
    out.append("FileMaker native-AI capabilities used, by script. Steps are the source of truth — "
               "AI accounts/models are runtime config, not schema. Facts, not a verdict.")
    out.append("")
    caps = ai.get("capabilities", [])
    per_cap = ai.get("per_capability", {})
    if caps:
        out.append("## Capabilities")
        for c in caps:
            scripts = per_cap.get(c, [])
            out.append(f"- {labels.get(c, c)}: {len(scripts)} script(s) — {_join(scripts)}")
        out.append("")
    calc = ai.get("calc_functions", {})
    if calc:
        out.append("## AI calc functions")
        for fn, objs in calc.items():
            out.append(f"- {fn}: {len(objs)} object(s) — {_join(objs)}")
        out.append("")
    for label, key in (("Configured providers", "providers"), ("Configured accounts", "accounts"),
                       ("Configured models", "models")):
        vals = ai.get(key, [])
        if vals:
            out.append(f"- {label}: {_join(vals)}")
    if ai.get("flags"):
        out.append("")
        out.append("## Notes")
        for f in ai["flags"]:
            out.append(f"- ⚠ {f}")
    return "\n".join(out).rstrip()


def format_workflow_deltas_md(path_a: str, path_b: str, deltas: list, limit: int = 100) -> str:
    """`deltas` is diff._workflow_deltas(art_a, art_b)."""
    total = len(deltas)
    shown_deltas = deltas[:limit]
    truncated = total > len(shown_deltas)
    head = [
        f"# Workflow deltas — {path_a} → {path_b}",
        "How each workflow's observed blast radius changed between the two artifacts "
        "(matched by entry script). Facts from the xref graph, not a verdict.",
    ]
    if not deltas:
        head.append("No workflow-level changes between the two artifacts.")
        return "\n".join(head)
    head.append(f"{total} changed workflow(s); showing {len(shown_deltas)} (raise `limit` to see more)."
                if truncated else f"{total} changed workflow(s).")
    out = head + [""]
    _LBL = {"writes": "writes", "reads": "reads", "calls": "calls", "conditions": "branches on",
            "triggers": "triggers", "sql_tables": "SQL tables", "lands_in": "lands in"}
    for d in shown_deltas:
        st = d["status"]
        if st == "new":
            out.append(f"- NEW · {d['name']} — writes {d['writes']} · reads {d['reads']} · "
                       f"calls {d['calls']}")
        elif st == "removed":
            out.append(f"- REMOVED · {d['name']}")
        else:
            bits = []
            for f, ch in d["changes"].items():
                lbl = _LBL.get(f, f)
                if ch["added"]:
                    bits.append(f"+{len(ch['added'])} {lbl}: {_join(ch['added'], 4)}")
                if ch["removed"]:
                    bits.append(f"−{len(ch['removed'])} {lbl}: {_join(ch['removed'], 4)}")
            out.append(f"- CHANGED · {d['name']} — {'  '.join(bits)}")
    if truncated:
        out.append("")
        out.append(f"… {total - len(shown_deltas)} more changed workflow(s) not shown (raise `limit`).")
    return "\n".join(out).rstrip()
