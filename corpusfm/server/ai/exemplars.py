"""Object-level step-exemplar retrieval.

Returns real, VERIFIED-WORKING step sequences from ingested artifacts as
adapt-ready templates — the volatile bits (field refs, literals, names) flagged
as placeholders by the structure-catalog sanitizer.

This complements two existing surfaces:
  - structure_catalog.steps_templates — GENERIC per-step-id templates (one step).
  - the seed workflow (list_artifacts(tag="seed")) — WHOLE-FILE discovery.
This sits between them: OBJECT/SEQUENCE-level, drawn from real corpus scripts, so
an author grounds a patch in a step sequence that has actually been ingested rather
than model memory.

Pure functions over (rel_path, ArtifactItem) pairs — no backend coupling, so the
matching + sanitizing logic is unit-testable without a stored archive.
"""
from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field

from corpusfm.core.structure_catalog.sanitizer import sanitize_step_xml

STEPS_CATALOG = "StepsForScripts"
_MAX_SANITIZED_STEPS = 40
_MAX_READABLE_LINES = 60


@dataclass
class StepExemplar:
    source_path: str
    object_name: str
    section: str
    fm_uuid: str
    folder_path: list
    score: float
    readable_steps: str
    sanitized_steps: str
    step_count: int


def _tokens(s: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (s or "").lower()) if t]


def _score(query_tokens: list[str], name: str, summary: str, rendered: str) -> float:
    """Token-overlap relevance: a name hit weighs most, then summary, then body."""
    if not query_tokens:
        return 0.0
    name_set = set(_tokens(name))
    summary_set = set(_tokens(summary))
    rendered_set = set(_tokens(rendered))
    score = 0.0
    for tok in query_tokens:
        if tok in name_set:
            score += 3.0
        elif tok in summary_set:
            score += 2.0
        elif tok in rendered_set:
            score += 1.0
    # Bonus when every query token landed somewhere — favours full-phrase matches.
    hit = name_set | summary_set | rendered_set
    if all(tok in hit for tok in query_tokens):
        score += 1.0
    return score


def sanitize_script_steps(steps_xml: str) -> tuple[str, int]:
    """Sanitize every <Step> in a StepsForScripts block.

    Returns (joined sanitized templates, step_count). On a parse failure returns
    ("", 0) — the caller falls back to the readable rendering.
    """
    if not steps_xml:
        return "", 0
    try:
        root = ET.fromstring(steps_xml)
    except ET.ParseError:
        return "", 0
    steps = root.findall(".//Step")
    out = []
    for step in steps[:_MAX_SANITIZED_STEPS]:
        templ = sanitize_step_xml(ET.tostring(step, encoding="unicode"))
        if templ:
            out.append(templ.strip())
    truncated = len(steps) > _MAX_SANITIZED_STEPS
    text = "\n".join(out)
    if truncated:
        text += f"\n<!-- … {len(steps) - _MAX_SANITIZED_STEPS} more steps omitted -->"
    return text, len(steps)


def _steps_xml_for(item) -> str:
    for src in getattr(item, "xml_sources", []) or []:
        if getattr(src, "catalog", "") == STEPS_CATALOG:
            return src.xml
    return ""


def _cap_lines(text: str, n: int = _MAX_READABLE_LINES) -> str:
    lines = (text or "").splitlines()
    if len(lines) <= n:
        return text or ""
    return "\n".join(lines[:n]) + f"\n… ({len(lines) - n} more lines)"


def find_step_exemplars(
    items,
    query: str,
    limit: int = 3,
    section: str = "ScriptCatalog",
) -> list[StepExemplar]:
    """Rank (rel_path, ArtifactItem) pairs against `query`; return the top matches.

    Only non-folder items in `section` are considered. Each returned exemplar carries
    both the readable rendering (capped) and the sanitized, placeholdered step XML.
    """
    qtokens = _tokens(query)
    scored: list[StepExemplar] = []
    for rel_path, item in items:
        if getattr(item, "section", "") != section:
            continue
        if getattr(item, "is_folder", False):
            continue
        score = _score(qtokens, item.name, getattr(item, "summary", "") or "", item.rendered_text)
        if score <= 0:
            continue
        sanitized, count = sanitize_script_steps(_steps_xml_for(item))
        scored.append(
            StepExemplar(
                source_path=rel_path,
                object_name=item.name,
                section=item.section,
                fm_uuid=getattr(item, "fm_uuid", "") or "",
                folder_path=list(getattr(item, "folder_path", []) or []),
                score=score,
                readable_steps=_cap_lines(item.rendered_text),
                sanitized_steps=sanitized,
                step_count=count,
            )
        )
    # Highest score first; tie-break on shorter scripts (cleaner exemplars) then name.
    scored.sort(key=lambda e: (-e.score, e.step_count, e.object_name.lower()))
    return scored[:limit]


def render_exemplars(
    exemplars: list[StepExemplar],
    query: str,
    scope: str,
    max_chars: int | None = None,
    compact: bool = False,
) -> str:
    """Format exemplars as the MCP tool's text response.

    Bounded output (packet 1024 §2): a whole-script exemplar's sanitized step XML can be tens of
    KB, so ``limit`` matches alone once overflowed an AI caller's tool-output budget. ``max_chars``
    fills exemplars greedily and lists the rest by name once the budget is reached; ``compact``
    drops the sanitized-XML block entirely (readable shapes only) for callers who want step
    *shapes*, not whole scripts.
    """
    if not exemplars:
        return (
            f'No step exemplars matched "{query}" (scope: {scope}).\n'
            "Try broader terms, scope to a tag (e.g. tag=\"seed\"), or widen the corpus."
        )
    header = [
        f'Step exemplars for "{query}"  ({len(exemplars)} match(es); scope: {scope})',
        "",
        "Adapt these to your target: replace the {placeholders} with your file's own",
        "field / script / layout names and literals. These are real step sequences that",
        "have actually been ingested — ground your patch in them, do not invent step XML.",
        "",
    ]
    footer = (
        "See also: get_patch_authoring_guide (action grammar) and the STRUCTURE CATALOG "
        "block in get_schema_context (per-step-id templates)."
    )

    def _block(i: int, ex: StepExemplar) -> str:
        folder = f" · folder: {'/'.join(ex.folder_path)}" if ex.folder_path else ""
        lines = [
            f"═══ {i}. {ex.object_name}   ({ex.section} · {ex.source_path}{folder})  "
            f"[score {ex.score:g}, {ex.step_count} steps]",
            "Readable:",
            ex.readable_steps or "(no rendered content)",
            "",
        ]
        if not compact:
            if ex.sanitized_steps:
                lines.append("Sanitized step XML (placeholders flagged):")
                lines.append(ex.sanitized_steps)
            else:
                lines.append("(step XML unavailable — use the readable form above)")
            lines.append("")
        return "\n".join(lines)

    out = list(header)
    used = sum(len(s) + 1 for s in header)
    shown = 0
    omitted: list[StepExemplar] = []
    for i, ex in enumerate(exemplars, 1):
        block = _block(i, ex)
        if max_chars and shown >= 1 and used + len(block) > max_chars:
            omitted.append(ex)
            continue
        if max_chars and shown == 0 and len(block) > max_chars:
            # A single exemplar bigger than the whole budget — truncate it rather than spill,
            # and point at the narrower retrieval tools for the full body.
            block = block[:max_chars] + (
                f"\n… [exemplar truncated at {max_chars} chars — set compact=true for readable "
                "shapes only, or fetch the full script with get_object / get_script_steps]"
            )
        out.append(block)
        used += len(block) + 1
        shown += 1
    if omitted:
        names = ", ".join(f"{e.object_name} ({e.step_count} steps)" for e in omitted)
        out.append(
            f"… {len(omitted)} more exemplar(s) omitted to stay under {max_chars} chars: {names}. "
            "Narrow with artifact_path=…, set compact=true (readable shapes only), lower limit, or "
            "fetch one script's full XML with get_object / get_script_steps."
        )
        out.append("")
    out.append(footer)
    return "\n".join(out)
