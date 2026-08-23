"""FMUpgradeTool capability ledger — loader + AI-guidance renderer.

The ledger (patch_capabilities.yaml) is the single source of truth for
what FMUpgradeTool can and cannot do, how each claim was verified, and the tool
version it was verified against. Two consumers:

  - a human reviewer reads the YAML directly (consumable evidence of rigor);
  - the patch-AI system prompt renders render_capability_guidance() so generation
    respects known limits rather than guessing.

Behavior is tool-version-specific — re-verify on a new FMUpgradeTool build, and
keep `open_questions` honest (it is the discovery frontier). See CLAUDE.md
"What goes stale" for the maintenance contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_LEDGER_PATH = Path(__file__).parent / "patch_capabilities.yaml"

_STATUS_VALUES = frozenset({"verified", "refuted", "inferred", "unknown"})
_CATEGORY_VALUES = frozenset({"apply-semantics", "grammar", "limitation", "operational"})


@dataclass
class Capability:
    id: str
    title: str
    category: str
    status: str
    behavior: str
    ai_guidance: str = ""
    implication: str = ""
    evidence: str = ""
    verified_via: str = ""
    tool_version: str = ""
    date: str = ""


@dataclass
class OpenQuestion:
    id: str
    question: str


@dataclass
class CapabilityLedger:
    tool: str
    patch_format_version: str
    verified_tool_versions: list = field(default_factory=list)
    entries: list = field(default_factory=list)         # list[Capability]
    open_questions: list = field(default_factory=list)  # list[OpenQuestion]

    def by_category(self, category: str) -> list:
        return [e for e in self.entries if e.category == category]

    def get(self, entry_id: str) -> "Capability | None":
        return next((e for e in self.entries if e.id == entry_id), None)


def _flow(text: str) -> str:
    """Collapse a YAML folded-scalar's soft-wrapped whitespace into one line."""
    return " ".join((text or "").split())


def load_capabilities() -> CapabilityLedger:
    """Load and validate the FMUpgradeTool capability ledger."""
    with open(_LEDGER_PATH, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    entries: list = []
    for e in raw.get("entries", []):
        cap = Capability(
            id=e["id"],
            title=e["title"],
            category=e["category"],
            status=e["status"],
            behavior=_flow(e.get("behavior", "")),
            ai_guidance=_flow(e.get("ai_guidance", "")),
            implication=_flow(e.get("implication", "")),
            evidence=_flow(e.get("evidence", "")),
            verified_via=e.get("verified_via", ""),
            tool_version=e.get("tool_version", ""),
            date=str(e.get("date", "")),
        )
        if cap.status not in _STATUS_VALUES:
            raise ValueError(f"capability {cap.id!r}: bad status {cap.status!r}")
        if cap.category not in _CATEGORY_VALUES:
            raise ValueError(f"capability {cap.id!r}: bad category {cap.category!r}")
        entries.append(cap)

    questions = [OpenQuestion(id=q["id"], question=_flow(q.get("question", "")))
                 for q in raw.get("open_questions", [])]

    return CapabilityLedger(
        tool=raw.get("tool", "FMUpgradeTool"),
        patch_format_version=raw.get("patch_format_version", ""),
        verified_tool_versions=list(raw.get("verified_tool_versions", [])),
        entries=entries,
        open_questions=questions,
    )


def render_capability_guidance(ledger: "CapabilityLedger | None" = None) -> str:
    """Render the AI-facing capabilities/limits block for the patch system prompt.

    Only entries that carry ai_guidance are surfaced (operational notes are for
    humans). Limitations are called out separately so the model refuses and
    flags rather than fabricating behavior the tool does not support.
    """
    led = ledger or load_capabilities()
    versions = ", ".join(led.verified_tool_versions) or "unspecified"

    lines = [f"KNOWN FMUPGRADETOOL CAPABILITIES & LIMITS (verified on {led.tool} {versions}):"]
    caps = [e for e in led.entries if e.ai_guidance and e.category != "limitation"]
    lims = [e for e in led.entries if e.ai_guidance and e.category == "limitation"]
    for e in caps:
        lines.append(f"  - {e.ai_guidance}")
    if lims:
        lines.append("LIMITS — do not work around these; surface them honestly:")
        for e in lims:
            lines.append(f"  - {e.ai_guidance}")
    return "\n".join(lines)
