"""FM2026 native-AI usage lens — what AI capabilities a solution uses, and where.

FileMaker 2026 added a native AI stack (semantic find, embeddings, RAG, LLM generation,
NL queries, image captioning, ML/regression). Grounded against a real 26.0.1 export, that
usage is expressed almost ENTIRELY through SCRIPT STEPS — there are no AI/RAG-account or
embedding-field schema objects to inventory; accounts/models/prompt-templates are runtime
config passed as step parameters. So this lens is a deterministic inventory of the AI script
steps each script uses (plus any AI calc functions, when a solution uses them), grouped into
capability families, with soft consistency flags.

Pure and on-demand — derived from the Artifact, never stored (mirrors workflows.py /
structure_intent.py). The native-AI step IDs already parse (mapped in v2.2.3.0 for FM 22.x +
the FM2026 image-caption steps in v2.3.0.0); this layer classifies and surfaces them.

Public API:
    analyze_ai_usage(artifact) -> AIUsageReport
    render_ai_usage(report) -> str           # the AI-context / human block
"""

from __future__ import annotations

import re
from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field


# AI script step id → (capability key, human label). The native-AI steps (202, 212-227) were
# added by FM 22.x; the image-caption steps (240/241) are FM2026. 223 (Set Revert Transaction
# on Error) and other 2xx steps are deliberately NOT here — they are transactions, not AI.
AI_STEPS = {
    212: ("config", "Configure AI Account"),
    227: ("config", "Configure RAG Account"),
    226: ("config", "Configure Prompt Template"),
    217: ("config", "Set AI Call Logging"),
    202: ("ml", "Configure Machine Learning Model"),
    222: ("ml", "Configure Regression Model"),
    213: ("ml", "Fine-Tune Model"),
    215: ("embedding", "Insert Embedding"),
    216: ("embedding", "Insert Embedding in Found Set"),
    218: ("semantic", "Perform Semantic Find"),
    219: ("rag", "Perform RAG Action"),
    220: ("generation", "Generate Response from Model"),
    214: ("nl_query", "Perform SQL Query by Natural Language"),
    221: ("nl_query", "Perform Find by Natural Language"),
    240: ("image", "Insert Image Captions in Found Set"),
    241: ("image", "Insert Image Caption"),
}

CAPABILITY_LABELS = {
    "config": "AI/RAG account & prompt configuration",
    "ml": "ML / regression / fine-tuning",
    "embedding": "Embeddings",
    "semantic": "Semantic find",
    "rag": "Retrieval-augmented generation (RAG)",
    "generation": "LLM response generation",
    "nl_query": "Natural-language query (SQL / Find)",
    "image": "AI image captioning",
}

# Stable display order for capabilities.
_CAP_ORDER = ["config", "ml", "embedding", "semantic", "rag", "generation", "nl_query", "image"]

# AI-related calculation functions → the capability they imply. Scanned in calc text; absent
# in simple solutions but real in ones that compute over embeddings.
AI_FUNCTIONS = {
    "getembedding": "embedding",
    "cosinesimilarity": "semantic",
}
_FN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\s*\(")

# Salient AI-step parameter slots — the configured detail worth surfacing (grounded on a real
# 26.0.1 export). The Parameter@type names the slot; the value is a calc literal / enum List.
_ACCOUNT_SLOTS = {"LLMAccountName", "LLMEmbeddingAccountName", "RAGAccountName",
                  "AccountName", "FineTuneAccountName"}
_MODEL_SLOTS = {"LLMModel", "LLMEmbeddingModel", "LLMTrainModelName", "FineTuneBaseModel"}
_PROVIDER_SLOTS = {"ModelProvider"}                       # + the bare provider List on step 212
_KEY_SLOTS = {"LLMAPIKey", "RAGAPIKey"}
_LITERAL_RE = re.compile(r'^\s*"(.*)"\s*$', re.DOTALL)    # a calc that is a bare quoted literal


def _unquote(text: str):
    """A calc that is a single quoted literal → its contents; None for a non-literal expression
    (a field/variable reference or concatenation — not a static configured value)."""
    m = _LITERAL_RE.match(text or "")
    return m.group(1) if m else None


@dataclass
class AIUsageReport:
    per_script: dict = field(default_factory=dict)       # script name -> [(step_id, label)]
    per_capability: dict = field(default_factory=dict)   # cap key -> sorted [script names]
    calc_functions: dict = field(default_factory=dict)   # function name -> sorted [obj names]
    flags: list = field(default_factory=list)            # soft consistency notes
    accounts: list = field(default_factory=list)         # configured AI/RAG account names (literals)
    models: list = field(default_factory=list)           # configured model names (literals)
    providers: list = field(default_factory=list)        # configured providers (e.g. OpenAI)
    exposed_keys: list = field(default_factory=list)     # [(script, step_label)] API key as a literal

    @property
    def uses_ai(self) -> bool:
        return bool(self.per_script or self.calc_functions)

    @property
    def capabilities(self) -> list:
        caps = set(self.per_capability)
        return [c for c in _CAP_ORDER if c in caps]

    def to_dict(self) -> dict:
        return {
            "uses_ai": self.uses_ai,
            "capabilities": self.capabilities,
            "per_capability": {k: sorted(v) for k, v in self.per_capability.items()},
            "per_script": {k: [{"step_id": s, "label": l} for s, l in v]
                           for k, v in self.per_script.items()},
            "calc_functions": {k: sorted(v) for k, v in self.calc_functions.items()},
            "flags": list(self.flags),
            "accounts": list(self.accounts),
            "models": list(self.models),
            "providers": list(self.providers),
            "exposed_keys": [{"script": s, "step": l} for s, l in self.exposed_keys],
        }


def _iter_step_ids(item) -> list:
    """All step ids in a script item's step XML (StepsForScripts source)."""
    ids = []
    for src in getattr(item, "xml_sources", []) or []:
        try:
            root = ET.fromstring(src.xml)
        except ET.ParseError:
            continue
        for st in root.iter("Step"):
            try:
                ids.append(int(st.get("id")))
            except (TypeError, ValueError):
                continue
    return ids


def _ai_step_config(item):
    """Yield (slot, value, step_id) for the salient configured params of an item's AI steps.
    `slot` is one of account/model/provider/key; `value` is the literal (accounts/models) or
    enum (provider); key yields the raw calc text so the caller can flag literal exposure."""
    for src in getattr(item, "xml_sources", []) or []:
        try:
            root = ET.fromstring(src.xml)
        except ET.ParseError:
            continue
        for st in root.iter("Step"):
            try:
                sid = int(st.get("id"))
            except (TypeError, ValueError):
                continue
            if sid not in AI_STEPS:
                continue
            pv = st.find("ParameterValues")
            if pv is None:
                continue
            for p in pv.findall("Parameter"):
                ptype = p.get("type", "")
                # provider is an enum List (ModelProvider, or the bare List on Configure AI Account)
                lst = p.find("List")
                if lst is not None and (ptype in _PROVIDER_SLOTS or (sid == 212 and ptype == "List")):
                    yield ("provider", lst.get("name", ""), sid)
                    continue
                txt_el = p.find(".//Text")
                txt = (txt_el.text or "") if txt_el is not None else ""
                if ptype in _ACCOUNT_SLOTS:
                    lit = _unquote(txt)
                    if lit:
                        yield ("account", lit, sid)
                elif ptype in _MODEL_SLOTS:
                    lit = _unquote(txt)
                    if lit:
                        yield ("model", lit, sid)
                elif ptype in _KEY_SLOTS:
                    yield ("key", txt, sid)


def _calc_text(item) -> str:
    """All calculation/source text from an item (rendered_text + raw xml_sources)."""
    parts = [item.rendered_text or ""]
    for src in getattr(item, "xml_sources", []) or []:
        parts.append(src.xml or "")
    return "\n".join(parts)


def analyze_ai_usage(artifact) -> AIUsageReport:
    """Inventory the native-AI usage of an artifact: which scripts use which AI steps, any AI
    calc functions, the capability families touched, and soft consistency flags."""
    rep = AIUsageReport()
    per_cap: dict = {}
    accounts, models, providers, exposed = set(), set(), set(), []

    for item in artifact.items.values():
        if item.section != "ScriptCatalog" or item.is_folder:
            continue
        hits = [(sid, AI_STEPS[sid]) for sid in _iter_step_ids(item) if sid in AI_STEPS]
        if not hits:
            continue
        # de-dup (a script may call the same AI step many times) but keep order of first use
        seen = set()
        ordered = []
        for sid, (cap, label) in hits:
            if sid not in seen:
                seen.add(sid)
                ordered.append((sid, label))
            per_cap.setdefault(cap, set()).add(item.name)
        rep.per_script[item.name] = ordered

        # configured detail (accounts/models/providers) + literal-API-key exposure
        for slot, value, sid in _ai_step_config(item):
            if slot == "account":
                accounts.add(value)
            elif slot == "model":
                models.add(value)
            elif slot == "provider" and value:
                providers.add(value)
            elif slot == "key" and _unquote(value):   # a quoted literal key, not a field/var ref
                exposed.append((item.name, AI_STEPS[sid][1]))

    rep.accounts = sorted(accounts)
    rep.models = sorted(models)
    rep.providers = sorted(providers)
    rep.exposed_keys = exposed

    # AI calc functions (embedding/similarity math) — fields + custom functions
    for item in artifact.items.values():
        if item.section not in ("FieldsForTables", "CustomFunctionsCatalog") or item.is_folder:
            continue
        text = _calc_text(item)
        if "(" not in text:
            continue
        for m in _FN_RE.finditer(text):
            fn = m.group(1)
            cap = AI_FUNCTIONS.get(fn.lower())
            if cap:
                rep.calc_functions.setdefault(fn, set()).add(item.name)
                per_cap.setdefault(cap, set()).add(item.name)

    rep.per_capability = {k: sorted(v) for k, v in per_cap.items()}
    rep.calc_functions = {k: sorted(v) for k, v in rep.calc_functions.items()}
    rep.flags = _consistency_flags(rep)
    return rep


def _consistency_flags(rep: AIUsageReport) -> list:
    """Soft, non-judgmental observations (the chair principle: flag what IS, don't decide).

    Account/embedding setup may live in a startup script, another file, or runtime config, so
    these are NOTES for a reviewer to confirm — never assertions of a defect."""
    caps = set(rep.per_capability)
    flags = []
    consumes = caps & {"semantic", "rag", "generation", "nl_query"}
    if consumes and "config" not in caps:
        flags.append(
            "uses AI features (" + ", ".join(sorted(consumes)) +
            ") but no Configure AI/RAG Account step appears in this file — accounts may be "
            "configured in a startup script, another file, or at runtime.")
    if "semantic" in caps and "embedding" not in caps:
        flags.append(
            "Perform Semantic Find is used but no Insert Embedding step appears in this file — "
            "the embeddings it searches may be populated elsewhere.")
    if "rag" in caps and "config" in caps and not any(
            "RAG Account" in l for v in rep.per_script.values() for _, l in v):
        flags.append(
            "Perform RAG Action is used but no Configure RAG Account step appears in this file.")
    if rep.exposed_keys:
        where = ", ".join(sorted({s for s, _ in rep.exposed_keys}))
        flags.append(
            f"an AI/RAG API key is hard-coded as a literal in {len(rep.exposed_keys)} step(s) "
            f"({where}) — it travels in the schema export; consider a field/variable reference.")
    return flags


def render_ai_usage(report: AIUsageReport, *, max_scripts: int = 8) -> str:
    """Render the AI-usage block (AI context + human overlay). Empty string when no AI usage."""
    if not report.uses_ai:
        return ""
    out = ["AI USAGE — FileMaker native-AI capabilities this solution uses "
           "(steps are the source of truth; AI accounts/models are runtime config, not schema):"]
    out.append("  capabilities: " + ", ".join(CAPABILITY_LABELS[c] for c in report.capabilities))
    for cap in report.capabilities:
        scripts = report.per_capability.get(cap, [])
        shown = ", ".join(scripts[:max_scripts]) + ("…" if len(scripts) > max_scripts else "")
        out.append(f"  · {CAPABILITY_LABELS[cap]}: {len(scripts)} script(s) — {shown}")
    if report.providers:
        out.append("  providers: " + ", ".join(report.providers))
    if report.accounts:
        out.append("  accounts (configured in-file): " + ", ".join(report.accounts))
    if report.models:
        out.append("  models (configured in-file): " + ", ".join(report.models))
    if report.calc_functions:
        out.append("  AI calc functions: " + ", ".join(
            f"{fn} ({len(objs)})" for fn, objs in sorted(report.calc_functions.items())))
    for f in report.flags:
        out.append(f"  ⚠ note: {f}")
    return "\n".join(out)
