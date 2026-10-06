"""High-level summarization helpers.

generate_summaries() iterates all renderable items in a ParseResult and calls
the provider for each one. Results are keyed as "folder_name/item_name" so they
can be stored flat in summaries.json and looked up cheaply during git export.

save_summaries() / load_summaries() handle the summaries.json sidecar file.

get_provider() reads AppConfig + env vars and returns a ready-to-use provider,
or None when AI summaries are disabled or misconfigured.

summarize_item() generates a one-line semantic summary for a single schema item.
The prompt is kept minimal: section type + name + rendered content.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from corpusfm.server.ai._watchdog import CallCancelled, CallTimeout, call_with_deadline

if TYPE_CHECKING:
    from corpusfm.app.app_config import AppConfig
    from corpusfm.artifact import Artifact
    from corpusfm.server.ai.providers import AIProvider

logger = logging.getLogger(__name__)

# Packet 057 — per-object wall-clock deadline + circuit breaker. A hung AI call (socket timeout held open
# by a proxy) is abandoned after this many seconds so the job self-heals past it; N consecutive timeouts
# abort the whole job (bounding leaked threads + surfacing a dead endpoint). A normal object is 2–30s, so
# 120s only trips on a genuine hang or a rare oversize map-reduce item (which is then just skipped).
_PER_ITEM_DEADLINE_S = 120
_MAX_CONSECUTIVE_TIMEOUTS = 3

_SECTION_LABELS = {
    "scripts": "FileMaker script",
    "custom_functions": "FileMaker custom function",
    "tables": "FileMaker base table",
    "layouts": "FileMaker layout",
    "value_lists": "FileMaker value list",
    "relationships": "FileMaker relationship",
    "addons": "FileMaker addon",
    "fields": "FileMaker calculation field",
}

_SUMMARY_PROMPT = """\
You are summarizing a FileMaker schema item for a developer reference index.
Write exactly ONE sentence (under 20 words) describing what this {item_type} does or represents.
Do not start with "This" or the item name. Be concrete and specific.

Item name: {name}

Content:
{content}

Summary:"""

# Output budget for a one-line summary. The summary itself is tiny, but a THINKING model
# (Qwen3, DeepSeek-R1, …) spends most of this budget on its <think> reasoning before emitting
# the line — too small a cap truncates it mid-thought and returns empty. max_tokens is a CAP,
# not a target, so this is free for non-thinking models (they stop at the natural end). The
# test button and the real summary path share it so the test predicts production.
_SUMMARY_MAX_TOKENS = 1024

# Input content budget (packet 053): we do NOT truncate — the gist of a calc or a long script is
# rarely in the first chunk, so the TOTALITY matters. Up to the budget, send the whole object in one
# call (modern models have large context). Over the budget, map-reduce: extract per chunk, then
# synthesize — so every part informs the one-liner. A budget of 0 means "never chunk" (single call).
_DEFAULT_CONTENT_BUDGET = 12000
_CHUNK_OVERLAP = 200
_EXTRACT_MAX_TOKENS = 512

# Per-chunk extraction for oversize objects — terse intent notes, later synthesized into one line.
_EXTRACT_PROMPT = """\
This is PART {n} of {total} of a FileMaker {item_type} named "{name}".
List the key actions, logic, or intent in THIS part as a few terse bullet points. No preamble.

Content:
{content}

Notes:"""


def get_provider(app_config: "AppConfig") -> Optional["AIProvider"]:
    """Return a configured AI provider, or None if disabled/misconfigured."""
    from corpusfm.server.ai.providers import AnthropicProvider, OpenAICompatProvider

    provider_name = getattr(app_config, "ai_summary_provider", "") or ""
    model = getattr(app_config, "ai_summary_model", "") or ""
    base_url = getattr(app_config, "ai_summary_base_url", "") or ""
    api_version = getattr(app_config, "ai_summary_api_version", "") or ""

    if not provider_name:
        return None

    # UI-settable CHAT key (packet 1007: in the SETTING.AiKeys container; packet 1151: the chat and
    # embed endpoints hold independent keys) takes precedence; env var is the older-setup fallback.
    ui_key = ""
    try:
        from corpusfm.server import ai_env
        ui_key = ai_env.read_ai_key("chat")
    except Exception:
        ui_key = ""

    if provider_name == "anthropic":
        api_key = ui_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.warning("ai_summary_provider=anthropic but no API key set (UI or ANTHROPIC_API_KEY)")
            return None
        return AnthropicProvider(model=model, api_key=api_key)

    if provider_name in ("openai_compat", "azure_openai"):
        api_key = ui_key or os.environ.get("AI_SUMMARY_API_KEY", "")
        return OpenAICompatProvider(model=model, api_key=api_key, base_url=base_url,
                                    provider=provider_name, api_version=api_version)

    logger.warning("Unknown ai_summary_provider: %r — AI summaries disabled", provider_name)
    return None


def summary_provider_ready(app_config: "AppConfig") -> bool:
    """True when an AI summary provider is configured (get_provider would succeed).

    The gate for offering on-demand summary generation in the UI. Cheap — get_provider
    only constructs the provider object, it makes no network call."""
    return get_provider(app_config) is not None


def test_summary_endpoint(
    provider_name: str, model: str = "", base_url: str = "", api_key: str = "",
    api_version: str = "", *, use_env_key: bool = True
) -> dict:
    """Do a tiny live chat round-trip to prove the summary (chat) provider works.

    Mirrors test_embedding_endpoint for the embeddings side. Returns
    {ok, reply?, model?, error?}. Resolves the API key from env when not passed
    (ANTHROPIC_API_KEY / AI_SUMMARY_API_KEY), same precedence as get_provider.
    api_version is only used for the azure_openai provider. ``use_env_key=False`` means NO credential
    is permitted beyond ``api_key`` (packet 1401-02)."""
    from corpusfm.server.ai.providers import AnthropicProvider, OpenAICompatProvider

    provider_name = (provider_name or "").strip()
    if not provider_name:
        return {"ok": False, "error": "No AI summary provider selected."}
    try:
        if provider_name == "anthropic":
            if use_env_key:
                api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return {"ok": False, "error": "Anthropic selected but no API key is set."}
            provider = AnthropicProvider(model=model, api_key=api_key)
        elif provider_name in ("openai_compat", "azure_openai"):
            if use_env_key:
                api_key = api_key or os.environ.get("AI_SUMMARY_API_KEY", "")
            provider = OpenAICompatProvider(model=model, api_key=api_key, base_url=base_url,
                                            provider=provider_name, api_version=api_version)
        else:
            return {"ok": False, "error": f"Unknown provider: {provider_name!r}"}
        # Use the real summary token budget, not a tiny cap — a thinking model (Qwen3,
        # DeepSeek-R1, …) spends most of the budget reasoning and returns empty content if it's
        # too small, which is exactly what summaries would hit.
        reply = provider.generate("Reply with the single word: ok.", max_tokens=_SUMMARY_MAX_TOKENS)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    if not (reply or "").strip():
        return {"ok": False, "error": "Provider reachable but returned no text — likely a "
                "'thinking' model that didn't finish, or an embedding-only model. Try a "
                "non-thinking chat model (e.g. llama3.1)."}
    return {"ok": True, "reply": reply.strip()[:120], "model": model or "(default)"}


def _chunks(text: str, size: int, overlap: int):
    """Yield ~size-char chunks with a small overlap so logic spanning a boundary isn't lost."""
    if size <= 0 or len(text) <= size:
        yield text
        return
    step = max(1, size - overlap)
    i = 0
    n = len(text)
    while i < n:
        yield text[i:i + size]
        i += step


def _one_line(provider, item_type, name, content, usage_text="") -> str:
    """The single summarization call. usage_text (optional xref) is appended when provided."""
    prompt = _SUMMARY_PROMPT.format(item_type=item_type, name=name, content=content)
    if usage_text:
        prompt = prompt.replace("\nSummary:", f"\nHow it is used (cross-references):\n{usage_text}\n\nSummary:")
    return provider.generate(prompt, max_tokens=_SUMMARY_MAX_TOKENS)


def summarize_item(
    provider: "AIProvider",
    folder_name: str,
    name: str,
    rendered_text: str,
    max_content_chars: int = _DEFAULT_CONTENT_BUDGET,
    usage_text: str = "",
) -> str:
    """Generate a one-line summary for a schema item.

    Sends the WHOLE object up to ``max_content_chars`` (no lossy truncation). Over that budget it
    map-reduces — a terse extract per chunk, then one synthesis call — so the totality of the object
    (not just its first chunk) informs the summary. ``max_content_chars=0`` disables chunking (single
    call). ``usage_text`` (optional cross-references) is appended to the prompt when provided.

    Returns empty string on any error so callers can skip without crashing.
    """
    item_type = _SECTION_LABELS.get(folder_name, "FileMaker schema item")
    content = rendered_text or ""
    budget = max_content_chars if (max_content_chars and max_content_chars > 0) else 0
    try:
        if budget == 0 or len(content) <= budget:
            return _one_line(provider, item_type, name, content, usage_text)
        # Oversize → map-reduce. Extract terse notes per chunk, then synthesize one line from them.
        parts = list(_chunks(content, budget, _CHUNK_OVERLAP))
        notes = []
        for n, chunk in enumerate(parts, 1):
            try:
                note = provider.generate(
                    _EXTRACT_PROMPT.format(n=n, total=len(parts), item_type=item_type,
                                           name=name, content=chunk),
                    max_tokens=_EXTRACT_MAX_TOKENS,
                )
                if note and note.strip():
                    notes.append(note.strip())
            except Exception:
                logger.debug("chunk extract failed for %r part %d", name, n, exc_info=True)
        combined = "\n".join(notes)[:budget] if notes else content[:budget]
        return _one_line(provider, item_type, name, combined, usage_text)
    except Exception:
        logger.debug("AI summary failed for %r / %r", folder_name, name, exc_info=True)
        return ""


# ── Catalog → git folder mapping (mirrors git_formatter) ──────────────────────

_CATALOG_TO_FOLDER = {
    "ScriptCatalog":          "scripts",
    "CustomFunctionsCatalog": "custom_functions",
    "BaseTableCatalog":       "tables",
    "LayoutCatalog":          "layouts",
    "ValueListCatalog":       "value_lists",
    "RelationshipCatalog":    "relationships",
    "BaseDirectoryCatalog":   "addons",
}

# Calc-bearing fields are summarized too (packet 053 D) but are NOT in _CATALOG_TO_FOLDER on purpose —
# that map is also the vector index's section filter, and we don't want every field (most of them plain
# data fields) flooding the search index. So fields get a summary folder ONLY here, gated on has_calc.
_FIELDS_SECTION = "FieldsForTables"


def _summary_folder(item) -> "str | None":
    """The summary folder for an item, or None if it isn't summarized. Calc-bearing fields →
    'fields'; plain fields → None (skipped). Everything else → _CATALOG_TO_FOLDER."""
    f = _CATALOG_TO_FOLDER.get(getattr(item, "section", ""))
    if f is not None:
        return f
    if getattr(item, "section", "") == _FIELDS_SECTION and getattr(item, "has_calc", False):
        return "fields"
    return None


def summarizable_items(artifact: "Artifact") -> list:
    """The items that get summarized (incl. calc-bearing fields). Uses the shared predicate in
    artifact.types so the ingest-time count can't drift from what's actually summarized."""
    from corpusfm.artifact.types import is_summarizable_item
    return [it for it in artifact.items.values() if is_summarizable_item(it)]


def _xref_usage_index(artifact: "Artifact", cap: int = 12) -> dict:
    """{item_id: "Used by: … · Uses: …"} from the artifact's xref edges — the optional usage block
    appended to the summary prompt (packet 053 E2). Capped so a hub object can't explode the prompt."""
    inbound: dict = {}
    outbound: dict = {}
    for e in (getattr(artifact, "xref_map", None) or []):
        frm = getattr(e, "from_id", None); to = getattr(e, "to", None)
        if frm is not None:
            outbound.setdefault(frm, []).append(getattr(e, "to_name", "") or to or "")
        if to is not None:
            inbound.setdefault(to, []).append(getattr(e, "from_name", "") or frm or "")
    out: dict = {}
    ids = set(inbound) | set(outbound)
    for iid in ids:
        ub = [n for n in dict.fromkeys(inbound.get(iid, [])) if n][:cap]
        us = [n for n in dict.fromkeys(outbound.get(iid, [])) if n][:cap]
        bits = []
        if ub: bits.append("Used by: " + ", ".join(ub))
        if us: bits.append("Uses: " + ", ".join(us))
        if bits:
            out[iid] = " · ".join(bits)
    return out


def generate_summaries(
    artifact: "Artifact",
    provider: "AIProvider",
    should_cancel: Optional[Callable[[], bool]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
    max_content_chars: int = _DEFAULT_CONTENT_BUDGET,
    include_xref: bool = False,
) -> dict[str, str]:
    """Generate one-line summaries for all summarizable items in an Artifact.

    Keyed by **item_id** (packet 053 — unique by construction, so two objects with the same name no
    longer collide) PLUS a back-compat ``folder/name`` alias (lossy for duplicate names, like the v1
    files, so folder/name readers keep working unchanged). Use `lookup_summary` to resolve — it prefers
    item_id. No summary is lost: both colliding objects are stored under their distinct item_ids.

    should_cancel: cooperative Stop poll (checked per item) — returns the PARTIAL dict so far.
    on_progress(done, total): per-item progress callback (drives the queue's object count).
    max_content_chars: input budget; over it, summarize_item map-reduces (no truncation). 0 = single call.
    include_xref: when True, append each item's cross-references to its prompt (default off).
    """
    summaries: dict[str, str] = {}
    items = summarizable_items(artifact)
    total = len(items)
    done = 0
    usage = _xref_usage_index(artifact) if include_xref else {}
    consecutive_timeouts = 0

    for item in items:
        if should_cancel is not None and should_cancel():
            break
        folder_name = _summary_folder(item)
        try:
            # Packet 057: a hard wall-clock deadline per object. A hung AI call (the socket timeout can be
            # held open by a proxy) is abandoned so the job self-heals past it instead of freezing. The
            # deadline is cancel-aware (checks should_cancel every ~0.5s) so Stop is responsive mid-object
            # instead of waiting out the whole deadline.
            summary = call_with_deadline(
                lambda it=item, fn=folder_name: summarize_item(
                    provider, fn, it.name, it.rendered_text or "",
                    max_content_chars=max_content_chars, usage_text=usage.get(it.item_id, "")),
                _PER_ITEM_DEADLINE_S, should_cancel=should_cancel,
            )
            consecutive_timeouts = 0
            if summary:
                summaries[item.item_id] = summary            # primary, collision-proof
                summaries[f"{folder_name}/{item.name}"] = summary   # back-compat alias (folder/name readers)
        except CallCancelled:
            break     # Stop fired mid-object → return the partial summaries gathered so far.
        except CallTimeout:
            consecutive_timeouts += 1
            logger.warning("summary timed out for %r after %ds (%d in a row)",
                           item.item_id, _PER_ITEM_DEADLINE_S, consecutive_timeouts)
            if consecutive_timeouts >= _MAX_CONSECUTIVE_TIMEOUTS:
                raise RuntimeError(
                    f"AI summary endpoint stopped responding — {consecutive_timeouts} objects in a row "
                    f"exceeded {_PER_ITEM_DEADLINE_S}s. Aborting; check the AI endpoint, then Restart.")
            # else: skip this one object and keep going (self-heal).
        except Exception:
            logger.debug("generate_summaries: skipping %r", item.item_id, exc_info=True)
            consecutive_timeouts = 0
        done += 1
        if on_progress is not None:
            try:
                on_progress(done, total)
            except Exception:
                pass

    return summaries


def lookup_summary(summaries: dict, item) -> str:
    """Resolve an item's summary across v2 (item_id key) + v1/alias (folder/name) files.
    Prefers the collision-proof item_id; falls back to folder/name."""
    if not summaries:
        return ""
    s = summaries.get(getattr(item, "item_id", "") or "")
    if s:
        return s
    folder = _summary_folder(item)
    if folder:
        return summaries.get(f"{folder}/{getattr(item, 'name', '')}", "") or ""
    return ""


def save_summaries(summaries: dict[str, str], path: Path) -> None:
    """Write summaries dict to summaries.json."""
    path.write_text(json.dumps(summaries, indent=2, ensure_ascii=False), encoding="utf-8")


def load_summaries(path: Path) -> dict[str, str]:
    """Load summaries.json; returns empty dict if absent or unreadable."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
