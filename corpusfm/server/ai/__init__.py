"""AI provider infrastructure for CORPUSfm.

Supports two provider shapes:
  - anthropic   : Anthropic native SDK (claude-* models)
  - openai_compat: Any OpenAI-compatible REST endpoint (OpenAI, Groq, Together,
                   Ollama, LM Studio, etc.)

API keys come from env vars, never from FM or app_config.yaml:
  Anthropic      : ANTHROPIC_API_KEY
  OpenAI-compat  : AI_SUMMARY_API_KEY

Provider + model selection live in AppConfig:
  ai_summary_provider  : "anthropic" | "openai_compat" | "" (disabled)
  ai_summary_model     : model string; empty = provider default
  ai_summary_base_url  : base URL for openai_compat; empty = https://api.openai.com/v1

Public API:
    get_provider(app_config) -> AIProvider | None
    summary_provider_ready(app_config) -> bool
    summarize_item(provider, folder_name, name, rendered_text) -> str
    generate_summaries(artifact, provider) -> dict[str, str]
    save_summaries(summaries, path) / load_summaries(path)
    AIProvider  (protocol)
    AnthropicProvider
    OpenAICompatProvider
"""

from corpusfm.server.ai.providers import AIProvider, AnthropicProvider, OpenAICompatProvider
from corpusfm.server.ai.summarize import (
    generate_summaries,
    get_provider,
    load_summaries,
    save_summaries,
    summarize_item,
    summary_provider_ready,
    test_summary_endpoint,
)

__all__ = [
    "AIProvider",
    "AnthropicProvider",
    "OpenAICompatProvider",
    "get_provider",
    "summary_provider_ready",
    "summarize_item",
    "generate_summaries",
    "save_summaries",
    "load_summaries",
    "test_summary_endpoint",
]
