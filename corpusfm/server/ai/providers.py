"""AI provider implementations for headless enrichment.

A provider exposes one entry point:
  generate(prompt, *, system, max_tokens) -> str

This is single-shot text completion used by the unattended enrichment path —
one-line item summaries at ingest (see summarize.py). There is no interactive
or multi-turn use: CORPUSfm no longer hosts an in-app generation harness;
attended patch/clip authoring is the driving agent's job over MCP. Embeddings
are a separate path (vector_index.py), not a provider here.

Both providers are thin wrappers — no retry logic, no streaming. Callers are
responsible for prompt construction.

system: optional stable orientation text; passed as a dedicated system message when
supported (Anthropic native API) or prepended as a system-role message (OpenAI format).
"""

from __future__ import annotations

import json
import re
from typing import Protocol


_ANTHROPIC_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_OPENAI_COMPAT_DEFAULT_MODEL = "gpt-4o-mini"
_OPENAI_COMPAT_DEFAULT_BASE_URL = "https://api.openai.com/v1"

# Thinking models (Qwen3, DeepSeek-R1, etc.) emit a chain-of-thought block in the chat
# `content`. We only ever want the final answer, so strip it — otherwise a one-line summary
# would be polluted with reasoning, and a small token budget would return ONLY (truncated)
# reasoning and look empty.
_THINK_RE = re.compile(r"<think\b[^>]*>.*?</think>", re.DOTALL | re.IGNORECASE)


def _strip_reasoning(text: str) -> str:
    if not text:
        return ""
    text = _THINK_RE.sub("", text)
    # A budget cut-off can leave an unclosed opening tag with no answer after it.
    low = text.lower()
    if "<think>" in low and "</think>" not in low:
        text = text[:low.index("<think>")]
    return text.strip()


class AIProvider(Protocol):
    def generate(self, prompt: str, *, system: str = "", max_tokens: int = 256) -> str: ...


class AnthropicProvider:
    """Anthropic native SDK provider.

    API key from ANTHROPIC_API_KEY env var (already required by the anthropic package).
    """

    def __init__(self, model: str = "", api_key: str = ""):
        self._model = model or _ANTHROPIC_DEFAULT_MODEL
        self._api_key = api_key  # empty = SDK reads ANTHROPIC_API_KEY from env

    def generate(self, prompt: str, *, system: str = "", max_tokens: int = 256) -> str:
        import anthropic
        kwargs = {}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        client = anthropic.Anthropic(**kwargs)
        create_kwargs: dict = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            create_kwargs["system"] = system
        msg = client.messages.create(**create_kwargs)
        return msg.content[0].text.strip()


class OpenAICompatProvider:
    """OpenAI-compatible REST endpoint provider.

    Works with OpenAI, Groq, Together, Mistral, Ollama, LM Studio, and any
    other service that implements the /chat/completions endpoint shape — AND
    with Azure OpenAI (provider="azure_openai"), which differs only in the URL
    (deployment-in-path + api-version query) and the auth header (api-key vs
    Bearer); the payload + response shapes are identical. See ai._endpoints.

    For Azure, `model` is the chat DEPLOYMENT name (Azure routes it in the URL).

    API key from AI_SUMMARY_API_KEY env var.
    """

    def __init__(self, model: str = "", api_key: str = "", base_url: str = "",
                 provider: str = "openai_compat", api_version: str = ""):
        from corpusfm.server.ai._endpoints import is_azure
        self._model = model or _OPENAI_COMPAT_DEFAULT_MODEL
        self._api_key = api_key
        self._provider = provider or "openai_compat"
        self._api_version = api_version
        # Azure has no universal default base; only openai_compat falls back to OpenAI.
        default_base = "" if is_azure(self._provider) else _OPENAI_COMPAT_DEFAULT_BASE_URL
        self._base_url = (base_url or default_base).rstrip("/")
        # OpenAI's gpt-5 / o-series reasoning models reject the legacy
        # "max_tokens" field and require "max_completion_tokens". We send the
        # legacy field by default for broad compatibility (Groq, Ollama, Together
        # still expect it) and flip to the new one on the first call an endpoint
        # rejects it — caching the choice on the instance.
        self._token_param = "max_tokens"

    def generate(self, prompt: str, *, system: str = "", max_tokens: int = 256) -> str:
        import requests

        from corpusfm.server.ai._endpoints import auth_headers, endpoint_url
        headers = auth_headers(self._provider, self._api_key)
        chat_url = endpoint_url(self._provider, self._base_url, "chat/completions",
                                deployment=self._model, api_version=self._api_version)
        chat: list[dict] = []
        if system:
            chat.append({"role": "system", "content": system})
        chat.append({"role": "user", "content": prompt})

        def _post() -> "requests.Response":
            payload = {
                "model": self._model,
                "messages": chat,
                self._token_param: max_tokens,
            }
            return requests.post(
                chat_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=(10, 120),   # (connect, read); the summarize loop also wraps this in a hard
                                     # wall-clock watchdog (packet 057) since a proxy can hold the socket.
            )

        resp = _post()
        if (
            resp.status_code == 400
            and self._token_param == "max_tokens"
            and "max_completion_tokens" in resp.text
        ):
            self._token_param = "max_completion_tokens"
            resp = _post()
        resp.raise_for_status()
        choice = resp.json()["choices"][0]
        text = _strip_reasoning((choice.get("message") or {}).get("content") or "")
        # A 'thinking' model (Qwen3, DeepSeek-R1, …) can burn the whole budget on its reasoning
        # and stop with no answer (finish_reason 'length', empty content). Say so plainly instead
        # of returning a bare empty string — the cause + fix are not obvious otherwise.
        if not text and choice.get("finish_reason") == "length":
            raise RuntimeError(
                "The model reached the token limit before answering — typical of a 'thinking' "
                "model. Use a non-thinking chat model (e.g. llama3.1) for summaries, or raise "
                "the token budget."
            )
        return text
