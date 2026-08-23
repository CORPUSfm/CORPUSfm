"""Shared endpoint dialect for the AI request builders (packet 1151).

Both AI consumers — chat summaries (``providers.py``) and embeddings
(``vector_index.py``) — speak one of two REST dialects:

- **OpenAI-compatible** (OpenAI, Ollama, LM Studio, …): ``{base}/chat/completions``
  / ``{base}/embeddings`` with an ``Authorization: Bearer`` header and the model in
  the request body.
- **Azure OpenAI**: ``{base}/openai/deployments/{deployment}/{op}?api-version={ver}``
  with an ``api-key`` header; the *deployment* name carries the model routing in the
  URL (the body ``model`` field is ignored by Azure).

These helpers are the single place those two shapes are expressed, so the chat and
embedding paths can never drift from each other. Everything downstream — request
bodies, response parsing, retries, timeouts — is identical across dialects.
"""

from __future__ import annotations

AZURE_PROVIDER = "azure_openai"

# A GA Azure api-version that serves BOTH chat/completions and embeddings. Only a
# fallback: the UI collects the real api-version per endpoint (a resource may pin a
# newer/preview one). Never silently "correct" a user-supplied value — use theirs.
AZURE_DEFAULT_API_VERSION = "2024-10-21"


def is_azure(provider: str) -> bool:
    return (provider or "") == AZURE_PROVIDER


def endpoint_url(provider: str, base_url: str, op: str,
                 deployment: str = "", api_version: str = "") -> str:
    """Build the operation URL for `op` ∈ {"chat/completions", "embeddings"}.

    Azure routes the deployment in the path + an api-version query; every other
    OpenAI-compatible endpoint is just `{base}/{op}`.
    """
    base = (base_url or "").rstrip("/")
    if is_azure(provider):
        ver = api_version or AZURE_DEFAULT_API_VERSION
        return f"{base}/openai/deployments/{deployment}/{op}?api-version={ver}"
    return f"{base}/{op}"


def auth_headers(provider: str, api_key: str, *, content_type: bool = True) -> dict:
    """The auth header for the dialect: Azure uses `api-key`, everyone else `Bearer`."""
    headers: dict = {}
    if content_type:
        headers["Content-Type"] = "application/json"
    if api_key:
        if is_azure(provider):
            headers["api-key"] = api_key
        else:
            headers["Authorization"] = f"Bearer {api_key}"
    return headers
