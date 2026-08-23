"""What the running MCP application actually mounted, and whether it actually enforces (packet 1248).

**One authority, recorded by the code that decides.** Every MCP status surface used to answer from
its own reading of `is_server_mode()` plus a token found in `.mcp_env` or the environment — three
sources for two facts — and two of those readings were provably wrong:

* `is_server_mode()` false with a token in the process environment composes a real bearer verifier and
  mounts an enforcing endpoint, while Health called it *"Mounted (dev / loopback, token-less)."*
* server mode with a token only in `.mcp_env` mounts **nothing** (the fail-closed refusal reads the
  environment, not the file), while Health called it *"Mounted (token-gated, fail-closed)."*

Both were reproduced on `main` before this module existed. The cause is the same in each: a claim
about **mount and enforcement** derived from inputs that decide neither.

**So nothing here infers.** `record_mounted` / `record_not_mounted` are called by
`app.web.app._build_mcp_app` — the one function that makes the decision — at the moment it makes it.
`runtime_status()` reports what was recorded, and reads `enforced` **live from the composed FastMCP
instance** rather than from a snapshot, so it states the object's own current auth, not a belief about
it.

**A token in `.mcp_env` is configuration, never evidence of a mount.** That file's precedence is real
and is untouched: the verifier prefers it when *accepting* a token, which is what lets a regeneration
take effect without a restart. Preferring a value has nothing to do with whether a verifier exists,
and conflating the two is the defect above.

**Never returns, logs or accepts a token value** — only booleans and fixed sentences.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional

_LOCK = threading.Lock()
_MCP: Optional[Any] = None          # the composed FastMCP instance, when one was mounted
_MOUNTED: bool = False
_COMPOSED: bool = False
_REASON: str = ""


@dataclass(frozen=True)
class McpRuntimeStatus:
    """The two facts, and whether anyone is in a position to state them.

    `composed` is not decoration: a process that never built the web application — a CLI run, a test
    that imports a module directly — has no mount to describe, and saying "not mounted" there would be
    an answer to a question nobody asked. Consumers report that state as unknown rather than as a
    negative finding.
    """

    composed: bool
    mounted: bool
    enforced: bool
    reason: str = ""

    @property
    def known(self) -> bool:
        return self.composed


def record_mounted(mcp_instance: Any) -> None:
    """Called by `_build_mcp_app` when it mounts the endpoint. Holds the instance, not a snapshot."""
    global _MCP, _MOUNTED, _COMPOSED, _REASON
    with _LOCK:
        _MCP, _MOUNTED, _COMPOSED, _REASON = mcp_instance, True, True, ""


def record_not_mounted(reason: str) -> None:
    """Recorded when the endpoint is not mounted. The reason is a fixed sentence from the caller.

    No production caller remains: mounting stopped being conditional when the server-wide token went
    (packet 1258). Kept because the vocabulary is the reporting contract — `runtime_status` still has
    to be able to say "composed, not mounted" for a composition that fails for some other reason, and
    a status module that cannot express failure reports success by construction.
    """
    global _MCP, _MOUNTED, _COMPOSED, _REASON
    with _LOCK:
        _MCP, _MOUNTED, _COMPOSED, _REASON = None, False, True, reason


def begin_composition() -> None:
    """Clear any previous record. Called at the START of every composition, production included.

    Named for what it does rather than for who calls it: `create_app` calls this before building the
    MCP application, so a record left by an earlier composition in the same process can never
    describe the app being built now. Production composes once; a test session composes many, and the
    stale-record version of this module reported one application's mount to another.
    """
    global _MCP, _MOUNTED, _COMPOSED, _REASON
    with _LOCK:
        _MCP, _MOUNTED, _COMPOSED, _REASON = None, False, False, ""


def runtime_status() -> McpRuntimeStatus:
    """The mount and enforcement facts of THIS process's MCP application.

    `enforced` is read from the composed instance's own `auth` at call time. A verifier exists exactly
    when the MCP was composed in server mode (packet 1258 — no credential in the environment decides
    it any more), which is the condition that makes the endpoint reject an unauthenticated request, so
    this answers the question the transport answers, from the same object.
    """
    with _LOCK:
        composed, mounted, instance, reason = _COMPOSED, _MOUNTED, _MCP, _REASON
    if not composed:
        return McpRuntimeStatus(False, False, False,
                                "the MCP application has not been composed in this process")
    if not mounted:
        return McpRuntimeStatus(True, False, False, reason)
    enforced = getattr(instance, "auth", None) is not None
    return McpRuntimeStatus(True, True, enforced, "")


__all__ = ["McpRuntimeStatus", "begin_composition", "record_mounted", "record_not_mounted",
           "runtime_status"]
