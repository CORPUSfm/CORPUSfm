"""Security event trail — compact, append-only, local, and best-effort.

Deliberately NOT called a ledger: nothing here guarantees durability or completeness, and an append
that fails is dropped (loudly logged, never retried). Treat it as attributable diagnostics.

Records security-relevant and privileged actions (who did what, to what, and the outcome) so they
become attributable after the fact. It is deliberately distinct from the other audit-ish paths:

  * operational telemetry  — apply_metrics.jsonl / discovery.jsonl (how long / how often)
  * artifact-activity history — corpusfm.server.history (HISTORY events, cascades on artifact delete)

This is the SECURITY trail, and it is kept LOCAL — a JSONL file, NOT the storage backend — for two
reasons: backend activation is itself an audited event, and the trail must survive a backend outage.
Append-only and **best-effort**: a logging failure NEVER blocks or fails the primary action (there
is no fail-closed audit convention in this codebase). **No secrets are written** — record presence
and identifiers, never values: tokens, passwords, hashes, patch/schema XML, and AI prompts are
dropped/redacted defensively even if a caller passes them.

Backend ledger only — no dashboard or UI in this pass. `read_audit()` exists for tests and any
future surfacing.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("corpusfm.audit")
_lock = threading.Lock()

# ── known actions (kept small + stable; the conformance test asserts callers use these) ──
USER_CREATED = "user.created"
USER_DELETED = "user.deleted"
USER_ACTIVE_CHANGED = "user.active_changed"
USER_GATES_CHANGED = "user.gates_changed"
USER_PASSWORD_RESET = "user.password_reset"
MCP_TOKEN_ROTATED = "mcp.user_token_rotated"
SERVICE_TOKEN_REGENERATED = "mcp.service_token_regenerated"
FMS_ADMIN_MCP_TOGGLED = "mcp.fms_admin_tools_toggled"
PATCHING_MCP_TOGGLED = "mcp.patching_tools_toggled"
BROWSER_LIFETIME_CHANGED = "mcp.browser_connection_lifetime_changed"   # packet 1183 — the policy ladder
# packet 1182 — a user disconnected ONE of their own OAuth connections (target = the client id). The
# STORED string keeps its historical spelling on purpose: renaming it would split one event across two
# vocabularies in logs that already exist. Packet 1220 retired "mcp.browser_oauth_toggled" — nothing can
# emit it any more (there is no switch), and old rows still read back fine because nothing filters on
# this set.
MCP_BROWSER_CONNECTION_DISCONNECTED = "mcp.browser_connection_disconnected"
COMPARTMENT_RESTRICTION_TOGGLED = "apply.compartment_restriction_toggled"
PKI_CHANGED = "pki.changed"                     # generated / registered / tested / removed (see meta.op)
FMS_PLAN = "fms.plan"
FMS_EXECUTE = "fms.execute"
PATCH_APPLY = "patch.apply"
PATCH_DRY_RUN = "patch.dry_run"
PATCH_VERIFY = "patch.verify"
STORAGE_BACKEND_ACTIVATED = "storage.backend_activated"
UPDATE_APPLIED = "update.applied"
# External auth (packet 1065 — OIDC/LDAP)
AUTH_SSO_LOGIN = "auth.sso_login"
USER_JIT_CREATED = "user.jit_created"
EXTERNAL_AUTH_CONFIG_CHANGED = "auth.external_config_changed"

KNOWN_ACTIONS = frozenset({
    USER_CREATED, USER_DELETED, USER_ACTIVE_CHANGED, USER_GATES_CHANGED, USER_PASSWORD_RESET,
    MCP_TOKEN_ROTATED, SERVICE_TOKEN_REGENERATED, FMS_ADMIN_MCP_TOGGLED, PATCHING_MCP_TOGGLED,
    BROWSER_LIFETIME_CHANGED,
    MCP_BROWSER_CONNECTION_DISCONNECTED,
    COMPARTMENT_RESTRICTION_TOGGLED,
    PKI_CHANGED,
    FMS_PLAN, FMS_EXECUTE, PATCH_APPLY, PATCH_DRY_RUN, PATCH_VERIFY,
    STORAGE_BACKEND_ACTIVATED, UPDATE_APPLIED,
    AUTH_SSO_LOGIN, USER_JIT_CREATED, EXTERNAL_AUTH_CONFIG_CHANGED,
})

# Defence-in-depth secret scrub: any meta key whose name hints at a secret is dropped, and every
# value is truncated. The ledger should carry identifiers/flags, never secret material.
_SECRET_KEY = re.compile(r"token|password|passwd|pwd|secret|key|pem|hash|cookie|cred", re.IGNORECASE)
_MAX_VALUE_LEN = 200
_MAX_META_KEYS = 24


def audit_log_path() -> Path:
    """Location of the security event trail. Override with CORPUSFM_AUDIT_LOG (tests/ops)."""
    from corpusfm.lifecycle import app_paths

    # DEVELOPMENT ONLY (packet 1246-03-01). A published installation's audit log lives in its own
    # state directory and nowhere else — an environment variable that could move it is a way to
    # write the security record somewhere the installation does not own, and it worked even when
    # the installation's record could not be read at all.
    override = app_paths.development_override(
        "CORPUSFM_AUDIT_LOG", lambda: os.environ.get("CORPUSFM_AUDIT_LOG"),
        what="the audit log location")
    if override:
        return Path(override)
    return app_paths.state_dir() / "audit.jsonl"


def _scrub_value(v):
    if isinstance(v, str):
        return v[:_MAX_VALUE_LEN] + "…" if len(v) > _MAX_VALUE_LEN else v
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    if isinstance(v, (list, tuple)):
        return [_scrub_value(x) for x in v[:_MAX_META_KEYS]]
    return str(v)[:_MAX_VALUE_LEN]


def _scrub_meta(meta: dict) -> dict:
    out: dict = {}
    for i, (k, v) in enumerate(meta.items()):
        if i >= _MAX_META_KEYS:
            break
        out[str(k)] = "<redacted>" if _SECRET_KEY.search(str(k)) else _scrub_value(v)
    return out


def record(action: str, *, actor: str = "system", target: str = "", outcome: str = "ok",
           meta: "dict | None" = None, path: "Path | None" = None) -> None:
    """Append one security event to the ledger. Best-effort — never raises, never blocks the caller.

    actor   — who did it (a username, "system", "installer", or "token:<scopes>")
    target  — what it acted on (a username, db name, connection, …)
    outcome — "ok" | "denied" | "error" | a short status
    meta    — small extra context dict (identifiers/flags only; secret-named keys are redacted)
    """
    try:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": str(actor or "system")[:_MAX_VALUE_LEN],
            "action": str(action)[:_MAX_VALUE_LEN],
            "target": str(target)[:_MAX_VALUE_LEN],
            "outcome": str(outcome)[:_MAX_VALUE_LEN],
        }
        if meta:
            entry["meta"] = _scrub_meta(meta)
        log_path = Path(path) if path is not None else audit_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # Audit logging must never break a real action — but a DROPPED security event must not also be
        # invisible, or the trail reads complete while it is not. Logged to the module logger, never
        # back into the file that just refused a write; nested so a logging failure cannot resurrect
        # the exception this handler exists to swallow.
        try:
            log.warning("audit: dropped event %r (trail is incomplete)", action, exc_info=True)
        except Exception:
            pass
        return


def read_audit(limit: int = 200, path: "Path | None" = None) -> list[dict]:
    """Return up to `limit` events, newest-first. Empty if the ledger is absent/unreadable."""
    log_path = Path(path) if path is not None else audit_log_path()
    if not log_path.exists():
        return []
    entries: list[dict] = []
    try:
        with log_path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        return []
    entries.reverse()
    return entries[: max(0, limit)]
