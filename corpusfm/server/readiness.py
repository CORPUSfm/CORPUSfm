"""Server readiness — the single source of truth for capability + tier status.

Diagnose-first: the server always reaches Tier 0 (this report). Every check is cheap and
NEVER throws — a failure becomes a status, not a crash. The web app (gate + UI), the CLI
(`corpusfm status`), and the server-side feature gates all read this one module.

Tiers:
  0  always — the status surface + login + Settings entry
  1  storage reachable + SETTINGS initialized + encryption key  → catalog/read
  2  Tier 1 + PKI + FMUpgradeTool + db-helper                   → apply / jobs
  3  Tier 1 + embedder                                          → semantic search
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass

OK = "ok"
MISSING = "not_configured"
ERROR = "error"

_PROBE_TTL = 20.0
_REPORT_TTL = 20.0
_probe_cache: dict = {"t": 0.0, "val": None}
_report_cache: dict = {"t": 0.0, "val": None}


@dataclass
class Capability:
    key: str
    label: str
    tier: int
    ok: bool
    status: str
    detail: str = ""
    fix: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── the one network call: probe the storage backend (cached) ─────────────────

def _do_storage_probe() -> dict:
    # A PUBLISHED INSTALLATION PROBES ITS OWN CORPUS (packet 1246-10-04). The resolver names the
    # host, database, account and secret from the manifest and the held credential; a failure to
    # resolve is REPORTED, never degraded into "local", which is the split-brain the block below
    # already refused for a different store.
    from corpusfm.lifecycle import runtime_storage

    try:
        resolved = runtime_storage.resolve()
    except Exception as exc:  # noqa: BLE001
        return {"mode": "unknown", "error": f"published storage authority unavailable: {exc}"}
    if resolved is not None:
        try:
            from corpusfm.server.fm_bootstrap import probe
            pr = probe(resolved.host, resolved.database_name, resolved.account,
                       resolved._secret, verify_ssl=resolved.verify_ssl)
            return {
                "mode": "fm", "reachable": pr.reachable, "authed": pr.authed,
                "has_odata": pr.has_odata, "settings_state": pr.settings_state,
                "default_cred": pr.is_default_credential, "error": pr.error,
            }
        except Exception as exc:  # noqa: BLE001
            return {"mode": "fm", "reachable": False, "error": str(exc)}

    try:
        from corpusfm.install import read_install_config, read_install_mode
        cfg = read_install_config()
    except Exception as exc:  # noqa: BLE001
        return {"mode": "unknown", "error": str(exc)}
    if cfg.get("storage_backend") != "fm_odata":
        # Packet 066: distinguish a genuine local/dev box from a SERVER install whose install.yaml is
        # corrupt/partial. read_install_config() returns {} for BOTH "absent" and "unparseable", and a
        # server box that has silently lost its fm_odata config would otherwise report healthy on
        # LocalBackend — writing artifacts to local disk while the operator believes they're in FileMaker
        # (silent split-brain). read_install_mode() is None only when the marker is genuinely ABSENT
        # (the LocalBackend dev/test path); a present marker fails closed to "server".
        try:
            mode = read_install_mode()
        except Exception:  # noqa: BLE001
            mode = "server"
        if mode == "server":
            return {"mode": "unknown",
                    "error": "install.yaml present on a server install but storage_backend is "
                             "missing/unreadable (not 'fm_odata') — refusing to silently use local storage."}
        return {"mode": "local"}  # dev/local backend — Tier 1 trivially established
    try:
        from corpusfm.server.fm_bootstrap import probe
        pr = probe(
            cfg.get("fm_host", "localhost"),
            cfg.get("fm_database", "CORPUSfm_DB"),
            cfg.get("fm_user", "CORPUSfm-Automation"),
            cfg.get("fm_password", ""),
            verify_ssl=bool(cfg.get("fm_verify_ssl", False)),
        )
        return {
            "mode": "fm", "reachable": pr.reachable, "authed": pr.authed,
            "has_odata": pr.has_odata, "settings_state": pr.settings_state,
            "default_cred": pr.is_default_credential, "error": pr.error,
        }
    except Exception as exc:  # noqa: BLE001
        return {"mode": "fm", "reachable": False, "error": str(exc)}


def _storage_probe(force: bool = False) -> dict:
    now = time.time()
    if not force and _probe_cache["val"] is not None and now - _probe_cache["t"] < _PROBE_TTL:
        return _probe_cache["val"]
    val = _do_storage_probe()
    _probe_cache.update(t=now, val=val)
    return val


# ── individual capability checks (each returns (ok, status, detail, fix)) ─────

def _cap_storage(p: dict):
    mode = p.get("mode")
    if mode == "local":
        return True, OK, "Local storage backend (dev path).", ""
    if mode == "unknown":
        return False, ERROR, p.get("error") or "install config unreadable", "Check ~/.corpusfm/install.yaml."
    if not p.get("reachable"):
        return False, ERROR, p.get("error") or "FileMaker Server unreachable.", "Confirm FMS is running and the storage DB is hosted."
    if not p.get("authed"):
        return False, ERROR, "Storage credential rejected.", "Re-bootstrap the automation account (Settings → FileMaker)."
    if not p.get("has_odata"):
        return False, ERROR, p.get("error") or "OData not accessible.", "Grant the fmodata extended privilege to the automation account."
    return True, OK, "Storage reachable.", ""


def _cap_settings(p: dict):
    if p.get("mode") != "fm":
        return True, OK, "n/a (local backend).", ""
    st = p.get("settings_state")
    if st == "initialized":
        return True, OK, "SETTINGS initialized.", ""
    if st in ("empty", "missing"):
        return False, MISSING, f"SETTINGS not initialized ({st}).", "Restart to self-bootstrap, or use Settings → FileMaker."
    return False, ERROR, "SETTINGS state unknown.", "Verify OData access to the storage DB."


def _cap_encryption():
    try:
        from corpusfm.core.crypto import get_corpus_key
        get_corpus_key()
        return True, OK, "Encryption key present.", ""
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, f"no encryption key: {exc}", "Ensure corpus.key / CORPUSFM_ENCRYPTION_KEY is available."


def _cap_pki():
    """Installation-level Admin API identity (packet 1247).

    A published installation owns ONE identity; this reports what the runtime resolver found, with
    the resolver's own reason. "Absent" is the only state that reads as not-configured — an identity
    that is present and unreadable is an ERROR, because telling an administrator to create a key that
    already exists sends them to the wrong repair.
    """
    try:
        from corpusfm.server.admin_api_identity import admin_api_identity
        identity = admin_api_identity()
        if identity.available:
            return True, OK, "FMS Admin PKI configured.", ""
        status = MISSING if identity.is_absent else ERROR
        return False, status, identity.reason, identity.remedy
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, str(exc), "Check the PKI configuration."


def _cap_tool():
    try:
        from corpusfm.server.patch_apply import find_tool, tool_version
        tool = find_tool()
        if not tool:
            return False, MISSING, "FMUpgradeTool not found.", "Install FMUpgradeTool on the FileMaker Server box."
        # Packet 066: presence is not capability. A found-but-unrunnable binary (wrong arch, missing lib,
        # non-exec) must NOT report OK → the apply path would then close the live DB before failing. Require
        # a successful version probe; "found but won't run" is an ERROR, not OK.
        ver = tool_version(tool)
        if not ver:
            return (False, ERROR,
                    f"FMUpgradeTool found ({tool}) but did not run (version probe failed).",
                    "Verify the binary is executable and the correct architecture for this box.")
        return True, OK, f"FMUpgradeTool {ver}.", ""
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, str(exc), ""


def _is_windows() -> bool:
    return os.name == "nt"


def _cap_helper():
    """The privileged DB-staging capability — three distinct platform paths:
      * Windows → direct-FS (the LocalSystem service writes the Databases dir; no broker). Available
        when the FMS Databases dir is found. Mutations are playground-gated during bring-up.
      * Linux   → the scoped cfm-db-helper sudo broker (installer-dropped).
      * unavailable → a clear, platform-correct reason + fix.
    """
    try:
        if _is_windows():
            from corpusfm.server import win_db_ops
            if win_db_ops.available():
                return (True, OK,
                        f"Windows direct-FS DB access (LocalSystem) — apply is {_apply_scope_note()}", "")
            return (False, MISSING,
                    "FMS Databases directory not found on this Windows box.",
                    "Confirm FileMaker Server is installed here and the CORPUSfm service runs as "
                    "LocalSystem (set CORPUSFM_FMS_DATABASES_DIR to override detection).")
        from corpusfm.server.db_helper import helper_available
        if helper_available():
            return True, OK, f"Scoped DB helper installed — apply is {_apply_scope_note()}", ""
        # Its absence selects nothing (packet 1246-05-02 §4.1): an in-compartment target is applied
        # through the confined compartment transaction with no helper at all, so this is reported as
        # a missing capability for OUTSIDE-compartment work, never as "apply falls back to a weaker
        # route".
        return (False, MISSING,
                "Scoped DB helper not installed — apply outside CORPUSfm's compartment is refused. "
                f"Apply is {_apply_scope_note()}",
                "Run the installer to drop cfm-db-helper.")
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, str(exc), ""


def _apply_scope_note() -> str:
    """One-line description of the current apply SCOPE. Read-only; same wording on both platforms
    since the gate is unified.

    The VERIFIED compartment is reported first because it is the prerequisite: with no verified
    compartment every patch/apply target is refused whatever the preference says. An unverified
    compartment is reported as **unverified**, never as "not configured yet" — registration alone is
    not a runtime permission, and saying "not configured" would suggest the wrong remedy."""
    try:
        from corpusfm.app.app_config import load_app_config
        from corpusfm.server import db_helper
        try:
            authority = db_helper.load_published_patch_authority(require_verified=False)
        except db_helper.PatchAuthorityError as exc:
            return (f"CLOSED — this installation has no patch compartment authority ({exc}). "
                    "Every patch/apply target is refused.")
        if not authority.patch.verified:
            return (f"CLOSED — the patch compartment at {authority.patch_hosting_dir} is UNVERIFIED "
                    f"(registered={bool(authority.patch.registered)}). Every patch/apply target is "
                    "refused until the compartment is proven.")
        if not load_app_config().restrict_apply_to_compartment:
            return ("unrestricted within the verified compartment's installation (any hosted DB "
                    "except the storage DB — compartment restriction OFF).")
        return (f"restricted to CORPUSfm's verified compartment (files hosted from "
                f"{authority.patch_hosting_dir}; the storage DB is always refused).")
    except Exception:
        return "compartment-restricted."


def _cap_embedder():
    try:
        from corpusfm.server.ai.vector_index import has_embedding_configured
        from corpusfm.app.app_config import load_app_config
        if has_embedding_configured(load_app_config()):
            return True, OK, "Embedder configured.", ""
        return False, MISSING, "No embedder configured.", "Set an embedding endpoint (Settings → Integrations) to enable semantic search."
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, str(exc), ""


def _cap_mcp():
    """Is this box SERVING an authenticated MCP?

    It used to ask whether a service token was provisioned, because that token decided both the mount
    and the auth. With MCP access user-account-centric (packet 1258) there is no such token, and the
    honest question is what the composed application actually did: `mcp_status` is recorded by the one
    site that mounts, so it answers for this process rather than re-deriving from configuration — the
    inference that disagreed with reality in both directions.

    `enforced` is the load-bearing half. A mounted-but-unauthenticated MCP on a deployed box would be
    the serious failure, so it reports as such rather than as a healthy capability.
    """
    try:
        from corpusfm.server import mcp_status
        st = mcp_status.runtime_status()
        if st is not None and st.known:
            if st.mounted and st.enforced:
                return True, OK, "MCP is served and authenticated.", ""
            if st.mounted:
                return False, ERROR, "MCP is served WITHOUT authentication.", (
                    "This box is in server mode but the MCP endpoint accepts unauthenticated "
                    "requests. Restart the service; if it persists, treat it as a security incident.")
            return False, MISSING, "MCP is not served.", (
                f"{st.reason or 'The endpoint was not mounted.'} Re-run the installer on this server.")
        # No composition record (a bare app, or a probe running outside the web process).
        from corpusfm.config import is_server_mode
        if is_server_mode():
            return True, OK, "MCP is served and authenticated (from configuration).", ""
        return False, MISSING, "MCP is not served.", "This box is not in server mode."
    except Exception as exc:  # noqa: BLE001
        return False, ERROR, str(exc), ""


# ── the report ───────────────────────────────────────────────────────────────

def report(force: bool = False) -> dict:
    now = time.time()
    if not force and _report_cache["val"] is not None and now - _report_cache["t"] < _REPORT_TTL:
        return _report_cache["val"]
    p = _storage_probe(force=force)
    caps: list[Capability] = []

    def add(key, label, tier, res):
        ok, status, detail, fix = res
        caps.append(Capability(key, label, tier, ok, status, detail, fix))

    add("storage", "Storage backend", 1, _cap_storage(p))
    add("settings", "SETTINGS initialized", 1, _cap_settings(p))
    add("encryption_key", "Encryption key", 1, _cap_encryption())
    add("pki", "FMS Admin PKI", 2, _cap_pki())
    add("upgrade_tool", "FMUpgradeTool", 2, _cap_tool())
    add("db_helper", "Scoped DB helper", 2, _cap_helper())
    add("embedder", "Embedder (search)", 3, _cap_embedder())
    add("mcp", "MCP", 0, _cap_mcp())

    by = {c.key: c for c in caps}
    tier1 = all(by[k].ok for k in ("storage", "settings", "encryption_key"))
    tier2 = tier1 and all(by[k].ok for k in ("pki", "upgrade_tool", "db_helper"))
    tier3 = tier1 and by["embedder"].ok

    out = {
        "tier": 2 if tier2 else (1 if tier1 else 0),
        "tier1_ready": tier1,
        "tier2_ready": tier2,
        "tier3_ready": tier3,
        "storage_default_cred": bool(p.get("default_cred")),
        "capabilities": [c.to_dict() for c in caps],
        "checked_at": now,
    }
    _report_cache.update(t=now, val=out)
    return out


def invalidate() -> None:
    """Drop the caches (call after a config change that affects readiness)."""
    _probe_cache.update(val=None)
    _report_cache.update(val=None)


def tier_ready(n: int) -> bool:
    r = report()
    return bool(r.get(f"tier{n}_ready"))


def require_capability(key: str) -> dict | None:
    """None if the single capability is ok; else a structured 'unavailable' payload. Use for
    features that need ONE capability (e.g. validate/encrypt need the tool, not full Tier 2)."""
    for c in report()["capabilities"]:
        if c["key"] == key:
            if c["ok"]:
                return None
            return {"available": False, "capability": key, "reason": c["detail"], "how": c["fix"]}
    return {"available": False, "capability": key, "reason": "unknown capability", "how": ""}


def require_tier(n: int) -> dict | None:
    """None if Tier n is established; else a structured 'tier-unmet' payload a route/MCP tool
    can return verbatim instead of erroring."""
    r = report()
    if r.get(f"tier{n}_ready"):
        return None
    missing = [c for c in r["capabilities"] if c["tier"] == n and not c["ok"]]
    return {
        "available": False,
        "tier": n,
        "reason": "; ".join(c["detail"] for c in missing) or f"Tier {n} not established",
        "how": " ".join(c["fix"] for c in missing if c["fix"]),
        "capabilities": missing,
    }
