"""Installation health — the read-only capability surface behind Settings → Health.

This is a thin COMPOSING layer over :mod:`corpusfm.server.readiness` (the single source of truth
for tier/capability status). Health adds the install-fact framing an operator needs before trying
a workflow: the environment block (version / deployed commit / platform / FMS version), a few
capability rows readiness doesn't carry (XML parse hardening, MCP mount state, FMUpgradeTool
version, the derived patch-apply / generate-db rows, update-origin trust), and a ``fix_tab`` hint
that links an unhealthy row to the Settings tab where it is configured.

It REPORTS capability, it does not configure anything — configuration stays on the other tabs.
Every probe is cheap and NEVER throws; a failure becomes a status, not a crash. Where a capability
is genuinely undeterminable (e.g. the FMUpgradeTool version on a box where the tool won't report
it), the row says so rather than over-claiming.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import corpusfm
from corpusfm.server import readiness

OK = readiness.OK
MISSING = readiness.MISSING
ERROR = readiness.ERROR
UNKNOWN = "unknown"
# A capability that is CONFIGURED and working but running in a reduced mode. Distinct from
# not_configured ("Unavailable" — never set up) and error ("Error" — broken): a degraded row means the
# feature still does its job while something about it needs attention. Added for the OAuth cleanup row
# (packet 1191), which must read as a warning rather than as a broken install.
DEGRADED = "degraded"

# Capability key → the Settings tab that fixes it (the Health row links there when unhealthy).
# A key absent from this map has no in-app fix path (it's an install/platform-level fact).
# Settings section each capability is fixed in (consolidated 6-section IA, 2026-06). The Settings
# page also alias-maps legacy keys, but keep these current so the "Fix in …" deep-link is correct.
_FIX_TAB = {
    "storage": "storage",
    "settings": "filemaker",
    "encryption_key": "storage",
    "pki": "filemaker",
    "embedder": "integrations",
    "mcp": "general",
    "update_trust": "general",
}

_FMS_VERSION_TTL = 300.0
_fms_cache: dict = {"t": 0.0, "val": None}


def _deployed_commit() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True, text=True, timeout=2,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def _platform() -> str:
    return f"{platform.system()} {platform.release()} ({platform.machine()})".strip()


def _fms_version() -> str:
    """Best-effort FileMaker Server version via the unauthenticated Admin API productInfo endpoint.
    Cached; returns "" when not co-located, unreachable, or undeterminable."""
    now = time.time()
    if _fms_cache["val"] is not None and now - _fms_cache["t"] < _FMS_VERSION_TTL:
        return _fms_cache["val"]
    val = _do_fms_version()
    _fms_cache.update(t=now, val=val)
    return val


def _do_fms_version() -> str:
    from corpusfm.lifecycle import runtime_storage

    try:
        active = runtime_storage.fm_storage_active()
    except Exception:  # noqa: BLE001
        active = None
    if active is not None:
        if not active:
            return ""
        host, verify = runtime_storage.COLOCATED_HOST, False
    else:
        try:
            from corpusfm.install import read_install_config
            cfg = read_install_config()
        except Exception:  # noqa: BLE001
            return ""
        if cfg.get("storage_backend") != "fm_odata":
            return ""
        host = cfg.get("fm_host", "localhost")
        verify = bool(cfg.get("fm_verify_ssl", False))
    try:
        import requests
        r = requests.get(
            f"https://{host}/fmi/admin/api/v2/productInfo",
            timeout=4, verify=verify,
        )
        if r.status_code != 200:
            return ""
        info = (r.json() or {}).get("response", {}).get("productInfo", {})
        ver = str(info.get("version", "")).strip()
        build = str(info.get("buildDate", "")).strip()
        return f"{ver} ({build})" if ver and build else ver
    except Exception:  # noqa: BLE001
        return ""


def _row(key, label, tier, ok, status, detail="", fix=""):
    return {
        "key": key, "label": label, "tier": tier, "ok": bool(ok), "status": status,
        "detail": detail, "fix": fix, "fix_tab": _FIX_TAB.get(key, ""),
    }


def _xml_hardening_row() -> dict:
    try:
        from corpusfm.core.safe_xml import XML_HARDENED
        if XML_HARDENED:
            return _row("xml_hardening", "XML parse hardening", 1, True, OK,
                        "defusedxml active — entity-expansion / XXE blocked at parse time.")
        return _row("xml_hardening", "XML parse hardening", 1, False, ERROR,
                    "defusedxml NOT active — running on the stdlib parser (dev fallback).",
                    "Reinstall dependencies (re-run install.sh) so defusedxml is present.")
    except Exception as exc:  # noqa: BLE001
        return _row("xml_hardening", "XML parse hardening", 1, False, ERROR, str(exc))


def _mcp_row() -> dict:
    """What the MCP application this process composed actually mounted, and whether it enforces.

    RE-EXPRESSED (packet 1248). This used to compute `mounted` from `is_server_mode()` plus a token
    read from `.mcp_env` or the environment, and then derive "token-less" from the MODE — discarding
    the token it had just read. Both halves were wrong and both were reproduced: an unpublished-mode
    process with an environment token serves an ENFORCING endpoint while this row said
    "dev / loopback, token-less", and a server-mode process whose token lives only in `.mcp_env`
    mounts NOTHING while this row said "Mounted (token-gated, fail-closed)".

    It now reports `mcp_status.runtime_status()` — recorded by the composition itself, with
    `enforced` read from the composed instance's own auth. Nothing here infers from deployment mode,
    and a token discoverable in `.mcp_env` is never taken as evidence that a verifier exists.
    """
    try:
        from corpusfm.server import mcp_status

        status = mcp_status.runtime_status()
        if not status.known:
            # Honest rather than negative: no MCP application was composed in THIS process, so there
            # is no mount to describe. Reachable from a CLI or a direct import, never from the web
            # process this row is rendered by.
            return _row("mcp", "MCP endpoint", 0, True, OK,
                        "Not composed in this process — no mount to report.")
        if status.mounted and status.enforced:
            return _row("mcp", "MCP endpoint", 0, True, OK, "Mounted (token-gated, fail-closed).")
        if status.mounted:
            return _row("mcp", "MCP endpoint", 0, True, OK, "Mounted (dev / loopback, token-less).")
        return _row("mcp", "MCP endpoint", 0, False, MISSING,
                    f"Not mounted — {status.reason}." if status.reason else "Not mounted.",
                    "Re-run install.sh on this server to provision the MCP token.")
    except Exception as exc:  # noqa: BLE001
        return _row("mcp", "MCP endpoint", 0, False, ERROR, str(exc))


def _tool_rows() -> list[dict]:
    """FMUpgradeTool presence/version + the two derived capabilities it gates: patch
    validate/encrypt/apply, and database-file materialization (--generateDBFile, FM 2026+)."""
    from corpusfm.server.patch_apply import find_tool, find_fmsadmin, tool_version, version_major

    tool = find_tool()
    rows: list[dict] = []
    if tool is None:
        rows.append(_row("upgrade_tool", "FMUpgradeTool", 2, False, MISSING,
                         "FMUpgradeTool not found — patch validate/encrypt/apply and database-file "
                         "materialization are unavailable on this box.",
                         "Install FMUpgradeTool on the FileMaker Server machine (FMS 2024 does not "
                         "ship it; FMS 2026 does)."))
        rows.append(_row("patch_ops", "Patch validate / encrypt / apply", 2, False, MISSING,
                         "Requires FMUpgradeTool (not found)."))
        rows.append(_row("generate_db_file", "Database-file materialization", 2, False, MISSING,
                         "Requires the FM 2026 FMUpgradeTool (--generateDBFile; not found)."))
        return rows

    ver = tool_version(tool)
    ver_label = ver or "version not reported"
    rows.append(_row("upgrade_tool", "FMUpgradeTool", 2, True, OK,
                     f"Found ({ver_label}) at {tool}."))

    # Patch validate/encrypt/apply: the tool is enough to validate/encrypt; apply additionally needs
    # a way to take the live DB offline (Admin API PKI, or co-located fmsadmin). Validate/encrypt is
    # the floor — report available, and note the apply path.
    fmsadmin = find_fmsadmin()
    pki = False
    pki_remedy = ""
    try:
        from corpusfm.server.admin_api_identity import admin_api_identity
        identity = admin_api_identity()
        pki = identity.available
        pki_remedy = identity.remedy
    except Exception:  # noqa: BLE001
        pki = False
    if pki or fmsadmin is not None:
        how = "Admin API PKI" if pki else "co-located fmsadmin"
        detail = f"Available — apply takes the DB offline via {how}."
        if not pki and pki_remedy:
            # fmsadmin genuinely provides the offline path, so this row is OK — but it is the row that
            # consumes the identity state, and an earlier version discarded it here. A box whose
            # published identity is unreadable would then read as entirely healthy on this row while
            # the PKI row above says otherwise. Say both (review finding, 2026-08-12).
            detail += " The Admin API identity is not usable — see FMS Admin PKI above."
        rows.append(_row("patch_ops", "Patch validate / encrypt / apply", 2, True, OK, detail,
                         "" if pki else pki_remedy))
    else:
        rows.append(_row("patch_ops", "Patch validate / encrypt / apply", 2, True, OK,
                         "Validate/encrypt available; apply needs Admin API PKI or co-located "
                         "fmsadmin to take the live database offline.",
                         pki_remedy or "Register this installation's Admin API identity with "
                                       "`corpusfm-lifecycle admin-identity`."))

    # generateDBFile is a FM 2026 (tool major 26+) feature; 22.x builds lack it.
    major = version_major(ver)
    if major >= 26:
        rows.append(_row("generate_db_file", "Database-file materialization", 2, True, OK,
                         f"Available — FMUpgradeTool {ver} supports --generateDBFile."))
    elif major and major < 26:
        rows.append(_row("generate_db_file", "Database-file materialization", 2, False, MISSING,
                         f"FMUpgradeTool {ver} predates --generateDBFile (needs the FM 2026 build)."))
    else:
        rows.append(_row("generate_db_file", "Database-file materialization", 2, False, UNKNOWN,
                         "FMUpgradeTool present but its version was not reported — --generateDBFile "
                         "requires the FM 2026 build; availability could not be confirmed."))
    return rows


def _update_trust_row() -> dict:
    """Update supply-chain trust: is this checkout's origin the expected repo and is the tracked
    tree clean? (Only meaningful for a git checkout — the only shipped install path.)"""
    try:
        from corpusfm.updater import _repo_root, verify_origin, is_dirty
        repo = _repo_root()
        if not (repo / ".git").exists():
            return _row("update_trust", "Update origin & integrity", 0, True, OK,
                        "Not a git checkout — update-trust checks n/a.")
        ok_origin, actual = verify_origin(repo)
        if not ok_origin:
            return _row("update_trust", "Update origin & integrity", 0, False, ERROR,
                        f"Checkout origin is not the expected CORPUSfm repository "
                        f"(got: {actual or 'unknown'}).",
                        "Point origin at the canonical repository before upgrading.")
        if is_dirty(repo):
            return _row("update_trust", "Update origin & integrity", 0, False, ERROR,
                        "Tracked files have local modifications — a privileged upgrade refuses a "
                        "dirty tree (untracked runtime data is ignored).",
                        "Revert local code changes, or upgrade with --allow-dirty if intentional.")
        return _row("update_trust", "Update origin & integrity", 0, True, OK,
                    "Origin verified; tracked tree clean.")
    except Exception as exc:  # noqa: BLE001
        return _row("update_trust", "Update origin & integrity", 0, False, ERROR, str(exc))


def report(force: bool = False) -> dict:
    """The structured Health payload: environment facts + an ordered capability list.

    Capability rows reuse readiness's checks where they exist (storage / SETTINGS / encryption /
    PKI / scoped helper / embedder) and add the Health-only rows (XML hardening, MCP mount,
    FMUpgradeTool + derived patch/generate rows, update trust). Each row carries a ``fix_tab`` so
    an unhealthy row can deep-link to the tab that configures it.
    """
    from corpusfm.runtime import build_context

    r = readiness.report(force=force)
    by_key = {c["key"]: c for c in r["capabilities"]}

    def reuse(key):
        c = by_key.get(key)
        if not c:
            return None
        return _row(c["key"], c["label"], c["tier"], c["ok"], c["status"], c["detail"], c["fix"])

    caps: list[dict] = []
    for key in ("storage", "settings", "encryption_key"):
        row = reuse(key)
        if row:
            caps.append(row)
    caps.append(_xml_hardening_row())
    caps.append(_mcp_row())
    for key in ("pki",):
        row = reuse(key)
        if row:
            caps.append(row)
    caps.extend(_tool_rows())
    row = reuse("db_helper")
    if row:
        caps.append(row)
    row = reuse("embedder")
    if row:
        caps.append(row)
    caps.append(_update_trust_row())

    py = sys.version_info
    # Python provenance: a venv built from CORPUSfm's bundled CPython has its base_prefix UNDER the
    # install's python/ dir (Linux installer ships python-build-standalone there). Anything else is
    # a system/other interpreter (dev box, run-from-source). Path-segment match → no hardcoded root.
    py_base = sys.base_prefix
    py_source = "bundled" if "/CORPUSfm/python/" in (py_base.rstrip("/") + "/") else "system"
    return {
        "environment": {
            "app_version": corpusfm.__version__,
            "deployed_commit": _deployed_commit(),
            "platform": _platform(),
            "python_version": f"{py.major}.{py.minor}.{py.micro}",
            "python_source": py_source,
            "python_base": py_base,
            "mode": "server" if build_context().is_server else "local",
            "fms_version": _fms_version(),
        },
        "tier": r["tier"],
        "tier1_ready": r["tier1_ready"],
        "tier2_ready": r["tier2_ready"],
        "tier3_ready": r["tier3_ready"],
        "capabilities": caps,
        "checked_at": r["checked_at"],
    }
