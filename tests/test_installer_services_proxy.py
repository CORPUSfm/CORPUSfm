"""Packet 028 Batch 9: the installer SERVICES/PROXY contract — the sharpest OS-specific domain.

These static guards pin the two hard-won, regression-prone proxy invariants that are documented but
were previously unasserted:

- Linux: editing FMS's nginx config is DEFENSIVE — back up, validate, and ROLL BACK on failure, so a
  bad edit never breaks FMS's :443 on the restart.
- Windows: the IIS proxy is ISOLATED — it lives only in the /corpusfm application's own web.config and
  NEVER edits FMS's shared rewrite config (allowedServerVariables / FMWebSite rules), which would
  break FMS's own /fmi/ URL Rewrite (the 500.50 lesson).

Full apply behavior (a real reload, remote /corpusfm/login) is the live-gate proof (Batch 13); these
lock the static contract so a refactor can't silently regress it.
"""
from __future__ import annotations

import inspect
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PROXY_SH = (ROOT / "installer/linux/cfm-web-proxy.sh").read_text(encoding="utf-8")
PROXY_EXEC_SH = (ROOT / "installer/linux/cfm-proxy-exec.sh").read_text(encoding="utf-8")
PROXY_EXEC_PS = (ROOT / "installer/windows/cfm-proxy-exec.ps1").read_text(encoding="utf-8")
INSTALL_PS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")


# ── Linux: nginx edit is backup → validate → rollback-on-failure ──────────────────

def test_linux_nginx_edit_backs_up_and_rolls_back_on_invalid():
    # the main config is backed up before the edit
    assert 'bak="$(mktemp)"; cp "$main" "$bak"' in PROXY_SH
    # on a FAILED validation the backup is restored over the live config (never leave :443 broken)
    assert 'cp "$bak" "$main"' in PROXY_SH
    assert "rolled back" in PROXY_SH.lower()
    # the include is backed up + restored/removed too (it's overwritten before the main is validated)
    assert 'inc_bak="$(mktemp)"; cp "$inc" "$inc_bak"' in PROXY_SH
    assert 'cp "$inc_bak" "$inc"' in PROXY_SH


def test_linux_proxy_is_idempotent_no_needless_restart():
    # an unchanged proxy must NOT restart the FMS web server (it blips OData/WebDirect/Admin-API)
    assert "no restart needed" in PROXY_SH or "no web-server restart needed" in PROXY_SH
    assert "cmp -s" in PROXY_SH    # the change-detect that gates the restart


def test_linux_proxy_has_remove_companion():
    # uninstall parity: a remove mode must exist (strip our block + reload)
    assert "remove)" in PROXY_SH and "remove_nginx" in PROXY_SH


# ── Windows: IIS proxy is isolated — never touches FMS's shared rewrite config ────

def test_windows_proxy_lives_in_isolated_app_webconfig():
    """The rule survives; the AUTHOR changed. The routing must live in the /corpusfm application's
    own web.config and never in FMS's shared rewrite configuration — but the installer no longer
    writes it. The lifecycle proxy provider publishes and owns that family (developer ruling,
    2026-08-09), so the isolation is asserted where the rendering now happens."""
    from corpusfm.lifecycle.proxy_render import desired_family

    assert "Set-Content -Path (Join-Path $ProxyDir 'web.config')" not in INSTALL_PS, \
        "the installer publishes routing again, alongside the provider that owns it"

    parts = desired_family("iis", prefix="/corpusfm", port=8533,
                           app_dir="C:\\Program Files\\CORPUSfm\\proxy",
                           metadata_dir="C:\\Program Files\\CORPUSfm\\proxy-mcp")
    body = parts["config:/corpusfm"]
    assert "<rewrite>" in body and "127.0.0.1:8533" in body
    assert "allowedServerVariables" not in body, "an app-local config must not touch shared rewrite"


def test_windows_never_edits_fms_shared_rewrite_config():
    # allowedServerVariables / FMWebSite rewrite rules are FMS's shared config — editing them breaks
    # FMS's /fmi/ URL Rewrite (500.50). The installer must never WRITE them. The only allowed mention
    # of allowedServerVariables is the cautionary comment; there must be no Set/Add against it.
    for verb in ("Set-WebConfigurationProperty", "Add-WebConfigurationProperty", "Set-WebConfiguration"):
        for line in INSTALL_PS.splitlines():
            s = line.strip()
            if s.startswith("#") or s.startswith("<#"):
                continue
            if verb in line:
                assert "allowedServerVariables" not in line, f"must not edit shared allowedServerVariables: {line!r}"
                assert "FMWebSite' -Filter" not in line or "system.webServer/proxy" in line, \
                    f"must not edit FMWebSite rewrite rules: {line!r}"
    # the server-level write that IS allowed is enabling the ARR proxy feature (not a rewrite rule)
    assert "system.webServer/proxy' -Name 'enabled'" in INSTALL_PS


# ── Packet 1175: RFC 9728 metadata proxy routes — nginx + Apache parity, exact-match, --no-mcp ────

def test_retained_linux_preflight_helper_knows_both_protected_resource_paths():
    # nginx: EXACT-match `location =` for the host-root well-known path + its trailing-slash form,
    # forwarded UNCHANGED (proxy_pass with no URI) — never a prefix/regex that could catch descendants
    assert 'local wk="/.well-known/oauth-protected-resource${PREFIX}/mcp"' in PROXY_SH
    assert "location = ${wk} {" in PROXY_SH and "location = ${wk}/ {" in PROXY_SH
    # apache: anchored ProxyPassMatch (^…$) for both forms → exact, no descendant (.../mcp/x) matches
    assert 'ProxyPassMatch "^/\\.well-known/oauth-protected-resource${PREFIX}/mcp\\$"' in PROXY_SH
    assert 'ProxyPassMatch "^/\\.well-known/oauth-protected-resource${PREFIX}/mcp/\\$"' in PROXY_SH


def test_current_executors_hold_the_correct_front_specific_route_boundary():
    # Linux never re-renders: it applies the application's exact block/include candidate files.
    assert "oauth-protected-resource" not in PROXY_EXEC_SH
    assert "--block-file" in PROXY_EXEC_SH and "--include-file" in PROXY_EXEC_SH

    # IIS mounts each no-slash metadata vpath as an application root; the slash request reaches the
    # same root. Registering a second slash-form child would collide after IIS/path normalization.
    # Only forwarding fronts enumerate the alias; the IIS executor stays at three child roots.
    start = PROXY_EXEC_PS.index("function Get-CfmMetadataVpaths")
    body = PROXY_EXEC_PS[start:PROXY_EXEC_PS.index("\n}\n", start)]
    expected = (
        '"/.well-known/oauth-protected-resource$NormalizedPrefix/mcp"',
        '"/.well-known/oauth-authorization-server$NormalizedPrefix/mcp"',
        '"/.well-known/openid-configuration$NormalizedPrefix/mcp"',
    )
    assert all(route in body for route in expected)
    assert body.count("/.well-known/") == 3
    assert 'oauth-protected-resource$NormalizedPrefix/mcp/"' not in body
    assert 'oauth-authorization-server$NormalizedPrefix/mcp/"' not in body
    assert 'openid-configuration$NormalizedPrefix/mcp/"' not in body


def test_linux_metadata_routes_preserve_ordinary_proxy_and_rollback():
    """RE-EXPRESSED (§4D.0; applied for A4, packet 1246-04-05).

    §4D.0 dispositioned this RE-EXPRESS *"against 1246-06's renderer and `mcp_metadata = true`"* and
    the disposition was **never applied** — the function stayed byte-identical to `31b20651`, and
    rule 4 of the guard checks only PRESENCE, so nothing noticed. A4 is that omission.

    **Both invariants the original defended are preserved and are now stated as what they mean:**

    * the ORDINARY reverse proxy is unconditional — it exists whatever the MCP state, which is why
      the parenthetical said *"present even with `--no-mcp`"*. That flag is retired and MCP always
      installs (§4H.2), so the surviving rule is stronger and is asserted directly: the ordinary
      location/ProxyPass sits OUTSIDE the `MCP_ENABLED` block, so no MCP state can remove it;
    * apache keeps its backup → validate → ROLLBACK discipline, unchanged by the metadata addition.

    And the integrator now demands `mcp_metadata = true` (`_px_read_request` refuses anything else),
    so the metadata routes are not optional either — the retired gate is the only thing that went.
    """
    # 1. THE ORDINARY PROXY, and OUTSIDE the MCP-gated block.
    assert "location ^~ ${PREFIX}/ {" in PROXY_SH
    assert "ProxyPass ${PREFIX}/ http://127.0.0.1:${PORT}/" in PROXY_SH
    gate = PROXY_SH.index('if [[ "$MCP_ENABLED" == "1" ]]; then')
    assert PROXY_SH.index("location ^~ ${PREFIX}/ {") < gate, (
        "the ordinary reverse proxy sits inside the MCP-gated block, so an MCP state could remove it"
    )

    # 2. BACKUP → VALIDATE → ROLLBACK, in that order.
    assert 'cp "$bak" "$conf"' in PROXY_SH and "apache config test FAILED" in PROXY_SH
    assert PROXY_SH.index("apache config test FAILED") < PROXY_SH.rindex('cp "$bak" "$conf"'), (
        "the rollback does not follow the validation that triggers it"
    )

    # 3. `mcp_metadata` is no longer a MODE the installer may choose — the shipped parser refuses
    #    anything but `true`, so the routes this test's siblings assert cannot be gated away.
    from corpusfm.lifecycle import cli

    assert "mcp_metadata" in cli._PX_REQUEST_KEYS["reconcile"]
    assert "mcp_metadata must be exactly true" in inspect.getsource(cli._px_read_request)


def test_linux_authorization_server_metadata_routes_packet_1179():
    # nginx: the two Stage-A-proven prefixed AS metadata forms (exact `location =`), inside the same
    # MCP_ENABLED block as the protected-resource routes.
    assert 'local as="/.well-known/oauth-authorization-server${PREFIX}/mcp"' in PROXY_SH
    assert 'local oidc="/.well-known/openid-configuration${PREFIX}/mcp"' in PROXY_SH
    assert "location = ${as} {" in PROXY_SH and "location = ${oidc} {" in PROXY_SH
    # apache: anchored ProxyPassMatch for both AS forms (exact, no descendant)
    assert 'ProxyPassMatch "^/\\.well-known/oauth-authorization-server${PREFIX}/mcp\\$"' in PROXY_SH
    assert 'ProxyPassMatch "^/\\.well-known/openid-configuration${PREFIX}/mcp\\$"' in PROXY_SH
    # the bare host-root /.well-known/openid-configuration is NOT claimed on a shared FMS box
    assert 'location = /.well-known/openid-configuration ' not in PROXY_SH
    assert 'ProxyPassMatch "^/\\.well-known/openid-configuration\\$"' not in PROXY_SH


# ── A6.1 — first scheduler activation warning (packet 1000-09) ───────────────────────

def test_scheduler_first_activation_is_gated():
    """RE-EXPRESSED from `test_linux_scheduler_first_activation_is_gated` (A6.1).

    **The flag was retired; the invariant was not.** `--no-scheduler` is gone and the scheduler
    always installs (§4H.2) — so *"first activation is gated on the flag"* has no subject. What
    packet 1023 actually established is different and still true: **an upgrade of a box that
    predates the scheduler unit silently activates previously-inert scheduled Jobs**, so the FIRST
    activation must warn or ask before phase 21 starts it. An operator who never ran a scheduler
    should not discover one running because they upgraded.

    Re-expressed against both platforms, because the obligation was never Linux-specific.
    """
    import pathlib as _p
    import re as _re

    root = _p.Path(__file__).resolve().parent.parent
    sh = (root / "installer/linux/install.sh").read_text(encoding="utf-8")
    ps1 = (root / "installer/windows/install.ps1").read_text(encoding="ascii")

    conditions = {
        "linux": r"if\s+\$IS_UPGRADE\s+&&\s+!\s+\$SCHED_UNIT_PREEXISTED\s*;\s*then(?P<body>.*?)\nfi",
        "windows": r"if\s*\(\$IsUpgrade\s+-and\s+-not\s+\$SchedServicePreexisted\)\s*\{(?P<body>.*?)\n\}",
    }
    for name, raw in (("linux", sh), ("windows", ps1)):
        code = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))
        # 1. The installer must be able to TELL a first activation from an already-active scheduler.
        preexisted = _re.search(r"(SCHED_UNIT_PREEXISTED|SchedServicePreexisted|SchedPreexist)\w*",
                                code)
        assert preexisted, f"{name}: nothing distinguishes a first scheduler activation"
        marker = preexisted.group(0)
        # 2. The exact cell is UPDATE + ABSENT. Fresh installs and pre-existing units stay quiet.
        gate = _re.search(conditions[name], code, _re.S)
        assert gate, f"{name}: the first-activation distinction does not gate phase 21"
        assert _re.search(r"\b(warn|Warn|cfm_confirm|Confirm-|Read-Host)\b", gate.group("body")), (
            f"{name}: a first scheduler activation neither warns nor asks for consent")

        # 3. Capture precedes registration/start, and the warning precedes the start.
        capture = code.index(marker)
        warning = gate.start()
        start = (code.index('systemctl start "$_unit"') if name == "linux"
                 else code.index("& $exe start"))
        assert capture < warning < start, (name, capture, warning, start)
