"""Installer hardening static checks (Batch 5 of the foundation-completion train).

Three Windows-side gaps were closed to match the Linux installer's existing behavior. PowerShell
isn't on the CI host, so — like test_windows_install_trust — these are static assertions on
installer/windows/install.ps1:
  1. a clean refusal when IIS itself is absent (not a raw WebAdministration stack trace);
  2. stage-before-wipe: the new interpreter is downloaded + checksum-verified BEFORE the running
     services are stopped and $PyDir is wiped (a bad download leaves the old runtime alive);
  3. an MCP fail-closed smoke test in the Verify stage (parity with install.sh's 401 check).
"""

from __future__ import annotations

import pathlib

_PS = pathlib.Path(__file__).resolve().parent.parent / "installer/windows/install.ps1"
_T = _PS.read_text()


# ── 1. missing IIS / URL Rewrite / ARR messaging ────────────────────────────────

def test_webadministration_import_dies_cleanly_when_iis_absent():
    # the import must be guarded so an IIS-less box gets an actionable Die, not a raw module error
    i = _T.index("Import-Module WebAdministration")
    block = _T[i - 10: i + 260]
    assert "try { Import-Module WebAdministration" in _T
    assert "catch { Die" in block and "IIS is not available" in block


def test_url_rewrite_and_arr_detection_still_present_with_msi_names():
    assert "URL Rewrite module missing" in _T and "rewrite_amd64_en-US.msi" in _T
    assert "Application Request Routing (ARR) missing" in _T and "requestRouter_amd64.msi" in _T


def test_does_not_auto_install_iis_components():
    # policy: we detect + instruct, never silently install IIS features
    assert "Install-WindowsFeature" not in _T and "Add-WindowsFeature" not in _T
    assert "dism" not in _T.lower()


# ── 2. stage-before-wipe for the bundled interpreter ────────────────────────────

def test_checksum_mismatch_dies_before_extract():
    mismatch = _T.index("checksum mismatch")
    extract = _T.index("Expand-Archive -Path $zip -DestinationPath $PyDir")
    assert mismatch < extract, "a checksum mismatch must Die before any extract"


# ── 3. MCP fail-closed self-test (parity with install.sh) ───────────────────────

def test_codepost_helper_present():
    assert "function CodePost(" in _T, "need a POST status helper for the MCP smoke test"
    assert "$req.Method = 'POST'" in _T


def test_verify_stage_checks_mcp_fail_closed():
    # the Verify stage must POST the loopback /mcp/ and expect 401, guarded by -not $NoMcp
    # RE-EXPRESSED (packet 1246-04-05): `-NoMcp` is retired — MCP ALWAYS installs (§4H.2) — so the
    # GATE is gone and asserting it would forbid the retirement. The rule it guarded survives and is
    # now unconditional, which is strictly stronger: the verify stage proves the folded-in MCP
    # rejects an unauthenticated request.
    assert 'CodePost "http://127.0.0.1:$WebPort/mcp/"' in _T
    assert "if (-not $NoMcp)" not in _T, "the retired -NoMcp gate is back"
    i = _T.index('CodePost "http://127.0.0.1:$WebPort/mcp/"')
    block = _T[i - 60: i + 320]
    assert "401" in block and "fail-closed" in block.lower()
