"""Cross-platform OData preflight (inbox packet 001, Batch 1).

OData is CORPUSfm's REQUIRED FileMaker surface (the storage/backend path). The check now runs in
each installer's pre-mutation Detection phase so an OData-disabled box fails EARLY with actionable
guidance, instead of after Python/deps/services/proxy are installed. The installer REQUIRES the
admin to enable OData in the Admin Console — it never auto-toggles FMS connectors. Static assertions
on both installer scripts (PowerShell/bash aren't both runnable on the CI host), mirroring the other
installer guards.
"""

from __future__ import annotations

import pathlib

_SH = (pathlib.Path(__file__).resolve().parent.parent / "installer/linux/install.sh").read_text()
_PS = (pathlib.Path(__file__).resolve().parent.parent / "installer/windows/install.ps1").read_text()


# ── Linux ───────────────────────────────────────────────────────────────────────

def test_linux_odata_preflight_runs_in_detection_before_mutation():
    pre = _SH.index('Checking OData API (required for the FileMaker storage backend)')
    detection = _SH.index('cfm_section "Detection"')
    progress = _SH.index('cfm_section "Progress"')
    assert detection < pre < progress, "OData preflight must sit in Detection, before Progress/mutation"


def test_linux_odata_accepts_200_or_401_else_dies():
    block = _SH[_SH.index('Checking OData API (required'): _SH.index('Checking OData API (required') + 700]
    assert "200|401)" in block, "200/401 must be treated as enabled"
    assert "die " in block and "OData API is required but not responding" in block
    assert "admin-console" in block.lower(), "Die must point at the Admin Console"


def test_linux_odata_preflight_has_a_total_response_deadline():
    """A completed TCP/TLS connection must not let a stalled FMS response hang Detection."""
    block = _SH[_SH.index('Checking OData API (required'): _SH.index('Checking OData API (required') + 700]
    assert "--connect-timeout 5" in block
    assert "--max-time 15" in block


def test_linux_old_late_hardfail_removed():
    """The early preflight replaced the post-mutation duplicate hard-fail — and the LATE half of the
    rule still stands: OData being enabled at Detection does not prove storage is usable when the
    install finishes, so something after the mutation must still read it and refuse success.

    RE-EXPRESSED (packet 1000-13). The anchor was the post-deploy readiness poll, `Waiting for
    CORPUSfm_DB to become available via OData`, which the 21-phase conversion retired: waiting for
    the DB to appear was replaced by phase 21's Summary check, which does the stronger thing — a
    real read through the SAME backend the app uses, whose failure is CRITICAL. Asserting the wait
    would have pinned a weaker predecessor; the rule is asserted against what now enforces it.
    """
    assert "Re-run this installer after enabling OData." not in _SH

    # A real read through the app's own backend, with BOTH arms present: silence on failure would be
    # the whole defect.
    assert "from corpusfm.storage import get_backend" in _SH, \
        "the post-install storage read is gone — OData at Detection is not proof of a usable store"
    ok_at = _SH.index('ok "Storage reachable')
    bad_at = _SH.index('warn "Storage is NOT reachable')

    # ...and the failure arm is CRITICAL, not a warning under a green banner.
    crit = _SH.index("CFM_SELFTEST_CRIT=1", bad_at)
    assert crit - bad_at < 400, "an unreachable store no longer marks the install critical"

    # ...and critical means the installer REFUSES to report success.
    refusal = _SH.index("[[ $CFM_SELFTEST_CRIT -eq 0 ]]")
    assert ok_at < refusal and crit < refusal, \
        "the storage read is evaluated after the gate that would act on it"
    assert "die " in _SH[refusal:refusal + 400], "a critical self-test no longer dies"
    assert refusal < _SH.index("CORPUSfm installed successfully"), \
        "the success banner is reachable without passing the storage read"


# ── Windows ──────────────────────────────────────────────────────────────────────

def test_windows_odata_preflight_runs_in_detection_before_mutation():
    pre = _PS.index("OData API is required but not responding")
    detection = _PS.index('Section "Detection"')
    progress = _PS.index('Section "Progress"')
    assert detection < pre < progress, "OData preflight must sit in Detection, before Progress/mutation"


def test_windows_odata_accepts_200_or_401_and_dies_with_guidance():
    block = _PS[_PS.index("OData PREFLIGHT"): _PS.index("OData PREFLIGHT") + 1300]
    assert "$odataPre -eq 200 -or $odataPre -eq 401" in block
    assert "Admin Console" in block and "FileMaker OData API" in block


def test_windows_no_longer_auto_enables_odata():
    # the Admin-API connector auto-enable (auto-toggle) is removed — require, don't flip
    assert "enabling the OData + Data API connectors" not in _PS
    assert "_enable.py" not in _PS
    assert '/fmi/admin/api/v2/%s/config' not in _PS and '"fmodata", "fmdapi"' not in _PS


# ── Data API is NOT a primary install requirement ────────────────────────────────

def test_data_api_not_an_install_gate():
    # neither installer fails/gates on the Data API (/fmi/data) — it's a runtime Jobs/DDR-pull
    # dependency (fms_client), not an install prerequisite. OData is the required surface.
    for txt in (_SH, _PS):
        assert "/fmi/data/" not in txt, "installers must not gate on the Data API surface"
