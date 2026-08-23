"""Packet 018 Batch 7a: installer/uninstaller loopback PKI/Admin-API snippets stay quiet.

Admin-API calls run over the FMS web server's https — on the box that's the LOOPBACK
(https://127.0.0.1/…), which can't cert-verify against the FMS public cert (SAN = hostname, not the
loopback IP), so callers pass verify_ssl=False. The resulting urllib3 InsecureRequestWarning must NOT
pollute concise installer output. Silenced at the source (fms_admin_pki module) AND in whatever
inline Python the installer scripts still carry. The suppression is CATEGORY-SCOPED
(InsecureRequestWarning only) so it never hides real PKI/Admin-API errors (those raise / return
status).
"""
from __future__ import annotations

import importlib
import warnings
from pathlib import Path
from application_checkout import APPLICATION_ROOT

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
UNINSTALL_SH = (ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8")
INSTALL_PS = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")
UNINSTALL_PS = (ROOT / "installer/windows/uninstall.ps1").read_text(encoding="utf-8")


def test_fms_admin_pki_module_silences_insecure_warning_at_import():
    from urllib3.exceptions import InsecureRequestWarning
    import corpusfm.server.fms_admin_pki as pki
    importlib.reload(pki)   # re-run the module-level urllib3.disable_warnings(...) in this test
    assert any(f[0] == "ignore" and f[2] is InsecureRequestWarning for f in warnings.filters)


#: Every admin-identity production module, DISCOVERED rather than listed. A hand-written list is
#: what failed here: the guard below once named two of five and omitted `admin_identity_adapter.py`
#: — the one module that actually composes the HTTPS calls, with `verify=False` on every one of
#: them, and therefore the single most likely place for a blanket suppression to be added.
ADMIN_IDENTITY_DIR = APPLICATION_ROOT / "corpusfm/lifecycle"
ADMIN_IDENTITY_MODULES = sorted(p.name for p in ADMIN_IDENTITY_DIR.glob("admin_identity*.py"))

#: The blanket forms. Category-scoped suppression is legitimate and is asserted separately below;
#: what is forbidden is anything that silences a whole process or module.
BLANKET_SUPPRESSION = (
    'simplefilter("ignore")', "simplefilter('ignore')",
    'filterwarnings("ignore")', "filterwarnings('ignore')",
    "disable_warnings()",
    "catch_warnings(",
)


def test_the_admin_identity_module_census_is_complete_and_current():
    """SET EQUALITY, not partial membership — so a sixth module cannot arrive unguarded.

    The count is not written down anywhere else: this compares what is on disk against what the
    guard below iterates, which is the same set by construction. What it pins is that the set is
    DISCOVERED, and that the known modules are all of them.

    `admin_identity_runtime.py` is the sixth, added by packet 1247 (the read-only resolver the running
    application and `fms_folders.build_adapter` share). It is acknowledged here rather than the set
    being loosened: the guard worked exactly as intended — a new module arrived and had to be
    accounted for — and it reaches FileMaker Server through no transport of its own, so the
    blanket-suppression scan below is the whole of what it owes.
    """
    assert set(ADMIN_IDENTITY_MODULES) == {
        "admin_identity.py",
        "admin_identity_store.py",
        "admin_identity_ops.py",
        "admin_identity_adapter.py",
        "admin_identity_recovery.py",
        "admin_identity_runtime.py",
    }


def test_no_admin_identity_module_opens_a_blanket_warning_suppression():
    """Packet 1246-07's primitives live in `fms_admin_pki`, so they inherit its CATEGORY-SCOPED
    suppression; the lifecycle modules reach FileMaker Server only through those primitives and must
    not open a process- or module-wide one of their own.

    Every module in the census is inspected — including the adapter, which is where the real HTTPS
    calls are composed and where a blanket `simplefilter("ignore")` would hide every warning the
    process raises, not merely the loopback certificate one.
    """
    assert ADMIN_IDENTITY_MODULES, "the census found no admin-identity modules at all"
    for name in ADMIN_IDENTITY_MODULES:
        source = (ADMIN_IDENTITY_DIR / name).read_text(encoding="utf-8")
        for forbidden in BLANKET_SUPPRESSION:
            assert forbidden not in source, f"{name} opens a blanket suppression: {forbidden}"


def test_the_repository_wide_suppression_census_is_measured_not_predicted():
    """Every warning-suppression call in the shipped package, and each one accounted for.

    A guard that checks a predicted list proves nothing about a call somebody adds elsewhere. This
    walks the package, so a NEW suppression anywhere fails here and has to be classified by hand —
    which is the point: each one is a deliberate decision, not a default.
    """
    import re

    pattern = re.compile(r"\b(simplefilter|filterwarnings|disable_warnings|catch_warnings)\s*\(")
    found = set()
    for path in (APPLICATION_ROOT / "corpusfm").rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if pattern.search(line) and not line.lstrip().startswith("#"):
                found.add(str(path.relative_to(APPLICATION_ROOT)))
    assert found == {
        # Category-scoped `InsecureRequestWarning` at the three FMS/OData transports.
        "corpusfm/server/fms_admin_pki.py",
        "corpusfm/storage/fm_odata.py",
        # The CLI's own `--quiet` handling, scoped to a command-line request.
        "corpusfm/server/cli/main.py",
    }, sorted(found)
    assert not any(name.startswith("corpusfm/lifecycle/admin_identity") for name in found)


def test_fms_admin_pki_suppression_is_category_scoped_not_blanket():
    src = (APPLICATION_ROOT / "corpusfm/server/fms_admin_pki.py").read_text(encoding="utf-8")
    # the specific category — never a blanket warnings.simplefilter('ignore') that would hide everything
    assert "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)" in src


#: RE-EXPRESSED (packet 1000-13). These two tests named the INLINE PKI register/deregister snippets
#: in the four installer scripts. Those snippets are gone: PKI moved behind the lifecycle components
#: (`fms_admin_pki` and the `admin_identity_*` modules above), so neither uninstaller embeds Python
#: at all any more, and the only inline snippet either INSTALLER still carries is the phase-21
#: storage self-test. Asserting a vanished snippet was asserting the past, and the surviving one had
#: no guard: both carried a BARE `disable_warnings()` — the blanket form this whole file forbids
#: everywhere else. The RULE is unchanged and is asserted where it now lives.
_INLINE_SNIPPET_SCRIPTS = (("install.sh", INSTALL_SH), ("install.ps1", INSTALL_PS))


def _script_code(text: str) -> str:
    """Comment-blind, for the reason this project has now recorded four times: these scripts explain
    at the call site why the suppression is category-scoped, and a scan that reads the explanation
    reports the rule's own rationale as the violation."""
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def test_the_installers_inline_python_suppression_is_category_scoped():
    """The loopback storage read runs with verify_ssl=False, so the warning must be silenced — but
    scoped to InsecureRequestWarning. This snippet is what decides whether the install reports
    storage usable, so a blanket suppression there hides exactly the warnings worth seeing."""
    for name, text in _INLINE_SNIPPET_SCRIPTS:
        code = _script_code(text)
        assert "urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)" in code, (
            f"{name}: the inline storage self-test no longer scopes its urllib3 suppression")


def test_no_installer_script_opens_a_blanket_suppression():
    """CONTROL for the test above, and the half that survives a snippet moving or being deleted:
    whatever inline Python the four scripts carry, none of it may silence a whole process."""
    for name, text in (("install.sh", INSTALL_SH), ("uninstall.sh", UNINSTALL_SH),
                       ("install.ps1", INSTALL_PS), ("uninstall.ps1", UNINSTALL_PS)):
        code = _script_code(text)
        for forbidden in BLANKET_SUPPRESSION:
            assert forbidden not in code, f"{name} opens a blanket suppression: {forbidden}"
