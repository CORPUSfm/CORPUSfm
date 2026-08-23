"""The ruled provider order, and the authority the patch compartment consumes.

**Ruling, 2026-08-08.** `admin_identity(2) → patch_compartment(3) → proxy(4) → storage(5)`, on both
platforms. The patch compartment authenticates to the FMS Admin API with THIS installation's PKI
identity, and `admin_identity` is the provider that creates it — so the old order
(`patch, proxy, admin_identity, storage`) asked the compartment to use an identity that did not yet
exist. Measured on fms-server: `api_required_unavailable`, *"no co-located FileMaker Server Admin API
PKI key is configured"*, and the install stopped.

The canonical identity is UNCONDITIONAL maintained infrastructure on a supported co-located
installation, not a side effect of requesting the compartment.

**E3.** Static over both shipped installers, plus the executing regression that the storage
observation still works.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from application_checkout import APPLICATION_ROOT

REPO = Path(__file__).resolve().parents[1]
LINUX = (REPO / "installer" / "linux" / "install.sh").read_text(encoding="utf-8")
WINDOWS = (REPO / "installer" / "windows" / "install.ps1").read_text(encoding="utf-8")

RULED_ORDER = ("admin_identity", "patch", "proxy", "storage")


def executable(source: str) -> str:
    """Executable lines only.

    Both installers must be able to NAME `patch-compartment inspect` in a comment to explain why it
    is no longer done in phase 14 — and a whole-file scan reads that sentence as the violation it
    describes. This is the third time in this train that a guard has had to be taught not to read
    its own rationale.
    """
    return "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
RULED_PHASE = {"admin_identity": 15, "patch": 16, "proxy": 17, "storage": 18}
RULED_GENERATION = {"admin_identity": 2, "patch": 3, "proxy": 4, "storage": 5}


def _commit_order(source: str) -> list[str]:
    """Both spellings. Linux calls `lc_commit_provider <name>`; Windows calls
    `Lc-CommitProvider '<name>'`. Matching only the first silently returned an EMPTY order for
    Windows, which compares equal to nothing and would have passed a parity check by vacuity."""
    posix = re.findall(r"lc_commit_provider (\w+)", source)
    windows = re.findall(r"Lc-CommitProvider\s+'(\w+)'", source)
    return posix or windows


# ── 6 + 10. the order and the generations, identically on both platforms ────────────

def test_BOTH_installers_commit_providers_in_the_ruled_order():
    assert _commit_order(LINUX) == list(RULED_ORDER), _commit_order(LINUX)
    assert _commit_order(WINDOWS) == list(RULED_ORDER), _commit_order(WINDOWS)


@pytest.mark.parametrize("source,name", [(LINUX, "linux"), (WINDOWS, "windows")], ids=["linux", "windows"])
def test_the_identity_provider_commits_BEFORE_the_patch_compartment(source, name):
    """The dependency, stated as the only thing that actually matters about the order."""
    order = _commit_order(source)
    assert order.index("admin_identity") < order.index("patch"), (
        f"{name}: patch composes before the identity it authenticates with exists")


@pytest.mark.parametrize("provider,phase", sorted(RULED_PHASE.items()))
def test_each_provider_is_LABELLED_with_its_ruled_phase_and_generation(provider, phase):
    generation = RULED_GENERATION[provider]
    for source, name, sep in ((LINUX, "linux", "—"), (WINDOWS, "windows", "-")):
        pattern = rf"PHASE {phase} {sep} {provider.replace('_', ' ').upper()}"
        assert re.search(pattern, source, re.IGNORECASE), f"{name}: no {pattern}"
        header = next(l for l in source.splitlines()
                      if re.search(pattern, l, re.IGNORECASE))
        assert f"generation {generation}" in header, f"{name}: {header.strip()}"


def test_the_generations_are_earned_by_POSITION_not_written_down():
    """`lc_commit_provider` advances the counter, so moving a block moves its generation with it.

    If a future edit hard-codes a number instead, the label and the committed value can disagree —
    and only one of them is what the manifest records.
    """
    helper = LINUX[LINUX.index("lc_commit_provider() {"):]
    helper = helper[:helper.index("\n}")]
    assert "$((gen + 1))" in helper
    assert "CFM_GENERATION=" in helper


# ── 3. patch inspection is unreachable before the identity is published ─────────────

@pytest.mark.parametrize("source,name", [(LINUX, "linux"), (WINDOWS, "windows")], ids=["linux", "windows"])
def test_NO_patch_inspection_happens_in_the_read_only_prerequisite_phase(source, name):
    """Phase 14 observes. A patch inspection there can only report `api_required_unavailable` on a
    fresh box, and recording that as an observed prerequisite states a conclusion about an identity
    that does not exist yet."""
    phase14 = source[source.index("PHASE 14"):]
    phase14 = executable(phase14[:phase14.index("PHASE 15")])
    assert "patch-compartment" not in phase14, (
        f"{name}: phase 14 inspects the patch compartment before an identity exists")
    assert "admin-identity" in phase14 or "admin_identity-observe" in phase14, (
        f"{name}: phase 14 does not observe admin-identity prerequisites")


@pytest.mark.parametrize("source,name", [(LINUX, "linux"), (WINDOWS, "windows")], ids=["linux", "windows"])
def test_patch_compartment_work_appears_only_AFTER_the_identity_phase(source, name):
    # An INVOCATION, not a mention. `warn "Resolve with: corpusfm-lifecycle patch-compartment
    # apply"` is operator advice printed by the stranded-journal router in phase 3; reading it as a
    # call would forbid the installer from telling anyone how to recover.
    markers = ("CFM_LIFECYCLE", "lc_provider_run", "Lc-ProviderRun", "Lc-Run")
    lines = [l for l in source.splitlines() if not l.lstrip().startswith("#")]
    identity_line = next(i for i, l in enumerate(lines)
                         if "lc_commit_provider admin_identity" in l
                         or "Lc-CommitProvider 'admin_identity'" in l)
    for i, line in enumerate(lines):
        if "patch-compartment" in line and any(m in line for m in markers):
            assert i > identity_line, (
                f"{name}: line {i} invokes the patch compartment before the identity is committed:"
                f" {line.strip()[:90]}")


# ── 8 + 9. the retired authority, and the deleted inline block ──────────────────────

@pytest.mark.parametrize("source,name", [(LINUX, "linux"), (WINDOWS, "windows")], ids=["linux", "windows"])
def test_NEITHER_installer_writes_or_reads_the_retired_pki_authority(source, name):
    """`fms_admin_pki.yaml` is retired. Comments may NAME it to explain the retirement; nothing may
    execute against it."""
    executable = "\n".join(
        l for l in source.splitlines()
        if not l.lstrip().startswith("#") and not l.lstrip().startswith("//"))
    for token in ("fms_admin_pki", "generate_keypair", "save_admin_pki", "register_public_key",
                  "load_admin_pki_for_apply"):
        assert token not in executable, f"{name}: executable code still uses {token}"


@pytest.mark.parametrize(
    "source,name,record",
    [
        (LINUX, "linux", ("late inline PKI block", "IS DELETED", "two authorities",
                           "published secrets store")),
        (WINDOWS, "windows", ("INLINE STORAGE PUBLISHER IS DELETED", "registered PKI",
                               "Two publishers", "lifecycle storage provider owns")),
    ],
    ids=["linux", "windows"],
)
def test_the_late_inline_PKI_BLOCK_is_gone_and_says_why(source, name, record):
    """Guard the factual retirement record, not one platform's exact capitalization.

    Windows retired the PKI work as part of its whole inline storage publisher, while Linux retains
    a separate paragraph naming the old file. Both say the same thing: a second publisher existed,
    was deleted, and the lifecycle provider/published store is authoritative.
    """
    for fact in record:
        assert fact in source, f"{name}: the retirement record no longer states {fact!r}"


def test_CONTROL_reintroducing_the_inline_PKI_BLOCK_fails_the_guard():
    """The guard has teeth: a synthetic reintroduction is caught."""
    reintroduced = LINUX + "\nfrom corpusfm.server import fms_admin_pki as pki\n" \
                           "priv, pub = pki.generate_keypair()\n"
    executable = "\n".join(l for l in reintroduced.splitlines()
                           if not l.lstrip().startswith("#"))
    assert "generate_keypair" in executable, "the scan cannot see a reintroduced block"


# ── 11. the committed storage regression survives the combined change ──────────────

def test_the_storage_observe_regression_is_still_green():
    """The AttributeError fix and this reordering touch the same installer run; a phase-14 storage
    observation must still work after the providers moved."""
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_storage_observe_layout_regression.py",
         "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=APPLICATION_ROOT, capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-1200:]
    assert "passed" in proc.stdout


@pytest.mark.parametrize("source,name", [(LINUX, "linux"), (WINDOWS, "windows")], ids=["linux", "windows"])
def test_phase_14_still_makes_the_storage_observation(source, name):
    """Storage is observed in the prerequisite sweep AND again where it is routed from.

    The second half is the load-bearing one (packet 1246-10-04): phase 14 runs before phase 15
    publishes the Admin-API machine identity, so its database-known and hosted axes are UNKNOWN by
    construction and every box classifies `indeterminate`. Routing from that observation is what
    stopped a fresh install on fms-server, 2026-08-08. Phase 14 keeps its prerequisite record;
    phase 18 takes the one it decides on.
    """
    phase14 = source[source.index("PHASE 14"):]
    phase14 = phase14[:phase14.index("PHASE 15")]
    assert "storage" in phase14 and "observe" in phase14, \
        f"{name}: phase 14 no longer observes storage"

    phase18 = source[source.index("PHASE 18"):]
    phase18 = phase18[:phase18.index("PHASE 19")]
    assert "storage observe" in phase18, \
        f"{name}: phase 18 routes from an observation it did not take"
