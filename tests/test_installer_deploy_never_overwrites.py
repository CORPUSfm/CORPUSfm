"""Packet 1238's two invariants, re-expressed onto the components that now own them (packet 1000-12).

**The original defect.** `fmsadmin ... list files | grep -q CORPUSfm_DB` discards fmsadmin's exit
status (the pipeline reports grep's), so a call that FAILED emits nothing and is indistinguishable
from a clean "not hosted". The installer's inline deploy branch then copied the shipped blank
template onto the destination — which on Linux, with no mandatory file locking, rewrites a live
FMS-hosted `.fmp12` underneath FileMaker Server's open descriptor, destroying the customer's
artifacts, users, settings and AI keys.

Two invariants came out of it, the second load-bearing:

1. "could not ask" is separated from "not hosted" — a non-zero fmsadmin is not an answer;
2. an existing file at the destination stops the deploy, whatever the hosted check said.

**Both survive. Their SUBJECT does not.** This file used to extract the inline Linux deploy block,
the Linux sandbox block and the Windows deploy block by their section-header comments and run them.
All three are deleted: the lifecycle storage provider is the single publisher of the storage
database on both platforms, and an installer that no longer deploys cannot be tested for how it
deploys. Extracting a region that is gone is not a red test finding a regression — it is a harness
asserting against a retired surface, so it is retired here rather than skipped or xfailed.

**Where each invariant lives now**, named so nothing is quietly dropped:

- *Invariant 1* is `storage_identity_ops.collect_facts`: `adapter.list_databases()` returning `None`
  yields `DatabaseKnown.UNKNOWN`, never `NOT_KNOWN` — the same three answers on the Admin-API
  channel that `fm_db_hosted` gave on the fmsadmin one. `storage_identity.classify` routes any
  UNKNOWN axis to `INDETERMINATE`, and `fresh_clause_failures` requires `database_not_known`
  POSITIVELY, so an unanswered question can never satisfy the fresh conjunction. Behavioural
  coverage of the live channel: `tests/test_storage_identity_ops.py
  ::test_an_unavailable_admin_api_never_reaches_proven_fresh`.
- *Invariant 2* is the `target_file_absent` clause of that same conjunction plus the last gate before
  the write — `storage_identity_ops._run_fresh_sequence` refuses `target_occupied` when the target
  exists and this operation's own record does not claim to have placed it. Behavioural coverage:
  `tests/test_storage_identity_ops.py::test_a_planted_existing_database_is_never_overwritten`,
  `::test_resuming_an_interrupted_repair_never_overwrites_the_live_corpus` and
  `::test_placement_refuses_a_target_this_operation_did_not_place`.
- *Single publisher* — that no installer publishes storage AFTER the provider has composed — is
  `tests/test_installer_storage_tail.py`, both platforms.

**What this file keeps for itself**, because nothing else owns it:

- the three-answer shell helper, which still ships in `_cfm_lib.sh`;
- the general form of the defect: no shipped installer or uninstaller may decide anything from a
  `list files` pipeline whose status belongs to the filter;
- single publisher BEFORE the provider — the tail guard starts at the discard marker, so a publisher
  placed earlier in the run would pass it. Nothing in either installer may construct the storage
  destination or invoke the deploy helper at all.
- the fact-level statement of both invariants, each with the control that keeps it honest: a guard
  that only proves refusal is satisfied by a component that refuses everything.

*Observation, not this file's to act on (RC1, product code):* `fm_deploy_template` survives as a
definition in `install.sh` with no caller, and `fm_db_hosted` in `_cfm_lib.sh` now has none either.
Removing shipped code is out of scope here; the guards below pin what matters, which is that neither
is invoked.
"""
from __future__ import annotations

import re
from pathlib import Path

from corpusfm.lifecycle import storage_identity as si

from tests.installer_sim.harness import extract_sh_func, run_bash
from tests.installer_sim.fake_fms import make_fake_fmsadmin

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "installer/linux/install.sh"
INSTALL_PS1 = ROOT / "installer/windows/install.ps1"
UNINSTALL_SH = ROOT / "installer/linux/uninstall.sh"
UNINSTALL_PS1 = ROOT / "installer/windows/uninstall.ps1"
# fm_db_hosted moved to the shared library when packet 1237 needed the same three-answer question in
# the uninstaller. Both of its callers have since gone with the inline publishers; the definition
# ships, so its contract is still exercised below.
CFM_LIB = ROOT / "installer/linux/_cfm_lib.sh"

#: Every shipped script that could ask FileMaker Server what it is hosting.
SHIPPED_SCRIPTS = (INSTALL_SH, CFM_LIB, UNINSTALL_SH, INSTALL_PS1, UNINSTALL_PS1)


def _code(path: Path) -> str:
    """Source with comment lines removed. This file's own rationale names the forbidden shapes, and a
    guard that reports its own explanation is a mistake CLAUDE.md records twice."""
    return "\n".join(ln for ln in path.read_text(encoding="utf-8").splitlines()
                     if not ln.lstrip().startswith("#"))


# ── the shell helper, which still ships ───────────────────────────────────────────────────────────

def test_helper_reports_three_distinct_answers(tmp_path):
    """fm_db_hosted's contract directly: 0 hosted / 1 not hosted / 2 could-not-ask. Poisoning only
    the failure case would leave 'always 2' passing, so all three are asserted in one run."""
    binp = tmp_path / "bin"
    make_fake_fmsadmin(binp, hosted=("CORPUSfm_DB.fmp12",), good_pass="admin")
    script = (
        "set -euo pipefail\n"
        + extract_sh_func("fm_db_hosted", CFM_LIB) + "\n"
        'r=0; FM_ADMIN_PASS=admin  fm_db_hosted CORPUSfm_DB      || r=$?; echo "hosted=$r"\n'
        'r=0; FM_ADMIN_PASS=admin  fm_db_hosted CORPUSfm_Missing || r=$?; echo "absent=$r"\n'
        'r=0; FM_ADMIN_PASS=nope   fm_db_hosted CORPUSfm_DB      || r=$?; echo "failed=$r"\n'
    )
    proc = run_bash(script, {"FM_ADMIN_USER": "admin", "FM_ADMIN_PASS": "admin",
                             "FAKE_FMSADMIN_LOG": str(tmp_path / "fmlog")}, binp)
    assert proc.returncode == 0, proc.stderr
    assert "hosted=0" in proc.stdout
    assert "absent=1" in proc.stdout
    assert "failed=2" in proc.stdout


# ── the defect in its general form, across every shipped script ───────────────────────────────────

def test_no_hosted_check_decides_on_grep_alone():
    """No remaining `list files` pipeline may hand its status to a filter. Widened from the Linux
    installer to every shipped script, because the question moved: the installer asks it once as a
    reachability check and the shared library asks it as a three-answer helper."""
    offences = []
    for path in SHIPPED_SCRIPTS:
        for match in re.finditer(r"list files[^\n]*\|[^\n]*(grep|Select-String|findstr)",
                                 _code(path)):
            offences.append(f"{path.name}: {match.group(0)}")
    assert not offences, f"a hosted decision is made by a status-discarding pipeline: {offences}"


# ── single publisher, from the START of the run ───────────────────────────────────────────────────

def test_no_installer_constructs_the_storage_DESTINATION():
    """The destination is DERIVED by `storage_identity.storage_target` and by nothing else, so an
    installer cannot name it without having decided to write there itself.

    `test_installer_storage_tail.py` owns the same rule from the provider's discard marker onward;
    this one covers the whole script, which is where a publisher placed BEFORE the provider would
    otherwise sit unseen.
    """
    derived = si.storage_target("/anywhere")
    tail = f"{si.STORAGE_SUBDIRECTORY}/{si.STORAGE_DATABASE_FILENAME}"
    assert derived.parts[-2:] == (si.STORAGE_SUBDIRECTORY, si.STORAGE_DATABASE_FILENAME), (
        "the storage destination is no longer derived as subdirectory + filename; this guard is "
        f"looking for the wrong path ({derived})"
    )

    named = []
    for path in SHIPPED_SCRIPTS:
        body = _code(path)
        for spelling in (tail, tail.replace("/", "\\")):
            if spelling in body:
                named.append(f"{path.name}: {spelling}")
    assert not named, f"an installer names the storage destination directly: {named}"


def test_no_installer_INVOKES_the_deploy_helper():
    """The definition survives in `install.sh` with no caller (RC1, recorded in the docstring). What
    must stay true is that nothing calls it — a single call would restore the retired publisher."""
    definition = re.compile(r"^\s*fm_deploy_template\s*\(\)")
    invocations = [ln.strip() for ln in _code(INSTALL_SH).splitlines()
                   if "fm_deploy_template" in ln and not definition.match(ln)]
    assert not invocations, f"the retired deploy helper is called again: {invocations}"


# ── both invariants where they now live, each with its control ────────────────────────────────────

def _fresh_facts(**overrides) -> si.StorageFacts:
    """A box that IS genuinely fresh: FMS installed and answering, the database unknown to it, the
    destination empty, no conflicting copy, no manifest expecting a corpus.

    The bootstrap credential is REFUSED because there is no database to accept it yet — attempted
    and refused, which `validate_relations` permits against a reachable server.
    """
    facts = dict(
        fms_presence=si.FmsPresence.INSTALLED.value,
        database_known=si.DatabaseKnown.NOT_KNOWN.value,
        target_file=si.TargetFile.ABSENT.value,
        hosted_state=si.HostedState.UNKNOWN.value,
        local_material=si.LocalMaterial.ABSENT.value,
        promoted_probe=si.ProbeFact.NOT_ATTEMPTED.value,
        default_probe=si.ProbeFact.REFUSED.value,
        candidate_probe=si.ProbeFact.NOT_ATTEMPTED.value,
        odata=si.Reachability.REACHABLE.value,
        settings_state=si.SettingsState.UNKNOWN.value,
        user_table=si.UserTable.UNKNOWN.value,
        manifest_expectation=si.ManifestExpectation.NO_EXPECTATION.value,
        conflicts=(),
    )
    facts.update(overrides)
    return si.StorageFacts(**facts)


def _is_fresh(facts: si.StorageFacts) -> tuple[bool, tuple[str, ...]]:
    return si.proven_fresh(facts, mode="fresh_install",
                           evidence=si.OperationEvidence.NONE.value)


def test_CONTROL_a_genuinely_fresh_box_is_still_proven_fresh():
    """THE CONTROL for both refusals below. Without it, each is satisfied by a conjunction that has
    stopped admitting anything — which is exactly the failure mode of an installer that refuses to
    deploy at all."""
    ok, failures = _is_fresh(_fresh_facts())
    assert (ok, failures) == (True, ())
    assert si.classify(_fresh_facts()) == si.StorageState.PROVEN_FRESH.value


def test_a_hosted_query_that_COULD_NOT_ANSWER_is_never_read_as_not_hosted():
    """Invariant 1. `list_databases()` returning nothing usable is `UNKNOWN`, and UNKNOWN is its own
    answer: it classifies as indeterminate and fails the clause that a fresh install needs."""
    facts = _fresh_facts(database_known=si.DatabaseKnown.UNKNOWN.value)
    assert si.classify(facts) == si.StorageState.INDETERMINATE.value
    assert "database_not_known" in si.fresh_clause_failures(facts)
    assert _is_fresh(facts)[0] is False


def test_a_file_at_the_DESTINATION_stops_the_fresh_route():
    """Invariant 2, at the conjunction. A present target fails `target_file_absent`, so the route
    that would place the shipped template is not reachable — before any copy is attempted."""
    facts = _fresh_facts(target_file=si.TargetFile.PRESENT.value)
    assert "target_file_absent" in si.fresh_clause_failures(facts)
    ok, _failures = _is_fresh(facts)
    assert ok is False
    assert si.classify(facts) != si.StorageState.PROVEN_FRESH.value


def test_a_destination_that_could_not_be_INSPECTED_is_not_treated_as_absent():
    """The same conflation one layer down: a target the process could not stat is UNKNOWN, and an
    unanswered question about the destination must not become permission to write to it."""
    facts = _fresh_facts(target_file=si.TargetFile.UNKNOWN.value)
    assert si.classify(facts) == si.StorageState.INDETERMINATE.value
    assert "target_file_absent" in si.fresh_clause_failures(facts)
    assert _is_fresh(facts)[0] is False
