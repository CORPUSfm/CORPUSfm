"""A001's accumulated recovery route, EXECUTED — not merely read.

**The defect this covers.** The composition operation `retire_scheduler_authority` was resumable
from the start, and the real installers could not reach it. Phase 3 sends every retained journal
through the shared provider disposition, `a001_scheduler_authority` is not a provider, so
`_provider_for_journal` answers `None` and `_preflight` raises *"the unresolved lifecycle journal
does not identify its provider"* — the installer dies before A001 step 5 exists.

So these run the REAL `lc_recover_a001_authority` body out of `install.sh`, against stubbed
lifecycle/systemd boundaries, and assert what the installer does at each crash point. Static reads
alone would not have caught the reachability defect, because every static claim about the operation
was true.

The Windows body is asserted structurally in `test_scheduler_retirement_adapter.py` (no PowerShell
execution harness exists here); the SEMANTIC parity of the two is asserted at the end of this file.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

REPO_SH = Path(__file__).resolve().parents[1] / "installer" / "linux" / "install.sh"
SH = REPO_SH.read_text(encoding="utf-8")
PS1 = (Path(__file__).resolve().parents[1] / "installer" / "windows" / "install.ps1").read_text(
    encoding="ascii")


def _fn_body(name: str) -> str:
    """One shell function, brace-matched out of the real script."""
    start = SH.index(f"{name}() {{")
    depth, i = 0, SH.index("{", start)
    for j in range(i, len(SH)):
        if SH[j] == "{":
            depth += 1
        elif SH[j] == "}":
            depth -= 1
            if depth == 0:
                return SH[start:j + 1]
    raise AssertionError(name)


#: Everything the recovery body touches, replaced by observable stubs. `lc_run` is the mutation
#: boundary and is the thing whose ARGUMENTS matter most: the generation it passes is the property
#: several of these tests exist to pin.
#: `set -euo pipefail` MATCHES PRODUCTION. The harness first used `-uo` only, and that silently
#: weakened it: `out="$(lc_run …)"` is a command substitution, so a `die` inside it exits the
#: SUBSHELL, and without `-e` the outer body carried on with an empty `$out`. Production has `-e`,
#: where the assignment inherits the substitution's status and the script stops. A harness laxer
#: than production reports the wrong answer about propagation.
HARNESS = """set -euo pipefail
SCHED_SERVICE_RETIRED=corpusfm-scheduler
CFM_LOG=$LOG.installlog
CFM_LIFECYCLE=(cfm_status_stub)
die() { echo "DIE: $*" >&2; exit 1; }   # STDERR, as `_cfm_lib.sh::die` does
ok()   { echo "OK: $*"; }
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*"; }
lc_json_field() { printf '%%s' "$1" | python3 -c 'import json,sys;d=json.load(sys.stdin);v=d.get(sys.argv[1]);print("" if v is None else v)' "$2"; }
lc_request() { local f; f="$(mktemp)"; printf '%%s' "$2" > "$f"; printf '%%s' "$f"; }
lc_run() {
    local what="$1"; shift
    echo "LC_RUN: $what :: $*" >> "$LOG"
    # the request file is the last argument
    local req="${@: -1}"
    echo "LC_REQUEST: $(cat "$req")" >> "$LOG"
    if [[ "${LC_RUN_REFUSES:-}" == "1" ]]; then
        echo "LC_RUN_REFUSED" >> "$LOG"
        die "$what refused: the a001_scheduler_authority journal and manifest disagree"
    fi
    printf '%%s' "$AFTER_COMMIT_JSON"
}
cfm_status_stub() { printf '%%s' "$AFTER_STATUS_JSON"; }
systemctl() { printf '%%s' "$FAKE_LOADSTATE"; }
%s

_lc_state='%s'
_lc_locator='%s'
_lc_manifest='%s'
_lc_install_dir='%s'
_lc_j_inst='%s'
lc_recover_a001_authority '%s'
echo "REACHED_END"
"""


def OUT(r):
    """die() writes to STDERR (as production does), and a die inside `$( )` would otherwise be
    invisible to a stdout-only assertion — which is exactly the propagation these tests measure."""
    return r.stdout + r.stderr


def _status(*, journal="checkpointed", op="op-1", inst="3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92",
            locator="present", manifest="valid", install_dir="/opt/CORPUSfm", generation=7):
    return json.dumps({"journal": journal, "journal_operation": op, "installation_id": inst,
                       "locator": locator, "manifest": manifest, "install_dir": install_dir,
                       "generation": generation})


def _record(*, state="checkpointed", sub="a001_scheduler_authority", result=None,
            op="op-1", inst="3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"):
    return json.dumps({"operation_id": op, "installation_id": inst,
                       "mode": "a001_scheduler_authority", "state": state,
                       "current_subsystem": sub, "result": result})


def run_recovery(tmp_path, *, record=None, status=None, loadstate="not-found",
                 unit_file_exists=False, commit_generation=8, after=None, tag="t",
                 operation_refuses=False, returned_op=None):
    log = tmp_path / f"calls-{tag}.log"
    status = status or _status()
    st = json.loads(status)
    after = after if after is not None else json.dumps(
        {"journal": "none", "manifest": "valid", "install_dir": st["install_dir"],
         "generation": commit_generation, "installation_id": st["installation_id"]})
    unit = tmp_path / "corpusfm-scheduler.service"
    if unit_file_exists:
        unit.write_text("[Unit]\n")
    body = _fn_body("lc_recover_a001_authority").replace(
        '/etc/systemd/system/${SCHED_SERVICE_RETIRED}.service', str(unit))
    script = tmp_path / f"rec-{tag}.sh"
    script.write_text(HARNESS % (body, status, st["locator"], st["manifest"], st["install_dir"],
                                 st["installation_id"], record or _record()))
    r = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True,
        env={**os.environ, "LOG": str(log), "FAKE_LOADSTATE": loadstate,
             "AFTER_COMMIT_JSON": json.dumps(
                 {"committed_generation": commit_generation, "removed": True,
                  "operation_id": returned_op if returned_op is not None
                  else json.loads(record or _record())["operation_id"]}),
             "AFTER_STATUS_JSON": after,
             "LC_RUN_REFUSES": "1" if operation_refuses else "0"})
    return r, (log.read_text().splitlines() if log.exists() else [])


# ── the four crash points ─────────────────────────────────────────────────────────────────────────

def test_crash_after_begin_before_checkpoint_recovers(tmp_path):
    """`open`, no subsystem yet."""
    r, calls = run_recovery(tmp_path, record=_record(state="open", sub=None), tag="c1")
    assert "OK: A001 authority retirement completed at generation 8" in OUT(r)
    assert any("LC_RUN: A001 authority recovery" in c for c in calls)


def test_crash_after_checkpoint_before_manifest_write_recovers(tmp_path):
    r, calls = run_recovery(tmp_path, tag="c2")
    assert "OK: A001 authority retirement completed at generation 8" in OUT(r)
    assert any("retire-scheduler-authority" in c for c in calls)


def test_crash_after_write_before_commit_recovers(tmp_path):
    """Same journal shape as c2 from the installer's side; the operation distinguishes them."""
    r, _ = run_recovery(tmp_path, record=_record(state="checkpointed"), commit_generation=8,
                        tag="c3")
    assert "OK: A001 authority retirement completed at generation 8" in OUT(r)


def test_crash_after_resolution_before_discard_recovers(tmp_path):
    r, _ = run_recovery(tmp_path, record=_record(state="resolved", result="completed"), tag="c4")
    assert "OK: A001 authority retirement completed at generation 8" in OUT(r)


# ── the CURRENT generation is used, never a remembered one ────────────────────────────────────────

def test_the_current_manifest_generation_is_used_not_a_remembered_one(tmp_path):
    """The interrupted process may have inspected 6; the record now reads 7. The request must carry
    7, because the write it is resuming is CAS'd against the published generation."""
    r, calls = run_recovery(tmp_path, status=_status(generation=7), commit_generation=8, tag="gen")
    req = [c for c in calls if c.startswith("LC_REQUEST:")]
    assert req, OUT(r) + r.stderr
    payload = json.loads(req[0].split("LC_REQUEST: ", 1)[1])
    assert payload["expected_generation"] == 7
    assert payload["installation_id"] == "3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"
    assert payload["install_dir"] == "/opt/CORPUSfm"
    assert "role" not in payload


# ── physical residue refuses, WITHOUT losing the authority ────────────────────────────────────────

def test_a_surviving_unit_file_refuses_and_leaves_the_journal(tmp_path):
    r, calls = run_recovery(tmp_path, unit_file_exists=True, tag="res1")
    assert r.returncode != 0
    assert "still exists" in OUT(r) and "remains untouched" in OUT(r)
    assert not any("LC_RUN" in c for c in calls), "a mutation ran despite physical residue"


def test_a_loaded_systemd_unit_refuses_and_leaves_the_journal(tmp_path):
    r, calls = run_recovery(tmp_path, loadstate="loaded", tag="res2")
    assert r.returncode != 0
    assert "still exposes" in OUT(r) and "remains untouched" in OUT(r)
    assert not any("LC_RUN" in c for c in calls)


# ── contradictory journal shapes refuse ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("record,needle", [
    (_record(state="needs_recovery"), "not a resumable retirement"),
    (_record(state="open", sub="a001_scheduler_authority"), "contradicts itself"),
    (_record(state="checkpointed", sub="storage"), "not a001_scheduler_authority"),
    (_record(state="resolved", sub="a001_scheduler_authority", result="rolled_back"),
     "only a completed retirement"),
    (_record(inst="not-a-uuid"), "not a canonical lowercase UUID"),
    (_record(op=""), "names no operation"),
])
def test_a_contradictory_journal_refuses_without_mutating(tmp_path, record, needle):
    r, calls = run_recovery(tmp_path, record=record, tag=f"bad{abs(hash(needle))%9999}")
    assert r.returncode != 0, OUT(r)
    assert needle in OUT(r)
    assert not any("LC_RUN" in c for c in calls), "a mutation ran on a contradictory journal"


@pytest.mark.parametrize("status,needle", [
    (_status(locator="missing"), "publishes no locator"),
    (_status(manifest="invalid"), "refusing to recover against a record"),
    (_status(generation=0), "refusing to recover A001 against it"),
])
def test_unusable_published_authority_refuses(tmp_path, status, needle):
    r, calls = run_recovery(tmp_path, status=status, tag=f"auth{abs(hash(needle))%9999}")
    assert r.returncode != 0, OUT(r)
    assert needle in OUT(r)
    assert not any("LC_RUN" in c for c in calls)


# ── the read-back after recovery ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("after,needle", [
    ('{"journal":"checkpointed","manifest":"valid","install_dir":"/opt/CORPUSfm","generation":8,'
     '"installation_id":"3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"}',
     "a lifecycle journal is still retained"),
    ('{"journal":"none","manifest":"invalid","install_dir":"/opt/CORPUSfm","generation":8,'
     '"installation_id":"3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"}',
     "no longer reads valid"),
    ('{"journal":"none","manifest":"valid","install_dir":"/elsewhere","generation":8,'
     '"installation_id":"3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"}',
     "published software root changed"),
    ('{"journal":"none","manifest":"valid","install_dir":"/opt/CORPUSfm","generation":99,'
     '"installation_id":"3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"}',
     "but the record reads"),
    ('{"journal":"none","manifest":"valid","install_dir":"/opt/CORPUSfm","generation":8,'
     '"installation_id":"99999999-9999-4999-8999-999999999999"}',
     "published installation identity changed"),
])
def test_the_post_recovery_readback_must_agree(tmp_path, after, needle):
    r, _ = run_recovery(tmp_path, after=after, tag=f"rb{abs(hash(needle))%9999}")
    assert r.returncode != 0, OUT(r)
    assert needle in OUT(r)


# ── recovery ENDS the invocation ──────────────────────────────────────────────────────────────────

def test_successful_recovery_ends_the_invocation_and_demands_a_rerun(tmp_path):
    """Recovery is never combined with the remaining phases: a run that repairs and then installs
    cannot say which half a later failure belongs to."""
    r, _ = run_recovery(tmp_path, tag="end")
    assert r.returncode != 0, "a successful recovery continued into the installation"
    assert "Re-run this Series 2 package to" in OUT(r)
    assert "REACHED_END" not in OUT(r), "control returned to the caller after recovery"


# ── the route is reached BEFORE generic provider disposition, on both platforms ───────────────────

def test_linux_a001_is_recognised_before_generic_provider_disposition():
    code = "\n".join(l for l in SH.splitlines() if not l.lstrip().startswith("#"))
    branch = code.index('if [[ "$_lc_j_mode" == a001_scheduler_authority ]]; then')
    disposition = code.index("            lc_preflight_disposition")
    assert branch < disposition


def test_windows_a001_is_recognised_before_generic_provider_disposition():
    code = "\n".join(l for l in PS1.splitlines() if not l.lstrip().startswith("#"))
    branch = code.index("if ($lcJMode -eq 'a001_scheduler_authority') {")
    disposition = code.index("    Lc-PreflightDisposition")
    assert branch < disposition


def test_a001_is_not_made_a_provider():
    """The provider vocabulary is untouched: A001 is routed ahead of it, not added to it."""
    from corpusfm.lifecycle.installer_disposition import PROVIDERS
    assert PROVIDERS == frozenset({"admin_identity", "patch", "proxy", "storage"})
    for src in (SH, PS1):
        assert "a001_scheduler_authority" in src
    code = "\n".join(l for l in SH.splitlines() if not l.lstrip().startswith("#"))
    assert 'lc_discard_provider "a001' not in code
    assert "PROVIDERS" not in _fn_body("lc_recover_a001_authority")


# ── both platforms reach the same semantic outcome ────────────────────────────────────────────────

def test_both_platforms_assert_the_same_recovery_semantics():
    """Two implementations, one contract. Asserted as a checklist so a platform that quietly drops
    one of them fails here rather than on a box."""
    sh_body = _fn_body("lc_recover_a001_authority")
    i = PS1.index("function Lc-RecoverA001Authority")
    ps_body = PS1[i:PS1.index("\nfunction Lc-RetireSchedulerAuthority", i)]
    for what, sh_needle, ps_needle in [
        ("accepts open",              "open)",                 "'open' {"),
        ("accepts checkpointed",      "checkpointed)",         "'checkpointed' {"),
        ("accepts resolved+completed", 'result" == "completed"', "$result -ne 'completed'"),
        ("refuses other states",      "not a resumable retirement", "not a resumable retirement"),
        ("requires the canonical lowercase UUID",
                                      "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                                      "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
        ("compares the journal id to the PUBLISHED locator",
                                      'lc_json_field "$_lc_state" installation_id',
                                      "Lc-Field $State 'installation_id'"),
        ("compares the journal op to the status op",
                                      'lc_json_field "$_lc_state" journal_operation',
                                      "Lc-Field $State 'journal_operation'"),
        ("checks the returned operation id",
                                      'lc_json_field "$out" operation_id',
                                      "Lc-Field $out 'operation_id'"),
        ("rechecks the identity after recovery",
                                      'lc_json_field "$after" installation_id',
                                      "Lc-Field $after 'installation_id'"),
        ("requires a locator",        "publishes no locator",  "publishes no locator"),
        ("requires a valid manifest", "refusing to recover against a record",
                                      "refusing to recover against a record"),
        ("re-proves physical absence", "systemctl show -p LoadState", "Get-CfmRetiredSchedulerArtifacts"),
        ("uses the current generation", "lc_json_field \"$_lc_state\" generation", "Lc-Field $State 'generation'"),
        ("calls the one operation",   "retire-scheduler-authority", "retire-scheduler-authority"),
        ("rereads status",            "journal)\" == \"none\"", "'journal')) -ne 'none'"),
        ("ends the invocation",       "Re-run this Series 2 package", "Re-run this Series 2 package"),
    ]:
        assert sh_needle in sh_body, f"linux lost: {what}"
        assert ps_needle in ps_body, f"windows lost: {what}"


# ── the OPERATION owns the state matrix; the installer must not second-guess it ───────────────────
#
# The full rule pairs the journal state with whether the manifest still records the scheduler, and
# only the application operation can see both halves. These scripts have no manifest reader. So a
# pair the installer's cheap journal-only checks let through, and the operation then refuses, must
# end the invocation with the journal untouched — never be reinterpreted as recoverable.

def test_an_operation_refusal_ends_the_invocation_and_retires_nothing(tmp_path):
    r, calls = run_recovery(tmp_path, operation_refuses=True, tag="refuse")
    assert r.returncode != 0
    assert "refused" in OUT(r)
    assert any("LC_RUN_REFUSED" in c for c in calls), "the operation was not reached"
    assert "REACHED_END" not in OUT(r), "a refusal was reinterpreted as recoverable"
    assert "A001 authority retirement completed" not in OUT(r)


@pytest.mark.parametrize("state,sub,result", [
    ("open", None, None),
    ("checkpointed", "a001_scheduler_authority", None),
    ("resolved", "a001_scheduler_authority", "completed"),
])
def test_every_journal_shape_the_installer_accepts_is_still_judged_by_the_operation(
        tmp_path, state, sub, result):
    """The installer's checks are a SUBSET. Each shape it accepts must still reach the operation —
    which is what pairs it with the manifest — rather than being treated as settled here."""
    rec = _record(state=state, sub=sub, result=result)
    r, calls = run_recovery(tmp_path, record=rec, operation_refuses=True,
                            tag=f"sub{state}{sub}")
    assert any("LC_RUN: A001 authority recovery" in c for c in calls), \
        f"{state}/{sub} never reached the operation"
    assert r.returncode != 0


def test_the_installer_does_not_discard_a_journal_on_any_path():
    """Nothing in the recovery route retires a record. Only the operation does, and only on success."""
    def _code(text, marker):
        # COMMENTS EXCLUDED. This guard has to name what it forbids, and its own rationale says
        # "nothing here discards a record" — a whole-body scan reports that sentence as the
        # violation. The same mistake has appeared three times in this repository.
        return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(marker))

    import re as _re
    body = _code(_fn_body("lc_recover_a001_authority"), "#")
    # CALLS, not substrings. `resolved)` is a case label for a journal STATE and must not read as a
    # `resolve` call — the first version of this guard tripped on exactly that.
    for retire in (r"\blc_discard_provider\b", r"\bjournal\.discard\b", r"\bjournal\.resolve\b",
                   r"\brm\s+-f\b", r"discard-provider"):
        assert not _re.search(retire, body), \
            f"the recovery route retires a journal itself: {retire}"
    i = PS1.index("function Lc-RecoverA001Authority")
    ps_body = _code(PS1[i:PS1.index("\nfunction Lc-RetireSchedulerAuthority", i)], "#")
    for retire in (r"Lc-DiscardProvider", r"Remove-Item", r"discard-provider"):
        assert not _re.search(retire, ps_body), \
            f"the Windows recovery route retires a journal itself: {retire}"


def test_neither_installer_reads_the_manifest_to_decide_the_matrix():
    """The division of authority, asserted: the scripts judge the journal alone and hand the PAIR to
    the operation. A script that grew a manifest reader would be duplicating a rule that can then
    drift from the one that decides."""
    body = _fn_body("lc_recover_a001_authority")
    i = PS1.index("function Lc-RecoverA001Authority")
    ps_body = PS1[i:PS1.index("\nfunction Lc-RetireSchedulerAuthority", i)]
    for reader in ("installation.json", "manifest\\services", "services["):
        assert reader not in body, f"the linux route reads the manifest: {reader}"
        assert reader not in ps_body, f"the windows route reads the manifest: {reader}"
    # it reads the STATUS view's manifest verdict, which is a different and legitimate thing
    assert "_lc_manifest" in body and "Lc-Field $State 'manifest'" in ps_body


# ── IDENTITY PROOFS — two sources compared, never one against itself ─────────────────────────────
#
# `status.installation_id` is read from the published LOCATOR and `status.journal_operation` from the
# journal state block; the record's own `installation_id`/`operation_id` come from reading the
# journal file directly. Comparing them is a real cross-source check.
#
# The version this replaces compared `$_lc_j_inst` with `$inst` — BOTH read from the same journal
# record. That is a tautology: it can only fail if one of two reads of one file disagree, and it
# proved nothing about whether the journal belongs to the installation being recovered.

def test_a_journal_naming_another_INSTALLATION_refuses(tmp_path):
    r, calls = run_recovery(
        tmp_path,
        record=_record(inst="11112222-3333-4444-5555-666677778888"),
        status=_status(inst="3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b92"), tag="instmm")
    assert r.returncode != 0
    assert "belongs elsewhere" in OUT(r)
    assert not any("LC_RUN" in c for c in calls), "a mutation ran on a foreign journal"


def test_a_journal_naming_another_OPERATION_refuses(tmp_path):
    r, calls = run_recovery(tmp_path, record=_record(op="op-other"),
                            status=_status(op="op-1"), tag="opmm")
    assert r.returncode != 0
    assert "the evidence disagrees with itself" in OUT(r)
    assert not any("LC_RUN" in c for c in calls)


@pytest.mark.parametrize("bad", [
    "------------------------------------",          # thirty-six dashes
    "3F2A1C40-0B7E-4D2A-9C31-5E6F70A81B92",          # uppercase
    "3f2a1c400b7e4d2a9c315e6f70a81b92aaaa",          # right length, no dashes
    "3f2a1c40-0b7e-4d2a-9c31-5e6f70a81b9",           # one short
])
def test_a_malformed_36_character_pseudo_uuid_refuses(tmp_path, bad):
    """`^[0-9a-fA-F-]{36}$` accepted every one of these. It was a length check wearing an identity
    check's clothes."""
    r, calls = run_recovery(tmp_path, record=_record(inst=bad), status=_status(inst=bad),
                            tag=f"uuid{abs(hash(bad))%9999}")
    assert r.returncode != 0, OUT(r)
    assert "not a canonical lowercase UUID" in OUT(r)
    assert not any("LC_RUN" in c for c in calls)


def test_a_result_naming_another_operation_refuses(tmp_path):
    """The composition joined a different record than the one phase 3 routed here."""
    r, _ = run_recovery(tmp_path, returned_op="op-somebody-else", tag="retop")
    assert r.returncode != 0
    assert "finished operation 'op-somebody-else'" in OUT(r)
    assert "A001 authority retirement completed" not in OUT(r)


def test_the_installation_identity_is_rechecked_after_recovery(tmp_path):
    r, _ = run_recovery(
        tmp_path,
        after=json.dumps({"journal": "none", "manifest": "valid", "install_dir": "/opt/CORPUSfm",
                          "generation": 8,
                          "installation_id": "99999999-9999-4999-8999-999999999999"}),
        tag="postid")
    assert r.returncode != 0
    assert "published installation identity changed" in OUT(r)


def test_the_valid_path_still_succeeds_and_still_ends_the_invocation(tmp_path):
    """The control against a guard that refuses everything: the ordinary recovery must still work,
    and must still stop the run."""
    r, calls = run_recovery(tmp_path, tag="valid")
    assert "OK: A001 authority retirement completed at generation 8" in OUT(r)
    assert any("LC_RUN: A001 authority recovery" in c for c in calls)
    assert r.returncode != 0 and "Re-run this Series 2 package to" in OUT(r)
    assert "REACHED_END" not in OUT(r)


def test_linux_no_longer_compares_the_journal_against_itself():
    """The tautology, asserted gone by name."""
    body = _fn_body("lc_recover_a001_authority")
    assert '[[ "$_lc_j_inst" == "$inst" ]]' not in body, "the tautological comparison is back"
    assert 'status_inst="$(lc_json_field "$_lc_state" installation_id)"' in body


def test_neither_platform_keeps_the_permissive_length_check():
    """COMMENTS EXCLUDED. Both scripts now explain in prose what the old `^[0-9a-fA-F-]{36}$` test
    accepted, so a whole-file scan reports the explanation as the violation. Fourth time this exact
    trap has appeared in this repository — the rule is that a guard naming what it forbids must read
    code only."""
    for name, src in (("linux", SH), ("windows", PS1)):
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        assert "[0-9a-fA-F-]{36}" not in code, f"{name}: the permissive length check is back"
        assert "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" in code, \
            f"{name}: the canonical UUID test is missing"
