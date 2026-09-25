"""Packet 1246-04-03 — the LINUX 21-phase orchestration.

**Opens `installer/linux/install.sh` and nothing else.** Never `install.ps1`: that is 1246-04-04's,
and a test that reads both is what left neither platform child with a green bar it could reach.

**Scope fence.** 1246-04-02 owns the option and trust surface and proves it in
`test_linux_installer_surface.py`; this module asserts the SEQUENCE. Where the two could overlap,
this one defers — a surface regression should fail 04-02's module, by name.

**Candidate override.** `CFM_INSTALLER_SH` points the suite at an off-tree candidate while it is
being built. It is harness authority only: production never reads it, and the default is the
repository script.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_SH = Path(__file__).resolve().parents[1] / "installer" / "linux" / "install.sh"
SH_PATH = Path(os.environ.get("CFM_INSTALLER_SH", REPO_SH))

#: RULED 2026-08-08: admin_identity FIRST. The patch compartment authenticates to the FMS Admin API
#: with the identity admin_identity creates, so the old order (patch, proxy, admin_identity,
#: storage) asked it to use one that did not exist yet — measured on fms-server, where patch refused
#: `api_required_unavailable` on a fresh box and the install stopped.
PROVIDERS = ["admin_identity", "patch", "proxy", "storage"]
PROTOCOL_F = ["admin_identity", "proxy", "storage"]


@pytest.fixture(scope="module")
def sh() -> str:
    return SH_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def phases(sh: str) -> dict[int, str]:
    """phase number -> its body, in file order."""
    marks = [(int(m.group(1)), m.start(), m.end())
             for m in re.finditer(r"^# ═══ PHASE (\d+) —[^\n]*\n", sh, re.M)]
    out = {}
    for i, (n, _, end) in enumerate(marks):
        stop = marks[i + 1][1] if i + 1 < len(marks) else len(sh)
        out[n] = sh[end:stop]
    return out


def code(body: str) -> str:
    return "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))


def pos(sh: str, needle: str) -> int:
    i = sh.find(needle)
    assert i >= 0, f"not found: {needle!r}"
    return i


# ── the sequence itself ──────────────────────────────────────────────────────


def test_phases_are_exactly_one_to_twentyone_in_order(sh):
    seen = [int(m.group(1)) for m in re.finditer(r"^# ═══ PHASE (\d+) —", sh, re.M)]
    assert seen == list(range(1, 22)), f"phase markers: {seen}"


def test_every_phase_carries_executable_work(phases):
    """A phase marker with nothing under it is a contract that reads as implemented and is not."""
    empty = [n for n, body in phases.items() if not [l for l in code(body).splitlines() if l.strip()]]
    assert not empty, f"phases present but empty: {empty}"


# ── quiesce, replacement, start ──────────────────────────────────────────────


def test_quiesce_precedes_the_first_replacement(sh):
    """Phase 9 stops the services; phase 10 is the first phase that replaces an installed byte."""
    assert pos(sh, "# ═══ PHASE 9 ") < pos(sh, "# ═══ PHASE 10 ")


def test_the_quiesce_phase_actually_stops_services(phases):
    assert re.search(r"systemctl\s+stop", code(phases[9])), "phase 9 stops nothing"


def test_phase_9_quiesces_the_current_service_pair_not_the_retired_mcp(phases):
    body = code(phases[9])
    loop = re.search(r'for _unit in (.*?); do', body)
    assert loop, "phase 9 does not enumerate the services it quiesces"
    assert set(re.findall(r'\$(\w+_SERVICE)', loop.group(1))) == {
        "WEB_SERVICE", "SCHED_SERVICE",
    }
    assert "MCP_SERVICE" not in loop.group(1), "the retired standalone MCP replaced the scheduler"


def _exit_handler(sh: str) -> str:
    start = sh.index("lc_cleanup() {")
    stop = sh.index("trap lc_exit EXIT", start)
    return sh[start:stop]


def _dispatcher(sh: str) -> str:
    start = sh.index("lc_dispatch() {")
    return sh[start:sh.index("\n}", start) + 2]


def _run_exit_handler(tmp_path, sh: str, *, leave=False, phase21=False, ready=True,
                      journal=None, already_active=(), dispatch_rc=None):
    state = tmp_path / "state"
    state.mkdir()
    install = tmp_path / "install"
    python = install / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.symlink_to(sys.executable)
    if journal is not None:
        payload = journal if str(journal).lstrip().startswith("{") else (
            '{"state":"' + journal + '"}\n')
        (state / "lifecycle-journal.json").write_text(
            payload, encoding="utf-8")
    starts = tmp_path / "starts"
    requests = tmp_path / "requests"
    requests.mkdir()
    active = " ".join(already_active)
    script = f'''\
set -u
LC_REQ_DIR={requests!s}
CFM_STATE_DIR={state!s}
INSTALL_DIR={install!s}
LEAVE_SERVICES_STOPPED_FILE={requests / "leave-services-stopped"!s}
QUIESCED_ACTIVE_UNITS=(corpusfm corpusfm-scheduler)
QUIESCE_RESTORE_ARMED=true
QUIESCE_RESTORE_READY={str(ready).lower()}
LEAVE_SERVICES_STOPPED={str(leave).lower()}
PHASE21_OWNS_START={str(phase21).lower()}
warn() {{ :; }}
die() {{ exit 1; }}
systemctl() {{
  if [[ "$1" == is-active ]]; then
    [[ " {active} " == *" $3 "* ]]
    return
  fi
  if [[ "$1" == start ]]; then printf '%s\\n' "$2" >> {starts!s}; return 0; fi
  return 1
}}
{_exit_handler(sh)}
{_dispatcher(sh) if dispatch_rc is not None else ''}
{'( lc_dispatch ' + str(dispatch_rc) + ' test ); rc=$?' if dispatch_rc is not None else '( exit 37 ); rc=$?'}
( exit "$rc" ); lc_exit
'''
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    started = starts.read_text().splitlines() if starts.exists() else []
    return out, started


def test_an_ordinary_pre21_failure_restores_exactly_the_prior_active_set(tmp_path, sh):
    out, started = _run_exit_handler(tmp_path, sh, already_active=("corpusfm-scheduler",))
    assert out.returncode == 37, out.stderr
    assert started == ["corpusfm"]


@pytest.mark.parametrize("leave,phase21,ready,journal", [
    (True, False, True, None),
    (False, True, True, None),
    (False, False, False, None),
    (False, False, True, "open"),
    (False, False, True, "checkpointed"),
    (False, False, True, "needs_recovery"),
])
def test_recovery_or_an_unready_runtime_never_auto_starts_services(
        tmp_path, sh, leave, phase21, ready, journal):
    out, started = _run_exit_handler(
        tmp_path, sh, leave=leave, phase21=phase21, ready=ready, journal=journal)
    assert out.returncode == 37, out.stderr
    assert started == []


def test_a_resolved_record_permits_restoring_the_preexisting_service(tmp_path, sh):
    out, started = _run_exit_handler(tmp_path, sh, journal="resolved")
    assert out.returncode == 37, out.stderr
    assert started == ["corpusfm", "corpusfm-scheduler"]


def test_the_parent_observes_a_leave_stopped_sentinel_written_by_a_subshell(tmp_path, sh):
    out, started = _run_exit_handler(tmp_path, sh, dispatch_rc=5)
    assert out.returncode == 1, out.stderr
    assert started == []
    dispatch = _dispatcher(sh)
    for rc in (3, 5):
        arm = re.search(rf"{rc}\)(.*?);;", dispatch, re.S)
        assert arm and 'LEAVE_SERVICES_STOPPED_FILE' in arm.group(1)


def test_a_nested_resolved_word_cannot_override_an_open_top_level_journal(tmp_path, sh):
    out, started = _run_exit_handler(
        tmp_path, sh, journal='{"state":"open","detail":{"state":"resolved"}}\n')
    assert out.returncode == 37, out.stderr
    assert started == []


def test_no_service_starts_before_phase_21(sh, phases):
    """`systemctl start` and an unguarded `restart` both START a stopped unit."""
    for n, body in phases.items():
        if n == 21:
            continue
        for line in code(body).splitlines():
            hit = re.search(r"systemctl\s+(start|--now\s+enable)\b", line)
            if not hit:
                continue
            # Judge EXECUTED commands, not generated text. Phase 13 writes a sudoers rule whose
            # payload contains `systemctl start corpusfm-update.service` — that AUTHORIZES a later
            # start, it does not perform one, and a string scan cannot tell the difference.
            before = line[:hit.start()]
            emitting = re.search(r"\b(printf|echo|cat)\b", before) or before.count("'") % 2 == 1
            assert emitting, f"phase {n} starts a service before phase 21: {line.strip()}"


def test_the_only_pre_21_service_start_text_is_a_sudoers_grant(phases):
    """Control for the exclusion above — it must not become a blanket exemption.

    If a real `systemctl start` is ever added before phase 21 outside a generated payload, the test
    above fires. This one pins WHAT the permitted occurrences actually are, so the exemption cannot
    silently widen.
    """
    permitted = []
    for n, body in phases.items():
        if n == 21:
            continue
        for line in code(body).splitlines():
            if re.search(r"systemctl\s+start\b", line):
                permitted.append((n, line.strip()))
    for n, line in permitted:
        assert "NOPASSWD" in line and "corpusfm-update.service" in line, (
            f"phase {n} contains a service start that is not the updater sudoers grant: {line}"
        )


def test_phase_21_starts_exactly_what_phase_20_verified(phases):
    """Identity, not merely order: the units 21 starts are the ones 20 wrote and read back."""
    installed = set(re.findall(r'\$(WEB_SERVICE|SCHED_SERVICE)', code(phases[20])))
    started = set(re.findall(r'\$(WEB_SERVICE|SCHED_SERVICE)', code(phases[21])))
    assert installed, "phase 20 installs no recognisable definition"
    assert started <= installed, f"phase 21 starts something 20 never verified: {started - installed}"


def test_definitions_are_installed_after_quiesce(sh):
    assert pos(sh, "# ═══ PHASE 9 ") < pos(sh, "# ═══ PHASE 20 ")


# ── the credential split ─────────────────────────────────────────────────────


def test_the_credential_determination_precedes_the_plan(sh, phases):
    """Phase 6's plan states whether credentials will be asked for, so the determination — which is
    credential-free — must run before it. Fused with the acquisition, phase 6 read a phase-7 fact."""
    assert "NEED_FMS_CREDS=" in code(phases[5]), "the determination is not at phase 5"
    assert pos(sh, "# ═══ PHASE 5 ") < pos(sh, "# ═══ PHASE 6 ")


def test_the_determination_needs_no_credential(phases):
    body = code(phases[5])
    assert "cfm-web-proxy.sh" in body, "the determination no longer reads configuration"
    assert "FM_ADMIN_PASS=" not in body, "the determination acquires a credential"


def test_credential_acquisition_happens_in_preflight(phases):
    assert "fms_present" in code(phases[5]), "credential acquisition left preflight"


# ── composition ──────────────────────────────────────────────────────────────


def test_foundation_publishes_at_phase_11(phases):
    body = code(phases[11])
    assert "composition foundation" in body
    assert re.search(r'CFM_GENERATION.*==\s*"1"|"1"\s*\]\]', body), "generation 1 is not asserted"


def test_the_foundation_request_carries_exactly_the_shipped_keys(phases):
    """The schema is exhaustive: no web facts, no path fields, no expected generation."""
    from corpusfm.lifecycle import cli

    body = phases[11]
    for key in cli._CO_REQUEST_KEYS["foundation"]:
        assert f'"{key}"' in body, f"foundation request omits {key}"
    for forbidden in ("web_prefix", "port", "secrets_dir", "config_dir"):
        assert f'"{forbidden}"' not in body, f"foundation request carries {forbidden}"


def test_the_foundation_records_every_fixed_path_the_linux_uninstaller_must_remove(phases):
    body = phases[11]
    for path in ("/usr/local/bin/corpusfm", "/etc/sudoers.d/corpusfm-db-helper",
                 "/etc/sudoers.d/corpusfm-update", "/etc/tmpfiles.d/corpusfm.conf"):
        assert path in body
    assert '"created_service_account":%s' in body


def test_the_commit_request_carries_exactly_the_shipped_keys(sh):
    from corpusfm.lifecycle import cli

    helper = sh[pos(sh, "lc_commit_provider() {"):]
    helper = helper[:helper.index("\n}")]
    for key in cli._CO_REQUEST_KEYS["commit-provider"]:
        assert f'"{key}"' in helper, f"commit request omits {key}"


@pytest.mark.parametrize("provider,phase", list(zip(PROVIDERS, (15, 16, 17, 18))))
def test_each_provider_commits_in_its_ruled_phase(provider, phase, phases):
    assert f"lc_commit_provider {provider}" in code(phases[phase])


def test_the_provider_order_is_admin_patch_proxy_storage(sh):
    """The order IS the dependency. admin_identity must commit before patch consumes it."""
    order = re.findall(r"lc_commit_provider (\w+)", sh)
    assert order == PROVIDERS, f"provider order: {order}"
    assert order.index("admin_identity") < order.index("patch"), (
        "patch composes before the identity it authenticates with exists")


def test_generations_advance_one_per_provider(sh):
    """foundation 1, then 2,3,4,5 — enforced by the helper, which refuses anything else."""
    helper = sh[pos(sh, "lc_commit_provider() {"):]
    helper = helper[:helper.index("\n}")]
    assert "$((gen + 1))" in helper, "the commit does not require generation+1"
    assert "refusing to continue" in helper, "a wrong generation does not stop the run"


def test_patch_follows_protocol_P_and_has_no_finalize(phases):
    """Its `apply` resolves its own journal, so there is no finalize verb to call."""
    body = code(phases[16])
    assert "patch-compartment apply" in body
    assert "finalize" not in body, "Protocol P has no finalize; calling one is a contract error"


@pytest.mark.parametrize("provider,phase", list(zip(PROTOCOL_F, (15, 17, 18))))
def test_each_protocol_F_provider_finalizes(provider, phase, phases):
    """Names the provider, rather than accepting ANY finalize in the phase.

    The old assertion matched `lc_run "\\w+ finalize"`, so the parametrised provider name was
    decorative: a phase that finalized somebody else satisfied it, and after the 2026-08-08
    reorder the pairing was briefly wrong while the test stayed green.
    """
    assert f'lc_run "{provider} finalize"' in code(phases[phase]), (
        f"{provider} never finalizes in phase {phase}")


def test_every_provider_journal_is_discarded_at_its_boundary(sh):
    """Required, not tidy-up: storage answers foreign_open on the PRESENCE of any journal record, so
    a leftover one stops the NEXT provider before it starts."""
    helper = sh[pos(sh, "# Commit one provider"):pos(sh, "lc_commit_provider() {")]
    assert "discard" in helper.lower(), "the discard requirement is not stated where it is performed"


def test_storage_composition_ready_predicate_is_exact(phases):
    body = phases[18]
    assert "first_administrator_owed" in body, "storage's composable success predicate is not named"
    assert "incomplete_safe" in body


# ── failure and recovery ─────────────────────────────────────────────────────


def test_prior_operation_routing_ends_the_invocation(phases):
    """RE-EXPRESSED (packet 1246-04-04, correction C).

    The rule is unchanged — an operation in flight OWNS the box, and cleanup is never combined with
    new work. What was wrong is what the rule was tested against: this used to assert the string
    `requires_recovery`, which is exactly the key `status --json` DOES NOT EMIT. The guard passed
    while the installer's grep matched nothing on every box, which is the failure mode a spelling
    assertion produces — the test reported the defect as compliance.

    So it now asserts over the vocabulary the CLI really emits, read from the CLI.
    """
    body = code(phases[3])
    assert "requires_recovery" not in body, (
        "the dead grep is back; `requires_recovery()` is an internal Journal predicate and "
        "`status --json` has never emitted a key by that name"
    )
    for state in ("open", "checkpointed", "needs_recovery", "resolved"):
        assert state in body, f"the routing does not answer for journal state {state!r}"
    assert "die" in body, "routing does not end the invocation"


def test_the_routing_reads_only_fields_STATUS_JSON_ACTUALLY_EMITS(phases):
    """The other half: every field phase 3 reads must be one the shipped emitter produces.

    Measured against `cli._status_payload`'s own source rather than a list written here, so a field
    that is renamed there fails this instead of silently reintroducing a dead read.
    """
    import inspect

    from corpusfm.lifecycle import cli as _cli

    source = inspect.getsource(_cli._status) + inspect.getsource(_cli._journal_state)
    emitted = set(re.findall(r'\b(?:report|extra)\["(\w+)"\]', source))
    emitted |= set(re.findall(r'"(\w+)":', source))
    read = set(re.findall(r'lc_json_field "\$_lc_state" (\w+)', phases[3]))
    assert read, "phase 3 reads no status field at all"
    assert read <= emitted, f"phase 3 reads fields nothing emits: {sorted(read - emitted)}"


def test_the_recovery_route_NAMES_THE_SHIPPED_PROTOCOL_for_each_subsystem(phases):
    """Recovery routing is delegated to the shared application disposition boundary."""
    body = code(phases[3])
    assert "lc_preflight_disposition" in body
    assert "LC_RECOVERY_COMMAND" in body
    assert "lc_discard_provider" in body, "a resolved-but-undischarged record is not routed"


def test_incomplete_safe_leaves_the_box_stopped(sh):
    disp = sh[pos(sh, "lc_dispatch() {"):]
    disp = disp[:disp.index("\n}")]
    assert re.search(r"5\).*incomplete_safe", disp, re.S), "exit 5 is unhandled"
    assert "stay STOPPED" in disp or "stays STOPPED" in disp, (
        "an incomplete_safe result does not tell the operator the box is stopped"
    )
    assert re.search(r"5\).*LEAVE_SERVICES_STOPPED_FILE", disp, re.S), (
        "incomplete_safe still lets the EXIT handler restart a service"
    )


def test_every_lifecycle_exit_code_is_handled(sh):
    from corpusfm.lifecycle import cli

    disp = sh[pos(sh, "lc_dispatch() {"):]
    disp = disp[:disp.index("\n}")]
    for rc in sorted(set(cli._CO_EXIT_CODES.values()) | {cli._CO_BAD_REQUEST}):
        assert re.search(rf"^\s*{rc}\)", disp, re.M), f"exit {rc} has no branch"


def test_a_refused_request_is_reported_as_an_installer_defect(sh):
    """Exit 4 means the installer built a request the build rejects — never the box's fault."""
    disp = sh[pos(sh, "lc_dispatch() {"):]
    assert "installer defect" in disp[:disp.index("\n}")]


# ── secret fencing ───────────────────────────────────────────────────────────


#: The keys a SHIPPED schema legitimately spells with a word this test otherwise bans, and what each
#: one is. Named individually, because "it contains the word" is what this test decides on and an
#: unnamed exception would be a hole rather than a rule.
_ALLOWED_FLAGGED_KEYS = {
    # A credential TRANSPORT — never a value. `_px_credential_input_ok` / `_st_transport_ok` refuse
    # anything that is not `absent` (proxy and admin-identity only), `prompt`, `stdin` or `fd:<n>`.
    "credential_input": ("absent", "prompt", "stdin"),
    "admin_credential_input": ("prompt", "stdin"),
    # A DIRECTORY. `secrets_dir` is where the provider reads its own material FROM; the path is not
    # the material, and every provider request in the shipped schemas carries it.
    "secrets_dir": None,
}

_FLAGGED_WORDS = ("password", "token", "secret", "credential", "pem")


def test_no_request_object_carries_a_credential(sh):
    """A request may name an installation and an operation. It may never name a secret.

    RE-EXPRESSED (packet 1246-04-04, correction R5). This banned five substrings outright — and the
    shipped schemas THEMSELVES spell `credential_input`, `admin_credential_input` and `secrets_dir`,
    so the moment the installer's requests were corrected to match the production parsers the ban
    forbade conformance with the very contract it was protecting. Banning the WORD had stopped being
    the same thing as banning the SECRET.

    The rule is unchanged and is now stated directly. Every key whose name carries one of those
    words must be one of the three the shipped schemas define; a transport key must additionally be
    given a transport LITERAL, never a shell variable that could hold a value. Any other flagged key
    is refused exactly as before.
    """
    for m in re.finditer(r"lc_request\s+\S+\s+\"\$\(printf\s+'([^']+)'", sh):
        schema = m.group(1)
        for name, quote, value in re.findall(r'"(\w+)":\s*("?)([^,"}]*)\2', schema):
            if not any(word in name.lower() for word in _FLAGGED_WORDS):
                continue
            assert name in _ALLOWED_FLAGGED_KEYS, (
                f"request schema names {name!r}, which no shipped schema defines: {schema[:80]}"
            )
            allowed = _ALLOWED_FLAGGED_KEYS[name]
            if allowed is None:
                continue
            assert value in allowed or value.startswith("fd:"), (
                f"{name} is given {value!r}, which is not a transport token"
            )
        # …and the words may not appear anywhere OUTSIDE a key name either — not in a value, not in
        # a field this scan did not parse.
        residue = schema
        for name in _ALLOWED_FLAGGED_KEYS:
            residue = residue.replace(f'"{name}"', "")
        for word in _FLAGGED_WORDS:
            assert word not in residue.lower(), (
                f"request schema mentions {word!r} outside a shipped key: {schema[:80]}"
            )


def test_request_files_are_root_owned_and_removed(sh):
    helper = sh[pos(sh, "lc_request() {"):]
    helper = helper[:helper.index("\n}")]
    assert "umask 077" in helper and "chmod 700" in helper
    assert "chown root:root" in helper
    assert "lc_cleanup" in _exit_handler(sh) and "trap lc_exit EXIT" in sh, (
        "request files outlive the composed exit handler"
    )


def test_no_credential_variable_is_interpolated_into_a_request(sh):
    for m in re.finditer(r"lc_request[^\n]*\n(?:[^\n]*\\\n)*[^\n]*", sh):
        blob = m.group(0)
        assert not re.search(r"\$\{?(FM_ADMIN_PASS|CFM_ADMIN_PASS|GIT_PAT|_CFM_FM_PASS_IN)\b", blob), (
            f"a credential reaches a request: {blob[:90]}"
        )


# ── the cutover stays gone ───────────────────────────────────────────────────


def test_no_cutover_module_or_invocation(sh):
    for line in sh.splitlines():
        if line.lstrip().startswith("#"):
            continue
        assert "cutover_cli" not in line and "lifecycle.cutover" not in line


# ── shell integrity ──────────────────────────────────────────────────────────


def test_the_script_parses():
    assert subprocess.run(["bash", "-n", str(SH_PATH)], capture_output=True).returncode == 0


def test_set_u_survives_the_reorder(sh):
    assert re.search(r"^set -euo pipefail", sh, re.M)


def test_the_lifecycle_helpers_are_defined_before_any_phase_uses_them(sh):
    """The reorder's characteristic failure is a block moved ahead of what produces what it reads."""
    assert pos(sh, "lc_commit_provider() {") < pos(sh, "# ═══ PHASE 1 ")
    assert pos(sh, "lc_dispatch() {") < pos(sh, "# ═══ PHASE 1 ")


# ── derived-path census: every path that depends on a parseable input ────────
#
# RC3, found by EXECUTION and invisible to `bash -n` and to every static test here. These are all
# assigned in the prologue, BEFORE the parser runs. That was harmless until 1246-04-02 added
# `--install-dir`: after it, an operator installing to /srv/CORPUSfm still got the bundled
# interpreter written to the DEFAULT /opt/CORPUSfm. The fix re-derives them after parsing, and it
# had to be TRANSITIVE — PY_HOME is computed from PY_BASE and PY_BUNDLED from PY_HOME, so
# re-deriving only the root left the same defect one and two levels down.

DERIVED_FROM_INSTALL_DIR = ["PY_BASE", "PY_HOME", "PY_BUNDLED", "CFM_LIFECYCLE"]


def _redrive_block(sh: str) -> str:
    """The block runs to the next section comment at column 0 that is NOT part of it.

    A naive "cut at the next `# `" stopped at the block's own second line, so the census read an
    almost-empty string and every assertion in it failed for the wrong reason."""
    start = sh.index("# ── Re-derive every path that DEPENDS on a parseable input")
    end = sh.index("# --silent", start)
    return sh[start:end]


@pytest.mark.parametrize("name", DERIVED_FROM_INSTALL_DIR)
def test_every_install_dir_derivative_is_re_derived_after_parsing(name, sh):
    assert re.search(rf"^{name}=", _redrive_block(sh), re.M), (
        f"{name} is derived from INSTALL_DIR but never re-derived after the parser; "
        f"--install-dir would not move it"
    )


def test_the_re_derivation_happens_after_the_parser_and_before_any_consumer(sh):
    parser = sh.index("while [[ $# -gt 0 ]]; do")
    redrive = sh.index("# ── Re-derive every path that DEPENDS on a parseable input")
    first_use = sh.index('[[ -x "$PY_BUNDLED" ]]')
    assert parser < redrive < first_use, "the re-derivation is not between the parser and its consumers"


def test_the_re_derivation_is_transitive(sh):
    """PY_HOME comes from PY_BASE and PY_BUNDLED from PY_HOME. Re-deriving only the root is the
    same defect one level down — which is exactly what the first attempt did."""
    block = _redrive_block(sh)
    assert re.search(r'^PY_HOME="\$PY_BASE/', block, re.M)
    assert re.search(r'^PY_BUNDLED="\$PY_HOME/', block, re.M)


def test_the_default_patch_hosting_dir_follows_the_parsed_install_dir(sh):
    block = _redrive_block(sh)
    assert re.search(r'HOSTING_DIR="\$\{INSTALL_DIR\}-Hosted"', block), (
        "the default hosting directory does not follow --install-dir"
    )


def test_an_explicit_patch_hosting_dir_is_left_exact(sh):
    """`${VAR:-default}` cannot express this: by the re-derivation point the variable already holds
    the pre-parse default, so a second `:-` would read that default as operator authority."""
    assert '--patch-hosting-dir)  HOSTING_DIR="$2"; HOSTING_DIR_EXPLICIT=1' in sh, (
        "the parser does not record that the value was supplied explicitly"
    )
    assert 'if [[ -z "${HOSTING_DIR_EXPLICIT:-}" ]]; then' in _redrive_block(sh), (
        "the re-derivation overwrites an explicitly supplied hosting directory"
    )


def test_fm_db_dir_follows_a_custom_fms_root(sh):
    assert re.search(r'^FM_DB_DIR="\$FMS_ROOT/Data/Databases"', _redrive_block(sh), re.M)


def test_no_default_opt_corpusfm_derivative_survives_a_custom_install_dir(sh):
    """The census, as one assertion: nothing between the parser and the first consumer may still
    hard-code the default root."""
    executable = code(_redrive_block(sh))
    assert "/opt/CORPUSfm" not in executable, (
        f"a default path survives re-derivation: {executable[:120]}"
    )
    # The block's own COMMENT names the default while explaining the defect. A guard whose rationale
    # must name what it forbids has to exclude comments, or it reports its own explanation.
    assert "/opt/CORPUSfm" in _redrive_block(sh), "the rationale no longer explains the defect"


# ── phase 21, EXECUTED — the presence of a start call is not the property ────
#
# The earlier controls asserted a `start` appeared somewhere in phase 21. A half-fix that started
# services only on the fresh path satisfied them, and every upgrade finished with the product
# stopped. These RUN the phase-21 body instead, under both conditions, against a stub systemctl.

PHASE21_HARNESS = """set -euo pipefail
WEB_SERVICE=corpusfm; SCHED_SERVICE=corpusfm-scheduler
VERIFIED_UNITS=("$WEB_SERVICE" "$SCHED_SERVICE")
IS_UPGRADE=%s
INSTALLER_ENTRY_POINT="${LOG}.installer"; touch "$INSTALLER_ENTRY_POINT"
# Production records this before definitions are installed. This harness exercises unconditional
# enable/start, not the first-activation warning, so supply the already-present update shape rather
# than leaving the new observation unbound under `set -u`.
SCHED_UNIT_PREEXISTED=true
CFM_ATTEMPT=false
die() { echo "die: $*"; exit 1; }
ok() { echo "ok: $*"; }
chown() { :; }
chmod() { :; }
stat() { printf 'root:root:700'; }
systemctl() { echo "systemctl $*" >> "$LOG"; }
%s
"""


def phase21_body(sh: str) -> str:
    """The START half of phase 21 only.

    The phase gained a POST-START VERIFICATION block (the 1246-04-03 post-closure correction), which
    makes real network and `sudo` calls — so the start controls slice up to it rather than dragging
    it in. `summary_body` below runs the other half, under its own stubs.
    """
    start = sh.index("# \u2550\u2550\u2550 PHASE 21 ")
    start = sh.index("\n", start) + 1
    return sh[start:sh.index("# \u2500\u2500 POST-START VERIFICATION", start)]


def summary_body(sh: str) -> str:
    start = sh.index("# \u2500\u2500 POST-START VERIFICATION")
    return sh[start:sh.index("# \u2500\u2500 S9 Next steps", start)]


def run_phase21(sh, tmp_path, *, is_upgrade: bool, tag="") -> list[str]:
    log = tmp_path / f"calls-{is_upgrade}{tag}.log"
    script = tmp_path / f"p21-{is_upgrade}{tag}.sh"
    # The phase-21 body enables through the packet-1398 attempt wrapper, a pass-through here.
    wrapper = sh[sh.index("la_unit_toggle() {"):sh.index("\n}\n", sh.index("la_unit_toggle() {")) + 3]
    script.write_text(PHASE21_HARNESS % ("true" if is_upgrade else "false", wrapper + phase21_body(sh)))
    r = subprocess.run(["bash", str(script)], capture_output=True, text=True,
                       env={**os.environ, "LOG": str(log)})
    assert r.returncode == 0, f"phase 21 body failed: {r.stdout}{r.stderr}"
    return log.read_text().splitlines() if log.exists() else []


@pytest.mark.parametrize("is_upgrade", [False, True], ids=["fresh", "upgrade"])
def test_phase_21_enables_and_starts_both_units_on_both_paths(sh, tmp_path, is_upgrade):
    calls = run_phase21(sh, tmp_path, is_upgrade=is_upgrade)
    for unit in ("corpusfm", "corpusfm-scheduler"):
        assert f"systemctl enable {unit}" in calls, f"{unit} not enabled (is_upgrade={is_upgrade})"
        assert f"systemctl start {unit}" in calls, f"{unit} NOT STARTED (is_upgrade={is_upgrade})"


@pytest.mark.parametrize("is_upgrade", [False, True], ids=["fresh", "upgrade"])
def test_removing_the_start_fails_this_control_on_each_path(sh, tmp_path, is_upgrade):
    """The control must die on the mutation it exists for, on EACH path independently."""
    broken = sh.replace('    systemctl start "$_unit" || die', "    : || die", 1)
    calls = run_phase21(broken, tmp_path, is_upgrade=is_upgrade, tag="-broken")
    assert not [c for c in calls if c.startswith("systemctl start")], (
        "the mutation did not remove the start; this control proves nothing"
    )


def test_phase_21_starts_exactly_the_phase_20_verified_set(sh):
    body = code(phase21_body(sh))
    assert 'for _unit in "${VERIFIED_UNITS[@]}"' in body, "phase 21 does not iterate the verified set"
    p20 = sh[sh.index("# \u2550\u2550\u2550 PHASE 20 "):sh.index("# \u2550\u2550\u2550 PHASE 21 ")]
    assert "VERIFIED_UNITS+=(" in p20, "phase 20 never records what it verified"
    assert p20.index("VERIFIED_UNITS+=(") > p20.index("read back"), (
        "a unit is recorded as verified before it is read back"
    )


def test_no_service_start_is_reachable_before_phase_21(sh):
    pre = sh[:sh.index("# \u2550\u2550\u2550 PHASE 21 ")]
    recovery = _exit_handler(sh)
    for ln in pre.splitlines():
        if ln.lstrip().startswith("#"):
            continue
        if not re.search(r"systemctl\s+(start|restart)\b", ln):
            continue
        # EXECUTED commands only. A sudoers payload and an `info` line that tells an administrator
        # what to run later both contain the words and perform nothing.
        if re.search(r"\b(info|warn|ok|echo|printf)\b", ln) or "NOPASSWD" in ln:
            continue
        # The one failure-only recovery path. Executed controls above prove its prior-active set
        # and every veto; it is not an ordinary phase start.
        if ln in recovery and 'systemctl start "$unit"' in ln:
            continue
        assert False, f"a service action is reachable before phase 21: {ln.strip()}"
    assert recovery.count('systemctl start "$unit"') == 1
    for guard in ("QUIESCE_RESTORE_ARMED", "QUIESCE_RESTORE_READY",
                  "LEAVE_SERVICES_STOPPED", "PHASE21_OWNS_START"):
        assert guard in recovery, f"the failure-only restoration lost its {guard} veto"
    assert "restart_web" not in code(sh), "the pre-phase-21 restart helper is back"


def test_final_definitions_come_from_the_canonical_renderer(sh):
    p20 = sh[sh.index("# \u2550\u2550\u2550 PHASE 20 "):sh.index("# \u2550\u2550\u2550 PHASE 21 ")]
    assert "service_identity" in p20 and "render_systemd_unit" in p20
    assert "$INSTALL_DIR/.corpusfm" not in p20, "a transitional .corpusfm grant survives"


def test_the_canonical_units_grant_no_writable_installed_secret():
    from corpusfm.lifecycle import os_layout, service_identity as si

    osl = os_layout.posix_os_layout()
    # `install_dir` is an explicit authority now (packet 1246-04 correction E); the value here is
    # the one `install.sh` supplies, i.e. what a stock installation chooses.
    rendered = {r: si.render_systemd_unit(
                    si.systemd_unit_spec(r, osl, install_dir=si.DEFAULT_POSIX_INSTALL_DIR,
                                         description=f"CORPUSfm {r}"))
                for r in si.SERVICE_ROLES}
    def grants(text):
        return {l.split("=", 1)[1] for l in text.splitlines() if l.startswith("ReadWritePaths=")}

    for role, text in rendered.items():
        for path in grants(text):
            assert ".corpusfm" not in path, f"{role} grants a transitional path: {path}"
            assert not path.startswith(str(osl.secrets_dir)), (
                f"{role} grants a writable installed secret: {path}"
            )


def test_linux_retires_both_global_mcp_token_files_before_phase_21(sh):
    p20 = sh[sh.index("# ═══ PHASE 20 "):sh.index("# ═══ PHASE 21 ")]
    assert '"$CFM_SECRETS_DIR/.mcp_env"' in p20
    assert '"$INSTALL_DIR/.mcp_env"' in p20
    assert 'rm -f -- "$_mcp_env"' in p20
    assert "CORPUSFM_MCP_TOKEN" not in sh


# ── the privileged updater (packet 1246-04-04, correction F item 8) ───────────────────

UPDATER_SH = REPO_SH.parent / "corpusfm-update.sh"


def test_the_updater_is_rendered_by_the_SHIPPED_RENDERER_and_not_by_this_script(phases):
    """The Linux half of correction F, and the direct catch for the five-of-nine defect.

    `install.sh` rendered the updater with a five-expression `sed`. The shipped template carries
    NINE placeholders, so `@@HELPER@@`, `@@PUBLISHER@@`, `@@LIB_DIR@@` and `@@GIT@@` survived into
    the artifact as literal paths — and the phase's own `grep -q '@@'` then died. Phase 13 aborted
    on every run, on every box (recorded as finding F1 at RC3, reachability 1.0).

    The correction is not "add four more `-e` expressions": a second renderer is how a template
    gains a placeholder its installer does not know about. `update_boundary.render_linux_updater()`
    takes nothing, derives all nine from the published record, and refuses on any it did not fill.
    """
    body = code(phases[13])
    assert "render_linux_updater" in body, "the shipped renderer is not called"
    assert 'sed -e "s|@@' not in body, "the installer still hand-renders placeholders"
    assert "grep -q '@@'" in body, "the unrendered-placeholder guard is gone"


def test_the_defect_the_retired_SED_had_is_named_and_the_renderer_covers_it():
    """The discriminating half. Reconstructs what the retired rendering covered and shows that the
    four it dropped are real placeholders in the shipped template — so this is a caught defect, not
    a refactor — then requires the renderer to account for all nine."""
    from corpusfm.lifecycle import update_boundary as _ub

    retired_sed_covered = {"@@INSTALL_DIR@@", "@@STATE_DIR@@", "@@LOG_DIR@@",
                           "@@SRC_DIR@@", "@@VENV_PY@@"}
    shipped = {f"@@{n}@@" for n in re.findall(r"@@(\w+)@@",
                                              UPDATER_SH.read_text(encoding="utf-8"))}
    assert shipped - retired_sed_covered == {"@@HELPER@@", "@@PUBLISHER@@",
                                             "@@LIB_DIR@@", "@@GIT@@"}
    assert shipped <= set(_ub.LINUX_PLACEHOLDERS), (
        f"the renderer knows nothing about {sorted(shipped - set(_ub.LINUX_PLACEHOLDERS))}"
    )


def test_the_updater_is_rendered_only_AFTER_the_foundation_is_published(sh):
    """The renderer resolves the PUBLISHED locator and its agreeing manifest. Rendering before
    phase 11 would refuse — and the refusal would be a `die` on every install, which is the exact
    shape of the defect this correction removes."""
    assert pos(sh, "composition foundation --request") < pos(sh, "render_linux_updater")


# ── the restored POST-START VERIFICATION, EXECUTED (1246-04-03 post-closure correction) ──
#
# `install.sh` lost its whole post-install self-test in the 21-phase conversion: it started the
# units and printed "installed successfully" without checking anything, while `install.ps1` kept its
# Verify stage. Two comments still referred to "the self-test above", which is how the loss stayed
# invisible for a whole packet family — and no §4H parity fact could see it, because none of them
# said a post-install verification had to exist.
#
# **Presence checks are what let it disappear**, so these RUN the block: once with every gate
# healthy, then once per critical gate failing on its own. A verification whose failure path nobody
# has executed is a banner with extra steps.

SUMMARY_HARNESS = """set -euo pipefail
INSTALL_DIR=%(install)s
CFM_CONFIG_DIR=%(install)s/config
mkdir -p "$CFM_CONFIG_DIR"
INSTALL_YAML="$CFM_CONFIG_DIR/install.yaml"; touch "$INSTALL_YAML"
SERVICE_USER=nobody
EXPECTED_REMOTE=https://example.invalid/CORPUSfm.git
CFM_BUILD_COMMIT=abc123
WEB_PORT=8533
WEB_PREFIX=/corpusfm
VERIFIED_UNITS=(corpusfm corpusfm-scheduler)
CFM_ACTIVE=%(active)s
CFM_LOGIN=%(login)s
CFM_STORAGE=%(storage)s
CFM_HTTP=%(http)s
CFM_PROXY=%(proxy)s
CFM_MCP=%(mcp)s
CFM_ATTEMPT=false
die() { echo "DIE: $*"; exit 9; }
ok() { echo "OK: $*"; }
warn() { echo "WARN: $*"; }
info() { echo "INFO: $*"; }
cfm_section() { echo "SECTION: $*"; }
seq() { command seq 1 2; }              # never poll thirty times in a test
sleep() { :; }
systemctl() { [ "$1" = is-active ] && return $CFM_ACTIVE; return 0; }
normalize_remote() { printf '%%s' "$1"; }
stat() {
  case "$*" in
    *install.yaml*) printf 'nobody:nobody:600' ;;
    *src/.git/config*|*.gitconfig*) printf 'root:nobody:640' ;;
    *) printf 'root:root' ;;
  esac
}
curl() {
  local url="${*: -1}"
  case "$url" in
    *:8533/login)  printf '%%s' "$CFM_HTTP" ;;
    *:8533/mcp/)   printf '%%s' "$CFM_MCP" ;;
    */fmi/*)       printf '200' ;;
    *)             printf '%%s' "$CFM_PROXY" ;;
  esac
}
sudo() {                                 # the two python probes, by which flag they carry
  case "$*" in
    *"test -w"*install.yaml*) return 0 ;;
    *"test -w"*) return 1 ;;
    *external_base*) printf 'OK:https://example.invalid/corpusfm' ;;
    *"remote get-url origin"*) printf 'https://example.invalid/CORPUSfm.git' ;;
    *"rev-parse HEAD"*) printf 'abc123' ;;
    *get_backend*) printf '%%s' "$CFM_STORAGE" ;;
    *users_exist*) printf '%%s' "$CFM_LOGIN" ;;
    *)             printf '' ;;
  esac
}
%(body)s
echo "REACHED-END"
"""


def run_summary(sh, tmp_path, *, tag="", active=0, http="200", proxy="200", mcp="401",
                storage="OK:7", login="1"):
    script = tmp_path / f"summary{tag}.sh"
    script.write_text(SUMMARY_HARNESS % {
        "install": str(tmp_path), "active": active, "login": login, "storage": storage,
        "http": http, "proxy": proxy, "mcp": mcp, "body": summary_body(sh)})
    return subprocess.run(["bash", str(script)], capture_output=True, text=True)


def test_the_post_install_verification_PASSES_when_every_gate_is_healthy(sh, tmp_path):
    """THE CLEAN CONTROL. Without it every refusal below is satisfied by a block that always dies."""
    r = run_summary(sh, tmp_path)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    assert "REACHED-END" in r.stdout, "the success path never reached Next steps"
    assert "OK: Post-install verification passed" in r.stdout
    for proof in ("corpusfm active", "Loopback login responds", "Proxied /corpusfm/ responds",
                  "MCP fail-closed", "Storage reachable", "Login user configured",
                  "coexistence verified"):
        assert proof in r.stdout, f"the healthy run never proved: {proof}"


@pytest.mark.parametrize("http", ["200", "301", "302", "307", "308", "401"])
def test_the_loopback_gate_accepts_live_route_dispositions(sh, tmp_path, http):
    """The installed app may redirect an already-configured login to its published mount."""
    r = run_summary(sh, tmp_path, tag=f"loopback-{http}", http=http)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"
    assert f"Loopback login responds (HTTP {http})" in r.stdout
    assert "OK: Post-install verification passed" in r.stdout


@pytest.mark.parametrize("gate,kwargs,expected", [
    ("a verified unit is not active", {"active": 3}, "is NOT active"),
    ("the app does not answer on loopback", {"http": "000"}, "did NOT answer healthily"),
    ("the loopback route is absent", {"http": "404"}, "did NOT answer healthily"),
    ("the loopback app is broken", {"http": "500"}, "did NOT answer healthily"),
    ("the proxied route does not answer", {"proxy": "502"}, "proxied route"),
    ("unauthenticated MCP is accepted", {"mcp": "200"}, "did NOT reject unauthenticated access"),
    ("storage is unreachable", {"storage": "FAIL:OSError"}, "Storage is NOT reachable"),
    ("no login user exists", {"login": "0"}, "No login user yet"),
])
def test_EVERY_CRITICAL_GATE_INDEPENDENTLY_REFUSES_SUCCESS(sh, tmp_path, gate, kwargs, expected):
    """Each failure alone. A verification that only fails when several things break at once would
    pass a box with exactly one thing wrong — which is the ordinary case."""
    r = run_summary(sh, tmp_path, tag=gate.replace(" ", "-"), **kwargs)
    assert r.returncode == 9, f"{gate}: the install reported success anyway\n{r.stdout}"
    assert expected in r.stdout, f"{gate}: the refusal does not say why\n{r.stdout}"
    assert "DIE: Post-install verification FAILED" in r.stdout
    assert "REACHED-END" not in r.stdout, f"{gate}: Next steps was reached over a degraded install"
    assert "Post-install verification passed" not in r.stdout


def test_an_UNKNOWN_login_state_warns_without_refusing(sh, tmp_path):
    """Three outcomes, not two (packet 1201). A storage outage is not a claim that no user exists —
    and refusing an upgrade over a transient read would repeat the same overclaim one layer up."""
    r = run_summary(sh, tmp_path, tag="login-unknown", login="?")
    assert r.returncode == 0
    assert "Could not verify the login user" in r.stdout
    assert "REACHED-END" in r.stdout


def test_FMS_COEXISTENCE_is_reported_but_is_not_ours_to_gate_on(sh, tmp_path):
    """Both halves of the proxy obligation are checked, and only one is critical: FMS's own health
    is the administrator's layer, so a degraded `/fmi/` warns rather than failing our install."""
    body = summary_body(sh)
    assert "/fmi/mwpew/wpe/info" in body, "FMS coexistence is never checked"
    fms = body[body.index("CFM_ST_FMS="):]
    assert "CFM_SELFTEST_CRIT=1" not in fms.split("# 4.")[0], (
        "a degraded FMS /fmi/ fails OUR install; that is the administrator's layer"
    )


def test_the_verification_runs_AFTER_the_units_start_and_BEFORE_next_steps(sh):
    """Order is the whole point: a check that runs before the services start proves nothing about
    the installation the operator is about to be told is finished."""
    start = sh.index('systemctl start "$_unit"')
    verify = sh.index("# ── POST-START VERIFICATION")
    banner = sh.index("CORPUSfm installed successfully")
    assert start < verify < banner


def test_the_fresh_success_tail_reaches_farewell_without_retired_storage_state(sh, tmp_path):
    """The live takeover passed every gate, then a dead FM_DB_READY reference failed under set -u."""
    start = sh.index("if $IS_UPGRADE; then", sh.index("# ── S9 Next steps"))
    tail = sh[start:]
    assert "FM_DB_READY" not in tail
    assert "server_configs.yaml" not in tail
    script = tmp_path / "fresh-success-tail.sh"
    script.write_text(
        "set -euo pipefail\n"
        "IS_UPGRADE=false\n"
        "cfm_section() { echo \"SECTION: $*\"; }\n"
        "ok() { echo \"OK: $*\"; }\n"
        + tail,
        encoding="utf-8",
    )
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True)
    assert result.returncode == 0, f"{result.stdout}{result.stderr}"
    assert "SECTION: Farewell" in result.stdout
    assert "OK: Thank you!" in result.stdout


def test_NO_COMMENT_STILL_CLAIMS_A_SELF_TEST_THAT_DOES_NOT_EXIST(sh):
    """The two stale comments are how the loss stayed invisible — one said the self-test caught
    residue, the other that it die()s on any critical failure, while neither existed."""
    for line in SH_PATH.read_text(encoding="utf-8").splitlines():
        if "self-test" not in line:
            continue
        assert "stayed invisible" in line, f"a stale self-test claim survives: {line.strip()[:100]}"
