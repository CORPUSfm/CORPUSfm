"""Packet 1246-04-02 — the LINUX option and trust surface.

**This module opens `installer/linux/install.sh` and NOTHING ELSE.** Every existing installer test
that could judge a Linux conversion is cross-platform — `test_installer_conformance.py` reads
`install.sh` and `install.ps1` inside one function — so neither platform child can use them as a
green bar. That is what this module exists to supply.

**Scope fence, stated so a later reader does not mistake silence for a claim.** This packet owns the
option surface and the trust rails. It does **not** own the 21-phase orchestration (packet
1246-04-03), so nothing here asserts phase order, foundation publication, provider composition,
updater registration or service-start ordering. Assertions about those belong in
`test_linux_installer_orchestration.py` and would be false here.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SH_PATH = Path(__file__).resolve().parents[1] / "installer" / "linux" / "install.sh"


@pytest.fixture(scope="module")
def sh() -> str:
    return SH_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def parser(sh: str) -> str:
    """The `case` block only.

    Keyed to the arg-parsing loop rather than the whole file, because the help text deliberately
    NAMES every retired spelling — a scan of the file would report the documentation of a retirement
    as the retirement failing.
    """
    start = sh.index('while [[ $# -gt 0 ]]; do')
    return sh[start:sh.index("\ndone\n", start)]


def code_lines(sh: str) -> list[str]:
    """Executable lines only — comments excluded.

    A guard whose own rationale must name the thing it forbids has to exclude comments from its
    scan, or it reports its own explanation as the violation.
    """
    return [ln for ln in sh.splitlines() if not ln.lstrip().startswith("#")]


def _shell_function(sh: str, name: str) -> str:
    start = sh.index(f"{name}()")
    end = sh.index("\n}\n", start) + 3
    return sh[start:end]


# ── the ten supported semantic option groups ─────────────────────────────────

SUPPORTED = {
    "--install-dir", "--patch-hosting-dir", "--fms-root",
    "--proxy-policy-add", "--proxy-policy-ignore",
    "--repair-storage-access", "--replace-existing-install",
    "--yes", "--silent", "--verbose",
}


def parsed_options(parser: str) -> set[str]:
    """Every spelling the case block actually accepts."""
    found: set[str] = set()
    for arm in re.findall(r"^\s{8}([-|\w]+(?:\|[-\w]+)*)\)", parser, re.M):
        found |= {a for a in arm.split("|") if a.startswith("-")}
    return found


def test_exactly_the_ten_supported_option_groups_parse(parser):
    parsed = parsed_options(parser)
    assert SUPPORTED <= parsed, f"missing: {sorted(SUPPORTED - parsed)}"
    extra = parsed - SUPPORTED - {"-v", "-h", "--help"}
    assert not extra, f"unexpected options accepted: {sorted(extra)}"


def test_the_short_forms_are_exactly_v_and_h(parser):
    """`-v` and `-h` are the only short forms; a new one is a surface change, not a convenience."""
    assert {"-v", "-h"} <= parsed_options(parser)


# ── the eighteen retirements ─────────────────────────────────────────────────

RETIRED = [
    "--port", "--no-pull", "--ref", "--allow-dirty", "--enable-mcp", "--no-mcp",
    "--no-scheduler", "--mcp-port", "--mcp-host", "--mcp-loopback", "--mcp-token",
    "--mcp-lan-subnet", "--fm-admin-user", "--fm-admin-pass", "--admin-user",
    "--admin-pass", "--git-pat", "--assume-yes",
]


def test_the_retirement_list_is_exactly_eighteen():
    assert len(RETIRED) == len(set(RETIRED)) == 18


@pytest.mark.parametrize("option", RETIRED)
def test_every_retired_spelling_reaches_unknown_option_refusal(option, parser):
    """Not aliased, not ignored, not accepted-and-warned — it must fall through to `*)`.

    An option that still parses but no longer does anything is worse than one that is gone: the
    operator's command line keeps working while its meaning changes underneath them.
    """
    assert option not in parsed_options(parser), f"{option} still parses"


def test_the_catch_all_arm_dies_rather_than_warning(parser):
    assert re.search(r'^\s*\*\)\s*die "Unknown option', parser, re.M), (
        "the fall-through arm must die; a warn-and-continue would accept every retired spelling"
    )


def test_install_dir_is_normalized_before_any_dependent_path_is_rederived(sh):
    normalize = sh.index('INSTALL_DIR="$(realpath -m -- "$INSTALL_DIR")"')
    assert normalize < sh.index('PY_BASE="$INSTALL_DIR/python"', normalize)
    assert normalize < sh.index('CFM_LIFECYCLE=(env ', normalize)


@pytest.mark.parametrize(
    "shape,published,expected",
    [
        ("missing", False, "empty"),
        ("empty", False, "empty"),
        ("foreign", False, "foreign"),
        ("trace", False, "unaccounted"),
        ("trace", True, "current"),
    ],
)
def test_install_root_classification_is_about_recorded_ownership(sh, tmp_path, shape, published,
                                                                  expected):
    root = tmp_path / shape
    if shape != "missing":
        root.mkdir()
    if shape == "foreign":
        (root / "somebody-elses-file").write_text("x")
    if shape == "trace":
        (root / "src").mkdir()
    script = _shell_function(sh, "install_root_state") + '\ninstall_root_state "$1" "$2"\n'
    got = subprocess.run(
        ["bash", "-c", script, "test", str(root), str(published).lower()],
        check=True, capture_output=True, text=True,
    ).stdout
    assert got == expected


def test_replace_existing_install_is_consumed_only_for_the_foreign_root(sh):
    function = _shell_function(sh, "prepare_install_root")
    foreign = function[function.index("foreign)"):function.index("unaccounted)")]
    unaccounted = function[function.index("unaccounted)"):]
    assert '"$replace" == true' in foreign and "mv --" in foreign
    assert '"$replace" == true' not in unaccounted
    assert "cannot convert or discard" in unaccounted
    check = 'check_install_root "$INSTALL_DIR" "$PUBLISHED_HERE" "$REPLACE_EXISTING_INSTALL"'
    call = 'prepare_install_root "$INSTALL_DIR" "$PUBLISHED_HERE" "$REPLACE_EXISTING_INSTALL"'
    assert sh.index(check, sh.index("# ═══ PHASE 3")) < sh.index("# ═══ PHASE 7")
    assert sh.index("apt-get update -qq") < sh.index(call) < sh.index(
        "install -d -m 0755 -o root -g root /etc/corpusfm"), (
        "replacement consent is consumed after apt succeeds and before layout writes")


@pytest.mark.parametrize(
    "shape,published,replace,expected_rc,root_survives",
    [
        ("missing", False, False, 0, False),
        ("empty", False, False, 0, True),
        ("foreign", False, False, 97, True),
        ("foreign", False, True, 0, False),
        ("trace", False, False, 97, True),
        ("trace", False, True, 97, True),
        ("trace", True, False, 0, True),
    ],
)
def test_install_root_preparation_executes_every_consent_cell(
        sh, tmp_path, shape, published, replace, expected_rc, root_survives):
    root = tmp_path / shape
    if shape != "missing":
        root.mkdir()
    if shape == "foreign":
        (root / "somebody-elses-file").write_text("x")
    if shape == "trace":
        (root / "src").mkdir()
    script = (
        _shell_function(sh, "install_root_state")
        + _shell_function(sh, "prepare_install_root")
        + '\nwarn() { :; }\ndie() { exit 97; }\nprepare_install_root "$1" "$2" "$3"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script, "test", str(root), str(published).lower(), str(replace).lower()],
        capture_output=True, text=True,
    )
    assert result.returncode == expected_rc
    assert root.exists() is root_survives
    if shape == "foreign" and replace:
        asides = list(tmp_path.glob("foreign.replaced-*"))
        assert len(asides) == 1
        assert (asides[0] / "somebody-elses-file").read_text() == "x"


def test_no_retired_spelling_survives_as_an_alias(parser):
    """A `|` alias is the exact shape this retirement could regress into."""
    for arm in re.findall(r"^\s{8}([-|\w]+(?:\|[-\w]+)*)\)", parser, re.M):
        for alias in arm.split("|"):
            assert alias not in RETIRED, f"{alias} survives as an alias of {arm}"


# ── retired variables and their downstream consumers ─────────────────────────

GONE = ["ORIG_ARGS", "CFM_PULLED", "CFM_REEXEC_FILE", "CFM_CONSENT_CARRIED",
        "NO_PULL", "GIT_REF", "ALLOW_DIRTY"]


@pytest.mark.parametrize("name", GONE)
def test_no_executable_line_references_a_retired_variable(name, sh):
    """Removal means the CONSUMERS go too — not a dead default with no way to set it."""
    hits = [ln.strip() for ln in code_lines(sh) if re.search(rf"\b{name}\b", ln)]
    assert not hits, f"{name} still consumed at: {hits[:3]}"


def test_the_self_pull_and_its_re_exec_are_gone(sh):
    body = "\n".join(code_lines(sh))
    assert "exec env CFM_PULLED" not in body
    assert "pull --ff-only origin main" not in body, "the installer still fetches its own code"
    assert "--detach" not in body, "the pinned-ref checkout survives"


# ── the trust rails: unconditional and unwaivable ────────────────────────────

def test_origin_and_clean_tree_are_both_asserted(sh):
    body = "\n".join(code_lines(sh))
    assert "assert_origin" in body and "assert_clean_tree" in body


def test_no_flag_can_waive_either_trust_rail(sh):
    """The rails were parameterised by `--allow-dirty`; no flag can waive them now.

    **SCOPE, corrected 2026-08-06.** This module previously described them as unconditional against
    "whatever checkout is being installed". They are not: they run on the SUPPORTED IN-PLACE UPDATE
    path — re-running the installer from the installation's own `src/` — and nowhere else. They do
    not adjudicate fresh-install or external-checkout provenance, and claim no defence against a
    malicious installer. That was a reporting defect, not a behaviour defect; the call site is
    unchanged.

    **Re-expressed after this assertion was wrong.** It first forbade `&& return 0` anywhere in the
    function — but the clean-tree rail's SUCCESS path is exactly `[[ -z "$dirty" ]] && return 0`,
    and forbidding that would forbid the rail passing. The property is narrower and is the one
    `--allow-dirty` actually violated: **no return may be conditioned on a caller-supplied value.**
    """
    body = sh[sh.index("assert_clean_tree() {"):]
    body = body[:body.index("\n}")]
    assert "ALLOW_DIRTY" not in body, "the waiver variable is back"
    for ln in body.splitlines():
        if "return 0" in ln:
            assert "dirty" in ln, (
                f"a return is conditioned on something other than the tree's own state: {ln.strip()}"
            )


def test_no_refusal_message_names_a_retired_option(sh):
    """A refusal that tells the operator to re-run with an option that no longer exists is worse
    than no advice at all — it sends them to a command line that dies at the parser.

    Found by this module: the clean-tree refusal still offered `--no-pull` and `--allow-dirty`.
    """
    # Scan the whole MESSAGE, not the line that starts it. A `die "...` message wraps across
    # several lines, and only the first contains `die` — a line-based scan let a second instance of
    # exactly this defect survive in `assert_origin` while reporting the file clean.
    body = "\n".join(code_lines(sh))
    messages = re.findall(r'\b(?:die|warn|info|ok|echo|printf)\b[^"\n]*"((?:[^"\\]|\\.)*)"',
                          body, re.S)
    assert messages, "no operator messages were found; this scan is no longer reading anything"
    for msg in messages:
        named = [o for o in RETIRED if re.search(rf"{re.escape(o)}(?![\w-])", msg)]
        assert not named, f"{named} named in an operator message: {msg.strip()[:110]!r}"


def test_the_message_scan_reads_wrapped_messages(sh):
    """Control for the scan above — it must see a retired option on a CONTINUATION line.

    Without this the scan silently narrows back to first-lines-only and reports a clean file.
    """
    probe = 'die "Refused for a reason.\n     Fix it, or re-run with --no-pull to skip."'
    messages = re.findall(r'\b(?:die|warn|info|ok|echo|printf)\b[^"\n]*"((?:[^"\\]|\\.)*)"',
                          probe, re.S)
    assert messages and any("--no-pull" in m for m in messages), (
        "the scan cannot see a retired option on a wrapped message line"
    )


def test_the_clean_tree_rail_still_refuses(sh):
    body = sh[sh.index("assert_clean_tree() {"):]
    assert "die" in body[:body.index("\n}")], "the rail must refuse, not warn"


# ── credential transport ─────────────────────────────────────────────────────

def test_public_source_has_no_pat_authority(sh):
    """The retired option may be refused, but no PAT value or embedded credential may exist."""
    assert "GIT_PAT=" not in sh
    assert "EMBEDDED_PAT=" not in sh
    assert 'REPO_URL="https://github.com/CORPUSfm/CORPUSfm.git"' in sh


@pytest.mark.parametrize("var,env", [
    ("FM_ADMIN_USER", "FM_ADMIN_USER"),
    ("CFM_ADMIN_USER", "CORPUSFM_ADMIN_USER"),
    ("CFM_ADMIN_PASS", "CORPUSFM_ADMIN_PASS"),
])
def test_credentials_come_from_the_environment_not_argv(var, env, sh, parser):
    assert re.search(rf'^{var}="\$\{{{env}:-\}}"', sh, re.M), f"{var} is not env-sourced"
    assert not any(o in parsed_options(parser) for o in
                   ("--fm-admin-user", "--fm-admin-pass", "--admin-user", "--admin-pass")), (
        "a credential option survives in the parser"
    )


def test_no_credential_reaches_console_or_log_output(sh):
    """A secret must not reach stdout or the install transcript.

    **Narrowed after this assertion was too broad.** It first forbade a credential on any line
    containing `printf`, which caught `printf '%s' "$GIT_PAT" > .git-pat` — the SANCTIONED headless
    credential-helper file, whose whole purpose is to persist that token. Writing a secret to a
    protected file is not leaking it; printing it is. So redirected writes are excluded here and
    their protection is asserted separately below.
    """
    secret = re.compile(r"\$\{?(FM_ADMIN_PASS|CFM_ADMIN_PASS|_CFM_FM_PASS_IN|GIT_PAT)\b")
    for ln in code_lines(sh):
        if re.search(r">\s*\"?\$\w", ln):
            continue                      # a redirected write, judged by the protection test below
        # A PIPE INTO A CHILD IS THE SANCTIONED TRANSPORT, not console output. `storage
        # create-first-admin` takes `admin_credential_input: "stdin"` — the shipped schema has no
        # form that carries the value — so the password must reach it on stdin, and
        # `printf '%s' "$CFM_ADMIN_PASS" | …` is exactly how. What this test forbids is a secret
        # reaching a TERMINAL or a LOG; a pipe reaches neither. Excluded by the same reasoning the
        # redirected-write exclusion above already uses, and narrowly: only when the printf's output
        # is consumed by a command on the same line. (Correction R5, packet 1246-04-04.)
        # …including when the pipe is on the CONTINUATION line: `lc_fms_frame` writes the
        # credential frame with `printf … \` on one line and `| python -c` on the next.
        if re.match(r"^\s*(?:_?\w+=)?\"?\$?\(?\s*printf\b[^|]*(?:\||\\\s*$)", ln):
            continue
        # Judge the printed ARGUMENTS, not the whole line: a guard that condition-tests a secret and
        # then prints an unrelated message is not leaking it, and scanning the line said it was.
        for call in re.findall(r"\b(?:echo|printf|info|warn|ok)\b([^;&|]*)", ln):
            assert not secret.search(call), f"a credential reaches console output: {ln.strip()}"


def test_no_source_pat_file_is_created_and_private_era_files_are_removed(sh):
    assert not re.search(r">\s*\"\$INSTALL_DIR/\.git-pat(?:-helper)?\"", sh)
    cleanup = sh[sh.index("configure_public_source() {"):]
    assert 'rm -f "$INSTALL_DIR/.git-pat" "$INSTALL_DIR/.git-pat-helper"' in cleanup


# ── consent ──────────────────────────────────────────────────────────────────

def test_consent_is_collected_once_by_the_process_that_does_the_work(sh):
    """The re-exec token existed so a run that fetched code could carry consent into its child.

    There is no child now, so there is no carried consent — and no sentinel that could suppress the
    confirmation on a first run, which is the failure packet 1236 found.
    """
    body = "\n".join(code_lines(sh))
    assert "CFM_CONSENT_CARRIED" not in body
    assert "corpusfm-reexec" not in body
    assert 'cfm_section "Confirm"' in body, "the confirm section is gone entirely"


# ── the retired cutover invocation ───────────────────────────────────────────

def test_no_executable_line_invokes_or_imports_the_cutover(sh):
    """`cutover.py` / `cutover_cli.py` were removed from the product; they were never written.

    Comments are excluded deliberately: the block explaining the removal has to name what it
    removed.
    """
    for ln in code_lines(sh):
        assert "cutover_cli" not in ln, f"a live cutover invocation survives: {ln.strip()}"
        assert "lifecycle.cutover" not in ln


# ── help truth ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def help_block(sh: str) -> str:
    return sh[sh.index("# Usage:"):sh.index("# Updates button:")]


@pytest.mark.parametrize("option", sorted(SUPPORTED))
def test_help_documents_every_supported_option(option, help_block):
    assert option in help_block, f"{option} is supported but undocumented"


def test_help_does_not_OFFER_a_retired_option(help_block):
    """Offering is a line that presents it as usable; NAMING it under 'RETIRED' is the opposite."""
    offered = help_block[:help_block.index("# RETIRED, and REJECTED")]
    for option in RETIRED:
        assert not re.search(rf"^#\s+{re.escape(option)}\b", offered, re.M), f"{option} is offered"


def test_help_identifies_every_retirement(help_block):
    """An operator whose old command line now fails must learn why from `--help`."""
    retired_section = help_block[help_block.index("# RETIRED, and REJECTED"):]
    missing = [o for o in RETIRED if o not in retired_section]
    assert not missing, f"retirements not disclosed: {missing}"


def test_help_states_the_environment_credential_rule(help_block):
    assert "FM_ADMIN_USER" in help_block and "CORPUSFM_ADMIN_USER" in help_block
    assert "NEVER PASSED AS OPTIONS" in help_block


# ── shell safety ─────────────────────────────────────────────────────────────

def test_the_script_parses(sh):
    assert subprocess.run(["bash", "-n", str(SH_PATH)], capture_output=True).returncode == 0


def test_set_u_is_on_and_every_new_variable_is_declared(sh):
    assert re.search(r"^set -euo pipefail", sh, re.M)
    for name in ("PROXY_POLICY_ADD", "PROXY_POLICY_IGNORE",
                 "REPAIR_STORAGE_ACCESS", "REPLACE_EXISTING_INSTALL"):
        assert re.search(rf"^{name}=", sh, re.M), (
            f"{name} is appended to or read by the parser but never declared; under `set -u` that "
            f"aborts the run at the first use"
        )


def test_the_two_new_arrays_are_declared_as_arrays(sh):
    for name in ("PROXY_POLICY_ADD", "PROXY_POLICY_IGNORE"):
        assert re.search(rf"^{name}=\(\)", sh, re.M), f"{name} must be an array; the parser uses +=("


def test_the_repeatable_options_append_rather_than_overwrite(parser):
    for name, opt in (("PROXY_POLICY_ADD", "--proxy-policy-add"),
                      ("PROXY_POLICY_IGNORE", "--proxy-policy-ignore")):
        arm = re.search(rf"{re.escape(opt)}\)\s*(.+?);;", parser, re.S)
        assert arm and f'{name}+=("$2")' in arm.group(1), f"{opt} must append, not replace"


def test_every_option_value_is_quoted(parser):
    """`--install-dir /opt/My Install` must not word-split."""
    for assignment in re.findall(r'^\s{8}--[\w-]+\)\s+(\w+)=(\S+)', parser, re.M):
        _, value = assignment
        if value.startswith("$"):
            assert value.startswith('"') or value in ('$2',) or '"' in value, (
                f"unquoted option value: {assignment}"
            )


def test_unknown_option_refusal_exits_nonzero(sh):
    """`die` must terminate; a `die` that returned would fall through to the install."""
    body = sh[sh.index("die() {"):] if "die() {" in sh else ""
    if body:
        assert "exit 1" in body[:body.index("\n}")], "die must exit non-zero"


def test_both_trust_rails_are_REACHED_on_the_in_place_update_path(sh):
    """The assertions above check each rail's BODY. Neither checks that it is ever CALLED.

    That gap let an overstated claim pass green: a rail with an impeccable body and no reachable
    call site would satisfy every other test in this module. This is the narrow control — on the
    supported in-place-update condition, both rails run.
    """
    guard = re.search(
        r'if \$IS_UPGRADE && \[\[ "\$REPO_DIR" == "\$INSTALL_DIR/src".*?\nfi\n', sh, re.S)
    assert guard, "the in-place-update guard is gone; the rails may no longer be reached at all"
    body = guard.group(0)
    assert "assert_origin" in body, "the origin rail is not called on the in-place-update path"
    assert "assert_clean_tree" in body, "the clean-tree rail is not called on the in-place-update path"


def test_the_module_claims_no_universal_checkout_verification(sh):
    """A guard against the specific overstatement, in the script and in this module."""
    for blob, what in ((sh, "install.sh"), (Path(__file__).read_text(), "this module")):
        for claim in ("whatever checkout is being installed", "unconditional on every source"):
            # A QUOTED occurrence is a citation of the retired wording; an unquoted one asserts
            # it. Without that distinction this guard reports its own correction — which quotes the
            # claim in order to retire it — as the violation.
            live = [l for l in blob.splitlines()
                    if claim in l and f'"{claim}' not in l and f"'{claim}" not in l]
            assert not live, f"{what} still claims {claim!r}: {live[:1]}"


# ── phase 12: the keys, at the FIXED secrets directory ────────────────────────────────
#
# Measured on fms-server 2026-08-08: the block this replaced guarded on
# `$INSTALL_DIR/.corpusfm/{corpus,secret,machine,server}.key` — the RETIRED home — and created the
# keys as $SERVICE_USER, which cannot write the administrator-owned fixed secrets directory. The
# failure downgraded to "created on first use" and phase 15 refused for want of a Machine Key. Each
# assertion below is one half of that defect.

def test_phase_12_does_not_detect_keys_in_the_RETIRED_home(sh: str):
    """The guards must not read `$INSTALL_DIR/.corpusfm/<key>` — the resolver stopped using it."""
    body = "\n".join(line for line in sh.splitlines() if not line.lstrip().startswith("#"))
    for name in ("corpus.key", "secret.key", "machine.key", "server.key"):
        assert f'$INSTALL_DIR/.corpusfm/{name}' not in body, \
            f"phase 12 still detects {name} in the retired home"


def test_phase_12_has_NO_first_use_continuation(sh: str):
    """"Created on first use" was a lie: nothing in the runtime writes the fixed secrets directory."""
    assert "created on first use" not in sh.lower(), \
        "the warning path that let a missing key reach phase 15 is still here"


def test_phase_12_provisions_through_the_PRIVILEGED_lifecycle_operation(sh: str):
    assert "provision-keys" in sh, "phase 12 does not invoke the key-provisioning operation"
    # `lc_run`, not `lc_run_raw`: lc_run dispatches a non-zero exit into `die`, which is what makes
    # a failure fatal before phase 15 rather than a warning carried past it.
    assert re.search(r'lc_run "key provisioning" provision-keys --request', sh), \
        "key provisioning is not run through the dispatching runner, so a failure would not be fatal"


def test_phase_12_does_not_create_the_keys_AS_THE_SERVICE_USER(sh: str):
    """The fixed secrets directory is administrator-owned and service-non-writable, by policy."""
    assert not re.search(r'sudo -u "\$SERVICE_USER".*get_machine_key', sh), \
        "the keys are still created as the service account, which cannot write the secrets directory"


def test_the_RETIRED_marker_setters_are_not_invoked(sh: str):
    """`corpusfm set-hosting-dir` / `set-support-dir` went with packet 1246-05-02's marker keys.

    They were still being called, failed on every install because the subcommands no longer exist,
    and printed a warning whose remedy named the same retired command.
    """
    for retired in ("set-hosting-dir", "set-support-dir"):
        assert not re.search(rf'corpusfm\.server\.cli\s+{retired}', sh), \
            f"the installer still invokes the retired {retired}"
