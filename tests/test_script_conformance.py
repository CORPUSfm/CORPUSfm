"""Installer-family script conformance to the S1-S10 contract (installer/SPEC.md).

This is the static enforcer named in the SPEC's "Script conformance" + "Validation harness"
sections. Every shipped CLI script (Tier 1 + Tier 2) must:

  1. source/dot-source the shared library (_cfm_lib.sh / _cfm_lib.ps1),
  2. define NO local output primitives (they live in the library only), and
  3. invoke ALL TEN contract sections, in order (empty ones are ceremonial no-ops, never omitted).

The library files themselves are exempt (they DEFINE the primitives). Tier-3 build/ scripts are
out of scope (not shipped, not operator-facing).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parent.parent / "installer"

# The ten canonical sections, in order. A script's i-th section call must START WITH the i-th
# title (case-insensitive) - descriptive suffixes are allowed ("Detection - orientation"), but
# identity + order are enforced.
CANONICAL_SECTIONS = [
    "Hello",
    "Self-check",
    "Settings",
    "Permissions",
    "Detection",
    "Confirm",
    "Progress",
    "Summary",
    "Next steps",
    "Farewell",
]

# Tier-1 operator-facing lifecycle scripts — the full S1-S10 skeleton is mandatory + enforced here.
# _cfm_lib.* are excluded (they ARE the library). The Tier-2 helpers are NOT enforced for the full
# skeleton on purpose (see installer/SPEC.md "Script conformance"): cfm-db-helper.sh is a
# security-critical sudoers root broker kept deliberately minimal + auditable, cfm-web-proxy.sh
# edits FMS's own web config with rollback, cfm-mcp-ctl.sh + cfm-storage-swap.sh are retired
# (install.sh removes their installed copies + grants), and package-installer.sh is a Tier-3
# build/release script. Forcing the ceremonial skeleton onto a root security boundary is not
# "within reason"; a later, careful pass can unify their output primitives.
BASH_SCRIPTS = [
    "linux/install.sh",
    "linux/uninstall.sh",
]
PS_SCRIPTS = [
    "windows/install.ps1",
    "windows/uninstall.ps1",
]

# Primitives that must NOT be redefined in a script body (the library owns them).
BANNED_BASH_PRIMITIVE = re.compile(
    r"^\s*(hello|info|ok|warn|die|success|header)\s*\(\)\s*\{", re.MULTILINE
)
BANNED_PS_PRIMITIVE = re.compile(
    r"^\s*function\s+(Hello|Info|Ok|Warn|Die|Section)\b", re.MULTILINE | re.IGNORECASE
)

SOURCE_BASH = re.compile(r"(?m)^\s*(?:source|\.)\s+\S*_cfm_lib\.sh")

# PowerShell dot-source detection (packet 1233). The previous pattern ended in an unanchored
# alternation — `^\s*\.\s+\S*_cfm_lib\.ps1|_cfm_lib\.ps1` — and `|` has the LOWEST precedence in a
# regex, so the whole thing collapsed to "contains the filename anywhere" and was satisfied by
# install.ps1's own prose comments. It passed with the dot-source line deleted.
#
# It got that way because install.ps1 dot-sources through a VARIABLE (`$LibPath = Join-Path
# $PSScriptRoot '_cfm_lib.ps1'` … `. $LibPath`), which the anchored form genuinely missed — so the
# regex was widened until it went green instead of taught the real shape. Both real shapes are
# matched explicitly below; there is no escape hatch.
_PS_DOT_SOURCE_LITERAL = re.compile(r"(?m)^\s*\.\s+[^#\n]*_cfm_lib\.ps1")
_PS_LIB_VAR_ASSIGN = re.compile(r"(?m)^\s*\$(\w+)\s*=\s*[^#\n]*_cfm_lib\.ps1")


def _ps_dot_sources_library(text: str) -> bool:
    """True iff the script really dot-sources _cfm_lib.ps1 — literally, or via a variable assigned
    from it. A bare mention (comment, prose, help text) must never satisfy this."""
    if _PS_DOT_SOURCE_LITERAL.search(text):
        return True
    for var in _PS_LIB_VAR_ASSIGN.findall(text):
        if re.search(rf"(?m)^\s*\.\s+\${var}\b", text):
            return True
    return False

# Sanctioned one-sided library helpers (packet 1231). An exemption list is exactly how a guard
# quietly stops guarding, so each entry carries its reason and the list stays short.
#   - the five output primitives are `hello`/`Hello`, not `cfm_hello`/`Cfm-Hello`, so neither
#     pattern above sees them; they need no exemption.
#   - `cfm_section` ⇄ `Section` is the SPEC's named exception — a bare unambiguous noun whose two
#     spellings read as the same thing; renaming would churn ~20 call sites for no legibility gain.
#   - the rest are language-private internals with no counterpart to have.
# Every entry must be NECESSARY as well as justified: an exemption for a function that does have a
# twin is dead weight that would silently absorb a real future gap.
_PARITY_EXEMPT_BASH = {
    "section",      # PowerShell twin is the bare `Section` (SPEC-sanctioned exception)
}
_PARITY_EXEMPT_PS = {
    "runone",       # private to Cfm-RunSteps; bash's `_cfm_run_one` is underscore-private, not `cfm_*`
    "logline",      # private log writer; bash's `_cfm_logline` is likewise underscore-private
    "ts",           # private timestamp helper; bash's `_cfm_ts` is underscore-private
}

SECTION_BASH = re.compile(r"""(?m)^\s*cfm_section\s+["']([^"']+)["']""")
SECTION_PS = re.compile(r"""(?m)^\s*Section\s+["']([^"']+)["']""")

# Invariant (SPEC.md §4): credentials are the *means* to mutate, never consent. The §6 Confirm
# skip must be gated on a consent flag, never on a credential variable. We enforce the contrapositive
# structurally: no credential *variable reference* appears in the §6 Confirm section body. (The
# announce text may say the word "credentials"; it must not branch on the credential value.)
CRED_BASH = re.compile(r"\$\{?FM_ADMIN_(PASS|USER)")
CRED_PS = re.compile(r"\$FmAdmin(Pass|User)", re.IGNORECASE)


def _read(name: str) -> str:
    return (INSTALLER / name).read_text(encoding="utf-8")


def _section_body(text: str, runner: re.Pattern, title: str) -> str:
    """Return the slice of `text` from the named cfm_section/Section call to the next one.

    A section that cannot be found is a FAILURE, never an empty string (packet 1233). The old
    `return ""` fell open: an empty body satisfies every assertion made against it, so a miss here
    would have silently disarmed `test_credentials_do_not_gate_confirm` on the affected scripts while
    the suite reported green — the same shape as the other two guards that packet repaired.
    """
    marks = list(runner.finditer(text))
    for i, m in enumerate(marks):
        if m.group(1).lower().startswith(title.lower()):
            end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
            return text[m.end():end]
    raise AssertionError(
        f"section {title!r} not found — found {[m.group(1) for m in marks]}. "
        "A missing section must fail loudly; an empty body would pass every assertion."
    )


def _assert_ordered_sections(titles: list[str], script: str) -> None:
    assert len(titles) == len(CANONICAL_SECTIONS), (
        f"{script}: expected {len(CANONICAL_SECTIONS)} section calls, found {len(titles)}: {titles}"
    )
    for i, (got, want) in enumerate(zip(titles, CANONICAL_SECTIONS), start=1):
        assert got.lower().startswith(want.lower()), (
            f"{script}: section {i} is {got!r}, expected to start with {want!r}"
        )


@pytest.mark.parametrize("script", BASH_SCRIPTS)
class TestBashConformance:
    def test_sources_shared_library(self, script):
        text = _read(script)
        assert SOURCE_BASH.search(text) or (
            script == "linux/install.sh" and
            'source "$SCRIPT_DIR/_cfm_lib.sh"' in text
        ), f"{script} does not source _cfm_lib.sh"

    def test_defines_no_local_primitives(self, script):
        m = BANNED_BASH_PRIMITIVE.search(_read(script))
        assert not m, f"{script} defines a banned local primitive: {m.group(1) if m else ''}()"

    def test_credentials_do_not_gate_confirm(self, script):
        """RE-EXPRESSED (packet 1246-04-05). The rule is unchanged — **a credential must never gate
        the consent prompt** — and it is now asserted on the PROMPT rather than on a section slice.

        §4H moved credential acquisition to phase 7, which sits inside the Confirm section's
        boundaries, so a whole-section variable ban began flagging an informational branch about the
        reverse proxy that gates nothing. Banning the variable there would have forbidden the ruled
        phase order; what actually matters is that `cfm_confirm` is not reached conditionally on a
        credential being present.
        """
        body = _section_body(_read(script), SECTION_BASH, "Confirm")
        for line in body.splitlines():
            if "cfm_confirm" not in line or line.lstrip().startswith("#"):
                continue
            m = CRED_BASH.search(line)
            assert not m, (
                f"{script}: the consent prompt is gated on a credential "
                f"({m.group(0) if m else ''}) — credentials must never gate confirmation"
            )
        # …and the prompt must actually be there, or this passes vacuously.
        assert "cfm_confirm" in body, f"{script}: the Confirm section asks for no consent"


@pytest.mark.parametrize("script", PS_SCRIPTS)
class TestPowerShellConformance:
    def test_sources_shared_library(self, script):
        assert _ps_dot_sources_library(_read(script)), f"{script} does not dot-source _cfm_lib.ps1"

    def test_defines_no_local_primitives(self, script):
        m = BANNED_PS_PRIMITIVE.search(_read(script))
        assert not m, f"{script} defines a banned local primitive: function {m.group(1) if m else ''}"

    def test_credentials_do_not_gate_confirm(self, script):
        body = _section_body(_read(script), SECTION_PS, "Confirm")
        # Usernames and validation readiness belong in the informed plan. The credential must not
        # decide whether the one consent call happens, so inspect that call rather than banning an
        # informational username from the entire section.
        calls = [line for line in body.splitlines()
                 if "Cfm-Confirm" in line and not line.lstrip().startswith("#")]
        assert calls, f"{script}: the Confirm section asks for no consent"
        for line in calls:
            m = CRED_PS.search(line)
            assert not m, (
                f"{script}: the consent prompt is gated on a credential "
                f"({m.group(0) if m else ''}) — credentials must never gate confirmation"
            )


class TestLibrariesPresent:
    def test_consent_is_granted_by_a_positive_match_never_a_negation(self):
        """The consent gate must test FOR a yes, never AGAINST one.

        MEASURED on a live box 2026-07-31: with stdin closed, PowerShell's `Read-Host` returns
        `$null`, and `$null -notmatch '<pattern>'` evaluates to EMPTY rather than `$true`. The abort
        branch never ran, `Cfm-Confirm` returned as though consent were given, and a non-interactive
        uninstall with no consent flag **removed a real install**.

        Both libraries must match positively so an absent, null, or unreadable answer means NO. The
        bash twin was already correct (`case "$reply" in [Yy])` is a positive match), which is why
        only PowerShell was wrong — assert both so neither drifts.
        """
        ps = _read("windows/_cfm_lib.ps1")
        fn = ps[ps.index("function Cfm-Confirm"):ps.index("function Cfm-Confirm") + 1600]
        # COMMENTS EXCLUDED. This guard's own rationale has to name `-notmatch` to explain the
        # hazard, so scanning raw text makes the guard report itself — CLAUDE.md records that exact
        # mistake twice (test_windows_nginx_proxy.py, test_no_native_select.py) and this was the third.
        code = "\n".join(l for l in fn.splitlines() if not l.lstrip().startswith("#"))
        assert "-notmatch" not in code, (
            "Cfm-Confirm must not branch on a NEGATED match — a null reply makes that expression "
            "empty, not true, so the abort silently does not happen.")
        assert re.search(r'if \("\$reply" -match ', ps), (
            "Cfm-Confirm must positively match a yes, with $reply coerced to a string")
        sh = _read("linux/_cfm_lib.sh")
        body = sh[sh.index("cfm_confirm()"):sh.index("cfm_confirm()") + 900]
        assert re.search(r"\[Yy\]\)", body), "cfm_confirm must positively match a yes"

    def test_consent_is_never_inherited_from_the_environment(self):
        """packet 1236 — an exported variable must not grant consent.

        `CFM_ASSUME_YES` and `CFM_FORCE` were seeded `${VAR:-false}`, copied from `CFM_SILENT` where
        the idiom is legitimate (silence is an OUTPUT mode a Tier-2 helper genuinely inherits).
        Consent is not an output mode. `CFM_FORCE` was the sharp case: exported, it granted INSTALLER
        consent through a flag the installers deliberately do not accept.

        Asserted as ABSENCE of the inheriting idiom, so the rule survives renaming the variables.
        """
        lib = _read("linux/_cfm_lib.sh")
        for var in ("CFM_ASSUME_YES", "CFM_FORCE"):
            assert not re.search(rf'{var}="\$\{{{var}:-', lib), (
                f"{var} must NOT be seeded from the environment — consent comes from parsed flags "
                "only, or a stale export/`sudo -E` turns a first run into an unconfirmed one.")
            assert re.search(rf"(?m)^{var}=false$", lib), f"{var} must default false unconditionally"

    def test_fm_password_is_unexported_immediately(self):
        """packet 1236 — the FM admin password must not be inherited by unrelated children.

        Linux kept `FM_ADMIN_PASS` exported through apt-get, git and pip (which runs third-party
        package code); Windows left `$env:FM_ADMIN_PASS` set for most of the run. SPEC §4 promises the
        credential is "used transiently", and packet 1234 now tells the operator so at the prompt — a
        variable inherited by pip is not transient in the sense the operator will hear.
        """
        # Uninstallers now hold a plan-requested one-use credential locally. They must wipe the
        # value after the framed call and never source it from an inherited environment entry.
        for script in ("linux/uninstall.sh", "windows/uninstall.ps1"):
            text = _read(script)
            assert "$env:FM_ADMIN_PASS" not in text
            assert "used for this run only" in text
            assert ("unset FM_ADMIN_PASS" in text or "$planPass = ''" in text
                    or "$script:LcCredentialPass = ''" in text)
        for script, needle in (("linux/install.sh", "unset FM_ADMIN_PASS"),
                               ("windows/install.ps1", "$env:FM_ADMIN_PASS = $null")):
            text = _read(script)
            assert needle in text, f"{script}: must clear the environment entry after capturing it"
            # …and do it EARLY: before the first child process could inherit it
            first_clear = text.index(needle)
            for child in ("apt-get update", "Cfm-Run", "gitsu ", "& $Git "):
                if child in text:
                    assert first_clear < text.index(child), (
                        f"{script}: clears FM_ADMIN_PASS after {child!r} has already run — every "
                        "intervening child inherits the password, which is the defect.")
                    break

    def test_the_UNINSTALLERS_use_only_plan_bound_FMS_authority(self):
        """The launcher may validate a transient credential only after the typed plan requires it.

        The rule (packet 1232, a developer ruling on security grounds): *a privileged local tool must
        not let someone holding root but NOT FMS admin credentials use it to dismantle FMS-side
        state, and no flag confers FMS authority — `--force` tolerates a step that FAILED, never a
        precondition that is ABSENT.*

        It used to be enforced by a `die` in §4 of each uninstaller, and that shape carried two
        problems of its own: the credential was demanded UP FRONT, from a local guess at whether FMS
        work was owed (`command -v fmsadmin` plus a marker file), and it was demanded even on the
        runs that would never have needed one.

        No flag confers FMS authority; inability to authenticate leaves the operation owed.
        """
        for script in ("linux/uninstall.sh", "windows/uninstall.ps1"):
            # COMMENTS EXCLUDED. Both files explain at length what they no longer do, and a guard
            # that read its own subject's rationale as a violation is noise — the mistake this
            # repository has made twice and written down both times.
            from tests.test_uninstall_stage_fence import _executable_lines

            text = "\n".join(_executable_lines(INSTALLER / script))
            for capability in ("Admin API", "admin_identity", "proxy_transaction", ".fmp12"):
                assert capability not in text, (
                    f"{script} can reach {capability}; a launcher that performs FMS work is a "
                    "launcher that can be made to perform it without FMS authority")
            # `force` reaches exactly one place: the request field the lifecycle component reads.
            assert "credential_transport" in text
            assert "credential_required" in text
            assert "used for this run only" in text

    def test_FORCE_reaches_ONLY_the_request_and_never_a_credential_decision(self):
        """`--force` means *continue past work that cannot be completed now*. It has never meant
        *proceed without authority*, and the launcher is where that distinction used to be enforced
        by prose. It is structural now: force is one boolean field of the request, and the component
        decides what it permits."""
        sh, ps = _read("linux/uninstall.sh"), _read("windows/uninstall.ps1")
        assert '"force": os.environ["FORCE"] == "true"' in sh or "os.environ[\"FORCE\"]" in sh
        assert "force                = [bool]$script:CfmForce" in ps
        for text in (sh, ps):
            # No branch anywhere makes a CREDENTIAL decision from force.
            for line in text.splitlines():
                lowered = line.lower()
                if "force" in lowered and not lowered.strip().startswith("#"):
                    assert "credential" not in lowered, line

    def test_common_option_interface_is_the_same_on_all_four(self):
        """packet 1230 — the §3 common-interface flags, and the ONE deliberate divergence.

        Before this, no flag was present on all four scripts and the gaps did not fall along any
        principled line: installers had silent+yes, uninstallers had force+yes, and nothing named a
        reason for either half. A difference that divides by SCRIPT KIND rather than by consequence
        is the signature of drift.

        `--force` is the exception and it is a DECISION, asserted here so it cannot be "fixed" back:
        it means continue-past-failed-steps, which an uninstaller needs (its stages are conditionally
        present — you find out what is there) and an installer must not have (its fallible stages are
        optional, served by `--no-<stage>`, and forcing past them produces the half-installed box the
        health gate exists to catch).
        """
        sh_i, sh_u = _read("linux/install.sh"), _read("linux/uninstall.sh")
        ps_i, ps_u = _read("windows/install.ps1"), _read("windows/uninstall.ps1")
        for name, text, flags in (
            ("install.sh", sh_i, ("--silent", "--verbose", "--yes")),
            # `--keep-data` LEFT this list at stage 6: it is retired on both platforms, and the
            # catch-all refuses it as unknown rather than accepting it and doing nothing.
            ("uninstall.sh", sh_u, ("--silent", "--verbose", "--yes", "--force")),
        ):
            for f in flags:
                assert f"{f})" in text or f"{f}|" in text or f"|{f})" in text, f"{name} does not parse {f}"
        for name, text, flags in (
            ("install.ps1", ps_i, ("$Silent", "$Yes")),
            ("uninstall.ps1", ps_u, ("$Silent", "$Yes", "$Force")),
        ):
            param = text[text.index("param("):text.index("param(") + 1500]
            for f in flags:
                assert f"[switch]{f}" in param, f"{name} does not declare {f}"

        assert "--keep-data)" not in sh_u and "$retired += '-KeepData'" in ps_u, (
            "keep-data is retired on BOTH platforms: Linux has no case arm so the catch-all refuses "
            "it, and Windows declares it only to refuse it by name. A retirement honoured on one "
            "platform is a retirement that did not happen.")
        assert "--force)" not in sh_i, (
            "install.sh must NOT accept --force: it means continue-past-failed-steps, and every "
            "installer stage where that is legitimate is served by a --no-<stage> opt-out. "
            "Uninstall-only is a documented divergence (installer/SPEC.md), not a gap to close.")
        assert "[switch]$Force" not in ps_i[ps_i.index("param("):ps_i.index("param(") + 1500], (
            "install.ps1 must NOT declare -Force — see install.sh above.")

    def test_declared_flags_reach_the_library_gears(self):
        """packet 1230 — a declared flag must be WIRED, not merely accepted.

        Three defects of this exact shape existed simultaneously: `uninstall.ps1 -Verbose` arrived via
        [CmdletBinding()] and was never mapped; `install.ps1 -Silent` granted consent and suppressed
        prompts while every banner still printed; both uninstallers had no `--silent` at all. **All
        three ACCEPT their flag correctly**, so any test written against acceptance passes against
        every one of them — which is why nothing caught them.

        HONEST LIMIT: this asserts the WIRING (the flag assigns the library's gear), not the runtime
        effect. Proving the effect needs a real shell and a real PowerShell host — it belongs to the
        box runs, and this static guard is the cheap half that runs on every suite pass.
        """
        for script, pairs in (
            ("linux/install.sh", (("SILENT", "CFM_SILENT"), ("VERBOSE", "CFM_VERBOSE"),
                                  ("ASSUME_YES", "CFM_ASSUME_YES"))),
            ("linux/uninstall.sh", (("--silent", "CFM_SILENT"), ("--verbose", "CFM_VERBOSE"),
                                    ("--yes", "CFM_ASSUME_YES"), ("--force", "CFM_FORCE"))),
            ("windows/install.ps1", (("$Silent", "CfmSilent"), ("VerbosePreference", "CfmVerbose"),
                                     ("$Yes", "CfmAssumeYes"))),
            ("windows/uninstall.ps1", (("$Silent", "CfmSilent"), ("VerbosePreference", "CfmVerbose"),
                                       ("$Yes", "CfmAssumeYes"), ("$Force", "CfmForce"))),
        ):
            text = _read(script)
            for flag, gear in pairs:
                assert gear in text, f"{script}: {flag} is declared but never reaches {gear}"

    def test_library_vocabularies_correspond(self):
        """packet 1231 — `cfm_<name>` (bash) must have a `Cfm-<Name>` twin (PowerShell), and back.

        The rule is the §3 flag rule applied to the library: same WORD, native punctuation
        (`--fms-root` ⇄ `-FmsRoot`). It exists because the step runner drifted to entirely different
        words — `cfm_summary` vs `Write-Summary`, `cfm_step` vs `Add-Step` — and nothing noticed for
        as long as it took someone to read both files side by side.

        Assert the CORRESPONDENCE, never the spelling of any one name: a test pinning the literal
        `Cfm-Summary` would die the moment that function is renamed for a good reason, and the parity
        rule would stop being enforced silently.
        """
        bash, ps = _read("linux/_cfm_lib.sh"), _read("windows/_cfm_lib.ps1")
        b = {m.lower() for m in re.findall(r"(?m)^cfm_(\w+)\s*\(\)", bash)}
        p = {m.lower() for m in re.findall(r"(?m)^function\s+Cfm-(\w+)", ps)}

        def canon(names):   # cfm_run_steps <-> Cfm-RunSteps: compare on letters alone
            return {n.replace("_", "") for n in names}

        missing_ps = {n for n in b if n.replace("_", "") not in canon(p)} - _PARITY_EXEMPT_BASH
        missing_bash = {n for n in p if n.replace("_", "") not in canon(b)} - _PARITY_EXEMPT_PS
        assert not missing_ps, (
            f"_cfm_lib.sh defines cfm_{sorted(missing_ps)} with no Cfm-<Name> twin in _cfm_lib.ps1. "
            "Add the twin, or add it to the exemption list WITH a reason.")
        assert not missing_bash, (
            f"_cfm_lib.ps1 defines Cfm-{sorted(missing_bash)} with no cfm_<name> twin in _cfm_lib.sh. "
            "Add the twin, or add it to the exemption list WITH a reason.")

    def test_bash_library_exists(self):
        assert (INSTALLER / "linux" / "_cfm_lib.sh").is_file()

    def test_ps_library_exists(self):
        assert (INSTALLER / "windows" / "_cfm_lib.ps1").is_file()

    def test_libraries_are_ascii(self):
        # PowerShell 5.1 reads a BOM-less .ps1 as ANSI; keep both libs ASCII-only.
        for lib in ("linux/_cfm_lib.sh", "windows/_cfm_lib.ps1"):
            text = _read(lib)
            bad = [(i + 1, ln) for i, ln in enumerate(text.splitlines()) if not ln.isascii()]
            assert not bad, f"{lib} has non-ASCII lines: {bad[:3]}"
