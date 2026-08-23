"""The installed privileged one-shot updater, statically (packet 1246-03, E4).

These are text assertions over shipped scripts, which is this project's established way of testing
installer artifacts — the alternative is a box, and a rule enforced only where nobody looks is not
enforced.

What they defend, in one sentence each: the elevated updater must resolve `origin/main` itself; the
one caller-supplied value must be usable only for a refusal; the grant the service holds must be one
command; and the outcome record must be root-written and service-readable.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest
from application_checkout import APPLICATION_ROOT

INSTALLER = pathlib.Path(__file__).resolve().parent.parent / "installer"
LINUX = INSTALLER / "linux" / "corpusfm-update.sh"
WINDOWS = INSTALLER / "windows" / "corpusfm-update.ps1"


@pytest.fixture(scope="module")
def linux() -> str:
    return LINUX.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def windows() -> str:
    return WINDOWS.read_text(encoding="utf-8")


def _code(text: str) -> str:
    """The script minus comments.

    A guard whose own rationale names the thing it forbids reports itself as a violation — this
    project has made that mistake three times, so the scan excludes comment lines by construction
    rather than by hoping the prose avoids the words.
    """
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        out.append(line.split(" #")[0] if " #" in line else line)
    return "\n".join(out)


def test_both_platform_updaters_ship():
    assert LINUX.is_file() and WINDOWS.is_file()


def _git_words(body: str) -> list[str]:
    """Every bare word a git invocation carries, however the platform spells the call.

    Linux writes `rev-parse origin/main`; Windows now passes an argument ARRAY
    (`'rev-parse', 'origin/main'`) because a re-parsed command line is the injection surface F1
    removed. Pinning either spelling tests the punctuation rather than the rule, so this reduces
    both to the words that reach git.
    """
    return re.findall(r"[A-Za-z0-9_./-]+", body.replace("'", " ").replace('"', " "))


def test_the_updater_resolves_origin_main_itself(linux, windows):
    """The whole privilege argument rests on this: the box decides what code it installs."""
    for body in (_code(linux), _code(windows)):
        words = _git_words(body)
        assert "rev-parse" in words and "origin/main" in words


def test_the_authorized_tip_is_never_passed_to_git(linux, windows):
    """`expected_head` is compared, never used to fetch, check out, reset or name a ref."""
    for body, var in ((_code(linux), "REQUESTED"), (_code(windows), "Requested")):
        for line in body.splitlines():
            if var not in line:
                continue
            assert not re.search(r"\b(checkout|reset|merge|fetch|pull|rev-parse)\b", line), (
                f"the authorized tip reaches a git operation: {line.strip()!r}"
            )


def test_consent_requires_the_exact_tip_not_a_prefix(linux, windows):
    """Ruling O2 says the EXACT tip. An abbreviation authorizes every commit sharing it.

    This test previously asserted the opposite — that a prefix match was correct — which is the
    shape of mistake the project's "assert what must be TRUE" rule warns about: it pinned my
    reasoning rather than the requirement, and would have kept passing while the requirement was
    violated.
    """
    assert '[[ "$OBSERVED" != "$REQUESTED" ]]' in _code(linux)
    assert "$script:Observed -ne $script:Requested" in _code(windows)
    # Scoped to the lines that MENTION the authorized tip. A blanket "StartsWith appears nowhere"
    # was wrong: the untracked-content gate legitimately prefix-matches allowed paths, and a guard
    # that forbids a substring rather than a behaviour catches the wrong thing.
    for body, var in ((_code(linux), "REQUESTED"), (_code(windows), "Requested")):
        for line in body.splitlines():
            if var not in line:
                continue
            assert "StartsWith" not in line and '"$REQUESTED"*' not in line, (
                f"consent is compared by prefix: {line.strip()!r}"
            )


def test_target_changed_names_both_tips_and_the_recovery_on_both_platforms(linux, windows):
    """The outcome must explain the mismatch, not merely name the newly observed tip.

    The Windows artifact once emitted only ``origin/main is now <observed>``. That looked like
    comma truncation at the publisher boundary, but the diagnostic half had never been constructed.
    Pin the two independently validated SHA values and the fixed next action in both one-shots.
    """
    linux_code, windows_code = _code(linux), _code(windows)
    assert '${OBSERVED:0:12}' in linux_code and '${REQUESTED:0:12}' in linux_code
    assert '$script:Observed.Substring(0,12)' in windows_code
    assert '$script:Requested.Substring(0,12)' in windows_code
    recovery = "Check for updates again and authorize the current tip."
    assert recovery in linux_code and recovery in windows_code


def test_the_request_carries_no_ref_path_command_or_environment(linux, windows):
    """Two fields are read out of the request file, and neither can become an instruction."""
    for body in (_code(linux), _code(windows)):
        read_fields = set(re.findall(r'get\("([a-z_]+)"', body)) | set(
            re.findall(r"\$request\.([a-z_]+)", body))
        read_fields -= {"problems"}   # the tree-inspection helper's own JSON, not the request
        assert read_fields <= {"trigger_id", "expected_head"}, (
            f"the updater reads more than consent and correlation from the request: {read_fields}"
        )


def test_both_inputs_are_validated_against_a_strict_shape(linux, windows):
    assert "^[0-9a-f]{40,64}$" in linux and "^[0-9a-f]{40,64}$" in windows
    assert "^[A-Za-z0-9_-]{1,64}$" in linux and "^[A-Za-z0-9_-]{1,64}$" in windows


def test_the_updater_refuses_a_foreign_origin_and_an_unclean_tree(linux, windows):
    for body in (_code(linux), _code(windows)):
        assert "origin_mismatch" in body
        assert "unclean_tree" in body


def test_the_updater_refuses_a_non_fast_forward(linux, windows):
    for body in (_code(linux), _code(windows)):
        words = _git_words(body)
        assert "merge-base" in words and "--is-ancestor" in words
        assert "not_fast_forward" in body


def test_privileged_changes_are_classified_through_the_shared_boundary(linux, windows):
    """One classifier, not a second list in shell that drifts from the Python one."""
    for body in (_code(linux), _code(windows)):
        assert "update_boundary" in body
        assert "needs_installer" in body


def test_a_failed_start_or_import_restores_the_previous_deployment(linux, windows):
    assert "import_probe_failed" in _code(linux) and "service_did_not_start" in _code(linux)
    assert "import_probe_failed" in _code(windows) and "service_did_not_start" in _code(windows)
    for body in (_code(linux), _code(windows)):
        words = _git_words(body)
        assert "reset" in words and "--hard" in words


def test_the_outcome_record_is_written_by_root_and_readable_by_the_service(linux, windows):
    """The MODE moved, so this asserts it where it now lives (N2).

    `chmod 644` in the shell was the old evidence; neither script writes the record any more, so
    that string is gone and asserting it would have pinned an implementation this packet deleted.
    The rule is unchanged — root writes it, the service must be able to read it — and the one place
    that can now be true is `update_boundary.write_outcome`.
    """
    import inspect as _inspect

    from corpusfm.lifecycle import update_boundary

    source = _inspect.getsource(update_boundary.write_outcome)
    assert "mode=0o644" in source, "the service must be able to read the outcome"
    for body in (_code(linux), _code(windows)):
        assert "trigger_id" in body and "resulting_head" in body and "log_path" in body


def test_the_outcome_record_carries_no_secret(linux, windows):
    """No field of the record is NAMED a secret — checked with the project's own guard.

    Reusing `secret_guard.name_is_secretish` rather than a hand-written word list is deliberate: a
    local list drifts from the real rule, and a naive substring version of this test failed on
    `log_path` because `pat` is inside it. The guard already handles that — it tokenises.
    """
    from corpusfm.lifecycle.secret_guard import name_is_secretish
    from corpusfm.lifecycle.update_boundary import OUTCOME_FIELDS

    # The field list lives in ONE place now (N2) rather than being scraped out of two shells that
    # could disagree with it and with each other.
    assert OUTCOME_FIELDS, "no outcome fields were found to check"
    offenders = {f: name_is_secretish(f) for f in OUTCOME_FIELDS if name_is_secretish(f)}
    assert not offenders, f"the outcome record names a secret: {offenders}"

    # And each shell may only NAME those fields — a field the schema does not declare is refused by
    # the publisher, so a script inventing one would produce no record at all.
    for body in (_code(linux), _code(windows)):
        named = set(re.findall(r"([a-z_]+)=", body)) & set(OUTCOME_FIELDS)
        assert named, "the script names no outcome field"
        assert named <= set(OUTCOME_FIELDS)


def test_neither_updater_reads_authority_from_the_environment(linux, windows):
    """These scripts run as root and rewrite the code the box executes.

    An environment variable that can move `SRC` is an environment variable that can choose the tree
    an elevated operation advances. The shipped scripts carry placeholders the installer renders;
    nothing at run time can redirect them. Tests render their own copy — a seam, not an input.
    """
    for body in (_code(linux), _code(windows)):
        for forbidden in ("CFM_INSTALL_DIR", "CFM_STATE_DIR", "CFM_LOG_DIR",
                          "CFM_SRC_DIR", "CFM_VENV_PY"):
            assert forbidden not in body, f"{forbidden} is production environment authority"


def test_both_updaters_ship_with_placeholders_the_installer_must_render(linux, windows):
    for body in (linux, windows):
        for placeholder in ("@@INSTALL_DIR@@", "@@STATE_DIR@@", "@@SRC_DIR@@", "@@VENV_PY@@"):
            assert placeholder in body


def test_the_origin_check_is_canonical_not_a_substring(linux, windows):
    """`*github.com/blconstructs/X*` also matches https://evil.example/github.com/blconstructs/X."""
    assert 'CANON" != "CORPUSfm/CORPUSfm"' in _code(linux)
    assert "$canon -ne 'CORPUSfm/CORPUSfm'" in _code(windows)
    for body in (_code(linux), _code(windows)):
        assert "-notlike" not in body
        assert '*"$EXPECTED_ORIGIN"*' not in body


def test_tree_inspection_is_delegated_to_the_bounded_helper(linux, windows):
    """Git pathnames are not a shell datatype.

    Both scripts parsed porcelain in-language and each fix produced a subtler defect — a quoted
    spelling, then an ignored file, then a control character. One Python helper, used by both, is
    the answer; these assert the delegation rather than re-testing the parsing, which
    `test_privileged_updater_behaviour.py` does by execution.
    """
    for body in (_code(linux), _code(windows)):
        # R7b moved the helper OUT of the checkout, so it is no longer named as a module — naming
        # it that way is precisely the defect. What must hold is that the rendered installed helper
        # is what runs, and that no pathname is parsed here.
        assert "HELPER" in body.upper(), "the bounded helper is not invoked"
        assert "-m corpusfm.lifecycle.tree_inspection" not in body
        assert "unclean_tree" in body
        assert "--porcelain" not in body, "the script still parses porcelain itself"


def test_the_helper_allows_exactly_one_artifact_and_no_directory_prefix():
    from corpusfm.lifecycle import tree_inspection

    assert tree_inspection.ALLOWED_EXACT == frozenset({"corpusfm/_build.txt"})
    for entry in tree_inspection.ALLOWED_EXACT:
        assert not entry.endswith("/"), "a directory prefix allows arbitrary content beneath it"
        assert not entry.endswith(".py"), "an allowlisted path could shadow imported code"


def test_a_non_utf8_pathname_is_rejected_not_guessed_at(monkeypatch):
    """Exercised through the helper, because a filesystem that refuses such names would SKIP.

    The behavioural suite plants a real file, and APFS rejects it — so that test skips, and a
    skipped test cannot catch a mutation. This one feeds the porcelain bytes directly, so the rule
    is enforced on every host.
    """
    from corpusfm.lifecycle import tree_inspection

    monkeypatch.setattr(tree_inspection, "_porcelain",
                        lambda repo: [b"?? bad\xff.py"])
    problems = tree_inspection.inspect("/nowhere")
    assert problems, "a name we cannot decode was silently accepted"
    assert "not valid UTF-8" in problems[0]
    assert "\\xff" in problems[0], "the name must be shown escaped, not dropped"


def test_a_decodable_untracked_name_is_still_judged_on_its_path(monkeypatch):
    """CONTROL — the decode branch must not swallow ordinary findings."""
    from corpusfm.lifecycle import tree_inspection

    monkeypatch.setattr(tree_inspection, "_porcelain", lambda repo: [b"?? corpusfm/_build.txt"])
    assert tree_inspection.inspect("/nowhere") == []
    monkeypatch.setattr(tree_inspection, "_porcelain", lambda repo: [b"?? corpusfm/evil.py"])
    assert tree_inspection.inspect("/nowhere")


def test_the_helper_output_is_always_valid_json(monkeypatch, capsys):
    """Control characters — CR included — must be encoded, not embedded."""
    import json as _json

    from corpusfm.lifecycle import tree_inspection

    monkeypatch.setattr(tree_inspection, "_porcelain", lambda repo: [b"?? we\rird\n.py"])
    tree_inspection.main(["/nowhere"])
    payload = _json.loads(capsys.readouterr().out)   # raises if a raw control byte got through
    assert payload["ok"] is False and payload["problems"]


# ══════════════════════════════════════════════════════════════════════════════════════
# F4, as a POSITIVE structure rather than a list of phrases.
#
# The first attempt was a denylist of sentences I had already found, which is the inverse of this
# project's own rule: it could only ever catch what had already been caught, and it duly missed
# `settings.py`'s own docstring and two lines of UI copy. What follows asserts the shape the truth
# has to take — the route delegates, the UI asks for the privileged updater with the exact inspected
# target, and stamp staleness has no in-app control.
# ══════════════════════════════════════════════════════════════════════════════════════

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROUTE = APPLICATION_ROOT / "corpusfm/app/web/routes/api/settings.py"
SETTINGS_HTML = APPLICATION_ROOT / "corpusfm/app/web/templates/settings.html"


def _apply_route_source() -> str:
    body = ROUTE.read_text(encoding="utf-8")
    start = body.index("def apply_update(")
    end = body.index("\n@router.", start)
    return body[start:end]


def test_the_apply_route_DELEGATES_and_implements_no_update_of_its_own():
    """The structural claim, not a claim about wording: this route runs no git and forks nothing.

    Whatever its prose says, a route that shells out is a route that updates. Asserting the
    delegation and the absence of an implementation makes the prose checkable rather than trusted.
    """
    source = _apply_route_source()
    assert "update_service.apply(" in source, "the apply route no longer delegates"
    for implementation in ("subprocess", "_run_git", "os.system", "Popen", '"pull"', '"fetch"',
                           '"reset"', '"merge"'):
        assert implementation not in source, (
            f"the apply route carries an update implementation ({implementation})"
        )


def test_the_apply_route_DESCRIBES_THE_WHOLE_CONTRACT():
    """The docstring is the first thing a maintainer reads, and it kept describing the deleted route.

    Three rounds patched a phrase and left a paragraph — the last one still called this "the legacy
    path" and claimed it passes no `expected_head`, directly beside the corrected text. So the check
    is over the WHOLE current docstring and is entirely positive: every element of the contract must
    be present. A description that omits a step is a description a maintainer will complete from
    memory.
    """
    doc = _apply_route_source()
    doc = doc[doc.index('"""'):doc.index('"""', doc.index('"""') + 3)]
    required = {
        "the inspected target": "target_head",
        "the delegation": "update_service.apply",
        "the fixed request": "inbox",
        "the audit actor": "actor",
        "independent resolution": "origin/main",
        "refusal-only consent": "refusal-only",
        "the outcome channel": "outcome",
        "stamp repair as observation": "observation",
        "no git here": "runs no git",
    }
    missing = [name for name, token in required.items() if token not in doc]
    assert not missing, f"the contract description omits: {missing}"


def test_the_UI_asks_the_PRIVILEGED_UPDATER_for_the_EXACT_INSPECTED_TARGET():
    """The browser must send back the head it showed the administrator.

    This is behaviour, not copy: without `expected_head` the shared authority refuses
    `consent_required`, so a button that omitted it could not apply anything at all — which is what
    this one did after the self-pull was deleted. The dialog must also say whose work it is.
    """
    html = SETTINGS_HTML.read_text(encoding="utf-8")
    apply_fn = html[html.index("async applyUpdate()"):]
    apply_fn = apply_fn[:apply_fn.index("\n    async ")]
    assert "expected_head=" in apply_fn, "the apply button sends no consent value"
    assert "this.update.target_head" in apply_fn, "the consent value is not the inspected target"
    assert "'/api/settings/apply-update" in apply_fn, "the button no longer calls the apply route"

    dialog = html[html.index("{# Apply update confirm #}"):]
    dialog = dialog[:dialog.index("{# Add git registration #}")]
    assert "privileged updater" in dialog, "the dialog does not say who performs the update"
    assert "target_head" in dialog, "the dialog does not show the exact inspected commit"


def test_STAMP_STALENESS_IS_AN_OBSERVATION_WITH_NO_IN_APP_CONTROL():
    """It is reported so nobody is told "up to date" while the runtime says otherwise — and that is
    all. The repair action was deleted with the self-pull; the affordance outlived it by three
    rounds, performing a restart and no repair."""
    html = SETTINGS_HTML.read_text(encoding="utf-8")
    assert "stamp_repair" in html, "the observation is no longer surfaced at all"
    for control in ("repairVersion", "confirmRepair"):
        assert control not in html, f"an in-app stamp-repair control is back ({control})"

    # RE-EXPRESSED (packet 1251): the route no longer computes this itself — it consumes
    # `update_service.check()`, which computes it in `_assembled_check`. The rule is that the
    # observation is still COMPUTED and still REACHES the response, not which module does the
    # arithmetic, so it is asserted of both halves.
    route = ROUTE.read_text(encoding="utf-8")
    assert '"stamp_repair": res.stamp_repair' in route, "the observation no longer reaches the response"
    assert "_repair_stamp" not in route
    service = (APPLICATION_ROOT / "corpusfm/server/update_service.py").read_text(encoding="utf-8")
    assert "is_stamp_stale" in service, "the observation is no longer computed"

    mcp = (APPLICATION_ROOT / "corpusfm/mcp/server.py").read_text(encoding="utf-8")
    assert "OBSERVED ONLY" in mcp and "no in-app repair" in mcp, (
        "the tool catalog no longer says stamp staleness is an observation"
    )


# ══════════════════════════════════════════════════════════════════════════════════════
# N2 — the invocation CENSUS. The claim "no raw child output crosses the boundary" was made three
# times and refuted twice, each time by an invocation nobody had enumerated: first `git fetch`, then
# the command substitutions, then `systemctl is-active` and `merge-base`. Enumerating is the only
# way that claim stops being an inference.
# ══════════════════════════════════════════════════════════════════════════════════════

def test_THE_LINUX_SILENCE_BOUNDARY_IS_THE_FIRST_EXECUTED_STATEMENT(linux):
    """One redirection, before anything at all. Not a census, and not "before the risky ones".

    Three rounds redirected invocations one at a time and then enumerated them; each round the claim
    was refuted by an invocation nobody had listed — `git fetch`, the command substitutions,
    `systemctl is-active`, a bare `sleep`. A list of commands is wrong the moment somebody adds one.

    A first attempt at this boundary sat after `mkdir` and the log open, and a poison that fires on
    EVERY command escaped through the gap. So the property is absolute: `exec 1>/dev/null
    2>/dev/null` is the first executed statement in the script, and nothing precedes it but `set`.
    """
    body = _code(linux)
    statements = [l.strip() for l in body.splitlines()
                  if l.strip() and not l.strip().startswith("#")]
    silence = statements.index("exec 1>/dev/null 2>/dev/null")
    assert all(s.startswith("set ") for s in statements[:silence]), (
        f"these execute before the silence boundary: {statements[:silence]}"
    )
    # fd 3 is the log, and it must be opened AFTER — redirecting 1 and 2 leaves it untouched, which
    # is the whole reason the log survives when the streams do not.
    assert body.index("exec 3>>") > body.index("exec 1>/dev/null"), (
        "the log descriptor is opened before the boundary, so its own failure could speak"
    )


def test_THE_WINDOWS_OPERATIONAL_BODY_IS_INSIDE_ONE_SILENCED_BOUNDARY(windows):
    """The same property, expressed the way PowerShell expresses it.

    `& { ... } *> $null` redirects every PowerShell stream — success, error, warning, verbose, debug,
    information — and native child output inherits it. What must hold is that nothing operational
    sits outside the block: only the parameter list, the error preference and the rendered literals.
    """
    body = _code(windows)
    opened = body.index("& {")
    closed = body.rindex("} *> $null")
    before, after = body[:opened], body[closed + len("} *> $null"):]

    allowed_statements = {
        "[CmdletBinding()]",
        "param()",
        "$ErrorActionPreference = 'Stop'",
    }
    for line in before.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert stripped in allowed_statements, (
            f"this executes outside the silenced boundary: {stripped[:100]}"
        )
    assert not after.strip(), f"code follows the silenced boundary: {after.strip()[:100]}"


def test_EVERY_CAPTURED_LINUX_DATUM_IS_VALIDATED_BEFORE_USE(linux):
    """A captured value is whatever the child printed, and two of them decide what gets merged.

    `rev-parse` was trusted for three rounds: its stdout went straight into a merge argument and
    into the outcome record. Capturing is containment, not validation.
    """
    body = _code(linux)
    # The PATTERN is extracted and EXERCISED, not merely found. A validation that matches
    # everything is present and does nothing — `=~ ^.*$` reads as a check and survives a grep.
    # Rejected by EVERY validator here, whatever the datum means: an empty capture, one carrying
    # shell metacharacters, and one spanning lines.
    always_rogue = ["", "0" * 40 + " ; rm -rf /", "a\nb", "$(id)", "../../etc/passwd"]
    # A commit id is a stricter thing than an identifier, so the two are checked as what they are
    # rather than against one list that would be wrong for one of them.
    data = {
        "TRIGGER_ID": ("trig-1", []),
        "REQUESTED": ("0" * 40, ["not-a-sha", "0" * 39, "g" * 40, "HEAD", "origin/main"]),
        "OLD_HEAD": ("0" * 40, ["not-a-sha", "0" * 39, "g" * 40, "HEAD", "origin/main"]),
        "OBSERVED": ("0" * 40, ["not-a-sha", "0" * 39, "g" * 40, "HEAD", "origin/main"]),
        "RESULT_HEAD": ("0" * 40, ["not-a-sha", "0" * 39, "g" * 40, "HEAD", "origin/main"]),
    }
    for datum, (good, rogue) in data.items():
        found = re.search(rf'\[\[ "\${datum}"\s*=~\s*(\S+)\s*\]\]', body)
        assert found, f"{datum} is captured from a child and used without being validated"
        probe = ["bash", "-c", f'[[ "$1" =~ {found.group(1)} ]]', "_"]
        accepted = [v for v in always_rogue + rogue
                    if subprocess.run(probe + [v], capture_output=True).returncode == 0]
        assert not accepted, f"{datum}'s validation accepts {accepted!r}"
        assert subprocess.run(probe + [good], capture_output=True).returncode == 0, (
            f"{datum}'s validation rejects a legitimate value"
        )


def test_NO_WINDOWS_CHILD_IS_LAUNCHED_OUTSIDE_THE_CAPTURING_BOUNDARY(windows):
    """Inside the silenced block, children still go through ONE capturing launch boundary.

    The outer silence stops anything reaching a stream; `Invoke-Fixed` is what builds each child's
    environment from empty and captures its output for validation. The two are different jobs and
    both are required — `&` would inherit the whole environment even though its output is silenced.
    """
    body = _code(windows)
    for bypass in ("& $Git", "& $Py", "& $Helper", "& $Publisher", "Start-Process",
                   "Invoke-Expression"):
        assert bypass not in body, f"{bypass!r} launches a child outside the capturing boundary"
    for line in body.splitlines():
        if "Write-Log" in line:
            assert ".StdOut" not in line and ".StdErr" not in line, (
                f"raw child output is written to the log: {line.strip()[:120]}"
            )


def test_EVERY_CAPTURED_WINDOWS_HEAD_IS_VALIDATED_BEFORE_USE(windows):
    body = _code(windows)
    for datum in ("oldHead", "script:Observed", "script:ResultHead", "script:TriggerId",
                  "script:Requested"):
        assert re.search(rf"\${re.escape(datum)} -notmatch", body), (
            f"${datum} is captured from a child and used without being validated"
        )


def test_THE_CHECK_RESPONSE_EXPOSES_THE_INSPECTED_TARGET():
    """The first step of the contract, and the one that was missing.

    The browser cannot hand back a value it was never given. `target_head` was computed by the check
    route and dropped on the floor, so the apply button sent no consent and could not apply anything
    — for three rounds, behind copy that said it pulled.
    """
    route = ROUTE.read_text(encoding="utf-8")
    check = route[route.index("def check_update("):route.index("def apply_update(")]
    # The KEY, not the expression that fills it (packet 1251 moved the value onto the shared
    # authority's result). What must be true is that the browser is handed the exact inspected
    # commit; where the route reads it from is not the rule.
    assert '"target_head": res.target_head' in check, \
        "the check response does not expose the target head"

    html = SETTINGS_HTML.read_text(encoding="utf-8")
    assert "target_head: d.target_head" in html, "the browser discards the inspected target"
    assert "target_head: ''" in html, "the component declares no target_head state"


def test_NO_CURRENT_UPDATE_SURFACE_CLAIMS_THE_APP_UPDATES_ITSELF():
    """One sweep over every surface that currently describes updating, asserted POSITIVELY.

    Each of these must say the privileged updater does the work. This replaces a phrase denylist
    that could only ever catch sentences already found — it missed the route docstring's second
    paragraph and two lines of island copy, both of which a reader meets before anything else.
    """
    html = SETTINGS_HTML.read_text(encoding="utf-8")
    # Anchored on the UPDATES island specifically — there is more than one island on this page, and
    # the first one is the reload control.
    updates = html.index("checkUpdate(")   # `checkUpdate(true)` since packet 1251's explicit refresh
    island = html[html.rindex('<div class="cfm-island-top">', 0, updates):
                  html.index('<div class="cfm-meta-grid', updates)]
    assert "privileged updater" in island, "the update island does not say who does the work"
    assert "does not update itself" in island, "the island does not say the app is not the updater"

    dialog = html[html.index("{# Apply update confirm #}"):html.index("{# Add git registration #}")]
    assert "privileged updater" in dialog and "target_head" in dialog

    mcp = (APPLICATION_ROOT / "corpusfm/mcp/server.py").read_text(encoding="utf-8")
    tools = mcp[mcp.index("  update_check "):mcp.index("  update_status ")]
    assert "TRIGGERS the fixed elevated one-shot" in tools
    assert "The service performs no git operation." in tools
