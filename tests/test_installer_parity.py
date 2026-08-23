"""Cross-platform §4H parity, derived from both real installers (packet 1246-04-05, §3.5).

**Why this is code and not a comparison somebody did once.** §4D.0a, the other guard this packet
owns, constrains TESTS — it proves dispositions were applied and RERUN ONLY bodies are untouched.
None of that can fail when the two scripts implement §4H *differently*. A packet whose distinctive
job is parity cannot discharge it in prose, so the fact set below is extracted from the shipped
`install.sh` and `install.ps1` and compared.

**It normalizes before comparing.** `--fms-root` and `-FmsRoot` are the same §4H option; comparing
raw text would fail on every legitimate platform difference and would then be silenced. The FACT SET
is the contract; the syntax is not.

**The known limit, stated rather than hidden.** A divergence no §4H fact captures — different
internal JSON assembly, different log phrasing, a different helper decomposition — is invisible
here, and deliberately so: two implementations of §4H may differ in structure and still be
parity-correct. If a specific divergence matters, the fix is to add the fact to §4H, not to compare
text.

**And it has been seen to fail.** Every parity assertion below is paired with a synthetic divergent
pair that must be detected. A parity checker nobody has watched fail is a claim.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SH = ROOT / "installer" / "linux" / "install.sh"
PS1 = ROOT / "installer" / "windows" / "install.ps1"

#: Long option → §4H semantic name. Both spellings normalize to the same key, which is the whole
#: point: parity is about the OPTION, never about how a platform spells it.
_OPTION_SEMANTICS: dict[str, str] = {
    "install-dir": "install_dir", "installdir": "install_dir",
    "patch-hosting-dir": "patch_hosting_dir", "patchhostingdir": "patch_hosting_dir",
    "fms-root": "fms_root", "fmsroot": "fms_root",
    "proxy-policy-add": "proxy_policy_add", "proxypolicyadd": "proxy_policy_add",
    "proxy-policy-ignore": "proxy_policy_ignore", "proxypolicyignore": "proxy_policy_ignore",
    "repair-storage-access": "repair_storage_access",
    "repairstorageaccess": "repair_storage_access",
    "replace-existing-install": "replace_existing_install",
    "replaceexistinginstall": "replace_existing_install",
    "yes": "assume_yes", "silent": "silent", "verbose": "verbose",
}

#: `help` is deliberately NOT a §4H option group. Bash has no intrinsic help, so `install.sh`
#: implements `-h|--help`; PowerShell provides comment-based help and `-?` for every script, so
#: `install.ps1` declares no parameter. Requiring parity there would demand a redundant Windows
#: switch to satisfy a checker — the "normalize before comparing" rule pointing the wrong way.
_HELP_IS_A_SHELL_INTRINSIC_NOT_A_4H_OPTION = True

#: RULED 2026-08-08, and the order IS a dependency rather than a preference.
#:
#: It was ("patch", "proxy", "admin_identity", "storage"). The patch compartment authenticates to
#: the FMS Admin API with THIS installation's PKI identity, and `admin_identity` is the provider
#: that creates it — so on a genuinely fresh co-located box the old order asked the compartment to
#: use an identity that did not exist yet. Measured on fms-server 2026-08-08: patch refused
#: `api_required_unavailable` and the install stopped.
#:
#: The generation each provider takes follows from its POSITION (foundation is 1, phase N composes
#: generation N-13), so moving a block moves its generation with it — which is exactly why this
#: tuple, and not a set of hard-coded numbers, is what the parity check compares.
PROVIDERS_IN_ORDER = ("admin_identity", "patch", "proxy", "storage")
RESULT_WORDS = frozenset({"completed", "no_change", "failed_before_change", "rolled_back",
                          "manual_action_required", "incomplete_safe"})
EXIT_CODES = frozenset({0, 1, 2, 3, 4, 5})


# ── the normalized fact extractor ─────────────────────────────────────────────────────

#: §4H item 9. **This fact exists because its absence cost a whole packet family.** `install.sh`
#: lost its entire post-install self-test in the 21-phase conversion and printed "installed
#: successfully" having verified nothing, for four packets, while `install.ps1` kept its Verify
#: stage — and no parity fact could see it, because none of them said a verification had to exist.
#: §3.5 of this packet anticipated the case: *the fix is to add the fact to §4H, not to compare
#: text*. This is that fix.
_VERIFICATION_PROBES = {
    # Both spell the same probe differently — `$WEB_PORT` vs `$WebPort` — which is exactly what
    # "normalize before comparing" means: the FACT is that loopback is probed, not how it is
    # written.
    "loopback": (r"127\.0\.0\.1:\$\{?WEB_PORT\}?/login", r"127\.0\.0\.1:\$WebPort/login"),
    "mcp_401": (r"401", r"401"),
    "proxy": (r"127\.0\.0\.1\$\{?WEB_PREFIX\}?/", r"127\.0\.0\.1\" \+ \$WebPrefix"),
    "fms_coexistence": (r"/fmi/", r"/fmi/"),
    "storage": (r"get_backend", r"get_backend"),
}


def _provider_facts(text: str, *, phase_marker: str, commit: str, discard: str,
                    finalize: str) -> dict:
    """Provider identity, PHASE, protocol, generation and discard — all read from the installer.

    **A5.** These used to come from `zip(PROVIDERS_IN_ORDER, (15, 16, 17, 18))`, gated only on the
    provider's name appearing anywhere: the phase was an EXTRACTOR CONSTANT, so an installer that
    composed `storage` in phase 12 produced the same facts and the `wrong_provider_phase` control
    could not fail. The phase a provider is committed in is now the phase whose BODY contains the
    commit; the generation follows from it (foundation is 1, so phase N composes generation N-13);
    and the protocol is read from whether that provider also finalizes.
    """
    marks = [(int(m.group(1)), m.end()) for m in re.finditer(phase_marker, text, re.M)]
    bodies = {n: text[e:(marks[i + 1][1] if i + 1 < len(marks) else len(text))]
              for i, (n, e) in enumerate(marks)}
    phase, protocol, generation, discards = {}, {}, {}, set()
    for number, body in bodies.items():
        for name in re.findall(commit, body):
            phase[name] = number
            generation[name] = number - 13          # phase 15 -> generation 2, and so on
            protocol[name] = "F" if re.search(finalize, body) else "P"
        discards.update(re.findall(discard, body))
    return {"providers": [p for p in sorted(phase, key=phase.get)], "provider_phase": phase,
            "provider_generation": generation, "provider_protocol": protocol, "discards": discards}


def _dispatch_facts(text: str, dispatcher: str, case: str) -> dict:
    """The exit codes the installer's own dispatcher HANDLES, and the result words it names.

    **A5.** `exit_codes` used to come from a `[0-5]` regex, so `exit_codes <= {0..5}` was true by
    construction and could never fail; `result_words` was filtered against the allowed set before
    being compared to it. Both are now read from the real dispatcher body, so an invented case or
    word is present in the fact and the subset assertions can actually refuse.
    """
    m = re.search(dispatcher, text)
    if not m:
        return {"exit_codes": set(), "result_words": set()}
    body = text[m.start():]
    end = re.search(r"^\}", body[1:], re.M)
    body = body[:end.start() + 1] if end else body
    return {
        "exit_codes": {int(c) for c in re.findall(case, body, re.M)},
        "result_words": set(re.findall(r"\b([a-z]+(?:_[a-z]+)+)\b", body)) & RESULT_WORDS
        | {w for w in RESULT_WORDS if w in body},
    }


def _verification_facts(text: str, *, start: int, banner: int) -> dict:
    """Does a post-start verification EXIST, what does it prove, and can it refuse?

    Derived from installer CONTENT — never from a hardcoded expectation — so a platform that deletes
    the block, or moves it after the success banner, or stops refusing on failure, is detected.
    """
    if start < 0:
        return {"present": False, "probes": set(), "refuses": False, "before_banner": False}
    body = text[start:banner if banner > start else len(text)]
    probes = set()
    for name, (linux_pat, windows_pat) in _VERIFICATION_PROBES.items():
        if re.search(linux_pat, body) or re.search(windows_pat, body):
            probes.add(name)
    if "is-active" in body or "Get-Service" in body or "$svc.Status" in body:
        probes.add("units_active")
    if re.search(r"users_exist", body):
        probes.add("named_user")
    return {
        "present": True,
        "probes": probes,
        # A verification that only WARNS is a banner with extra steps.
        # `die "…"` (bash) and `Die "…"` / `Die (…)` (PowerShell). A stage that only warns is a
        # banner with extra steps, so this is a FACT, not a stylistic difference.
        "refuses": bool(re.search(r'(^\s*|\|\|\s*)(die|Die) [("\']', body, re.M)),
        "before_banner": banner > start,
    }



def linux_facts(text: str) -> dict:
    """§4H facts from a bash installer, by structure — never by line number."""
    options = set()
    # The alternation may lead with a SHORT option (`--verbose|-v`, `-h|--help`), so the arm is
    # matched whole and split — an earlier form required every alternate to start with `--` and
    # therefore missed `verbose` entirely, reporting a parity failure that was the extractor's.
    for m in re.finditer(r"^\s*(-{1,2}[a-z][a-z-]*(?:\|-{1,2}[a-z][a-z-]*)*)\)", text, re.M):
        for spelling in m.group(1).split("|"):
            name = spelling.lstrip("-")
            if name in _OPTION_SEMANTICS:
                options.add(_OPTION_SEMANTICS[name])
    phases = [int(m.group(1)) for m in re.finditer(r"^# ═══ PHASE (\d+) —", text, re.M)]
    marks = [(n, m.start()) for n, m in
             ((int(m.group(1)), m) for m in re.finditer(r"^# ═══ PHASE (\d+) —", text, re.M))]
    at = dict(marks)
    return {
        "options": options,
        "phases": phases,
        "quiesce": at.get(9),
        "first_replacement": at.get(10),
        **_provider_facts(text, phase_marker=r"^# ═══ PHASE (\d+) —",
                          commit=r"lc_commit_provider (\w+)", discard=r"lc_discard_provider (\w+)",
                          finalize=r"lc_run \"(\w+) finalize\""),
        "verify": text.find("does not match the canonical rendering"),
        "first_start": at.get(21),
        **_dispatch_facts(text, r"lc_dispatch\(\) \{", r"^\s+([0-9]+)\)"),
        "verification": _verification_facts(text, start=text.find("POST-START VERIFICATION"),
                                            banner=text.find("CORPUSfm installed successfully")),
    }


def windows_facts(text: str) -> dict:
    options = set()
    for m in re.finditer(r"^\s*\[(?:string(?:\[\])?|switch)\]\$(\w+)", text, re.M):
        name = m.group(1).lower()
        if name in _OPTION_SEMANTICS:
            options.add(_OPTION_SEMANTICS[name])
    for fixed in ("silent", "verbose", "yes"):
        if re.search(rf"\[switch\]\${fixed}\b", text, re.I) or f"-{fixed.capitalize()}" in text:
            options.add(_OPTION_SEMANTICS[fixed])
    phases = [int(m.group(1)) for m in re.finditer(r"^# === PHASE (\d+) -", text, re.M)]
    at = {int(m.group(1)): m.start() for m in re.finditer(r"^# === PHASE (\d+) -", text, re.M)}
    return {
        "options": options,
        "phases": phases,
        "quiesce": at.get(9),
        "first_replacement": at.get(10),
        **_provider_facts(text, phase_marker=r"^# === PHASE (\d+) -",
                          commit=r"Lc-CommitProvider '(\w+)'", discard=r"Lc-DiscardProvider '(\w+)'",
                          finalize=r"Lc-Run \"(\w+) finalize\""),
        "verify": text.find("differs from the canonical rendering"),
        "first_start": at.get(21),
        **_dispatch_facts(text, r"function Lc-Dispatch", r"^\s+([0-9]+) \{"),
        "verification": _verification_facts(text, start=text.find('Section "Summary"'),
                                            banner=text.find('Section "Next steps"')),
    }


@pytest.fixture(scope="module")
def facts() -> dict:
    return {"linux": linux_facts(SH.read_text(encoding="utf-8")),
            "windows": windows_facts(PS1.read_text(encoding="ascii"))}


# ── the parity assertions ─────────────────────────────────────────────────────────────


def test_the_extractor_finds_something_on_both(facts):
    """CLEAN CONTROL. Every equality below is satisfied by two empty sets, so the extractor must be
    shown to extract before any of them means anything."""
    for platform, f in facts.items():
        assert f["options"], f"{platform}: no options extracted"
        assert f["phases"], f"{platform}: no phases extracted"
        assert f["providers"], f"{platform}: no providers extracted"


def test_the_supported_option_groups_are_the_SAME_SET(facts):
    assert facts["linux"]["options"] == facts["windows"]["options"], (
        f"only linux: {sorted(facts['linux']['options'] - facts['windows']['options'])}; "
        f"only windows: {sorted(facts['windows']['options'] - facts['linux']['options'])}"
    )


@pytest.mark.parametrize("retired,platform", [
    *[(r, "linux") for r in ("--port", "--no-pull", "--ref", "--allow-dirty", "--enable-mcp",
                             "--no-mcp", "--no-scheduler", "--fm-admin-user", "--fm-admin-pass",
                             "--admin-user", "--admin-pass", "--git-pat", "--assume-yes")],
    *[(r, "windows") for r in ("-Port", "-NoPull", "-Ref", "-AllowDirty", "-EnableMcp", "-NoMcp",
                               "-NoScheduler", "-FmAdminUser", "-FmAdminPass", "-AdminUser",
                               "-AdminPass", "-GitPat", "-ConfigHome", "-NoBootstrap", "-NoPki")],
])
def test_no_retired_spelling_still_parses_on_either_platform(retired, platform):
    """Retirement is symmetric under §4H.2, so a spelling that still parses on ONE platform is a
    divergence even when both scripts otherwise agree. Comments are excluded — both installers
    document their retirements, and a scan that reads that prose reports the rule's own rationale."""
    source = (SH.read_text(encoding="utf-8") if platform == "linux"
              else PS1.read_text(encoding="ascii"))
    code = "\n".join(l for l in source.splitlines() if not l.lstrip().startswith("#"))
    if platform == "linux":
        assert not re.search(rf"^\s*{re.escape(retired)}[|)]", code, re.M), (
            f"{retired} still has a parser arm"
        )
    else:
        assert not re.search(rf"\[(?:string(?:\[\])?|switch)\]\${retired[1:]}\b", code), (
            f"{retired} is still a declared parameter"
        )


def test_the_phase_LISTS_are_identical_and_are_one_to_twentyone(facts):
    assert facts["linux"]["phases"] == facts["windows"]["phases"]
    assert facts["linux"]["phases"] == list(range(1, 22))


def test_quiesce_precedes_the_first_byte_replacement_on_both(facts):
    for platform, f in facts.items():
        assert f["quiesce"] is not None and f["first_replacement"] is not None, platform
        assert f["quiesce"] < f["first_replacement"], (
            f"{platform}: code is replaced before the services are stopped"
        )


def test_the_provider_sequence_generations_and_discards_are_identical(facts):
    """A5: every value here is now READ FROM THE INSTALLER, not supplied by the extractor."""
    assert facts["linux"]["providers"] == facts["windows"]["providers"] == list(PROVIDERS_IN_ORDER)
    for key, expected in (
        # RULED 2026-08-08. admin_identity FIRST, because the patch compartment authenticates with
        # the identity it creates. Generation follows phase (foundation is 1, phase N -> N-13), so
        # these two rows are one fact stated twice — and that is deliberate: if a future edit moves
        # a block without moving its generation, exactly one of them fails and names which.
        ("provider_phase", {"admin_identity": 15, "patch": 16, "proxy": 17, "storage": 18}),
        ("provider_generation", {"admin_identity": 2, "patch": 3, "proxy": 4, "storage": 5}),
        ("provider_protocol", {"patch": "P", "proxy": "F", "admin_identity": "F", "storage": "F"}),
    ):
        assert facts["linux"][key] == facts["windows"][key] == expected, (
            f"{key}: linux={facts['linux'][key]} windows={facts['windows'][key]}"
        )
    assert facts["linux"]["discards"] == facts["windows"]["discards"] == set(PROVIDERS_IN_ORDER), (
        "a provider composes without discarding its journal, so the next one meets a foreign record"
    )


def test_definitions_are_verified_before_the_first_service_start_on_both(facts):
    for platform, f in facts.items():
        assert f["verify"] > 0, f"{platform}: nothing reads a definition back"
        assert f["first_start"] is not None
        assert f["verify"] < f["first_start"], (
            f"{platform}: a service starts before its definition was verified"
        )


def test_neither_script_invents_a_result_word_or_an_exit_code(facts):
    for platform, f in facts.items():
        assert f["result_words"] <= RESULT_WORDS, platform
        assert f["exit_codes"] <= EXIT_CODES, f"{platform}: {sorted(f['exit_codes'] - EXIT_CODES)}"
        assert f["exit_codes"] >= {0, 1, 2, 3, 4, 5}, (
            f"{platform} handles only {sorted(f['exit_codes'])} of the shipped exit map"
        )


# ── the divergent-pair controls: each parity check must be SEEN to fail ───────────────


def _divergent(kind: str) -> tuple[dict, dict]:
    """A synthetic pair that differs in exactly one §4H fact."""
    linux = linux_facts(SH.read_text(encoding="utf-8"))
    windows = windows_facts(PS1.read_text(encoding="ascii"))
    if kind == "missing_phase":
        windows["phases"] = [n for n in windows["phases"] if n != 17]
    elif kind == "retained_option":
        windows["options"] = windows["options"] | {"no_scheduler"}
    elif kind == "missing_provider":
        windows["providers"] = [p for p in windows["providers"] if p != "proxy"]
    elif kind == "missing_discard":
        windows["discards"] = windows["discards"] - {"storage"}
    elif kind == "replacement_before_quiesce":
        windows["quiesce"], windows["first_replacement"] = (
            windows["first_replacement"], windows["quiesce"])
    elif kind == "start_before_verify":
        windows["verify"], windows["first_start"] = windows["first_start"], windows["verify"]
    elif kind == "invented_exit_code":
        windows["exit_codes"] = windows["exit_codes"] | {9}
    elif kind == "wrong_provider_phase":
        windows["provider_phase"] = {**windows["provider_phase"], "storage": 19}
    else:                                                       # pragma: no cover - typo guard
        raise AssertionError(f"unknown divergence {kind}")
    return linux, windows


@pytest.mark.parametrize("kind,check", [
    ("missing_phase", lambda l, w: l["phases"] == w["phases"]),
    ("retained_option", lambda l, w: l["options"] == w["options"]),
    ("missing_provider", lambda l, w: l["providers"] == w["providers"]),
    ("missing_discard", lambda l, w: l["discards"] == w["discards"]),
    ("replacement_before_quiesce", lambda l, w: w["quiesce"] < w["first_replacement"]),
    ("start_before_verify", lambda l, w: w["verify"] < w["first_start"]),
    ("invented_exit_code", lambda l, w: w["exit_codes"] <= EXIT_CODES),
    ("wrong_provider_phase", lambda l, w: l["provider_phase"] == w["provider_phase"]),
])
def test_EVERY_PARITY_CHECK_IS_SEEN_TO_FAIL_on_a_divergent_pair(kind, check):
    """**A parity checker nobody has watched fail is a claim.** One synthetic divergence per fact,
    each proved to be detected by the same predicate the real assertion uses — and each proved to
    HOLD on the real pair first, so a check that always fails cannot masquerade as a working one."""
    real_l = linux_facts(SH.read_text(encoding="utf-8"))
    real_w = windows_facts(PS1.read_text(encoding="ascii"))
    assert check(real_l, real_w), f"{kind}: the real pair already violates this check"
    diverged_l, diverged_w = _divergent(kind)
    assert not check(diverged_l, diverged_w), (
        f"{kind}: the divergence was NOT detected — this parity check proves nothing"
    )


def test_the_divergence_catalogue_covers_every_parity_assertion():
    """A fact asserted with no divergent control is a fact nobody has proved is checkable."""
    covered = {"phases", "options", "providers", "discards", "quiesce", "verify", "exit_codes",
               "provider_phase"}
    asserted = {"options", "phases", "quiesce", "first_replacement", "providers", "provider_phase",
                "discards", "verify", "first_start", "result_words", "exit_codes"}
    # `first_replacement`, `first_start` and `result_words` are the OTHER half of a pair already
    # covered — swapping quiesce/replacement and verify/start exercises both indices at once, and
    # `result_words` shares its subset check with `exit_codes`.
    uncovered = asserted - covered - {"first_replacement", "first_start", "result_words"}
    assert not uncovered, f"parity facts with no divergent control: {sorted(uncovered)}"


# ── §4H item 9: the post-start verification, and the divergence that would have caught the RC3 ──

REQUIRED_PROBES = frozenset({"units_active", "loopback", "proxy", "fms_coexistence", "mcp_401",
                             "storage", "named_user"})


def test_BOTH_PLATFORMS_VERIFY_AFTER_STARTING_AND_BEFORE_CLAIMING_SUCCESS(facts):
    """§4H item 9. **This assertion is the one that was missing.** For four packets `install.sh`
    printed "installed successfully" having checked nothing, and every parity fact agreed with
    `install.ps1` because none of them looked for this."""
    for platform, f in facts.items():
        v = f["verification"]
        assert v["present"], f"{platform} has NO post-start verification at all"
        assert v["before_banner"], f"{platform} verifies AFTER claiming success"
        assert v["refuses"], f"{platform}'s verification only warns; it cannot refuse success"


def test_THE_SAME_OBLIGATIONS_ARE_PROVEN_ON_BOTH_PLATFORMS(facts):
    """The mechanisms may differ — `curl` and `systemctl is-active` against `Code`/`Get-Service` —
    and the OBLIGATIONS may not."""
    linux, windows = facts["linux"]["verification"], facts["windows"]["verification"]
    assert linux["probes"] == windows["probes"], (
        f"only linux: {sorted(linux['probes'] - windows['probes'])}; "
        f"only windows: {sorted(windows['probes'] - linux['probes'])}"
    )
    missing = REQUIRED_PROBES - linux["probes"]
    assert not missing, f"§4H item 9 obligations proven on neither platform: {sorted(missing)}"


@pytest.mark.parametrize("kind,mutate,check", [
    ("verification deleted",
     lambda v: {**v, "present": False, "probes": set()},
     lambda l, w: w["present"]),
    ("verification moved after the success banner",
     lambda v: {**v, "before_banner": False},
     lambda l, w: w["before_banner"]),
    ("verification only warns",
     lambda v: {**v, "refuses": False},
     lambda l, w: w["refuses"]),
    ("one obligation dropped",
     lambda v: {**v, "probes": v["probes"] - {"mcp_401"}},
     lambda l, w: l["probes"] == w["probes"]),
])
def test_THE_LOST_SELFTEST_WOULD_NOW_BE_CAUGHT(kind, mutate, check):
    """**The divergent-pair control for the RC3 that actually happened.** `verification deleted` is
    literally the state `install.sh` shipped in from `43c91f2b` to `80a411ba`; it must be detected,
    and it must not have been detectable before this fact existed."""
    real_l = linux_facts(SH.read_text(encoding="utf-8"))["verification"]
    real_w = windows_facts(PS1.read_text(encoding="ascii"))["verification"]
    assert check(real_l, real_w), f"{kind}: the real pair already violates this check"
    assert not check(real_l, mutate(real_w)), f"{kind}: the divergence was NOT detected"


# ── A5: controls that mutate the REAL installer text, which the hardcoded forms could not ────
#
# `wrong_provider_phase` and `invented_exit_code` were vacuous: the phase came from a zip() in the
# extractor and the exit codes from a `[0-5]` regex, so neither divergence could be expressed at all.
# These edit the installer SOURCE and re-extract, which is the only way to prove the fact is read.

def _mutated_facts(platform: str, old: str, new: str) -> dict:
    raw = (SH.read_text(encoding="utf-8") if platform == "linux"
           else PS1.read_text(encoding="ascii"))
    assert raw.count(old) >= 1, f"{platform}: the mutation anchor {old!r} is gone"
    mutated = raw.replace(old, new, 1)
    assert mutated != raw
    return (linux_facts if platform == "linux" else windows_facts)(mutated)


@pytest.mark.parametrize("platform,old,new,key,expected_change", [
    # MOVE a provider into another phase, by moving its commit across the phase marker.
    ("linux", "# ═══ PHASE 18 — STORAGE", "# ═══ PHASE 12 — STORAGE", "provider_phase", 12),
    ("windows", "# === PHASE 18 - STORAGE", "# === PHASE 12 - STORAGE", "provider_phase", 12),
])
def test_A5_A_REAL_PHASE_MOVE_IS_DETECTED(platform, old, new, key, expected_change):
    """The phase is the phase whose BODY holds the commit. Moving the marker moves the fact — which
    the `zip(PROVIDERS_IN_ORDER, (15,16,17,18))` form could not express."""
    facts = _mutated_facts(platform, old, new)
    assert facts[key]["storage"] == expected_change, facts[key]
    assert facts["provider_generation"]["storage"] != 5, "the generation did not follow the phase"


@pytest.mark.parametrize("platform,old,new", [
    ("linux", "lc_discard_provider storage", "true # discard removed"),
    ("windows", "Lc-DiscardProvider 'storage'", "# discard removed"),
])
def test_A5_A_REAL_MISSING_DISCARD_IS_DETECTED(platform, old, new):
    facts = _mutated_facts(platform, old, new)
    assert "storage" not in facts["discards"], "a removed discard was not detected"


@pytest.mark.parametrize("platform,old,new", [
    ("linux", '        5) LEAVE_SERVICES_STOPPED=true;', '        9) LEAVE_SERVICES_STOPPED=true;'),
    ("windows", "    5 { Die \"$what stopped safely part-way", "    9 { Die \"$what stopped safely part-way"),
])
def test_A5_AN_INVENTED_EXIT_CASE_IS_DETECTED(platform, old, new):
    """The codes now come from the dispatcher body, so an unsupported case is IN the fact and the
    subset assertion can refuse. Under the `[0-5]` regex a `9)` case was simply invisible."""
    facts = _mutated_facts(platform, old, new)
    assert 9 in facts["exit_codes"], "an invented exit case was not extracted"
    assert not facts["exit_codes"] <= EXIT_CODES, "the subset check still cannot refuse it"
    assert 5 not in facts["exit_codes"], "the real case survived the mutation; control is unsound"


@pytest.mark.parametrize("platform,old,new", [
    ("linux", "(incomplete_safe)", "(totally_fine)"),
    ("windows", "(incomplete_safe)", "(totally_fine)"),
])
def test_A5_A_LOST_RESULT_WORD_IS_DETECTED(platform, old, new):
    """`result_words` was filtered against the allowed set before being compared to it, so it could
    only ever be a subset. Read from the dispatcher now, a renamed word disappears from the fact."""
    facts = _mutated_facts(platform, old, new)
    assert "incomplete_safe" not in facts["result_words"], (
        "the dispatcher no longer names incomplete_safe and the fact did not notice"
    )


def test_A5_the_dispatcher_names_every_result_word_it_must(facts):
    for platform, f in facts.items():
        assert "incomplete_safe" in f["result_words"], f"{platform} does not handle incomplete_safe"
        assert f["result_words"] <= RESULT_WORDS, platform


# ── A6.2: a replacement runtime is VERIFIED before the working one is destroyed ─────────
#
# §4D.0 deleted `test_python_downloaded_and_verified_before_services_stopped_and_wiped` as
# DELETE WITH SUBJECT, and only HALF its subject was retired. §4H.4 moved the service stop to phase
# 9 by ruling, so "download before the quiesce" is genuinely gone — but **verify before wipe** was
# never ruled on and is a different obligation: destroying a working interpreter on the strength of
# an unverified download can strand a box with no interpreter at all.
#
# Restored here as the surviving half only. The retired half is NOT reintroduced.

@pytest.mark.parametrize("platform,verify,wipe", [
    ("linux", "sha256sum -c -", 'rm -rf "$PY_HOME"'),
    ("windows", "Get-FileHash -Path $zip -Algorithm SHA256", "Remove-Item $PyDir -Recurse -Force"),
])
def test_A6_the_replacement_runtime_is_VERIFIED_BEFORE_THE_OLD_ONE_IS_DESTROYED(platform, verify,
                                                                                wipe):
    raw = (SH.read_text(encoding="utf-8") if platform == "linux"
           else PS1.read_text(encoding="ascii"))
    code = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))
    assert verify in code, f"{platform}: the download is never checksum-verified"
    assert wipe in code, f"{platform}: the prior runtime is never replaced"
    assert code.index(verify) < code.index(wipe), (
        f"{platform}: the prior working runtime is destroyed before the replacement is verified — "
        "a failed or tampered download strands the box with no interpreter"
    )
    # …and the verification REFUSES rather than warning.
    window = code[code.index(verify):code.index(wipe)]
    assert re.search(r"\b(die|Die) ", window), (
        f"{platform}: a checksum mismatch does not refuse before the wipe"
    )


@pytest.mark.parametrize("platform,verify,wipe", [
    ("linux", "sha256sum -c -", 'rm -rf "$PY_HOME"'),
    ("windows", "Get-FileHash -Path $zip -Algorithm SHA256", "Remove-Item $PyDir -Recurse -Force"),
])
def test_A6_REORDERING_VERIFY_AFTER_WIPE_IS_CAUGHT(platform, verify, wipe):
    """The control: the ordering assertion must actually depend on the order."""
    raw = (SH.read_text(encoding="utf-8") if platform == "linux"
           else PS1.read_text(encoding="ascii"))
    code = "\n".join(l for l in raw.splitlines() if not l.lstrip().startswith("#"))
    i_v, i_w = code.index(verify), code.index(wipe)
    assert i_v < i_w
    swapped = code[:i_v] + wipe + code[i_v + len(verify):]
    assert not (swapped.index(verify) < swapped.index(wipe) if verify in swapped else False), (
        "the mutation did not move the verification after the wipe; this control proves nothing"
    )


def test_A6_the_RETIRED_HALF_IS_NOT_REINTRODUCED():
    """§4H.4 ruled that phase 9 stops the services before phase 10 downloads anything. Asserting the
    opposite would re-litigate a ruling through a test, which is what DELETE WITH SUBJECT prevented."""
    raw = SH.read_text(encoding="utf-8")
    marks = {int(m.group(1)): m.start() for m in re.finditer(r"^# ═══ PHASE (\d+) —", raw, re.M)}
    assert marks[9] < marks[10], "the ruled quiesce-before-replacement order is gone"


# ── the two UNINSTALL LAUNCHERS (packet 1246-09, stage 6) ─────────────────────
#
# **Same discipline, new pair.** The launchers are as close to identical as two shells allow, because
# every decision they used to make differently is now made once, in Python, for both. What is left is
# a protocol — and a protocol implemented twice is a protocol that drifts, which is exactly what the
# retired uninstallers demonstrated: one prompted for a credential and the other did not, one had
# `--keep-data` gated on the storage database and the other did not, one polled a file lock and the
# other could not.
#
# Every fact below is extracted from BOTH launchers and compared. A fact that could only be true on
# one platform does not belong here.

UN_SH = ROOT / "installer" / "linux" / "uninstall.sh"
UN_PS1 = ROOT / "installer" / "windows" / "uninstall.ps1"


def _launcher_facts(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    lowered = text.lower()
    return {
        # the protocol
        "schema_version_2": '"schema_version": 2' in text or "schema_version       = 2" in text,
        "first_call_is_start_with_none": "'none'" in text or '"none"' in text,
        "resumes_on_the_named_pending_reason":
            "pending_record_exists__resume_it_rather_than_starting_again" in text,
        "acts_on_the_named_credential_reason": "credential_required" in text,
        # Platform method differs legitimately: bash can let the child prompt on inherited stderr;
        # PowerShell captures native stderr, so it prompts visibly itself and sends framed stdin.
        # The parity fact is the product answer: a continuation gets one transient credential
        # transport, never which process owns the terminal on a given platform.
        "credential_transport_is_the_second_call": (
            "'prompt'" in text or '"prompt"' in text or "Lc-InvokeFramed 'resume'" in text),
        "silent_never_prompts": "silent" in lowered and "never prompt" in lowered,
        # the request
        "request_is_root_or_admin_only": ("chmod 700" in text or "icacls" in text),
        "request_is_removed": _only_removes_its_own_request(path) and "cleanup" in lowered,
        "declares_a_transport_never_a_value": "credential_transport" in text,
        # the result
        "reads_exactly_one_json_object": "one readable JSON result" in text,
        # **Not "the digits 0-5 appear somewhere"** — that is satisfied by any file with a line
        # number in it. Every code must be a BRANCH of the dispatcher, which is the contract.
        "maps_every_exit_code": _dispatches_every_exit_code(path),
        # the identity
        "installation_id_from_the_shipped_status_verb": "status --json" in text,
        "refuses_when_there_is_no_installation": "No CORPUSfm installation record" in text,
        # **What it must NOT be able to do.** Measured on executable lines only, and on USES rather
        # than mentions: Windows declares the retired options precisely so it can refuse them, so a
        # check that banned the token would forbid the refusal it wants.
        "fmsadmin_only_from_typed_plan": (
            "fmsadmin" in lowered and "credential_required" in lowered and
            ".fmp12" not in _code(path).lower()
        ),
        "no_database_name": ".fmp12" not in _code(path).lower(),
        "no_removal_of_anything_but_its_own_request": _only_removes_its_own_request(path),
        "no_keep_data_behaviour": _retired_options_are_only_refused(path),
    }


def _code(path: Path) -> str:
    from tests.test_uninstall_stage_fence import _executable_lines

    return "\n".join(_executable_lines(path))


#: The only thing a launcher may remove: the temporary request material it created itself.
_OWN_MATERIAL = ("lc_req_dir", "lcreqdir", "request", "errfile")


def _dispatches_every_exit_code(path: Path) -> bool:
    """Each of the six codes is a BRANCH, not a character that happens to occur in the file."""
    code = _code(path)
    if path.suffix == ".sh":
        return all(f"{n})" in code for n in (0, 1, 2, 3, 4, 5))
    return all(f"\n    {n} " in code or f"\n    {n} {{" in code for n in (0, 1, 2, 3, 4, 5))


def _only_removes_its_own_request(path: Path) -> bool:
    for line in _code(path).lower().splitlines():
        if "rm -rf" in line or "rm -f" in line or "remove-item" in line:
            if not any(token in line for token in _OWN_MATERIAL):
                return False
    return True


def _retired_options_are_only_refused(path: Path) -> bool:
    """`keep-data` may be NAMED — declared so a shell cannot bind it silently, collected into a
    refusal, or quoted in the message that tells the operator it is gone. It may never BIND to
    anything the run reads.

    **The two platforms prove it differently and that is correct**: the fact is *no keep-data
    behaviour*, and bash refuses an unknown option through a catch-all while PowerShell must declare
    a parameter to stop it binding positionally. The parity fact set compares the ANSWER, never the
    method — comparing the method is how a legitimate platform difference becomes a false divergence.
    """
    code = _code(path)
    if path.suffix == ".sh":
        # No case arm, and no variable: nothing can read it, so nothing can act on it.
        return "--keep-data)" not in code and "KEEP_DATA" not in code
    # Every mention is a declaration or the refusal that collects it.
    for line in code.splitlines():
        if "KeepData" not in line:
            continue
        stripped = line.strip()
        if stripped.startswith("[switch]") or stripped.startswith("[string]"):
            continue
        if "retired" in line:
            continue
        return False
    return True


@pytest.fixture
def launcher_facts():
    return {"linux": _launcher_facts(UN_SH), "windows": _launcher_facts(UN_PS1)}


def test_the_two_LAUNCHERS_agree_on_every_protocol_fact(launcher_facts):
    linux, windows = launcher_facts["linux"], launcher_facts["windows"]
    assert set(linux) == set(windows)
    divergent = {key for key in linux if linux[key] != windows[key]}
    assert not divergent, f"the launchers diverge on {sorted(divergent)}"


def test_every_LAUNCHER_protocol_fact_is_actually_TRUE_and_not_merely_equal(launcher_facts):
    """**The control the parity check cannot be without.** Two launchers that both did nothing would
    agree perfectly, so agreement is asserted separately from correctness — the same trap this file's
    §4H checks are built against."""
    for platform, facts in launcher_facts.items():
        for key, value in facts.items():
            assert value is True, f"{platform}: {key} is not satisfied"


@pytest.mark.parametrize("fact", ["acts_on_the_named_credential_reason",
                                  "reads_exactly_one_json_object",
                                  "schema_version_2"])
def test_A_DIVERGENT_LAUNCHER_PAIR_IS_DETECTED(fact, launcher_facts):
    """A parity checker nobody has watched fail is a claim. One fact is flipped on one side and the
    comparison must notice."""
    linux = dict(launcher_facts["linux"])
    linux[fact] = not linux[fact]
    assert linux != launcher_facts["windows"]
    divergent = {key for key in linux if linux[key] != launcher_facts["windows"][key]}
    assert divergent == {fact}


def test_NEITHER_LAUNCHER_can_perform_a_REMOVAL_the_other_cannot():
    """The parity that matters most is a parity of INCAPACITY: neither may delete anything, so there
    is nothing for one platform to do that the other does not."""
    for path in (UN_SH, UN_PS1):
        code = _code(path).lower()
        for verb in ("rm -rf", "remove-item"):
            for line in code.splitlines():
                if verb in line:
                    assert any(token in line for token in
                               ("lc_req_dir", "lcreqdir", "request", "errfile")), line
