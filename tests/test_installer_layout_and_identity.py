"""The installers actually implement the ruled layout and identities (packet 1246-03, E1/E3 + O3).

Static text assertions, because the alternative is a box — and this project has learned twice that a
rule enforced only where nobody looks is not enforced. The browser-only `<select>` ban let three
native selects accumulate; the service-identity rule has exactly the same shape and a worse blast
radius.

Every scan excludes comment lines. A guard whose own rationale has to name the thing it forbids
reports itself as a violation, and this project has made that mistake three times.
"""

from __future__ import annotations

import pathlib
import inspect
import re

import pytest

INSTALLER = pathlib.Path(__file__).resolve().parent.parent / "installer"
SH = INSTALLER / "linux" / "install.sh"
PS1 = INSTALLER / "windows" / "install.ps1"


def _code(path: pathlib.Path) -> str:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


@pytest.fixture(scope="module")
def sh() -> str:
    return _code(SH)


@pytest.fixture(scope="module")
def ps1() -> str:
    return _code(PS1)


def test_both_existing_install_paths_publish_the_verified_installer_identity(sh, ps1):
    assert "composition publish-installer --request" in sh
    assert "@('composition','publish-installer','--request',$req)" in ps1
    for field in ("installer_series", "installer_version", "installer_bundle_protocol",
                  "installer_source", "expected_generation"):
        assert field in sh and field in ps1


# ── E1: the fixed OS locations exist and are owned correctly ──────────────────────────

@pytest.mark.parametrize(
    "path", ["/etc/corpusfm", "/var/lib/corpusfm/state", "/var/lib/corpusfm/secrets",
             "/var/log/corpusfm", "/run/corpusfm"])
def test_the_linux_installer_creates_every_fixed_location(sh, path):
    assert path in sh, f"the installer never creates {path}"


def test_the_secrets_directory_is_root_owned(sh):
    """Directory permission is what withholds create/delete/rename from the service."""
    line = next(l for l in sh.splitlines() if "/var/lib/corpusfm/secrets" in l and "install -d" in l)
    assert "-o root -g root" in line, f"the secrets directory is not root-owned: {line.strip()}"


def test_state_and_logs_are_writable_by_the_service(sh):
    for path in ("/var/lib/corpusfm/state", "/var/log/corpusfm"):
        line = next(l for l in sh.splitlines() if path in l and "install -d" in l)
        assert '-o "$SERVICE_USER"' in line, f"{path} is not service-owned: {line.strip()}"


def test_the_volatile_runtime_directory_is_recreated_at_boot(sh):
    """Creating /run/corpusfm during installation is insufficient: /run is empty after reboot."""
    assert "d /run/corpusfm 0750 corpusfm corpusfm -" in sh


# ── E3: the source tree stops being service-writable ──────────────────────────────────

def test_the_source_tree_is_never_chowned_to_the_service_user(sh):
    """THE defect: `chown -R corpusfm:corpusfm $INSTALL_DIR/src` is what let the running service
    rewrite the code it executes."""
    offenders = [
        l.strip() for l in sh.splitlines()
        if re.search(r'chown\s+(-R\s+)?"?\$SERVICE_USER"?:"?\$SERVICE_USER"?\s+"\$INSTALL_DIR/src"\s*$', l)
    ]
    assert not offenders, f"the source tree is handed to the service identity: {offenders}"


def test_the_source_tree_is_root_owned_and_not_group_writable(sh):
    assert 'chown -R root:"$SERVICE_USER" "$INSTALL_DIR/src"' in sh
    assert 'chmod -R g-w,o-rwx "$INSTALL_DIR/src"' in sh


def test_no_mutating_deployment_git_operation_runs_as_the_service_user(sh):
    """Read-only verification may use the service view; mutation must remain privileged."""
    offenders = [l.strip() for l in sh.splitlines()
                 if re.search(r'sudo\s+-u\s+"?\$SERVICE_USER"?.*\bgit\s+.*\b(clone|fetch|pull|reset|checkout|config)\b', l)]
    assert not offenders, f"deployment git still runs as the service identity: {offenders}"


def test_service_runtime_directories_are_outside_the_recursive_source_chown(sh):
    """Runtime state belongs under /var, never inside the root-owned source checkout."""
    assert 'chown -R root:"$SERVICE_USER" "$INSTALL_DIR/src"' in sh
    assert 'install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/corpusfm/state/update-inbox' in sh
    assert 'for _rt in "$INSTALL_DIR/src/archive"' not in sh


# ── E3: Windows names an identity, always ─────────────────────────────────────────────

def test_the_winsw_definition_names_a_service_account():
    """RE-EXPRESSED against `service_identity` (packet 1246-04-05).

    The definition previously said NOTHING, and Windows filled the silence with LocalSystem. That
    rule is unchanged; the XML moved. 1246-04-03 replaced the installer's hand-written WinSW
    fragment with canonical rendering, so the `<serviceaccount>` element now comes from the
    renderer — and the renderer **cannot** omit it: `service_identity` refuses a definition that
    names no identity, which is stronger than a text search for the element.
    """
    from corpusfm.lifecycle import os_layout as ol, service_identity as si

    os_l = ol.windows_os_layout()
    for role in si.SERVICE_ROLES:
        xml = si.render_winsw_service(si.winsw_service_spec(
            role, os_l, install_dir=r"C:\Program Files\CORPUSfm", service_id=f"corpusfm-{role}",
            display_name=f"CORPUSfm {role}", description=f"CORPUSfm {role}"))
        assert "<serviceaccount>" in xml
        assert f"<username>NT SERVICE\\corpusfm-{role}</username>" in xml
        assert si.service_definition_names_an_identity(xml)


def test_no_windows_service_is_configured_as_a_privileged_account(ps1):
    for forbidden in ("LocalSystem", "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"):
        offenders = [l.strip() for l in ps1.splitlines()
                     if forbidden.lower() in l.lower() and "serviceaccount" not in l.lower()
                     and "username" in l.lower()]
        assert not offenders, f"a service is configured as {forbidden}: {offenders}"


def test_the_service_identities_are_granted_the_access_they_need(ps1):
    """Shipping `<serviceaccount>` without matching ACLs would break the install outright — the
    services stop inheriting LocalSystem's access to everything the moment they stop being it."""
    assert "icacls" in ps1 and "NT SERVICE" in ps1
    # The grant now goes through Grant-OrDie, which is the point: a failure is fatal rather than a
    # warning. Assert the CAPABILITY, not the spelling of the call that provides it.
    assert re.search(r"Grant-OrDie \$LogDir\s+\(\$sid \+ ':\(OI\)\(CI\)\(M\)'\)", ps1), (
        "the service cannot write its logs"
    )


# NOTE ON WHAT THESE WINDOWS TESTS ARE. They are STATIC POLICY tests: they read install.ps1 and
# assert the ACL COMMANDS it issues. They do not and cannot prove EFFECTIVE rights — icacls
# semantics, ACE ordering and inheritance are Windows behaviour, and asserting them from string
# matching is exactly the overclaim review caught in the first round (a `/grant (R)` sitting next to
# an inherited Modify, which changes nothing). Effective-rights proof is a live-lane obligation and
# is recorded as owed in the packet, not claimed here.

def test_the_cutover_definitions_never_grant_the_mixed_legacy_directory():
    """RE-EXPRESSED against `service_identity` (packet 1246-04-05, §3.2).

    R1/R2, and the property that actually matters: PARENT-DIRECTORY authority. Per-file protection
    is defeated by a parent the service can create, delete and rename entries in — it deletes the
    protected key and puts its own there. So the question is not "is this ACE spelled (R)" but "can
    the identity reach the secret through its parent at all".

    **The rule is unchanged; the thing that renders it moved.** This imported
    `lifecycle.cutover_cli.build_definitions`, and there is no cutover — 1246-03 removed it and
    1246-04-03 replaced the installer's hand-written heredocs with canonical rendering. **No
    cutover-shaped abstraction is recreated here**: the definitions the box actually installs come
    from `service_identity`, so that is what is asserted.
    """
    from corpusfm.lifecycle import layout as lm, os_layout as ol, service_identity as si

    for flavour, os_l, install_dir in (
        (lm.POSIX, ol.posix_os_layout(), "/opt/CORPUSfm"),
        (lm.WINDOWS, ol.windows_os_layout(), r"C:\Program Files\CORPUSfm"),
    ):
        for role in si.SERVICE_ROLES:
            if flavour == lm.POSIX:
                rendered = si.render_systemd_unit(
                    si.systemd_unit_spec(role, os_l, install_dir=install_dir,
                                         description=f"CORPUSfm {role}"))
                granted = [l.split("=", 1)[1] for l in rendered.splitlines()
                           if l.startswith("ReadWritePaths=")]
            else:
                rendered = si.render_winsw_service(
                    si.winsw_service_spec(role, os_l, install_dir=install_dir,
                                          service_id=f"corpusfm-{role}",
                                          display_name=f"CORPUSfm {role}",
                                          description=f"CORPUSfm {role}"))
                # Scanned on the RENDERED definition rather than a spec attribute: what ships is the
                # text, and a field the renderer stopped emitting would still read correctly here.
                granted = [rendered]
            # THE SECRETS DIRECTORY ITSELF is never granted. Packet 1258 also retired the sole
            # exact-file exception, asserted separately below.
            assert not any(str(os_l.secrets_dir) == g or
                           (g is rendered and f">{os_l.secrets_dir}<" in g) for g in granted), (
                f"{flavour}/{role} is granted the secrets DIRECTORY, which defeats per-file "
                f"protection through the parent"
            )
            assert rendered


def test_neither_definition_carries_a_writable_secret_exception():
    """The retired global token leaves no per-file secret grant on either runtime role."""
    from corpusfm.lifecycle import os_layout as ol, service_identity as si

    os_l = ol.posix_os_layout()
    rendered = {
        role: si.render_systemd_unit(
            si.systemd_unit_spec(role, os_l, install_dir="/opt/CORPUSfm",
                                 description=f"CORPUSfm {role}"))
        for role in si.SERVICE_ROLES
    }
    for role, definition in rendered.items():
        for line in definition.splitlines():
            if line.startswith("ReadWritePaths="):
                path = line.split("=", 1)[1]
                assert not path.startswith(str(os_l.secrets_dir)), (
                    f"{role} is granted a writable installed secret: {path}"
                )


def _phase_map(raw: str, marker: str) -> dict:
    marks = [(int(m.group(1)), m.end()) for m in re.finditer(marker, raw, re.M)]
    return {n: raw[e:(marks[i + 1][1] if i + 1 < len(marks) else len(raw))]
            for i, (n, e) in enumerate(marks)}


#: Per platform: how a service START looks, and which phase is allowed to do it.
_START_FORMS = {
    "linux": (r"^\s*systemctl\s+(start|--now\s+enable)\b", r"^# ═══ PHASE (\d+) —"),
    "windows": (r"^\s*&\s*\$exe\s+start\b", r"^# === PHASE (\d+) -"),
}


def _early_starts(raw: str, platform: str) -> list:
    """Every service start outside phase 21, derived from the REAL phase body it sits in."""
    start_form, phase_marker = _START_FORMS[platform]
    offenders = []
    for number, body in _phase_map(raw, phase_marker).items():
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not re.match(start_form, line):
                continue
            # The one-shot updater unit is not a CORPUSfm service; the sudoers grant names it.
            if "corpusfm-update.service" in stripped:
                continue
            if number != 21:
                offenders.append((number, stripped))
    return offenders


def test_no_service_is_started_before_the_cutover(sh, ps1):
    """RE-EXPRESSED (§4D.0), and CORRECTED for A2 (packet 1246-04-05).

    *No service starts before phase 20 verifies the definitions.* The ruling's prohibition was never
    *start* — it was **never start a hardened identity against a layout nothing has verified**. The
    cutover was one way to guarantee that and it is gone; the 21-phase sequence is stronger, because
    phase 20 renders each definition canonically, **reads it back**, and phase 21 starts exactly
    that verified set.

    **A2: this took `ps1` and never read it.** Only Linux `systemctl start` lines were scanned, so
    Windows — which starts through the WinSW wrapper, `& $exe start` — was unguarded for a rule that
    was always platform-neutral. Both are consumed now, each through its own real phase map.

    **A2, second pass.** The first correction scanned Windows through the module-level `PS1` path
    and left the `ps1` PARAMETER unread — the same defect one layer down, and a confirmation pass
    caught it. The phase scan genuinely needs the RAW text (the phase markers are comments, which
    the fixtures strip), so the fixtures cannot serve it; what they can serve is the second half of
    this rule, and both now do. The Linux half forbids the retired `restart_web`, which started a
    stopped unit outside the sequence. The Windows half is the same rule against the same act:
    nothing may restart the service outside phase 21, and a `Restart-Service`/`& $exe restart` in
    the comment-stripped code would be exactly that.
    """
    for platform, raw in (("linux", SH.read_text(encoding="utf-8")),
                          ("windows", PS1.read_text(encoding="ascii"))):
        offenders = _early_starts(raw, platform)
        assert not offenders, (
            f"{platform}: a CORPUSfm service starts before phase 20 verified it: {offenders}"
        )
        # …and phase 21 really does start something, or the scan above passes vacuously.
        assert _START_FORMS[platform][0]
        phase21 = _phase_map(raw, _START_FORMS[platform][1])[21]
        assert re.search(_START_FORMS[platform][0], phase21, re.M), (
            f"{platform}: phase 21 starts nothing, so this guard proves nothing"
        )
    assert "restart_web" not in sh, "restart_web is back; it starts a stopped unit"
    for form in ("Restart-Service", "$exe restart", "$exe.restart"):
        assert form not in ps1, f"{form} restarts the service outside the phase-21 start"


#: How a service start is SPELLED when injected, per platform. Each must match its `_START_FORMS`
#: detector — that pairing is the whole mechanism under test.
_INJECTED_START = {"linux": "systemctl start corpusfm", "windows": "& $exe start | Out-Null"}


def _inject_start(raw: str, platform: str, number: int) -> str:
    """Put a service start inside the REAL body of phase `number`, found through the real marker."""
    _, phase_marker = _START_FORMS[platform]
    for m in re.finditer(phase_marker, raw, re.M):
        if int(m.group(1)) == number:
            at = raw.index("\n", m.end()) + 1
            return raw[:at] + _INJECTED_START[platform] + "\n" + raw[at:]
    raise AssertionError(f"{platform}: phase {number} is not in the phase map")


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_AN_EARLY_START_INJECTED_INTO_EITHER_PLATFORM_IS_CAUGHT(platform):
    """The A2 control, INDEPENDENTLY per platform. Without it, "both are consumed" is a claim about
    a loop nobody has watched fail — and the Windows half in particular had been silently inert.

    RE-EXPRESSED (packet 1000-07). The old version injected at a LITERAL heading, `PHASE 15 — PATCH`.
    Phase 15 is now ADMIN IDENTITY and the patch compartment is phase 16, so the anchor was gone and
    the control died — leaving `test_no_service_is_started_before_the_cutover` claiming a per-platform
    scan that nothing had watched fail. Pinning the new heading would only queue the same failure
    behind the next reordering, so the injection point is DERIVED from the phase map the detector
    itself uses: every phase that exists and is not 21 must be a place an early start is caught. That
    is a stronger rule than the single phase it replaces and it cannot go stale.
    """
    raw = (SH.read_text(encoding="utf-8") if platform == "linux"
           else PS1.read_text(encoding="ascii"))
    _, phase_marker = _START_FORMS[platform]
    phases = sorted(_phase_map(raw, phase_marker))
    assert 21 in phases, f"{platform}: no phase 21, so 'before the cutover' has no meaning"
    early = [n for n in phases if n != 21]
    assert len(early) > 5, f"{platform}: the phase map found only {phases}"
    assert not _early_starts(raw, platform), f"{platform}: the real file already starts early"

    for number in early:
        offenders = _early_starts(_inject_start(raw, platform, number), platform)
        assert [n for n, _line in offenders] == [number], (
            f"{platform}: an early start injected into phase {number} was NOT detected as exactly "
            f"that — this guard is inert there (saw {offenders})"
        )


def test_both_installers_invoke_the_cutover(sh, ps1):
    """RE-EXPRESSED (§4D.0): *both installers run phases 15–18 and, on update, phase 9*.

    The 2026-08-03 ruling said 1246-03 owns invoking its cutover and 1246-04 must inherit a working
    one. **1246-03 removed the cutover instead**, by developer disposition — so what this test
    defends is the surviving obligation: each installer composes every provider, and each quiesces
    before replacing a byte. **No cutover abstraction is recreated**, and the name is kept so the
    census and this function still refer to the same subject.
    """
    for source, name in ((sh, "linux"), (ps1, "windows")):
        assert "cutover_cli" not in source, f"{name} invokes a cutover that does not exist"
        for provider in ("patch", "proxy", "admin_identity", "storage"):
            assert re.search(rf"(lc_commit_provider|Lc-CommitProvider) '?{provider}\b", source), (
                f"{name} never composes {provider}"
            )
    assert "PHASE 9 — QUIESCE UPDATE" in SH.read_text(encoding="utf-8")
    assert "PHASE 9 - QUIESCE UPDATE" in PS1.read_text(encoding="ascii")


def test_windows_acl_failure_is_fatal_not_a_warning(ps1):
    """A service running with permissions nobody established is the LocalSystem defect again.

    RE-EXPRESSED (packet 1000-07). This named three `Die` message strings, two of which belonged to
    the phase-20 `icacls` sequences the developer retired on 2026-08-09 when `WindowsLayoutProtector`
    became the single authority for secret protection. Asserting them would now forbid that ruling.
    The rule it was defending is unchanged, so it is asserted where the acts now are:

    * every ACL this script issues ITSELF reaches `Die` on failure — never `Warn`;
    * the authoritative protection of the installed secrets is delegated to the provider, and that
      delegation is fatal for every non-success result.

    SCOPED TO `install.ps1` DELIBERATELY. `_cfm_lib.ps1`'s `Lock-FileAcl` / `Lock-DirTreeAcl` warn by
    documented intent — they are idempotent best-effort locks over box-local files whose authoritative
    protection is established later by the provider. That is current product behaviour, not a gap, and
    this guard must not be read as forbidding it. The provider half's fatality is proven behaviourally
    by `test_key_provisioning.py::test_INABILITY_TO_PROTECT_is_fatal` and
    `::test_a_protector_that_VERIFIES_a_problem_is_fatal`.
    """
    body = "\n".join(ps1.splitlines())
    assert "function Grant-OrDie" in body
    grant_or_die = body[body.index("function Grant-OrDie"):][:400]
    assert "Die " in grant_or_die.split("\n}")[0], "Grant-OrDie no longer dies"

    lines = ps1.splitlines()
    issuing = [i for i, l in enumerate(lines) if re.search(r"&\s*icacls\b", l)]
    assert issuing, "no icacls call in install.ps1 — this guard would pass vacuously"
    for at in issuing:
        checked_at = None
        for offset, line in enumerate(lines[at + 1:at + 6], start=at + 1):
            if "$LASTEXITCODE" not in line:
                continue
            checked_at = offset
            break
        if checked_at is None:
            raise AssertionError(
                f"an ACL is issued and its result is never tested: {lines[at].strip()}")
        refusal = "\n".join(lines[checked_at:checked_at + 6])
    assert ("Die " in refusal or "exit 2" in refusal) and "Warn " not in refusal, (
            f"an ACL failure does not reach a fatal refusal: {lines[at].strip()} -> {refusal}")

    # …and the secrets themselves are the provider's, reached through a dispatcher with no
    # non-fatal branch except success.
    assert re.search(r"Lc-Run [^\n]*'provision-keys'", body), (
        "the installed secrets are no longer protected through the provider")
    dispatch = body[body.index("function Lc-Dispatch"):]
    dispatch = dispatch[:dispatch.index("\n}")]
    branches = [l.strip() for l in dispatch.splitlines()
                if re.match(r"^\s*(\d+|default)\s*\{", l)]
    assert len(branches) >= 6, branches
    for branch in branches:
        if branch.startswith("0 "):
            continue
        assert "Die " in branch, f"a lifecycle failure does not abort the install: {branch}"


def test_the_outcome_directory_is_root_owned_on_both_platforms(sh, ps1):
    """R4: correlation is not authentication — the outcome must come from somewhere we cannot write."""
    line = next(l for l in sh.splitlines() if "update-outcome" in l and "install -d" in l)
    assert "-o root -g root" in line, f"the outcome directory is service-owned: {line.strip()}"
    inbox = next(l for l in sh.splitlines() if "update-inbox" in l and "install -d" in l)
    assert '-o "$SERVICE_USER"' in inbox, "the request inbox must be service-writable"

    body = "\n".join(ps1.splitlines())
    assert "$OutcomeDir /inheritance:r /grant:r" in body
    protect = body[body.index("$OutcomeDir /inheritance:r"):][:300]
    assert "(RX)" in protect and "(M)" not in protect, (
        "the services must not be able to write or replace the outcome"
    )


def test_the_powershell_renderer_escapes_apostrophes(ps1):
    """R6: a rendered path with an apostrophe closes the single-quoted literal early.

    The filter is `Replace('@@`, not `.Replace('@@`: these are method-chained across lines, so the
    dot belongs to the PREVIOUS line and a dot-anchored pattern misses every one of them. A mutation
    that unescaped exactly one placeholder survived the dot-anchored version.
    """
    # RE-EXPRESSED (packet 1246-04-05). The rule is unchanged and the escaping MOVED: correction F
    # retired the installer's nine hand-written `.Replace('@@X@@', (Esc-PsLiteral …))` calls in
    # favour of the shipped renderer, which applies the same doubling in one place. Asserting the
    # retired call shape would now forbid the correction; asserting the RULE is what survives.
    from corpusfm.lifecycle import update_boundary as ub

    source = inspect.getsource(ub._substitute)
    assert 'value.replace("\'", "\'\'")' in source, (
        "the PowerShell quoting escape is gone from the shipped renderer"
    )
    assert 'quoting == "powershell"' in source
    # …and the installer no longer hand-renders any placeholder at all.
    assert not re.search(r"Replace\('@@", ps1), "a hand-rendered placeholder is back"


@pytest.mark.parametrize(
    "path",
    [
        r"C:\Program Files\CORPUSfm",                    # ordinary
        r"C:\Users\O'Brien\CORPUSfm",                   # ORDINARY and legal, and it broke the render
        r"C:\x'; Remove-Item -Recurse C:\ ; '",          # poisoned: closes the literal and injects
    ],
)
def test_the_escape_rule_keeps_a_single_quoted_literal_balanced(path):
    """The rule itself, applied the way install.ps1 applies it.

    PowerShell escapes an apostrophe inside a single-quoted literal by DOUBLING it. A literal is
    well-formed when every apostrophe in the body is doubled — which is exactly what makes the
    injection case above inert rather than executable.
    """
    escaped = path.replace("'", "''")
    literal = f"'{escaped}'"
    body = literal[1:-1]
    i = 0
    while i < len(body):
        if body[i] == "'":
            assert i + 1 < len(body) and body[i + 1] == "'", (
                f"an unpaired apostrophe would close the literal early: {literal}"
            )
            i += 2
        else:
            i += 1
    # And the escaped form must still round-trip to the original path.
    assert body.replace("''", "'") == path


def test_the_updater_script_is_not_writable_by_any_service_identity(ps1):
    """The script IS the action of the elevated task; write access to it is write access to what
    the task executes."""
    # RE-EXPRESSED (packet 1246-04-05). The phase-13 ACL is SYSTEM + Administrators only, and the
    # web identity's read+execute moved to PHASE 20 — deliberately, because `NT SERVICE\<id>` has
    # no SID until the service is registered and phase 20 is where that happens. There is no
    # exposure window: the grant lands before phase 21 starts anything. The surviving rule — no
    # service identity may WRITE the script the elevated task executes — is asserted across both.
    #
    # RE-EXPRESSED AGAIN (packet 1000-10, R10). This read the line containing `$UpdaterDst
    # /inheritance:r`, which is a SPELLING: phase 13 now grants the DACL on a staged file and
    # publishes it by rename, so that literal is gone and the assertion would have failed as stale
    # while the rule it defends held perfectly. The rule is about the file that BECOMES the task's
    # action, so the path is derived from the publication itself rather than retyped — and it is
    # separately required that the grant precede the publication, because a DACL applied after the
    # rename would leave the executed path unprotected for a window.
    publish = next(l for l in ps1.splitlines() if re.search(r"Move-Item -Force \$\w+ \$UpdaterDst", l))
    staged = re.search(r"Move-Item -Force (\$\w+) \$UpdaterDst", publish).group(1)
    line = next(l for l in ps1.splitlines() if f"{staged} /inheritance:r" in l)
    assert "(RX)" in line and "(F)" in line
    assert "$SchedSid" not in line and "$WebSid" not in line
    assert ps1.index(line) < ps1.index(publish), (
        "the updater's DACL is applied after it is published; the executed path is unprotected "
        "until it lands"
    )
    # The phase-20 grant is issued through a LOOP over the three administrator-owned paths, so the
    # line NAMING $UpdaterDst is the loop header and the line granting is its body. Read the loop.
    body = "\n".join(ps1.splitlines())
    m = re.search(r"foreach \(\$p in @\([^)]*\$UpdaterDst[^)]*\)\) \{(.*?)\n\}", body, re.S)
    assert m, "the updater script receives no service grant at phase 20"
    grants = [l for l in m.group(1).splitlines() if "Grant-OrDie" in l]
    assert grants and all("(RX)" in l for l in grants), (
        f"the updater script is granted more than read+execute: {grants}"
    )
    assert not [l for l in grants if "$SchedSid" in l], "the scheduler was granted the update path"


def test_the_privileged_update_task_is_registered(ps1):
    """Round 1 shipped the PowerShell updater and registered nothing, so `update_service` probed for
    a task that did not exist and the whole boundary was unreachable on Windows."""
    # Anchored at the start of a line, because a commented-out call still CONTAINS the string —
    # a mutation proved exactly that against the first version of this assertion.
    assert re.search(r"^\s*Register-ScheduledTask\s", ps1, re.MULTILINE), (
        "the task registration is absent or commented out"
    )
    assert "'CORPUSfm Update'" in ps1
    assert re.search(r"^\s*\$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM'", ps1,
                     re.MULTILINE)
    assert re.search(r"^\s*\$regTask\.SetSecurityDescriptor", ps1, re.MULTILINE), (
        "the task's own DACL is never tightened"
    )


def test_the_task_action_is_fixed_and_takes_no_caller_input(ps1):
    action = next(l for l in ps1.splitlines() if "New-ScheduledTaskAction" in l)
    assert "powershell.exe" in action
    following = "\n".join(ps1.splitlines()[ps1.splitlines().index(action):][:3])
    assert "-File" in following and "$UpdaterDst" in following
    assert "$expected" not in following and "$args" not in following


def test_the_effective_rights_are_reported_rather_than_inferred(ps1):
    """A static test cannot prove effective rights; the installer can at least PRINT them.

    This is what makes the live lane checkable by reading a transcript instead of re-deriving the
    ACL model by hand.
    """
    body = "\n".join(ps1.splitlines())
    assert "AreAccessRulesProtected" in body
    assert "FileSystemRights" in body


def _unit(sh_text: str, marker: str) -> str:
    """One rendered unit heredoc, so the two units can be asserted apart."""
    start = sh_text.index(marker)
    end = sh_text.index("\nUNIT\n", start) if marker.endswith("UNIT") else len(sh_text)
    return sh_text[start:end]


def test_the_web_unit_has_no_writable_secret_exception(sh):
    """ProtectSystem remains strict without a file-level exception under the secrets directory."""
    from corpusfm.lifecycle import os_layout as ol, service_identity as si

    os_l = ol.posix_os_layout()
    web = si.render_systemd_unit(si.systemd_unit_spec(
        "web", os_l, install_dir="/opt/CORPUSfm", description="CORPUSfm web"))
    assert "ProtectSystem=strict" in web
    assert not any(
        line.startswith("ReadWritePaths=") and
        line.split("=", 1)[1].startswith(str(os_l.secrets_dir))
        for line in web.splitlines()
    )


def test_neither_unit_grants_the_secrets_DIRECTORY(sh):
    """A directory grant would let a runtime service replace any installed secret in it."""
    for line in sh.splitlines():
        if not line.startswith("ReadWritePaths="):
            continue
        value = line.split("=", 1)[1].lstrip("-")
        assert not value.rstrip("/").endswith("secrets"), f"the secrets directory is writable: {line}"


def test_the_retired_scheduler_ROLE_CANNOT_BE_RENDERED_AT_ALL(sh):
    """RE-EXPRESSED for application packet 1361-01, round 3, and the guarantee is STRONGER.

    This used to render a scheduler unit and assert it granted no writable installed secret. There
    is no scheduler unit any more: scheduling is a background component of the web process, and
    `corpusfm.server.scheduler` refuses to run as a `__main__`. So the rule that matters now is that
    the renderer cannot produce that definition — a unit nobody can render grants nothing at all,
    and it cannot come back by accident. The no-writable-secret rule is asserted over every role the
    renderer DOES produce, by `test_neither_definition_carries_a_writable_secret_exception` above."""
    from corpusfm.lifecycle import os_layout as ol, service_identity as si

    os_l = ol.posix_os_layout()
    assert si.SCHEDULER_ROLE not in si.SERVICE_ROLES
    with pytest.raises(si.PrivilegedIdentityRefused):
        si.systemd_unit_spec(si.SCHEDULER_ROLE, os_l, install_dir="/opt/CORPUSfm",
                             description="CORPUSfm scheduler")
    # Still REMOVABLE by name, which is what an upgrade and an uninstall need.
    assert si.service_name(si.SCHEDULER_ROLE, "posix") == "corpusfm-scheduler"


# ── E4: the privileged update path is installed, and the grant is one command ─────────

def test_the_one_shot_updater_and_its_unit_are_installed(sh):
    assert "corpusfm-update.sh" in sh
    assert "/etc/systemd/system/corpusfm-update.service" in sh
    assert "Type=oneshot" in sh


def test_the_service_grant_is_exactly_one_command(sh):
    """No path, no ref, no command, no environment — the caller can start one unit."""
    line = next(l for l in sh.splitlines() if "NOPASSWD" in l and "corpusfm-update" in l)
    assert "systemctl start corpusfm-update.service" in line
    assert "*" not in line, f"a wildcard in an update grant is not a scoped grant: {line.strip()}"


def test_the_sudoers_rule_is_validated_before_installation(sh):
    """A malformed sudoers file can lock every sudo user out of the box."""
    block = sh[sh.index("Privileged one-shot updater") if "Privileged one-shot updater" in sh
               else 0:]
    assert "visudo -cf" in block
