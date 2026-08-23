"""The Windows installer asks for FMS admin credentials only when its measured plan uses them.

WHY THIS EXISTS
    Windows uses fmsadmin for a fresh storage bootstrap and an explicitly requested storage-access
    repair. Its isolated IIS application requires no FMS restart. An active Claris nginx front does:
    its staged include is activated by an authenticated FileMaker HTTP-server restart.

    install.sh has done this on Linux for a while and prints why it is skipping. Windows needs the
    credential LESS — its IIS path needs no `fmsadmin restart httpserver` — and was the one asking
    every time.

WHAT THIS CANNOT CHECK
    That a human is no longer asked. Only a real re-run on a Windows box shows that, and this guard
    exists so the STRUCTURE cannot silently regress between those runs.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
PS1 = REPO / "installer" / "windows" / "install.ps1"

# PowerShell comments. Stripped before scanning because this rule's own rationale, inside the script,
# necessarily names the thing it forbids — the mistake made twice in this repo already (2026-07-28,
# test_windows_nginx_proxy.py and test_no_native_select.py).
_PS_COMMENT = re.compile(r"(?m)#.*$")


def _code() -> str:
    return _PS_COMMENT.sub("", PS1.read_text(encoding="utf-8"))


def test_the_credential_prompt_follows_the_measured_mode():
    """Fresh bootstrap, explicit repair, and measured active Claris consume the credential."""
    code = _code()
    assert re.search(
        r"\$NeedFmsCreds\s*=\s*\(-not \$IsUpgrade\) -or \[bool\]\$RepairStorageAccess "
        r"-or \$ClarisNginxActive", code
    ), "credential need is no longer bound to fresh bootstrap or explicit repair"
    assert re.search(r"if \(\$NeedFmsCreds[^)]*-not \$FmAdminPass", code), (
        "the credential prompt does not consult the measured plan")


def test_retired_server_configs_projection_does_not_decide_installer_work():
    code = _code()
    preparation = code[code.index("$NeedFmsCreds ="):code.index('Section "Confirm"')]
    assert "server_configs.yaml" not in preparation
    assert "$BootstrapDone" not in preparation


def test_no_assignment_in_the_permissions_section_is_unused():
    """An assignment sitting exactly where a check belongs, used nowhere, is what this packet was."""
    code = _code()
    start = code.index("Section \"Permissions\"")
    end = code.index("Section \"Detection\"")
    block = code[start:end]
    for var in set(re.findall(r"^\$(\w+) = ", block, re.M)):
        used = len(re.findall(r"\$" + var + r"\b", code))
        assert used > 1, f"${var} is assigned in Permissions and never read"


def test_every_escape_hatch_survives():
    """Flag and environment must still supply the credential explicitly, for the runs that need it."""
    code = _code()
    for hatch in ("$FmAdminPass", "$env:FM_ADMIN_PASS", "$FmAdminUser", "$env:FM_ADMIN_USER"):
        assert hatch in code, f"{hatch} escape hatch is gone"


def test_a_run_that_needs_the_credential_and_lacks_it_fails_with_the_flag_to_pass():
    """Never cryptically, and never by re-prompting halfway through an install."""
    code = _code()
    # RE-EXPRESSED TWICE. First (1246-04): `-FmAdminPass` is retired with no alias, so the message
    # must name the ENVIRONMENT secret — the only way in.
    #
    # Again (packet 1000-13): the anchor was the message's opening words, `Storage bootstrap needs`,
    # and the message no longer opens that way. The failure moved to where the credential is
    # ACQUIRED — inside the `$NeedFmsCreds -and -not $FmAdminPass` arm, guarded by `$Silent`, which
    # is the honest home: an interactive run does not fail, it prompts. Pinning the old opening
    # would have demanded a message that must no longer exist.
    #
    # The rule is unchanged and is asserted structurally: the ONLY run that can need the credential
    # and be unable to obtain one is a silent run, and it dies naming the environment variable.
    arm = code[code.index("$NeedFmsCreds -and -not $FmAdminPass"):]
    arm = arm[:arm.index("-AsSecureString")]
    m = re.search(r'Die "[^"]*"', arm)
    assert m, "a silent run that needs the credential and lacks it no longer fails at all"
    assert "$Silent" in arm[:arm.index(m.group(0))], (
        "the failure is no longer gated on --silent, so an INTERACTIVE run dies instead of "
        "prompting — the prompt below it would be unreachable")
    assert "FM_ADMIN_PASS" in m.group(0), "the failure no longer names what to pass"
    assert "-FmAdminPass" not in m.group(0), "the message still offers a retired parameter"


def test_the_skip_says_why():
    """A silent skip is indistinguishable from a bug the other way — install.sh sets the precedent."""
    code = _code()
    assert re.search(r'Info "Published-install update preserves storage[^"]*"', code), (
        "skipping the credential prompt must describe the measured update plan")


def test_the_credential_is_still_never_stored():
    """Untouched by this packet, asserted so it stays that way: the persisted storage credential is
    the rotated automation account, never the FM admin one."""
    code = _code()
    assert "$FmAdminPass = ''" in code, "the transient credential is no longer cleared after use"
    assert "Remove-Item Env:\\FM_ADMIN_PASS" in code, "the env copy is no longer removed after use"
