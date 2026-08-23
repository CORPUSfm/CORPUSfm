"""Packet 019: the installer/uninstaller OUTPUT WARNING contract.

Disruptive/destructive actions must stay VISIBLE in the operator-facing output even though routine
command chatter is folded into the transcript. These static guards pin the warnings we never want to
go silent (an FMS web-server restart, an uninstall that removes software + data + the storage DB, and
that FM admin credentials are transient — used, never stored / never consent). They also prevent the
retired manual Additional Database Folder instruction from returning after the lifecycle patch
provider has registered and verified that slot itself.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _code_only(text: str, *, powershell: bool = False) -> str:
    """Strip comment lines (packet 1233).

    Every assertion in this file is about what the OPERATOR SEES, and a substring search over the
    whole file is satisfied by a comment — so a refactor that moved a warning out of its `warn` call
    and into an explanatory comment above it would keep these tests green while the operator saw
    nothing. CLAUDE.md records the same failure twice already (test_windows_nginx_proxy.py,
    test_no_native_select.py); these were the third and fourth instances.

    REJECTED ALTERNATIVE — assert the string sits inside an output primitive call (`warn "…"` /
    `Warn ("…")`). Stronger in principle, but these messages are routinely line-wrapped and
    concatenated across several source lines, so that matcher would go red for reasons unrelated to
    the rule. Do not "improve" this into that form.

    Not stripped: PowerShell here-strings (`@"…"@`) hold non-comment, non-output content such as the
    proxy web.config XML. No current target string lives in one — a note for whoever adds the next
    assertion, not a defect today.
    """
    if powershell:
        text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


INSTALL_SH = _code_only((ROOT / "installer/linux/install.sh").read_text(encoding="utf-8"))
UNINSTALL_SH = _code_only((ROOT / "installer/linux/uninstall.sh").read_text(encoding="utf-8"))
INSTALL_PS = _code_only((ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8"),
                        powershell=True)
UNINSTALL_PS = _code_only((ROOT / "installer/windows/uninstall.ps1").read_text(encoding="utf-8"),
                          powershell=True)


def test_install_warns_about_fms_web_server_restart():
    # the proxy step restarts the FMS web server (brief WebDirect/OData/Admin interruption) — must be stated
    assert "RESTARTS the FMS web server" in INSTALL_SH


# packet 1234 — the guarantee is now SAID, not just true. It lived only in comments (install.sh:1659,
# install.ps1:261/676/745, uninstall.ps1:58), so this assertion passed vacuously for the life of the
# test; packet 1233 made it comment-blind, which turned it red and is how the gap was found. The
# xfail(strict) that recorded it is removed because the message landed, not because it was relaxed.
#
# All FOUR scripts, and the string must sit beside the PROMPT: a reassurance the operator reads after
# typing their password is not a reassurance.
#
# RE-EXPRESSED (packet 1000-13). The pinned spelling was `never written to disk`, which BOTH
# uninstallers stopped saying — not because the guarantee weakened but because it got stronger. They
# no longer handle a credential at all: the lifecycle component prompts for it, so they say "used
# for this run only, is never written down, and never passes through this script". Pinning the old
# words would have read as "the reassurance is gone" when the reassurance had grown. What must be
# TRUE is that each script states the credential is transient, beside its own prompt.
_TRANSIENT_PHRASINGS = ("never written to disk", "never written down", "never stored")


def test_fm_admin_credentials_are_transient_not_stored():
    for name, text in (("install.sh", INSTALL_SH), ("uninstall.sh", UNINSTALL_SH),
                       ("install.ps1", INSTALL_PS), ("uninstall.ps1", UNINSTALL_PS)):
        lowered = text.lower()
        assert any(phrase in lowered for phrase in _TRANSIENT_PHRASINGS), (
            f"{name}: the operator must be TOLD, beside the prompt, that the FM admin password is "
            "used for this run only. Comments do not count — this assertion runs over "
            "comment-stripped text.")


def test_uninstall_warns_it_removes_software_and_data():
    """RE-EXPRESSED (packet 1000-13). Both scripts were pinned by their OWN wording — Linux's
    "remove CORPUSfm services, software, and all data" and Windows's "the hosted storage DB" +
    "all config/data" — and both spellings are gone. They were replaced by one disclosure the two
    platforms now share verbatim, which also says the thing neither used to: what is KEPT.

    The rule is unchanged and is asserted symmetrically, because the scope of a destructive action
    is not a per-platform matter.
    """
    for name, text in (("uninstall.sh", UNINSTALL_SH), ("uninstall.ps1", UNINSTALL_PS)):
        lowered = text.lower()
        for owed in ("its services", "its software", "its data"):
            assert owed in lowered, (
                f"{name}: the operator is no longer told the uninstall removes {owed.split()[1]}")
        assert "registrations it made" in lowered, (
            f"{name}: the FileMaker Server registrations it removes are no longer disclosed")
        assert "did not create are kept" in lowered, (
            f"{name}: the disclosure no longer bounds itself — an operator reading 'its data' with "
            "no statement of what SURVIVES cannot tell whether their databases are at risk")


def test_uninstall_storage_db_removal_is_surfaced():
    """RE-EXPRESSED (packet 1000-14). The old assertion looked for a `Storage DB` STEP HEADING, and
    after the 1246 lifecycle rethread there is no such step in either launcher: they plan nothing and
    delete nothing, so a step name was the wrong anchor and its absence was not the loss of the rule.

    The rule survives intact and is what is asserted now, symmetrically: the operator is told, in
    output they will see, that the CORPUSfm storage database — the one holding everything the
    installation ever ingested — is removed. The disclosure above it says "its data", and "its data"
    is exactly the phrase a human reads as *the program's own files*, not *my corpus*.
    """
    for name, text in (("uninstall.sh", UNINSTALL_SH), ("uninstall.ps1", UNINSTALL_PS)):
        lowered = text.lower()
        assert "storage db" in lowered, (
            f"{name}: the storage database is no longer named — it is disclosed only inside the "
            "word 'data', which does not tell an operator their corpus goes with it")
        assert "copy it first" in lowered, (
            f"{name}: the operator is told the storage database goes and is not told they can keep "
            "it; a destructive disclosure with no remedy beside it is half a disclosure")


# The patch lifecycle now registers and reads back the Additional Database Folder itself. The old
# packet-1239 warning became actively false: package 0.2384 published slot 2 as registered+verified
# after displaying an ACTION REQUIRED instruction to do that same work manually.
def test_installers_do_not_report_a_manual_hosting_step_the_patch_provider_completed():
    for name, text in (("install.sh", INSTALL_SH), ("install.ps1", INSTALL_PS)):
        assert "ACTION REQUIRED" not in text, (
            f"{name}: stale manual-folder instruction survived even though patch composition owns "
            "and verifies slot registration")
        assert "patch-compartment" in text


# ── credentials are MEANS, not CONSENT ─────────────────────────────────────────────────────────────
#
# RETIRED HERE (packet 1228). `test_confirm_gate_is_consent_flags_not_credential_presence` used to
# live at this spot and pinned literal source strings — `if ! $SILENT && ! $ASSUME_YES && …` and
# `if ($Silent -or $Yes) {`. The RULE it defended is real and unchanged: a present FMS admin password
# is not permission to proceed (packet 020).
#
# It is not being deleted because the rule stopped mattering, and it is NOT being rewritten to match
# the new spelling. `tests/test_script_conformance.py::test_credentials_do_not_gate_confirm` already
# enforces the same rule STRUCTURALLY on all four scripts — it slices the §6 section body and fails if
# a credential *variable* appears in it, whatever the surrounding code looks like. That is strictly
# stronger, and it survives exactly the kind of change that just happened here: 1228 replaced both
# pinned strings with a `cfm_confirm` / `Cfm-Confirm` call, which would have turned the pinned test
# red and invited someone to "update the string" — the failure mode CLAUDE.md names, where the guard
# stops enforcing and the breakage reads as a stale test.
#
# Do not reintroduce a spelling-pinned version of this test.
