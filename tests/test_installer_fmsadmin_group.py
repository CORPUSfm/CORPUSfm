"""Targeted Linux fmsadmin-group preflight (inbox packet 001, Batch 2).

The install runs as root, and root drives `fmsadmin` WITHOUT fmsadmin-group membership (verified on
Ubuntu 22.04/FMS 2025), so installation never needs it. A NON-root user does need the group to run
fmsadmin admin commands. So the installer adds a TARGETED, NON-FATAL warning — never a blanket
root-in-fmsadmin requirement, never an auto group change. Static assertions on install.sh.
"""

from __future__ import annotations

import pathlib

_SH = (pathlib.Path(__file__).resolve().parent.parent / "installer/linux/install.sh").read_text()


def _fa_block() -> str:
    i = _SH.index("# fmsadmin group (NON-FATAL")
    return _SH[i: i + 2000]


def test_no_blanket_root_in_fmsadmin_requirement():
    blk = _fa_block()
    # the group note must never `die`/`exit` — it is informational only
    assert "die " not in blk and "exit 1" not in blk, "fmsadmin-group handling must not block the install"
    # and it must explicitly state root does not need it
    assert "runs as root" in blk.lower() or "runs as ROOT" in _SH[_SH.index("# fmsadmin group (NON-FATAL"):_SH.index("# fmsadmin group (NON-FATAL")+400]


def test_warning_is_targeted_to_the_invoking_non_root_user():
    blk = _fa_block()
    assert '"$_inv" != "root"' in blk, "must not warn when invoked directly as root"
    assert 'SUDO_USER' in blk, "the invoking operator is identified via SUDO_USER"
    assert "MANUALLY" in blk, "the warning must scope the need to MANUAL fmsadmin use"


def test_remediation_names_command_plus_relogin():
    blk = _fa_block()
    assert "usermod -aG fmsadmin" in blk, "must give the exact group-add command"
    assert ("log out/in" in blk or "re-login" in blk) and "reboot" in blk, "must note a new session/reboot is required"


def test_service_user_guidance_for_optional_fmsadmin_features():
    blk = _fa_block()
    assert "$SERVICE_USER" in blk
    assert "fms_local" in blk and "fallback" in blk, "service-user note must scope to fms_local / patch fallback"
    assert "systemctl restart" in blk, "service-user remediation must include a restart"


def test_installer_never_auto_adds_a_group():
    # usermod must appear ONLY inside warn/info guidance strings, never as an executed command line
    import re
    for line in _SH.splitlines():
        s = line.strip()
        assert not re.match(r"^(sudo\s+)?usermod\b", s), f"installer must not execute usermod: {line!r}"


def test_group_note_lives_in_detection_before_mutation():
    note = _SH.index("# fmsadmin group (NON-FATAL")
    detection = _SH.index('cfm_section "Detection"')
    progress = _SH.index('cfm_section "Progress"')
    assert detection < note < progress, "the fmsadmin-group note belongs in Detection, pre-mutation"
