"""Batch 1: installer FMS admin USERNAME handling.

Both installers must (a) accept a non-`admin` FMS admin username via an automation flag, (b) prompt
for it interactively, and (c) not let docs promote password-only
invocation as the universal form. These are static (text) checks over the shipped installer scripts
and docs — they don't execute the installers.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINUX = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
WIN = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
SPEC = (ROOT / "installer/SPEC.md").read_text(encoding="utf-8")


# ── Linux ─────────────────────────────────────────────────────────────────────

def test_linux_interactive_account_prompts_match_windows():
    assert 'read -rp "  FM Server admin account username: " FM_ADMIN_USER' in LINUX
    assert 'read -rsp "  FM Server admin account password: " FM_ADMIN_PASS' in LINUX
    assert 'while [[ -z "$FM_ADMIN_PASS" ]]' in LINUX
    assert 'FM_ADMIN_USER="${FM_ADMIN_USER:-admin}"' in LINUX


def test_linux_env_sources_username():
    assert 'FM_ADMIN_USER="${FM_ADMIN_USER:-}"' in LINUX


# ── Windows ─────────────────────────────────────────────────────────────────────

def test_windows_interactive_username_prompt_names_the_account_field():
    assert 'Read-Host "  FM Server admin account username:"' in WIN


def test_windows_env_sources_username_for_parity():
    assert "$env:FM_ADMIN_USER" in WIN


def test_windows_password_prompt_states_there_is_no_default_and_rejects_blank_input():
    assert 'Read-Host "  FM Server admin account password:"' in WIN
    assert "while ($sec.Length -eq 0)" in WIN
    assert 'password (" + $FmAdminUser + ")' not in WIN


# ── Docs do not promote password-only as universal ───────────────────────────────
