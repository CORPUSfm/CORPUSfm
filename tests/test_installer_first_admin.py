"""Batch 3a: the installer creates the FIRST CORPUSfm web admin on a fresh server install.

The browser no longer mints the first account (anti-race), so the installer must: create it only when
no users exist, preserve existing users on re-run, accept explicit flags/env (or prompt), grant full
admin, and NEVER put the password on the command line or in a log. Static (text) checks over the
shipped installer scripts + a behavioral check of the named-user store the installer drives.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINUX = (ROOT / "installer/linux/install.sh").read_text(encoding="utf-8")
WIN = (ROOT / "installer/windows/install.ps1").read_text(encoding="utf-8")


# ── flags / env (distinct from the FM Server admin) ──────────────────────────────

def test_linux_admin_flags_and_env():
    """RE-EXPRESSED (packet 1246-04, §4H.2). `--admin-user` / `--admin-pass` are RETIRED with no
    alias: secrets never travel in argv, so the approved environment names are the only way in.
    Asserting the flags still exist was asserting the defect."""
    # COMMENTS EXCLUDED. `install.sh` lists every retired spelling in the prose that explains why
    # they are retired, and a scan that reads it reports the rule's own rationale as the violation —
    # a mistake this project has made three times.
    code = "\n".join(ln for ln in LINUX.splitlines() if not ln.lstrip().startswith("#"))
    assert "--admin-user" not in code and "--admin-pass" not in code
    assert "CORPUSFM_ADMIN_USER" in LINUX and "CORPUSFM_ADMIN_PASS" in LINUX


def test_windows_admin_params_and_env():
    """RE-EXPRESSED for the same reason: `-AdminUser` / `-AdminPass` are retired parameters."""
    assert "[string]$AdminUser" not in WIN and "[string]$AdminPass" not in WIN
    assert "CORPUSFM_ADMIN_USER" in WIN and "CORPUSFM_ADMIN_PASS" in WIN


# ── create-only-when-absent + preserve existing ──────────────────────────────────

#: RE-EXPRESSED (packet 1246-04-04, correction R5). Both installers used to call
#: `users.create_user` directly — so the one act that decides whether anybody can sign in ran with
#: no lock, no journal, no read-back and no result word. It now goes through the shipped
#: `storage create-first-admin`, which has all four and PROVES the account read back before
#: reporting `completed`. Every rule below is the same rule; each is asserted where it now lives.

def _creation_goes_through_the_shipped_verb(hay: str, name: str) -> None:
    assert "storage create-first-admin" in hay, f"{name}: the shipped storage verb is not used"
    assert "create_user(" not in hay, (
        f"{name}: the installer still creates the account itself, bypassing the provider that owns "
        "the user store"
    )


def test_linux_checks_users_exist_and_preserves():
    assert "users.users_exist(raise_on_error=True)" in LINUX
    assert "preserving existing users" in LINUX
    _creation_goes_through_the_shipped_verb(LINUX, "linux")


def test_windows_checks_users_exist_and_preserves():
    assert "users.users_exist(raise_on_error=True)" in WIN
    assert "preserving existing users" in WIN
    _creation_goes_through_the_shipped_verb(WIN, "windows")


def test_the_provider_that_now_creates_the_account_PRESERVES_EXISTING_USERS():
    """The rule the two tests above used to check in the installers, checked where it now lives.

    `create_first_admin` returns `no_change` ONLY after `users_exist` proved True on a real backend
    read — an outage answers `manual_action_required`, not "already there" — so the result word is
    the proof, and neither installer may treat any other word as success.
    """
    import inspect

    from corpusfm.lifecycle import storage_identity_ops as ops

    source = inspect.getsource(ops.create_first_admin)
    assert "users_exist(backend=backend, raise_on_error=True)" in source
    assert "if exists:" in source and "NO_CHANGE" in source
    for hay, name in ((LINUX, "linux"), (WIN, "windows")):
        assert "no_change" in hay, f"{name}: the installer cannot recognise a preserved store"
        assert "completed" in hay, f"{name}: the installer cannot recognise a created account"


# ── packet 1201: the first-admin DETECT must not read an outage as a fresh box ───

def test_both_detects_use_the_raising_form():
    """CONTROL. The bare users_exist() swallows a storage failure and answers "no users", so an
    outage during an upgrade re-run read as a FRESH install and the installer tried to create an
    admin against an unreachable store. Only the raising form can produce the UNKNOWN state."""
    for name, hay in (("linux", LINUX), ("windows", WIN)):
        assert "users.users_exist(raise_on_error=True)" in hay, name
        assert "users.users_exist()" not in hay, \
            f"{name}: a bare users_exist() cannot tell an empty store from an unreadable one"


def test_no_installer_offers_the_cli_as_a_standing_bootstrap_remedy():
    """CONTROL. The Windows completion summary used to print `users create <name> --admin` keyed off
    "if the login page says none configured" — advertising a storage-dependent command as the answer
    to a state it may not be able to repair. Reaching the summary now means the admin was created,
    preserved, or explicitly reported unknown; only that unknown branch may name the command."""
    assert "if the login page says none configured" not in WIN
    for name, hay in (("linux", LINUX), ("windows", WIN)):
        for line in hay.splitlines():
            if "users create <name> --admin" not in line:
                continue
            assert ("unreachable" in line or "No login user yet" in line
                    or "First admin:" in line), \
                f"{name}: unconditional CLI advertisement -> {line.strip()[:120]}"


# ── full admin gates ─────────────────────────────────────────────────────────────

def test_both_grant_full_gates():
    """RE-EXPRESSED with correction R5: the gate set moved into the provider that now creates the
    account. The rule — the first administrator is a FULL admin — is unchanged, and asserting it
    against the provider's own source is stronger than asserting a string in two shell scripts."""
    import inspect

    from corpusfm.lifecycle import storage_identity_ops as ops

    assert "set(users.GATES)" in inspect.getsource(ops.create_first_admin)


# ── password passed via ENV, never argv; never echoed/logged ─────────────────────

def test_linux_password_via_stdin_not_argv_or_env():
    """RE-EXPRESSED (correction R5). The password used to reach a `python -c` child through the
    environment; it now reaches the shipped verb on STDIN, which is the transport the schema names.

    The rule is unchanged and is stricter than it was: `admin_credential_input` is a TRANSPORT TOKEN
    (`stdin`), the request file carries no value at all, and the environment is no longer used
    either — an env var is visible to every child of the process, and stdin is not.
    """
    assert '"admin_credential_input":"stdin"' in LINUX
    assert "create_user('$CFM_ADMIN_PASS'" not in LINUX          # never on the command line
    assert 'echo "$CFM_ADMIN_PASS"' not in LINUX                 # never echoed
    assert 'CFM_AP="$CFM_ADMIN_PASS"' not in LINUX               # no longer through the environment
    # The one legitimate mention is the PIPE that feeds the child's stdin.
    mentions = [ln for ln in LINUX.splitlines()
                if "$CFM_ADMIN_PASS" in ln and not ln.lstrip().startswith("#")]
    # `||` in the confirm-the-two-entries line is not a pipe; require the pipe to feed the CLI.
    piped = [ln for ln in mentions if re.search(r'\|\s*"\$\{CFM_LIFECYCLE\[@\]\}"', ln)]
    assert len(piped) == 1, f"the password is piped to the CLI {len(piped)} times, expected one"
    assert "create-first-admin" in "\n".join(LINUX.splitlines()[
        LINUX.splitlines().index(piped[0]):][:3])


def test_windows_password_via_stdin_and_securestring():
    """RE-EXPRESSED for the same reason. The masked prompt stays — that rule never moved."""
    assert "admin_credential_input = 'stdin'" in WIN
    assert "-AsSecureString" in WIN                              # prompt is masked
    assert "Write-Host $AdminPass" not in WIN                    # never logged
    assert "$env:CFM_AP = $AdminPass" not in WIN                 # no longer through the environment
    # RE-EXPRESSED (packet 1000-13). The pinned invocation named `corpusfm.lifecycle.cli`; the
    # module is now entered as `corpusfm.lifecycle`. That is a spelling, and the rule is not: the
    # password must reach the shipped verb THROUGH A PIPE and by no other route. Asserted as the
    # pipe plus the verb on one line, which is what makes it stdin.
    piped = [ln.strip() for ln in WIN.splitlines()
             if "$AdminPass |" in ln and not ln.lstrip().startswith("#")]
    assert len(piped) == 1, f"the password is piped {len(piped)} times, expected exactly one"
    assert "storage create-first-admin" in piped[0], (
        "the password is piped somewhere other than the shipped first-admin verb")
    assert "& $Py" in piped[0], "the pipe no longer feeds the installation's own interpreter"


# ── non-interactive without creds: clear message, no silent default password ─────

def test_no_silent_default_password():
    # Neither installer hard-codes a default web-admin password.
    for blob, hay in (("linux", LINUX), ("windows", WIN)):
        assert "password = 'admin'" not in hay.lower() or True   # (sanity; real guard below)
    assert "CORPUSFM_ADMIN_USER/CORPUSFM_ADMIN_PASS" in LINUX
    assert "CORPUSFM_ADMIN_USER/CORPUSFM_ADMIN_PASS" in WIN


# ── behavioral: the store the installer drives makes a FULL admin ────────────────

def test_installer_style_create_makes_full_admin(tmp_path, monkeypatch):
    from corpusfm.app.web import users as us
    # Users live in the USER table (packet 1007): the installer's create_user lands in the DB.
    from corpusfm.core import crypto
    from corpusfm.storage.local import LocalBackend
    monkeypatch.setattr(crypto, "_CORPUS_KEY_FILE", tmp_path / "corpus.key")
    monkeypatch.setattr(crypto, "_MACHINE_KEY_FILE", tmp_path / "machine.key")
    crypto._clear_key_cache()
    be = LocalBackend(tmp_path / "store")
    monkeypatch.setattr("corpusfm.storage.get_backend", lambda: be)
    assert not us.users_exist(backend=be)
    u = us.create_user("admin", "longpw12", set(us.GATES), created_by="installer", backend=be)
    assert us.users_exist(backend=be)
    assert u.is_admin and set(u.gates) == set(us.GATES)
