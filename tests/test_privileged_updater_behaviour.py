"""The one-shot updaters' preconditions, EXECUTED (packet 1246-03).

The static tests beside this file assert what a script *says*. Two mutations proved that is not
enough: removing the untracked-content refusal left every asserted string in place and the guard
still passed, because a string is present whether or not the branch that uses it is reachable.

So these run the real scripts against a real temporary git repository and read the refusal from the
outcome record root writes. No elevation is needed — every path the tests reach refuses before the
first mutation.

**Rendered through PRODUCTION, not by this file (F7).** The fixtures publish a real manifest and go
through the platform's production rendering entry point. An earlier version applied
its own substitution table with `text.replace(...)`, which meant a defect in the renderer changed
nothing about the artifact these tests then executed — the executed evidence covered everything
except the code that produces what ships.

Requirements are declared rather than assumed: `git` and `bash` for the Linux artifact, and `pwsh`
for the two Windows runs, which skip where it is absent. **The Windows runs execute PowerShell on a
POSIX host** — they prove the artifact's own logic and process boundary, and nothing about Windows
service behaviour, which stays on a real box.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from tests import updater_installation as _ui

UPDATER = pathlib.Path(__file__).resolve().parent.parent / "installer" / "linux" / "corpusfm-update.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and shutil.which("bash")) or os.name == "nt",
    reason="needs git and bash on a POSIX host",
)

TIP_PLACEHOLDER = "0" * 40


def _git(repo, *args, check=True):
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A real published installation, rendered through the PRODUCTION renderer (F7).

    Every path here comes out of a manifest on disk by way of
    `update_boundary.updater_substitutions()` — there is no substitution table written by this test
    and no `.replace()` loop. A defect in the renderer therefore changes what these tests execute,
    which is the whole point: the previous fixture rendered its own copy and could not have noticed.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)

    values = _ui.substitutions(life, locator, monkeypatch)
    rendered = tmp_path / "corpusfm-update"
    rendered.write_text(_ui.render("installer/linux/corpusfm-update.sh"), encoding="utf-8")
    rendered.chmod(0o755)
    state = pathlib.Path(values["@@STATE_DIR@@"])
    return dict(script=rendered, src=src, state=state,
                logs=pathlib.Path(values["@@LOG_DIR@@"]), install=install_dir, values=values,
                life=life, locator=locator, monkeypatch=monkeypatch)


def _bind_fake_git(install, tmp_path, *, origin=None):
    """Re-render this installation with deterministic Git; no executed test may reach a network.

    The checkout stays real, so tests can still plant and inspect actual tree state. Only the Git
    executable named by the rendered privileged artifact is replaced.
    """
    head = _git(install["src"], "rev-parse", "HEAD").stdout.strip()
    fake = _ui.fake_git(
        tmp_path / "fake" / "git", calls=tmp_path / "git-calls.txt",
        old_head=head, new_head="b" * 40,
        origin=origin or _ui.CANONICAL_ORIGIN,
    )
    values = _ui.substitutions(
        install["life"], install["locator"], install["monkeypatch"], git_executable=fake,
    )
    install["script"].write_text(
        _ui.render("installer/linux/corpusfm-update.sh"), encoding="utf-8",
    )
    install["values"] = values
    return fake


def _request(install, **over):
    payload = {"trigger_id": "trig-1", "expected_head": TIP_PLACEHOLDER}
    payload.update(over)
    return _ui.request(install["state"], **payload)


def _run(install):
    subprocess.run(["bash", str(install["script"])], capture_output=True, text=True, timeout=120)
    path = install["state"] / "update-outcome" / "update_outcome.json"
    return json.loads(path.read_text()) if path.exists() else None


def test_a_planted_untracked_file_refuses(install):
    """The mutation that survived a string-matching test. This one executes the guard."""
    _request(install)
    (install["src"] / "corpusfm").mkdir(parents=True, exist_ok=True)
    (install["src"] / "corpusfm" / "evil.py").write_text("import os\n")
    outcome = _run(install)
    assert outcome is not None, "the updater wrote no outcome at all"
    assert outcome["reason_code"] == "unclean_tree", outcome
    assert "evil.py" in outcome["detail"]


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example/github.com/CORPUSfm/CORPUSfm.git",
        "https://github.com.evil.example/CORPUSfm/CORPUSfm",
        "https://github.com/someoneelse/CORPUSfm.git",
    ],
)
def test_a_hostile_origin_that_merely_contains_the_expected_name_refuses(install, origin):
    """The substring check accepted every one of these. They are different servers or different
    repositories, and the canonical comparison is what tells them apart."""
    _git(install["src"], "remote", "set-url", "origin", origin)
    _request(install)
    outcome = _run(install)
    assert outcome is not None
    assert outcome["reason_code"] == "origin_mismatch", outcome


@pytest.mark.parametrize(
    "origin",
    [
        "https://github.com/CORPUSfm/CORPUSfm.git",
        "https://github.com/CORPUSfm/CORPUSfm",
        "git@github.com:CORPUSfm/CORPUSfm.git",
    ],
)
def test_every_legitimate_spelling_of_the_origin_is_accepted(install, origin, tmp_path):
    """CONTROL. A canonicaliser that refused a real remote would break every box on the first
    upgrade, which is a worse failure than the one it prevents."""
    _git(install["src"], "remote", "set-url", "origin", origin)
    _bind_fake_git(install, tmp_path, origin=origin)
    _request(install)
    outcome = _run(install)
    assert outcome is not None
    assert outcome["reason_code"] != "origin_mismatch", outcome


def test_a_dirty_tree_refuses(install):
    _request(install)
    (install["src"] / "file.txt").write_text("modified\n")
    outcome = _run(install)
    assert outcome["reason_code"] == "unclean_tree", outcome


def test_an_abbreviated_consent_refuses(install):
    """Exact equality, executed rather than asserted about."""
    _request(install, expected_head=TIP_PLACEHOLDER[:12])
    outcome = _run(install)
    assert outcome["reason_code"] == "bad_expected_head", outcome


def test_a_ref_shaped_consent_refuses(install):
    _request(install, expected_head="origin/main")
    outcome = _run(install)
    assert outcome["reason_code"] == "bad_expected_head", outcome


def test_a_missing_request_refuses(install):
    # Packet 1380-02 / F-UPD-REPLAY: with neither a PENDING nor an ACTIVE request the updater does
    # NOTHING and writes NO outcome, so a stray or manual task activation cannot overwrite the last
    # real outcome or replay a stale request. (It used to write a `no_request` outcome every run.)
    outcome = _run(install)
    assert outcome is None, f"a missing request must leave no outcome, got {outcome}"


def test_the_outcome_record_is_world_readable_and_holds_no_secret(install):
    _request(install)
    _run(install)
    path = install["state"] / "update-outcome" / "update_outcome.json"
    import stat as _stat
    assert _stat.S_IMODE(path.stat().st_mode) & 0o044, "the service must be able to read it"

    from corpusfm.lifecycle.secret_guard import scan
    assert not scan(json.loads(path.read_text()))


@pytest.mark.parametrize(
    "planted",
    ["corpusfm/_build.txt.suffix", "archive/__init__.py", "logs/evil.py", "jobs/x.py",
     "history/__init__.py", "corpusfm/plugin.py"],
)
def test_the_allowlist_is_exact_and_does_not_cover_directories(install, planted):
    """R7. Prefix matching let `_build.txt.suffix` through, and a `.py` under archive/ or logs/
    turned a data directory into an importable package that could shadow a bare import."""
    _request(install)
    path = install["src"] / planted
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x = 1\n")
    outcome = _run(install)
    assert outcome["reason_code"] == "unclean_tree", outcome
    assert planted.split("/")[-1] in outcome["detail"]


def test_the_one_exact_allowed_file_still_passes(install):
    """CONTROL — the running app reads `_build.txt` as its version stamp."""
    _request(install)
    (install["src"] / "corpusfm").mkdir(parents=True, exist_ok=True)
    (install["src"] / "corpusfm" / "_build.txt").write_text("1589\n")
    outcome = _run(install)
    assert outcome["reason_code"] != "unclean_tree", outcome


@pytest.mark.parametrize("name", ["a file with spaces.py", 'quo"te.py'])
def test_a_quoted_porcelain_path_is_decoded_not_compared_quoted(install, name):
    """`-z`, specifically. Ordinary porcelain C-quotes these, so a substr() parse compares the
    QUOTED spelling — which fails closed here but is simply wrong parsing."""
    _request(install)
    (install["src"] / name).write_text("x = 1\n")
    outcome = _run(install)
    assert outcome["reason_code"] == "unclean_tree", outcome
    assert '\\"' not in outcome["detail"], "the path was reported in its quoted form"


def test_an_ignored_importable_file_is_caught(install):
    """`.gitignore` covers `archive/` and `__pycache__/`, so `--untracked-files=all` never saw them.

    An ignored importable file is the MOST interesting thing in a deployed checkout, not the least:
    it can shadow a bare import during the post-update probe and nothing else would notice.
    """
    _request(install)
    (install["src"] / ".gitignore").write_text("archive/\n")
    _git(install["src"], "add", ".gitignore")
    _git(install["src"], "commit", "-qm", "ignore archive")
    (install["src"] / "archive").mkdir()
    (install["src"] / "archive" / "__init__.py").write_text("x = 1\n")
    outcome = _run(install)
    assert outcome["reason_code"] == "unclean_tree", outcome
    # Git reports the ignored DIRECTORY rather than each file inside it, which is the honest signal:
    # an ignored tree in the deployed checkout is refused whatever it contains.
    assert "archive/" in outcome["detail"]


def test_a_directory_named_like_the_allowed_file_is_caught(install):
    """Exact equality is about the PATH, and a directory with that name holds arbitrary content."""
    _request(install)
    stamp_dir = install["src"] / "corpusfm" / "_build.txt"
    stamp_dir.mkdir(parents=True)
    (stamp_dir / "payload.py").write_text("x = 1\n")
    outcome = _run(install)
    assert outcome["reason_code"] == "unclean_tree", outcome


def test_a_non_utf8_filename_is_reported_safely(install):
    """Rejected, described by its escaped form, and the outcome stays valid JSON."""
    import os

    _request(install)
    try:
        os.close(os.open(os.path.join(bytes(install["src"]), b"bad\xff.py"),
                         os.O_CREAT | os.O_WRONLY, 0o644))
    except (OSError, ValueError):
        pytest.skip("this filesystem will not accept a non-UTF-8 name")
    outcome = _run(install)
    assert outcome is not None, "the outcome was unparseable JSON"
    assert outcome["reason_code"] == "unclean_tree", outcome


def test_a_carriage_return_in_a_name_keeps_the_outcome_parseable(install):
    _request(install)
    try:
        (install["src"] / "we\rird.py").write_text("x = 1\n")
    except OSError:
        pytest.skip("this filesystem will not accept a CR in a name")
    outcome = _run(install)
    assert outcome is not None, "a control character broke the outcome JSON"
    assert outcome["reason_code"] == "unclean_tree", outcome


def test_the_outcome_is_written_to_the_root_owned_directory(install):
    """R4: request and outcome have different authorities and different homes."""
    _request(install)
    _run(install)
    assert (install["state"] / "update-outcome" / "update_outcome.json").exists()
    assert not (install["state"] / "update_outcome.json").exists(), (
        "the outcome is still in the service-writable state directory"
    )


def test_the_environment_cannot_redirect_the_rendered_script(install, tmp_path):
    """Item 6, executed: the elevated script must ignore every CFM_* variable.

    The poisoned directory is deliberately NOT a git checkout, so the observable difference is
    decisive: if the script honoured `CFM_SRC_DIR` it would look there, find no `.git`, and refuse
    `not_git_deployment`. Getting past that means it used the rendered path. A weaker version of
    this test only checked that nothing was written into the attacker's directory — which stayed
    true even when the override WAS honoured, and a mutation duly survived it.
    """
    elsewhere = tmp_path / "attacker"
    elsewhere.mkdir()
    _request(install)
    env = {**os.environ, "CFM_SRC_DIR": str(elsewhere), "CFM_STATE_DIR": str(elsewhere),
           "CFM_INSTALL_DIR": str(elsewhere), "CFM_VENV_PY": "/bin/false",
           "CFM_LOG_DIR": str(elsewhere)}
    subprocess.run(["bash", str(install["script"])], capture_output=True, text=True,
                   timeout=120, env=env)

    path = install["state"] / "update-outcome" / "update_outcome.json"
    assert path.exists(), "the outcome went somewhere the environment chose"
    outcome = json.loads(path.read_text())
    assert outcome["reason_code"] != "not_git_deployment", (
        "the script looked for the checkout where the ENVIRONMENT pointed, not where it was rendered"
    )
    assert not list(elsewhere.iterdir()), "the script wrote into an attacker-named directory"


# ══════════════════════════════════════════════════════════════════════════════════════
# Packet 1246-03-03 — the environment the inspector runs in, where the helper comes from,
# and whether the rendered updaters agree with 03-01 about where anything is.
# ══════════════════════════════════════════════════════════════════════════════════════

import json as _json
import os as _os
import re as _re
import shutil as _shutil
import subprocess as _subprocess
from pathlib import Path as _Path

import pytest as _pytest

from corpusfm.lifecycle import layout as _layout_mod
from corpusfm.lifecycle import tree_inspection as _ti
from corpusfm.lifecycle import update_boundary as _ub


def _real_repo(tmp_path, *, name="src"):
    """A real git repository. No double: the whole question is what git actually reports."""
    repo = tmp_path / name
    repo.mkdir(parents=True)
    env = {**_os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
    _subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True, env=env)
    (repo / "kept.py").write_text("x = 1\n")
    _subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env)
    _subprocess.run(["git", "commit", "-qm", "one"], cwd=repo, check=True, env=env)
    return repo


# ── R7a: the environment cannot steer the inspection ──────────────────────────────────

@_pytest.mark.parametrize("var", ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"])
def test_an_attacker_controlled_GIT_VARIABLE_does_not_change_the_verdict(var, tmp_path, monkeypatch):
    """Each of these redirects which repository git reads or what it is compared against.

    The decoy is a REAL second repository with a real modification in it, so a leaked variable
    produces a genuinely different answer rather than an error that happens to look like a refusal.
    """
    clean = _real_repo(tmp_path, name="clean")
    decoy = _real_repo(tmp_path, name="decoy")
    (decoy / "kept.py").write_text("x = 2\n")           # decoy is dirty
    assert _ti.inspect(decoy), "the decoy must be dirty, or this proves nothing"

    monkeypatch.setenv(var, str(decoy / ".git") if var == "GIT_DIR" else str(decoy))
    assert _ti.inspect(clean) == [], f"{var} reached git and changed the verdict"


def test_an_attacker_controlled_PATH_cannot_choose_the_GIT_BINARY(tmp_path, monkeypatch):
    """A bare `git` is whatever PATH says, and PATH is settable by anything that can set an
    environment variable on the elevated process."""
    repo = _real_repo(tmp_path)
    fake_bin = tmp_path / "evil"
    fake_bin.mkdir()
    forged = fake_bin / "git"
    forged.write_text("#!/bin/sh\nprintf ''\nexit 0\n")   # would report every tree clean
    forged.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))
    (repo / "planted.py").write_text("import os\n")
    problems = _ti.inspect(repo)
    assert problems, "the forged git on PATH was used and reported the tree clean"
    assert any("planted.py" in p for p in problems)


def test_an_attacker_controlled_GIT_CONFIG_cannot_reach_the_inspection(tmp_path, monkeypatch):
    """`GIT_CONFIG_*` carries arbitrary config, including alias definitions that execute."""
    repo = _real_repo(tmp_path)
    hostile = tmp_path / "hostile.gitconfig"
    hostile.write_text("[status]\n\tshowUntrackedFiles = no\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(hostile))
    (repo / "planted.py").write_text("import os\n")
    problems = _ti.inspect(repo)
    assert any("planted.py" in p for p in problems), "hostile git config suppressed the finding"


def test_the_git_binary_is_ABSOLUTE_and_not_resolved_through_PATH(monkeypatch):
    chosen = _ti.git_executable()
    assert _Path(chosen).is_absolute()
    assert chosen in _ti.GIT_CANDIDATES


def test_WINDOWS_tree_inspection_derives_the_installed_MinGit_from_the_checkout(tmp_path, monkeypatch):
    install = tmp_path / "CORPUSfm"
    repo = install / "src"
    git = install.joinpath(*_ti.WINDOWS_GIT_RELATIVE)
    repo.mkdir(parents=True)
    git.parent.mkdir(parents=True)
    git.write_bytes(b"measured executable")
    monkeypatch.setattr(_ti, "_platform_name", lambda: "nt")
    monkeypatch.setenv("PATH", str(tmp_path / "hostile"))

    assert _Path(_ti._git_for_repo(repo)) == git


def test_WINDOWS_tree_inspection_refuses_when_its_installed_MinGit_is_absent(tmp_path, monkeypatch):
    repo = tmp_path / "CORPUSfm" / "src"
    repo.mkdir(parents=True)
    monkeypatch.setattr(_ti, "_platform_name", lambda: "nt")

    with _pytest.raises(_ti.GitUnavailable, match="refusing to resolve one through PATH"):
        _ti._git_for_repo(repo)


def test_WINDOWS_tree_inspection_pins_the_checkout_line_endings_when_system_config_is_absent(
        tmp_path, monkeypatch):
    install = tmp_path / "CORPUSfm"
    repo = install / "src"
    git = install.joinpath(*_ti.WINDOWS_GIT_RELATIVE)
    repo.mkdir(parents=True)
    git.parent.mkdir(parents=True)
    git.write_bytes(b"measured executable")
    seen = {}

    def capture(argv, **kwargs):
        seen["argv"] = argv
        return _subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(_ti, "_platform_name", lambda: "nt")
    monkeypatch.setattr(_subprocess, "run", capture)
    assert _ti._porcelain(repo) == []
    assert seen["argv"][1:3] == ["-c", "core.autocrlf=true"]
    assert _Path(seen["argv"][0]) == git


def test_the_INVOCATION_ITSELF_names_an_absolute_binary(tmp_path, monkeypatch):
    """The call site, not just the resolver.

    The forged-PATH test above cannot isolate this: the built environment already pins PATH, so a
    bare `git` would still find the real one and the verdict would be identical. What distinguishes
    the two rules is what is actually handed to `exec` — so that is what this captures.
    """
    seen = {}
    real = _subprocess.run

    def capture(cmd, **kw):
        seen["argv0"] = cmd[0]
        seen["env"] = kw.get("env")
        return real(cmd, **kw)

    monkeypatch.setattr(_subprocess, "run", capture)
    _ti.inspect(_real_repo(tmp_path))
    assert seen["argv0"] and _Path(seen["argv0"]).is_absolute(), (
        f"git was invoked as {seen['argv0']!r}, which PATH resolves"
    )
    assert seen["env"] is not None, "the invocation inherited the ambient environment"


def test_no_git_at_any_known_location_REFUSES_rather_than_falling_back_to_PATH():
    with _pytest.raises(_ti.GitUnavailable):
        _ti.git_executable(candidates=("/nonexistent/git",))


def test_the_built_environment_names_only_what_git_needs(tmp_path, monkeypatch):
    """Built, not filtered: a denylist means maintaining a list of every variable git has honoured.

    The config entries are asserted by VALUE, not merely by presence. A hostile `GIT_CONFIG_GLOBAL`
    cannot change *this* command's verdict — every option it might touch is pinned with an explicit
    `-c` or a command-line flag — so the verdict cannot be the guard. What can be checked is that
    the variable is pointed at nowhere, which is the property the pinning depends on.
    """
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/tmp/hostile.gitconfig")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/tmp/hostile.gitconfig")
    env = _ti.sanitised_environment(tmp_path)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["GIT_CONFIG_GLOBAL"] == _os.devnull
    assert env["GIT_CONFIG_SYSTEM"] == _os.devnull
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    for leaked in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "PYTHONPATH", "LD_PRELOAD"):
        assert leaked not in env


def test_a_clean_real_tree_is_still_clean(tmp_path):
    """CLEAN CONTROL for every refusal above."""
    assert _ti.inspect(_real_repo(tmp_path)) == []


# ── R7b: the helper comes from the installed location, never the checkout ─────────────

def test_the_helper_is_resolved_from_the_INSTALL_DIRECTORY_not_the_checkout(tmp_path):
    install = tmp_path / "opt" / "CORPUSfm"
    assert _ub.helper_path(install) == install / "bin" / "tree_inspection.py"


@_pytest.mark.parametrize("artifact", ["installer/linux/corpusfm-update.sh",
                                       "installer/windows/corpusfm-update.ps1"])
def test_neither_updater_LOADS_THE_HELPER_FROM_THE_TREE_IT_JUDGES(artifact):
    """Asserted on BOTH platforms: a provenance property proven on one says nothing about the other.

    The Windows half is an ARTIFACT-LEVEL check — PowerShell is not executed here, and actual
    Windows execution is deferred rather than implied.

    THE SHARED RULE is unchanged: the tree inspector is never loaded as a module from the checkout
    it is judging, and its location comes from installation authority rather than being improvised.
    WHERE that authority lives now differs by platform (packet 1380-02) — Linux still renders it in,
    Windows derives it from the fixed locator after that locator, its manifest and its own location agree —
    so the assertion follows the authority instead of pinning one platform's spelling onto both.
    """
    text = _Path(artifact).read_text()
    body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "-m corpusfm.lifecycle.tree_inspection" not in body, (
        "the helper is still loaded as a module from the checkout"
    )
    if artifact.endswith(".ps1"):
        assert "$Helper = $UpdaterLayout.Helper" in body, (
            "the helper location no longer comes from the locator-derived layout"
        )
        assert "@@HELPER@@" not in text, (
            "a rendered seam is back in an artifact that must be installed byte-for-byte"
        )
    else:
        assert "@@HELPER@@" in text, (
            "the helper location is not rendered from installation authority"
        )


@_pytest.mark.parametrize("removed", ["@@HELPER@@", "@@PUBLISHER@@"])
def test_the_linux_updater_REFUSES_when_an_INSTALLED_HELPER_is_missing(tmp_path, monkeypatch, removed):
    """Executed, not read. Missing authority must refuse rather than find another route — and that
    now covers the outcome publisher as well as the tree inspector, because both are places the
    elevated side would otherwise have to improvise."""
    rendered, logs = _render_linux(tmp_path, monkeypatch, remove=removed, want_log=True)
    result = _subprocess.run(["bash", str(rendered)], capture_output=True, text=True)
    assert result.returncode != 0
    # The refusal is in the LOG, not on a stream: this script has no stdout or stderr after the
    # structural silence boundary. An administrator reads the log and the outcome record.
    assert result.stdout == "" and result.stderr == ""
    assert "is missing" in (logs / "update.log").read_text()


def test_the_linux_updater_REFUSES_when_the_git_binary_is_missing(tmp_path, monkeypatch):
    missing = tmp_path / "no" / "such" / "git"
    rendered, logs = _render_linux(tmp_path, monkeypatch, git=missing, want_log=True)
    result = _subprocess.run(["bash", str(rendered)], capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stdout == "" and result.stderr == ""
    assert "not executable" in (logs / "update.log").read_text()


def _render_linux(tmp_path, monkeypatch, *, remove=None, git=None, want_log=False):
    """Render through production, then DELETE one installed file to prove the executed refusal.

    `remove` names a substitution key whose file is taken away after rendering. That is the honest
    shape of the question — the script is rendered from real authority, and the thing that is
    missing is missing on disk — where the previous version rendered a path that had never existed
    and therefore also proved nothing about what the installer produces.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    if remove:
        _Path(values[remove]).unlink()
    out = tmp_path / "corpusfm-update.sh"
    out.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    return (out, _Path(values["@@LOG_DIR@@"])) if want_log else out


# ── deliverable 3 / R4-Linux: the rendered paths ARE 03-01's paths ────────────────────

def test_every_rendered_updater_path_equals_what_the_resolver_answers(tmp_path, monkeypatch):
    """The path-agreement test. R4-Linux was a rendered `$INSTALL_DIR/.corpusfm` while the
    application resolved `/var/lib/corpusfm/state` — root and the service disagreeing about where
    the request and outcome live."""
    from corpusfm.lifecycle import app_paths

    life, locator, install, _os_l = _ui.publish(tmp_path)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable="/usr/bin/git")
    paths = app_paths.resolve()
    assert values["@@STATE_DIR@@"] == str(paths.state_dir)
    assert values["@@LOG_DIR@@"] == str(paths.log_dir)
    assert values["@@HELPER@@"] == str(_ub.helper_path(install))
    assert values["@@PUBLISHER@@"] == str(_ub.publisher_path(install))
    assert ".corpusfm" not in values["@@STATE_DIR@@"], "the install-time literal is back"


# ── N1: there is nothing left for a caller to supply ─────────────────────────────────

def test_NO_PUBLIC_CALLABLE_IN_THE_BOUNDARY_CAN_BE_HANDED_AUTHORITY():
    """The API-surface guard (N1, round 4). Not a list of two functions — a sweep of the module.

    Round 3 closed `layout=` / `locator=` on the resolver and left `render_updater(template,
    substitutions, ...)` public, so a caller could skip the derivation entirely and render a valid
    elevated artifact from values it invented. Closing one named seam while a second stands open is
    how this kept happening, so this asserts over EVERY public callable rather than the two the last
    fix touched.
    """
    import inspect as _inspect

    forbidden = {"template", "substitutions", "locator", "layout", "paths", "authority", "plan",
                 "install_dir", "src_dir", "venv_python", "git_executable", "manifest",
                 "helper", "publisher", "placeholders", "quoting"}
    allowed_path_helpers = {"helper_path", "publisher_path", "library_path"}
    # ONE renderer now (packet 1380-02 D-A): Linux still renders, Windows is static and signed.
    template_renderers = {"render_linux_updater"}
    # `classify(paths)` and `assert_code_only(paths)` take the CHANGED FILE NAMES out of a git diff.
    # They decide a verdict about an update; they never name a location the updater uses, so the
    # same word means something else here. Named individually rather than by dropping "paths" from
    # the forbidden set, which is the word that matters on the rendering surface.
    classification_inputs = {"classify", "assert_code_only"}
    offenders = {}
    for name, obj in vars(_ub).items():
        if name.startswith("_") or not callable(obj) or getattr(obj, "__module__", "") != _ub.__name__:
            continue
        if _inspect.isclass(obj):
            continue          # exception and record types; not an authority surface
        params = set(_inspect.signature(obj).parameters)
        if name in allowed_path_helpers or name in classification_inputs or name in template_renderers:
            continue
        bad = params & forbidden
        if bad:
            offenders[name] = sorted(bad)
    assert not offenders, f"public callables that can be handed authority: {offenders}"

    assert not hasattr(_ub, "render_updater"), (
        "the public renderer is back; it accepts a substitution table nothing derived"
    )
    for entry in (_ub.render_linux_updater,):
        assert set(_inspect.signature(entry).parameters) == {"template"}, (
            f"{entry.__name__} accepts more than the installer-owned template bytes"
        )


def test_the_AUTHORITY_AND_RENDERING_API_takes_nothing_at_all():
    """The structural half of N1, and the reason the containment checks below are not the guard.

    A check performed on a caller's own input is only ever as good as the caller. Two rounds of this
    packet narrowed the seam without closing it: first the four paths became one `ResolvedPaths` plus
    four checked arguments, then a `layout=` / `locator=` pair "for tests". The pair was still a
    production seam — a locator naming any schema-consistent manifest chose the install root, and
    every derived path with it. So both functions now take **nothing**, and this asserts exactly
    that rather than a shorter list of forbidden names.
    """
    import inspect as _inspect

    for fn in (_ub.updater_substitutions, _ub.resolve_updater_authority):
        params = _inspect.signature(fn).parameters
        assert not params, f"{fn.__name__} still accepts {sorted(params)}"

    # The three path helpers that remain public are PURE derivations — given an install directory
    # they return where a file would be. None resolves authority or renders anything, so naming one
    # an install directory buys a caller a string and no influence over any artifact.
    #
    # Checked on the PARSED BODY, not on the source text: these functions' own prose explains why
    # the helper location exists ("nothing to resolve"), and a scan that reads a docstring reports
    # the rationale as the violation — a mistake this project has made three times.
    import ast as _ast
    import textwrap as _textwrap

    for fn in (_ub.helper_path, _ub.publisher_path, _ub.library_path):
        assert list(_inspect.signature(fn).parameters) == ["install_dir"]
        tree = _ast.parse(_textwrap.dedent(_inspect.getsource(fn)))
        body = [n for n in tree.body[0].body
                if not (isinstance(n, _ast.Expr) and isinstance(n.value, _ast.Constant))]
        assert len(body) == 1 and isinstance(body[0], _ast.Return), (
            f"{fn.__name__} does more than compute and return a path"
        )
        called = {n.func.id for n in _ast.walk(body[0])
                  if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)}
        assert called <= {"Path"}, f"{fn.__name__} calls {called - {'Path'}}"


@_pytest.mark.parametrize("locator_kind", ["absent", "unreadable"])
def test_AUTHORITY_THAT_IS_MISSING_OR_UNREADABLE_refuses_before_rendering(tmp_path, monkeypatch,
                                                                          locator_kind):
    """An installation whose record cannot be read is not an unpublished one, and neither of them
    is a reason to render an elevated script against a guessed layout."""
    life, published, _install, _os_l = _ui.publish(tmp_path)
    # The absent locator would answer perfectly if anything asked it — see `AbsentLocator`. Without
    # that, the refusal could come from the read blowing up rather than from the existence check.
    locator = (_ui.AbsentLocator(published.read()) if locator_kind == "absent"
               else _ui.UnreadableLocator())
    _ui.use(life, locator, monkeypatch)
    with _pytest.raises(_ub.UpdaterAuthorityUnresolved):
        _ub.updater_substitutions()


def test_a_DEVELOPMENT_LAYOUT_is_not_an_installation_to_render_for(tmp_path, monkeypatch):
    """The development seam resolves paths for a developer's tree. Rendering a root-owned script
    that rewrites code against it would take a development directory as production authority."""
    from corpusfm.lifecycle import app_paths

    life, locator, _install, _os_l = _ui.publish(tmp_path)
    _ui.use(life, locator, monkeypatch)
    monkeypatch.setattr(app_paths, "resolve",
                        lambda *a, **kw: app_paths.development_layout(tmp_path / "dev"))
    with _pytest.raises(_ub.UpdaterAuthorityUnresolved, match="published"):
        _ub.updater_substitutions()


def test_a_CONTRADICTORY_RECORD_refuses(tmp_path, monkeypatch):
    """The locator and the manifest must agree about which installation this is. A locator pointing
    at another installation's manifest would otherwise render THAT installation's paths into THIS
    box's elevated updater."""
    from corpusfm.lifecycle.schema import LocatorRecord

    life, _locator, install, _os_l = _ui.publish(tmp_path)
    other = LocatorRecord(installation_id="11111111-2222-3333-4444-555555555555",
                          install_dir=str(install))
    _ui.use(life, _ui.RecordedLocator(other), monkeypatch)
    with _pytest.raises(_ub.UpdaterAuthorityUnresolved, match="contradictory"):
        _ub.updater_substitutions()


def test_NO_GIT_AT_A_KNOWN_LOCATION_refuses_rather_than_rendering_a_bare_name(tmp_path, monkeypatch):
    """`GIT=git` in a root script is PATH deciding which binary rewrites the box's code. The
    resolver refuses, and this proves the refusal is not swallowed into a rendered default."""
    life, locator, _install, _os_l = _ui.publish(tmp_path)
    _ui.use(life, locator, monkeypatch)

    def _unavailable(*a, **k):
        raise _ti.GitUnavailable("no git anywhere")

    monkeypatch.setattr(_ti, "git_executable", _unavailable)
    with _pytest.raises(_ub.UpdaterAuthorityUnresolved, match="PATH"):
        _ub.updater_substitutions()


def test_a_MANIFEST_INSTALL_DIR_THAT_ESCAPES_ITSELF_is_refused(tmp_path, monkeypatch):
    """Containment is CANONICAL: `..` is collapsed before anything is compared.

    `PurePath.relative_to` does not collapse, so an install directory spelled with `..` used to
    yield derived paths that compared as contained while landing somewhere else entirely. Exercised
    by pointing the derivation at such a directory and requiring the derived checkout to be judged
    on where it actually is.
    """
    install = tmp_path / "opt" / "CORPUSfm"
    escaped = install / ".." / ".." / "elsewhere" / "src"

    # The collapse itself: `..` is removed, so the comparison is made on where the path lands.
    assert str(_ub._collapsed("posix", str(escaped))) == str(tmp_path / "elsewhere" / "src")

    # And the CHECK refuses it. Driven directly because N1 means production cannot hand this in any
    # more — every path is derived from the install directory. That is the point of N1, and it is
    # also why the check has to be exercised at its own boundary: a guard nothing can currently
    # reach is exactly the guard that quietly stops working.
    with _pytest.raises(_ub.UpdaterPathsUnresolved, match="not inside"):
        _ub._assert_under(install, (escaped,), what="the install directory", flavour="posix")

    # CLEAN CONTROL — an ordinary derived path passes, so the refusal above is about containment
    # and not about the checker refusing everything.
    _ub._assert_under(install, (install / "src",), what="the install directory", flavour="posix")


@_pytest.mark.parametrize("artifact,placeholders", [
    ("installer/linux/corpusfm-update.sh", _ub.LINUX_PLACEHOLDERS),
])
def test_a_SURVIVING_PLACEHOLDER_is_refused_rather_than_shipped(artifact, placeholders):
    """`@@STATE_DIR@@/update-inbox` is a real directory name — an unsubstituted placeholder is a
    path the script would use literally."""
    template = _Path(artifact).read_text()
    # Driven through the PRIVATE plan-only helper: round 4 removed the public renderer, so there is
    # no supported way to hand it a substitution table any more — which is the point. What is still
    # worth proving is that the mechanical half looks at the RESULT rather than at whether it did
    # the work: a value that puts the placeholder back must be refused.
    values = {p: "/x" for p in placeholders}
    values[placeholders[0]] = placeholders[0]
    plan = _ub._UpdaterPlan(template=template, values=values,
                            placeholders=tuple(placeholders), quoting="none")
    with _pytest.raises(_ub.UpdaterPathsUnresolved, match="still contains"):
        _ub._substitute(plan)

    _ub._substitute(_ub._UpdaterPlan(template=template, values={p: "/x" for p in placeholders},
                                     placeholders=tuple(placeholders), quoting="none"))


def test_the_WINDOWS_UPDATER_CARRIES_NO_PLACEHOLDER_TO_SURVIVE():
    """The Windows half of the rule above, INVERTED by packet 1380-02 D-A rather than dropped.

    Linux still renders, so "a surviving placeholder is refused" is still its rule. The Windows
    updater is static and signed: its installed bytes must be the bytes that were signed, so it
    carries no seam at all and there is nothing left to survive. Asserting the absence is what stops
    a placeholder being reintroduced into an artifact nothing renders any more - which would ship a
    literal `@@STATE_DIR@@` as a path to a script running as SYSTEM.

    The pattern is the SEAM SHAPE, not a bare `@@`: prose may legitimately discuss the mechanism,
    and a guard a comment can trip is a guard that gets weakened rather than obeyed.
    """
    template = _Path("installer/windows/corpusfm-update.ps1").read_text()
    survivors = _re.findall(r"@@\w+@@", template)
    assert survivors == [], f"the static Windows updater carries rendered placeholders: {survivors}"
    assert not hasattr(_ub, "render_windows_updater"), (
        "a Windows renderer is back; a per-installation artifact cannot be signed"
    )
    assert not hasattr(_ub, "WINDOWS_PLACEHOLDERS"), (
        "an empty placeholder tuple would keep a renderer that silently returns an unchanged template"
    )


# ══════════════════════════════════════════════════════════════════════════════════════
# Review round 1 — the accepted findings.
# ══════════════════════════════════════════════════════════════════════════════════════

@_pytest.mark.parametrize("artifact,comparison", [
    ("installer/linux/corpusfm-update.sh", 'if [[ "$OBSERVED" != "$REQUESTED" ]]; then'),
    ("installer/windows/corpusfm-update.ps1",
     "if ($script:Observed -ne $script:Requested) {")])
def test_consent_is_compared_AFTER_every_other_eligibility_gate(artifact, comparison):
    """D5. `expected_head` is a consent precondition, not a selector — so it must be evaluated
    behind the gates, not in front of them. Both artifacts compared it immediately after resolving
    origin/main, ahead of the fast-forward and classification checks."""
    text = _Path(artifact).read_text()
    consent = text.index(comparison)
    assert text.index("not_fast_forward") < consent, "consent precedes the fast-forward gate"
    assert text.index("needs_installer") < consent, "consent precedes the classification gate"
    assert text.count(comparison) == 1, "consent has more than one operative comparison"
    # Every mention of the refusal REASON must sit inside that single comparison. This used to read
    # `text.count("target_changed") == 1`, which was a SPELLING proxy for the same rule and broke on a
    # legitimate change: packet 1373 added a branch INSIDE the one comparison so that the scheduled
    # all-zero observation exits 0 instead of leaving a permanently failed systemd unit. That added no
    # second consent decision -- the assertion above still holds -- it only named the reason more than
    # once. What must be true is that no consent verdict is reached BEFORE the gates, which is what
    # this now checks directly.
    first_reason = text.index("target_changed")
    assert first_reason > consent, "a consent verdict is reached before the single comparison"


def test_the_linux_environment_is_BUILT_not_filtered():
    """D2. Unsetting the variables one thinks of leaves the ones one does not — `HOME` reaches a
    ~/.gitconfig, `XDG_CONFIG_HOME` reaches the same file another way, `GIT_CONFIG_PARAMETERS`
    injects config directly."""
    text = _Path("installer/linux/corpusfm-update.sh").read_text()
    body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "compgen -e" in body, "the environment is filtered by a denylist, not cleared and built"
    for pinned in ("export HOME=", "export XDG_CONFIG_HOME=", "export GIT_CONFIG_GLOBAL=",
                   "export GIT_CONFIG_SYSTEM=", "export PATH=", "export IFS="):
        assert pinned in body, f"{pinned!r} is not pinned"


def test_the_windows_environment_is_BUILT_FROM_EMPTY_for_every_child():
    """F1. The Windows half used a DENYLIST — it removed a list of variables from its own process
    and let children inherit the rest, which left `PSModulePath`, `PYTHONUSERBASE`, `APPDATA` and
    every proxy variable in place. The structural fix is that no child inherits anything.

    Artifact-level, and paired with an EXECUTED proof below; this one is here because "there is no
    denylist left" is a property of the text, not of a run.
    """
    text = _Path("installer/windows/corpusfm-update.ps1").read_text()
    body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    assert "EnvironmentVariables.Clear()" in body, "the child environment is not cleared"
    assert "$psi.Arguments = Encode-WindowsCommandLine $Arguments" in body, (
        "the Windows PowerShell 5.1-compatible argv boundary is absent")
    assert "Remove-Item ('Env:" not in body and "Remove-Item (\"Env:" not in body, (
        "the denylist that removed named variables from this process is back"
    )
    # Nothing may write into the PARENT's environment either: a pinned `$env:X` is the shape that
    # made the denylist look sufficient, and with built child environments it has no reader.
    assert "$env:PATH =" not in body and "$env:PYTHONPATH =" not in body, (
        "a value is still being pinned into the parent process environment"
    )


def test_the_windows_launch_boundary_is_used_for_EVERY_child_process():
    """One boundary, or the exceptions are where the inheritance comes back.

    `&` is PowerShell's ordinary call operator and inherits the whole environment, so a single
    surviving `& $Git` or `& $Py` would quietly reintroduce exactly what F1 removed.
    """
    text = _Path("installer/windows/corpusfm-update.ps1").read_text()
    body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    for leaked in ("& $Git", "& $Py", "& $Helper", "& $Publisher"):
        assert leaked not in body, f"{leaked!r} bypasses the launch boundary and inherits everything"


def test_a_POWERSHELL_value_containing_an_apostrophe_is_escaped(tmp_path):
    """R6. The Windows artifact carries these values inside single-quoted literals: one `'` in an
    installation path ends the literal and the rest of the path becomes PowerShell."""
    template = "$Src = '@@SRC_DIR@@'\n"
    out = _ub._substitute(_ub._UpdaterPlan(
        template=template, values={"@@SRC_DIR@@": "C:\\O'Brien\\src"},
        placeholders=("@@SRC_DIR@@",), quoting="powershell"))
    assert out == "$Src = 'C:\\O''Brien\\src'\n"


def test_a_POWERSHELL_value_containing_a_LINE_BREAK_is_refused():
    """No quoting makes that safe, so it refuses rather than producing something plausible."""
    with _pytest.raises(_ub.UpdaterPathsUnresolved, match="line break"):
        _ub._substitute(_ub._UpdaterPlan(
            template="$Src = '@@SRC_DIR@@'", values={"@@SRC_DIR@@": "C:\\a\nWrite-Host evil"},
            placeholders=("@@SRC_DIR@@",), quoting="powershell"))


def test_the_default_quoting_leaves_a_posix_value_alone(tmp_path):
    """CLEAN CONTROL: the Linux artifact uses double quotes and must not gain doubled apostrophes."""
    out = _ub._substitute(_ub._UpdaterPlan(
        template="SRC=\"@@SRC_DIR@@\"", values={"@@SRC_DIR@@": "/opt/O'Brien"},
        placeholders=("@@SRC_DIR@@",), quoting="none"))
    assert out == "SRC=\"/opt/O'Brien\""


# The older-reachable-commit rule used to be tested HERE, with a stated limitation: the run never
# reached the consent comparison, because the origin check needs the canonical GitHub URL and there
# is no network in a test. It asserted only that HEAD did not move, and said so honestly.
#
# N3 removed the limitation rather than the rule. `test_an_OLDER_REACHABLE_COMMIT_refuses_and_never
# _reaches_GIT` below reaches the comparison, gets `target_changed` from the real script, keeps the
# HEAD assertion, and adds the property the weaker version could not reach: the authorized value is
# passed to no git invocation at all. The rule is stronger and in one place, so this one is gone.




# ══════════════════════════════════════════════════════════════════════════════════════
# Round 2 corrections — F7 (the executed artifact comes from the production renderer),
# N2 (the outcome is written through the structural secret fence), N3 (the consent gate,
# executed), F1 (the Windows child environment, executed under pwsh on a POSIX host).
# ══════════════════════════════════════════════════════════════════════════════════════

def test_a_DEFECTIVE_PRODUCTION_RENDERER_changes_what_is_executed(tmp_path, monkeypatch):
    """The poisoned control for F7 — and the one place a test-owned renderer legitimately appears.

    Every executed test in this file runs a rendered copy, so the claim "these tests exercise the
    shipped artifact" is only true if the RENDERER is in the loop. This control uses a deliberately
    defective test-owned renderer to prove exactly that dependency: with production substitution
    broken, the executed run must change. The old `.replace()` fixtures could not have shown it,
    because a renderer defect left their artifact untouched.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    _ui.checkout(install_dir)
    values = _ui.substitutions(life, locator, monkeypatch)
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="0" * 40)

    good = tmp_path / "good.sh"
    good.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    _subprocess.run(["bash", str(good)], capture_output=True, text=True, timeout=120)
    assert _ui.outcome(state) is not None, "CONTROL: the intact artifact must reach an outcome"

    _ub.outcome_path(state).unlink()

    def defective(plan):
        """One placeholder left behind — the exact class the real substitution exists to refuse."""
        rendered = plan.template
        for name, value in plan.values.items():
            if name != "@@GIT@@":
                rendered = rendered.replace(name, value)
        return rendered

    monkeypatch.setattr(_ub, "_substitute", defective)
    bad = tmp_path / "bad.sh"
    bad.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    result = _subprocess.run(["bash", str(bad)], capture_output=True, text=True, timeout=120)
    assert result.returncode != 0
    assert _ui.outcome(state) is None, (
        "the renderer defect changed nothing about the executed run — the executed artifact is not "
        "coming from the production renderer"
    )


# ── N2: the outcome record goes through the structural secret fence ───────────────────

def test_neither_shell_artifact_COMPOSES_an_outcome_record(tmp_path):
    """Both used to build the JSON themselves, so the record root writes was the one lifecycle
    record that never met `secret_guard`. Duplicating the patterns into bash and PowerShell would
    have been three fences that disagree; there is now one, in Python."""
    for artifact, marker in (("installer/linux/corpusfm-update.sh", "$PUBLISHER"),
                             ("installer/windows/corpusfm-update.ps1", "$Publisher")):
        text = _Path(artifact).read_text()
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        assert marker in body, f"{artifact} does not invoke the outcome publisher"
        assert '"privileged_classes"' not in body and 'privileged_classes =' not in body, (
            f"{artifact} still composes the outcome document itself"
        )
        assert "json_escape" not in body, f"{artifact} still hand-escapes JSON"


def test_a_SECRET_SHAPED_DETAIL_leaves_no_outcome_and_says_so_safely(tmp_path, monkeypatch):
    """Executed end to end: a planted filename that reads like a credential reaches `detail`, the
    fence refuses, and NOTHING is published — the honest outcome, because a record we cannot vouch
    for is worse than no record."""
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    values = _ui.substitutions(life, locator, monkeypatch)
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="0" * 40)
    (src / "CORPUSFM_MCP_TOKEN=8f3a91bd77c04e12.py").write_text("x = 1\n")

    script = tmp_path / "u.sh"
    script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)

    assert _ui.outcome(state) is None, "a secret-shaped detail was published anyway"
    log = (_Path(values["@@LOG_DIR@@"]) / "update.log").read_text()
    assert "NO OUTCOME PUBLISHED" in log, "the refusal was silent"
    assert "8f3a91bd77c04e12" not in log, "the refusal message leaked the value it refused"


def test_an_UNKNOWN_FIELD_NAME_is_refused_rather_than_dropped(tmp_path):
    """A secret-shaped FIELD NAME is the other half of the fence, and a parser that ignores what it
    does not recognise hands the fence a record the fence cannot fail."""
    from corpusfm.lifecycle import outcome_publisher as _op

    with _pytest.raises(_op.PublicationRefused, match="not a field"):
        _op.parse_fields(["operation_id=a", "trigger_id=b", "state=refused",
                          "api_key=sk-live-not-a-real-one"])


def test_the_publisher_LOADS_ITS_FENCE_FROM_THE_INSTALLED_LIBRARY_not_the_checkout(tmp_path):
    """R7b, one module over. The publisher validates the record that describes the tree being
    judged, so loading its validation out of that tree would be the same defect the tree inspector
    was corrected on."""
    from corpusfm.lifecycle import outcome_publisher as _op

    entry = tmp_path / "opt" / "CORPUSfm" / "bin" / "publish_outcome.py"
    assert _op.library_root(str(entry)) == tmp_path / "opt" / "CORPUSfm" / "lib"
    entry.parent.mkdir(parents=True)
    entry.write_text("x = 1\n")
    with _pytest.raises(_op.PublicationRefused, match="administrator-owned library"):
        _op.install_library_root(str(entry))


def test_a_VALID_OUTCOME_still_publishes_world_readable(tmp_path):
    """CLEAN CONTROL for the two refusals above."""
    from corpusfm.lifecycle import outcome_publisher as _op

    state = tmp_path / "state"
    (state / _ub.OUTCOME_DIRNAME).mkdir(parents=True)
    path = _op.publish(str(state), ["operation_id=op1", "trigger_id=t1", "state=completed",
                                    "detail=update applied", "rolled_back=false"])
    import stat as _stat
    assert _stat.S_IMODE(path.stat().st_mode) & 0o044
    assert _json.loads(path.read_text())["state"] == "completed"


# ── N3: the consent gate, EXECUTED ────────────────────────────────────────────────────

@_pytest.fixture
def consent_box(tmp_path, monkeypatch):
    """A rendered updater whose git is a deterministic fake reachable ONLY through the rendering.

    The real checkout stays real — the tree inspector runs against it with real git — so the only
    thing standing in is the network-shaped half no offline test can have. The fake is named by the
    rendered `@@GIT@@` value alone: it is not on PATH, no environment variable points at it, and no
    request field can select it. The substitution is `tree_inspection.git_executable`, patched in
    this test process; nothing shipped gained a selector.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    (src / "second.txt").write_text("two\n")
    _ui.git(src, "add", "-A")
    _ui.git(src, "commit", "-qm", "second")
    older = _ui.git(src, "rev-parse", "HEAD~1").stdout.strip()
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    (src / "corpusfm").mkdir()
    (src / "corpusfm" / "_build.txt").write_text("1\n")
    target = "b" * 40
    calls = tmp_path / "git-calls.txt"

    def build(**fake):
        fake.setdefault("new_head", target)
        git = _ui.fake_git(tmp_path / "fake" / "git", calls=calls, old_head=head, **fake)
        values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
        script = tmp_path / "u.sh"
        script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
        return script, _Path(values["@@STATE_DIR@@"])

    return dict(build=build, src=src, install=install_dir, older=older, head=head,
                target=target, calls=calls)


def test_the_EXACT_CURRENT_TIP_proceeds_past_the_consent_gate(consent_box):
    """The positive half. Everything before consent passes, consent matches, and execution
    continues into the apply phase — proven by a refusal that can only come from AFTER it."""
    script, state = consent_box["build"]()
    _ui.request(state, expected_head=consent_box["target"])
    _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)
    outcome = _ui.outcome(state)
    assert outcome is not None
    assert outcome["reason_code"] == "import_probe_failed", (
        f"execution did not get past consent: {outcome}"
    )


def test_an_OLDER_REACHABLE_COMMIT_refuses_and_never_reaches_GIT(consent_box):
    """A real, older, reachable full SHA. It refuses, HEAD does not move, and — the property that
    matters — it is passed to no git invocation at all: a selector would have to be."""
    script, state = consent_box["build"]()
    before = _ui.git(consent_box["src"], "rev-parse", "HEAD").stdout.strip()
    _ui.request(state, expected_head=consent_box["older"])
    _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)

    outcome = _ui.outcome(state)
    assert outcome is not None and outcome["reason_code"] == "target_changed", outcome
    assert outcome["detail"] == (
        f"origin/main is now {consent_box['target'][:12]}, but this update was authorized for "
        f"{consent_box['older'][:12]}. Check for updates again and authorize the current tip."
    ), outcome
    assert _ui.git(consent_box["src"], "rev-parse", "HEAD").stdout.strip() == before, (
        "the authorized older commit was checked out - expected_head selected rather than consented"
    )
    assert consent_box["older"] not in consent_box["calls"].read_text(), (
        "the authorized value was handed to git; it is a consent precondition, not a selector"
    )


# Every gate the artifact evaluates BEFORE the consent comparison, each paired independently with a
# wrong `expected_head`. A script that compared consent first would answer `target_changed` to all
# five; each must instead answer for itself. Round 2 extended this from two gates to five after the
# reviewer pointed out that origin, fetch and fast-forward were never executed in this pairing.
_PRE_CONSENT_GATES = [
    ("not_git_deployment", "the checkout is not a git deployment"),
    ("origin_mismatch", "the origin is not this repository"),
    ("fetch_failed", "origin/main could not be fetched"),
    ("head_unreadable", "a captured commit id is not a commit id"),
    ("not_fast_forward", "the resolved tip is not a descendant of HEAD"),
    ("unclean_tree", "the deployed checkout holds something it should not"),
    ("needs_installer", "the change needs the elevated installer"),
]


@_pytest.mark.parametrize("expected,_why", _PRE_CONSENT_GATES,
                          ids=[g for g, _ in _PRE_CONSENT_GATES])
def test_EVERY_PRE_CONSENT_GATE_answers_before_the_consent_comparison(consent_box, expected, _why):
    """Ordering, executed for each gate rather than asserted about the text.

    `expected_head` is deliberately wrong in every case — an older reachable commit, so it is a
    legitimate value and not a malformed one. Consent must therefore never be what answers.
    """
    fake = {}
    if expected == "origin_mismatch":
        fake["origin"] = "https://github.com/someoneelse/CORPUSfm.git"
    elif expected == "fetch_failed":
        fake["fetch_rc"] = 1
    elif expected == "head_unreadable":
        # A capture that is not a commit id. `rev-parse` printing something else means the child did
        # something other than what was asked, and it must not become a merge argument.
        fake["new_head"] = "not-a-commit"
    elif expected == "not_fast_forward":
        fake["ancestor_rc"] = 1
    elif expected == "needs_installer":
        fake["changed"] = "requirements.txt"

    script, state = consent_box["build"](**fake)
    if expected == "not_git_deployment":
        _shutil.rmtree(consent_box["src"] / ".git")
    elif expected == "unclean_tree":
        (consent_box["src"] / "planted.py").write_text("import os\n")

    _ui.request(state, expected_head=consent_box["older"])
    _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)
    outcome = _ui.outcome(state)
    assert outcome is not None, "the updater wrote no outcome at all"
    assert outcome["reason_code"] == expected, (
        f"consent short-circuited the {expected} gate: {outcome}"
    )


def test_the_pre_consent_gate_list_matches_what_the_ARTIFACT_names(consent_box):
    """The list above is only as good as its completeness, so it is checked against the script.

    Every `die refused|failed <code>` the artifact can reach before the consent comparison must
    appear in `_PRE_CONSENT_GATES`. A gate added later without a pairing fails here rather than
    quietly reducing what "every eligibility gate" means.
    """
    text = _Path("installer/linux/corpusfm-update.sh").read_text()
    before = text[:text.index("# CONSENT, EVALUATED LAST")]
    named = set(_re.findall(r"die (?:refused|failed) ([a-z_]+)", before))
    # The request-shape refusals are not pairable with a wrong expected_head: they reject the request
    # itself, and `bad_expected_head` IS the malformed-consent case, covered separately. `bad_request`
    # is the claim's malformed/unreadable-record refusal (packet 1380-02); `no_request` is now a plain
    # log+exit that writes no outcome, so it no longer appears in the `die` scan at all.
    request_shape = {"no_request", "bad_request", "bad_trigger_id", "bad_expected_head"}
    covered = {g for g, _ in _PRE_CONSENT_GATES} | request_shape
    assert named <= covered, f"the artifact refuses for gates nothing pairs with: {named - covered}"


# ── F1: the Windows child environment, EXECUTED ───────────────────────────────────────

_PWSH = shutil.which("pwsh")

#: WHY THESE ARE SKIPPED, AND WHAT REPLACES THEM (packet 1380-02 D-A).
#:
#: The Windows updater is static and signed, and it refuses before any child runs unless the fixed
#: HKLM locator, its agreeing manifest and its own location name one installation. Producing that on
#: this host would mean handing the updater an injectable authority root - precisely the seam D-A
#: exists to remove, reintroduced in order to test it.
#:
#: These runs were never acceptance evidence in the first place: pwsh 7 against a POSIX-shaped
#: fixture is supporting evidence, and Windows PowerShell 5.1, SYSTEM and AllSigned acceptance was
#: always owed to the authorized private Windows gate. What replaces the executed coverage offline is
#: `Get-CfmUpdaterRootVerdict`, a pure decision exercised with injected facts and mutation-tested.
_WINDOWS_GATE = _pytest.mark.skip(
    reason="needs a published Windows installation (HKLM locator, fixed "
           "ProgramData layout); Windows PowerShell 5.1 gate work, not a Mac result")

POISON = {
    # F1 round 2 — the two that decide where system32 is. They used to be READ and handed to both
    # children; they are now derived from the operating system and these values must reach nothing.
    "SystemRoot": "/attacker/tree",
    "windir": "/attacker/tree",
    "PSModulePath": "/attacker/modules",
    "PYTHONUSERBASE": "/attacker/site",
    "PYTHONPATH": "/attacker/py",
    "APPDATA": "/attacker/appdata",
    "GIT_DIR": "/attacker/repo/.git",
    "GIT_CONFIG_GLOBAL": "/attacker/gitconfig",
    "LD_PRELOAD": "/attacker/evil.so",
    "http_proxy": "http://attacker.example:8080",
}


@_WINDOWS_GATE
def test_NO_POISONED_AMBIENT_VARIABLE_REACHES_EITHER_WINDOWS_CHILD(tmp_path, monkeypatch):
    """F1, executed. PowerShell runs on a POSIX host here, so this proves the artifact's process
    boundary and nothing about Windows service behaviour — that remains 1246-10's, on a real box.

    What it does prove is the property the denylist could not: both children — git and the installed
    Python helper — start with an environment built from nothing, so a variable the parent was
    handed is simply absent rather than merely unnamed.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    _ui.checkout(install_dir)

    # The stand-in git dumps its environment through an ABSOLUTE interpreter shebang. A `/bin/sh`
    # script could not: the child's PATH is the Windows one the artifact builds, so `env` would not
    # be found and the dump would be silently empty — a test that passes by measuring nothing.
    git_env = tmp_path / "git-env.json"
    fake = tmp_path / "fake" / "git"
    fake.parent.mkdir(parents=True)
    fake.write_text(
        f"#!{sys.executable}\n"
        "import json, os\n"
        f"json.dump(dict(os.environ), open({str(git_env)!r}, 'w'))\n"
        f"print({_ui.CANONICAL_ORIGIN!r})\n"
    )
    fake.chmod(0o755)

    values = _ui.substitutions(life, locator, monkeypatch, git_executable=fake)
    # The INSTALLED helper location is where the second child comes from, so the dumper goes there:
    # substituting anything else would be testing a path production never uses.
    helper_env = tmp_path / "helper-env.json"
    _Path(values["@@HELPER@@"]).write_text(
        "import json, os, sys\n"
        f"json.dump(dict(os.environ), open({str(helper_env)!r}, 'w'))\n"
        "print(json.dumps({'ok': False, 'problems': ['stand-in helper']}))\n"
        "sys.exit(1)\n"
    )
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="c" * 40)

    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    result = _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                             capture_output=True, text=True, timeout=180,
                             env={**_os.environ, **POISON})

    assert git_env.exists(), f"git was never launched: {result.stdout}{result.stderr}"
    assert helper_env.exists(), f"the helper was never launched: {result.stdout}{result.stderr}"
    git_seen = _json.loads(git_env.read_text())
    helper_seen = _json.loads(helper_env.read_text())
    assert git_seen and helper_seen, "an empty dump proves nothing about what did not reach it"
    for name, value in POISON.items():
        for child, seen in (("git", git_seen), ("helper", helper_seen)):
            assert seen.get(name) != value, f"{name} reached the {child} child"
    # F1 round 2: the system directory is derived from the OS (GetSystemDirectory via
    # [Environment]::SystemDirectory), never from $env:SystemRoot. So the poison includes those two
    # variables, and the check is that the children were given the OS's answer and not the
    # attacker's — on this host the OS answers a POSIX path, which is exactly why it is compared
    # rather than pattern-matched against a Windows spelling.
    import subprocess as _sp

    os_system_dir = _sp.run(
        [_PWSH, "-NoProfile", "-Command", "[System.Environment]::SystemDirectory"],
        capture_output=True, text=True, env={**_os.environ, **POISON}).stdout.strip()
    assert os_system_dir, "the OS reported no system directory; this control proves nothing"
    for child, seen in (("git", git_seen), ("helper", helper_seen)):
        assert seen.get("PATH", "").startswith(os_system_dir), (
            f"the {child} child's PATH is not the OS-derived one: {seen.get('PATH')!r}"
        )
        assert POISON["SystemRoot"] not in seen.get("PATH", ""), f"{child} PATH carries the poison"
        assert seen.get("SystemRoot") != POISON["SystemRoot"]
        assert seen.get("windir") != POISON["windir"]
    assert "PYTHONPATH" not in helper_seen, "the helper child inherited PYTHONPATH"


@_WINDOWS_GATE
def test_the_WINDOWS_ARTIFACT_publishes_its_outcome_through_the_same_fence(tmp_path, monkeypatch):
    """CLEAN CONTROL for the run above, and N2 on the Windows side: the refusal it reaches is
    written by the installed Python publisher, not composed in PowerShell."""
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    # A hostile origin, so the refusal this reaches is decided by the artifact and not by whether
    # the machine running the test happens to have a network.
    _ui.checkout(install_dir, origin="https://github.com/someoneelse/CORPUSfm.git")
    values = _ui.substitutions(life, locator, monkeypatch,
                               git_executable=_ti.git_executable())
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="c" * 40)
    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                    capture_output=True, text=True, timeout=180)
    outcome = _ui.outcome(state)
    assert outcome is not None, "the Windows artifact published no outcome"
    assert outcome["reason_code"] == "origin_mismatch", outcome
    from corpusfm.lifecycle.secret_guard import scan
    assert not scan(outcome)


def test_a_RELATIVE_GIT_from_the_resolver_is_still_refused(tmp_path, monkeypatch):
    """The last line of the git rule, kept after N1 removed the caller.

    No caller supplies git any more, so the old "a relative `git_executable` argument is refused"
    test had no argument left to pass. The rule it defended is not gone: whatever the resolver
    answers is still checked, because `GIT=git` inside a root script is PATH deciding which binary
    rewrites the box's code. The resolver is the seam that can still produce one.
    """
    life, locator, _install, _os_l = _ui.publish(tmp_path)
    _ui.use(life, locator, monkeypatch)
    monkeypatch.setattr(_ti, "git_executable", lambda *a, **k: "git")
    with _pytest.raises(_ub.UpdaterPathsUnresolved, match="PATH"):
        _ub.updater_substitutions()


@_WINDOWS_GATE
def test_A_PLANTED_SECRET_REACHES_NO_WINDOWS_OUTPUT_LOG_OR_ARTIFACT(tmp_path, monkeypatch):
    """N2 round 2, executed on the Windows artifact with a unique planted value.

    The round-1 version of this control ran on Linux only, and passed — because Linux's `die()` has
    always logged the reason CODE. Windows logged `reason + " - " + detail`, so a credential-shaped
    filename inside an `unclean_tree` detail was written to `update.log` in full while the publisher
    correctly refused to record it. A fence proven on one platform said nothing about the other.

    The planted value is unique to this run, and EVERYTHING the run produced is searched: stdout,
    stderr, the log, the outcome directory, and every file under the state and log trees.
    """
    secret = "Zq7Z9c1f4Ab2De55Xk"
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    (src / f"CORPUSFM_MCP_TOKEN={secret}.py").write_text("x = 1\n")

    values = _ui.substitutions(life, locator, monkeypatch, git_executable=_ti.git_executable())
    state = _Path(values["@@STATE_DIR@@"])
    logs = _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head="c" * 40)
    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    result = _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                             capture_output=True, text=True, timeout=180)

    assert _ui.outcome(state) is None, "the outcome was published despite a secret-shaped detail"

    searched = [("stdout", result.stdout), ("stderr", result.stderr)]
    for root in (state, logs):
        for path in root.rglob("*"):
            if path.is_file():
                searched.append((str(path), path.read_text(errors="replace")))
    assert any(name.endswith("update.log") for name, _ in searched), (
        "no log was produced, so this control searched nothing that could have leaked"
    )
    leaked = [name for name, body in searched if secret in body]
    assert not leaked, f"the planted secret reached: {leaked}"

    # CLEAN CONTROL — the run did refuse for the right reason, so the absence above is not the
    # absence of a run.
    log = (logs / "update.log").read_text()
    assert "unclean_tree" in log, log


@_WINDOWS_GATE
def test_the_windows_updater_REFUSES_when_the_system_directory_is_unusable(tmp_path, monkeypatch):
    """F1's refusal half: no fallback when the OS cannot name its own system directory.

    FAULT INJECTION on the rendered COPY, not a test-owned renderer: the artifact is rendered through
    production and then the one OS lookup in it is replaced with a path that does not exist. This is
    the same shape as deleting an installed helper to prove the missing-helper refusal — the thing
    that is broken is broken on disk, and everything else is what ships.

    It has to be injected because the alternative is asking a working operating system to stop
    knowing where its system directory is, and a rule that can only be stated is a rule that quietly
    stops being true.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    git = _ui.fake_git(tmp_path / "fake" / "git", calls=tmp_path / "git-calls.txt",
                       old_head=head, new_head="b" * 40)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="c" * 40)

    rendered = _ui.render("installer/windows/corpusfm-update.ps1")
    assert "[System.Environment]::SystemDirectory" in rendered, (
        "the system directory is no longer taken from the OS; this injection targets nothing"
    )
    injured = rendered.replace("[System.Environment]::SystemDirectory",
                               "'/no/such/system/directory'")
    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(injured)
    result = _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                             capture_output=True, text=True, timeout=180)

    assert result.returncode != 0, "an unusable system directory did not refuse"
    # pwsh colours and hard-wraps `Write-Error`, inserting escape codes and `| ` continuations mid
    # sentence, so the raw text never contains the phrase contiguously. Normalise before matching —
    # otherwise this asserts something about terminal formatting rather than about the refusal.
    said = _re.sub(r"\x1b\[[0-9;]*m", "", result.stdout + result.stderr)
    said = _re.sub(r"\s*\|\s*", " ", said)
    said = _re.sub(r"\s+", " ", said)
    assert "system directory" in said, said
    assert _ui.outcome(state) is None, "it got far enough to publish an outcome"
    assert not (_Path(values["@@LOG_DIR@@"]) / "update.log").exists(), (
        "the refusal happened after the run had already started doing work"
    )


# ── N2 round 4: no raw child output crosses the boundary, on either platform ──────────

_PLANTED = "Rk8x2Vq7Ld4Nb9Tz3W"


def test_NO_RAW_CHILD_OUTPUT_FROM_ANY_LINUX_PHASE_SURVIVES(tmp_path, monkeypatch):
    """Every child phase shouts a unique value; nothing the run produced may contain it.

    Round 3 closed `Stop-With` on Windows and stopped there. The reviewer was right that the rest
    still leaked: `git fetch` stderr reached the journal unread, and merge, reset, the import probe
    and the service commands were piped straight into `update.log`. None of that passes a fence, and
    a fetch failure is precisely where a REMOTE gets to choose the text.

    The run is driven all the way past consent through the apply phase, so merge, the build stamp
    and the import probe all execute.

    RE-EXPRESSED for application packet 1361-01, round 3. It used to make the import probe SUCCEED
    only so the run would continue into the SERVICE phase, and then asserted `service_did_not_start`
    as proof it had got that far. There is no service phase: the scheduler service is retired and
    this script restarts nothing. The probe is still made to succeed — that is what carries the run
    through merge, the stamp and the probe, the noisiest children — and the completion outcome is
    what now proves the run reached the end rather than refusing early.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    src = _ui.checkout(install_dir)
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    target = "b" * 40

    _ui.noisy_interpreter(install_dir, secret=_PLANTED)
    _ui.noisy_helper(install_dir, secret=_PLANTED)
    # Make the import probe SUCCEED, so the run reaches the END of the apply phase rather than
    # refusing at `import_probe_failed` before merge, the stamp and the probe have all run.
    # Expose a complete application package to the import probe through the same single package
    # symlink this test used before build stamping became part of the updater transaction. The
    # private copy keeps the test from ever writing the application checkout's real stamp.
    runtime_package = tmp_path / "runtime-package"
    _shutil.copytree(_ui.REPO / "corpusfm", runtime_package)
    (runtime_package / "_build.txt").write_text("1\n")
    if (src / "corpusfm").exists():
        _shutil.rmtree(src / "corpusfm")
    (src / "corpusfm").symlink_to(runtime_package)
    git = _ui.noisy_git(tmp_path / "fake" / "git", secret=_PLANTED, old_head=head, new_head=target)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head=target)

    script = tmp_path / "u.sh"
    script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    result = _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=180)

    outcome = _ui.outcome(state)
    assert outcome is not None and outcome["reason_code"] == "ok", (
        f"the run did not reach the end of the apply phase, so the noisiest children never ran: "
        f"{outcome}"
    )
    searched = _ui.everything_produced(state, logs,
                                       extra=[("stdout", result.stdout), ("stderr", result.stderr)])
    assert any(n.endswith("update.log") for n, _ in searched), "no log was produced to search"
    leaked = [name for name, body in searched if _PLANTED in body]
    assert not leaked, f"raw child output survived in: {leaked}"

    # THE ELEVATED UPDATER WRITES NOTHING TO ITS OWN STREAMS. On an installed box those are the
    # journal, and this is what catches the classes a planted secret cannot reach: an unredirected
    # child of any kind makes the SHELL speak.
    assert result.stderr == "", f"the updater wrote to its own stderr: {result.stderr[:400]!r}"
    assert result.stdout == "", f"the updater wrote to its own stdout: {result.stdout[:400]!r}"


@_WINDOWS_GATE
def test_NO_RAW_CHILD_OUTPUT_FROM_ANY_WINDOWS_PHASE_SURVIVES(tmp_path, monkeypatch):
    """The same sweep on the Windows artifact, stopped one phase earlier — and said so.

    This drives the run to the CLASSIFICATION refusal, which is after git's
    remote/fetch/rev-parse/merge-base/diff and after the installed helper and the classifier, and
    before merge, the build stamp and the import probe. **Those last three are covered on Linux and
    not here**, which is a real limit of running the Windows artifact off Windows rather than
    something this test proves. (The reason used to be `Restart-Service`, which does not exist on a
    POSIX host; that call is gone with the retired scheduler service, but driving the PowerShell
    artifact through a real apply off Windows remains out of this test's reach.)
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    src = _ui.checkout(install_dir)
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    target = "b" * 40

    _ui.noisy_interpreter(install_dir, secret=_PLANTED)
    _ui.noisy_helper(install_dir, secret=_PLANTED)
    git = _ui.noisy_git(tmp_path / "fake" / "git", secret=_PLANTED, old_head=head, new_head=target,
                        changed="requirements.txt")
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head=target)

    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    result = _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                             capture_output=True, text=True, timeout=180)

    outcome = _ui.outcome(state)
    assert outcome is not None, f"no outcome: {result.stdout}{result.stderr}"
    assert outcome["reason_code"] == "needs_installer", outcome
    searched = _ui.everything_produced(state, logs,
                                       extra=[("stdout", result.stdout), ("stderr", result.stderr)])
    assert any(n.endswith("update.log") for n, _ in searched), "no log was produced to search"
    leaked = [name for name, body in searched if _PLANTED in body]
    assert not leaked, f"raw child output survived in: {leaked}"


@_pytest.mark.parametrize("artifact", [
    "linux",
    _pytest.param("windows", marks=_WINDOWS_GATE),
])
def test_a_SHOUTING_HELPER_still_yields_its_REAL_problem_list(tmp_path, monkeypatch, artifact):
    """The other half of "discard the helper's stderr": the document must still parse.

    Folding stderr into the helper's stdout does not leak — a contaminated document simply fails to
    parse, and the detail collapses to "could not be inspected". That is the actual harm, and it is
    worth its own control: a real refusal turns into a generic one, so an administrator loses the
    filename that would have told them what to remove.
    """
    if artifact == "windows" and not _PWSH:
        _pytest.skip("needs pwsh to execute the Windows artifact")
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    _ui.checkout(install_dir)
    head = _ui.git(install_dir / "src", "rev-parse", "HEAD").stdout.strip()

    # An UNCLEAN helper that also shouts: stdout is a valid problems document, stderr is noise.
    helper = _ub.helper_path(install_dir)
    helper.write_text(
        "import json, sys\n"
        f"print({_PLANTED!r}, file=sys.stderr)\n"
        "print(json.dumps({'ok': False, 'problems': ['untracked content: planted_marker.py']}))\n"
        "sys.exit(1)\n")
    git = _ui.noisy_git(tmp_path / "fake" / "git", secret=_PLANTED, old_head=head, new_head="b" * 40)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state = _Path(values["@@STATE_DIR@@"])
    _ui.request(state, expected_head="b" * 40)

    if artifact == "linux":
        script = tmp_path / "u.sh"
        script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
        _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)
    else:
        script = tmp_path / "u.ps1"
        script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
        _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                        capture_output=True, text=True, timeout=180)

    outcome = _ui.outcome(state)
    assert outcome is not None and outcome["reason_code"] == "unclean_tree", outcome
    assert "planted_marker.py" in outcome["detail"], (
        f"the helper's real problem list was lost to its own stderr: {outcome['detail']!r}"
    )
    assert _PLANTED not in outcome["detail"]


def test_A_REFUSED_PUBLICATION_LOGS_ITS_EXIT_STATUS_AND_NOT_ITS_CHILD_OUTPUT(tmp_path, monkeypatch):
    """The publisher is trusted, and "prefer not retaining it" still applies to it.

    Its own message is redacted, so the case that matters is the one where the INTERPRETER running
    it has something to say: with a shouting wrapper, logging the publisher's captured output logs
    whatever that wrapper wrote. Exit status is what an administrator can act on.
    """
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    src = _ui.checkout(install_dir)
    _ui.noisy_interpreter(install_dir, secret=_PLANTED)
    # A secret-shaped filename, so the publisher REFUSES and the failure branch is the one taken.
    (src / "CORPUSFM_MCP_TOKEN=4d2f9a7c15be03.py").write_text("x = 1\n")

    values = _ui.substitutions(life, locator, monkeypatch)
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head="0" * 40)
    script = tmp_path / "u.sh"
    script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=120)

    assert _ui.outcome(state) is None, "a secret-shaped detail was published anyway"
    log = (logs / "update.log").read_text()
    assert "NO OUTCOME PUBLISHED" in log, "the refusal was silent"
    assert _PLANTED not in log, "the publisher's child output was logged"
    assert "4d2f9a7c15be03" not in log, "the refused value itself was logged"


@_WINDOWS_GATE
def test_A_MALFORMED_REQUEST_REFUSES_WITHOUT_QUOTING_ITSELF_TO_THE_CONSOLE(tmp_path, monkeypatch):
    """The request inbox is SERVICE-writable, so parsing it is handling untrusted input.

    With `$ErrorActionPreference = 'Stop'`, a malformed document made `ConvertFrom-Json` raise a
    terminating error whose message quotes the offending content — the service choosing what appears
    in the console and therefore the journal. Caught now, and answered with a fixed reason code.
    """
    secret = "Jm4Q8pR2yX7hV1sN6c"
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    _ui.checkout(install_dir)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=_ti.git_executable())
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])

    inbox = state / _ub.INBOX_DIRNAME
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / _ub.REQUEST_FILENAME).write_text('{"trigger_id": "t1", "expected_head": ' + secret)

    script = tmp_path / "corpusfm-update.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    result = _subprocess.run([_PWSH, "-NoProfile", "-File", str(script)],
                             capture_output=True, text=True, timeout=180)

    outcome = _ui.outcome(state)
    assert outcome is not None and outcome["reason_code"] == "bad_request", (
        f"a malformed request did not refuse cleanly: {outcome} / {result.stdout}{result.stderr}"
    )
    # The request file itself is the INPUT this test wrote, not something the run produced, so it
    # is excluded by name — searching it would report the test's own plant as a leak.
    request_file = str(_ub.request_path(state))
    searched = [(n, b) for n, b in
                _ui.everything_produced(state, logs,
                                        extra=[("stdout", result.stdout),
                                               ("stderr", result.stderr)])
                if n != request_file]
    assert any(n.endswith("update.log") for n, _ in searched), "no log was produced to search"
    leaked = [name for name, body in searched if secret in body]
    assert not leaked, f"the malformed request quoted itself into: {leaked}"


# ── Structural silence: a poison that names no command ────────────────────────────────

def test_A_COMMAND_NO_TEST_NAMES_STILL_CANNOT_SPEAK(tmp_path, monkeypatch):
    """The control that does not depend on knowing what the script runs.

    Every earlier version of this poison substituted a binary the test had to name — git, the
    helper, the interpreter — which is how `sleep` survived four rounds: nobody had listed it. This
    one names nothing. A `DEBUG` trap installed through `BASH_ENV` fires before EVERY simple command
    the script executes, whatever it is and whether or not it exists yet, and each firing shouts a
    unique value on both streams.

    The trap is a shell function-level construct, so the script's own environment-clearing loop —
    which unsets VARIABLES — cannot remove it. If the structural boundary is in place the value
    disappears; if it is removed, thousands of copies land on the journal.
    """
    secret = "Vt9x3Kd7Qp2Lm6Rz8B"
    shim = tmp_path / "shim.sh"
    # It stays quiet for the first two firings and shouts on every one after. Those two are `set`
    # and the `exec` that ARMS the boundary — nothing can silence output emitted before the
    # statement that silences it, and that is a property of ordering, not an exemption for a
    # command. After them the trap names nothing and excludes nothing.
    shim.write_text(
        "_n=0\n"
        "trap '_n=$((_n+1)); [[ $_n -le 2 ]] || { "
        f'printf "%s\\n" {secret}; printf "%s\\n" {secret} >&2; }}\' DEBUG\n'
    )

    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    # THE DETERMINISTIC GIT, not the real one (packet 1000-13). With `@@GIT@@` bound to the real
    # binary this run reached `git fetch origin main` against the canonical GitHub URL — a network
    # round-trip inside an offline test, and a remote-controlled one at that. It "worked" only
    # because the fetch failed and `fetch_failed` is still an outcome, so the trap fired over a
    # SHORTER run than the one this test claims to cover.
    #
    # `fake_git` is the seam the consent tests already use: reachable only through the rendered
    # value, never on PATH, selectable by nothing a request or an attacker controls. With it the run
    # gets past origin, fetch, rev-parse, fast-forward and the tree inspection, refusing at consent
    # ("c" * 40 is not the fake tip) — strictly MORE commands under the trap, and no network.
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    git = _ui.fake_git(tmp_path / "fake" / "git", calls=tmp_path / "git-calls.txt",
                       old_head=head, new_head="b" * 40)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head="c" * 40)

    script = tmp_path / "u.sh"
    script.write_text(_ui.render("installer/linux/corpusfm-update.sh"))
    result = _subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=180,
                             env={**_os.environ, "BASH_ENV": str(shim)})

    assert _ui.outcome(state) is not None, "the run produced no outcome, so it proved nothing"
    searched = _ui.everything_produced(state, logs,
                                       extra=[("stdout", result.stdout), ("stderr", result.stderr)])
    leaked = [name for name, body in searched if secret in body]
    assert not leaked, f"a command no test names reached: {leaked}"
    assert result.stdout == "" and result.stderr == ""


@_WINDOWS_GATE
def test_THE_WINDOWS_BOUNDARY_SILENCES_WHAT_NO_TEST_NAMES(tmp_path, monkeypatch):
    """The Windows counterpart, and an HONEST statement of what it does and does not prove.

    `Out-Default` is what PowerShell hands every implicitly-emitted value to, so replacing it before
    the artifact runs would make any implicit output shout the planted value — without the test
    knowing which statement produced it. **It does not fire here, and that is recorded rather than
    hidden:** the body emits nothing implicitly, so this run proves the artifact is quiet, not that
    the boundary is what quietens it.

    **What proves the boundary on Windows is structural**, in
    `test_THE_WINDOWS_OPERATIONAL_BODY_IS_INSIDE_ONE_SILENCED_BOUNDARY`, and M321 is aimed there.
    Nothing on a POSIX host reliably drives PowerShell's own streams inside this artifact —
    `Set-PSDebug` trace goes to the host and ignores redirection, and the preference variables do not
    make these cmdlets speak. The Linux half IS proven by execution, by a trap that fires on every
    command; the asymmetry is a limit of running the Windows artifact off Windows.
    """
    secret = "Hq5w8Ny4Tc1Jf7Bs2D"
    life, locator, install_dir, _os_l = _ui.publish(tmp_path)
    _ui.install_administrator_files(install_dir)
    _ui.install_interpreter(install_dir)
    src = _ui.checkout(install_dir)
    head = _ui.git(src, "rev-parse", "HEAD").stdout.strip()
    git = _ui.fake_git(tmp_path / "fake" / "git", calls=tmp_path / "git-calls.txt",
                       old_head=head, new_head="b" * 40)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git)
    state, logs = _Path(values["@@STATE_DIR@@"]), _Path(values["@@LOG_DIR@@"])
    _ui.request(state, expected_head="c" * 40)

    script = tmp_path / "u.ps1"
    script.write_text(_ui.render("installer/windows/corpusfm-update.ps1"))
    poison = (
        "function Out-Default { "
        f"[Console]::Out.WriteLine('{secret}'); [Console]::Error.WriteLine('{secret}') }}; "
        f"& '{script}'"
    )
    result = _subprocess.run([_PWSH, "-NoProfile", "-Command", poison],
                             capture_output=True, text=True, timeout=180)

    assert _ui.outcome(state) is not None, f"no outcome: {result.stdout}{result.stderr}"
    searched = _ui.everything_produced(state, logs,
                                       extra=[("stdout", result.stdout), ("stderr", result.stderr)])
    leaked = [name for name, body in searched if secret in body]
    assert not leaked, f"output escaped the silenced boundary into: {leaked}"


# ── which interpreter the RENDERED artifact names (packet 1246-04-04, correction F) ────
#
# The unit vectors for the derivation live in `tests/test_update_boundary.py`. What is proven here
# is the end-to-end half on the platform that can be executed: a REAL published installation, the
# production `updater_substitutions()` / `render_linux_updater()`, and the value that reaches the
# script. Both roots are exercised, because a derivation only ever seen at the stock root cannot
# show that it reads the root it was given.
#
# There is no executed Windows counterpart and this does not claim one: a Windows-flavoured
# authority needs `D:\...` directories that genuinely exist, which no POSIX host can publish. The
# Windows evidence is the derivation vectors plus the mutation control next door.

@_pytest.mark.parametrize("relative_root", ["opt/CORPUSfm", "srv/apps/CORPUSfm"])
def test_the_RENDERED_LINUX_UPDATER_names_the_venv_under_ITS_OWN_install_dir(
        tmp_path, monkeypatch, relative_root):
    from corpusfm.lifecycle import service_identity as _si

    life, locator, install, _os_l = _ui.publish(tmp_path, relative_root=relative_root)
    _ui.install_administrator_files(install)
    git_bin = _ui.fake_git(tmp_path / "bin" / "git", calls=tmp_path / "calls",
                           old_head="a" * 40, new_head="b" * 40)
    values = _ui.substitutions(life, locator, monkeypatch, git_executable=git_bin)

    expected = str(install) + "/venv/bin/python"
    assert values["@@VENV_PY@@"] == expected
    # …and it is the same string the service definitions would use for this installation.
    assert values["@@VENV_PY@@"] == _si.interpreter_for("posix", str(install))
    # The root really did vary — otherwise both parameters prove one thing.
    assert str(install).endswith("/" + relative_root)

    rendered = _ui.render("installer/linux/corpusfm-update.sh")
    assert f'VENV_PY="{expected}"' in rendered
    assert "@@" not in rendered


# ══════════════════════════════════════════════════════════════════════════════════════
# Packet 1373 — a healthy observation must not leave a failed service state.
# ══════════════════════════════════════════════════════════════════════════════════════

def _run_status(install):
    """`(exit_status, outcome)` — the same run as `_run`, keeping the status it discards."""
    proc = subprocess.run(["bash", str(install["script"])],
                          capture_output=True, text=True, timeout=120)
    path = install["state"] / "update-outcome" / "update_outcome.json"
    return proc.returncode, (json.loads(path.read_text()) if path.exists() else None)


def test_the_scheduled_observation_refuses_but_does_not_EXIT_nonzero(install, tmp_path):
    """The web service refreshes this box's Git refs by running the updater with an ALL-ZERO consent
    value. Forty zeroes is not a Git object id, so the comparison can only refuse — that refusal IS
    the mechanism, and it runs every two hours on a perfectly healthy installation.

    Exiting 1 made systemd mark the `Type=oneshot` unit `failed` and KEEP it there, so every healthy
    Linux box permanently occupied `systemctl --failed` — the first place an administrator looks for
    a fault. Measured on u-test-private, packet 1373.

    THE REFUSAL ITSELF IS UNCHANGED, which is the half that matters: same `refused`, same
    `target_changed`, same detail. Only the exit status moves, and only for a value that cannot be a
    commit. The web service reads the outcome record and never the status, so what it sees is
    identical.
    """
    _bind_fake_git(install, tmp_path)
    _request(install, expected_head="0" * 40)
    status, outcome = _run_status(install)
    assert outcome is not None, "the updater wrote no outcome at all"
    assert outcome["state"] == "refused", outcome
    assert outcome["reason_code"] == "target_changed", outcome
    assert status == 0, "a healthy scheduled observation still exits nonzero"


def test_a_REAL_stale_consent_refusal_still_exits_nonzero(install, tmp_path):
    """CONTROL, and the one that keeps the fix honest.

    An administrator who authorized a commit that has since moved gets the same reason code — and
    must still be a nonzero exit, because something was actually asked for and refused. If this ever
    passed at 0, the packet would have turned genuine updater refusals into success, which is
    precisely what it was forbidden to do.
    """
    _bind_fake_git(install, tmp_path)
    _request(install, expected_head="a" * 40)
    status, outcome = _run_status(install)
    assert outcome is not None
    assert outcome["reason_code"] == "target_changed", outcome
    assert status != 0, "a real stale-consent refusal was turned into a success"


def test_an_ordinary_failure_is_untouched_by_the_observation_branch(install):
    """CONTROL for BREADTH. A refusal reached before the consent gate never sees the new branch and
    must keep exiting nonzero — the change must not have widened into 'refusals succeed'."""
    _request(install)
    (install["src"] / "corpusfm").mkdir(parents=True, exist_ok=True)
    (install["src"] / "corpusfm" / "evil.py").write_text("import os\n")
    status, outcome = _run_status(install)
    assert outcome is not None
    assert outcome["reason_code"] == "unclean_tree", outcome
    assert status != 0, "an unclean-tree refusal was turned into a success"
