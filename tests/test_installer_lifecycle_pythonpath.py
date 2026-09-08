"""`CFM_LIFECYCLE` must carry PYTHONPATH — the defect that aborted both live installs.

`corpusfm` is not installed into the venv (no `pip install -e`, no `.pth`), so every invocation in
`installer/linux/install.sh` makes it importable with `PYTHONPATH="$INSTALL_DIR/src"`. That array was
the one exception, and the omission was invisible for a reason worth naming: `export PYTHONPATH` at
the CLI-wrapper heredoc LOOKS like a shell-level export and is a line of the *generated wrapper*.

Measured on `fms-server`, 2026-08-08: every lifecycle call ran a Python that could not import
`corpusfm`, so `status --json` produced no output and `composition foundation` refused — aborting an
upgrade AND a fresh install at the first lifecycle step.

**E3.** Real subprocesses against a real, deliberately package-empty venv.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import venv
from pathlib import Path

import pytest
from application_checkout import APPLICATION_ROOT

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "installer" / "linux" / "install.sh"
SOURCE = INSTALL_SH.read_text(encoding="utf-8")

EXPECTED = ('CFM_LIFECYCLE=(env "PYTHONPATH=$INSTALL_DIR/src" "$INSTALL_DIR/venv/bin/python" '
            "-m corpusfm.lifecycle)")


# ── the assignment itself ────────────────────────────────────────────────────────────

def test_EVERY_CFM_LIFECYCLE_assignment_carries_PYTHONPATH():
    assignments = [line.strip() for line in SOURCE.splitlines()
                   if line.strip().startswith("CFM_LIFECYCLE=(")]
    assert assignments, "the installer never binds the lifecycle CLI"
    for line in assignments:
        assert line == EXPECTED, f"assignment lacks PYTHONPATH: {line}"


def test_EVERY_invocation_uses_the_corrected_array():
    """No call may bypass the array by spelling the interpreter out again."""
    # `-m corpusfm.lifecycle.cli` is a SHELL invocation; `from corpusfm.lifecycle.cli import …` is a
    # Python import inside an embedded snippet, and those snippets carry their own PYTHONPATH prefix.
    # Flagging both would report three correct call sites as defects.
    offenders = []
    for number, line in enumerate(SOURCE.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#") or "-m corpusfm.lifecycle" not in stripped:
            continue
        if not stripped.startswith("CFM_LIFECYCLE=("):
            offenders.append(f"{number}: {stripped[:90]}")
    assert not offenders, f"the lifecycle CLI is invoked outside the array: {offenders}"

    uses = [n for n, line in enumerate(SOURCE.splitlines(), 1)
            if '"${CFM_LIFECYCLE[@]}"' in line]
    assert uses, "the array is never used"


def test_the_fix_FOLLOWS_a_non_default_install_dir():
    """`--install-dir` moves the tree, and the interpreter, the source and PYTHONPATH must move
    together. A literal path in any one of them would silently read another installation."""
    assignments = [l.strip() for l in SOURCE.splitlines() if l.strip().startswith("CFM_LIFECYCLE=(")]
    for line in assignments:
        assert line.count("$INSTALL_DIR") == 2, line
        assert "/opt/CORPUSfm" not in line, "a literal install path was hard-coded"
    assert re.search(r'--install-dir\)\s+INSTALL_DIR="\$2"', SOURCE), \
        "--install-dir no longer assigns INSTALL_DIR"


def test_the_package_is_NOT_INSTALLED_into_the_venv_and_is_BOUND_to_it():
    """The premise, re-expressed (packet 1246-10-04).

    It used to read *"no `pip install -e`, no `.pth`"*, and the first half is still the rule: an
    installed package is a copy the service could be pointed at, and an editable install writes a
    path the service may rewrite. The second half was too strong. The rendered unit's environment is
    a closed allowlist — no `PYTHONPATH`, deliberately — so `ExecStart=<venv>/bin/python -m
    corpusfm.app.web` had nothing to import from, and both services failed `ModuleNotFoundError`
    with canonical definitions (fms-server, 2026-08-08).

    So the venv is BOUND to the deployed tree by exactly ONE administrator-owned `.pth`: root-owned,
    service-readable, service-unwritable — a path the service may read and may not redirect. The
    installer's own invocations keep their explicit `PYTHONPATH`; nothing about that changed.

    Over EXECUTABLE lines only, because the correction's comment has to be able to name the thing it
    describes.
    """
    code = [l for l in SOURCE.splitlines() if not l.strip().startswith("#")]
    body = "\n".join(code)
    assert "pip install -e" not in body, "the package is being installed into the venv"

    binding = [l.strip() for l in code if "CFM_PTH" in l or ".pth" in l]
    assert binding, "the venv is no longer bound to the deployed source"
    assert any('CFM_PTH="$CFM_SITE_PACKAGES/corpusfm-source.pth"' in l for l in binding), binding
    written = [l for l in binding if "printf" in l]
    assert len(written) == 1, f"expected exactly one binding to be written: {written}"
    assert '"$INSTALL_DIR/src"' in written[0] and "'%s\\n'" in written[0], written[0]


def test_THE_BINDING_IS_ADMINISTRATOR_OWNED_and_service_unwritable():
    """A binding the service could rewrite is a path the service chooses — which is the authority
    the whole no-install-into-the-venv rule exists to withhold."""
    code = "\n".join(l for l in SOURCE.splitlines() if not l.strip().startswith("#"))
    assert 'chown root:"$SERVICE_USER" "$CFM_PTH"' in code
    assert 'chmod 0640 "$CFM_PTH"' in code


def test_SITE_PACKAGES_IS_ASKED_OF_THE_INTERPRETER_not_guessed():
    """A hard-coded `lib/python3.13/site-packages` is right until the interpreter moves."""
    code = "\n".join(l for l in SOURCE.splitlines() if not l.strip().startswith("#"))
    assert "sysconfig" in code and 'get_paths()["purelib"]' in code
    assert "lib/python3" not in code, "the version directory is guessed"


def test_THE_BINDING_IS_PROVEN_AS_THE_SERVICE_with_PYTHONPATH_unset():
    """The unit carries no PYTHONPATH and starts in install_dir; the proof must match both.

    The external payload is itself an importable checkout.  Running the probe from that checkout
    makes Python choose its current directory before the installed ``.pth`` and falsely rejects a
    correct binding.
    """
    code = "\n".join(l for l in SOURCE.splitlines() if not l.strip().startswith("#"))
    assert 'cd "$INSTALL_DIR" && sudo -u "$SERVICE_USER" -H env -u PYTHONPATH' in code
    assert '"$INSTALL_DIR/venv/bin/python" -c' in code
    assert 'import corpusfm; print(corpusfm.__file__)' in code
    assert '"$INSTALL_DIR/src/corpusfm/"*)' in code, "the resolved file is not fenced to the tree"
    binding_at = code.index("CFM_SITE_PACKAGES=")
    render_at = code.index("Rendering final service definitions")
    assert binding_at < render_at, "the binding is established after the services are rendered"


# ── real subprocesses against a package-empty venv ──────────────────────────────────

@pytest.fixture(scope="module")
def empty_venv(tmp_path_factory):
    """A venv with NO corpusfm in it — exactly the installed shape."""
    # `system_site_packages=True` reproduces the INSTALLED shape: third-party dependencies present
    # (the real venv installs them from requirements-server.txt), `corpusfm` absent. Verified: the
    # project interpreter cannot import corpusfm without PYTHONPATH either.
    root = tmp_path_factory.mktemp("install-dir")
    venv.create(root / "venv", with_pip=False, symlinks=True, system_site_packages=True)
    python = root / "venv" / "bin" / "python"
    assert python.exists()
    return {"root": root, "python": python, "src": APPLICATION_ROOT}


def test_the_lifecycle_CLI_imports_from_the_INSTALLED_SOURCE_TREE(empty_venv):
    proc = subprocess.run(
        ["env", f"PYTHONPATH={empty_venv['src']}", str(empty_venv["python"]),
         "-c", "import corpusfm.lifecycle.cli as m; print(m.__file__)"],
        capture_output=True, text=True, timeout=120, cwd="/")
    assert proc.returncode == 0, proc.stderr[-400:]
    assert "corpusfm/lifecycle/cli.py" in proc.stdout


def test_an_EXTERNAL_checkout_CWD_wins_over_the_pth_until_the_probe_steps_out(
    empty_venv, tmp_path
):
    """Executed premise for the live 1000-15 refusal, not a restatement of shell text."""
    installed = tmp_path / "installed"
    external = tmp_path / "external"
    (installed / "src" / "corpusfm").mkdir(parents=True)
    (external / "corpusfm").mkdir(parents=True)
    (installed / "src" / "corpusfm" / "__init__.py").write_text("ORIGIN='installed'\n")
    (external / "corpusfm" / "__init__.py").write_text("ORIGIN='external'\n")
    purelib = subprocess.check_output(
        [str(empty_venv["python"]), "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        text=True,
    ).strip()
    binding = Path(purelib) / "corpusfm-cwd-control.pth"
    binding.write_text(f"{installed / 'src'}\n", encoding="utf-8")
    try:
        probe = [str(empty_venv["python"]), "-c", "import corpusfm; print(corpusfm.ORIGIN)"]
        from_external = subprocess.run(probe, cwd=external, capture_output=True, text=True)
        from_installed_root = subprocess.run(probe, cwd=installed, capture_output=True, text=True)
    finally:
        binding.unlink()

    assert from_external.returncode == 0 and from_external.stdout.strip() == "external"
    assert from_installed_root.returncode == 0 and from_installed_root.stdout.strip() == "installed"


def test_status_json_emits_its_STRUCTURED_OBJECT(empty_venv):
    """What the installer actually consumes. Empty output is what the defect produced."""
    proc = subprocess.run(
        ["env", f"PYTHONPATH={empty_venv['src']}", str(empty_venv["python"]),
         "-m", "corpusfm.lifecycle", "status", "--json"],
        capture_output=True, text=True, timeout=180, cwd="/")
    assert proc.stdout.strip(), f"status --json produced NO OUTPUT (rc={proc.returncode})"
    payload = json.loads(proc.stdout)
    assert isinstance(payload, dict) and payload, payload
    # `journal` and `locator` are always present; `manifest` appears only once a locator is
    # readable, because `_status` returns early when there is none. Requiring it here would pin a
    # state this machine is not in rather than the structure the installer parses.
    assert "journal" in payload and "locator" in payload, sorted(payload)
    assert payload["locator"] in {"missing", "invalid", "present"}, payload["locator"]


def test_CONTROL_removing_PYTHONPATH_reproduces_ModuleNotFoundError(empty_venv):
    """The discriminating half — the exact failure measured on the box."""
    proc = subprocess.run(
        [str(empty_venv["python"]), "-m", "corpusfm.lifecycle", "status", "--json"],
        capture_output=True, text=True, timeout=120, cwd="/",
        env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode != 0
    assert "No module named 'corpusfm'" in (proc.stderr + proc.stdout), proc.stderr[-300:]
    assert not proc.stdout.strip(), "it produced output despite the import failure"


# ── the SECOND defect: the module must be the PACKAGE, not `cli` ─────────────────────

def test_the_invocation_targets_the_PACKAGE_not_the_cli_module():
    """`cli.py` has no `if __name__ == "__main__"` guard.

    `python -m corpusfm.lifecycle.cli` therefore imports it as `__main__`, calls nothing and exits 0
    with no output — which is precisely the *"`corpusfm-lifecycle status --json` produced no output
    (exit 0)"* the installer reported before aborting. The runnable entry point is the package, whose
    `__main__.py` calls `cli.main()`.
    """
    assert "-m corpusfm.lifecycle)" in EXPECTED
    assert "corpusfm.lifecycle.cli)" not in SOURCE, "the non-runnable module target is back"

    cli = (APPLICATION_ROOT / "corpusfm" / "lifecycle" / "cli.py").read_text(encoding="utf-8")
    assert '__name__ == "__main__"' not in cli, (
        "cli.py grew a main guard — if that is deliberate, this correction can be revisited, but "
        "the installer must not depend on it silently")
    main_py = (APPLICATION_ROOT / "corpusfm" / "lifecycle" / "__main__.py").read_text(encoding="utf-8")
    assert "from .cli import main" in main_py and "sys.exit(main())" in main_py


def test_CONTROL_the_cli_module_form_produces_NO_OUTPUT_and_exits_zero(empty_venv):
    """The discriminating half — the exact silent failure, reproduced.

    Fixing only PYTHONPATH would have turned a loud ImportError into this: a quieter failure, not a
    working install.
    """
    proc = subprocess.run(
        ["env", f"PYTHONPATH={empty_venv['src']}", str(empty_venv["python"]),
         "-m", "corpusfm.lifecycle.cli", "status", "--json"],
        capture_output=True, text=True, timeout=180, cwd="/")
    assert proc.returncode == 0, "it did not even exit 0 — the symptom has changed"
    assert not proc.stdout.strip(), "the cli-module form produced output; the premise has changed"


def test_the_PACKAGE_form_emits_the_same_object_the_installer_parses(empty_venv):
    proc = subprocess.run(
        ["env", f"PYTHONPATH={empty_venv['src']}", str(empty_venv["python"]),
         "-m", "corpusfm.lifecycle", "status", "--json"],
        capture_output=True, text=True, timeout=180, cwd="/")
    assert proc.returncode == 0, proc.stderr[-300:]
    payload = json.loads(proc.stdout)
    assert "locator" in payload and "journal" in payload, sorted(payload)


# ── the binding itself, against a real package-empty venv ───────────────────────────

def _write_binding(site_packages: Path, target: Path) -> Path:
    """The installer's own binding shape: one absolute path, one newline, one file."""
    pth = site_packages / "corpusfm-source.pth"
    pth.write_text(f"{target}\n", encoding="utf-8")
    return pth


def test_A_BARE_VENV_IMPORT_FAILS_BEFORE_THE_BINDING_AND_SUCCEEDS_AFTER(empty_venv):
    """The whole claim, as two real subprocesses with PYTHONPATH explicitly unset — which is the
    environment the rendered unit actually gives `ExecStart`."""
    python, root, src = empty_venv["python"], empty_venv["root"], empty_venv["src"]
    env = {"PATH": "/usr/bin:/bin"}

    before = subprocess.run([str(python), "-c", "import corpusfm"],
                            capture_output=True, text=True, env=env, timeout=60, cwd="/")
    assert before.returncode != 0 and "No module named 'corpusfm'" in before.stderr, before.stderr

    site = subprocess.run(
        [str(python), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
        capture_output=True, text=True, env=env, timeout=60, cwd="/")
    assert site.returncode == 0, site.stderr
    pth = _write_binding(Path(site.stdout.strip()), src)

    after = subprocess.run([str(python), "-c", "import corpusfm; print(corpusfm.__file__)"],
                           capture_output=True, text=True, env=env, timeout=60, cwd="/")
    assert after.returncode == 0, after.stderr
    assert after.stdout.strip().startswith(str(src)), after.stdout
    assert "PYTHONPATH" not in env
    pth.unlink()


def test_A_WRONG_SOURCE_PATH_IS_REFUSED(empty_venv, tmp_path):
    """The installer's fence, exercised: a binding that resolves outside the installed tree must not
    be accepted, or a run would start services against somebody else's checkout."""
    python, src = empty_venv["python"], empty_venv["src"]
    env = {"PATH": "/usr/bin:/bin"}

    sibling = tmp_path / "not-ours"
    (sibling / "corpusfm").mkdir(parents=True)
    (sibling / "corpusfm" / "__init__.py").write_text("", encoding="utf-8")

    site = subprocess.run(
        [str(python), "-c", 'import sysconfig; print(sysconfig.get_paths()["purelib"])'],
        capture_output=True, text=True, env=env, timeout=60, cwd="/")
    pth = _write_binding(Path(site.stdout.strip()), sibling)
    try:
        resolved = subprocess.run(
            [str(python), "-c", "import corpusfm; print(corpusfm.__file__)"],
            capture_output=True, text=True, env=env, timeout=60, cwd="/")
        assert resolved.returncode == 0, resolved.stderr
        # This is what the installer's `case` sees, and it must NOT match the installed tree.
        assert not resolved.stdout.strip().startswith(f"{src}/corpusfm/"), \
            "a sibling source was accepted as the installed tree"
    finally:
        pth.unlink()


def test_THE_CANONICAL_UNITS_REMAIN_FREE_OF_PYTHONPATH(tmp_path):
    """The unit's environment is a closed allowlist and stays one: the binding is in the venv, not
    in the service definition."""
    from corpusfm.lifecycle import os_layout, service_identity as si

    layout = os_layout.OsLayout(
        flavour="posix", config_dir=tmp_path / "etc", state_dir=tmp_path / "state",
        secrets_dir=tmp_path / "secrets", log_dir=tmp_path / "log", run_dir=tmp_path / "run")
    for role in si.SERVICE_ROLES:
        unit = si.render_systemd_unit(
            si.systemd_unit_spec(role, layout, install_dir=str(tmp_path / "opt"),
                                 description=f"CORPUSfm {role}"))
        assert "PYTHONPATH" not in unit, f"{role}: the unit carries PYTHONPATH"
        assert "HOME=" not in unit, f"{role}: the unit carries HOME"
