"""Packet 1407 — the Windows bundled-Python health predicate never terminates the installer.

What must be true:
  - `Get-BundledPythonState` is a NON-THROWING predicate: a missing, partial or broken interpreter, ssl or
    pip reads as unhealthy instead of aborting the installer;
  - only its native probes run under a scoped non-terminating preference, each exit code is captured on
    the next line, and the caller's preference is restored in `finally`, on success and on failure;
  - the installer's global `Stop` is untouched, so failures OUTSIDE the predicate still terminate;
  - the post-bootstrap check goes through the same predicate (no second raw `pip --version`).

Windows PowerShell 5.1 turns a native command's stderr into a terminating NativeCommandError under `Stop`.
pwsh 7 does not, so these tests set `$PSNativeCommandUseErrorActionPreference = $true`, which makes a
non-zero native exit terminate under `Stop` — the closest pwsh-7 emulation. The decisive proof is the
real-PS-5.1 run recorded with packet 1407; these tests guard the shape and the contract on every suite run.

Two properties only real PS 5.1 can discriminate, and are proven there instead: the scoped 'Continue' keeps a
probe that writes to stderr but succeeds from reading as unhealthy (pwsh 7 never turns stderr into an error),
and the 'finally' restore — required, and asserted statically — cannot be observed by a caller, because an
assignment to $ErrorActionPreference inside a function is local to that function.
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PS1 = (ROOT / "installer/windows/install.ps1").read_text()


def _func(name: str) -> str:
    a = re.search(rf"function {re.escape(name)}\b[^\n]*\{{\n", PS1).start()
    return PS1[a:PS1.index("\n}\n", a) + 3]


PREDICATE = _func("Get-BundledPythonState")


# -- static: the shape of the contract -------------------------------------------------------------

def test_probes_run_under_a_scoped_preference_restored_in_finally():
    body = PREDICATE
    save = body.index("$eapProbe = $ErrorActionPreference")
    open_try = body.index("try {", save)
    relax = body.index("$ErrorActionPreference = 'Continue'", open_try)
    catch = body.index("} catch {", relax)
    final = body.index("} finally {", catch)
    assert body.index("$ErrorActionPreference = $eapProbe", final) > final
    assert body.count("$ErrorActionPreference = 'Continue'") == 1
    assert "$state.Ok = $false" in body[catch:final]


def test_every_native_probe_captures_its_exit_code_on_the_next_line():
    lines = [l.strip() for l in PREDICATE.splitlines() if l.strip()]
    probes = [i for i, l in enumerate(lines) if "& $Py" in l]
    assert len(probes) == 3, probes
    for i in probes:
        assert lines[i + 1] == "$rc = $LASTEXITCODE", lines[i:i + 2]


def test_the_global_stop_is_not_relaxed():
    # One global Stop; every top-level relaxation is the pre-existing save-then-relax pattern, never bare.
    top = [l for l in PS1.splitlines() if re.match(r"^\$\w+ = \$ErrorActionPreference; |^\$ErrorActionPreference = ", l)]
    assert top.count("$ErrorActionPreference = 'Stop'") == 1
    bare = [l for l in top if l.startswith("$ErrorActionPreference = 'Continue'")]
    assert bare == [], bare


def test_post_bootstrap_check_uses_the_safe_predicate():
    ensure = _func("Ensure-BundledPython")
    after = ensure[ensure.index('Cfm-Run "pip bootstrap"'):]
    assert "if (-not (Get-BundledPythonState).Ok) { Die " in after
    assert "pip --version" not in ensure
    assert PS1.count("-m pip --version") == 1, "the only pip probe lives inside the predicate"


# -- behavioral (pwsh, PS-5.1 emulation) ----------------------------------------------------------

pwsh = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(pwsh is None, reason="pwsh not available")

FAKE = r"""#!/bin/bash
D="$(dirname "$0")"; M=$(cat "$D/mode")
if [ "$M" = broken ]; then echo "Fatal Python error: init_fs_encoding" >&2; exit 1; fi
case "$1" in
  -c) case "$2" in
        *platform*) cat "$D/version";;
        *ssl*) [ "$M" = nossl ] && { echo "ModuleNotFoundError: No module named '_ssl'" >&2; exit 1; }; exit 0;;
      esac;;
  -m) [ "$M" = nopip ] && { echo "No module named pip" >&2; exit 1; }; echo "pip 26.2.1";;
esac
"""

HARNESS = r"""
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$script:PythonRuntimeVersion = '3.13.16'
$Py = $env:H_PY
if ($env:H_FORCE_THROW) { function Out-Null { throw 'injected failure inside the predicate' } }
if ($env:H_STALE_ZERO) { $global:LASTEXITCODE = 0 }
"""

TAIL = r"""
try { $s = Get-BundledPythonState; "RESULT ok=$($s.Ok) version=$($s.Version)" } catch { "THREW $($_.Exception.GetType().Name)" }
"EAP_AFTER=$ErrorActionPreference"
try { & sh -c 'echo outside >&2; exit 3' 2>$null; "OUTSIDE did-not-stop" } catch { "OUTSIDE stopped" }
"""


def _predicate(tmp_path, mode="healthy", version="3.13.16", *, executable=True, present=True,
               body=PREDICATE, env_extra=None):
    d = tmp_path / "python"
    d.mkdir(exist_ok=True)
    py = d / "python.exe"
    if present:
        # "Cannot start" is a missing shebang interpreter, never a non-executable file: pwsh on macOS hands a
        # non-executable path to /usr/bin/open, which launches whatever app owns `.exe` on the developer's Mac.
        py.write_text(FAKE if executable else FAKE.replace("#!/bin/bash", "#!/nonexistent/corpusfm-test-interpreter", 1))
        py.chmod(0o755)
        (d / "mode").write_text(mode)
        (d / "version").write_text(version)
    script = tmp_path / "h.ps1"
    script.write_text(HARNESS + body + TAIL)
    env = dict(os.environ, H_PY=str(py))
    env.update(env_extra or {})
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(script)], capture_output=True, text=True, env=env)
    return r.stdout


CASES = {
    "healthy": (dict(), "RESULT ok=True version=3.13.16"),
    "missing pip": (dict(mode="nopip"), "RESULT ok=False version=3.13.16"),
    "broken ssl import": (dict(mode="nossl"), "RESULT ok=False version=3.13.16"),
    "broken interpreter": (dict(mode="broken"), "RESULT ok=False version="),
    "older version": (dict(version="3.13.14"), "RESULT ok=False version=3.13.14"),
    "absent interpreter": (dict(present=False), "RESULT ok=False version="),
    "interpreter cannot start (stale LASTEXITCODE 0)": (dict(executable=False, env_extra={"H_STALE_ZERO": "1"}),
                                                        "RESULT ok=False version="),
}


@needs_pwsh
@pytest.mark.parametrize("case", sorted(CASES))
def test_predicate_reads_health_without_throwing_and_restores_the_callers_preference(tmp_path, case):
    kwargs, expected = CASES[case]
    out = _predicate(tmp_path, **kwargs)
    assert expected in out.splitlines(), out
    assert "EAP_AFTER=Stop" in out, out
    assert "OUTSIDE stopped" in out, "a failure outside the predicate must still terminate"


@needs_pwsh
def test_preference_is_restored_when_the_predicate_fails_internally(tmp_path):
    out = _predicate(tmp_path, env_extra={"H_FORCE_THROW": "1"})
    assert "RESULT ok=False version=3.13.16" in out, out
    assert "EAP_AFTER=Stop" in out and "OUTSIDE stopped" in out, out


# -- mutation controls: the detectors must fail when the contract is broken -----------------------

@needs_pwsh
def test_control_removing_the_scoped_error_handling_makes_missing_pip_terminate(tmp_path):
    # The scoped handling is the 'Continue' relaxation plus the catch. Remove both and the probes are the
    # raw shapes 0.3050 shipped: a missing pip terminates (the real-PS-5.1 failure of packet 1407).
    mutated = PREDICATE.replace("    $ErrorActionPreference = 'Continue'\n", "")
    mutated = re.sub(r"  \} catch \{\n    \$state\.Ok = \$false\n", "", mutated)
    assert mutated.count("Continue") == 0 and "catch" not in mutated
    out = _predicate(tmp_path, mode="nopip", body=mutated)
    assert "THREW" in out and "RESULT" not in out, out
    assert "RESULT ok=False" in _predicate(tmp_path, mode="nopip"), "the unmutated predicate must not throw"


@needs_pwsh
def test_control_removing_the_catch_lets_an_internal_failure_escape(tmp_path):
    mutated = re.sub(r"  \} catch \{\n    \$state\.Ok = \$false\n", "", PREDICATE)
    assert mutated != PREDICATE
    out = _predicate(tmp_path, env_extra={"H_FORCE_THROW": "1"}, body=mutated)
    assert "THREW" in out, out
