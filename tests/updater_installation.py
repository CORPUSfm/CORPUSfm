"""A REAL published installation for the updater tests, and the production rendering path.

Not a test module — a fixture library shared by the executed updater suites (packet 1246-03-03, F7).

**Why it exists.** Every executed updater test used to render the artifact with its own
`text.replace("@@X@@", value)` loop over a table it made up. That tests a string the test wrote: a
defect in the production renderer — a placeholder it forgot, quoting it got wrong, a containment
check it skipped — changed nothing about the artifact the test then executed, so the executed
evidence covered everything except the code that produces what ships.

So this builds a real locator record and a real manifest on disk and calls the platform's
PRODUCTION rendering entry point — `update_boundary.render_linux_updater()` /
`render_windows_updater()`, which take nothing at all, not even the template. What is executed
downstream is what the installer would install.

**The claim, stated precisely.** Every test that *exercises* an updater renders it through the
production path. There is exactly one test-owned renderer in the suite — the `defective()` one
inside `test_a_DEFECTIVE_PRODUCTION_RENDERER_changes_what_is_executed` — and it exists to prove that
dependency: it deliberately breaks the substitution and requires the executed run to change. Saying
"no test contains a renderer" would be false, and would describe the control as an exception rather
than as the evidence it is.

**Where the seam is, and where it is NOT.** The two rendering entry points, the authority resolver
and `updater_substitutions()` all take **nothing** — no template, no substitutions, no layout, no
locator, no path. Two earlier rounds narrowed this without closing it: first `layout=` / `locator=`
were kept "for tests" (a caller naming any schema-consistent manifest chose the install root), then
the public `render_updater(template, substitutions, ...)` survived them (a caller could skip the
derivation entirely and render from values it invented).

So a test redirects the **platform lookup** instead, in its own process: it patches
`lifecycle.layout.platform_layout` and `lifecycle.locator.locator_for`, which is what
`update_boundary` *and* `app_paths` both call. That changes what the operating system appears to
hold; it adds nothing a caller could pass. The locator is a double holding a REAL, schema-validated
`LocatorRecord` — publishing the file itself requires elevation a test does not have — and the
manifest it names is genuinely on disk and genuinely read back.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from application_checkout import APPLICATION_ROOT
from corpusfm.lifecycle import app_paths, layout as layout_mod, locator as locator_mod, os_layout
from corpusfm.lifecycle import tree_inspection as _ti
from corpusfm.lifecycle import update_boundary as _ub
from corpusfm.lifecycle.lock import LifecycleLock
from corpusfm.lifecycle.manifest import ManifestStore
from corpusfm.lifecycle.schema import InstallationManifest, LocatorRecord, PathsBlock

INSTALLER_REPO = Path(__file__).resolve().parent.parent
REPO = APPLICATION_ROOT
INSTALLATION_ID = "6f1f5f2e-1c2b-4a3d-9e77-8b0c1d2e3f40"

CANONICAL_ORIGIN = "https://github.com/CORPUSfm/CORPUSfm.git"


class RecordedLocator:
    """A locator adapter over a real record. Read-only by construction: no publish, no remove."""

    def __init__(self, record):
        # Round-tripped through the schema so this is the record the production reader would get,
        # not a hand-built object that merely has the right attribute names.
        self._record = LocatorRecord.from_dict(record.to_dict())

    def describe(self) -> str:
        return "a published test installation"

    def exists(self) -> bool:
        return True

    def read(self):
        return self._record


class AbsentLocator:
    """Absent, but it would answer PERFECTLY if anything asked.

    The obvious version raises from `read()`, and that hides the rule: a resolver that skipped the
    existence check entirely would still refuse, on the exception. Handing back a real record makes
    the existence check the only thing that can produce the refusal — so removing it is visible.
    """

    def __init__(self, record=None):
        self._record = record

    def describe(self) -> str:
        return "no test installation"

    def exists(self) -> bool:
        return False

    def read(self):
        if self._record is None:
            raise AssertionError("read() on an absent locator")
        return self._record


class UnreadableLocator:
    def __init__(self, error=None):
        self._error = error or OSError("the locator could not be read")

    def describe(self) -> str:
        return "an unreadable test installation"

    def exists(self) -> bool:
        return True

    def read(self):
        raise self._error


def publish(tmp_path: Path, *, relative_root: str = "opt/CORPUSfm"):
    """A real manifest on disk plus the locator record that names it. Returns everything needed.

    `relative_root` mirrors the stock `/opt/CORPUSfm` by default. A caller passes something else to
    prove a derivation reads the root it was given rather than a constant that happens to match it —
    the property correction E was made for, exercised here on the updater's own paths.
    """
    install_dir = tmp_path.joinpath(*relative_root.split("/"))
    install_dir.mkdir(parents=True, exist_ok=True)
    life = layout_mod.posix_layout(tmp_path)
    os_l = os_layout.posix_os_layout(tmp_path)
    for directory in os_l.all_dirs():
        directory.mkdir(parents=True, exist_ok=True)

    paths = PathsBlock(install_dir=str(install_dir), **os_l.as_paths_fields())
    manifest = InstallationManifest(
        installation_id=INSTALLATION_ID, paths=paths,
        created_utc="2026-08-03T00:00:00+00:00", updated_utc="2026-08-03T00:00:00+00:00",
    )
    lock = LifecycleLock(life)
    lock.acquire()
    try:
        ManifestStore(install_dir, layout=life).write(manifest, lock=lock, expected_generation=0)
    finally:
        lock.release()

    record = LocatorRecord(installation_id=INSTALLATION_ID, install_dir=str(install_dir))
    return life, RecordedLocator(record), install_dir, os_l


def install_administrator_files(install_dir: Path) -> None:
    """The administrator-owned entry points plus the library they load from.

    `lib/` is a symlink to the repository package: the point of the location is that it is OUTSIDE
    the checkout being judged, not that it is a physical copy, and a symlink keeps the test reading
    the code under test rather than a snapshot of it.
    """
    bin_dir = install_dir / _ub.HELPER_DIRNAME
    bin_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(REPO / "corpusfm" / "lifecycle" / "tree_inspection.py",
                bin_dir / _ub.HELPER_FILENAME)
    shutil.copy(REPO / "corpusfm" / "lifecycle" / "outcome_publisher.py",
                bin_dir / _ub.PUBLISHER_FILENAME)
    shutil.copy(REPO / "corpusfm" / "lifecycle" / "bytecode_cleanup.py",
                bin_dir / "bytecode_cleanup.py")
    lib = install_dir / _ub.LIBRARY_DIRNAME
    lib.mkdir(parents=True, exist_ok=True)
    link = lib / "corpusfm"
    if not link.exists():
        link.symlink_to(REPO / "corpusfm")
    # The rendered Windows updater names this fixed administrator-owned store in every Git
    # invocation. Its content is inert in the offline harness, but presence is a real precondition;
    # omitting it would make every Windows execution stop before the boundary under test.
    (install_dir / ".git-credentials").write_text(
        "https://x-access-token:test-fixture-only@github.com\n", encoding="utf-8"
    )


def install_interpreter(install_dir: Path, *, interpreter: str | None = None) -> Path:
    venv_python = Path(_ub._interpreter_path("posix", install_dir))
    venv_python.parent.mkdir(parents=True, exist_ok=True)
    if not venv_python.exists():
        venv_python.symlink_to(interpreter or sys.executable)
    return venv_python


def git(repo: Path, *args, check=True):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e"}
    result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


def checkout(install_dir: Path, *, origin: str = CANONICAL_ORIGIN) -> Path:
    src = install_dir / _ub.CHECKOUT_DIRNAME
    src.mkdir(parents=True, exist_ok=True)
    git(src, "init", "-q", "-b", "main")
    git(src, "config", "user.email", "t@example.com")
    git(src, "config", "user.name", "t")
    git(src, "remote", "add", "origin", origin)
    (src / "file.txt").write_text("hello\n")
    # Public product identity is declared independently of this intentionally short test history.
    (src / "release-build.txt").write_text("2564\n")
    git(src, "add", "-A")
    git(src, "commit", "-qm", "initial")
    return src


FAKE_GIT_TEMPLATE = """#!/bin/sh
# A deterministic stand-in for git, reachable ONLY through the rendered @@GIT@@ value. It is never
# on PATH and no environment variable names it, so nothing a request or an attacker controls can
# select it -- the test substitutes the production resolver in-process instead.
printf '%s\\n' "$*" >> "{calls}"
# The subcommand is whatever follows the fixed -c options the updater always passes.
sub=""
for a in "$@"; do
  case "$a" in
    -c|safe.directory=*|credential.helper=*|-C|/*) continue ;;
  esac
  sub="$a"; break
done
case "$sub" in
  remote) printf '%s\\n' "{origin}" ;;
  fetch)  exit {fetch_rc} ;;
  rev-parse)
      case "$*" in
        *origin/main*) printf '%s\\n' "{new_head}" ;;
        *) printf '%s\\n' "{old_head}" ;;
      esac ;;
  rev-list) printf '%s\\n' "42" ;;
  merge-base) exit {ancestor_rc} ;;
  diff) printf '%s\\n' "{changed}" ;;
  merge) exit 0 ;;
  *) exit 0 ;;
esac
"""


def fake_git(path: Path, *, calls: Path, old_head: str, new_head: str,
             origin: str = CANONICAL_ORIGIN, changed: str = "corpusfm/core/parser.py",
             ancestor_rc: int = 0, fetch_rc: int = 0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FAKE_GIT_TEMPLATE.format(calls=calls, origin=origin, old_head=old_head,
                                             new_head=new_head, changed=changed,
                                             ancestor_rc=ancestor_rc, fetch_rc=fetch_rc))
    path.chmod(0o755)
    return path


def use(life, locator, monkeypatch) -> None:
    """Make this process's PLATFORM lookup answer with the temporary installation.

    Patched on the modules `update_boundary` and `app_paths` both import from, so one redirection
    serves the whole resolution rather than each caller being handed an object. `app_paths` caches
    its answer per process, so the cache is cleared here and again at teardown — a resolved snapshot
    outliving the test that made it is the frozen-answer defect 03-01 exists to prevent.
    """
    monkeypatch.setattr(layout_mod, "platform_layout", lambda: life)
    monkeypatch.setattr(locator_mod, "locator_for", lambda lay=None, **kw: locator)
    # Setting `_cached` THROUGH monkeypatch is what makes the teardown safe: pytest restores the
    # value this process had before the test, so the temporary installation's snapshot cannot
    # outlive it.
    monkeypatch.setattr(app_paths, "_cached", None)


def substitutions(life, locator, monkeypatch, *, git_executable: Path | str | None = None) -> dict:
    """The PRODUCTION substitution builder. It takes no arguments; this only arranges the world.

    `tree_inspection.git_executable` is the single place a git binary is chosen. Pointing it at a
    temporary absolute executable is how an executed test gets deterministic git behaviour without
    adding any production argument, environment variable or request field that could select one.
    """
    use(life, locator, monkeypatch)
    if git_executable is not None:
        monkeypatch.setattr(_ti, "git_executable", lambda *a, **k: str(git_executable))
    return _ub.updater_substitutions()


class WindowsIsStaticNow(AssertionError):
    """Raised when a test asks this harness to render the Windows updater.

    Packet 1380-02 D-A removed the Windows renderer: the artifact is static and signed, and it derives
    its installation-specific values from the fixed HKLM locator instead.

    **This harness deliberately cannot produce a runnable Windows updater off a Windows box, and that
    refusal is the honest outcome rather than a gap to paper over.** Running one requires a
    published HKLM locator and manifest and the fixed `C:\\ProgramData\\CORPUSfm` layout.
    Supplying those from a fixture would mean giving the updater an injectable authority root - which
    is precisely the seam D-A exists to remove, reintroduced in the name of testing it.

    What replaces the executed coverage: the updater's *decision* is a pure function exercised with
    injected facts (offline, mutation-tested), and its *collection* - the registry and manifest
    reads - is Windows-only and belongs to the authorized private Windows gate.
    """


def render(artifact: str) -> str:
    """Render LINUX focused-installer template bytes through the application's production boundary.

    Repository separation moved the verified template into this repository while the application
    retained installation-specific derivation and substitution. The caller may supply bytes but no
    path, layout, locator, or substitution authority.
    """
    if artifact.endswith(".ps1"):
        raise WindowsIsStaticNow(
            f"{artifact} is installed byte-for-byte and derives its paths from the HKLM locator; "
            "there is nothing to render. Its decision logic is covered offline and its filesystem, "
            "registry and policy behaviour belongs to the Windows gate."
        )
    template = (INSTALLER_REPO / artifact).read_text(encoding="utf-8")
    return _ub.render_linux_updater(template)


def static_windows_updater() -> str:
    """The shipped Windows updater EXACTLY as it will be installed - a copy, never a render.

    The installer copies this file and proves the copy byte-identical, so a test that wants the
    installed bytes should read the same bytes rather than a transformation of them.
    """
    return (INSTALLER_REPO / "installer/windows/corpusfm-update.ps1").read_text(encoding="ascii")


def request(state_dir: Path, *, trigger_id: str = "trig-1", expected_head: str) -> Path:
    import json

    inbox = Path(state_dir) / _ub.INBOX_DIRNAME
    inbox.mkdir(parents=True, exist_ok=True)
    path = inbox / _ub.REQUEST_FILENAME
    path.write_text(json.dumps({"trigger_id": trigger_id, "expected_head": expected_head}))
    return path


def outcome(state_dir: Path):
    import json

    path = _ub.outcome_path(state_dir)
    return json.loads(path.read_text()) if path.exists() else None


def reset_paths():
    app_paths.reset_cache()


# ── N2 round 4: a child that shouts a unique secret on both streams ───────────────────

NOISY_GIT_TEMPLATE = """#!/bin/sh
# Every git phase emits the planted value on BOTH streams. stdout is contaminated only for the
# subcommands whose stdout the updater discards; the ones it parses answer correctly, or the run
# would fail for a reason that has nothing to do with what leaked.
printf '%s\\n' "{secret}" >&2
sub=""
for a in "$@"; do
  case "$a" in
    -c|safe.directory=*|credential.helper=*|-C|/*) continue ;;
  esac
  sub="$a"; break
done
case "$sub" in
  remote) printf '%s\\n' "{origin}" ;;
  fetch)  printf '%s\\n' "{secret}"; exit 0 ;;
  rev-parse)
      case "$*" in
        *origin/main*) printf '%s\\n' "{new_head}" ;;
        *) printf '%s\\n' "{old_head}" ;;
      esac ;;
  rev-list) printf '%s\\n' "42" ;;
  merge-base) printf '%s\\n' "{secret}"; exit 0 ;;
  diff) printf '%s\\n' "{changed}" ;;
  merge|reset) printf '%s\\n' "{secret}"; exit 0 ;;
  *) exit 0 ;;
esac
"""


def noisy_git(path: Path, *, secret: str, old_head: str, new_head: str,
              origin: str = CANONICAL_ORIGIN, changed: str = "corpusfm/core/parser.py") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(NOISY_GIT_TEMPLATE.format(secret=secret, origin=origin, old_head=old_head,
                                              new_head=new_head, changed=changed))
    path.chmod(0o755)
    return path


def noisy_interpreter(install_dir: Path, *, secret: str) -> Path:
    """Replace the installed venv interpreter with a wrapper that shouts on stderr, then execs.

    This is how the classifier, the import probe and the publisher all get a voice: they are the same
    binary. stdout is left clean because the updater PARSES the stdout of two of those children.
    """
    venv_python = Path(_ub._interpreter_path("posix", install_dir))
    venv_python.parent.mkdir(parents=True, exist_ok=True)
    if venv_python.exists() or venv_python.is_symlink():
        venv_python.unlink()
    # The import probe is STOOD IN FOR, not made to pass: `import corpusfm.app.web.app` resolves
    # installation paths at import time and refuses on any machine without a record, so no test
    # environment can satisfy it. What is under test here is the CONTAINMENT of its output, not its
    # verdict — so the wrapper answers that one invocation itself, noisily, and execs for the rest.
    venv_python.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' {secret!r} >&2\n"
        'case "$*" in\n'
        f"  *'import corpusfm.app.web.app'*) printf '%s\\n' {secret!r}; exit 0 ;;\n"
        "esac\n"
        f"exec {sys.executable!r} \"$@\"\n")
    venv_python.chmod(0o755)
    return venv_python


def noisy_helper(install_dir: Path, *, secret: str, clean: bool = True) -> Path:
    """The installed tree inspector, shouting on both streams. Its stdout is a parsed document, so
    the secret goes there too — deliberately, because that is the stream the updater keeps."""
    helper = _ub.helper_path(install_dir)
    helper.write_text(
        "import json, sys\n"
        f"print({secret!r}, file=sys.stderr)\n"
        f"print(json.dumps({{'ok': True, 'problems': [], 'noise': {secret!r}}}))\n"
        f"sys.exit({0 if clean else 1})\n")
    return helper


def everything_produced(*roots, extra=()):
    """Every byte this run could have left behind, for a planted-secret search."""
    found = list(extra)
    for root in roots:
        for path in Path(root).rglob("*"):
            if path.is_file():
                found.append((str(path), path.read_text(errors="replace")))
    return found
