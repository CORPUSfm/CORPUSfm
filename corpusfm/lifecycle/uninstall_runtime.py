"""The short-lived uninstall runtime (packet 1000-14).

**Why this exists.** The uninstall launcher runs the interpreter that ships beside it — on Windows
`<install_root>\\python\\python.exe` — and `install_root` is the last thing an uninstall removes.
Windows will not unlink a running image or remove a directory that is a live process's working
directory, so the executor's self-runtime guard refuses that removal, correctly and before touching
anything. Correct, and a dead end: every ordinary Windows uninstall would end in
`manual_action_required` with a human owed the last directory.

So this module makes the uninstall run from somewhere else. It copies the interpreter and the
product code this process is actually running — never a caller's idea of them — into a short-lived
directory outside the installation, **proves the copy by running it**, and hands back the executable
the launcher should use instead. Nothing else changes: the same CLI, the same request, the same
credential handling, the same one-JSON-object result.

**What it deliberately is not.** It plans no deletions and holds no target authority: it never reads
the pending record, never names a resource, and never learns what the uninstall will remove. It is
not a second deletion engine, not a scheduled task, and not a reboot-time deferral. The authority
that decides what may be deleted is unchanged and unweakened — and the self-runtime guard stays
exactly where it is, because a direct or malformed invocation that skips this module must still
refuse rather than strand a box.

**`destination` is verified, not trusted** (corrected after the first version of this module).
The launcher protects the directory it hands over, and the first version relied on that: it accepted
a pre-existing empty destination, re-permissioned it, filled it, and would recursively remove it on a
later refusal — three privileged acts on material this invocation did not create, resting entirely on
one caller having chosen the path well. **A privileged callee does not get to assume its caller.** So:
the leaf must NOT exist and is never adopted; the parent is judged as a protected directory before
the leaf is made, by the same `_stat_refusal` / `_windows_authority_refusal` policy every other
privileged input in this component is judged by; the leaf is created atomically and privately and its
authority read back; and every failure-path removal is aimed at the inode this call created, so a
path substituted underneath it is left alone.

**POSIX does not use it, and that is measured rather than assumed.** A POSIX unlink of a running
image succeeds and the process keeps its mapping, so the Linux launcher runs the installed
interpreter and removes it from under itself. `tests/test_uninstall_runtime.py` executes that
platform property rather than asserting it.

**The one cost, stated plainly.** The interpreter directory is copied whole — on the Windows
embeddable layout that includes `Lib\\site-packages`, so the copy is as large as the installed
dependency set. Copying only what the lifecycle CLI imports at start-up would be much smaller (it
reaches no third-party package at all), but the FileMaker Server, PKI and proxy operations import
lazily, and a runtime missing one of those imports fails AFTER the uninstall has begun mutating —
which is the failure this module exists to remove, reintroduced one layer down.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .errors import LifecycleError

#: The staged layout, relative to the destination. Two directories and no more: the interpreter as
#: it was installed, and the product package. Named here so the prober, the binder and the report
#: cannot drift apart.
STAGED_RUNTIME = "runtime"
STAGED_SOURCE = "source"

#: What the probe answers. A staged runtime is accepted only when it can be RUN and reports every one
#: of these from outside the installation.
PROBE = (
    "import json, os, sys\n"
    "import corpusfm\n"
    "print(json.dumps({'executable': sys.executable, 'cwd': os.getcwd(),\n"
    "                  'package': corpusfm.__file__,\n"
    "                  'path': [p for p in sys.path if p]}))\n"
)


class RuntimeStagingRefused(LifecycleError):
    """The runtime could not be staged. Nothing outside the destination was touched."""


def _runtime_root() -> Path:
    """The directory holding the interpreter running this process. A seam, so the staging can be
    driven against a layout a test controls — reading `sys.executable` directly would make this
    module exercisable only on the box it is meant to protect."""
    return Path(sys.executable).resolve().parent


def _package_root() -> Path:
    """The directory `import corpusfm` resolved from, for THIS process. The same seam, same reason."""
    import corpusfm

    return Path(corpusfm.__file__).resolve().parent


def source_root() -> Path:
    """The installation this process is running out of, derived from the process itself.

    **The common ancestor of the interpreter and the package, and nothing else.** There is no
    argument for it and no default: a caller that could name this could name any directory, and the
    externality proof below would then be a proof about the caller's opinion.
    """
    runtime, package = _runtime_root(), _package_root()
    try:
        return Path(os.path.commonpath([str(runtime), str(package)]))
    except ValueError as exc:                                             # different volumes
        raise RuntimeStagingRefused(
            f"the interpreter ({runtime}) and the product code ({package}) share no common "
            f"directory, so this process cannot say what installation it belongs to: {exc}") from exc


def _inside(child, parent) -> bool:
    child, parent = Path(str(child)).resolve(), Path(str(parent)).resolve()
    return child == parent or parent in child.parents


def _lstat_or_none(path):
    try:
        return os.lstat(str(path))
    except OSError:
        return None


def _identity_of(path) -> tuple:
    """`(st_dev, st_ino)` — what makes a later removal provably aimed at what WE created."""
    st = os.lstat(str(path))
    return (st.st_dev, st.st_ino)


# ── the destination's authority, judged by the POLICY THIS REPOSITORY ALREADY HAS ─────────────
#
# **A privileged callee does not trust the caller to have chosen and protected the path.** The
# launcher protects the directory it hands over, and that is worth doing — but this verb is reachable
# without the launcher, so the protection has to be VERIFIED here rather than assumed from one
# caller's good behaviour.
#
# The rule is not restated: `_stat_refusal` and `_windows_authority_refusal` are the same two
# functions every other privileged input in this component is judged by, and the Windows half reads
# through `protection.WindowsFileAuthorityApi`, which already answers about a DIRECTORY
# (`authority_of_path` — opening a directory as a descriptor is a POSIX idiom that fails on Windows).
# Nothing here is a second ACL implementation, and both are imported inside the functions because the
# CLI imports THIS module: two lazy imports, no cycle, and the policy stays where its own tests and
# mutation anchors already are.


def _authority_refusal(path: Path, *, what: str, authority_api=None) -> str | None:
    """`None` when `path` is a directory only the permitted elevated authorities can write."""
    from .cli import _stat_refusal, _windows_authority_refusal

    if os.name != "nt" and authority_api is None:
        # The descriptor, not the path: `O_NOFOLLOW` refuses to open a link at all and `O_DIRECTORY`
        # refuses anything that is not a directory, so what is judged is the object actually opened.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(str(path), flags)
        except OSError as exc:
            return f"{what} could not be opened as a plain directory: {exc.strerror}"
        try:
            return _stat_refusal(os.fstat(fd), what)
        finally:
            os.close(fd)
    api = authority_api
    if api is None:                                   # pragma: no cover - platform-specific
        from .protection import real_windows_file_authority

        api = real_windows_file_authority()
    st = _lstat_or_none(path)
    if st is None:
        return f"{what} is not there"
    if _is_reparse_or_link(st):
        return f"{what} is a link or reparse point, not a directory"
    try:
        authority = api.authority_of_path(str(path))
        system_sid = api.system_sid_text()
        owner_sids = tuple(api.invoking_owner_sids())
    except Exception as exc:                                              # noqa: BLE001
        # Fail CLOSED, exactly as the request check does: authority that cannot be read is not
        # authority.
        return f"{what}: its ownership and access could not be read ({type(exc).__name__})"
    return _windows_authority_refusal(authority, system_sid=system_sid, owner_sids=owner_sids,
                                      what=what)


def _is_reparse_or_link(st) -> bool:
    import stat as _stat

    if _stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0)
                & getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _protect_windows_leaf(path: Path, *, acl_api=None) -> None:
    """Replace inherited creation-time ACLs with the repository's canonical admin-only policy.

    ``os.mkdir(..., 0700)`` is not an ACL operation on Windows.  On the live box the new leaf
    inherited an OWNER RIGHTS (S-1-3-4) trustee and correctly failed its read-back.  Use the same
    pywin32 authority that protects the installed secrets: retain the invoking administrator who
    created the leaf as owner, and establish SYSTEM + Administrators full control with a protected
    DACL and nobody else. A supplied API is the executed cross-platform seam.
    """
    if os.name != "nt" and acl_api is None:
        return
    if acl_api is None:                                    # pragma: no cover - Windows only
        from .protection import real_windows_acl_api

        acl_api = real_windows_acl_api()
    from .protection import FILE_ALL_ACCESS

    system = acl_api.system_sid()
    administrators = acl_api.administrators_sid()
    acl_api.set_protected_dacl_preserve_owner(
        path, ((system, FILE_ALL_ACCESS), (administrators, FILE_ALL_ACCESS)))


def links_under(tree: Path) -> tuple:
    """Every link or reparse point under `tree`. **Empty is the proof.**

    A staged entry that is a link can resolve anywhere — including back into the installation, which
    the start-up probe would not notice because nothing imports it until later. With no links in the
    staged tree there is no such entry to follow, so this is checked rather than argued: `copytree`
    is told to follow links and copy their targets as ordinary material, and then the result is
    walked to prove it did.

    (A `.pth` file in the staged `site-packages` could also name a path back into the installation.
    That one IS visible at start-up — `site` processes it before the probe reports `sys.path`, and
    every existing entry on that path is judged against the installation.)
    """
    offenders = []
    for current, directories, files in os.walk(str(tree), followlinks=False):
        for name in list(directories) + list(files):
            entry = Path(current) / name
            st = _lstat_or_none(entry)
            if st is not None and _is_reparse_or_link(st):
                offenders.append(str(entry))
    return tuple(offenders)


def _import_path_file(runtime: Path):
    """The embeddable interpreter's `python*._pth`, if this layout has one.

    Its presence is what decides how the staged interpreter is bound to the staged package: an
    embeddable Python ignores `PYTHONPATH` while a `._pth` is present, so binding it any other way
    would be a binding that silently does nothing.
    """
    candidates = sorted(runtime.glob("python*._pth"))
    return candidates[0] if candidates else None


def rebound_import_path(text: str, *, original_source: Path, staged_source: Path) -> str:
    """The `._pth` body with every entry that resolved into the ORIGINAL source replaced.

    Pure, and separated from the file it will be written to, because the effect of a `._pth` is only
    observable on the interpreter that reads one — this is the half that can be checked anywhere.
    Entries are matched by where they RESOLVE, not by how they are spelled: the installer writes an
    absolute path there, and a relative entry means something different once the file has moved.
    """
    lines = []
    for line in text.splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#") and entry not in ("import site",):
            try:
                resolved = Path(entry)
            except (TypeError, ValueError):                               # pragma: no cover
                resolved = None
            if resolved is not None and resolved.is_absolute() and _inside(entry, original_source):
                lines.append(str(staged_source))
                continue
        lines.append(line)
    return "\n".join(lines) + "\n"


def _probe(executable: Path, *, cwd: Path, env: dict) -> dict:
    """RUN the staged interpreter and ask it where it is. The proof, rather than the intention.

    **`-s` and not `-I`, and the difference is the whole test.** `-I` implies `-E`, which discards
    the environment — including the `PYTHONPATH` that IS the binding on any layout without a `._pth`.
    A probe isolated that hard would refuse every non-embeddable runtime while reporting it as
    unbindable, which is a proof of the probe's own flags. `-s` drops the user site directory, the
    environment passed in is built here rather than inherited, and the interpreter-home variables are
    stripped, so what it reports is what the staged binding produces.
    """
    try:
        completed = subprocess.run(
            [str(executable), "-s", "-c", PROBE], capture_output=True, text=True,
            cwd=str(cwd), env=env, timeout=120, check=False)
    except OSError as exc:
        raise RuntimeStagingRefused(
            f"the staged interpreter {executable} could not be run: {exc}") from exc
    if completed.returncode != 0:
        raise RuntimeStagingRefused(
            f"the staged interpreter {executable} exited {completed.returncode} and could not "
            f"import the product code: {completed.stderr.strip()[:400]}")
    try:
        answer = json.loads(completed.stdout)
    except ValueError as exc:
        raise RuntimeStagingRefused(
            f"the staged interpreter {executable} did not report where it is: "
            f"{completed.stdout.strip()[:200]!r}") from exc
    if not isinstance(answer, dict):                                      # pragma: no cover
        raise RuntimeStagingRefused("the staged interpreter's report is not one object")
    return answer


def _verify_external(answer: dict, *, root: Path) -> tuple:
    """Every place the staged runtime reads from, judged against the installation it came from.

    The executable, the working directory, the package it imported, and every existing entry on its
    import path. **One of them inside the installation is the whole failure**: the removal would
    reach it, and the run would die somewhere after it had started deleting.
    """
    inside = []
    for label, value in (("executable", answer.get("executable")),
                         ("working directory", answer.get("cwd")),
                         ("product code", answer.get("package"))):
        if value and _inside(value, root):
            inside.append(f"{label} {value}")
    for entry in answer.get("path") or ():
        if entry and Path(entry).exists() and _inside(entry, root):
            inside.append(f"import path entry {entry}")
    return tuple(inside)


def stage(destination, *, authority_api=None, acl_api=None) -> dict:
    """Copy this process's runtime and product code to `destination`, prove it, and report it.

    The report is one flat object: `executable` is what a launcher runs instead of the installed
    interpreter, and `root` is the material to remove when the invocation ends.

    **`destination` is a leaf this invocation CREATES, never one it finds.** A pre-existing directory
    is refused whether or not it is empty, and is not adopted, re-permissioned, populated or removed
    — an empty directory somebody else made is still somebody else's, and this verb runs privileged.
    The parent is verified as a protected directory before the leaf is created, and the leaf's own
    authority is read back after; every refusal from the creation onward removes exactly the leaf
    this call made, identified by the inode it got when it was made.
    """
    destination = Path(str(destination))
    root = source_root()
    if _inside(destination, root):
        raise RuntimeStagingRefused(
            f"{destination} is inside the installation at {root}; a runtime staged into the tree "
            "being removed is not staged at all")
    if _lstat_or_none(destination) is not None:
        raise RuntimeStagingRefused(
            f"{destination} already exists; the uninstall runtime is staged into a directory this "
            "invocation creates, and an existing one — empty or not — is left exactly as it is")

    parent = destination.parent
    refusal = _authority_refusal(parent, what=f"the staging parent {parent}",
                                 authority_api=authority_api)
    if refusal is not None:
        raise RuntimeStagingRefused(
            f"{refusal}; a privileged copy is not written into a directory that is not protected")

    # ATOMIC, and it is the creation that enforces the rule above: `mkdir` fails if anything is
    # already there, so nothing can appear between the check and the copy and be adopted.
    try:
        os.mkdir(str(destination), 0o700)
    except FileExistsError as exc:
        raise RuntimeStagingRefused(
            f"{destination} appeared between the check and the creation; nothing was written") from exc
    except OSError as exc:
        raise RuntimeStagingRefused(
            f"{destination} could not be created: {exc}") from exc
    created = _identity_of(destination)
    try:
        os.chmod(str(destination), 0o700)                 # our own material, whatever the umask did
    except OSError:                                       # pragma: no cover - platform-specific
        pass

    try:
        _protect_windows_leaf(destination, acl_api=acl_api)
    except Exception as exc:                              # noqa: BLE001
        discard(destination, identity=created)
        raise RuntimeStagingRefused(
            f"the staging directory {destination} could not be protected: {exc}") from exc

    refusal = _authority_refusal(destination, what=f"the staging directory {destination}",
                                 authority_api=authority_api)
    if refusal is not None:
        discard(destination, identity=created)
        raise RuntimeStagingRefused(
            f"{refusal}; the directory this invocation just created did not read back as protected")

    runtime_source, package_source = _runtime_root(), _package_root()
    staged_runtime = destination / STAGED_RUNTIME
    staged_source = destination / STAGED_SOURCE
    try:
        # **`symlinks=False`: a link is copied as the material it points at.** Preserving one would
        # stage a route back into the installation that nothing follows until a later lazy import —
        # after the removal has begun. `links_under` then proves the copy really is link-free.
        shutil.copytree(str(runtime_source), str(staged_runtime), symlinks=False,
                        dirs_exist_ok=False)
        shutil.copytree(str(package_source), str(staged_source / package_source.name),
                        symlinks=False, dirs_exist_ok=False)
    except (OSError, shutil.Error) as exc:
        discard(destination, identity=created)
        raise RuntimeStagingRefused(
            f"the uninstall runtime could not be copied to {destination}: {exc}") from exc

    surviving = links_under(destination)
    if surviving:
        discard(destination, identity=created)
        raise RuntimeStagingRefused(
            f"the staged runtime still holds {len(surviving)} link(s) or reparse point(s), which can "
            f"resolve back into the installation at a later import: {', '.join(surviving[:5])}")

    executable = staged_runtime / Path(sys.executable).name
    if not executable.exists():
        discard(destination, identity=created)
        raise RuntimeStagingRefused(
            f"the copied runtime has no interpreter at {executable}; the installed layout is not "
            "the one this staging understands")

    # THE BINDING. An embeddable interpreter reads its `._pth` and ignores `PYTHONPATH`; anything
    # else reads `PYTHONPATH`. Doing both would hide which one carried the run.
    environment = {k: v for k, v in os.environ.items()
                   if k not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    pth = _import_path_file(staged_runtime)
    if pth is not None:
        try:
            pth.write_text(
                rebound_import_path(pth.read_text(encoding="utf-8", errors="replace"),
                                    original_source=package_source.parent,
                                    staged_source=staged_source),
                encoding="utf-8")
        except OSError as exc:
            discard(destination, identity=created)
            raise RuntimeStagingRefused(
                f"the staged interpreter's import path at {pth} could not be rebound: {exc}") from exc
        bound_by = str(pth)
    else:
        environment["PYTHONPATH"] = str(staged_source)
        bound_by = "PYTHONPATH"

    # **EVERY refusal from here on takes the copy with it.** Found by its own control: a probe that
    # raised left a staged runtime nobody would ever run and nobody was going to remove — the litter
    # this module exists to avoid, produced by the module itself.
    try:
        answer = _probe(executable, cwd=destination, env=environment)
        inside = _verify_external(answer, root=root)
        if inside:
            raise RuntimeStagingRefused(
                f"the staged runtime still reads from the installation at {root}: "
                f"{'; '.join(inside)}")
    except RuntimeStagingRefused:
        discard(destination, identity=created)
        raise
    return {"result": "staged", "executable": str(executable), "root": str(destination),
            "source_root": str(root), "bound_by": bound_by,
            "observed": {"executable": answer.get("executable"), "cwd": answer.get("cwd"),
                         "package": answer.get("package")}}


def discard(destination, *, identity=None) -> bool:
    """Remove staged material. **The one deletion in this module, and it can only reach a copy.**

    A staged runtime is removed by whoever created the destination, because the staged interpreter
    cannot remove its own running image any more than the installed one could — which is the fact
    this whole module exists because of. This is the failure-path cleanup; the successful path is
    cleaned by the launcher when the invocation ends.

    **`identity` is what makes a failure-path removal provably aimed at this invocation's own
    material.** `stage` records the `(st_dev, st_ino)` of the directory it created and passes it
    back here, so a path that has since been replaced — by anything, including a link — is left
    alone rather than recursively removed on somebody else's behalf. Called without one (a caller
    cleaning up its own successful stage) it removes what it is given.
    """
    destination = Path(str(destination))
    st = _lstat_or_none(destination)
    if st is None:
        return False
    if identity is not None:
        if _is_reparse_or_link(st) or (st.st_dev, st.st_ino) != tuple(identity):
            return False
    shutil.rmtree(str(destination), ignore_errors=True)
    return _lstat_or_none(destination) is None
