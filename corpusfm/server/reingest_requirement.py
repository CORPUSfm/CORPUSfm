"""Needs re-ingestion: the update declares it, the update applies it (packet 1467).

THE DECLARATION: ``corpusfm/ingestion/ingestion_revision.txt`` names the build of the most recent
change to the stored-derivation inputs (``stored_derivation_inputs.txt``). It is generated during
release preparation (``scripts/ingestion_revision.py --write``) and a test fails while it is stale.
Because it is cumulative, one comparison covers the whole installed-to-incoming range, skipped
releases included: the update requires re-ingestion exactly when the incoming tree's revision is
newer than the installed build. The installed updater infers nothing from source.

THE OPERATION: :func:`apply_update_status`, called by BOTH update paths once the new code is in place:

* in-app — the web process that requested the update, after root reports ``completed`` and before
  it restarts (``update_service``); it reads the incoming tree's declaration with ``git show``;
* installer — ``corpusfm update-notice``, which the installer already runs as its final step of an
  upgrade (``cli/cmd_update_notice``), in the new code; the installed build is the transition the
  notice flow recorded.

Never at service startup. When the update declares re-ingestion, every existing schema artifact is
marked; otherwise every outstanding mark is cleared. **Clean is the state an update assigns, not proof
that stored content was regenerated.** A committed re-ingest also clears its own mark; a failed one
does not. An answer that cannot be determined is clean. Write failures are logged and reported, never
retried or rolled back: the next update sets the state again. A transition already applied is not
applied twice, so an artifact re-ingested in between is not made stale again.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

INPUTS_FILE = "corpusfm/ingestion/stored_derivation_inputs.txt"
REVISION_FILE = "corpusfm/ingestion/ingestion_revision.txt"
_DECLARATION_FILES = (INPUTS_FILE, REVISION_FILE)
_STORAGE = "STORAGE"
_ROOT = Path(__file__).resolve().parents[2]


# ── the boundary and the declaration ─────────────────────────────────────────────────────────

def parse_inputs(text: str) -> tuple[str, ...]:
    out = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return tuple(out)


def own_inputs() -> tuple[str, ...]:
    return parse_inputs((_ROOT / INPUTS_FILE).read_text(encoding="utf-8"))


def _split(inputs) -> tuple[tuple[str, ...], dict]:
    """Whole-path entries, and ``path::function`` entries grouped by file. A file that also holds
    read-side code names the functions whose source shapes stored output, so editing the rest of it
    (how a stored record is read back or displayed) declares nothing."""
    whole, scoped = [], {}
    for entry in inputs:
        path, sep, func = entry.partition("::")
        if sep:
            scoped.setdefault(path, set()).add(func)
        else:
            whole.append(entry)
    return tuple(whole), scoped


def is_input(path: str, inputs) -> bool:
    """Whether ``path`` lies inside the boundary at all (a function-scoped file counts as covered)."""
    if path in _DECLARATION_FILES:
        return False
    whole, scoped = _split(inputs)
    return path in scoped or any(path == p or (p.endswith("/") and path.startswith(p)) for p in whole)


def _function_sources(text: Optional[str], names) -> dict:
    import ast
    if text is None:
        return {}
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return {"<unparseable>": text}
    return {n.name: ast.get_source_segment(text, n) for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names}


def _changes_output(path: str, before, after, inputs) -> bool:
    """``before``/``after`` are callables returning the file text (or None), read only when the
    file is function-scoped; a whole-path entry never needs its content (which may be binary)."""
    whole, scoped = _split(inputs)
    if path in _DECLARATION_FILES:
        return False
    if any(path == p or (p.endswith("/") and path.startswith(p)) for p in whole):
        return True
    names = scoped.get(path)
    return bool(names) and _function_sources(before(), names) != _function_sources(after(), names)


def parse_revision(text: Optional[str]) -> Optional[int]:
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            return int(line) if line.isdigit() and int(line) > 0 else None
    return None


def own_revision() -> Optional[int]:
    try:
        return parse_revision((_ROOT / REVISION_FILE).read_text(encoding="utf-8"))
    except OSError:
        return None


def compute_revision(repo: Path) -> Optional[int]:
    """Release preparation: the build of the newest change to stored ingestion output. A qualifying
    change that is staged or still in the working tree counts as the commit about to be made."""
    from corpusfm import updater

    def git(*args):
        r = updater._run_git(repo, *args, timeout=60)
        return r.stdout if r.returncode == 0 else None

    def show(ref, path):
        r = updater._run_git(repo, "show", f"{ref}:{path}")
        return r.stdout if r.returncode == 0 else None

    inputs = own_inputs()
    whole, scoped = _split(inputs)
    pathspec = list(whole) + sorted(scoped) + [f":!{f}" for f in _DECLARATION_FILES]
    head = git("rev-list", "--count", "HEAD")
    pending = git("diff", "HEAD", "--name-only", "--", *pathspec)
    untracked = git("ls-files", "--others", "--exclude-standard", "--", *pathspec)
    if head is None or pending is None:
        return None
    def disk(path):
        f = repo / path
        return f.read_text(encoding="utf-8") if f.exists() else None

    for path in pending.split() + (untracked or "").split():
        if _changes_output(path, lambda: show("HEAD", path), lambda: disk(path), inputs):
            return int(head.strip()) + 1
    log = git("log", "--format=%H", "HEAD", "--", *pathspec)
    for sha in (log or "").split():
        if commit_changes_output(repo, sha, inputs):
            count = git("rev-list", "--count", sha)
            return int(count.strip()) if count else None
    return None


def commit_changes_output(repo: Path, sha: str, inputs=None) -> bool:
    """Whether one commit changes stored ingestion output, by the boundary."""
    from corpusfm import updater

    def show(ref, path):
        r = updater._run_git(repo, "show", f"{ref}:{path}")
        return r.stdout if r.returncode == 0 else None

    inputs = own_inputs() if inputs is None else inputs
    r = updater._run_git(repo, "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", sha)
    for path in (r.stdout or "").split() if r.returncode == 0 else ():
        if _changes_output(path, lambda: show(f"{sha}^", path), lambda: show(sha, path), inputs):
            return True
    return False


def requires_reingestion(installed_build: Optional[int], declared_revision: Optional[int]) -> Optional[bool]:
    """True / False, or None when it cannot be determined (which the operation treats as clean)."""
    if not installed_build or not declared_revision:
        return None
    return declared_revision > installed_build


# ── the one status-setting operation ─────────────────────────────────────────────────────────

def _set_marks(backend, mark: Optional[dict]) -> dict:
    """Mark every stored schema artifact with ``mark``, or clear every outstanding mark (``None``).
    Per-record failures are counted and logged, never raised."""
    from corpusfm.artifact.capabilities import SCHEMA_TYPES
    from corpusfm.server import catalog
    from corpusfm.storage.artifact_record import REINGEST_MARK_KEY as KEY

    eng = backend.engine
    changed, unchanged, failed, confirmed = 0, 0, [], []
    for row in eng.list_where(_STORAGE, isin={"Type": sorted(SCHEMA_TYPES)}):
        jor = dict(row.jor or {})
        if jor.get("Type") not in SCHEMA_TYPES:
            continue
        if mark is None:
            if KEY not in jor:
                unchanged += 1
                continue
            jor.pop(KEY)
        else:
            current = jor.get(KEY)
            if isinstance(current, dict) and current.get("requirement") == mark["requirement"]:
                unchanged += 1
                continue
            jor[KEY] = mark
        try:
            written = eng.update(_STORAGE, row.key, jor)
        except Exception:
            logger.error("needs re-ingestion: could not set the status of %s", row.key, exc_info=True)
            failed.append(row.key)
            continue
        changed += 1
        if written is None:
            catalog.note_unpublishable_write(_STORAGE, row.key, "reingest status")
        else:
            confirmed.append((catalog.TABLE_STORAGE, written.key, written.raw))
    catalog.publish_batch(backend, confirmed, ())   # one operation, published once
    return {"changed": changed, "unchanged": unchanged, "failed": failed}


def apply_update_status(backend, *, installed_build: Optional[int], incoming_build: Optional[int],
                        declared_revision: Optional[int], path: str) -> dict:
    """Set every existing schema artifact's re-ingestion status for one completed update."""
    from corpusfm.server import update_notice

    transition = f"{installed_build or '?'}->{incoming_build or '?'}"
    if installed_build and incoming_build and update_notice.reingest_transition_applied(transition):
        return {"transition": transition, "path": path, "repeat": True}
    verdict = requires_reingestion(installed_build, declared_revision)
    if verdict is None:
        logger.warning("needs re-ingestion: %s update %s could not be evaluated (declared revision "
                       "%s); artifacts are set clean", path, transition, declared_revision)
    required = bool(verdict)
    mark = None
    if required:
        mark = {"requirement": transition, "version": f"0.{incoming_build}" if incoming_build else "",
                "declared_revision": declared_revision,
                "marked_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    result = _set_marks(backend, mark)
    if result["failed"]:
        logger.error("needs re-ingestion: %d artifact status write(s) failed for %s; the next "
                     "update sets the status again", len(result["failed"]), transition)
    if installed_build and incoming_build:
        update_notice.record_reingest_transition(
            transition, incoming_build=incoming_build, required=required,
            outstanding=(result["changed"] + result["unchanged"]) if required else 0)
    return {"transition": transition, "path": path, "required": required,
            "determined": verdict is not None, "declared_revision": declared_revision, **result}


def summary_line(summary: dict) -> str:
    """One sentence for an update result or the installer transcript."""
    if summary.get("repeat"):
        return ""
    if summary.get("error"):
        return f"Re-ingestion status could not be set ({summary['error']})."
    failed = len(summary.get("failed") or [])
    tail = f" {failed} could not be updated; see the server log." if failed else ""
    if summary.get("required"):
        n = summary.get("changed", 0) + summary.get("unchanged", 0) - failed
        return (f"This update changes what ingestion stores: {n} artifact{'s' if n != 1 else ''} "
                f"marked Needs re-ingestion.{tail}")
    if summary.get("changed") or failed:
        return f"Re-ingestion marks cleared on {summary.get('changed', 0)} artifact(s).{tail}"
    return ""


# ── the two entry points ─────────────────────────────────────────────────────────────────────

def apply_in_app(backend, *, repo: Path, new_head: str) -> dict:
    """The in-app path: this (pre-restart) process's build is the installed one; the incoming tree's
    declaration is read from the commit root just checked out."""
    from corpusfm import updater
    from corpusfm.buildstamp import RELEASE_BUILD_NAME, valid_declared_build
    from corpusfm.server.update_notice import current_build

    declared = incoming = None
    try:
        shown = updater._run_git(repo, "show", f"{new_head}:{REVISION_FILE}")
        declared = parse_revision(shown.stdout) if shown.returncode == 0 else None
        decl = updater._run_git(repo, "show", f"{new_head}:{RELEASE_BUILD_NAME}")
        build = valid_declared_build(decl.stdout) if decl.returncode == 0 else None
        if not build:
            count = updater._run_git(repo, "rev-list", "--count", new_head)
            build = (count.stdout or "").strip() if count.returncode == 0 else None
        incoming = int(build) if build and str(build).isdigit() else None
    except Exception:
        logger.warning("needs re-ingestion: the incoming declaration could not be read", exc_info=True)
    return apply_update_status(backend, installed_build=current_build() or None, incoming_build=incoming,
                               declared_revision=declared, path="in-app")


def apply_installer(backend) -> dict:
    """The installer path, run in the new code by ``corpusfm update-notice``: the installed build is
    the transition the notice flow recorded for this build."""
    from corpusfm.server import update_notice

    current = update_notice.current_build() or None
    return apply_update_status(backend, installed_build=update_notice.recorded_prev_build(current),
                               incoming_build=current, declared_revision=own_revision(),
                               path="installer")
