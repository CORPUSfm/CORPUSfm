"""Git archive storage — Storage Mode C.

Each FM file is tracked as a single file (latest.json.gz) in a local git repo.
Every comparison auto-commits a new entry; git history IS the diff log.

Source files are gzip-compressed to stay under GitHub's 100 MB file size limit.
A 100 MB JSON file compresses to ~10-20 MB.

Public API:
    default_git_dir()                                 -> Path
    save_schema_xml(result, repo_dir)                 -> str  (commit SHA)
    load_schema_xml_from_sha(repo_dir, sha, file_name) -> ParseResult
    list_commits(repo_dir)                            -> dict[str, list[CommitMeta]]
    configure_remote(repo_dir, url)                   -> None
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from corpusfm.core.parser import ParseResult

_PROJECT_ROOT = Path(__file__).parent.parent.parent


def _safe_file_name(result: ParseResult) -> str:
    """Filesystem-safe directory name derived from FM file metadata."""
    raw = result.metadata.get("File") or result.label or "unknown"
    name = raw.replace(".fmp12", "").strip()
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    base = safe.strip("._-") or "unknown"
    return f"{base}_addon" if result.is_addon else base
_AUTHOR_NAME = "CORPUSfm Tool"
_AUTHOR_EMAIL = "corpusfm@local"


@dataclass
class CommitMeta:
    file_name: str       # FM file subdirectory name
    sha: str             # full git commit SHA
    committed_at: str    # ISO timestamp string
    label: str           # user-facing label at save time
    schema_version: str
    fm_version: str


def default_git_dir() -> Path:
    return _PROJECT_ROOT / "git_archive"


def _init_or_open(repo_dir: Path):
    """Open existing git repo or initialize a new one. Returns git.Repo."""
    import git
    if (repo_dir / ".git").exists():
        return git.Repo(repo_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)
    return git.Repo.init(repo_dir)


def save_schema_xml(result: ParseResult, repo_dir: Path) -> str:
    """Commit a ParseResult to the git archive. Returns the commit SHA."""
    import git

    repo = _init_or_open(repo_dir)
    file_name = _safe_file_name(result)

    snap_path = repo_dir / file_name / "latest.json.gz"
    snap_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "label": result.label,
        "sections": result.sections,
        "fields": result.fields,
        "steps": result.steps,
        "metadata": result.metadata,
        "schema_version": result.schema_version,
        "schema_warning": result.schema_warning,
        "step_xml": result.step_xml,
        "section_xml": result.section_xml,
        "calcs": result.calcs,
        "cf_xml": result.cf_xml,
        "field_names": result.field_names,
    }
    snap_path.write_bytes(
        gzip.compress(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    )

    # Remove stale uncompressed file if upgrading from pre-gzip version
    old_path = repo_dir / file_name / "latest.json"
    if old_path.exists():
        old_path.unlink()
        repo.index.remove([str(old_path.relative_to(repo_dir))], working_tree=False)

    repo.index.add([str(snap_path.relative_to(repo_dir))])

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    meta_json = json.dumps({
        "label": result.label,
        "schema_version": result.schema_version,
        "fm_version": result.metadata.get("Source", ""),
        "file_name": file_name,
    })
    msg = f"snapshot: {file_name} @ {now}\n{meta_json}"

    actor = git.Actor(_AUTHOR_NAME, _AUTHOR_EMAIL)
    commit = repo.index.commit(msg, author=actor, committer=actor)
    return commit.hexsha


def load_schema_xml_from_sha(repo_dir: Path, sha: str, file_name: str) -> ParseResult:
    """Load a ParseResult from a specific commit SHA."""
    import git

    repo = git.Repo(repo_dir)
    commit = repo.commit(sha)
    # Support both compressed (current) and legacy uncompressed blobs
    try:
        blob = commit.tree / file_name / "latest.json.gz"
        raw = gzip.decompress(blob.data_stream.read())
    except KeyError:
        blob = commit.tree / file_name / "latest.json"
        raw = blob.data_stream.read()
    data = json.loads(raw.decode("utf-8"))
    return ParseResult(
        label=data["label"],
        sections=data["sections"],
        fields=data["fields"],
        steps=data["steps"],
        metadata=data["metadata"],
        schema_version=data["schema_version"],
        schema_warning=data.get("schema_warning"),
        step_xml=data.get("step_xml", {}),
        section_xml=data.get("section_xml", {}),
        calcs=data.get("calcs", {}),
        cf_xml=data.get("cf_xml", {}),
        field_names=data.get("field_names", {}),
    )


def list_commits(repo_dir: Path) -> dict[str, list[CommitMeta]]:
    """Return {file_name: [CommitMeta, ...]} newest-first per FM file.

    Only includes commits written by save_schema_xml (message starts with 'snapshot:').
    """
    import git

    if not (repo_dir / ".git").exists():
        return {}

    try:
        repo = git.Repo(repo_dir)
        repo.head.commit  # raises ValueError if repo has no commits
    except (git.InvalidGitRepositoryError, ValueError):
        return {}

    result: dict[str, list[CommitMeta]] = {}
    for commit in repo.iter_commits():
        lines = commit.message.strip().split("\n", 1)
        if not lines[0].startswith("snapshot:"):
            continue

        try:
            meta = json.loads(lines[1]) if len(lines) > 1 else {}
        except (json.JSONDecodeError, IndexError):
            meta = {}

        file_name = meta.get("file_name", "")
        if not file_name:
            try:
                file_name = lines[0].split("snapshot: ", 1)[1].split(" @ ")[0]
            except IndexError:
                continue

        cm = CommitMeta(
            file_name=file_name,
            sha=commit.hexsha,
            committed_at=commit.committed_datetime.isoformat(timespec="seconds"),
            label=meta.get("label", file_name),
            schema_version=meta.get("schema_version", ""),
            fm_version=meta.get("fm_version", ""),
        )
        result.setdefault(file_name, []).append(cm)

    return result


def configure_remote(repo_dir: Path, url: str) -> None:
    """Add or replace the 'origin' remote."""
    import git
    repo = _init_or_open(repo_dir)
    if "origin" in [r.name for r in repo.remotes]:
        repo.delete_remote("origin")
    repo.create_remote("origin", url)
