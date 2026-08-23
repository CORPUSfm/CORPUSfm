"""Core git export logic for git_formatter.

Writes structured and rendered .txt files to a git repository, one file per
catalog item, then commits. Handles deletions when items are removed from FM.

Public API:
    export(result, repo_dir, config) -> ExportResult          (ParseResult path)
    export_artifact(artifact, repo_dir, config) -> ExportResult  (Artifact path)
    ExportConfig
    ExportResult
"""

from __future__ import annotations

from corpusfm.core import safe_xml as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from corpusfm.core.parser import ParseResult
from corpusfm.core.xref.graph import XRefGraph

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact, ArtifactItem
from corpusfm.core.git_formatter._renderer import (
    ALL_SECTIONS,
    CATALOG_TO_FOLDER,
    DEFAULT_LARGE_THRESHOLD,
    item_filename,
    make_file_label,
    relationship_filename,
    render_addon_rendered,
    render_addon_structured,
    render_cf_rendered,
    render_cf_structured,
    render_layout_rendered,
    render_layout_structured,
    render_relationship_rendered,
    render_relationship_structured,
    render_script_rendered,
    render_script_structured,
    render_table_rendered,
    render_table_structured,
    render_valuelist_rendered,
    render_valuelist_structured,
)

_AUTHOR_NAME = "CORPUSfm Tool"
_AUTHOR_EMAIL = "corpusfm@local"


@dataclass
class ExportConfig:
    modes: list = field(default_factory=lambda: ["structured", "rendered"])
    sections: list = field(default_factory=lambda: list(ALL_SECTIONS))
    show_hidden: bool = True
    large_content_threshold: int = DEFAULT_LARGE_THRESHOLD
    job_name: Optional[str] = None
    xref_graph: Optional[XRefGraph] = None
    # Flat dict of "folder_name/item_name" → one-line summary string.
    summaries: Optional[dict] = None


@dataclass
class ExportResult:
    file_label: str
    commit_sha: str
    files_written: int
    files_deleted: int
    push_ok: Optional[bool] = None   # set when an export pushed to a remote
    push_msg: str = ""


def _init_or_open(repo_dir: Path):
    import git
    if (repo_dir / ".git").exists():
        return git.Repo(repo_dir)
    repo_dir.mkdir(parents=True, exist_ok=True)
    return git.Repo.init(repo_dir)


def _existing_txt_files(section_dir: Path) -> set[str]:
    """Return filenames (not full paths) of all .txt files directly in section_dir."""
    if not section_dir.exists():
        return set()
    return {p.name for p in section_dir.iterdir() if p.suffix == ".txt"}


def _get_item_id(xml_str: str) -> str:
    try:
        return ET.fromstring(xml_str).get("id", "") or ""
    except ET.ParseError:
        return ""


def _xref_block(folder_name: str, name: str, xref: XRefGraph) -> str:
    """Return a formatted XRef block for a rendered .txt file, or empty string."""
    lines: list[str] = []

    if folder_name == "scripts":
        calls = xref.script_calls.get(name, [])
        called_by = xref.script_called_by.get(name, [])
        uses_fields = xref.script_uses_fields.get(name, [])
        if calls:
            lines.append(f"Calls: {', '.join(calls)}")
        if called_by:
            lines.append(f"Called by: {', '.join(called_by)}")
        if uses_fields:
            lines.append(f"Uses fields: {', '.join(uses_fields)}")

    elif folder_name == "custom_functions":
        uses_fields = xref.cf_uses_fields.get(name, [])
        used_in_cfs = [
            cf for cf, fields in xref.cf_uses_fields.items()
            if name in fields
        ]
        used_in_scripts = xref.field_used_in_scripts  # not directly indexed by CF
        if uses_fields:
            lines.append(f"Uses fields: {', '.join(uses_fields)}")
        if used_in_cfs:
            lines.append(f"Used in CFs: {', '.join(used_in_cfs)}")

    elif folder_name == "tables":
        # Collect all fields from this table used anywhere (TO::Field where TO base table == name)
        field_prefix = f"{name}::"
        used_scripts = sorted({
            s
            for field_ref, scripts in xref.field_used_in_scripts.items()
            if field_ref.startswith(field_prefix)
            for s in scripts
        })
        used_cfs = sorted({
            cf
            for field_ref, cfs in xref.field_used_in_cfs.items()
            if field_ref.startswith(field_prefix)
            for cf in cfs
        })
        if used_scripts:
            lines.append(f"Fields used in scripts: {', '.join(used_scripts)}")
        if used_cfs:
            lines.append(f"Fields used in CFs: {', '.join(used_cfs)}")

    elif folder_name == "layouts":
        # layout→script calls stored under calls_scripts in xref_item (Explorer); not in XRefGraph yet
        pass

    elif folder_name == "value_lists":
        pass

    if not lines:
        return ""
    return "\n--- XRef ---\n" + "\n".join(lines)


def _render_structured(
    folder_name: str,
    name: str,
    xml_str: str,
    result: ParseResult,
    config: ExportConfig,
) -> str:
    if folder_name == "scripts":
        return render_script_structured(name, xml_str, result.step_xml.get(name, ""))
    if folder_name == "custom_functions":
        return render_cf_structured(name, xml_str, result.cf_xml.get(name, ""))
    if folder_name == "tables":
        return render_table_structured(name, xml_str, result.field_names.get(name))
    if folder_name == "layouts":
        return render_layout_structured(name, xml_str)
    if folder_name == "value_lists":
        return render_valuelist_structured(name, xml_str)
    if folder_name == "relationships":
        return render_relationship_structured(name, xml_str)
    if folder_name == "addons":
        return render_addon_structured(name, xml_str)
    return f"Name: {name}"


def _render_rendered(
    folder_name: str,
    name: str,
    xml_str: str,
    result: ParseResult,
    config: ExportConfig,
) -> str:
    kw = dict(show_hidden=config.show_hidden, threshold=config.large_content_threshold)
    if folder_name == "scripts":
        return render_script_rendered(name, xml_str, result.step_xml.get(name, ""), **kw)
    if folder_name == "custom_functions":
        return render_cf_rendered(name, xml_str, result.cf_xml.get(name, ""), **kw)
    if folder_name == "tables":
        return render_table_rendered(name, xml_str, result.field_names.get(name))
    if folder_name == "layouts":
        return render_layout_rendered(name, xml_str)
    if folder_name == "value_lists":
        return render_valuelist_rendered(name, xml_str)
    if folder_name == "relationships":
        return render_relationship_rendered(name, xml_str)
    if folder_name == "addons":
        return render_addon_rendered(name, xml_str)
    return f"Name: {name}"


def export(
    result: ParseResult,
    repo_dir: Path,
    config: ExportConfig = None,
) -> ExportResult:
    """Write structured/rendered .txt files and commit to git.

    One file per catalog item. Items removed from FM are deleted from the repo.
    Returns ExportResult with the commit SHA and file counts.
    """
    import git

    if config is None:
        config = ExportConfig()

    repo = _init_or_open(repo_dir)
    fm_file_name = result.metadata.get("File", result.label)
    file_label = make_file_label(fm_file_name, config.job_name)

    staged_for_add: list[str] = []
    staged_for_remove: list[str] = []
    files_written = 0
    files_deleted = 0

    for mode in config.modes:
        mode_dir = repo_dir / file_label / mode

        for catalog_key, folder_name in CATALOG_TO_FOLDER.items():
            if folder_name not in config.sections:
                continue
            items = result.section_xml.get(catalog_key, {})

            section_dir = mode_dir / folder_name
            existing = _existing_txt_files(section_dir)
            written: set[str] = set()

            for name, xml_str in items.items():
                if folder_name == "relationships":
                    fname = relationship_filename(name, xml_str)
                else:
                    item_id = _get_item_id(xml_str)
                    fname = item_filename(item_id, name)

                if mode == "structured":
                    content = _render_structured(folder_name, name, xml_str, result, config)
                else:
                    content = _render_rendered(folder_name, name, xml_str, result, config)
                    if config.summaries is not None:
                        summary = config.summaries.get(f"{folder_name}/{name}", "")
                        if summary:
                            content += f"\n--- Summary ---\n{summary}"
                    if config.xref_graph is not None:
                        content += _xref_block(folder_name, name, config.xref_graph)

                out_path = section_dir / fname
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(content + "\n", encoding="utf-8")
                rel = str(out_path.relative_to(repo_dir))
                staged_for_add.append(rel)
                written.add(fname)
                files_written += 1

            # Remove files for items that no longer exist in FM
            for stale in existing - written:
                stale_path = section_dir / stale
                stale_path.unlink(missing_ok=True)
                rel = str(stale_path.relative_to(repo_dir))
                staged_for_remove.append(rel)
                files_deleted += 1

    if not staged_for_add and not staged_for_remove:
        return ExportResult(
            file_label=file_label, commit_sha="", files_written=0, files_deleted=0
        )

    repo.index.add(staged_for_add)
    if staged_for_remove:
        try:
            repo.index.remove(staged_for_remove, working_tree=False)
        except Exception:
            pass

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    msg = f"{file_label} {now}"
    actor = git.Actor(_AUTHOR_NAME, _AUTHOR_EMAIL)
    commit = repo.index.commit(msg, author=actor, committer=actor)

    return ExportResult(
        file_label=file_label,
        commit_sha=commit.hexsha,
        files_written=files_written,
        files_deleted=files_deleted,
    )


# ── Artifact-native export path ───────────────────────────────────────────────

def _render_structured_from_item(item: "ArtifactItem", folder_name: str) -> str:
    lines = [f"Name: {item.name}"]
    item_id_val = item.attributes.get("id", "")
    if item_id_val:
        lines.append(f"ID: {item_id_val}")
    if item.fm_uuid:
        lines.append(f"UUID: {item.fm_uuid}")
    if item.is_folder:
        lines.append("Type: Folder")
    return "\n".join(lines)


def _xref_block_from_artifact(artifact: "Artifact", item: "ArtifactItem") -> str:
    folder_name = CATALOG_TO_FOLDER.get(item.section, "")
    lines: list[str] = []

    if folder_name == "scripts":
        calls = [xr.to_name for xr in artifact.xrefs_from(item.item_id) if xr.type == "ScriptReference"]
        called_by = [xr.from_name for xr in artifact.xrefs_to(item.item_id) if xr.type == "ScriptReference"]
        uses_fields = [xr.to_name for xr in artifact.xrefs_from(item.item_id) if xr.type == "FieldReference"]
        if calls:
            lines.append(f"Calls: {', '.join(calls)}")
        if called_by:
            lines.append(f"Called by: {', '.join(called_by)}")
        if uses_fields:
            lines.append(f"Uses fields: {', '.join(uses_fields)}")

    elif folder_name == "tables":
        field_prefix = f"{item.name}::"
        used_scripts = sorted({
            xr.from_name
            for xr in artifact.xref_map
            if xr.type == "FieldReference" and xr.to_name.startswith(field_prefix)
        })
        if used_scripts:
            lines.append(f"Fields used in scripts: {', '.join(used_scripts)}")

    if not lines:
        return ""
    return "\n--- XRef ---\n" + "\n".join(lines)


def export_artifact(
    artifact: "Artifact",
    repo_dir: Path,
    config: ExportConfig = None,
) -> ExportResult:
    """Write structured/rendered .txt files from an Artifact and commit to git.

    No ParseResult dependency — reads rendered_text and xref_map directly.
    """
    import git

    if config is None:
        config = ExportConfig()

    repo = _init_or_open(repo_dir)
    file_label = make_file_label(artifact.identity.file_name, config.job_name)

    staged_for_add: list[str] = []
    staged_for_remove: list[str] = []
    files_written = 0
    files_deleted = 0

    for mode in config.modes:
        mode_dir = repo_dir / file_label / mode

        for catalog_key, folder_name in CATALOG_TO_FOLDER.items():
            if folder_name not in config.sections:
                continue

            section_items = [
                item for item in artifact.items.values()
                if item.section == catalog_key
            ]

            section_dir = mode_dir / folder_name
            existing = _existing_txt_files(section_dir)
            written: set[str] = set()

            for item in section_items:
                fm_id = item.fm_uuid or item.attributes.get("id", "")
                fname = item_filename(fm_id, item.name)

                if mode == "structured":
                    content = _render_structured_from_item(item, folder_name)
                else:
                    content = item.rendered_text or item.name
                    if item.summary:
                        content += f"\n--- Summary ---\n{item.summary}"
                    content += _xref_block_from_artifact(artifact, item)

                out_path = section_dir / fname
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(content + "\n", encoding="utf-8")
                rel = str(out_path.relative_to(repo_dir))
                staged_for_add.append(rel)
                written.add(fname)
                files_written += 1

            for stale in existing - written:
                stale_path = section_dir / stale
                stale_path.unlink(missing_ok=True)
                rel = str(stale_path.relative_to(repo_dir))
                staged_for_remove.append(rel)
                files_deleted += 1

    # File-level block: the data model (TOs collapsed to base tables) as a mermaid
    # erDiagram — diffable in git, the shared human/AI language for the schema's shape.
    try:
        from corpusfm.core.structure_intent import structure_intent_dict, to_mermaid_erd
        si = structure_intent_dict(artifact)
        dm = si.get("data_model")
        if dm and dm.get("edges"):
            mm_path = repo_dir / file_label / "data-model.mmd"
            mm_path.parent.mkdir(parents=True, exist_ok=True)
            mm_path.write_text((si.get("mermaid") or to_mermaid_erd(dm)) + "\n", encoding="utf-8")
            staged_for_add.append(str(mm_path.relative_to(repo_dir)))
            files_written += 1
    except Exception:
        pass

    if not staged_for_add and not staged_for_remove:
        return ExportResult(
            file_label=file_label, commit_sha="", files_written=0, files_deleted=0
        )

    repo.index.add(staged_for_add)
    if staged_for_remove:
        try:
            repo.index.remove(staged_for_remove, working_tree=False)
        except Exception:
            pass

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    msg = f"{file_label} {now}"
    actor = git.Actor(_AUTHOR_NAME, _AUTHOR_EMAIL)
    commit = repo.index.commit(msg, author=actor, committer=actor)

    return ExportResult(
        file_label=file_label,
        commit_sha=commit.hexsha,
        files_written=files_written,
        files_deleted=files_deleted,
    )
