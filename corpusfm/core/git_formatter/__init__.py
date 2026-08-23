"""FileMaker git export formatter.

Writes structured and rendered plain-text .txt files to a git repository,
one file per catalog item (script, custom function, table, layout, etc.).
Optimized for git diff and AI consumption.

Core export (ParseResult path):
    export(result, repo_dir, config)  -> ExportResult
    ExportConfig
    ExportResult

Core export (Artifact path — no ParseResult dependency):
    export_artifact(artifact, repo_dir, config) -> ExportResult

Registration management (named git destinations):
    from corpusfm.core.git_formatter.registrations import (
        RegistrationConfig,
        add_registration,
        get_registration,
        list_registrations,
        remove_registration,
    )

Convenience — export to a named registration:
    export_to_registration(result, registration_name) -> ExportResult
    export_artifact_to_registration(artifact, registration_name) -> ExportResult
"""

from corpusfm.core.git_formatter._exporter import ExportConfig, ExportResult, export, export_artifact
from corpusfm.core.git_formatter.registrations import (
    RegistrationConfig,
    add_registration,
    effective_repo,
    generate_ssh_keypair,
    get_registration,
    is_valid_registration_name,
    list_registrations,
    push_registration,
    remove_registration,
    resolve_local_path,
    verify_registration,
)

__all__ = [
    "ExportConfig",
    "ExportResult",
    "export",
    "export_artifact",
    "RegistrationConfig",
    "add_registration",
    "get_registration",
    "list_registrations",
    "remove_registration",
    "export_to_registration",
    "export_artifact_to_registration",
    "resolve_local_path",
    "effective_repo",
    "verify_registration",
    "push_registration",
    "generate_ssh_keypair",
    "is_valid_registration_name",
]


def export_to_registration(
    result,
    registration_name: str,
    snap_dir=None,
) -> ExportResult:
    """Export a ParseResult using a named registration's config.

    Loads the registration by name, resolves its local clone path,
    builds an ExportConfig, and calls export(). XRefGraph is built
    automatically from the ParseResult and included in rendered output.
    If snap_dir is provided, summaries.json is loaded from it.
    """
    from pathlib import Path
    from corpusfm.core.xref.graph import build_xref_graph
    reg = get_registration(registration_name)
    try:
        xref_graph = build_xref_graph(result)
    except Exception:
        xref_graph = None
    summaries = None
    if snap_dir is not None:
        summaries_path = Path(snap_dir) / "summaries.json"
        if summaries_path.exists():
            try:
                import json
                summaries = json.loads(summaries_path.read_text(encoding="utf-8"))
            except Exception:
                pass
    config = ExportConfig(
        modes=reg.modes,
        sections=reg.sections,
        show_hidden=reg.show_hidden,
        large_content_threshold=reg.large_content_threshold,
        xref_graph=xref_graph,
        summaries=summaries,
    )
    return export(result, resolve_local_path(reg), config)


def export_artifact_to_registration(
    artifact,
    registration_name: str,
    repo: str = "",
    push: bool = False,
    modes=None,
) -> ExportResult:
    """Export an Artifact using a named registration's config, into the per-repo local
    history, optionally pushing to the credential's effective repo.

    No ParseResult dependency — reads rendered_text and xref_map from the artifact.
    `repo` is the Job/Artifact override (ignored for a deploy-key credential, which is
    bound to its own repo). `modes` is the per-call content override (e.g. a Job's
    choice of rendered/structured/both); when falsy the registration's own `modes`
    apply. The push result, when requested, rides on result.push_ok / result.push_msg.
    """
    reg = get_registration(registration_name)
    target_repo = effective_repo(reg, repo)
    config = ExportConfig(
        modes=list(modes) if modes else reg.modes,
        sections=reg.sections,
        show_hidden=reg.show_hidden,
        large_content_threshold=reg.large_content_threshold,
    )
    local = resolve_local_path(reg, target_repo)
    result = export_artifact(artifact, local, config)
    if push and target_repo:
        ok, msg = push_registration(reg, local, repo=target_repo)
        try:
            result.push_ok, result.push_msg = ok, msg
        except Exception:  # ExportResult may be frozen/slotted; best-effort annotation
            pass
    return result
