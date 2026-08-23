"""corpusfm.extensions.export — static HTML export for Explorer and Diff views.

Public API:
    generate_explorer_html(inputs: list[Artifact]) -> Path   (temp file, opened by caller)
    generate_diff_html(inp: ArtifactDiffInput) -> Path
"""

from corpusfm.extensions.export.contracts import ArtifactDiffInput
from corpusfm.extensions.export.diff import generate_diff_html
from corpusfm.extensions.export.explorer import generate_explorer_html

__all__ = ["ArtifactDiffInput", "generate_explorer_html", "generate_diff_html"]
