"""Extension input contracts — data objects passed to Explorer and Diff generators.

Extensions are pure functions: Artifact + metadata in, HTML file out.
No storage imports, no mode awareness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from corpusfm.artifact import Artifact
    from corpusfm.storage.local import ArtifactMeta


@dataclass
class ArtifactDiffInput:
    artifact_a: "Artifact"
    artifact_b: "Artifact"
    meta_a: "ArtifactMeta"
    meta_b: "ArtifactMeta"
