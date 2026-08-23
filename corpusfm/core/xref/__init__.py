"""Cross-reference graph and dead-end analysis for FM snapshots.

Public API:
    build_xref_graph(result: ParseResult) -> XRefGraph
    save_xref_graph(graph: XRefGraph, path: Path) -> None
    load_xref_graph(path: Path) -> XRefGraph
    compute_dead_ends(result: ParseResult, xref: XRefGraph) -> DeadEndReport
    save_dead_ends(report: DeadEndReport, path: Path) -> None
    load_dead_ends(path: Path) -> DeadEndReport
"""

from corpusfm.core.xref.graph import XRefGraph, build_xref_graph, load_xref_graph, save_xref_graph
from corpusfm.core.xref.dead_ends import DeadEndReport, compute_dead_ends, load_dead_ends, save_dead_ends

__all__ = [
    "XRefGraph", "build_xref_graph", "save_xref_graph", "load_xref_graph",
    "DeadEndReport", "compute_dead_ends", "save_dead_ends", "load_dead_ends",
]
