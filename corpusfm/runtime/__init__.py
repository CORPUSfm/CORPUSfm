"""Runtime composition layer — the explicit app graph built once at each surface's edge.

Public API:
    AppContext, AuthPolicy, build_context
"""

from corpusfm.runtime.compose import build_context
from corpusfm.runtime.context import AppContext, AuthPolicy

__all__ = ["AppContext", "AuthPolicy", "build_context"]
