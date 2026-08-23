"""FastAPI dependencies for the composed runtime context (inbox packet 006, slice S2).

Routes obtain the `AppContext` via `Depends(get_ctx)` instead of importing `is_server_mode()` /
`get_backend()` directly. `app.state.ctx` is set once at `create_app()`; a bare test app that was
built without that step (or a non-app request) falls back to a freshly composed context, so the
dependency is always satisfiable and tests can override it with `app.dependency_overrides[get_ctx]`.
"""

from __future__ import annotations

from fastapi import Request

from corpusfm.runtime import AppContext, build_context


def get_ctx(request: Request) -> AppContext:
    ctx = getattr(getattr(request.app, "state", None), "ctx", None)
    if isinstance(ctx, AppContext):
        return ctx
    return build_context()
