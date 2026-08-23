"""The composed runtime graph — `AppContext` (inbox packet 006, runtime-composition refactor).

A surface (web / MCP / CLI) builds ONE `AppContext` at its edge and threads it inward, instead of
each call site importing `is_server_mode()` / `get_backend()` / `load_app_config()` independently.

TRANSITIONAL by design: in this first slice the context is a thin **facade** over the existing
resolvers, so it centralises the *access point* without changing *when* resolution happens — the
per-call ergonomics the test suite relies on (toggling `CORPUSFM_MODE`, passing a fresh
`archive_dir`) are preserved exactly. A later slice may freeze resolution at build time once the
tests move to the explicit override / dependency-override mechanism. Read mode / auth / storage
through here, not by importing the getters directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class AuthPolicy:
    """Whether a surface enforces authentication + per-user gates.

    `enforces=True`  → server mode: require login and check gates (fail-closed).
    `enforces=False` → standalone / local-dev: open (no auth), the LocalBackend dev/test path.

    A single object so the scattered `if not is_server_mode(): <open>` checks collapse to one
    decision made by the composer. (Future auth methods — OIDC/TOTP — extend this, not the gates.)
    """

    enforces: bool


OPEN = AuthPolicy(enforces=False)
ENFORCING = AuthPolicy(enforces=True)


class AppContext:
    """The runtime graph a surface composes once and passes inward.

    `mode` / `auth_policy` derive from the install marker + env (via `config.is_server_mode`) and
    `storage()` / `app_config()` defer to the existing resolvers — so this facade is behaviour-
    identical to the current per-call discovery. An explicit `mode` / `archive_dir` (for tests or
    deliberate composition) overrides the resolvers.
    """

    def __init__(self, *, archive_dir: Optional[Path] = None, mode: Optional[str] = None):
        self._archive_dir = archive_dir
        self._mode_override = mode

    # ── runtime mode ───────────────────────────────────────────────────────────
    @property
    def mode(self) -> str:
        if self._mode_override is not None:
            return self._mode_override
        from corpusfm.config import is_server_mode
        return "server" if is_server_mode() else "local"

    @property
    def is_server(self) -> bool:
        return self.mode == "server"

    @property
    def auth_policy(self) -> AuthPolicy:
        return ENFORCING if self.is_server else OPEN

    # ── stores / config (deferred to the existing resolvers) ────────────────────
    @property
    def archive_dir(self) -> Optional[Path]:
        return self._archive_dir

    def storage(self):
        """The composed `StorageBackend` — `get_backend(archive_dir)` (FM OData wins on a server
        install; else a LocalBackend for the configured / overridden archive dir)."""
        from corpusfm.storage import get_backend
        return get_backend(self._archive_dir)

    def app_config(self):
        """The app settings — ALWAYS FRESH (packet 006, S8). This deliberately re-reads via
        load_app_config() on every call and is NEVER process-cached on the context.

        Freshness is the contract the whole app relies on: a UI Save (save_app_config), an
        installer write, another process (the scheduler), or a test that monkeypatches
        load_app_config must all be observed by the next read. Because the web AppContext is
        built ONCE at create_app(), caching settings here would go stale across every one of those
        and break the many tests that patch load_app_config. If repeated reads in a single request
        ever become a measured cost, dedupe REQUEST-scoped (memoise on request.state via a
        dependency) — not on this long-lived context.
        """
        from corpusfm.app.app_config import load_app_config
        return load_app_config()

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"AppContext(mode={self.mode!r}, archive_dir={self._archive_dir!r})"
