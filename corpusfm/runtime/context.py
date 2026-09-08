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

import threading
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
    `app_config()` defers to `load_app_config()` on every call. An explicit `mode` / `archive_dir`
    (for tests or deliberate composition) overrides the resolvers.

    `storage()` is the one exception to per-call discovery: it resolves once and retains the
    backend for this context's lifetime (see its docstring). Settings are still read fresh; what
    is retained is the connection-holding object, not any value read through it.
    """

    def __init__(self, *, archive_dir: Optional[Path] = None, mode: Optional[str] = None):
        self._archive_dir = archive_dir
        self._mode_override = mode
        self._backend = None
        self._backend_lock = threading.Lock()

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
        """The composed `StorageBackend`, resolved ONCE per context and retained (packet 1361-01).

        `get_backend()` is not a lookup — on a published installation it re-reads the installation
        record three times, loads the held credential, and constructs a fresh
        `FileMakerODataBackend`, whose per-thread session then pays a full TLS handshake on its
        first request. Measured on Windows that is ~110ms every time, against ~6ms once the
        session exists, so resolving per call made every settings read cost a handshake.

        Retention is per CONTEXT, never a module global: separate contexts (and an explicit
        `archive_dir` override) keep separate backends, which is what lets a test compose its own.

        Two properties this must not lose:

        * **A failure is never retained.** `get_backend()` raising leaves `_backend` unset, so the
          next call retries. Caching a failed resolution would convert a transient storage outage
          into a permanently broken context.
        * **The object is stable across an outage.** The backend holds no connection of its own —
          its sessions are thread-local and `requests` reconnects underneath them — so a database
          close/reopen recovers without replacing it.
        """
        backend = self._backend
        if backend is not None:
            return backend
        with self._backend_lock:
            # Re-check under the lock: a concurrent first call may have resolved while we waited,
            # and two backends would mean two session pools and two handshakes.
            if self._backend is None:
                from corpusfm.storage import get_backend
                resolved = get_backend(self._archive_dir)
                if resolved is None:
                    return None          # incomplete — nothing to retain, retry next call
                self._backend = resolved
            return self._backend

    def app_config(self):
        """The app settings — ALWAYS FRESH (packet 006, S8). This deliberately re-reads via
        load_app_config() on every call and is NEVER process-cached on the context.

        It reads through `storage()` — the backend this context already retains (packet 1361-01) —
        so the read costs a request, not a fresh backend and a TLS handshake. That is a change of
        ROUTE, not of freshness: every call still goes to the authority. `storage()` returning None
        leaves `backend=None`, which is `load_app_config`'s own "resolve for yourself" and the exact
        behaviour that preceded this.

        Freshness is the contract the whole app relies on: a UI Save (save_app_config), an
        installer write, another process (the scheduler), or a test that monkeypatches
        load_app_config must all be observed by the next read. Because the web AppContext is
        built ONCE at create_app(), caching settings here would go stale across every one of those
        and break the many tests that patch load_app_config. If repeated reads in a single request
        ever become a measured cost, dedupe REQUEST-scoped (memoise on request.state via a
        dependency) — not on this long-lived context.
        """
        from corpusfm.app.app_config import load_app_config
        return load_app_config(backend=self.storage())

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"AppContext(mode={self.mode!r}, archive_dir={self._archive_dir!r})"
