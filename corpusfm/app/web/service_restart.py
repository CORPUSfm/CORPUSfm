"""Ask the running CORPUSfm service to restart itself, through the ONE supported mechanism.

Some settings cannot take effect in the process that saved them. The MCP address is the standing case:
the auth composition and the host-root AS/operational routes are selected ONCE, at process start
(``mcp/server.py`` builds ``FastMCP(..., auth=_build_auth())`` at module scope), so a changed address is
served only after a restart. This module is where a route asks for one — it does not decide that one is
needed, and it never restarts anything implicitly.

The scheduler is the updater's own supported path (supervised SIGTERM / self-exec), fired shortly AFTER
the response flushes, and it is injectable (``restart_scheduler``) so a settings-save in a test never
kills the runner.

Packet 1220 emptied the other half of this module. It used to also answer "is browser OAuth serving in
THIS process?", which existed only because a flag could be flipped in a stack that was already built.
There is no flag, so there is no such question — OAuth is available whenever the box has a usable MCP
address.
"""

from __future__ import annotations

import logging

log = logging.getLogger("corpusfm.service_restart")


def _default_scheduler(supervised: bool) -> None:
    """Delegate to the updater's supported restart scheduler (supervised SIGTERM / standalone
    self-exec, fired ~1s after the response flushes)."""
    from corpusfm.server.update_service import _default_restart_scheduler
    _default_restart_scheduler(supervised)


# Injectable seam: tests replace this with a no-op so a settings-save never terminates the test runner.
restart_scheduler = _default_scheduler


def request_service_restart() -> bool:
    """Schedule the supported CORPUSfm service restart so a saved change takes effect. Best-effort:
    returns True if a restart was scheduled, False if it could not be (logged, never raises)."""
    try:
        from corpusfm.config import is_server_mode
        restart_scheduler(is_server_mode())
        return True
    except Exception:
        log.warning("service_restart: could not schedule the service restart", exc_info=True)
        return False
