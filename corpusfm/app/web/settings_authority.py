"""Packet 1396 — the shared authority gate for browser Settings writes.

In FileMaker mode a transient failure to READ the authoritative SETTING record must never
(a) present editable defaults, nor (b) let a read-then-write Settings route persist a full
``AppConfig`` that overwrites still-valid configuration — including external-auth and
browser-lifetime policy — with blanks. Every web route that calls ``save_app_config`` reads through
this first: a successful read (an authoritatively EMPTY record included, which yields
``AppConfig()`` defaults) returns the config; an outage or malformed record returns an explicit 503
and the route writes nothing and dispatches no secondary action.

The MCP-address acknowledgement (``mcp_address_prompt``) is the original strict caller; it reads a
single flag and already passes ``require_authority=True`` directly. CLI ``save_app_config`` callers
are outside this browser-Settings frame.
"""
from __future__ import annotations

from typing import Optional, Tuple

from fastapi.responses import JSONResponse


UNAVAILABLE_MESSAGE = (
    "Settings are temporarily unavailable — the configuration store could not be read, so nothing "
    "was changed. Reload Settings and try again."
)


def load_settings_authority() -> Tuple[Optional[object], Optional[JSONResponse]]:
    """``(AppConfig, None)`` on a good read; ``(None, 503-JSONResponse)`` when the FileMaker settings
    authority is unavailable or malformed. A route calls this in place of a permissive
    ``load_app_config()`` and returns the response half unchanged when it is not ``None``."""
    from corpusfm.app.app_config import load_app_config, SettingsUnavailable
    try:
        return load_app_config(require_authority=True), None
    except SettingsUnavailable:
        return None, JSONResponse(
            {"ok": False, "unavailable": True, "error": UNAVAILABLE_MESSAGE},
            status_code=503)
