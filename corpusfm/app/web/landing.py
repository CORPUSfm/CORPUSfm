"""Landable pages for the per-user "landing page" preference.

`/` redirects to the user's chosen page IF they can reach it (hold its gate; None = ungated),
else falls back to Documentation (the safe universal landing). The account-page dropdown offers
only the pages the user can actually reach. Kept dependency-free so both pages.py (the redirect +
the dropdown) and users.py (pref validation) can import it without a cycle.
"""

from __future__ import annotations

# (key, route, gate, label, server_only) — gate None = ungated (every authenticated user).
# Order = dropdown order. `server_only` is DEPLOYMENT availability, not a gate: MCP connection
# self-service is per-user, and the local development path has no users, so the page and its four
# account APIs refuse there (packet 1332). The key stays in LANDING_KEYS so an existing server user's
# stored preference remains valid — availability is decided at read time, never by rewriting prefs.
# Real destinations only: Documentation (a drawer, not a nav page) and Your account (a utility page)
# are reachable elsewhere and are NOT offered as landing choices. Documentation is still the safe
# fallback in landing_target() — as a literal route, not a selectable option.
LANDING_PAGES = [
    ("artifacts", "/artifacts", "library_mcp", "Artifacts", False),
    ("monitoring", "/monitoring", "automation", "Monitoring", False),
    ("jobs", "/jobs", "automation", "Jobs", False),
    ("runs", "/runs", "automation", "Runs", False),
    ("tags", "/tags", "library_mcp", "Tags", False),
    ("mcp", "/mcp-access", "library_mcp", "MCP", True),
    ("isv", "/isv", "patching", "ISV Tool", False),
    ("about", "/about", None, "About", False),
    ("logs", "/logs", "settings", "Logs", False),
    ("settings", "/settings", "settings", "Settings", False),
]
_BY_KEY = {k: (route, gate, label, srv) for k, route, gate, label, srv in LANDING_PAGES}
LANDING_KEYS = set(_BY_KEY)


def landing_target(key: str, has_gate, *, server_mode: bool) -> str | None:
    """Route for the chosen landing key if accessible, else None. ``has_gate`` is a
    callable(gate_name) -> bool. ``server_mode`` is the composed deployment mode, passed in
    explicitly so this module stays dependency-free and the caller cannot forget it.

    A stored `mcp` choice on the local path returns None — the caller's existing `/docs` fallback
    then applies. The preference itself is left untouched."""
    entry = _BY_KEY.get(key)
    if not entry:
        return None
    route, gate, _, server_only = entry
    if server_only and not server_mode:
        return None
    return route if (gate is None or has_gate(gate)) else None


def accessible_pages(has_gate, *, server_mode: bool) -> list[dict]:
    """The pages this user can land on (for the dropdown), as [{key, label}]."""
    return [{"key": k, "label": label}
            for k, route, gate, label, server_only in LANDING_PAGES
            if (gate is None or has_gate(gate)) and not (server_only and not server_mode)]
