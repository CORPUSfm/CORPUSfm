"""Landable pages for the per-user "landing page" preference.

`/` redirects to the user's chosen page IF they can reach it (hold its gate; None = ungated),
else falls back to Documentation (the safe universal landing). The account-page dropdown offers
only the pages the user can actually reach. Kept dependency-free so both pages.py (the redirect +
the dropdown) and users.py (pref validation) can import it without a cycle.
"""

from __future__ import annotations

# (key, route, gate, label) — gate None = ungated (every authenticated user). Order = dropdown order.
# Real destinations only: Documentation (a drawer, not a nav page) and Your account (a utility page)
# are reachable elsewhere and are NOT offered as landing choices. Documentation is still the safe
# fallback in landing_target() — as a literal route, not a selectable option.
LANDING_PAGES = [
    ("artifacts", "/artifacts", "library_mcp", "Artifacts"),
    ("monitoring", "/monitoring", "automation", "Monitoring"),
    ("jobs", "/jobs", "automation", "Jobs"),
    ("runs", "/runs", "automation", "Runs"),
    ("tags", "/tags", "library_mcp", "Tags"),
    ("mcp", "/mcp-access", "library_mcp", "MCP"),
    ("isv", "/isv", "patching", "ISV Tool"),
    ("about", "/about", None, "About"),
    ("logs", "/logs", "settings", "Logs"),
    ("settings", "/settings", "settings", "Settings"),
]
_BY_KEY = {k: (route, gate, label) for k, route, gate, label in LANDING_PAGES}
LANDING_KEYS = set(_BY_KEY)


def landing_target(key: str, has_gate) -> str | None:
    """Route for the chosen landing key if accessible, else None. ``has_gate`` is a
    callable(gate_name) -> bool."""
    entry = _BY_KEY.get(key)
    if not entry:
        return None
    route, gate, _ = entry
    return route if (gate is None or has_gate(gate)) else None


def accessible_pages(has_gate) -> list[dict]:
    """The pages this user can land on (for the dropdown), as [{key, label}]."""
    return [{"key": k, "label": label}
            for k, route, gate, label in LANDING_PAGES if gate is None or has_gate(gate)]
