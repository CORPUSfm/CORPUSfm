"""The first-sign-in MCP address confirmation (packet 1326) — one item, once per installation.

WHY IT EXISTS. A box ASSERTS its own MCP address at startup from *locally detected* evidence — the
weakest of the three grades the Unknowable-Install Principle names — and everything binds to it: the
OAuth resource, the 401 challenge, every connection's audience and the address the MCP tab hands out.
The product may not make an operator supply that address before it will work (consequence 2: input is an
OVERRIDE, never a precondition), so the correction is offered at the first moment there is a human who
can judge it, and never again.

WHAT LIVES HERE. The read-side projection and the two facts the prompt needs that nothing else computed:
a de-duplicated candidate list, and whether this box holds ANY MCP credential. Writes stay where they
already are — the address goes through ``POST /api/settings/external-address`` and the durable mark
through ``save_app_config`` — so there is no second validator, no second install.yaml writer and no
second restart scheduler.
"""
from __future__ import annotations

from typing import Optional

CREDENTIALS_UNKNOWN = "unknown"


def acknowledged() -> Optional[bool]:
    """Whether this installation has been prompted. ``None`` when the settings AUTHORITY cannot be read.

    An unreadable authority is NOT "unset" (Codex scope §1): showing the prompt from a fallback default
    would prompt a box that may already have answered, and — worse — a dismissal written against that
    fallback would report success while the real record still says otherwise."""
    from corpusfm.app.app_config import SettingsUnavailable, load_app_config
    try:
        return bool(load_app_config(require_authority=True).initial_mcp_address_acknowledged)
    except SettingsUnavailable:
        return None
    except Exception:
        return None


def acknowledge() -> bool:
    """Set the durable mark, freshly loading the authoritative config first so nothing else is written
    back from a stale copy. False when the write did not certainly commit — the caller must then NOT
    report a dismissal, and must not schedule a restart on the strength of it."""
    from corpusfm.app.app_config import load_app_config, save_app_config
    try:
        cfg = load_app_config(require_authority=True)
        if cfg.initial_mcp_address_acknowledged:
            return True
        cfg.initial_mcp_address_acknowledged = True
        save_app_config(cfg)
        return True
    except Exception:
        return False


def box_holds_any_mcp_credential() -> Optional[bool]:
    """Does ANY credential exist on this box — an unrevoked OAuth family, or any manual token?

    ``None`` when either store cannot be read: the caller then says conservatively that clients COULD
    need to sign in again, because the box could not confirm that none exist. This replaces the island's
    old assumption that every address change costs somebody a re-sign-in — true on a box in use, false
    on the fresh installation this prompt is written for, and never worth guessing (Codex scope §4).

    Deliberately bounded to a yes/no: no connection, owner or token detail leaves these stores for this
    question."""
    from corpusfm.app.web import mcp_tokens, oauth_store
    oauth = _any_oauth_family(oauth_store)
    if oauth is None:
        return None
    if oauth:
        return True
    tokens = _any_manual_token(mcp_tokens)
    if tokens is None:
        return None
    return bool(tokens)


def _any_oauth_family(oauth_store) -> Optional[bool]:
    engine = oauth_store._engine(None)
    if engine is None:
        return None
    try:
        for row in engine.list_all(oauth_store._TBL):
            jor = row.jor or {}
            if jor.get("Type") == "family" and jor.get("State") != oauth_store.FAMILY_REVOKED:
                return True
        return False
    except Exception:
        return None


def _any_manual_token(mcp_tokens) -> Optional[bool]:
    engine = mcp_tokens._engine(None)
    if engine is None:
        return None
    try:
        return any(True for _ in engine.list_all(mcp_tokens._TBL))
    except Exception:
        return None


def address_candidates(projection: dict) -> list:
    """Every base address this box can offer, de-duplicated, strongest evidence first: the address this
    browser request actually arrived on, then what the box currently asserts, then each non-loopback
    interface it can enumerate. No probe, no reachability claim — a candidate is a candidate."""
    from corpusfm.app.web.deployment import enumerate_local_bases
    out: list = []
    seen: set = set()

    def add(value: str, evidence: str) -> None:
        v = (value or "").rstrip("/")
        if not v or v in seen:
            return
        seen.add(v)
        out.append({"base": v, "evidence": evidence})

    add(projection.get("detected", ""), "reached in this browser")
    add(projection.get("serving", ""), "serving now")
    # The STORED value is its own candidate when it differs from what the process serves — an address
    # saved without the restart completing (Codex F1). Collapsing the pair with `serving or value` hid
    # the address already waiting to become live and offered the old running one in its place.
    if (projection.get("value") or "").rstrip("/") != (projection.get("serving") or "").rstrip("/"):
        add(projection.get("value", ""), "saved, awaiting restart")
    try:
        for base in enumerate_local_bases():
            add(base, "detected on a local interface")
    except Exception:
        pass
    return out


def reauthorize_warning(new_value: str, *, credentials: Optional[bool]) -> str:
    """The one re-sign-in sentence, measured rather than assumed. Empty ONLY when the box authoritatively
    holds no credential at all."""
    if credentials is False:
        return ""
    hedge = ("" if credentials else
             " (this box could not confirm whether any client is connected, so this may not apply)")
    if not new_value:
        return ("OAuth sign-in has no address to serve until one is set; existing MCP connections will "
                "stop working." + hedge)
    return ("Existing OAuth / MCP connections will need to sign in again after the address changes."
            + hedge)
