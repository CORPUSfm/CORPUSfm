"""One account-level view of every way a user has authorized MCP access (packet 1182).

Library → MCP is the single user-facing home for MCP access, and a user authorizes it in exactly two
ways:

  * OAUTH CONNECTIONS — an MCP client the user approved through OAuth sign-in. One connection is one
    CONSENT grant (user ↔ client ↔ resource) in the ``OAUTH`` table. The protocol rows underneath it —
    transactions, authorization codes, individual short-lived access credentials — are machinery, never
    shown as separate "sessions": a grant with five live access credentials is still ONE connection.
  * MANUAL TOKENS — named bearer credentials in the ``MCPTOKEN`` table, the advanced/development path
    for clients that cannot complete an OAuth flow.

The two physical stores stay separate (different credential protocols, indexing, expiry and single-use
rules); this module is where the product consolidation happens, so routes and templates never have to
understand two storage engines. Everything here is NON-SECRET: no secret-hash container is read, and a
storage failure is reported as a failure — never rendered as "you have no connections".
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("corpusfm.mcp_connections")

_NAME_MAX = 60          # display bound for a client-supplied name
_ID_PREFIX = 8          # non-secret client-id fragment shown for disambiguation

# Dropped by Unicode CATEGORY, not by an ASCII range. A DCR client name is untrusted text that becomes
# the displayed identity of a connection AND the name inside the Disconnect confirmation — so the
# invisible characters that can make one string read as another must go, not just C0/DEL:
#   Cc  C0/C1 controls + DEL          Cf  FORMAT — RLO/LRO/RLI/LRI/PDI (U+202A-202E, U+2066-2069),
#   Cs  lone surrogates (unencodable)     LRM/RLM, ZWSP, BOM: reorder or hide text with no glyph
#   Co  private use (arbitrary glyph)
# `Zl`/`Zp` are deliberately NOT here: they are whitespace and collapse to a single space below.
# `Cn` (unassigned) is also left in — dropping it would mangle a legitimate name whose script this
# interpreter's Unicode data predates.
_DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co"})


@dataclass
class OAuthConnection:
    """One OAuth connection = one consent grant. Only stored, provable facts appear here — there is no
    device, IP, browser or session-count field anywhere in the OAuth records. The refresh family does
    record when it last ISSUED (packet 1183), but that is protocol bookkeeping used to compute one
    boundary; it is never surfaced as "last used" telemetry."""
    connection_id: str      # the consent row key; only ever used for an ownership-checked disconnect
    client_name: str        # sanitized DCR client_name, or a short client-id label
    client_id_prefix: str   # non-secret, truncated
    resource: str           # the canonical MCP resource this grant is bound to
    granted_at: str         # ISO-8601 UTC (browser renders local)
    scopes: list            # the consented ceiling, filtered to the known gate vocabulary
    # When OAuth sign-in will be needed again: the earlier of this connection's effective inactivity
    # and absolute boundaries (packet 1183). "" when there is no active refresh family to derive it
    # from — an unknown date is left blank rather than guessed.
    reauthorization_due_at: str


def _iso(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(float(epoch or 0), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _gate_vocabulary() -> set:
    try:
        from corpusfm.app.web.users import GATES
        return set(GATES)
    except Exception:
        return set()


def _client_label(client_id: str) -> str:
    return f"Client {client_id[:_ID_PREFIX]}" if client_id else "Unnamed client"


def sanitize_client_name(raw, client_id: str) -> str:
    """A DCR client_name is client-supplied text we never validated — bound and clean it before it
    reaches a page, and fall back to a short client-id label when it is missing or unusable.

    Removal, not rejection: a name is stripped of every invisible/reordering character, whitespace is
    collapsed, and the result must still carry a readable ASCII alphanumeric — a name that is only
    directionality controls, only zero-width characters or only punctuation has no honest display form
    left, so it falls back to the short client-id label rather than showing an empty or misleading cell."""
    if not isinstance(raw, str):
        return _client_label(client_id)
    name = "".join(ch for ch in raw if unicodedata.category(ch) not in _DROP_CATEGORIES)
    name = re.sub(r"\s+", " ", name).strip()
    if not name or not re.search(r"[A-Za-z0-9]", name):
        return _client_label(client_id)
    return name[:_NAME_MAX]


def _client_name_for(client_id: str, *, backend=None) -> str:
    """The display name for a registered client. Reads ONLY the name out of the stored client record —
    redirect URIs and the rest of that untrusted client JSON never travel to the page.

    The lookup is STRICT (packet 1182 review round 5): a failed client read raises
    :class:`~corpusfm.app.web.oauth_store.OAuthStoreUnavailable` instead of degrading into the short
    client-id fallback. The fallback exists for metadata that is genuinely missing or unusable; using it
    for an unread row would let a partial outage render a real connection under a made-up label while the
    view still reported success."""
    from corpusfm.app.web import oauth_store
    rec = oauth_store.get_client_strict(client_id, backend=backend) or {}
    return sanitize_client_name(rec.get("client_name"), client_id)


def oauth_connections_for(uid: str, *, backend=None) -> Optional[list]:
    """This user's OAuth connections as :class:`OAuthConnection` records, or ``None`` when the OAuth
    store is unavailable (an honest error state, distinct from an empty list).

    ``None`` covers BOTH reads this view needs: the consent list and the client-metadata join. Either one
    failing means we cannot honestly describe this user's connections."""
    from corpusfm.app.web import oauth_store
    rows = oauth_store.list_connections_for(uid, backend=backend)
    if rows is None:
        return None
    vocab = _gate_vocabulary()
    out = []
    for c in rows:
        cid = str(c.get("client_id") or "")
        try:
            name = _client_name_for(cid, backend=backend)
        except oauth_store.OAuthStoreUnavailable:
            log.warning("mcp_connections: connection view fail-closed (client metadata unreadable)")
            return None
        out.append(OAuthConnection(
            connection_id=str(c.get("connection_id") or ""),
            client_name=name,
            client_id_prefix=cid[:_ID_PREFIX],
            resource=str(c.get("resource") or ""),
            granted_at=_iso(c.get("granted_at")),
            scopes=sorted(s for s in (c.get("scopes") or []) if s in vocab),
            reauthorization_due_at=_iso(c.get("reauthorization_due_at"))
            if c.get("reauthorization_due_at") else "",
        ))
    return out


def canonical_mcp_address() -> str:
    """The one MCP address a client is pointed at (the external base + the ``/mcp`` mount — the
    canonical no-slash form, packet 1329), or ``""``
    when this box has no usable address. This is the SAME base the OAuth grant is audience-bound to, so
    the address shown is the address that works.

    It is also the ONLY input to "is OAuth available here?" (packet 1220). That answer is derived from
    this value wherever it is needed and is never stored: a boolean beside it could drift from what the
    auth stack actually built, and a derived one cannot."""
    try:
        from corpusfm.app.web.deployment import external_base_url
        base = (external_base_url() or "").rstrip("/")
    except Exception:
        return ""
    # NO trailing slash (packet 1329): the MCP spec's canonical form, the form our audience
    # (`CfmOAuthProvider._canonical`) has always used, and the only form a strictly-matching client
    # (Cursor) accepts. `…/mcp/` keeps working for every existing configuration.
    return base + "/mcp" if base else ""


def account_mcp_view(uid: str, *, backend=None) -> dict:
    """The unified non-secret account view the MCP page renders.

    Each half carries its own ``ok``: one store being unavailable never hides the other, and neither
    outage is ever presented as "nothing here"."""
    address = canonical_mcp_address()
    try:
        from corpusfm.app.web.deployment import certificate_coverage
        certificate = certificate_coverage(address) if address else {"checked": False}
    except Exception:
        certificate = {"checked": False}
    view = {
        "oauth": {"address": address},
        # Beside, not inside, the oauth block: that block is held to exactly {address} by a mutation
        # control (availability stays derived from the address, never a flag beside it), and this is
        # a fact about the served host's certificate, not about availability (packet 1325 R4b).
        "certificate": certificate,
        "oauth_connections": {"ok": True, "error": "", "items": []},
        "manual_tokens": {"ok": True, "error": "", "items": []},
    }
    try:
        conns = oauth_connections_for(uid, backend=backend)
    except Exception:
        log.debug("mcp_connections: OAuth connection view failed", exc_info=True)
        conns = None
    if conns is None:
        view["oauth_connections"] = {
            "ok": False, "items": [],
            "error": "Your OAuth connections could not be read right now — the CORPUSfm database is "
                     "unavailable. This is not a list of none."}
    else:
        view["oauth_connections"]["items"] = [asdict(c) for c in conns]

    from corpusfm.app.web import mcp_tokens
    try:
        toks = mcp_tokens.list_for_or_none(uid, backend=backend)
    except Exception:
        log.debug("mcp_connections: manual token view failed", exc_info=True)
        toks = None
    if toks is None:
        view["manual_tokens"] = {
            "ok": False, "items": [],
            "error": "Your manual tokens could not be read right now — the CORPUSfm database is "
                     "unavailable. This is not a list of none."}
    else:
        view["manual_tokens"]["items"] = [
            {"id": m.id, "name": m.name, "token_id_prefix": (m.token_id[:_ID_PREFIX] if m.token_id else ""),
             "created_at": m.created_at} for m in toks]
    return view
