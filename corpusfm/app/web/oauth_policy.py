"""OAuth connection lifetime policy (packet 1183).

The access credential ROTATES every 8 hours, silently — the client exchanges a refresh credential and
nobody signs in because of it. What bounds an OAuth connection is this policy — two durations per
connection:

  * INACTIVITY expiry — how long a connection may sit unused before OAuth sign-in is required again.
    Every successful rotation advances it.
  * ABSOLUTE expiry — the maximum age of the connection, measured from the OAuth authorization that
    created it. Rotation NEVER advances it.

An administrator picks one of exactly three policies. There is deliberately no arbitrary duration input,
no "never expires", and no per-user exception: the choice is a small, auditable ladder.

Two rules make a policy change honest:

  * TIGHTENING IS IMMEDIATE. A family stores the ceilings it was issued under; validation enforces the
    STRICTER of those and the current administrator policy, so shortening the policy shortens every
    existing connection at once.
  * LOOSENING IS NOT RETROACTIVE. The issued ceiling is a hard cap, so a connection granted under Strict
    never silently becomes a one-year connection because someone later selected Standard.

The policy is read at authorization and at every refresh, so changing it needs no service restart.
"""

from __future__ import annotations

import math

_DAY = 86400

# policy id → (inactivity seconds, absolute-maximum seconds). The complete supported set.
POLICIES: dict[str, tuple[int, int]] = {
    "standard": (30 * _DAY, 365 * _DAY),   # 30 days inactive / 1 year maximum
    "reduced":  (7 * _DAY, 90 * _DAY),     # 7 days inactive / 90 days maximum
    "strict":   (1 * _DAY, 30 * _DAY),     # 1 day inactive / 30 days maximum
}

DEFAULT_POLICY_ID = "standard"

# What the Settings selector renders. Kept here so the label and the enforced duration can never drift.
POLICY_LABELS: dict[str, str] = {
    "standard": "Standard — 30 days inactive / 1 year maximum",
    "reduced":  "Reduced — 7 days inactive / 90 days maximum",
    "strict":   "Strict — 1 day inactive / 30 days maximum",
}


def normalize_policy_id(raw) -> str:
    """The stored value, validated to one of the three supported ids.

    An ABSENT/empty value (a fresh installation, or one that predates this setting) and an
    UNKNOWN/corrupt value both resolve to ``standard`` — the documented default. That is a bounded
    policy, so no reading of a damaged value can produce an unbounded connection; silently substituting
    the tightest policy instead would disconnect a whole team over a config typo without anyone choosing
    it."""
    if not isinstance(raw, str):
        return DEFAULT_POLICY_ID
    v = raw.strip().lower()
    return v if v in POLICIES else DEFAULT_POLICY_ID


def policy_bounds(policy_id: str) -> tuple[int, int]:
    """(inactivity seconds, absolute seconds) for a policy id, normalized."""
    return POLICIES[normalize_policy_id(policy_id)]


class PolicyUnavailable(RuntimeError):
    """The administrator policy AUTHORITY could not be read (packet 1189).

    Deliberately NOT a ``ValueError``, so it can never be mistaken for :class:`IssuedBoundsInvalid` or
    for ``oauth_store._FamilyCorrupt`` — those say "this stored row is damaged", which is a fact about
    one connection. This says "the server cannot state what is allowed right now", which is a fact about
    the server, and the two demand different handling at every site that sees both.

    Why this is not simply the default: enforcement takes the STRICTER of a family's issued ceilings and
    the CURRENT policy. Resolving an unreadable authority to Standard — the LOOSEST policy — deletes the
    current half of that minimum, so an administrator's tightening quietly stops being enforced for the
    length of the outage. Refusing the decision is the honest answer.

    What this must NOT become: substituting Strict instead would disconnect a whole team on a transient
    read error and be indistinguishable from data loss; caching a last-known-good policy would make a
    second source of truth for a security ceiling. Both were considered and rejected."""


class InjectedPolicyInvalid(ValueError):
    """A caller passed ``effective_bounds`` a ``policy=`` that is not a usable (idle, absolute) pair.

    Deliberately NOT :class:`PolicyUnavailable` (review round 3). That exception means "the
    administrator authority could not be read", and the store LOGS it as exactly that — so raising it
    for a programming error would put a false outage in an operator's log and send them looking at
    FileMaker for a bug in our own call site. This is a ValueError because it is a bad argument."""


def current_policy() -> tuple[str, int, int]:
    """The CURRENT administrator policy as ``(policy_id, idle_seconds, absolute_seconds)``.

    Read fresh (no caching) so a change takes effect on the next authorization/refresh without a service
    restart.

    RAISES :class:`PolicyUnavailable` when the authority cannot be read. An absent, empty or UNKNOWN
    stored VALUE is a different matter and still resolves to documented Standard through
    :func:`normalize_policy_id` — a config typo must not disconnect anyone, while an outage must not
    silently loosen anyone."""
    try:
        from corpusfm.app.app_config import SettingsUnavailable, load_authoritative_setting
    except Exception as exc:                  # the settings layer itself is unusable
        raise PolicyUnavailable("browser-connection policy authority is unreadable") from exc
    try:
        # Reads ONLY this key. Going through the full AppConfig would let a malformed UNRELATED field
        # raise and be reported as a policy outage — refusing a policy we could in fact read (found by
        # review). Anything about the VALUE is normalized below, never raised.
        raw = load_authoritative_setting("browser_connection_lifetime", "")
    except SettingsUnavailable as exc:
        raise PolicyUnavailable("browser-connection policy authority is unreadable") from exc
    pid = normalize_policy_id(raw)
    idle, absolute = POLICIES[pid]
    return pid, idle, absolute


class IssuedBoundsInvalid(ValueError):
    """A family's stored issued ceilings are not the schema they were written with — never interpreted.

    The normalization above is for the ADMINISTRATOR SETTING, where substituting the documented default
    is the right answer to a config typo. An ISSUED ceiling is the opposite kind of value: it is the
    non-retroactive cap a connection was granted under, and no other value can stand in for it. Falling
    back to the current policy there is a fail-OPEN — a Strict-issued family missing its 30-day
    ``AbsoluteExpiresAt`` would inherit Standard's year (review round 5)."""


def _issued_number(value, field: str) -> float:
    """One stored lifetime value, validated to a finite positive float, or :class:`IssuedBoundsInvalid`.

    The type is required to be the one the family writer stores — an actual number. Nothing is coerced:
    the string ``"2592000"``, ``None``, a NaN or infinity left by a damaged write, and a non-positive
    value are each a row that cannot be interpreted, not a row to guess at. ``bool`` is excluded because
    it is an ``int`` subclass and would otherwise pass as 1 second."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IssuedBoundsInvalid(f"{field} is not a stored number")
    v = float(value)
    if not math.isfinite(v) or v <= 0:
        raise IssuedBoundsInvalid(f"{field} is not a finite positive value")
    return v


def validate_issued_bounds(issued_idle_seconds, issued_absolute_expires_at,
                           authorized_at) -> tuple[float, float, float]:
    """The family's ISSUED ``(idle_seconds, absolute_expires_at, authorized_at)``, strictly validated.

    Raises :class:`IssuedBoundsInvalid` when any of the three is missing, malformed, non-finite or
    non-positive, and when the pair is internally inconsistent — an absolute expiry that does not FOLLOW
    the authorization it was measured from describes no window at all."""
    idle = _issued_number(issued_idle_seconds, "IdleSeconds")
    authorized = _issued_number(authorized_at, "AuthorizedAt")
    absolute = _issued_number(issued_absolute_expires_at, "AbsoluteExpiresAt")
    if absolute <= authorized:
        raise IssuedBoundsInvalid("AbsoluteExpiresAt does not follow AuthorizedAt")
    return idle, absolute, authorized


def effective_bounds(issued_idle_seconds, issued_absolute_expires_at, authorized_at,
                     *, policy: "tuple[int, int] | None" = None) -> tuple[float, float]:
    """The bounds actually enforced for one family: ``(idle_seconds, absolute_expires_at)``.

    Both are the STRICTER of what the family was issued and what the administrator policy allows NOW.
    ``authorized_at`` anchors the current policy's absolute window to the family's own authorization, so
    tightening measures from when the connection was made, not from the moment the setting changed.

    The issued half is validated first and RAISES :class:`IssuedBoundsInvalid` rather than degrading to
    the current policy — see that class. The current half RAISES :class:`PolicyUnavailable` when the
    authority is unreadable, rather than contributing the loosest policy to the ``min`` and thereby
    removing its own constraint.

    ``policy`` supplies an ALREADY-READ ``(idle_seconds, absolute_seconds)`` instead of reading again.
    An operation that mutates state must take its one policy read BEFORE the first write and then pass
    it here: re-reading part-way through means a failure can land after a code is consumed, prior
    credentials are revoked, or a refresh generation is spent — leaving the user worse off than before
    the outage. Review of packet 1189 found exactly that in the exchange and rotation paths."""
    issued_idle, issued_absolute, authorized = validate_issued_bounds(
        issued_idle_seconds, issued_absolute_expires_at, authorized_at)
    if policy is None:
        _pid, cur_idle, cur_absolute = current_policy()
    else:
        # An injected policy bypasses current_policy() entirely, so it gets the same scrutiny every
        # other number in this module gets. Nothing here can widen a ceiling on its own — the issued
        # half still bounds the min — but an unvalidated tuple is an API contract waiting to be broken
        # by a future caller (found by review). It must be a pair of finite positive numbers.
        try:
            cur_idle, cur_absolute = policy
        except (TypeError, ValueError) as exc:
            raise InjectedPolicyInvalid("an injected policy is not an (idle, absolute) pair") from exc
        for _v, _name in ((cur_idle, "idle"), (cur_absolute, "absolute")):
            if isinstance(_v, bool) or not isinstance(_v, (int, float)):
                raise InjectedPolicyInvalid(f"an injected policy's {_name} is not a number")
            try:
                # An int is unbounded in Python; float() on a big enough one raises OverflowError
                # rather than returning inf, so the finiteness check below would never be reached
                # (review round 3 — the validation promised more than it delivered).
                _f = float(_v)
            except (OverflowError, ValueError) as exc:
                raise InjectedPolicyInvalid(
                    f"an injected policy's {_name} is not representable") from exc
            if not math.isfinite(_f) or _f <= 0:
                raise InjectedPolicyInvalid(
                    f"an injected policy's {_name} is not a finite positive number")
    return min(issued_idle, float(cur_idle)), min(issued_absolute, authorized + float(cur_absolute))
