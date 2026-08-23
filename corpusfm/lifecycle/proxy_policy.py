"""Stored proxy policy, and the PURE decision that turns policy + observation into a plan.

Packet 1246-06 §5 separates eight concerns; this module owns two of them and deliberately touches no
others:

**Policy** — what CORPUSfm is RESPONSIBLE for, per type. It is not a claim that the front exists:
`schema.ProxyPolicyEntry`'s own docstring says so (*"not a claim that the front exists"*), which is
why `detected` is a separate field. **Every supported type is `managed` by default, INCLUDING absent
ones**; mutation happens only for an installed one; a managed absent type stays managed and is
reconciled when it later appears.

**Decision** — `decide()` is PURE. No filesystem, no subprocess, no clock. That is what makes the
whole managed/ignored × detected × active × drift table testable on its own, which is the only way a
table with that many cells gets checked at all.

**Not here:** rendering, writing, validating, activating, journaling, or anything that needs a
credential. Those are `proxy_transaction` and the OS-native executors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from .proxy_inventory import (
    BLOCK_ABSENT, BLOCK_CURRENT, BLOCK_DRIFTED, BLOCK_INVALID, ProxyObservation,
)
from .schema import PROXY_POLICIES, PROXY_TYPES, ProxyPolicyEntry

MANAGED = "managed"
IGNORED = "ignored"
assert (MANAGED, IGNORED) == PROXY_POLICIES

# The CLI selector. It is NEVER a stored value, never a manifest key, and never a PROXY_TYPES member.
ALL_SELECTOR = "all"

# What a plan says should happen to one type.
ACTION_NONE = "none"                       # nothing to do
ACTION_PUBLISH = "publish"                 # render + publish + validate
ACTION_REMOVE = "remove"                   # remove owned routing
ACTION_REFUSE = "refuse"                   # refuse BEFORE any publication
PLAN_ACTIONS: tuple[str, ...] = (ACTION_NONE, ACTION_PUBLISH, ACTION_REMOVE, ACTION_REFUSE)

# Activation mechanisms — per §6.2, cohorts are formed per MECHANISM, not per platform.
MECH_FMSADMIN_RESTART = "fmsadmin-restart"   # Linux fms-nginx / apache, active
MECH_IIS_PUBLISH = "iis-publish"             # Windows iis: publication IS activation
MECH_NONE = "none"                           # inactive front, or nothing changed
MECH_UNAVAILABLE = "unavailable"             # retained: a front whose activation nobody can perform
#: ACTIVE Windows Claris nginx. Its executor stages exact bytes and retains the before-image; the
#: lifecycle provider activates through the same operation-scoped fmsadmin restart contract used by
#: active Linux fronts. It is a distinct mechanism so planning and durable evidence still name the
#: actual front rather than pretending Windows is Linux.
MECH_CLARIS_ACTIVE = "claris-active"
FMSADMIN_RESTART_MECHANISMS = (MECH_FMSADMIN_RESTART, MECH_CLARIS_ACTIVE)
MECHANISMS: tuple[str, ...] = (
    MECH_FMSADMIN_RESTART, MECH_IIS_PUBLISH, MECH_CLARIS_ACTIVE, MECH_NONE, MECH_UNAVAILABLE,
    "unknown",
)


class ProxyPolicyUnavailable(Exception):
    """Stored policy could not be read. Never falls back, never guesses."""


@dataclass(frozen=True)
class ProxyPolicyView:
    """The stored policy, projected read-only. A value; it authorizes nothing by itself."""

    entries: Mapping[str, ProxyPolicyEntry]

    def policy_for(self, proxy_type: str) -> str:
        """`managed` unless an entry says otherwise.

        **The default is the RULE, not a convenience** (D9: *"Default fresh policy manages every
        supported type"*). An unrecorded type is CORPUSfm's responsibility; whether it can be acted
        on is a separate question answered by `detected`.
        """
        entry = self.entries.get(proxy_type)
        return entry.policy if entry is not None else MANAGED


@dataclass(frozen=True)
class PlannedType:
    """One type's decision. Carries WHY, so a refusal can explain itself without re-deriving."""

    proxy_type: str
    policy: str
    action: str
    mechanism: str
    installed: bool
    active: bool | None
    reason: str = ""
    operator_steps: tuple[str, ...] = ()
    # The rendering this type SHOULD end up with. Carried on the plan so the engine can verify the
    # executor's readback against it (ruling 3) without re-rendering and without re-deriving the
    # paths that produced it.
    desired: str | None = None


@dataclass(frozen=True)
class ProxyPlan:
    """A whole run's decision, before anything is touched."""

    types: tuple[PlannedType, ...]
    credentials_required: bool
    refusals: tuple[PlannedType, ...] = ()

    @property
    def mutating(self) -> tuple[PlannedType, ...]:
        return tuple(t for t in self.types if t.action in (ACTION_PUBLISH, ACTION_REMOVE))

    def cohort(self, mechanism: str) -> tuple[PlannedType, ...]:
        """The activation cohort for one mechanism (§6.2). Cohorts are per MECHANISM."""
        return tuple(t for t in self.mutating if t.mechanism == mechanism)


@dataclass(frozen=True)
class PolicyRequest:
    """What the caller asked for. `types` is already expanded — `all` never reaches here.

    `desired` is the THIRD fact planning needs (ruling 4): the fingerprint of the rendering this
    installation *should* have for its current prefix, port and mandatory MCP routes. Without it,
    "already matches the intended rendering" was a claim nothing had checked, and `reconcile` could
    not converge on a changed prefix — it saw a valid marker pair and called it current.
    """

    verb: str                                  # status | add | ignore | remove | reconcile
    types: tuple[str, ...]
    desired: Mapping[str, str] = field(default_factory=dict)   # proxy_type -> desired fingerprint
    extra: dict = field(default_factory=dict)


def expand_selector(value: str | None) -> tuple[str, ...]:
    """`all` expands HERE, at the boundary, and nowhere deeper.

    Keeping the expansion at the edge is what makes "`all` is a selector, never a stored type" true
    mechanically rather than by discipline: nothing downstream ever sees the token.
    """
    if value is None or value == ALL_SELECTOR:
        return tuple(PROXY_TYPES)
    if value not in PROXY_TYPES:
        raise ValueError(
            f"{value!r} is not a supported proxy type; expected one of "
            f"{', '.join(PROXY_TYPES)} or {ALL_SELECTOR!r}"
        )
    return (value,)


def read_proxy_policy() -> ProxyPolicyView:
    """The stored policy, from the published manifest and from nowhere else.

    **Takes no arguments.** A `layout` (or any other) seam here would be an alternate authority
    selector on the boundary built to remove alternate authority — the ruling already applied to
    `read_published_installation()` and to `app_paths.development_override`.
    """
    from .published import InstallationNotPublished, read_published_installation

    try:
        published = read_published_installation()
    except InstallationNotPublished as exc:
        raise ProxyPolicyUnavailable(
            f"{exc}; proxy policy has no authority on this installation"
        ) from exc
    return ProxyPolicyView(entries=dict(published.proxy_policy or {}))


# ── the decision table ────────────────────────────────────────────────────────────────────────

_CLARIS_ACTIVE_STEPS_MUTATE = (
    "Disable 'Use Nginx Web Server' in the FMS Admin Console (the front returns to IIS).",
    "Run: corpusfm-proxy reconcile claris-nginx",
    "Re-enable 'Use Nginx Web Server' — the enable transition loads the edit.",
)
_CLARIS_ACTIVE_STEPS_REMOVE = (
    "Disable 'Use Nginx Web Server' in the FMS Admin Console.",
    "Perform the removal or uninstall while it is inactive.",
    "Re-enable 'Use Nginx Web Server' if Claris nginx should remain the selected front.",
)


# The activation state could not be established. NOT a mechanism — a refusal to name one (ruling 3).
MECH_UNKNOWN = "unknown"


def mechanism_for(obs: ProxyObservation) -> str:
    """Which activation mechanism this front's change would need. **There is no single answer.**

    **`active is None` is not `active is False`, and this function is where that used to be lost.**
    Every branch below read `obs.active` as a truthiness test, so an undeterminable state — the
    ordinary Windows answer before the probe existed — resolved to the *inactive* mechanism. For
    Claris nginx that turned §6.4's absolute refusal into `MECH_NONE`, i.e. publish into the live
    configuration and report success. Unknown now has its own word.
    """
    if obs.proxy_type == "iis":
        if obs.installed and obs.active is None:
            return MECH_UNKNOWN
        return MECH_IIS_PUBLISH                     # publication IS activation; no FMS restart
    if obs.proxy_type == "claris-nginx":
        # Unknown remains a refusal. Active uses the provider's authenticated restart transaction;
        # inactive needs no activation beyond publication.
        if obs.installed and obs.active is None:
            return MECH_UNKNOWN
        # An ACTIVE front now has a mechanism, because its executor can stage and restore exact bytes.
        # Inactive is unchanged: publication alone is the whole change, and nothing needs reloading.
        return MECH_CLARIS_ACTIVE if obs.active else MECH_NONE
    # Linux fms-nginx / apache
    if obs.installed and obs.active is None:
        return MECH_UNKNOWN
    if obs.active:
        return MECH_FMSADMIN_RESTART
    return MECH_NONE


def decide(view: ProxyPolicyView, observations, *, request: PolicyRequest) -> ProxyPlan:
    """PURE. Policy + observation + request -> plan. No I/O of any kind."""
    by_type = {o.proxy_type: o for o in observations}
    planned: list[PlannedType] = []

    for proxy_type in request.types:
        obs = by_type.get(proxy_type)
        if obs is None:
            raise ValueError(f"no observation for {proxy_type!r}")
        policy = view.policy_for(proxy_type)
        mech = mechanism_for(obs)
        planned.append(_decide_one(proxy_type, policy, obs, mech, request.verb,
                                   block=effective_block(view, obs),
                                   desired=request.desired.get(proxy_type)))

    refusals = tuple(t for t in planned if t.action == ACTION_REFUSE)
    needs_creds = any(t.mechanism in FMSADMIN_RESTART_MECHANISMS for t in planned
                      if t.action in (ACTION_PUBLISH, ACTION_REMOVE))
    return ProxyPlan(types=tuple(planned), credentials_required=needs_creds, refusals=refusals)


def effective_block(view: ProxyPolicyView, obs: ProxyObservation) -> str:
    """The block state INCLUDING drift — recomputed here, never stored (§4).

    Drift is a comparison between two facts that live in different places: the digest of what is on
    disk (an observation) and `config_fingerprint`, the digest of the last rendering CORPUSfm
    successfully applied (stored policy). Discovery cannot see the second and policy cannot see the
    first, so neither module can answer alone — which is exactly why an earlier version, asking
    discovery to decide it, produced a state that could never occur.

    A recorded entry with no fingerprint is NOT drift: it means this installation has a block it
    never recorded applying, which is the ordinary state of a policy written before this packet
    existed. Calling that drift would refuse every first reconcile on an upgraded box.
    """
    if obs.owned_block != BLOCK_CURRENT:
        return obs.owned_block
    entry = view.entries.get(obs.proxy_type)
    if entry is None or not entry.config_fingerprint:
        return BLOCK_CURRENT
    return BLOCK_CURRENT if entry.config_fingerprint == obs.fingerprint else BLOCK_DRIFTED


_STATUS_STEPS_UNKNOWN = (
    "Establish which web front FileMaker Server is serving with (FMS Admin Console -> "
    "Configuration -> Web: 'Use Nginx Web Server'), then re-run.",
)


def _decide_one(proxy_type: str, policy: str, obs: ProxyObservation, mech: str,
                verb: str, *, block: str, desired: str | None = None) -> PlannedType:
    def made(action, reason="", steps=()):
        return PlannedType(proxy_type=proxy_type, policy=policy, action=action, mechanism=mech,
                           installed=obs.installed, active=obs.active, reason=reason,
                           operator_steps=steps, desired=desired)

    # **`status` is NOT short-circuited (ruling 6).** It used to return `ACTION_NONE` for every
    # input, which made `mutation_needed`, `refusals` and `fms_admin_login_required` structurally
    # always empty — so the verb §10 makes the `check` successor could never answer the question
    # 1246-04 is told to ask it. It now evaluates the stored policy exactly as `reconcile` would;
    # what makes it read-only is that the CALLER never executes the plan, which `cli` enforces and
    # tests assert by counting executor calls, journal writes and manifest generations.
    planning_verb = "reconcile" if verb == "status" else verb

    # `ignore` changes POLICY only. It is permitted even where no activation mechanism exists,
    # because it deliberately leaves existing routing exactly as it is.
    if planning_verb == "ignore":
        return made(ACTION_NONE, "policy only; existing routing is left untouched")

    if not obs.installed:
        # A managed ABSENT type stays managed and is reconciled when it appears. Not a failure.
        return made(ACTION_NONE, "not installed on this machine; policy is retained")

    if block == BLOCK_INVALID:
        return made(ACTION_REFUSE,
                    "the CORPUSfm markers in this configuration are neither absent nor one balanced "
                    "pair; refusing to reason about it",
                    ("Restore the configuration from backup, then re-run.",))

    # An ACTIVE Claris nginx front has NO activation mechanism at all, so `add`, `reconcile` AND
    # `remove` refuse BEFORE any filesystem or manifest publication — and `remove` refuses BEFORE
    # recording `ignored`. Publishing a change that can never be activated would strand it; recording
    # `ignored` while the routing survives would make the manifest say CORPUSfm stopped managing a
    # front it is still visibly serving through.
    # The activation state could not be established, so the activation REQUIREMENT cannot be
    # established either — and a change that may need a restart nobody can plan is exactly what
    # §7.2 refuses before publication (ruling 3). `ignore` already returned above.
    if mech == MECH_UNKNOWN:
        return made(ACTION_REFUSE,
                    "this front is installed but CORPUSfm could not establish whether it is the "
                    "active one, so the activation this change would require cannot be planned",
                    _STATUS_STEPS_UNKNOWN)

    if mech == MECH_UNAVAILABLE and planning_verb in ("add", "reconcile", "remove"):
        # Retained for any front whose activation genuinely has no performer. Claris nginx no longer
        # reaches here: `mechanism_for` answers MECH_CLARIS_ACTIVE for an active one (packet 1252).
        steps = _CLARIS_ACTIVE_STEPS_REMOVE if planning_verb == "remove" \
            else _CLARIS_ACTIVE_STEPS_MUTATE
        return made(ACTION_REFUSE,
                    "this front is ACTIVE and CORPUSfm has no supported activation for it, so this "
                    "change could be published but neither activated nor verified", steps)

    if planning_verb == "remove":
        if block == BLOCK_ABSENT:
            return made(ACTION_NONE, "no recognizable CORPUSfm routing present")
        return made(ACTION_REMOVE, "removing recognizable CORPUSfm-owned routing")

    # add / reconcile
    if policy == IGNORED and planning_verb == "reconcile":
        # `reconcile` OBSERVES an ignored type; it never alters it.
        return made(ACTION_NONE, "policy is ignored; reporting only")

    if block == BLOCK_DRIFTED:
        # `reconcile` converges, but never over an unexplained operator edit.
        return made(ACTION_REFUSE,
                    "the CORPUSfm-owned routing was edited outside CORPUSfm; refusing to overwrite "
                    "an unexplained change",
                    ("Inspect the marked block, then either restore it or run "
                     "`corpusfm-proxy remove` and re-add.",))

    if block == BLOCK_CURRENT:
        # **A valid marker pair alone is not "current" (ruling 4).** The block agrees with what was
        # last applied; whether it agrees with what this installation should NOW have is a separate
        # question, and answering it needs the desired rendering. Without that comparison a changed
        # `web.prefix` produced a `reconcile` that did nothing and reported success.
        if desired is None:
            return made(ACTION_REFUSE,
                        "the intended rendering for this front could not be computed, so whether "
                        "the existing routing is current cannot be established",
                        _STATUS_STEPS_UNKNOWN)
        if obs.fingerprint == desired:
            return made(ACTION_NONE, "routing matches the intended rendering")
        return made(ACTION_PUBLISH, "the routing differs from the intended rendering for this "
                                    "installation's prefix and port")

    return made(ACTION_PUBLISH, "publishing CORPUSfm routing")


def candidate_entry(planned: PlannedType, obs: ProxyObservation, *, result: str,
                    fingerprint: str | None) -> ProxyPolicyEntry:
    """The `ProxyPolicyEntry` candidate for one type after its transaction settled.

    `config_fingerprint` is the last SUCCESSFULLY APPLIED rendering — so it is carried forward
    unchanged unless this operation actually published one. Drift is recomputed against it; it is
    never a record of "what is on disk now", which would go stale the moment anyone edited anything.
    """
    return ProxyPolicyEntry(
        policy=planned.policy,
        detected=bool(planned.installed),
        active=planned.active,
        config_location=obs.config_location,
        config_fingerprint=fingerprint,
        last_result=result,
    )


__all__ = [
    "ACTION_NONE", "ACTION_PUBLISH", "ACTION_REFUSE", "ACTION_REMOVE", "ALL_SELECTOR",
    "IGNORED", "MANAGED", "MECHANISMS", "MECH_FMSADMIN_RESTART", "MECH_IIS_PUBLISH", "MECH_NONE",
    "MECH_CLARIS_ACTIVE", "MECH_UNAVAILABLE", "MECH_UNKNOWN", "PLAN_ACTIONS", "PlannedType", "PolicyRequest", "ProxyPlan",
    "ProxyPolicyUnavailable", "ProxyPolicyView", "candidate_entry", "decide", "effective_block",
    "expand_selector",
    "mechanism_for", "read_proxy_policy",
]
