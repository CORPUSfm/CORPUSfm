"""The CORPUSfm Admin-API machine identity: facts, relations, and one ordered classifier.

Packet 1246-07. **The subject is the installation's machine identity at the co-located FileMaker
Server** — a thing that is present or absent, working or broken, and removable — not "PKI", which is
merely how it is currently implemented (an RSA keypair and an RS256 JWT). Naming the component for
the mechanism is what produced a public ``corpusfm pki generate`` toolbox for what should be an
automatic invariant.

**Six FACT axes, classified. Mode and store-existence are NOT axes.** Five earlier framings of this
model failed the same way: one enum was asked to carry independent facts, a credential requirement
and an applicability question at once, and every attempt to resolve the resulting overlap with a
better label or a longer precedence paragraph produced a new overlap. The axes are therefore
separate, ``classify`` takes facts only, and totality is proven by enumerating the finite product
rather than argued (``tests/test_admin_identity.py::test_classifier_is_total``).

**Two things deliberately absent from ``IdentityState``.** A credential requirement is an *operation
output* (``apply_mode_policy``), and FMS absence is an *applicability result* (the ``NOT_APPLICABLE``
tag). Both were once states, and both were category errors: a state answers "what is this
installation's identity", and neither question does.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class FmsPresence(str, Enum):
    """Whether FileMaker Server is installed on THIS box.

    Established from authoritative LOCAL installation evidence (the verified ``fms_root``) and never
    from the network: an endpoint failure may establish UNREACHABLE for an FMS already known
    INSTALLED, and can never establish ABSENT.
    """

    INSTALLED = "installed"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class LocalMaterial(str, Enum):
    """What this box holds, once it is in a position to say.

    ``UNCLASSIFIED`` is not "we did not look" — it is "we *cannot* look yet", because definitive
    classification needs the Machine Key authority the integrator has not established. Every other
    value asserts a decryption outcome, and asserting one before there is a key to decrypt with is
    the defect this member exists to make unrepresentable.
    """

    UNCLASSIFIED = "unclassified"
    ABSENT = "absent"
    PRESENT_USABLE = "present_usable"
    PRESENT_UNUSABLE = "present_unusable"
    UNREADABLE = "unreadable"


class Reachability(str, Enum):
    """The outcome of one read-only, unauthenticated probe.

    ``NOT_APPLICABLE`` records that the probe was not RUN — presence was ABSENT or UNKNOWN — which is
    a different fact from "it ran and got nothing", and the two must not share a value.
    """

    ANSWERED = "answered"
    UNANSWERED = "unanswered"
    NOT_APPLICABLE = "not_applicable"


class LocalAuthentication(str, Enum):
    """The outcome of the one PKI authentication attempt.

    ``INCONCLUSIVE`` exists because a timeout, a 5xx or a reset proves nothing — not about the
    relationship, and not about reachability. Folding it into a refusal would manufacture a verdict
    from a failed request.
    """

    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    EXPLICITLY_REJECTED = "explicitly_rejected"
    INCONCLUSIVE = "inconclusive"


class RemoteRegistration(str, Enum):
    """What an AUTHORIZED GET saw — the only channel that may write this axis.

    A successful authentication proves ACCEPTANCE of our exact name and key, which is sufficient for
    WORKING; it does not write this axis, which legitimately stays ``NOT_OBSERVED`` until a GET runs.
    ``NAME_PRESENT_KEY_UNKNOWN`` is the 1708 oracle alone — the name is taken and no public key was
    ever read — and is not the same claim as ``CONFIRMED_PRESENT``, where a key was read and
    fingerprinted.
    """

    NOT_OBSERVED = "not_observed"
    CONFIRMED_ABSENT = "confirmed_absent"
    CONFIRMED_MATCHING = "confirmed_matching"
    CONFIRMED_MISMATCH = "confirmed_mismatch"
    CONFIRMED_PRESENT = "confirmed_present"
    NAME_PRESENT_KEY_UNKNOWN = "name_present_key_unknown"
    INCONCLUSIVE = "inconclusive"


class IdentityState(str, Enum):
    """Eight values, derived only when the facts justify one."""

    WORKING = "working"
    NOT_INSTALLED = "not_installed"
    LOCAL_ONLY = "local_only"
    REMOTE_ONLY = "remote_only"
    MISMATCHED = "mismatched"
    REJECTED = "rejected"
    LOCAL_UNUSABLE = "local_unusable"
    UNKNOWN = "unknown"


class Tag(str, Enum):
    """FOUR tags; a VALID observation has exactly one of the latter three."""

    INVALID_COMBINATION = "invalid_combination"
    PREREQUISITE_REQUIRED = "prerequisite_required"
    NOT_APPLICABLE = "not_applicable"
    IDENTITY_OBSERVATION = "identity_observation"


VALID_TAGS: tuple[Tag, ...] = (
    Tag.PREREQUISITE_REQUIRED,
    Tag.NOT_APPLICABLE,
    Tag.IDENTITY_OBSERVATION,
)

DAMAGED: frozenset[LocalMaterial] = frozenset(
    {LocalMaterial.PRESENT_UNUSABLE, LocalMaterial.UNREADABLE}
)

#: The authority operations a state can require. Never a credential, never a mode.
AUTHORITY_OPERATIONS: tuple[str, ...] = (
    "authorized_get",
    "add",
    "update",
    "delete",
    "authorized_replacement",
)

#: The modes this component is invoked in. Any other `LIFECYCLE_MODES` value is refused at the
#: request boundary, not here — a classifier that knew about modes would be one a mode could move.
MODES: tuple[str, ...] = ("fresh_install", "forward_update", "uninstall")

MODE_PERMITS: dict[str, frozenset[str]] = {
    "fresh_install": frozenset({"authorized_get", "add", "update", "authorized_replacement"}),
    "forward_update": frozenset({"authorized_get", "add", "update", "authorized_replacement"}),
    # Uninstall may look and may remove. It may not provision, replace or repair — asking for an
    # administrator password to perform an operation this mode forbids is collecting authority for
    # an act nobody may take.
    "uninstall": frozenset({"authorized_get", "delete"}),
}

#: Every relation `validate_relations` can return, in evaluation order. The order is part of the
#: contract: an invalid point names exactly one relation, deterministically.
REASONS: tuple[str, ...] = (
    "R1_no_fms_forbids_probe_auth_or_get",
    "R2_installed_fms_is_always_probed",
    "R3_unmet_prerequisite_requires_unclassified_material",
    "R4_established_prerequisite_forbids_unclassified_material",
    "R5_authentication_requires_usable_prepared_reachable",
    "R6_damaged_material_forbids_remote_observation",
    "R7_remote_observation_requires_installed_prepared_reachable",
    "R8_fingerprint_comparison_requires_usable_material",
    "R9_confirmed_present_requires_absent_material",
    "R10_successful_authentication_bounds_remote",
    "R11_ready_usable_unobserved_requires_attempt",
)


@dataclass(frozen=True)
class IdentityFacts:
    """The six classifier inputs. ``store_exists`` is NOT among them, deliberately."""

    prerequisite_established: bool
    fms_presence: FmsPresence
    local_material: LocalMaterial
    reachability: Reachability
    local_authentication: LocalAuthentication
    remote_registration: RemoteRegistration

    def as_tuple(self) -> tuple:
        return (
            self.prerequisite_established,
            self.fms_presence.value,
            self.local_material.value,
            self.reachability.value,
            self.local_authentication.value,
            self.remote_registration.value,
        )


@dataclass(frozen=True)
class ClassifiedResult:
    """What ``classify`` returns. ``store_exists`` and ``credentials_required`` arrive later."""

    tag: Tag
    state: IdentityState | None = None
    reason: str | None = None
    required_authority_operation: str | None = None
    finding: str | None = None
    store_exists: bool | None = None

    def key(self) -> tuple:
        """Everything a carried dimension must not be able to change."""
        return (self.tag, self.state, self.reason, self.required_authority_operation)


def validate_relations(facts: IdentityFacts) -> str | None:
    """The first violated relation's stable reason code, or ``None``.

    Runs BEFORE classification, which is what makes "no point produces both a refusal and a tag"
    structural rather than asserted.
    """
    if facts.fms_presence in (FmsPresence.ABSENT, FmsPresence.UNKNOWN) and not (
        facts.reachability is Reachability.NOT_APPLICABLE
        and facts.local_authentication is LocalAuthentication.NOT_ATTEMPTED
        and facts.remote_registration is RemoteRegistration.NOT_OBSERVED
    ):
        return "R1_no_fms_forbids_probe_auth_or_get"

    if facts.fms_presence is FmsPresence.INSTALLED and \
            facts.reachability is Reachability.NOT_APPLICABLE:
        return "R2_installed_fms_is_always_probed"

    if not facts.prerequisite_established and not (
        facts.local_material is LocalMaterial.UNCLASSIFIED
        and facts.local_authentication is LocalAuthentication.NOT_ATTEMPTED
        and facts.remote_registration is RemoteRegistration.NOT_OBSERVED
    ):
        return "R3_unmet_prerequisite_requires_unclassified_material"

    if facts.prerequisite_established and facts.local_material is LocalMaterial.UNCLASSIFIED:
        return "R4_established_prerequisite_forbids_unclassified_material"

    if facts.local_authentication is not LocalAuthentication.NOT_ATTEMPTED and not (
        facts.local_material is LocalMaterial.PRESENT_USABLE
        and facts.fms_presence is FmsPresence.INSTALLED
        and facts.prerequisite_established
        and facts.reachability is Reachability.ANSWERED
    ):
        return "R5_authentication_requires_usable_prepared_reachable"

    if facts.local_material in DAMAGED and \
            facts.remote_registration is not RemoteRegistration.NOT_OBSERVED:
        return "R6_damaged_material_forbids_remote_observation"

    if facts.remote_registration is not RemoteRegistration.NOT_OBSERVED and not (
        facts.fms_presence is FmsPresence.INSTALLED
        and facts.prerequisite_established
        and facts.reachability is Reachability.ANSWERED
    ):
        return "R7_remote_observation_requires_installed_prepared_reachable"

    if facts.remote_registration in (
        RemoteRegistration.CONFIRMED_MATCHING,
        RemoteRegistration.CONFIRMED_MISMATCH,
    ) and facts.local_material is not LocalMaterial.PRESENT_USABLE:
        return "R8_fingerprint_comparison_requires_usable_material"

    if facts.remote_registration is RemoteRegistration.CONFIRMED_PRESENT and \
            facts.local_material is not LocalMaterial.ABSENT:
        return "R9_confirmed_present_requires_absent_material"

    if facts.local_authentication is LocalAuthentication.SUCCEEDED and \
            facts.remote_registration not in (
                RemoteRegistration.NOT_OBSERVED, RemoteRegistration.CONFIRMED_MATCHING):
        return "R10_successful_authentication_bounds_remote"

    if (
        facts.prerequisite_established
        and facts.fms_presence is FmsPresence.INSTALLED
        and facts.reachability is Reachability.ANSWERED
        and facts.local_material is LocalMaterial.PRESENT_USABLE
        and facts.remote_registration is RemoteRegistration.NOT_OBSERVED
        and facts.local_authentication is LocalAuthentication.NOT_ATTEMPTED
    ):
        return "R11_ready_usable_unobserved_requires_attempt"

    return None


def classify(facts: IdentityFacts) -> ClassifiedResult:
    """FACTS ONLY — no mode, no ``store_exists``. First match wins.

    This is executed control flow, not a set of independently matching rules. An earlier version
    presented the derivation as unordered conjunctions and 36 points of the product matched two of
    them with different states; declaring that no ordering is required does not make rows disjoint,
    it removes the mechanism that would have resolved them.
    """
    violation = validate_relations(facts)
    if violation is not None:
        return ClassifiedResult(Tag.INVALID_COMBINATION, reason=violation)

    # Neither early presence result needs to decrypt identity material, so both precede the Machine
    # Key prerequisite. Making them wait on it would demand a key in order to report that no key is
    # needed.
    if facts.fms_presence is FmsPresence.UNKNOWN:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN)

    if facts.fms_presence is FmsPresence.ABSENT:
        return ClassifiedResult(Tag.NOT_APPLICABLE, reason="fms_absent")

    if not facts.prerequisite_established:            # presence is INSTALLED here
        return ClassifiedResult(Tag.PREREQUISITE_REQUIRED, reason="authoritative_machine_key")

    if facts.local_material in DAMAGED:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.LOCAL_UNUSABLE,
                                required_authority_operation="authorized_replacement")

    if facts.reachability is Reachability.UNANSWERED:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN)

    if facts.remote_registration is RemoteRegistration.INCONCLUSIVE:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN)

    if facts.remote_registration is RemoteRegistration.NAME_PRESENT_KEY_UNKNOWN:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN,
                                required_authority_operation="authorized_get")

    if facts.remote_registration is RemoteRegistration.CONFIRMED_ABSENT:
        return ClassifiedResult(
            Tag.IDENTITY_OBSERVATION,
            state=(IdentityState.NOT_INSTALLED
                   if facts.local_material is LocalMaterial.ABSENT else IdentityState.LOCAL_ONLY),
            required_authority_operation="add",
        )

    if facts.remote_registration is RemoteRegistration.CONFIRMED_MATCHING:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.WORKING)

    if facts.remote_registration is RemoteRegistration.CONFIRMED_MISMATCH:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.MISMATCHED,
                                required_authority_operation="update")

    if facts.remote_registration is RemoteRegistration.CONFIRMED_PRESENT:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.REMOTE_ONLY,
                                required_authority_operation="update")

    # RemoteRegistration.NOT_OBSERVED remains. A successful authentication proves ACCEPTANCE and is
    # sufficient for WORKING; no GET is issued merely to rewrite NOT_OBSERVED.
    if facts.local_authentication is LocalAuthentication.SUCCEEDED:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.WORKING)

    if facts.local_authentication is LocalAuthentication.EXPLICITLY_REJECTED:
        # Not terminal: the authorized GET refines this to LOCAL_ONLY, WORKING or MISMATCHED, which
        # is what makes those states reachable from a usable-local box at all.
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.REJECTED,
                                required_authority_operation="authorized_get")

    if facts.local_authentication is LocalAuthentication.INCONCLUSIVE:
        return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN)

    # NOT_ATTEMPTED; R11 leaves ABSENT as the only usable-material-free possibility.
    return ClassifiedResult(Tag.IDENTITY_OBSERVATION, state=IdentityState.UNKNOWN,
                            required_authority_operation="authorized_get",
                            finding="authorized_get_required")


def apply_mode_policy(result: ClassifiedResult, mode: str) -> tuple[bool, str | None]:
    """``(credentials_required, mode_refusal)``. NEVER changes tag, state or required operation.

    The separation is the guarantee: the classifier it consumes never saw a mode, so a mode is
    *structurally* unable to move a state. An earlier version took the mode as a classifier argument
    and asserted the property in prose.
    """
    if mode not in MODE_PERMITS:
        raise ValueError(f"{mode!r} is not a mode this component is invoked in: {MODES}")
    operation = result.required_authority_operation
    if result.tag is not Tag.IDENTITY_OBSERVATION or operation is None:
        return False, None
    if operation in MODE_PERMITS[mode]:
        return True, None
    return False, f"operation_{operation}_not_permitted_in_{mode}"


def attach_store_evidence(result: ClassifiedResult, store_exists: bool | None) -> ClassifiedResult:
    """``observe``'s step: carried evidence is ATTACHED, never consulted.

    ``PrerequisiteRequired`` and ``NotApplicable`` return it verbatim. No usable/unusable conclusion
    is derived from it anywhere — a file's existence is not a decryption outcome.
    """
    return replace(result, store_exists=store_exists)


def store_evidence_permitted(facts: IdentityFacts, store_exists: bool | None) -> bool:
    """Whether ``store_exists`` is COHERENT with an already-classified material.

    Asserted, never consulted by ``classify``. ``UNCLASSIFIED`` permits all three values because
    nobody has looked yet.
    """
    if not facts.prerequisite_established:
        return True
    if facts.local_material is LocalMaterial.ABSENT:
        return store_exists is False
    if facts.local_material is LocalMaterial.PRESENT_USABLE or facts.local_material in DAMAGED:
        return store_exists is True
    return True

# ── removal is not reconciliation (Codex ruling 2, 2026-08-05) ───────────────
#
# `apply_mode_policy` answers "may this mode PROVISION or REPLACE?" — its subject is the operation a
# RECONCILIATION would need. Removal was routed through it and inherited the wrong question: a
# `REMOTE_ONLY` box asked "may uninstall perform an update?", was told no, and returned `no_change`
# with exit 0 while leaving the registration standing on FileMaker Server. That is the orphaned
# registration this packet exists to close, produced by the packet itself.
#
# So removal gets its own decision, over its own facts, and it never consults a mode permit.


class RemoteObservation(str, Enum):
    """What ONE authorized look established about the EXACT recorded pair."""

    NOT_ATTEMPTED = "not_attempted"          # no authority was available to look with
    UNREADABLE = "unreadable"                # asked, and the registry did not answer usably
    ABSENT = "absent"                        # the name is not registered
    PRESENT_MATCHING = "present_matching"    # the name is registered and IS the recorded pair
    PRESENT_DIVERGENT = "present_divergent"  # the name is registered and is something else


class RemovalAction(str, Enum):
    NOTHING_TO_REMOVE = "nothing_to_remove"
    LOCAL_ONLY_CLEANUP = "local_only_cleanup"
    DELETE_WITH_INSTALLED_IDENTITY = "delete_with_installed_identity"
    DELETE_WITH_ADMIN_AUTHORITY = "delete_with_admin_authority"
    ADMIN_AUTHORITY_REQUIRED = "admin_authority_required"
    PRESERVE_AND_REPORT = "preserve_and_report"


@dataclass(frozen=True)
class RemovalFacts:
    """Everything the removal decision reads. No mode, and no reconciliation state."""

    presence: FmsPresence
    reachable: bool
    local: LocalMaterial
    local_matches_record: bool
    local_authenticates: bool
    observation: RemoteObservation


@dataclass(frozen=True)
class RemovalDecision:
    action: RemovalAction
    reason: str
    admin_authority_required: bool = False


def plan_removal(facts: RemovalFacts) -> RemovalDecision:
    """First match wins, and every branch is reachable. Never a speculative deletion.

    `admin_authority_required` is true in exactly one place: where Basic authority is what would
    ACTUALLY complete the exact cleanup. It is false when FileMaker Server is unreachable (no
    password can help), when the registry diverges (the contract forbids the deletion), and when
    there is nothing remote to delete.
    """
    local_present = facts.local is not LocalMaterial.ABSENT

    if facts.presence is FmsPresence.ABSENT:
        # PROVEN absent — not merely unread. Nothing remote can exist to clean up, and the local
        # material is this installation's own to remove.
        return RemovalDecision(
            RemovalAction.LOCAL_ONLY_CLEANUP if local_present else RemovalAction.NOTHING_TO_REMOVE,
            "no_installed_filemaker_server")

    if facts.presence is FmsPresence.UNKNOWN:
        # "I could not read the installation evidence" is not "there is no FileMaker Server", and
        # only one of those licenses removing anything. This is the tri-state the first draft
        # flattened into a boolean, where an unreadable presence would have cleaned up local
        # material on a box that may well have a live registration.
        return RemovalDecision(RemovalAction.PRESERVE_AND_REPORT, "fms_presence_unknown")

    if not facts.reachable:
        return RemovalDecision(RemovalAction.PRESERVE_AND_REPORT, "fms_unreachable")

    if facts.observation is RemoteObservation.NOT_ATTEMPTED:
        # The registry has not been read and this box cannot read it with what it holds. Basic
        # authority is precisely what would finish the job, so this is the one place it is asked for.
        return RemovalDecision(RemovalAction.ADMIN_AUTHORITY_REQUIRED,
                               "registry_not_read", admin_authority_required=True)

    if facts.observation is RemoteObservation.UNREADABLE:
        return RemovalDecision(RemovalAction.PRESERVE_AND_REPORT, "registry_unreadable")

    if facts.observation is RemoteObservation.PRESENT_DIVERGENT:
        # A same-named key that is not ours. Deleting it would destroy something this installation
        # did not create, and asking for a password to do so collects authority for a forbidden act.
        return RemovalDecision(RemovalAction.PRESERVE_AND_REPORT, "registration_is_not_ours")

    if facts.observation is RemoteObservation.ABSENT:
        # Remote absence is ESTABLISHED, which is what licenses removing local material — including
        # material that is present-unusable, as this installation's own leftovers.
        return RemovalDecision(
            RemovalAction.LOCAL_ONLY_CLEANUP if local_present else RemovalAction.NOTHING_TO_REMOVE,
            "remote_registration_confirmed_absent")

    # PRESENT_MATCHING: the exact recorded pair is up there and must come down.
    if (facts.local is LocalMaterial.PRESENT_USABLE
            and facts.local_matches_record and facts.local_authenticates):
        return RemovalDecision(RemovalAction.DELETE_WITH_INSTALLED_IDENTITY,
                               "identity_removes_itself")
    return RemovalDecision(RemovalAction.DELETE_WITH_ADMIN_AUTHORITY,
                           "no_usable_local_authority", admin_authority_required=True)


__all__ = [
    "AUTHORITY_OPERATIONS",
    "ClassifiedResult",
    "DAMAGED",
    "FmsPresence",
    "IdentityFacts",
    "IdentityState",
    "LocalAuthentication",
    "LocalMaterial",
    "MODES",
    "MODE_PERMITS",
    "REASONS",
    "Reachability",
    "RemoteObservation",
    "RemoteRegistration",
    "RemovalAction",
    "RemovalDecision",
    "RemovalFacts",
    "Tag",
    "VALID_TAGS",
    "apply_mode_policy",
    "attach_store_evidence",
    "classify",
    "plan_removal",
    "store_evidence_permitted",
    "validate_relations",
]
