"""The one read-only way the RUNNING application resolves this installation's Admin-API identity.

Packet 1247. The installer publishes exactly one Admin-API identity — the private key under the fixed
secrets directory, its registration name and public fingerprint in the installation manifest — and
before this module every runtime consumer still asked ``fms_admin_pki.load_admin_pki_for_apply()``,
whose store is a checkout-local ``fms_admin_pki.yaml``. On a published box that file does not exist,
so Jobs reported "no admin PKI key configured" and Health reported "No PKI admin key configured"
while a root-context call authenticated with the published identity and listed 36 databases.

**What this module answers, and what it refuses to guess:**

    available      the published record and the store agree, and the key decrypted
    absent         published, but no identity has been composed or none is stored
    unreadable     something IS there and could not be read (permission, I/O, a refused directory)
    unusable       present and not usable — malformed, undecryptable, or naming another registration
    disagrees      the store holds an identity this installation did not publish
    development    a development layout is selected IN-PROCESS; the installed identity does not apply
    indeterminate  no honest answer; the caller refuses rather than falling back

**"Absent" and "unreadable" are different facts and this module never collapses them** (packet
§Required behavior 3). ``admin_identity_store.load()`` deliberately answers ``None`` for both, which
is right for the operations that own the store — an unusable identity and a missing one lead to the
same lifecycle action — and wrong for a diagnostic, because "not configured" tells an administrator to
create something that already exists. So classification goes through ``classify_local_material`` and a
read failure is reported as a read failure.

**Agreement with the manifest is required (developer ruling D3, 2026-08-12).** A store whose
registration name or public fingerprint differs from the published block is not this installation's
authority — it is a leftover, a restored backup, or a second key — and authenticating with it would
present this box as something its own record does not claim to be. That check already guarded the
patch compartment (``fms_folders.build_adapter``); D4 re-expresses that path on this resolver so there
is ONE implementation of runtime identity authority rather than two copies of the same rule.

**Nothing here writes, stages, promotes, registers or removes anything**, and no reason string this
module produces carries private material: names, fingerprints and paths only. The private PEM crosses
the boundary exactly once, to the Admin-API transport that must sign a JWT with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .errors import LifecycleError

AVAILABLE = "available"
ABSENT = "absent"
UNREADABLE = "unreadable"
UNUSABLE = "unusable"
DISAGREES = "disagrees"
DEVELOPMENT = "development"
INDETERMINATE = "indeterminate"

#: Every state this resolver can answer. A caller that switches on the state is exhaustive against it.
RUNTIME_IDENTITY_STATES: tuple[str, ...] = (
    AVAILABLE, ABSENT, UNREADABLE, UNUSABLE, DISAGREES, DEVELOPMENT, INDETERMINATE,
)


@dataclass(frozen=True)
class RuntimeIdentity:
    """The three values an Admin-API call needs, and nothing else.

    ``private_pem`` is kept OUT of the generated ``repr``. A dataclass repr is how private material
    reaches a log or an exception message without anyone deciding to put it there — `logger.debug("%s",
    resolution)` is enough — and this packet's protected invariant is that it never does. The
    fingerprint below identifies the key for a diagnostic; it is public by construction.
    """

    registration_name: str
    host: str
    private_pem: bytes = field(repr=False)

    def fingerprint(self) -> str:
        from .admin_identity_store import fingerprint_of_private_pem

        return fingerprint_of_private_pem(self.private_pem)

    def as_admin_api_config(self) -> dict:
        """The shape the existing Admin-API call sites already read.

        Kept deliberately identical to what ``load_admin_pki_for_apply`` returned, so switching a
        consumer is one import and one call rather than a rewrite of its transport code. ``name`` is
        the registration name because that is what the JWT's ``iss`` must carry.
        """
        return {"name": self.registration_name, "host": self.host, "private_pem": self.private_pem}


@dataclass(frozen=True)
class RuntimeIdentityResolution:
    """One state, one reason, and an identity only when the state is ``available``."""

    state: str
    reason: str
    identity: Optional[RuntimeIdentity] = None

    @property
    def available(self) -> bool:
        return self.state == AVAILABLE and self.identity is not None

    def as_admin_api_config(self) -> Optional[dict]:
        return self.identity.as_admin_api_config() if self.available else None


def _resolution(state: str, reason: str,
                identity: Optional[RuntimeIdentity] = None) -> RuntimeIdentityResolution:
    return RuntimeIdentityResolution(state=state, reason=reason, identity=identity)


def resolve_published_identity() -> RuntimeIdentityResolution:
    """Published record → store → agreement. **The authority rule, and the only copy of it.**

    No development seam: this is what LIFECYCLE code asks, and lifecycle has no development path — a
    box either published an identity or it did not. `fms_folders.build_adapter` consumes exactly this
    (developer ruling D4, 2026-08-12), so the patch compartment and the running application can no
    longer disagree about which key is this installation's.

    It takes no arguments for the same reason ``published.read_published_installation`` takes none: a
    caller handing in a secrets directory or a layout would be choosing which installation's identity
    to authenticate as, which is the whole of the decision this function owns.
    """
    from . import published as pub

    try:
        record = pub.read_published_installation()
    except LifecycleError as exc:
        return _resolution(INDETERMINATE, str(exc))
    except Exception as exc:                       # noqa: BLE001 - refuse, never fall back
        return _resolution(
            INDETERMINATE, f"this installation's published record could not be read ({exc})")

    return _resolve_from_record(record)


def resolve_runtime_identity() -> RuntimeIdentityResolution:
    """What the running APPLICATION may use: the rule above, plus the development seam in front.

    The seam is here and nowhere else, so no consumer has to remember it. It is checked FIRST because
    a development process must not read another installation's record at all — and it is safe as a
    short-circuit because ``use_development_layout`` refuses outright on a machine that carries any
    installation trace, so a real box can never be in this state.
    """
    from . import app_paths

    try:
        if app_paths.development_layout_active():
            return _resolution(
                DEVELOPMENT,
                "a development layout is selected for this process, so this machine's installed "
                "identity does not apply",
            )
    except Exception as exc:                       # noqa: BLE001 - an unanswerable probe is not a no
        return _resolution(INDETERMINATE, f"the layout state could not be determined ({exc})")

    return resolve_published_identity()


def _resolve_from_record(record) -> RuntimeIdentityResolution:
    from . import admin_identity_store as store
    from .admin_identity import LocalMaterial

    secrets = getattr(record, "secrets_dir", None)
    if not secrets:
        return _resolution(
            INDETERMINATE,
            "this installation is published but its record names no secrets directory, so there is "
            "no location an Admin API identity could be read from",
        )

    pki = getattr(record, "pki", None)
    published_name = getattr(pki, "registration_name", None)
    published_fingerprint = getattr(pki, "public_fingerprint", None)
    if not published_name or not published_fingerprint:
        return _resolution(
            ABSENT,
            "this installation has published no Admin API identity (its manifest records no "
            "registration name and fingerprint)",
        )

    try:
        material = store.classify_local_material(secrets)
    except store.IdentityStoreError as exc:
        return _resolution(UNREADABLE, str(exc))
    except OSError as exc:
        return _resolution(
            UNREADABLE, f"the identity store under {secrets} could not be read ({exc})")
    except Exception as exc:                       # noqa: BLE001
        return _resolution(
            UNREADABLE, f"the identity store under {secrets} could not be classified ({exc})")

    if material is LocalMaterial.ABSENT:
        return _resolution(
            ABSENT,
            f"this installation published the Admin API identity {published_name!r} but no identity "
            f"is stored under {secrets}",
        )
    if material is LocalMaterial.UNREADABLE:
        return _resolution(
            UNREADABLE,
            f"the Admin API identity under {secrets} exists and could not be read by this process. "
            "Its readability is owned by the installation, not by the running application.",
        )
    if material is not LocalMaterial.PRESENT_USABLE:
        return _resolution(
            UNUSABLE,
            f"the Admin API identity under {secrets} is present and not usable ({material.value})",
        )

    try:
        identity = store.load(secrets)
    except Exception as exc:                       # noqa: BLE001 - classified usable a moment ago
        return _resolution(
            UNREADABLE, f"the Admin API identity under {secrets} could not be loaded ({exc})")
    if identity is None:
        return _resolution(
            UNUSABLE,
            f"the Admin API identity under {secrets} classified as usable but did not load; the "
            "store is inconsistent and will not be guessed at",
        )

    try:
        stored_fingerprint = identity.public_fingerprint()
    except Exception as exc:                       # noqa: BLE001
        return _resolution(
            UNUSABLE, f"the stored Admin API private key could not be fingerprinted ({exc})")

    if (identity.registration_name != published_name
            or stored_fingerprint != published_fingerprint):
        return _resolution(
            DISAGREES,
            "the stored Admin API identity is not the one this installation published: the store "
            f"holds {identity.registration_name!r}/{stored_fingerprint} and the installation "
            f"published {published_name!r}/{published_fingerprint}",
        )

    if not identity.host:
        return _resolution(
            UNUSABLE, f"the stored Admin API identity under {secrets} names no FileMaker Server host")

    return _resolution(
        AVAILABLE,
        f"the published Admin API identity {published_name!r} is available for {identity.host}",
        RuntimeIdentity(
            registration_name=identity.registration_name,
            host=identity.host,
            private_pem=identity.private_pem,
        ),
    )


__all__ = [
    "ABSENT",
    "AVAILABLE",
    "DEVELOPMENT",
    "DISAGREES",
    "INDETERMINATE",
    "RUNTIME_IDENTITY_STATES",
    "RuntimeIdentity",
    "RuntimeIdentityResolution",
    "UNREADABLE",
    "UNUSABLE",
    "resolve_published_identity",
    "resolve_runtime_identity",
]
