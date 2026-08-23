"""The application's single view of "which Admin API identity may this process use?" (packet 1247).

Every runtime consumer — Jobs file discovery, readiness, Health, patch apply/dry-run and the `fms_*`
MCP tools — asks here instead of reaching for a store. There is exactly one decision in this module
and it is made once, in `admin_api_identity()`:

* **A published installation uses the identity that installation published, and nothing else.** The
  resolver is `lifecycle.admin_identity_runtime`; there is no fallback to the retired checkout-local
  `fms_admin_pki.yaml`, and a published box that cannot read its own identity says so rather than
  reporting "not configured" (packet §Required behavior 3).
* **An explicitly selected development layout has no installed identity.** It reports absent and
  points to installation; there is no checkout-local compatibility authority.
* **Anything else is indeterminate and refuses.** A box whose installation record cannot be read is
  not a development box.

Nothing in here writes anything, and no value it returns to a caller for display carries private
material — `reason` holds names, fingerprints and paths only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from corpusfm.lifecycle.admin_identity_runtime import (
    ABSENT,
    AVAILABLE,
    RUNTIME_IDENTITY_STATES,
    resolve_runtime_identity,
)

#: What a surface should tell an administrator to do about each state. Kept here, next to the
#: decision, so Health, readiness and the MCP error text cannot drift apart in what they advise.
_REMEDIES = {
    "absent": "Register this installation's Admin API identity with `corpusfm-lifecycle "
              "admin-identity`.",
    # Covers both ways a present identity fails to be read: the process cannot open it, and the
    # secrets location itself was refused. Naming only file permissions sent the second case to the
    # wrong repair (review finding, 2026-08-12); the resolver's own reason says which one occurred.
    "unreadable": "The identity is there and this service could not read it — either the "
                  "installation's secrets permissions or the secrets location itself. That is owned "
                  "by the installation, not by CORPUSfm. Repair it and restart the service.",
    "unusable": "Re-establish this installation's Admin API identity with `corpusfm-lifecycle "
                "admin-identity`.",
    "disagrees": "The stored key is not the one this installation published. Reconcile it with "
                 "`corpusfm-lifecycle admin-identity`.",
    "indeterminate": "This installation's own record could not be read, so no Admin API identity "
                     "can be resolved. Repair the installation record.",
}


@dataclass(frozen=True)
class AdminApiIdentity:
    """One resolved answer: usable or not, why, and the config an Admin API call needs."""

    state: str
    reason: str
    # Out of the repr for the same reason `RuntimeIdentity.private_pem` is: this dict CARRIES the
    # private key, and a dataclass repr is how it would reach a log nobody meant to write it to.
    config: Optional[dict] = field(default=None, repr=False)
    # Set only by the development branch, whose repair is a different one: there is no installation
    # record to reconcile against, so the Settings pop-over IS the place to configure a key there.
    remedy_text: Optional[str] = None

    @property
    def available(self) -> bool:
        return self.config is not None

    @property
    def remedy(self) -> str:
        return self.remedy_text if self.remedy_text is not None else _REMEDIES.get(self.state, "")

    @property
    def is_absent(self) -> bool:
        """Nothing is there. The ONE unavailable state that reads as "not configured" — every other
        one means something exists and is wrong, which is a different repair."""
        return self.state == ABSENT


def admin_api_identity() -> AdminApiIdentity:
    """The identity this process may use, with the reason when it may not use one."""
    resolution = resolve_runtime_identity()

    if resolution.state == "development":
        return AdminApiIdentity(
            state=ABSENT,
            reason="this development layout publishes no Admin API identity",
            remedy_text="Install CORPUSfm to establish the installation-owned Admin API identity.",
        )

    if resolution.available:
        return AdminApiIdentity(state=AVAILABLE, reason=resolution.reason,
                                config=resolution.as_admin_api_config())
    return AdminApiIdentity(state=resolution.state, reason=resolution.reason)


def admin_api_config() -> Optional[dict]:
    """`{"name", "host", "private_pem"}` for an Admin API call, or `None`.

    The drop-in shape the switched call sites already read. A caller that must EXPLAIN the absence
    uses `admin_api_identity()` instead of inferring a reason from `None`.
    """
    return admin_api_identity().config


__all__ = [
    "AdminApiIdentity",
    "RUNTIME_IDENTITY_STATES",
    "admin_api_config",
    "admin_api_identity",
]
