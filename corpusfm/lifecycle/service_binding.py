"""Whether this installation's recorded services still bind (packet 1246-09, stage 6).

**This module reads. It has no other capability** — no removal, no service control beyond the two
fixed-argv *observations* `service_control` already owns, no credential, no write.

It exists because `service_binding` used to arrive in the uninstall REQUEST, from a caller that had
no way to establish it. The fact decides three deletions — `bound` plans the removal of the web
service, the scheduler service and the updater; every other word preserves all three — so a launcher
had two options and the packet forbade both: assert a word it had not observed, or re-implement the
five-part conjunction in bash and PowerShell.

**The conjunction is not re-implemented here either.** `posix_conjunction` and `windows_conjunction`
are the executors' own proof, extracted so there is exactly one of it, and this module is their
second caller. What it adds is the half a pure file check cannot answer — whether the service manager
knows the unit — through the same fixed-argv primitives the executors use.

Two rules the vocabulary forces, and both are stated rather than left to be inferred:

* **one word covers all three units.** `svcbind` is a single fact in the closed observation
  vocabulary and the planner applies it to every service. `bound` means every unit binds;
  `all_absent` means every definition and registration is absent; and `bound_or_absent` means each
  member independently has one of those two complete proofs. One genuinely drifted unit preserves
  all three. That is conservative in the safe direction — the direction where nothing is removed.
* **unreadable is not drift, and it REFUSES.** A permission error on a unit file, or a service
  manager that cannot be asked, is evidence of nothing. Reporting it as `name_only` would preserve
  the services *and let the run go on to delete the tree underneath them*, because a preserved
  service is not owed work and therefore withholds nothing. `observe_fms_presence` already refuses on
  exactly this reasoning; this is the same rule for the same reason.
"""

from __future__ import annotations

from . import service_control as sc
from . import uninstall_inventory as inv
from .layout import POSIX
from .service_identity import UNIT_KIND_SCHEDULED_TASK
from .uninstall_exec_posix import (
    CONJ_DEFINITION,
    CONJ_EXECUTABLE,
    CONJ_IDENTITY,
    CONJ_OK,
    CONJ_UNREADABLE,
    posix_conjunction,
)
from .uninstall_exec_windows import windows_conjunction

#: Which observation word each failed conjunction part produces. **The planner's existing decisions,
#: unchanged** — no new authority is minted here, and every one of these preserves.
_PART_TO_STATE = {
    CONJ_DEFINITION: inv.SVC_NAME_ONLY,
    CONJ_EXECUTABLE: inv.SVC_EXECUTABLE_OUTSIDE,
    CONJ_IDENTITY: inv.SVC_IDENTITY_DISAGREES,
}

#: Which word wins when the units disagree. Every member preserves, so this does not change what is
#: removed — it decides which drift the operator is TOLD about, and the most specific finding is the
#: most useful one.
_SEVERITY = (inv.SVC_IDENTITY_DISAGREES, inv.SVC_EXECUTABLE_OUTSIDE, inv.SVC_NAME_ONLY)


def _registration(record: dict, *, flavour: str, runner) -> tuple:
    """`(state, probe)` from the platform's own fixed-argv observation. Never a control action."""
    if flavour == POSIX:
        return sc.posix_unit_state(f"{record['name']}.service", runner=runner)
    if record.get("unit_kind") == UNIT_KIND_SCHEDULED_TASK:
        return sc.windows_scheduled_task_state(record["name"], runner=runner)
    return sc.windows_service_state(record["name"], runner=runner)


def observe_service_binding(manifest, *, flavour: str, runner=None, records=None) -> tuple:
    """`(state, detail)` from `inv.SVC_STATES`, or `(None, why not)` when it cannot be established.

    The caller supplies a subprocess runner and nothing else: no service name, no definition path, no
    install directory and no way to assert an answer. Names and paths come from
    `canonical_service_records(flavour, install_dir)` — the same function the foundation publishes
    from — and the install directory comes from the manifest.

    **`records` is a SEAM, exactly like `runner`.** POSIX unit files live under `/etc/systemd/system`,
    which a test cannot write, so a suite unable to substitute them could only ever exercise the
    *absent* half of the conjunction. The shipped caller passes it never — `_proved_service_binding`
    supplies a manifest, a flavour and a runner and nothing else, and a structural test says so.
    """
    from .service_identity import canonical_service_records

    install_dir = manifest.paths.install_dir if manifest is not None else None
    if not install_dir:
        # The planner has its own named refusal for incomplete path authority and it is the more
        # specific answer. Reporting *no established binding* here preserves the services and lets
        # `INCOMPLETE_PATHS` be the reason the run stops.
        return inv.SVC_NAME_ONLY, ("the manifest records no install directory, so nothing binds a "
                                   "recorded definition to this installation")

    found: list = []
    details: list = []
    absent = 0
    bound = 0
    service_records = tuple(
        canonical_service_records(flavour, install_dir) if records is None else records)
    for record in service_records:
        registered, probe = _registration(record, flavour=flavour, runner=runner)
        if registered == sc.UNREADABLE:
            return None, (f"the service manager could not be asked about {record['name']}: "
                          f"{(probe.stderr or probe.stdout or '').strip()!r}")
        if flavour == POSIX:
            part, why = posix_conjunction(
                definition_path=record["unit"], name=record["name"],
                install_dir=install_dir, expected_identity=record["identity"])
        else:
            part, why = windows_conjunction(
                definition_path=record["unit"], name=record["name"],
                install_dir=install_dir, expected_identity=record["identity"],
                unit_kind=record["unit_kind"])
        if part == CONJ_UNREADABLE:
            return None, f"a recorded service definition could not be read: {why}"
        if part == CONJ_DEFINITION and registered == sc.ABSENT:
            # Foundation records the canonical service identities before phase 20 creates any
            # definitions.  A failed installation in that interval therefore has neither a
            # definition nor a service-manager registration.  That is an already-absent resource,
            # not binding drift: the uninstall executors remove canonical recorded units
            # idempotently.  Keep the drift refusal when a manager still knows the name, because a
            # name with no binding definition could belong to something we did not install.
            details.append(f"{record['name']}: already absent")
            absent += 1
            continue
        if part != CONJ_OK:
            found.append(_PART_TO_STATE[part])
            details.append(f"{record['name']}: {why}")
        else:
            bound += 1
            details.append(f"{record['name']}: binds ({registered})")

    if not found:
        if absent == len(service_records):
            return inv.SVC_ALL_ABSENT, "; ".join(details)
        if absent and bound:
            # Each member independently carries one of the executor's two terminally actionable
            # proofs: the complete canonical binding, or definition+registration both absent.  The
            # typed executors re-prove the same member immediately before acting, so the family is
            # removable without pretending the absent members bind or the bound members are gone.
            return inv.SVC_BOUND_OR_ABSENT, "; ".join(details)
        return inv.SVC_BOUND, "; ".join(details)
    for word in _SEVERITY:
        if word in found:
            return word, "; ".join(details)
    return inv.SVC_NAME_ONLY, "; ".join(details)      # pragma: no cover - _SEVERITY is total


__all__ = ["observe_service_binding"]
