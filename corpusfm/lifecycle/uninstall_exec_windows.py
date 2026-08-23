"""Executing the typed pending operations on Windows (packet 1246-09, stage 4).

Everything platform-neutral — exact paths, the atomic storage removal, the proxy fronts, the PKI
registration, the folder slot, the authority boundary itself — lives in `uninstall_exec_posix` and is
inherited unchanged. **Three things differ, and each of them differs for a reason the retired
executor got wrong:**

* **a WinSW service is stopped and DELETED through the service manager before its definition is
  touched.** §X.1 #4 reproduced the opposite: the XML was removed and the registration was left, so
  Windows and POSIX meant different things by *remove the service*;
* **the updater is a SCHEDULED TASK, and there is no `sc.exe` anywhere in its removal.** Modelling it
  as a service would query one that never existed, receive *absent*, and report a removal that never
  happened. A test asserts the absence of the call, not merely the presence of the right one;
* **an account operation REFUSES.** A `NT SERVICE\\<service>` identity is virtual: the service
  manager creates and destroys it with the service, so there is nothing separate to remove. The
  builder no longer emits one (§AA), and this is the backstop for a record that already carries one.

**Early quiesce has no primitive on this platform, and that is reported rather than worked around.**
`service_control` offers `windows_stop_and_delete_service`, which deletes the registration — and the
managed-unit conjunction needs that registration to still be there when the removal proves ownership.
*(Superseded: `stop_services` returned a named refusal here while no stop-only Windows primitive
existed. `service_control.windows_stop_service` closed that gap; the paragraph is kept because the
refusal reason it introduced is still emitted for a scheduled task and for a registration that is
absent or unreadable.)* So `stop_services` returned a named refusal instead of quietly doing nothing or quietly doing too
much. It is an interface gap, not a design choice.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import service_control as sc
from .layout import WINDOWS
from .service_identity import UNIT_KIND_SCHEDULED_TASK, WINDOWS_UPDATER_IDENTITY
from .uninstall_exec_posix import (
    CONJ_DEFINITION,
    CONJ_EXECUTABLE,
    CONJ_IDENTITY,
    CONJ_OK,
    CONJ_UNREADABLE,
    EXEC_ALREADY_ABSENT,
    EXEC_COMPLETED,
    EXEC_FAILED,
    EXEC_REFUSED,
    REFUSE_CONJUNCTION,
    REFUSE_NO_QUIESCE_PRIMITIVE,
    REFUSE_SERVICE_ABSENT,
    REFUSE_SERVICE_NOT_STOPPED,
    REFUSE_SERVICE_UNREADABLE,
    REFUSE_VIRTUAL_ACCOUNT,
    STOP_SERVICES,
    Outcome,
    UninstallExecutor,
    _canonical,
    _is_link,
    _lstat_or_none,
    _within,
)


def _winsw_facts(text: str) -> dict:
    """`<id>`, `<executable>` and the service account, out of a WinSW definition.

    Parsed with `safe_xml`, like every other externally-supplied document in this repository — a
    service definition on a customer's box is exactly that.
    """
    from corpusfm.core import safe_xml as ET

    root = ET.fromstring(text)
    account = root.find("serviceaccount")
    username = account.find("username") if account is not None else None
    return {
        "id": (root.findtext("id") or "").strip(),
        "executable": (root.findtext("executable") or "").strip(),
        "identity": ((username.text or "").strip() if username is not None else ""),
    }


def windows_conjunction(*, definition_path, name: str, install_dir, expected_identity: str,
                        unit_kind: str) -> tuple:
    """`(part, detail)` — Windows's half of the five-part conjunction. Pure; reads one file.

    The classification exists for the same reason the POSIX one does: the executor asks *is there
    drift* and the service-binding observer asks *what kind*, and one implementation answers both.
    """
    definition = Path(definition_path)
    if _lstat_or_none(definition) is None:
        return CONJ_DEFINITION, f"the recorded definition {definition} is not there"
    if _is_link(os.lstat(str(definition))):
        return CONJ_DEFINITION, (
            f"the recorded definition {definition} is a reparse point, not a definition")
    root = _canonical(install_dir, flavour=WINDOWS)
    if unit_kind == UNIT_KIND_SCHEDULED_TASK:
            # **A scheduled task's definition IS its executable** — the recorded script the task
            # runs — so containment is proved against that path. The live PRINCIPAL is not
            # observable through any primitive this package holds (`schtasks /Query /TN` reports no
            # identity), so the identity part is proved against the platform's own updater identity:
        # a record naming anything else has been edited, and that is what can be checked here.
        # Stated plainly rather than implied, because an unstated limit reads as a proof.
        candidate = _canonical(definition, flavour=WINDOWS)
        if not _within(candidate, root, flavour=WINDOWS):
            return CONJ_EXECUTABLE, (
                f"the recorded task script {definition} is not beneath the recorded install "
                f"directory {install_dir!r}")
        if expected_identity != WINDOWS_UPDATER_IDENTITY:
            return CONJ_IDENTITY, (
                f"the recorded task identity {expected_identity!r} is not the "
                f"platform's updater identity {WINDOWS_UPDATER_IDENTITY!r}")
        return CONJ_OK, ""
    try:
        facts = _winsw_facts(definition.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        return CONJ_UNREADABLE, f"{definition} could not be read: {exc}"
    except Exception as exc:                                              # noqa: BLE001
        return CONJ_UNREADABLE, f"{definition} is not a readable WinSW definition: {exc}"
    if facts["id"] != name:
        return CONJ_DEFINITION, (
            f"{definition} registers {facts['id']!r} and this installation recorded {name!r}")
    if not facts["executable"]:
        return CONJ_DEFINITION, f"{definition} names no executable"
    candidate = _canonical(facts["executable"], flavour=WINDOWS)
    if not (candidate == root or _within(candidate, root, flavour=WINDOWS)):
        return CONJ_EXECUTABLE, (
            f"{definition} runs {facts['executable']!r}, which is not beneath the recorded "
            f"install directory {install_dir!r}")
    if facts["identity"] != expected_identity:
        return CONJ_IDENTITY, (
            f"{definition} runs as {facts['identity']!r} and this installation recorded "
            f"{expected_identity!r}; somebody has been editing our definition")
    return CONJ_OK, ""


class WindowsExecutor(UninstallExecutor):
    """WinSW services, one scheduled task, and no removable account."""

    FLAVOUR = WINDOWS

    def _quiesce_already_absent(self, operation, *, runner) -> bool:
        """A foundation-only install may record services before creating either one."""
        if _lstat_or_none(Path(operation.definition_path)) is not None:
            return False
        observed, _probe = sc.windows_service_state(operation.name, runner=runner)
        return observed == sc.ABSENT

    #: **This platform cannot delete what it is running.** A running image is held by its section
    #: object and a working directory by an open handle, so the recorded install root — which holds
    #: the bundled interpreter and the package — refuses rather than being deleted around them. The
    #: base class explains why the choice is keyed to the executor.
    SELF_RUNTIME_IS_REMOVABLE = False

    # -- the five-part conjunction --------------------------------------------

    def _prove_conjunction(self, operation) -> str:
        return windows_conjunction(
            definition_path=operation.definition_path, name=operation.name,
            install_dir=operation.install_dir, expected_identity=operation.expected_identity,
            unit_kind=operation.unit_kind)[1]

    # -- removal ---------------------------------------------------------------

    def _remove_managed_unit(self, operation, *, runner) -> Outcome:
        if operation.unit_kind == UNIT_KIND_SCHEDULED_TASK:
            return self._remove_scheduled_task(operation, runner=runner)
        return self._remove_service(operation, runner=runner)

    def _remove_service(self, operation, *, runner) -> Outcome:
        """stop/delete · observe the registration absent · remove the exact definition · read back."""
        registered, probe = sc.windows_service_state(operation.name, runner=runner)
        definition_there = _lstat_or_none(Path(operation.definition_path)) is not None
        if registered == sc.ABSENT and not definition_there:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_ALREADY_ABSENT, checkpointable=True,
                           observations=(f"{operation.name}=absent",),
                           detail="the service manager does not know the service and its definition "
                                  "is gone")
        if registered == sc.UNREADABLE:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"{operation.name}=unreadable",),
                           detail=f"the service manager could not be read: "
                                  f"{probe.stderr or probe.stdout!r}")
        drift = self._prove_conjunction(operation)
        if drift:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_CONJUNCTION, detail=drift)
        control = sc.windows_stop_and_delete_service(operation.name, runner=runner)
        if not control.substep_succeeded or control.observed != sc.ABSENT:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"stop_delete={control.state}",),
                           detail=control.detail or "the registration was not observed absent")
        # BETWEEN THE SUBSTEPS — see the POSIX executor: the deregistration and the definition
        # removal are two acts, and a substitution between them must not be honoured.
        operation = self._still(operation.resource, operation)
        removed, refusal = self._remove_definition(operation)
        observations = (f"stop_delete={control.state}", f"removed_definition={removed}")
        if refusal:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=observations, detail=refusal)
        return Outcome(resource=operation.resource, operation=operation.tag,
                       result=EXEC_COMPLETED, checkpointable=True, observations=observations,
                       detail=f"{operation.name} is deregistered and its definition is gone")

    def _remove_scheduled_task(self, operation, *, runner) -> Outcome:
        """Unregister the recorded TASK — never a service — then remove and read back its script."""
        registered, probe = sc.windows_scheduled_task_state(operation.name, runner=runner)
        script_there = _lstat_or_none(Path(operation.definition_path)) is not None
        if registered == sc.ABSENT and not script_there:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_ALREADY_ABSENT, checkpointable=True,
                           observations=(f"{operation.name}=absent",),
                           detail="the task scheduler does not know the task and its script is gone")
        if registered == sc.UNREADABLE:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"{operation.name}=unreadable",),
                           detail=f"the task scheduler could not be read: "
                                  f"{probe.stderr or probe.stdout!r}")
        drift = self._prove_conjunction(operation)
        if drift:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_CONJUNCTION, detail=drift)
        control = sc.windows_unregister_scheduled_task(operation.name, runner=runner)
        if not control.substep_succeeded or control.observed != sc.ABSENT:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=(f"unregister_task={control.state}",),
                           detail=control.detail or "the task was not observed absent")
        operation = self._still(operation.resource, operation)
        removed, refusal = self._remove_definition(operation)
        observations = (f"unregister_task={control.state}", f"removed_script={removed}")
        if refusal:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_FAILED, observations=observations, detail=refusal)
        return Outcome(resource=operation.resource, operation=operation.tag,
                       result=EXEC_COMPLETED, checkpointable=True, observations=observations,
                       detail=f"{operation.name} is unregistered and its script is gone")

    # -- the account that is not one -------------------------------------------

    def _remove_account(self, operation, *, runner) -> Outcome:
        return Outcome(
            resource=operation.resource, operation=operation.tag, result=EXEC_REFUSED,
            reason=REFUSE_VIRTUAL_ACCOUNT,
            detail=f"{operation.account!r} is a Windows service identity; it is created and "
                   "destroyed with its service and there is no separate account to remove. The "
                   "builder no longer records one, and a record that carries one is refused rather "
                   "than executed.")

    # -- early quiesce -------------------------------------------------------

    def _quiesce(self, operation, *, runner) -> Outcome:
        """Stop the recorded WinSW service — and nothing else (packet 1246-09 §Z.2).

        **The gap that stopped stage 4 is closed by `service_control.windows_stop_service`.** Before
        it, the only Windows stop this package had was `windows_stop_and_delete_service`, which
        deletes the registration — the very evidence `_remove_service` re-proves ownership against.
        Quiescing with it would have traded the quiesce for the conjunction, so this refused by name
        instead.

        The conjunction is re-proved here too, immediately before acting: `stop_services` rereads
        the record and hands over the CURRENT operation, and this asks the box whether that
        operation still describes what is installed. **An absent or unreadable registration is not
        quiescence** — the primitive says so and this does not translate it into one.
        """
        drift = self._prove_conjunction(operation)
        if drift:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_CONJUNCTION, detail=drift)
        if operation.unit_kind == UNIT_KIND_SCHEDULED_TASK:                # pragma: no cover
            # Unreachable: `stop_services` filters to `UNIT_KIND_SERVICE` before calling. Kept
            # because a scheduled task reaching a service stop is the one mistake this platform
            # invites, and the guard states it where a reader looks for it.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_NO_QUIESCE_PRIMITIVE,
                           detail=f"{operation.name} is a scheduled task, not an application "
                                  "service; an early quiesce does not touch it")
        result = sc.windows_stop_service(operation.name, runner=runner)
        observations = (f"{operation.name}={result.state}/{result.observed}",)
        if result.state == sc.COMPLETED:
            # NEVER checkpointable: the registration and the definition are both still there, and
            # the managed-unit operation that owns them is still owed.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_COMPLETED, checkpointable=False,
                           observations=observations, detail=result.detail)
        if result.state == sc.ALREADY_ABSENT:
            # **Absence is not quiescence.** The record says this installation owns a service the
            # box does not have; that is ownership drift, and the managed-unit operation must see it
            # rather than have an early quiesce quietly call it success.
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_SERVICE_ABSENT,
                           observations=observations,
                           detail=f"{operation.name} is not registered; an absent service is not a "
                                  "quiesced one, and the record still claims it")
        if result.observed == sc.UNREADABLE:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_SERVICE_UNREADABLE,
                           observations=observations,
                           detail=f"{operation.name}: {result.detail}")
        if result.state == sc.REFUSED:
            return Outcome(resource=operation.resource, operation=operation.tag,
                           result=EXEC_REFUSED, reason=REFUSE_SERVICE_NOT_STOPPED,
                           observations=observations,
                           detail=f"{operation.name}: {result.detail}")
        return Outcome(resource=operation.resource, operation=operation.tag, result=EXEC_FAILED,
                       observations=observations,
                       detail=f"{operation.name}: {result.detail}")


__all__ = ["STOP_SERVICES", "WindowsExecutor", "windows_conjunction"]
