"""Stopping and deregistering the platform's own service manager (packet 1246-09 §Z).

**This module controls units. It removes no definition file.** Deleting the definition is a
filesystem act with a different authority and a different failure mode, and folding it in here is
exactly how a failed stop came to be followed by a deletion that reported success.

**The result never comes from the command's return code alone.** Every primitive runs its action,
keeps the code and the output, and then **asks the service manager what is actually there**. The
three answers are kept apart:

* **absent** — the manager positively says it does not know this unit;
* **present** — it positively says it does;
* **unreadable** — the query failed, timed out, or returned something this module cannot interpret.

**Unreadable is not absent**, and that distinction is the whole point: `systemctl status` on a
missing unit and `systemctl status` on a machine where systemd is not answering both exit non-zero,
and treating them alike is how "we could not tell" becomes "it is gone".

Subprocesses take a **fixed absolute executable and an argv list**. There is no shell anywhere.

**These are TARGET-CAPABLE low-level primitives, and they accept a name.** That is stated plainly
because an earlier version of this docstring implied the opposite. They validate that a name is a
name — not an option, not a path, not a control sequence — and they do **not** establish deletion
authority and cannot. Nothing here knows which unit belongs to this installation.

**The future executor must supply every name exclusively from typed pending evidence.** A caller
that passes a name from anywhere else gets exactly what it asked for, which is why the authority
lives above this layer rather than in it.
"""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass, field

from .errors import LifecycleError

# ── the shared result contract ────────────────────────────────────────────────

#: The four terminal states. Closed: a caller switching on these has covered every case.
COMPLETED = "completed"
ALREADY_ABSENT = "already_absent"
REFUSED = "refused"
FAILED_UNKNOWN = "failed_unknown"

#: The unit is stopped and disabled and its DEFINITION IS STILL THERE. A substep that succeeded and
#: a resource that is not finished, which are two different facts and were one state.
STOP_DISABLE_PREPARED = "stop_disable_prepared"

CONTROL_STATES: tuple = (COMPLETED, ALREADY_ABSENT, REFUSED, FAILED_UNKNOWN,
                         STOP_DISABLE_PREPARED)

#: The two states in which a SUBSTEP did what it set out to do. **This is not checkpoint
#: permission** — see `ControlResult.substep_succeeded`. A pending operation may hold several
#: substeps, and only the executor that ran all of them can say whether the operation is finished.
SUBSTEP_SUCCEEDED: frozenset = frozenset({COMPLETED, ALREADY_ABSENT, STOP_DISABLE_PREPARED})

#: What the query saw. `UNREADABLE` is a first-class answer, not a failure to produce one.
PRESENT = "present"
ABSENT = "absent"
UNREADABLE = "unreadable"
OBSERVED_STATES: tuple = (PRESENT, ABSENT, UNREADABLE)


class ServiceControlRefused(LifecycleError):
    """The primitive must not act. Nothing was attempted."""


@dataclass(frozen=True)
class CommandRun:
    """One subprocess, kept whole. The code AND the output — a diagnosis needs both."""

    argv: tuple
    returncode: int
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict:
        return {"argv": list(self.argv), "returncode": self.returncode,
                "stdout": self.stdout, "stderr": self.stderr}


@dataclass(frozen=True)
class ControlResult:
    """What was attempted, what the commands returned, and what was then OBSERVED."""

    action: str
    unit: str
    state: str
    observed: str
    runs: tuple = field(default_factory=tuple)
    detail: str = ""

    def __post_init__(self):
        if self.state not in CONTROL_STATES:
            raise ServiceControlRefused(f"state must be one of {CONTROL_STATES}, got {self.state!r}")
        if self.observed not in OBSERVED_STATES:
            raise ServiceControlRefused(
                f"observed must be one of {OBSERVED_STATES}, got {self.observed!r}")

    @property
    def substep_succeeded(self) -> bool:
        """**Deliberately not called `may_checkpoint`.** These primitives report the state of ONE
        registration substep — a unit stopped, a service deleted, a task unregistered. Whether the
        pending OPERATION may be checkpointed depends on every substep it contains, including the
        definition removal these primitives never perform, and only the future executor holds that
        view. A property named for the checkpoint invited a caller to treat one substep's success as
        the whole resource's."""
        return self.state in SUBSTEP_SUCCEEDED

    def to_dict(self) -> dict:
        return {"action": self.action, "unit": self.unit, "state": self.state,
                "observed": self.observed, "detail": self.detail,
                "runs": [r.to_dict() for r in self.runs]}


def _plain_name(value: str, *, what: str, allow_backslash: bool = False) -> str:
    """One validator for all three primitives, because three were three different rules.

    A self-audit compared them and found ``--now`` rejected as a POSIX unit and accepted as a
    Windows service and a task; a backslash rejected for a service and accepted for a task; and a
    newline accepted everywhere. **argv arrays mean none of this is shell injection** — a space or a semicolon is one
    argument, not two — so the real hazard is different and narrower: an argument that the TOOL
    reads as an OPTION. `sc delete --now` and `schtasks /Delete /TN /F` both take their instructions
    from arguments, and a name beginning `-` or `/` is an instruction wearing a name.

    So: no leading `-` or `/`, no path separator (except a backslash where task folders use one),
    no quote, and no control character. Everything else — spaces included, because `CORPUSfm Update`
    contains one — is a name.
    """
    if not isinstance(value, str) or not value.strip():
        raise ServiceControlRefused(f"{what} must be a non-empty name")
    if value[0] in "-/":
        raise ServiceControlRefused(
            f"{value!r} begins with an option prefix; a {what} is selected by a typed authority and "
            "is never an instruction to the tool")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ServiceControlRefused(f"{value!r} contains a control character; not a {what}")
    forbidden = set('"\'/')
    if not allow_backslash:
        forbidden.add("\\")
    for character in sorted(forbidden):
        if character in value:
            raise ServiceControlRefused(
                f"{value!r} contains {character!r}; a {what} carries no quote or path separator")
    return value


def _run_argv(argv: list, *, runner=None, timeout: int = 60) -> CommandRun:
    """A fixed ABSOLUTE executable and an argv LIST. Never a shell, never a joined string."""
    if not argv:
        raise ServiceControlRefused("a subprocess needs an executable")
    executable = str(argv[0])
    absolute = executable.startswith("/") or (len(executable) > 2 and executable[1] == ":")
    if not absolute:
        raise ServiceControlRefused(
            f"a subprocess needs a fixed absolute executable, got {executable!r}")
    if runner is not None:
        return runner(list(argv))
    try:
        done = subprocess.run(argv, capture_output=True, text=True, check=False,  # noqa: S603
                              timeout=timeout)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        # `ValueError` is `subprocess`'s answer to an embedded NUL byte, and it is neither of the
        # other two. `_plain_name` already refuses control characters, so this is the belt to that
        # brace — but "typed results, always" must have no untyped exit at all.
        return CommandRun(argv=tuple(argv), returncode=-1, stderr=str(exc))
    return CommandRun(argv=tuple(argv), returncode=done.returncode,
                      stdout=done.stdout or "", stderr=done.stderr or "")


def _terminal(action, unit, observed, runs, *, detail=""):
    """The one place a state is derived from an OBSERVATION rather than from a return code."""
    if observed == ABSENT:
        return ControlResult(action=action, unit=unit, state=COMPLETED, observed=ABSENT,
                             runs=tuple(runs), detail=detail)
    if observed == PRESENT:
        return ControlResult(action=action, unit=unit, state=FAILED_UNKNOWN, observed=PRESENT,
                             runs=tuple(runs),
                             detail=detail or "the unit is still registered after the action")
    return ControlResult(action=action, unit=unit, state=FAILED_UNKNOWN, observed=UNREADABLE,
                         runs=tuple(runs),
                         detail=detail or "the service manager could not be read; unreadable is "
                                          "not absence")


# ── POSIX: systemd ────────────────────────────────────────────────────────────

SYSTEMCTL = "/usr/bin/systemctl"


def posix_unit_state(unit_name: str, *, runner=None) -> tuple:
    """`(observed, CommandRun)` for one exact unit.

    `systemctl list-unit-files --no-legend <name>` is used rather than `status`, because `status`
    exits non-zero for *inactive* as well as for *not-found* — one exit code covering two answers
    this module must keep apart.
    """
    run = _run_argv([SYSTEMCTL, "list-unit-files", "--no-legend", "--plain", unit_name],
                    runner=runner)
    if run.returncode == 0:
        lines = [line for line in run.stdout.splitlines() if line.strip()]
        matched = [line for line in lines if line.split()[:1] == [unit_name]]
        return (PRESENT if matched else ABSENT), run
    # systemd distinguishes "no such unit" from "I could not answer", and so must this.
    combined = f"{run.stdout}\n{run.stderr}".lower()
    # systemd's own wordings for "there is no such unit". A non-zero exit alone cannot be read as
    # absence — the same exit covers "I could not answer", which is the distinction this module is
    # built around.
    # `"no such file"` is deliberately NOT here: it appears in `Failed to connect to bus: No such
    # file or directory`, which is systemd being unreachable — the exact case that must stay
    # UNREADABLE. A substring broad enough to catch both is a substring that answers the wrong
    # question, and adding it made an unreachable manager read as an absent unit.
    for absence in ("0 unit files listed", "no files found", "not-found"):
        if absence in combined:
            return ABSENT, run

    # A diagnostic is already an answer about why systemd could not report the unit.  In
    # particular, do not follow "Failed to connect to bus" with another command and pretend the
    # manager might still be readable.  The fallback below is solely for systemd's silent exit 1.
    if combined.strip():
        return UNREADABLE, run

    # Ubuntu 24.04's systemd answers an exact, removed unit with exit 1 and NO output here.  That
    # is not enough to call it absent, but it is also not the end of systemd's read-only surface:
    # `show LoadState` gives the positive answer `not-found` for that exact unit.  Ask that bounded
    # second question only when the listing gave no interpretable answer.  A missing bus, a failed
    # show, an empty/multi-line property, or any malformed answer remains UNREADABLE.
    load = _run_argv(
        [SYSTEMCTL, "show", "--property=LoadState", "--value", unit_name], runner=runner)
    if load.returncode == 0:
        values = [line.strip().lower() for line in load.stdout.splitlines() if line.strip()]
        if values == ["not-found"]:
            return ABSENT, load
        if len(values) == 1:
            # Every other LoadState means systemd has a unit object for the exact name.  It may be
            # loaded, masked, erroneous, or merged, but it is observably not absent.
            return PRESENT, load
    return UNREADABLE, run


def posix_service_run_state(unit_name: str, *, runner=None) -> tuple:
    """`(observed, running_state, CommandRun)` — registration AND run state, kept apart.

    The POSIX counterpart of `windows_service_run_state`, and it exists for the same reason: *is it
    registered* and *is it running* are two questions, and folding them together makes an
    unreachable manager look like a stopped service.

    `systemctl is-active` answers only the second, and it answers `inactive` for a unit that does
    not exist — so registration is established first, by `posix_unit_state`, and this is asked only
    of a unit systemd has already said it knows. `running_state` is `ACTIVE`, another systemd word,
    or `None` when the answer could not be read as a state at all.
    """
    observed, probe = posix_unit_state(unit_name, runner=runner)
    if observed != PRESENT:
        return observed, None, probe
    run = _run_argv([SYSTEMCTL, "is-active", unit_name], runner=runner)
    word = (run.stdout or "").strip().splitlines()
    if not word:
        # `is-active` exits non-zero for an inactive unit, so a non-zero code is not a failure — but
        # NO output is: something answered without saying anything, and that is not an observation.
        return observed, None, run
    state = word[0].strip().upper()
    return observed, (state or None), run


def posix_stop_and_disable(unit_name: str, *, runner=None) -> ControlResult:
    """Stop and disable the EXACT recorded unit, then ask systemd what is there.

    **This removes no definition.** After a successful disable the unit file is still on disk and
    `list-unit-files` still reports it — so the honest observation here is *present*, and the
    caller's own read-back after removing the definition is what turns it into *absent*. Reporting
    `completed` on the strength of `systemctl disable` returning 0 is the failure this module
    exists to prevent.
    """
    _plain_name(unit_name, what="unit name")
    runs = []
    observed, probe = posix_unit_state(unit_name, runner=runner)
    runs.append(probe)
    if observed == ABSENT:
        return ControlResult(action="stop_disable", unit=unit_name, state=ALREADY_ABSENT,
                             observed=ABSENT, runs=tuple(runs),
                             detail="systemd does not know this unit; nothing was attempted")
    if observed == UNREADABLE:
        return ControlResult(action="stop_disable", unit=unit_name, state=FAILED_UNKNOWN,
                             observed=UNREADABLE, runs=tuple(runs),
                             detail="systemd could not be read before acting; nothing was attempted")

    for verb in ("stop", "disable"):
        run = _run_argv([SYSTEMCTL, verb, unit_name], runner=runner)
        runs.append(run)
        if run.returncode != 0:
            return ControlResult(
                action="stop_disable", unit=unit_name, state=FAILED_UNKNOWN, observed=PRESENT,
                runs=tuple(runs),
                detail=f"systemctl {verb} exited {run.returncode}; the unit was not brought down "
                       f"and no definition may be removed on this outcome")
    # **No daemon-reload here.** It belongs AFTER the executor removes the definition — reloading
    # while the file is still on disk tells systemd to re-read a unit that is still there, which
    # proves nothing and invites the caller to read the following query as a removal check.
    observed, probe = posix_unit_state(unit_name, runner=runner)
    runs.append(probe)
    if observed == PRESENT:
        # PREPARATORY. The unit is stopped and disabled and its definition is still there, so this
        # substep did what it set out to do — and the RESOURCE is not finished. `stop_disable_ok`
        # says the first thing without saying the second; `completed` here would have been read as
        # "the service is gone" by the one caller that matters.
        return ControlResult(
            action="stop_disable", unit=unit_name, state=STOP_DISABLE_PREPARED, observed=PRESENT,
            runs=tuple(runs),
            detail="stopped and disabled; the definition remains, which this primitive never "
                   "removes — the resource is not finished until the executor removes it and "
                   "`posix_reload_and_observe` confirms the unit is gone")
    if observed == ABSENT:
        return ControlResult(action="stop_disable", unit=unit_name, state=COMPLETED,
                             observed=ABSENT, runs=tuple(runs),
                             detail="stopped and disabled; systemd no longer lists the unit")
    return ControlResult(action="stop_disable", unit=unit_name, state=FAILED_UNKNOWN,
                         observed=UNREADABLE, runs=tuple(runs),
                         detail="the commands returned 0 but systemd could not be read afterwards; "
                                "unreadable is not success")


# ── Windows: services and scheduled tasks ─────────────────────────────────────

import os as _os  # noqa: E402  (kept local to the Windows section it serves)

_SYSTEM32 = _os.path.join(_os.environ.get("SystemRoot", r"C:\Windows"), "System32")
SC_EXE = _os.path.join(_SYSTEM32, "sc.exe")
SCHTASKS_EXE = _os.path.join(_SYSTEM32, "schtasks.exe")


#: `sc stop` on a service that is not running. The ONE failure a delete may follow.
SERVICE_NOT_ACTIVE = 1062


def _already_stopped(run: CommandRun) -> bool:
    combined = f"{run.stdout}\n{run.stderr}".lower()
    return str(SERVICE_NOT_ACTIVE) in combined or "has not been started" in combined


def windows_service_state(service_name: str, *, runner=None) -> tuple:
    """`(observed, CommandRun)` from `sc.exe query`. 1060 is *no such service*."""
    run = _run_argv([SC_EXE, "query", service_name], runner=runner)
    if run.returncode == 0:
        return PRESENT, run
    combined = f"{run.stdout}\n{run.stderr}".lower()
    if "1060" in combined or "does not exist" in combined:
        return ABSENT, run
    return UNREADABLE, run


def windows_stop_and_delete_service(service_name: str, *, runner=None, attempts: int = 3
                                    ) -> ControlResult:
    """Stop and delete the EXACT recorded WinSW service, then query until absent or bounded failure.

    Bounded, because `sc delete` marks a service for deletion and Windows may not complete it while
    a handle is open. Retrying forever would hang an uninstall; retrying never would call a pending
    deletion a failure. So: a fixed number of queries, and whatever is true at the end is reported.
    """
    _plain_name(service_name, what="service name")
    runs = []
    observed, probe = windows_service_state(service_name, runner=runner)
    runs.append(probe)
    if observed == ABSENT:
        return ControlResult(action="stop_delete", unit=service_name, state=ALREADY_ABSENT,
                             observed=ABSENT, runs=tuple(runs),
                             detail="the service manager does not know this service")
    if observed == UNREADABLE:
        return ControlResult(action="stop_delete", unit=service_name, state=FAILED_UNKNOWN,
                             observed=UNREADABLE, runs=tuple(runs),
                             detail="the service manager could not be read before acting")

    stop = _run_argv([SC_EXE, "stop", service_name], runner=runner)
    runs.append(stop)
    if stop.returncode != 0 and not _already_stopped(stop):
        # **Only the exact already-stopped condition may proceed.** Any other failure — access
        # denied, a dependent service, a hung stop — means the service is still RUNNING, and
        # deleting a running service leaves Windows with a registration marked for removal and a
        # process still serving. The previous version treated every stop failure as survivable.
        return ControlResult(
            action="stop_delete", unit=service_name, state=REFUSED, observed=PRESENT,
            runs=tuple(runs),
            detail=f"sc stop exited {stop.returncode} and it is not the already-stopped condition; "
                   "a running service is not deleted")
    delete = _run_argv([SC_EXE, "delete", service_name], runner=runner)
    runs.append(delete)
    if delete.returncode != 0:
        return ControlResult(action="stop_delete", unit=service_name, state=FAILED_UNKNOWN,
                             observed=PRESENT, runs=tuple(runs),
                             detail=f"sc delete exited {delete.returncode}; the service was not "
                                    "removed and no definition may be removed on this outcome")
    for _attempt in range(max(1, attempts)):
        observed, probe = windows_service_state(service_name, runner=runner)
        runs.append(probe)
        if observed == ABSENT:
            return ControlResult(action="stop_delete", unit=service_name, state=COMPLETED,
                                 observed=ABSENT, runs=tuple(runs))
        if observed == UNREADABLE:
            break
    return _terminal(
        "stop_delete", service_name, observed, runs,
        detail=("sc delete returned 0 but the service is still queryable; a deletion marked and "
                "not completed is not a deletion") if observed == PRESENT else "")


#: `sc query`'s STATE line for a service that has come to rest.
SERVICE_STATE_STOPPED = "STOPPED"


def windows_service_run_state(service_name: str, *, runner=None) -> tuple:
    """`(observed, running_state, CommandRun)` — registration AND run state, kept apart.

    `windows_service_state` answers *is it registered*. Quiescing needs a second, different answer:
    *is it running*. Folding them together would make an unreadable STATE line look like a stopped
    service, which is the substitution this module exists to refuse.

    `running_state` is `STOPPED`, another `sc` state word, or `None` when the output could not be
    read as a state at all.
    """
    observed, run = windows_service_state(service_name, runner=runner)
    if observed != PRESENT:
        return observed, None, run
    for line in (run.stdout or "").splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("STATE"):
            # `STOP_PENDING` and `START_PENDING` carry underscores, so `isalpha()` dropped them
            # and the state read as unreadable — a service mid-stop would have looked unobservable.
            words = [w for w in stripped.replace(":", " ").split()
                     if w.replace("_", "").isalpha()]
            # `STATE : 4 RUNNING` -> the trailing alphabetic word, never the numeric code.
            return observed, (words[-1].upper() if len(words) > 1 else None), run
    return observed, None, run


def windows_stop_service(service_name: str, *, runner=None, attempts: int = 60) -> ControlResult:
    """Stop the EXACT recorded service — and nothing else (packet 1246-09 §Z.2).

    **This is the primitive the stage-4 gate found missing.** The only Windows stop this module had
    was `windows_stop_and_delete_service`, which deletes the registration — the very evidence a
    managed-unit removal re-proves ownership against before it removes anything. Quiescing with it
    would have traded the quiesce for the conjunction.

    So this one **never calls `sc delete`, and never removes or alters a definition** (both asserted
    statically). It stops, and then it *looks*:

    * an **absent** registration is `already_absent` — nothing was attempted, and the caller decides
      what an absent service means for its own authority. This primitive does not call it quiescence;
    * an **unreadable** registration is `failed_unknown`. Unreadable is not absent, and it is not
      stopped either;
    * a registered service **already STOPPED** is `completed`: stop preparation succeeded, and there
      was nothing to do;
    * a **running** service is stopped and then polled, up to `attempts`, until `STOPPED` is
      *observed*. `sc stop` returning 0 only means the control was accepted — Windows stops
      asynchronously, so the return code is the beginning of the question;
    * an **unexpected stop failure** — anything that is not the exact already-stopped condition —
      is `refused`, because a service that would not take a stop control is still running.
    """
    _plain_name(service_name, what="service name")
    runs = []
    observed, running, probe = windows_service_run_state(service_name, runner=runner)
    runs.append(probe)
    if observed == ABSENT:
        return ControlResult(
            action="stop_service", unit=service_name, state=ALREADY_ABSENT, observed=ABSENT,
            runs=tuple(runs),
            detail="the service manager does not know this service; nothing was stopped, and an "
                   "absent registration is not this primitive's evidence of quiescence")
    if observed == UNREADABLE:
        return ControlResult(
            action="stop_service", unit=service_name, state=FAILED_UNKNOWN, observed=UNREADABLE,
            runs=tuple(runs),
            detail="the service manager could not be read; unreadable is neither absent nor stopped")
    if running == SERVICE_STATE_STOPPED:
        return ControlResult(
            action="stop_service", unit=service_name, state=COMPLETED, observed=PRESENT,
            runs=tuple(runs),
            detail="already stopped and still registered; stop preparation needs nothing further")

    stop = _run_argv([SC_EXE, "stop", service_name], runner=runner)
    runs.append(stop)
    if stop.returncode != 0 and not _already_stopped(stop):
        return ControlResult(
            action="stop_service", unit=service_name, state=REFUSED, observed=PRESENT,
            runs=tuple(runs),
            detail=f"sc stop exited {stop.returncode} and it is not the already-stopped condition; "
                   "a service that will not take a stop control is still running")
    for _attempt in range(max(1, attempts)):
        observed, running, probe = windows_service_run_state(service_name, runner=runner)
        runs.append(probe)
        if observed == UNREADABLE:
            return ControlResult(
                action="stop_service", unit=service_name, state=FAILED_UNKNOWN,
                observed=UNREADABLE, runs=tuple(runs),
                detail="the service manager could not be read after the stop; unreadable is not "
                       "stopped")
        if observed == ABSENT:
            # It vanished under us. Not our doing and not our evidence.
            return ControlResult(
                action="stop_service", unit=service_name, state=FAILED_UNKNOWN, observed=ABSENT,
                runs=tuple(runs),
                detail="the registration disappeared during the stop; something else is changing "
                       "this service")
        if running == SERVICE_STATE_STOPPED:
            return ControlResult(action="stop_service", unit=service_name, state=COMPLETED,
                                 observed=PRESENT, runs=tuple(runs),
                                 detail="observed STOPPED and still registered")
        if running == "STOP_PENDING" and _attempt + 1 < max(1, attempts):
            time.sleep(1)
    return ControlResult(
        action="stop_service", unit=service_name, state=FAILED_UNKNOWN, observed=PRESENT,
        runs=tuple(runs),
        detail=f"sc stop was accepted but the service is still {running or 'unreadable'} after "
               f"{max(1, attempts)} observation(s); a stop control accepted is not a service "
               "stopped")


def windows_scheduled_task_state(task_name: str, *, runner=None) -> tuple:
    """`(observed, CommandRun)` from `schtasks /Query /TN <name>`."""
    run = _run_argv([SCHTASKS_EXE, "/Query", "/TN", task_name], runner=runner)
    if run.returncode == 0:
        return (PRESENT if task_name.lower() in (run.stdout or "").lower() else UNREADABLE), run
    combined = f"{run.stdout}\n{run.stderr}".lower()
    if "cannot find the file specified" in combined or "does not exist" in combined \
            or "the system cannot find" in combined:
        return ABSENT, run
    return UNREADABLE, run


def windows_unregister_scheduled_task(task_name: str, *, runner=None) -> ControlResult:
    """Unregister the recorded scheduled task, then query it and require GENUINE absence.

    **The updater is a scheduled task, not a service.** It has no `sc.exe` registration to delete —
    modelling it as one would query a service that never existed, receive *absent*, and report a
    removal that never happened. There is no `sc.exe` call in this function, and a test asserts it.
    """
    # A scheduled task may live in a folder, so a backslash is part of a legitimate task name.
    _plain_name(task_name, what="task name", allow_backslash=True)
    runs = []
    observed, probe = windows_scheduled_task_state(task_name, runner=runner)
    runs.append(probe)
    if observed == ABSENT:
        return ControlResult(action="unregister_task", unit=task_name, state=ALREADY_ABSENT,
                             observed=ABSENT, runs=tuple(runs),
                             detail="the task scheduler does not know this task")
    if observed == UNREADABLE:
        return ControlResult(action="unregister_task", unit=task_name, state=FAILED_UNKNOWN,
                             observed=UNREADABLE, runs=tuple(runs),
                             detail="the task scheduler could not be read before acting")

    delete = _run_argv([SCHTASKS_EXE, "/Delete", "/TN", task_name, "/F"], runner=runner)
    runs.append(delete)
    if delete.returncode != 0:
        return ControlResult(action="unregister_task", unit=task_name, state=FAILED_UNKNOWN,
                             observed=PRESENT, runs=tuple(runs),
                             detail=f"schtasks /Delete exited {delete.returncode}")
    observed, probe = windows_scheduled_task_state(task_name, runner=runner)
    runs.append(probe)
    return _terminal("unregister_task", task_name, observed, runs)


def posix_reload_and_observe(unit_name: str, *, runner=None) -> ControlResult:
    """Reload systemd AFTER the definition has been removed, and confirm the unit is gone.

    **This is the other half of `posix_stop_and_disable`, and it is separate on purpose.** systemd
    caches unit state, so a query taken before a reload is a query about the past — and a reload
    taken while the definition is still on disk proves nothing at all. The order that means
    something is: stop and disable · the executor removes the definition · reload · observe.

    `completed` requires the unit to be observably **absent**. A failed reload or an unreadable
    query is `failed_unknown`, because after a definition removal the question *is it gone* has a
    real answer and "we could not tell" is not it.
    """
    _plain_name(unit_name, what="unit name")
    runs = [_run_argv([SYSTEMCTL, "daemon-reload"], runner=runner)]
    if runs[0].returncode != 0:
        return ControlResult(
            action="reload_observe", unit=unit_name, state=FAILED_UNKNOWN, observed=UNREADABLE,
            runs=tuple(runs),
            detail=f"systemctl daemon-reload exited {runs[0].returncode}; any query after it would "
                   "be answered from a stale view")
    observed, probe = posix_unit_state(unit_name, runner=runner)
    runs.append(probe)
    if observed == ABSENT:
        return ControlResult(action="reload_observe", unit=unit_name, state=COMPLETED,
                             observed=ABSENT, runs=tuple(runs),
                             detail="reloaded; systemd no longer knows this unit")
    if observed == PRESENT:
        return ControlResult(
            action="reload_observe", unit=unit_name, state=FAILED_UNKNOWN, observed=PRESENT,
            runs=tuple(runs),
            detail="the definition was reported removed and systemd still lists the unit")
    return ControlResult(
        action="reload_observe", unit=unit_name, state=FAILED_UNKNOWN, observed=UNREADABLE,
        runs=tuple(runs),
        detail="systemd could not be read after the reload; unreadable is not absence")
