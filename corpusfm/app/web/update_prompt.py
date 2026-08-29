"""Whether to put a waiting update in this administrator's face, once (packet 1341).

The box finds updates with nobody watching — `UpdateObserver` is a daemon thread on the app lifespan,
one box-wide observation every two hours, measured firing overnight with no browser open. So what it
discovers has no one to tell, and must be surfaced at the next sign-in instead.

WHAT THIS MODULE IS NOT. It never applies anything. The pop-over's action opens
`Settings → CORPUSfm → Updates`, which remains the only surface that confirms, pins the exact head,
applies, waits for the restart and handles `target_changed`. One apply path, one consent pin.

THE RECORD IS SKIP-ONLY. Applying is self-suppressing: once applied the box is current, so "an update
has registered" is false for everyone and nothing needs writing. *(Developer, 2026-08-26, correcting a
framing question that presumed otherwise: "If the user updates CORPUSfm we should no longer have a
pending update registered.")* The stored head exists for exactly one case — a user declined while an
update was still waiting.
"""
from __future__ import annotations

#: Suppression reasons, bounded and reported so a silent no-show is never a mystery.
NO_UPDATE = "no_update"
NOT_ADMIN = "not_admin"
INITIAL_SESSION = "initial_session"
ALREADY_SKIPPED = "already_skipped"
WORK_IN_FLIGHT = "work_in_flight"
RUNTIME_UNKNOWN = "runtime_unknown"
SHOW = ""


def restart_sensitive_work() -> "bool | None":
    """Is a queue worker HOLDING a record right now? None when the runtime cannot be evaluated.

    `current_ids()` is the authority that distinguishes HELD work from WAITING work. A merely queued
    record does not block: it is durable and resumes after a restart. Job runs execute through these
    same workers, so a genuinely running job is already covered — `active_runs()` is deliberately NOT
    used, because its broader "in flight" meaning includes queued producing records.
    """
    try:
        from corpusfm.server import queue_workers
        return bool(queue_workers.current_ids())
    except Exception:
        return None                      # unknown → the caller fails CLOSED


def initial_prompt_outstanding() -> "bool | None":
    """Is packet 1326's first-sign-in prompt still unacknowledged? None when unreadable.

    Read BEFORE deciding, so acknowledging 1326 and navigating within the same initial session can
    never reveal a second modal.
    """
    from corpusfm.app.web import mcp_address_prompt
    return mcp_address_prompt.acknowledged()


def decide(*, is_admin: bool, update_available: bool, target_head: str,
           skipped_head: str, opportunity: bool, acknowledged_1326: "bool | None",
           busy: "bool | None") -> str:
    """SHOW ("") or the reason it is suppressed. Pure — every input is supplied by the caller."""
    if not is_admin:
        return NOT_ADMIN
    if not update_available or not target_head:
        return NO_UPDATE
    if not opportunity:
        return INITIAL_SESSION
    if acknowledged_1326 is not True:
        # False (still owed) or None (unreadable). Either way 1326 owns this sign-in; an unreadable
        # authority is never treated as "acknowledged".
        return INITIAL_SESSION
    if skipped_head and skipped_head == target_head:
        return ALREADY_SKIPPED
    if busy is None:
        return RUNTIME_UNKNOWN           # fail closed: unknown is not idle
    if busy:
        return WORK_IN_FLIGHT
    return SHOW


def installer_required(projection: dict) -> bool:
    """Does this update need the installer? EITHER flag, matching the Settings implementation.

    When true the pop-over shows the operator guidance and NO apply wording — never a control that
    would be refused."""
    return bool(projection.get("schema_change") or projection.get("installer_change"))
