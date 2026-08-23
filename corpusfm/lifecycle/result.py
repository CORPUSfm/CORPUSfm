"""The lifecycle result vocabulary (packet 1246-01, parent decision 7).

Exactly six words. Every lifecycle operation — installer, uninstaller, proxy manager, recovery
adoption, privileged update — ends in one of them, on every platform, in every language.

The reason there are six and not two is the control the packet demands: *"do not let all failures
collapse into one label."* An administrator needs to know which of these happened before deciding
what to do next, and the three failure words answer three different questions:

- ``failed_before_change``  — nothing was touched. Fix the condition and re-run; the box is as it was.
- ``rolled_back``           — something was changed and then put back. The box is as it was, but the
                              operation proved it can reach the failing step.
- ``incomplete_safe``       — a change stands, the remainder was abandoned safely, and re-running
                              resumes. No administrator action is owed right now.
- ``manual_action_required``— a change stands and only a human can finish it.

``classify_failure`` is the single place that decision is made, so no caller can invent a fourth
mapping or quietly reuse one word for two states.
"""

from __future__ import annotations

COMPLETED = "completed"
NO_CHANGE = "no_change"
ROLLED_BACK = "rolled_back"
INCOMPLETE_SAFE = "incomplete_safe"
MANUAL_ACTION_REQUIRED = "manual_action_required"
FAILED_BEFORE_CHANGE = "failed_before_change"

RESULT_VOCABULARY: frozenset[str] = frozenset(
    {
        COMPLETED,
        NO_CHANGE,
        ROLLED_BACK,
        INCOMPLETE_SAFE,
        MANUAL_ACTION_REQUIRED,
        FAILED_BEFORE_CHANGE,
    }
)

SUCCESS_RESULTS: frozenset[str] = frozenset({COMPLETED, NO_CHANGE})


def is_result(value: object) -> bool:
    return isinstance(value, str) and value in RESULT_VOCABULARY


def validate_result(value: object) -> str:
    """Return ``value`` when it is one of the six words; raise ``ValueError`` otherwise."""
    if not is_result(value):
        raise ValueError(
            f"{value!r} is not a lifecycle result; expected one of "
            + ", ".join(sorted(RESULT_VOCABULARY))
        )
    return str(value)


def classify_failure(
    *, mutated: bool, restored: bool = False, manual_action: bool = False
) -> str:
    """Map an observed failure onto exactly one result word.

    ``mutated`` is the pivot and it means *a durable change was made*, not *a step was attempted*.
    Reaching a subsystem, staging a temporary file, or acquiring a lock is not mutation; anything a
    crash would leave behind is.
    """
    if not mutated:
        return FAILED_BEFORE_CHANGE
    if restored:
        return ROLLED_BACK
    if manual_action:
        return MANUAL_ACTION_REQUIRED
    return INCOMPLETE_SAFE
