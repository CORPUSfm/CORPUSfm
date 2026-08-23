"""Lifecycle error vocabulary (packet 1246-01).

The distinction the packet is built on: **missing is not invalid**. A locator that is absent means
"no CORPUSfm is installed here" and is an ordinary, actionable answer. A locator that is present and
unreadable, unparseable, wrongly versioned or contradicted by its manifest means "state exists and
cannot be trusted" — and the ruled response to that is to refuse, never to guess a default. Two
distinct exception branches make a caller unable to collapse them by accident.
"""

from __future__ import annotations


class LifecycleError(Exception):
    """Base of every lifecycle-record failure."""


class RecordMissing(LifecycleError):
    """No record at all. Not an error state on its own — an answer."""


class RecordInvalid(LifecycleError):
    """A record exists and cannot be trusted. Never resolved by falling back to a default."""


class SchemaVersionUnsupported(RecordInvalid):
    """The record declares a schema version this build does not implement."""


class IdentityMismatch(RecordInvalid):
    """Locator and manifest disagree about installation ID or manifest location."""


class SecretInLifecycleRecord(LifecycleError):
    """A structural guard caught secret-shaped material entering a lifecycle record."""


class LockUnavailable(LifecycleError):
    """The machine lifecycle lock is held elsewhere, or could not be evaluated. Fail closed."""


class LockNotHeld(LifecycleError):
    """A mutation was attempted without the held lifecycle lock that authorizes it."""


class GenerationConflict(LifecycleError):
    """Compare-and-swap lost: the on-disk manifest moved under this writer."""


class ElevationRequired(LifecycleError):
    """A locator write or delete was attempted without administrator privilege."""


class RecoveryRequired(LifecycleError):
    """An unresolved journal record demands recovery before another operation may start."""


class ExceptionalAuthorizationRequired(LifecycleError):
    """An exceptional decision was reached with only ordinary consent in hand."""
