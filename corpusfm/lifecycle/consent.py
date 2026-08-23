"""Consent and exceptional authorization (packet 1246-01, deliverable 5).

Two different things that a single ``--yes`` has repeatedly been asked to mean:

- **Ordinary consent** — "yes, do the thing you just described." ``--yes`` grants it; ``--silent``
  implies it, because a non-interactive run has nobody to ask.
- **Exceptional authorization** — "yes, discard this unrecognized install tree." Parent D6 is
  explicit that neither flag supplies this: *"ordinary consent is not authority to discard an
  unrecognized tree."* An exceptional decision is authorized by name, one decision at a time.

So they are separate fields with separate questions, and there is no path from the first to the
second. This module is the primitive; 1246-04 owns which flags feed it and 1246-09 owns the
uninstaller's. Keeping the rule here rather than in a parser means the two platforms cannot come to
disagree about it, which is exactly how the current `[y/N]`-versus-`Type 'yes'` split happened.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ExceptionalAuthorizationRequired


@dataclass(frozen=True)
class Consent:
    ordinary: bool = False
    exceptional: frozenset[str] = field(default_factory=frozenset)

    @staticmethod
    def from_flags(
        *, yes: bool = False, silent: bool = False, authorized: frozenset[str] | set[str] = frozenset()
    ) -> "Consent":
        """Build consent from the two interaction flags plus any named authorizations.

        ``silent`` implies ordinary consent and nothing else. That is the entire relationship
        between the flags — an implication in one direction only.
        """
        return Consent(
            ordinary=bool(yes or silent),
            exceptional=frozenset(authorized),
        )

    def has_ordinary(self) -> bool:
        return self.ordinary

    def has_exceptional(self, decision: str) -> bool:
        return decision in self.exceptional

    def require_exceptional(self, decision: str) -> None:
        """Raise unless this exact decision was authorized by name."""
        if decision not in self.exceptional:
            raise ExceptionalAuthorizationRequired(
                f"'{decision}' is an exceptional decision and needs its own named authorization; "
                "--yes and --silent grant ordinary consent only"
            )

    def granting(self, decision: str) -> "Consent":
        return Consent(ordinary=self.ordinary, exceptional=self.exceptional | {decision})
