"""The lifecycle output contract (packet 1246-01, deliverable 5; parent D6).

The developer's ruling is that the administrator wants **consequences and verified results** by
default, with mechanics available on demand. So the engine emits *semantic events*, and the mode
decides which reach the console. Nothing decides that by writing a different ``echo``.

| event | default | verbose | silent |
|---|---|---|---|
| banner, discovery, plan, prompt, phase, next_steps, progress, still-working | yes | yes | no |
| **detail** — commands, resolved paths, subprocess output | **no** | yes | no |
| warning, failure, action, preservation, result, log | yes | yes | **yes** |

Two consequences worth stating because they are the ones that get eroded:

- **Silent is not quiet about consequences.** It drops decoration, never a warning, a required
  action, a preservation decision, the result or the transcript path. A clean silent run therefore
  emits exactly ``RESULT:`` and ``LOG:`` — which is also how a caller can tell a clean run from one
  that had something to say.
- **The transcript keeps everything.** Mode governs the console only; every event is written to the
  log regardless, so "concise" never means "lost".

**Redaction, and its honest limit.** Every emitted line — console and transcript alike — passes
through the secret guard: values a caller registered, plus the unambiguous patterns in
``secret_guard``. It cannot promise that a subprocess never prints a secret in a shape nobody has
seen. It is a fence against the known, not a proof about the unknown, and it should not be described
as more than that.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Callable, TextIO

from .result import validate_result
from .secret_guard import redact

DEFAULT = "default"
VERBOSE = "verbose"
SILENT = "silent"
MODES: tuple[str, ...] = (DEFAULT, VERBOSE, SILENT)

BANNER = "banner"
DISCOVERY = "discovery"
PLAN = "plan"
PROMPT = "prompt"
PHASE = "phase"
DETAIL = "detail"
PROGRESS = "progress"
STILL_WORKING = "still_working"
NEXT_STEPS = "next_steps"
WARNING = "warning"
FAILURE = "failure"
ACTION = "action"
PRESERVATION = "preservation"
RESULT = "result"
LOG = "log"

# Always reaches the console, in every mode. These are the consequences, not the narration.
ALWAYS_EVENTS: frozenset[str] = frozenset(
    {WARNING, FAILURE, ACTION, PRESERVATION, RESULT, LOG}
)
# Mechanics. Verbose only — this is the line default output exists to hold.
VERBOSE_ONLY_EVENTS: frozenset[str] = frozenset({DETAIL})
# Decoration and narration. Default and verbose; silent drops them.
NARRATION_EVENTS: frozenset[str] = frozenset(
    {BANNER, DISCOVERY, PLAN, PROMPT, PHASE, PROGRESS, STILL_WORKING, NEXT_STEPS}
)

_PREFIX: dict[str, str] = {
    BANNER: "==>",
    DISCOVERY: "  *",
    PLAN: "  .",
    PROMPT: "  ?",
    PHASE: "  >",
    DETAIL: "  $",
    PROGRESS: "  ~",
    STILL_WORKING: "  ~",
    NEXT_STEPS: "  ->",
    WARNING: "  !",
    FAILURE: "  x",
    ACTION: "  !!",
    PRESERVATION: "  =",
    RESULT: "",
    LOG: "",
}


@dataclass(frozen=True)
class Event:
    kind: str
    text: str


def visible_in(kind: str, mode: str) -> bool:
    """Whether one event kind reaches the console in one mode. The whole matrix, in one place."""
    if kind in ALWAYS_EVENTS:
        return True
    if mode == SILENT:
        return False
    if kind in VERBOSE_ONLY_EVENTS:
        return mode == VERBOSE
    return True


class OutputEngine:
    """Emits lifecycle events. One instance per operation."""

    def __init__(
        self,
        mode: str = DEFAULT,
        *,
        stream: TextIO | None = None,
        log_path: str | None = None,
        log_sink: Callable[[str], None] | None = None,
        tty: bool | None = None,
        clock: Callable[[], float] | None = None,
        silence_threshold: float = 30.0,
    ):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self._stream = stream if stream is not None else sys.stdout
        self._log_path = log_path
        self._log_sink = log_sink
        self._tty = self._stream.isatty() if tty is None else tty
        self._clock = clock if clock is not None else _monotonic
        self._silence_threshold = silence_threshold
        self._last_console_at = self._clock()
        self._secrets: list[str] = []
        self.events: list[Event] = []
        self._progress_open = False

    # -- secrets ------------------------------------------------------------------------------

    def register_secret(self, value: str | None) -> None:
        """Teach the engine one concrete value it must never print."""
        if value and len(value) >= 4:
            self._secrets.append(value)

    def _clean(self, text: str) -> str:
        return redact(text, registered=self._secrets)

    # -- emission -----------------------------------------------------------------------------

    def emit(self, kind: str, text: str) -> Event:
        if kind not in _PREFIX:
            raise ValueError(f"unknown lifecycle event kind {kind!r}")
        event = Event(kind=kind, text=self._clean(text))
        self.events.append(event)
        self._to_log(event)
        if visible_in(kind, self.mode):
            self._to_console(event)
        return event

    def _to_log(self, event: Event) -> None:
        if self._log_sink is not None:
            self._log_sink(f"{event.kind}: {event.text}")

    def _to_console(self, event: Event) -> None:
        if self._progress_open:
            self._stream.write("\n")
            self._progress_open = False
        prefix = _PREFIX[event.kind]
        line = f"{prefix} {event.text}" if prefix else event.text
        self._stream.write(line + "\n")
        self._last_console_at = self._clock()

    # -- the vocabulary -----------------------------------------------------------------------

    def banner(self, text: str) -> Event:
        return self.emit(BANNER, text)

    def discovery(self, text: str) -> Event:
        return self.emit(DISCOVERY, text)

    def plan(self, text: str) -> Event:
        return self.emit(PLAN, text)

    def prompt(self, text: str) -> Event:
        return self.emit(PROMPT, text)

    def phase(self, text: str) -> Event:
        return self.emit(PHASE, text)

    def detail(self, text: str) -> Event:
        return self.emit(DETAIL, text)

    def next_steps(self, text: str) -> Event:
        return self.emit(NEXT_STEPS, text)

    def warning(self, text: str) -> Event:
        return self.emit(WARNING, text)

    def failure(self, text: str) -> Event:
        return self.emit(FAILURE, text)

    def action(self, text: str) -> Event:
        return self.emit(ACTION, text)

    def preservation(self, text: str) -> Event:
        return self.emit(PRESERVATION, text)

    def progress(self, text: str) -> Event:
        """A long step's live status. One rewritten TTY line; nothing at all when not a TTY."""
        event = Event(kind=PROGRESS, text=self._clean(text))
        self.events.append(event)
        self._to_log(event)
        if not visible_in(PROGRESS, self.mode) or not self._tty:
            return event
        self._stream.write("\r  ~ " + event.text)
        self._progress_open = True
        self._last_console_at = self._clock()
        return event

    def still_working(self, what: str) -> Event | None:
        """After prolonged console silence, say so once, with the transcript path.

        Called by long operations; emits only when the console has actually been quiet, so a chatty
        phase costs nothing. The clock is injected because a behaviour defined by elapsed time is
        otherwise untestable without sleeping.
        """
        if not visible_in(STILL_WORKING, self.mode):
            return None
        if self._clock() - self._last_console_at < self._silence_threshold:
            return None
        suffix = f" (transcript: {self._log_path})" if self._log_path else ""
        return self.emit(STILL_WORKING, f"still working: {what}{suffix}")

    def result(self, value: str) -> Event:
        """``RESULT: <one of the six words>``. Survives every mode."""
        return self.emit(RESULT, f"RESULT: {validate_result(value)}")

    def log(self, path: str | None = None) -> Event | None:
        """``LOG: <transcript path>``. Survives every mode."""
        target = path if path is not None else self._log_path
        if not target:
            return None
        return self.emit(LOG, f"LOG: {target}")

    # -- inspection ---------------------------------------------------------------------------

    def console_events(self) -> tuple[Event, ...]:
        """Exactly the events this mode put in front of the administrator."""
        return tuple(e for e in self.events if visible_in(e.kind, self.mode))


def _monotonic() -> float:
    import time

    return time.monotonic()
