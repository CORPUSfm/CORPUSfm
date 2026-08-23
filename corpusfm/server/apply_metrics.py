"""Apply-loop instrumentation — the thermometer for the patch apply pipeline.

The FMUpgradeTool apply loop (close -> patch -> swap -> reopen) is heavy and
fails in a handful of recurring ways. Before anyone optimizes the loop, we need
to know — from real runs — how long each step actually takes and how it tends to
fail. This module records, per run, the per-step wall-clock and (on failure) a
classified failure mode, appended to a JSONL log that accumulates across runs.

"Build the thermometer before the fix" (CLAUDE.md -> Ideas -> test-cycle cost).

Mirrors tools/discovery_log.py: append-only JSONL, thread-safe, never raises so
instrumentation can never break a real apply.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()

# Failure-mode taxonomy. Ordered: first match wins. Each rule maps a
# case-insensitive regex (matched against a FAILED step's output) to a stable
# label so failures aggregate across runs. classify_failure() is only meaningful
# on a step that already returned ok=False — the patterns assume an error string.
_FAILURE_RULES: list[tuple[str, str]] = [
    (r"timed out", "timeout"),
    (r"binary not found|not found:\s", "binary_not_found"),
    (r"\b956\b|maximum number of admin api sessions", "session_limit"),
    (r"no admin password provided|no pki key configured and no admin password", "no_admin_creds"),
    (r"no pki key configured and fmsadmin not found", "no_admin_tooling"),
    (r"pki admin-api .* failed|pki/.*:.*\b(error|fail)", "pki_failed"),
    (r"\b212\b|authentication failed|invalid credential|access denied|wrong password", "auth_failed"),
    (r"\b802\b|in use|currently open|client(s)? connected|database is locked", "db_busy"),
    (r"\[swap\] failed|errno|read-only file system|permission denied", "swap_failed"),
    (r"invalid patch|malformed|could not find|does not exist|no such|parse error|uuid", "patch_invalid"),
]


def classify_failure(output: str) -> str:
    """Map a failed step's raw output to a stable failure-mode label.

    Returns "unknown" when nothing matches. Call only for ok=False steps.
    """
    text = (output or "").lower()
    for pattern, kind in _FAILURE_RULES:
        if re.search(pattern, text):
            return kind
    return "unknown"


@dataclass
class StepMetric:
    """One step of the apply loop: how long it took and how it fared."""

    step: str  # close | apply | swap | reopen
    seconds: float
    ok: bool
    failure_kind: str = ""  # "" when ok; a taxonomy label otherwise

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "seconds": self.seconds,
            "ok": self.ok,
            "failure_kind": self.failure_kind,
        }


@dataclass
class ApplyMetrics:
    """A full apply-loop run: per-step timings + overall outcome."""

    database: str
    started_at: str  # ISO-8601 UTC
    total_seconds: float
    overall_ok: bool
    steps: list[StepMetric] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ts": self.started_at,
            "database": self.database,
            "total_seconds": self.total_seconds,
            "overall_ok": self.overall_ok,
            "steps": [s.to_dict() for s in self.steps],
            # Convenience: the failing step's kind (or "" on success), so a reader
            # can histogram failures without walking the steps list.
            "failure_kind": next(
                (s.failure_kind for s in self.steps if not s.ok), ""
            ),
        }


def metrics_log_path(archive_dir) -> Path:
    """Canonical location of the apply-metrics log under a backend archive dir."""
    return Path(archive_dir) / "apply_metrics.jsonl"


def record_step(
    step: str,
    seconds: float,
    ok: bool,
    *,
    database: str = "",
    output: str = "",
    metrics_path: Path | None = None,
) -> None:
    """Record a single non-apply step (validate / coherence / verify) as its own
    one-step run, so summarize_apply_metrics() folds it into the same per-step
    histogram as the close/apply/swap/reopen loop. No-op when metrics_path is None.

    The whole point of the thermometer is to compare the cheap pre-flight gates
    (coherence ~ms, validate ~s) against the heavy apply loop (close/swap/reopen),
    so the cheapest gate that can reject a bad patch runs first.
    """
    if metrics_path is None:
        return
    kind = "" if ok else classify_failure(output)
    append_apply_metrics(
        ApplyMetrics(
            database=database,
            started_at=datetime.now(timezone.utc).isoformat(),
            total_seconds=round(seconds, 3),
            overall_ok=ok,
            steps=[StepMetric(step=step, seconds=round(seconds, 3), ok=ok, failure_kind=kind)],
        ),
        metrics_path,
    )


def append_apply_metrics(metrics: ApplyMetrics, log_path: Path) -> None:
    """Append one apply-loop run to the metrics log. Best-effort, never raises."""
    try:
        entry = metrics.to_dict()
        log_path = Path(log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    except Exception:
        # Instrumentation must never break a real apply.
        return


def read_apply_metrics(log_path: Path) -> list[dict]:
    """Return all runs from the metrics log, newest-first. Empty if absent."""
    log_path = Path(log_path)
    if not log_path.exists():
        return []
    entries: list[dict] = []
    with log_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    entries.reverse()
    return entries


def summarize_apply_metrics(entries: list[dict]) -> dict:
    """Aggregate apply-loop runs into a readable thermometer.

    Returns counts, success rate, a failure-mode histogram, and per-step timing
    stats (count, mean, p50, max seconds). Built for a future Logs/Settings panel
    and for deciding where the loop actually hurts.
    """
    total = len(entries)
    if total == 0:
        return {"runs": 0, "ok": 0, "success_rate": 0.0, "failures": {}, "steps": {}}

    ok_runs = sum(1 for e in entries if e.get("overall_ok"))
    failures: dict[str, int] = {}
    for e in entries:
        if not e.get("overall_ok"):
            kind = e.get("failure_kind") or "unknown"
            failures[kind] = failures.get(kind, 0) + 1

    # Per-step timing samples.
    by_step: dict[str, list[float]] = {}
    for e in entries:
        for s in e.get("steps", []):
            name = s.get("step", "?")
            secs = s.get("seconds")
            if isinstance(secs, (int, float)):
                by_step.setdefault(name, []).append(float(secs))

    def _stats(samples: list[float]) -> dict:
        ordered = sorted(samples)
        n = len(ordered)
        return {
            "count": n,
            "mean": round(sum(ordered) / n, 3),
            "p50": round(ordered[n // 2], 3),
            "max": round(ordered[-1], 3),
        }

    steps = {name: _stats(s) for name, s in by_step.items()}

    return {
        "runs": total,
        "ok": ok_runs,
        "success_rate": round(ok_runs / total, 3),
        "failures": failures,
        "steps": steps,
    }
