"""Alert condition evaluation, history, and suppression.

Alert conditions:
  job_failed          — last run status is "error"
  job_overdue         — scheduled job hasn't run within grace period of expected fire time
  zero_diff_suspicion — N consecutive runs produced zero git changes (possible silent failure)
  scheduler_stopped   — scheduler.json heartbeat is stale (process died)
  disk_low            — archive directory free space below threshold

History + suppression live in the DB (the ``ALERT`` table, packet 1019) so alert state travels with the
data like every other operational table — a scheduler process writes events, the web/MCP read them.

Public API:
    AlertEvent
    check_conditions(archive_dir, config) -> list[AlertEvent]
    evaluate_alerts(archive_dir, config) -> list[AlertEvent]
    append_alert(event)
    load_alert_history(limit) -> list[AlertEvent]
    suppress_alert(condition, job_name, hours)
    is_suppressed(condition, job_name) -> bool
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from corpusfm.core import servertime as _servertime
from corpusfm.server.monitor.config import MonitorConfig


@dataclass
class AlertEvent:
    ts: str                        # ISO timestamp
    condition: str                 # job_failed | job_overdue | zero_diff_suspicion | scheduler_stopped | disk_low
    severity: str                  # error | warning
    message: str
    job_name: Optional[str] = None
    # The job's uuid (packet 1149) — the suppression key. A name is reusable: delete a job and
    # create another with the same name and the new one would inherit the dead one's muting.
    job_uuid: Optional[str] = None


def _repo(backend=None):
    """The AlertsRepo over a backend's engine (packet 1019), or None if unavailable.

    ``backend`` lets a caller that already holds one supply it (packet 1361-01). Resolving one here
    means a global `get_backend()`, which on a published installation builds a fresh
    FileMakerODataBackend and pays a TLS handshake — a real cost on a route polled every ten seconds
    by every open tab.
    """
    from corpusfm.storage.repos import alerts_repo
    try:
        if backend is None:
            from corpusfm.storage import get_backend
            backend = get_backend()
        return alerts_repo(backend)
    except Exception:
        return None


# ── Suppression (DB-backed) ────────────────────────────────────────────────────

def _scope(job_name: Optional[str], job_uuid: Optional[str] = None) -> Optional[str]:
    """The suppression scope for a job — its UUID whenever one can be had (packet 1149).

    Callers speak in names (the UI's alert row, the MCP tool's ``job_name``), which is right for a
    human interface and wrong for a stored key: a deleted-and-recreated job reuses the name but not
    the uuid, and would otherwise start life already muted. Resolve here, once. A name that no
    THE NAME FALLBACK IS GONE (packet 1372-02, R4). It resolved a job from a display label to build
    a suppression key, and duplicate names are ordinary now — so acknowledging one job's alert could
    suppress another's. A caller with no uuid gets the name back as an opaque key: it suppresses
    exactly what it names and joins to nothing."""
    return job_uuid or job_name


def suppress_alert(condition: str, job_name: Optional[str], hours: int,
                   job_uuid: Optional[str] = None) -> None:
    """Suppress an alert until now + ``hours`` — one ``suppress`` row per ``<condition>:<job uuid>``."""
    until = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    repo = _repo()
    if repo is not None:
        repo.set_suppress(condition, _scope(job_name, job_uuid), until, job_name=job_name)


def is_suppressed(condition: str, job_name: Optional[str],
                  job_uuid: Optional[str] = None) -> bool:
    """True if this alert is currently suppressed."""
    repo = _repo()
    return bool(repo and repo.is_suppressed(condition, _scope(job_name, job_uuid)))


# ── History (DB-backed) ─────────────────────────────────────────────────────────

def append_alert(event: AlertEvent) -> None:
    """Append one alert event to the DB history (``ALERT`` table)."""
    repo = _repo()
    if repo is not None:
        repo.append_event(ts=event.ts, condition=event.condition, severity=event.severity,
                          message=event.message, job_name=event.job_name)


def load_alert_history(limit: int = 50, *, strict: bool = False, backend=None) -> list[AlertEvent]:
    """The most recent ``limit`` alert events, newest first.

    ``strict=True`` raises `AlertReadUnavailable` instead of degrading an UNREADABLE history to an
    empty list (packet 1361-01). A genuinely empty ALERT table still answers ``[]`` under strict —
    "there are none" is an answer, "could not ask" is not, and only the caller knows whether it can
    afford to conflate them. Default False, so every existing caller keeps today's behavior.

    ``backend`` is passed straight to the repo, so a caller that already holds one is not made to
    resolve another.
    """
    from corpusfm.storage.repos import AlertReadUnavailable

    repo = _repo(backend)
    if repo is None:
        if strict:
            raise AlertReadUnavailable(
                "the active storage backend exposes no engine, so ALERT cannot be read.")
        return []
    try:
        rows = repo.list_history(limit)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("load_alert_history failed", exc_info=True)
        if strict:
            raise AlertReadUnavailable(
                "The alert history could not be read from storage "
                f"({type(exc).__name__}). See the CORPUSfm server log for detail.") from exc
        return []
    return [AlertEvent(ts=d["ts"], condition=d["condition"], severity=d["severity"],
                       message=d["message"], job_name=d["job_name"])
            for d in rows]


# ── Condition evaluation ──────────────────────────────────────────────────────

def check_conditions(
    archive_dir: Path,
    config: MonitorConfig,
) -> list[AlertEvent]:
    """Evaluate all alert conditions. Returns all currently firing alerts (suppressed or not)."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    events: list[AlertEvent] = []

    try:
        from corpusfm.server.jobs.store import list_jobs_with_state
        from corpusfm.server.jobs.history import list_runs_for
        from corpusfm.storage import get_backend
        backend = get_backend()

        for cfg, state in list_jobs_with_state():

            # ── job_failed ────────────────────────────────────────────────
            if state.last_status == "error":
                events.append(AlertEvent(
                    ts=now_iso,
                    condition="job_failed",
                    severity="error",
                    message=(
                        f"Job '{cfg.name}' failed: "
                        f"{state.last_error or 'unknown error'}"
                    ),
                    job_name=cfg.name,
                    job_uuid=getattr(cfg, "id", "") or "",
                ))

            # ── job_overdue ───────────────────────────────────────────────
            schedule_triggers = [
                t for t in cfg.triggers if t.type == "schedule"
            ] if cfg.triggers else []

            for trigger in schedule_triggers:
                try:
                    from corpusfm.server.scheduler import previous_fire
                    prev_fire = previous_fire(trigger)
                    if prev_fire is None:
                        continue

                    grace = timedelta(minutes=config.overdue_grace_minutes)
                    if now < prev_fire + grace:
                        continue  # within grace period

                    # Check if job ran after the expected fire time
                    ran_since = False
                    if state.last_run_ts:
                        last_run = datetime.fromisoformat(
                            state.last_run_ts.replace("Z", "+00:00")
                        )
                        if last_run.tzinfo is None:
                            last_run = last_run.replace(tzinfo=timezone.utc)
                        ran_since = last_run >= prev_fire

                    if not ran_since:
                        events.append(AlertEvent(
                            ts=now_iso,
                            condition="job_overdue",
                            severity="warning",
                            message=(
                                f"Job '{cfg.name}' is overdue. "
                                f"Expected at {prev_fire.strftime('%Y-%m-%d %H:%M')} "
                                # Server-local since packet 1185 — this said "UTC" while the value
                                # was UTC, and would have kept saying it once the value was not.
                                f"{_servertime.short_label(at=prev_fire)}"
                            ),
                            job_name=cfg.name,
                    job_uuid=getattr(cfg, "id", "") or "",
                        ))
                except Exception:
                    pass
                break  # one overdue check per job (first schedule trigger)

            # ── zero_diff_suspicion ───────────────────────────────────────
            has_git_export = (
                cfg.process
                and cfg.process.git_export
                and cfg.process.git_export.registrations
            )
            if has_git_export:
                try:
                    runs = list_runs_for(getattr(cfg, "id", "") or "",
                                         limit=config.zero_diff_threshold, backend=backend)
                    if len(runs) >= config.zero_diff_threshold:
                        all_no_change = all(
                            r.status == "ok"
                            and r.git_commits
                            and all(c == "no-change" for c in r.git_commits)
                            for r in runs
                        )
                        if all_no_change:
                            events.append(AlertEvent(
                                ts=now_iso,
                                condition="zero_diff_suspicion",
                                severity="warning",
                                message=(
                                    f"Job '{cfg.name}' produced zero git changes "
                                    f"for {len(runs)} consecutive runs — "
                                    "possible extraction failure"
                                ),
                                job_name=cfg.name,
                    job_uuid=getattr(cfg, "id", "") or "",
                            ))
                except Exception:
                    pass

    except Exception:
        pass

    # ── scheduler_stopped ─────────────────────────────────────────────────────
    # The scheduler is a WEB-OWNED component now (packet 1361-01, round 2), so this is an exact
    # in-process answer rather than a staleness judgement over a file another process wrote — and it
    # reads neither the filesystem nor FileMaker, which is what lets it be asked while paused.
    # `ever_started` is the in-memory successor to "a status file exists": a process that never
    # started the clock (readiness never opened) has no scheduler to call stopped.
    try:
        from corpusfm.server.scheduler import scheduler_ever_started, scheduler_is_running
        if scheduler_ever_started() and not scheduler_is_running():
            events.append(AlertEvent(
                ts=now_iso,
                condition="scheduler_stopped",
                severity="error",
                message="The scheduler clock has stopped inside the CORPUSfm web service",
            ))
    except Exception:
        pass

    # ── disk_low ──────────────────────────────────────────────────────────────
    try:
        if archive_dir.exists():
            stat = shutil.disk_usage(archive_dir)
            free_gb = stat.free / (1024 ** 3)
            if free_gb < config.disk_min_gb:
                events.append(AlertEvent(
                    ts=now_iso,
                    condition="disk_low",
                    severity="warning",
                    message=(
                        f"Archive disk space low: {free_gb:.1f} GB free "
                        f"(threshold: {config.disk_min_gb} GB)"
                    ),
                ))
    except Exception:
        pass

    return events


def evaluate_alerts(
    archive_dir: Path,
    config: MonitorConfig,
) -> list[AlertEvent]:
    """Return only unsuppressed firing alerts (for dispatch to notification channels)."""
    return [
        e for e in check_conditions(archive_dir, config)
        if not is_suppressed(e.condition, e.job_name, e.job_uuid)
    ]
