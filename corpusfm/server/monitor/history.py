"""Cross-job health summary for the monitoring tab.

Public API:
    JobHealthRow
    get_job_health(jobs_dir, config) -> list[JobHealthRow]
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from corpusfm.server.monitor.config import MonitorConfig


@dataclass
class JobHealthRow:
    name: str
    source_type: str
    schedule: Optional[str]        # first cron expression, or None
    last_run_ts: Optional[str]
    last_status: Optional[str]     # ok | error | None
    overdue: bool


def get_job_health(
    jobs_dir: Path,
    config: MonitorConfig,
) -> list[JobHealthRow]:
    """Return one health row per configured job, sorted by name."""
    from corpusfm.server.jobs.store import list_jobs_with_state

    rows: list[JobHealthRow] = []
    now = datetime.now(timezone.utc)

    for cfg, state in list_jobs_with_state(jobs_dir):

        from corpusfm.server.jobs import schedule as _sched
        schedule_triggers = [
            t for t in cfg.triggers if t.type == "schedule"
        ] if cfg.triggers else []
        trigger = schedule_triggers[0] if schedule_triggers else None
        resolved = trigger.resolved_schedule() if trigger is not None else None
        # The health row shows the schedule the way the job form does, not the way it is stored.
        schedule = _sched.summary(resolved) if resolved is not None else None

        overdue = False
        if trigger is not None:
            try:
                # Server-local, matching the clock the scheduler fires on (packet 1185).
                from corpusfm.server.scheduler import previous_fire
                prev_fire = previous_fire(trigger)
                grace = timedelta(minutes=config.overdue_grace_minutes)
                if prev_fire is not None and now >= prev_fire + grace:
                    ran_since = False
                    if state.last_run_ts:
                        last_run = datetime.fromisoformat(
                            state.last_run_ts.replace("Z", "+00:00")
                        )
                        if last_run.tzinfo is None:
                            last_run = last_run.replace(tzinfo=timezone.utc)
                        ran_since = last_run >= prev_fire
                    overdue = not ran_since
            except Exception:
                pass

        rows.append(JobHealthRow(
            name=cfg.name,
            source_type=cfg.source.type if cfg.source else "?",
            schedule=schedule,
            last_run_ts=state.last_run_ts,
            last_status=state.last_status,
            overdue=overdue,
        ))

    return sorted(rows, key=lambda r: r.name)
