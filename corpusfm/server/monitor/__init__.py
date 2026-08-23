"""corpusfm monitor — alert conditions, history, and notification dispatch.

Public API:
    MonitorConfig, load_monitor_config, save_monitor_config
    AlertEvent, check_conditions, evaluate_alerts
    append_alert, load_alert_history
    suppress_alert, is_suppressed
    JobHealthRow, get_job_health
    dispatch_alert
"""

from corpusfm.server.monitor.config import MonitorConfig, load_monitor_config, save_monitor_config
from corpusfm.server.monitor.alerts import (
    AlertEvent,
    check_conditions,
    evaluate_alerts,
    append_alert,
    load_alert_history,
    suppress_alert,
    is_suppressed,
)
from corpusfm.server.monitor.history import JobHealthRow, get_job_health
from corpusfm.server.monitor.notify import dispatch_alert

__all__ = [
    "MonitorConfig", "load_monitor_config", "save_monitor_config",
    "AlertEvent", "check_conditions", "evaluate_alerts",
    "append_alert", "load_alert_history",
    "suppress_alert", "is_suppressed",
    "JobHealthRow", "get_job_health",
    "dispatch_alert",
]
