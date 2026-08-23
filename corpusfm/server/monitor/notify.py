"""Notification channel dispatch — webhook and email.

"Display" (Monitoring tab + browser notification) is handled by the UI layer,
not this module. This module only sends to external channels.

Public API:
    send_webhook(url, event) -> bool
    send_email(email_config, event) -> bool
    dispatch_alert(event, config)
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from dataclasses import asdict
from email.message import EmailMessage

import requests

from corpusfm.server.monitor.alerts import AlertEvent
from corpusfm.server.monitor.config import MonitorConfig

log = logging.getLogger("corpusfm.server.monitor.notify")


def send_webhook(url: str, event: AlertEvent) -> bool:
    """POST alert as JSON to a webhook URL. Returns True on success."""
    payload = {k: v for k, v in asdict(event).items() if v is not None}
    payload["source"] = "corpusfm"
    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as exc:
        log.warning("Webhook delivery failed: %s", exc)
        return False


def send_email(email_config: dict, event: AlertEvent) -> bool:
    """Send alert via SMTP. Returns True on success.

    email_config keys:
        smtp_host, smtp_port (int, default 587), username, password,
        from_addr, to_addrs (list[str])
    """
    host = email_config.get("smtp_host", "")
    port = int(email_config.get("smtp_port", 587))
    username = email_config.get("username", "")
    password = email_config.get("password", "")
    from_addr = email_config.get("from_addr", username)
    to_addrs = email_config.get("to_addrs", [])

    if not host or not to_addrs:
        log.warning("Email config incomplete — skipping")
        return False

    subject = f"[corpusfm] {event.severity.upper()}: {event.condition}"
    body = f"{event.message}\n\nJob: {event.job_name or '—'}\nTime: {event.ts}"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(host, port) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            if username and password:
                smtp.login(username, password)
            smtp.sendmail(from_addr, to_addrs, msg.as_string())
        return True
    except Exception as exc:
        log.warning("Email delivery failed: %s", exc)
        return False


def dispatch_alert(event: AlertEvent, config: MonitorConfig) -> None:
    """Send event to all configured external channels (webhook, email).

    The display channel (UI + browser notification) is handled by the Monitoring tab.
    Errors in dispatch are logged but never raised — monitoring must not break the scheduler.
    """
    if config.webhook_url:
        send_webhook(config.webhook_url, event)

    if config.email:
        send_email(config.email, event)
