"""Notifications: dispatch alerts when a finding matches the configured status.

Channels (all optional, configured via env):
  - Slack incoming webhook  (NOTIFY_SLACK_WEBHOOK)
  - generic webhook (JSON POST)  (NOTIFY_GENERIC_WEBHOOK)
  - email via SMTP  (SMTP_* + NOTIFY_EMAIL_TO/FROM)

Failures to notify are logged and swallowed — a notification problem must never
break an assessment.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any

import requests

from app.config import settings

logger = logging.getLogger(__name__)


def _slack(text: str) -> None:
    requests.post(settings.notify_slack_webhook, json={"text": text},
                  timeout=settings.request_timeout_seconds)


def _webhook(payload: dict[str, Any]) -> None:
    requests.post(settings.notify_generic_webhook, json=payload,
                  timeout=settings.request_timeout_seconds)


def _email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.notify_email_from or settings.smtp_user
    msg["To"] = settings.notify_email_to
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.request_timeout_seconds) as s:
        s.starttls()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password or "")
        s.send_message(msg)


def notify_finding(finding) -> dict[str, bool]:
    """Dispatch a finding alert to every configured channel. Returns per-channel result."""
    if finding.status.value != settings.notify_on_status:
        return {}

    title = f"[Comp-Lens] {finding.status.value.upper()} · {finding.control_id} · {finding.source_system}"
    body = (f"Tenant: {finding.tenant_id}\nControl: {finding.control_id}\n"
            f"Asset: {finding.asset_id}\nSeverity: {finding.severity.value}\n"
            f"Status: {finding.status.value}\n{finding.description or ''}")
    payload = {
        "tenant_id": finding.tenant_id, "control_id": finding.control_id,
        "source_system": finding.source_system, "asset_id": finding.asset_id,
        "status": finding.status.value, "severity": finding.severity.value,
        "finding_id": finding.finding_id,
    }

    results: dict[str, bool] = {}
    for name, enabled, fn in (
        ("slack", settings.notify_slack_webhook, lambda: _slack(f"{title}\n{body}")),
        ("webhook", settings.notify_generic_webhook, lambda: _webhook(payload)),
        ("email", settings.smtp_host and settings.notify_email_to, lambda: _email(title, body)),
    ):
        if not enabled:
            continue
        try:
            fn()
            results[name] = True
        except Exception as exc:  # noqa: BLE001
            logger.warning("notify %s failed: %s", name, exc)
            results[name] = False
    return results
