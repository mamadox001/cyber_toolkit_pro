# =============================================================================
# CyberToolkit Pro — Multi-Channel Notification System
# =============================================================================
# Sends alerts when scans complete, critical findings discovered, or
# campaigns finish. Supports Slack, Discord, Telegram, Email, and Desktop.
# =============================================================================

import json
import os
from typing import Dict, Optional, List
from datetime import datetime

from core.config import Config
from core.logger import get_logger

logger = get_logger("notifier")


class Notifier:
    """Multi-channel notification system for framework events."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._cfg = Config()
        self._channels = []
        self._load_config()

    def _load_config(self):
        """Load notification channel configurations."""
        # Slack
        slack_webhook = self._cfg.get("notifications.slack_webhook", "")
        if slack_webhook:
            self._channels.append(("slack", slack_webhook))

        # Discord
        discord_webhook = self._cfg.get("notifications.discord_webhook", "")
        if discord_webhook:
            self._channels.append(("discord", discord_webhook))

        # Telegram
        tg_token = self._cfg.get("notifications.telegram_token", "")
        tg_chat = self._cfg.get("notifications.telegram_chat_id", "")
        if tg_token and tg_chat:
            self._channels.append(("telegram", {"token": tg_token, "chat_id": tg_chat}))

        # Email
        smtp_host = self._cfg.get("notifications.smtp_host", "")
        if smtp_host:
            self._channels.append(("email", {
                "host": smtp_host,
                "port": self._cfg.get("notifications.smtp_port", 587),
                "username": self._cfg.get("notifications.smtp_username", ""),
                "password": self._cfg.get("notifications.smtp_password", ""),
                "from": self._cfg.get("notifications.email_from", ""),
                "to": self._cfg.get("notifications.email_to", ""),
            }))

        # Desktop (always available as fallback)
        if self._cfg.get("notifications.desktop", True):
            self._channels.append(("desktop", None))

    def notify(self, title: str, message: str, severity: str = "info",
               data: Optional[Dict] = None) -> List[str]:
        """
        Send notification to all configured channels.
        Returns list of channels that were notified.
        """
        notified = []
        full_message = f"[{severity.upper()}] {title}\n{message}"
        if data:
            full_message += f"\n\nData: {json.dumps(data, indent=2, default=str)[:500]}"

        for channel_type, config in self._channels:
            try:
                if channel_type == "slack":
                    self._send_slack(config, title, message, severity)
                    notified.append("slack")
                elif channel_type == "discord":
                    self._send_discord(config, title, message, severity)
                    notified.append("discord")
                elif channel_type == "telegram":
                    self._send_telegram(config, title, message)
                    notified.append("telegram")
                elif channel_type == "email":
                    self._send_email(config, title, full_message)
                    notified.append("email")
                elif channel_type == "desktop":
                    self._send_desktop(title, message)
                    notified.append("desktop")
            except Exception as e:
                logger.error(f"Notification to {channel_type} failed: {e}")

        return notified

    def notify_scan_complete(self, tool_name: str, target: str,
                              status: str, findings_count: int,
                              duration_ms: float):
        """Notify that a scan has completed."""
        severity = "info"
        if findings_count > 0:
            severity = "warning"
        if status == "error":
            severity = "error"

        title = f"Scan Complete: {tool_name}"
        message = (
            f"Target: {target}\n"
            f"Status: {status}\n"
            f"Findings: {findings_count}\n"
            f"Duration: {duration_ms:.0f}ms"
        )
        self.notify(title, message, severity)

    def notify_campaign_complete(self, campaign_name: str,
                                  total_targets: int, total_findings: int,
                                  duration_seconds: float):
        """Notify that a campaign has completed."""
        severity = "warning" if total_findings > 0 else "info"
        title = f"Campaign Complete: {campaign_name}"
        message = (
            f"Targets: {total_targets}\n"
            f"Total Findings: {total_findings}\n"
            f"Duration: {duration_seconds:.1f}s"
        )
        self.notify(title, message, severity)

    def notify_critical_finding(self, tool_name: str, target: str,
                                 finding_title: str):
        """Notify about a critical/high severity finding."""
        title = f"CRITICAL Finding: {finding_title}"
        message = f"Tool: {tool_name}\nTarget: {target}"
        self.notify(title, message, "critical")

    def _send_slack(self, webhook_url: str, title: str,
                     message: str, severity: str):
        """Send Slack webhook notification."""
        import urllib.request
        colors = {"info": "#36a64f", "warning": "#ff9900",
                  "error": "#ff0000", "critical": "#990000"}
        payload = json.dumps({
            "attachments": [{
                "color": colors.get(severity, "#36a64f"),
                "title": f"CyberToolkit Pro: {title}",
                "text": message,
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_discord(self, webhook_url: str, title: str,
                       message: str, severity: str):
        """Send Discord webhook notification."""
        import urllib.request
        colors = {"info": 3066993, "warning": 16776960,
                  "error": 15158332, "critical": 10038562}
        payload = json.dumps({
            "embeds": [{
                "title": f"CyberToolkit Pro: {title}",
                "description": message,
                "color": colors.get(severity, 3066993),
            }]
        }).encode("utf-8")
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)

    def _send_telegram(self, config: Dict, title: str, message: str):
        """Send Telegram bot notification."""
        import urllib.request
        import urllib.parse
        token = config["token"]
        chat_id = config["chat_id"]
        text = f"*CyberToolkit Pro*\n*{title}*\n\n{message}"
        url = (
            f"https://api.telegram.org/bot{token}/sendMessage?"
            f"chat_id={chat_id}&text={urllib.parse.quote(text)}&parse_mode=Markdown"
        )
        urllib.request.urlopen(url, timeout=10)

    def _send_email(self, config: Dict, subject: str, body: str):
        """Send email notification via SMTP."""
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body)
        msg["Subject"] = f"CyberToolkit Pro: {subject}"
        msg["From"] = config["from"]
        msg["To"] = config["to"]
        with smtplib.SMTP(config["host"], config["port"]) as server:
            server.starttls()
            if config.get("username"):
                server.login(config["username"], config["password"])
            server.sendmail(config["from"], [config["to"]], msg.as_string())

    def _send_desktop(self, title: str, message: str):
        """Send desktop notification (console fallback)."""
        logger.info(f"[NOTIFICATION] {title}: {message}")


# Module-level singleton
_notifier = None


def get_notifier() -> Notifier:
    """Get the global notifier instance."""
    global _notifier
    if _notifier is None:
        _notifier = Notifier()
    return _notifier
