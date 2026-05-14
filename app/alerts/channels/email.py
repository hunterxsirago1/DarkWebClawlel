# app/alerts/channels/email.py
import smtplib
import logging
from email.mime.text import MIMEText
from app.config import settings

logger = logging.getLogger(__name__)


def send(finding: dict) -> bool:
    if not settings.ALERT_EMAIL_HOST:
        return False
    body = (
        f"Severity: {finding.get('severity', 'unknown')}\n"
        f"Matched: {finding.get('matched_value', '')}\n"
        f"Context: {finding.get('context', '')}\n"
        f"Source: {finding.get('source_url', 'unknown')}\n"
    )
    msg = MIMEText(body, "plain")
    msg["Subject"] = f"[{finding.get('severity', 'unknown').upper()}] Dark Web Alert"
    msg["From"] = settings.ALERT_EMAIL_FROM
    try:
        with smtplib.SMTP(settings.ALERT_EMAIL_HOST, settings.ALERT_EMAIL_PORT) as server:
            server.starttls()
            if settings.ALERT_EMAIL_USER:
                server.login(settings.ALERT_EMAIL_USER, settings.ALERT_EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Email alert failed: {e}")
        return False