# app/alerts/dispatcher.py
import logging
from app.config import settings
from app.db.crud import insert_alert, mark_finding_alerted

logger = logging.getLogger(__name__)


def dispatch_alert(finding: dict, session_factory) -> bool:
    channels = []
    if settings.ALERT_EMAIL_HOST:
        from app.alerts.channels import email
        channels.append(("email", email.send))
    if settings.SLACK_WEBHOOK_URL:
        from app.alerts.channels import slack
        channels.append(("slack", slack.send))
    if settings.WEBHOOK_URL:
        from app.alerts.channels import webhook
        channels.append(("webhook", webhook.send))

    if not channels:
        logger.warning("No alert channels configured")
        return False

    success = False
    for channel_name, send_fn in channels:
        try:
            result = send_fn(finding)
            session = session_factory()
            insert_alert(session, finding["id"], channel_name, result)
            if result:
                success = True
        except Exception as e:
            logger.error(f"Alert dispatch failed via {channel_name}: {e}")
            session = session_factory()
            insert_alert(session, finding["id"], channel_name, False, str(e))

    if success:
        session = session_factory()
        mark_finding_alerted(session, finding["id"])

    return success