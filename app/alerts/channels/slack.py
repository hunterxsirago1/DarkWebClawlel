# app/alerts/channels/slack.py
import requests
import logging
from app.config import settings

logger = logging.getLogger(__name__)


def send(finding: dict) -> bool:
    if not settings.SLACK_WEBHOOK_URL:
        return False
    severity = finding.get("severity", "unknown").upper()
    matched = finding.get("matched_value", "")
    context = finding.get("context", "")
    source = finding.get("source_url", "unknown")
    payload = {
        "text": f"🚨 *Dark Web Alert* `[{severity}]`\n"
                f"*Matched:* `{matched}`\n"
                f"*Context:* {context}\n"
                f"*Source:* {source}"
    }
    try:
        r = requests.post(settings.SLACK_WEBHOOK_URL, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False