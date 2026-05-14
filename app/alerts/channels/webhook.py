# app/alerts/channels/webhook.py
import requests
import logging
import hmac
import hashlib
from app.config import settings

logger = logging.getLogger(__name__)


def send(finding: dict) -> bool:
    if not settings.WEBHOOK_URL:
        return False
    headers = {"Content-Type": "application/json"}
    if settings.WEBHOOK_SECRET:
        sig = hmac.new(
            settings.WEBHOOK_SECRET.encode(),
            str(finding).encode(),
            hashlib.sha256
        ).hexdigest()
        headers["X-Webhook-Signature"] = sig
    try:
        r = requests.post(settings.WEBHOOK_URL, json=finding, headers=headers, timeout=10)
        return r.status_code in (200, 201, 202, 204)
    except Exception as e:
        logger.error(f"Webhook alert failed: {e}")
        return False