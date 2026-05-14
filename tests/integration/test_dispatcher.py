# tests/integration/test_dispatcher.py
import pytest
from unittest.mock import patch, MagicMock


def test_email_channel_sends():
    from app.alerts.channels import email as email_module
    mock_msg = MagicMock()
    mock_smtp_instance = MagicMock()
    mock_smtp_instance.send_message.return_value = None
    with patch.object(email_module.settings, "ALERT_EMAIL_HOST", "smtp.example.com"):
        with patch.object(email_module.settings, "ALERT_EMAIL_PORT", 587):
            with patch.object(email_module.settings, "ALERT_EMAIL_USER", "user"):
                with patch.object(email_module.settings, "ALERT_EMAIL_PASSWORD", "pass"):
                    with patch.object(email_module.settings, "ALERT_EMAIL_FROM", "from@example.com"):
                        with patch.object(email_module, "MIMEText", return_value=mock_msg):
                            with patch.object(email_module, "smtplib") as mock_smtp:
                                mock_smtp_instance.__enter__ = MagicMock(return_value=mock_smtp_instance)
                                mock_smtp_instance.__exit__ = MagicMock(return_value=False)
                                mock_smtp.SMTP.return_value = mock_smtp_instance
                                result = email_module.send({
                                    "id": 1,
                                    "matched_value": "test@example.com",
                                    "severity": "high",
                                    "context": "found in leak",
                                    "source_url": "http://example.onion",
                                })
                                assert result is True


def test_slack_channel_sends():
    from app.alerts.channels import slack as slack_module
    with patch.object(slack_module.settings, "SLACK_WEBHOOK_URL", "https://hooks.slack.com/fake"):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            result = slack_module.send({
                "id": 1,
                "matched_value": "test@example.com",
                "severity": "high",
                "context": "found in leak",
                "source_url": "http://example.onion",
            })
            assert result is True