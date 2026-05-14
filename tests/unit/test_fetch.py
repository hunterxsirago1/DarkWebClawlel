# tests/unit/test_fetch.py
import pytest
from unittest.mock import patch, MagicMock


def test_fetch_via_socks5_proxy():
    with patch("requests.Session") as mock_session:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Test content</html>"
        mock_response.headers = {"content-type": "text/html"}
        mock_session.return_value.get.return_value = mock_response

        from app.crawler.fetch import fetch_url
        status, content = fetch_url("http://test.onion/page", "socks5h://127.0.0.1:9050")
        assert status == 200
        assert "Test content" in content