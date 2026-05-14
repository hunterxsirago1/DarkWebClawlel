# tests/unit/test_tor_session.py
import pytest
from unittest.mock import MagicMock, patch


def test_circuit_rotation_signal():
    mock_instance = MagicMock()
    mock_controller_class = MagicMock()
    mock_controller_class.from_port.return_value = mock_instance
    with patch.dict("sys.modules", {"stem.control": MagicMock(Controller=mock_controller_class)}):
        with patch("app.crawler.tor_session.Controller", mock_controller_class):
            from app.crawler.tor_session import TorSession
            tor = TorSession()
            tor.rotate_circuit()
            mock_instance.send_signal.assert_called_once_with("NEWNYM")