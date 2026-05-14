# app/crawler/tor_session.py
import time
import logging
from app.config import settings

logger = logging.getLogger(__name__)

try:
    from stem.control import Controller
except ImportError:
    Controller = None


class TorSession:
    def __init__(self):
        self.controller = None
        self.request_count = 0
        self._connect()

    def _connect(self):
        if Controller is None:
            raise RuntimeError("stem library not installed")
        try:
            self.controller = Controller.from_port(
                host=settings.TOR_HOST,
                port=settings.TOR_CONTROL_PORT
            )
        except Exception as e:
            logger.error(f"Tor control port not available: {e}")
            raise RuntimeError("Tor is not running or control port not accessible")

    def get_circuit_id(self) -> str | None:
        if self.controller is None:
            return None
        try:
            active = self.controller.get_active_circuit()
            if active:
                circuit = self.controller.get_circuit(active)
                return circuit.id if circuit else None
            return None
        except Exception:
            return None

    def rotate_circuit(self):
        if self.controller is None:
            self._connect()
        try:
            self.controller.send_signal("NEWNYM")
            time.sleep(2)
            self.request_count = 0
            logger.info("Tor circuit rotated")
        except Exception as e:
            logger.error(f"Failed to rotate Tor circuit: {e}")

    def should_rotate(self) -> bool:
        self.request_count += 1
        return self.request_count % settings.NEWNYM_INTERVAL == 0

    def close(self):
        if self.controller:
            self.controller.close()
            self.controller = None