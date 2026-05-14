# app/crawler/fetch.py
import requests
import logging
from requests.exceptions import RequestException, SSLError, ProxyError
from app.config import settings

logger = logging.getLogger(__name__)


class Fetcher:
    def __init__(self, proxy_url: str = None):
        self.proxy_url = proxy_url or f"socks5h://{settings.TOR_HOST}:{settings.TOR_SOCKS_PORT}"
        self.session = requests.Session()
        self.session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def fetch(self, url: str, timeout: int = 30) -> tuple[int, str]:
        try:
            response = self.session.get(url, timeout=timeout)
            return response.status_code, response.text
        except ProxyError as e:
            logger.warning(f"Proxy error fetching {url}: {e}")
            return 0, ""
        except SSLError as e:
            logger.warning(f"SSL error fetching {url}: {e}")
            return 0, ""
        except RequestException as e:
            logger.warning(f"Request error fetching {url}: {e}")
            return 0, ""
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            return 0, ""


def fetch_url(url: str, proxy_url: str = None) -> tuple[int, str]:
    fetcher = Fetcher(proxy_url)
    return fetcher.fetch(url)