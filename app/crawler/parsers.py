# app/crawler/parsers.py
import re
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

ONION_LINK_REGEX = re.compile(r"http://[a-zA-Z0-9]{16,}\.onion[^\s\"'<>]*", re.IGNORECASE)


def extract_onion_links(html: str, base_url: str = None) -> list[str]:
    links = set()
    try:
        soup = BeautifulSoup(html, "lxml")
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if ".onion" in href.lower():
                if href.startswith("http"):
                    links.add(href.split("?")[0].split("#")[0])
                elif base_url:
                    links.add(urljoin(base_url, href).split("?")[0].split("#")[0])
        for match in ONION_LINK_REGEX.finditer(html):
            links.add(match.group(0).split("?")[0].split("#")[0])
    except Exception as e:
        logger.warning(f"Error parsing links: {e}")
    return list(links)


def extract_text_content(html: str) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
        for script in soup(["script", "style"]):
            script.decompose()
        text = soup.get_text(separator=" ", strip=True)
        text = re.sub(r"\s+", " ", text)
        return text
    except Exception as e:
        logger.warning(f"Error extracting text: {e}")
        return ""