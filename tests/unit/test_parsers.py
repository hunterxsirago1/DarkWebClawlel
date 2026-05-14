# tests/unit/test_parsers.py
import pytest
from app.crawler.parsers import extract_onion_links, extract_text_content

HTML_WITH_LINKS = """
<html>
<body>
<a href="http://example.onion/link1">Link 1</a>
<a href="http:// друга.onion/link2">Link 2</a>
<a href="http://google.com">Clear net</a>
<p>This is some paragraph text with sensitive content.</p>
</body>
</html>
"""


def test_extract_onion_links():
    links = extract_onion_links(HTML_WITH_LINKS)
    assert "http://example.onion/link1" in links


def test_extract_text_content():
    text = extract_text_content(HTML_WITH_LINKS)
    # anchor text passes through soup.get_text() — only script/style are stripped
    assert "sensitive content" in text
    assert "Link 1" in text  # anchor text is visible text


def test_extract_links_handles_malformed():
    malformed = "<html><a href='http://test.onion'>Broken"
    links = extract_onion_links(malformed)
    assert len(links) >= 1