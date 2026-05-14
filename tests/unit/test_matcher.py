# tests/unit/test_matcher.py
import pytest
import hashlib
from app.crawler.matcher import Matcher, compute_hash

TEST_WATCHLIST = [
    {"type": "keyword", "value": "fusemachines", "severity": "medium", "id": 1},
    {"type": "regex", "value": r"[a-zA-Z0-9._%+-]+@fusemachines\.com", "severity": "high", "id": 2},
    {"type": "regex", "value": r"rt_key_REDACTED[a-zA-Z0-9]{10}", "severity": "critical", "id": 3},
]


def test_keyword_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "Fusemachines corp leaked the database"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 1
    assert matches[0]["matched_value"] == "Fusemachines"


def test_regex_email_match():
    # Uses TEST_WATCHLIST which has keyword "fusemachines" (id=1) and email regex (id=2)
    # Content "admin@fusemachines.com" triggers BOTH rules (keyword + regex)
    # With one-match-per-rule, we get 2 matches total
    matcher = Matcher(TEST_WATCHLIST)
    content = "admin@fusemachines.com"  # triggers keyword rule (fusemachines) AND regex rule (email)
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 2
    ids = {m["watchlist_id"] for m in matches}
    assert 1 in ids
    assert 2 in ids


def test_regex_email_match_only():
    # Separate test with no keyword overlap — only regex rule fires
    watchlist_email_only = [
        {"type": "regex", "value": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", "severity": "high", "id": 5},
    ]
    matcher = Matcher(watchlist_email_only)
    content = "Contact us at admin@example.com for access"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 5


def test_regex_stripe_key_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "rt_key_REDACTEDxxxxREDACTEDxxxx"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 3


def test_hash_match():
    target_hash = hashlib.sha256(b"password: password").hexdigest()
    watchlist = [
        {"type": "hash", "value": target_hash, "severity": "high", "id": 4},
    ]
    matcher = Matcher(watchlist)
    content = "password: password"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 4


def test_no_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "Hello world, this is benign content"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 0


def test_compute_hash():
    expected = hashlib.sha256(b"test content").hexdigest()
    h = compute_hash("test content")
    assert h == expected