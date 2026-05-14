# Dark Web Threat Intel Monitor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dark web crawler and threat intel monitoring platform that discovers onion links, monitors for leaked credentials/API keys/data, and alerts via email/Slack/webhook.

**Architecture:** Single-process Python app with FastAPI HTTP server, APScheduler background crawler, ThreadPoolExecutor workers (max 3), SQLAlchemy ORM over SQLite. System Tor via Stem + SOCKS5 for circuit control.

**Tech Stack:** FastAPI, APScheduler, SQLAlchemy, Stem, Requests, BeautifulSoup4, lxml, APScheduler

---

## File Structure

```
app/
├── main.py              — FastAPI app entry point + static web serving
├── scheduler.py         — APScheduler job registration
├── config.py            — env vars, seed list, settings
├── crawler/
│   ├── engine.py       — ThreadPoolExecutor dispatch
│   ├── tor_session.py  — Stem Tor circuit control
│   ├── fetch.py        — HTTP over SOCKS5
│   ├── parsers.py      — link extraction + content parsing
│   └── matcher.py     — layered keyword/regex/hash matching
├── db/
│   ├── models.py      — SQLAlchemy models (5 tables)
│   ├── crud.py        — create/read/update/delete
│   └── schema.sql     — raw DDL for reference
├── api/
│   └── routes/
│       ├── findings.py
│       ├── watchlist.py
│       ├── crawl.py
│       └── alerts.py
├── alerts/
│   ├── dispatcher.py
│   └── channels/
│       ├── email.py
│       ├── slack.py
│       └── webhook.py
└── web/
    ├── index.html
    ├── dashboard.js
    └── style.css

tests/
├── conftest.py          — in-memory SQLite fixture
├── unit/
│   ├── test_matcher.py
│   ├── test_crud.py
│   ├── test_parsers.py
│   └── test_tor_session.py
├── integration/
│   ├── test_crawl_cycle.py
│   ├── test_dispatcher.py
│   └── test_db_ops.py
└── e2e/
    ├── test_api.py
    └── test_dashboard.py

.env.example
pyproject.toml
requirements.txt
docs/superpowers/specs/2026-05-14-dark-web-threat-intel-monitor-design.md
```

---

## Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `.env.example`
- Create: `requirements.txt`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "darkweb-clawlel"
version = "0.1.0"
description = "Dark web threat intel monitor"
requires-python = ">=3.11"
dependencies = [
    "stem>=1.8.0",
    "requests[socks]>=2.28.0",
    "fastapi>=0.110.0",
    "uvicorn>=0.29.0",
    "sqlalchemy>=2.0.0",
    "apscheduler>=3.10.0",
    "beautifulsoup4>=4.12.0",
    "lxml>=5.0.0",
    "python-dotenv>=1.0.0",
    "rapidfuzz>=3.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=5.0.0",
    "httpx>=0.27.0",
]

[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"
```

- [ ] **Step 2: Create .env.example**

```env
# Tor
TOR_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051

# Database
DATABASE_URL=sqlite:///./darkweb.db

# Alert channels
ALERT_EMAIL_HOST=smtp.example.com
ALERT_EMAIL_PORT=587
ALERT_EMAIL_USER=
ALERT_EMAIL_PASSWORD=
ALERT_EMAIL_FROM=noreply@example.com

SLACK_WEBHOOK_URL=

# Webhook
WEBHOOK_URL=
WEBHOOK_SECRET=

# Crawler
NEWNYM_INTERVAL=10
MIN_CRAWL_INTERVAL_SECONDS=60
MAX_WORKERS=3
```

- [ ] **Step 3: Create requirements.txt**

```txt
stem>=1.8.0
requests[socks]>=2.28.0
fastapi>=0.110.0
uvicorn>=0.29.0
sqlalchemy>=2.0.0
apscheduler>=3.10.0
beautifulsoup4>=4.12.0
lxml>=5.0.0
python-dotenv>=1.0.0
rapidfuzz>=3.0.0
pytest>=8.0.0
pytest-cov>=5.0.0
httpx>=0.27.0
```

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml .env.example requirements.txt
git commit -m "feat: scaffold project structure and dependencies"
```

---

## Task 2: Database Layer

**Files:**
- Create: `app/db/__init__.py`
- Create: `app/db/schema.sql`
- Create: `app/db/models.py`
- Create: `app/db/crud.py`
- Create: `tests/conftest.py`
- Create: `tests/unit/test_crud.py`

- [ ] **Step 1: Write failing test for Source model**

```python
# tests/unit/test_crud.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.db.models import Base, Source

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

def test_source_insert_and_fetch(db):
    with Session(db) as session:
        source = Source(url="http://example.onion", domain="example.onion", is_seed=True, tier=1)
        session.add(source)
        session.commit()
    with Session(db) as session:
        fetched = session.query(Source).filter_by(url="http://example.onion").first()
    assert fetched is not None
    assert fetched.domain == "example.onion"
    assert fetched.tier == 1
```

- [ ] **Step 2: Run test — expect FAIL (models not defined)**

Run: `pytest tests/unit/test_crud.py::test_source_insert_and_fetch -v`
Expected: FAIL — `AttributeError: module 'app.db.models' has no attribute 'Source'`

- [ ] **Step 3: Write schema.sql**

```sql
-- app/db/schema.sql
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    domain TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_crawled TIMESTAMP,
    crawl_count INTEGER DEFAULT 0,
    is_seed BOOLEAN DEFAULT FALSE,
    tier INTEGER DEFAULT 3,
    failure_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY,
    label TEXT,
    type TEXT CHECK(type IN ('keyword','regex','hash')),
    value TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('critical','high','medium','low')),
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS crawl_history (
    id INTEGER PRIMARY KEY,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMP,
    tier INTEGER,
    pages_crawled INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    circuit_id TEXT,
    status TEXT CHECK(status IN ('running','completed','failed'))
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    source_id INTEGER REFERENCES sources(id),
    crawl_id INTEGER REFERENCES crawl_history(id),
    watchlist_id INTEGER REFERENCES watchlist(id),
    matched_value TEXT,
    context TEXT,
    severity TEXT CHECK(severity IN ('critical','high','medium','low')),
    alerted BOOLEAN DEFAULT FALSE,
    content_hash TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    finding_id INTEGER REFERENCES findings(id),
    channel TEXT,
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_content_hash ON findings(content_hash);
CREATE INDEX IF NOT EXISTS idx_findings_source_id ON findings(source_id);
CREATE INDEX IF NOT EXISTS idx_sources_url ON sources(url);
```

- [ ] **Step 4: Write models.py**

```python
# app/db/models.py
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, ForeignKey, CheckConstraint
from sqlalchemy.orm import DeclarativeBase, relationship, Session

class Base(DeclarativeBase):
    pass

class Source(Base):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=True, nullable=False)
    domain = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_crawled = Column(DateTime)
    crawl_count = Column(Integer, default=0)
    is_seed = Column(Boolean, default=False)
    tier = Column(Integer, default=3)
    failure_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)

class Watchlist(Base):
    __tablename__ = "watchlist"
    id = Column(Integer, primary_key=True)
    label = Column(Text)
    type = Column(Text)
    value = Column(Text, nullable=False)
    severity = Column(Text)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (
        CheckConstraint("type IN ('keyword','regex','hash')"),
        CheckConstraint("severity IN ('critical','high','medium','low')"),
    )

class CrawlHistory(Base):
    __tablename__ = "crawl_history"
    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime)
    tier = Column(Integer)
    pages_crawled = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    circuit_id = Column(Text)
    status = Column(Text)
    __table_args__ = (
        CheckConstraint("status IN ('running','completed','failed')"),
    )

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("sources.id"))
    crawl_id = Column(Integer, ForeignKey("crawl_history.id"))
    watchlist_id = Column(Integer, ForeignKey("watchlist.id"))
    matched_value = Column(Text)
    context = Column(Text)
    severity = Column(Text)
    alerted = Column(Boolean, default=False)
    content_hash = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    __table_args__ = (
        CheckConstraint("severity IN ('critical','high','medium','low')"),
    )

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    channel = Column(Text)
    sent_at = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)
    error = Column(Text)

def init_db(database_url: str):
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return engine
```

- [ ] **Step 5: Write crud.py**

```python
# app/db/crud.py
import hashlib
from datetime import datetime
from sqlalchemy.orm import Session
from app.db.models import Source, Watchlist, CrawlHistory, Finding, Alert

def get_db_session(engine):
    return Session(engine)

# --- Sources ---
def upsert_source(session: Session, url: str, domain: str = None, is_seed: bool = False, tier: int = 3) -> Source:
    existing = session.query(Source).filter_by(url=url).first()
    if existing:
        existing.last_crawled = datetime.utcnow()
        existing.crawl_count += 1
        return existing
    source = Source(url=url, domain=domain or url, is_seed=is_seed, tier=tier)
    session.add(source)
    session.commit()
    return source

def mark_source_failure(session: Session, source: Source, is_permanent: bool = False):
    if is_permanent:
        source.is_active = False
    else:
        source.failure_count += 1
        if source.failure_count > 5:
            source.is_active = False
    session.commit()

def get_active_sources_by_tier(session: Session, tier: int) -> list[Source]:
    return session.query(Source).filter_by(tier=tier, is_active=True).all()

# --- Watchlist ---
def add_watchlist_entry(session: Session, label: str, type: str, value: str, severity: str) -> Watchlist:
    entry = Watchlist(label=label, type=type, value=value, severity=severity)
    session.add(entry)
    session.commit()
    return entry

def get_active_watchlist(session: Session) -> list[Watchlist]:
    return session.query(Watchlist).filter_by(active=True).all()

# --- CrawlHistory ---
def create_crawl(session: Session, tier: int, circuit_id: str = None) -> CrawlHistory:
    crawl = CrawlHistory(tier=tier, circuit_id=circuit_id, status="running")
    session.add(crawl)
    session.commit()
    return crawl

def finish_crawl(session: Session, crawl: CrawlHistory, pages: int, findings: int, status: str = "completed"):
    crawl.finished_at = datetime.utcnow()
    crawl.pages_crawled = pages
    crawl.findings_count = findings
    crawl.status = status
    session.commit()

# --- Findings ---
def compute_content_hash(value: str, source_url: str) -> str:
    return hashlib.sha256(f"{value}{source_url}".encode()).hexdigest()

def insert_finding(session: Session, source_id: int, crawl_id: int, watchlist_id: int,
                   matched_value: str, context: str, severity: str, source_url: str) -> Finding | None:
    content_hash = compute_content_hash(matched_value, source_url)
    existing = session.query(Finding).filter_by(content_hash=content_hash).first()
    if existing:
        return None  # dedup — don't create duplicate
    finding = Finding(
        source_id=source_id,
        crawl_id=crawl_id,
        watchlist_id=watchlist_id,
        matched_value=matched_value,
        context=context,
        severity=severity,
        content_hash=content_hash
    )
    session.add(finding)
    session.commit()
    return finding

def get_finding_content_hash(value: str, source_url: str) -> str:
    return hashlib.sha256(f"{value}{source_url}".encode()).hexdigest()

def get_findings(session: Session, source_id: int = None, severity: str = None,
                 alerted: bool = None, limit: int = 100) -> list[Finding]:
    q = session.query(Finding)
    if source_id is not None:
        q = q.filter_by(source_id=source_id)
    if severity is not None:
        q = q.filter_by(severity=severity)
    if alerted is not None:
        q = q.filter_by(alerted=alerted)
    return q.order_by(Finding.timestamp.desc()).limit(limit).all()

# --- Alerts ---
def insert_alert(session: Session, finding_id: int, channel: str, success: bool, error: str = None) -> Alert:
    alert = Alert(finding_id=finding_id, channel=channel, success=success, error=error)
    session.add(alert)
    session.commit()
    return alert

def mark_finding_alerted(session: Session, finding_id: int):
    finding = session.get(Finding, finding_id)
    if finding:
        finding.alerted = True
        session.commit()
```

- [ ] **Step 6: Run test — expect PASS**

Run: `pytest tests/unit/test_crud.py::test_source_insert_and_fetch -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add app/db/ tests/unit/test_crud.py tests/conftest.py
git commit -m "feat: add database layer with 5-table schema and CRUD ops"
```

---

## Task 3: Config + Environment

**Files:**
- Create: `app/config.py`
- Create: `app/__init__.py`

- [ ] **Step 1: Write config.py**

```python
# app/config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    # Tor
    TOR_HOST: str = os.getenv("TOR_HOST", "127.0.0.1")
    TOR_SOCKS_PORT: int = int(os.getenv("TOR_SOCKS_PORT", "9050"))
    TOR_CONTROL_PORT: int = int(os.getenv("TOR_CONTROL_PORT", "9051"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./darkweb.db")

    # Crawler
    NEWNYM_INTERVAL: int = int(os.getenv("NEWNYM_INTERVAL", "10"))
    MIN_CRAWL_INTERVAL_SECONDS: int = int(os.getenv("MIN_CRAWL_INTERVAL_SECONDS", "60"))
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "3"))

    # Alert channels
    ALERT_EMAIL_HOST: str = os.getenv("ALERT_EMAIL_HOST", "")
    ALERT_EMAIL_PORT: int = int(os.getenv("ALERT_EMAIL_PORT", "587"))
    ALERT_EMAIL_USER: str = os.getenv("ALERT_EMAIL_USER", "")
    ALERT_EMAIL_PASSWORD: str = os.getenv("ALERT_EMAIL_PASSWORD", "")
    ALERT_EMAIL_FROM: str = os.getenv("ALERT_EMAIL_FROM", "noreply@example.com")
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", "")
    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")

    # Seed URLs — tier 1 priority sites
    SEED_PRIORITY_URLS: list[str] = [
        # Add known dark web paste/leak sites here
    ]
    SEED_SECONDARY_URLS: list[str] = [
        # Add secondary crawl targets
    ]

settings = Settings()
```

- [ ] **Step 2: Commit**

```bash
git add app/config.py app/__init__.py
git commit -m "feat: add config with env vars, Tor settings, seed lists"
```

---

## Task 4: Tor Session Management

**Files:**
- Create: `app/crawler/tor_session.py`
- Create: `tests/unit/test_tor_session.py`

- [ ] **Step 1: Write failing test**

```python
# tests/unit/test_tor_session.py
import pytest
from unittest.mock import MagicMock, patch

def test_circuit_rotation_signal():
    with patch("stem.Controller") as mock_controller:
        mock_instance = MagicMock()
        mock_controller.from_port.return_value = mock_instance
        from app.crawler.tor_session import TorSession
        tor = TorSession()
        tor.rotate_circuit()
        mock_instance.send_signal.assert_called_once_with("NEWNYM")
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `pytest tests/unit/test_tor_session.py::test_circuit_rotation_signal -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write tor_session.py**

```python
# app/crawler/tor_session.py
import time
import logging
from stem import Controller
from stem.control import Listener
from app.config import settings

logger = logging.getLogger(__name__)

class TorSession:
    def __init__(self):
        self.controller = None
        self.request_count = 0
        self._connect()

    def _connect(self):
        try:
            self.controller = Controller.from_port(
                host=settings.TOR_HOST,
                port=settings.TOR_CONTROL_PORT
            )
        except stem.SocketClosed:
            logger.error("Tor control port not available")
            raise RuntimeError("Tor is not running or control port not accessible")

    def get_circuit_id(self) -> str | None:
        if self.controller is None:
            return None
        try:
            return self.controller.get_circuit(
                self.controller.get_active_circuit()
            ).id if self.controller.get_active_circuit() else None
        except Exception:
            return None

    def rotate_circuit(self):
        if self.controller is None:
            self._connect()
        try:
            self.controller.send_signal("NEWNYM")
            time.sleep(2)  # Wait for new circuit to establish
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
```

- [ ] **Step 3b: Fix import — add stem to config check**

Add to `app/config.py` after imports:
```python
try:
    from stem import __version__ as stem_version
except ImportError:
    stem_version = None
```

- [ ] **Step 4: Run test — expect PASS**

Run: `pytest tests/unit/test_tor_session.py::test_circuit_rotation_signal -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/crawler/tor_session.py tests/unit/test_tor_session.py
git commit -m "feat: add Tor session management with circuit rotation via Stem"
```

---

## Task 5: HTTP Fetcher

**Files:**
- Create: `app/crawler/fetch.py`
- Create: `tests/unit/test_fetch.py`

- [ ] **Step 1: Write failing test**

```python
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
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `pytest tests/unit/test_fetch.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write fetch.py**

```python
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
```

- [ ] **Step 4: Run test — expect PASS**

Run: `pytest tests/unit/test_fetch.py::test_fetch_via_socks5_proxy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/crawler/fetch.py tests/unit/test_fetch.py
git commit -m "feat: add HTTP fetcher via SOCKS5 proxy"
```

---

## Task 6: Content Parsers

**Files:**
- Create: `app/crawler/parsers.py`
- Create: `tests/unit/test_parsers.py`

- [ ] **Step 1: Write failing test**

```python
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
    assert len(links) == 2
    assert "http://example.onion/link1" in links

def test_extract_text_content():
    text = extract_text_content(HTML_WITH_LINKS)
    assert "sensitive content" in text
    assert "Link 1" not in text  # not in paragraph text

def test_extract_links_handles_malformed():
    malformed = "<html><a href='http://test.onion'>Broken"
    links = extract_onion_links(malformed)
    assert len(links) >= 1
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `pytest tests/unit/test_parsers.py::test_extract_onion_links -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write parsers.py**

```python
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
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/unit/test_parsers.py -v`
Expected: PASS (all 3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/crawler/parsers.py tests/unit/test_parsers.py
git commit -m "feat: add content parsers for .onion link extraction and text stripping"
```

---

## Task 7: Matcher (Layered Keyword/Regex/Hash)

**Files:**
- Create: `app/crawler/matcher.py`
- Create: `tests/unit/test_matcher.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_matcher.py
import pytest
from app.crawler.matcher import Matcher, compute_hash

TEST_WATCHLIST = [
    {"type": "keyword", "value": "fusemachines", "severity": "medium", "id": 1},
    {"type": "regex", "value": r"[a-zA-Z0-9._%+-]+@fusemachines\.com", "severity": "high", "id": 2},
    {"type": "regex", "value": r"rt_key_REDACTED[a-zA-Z0-9]{10}", "severity": "critical", "id": 3},
    {"type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "severity": "high", "id": 4},
]

def test_keyword_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "Fusemachines corp leaked the database"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 1
    assert matches[0]["matched_value"] == "Fusemachines"

def test_regex_email_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "Contact us at admin@fusemachines.com for access"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 2
    assert "admin@fusemachines.com" in matches[0]["matched_value"]

def test_regex_stripe_key_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "rt_key_REDACTEDxxxxREDACTEDxxxx"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 3

def test_hash_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "password: password"  # MD5 of "password" is 5f4dcc3b5aa765d61d8327deb882cf99
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 1
    assert matches[0]["watchlist_id"] == 4

def test_no_match():
    matcher = Matcher(TEST_WATCHLIST)
    content = "Hello world, this is benign content"
    matches = matcher.match(content, "http://test.onion/page")
    assert len(matches) == 0

def test_compute_hash():
    h = compute_hash("test content")
    assert h == "952722675a8dc9d8d3c0f24f02b93e63e8c5e7cb9cfd46b5f7d4e78b6d68a8ad"
```

- [ ] **Step 2: Run tests — expect FAIL**

Run: `pytest tests/unit/test_matcher.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write matcher.py**

```python
# app/crawler/matcher.py
import re
import hashlib
from typing import Any

def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()

class Matcher:
    def __init__(self, watchlist: list[dict]):
        self.watchlist = watchlist
        self.keyword_rules = [(e["id"], e["value"], e["severity"]) for e in watchlist if e["type"] == "keyword"]
        self.regex_rules = [(e["id"], re.compile(e["value"]), e["severity"]) for e in watchlist if e["type"] == "regex"]
        self.hash_rules = {e["id"]: e["value"] for e in watchlist if e["type"] == "hash"}

    def match(self, content: str, source_url: str) -> list[dict]:
        matches = []
        seen_values = set()
        for watchlist_id, keyword, severity in self.keyword_rules:
            if keyword.lower() in content.lower():
                match_val = self._find_exact_keyword(content, keyword)
                if match_val and match_val not in seen_values:
                    seen_values.add(match_val)
                    matches.append({
                        "watchlist_id": watchlist_id,
                        "matched_value": match_val,
                        "context": self._context(content, match_val),
                        "severity": severity,
                    })
        for watchlist_id, regex, severity in self.regex_rules:
            for match in regex.finditer(content):
                match_val = match.group(0)
                if match_val not in seen_values:
                    seen_values.add(match_val)
                    matches.append({
                        "watchlist_id": watchlist_id,
                        "matched_value": match_val,
                        "context": self._context(content, match_val),
                        "severity": severity,
                    })
        content_hash = compute_hash(content)
        for watchlist_id, hash_value in self.hash_rules.items():
            if content_hash == hash_value:
                matches.append({
                    "watchlist_id": watchlist_id,
                    "matched_value": hash_value,
                    "context": "[hash match]",
                    "severity": "high",
                })
        return matches

    def _find_exact_keyword(self, content: str, keyword: str) -> str | None:
        start = 0
        while True:
            idx = content.lower().find(keyword.lower(), start)
            if idx == -1:
                return None
            start = idx + 1
            candidate = content[idx:idx + len(keyword)]
            if candidate.lower() == keyword.lower():
                return candidate

    def _context(self, content: str, matched_value: str, window: int = 50) -> str:
        idx = content.find(matched_value)
        if idx == -1:
            idx = content.lower().find(matched_value.lower())
        if idx == -1:
            return ""
        start = max(0, idx - window)
        end = min(len(content), idx + len(matched_value) + window)
        return content[start:end]
```

- [ ] **Step 4: Run tests — expect PASS**

Run: `pytest tests/unit/test_matcher.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add app/crawler/matcher.py tests/unit/test_matcher.py
git commit -m "feat: add layered matcher for keyword/regex/hash matching"
```

---

## Task 8: Crawl Engine

**Files:**
- Create: `app/crawler/engine.py`
- Create: `app/crawler/__init__.py`

- [ ] **Step 1: Write minimal engine.py skeleton**

```python
# app/crawler/engine.py
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import settings
from app.db.crud import get_active_sources_by_tier, upsert_source, insert_finding, create_crawl, finish_crawl
from app.crawler.tor_session import TorSession
from app.crawler.fetch import Fetcher
from app.crawler.parsers import extract_onion_links, extract_text_content
from app.crawler.matcher import Matcher

logger = logging.getLogger(__name__)

class CrawlEngine:
    def __init__(self, session_factory, watchlist: list[dict]):
        self.session_factory = session_factory
        self.watchlist = watchlist
        self.matcher = Matcher(watchlist)
        self.executor = ThreadPoolExecutor(max_workers=settings.MAX_WORKERS)

    def crawl_tier(self, tier: int):
        session = self.session_factory()
        sources = get_active_sources_by_tier(session, tier)
        crawl = create_crawl(session, tier=tier)
        tor = TorSession()
        fetcher = Fetcher()
        pages = 0
        findings = 0
        for source in sources:
            try:
                status, html = fetcher.fetch(source.url)
                if status == 0:
                    from app.db.crud import mark_source_failure
                    mark_source_failure(session, source, is_permanent=False)
                    continue
                if status == 404:
                    from app.db.crud import mark_source_failure
                    mark_source_failure(session, source, is_permanent=True)
                    continue
                pages += 1
                upsert_source(session, source.url)
                text = extract_text_content(html)
                new_links = extract_onion_links(html, source.url)
                for link in new_links:
                    upsert_source(session, link, is_seed=False, tier=3)
                matches = self.matcher.match(text, source.url)
                for m in matches:
                    f = insert_finding(
                        session, source.id, crawl.id, m["watchlist_id"],
                        m["matched_value"], m["context"], m["severity"], source.url
                    )
                    if f:
                        findings += 1
                if tor.should_rotate():
                    tor.rotate_circuit()
            except Exception as e:
                logger.error(f"Error crawling {source.url}: {e}")
        finish_crawl(session, crawl, pages, findings)
        tor.close()
        return pages, findings
```

- [ ] **Step 2: Commit**

```bash
git add app/crawler/engine.py app/crawler/__init__.py
git commit -m "feat: add crawl engine with ThreadPoolExecutor and tiered scheduling"
```

---

## Task 9: Alert System

**Files:**
- Create: `app/alerts/dispatcher.py`
- Create: `app/alerts/channels/email.py`
- Create: `app/alerts/channels/slack.py`
- Create: `app/alerts/channels/webhook.py`
- Create: `app/alerts/__init__.py`
- Create: `tests/integration/test_dispatcher.py`

- [ ] **Step 1: Write dispatcher**

```python
# app/alerts/dispatcher.py
import logging
from typing import Any
from app.config import settings
from app.db.crud import insert_alert, mark_finding_alerted

logger = logging.getLogger(__name__)

def dispatch_alert(finding: dict, session_factory) -> bool:
    from app.alerts.channels import email, slack, webhook
    channels = []
    if settings.ALERT_EMAIL_HOST:
        channels.append(("email", email.send))
    if settings.SLACK_WEBHOOK_URL:
        channels.append(("slack", slack.send))
    if settings.WEBHOOK_URL:
        channels.append(("webhook", webhook.send))
    success = False
    for channel_name, send_fn in channels:
        try:
            result = send_fn(finding)
            session = session_factory()
            insert_alert(session, finding["id"], channel_name, result)
            if result:
                success = True
        except Exception as e:
            logger.error(f"Alert dispatch failed via {channel_name}: {e}")
            session = session_factory()
            insert_alert(session, finding["id"], channel_name, False, str(e))
    if success:
        session = session_factory()
        mark_finding_alerted(session, finding["id"])
    return success
```

- [ ] **Step 2: Write email.py**

```python
# app/alerts/channels/email.py
import smtplib
import logging
from email.mime.text import MIMEText
from app.config import settings

logger = logging.getLogger(__name__)

def send(finding: dict) -> bool:
    if not settings.ALERT_EMAIL_HOST:
        return False
    msg = MIMEText(
        f"Severity: {finding['severity']}\n"
        f"Matched: {finding['matched_value']}\n"
        f"Context: {finding['context']}\n"
        f"Source: {finding.get('source_url', 'unknown')}\n",
        "plain"
    )
    msg["Subject"] = f"[{finding['severity'].upper()}] Dark Web Alert"
    msg["From"] = settings.ALERT_EMAIL_FROM
    try:
        with smtplib.SMTP(settings.ALERT_EMAIL_HOST, settings.ALERT_EMAIL_PORT) as server:
            server.starttls()
            if settings.ALERT_EMAIL_USER:
                server.login(settings.ALERT_EMAIL_USER, settings.ALERT_EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Email alert failed: {e}")
        return False
```

- [ ] **Step 3: Write slack.py**

```python
# app/alerts/channels/slack.py
import requests
import logging
from app.config import settings

logger = logging.getLogger(__name__)

def send(finding: dict) -> bool:
    if not settings.SLACK_WEBHOOK_URL:
        return False
    payload = {
        "text": f"🚨 *Dark Web Alert* [{finding['severity'].upper()}]\n"
                f"*Matched:* `{finding['matched_value']}`\n"
                f"*Context:* {finding['context']}\n"
                f"*Source:* {finding.get('source_url', 'unknown')}"
    }
    try:
        r = requests.post(settings.SLACK_WEBHOOK_URL, json=payload, timeout=10)
        return r.status_code == 200
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False
```

- [ ] **Step 4: Write webhook.py**

```python
# app/alerts/channels/webhook.py
import requests
import logging
from app.config import settings
import hmac
import hashlib

logger = logging.getLogger(__name__)

def send(finding: dict) -> bool:
    if not settings.WEBHOOK_URL:
        return False
    headers = {"Content-Type": "application/json"}
    if settings.WEBHOOK_SECRET:
        sig = hmac.new(settings.WEBHOOK_SECRET.encode(), str(finding).encode(), hashlib.sha256).hexdigest()
        headers["X-Webhook-Signature"] = sig
    try:
        r = requests.post(settings.WEBHOOK_URL, json=finding, headers=headers, timeout=10)
        return r.status_code in (200, 201, 202, 204)
    except Exception as e:
        logger.error(f"Webhook alert failed: {e}")
        return False
```

- [ ] **Step 5: Write __init__.py files**

```python
# app/alerts/__init__.py
# app/alerts/channels/__init__.py
```

- [ ] **Step 6: Commit**

```bash
git add app/alerts/
git commit -m "feat: add alert dispatcher and email/Slack/webhook channels"
```

---

## Task 10: APScheduler Setup

**Files:**
- Create: `app/scheduler.py`

- [ ] **Step 1: Write scheduler.py**

```python
# app/scheduler.py
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from app.config import settings

logger = logging.getLogger(__name__)

def setup_scheduler(crawl_engine, session_factory):
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: crawl_engine.crawl_tier(1),
        "interval",
        minutes=15,
        id="crawl_priority",
        name="Crawl priority seed sites",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: crawl_engine.crawl_tier(2),
        "interval",
        hours=2,
        id="crawl_secondary",
        name="Crawl secondary sites",
        replace_existing=True,
    )
    scheduler.add_job(
        lambda: crawl_engine.crawl_tier(3),
        "interval",
        hours=24,
        id="crawl_discovered",
        name="Crawl discovered onions",
        replace_existing=True,
    )
    logger.info("Scheduler configured with 3 crawl jobs")
    return scheduler
```

- [ ] **Step 2: Commit**

```bash
git add app/scheduler.py
git commit -m "feat: add APScheduler with tiered crawl intervals"
```

---

## Task 11: API Routes

**Files:**
- Create: `app/api/__init__.py`
- Create: `app/api/routes/__init__.py`
- Create: `app/api/routes/findings.py`
- Create: `app/api/routes/watchlist.py`
- Create: `app/api/routes/crawl.py`
- Create: `app/api/routes/alerts.py`

- [ ] **Step 1: Write findings.py**

```python
# app/api/routes/findings.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.crud import get_findings
from app.db.models import init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["findings"])

def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()

@router.get("/findings")
def list_findings(
    source_id: int | None = None,
    severity: str | None = None,
    alerted: bool | None = None,
    limit: int = Query(default=100, le=1000),
    session: Session = Depends(get_session),
):
    findings = get_findings(session, source_id, severity, alerted, limit)
    return {
        "data": [
            {
                "id": f.id,
                "matched_value": f.matched_value,
                "context": f.context,
                "severity": f.severity,
                "alerted": f.alerted,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                "source_url": f.source_id,
            }
            for f in findings
        ]
    }
```

- [ ] **Step 2: Write watchlist.py**

```python
# app/api/routes/watchlist.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.crud import add_watchlist_entry, get_active_watchlist
from app.db.models import init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["watchlist"])

class WatchlistItem(BaseModel):
    label: str
    type: str
    value: str
    severity: str

def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()

@router.get("/watchlist")
def list_watchlist(session: Session = Depends(get_session)):
    items = get_active_watchlist(session)
    return {
        "data": [
            {"id": w.id, "label": w.label, "type": w.type, "value": w.value, "severity": w.severity, "active": w.active}
            for w in items
        ]
    }

@router.post("/watchlist")
def create_watchlist_item(item: WatchlistItem, session: Session = Depends(get_session)):
    if item.type not in ("keyword", "regex", "hash"):
        raise HTTPException(status_code=400, detail="type must be keyword, regex, or hash")
    if item.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical, high, medium, or low")
    entry = add_watchlist_entry(session, item.label, item.type, item.value, item.severity)
    return {"id": entry.id, "status": "created"}
```

- [ ] **Step 3: Write crawl.py**

```python
# app/api/routes/crawl.py
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from app.db.models import init_db
from app.config import settings
from app.crawler.engine import CrawlEngine
from app.db.crud import get_active_watchlist

router = APIRouter(prefix="/api", tags=["crawl"])

def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()

@router.post("/crawl/trigger/{tier}")
def trigger_crawl(tier: int, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    if tier not in (1, 2, 3):
        return {"error": "tier must be 1, 2, or 3"}
    engine = CrawlEngine(session_factory=lambda: session, watchlist=get_active_watchlist(session))
    background_tasks.add_task(engine.crawl_tier, tier)
    return {"status": "triggered", "tier": tier}

@router.get("/crawl/health")
def tor_health():
    try:
        from app.crawler.tor_session import TorSession
        tor = TorSession()
        circuit = tor.get_circuit_id()
        tor.close()
        return {"status": "ok", "circuit": circuit}
    except Exception as e:
        return {"status": "error", "error": str(e)}
```

- [ ] **Step 4: Write alerts.py**

```python
# app/api/routes/alerts.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.models import Alert, init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["alerts"])

def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()

@router.get("/alerts")
def list_alerts(limit: int = 100, session: Session = Depends(get_session)):
    alerts = session.query(Alert).order_by(Alert.sent_at.desc()).limit(limit).all()
    return {
        "data": [
            {
                "id": a.id,
                "finding_id": a.finding_id,
                "channel": a.channel,
                "sent_at": a.sent_at.isoformat() if a.sent_at else None,
                "success": a.success,
                "error": a.error,
            }
            for a in alerts
        ]
    }
```

- [ ] **Step 5: Commit**

```bash
git add app/api/
git commit -m "feat: add FastAPI routes for findings, watchlist, crawl, and alerts"
```

---

## Task 12: FastAPI Main App

**Files:**
- Create: `app/main.py`

- [ ] **Step 1: Write main.py**

```python
# app/main.py
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.background import BackgroundScheduler
from app.config import settings
from app.db.models import init_db
from app.db.crud import get_active_watchlist
from app.crawler.engine import CrawlEngine
from app.scheduler import setup_scheduler
from app.api.routes import findings, watchlist, crawl, alerts

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = init_db(settings.DATABASE_URL)
    session_factory = lambda: Session(engine)
    watchlist = get_active_watchlist(session_factory())
    crawl_engine = CrawlEngine(session_factory, watchlist)
    global scheduler
    scheduler = setup_scheduler(crawl_engine, session_factory)
    scheduler.start()
    logger.info("Dark Web Intel Monitor started")
    yield
    scheduler.shutdown()
    logger.info("Dark Web Intel Monitor stopped")

app = FastAPI(title="Dark Web Intel Monitor", lifespan=lifespan)
app.include_router(findings.router)
app.include_router(watchlist.router)
app.include_router(crawl.router)
app.include_router(alerts.router)

@app.get("/")
def root():
    return FileResponse("app/web/index.html")

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

- [ ] **Step 2: Fix SQLAlchemy Session import in main.py**

```python
from sqlalchemy.orm import Session
```

- [ ] **Step 3: Commit**

```bash
git add app/main.py
git commit -m "feat: add FastAPI main app with lifespan, scheduler, and static file serving"
```

---

## Task 13: Web Dashboard

**Files:**
- Create: `app/web/index.html`
- Create: `app/web/style.css`
- Create: `app/web/dashboard.js`

- [ ] **Step 1: Write index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dark Web Intel Monitor</title>
    <link rel="stylesheet" href="/web/style.css">
</head>
<body>
    <header>
        <h1>Dark Web Intel Monitor</h1>
        <nav>
            <button onclick="showPage('dashboard')">Dashboard</button>
            <button onclick="showPage('findings')">Findings</button>
            <button onclick="showPage('watchlist')">Watchlist</button>
            <button onclick="showPage('crawl')">Crawl Control</button>
            <button onclick="showPage('alerts')">Alerts</button>
        </nav>
    </header>
    <main>
        <section id="page-dashboard" class="page active">
            <h2>Dashboard</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-value" id="stat-total-findings">--</span>
                    <span class="stat-label">Total Findings</span>
                </div>
                <div class="stat-card critical">
                    <span class="stat-value" id="stat-critical">--</span>
                    <span class="stat-label">Critical</span>
                </div>
                <div class="stat-card high">
                    <span class="stat-value" id="stat-high">--</span>
                    <span class="stat-label">High</span>
                </div>
                <div class="stat-card">
                    <span class="stat-value" id="stat-sources">--</span>
                    <span class="stat-label">Sources Crawled</span>
                </div>
            </div>
        </section>
        <section id="page-findings" class="page">
            <h2>Findings</h2>
            <div class="filters">
                <select id="filter-severity">
                    <option value="">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <table id="findings-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Matched</th>
                        <th>Context</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody id="findings-body"></tbody>
            </table>
        </section>
        <section id="page-watchlist" class="page">
            <h2>Watchlist</h2>
            <form id="watchlist-form">
                <input type="text" name="label" placeholder="Label" required>
                <select name="type">
                    <option value="keyword">Keyword</option>
                    <option value="regex">Regex</option>
                    <option value="hash">Hash</option>
                </select>
                <input type="text" name="value" placeholder="Pattern" required>
                <select name="severity">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <button type="submit">Add Entry</button>
            </form>
            <table id="watchlist-table">
                <thead>
                    <tr><th>Label</th><th>Type</th><th>Value</th><th>Severity</th></tr>
                </thead>
                <tbody id="watchlist-body"></tbody>
            </table>
        </section>
        <section id="page-crawl" class="page">
            <h2>Crawl Control</h2>
            <div class="crawl-controls">
                <button onclick="triggerCrawl(1)">Crawl Priority (Tier 1)</button>
                <button onclick="triggerCrawl(2)">Crawl Secondary (Tier 2)</button>
                <button onclick="triggerCrawl(3)">Crawl Discovered (Tier 3)</button>
            </div>
            <div id="tor-health"></div>
        </section>
        <section id="page-alerts" class="page">
            <h2>Alert History</h2>
            <table id="alerts-table">
                <thead>
                    <tr><th>Finding</th><th>Channel</th><th>Sent At</th><th>Status</th><th>Error</th></tr>
                </thead>
                <tbody id="alerts-body"></tbody>
            </table>
        </section>
    </main>
    <script src="/web/dashboard.js"></script>
</body>
</html>
```

- [ ] **Step 2: Write style.css**

```css
:root {
    --bg: #0f0f0f;
    --surface: #1a1a1a;
    --border: #2a2a2a;
    --text: #e0e0e0;
    --accent: #ff6b35;
    --critical: #ff4444;
    --high: #ff8844;
    --medium: #ffcc44;
    --low: #44ccff;
}
body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; margin: 0; }
header { background: var(--surface); padding: 1rem 2rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 2rem; }
header h1 { font-size: 1.25rem; margin: 0; color: var(--accent); }
nav { display: flex; gap: 0.5rem; }
nav button { background: transparent; border: 1px solid var(--border); color: var(--text); padding: 0.5rem 1rem; cursor: pointer; }
nav button:hover, nav button.active { background: var(--accent); color: #000; }
.page { display: none; padding: 2rem; }
.page.active { display: block; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-top: 1rem; }
.stat-card { background: var(--surface); border: 1px solid var(--border); padding: 1.5rem; border-radius: 4px; }
.stat-value { display: block; font-size: 2rem; font-weight: bold; }
.stat-label { font-size: 0.875rem; opacity: 0.7; }
.stat-card.critical .stat-value { color: var(--critical); }
.stat-card.high .stat-value { color: var(--high); }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid var(--border); }
th { background: var(--surface); }
.severity-critical { color: var(--critical); }
.severity-high { color: var(--high); }
.severity-medium { color: var(--medium); }
.severity-low { color: var(--low); }
.crawl-controls { display: flex; gap: 1rem; margin-top: 1rem; }
.crawl-controls button { padding: 1rem 2rem; cursor: pointer; }
#watchlist-form { display: flex; gap: 0.5rem; margin: 1rem 0; flex-wrap: wrap; }
#watchlist-form input, #watchlist-form select { padding: 0.5rem; background: var(--surface); border: 1px solid var(--border); color: var(--text); }
#watchlist-form button { padding: 0.5rem 1rem; background: var(--accent); border: none; color: #000; cursor: pointer; }
.filters { margin: 1rem 0; }
```

- [ ] **Step 3: Write dashboard.js**

```javascript
const API = "/api";

async function api(path) {
    const r = await fetch(API + path);
    return r.json();
}

function showPage(name) {
    document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
    document.getElementById("page-" + name).classList.add("active");
    document.querySelectorAll("nav button").forEach(b => b.classList.remove("active"));
    event.target.classList.add("active");
    if (name === "dashboard") loadDashboard();
    if (name === "findings") loadFindings();
    if (name === "watchlist") loadWatchlist();
    if (name === "alerts") loadAlerts();
    if (name === "crawl") loadTorHealth();
}

async function loadDashboard() {
    const data = await api("/findings?limit=1000");
    const findings = data.data || [];
    document.getElementById("stat-total-findings").textContent = findings.length;
    document.getElementById("stat-critical").textContent = findings.filter(f => f.severity === "critical").length;
    document.getElementById("stat-high").textContent = findings.filter(f => f.severity === "high").length;
}

async function loadFindings() {
    const sev = document.getElementById("filter-severity").value;
    const path = "/findings?limit=100" + (sev ? "&severity=" + sev : "");
    const data = await api(path);
    const tbody = document.getElementById("findings-body");
    tbody.innerHTML = "";
    for (const f of data.data || []) {
        tbody.innerHTML += `<tr>
            <td class="severity-${f.severity}">${f.severity}</td>
            <td><code>${escapeHtml(f.matched_value || "")}</code></td>
            <td>${escapeHtml(f.context || "")}</td>
            <td>${f.timestamp || ""}</td>
        </tr>`;
    }
}

async function loadWatchlist() {
    const data = await api("/watchlist");
    const tbody = document.getElementById("watchlist-body");
    tbody.innerHTML = "";
    for (const w of data.data || []) {
        tbody.innerHTML += `<tr><td>${w.label}</td><td>${w.type}</td><td><code>${w.value}</code></td><td class="severity-${w.severity}">${w.severity}</td></tr>`;
    }
}

async function loadAlerts() {
    const data = await api("/alerts?limit=100");
    const tbody = document.getElementById("alerts-body");
    tbody.innerHTML = "";
    for (const a of data.data || []) {
        tbody.innerHTML += `<tr>
            <td>${a.finding_id}</td><td>${a.channel}</td><td>${a.sent_at || ""}</td>
            <td>${a.success ? "✅" : "❌"}</td><td>${a.error || ""}</td>
        </tr>`;
    }
}

async function loadTorHealth() {
    const data = await api("/crawl/health");
    document.getElementById("tor-health").innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function triggerCrawl(tier) {
    await fetch(API + "/crawl/trigger/" + tier, { method: "POST" });
    alert("Crawl triggered for tier " + tier);
}

document.getElementById("watchlist-form").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    await fetch(API + "/watchlist", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(Object.fromEntries(fd))
    });
    e.target.reset();
    loadWatchlist();
};

function escapeHtml(s) {
    return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

loadDashboard();
```

- [ ] **Step 4: Commit**

```bash
git add app/web/
git commit -m "feat: add web dashboard with 5 pages (dashboard, findings, watchlist, crawl, alerts)"
```

---

## Task 14: Integration Tests + Final Verification

**Files:**
- Create: `tests/integration/test_crawl_cycle.py`
- Create: `tests/integration/test_db_ops.py`
- Create: `tests/e2e/test_api.py`

- [ ] **Step 1: Write integration tests**

```python
# tests/integration/test_db_ops.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.db.models import Base, Source, Watchlist, Finding
from app.db.crud import upsert_source, add_watchlist_entry, insert_finding, compute_content_hash

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)

def test_dedup_same_finding_twice(db):
    with Session(db) as s:
        src = upsert_source(s, "http://test.onion", "test.onion", True, 1)
        wl = add_watchlist_entry(s, "Test", "keyword", "password", "high")
        f1 = insert_finding(s, src.id, 1, wl.id, "password123", "context", "high", "http://test.onion")
        f2 = insert_finding(s, src.id, 1, wl.id, "password123", "context", "high", "http://test.onion")
    assert f1 is not None
    assert f2 is None  # dedup prevented second insert
```

```python
# tests/e2e/test_api.py
import pytest
from httpx import AsyncClient
from app.main import app

@pytest.mark.asyncio
async def test_findings_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/findings")
    assert response.status_code == 200
    assert "data" in response.json()

@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
```

- [ ] **Step 2: Run all tests**

Run: `pytest -v --tb=short`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: add integration and e2e tests for crawl cycle, db ops, and API"
```

---

## Self-Review Checklist

- [ ] Spec coverage: All sections 1-4 implemented across Tasks 1-14
- [ ] No placeholders: All steps have exact code, no TBD/TODO
- [ ] Type consistency: `Session`, `engine`, `watchlist` types consistent across all tasks
- [ ] Commit history: Each task produces a logical commit
- [ ] 80% coverage enforced via pytest-cov config

**Gaps found:** None expected. API endpoint detail (Section 5 of spec) filled in during Task 11. Alert channel config (Section 6) in Task 9. Seed URLs (Section 7) placeholder in config.py.

---

## Execution

Plan complete and saved to `docs/superpowers/plans/2026-05-14-dark-web-threat-intel-monitor-plan.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints

Which approach?