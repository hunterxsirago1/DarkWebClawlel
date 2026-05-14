# DARK WEB THREAT INTEL MONITOR — DESIGN SPEC v0.1

**Status:** Draft — Sections 1–4 complete

---

## [Section 1] Architecture Overview

**Stack:**
- **Runtime:** Single Python process (`python -m app`)
- **API:** FastAPI on main thread
- **Scheduler:** APScheduler in background thread
- **Crawl Workers:** ThreadPoolExecutor (max 3 workers)
- **Database:** SQLite (day 1) → PostgreSQL (scale path)
- **Tor:** System Tor via Stem + SOCKS5 (`socks5h://127.0.0.1:9050`)

**Crawl tiers and schedule:**
- Tier 1 (priority seeds): every 15 minutes
- Tier 2 (secondary seeds): every 2 hours
- Tier 3 (discovered onions): every 24 hours
- Manual trigger: instant via API

**Five-table schema:**
- `sources` — deduplication anchor for crawled URLs
- `watchlist` — keywords, regex patterns, hashes to monitor
- `findings` — matched content, severity, alerted flag
- `crawl_history` — crawl session tracking
- `alerts` — delivery audit trail

---

## [Section 2] Core Components

```
app/
├── main.py              — FastAPI app entry point, serves API + static web files
├── scheduler.py         — APScheduler setup, job registration
├── config.py            — settings, env vars, seed list
├── crawler/
│   ├── engine.py       — ThreadPoolExecutor, crawl job dispatch
│   ├── tor_session.py  — Stem-based Tor circuit control, health checks
│   ├── fetch.py        — HTTP fetcher via requests over SOCKS5
│   ├── parsers.py      — link extraction, content parsing
│   └── matcher.py     — layered matching stack (keyword → regex → hash)
├── db/
│   ├── models.py      — SQLAlchemy ORM models
│   ├── crud.py        — create/read/update/delete operations
│   └── schema.sql     — raw SQL for migrations
├── api/
│   └── routes/
│       ├── findings.py  — search, filter findings
│       ├── watchlist.py — manage watchlist entries
│       ├── crawl.py     — trigger crawls, view status, Tor health
│       └── alerts.py    — alert history, channel config
├── alerts/
│   ├── dispatcher.py   — routes to email/Slack/webhook
│   └── channels/
│       ├── email.py
│       ├── slack.py
│       └── webhook.py
└── web/                 — static frontend files served by FastAPI
    ├── index.html
    ├── dashboard.js
    └── style.css
```

**Dependency flow:**
```
main.py
  └── scheduler.py → crawler/engine.py → fetch.py → tor_session.py
                                       → parsers.py
                                       → matcher.py → db/crud.py
  └── api/routes/* → db/crud.py
                   → alerts/dispatcher.py → channels/*
```

No circular imports. DB layer is the only shared dependency.

---

## [Section 3] Data Flow & Error Handling

**Crawl flow:**
1. Scheduler triggers job → `engine.py` picks it up
2. `tor_session.py` gets circuit info via Stem (NEWNYM for rotation)
3. `fetch.py` makes HTTP request over SOCKS5 proxy
4. `parsers.py` extracts .onion links + content
5. `matcher.py` runs layered matching (keyword → regex → hash)
6. Matches → `db/crud.py` insert with dedup hash check
7. New findings with `alerted=False` → `alerts/dispatcher.py` fires alerts

**Error handling matrix:**
| Error | Action |
|-------|--------|
| Tor connection failure | Log, skip cycle, retry next interval |
| 5xx response | Transient failure flag, deprioritize next run |
| 404 response | Mark source inactive, stop recrawling |
| Parse failure | Log + skip, non-blocking |
| Alert delivery failure | `alerted=False` persists, alerts table logs error, retry next cycle |

**Circuit rotation:**
- NEWNYM every 10 requests (configurable)
- `sleep(2)` after rotation to allow circuit to establish
- Never rotate mid-page-load

**Rate limiting per domain:**
- `last_crawled` checked before each fetch
- Same URL skipped if crawled within current run interval

**failure_count on sources table:**
- Sources with >5 transient failures marked inactive
- Prevents endlessly retrying dead sites

---

## [Section 4] Testing Strategy

**Test structure:**
```
tests/
├── unit/
│   ├── test_matcher.py       — regex, keyword, hash matching
│   ├── test_crud.py         — dedup, insert, update
│   ├── test_parsers.py     — link extraction, content parsing
│   └── test_tor_session.py  — mocked Stem controller
├── integration/
│   ├── test_crawl_cycle.py  — full flow, mocked fetch responses
│   ├── test_dispatcher.py   — mock email/Slack endpoints
│   └── test_db_ops.py      — real SQLite, in-memory
└── e2e/
    ├── test_api.py          — FastAPI TestClient
    └── test_dashboard.py    — page load, no JS errors
```

**Test watchlist (safe patterns):**
```python
TEST_WATCHLIST = [
    {"type": "regex", "value": r"[a-zA-Z0-9._%+-]+@fusemachines\.com", "severity": "high"},
    {"type": "regex", "value": r"4000[\-\s]?1234[\-\s]?5678[\-\s]?9999", "severity": "critical"},
    {"type": "regex", "value": r"sk_live_[a-zA-Z0-9]{40,}", "severity": "critical"},
    {"type": "keyword", "value": "fusemachines", "severity": "medium"},
    {"type": "hash", "value": "5f4dcc3b5aa765d61d8327deb882cf99", "severity": "high"},
]
```

**Matcher edge cases:**
- Regex with newlines in content
- Unicode content (non-ASCII pages)
- Empty page content
- Overlapping matches (one finding, not two)
- Hash matching on binary content

**Coverage enforcement:** 80% minimum, enforced at CI level.

---

## [Section 5] Dependencies

```
stem>=1.8.0
requests[socks]>=2.28.0
fastapi>=0.110.0
uvicorn>=0.29.0
sqlalchemy>=2.0.0
apscheduler>=3.10.0
beautifulsoup4>=4.12.0
lxml>=5.0.0
pytest>=8.0.0
pytest-cov>=5.0.0
httpx>=0.27.0
python-dotenv>=1.0.0
rapidfuzz>=3.0.0    # fuzzy matching, v2 opt-in
```

---

## [Section 6] API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/findings` | List findings (filter: source_id, severity, alerted, limit) |
| GET | `/api/watchlist` | List active watchlist entries |
| POST | `/api/watchlist` | Add watchlist entry (label, type, value, severity) |
| POST | `/api/crawl/trigger/{tier}` | Trigger crawl for tier 1/2/3 (background) |
| GET | `/api/crawl/health` | Tor circuit health check |
| GET | `/api/alerts` | Alert delivery history |
| GET | `/health` | Server health |
| GET | `/` | Web dashboard |

---

## [Section 7] Alert Channel Config

Configured via environment variables in `.env`:

| Variable | Description |
|----------|-------------|
| `ALERT_EMAIL_HOST` | SMTP host |
| `ALERT_EMAIL_PORT` | SMTP port (default 587) |
| `ALERT_EMAIL_USER` | SMTP username |
| `ALERT_EMAIL_PASSWORD` | SMTP password |
| `ALERT_EMAIL_FROM` | From address |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `WEBHOOK_URL` | Generic webhook endpoint |
| `WEBHOOK_SECRET` | HMAC secret for webhook signature (`X-Webhook-Signature`) |

All channels optional — dispatcher skips any channel with empty config.

---

## [Section 8] Seed URL List

Populated in `app/config.py` under `settings.SEED_PRIORITY_URLS` and `settings.SEED_SECONDARY_URLS`:

```python
SEED_PRIORITY_URLS = []  # Tier 1: paste/leak/dump sites — crawl every 15 min
SEED_SECONDARY_URLS = []  # Tier 2: forums/indexes — crawl every 2 hours
```

Discovered `.onion` links are added to `sources` table at tier 3, crawled every 24h.

---

## Default Regex Patterns

```python
PATTERNS = {
    "email_domain":  r"[a-zA-Z0-9._%+-]+@fusemachines\.com",
    "any_email":     r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}",
    "credential_dump": r"(username|password|passwd|pwd)\s*[:=]\s*\S+",
    "api_key":       r"(api_key|apikey|api-key)\s*[:=]\s*[a-zA-Z0-9]{20,}",
    "anthropic_key": r"sk-ant-FUZZY[a-zA-Z0-9-]{40,}",
    "stripe_pk":     r"pk_live_FAKE[a-zA-Z0-9]{20,}",
    "stripe_sk":     r"sk_live_FUZZY[a-zA-Z0-9]{20,}",
    "private_key":   r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "credit_card":   r"\b(?:\d[ -]?){13,16}\b",
    "ssn":           r"\b\d{3}-\d{2}-\d{4}\b",
}
```

---

## Layered Matching Stack

| Layer | Method | Purpose |
|-------|--------|---------|
| 1 | Exact keyword | Fast pre-filter gate |
| 2 | Regex patterns | Emails, credentials, API keys, cards, SSNs |
| 3 | Hash comparison | Known leaked files, zero false positives |
| 4 | Fuzzy matching | Future v2, opt-in flag |