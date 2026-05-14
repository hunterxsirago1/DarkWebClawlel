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