# app/db/crud.py
import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.db.models import Source, Watchlist, CrawlHistory, Finding, Alert


def compute_content_hash(value: str, source_url: str) -> str:
    return hashlib.sha256(f"{value}{source_url}".encode()).hexdigest()


# --- Sources ---
def upsert_source(session: Session, url: str, domain: str = None, is_seed: bool = False, tier: int = 3) -> Source:
    existing = session.query(Source).filter_by(url=url).first()
    if existing:
        existing.last_crawled = datetime.now(timezone.utc)
        existing.crawl_count += 1
        session.commit()
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
        if source.failure_count >= 5:
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
    crawl.finished_at = datetime.now(timezone.utc)
    crawl.pages_crawled = pages
    crawl.findings_count = findings
    crawl.status = status
    session.commit()


# --- Findings ---
def insert_finding(session: Session, source_id: int, crawl_id: int, watchlist_id: int,
                  matched_value: str, context: str, severity: str, source_url: str) -> Finding | None:
    content_hash = compute_content_hash(matched_value, source_url)
    existing = session.query(Finding).filter_by(content_hash=content_hash).first()
    if existing:
        return None  # dedup
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