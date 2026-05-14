# app/db/models.py
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, CheckConstraint
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=True, nullable=False)
    domain = Column(Text)
    first_seen = Column(DateTime, default=datetime.now(timezone.utc))
    last_crawled = Column(DateTime)
    crawl_count = Column(Integer, default=1)
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
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    __table_args__ = (
        CheckConstraint("type IN ('keyword','regex','hash')"),
        CheckConstraint("severity IN ('critical','high','medium','low')"),
    )


class CrawlHistory(Base):
    __tablename__ = "crawl_history"
    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, default=datetime.now(timezone.utc))
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
    source_id = Column(Integer)
    crawl_id = Column(Integer)
    watchlist_id = Column(Integer)
    matched_value = Column(Text)
    context = Column(Text)
    severity = Column(Text)
    alerted = Column(Boolean, default=False)
    content_hash = Column(Text)
    timestamp = Column(DateTime, default=datetime.now(timezone.utc))
    __table_args__ = (
        CheckConstraint("severity IN ('critical','high','medium','low')"),
    )


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer)
    channel = Column(Text)
    sent_at = Column(DateTime, default=datetime.now(timezone.utc))
    success = Column(Boolean)
    error = Column(Text)


def init_db(database_url: str):
    from sqlalchemy import create_engine
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    return engine