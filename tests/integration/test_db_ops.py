# tests/integration/test_db_ops.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.db.models import Base, Source, Watchlist, Finding
from app.db.crud import (
    upsert_source, add_watchlist_entry, insert_finding,
    compute_content_hash, get_active_sources_by_tier, mark_source_failure
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


def test_dedup_same_finding_twice(db: Session):
    src = upsert_source(db, "http://test.onion", "test.onion", True, 1)
    wl = add_watchlist_entry(db, "Test", "keyword", "password", "high")
    f1 = insert_finding(db, src.id, 1, wl.id, "password123", "context", "high", "http://test.onion")
    f2 = insert_finding(db, src.id, 1, wl.id, "password123", "context", "high", "http://test.onion")
    assert f1 is not None
    assert f2 is None


def test_upsert_source_updates_crawl_count(db: Session):
    src1 = upsert_source(db, "http://test.onion", "test.onion", True, 1)
    assert src1.crawl_count == 1
    db.expire(src1)
    src2 = upsert_source(db, "http://test.onion", "test.onion", True, 1)
    assert src2.crawl_count == 2


def test_failure_count_deactivates_source(db: Session):
    src = upsert_source(db, "http://dead.onion", "dead.onion", True, 1)
    for i in range(5):
        mark_source_failure(db, src, is_permanent=False)
        db.expire(src)
    assert src.is_active is False