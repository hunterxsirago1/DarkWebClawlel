# tests/unit/test_crud.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from app.db.models import Base, Source


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


def test_source_insert_and_fetch(db: Session):
    source = Source(url="http://example.onion", domain="example.onion", is_seed=True, tier=1)
    db.add(source)
    db.commit()
    fetched = db.query(Source).filter_by(url="http://example.onion").first()
    assert fetched is not None
    assert fetched.domain == "example.onion"
    assert fetched.tier == 1