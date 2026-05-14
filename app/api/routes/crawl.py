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