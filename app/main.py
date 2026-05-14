# app/main.py
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import os
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
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

web_path = os.path.join(os.path.dirname(__file__), "web")
if os.path.exists(web_path):
    app.mount("/web", StaticFiles(directory=web_path), name="web")


@app.get("/")
def root():
    path = os.path.join(os.path.dirname(__file__), "web", "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    return {"status": "ok", "message": "Dark Web Intel Monitor"}


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)