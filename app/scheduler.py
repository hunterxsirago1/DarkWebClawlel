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