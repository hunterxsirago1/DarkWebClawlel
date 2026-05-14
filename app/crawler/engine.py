# app/crawler/engine.py
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.config import settings
from app.db.crud import get_active_sources_by_tier, upsert_source, insert_finding, create_crawl, finish_crawl, mark_source_failure
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
        if not sources:
            logger.info(f"No active sources for tier {tier}")
            return 0, 0

        crawl = create_crawl(session, tier=tier)
        tor = TorSession()
        fetcher = Fetcher()
        pages = 0
        findings = 0

        for source in sources:
            try:
                status, html = fetcher.fetch(source.url)
                if status == 0:
                    mark_source_failure(session, source, is_permanent=False)
                    continue
                if status == 404:
                    mark_source_failure(session, source, is_permanent=True)
                    continue
                if status >= 500:
                    mark_source_failure(session, source, is_permanent=False)
                    continue

                pages += 1
                upsert_source(session, source.url, source.domain, source.is_seed, source.tier)
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