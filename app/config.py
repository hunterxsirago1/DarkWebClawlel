# app/config.py
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # Tor
    TOR_HOST: str = os.getenv("TOR_HOST", "127.0.0.1")
    TOR_SOCKS_PORT: int = int(os.getenv("TOR_SOCKS_PORT", "9050"))
    TOR_CONTROL_PORT: int = int(os.getenv("TOR_CONTROL_PORT", "9051"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./darkweb.db")

    # Crawler
    NEWNYM_INTERVAL: int = int(os.getenv("NEWNYM_INTERVAL", "10"))
    MIN_CRAWL_INTERVAL_SECONDS: int = int(os.getenv("MIN_CRAWL_INTERVAL_SECONDS", "60"))
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", "3"))

    # Alert channels
    ALERT_EMAIL_HOST: str = os.getenv("ALERT_EMAIL_HOST", "")
    ALERT_EMAIL_PORT: int = int(os.getenv("ALERT_EMAIL_PORT", "587"))
    ALERT_EMAIL_USER: str = os.getenv("ALERT_EMAIL_USER", "")
    ALERT_EMAIL_PASSWORD: str = os.getenv("ALERT_EMAIL_PASSWORD", "")
    ALERT_EMAIL_FROM: str = os.getenv("ALERT_EMAIL_FROM", "noreply@example.com")
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", "")
    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")

    # Seed URLs
    SEED_PRIORITY_URLS: list[str] = []
    SEED_SECONDARY_URLS: list[str] = []


settings = Settings()