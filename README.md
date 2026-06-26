# DarkWebClawlel

DarkWebClawlel is a robust Dark Web threat intelligence monitor and crawler built with Python. 

## Features
- **Tor Network Integration:** Utilizes `stem` and Tor proxies to continuously crawl onion sites.
- **Threat Intelligence API:** Provides a FastAPI-based REST API for querying monitored data and threat intel.
- **Automated Monitoring:** Uses `apscheduler` to run periodic scraping and analysis jobs.
- **Database Storage:** Leverages SQLAlchemy for robust data persistence.
- **Parsing & Matching:** Uses BeautifulSoup4 for HTML parsing and RapidFuzz for fuzzy matching of threat patterns.

## Tech Stack
- Python 3.11+
- FastAPI & Uvicorn
- SQLAlchemy
- Stem (Tor)