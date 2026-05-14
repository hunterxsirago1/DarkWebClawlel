# app/api/routes/watchlist.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.crud import add_watchlist_entry, get_active_watchlist
from app.db.models import init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["watchlist"])


class WatchlistItem(BaseModel):
    label: str
    type: str
    value: str
    severity: str


def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


@router.get("/watchlist")
def list_watchlist(session: Session = Depends(get_session)):
    items = get_active_watchlist(session)
    return {
        "data": [
            {
                "id": w.id,
                "label": w.label,
                "type": w.type,
                "value": w.value,
                "severity": w.severity,
                "active": w.active,
            }
            for w in items
        ]
    }


@router.post("/watchlist")
def create_watchlist_item(item: WatchlistItem, session: Session = Depends(get_session)):
    if item.type not in ("keyword", "regex", "hash"):
        raise HTTPException(status_code=400, detail="type must be keyword, regex, or hash")
    if item.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical, high, medium, or low")
    entry = add_watchlist_entry(session, item.label, item.type, item.value, item.severity)
    return {"id": entry.id, "status": "created"}