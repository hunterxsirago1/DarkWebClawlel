# app/api/routes/alerts.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.models import Alert, init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["alerts"])


def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


@router.get("/alerts")
def list_alerts(limit: int = 100, session: Session = Depends(get_session)):
    alerts = session.query(Alert).order_by(Alert.sent_at.desc()).limit(limit).all()
    return {
        "data": [
            {
                "id": a.id,
                "finding_id": a.finding_id,
                "channel": a.channel,
                "sent_at": a.sent_at.isoformat() if a.sent_at else None,
                "success": a.success,
                "error": a.error,
            }
            for a in alerts
        ]
    }