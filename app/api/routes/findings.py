# app/api/routes/findings.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.db.crud import get_findings
from app.db.models import init_db
from app.config import settings

router = APIRouter(prefix="/api", tags=["findings"])


def get_session():
    engine = init_db(settings.DATABASE_URL)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()


@router.get("/findings")
def list_findings(
    source_id: int | None = None,
    severity: str | None = None,
    alerted: bool | None = None,
    limit: int = Query(default=100, le=1000),
    session: Session = Depends(get_session),
):
    findings = get_findings(session, source_id, severity, alerted, limit)
    return {
        "data": [
            {
                "id": f.id,
                "matched_value": f.matched_value,
                "context": f.context,
                "severity": f.severity,
                "alerted": f.alerted,
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                "source_id": f.source_id,
            }
            for f in findings
        ]
    }