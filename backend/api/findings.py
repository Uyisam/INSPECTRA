
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database.connection import SessionLocal
from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.schemas.finding import FindingResponse


router = APIRouter(
    prefix="/findings",
    tags=["Findings"]
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class FindingStatusUpdate(BaseModel):
    status: str


@router.get("/", response_model=list[FindingResponse])
def get_findings(
    latest: bool = Query(default=False),
    db: Session = Depends(get_db)
):
    query = db.query(Finding)

    if latest:
        latest_scan = (
            db.query(Scan)
            .filter(
                Scan.status == "completed",
                Scan.completed_at.isnot(None)
            )
            .order_by(
                Scan.completed_at.desc(),
                Scan.id.desc()
            )
            .first()
        )

        if latest_scan is None:
            return []

        query = query.filter(
            Finding.scan_id == latest_scan.id
        )

    return query.order_by(
        Finding.risk_score.desc()
    ).all()


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
def update_finding_status(
    finding_id: int,
    update: FindingStatusUpdate,
    db: Session = Depends(get_db)
):
    allowed_statuses = {
        "open",
        "in_progress",
        "resolved"
    }

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Use open, in_progress or resolved."
        )

    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    finding.status = update.status
    db.commit()
    db.refresh(finding)

    return finding
