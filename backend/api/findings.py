from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database.connection import SessionLocal
from backend.models.finding import Finding
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


@router.get(
    "/",
    response_model=list[FindingResponse]
)
def get_findings(
    db: Session = Depends(get_db)
):
    findings = (
        db.query(Finding)
        .order_by(Finding.risk_score.desc())
        .all()
    )

    return findings


@router.get(
    "/{finding_id}",
    response_model=FindingResponse
)
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


@router.patch(
    "/{finding_id}/status",
    response_model=FindingResponse
)
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
            detail=(
                "Invalid status. "
                "Use open, in_progress or resolved."
            )
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