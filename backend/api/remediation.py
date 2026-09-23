from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.models.remediation import RemediationTask
from backend.models.finding import Finding


router = APIRouter(
    prefix="/remediation",
    tags=["Remediation"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ==========================================
# REQUEST SCHEMAS
# ==========================================

class RemediationCreate(BaseModel):
    finding_id: int
    title: str
    description: str | None = None
    assignee: str | None = None
    due_date: datetime | None = None


class RemediationStatusUpdate(BaseModel):
    status: str


class RemediationAssignmentUpdate(BaseModel):
    assignee: str | None = None


# ==========================================
# CREATE REMEDIATION TASK
# ==========================================

@router.post("/")
def create_remediation_task(
    task: RemediationCreate,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == task.finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    new_task = RemediationTask(
        finding_id=task.finding_id,
        title=task.title,
        description=task.description,
        status="open",
        assignee=task.assignee,
        due_date=task.due_date
    )

    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    return new_task


# ==========================================
# GET ALL REMEDIATION TASKS
# ==========================================

@router.get("/")
def get_remediation_tasks(
    db: Session = Depends(get_db)
):
    tasks = (
        db.query(RemediationTask)
        .order_by(
            RemediationTask.created_at.desc()
        )
        .all()
    )

    return tasks


# ==========================================
# GET SINGLE REMEDIATION TASK
# ==========================================

@router.get("/{task_id}")
def get_remediation_task(
    task_id: int,
    db: Session = Depends(get_db)
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=404,
            detail="Remediation task not found"
        )

    return task


# ==========================================
# UPDATE STATUS
# ==========================================

@router.patch("/{task_id}/status")
def update_remediation_status(
    task_id: int,
    update: RemediationStatusUpdate,
    db: Session = Depends(get_db)
):
    allowed_statuses = {
        "open",
        "in_progress",
        "resolved",
        "closed"
    }

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. "
                "Use open, in_progress, "
                "resolved or closed."
            )
        )

    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=404,
            detail="Remediation task not found"
        )

    task.status = update.status
    task.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(task)

    return task


# ==========================================
# ASSIGN TASK
# ==========================================

@router.patch("/{task_id}/assignee")
def update_remediation_assignee(
    task_id: int,
    update: RemediationAssignmentUpdate,
    db: Session = Depends(get_db)
):
    task = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id)
        .first()
    )

    if not task:
        raise HTTPException(
            status_code=404,
            detail="Remediation task not found"
        )

    task.assignee = update.assignee
    task.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(task)

    return task