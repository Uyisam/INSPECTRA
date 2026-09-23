from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database.connection import SessionLocal
from backend.models.notification import Notification


router = APIRouter(
    prefix="/notifications",
    tags=["Notifications"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ==========================================
# RESPONSE / UPDATE SCHEMAS
# ==========================================

class NotificationReadUpdate(BaseModel):
    is_read: bool


# ==========================================
# GET ALL NOTIFICATIONS
# ==========================================

@router.get("/")
def get_notifications(
    db: Session = Depends(get_db)
):
    notifications = (
        db.query(Notification)
        .order_by(
            Notification.created_at.desc()
        )
        .all()
    )

    return notifications


# ==========================================
# GET UNREAD NOTIFICATIONS
# ==========================================

@router.get("/unread")
def get_unread_notifications(
    db: Session = Depends(get_db)
):
    notifications = (
        db.query(Notification)
        .filter(
            Notification.is_read == "false"
        )
        .order_by(
            Notification.created_at.desc()
        )
        .all()
    )

    return notifications


# ==========================================
# GET SINGLE NOTIFICATION
# ==========================================

@router.get("/{notification_id}")
def get_notification(
    notification_id: int,
    db: Session = Depends(get_db)
):
    notification = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=404,
            detail="Notification not found"
        )

    return notification


# ==========================================
# MARK NOTIFICATION AS READ / UNREAD
# ==========================================

@router.patch("/{notification_id}/read")
def update_notification_read_status(
    notification_id: int,
    update: NotificationReadUpdate,
    db: Session = Depends(get_db)
):
    notification = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=404,
            detail="Notification not found"
        )

    notification.is_read = (
        "true"
        if update.is_read
        else "false"
    )

    db.commit()
    db.refresh(notification)

    return notification