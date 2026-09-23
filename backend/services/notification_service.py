from sqlalchemy.orm import Session

from backend.models.notification import Notification


def create_notification(
    db: Session,
    title: str,
    message: str,
    notification_type: str,
    severity: str | None = None
):
    """
    Create and store a notification in Inspectra.
    """

    notification = Notification(
        title=title,
        message=message,
        notification_type=notification_type,
        severity=severity,
        is_read="false"
    )

    db.add(notification)
    db.commit()
    db.refresh(notification)

    return notification