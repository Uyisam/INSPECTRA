from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime

from backend.database.connection import Base


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    title = Column(
        String(200),
        nullable=False
    )

    message = Column(
        Text,
        nullable=False
    )

    notification_type = Column(
        String(50),
        nullable=False
    )

    severity = Column(
        String(20),
        nullable=True
    )

    is_read = Column(
        String(10),
        default="false",
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )