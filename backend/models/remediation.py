from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
)
from datetime import datetime

from backend.database.connection import Base


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False
    )

    title = Column(
        String(200),
        nullable=False
    )

    description = Column(
        Text,
        nullable=True
    )

    status = Column(
        String(30),
        default="open",
        nullable=False
    )

    assignee = Column(
        String(150),
        nullable=True
    )

    due_date = Column(
        DateTime,
        nullable=True
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )