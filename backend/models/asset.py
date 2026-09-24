from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from backend.database.connection import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String(150),
        nullable=False
    )

    asset_type = Column(
        String(50),
        nullable=False
    )

    target = Column(
        Text,
        nullable=False
    )

    project_id = Column(
        Integer,
        ForeignKey("projects.id"),
        nullable=False
    )

    criticality = Column(
        String(20),
        default="medium",
        nullable=False
    )

    environment = Column(
        String(20),
        default="development",
        nullable=False
    )

    internet_exposed = Column(
        Boolean,
        default=False,
        nullable=False
    )

    project = relationship(
        "Project",
        backref="assets"
    )