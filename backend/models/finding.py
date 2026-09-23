from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey

from backend.database.connection import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=False
    )

    vulnerability_id = Column(
        String(100),
        nullable=False,
        index=True
    )

    package_name = Column(
        String(200),
        nullable=False
    )

    installed_version = Column(
        String(100),
        nullable=False
    )

    fixed_version = Column(
        String(100),
        nullable=True
    )

    severity = Column(
        String(20),
        nullable=False
    )

    cvss_score = Column(
        Float,
        nullable=True
    )

    title = Column(
        Text,
        nullable=True
    )

    description = Column(
        Text,
        nullable=True
    )

    primary_url = Column(
        Text,
        nullable=True
    )

    target = Column(
        Text,
        nullable=True
    )

    status = Column(
        String(30),
        default="open",
        nullable=False
    )

    risk_score = Column(
        Float,
        nullable=True
    )
    
    priority = Column(
        String(10),
        nullable=True
    )