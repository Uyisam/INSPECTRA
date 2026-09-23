from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: int
    scan_id: int

    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str | None = None

    severity: str
    cvss_score: float | None = None

    title: str | None = None
    description: str | None = None
    primary_url: str | None = None
    target: str | None = None

    status: str
    risk_score: float | None = None
    priority: str | None = None

    class Config:
        from_attributes = True