from pydantic import BaseModel
from datetime import datetime


class ScanCreate(BaseModel):
    asset_id: int
    scanner: str


class ScanResponse(BaseModel):
    id: int
    asset_id: int
    scanner: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None

    class Config:
        from_attributes = True