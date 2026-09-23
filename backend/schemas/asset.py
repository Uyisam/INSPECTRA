from pydantic import BaseModel


class AssetCreate(BaseModel):
    name: str
    asset_type: str
    target: str
    project_id: int


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    target: str
    project_id: int

    class Config:
        from_attributes = True