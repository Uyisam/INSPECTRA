from pydantic import BaseModel


class AssetCreate(BaseModel):
    name: str
    asset_type: str
    target: str
    project_id: int

    criticality: str = "medium"
    environment: str = "development"
    internet_exposed: bool = False


class AssetResponse(BaseModel):
    id: int
    name: str
    asset_type: str
    target: str
    project_id: int

    criticality: str
    environment: str
    internet_exposed: bool

    class Config:
        from_attributes = True