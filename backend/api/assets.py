from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.models.asset import Asset
from backend.schemas.asset import AssetCreate, AssetResponse


router = APIRouter(prefix="/assets", tags=["Assets"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/", response_model=AssetResponse)
def create_asset(asset: AssetCreate, db: Session = Depends(get_db)):
    new_asset = Asset(
        name=asset.name,
        asset_type=asset.asset_type,
        target=asset.target,
        project_id=asset.project_id
    )

    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    return new_asset


@router.get("/", response_model=list[AssetResponse])
def get_assets(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return assets