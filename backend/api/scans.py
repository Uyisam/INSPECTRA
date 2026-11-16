
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.models.scan import Scan
from backend.models.asset import Asset
from backend.schemas.scan import ScanCreate, ScanResponse

from backend.services.trivy_scanner import run_trivy_scan
from backend.services.finding_parser import parse_trivy_findings
from backend.services.finding_service import save_findings
from backend.services.notification_service import create_notification


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# ==========================================
# CREATE SCAN
# ==========================================

@router.post("/", response_model=ScanResponse)
def create_scan(
    scan: ScanCreate,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(Asset.id == scan.asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    new_scan = Scan(
        asset_id=scan.asset_id,
        scanner=scan.scanner,
        status="pending"
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    return new_scan


# ==========================================
# GET ALL SCANS
# ==========================================

@router.get("/", response_model=list[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(Scan).all()


# ==========================================
# RUN SCAN
# ==========================================

@router.post("/{scan_id}/run")
def run_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == scan.asset_id)
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    if asset.asset_type != "filesystem":
        raise HTTPException(
            status_code=400,
            detail=(
                "Trivy filesystem scanning currently "
                "requires an asset of type 'filesystem'"
            )
        )

    # Atomically claim the scan.
    # Only pending or failed scans can be started.
    updated_rows = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.status.in_(["pending", "failed"])
        )
        .update(
            {
                "status": "running",
                "started_at": datetime.utcnow(),
                "completed_at": None
            },
            synchronize_session=False
        )
    )

    if updated_rows == 0:
        db.refresh(scan)

        raise HTTPException(
            status_code=409,
            detail=(
                f"Scan cannot be started because its "
                f"current status is '{scan.status}'. "
                "Only pending or failed scans can run."
            )
        )

    db.commit()
    db.refresh(scan)

    try:
        results = run_trivy_scan(asset.target)

        parsed_findings = parse_trivy_findings(results)

        saved_findings = save_findings(
            db=db,
            scan_id=scan.id,
            findings=parsed_findings
        )

        for finding in saved_findings:
            if finding.severity in {"CRITICAL", "HIGH"}:
                create_notification(
                    db=db,
                    title=(
                        f"{finding.severity} "
                        "vulnerability detected"
                    ),
                    message=(
                        f"{finding.vulnerability_id} "
                        f"was detected in {finding.package_name} "
                        f"with risk score {finding.risk_score}."
                    ),
                    notification_type="vulnerability",
                    severity=finding.severity
                )

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        db.commit()

        return {
            "message": "Scan completed successfully",
            "scan_id": scan.id,
            "status": scan.status,
            "targets": len(results.get("Results", [])),
            "vulnerabilities": len(saved_findings)
        }

    except Exception as error:
        db.rollback()

        failed_scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .first()
        )

        if failed_scan and failed_scan.status == "running":
            failed_scan.status = "failed"
            failed_scan.completed_at = datetime.utcnow()
            db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(error)}"
        )
