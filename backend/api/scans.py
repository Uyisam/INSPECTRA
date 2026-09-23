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

@router.post(
    "/",
    response_model=ScanResponse
)
def create_scan(
    scan: ScanCreate,
    db: Session = Depends(get_db)
):
    asset = (
        db.query(Asset)
        .filter(
            Asset.id == scan.asset_id
        )
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

@router.get(
    "/",
    response_model=list[ScanResponse]
)
def get_scans(
    db: Session = Depends(get_db)
):
    scans = (
        db.query(Scan)
        .all()
    )

    return scans


# ==========================================
# RUN SCAN
# ==========================================

@router.post(
    "/{scan_id}/run"
)
def run_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    # --------------------------------------
    # FIND SCAN
    # --------------------------------------

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # --------------------------------------
    # FIND ASSET
    # --------------------------------------

    asset = (
        db.query(Asset)
        .filter(
            Asset.id == scan.asset_id
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=404,
            detail="Asset not found"
        )

    # --------------------------------------
    # VALIDATE ASSET TYPE
    # --------------------------------------

    if asset.asset_type != "filesystem":
        raise HTTPException(
            status_code=400,
            detail=(
                "Trivy filesystem scanning currently "
                "requires an asset of type 'filesystem'"
            )
        )

    # --------------------------------------
    # MARK SCAN AS RUNNING
    # --------------------------------------

    scan.status = "running"
    scan.started_at = datetime.utcnow()

    db.commit()

    # --------------------------------------
    # RUN TRIVY
    # --------------------------------------

    try:

        results = run_trivy_scan(
            asset.target
        )

        # ----------------------------------
        # PARSE TRIVY RESULTS
        # ----------------------------------

        parsed_findings = (
            parse_trivy_findings(
                results
            )
        )

        # ----------------------------------
        # SAVE FINDINGS
        # ----------------------------------

        saved_findings = save_findings(
            db=db,
            scan_id=scan.id,
            findings=parsed_findings
        )

        # ----------------------------------
        # CREATE SECURITY NOTIFICATIONS
        # ----------------------------------

        for finding in saved_findings:

            if finding.severity in {
                "CRITICAL",
                "HIGH"
            }:

                create_notification(
                    db=db,

                    title=(
                        f"{finding.severity} "
                        f"vulnerability detected"
                    ),

                    message=(
                        f"{finding.vulnerability_id} "
                        f"was detected in "
                        f"{finding.package_name} "
                        f"with risk score "
                        f"{finding.risk_score}."
                    ),

                    notification_type=(
                        "vulnerability"
                    ),

                    severity=finding.severity
                )

        # ----------------------------------
        # MARK SCAN AS COMPLETED
        # ----------------------------------

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()

        db.commit()

        return {
            "message": (
                "Scan completed successfully"
            ),

            "scan_id": scan.id,

            "status": scan.status,

            "targets": len(
                results.get(
                    "Results",
                    []
                )
            ),

            "vulnerabilities": len(
                saved_findings
            )
        }

    # --------------------------------------
    # HANDLE SCAN FAILURE
    # --------------------------------------

    except Exception as error:

        scan.status = "failed"
        scan.completed_at = datetime.utcnow()

        db.commit()

        raise HTTPException(
            status_code=500,
            detail=(
                f"Scan failed: {str(error)}"
            )
        )