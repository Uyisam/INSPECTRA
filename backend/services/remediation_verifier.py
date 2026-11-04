from datetime import datetime

from sqlalchemy.orm import Session

from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.asset import Asset

from backend.services.trivy_scanner import run_trivy_scan
from backend.services.finding_parser import parse_trivy_findings


def verify_finding_remediation(
    db: Session,
    finding_id: int
):
    """
    Re-scan the asset associated with a finding and determine
    whether the vulnerability is still present.

    A separate verification scan is created so that Inspectra
    maintains an audit trail of remediation verification.

    Returns:
        verified: True when the vulnerability is no longer detected
        verified: False when the vulnerability is still detected
        verification_scan_id: ID of the verification scan
    """

    # ==========================================
    # FIND ORIGINAL FINDING
    # ==========================================

    finding = (
        db.query(Finding)
        .filter(
            Finding.id == finding_id
        )
        .first()
    )

    if not finding:
        raise ValueError(
            "Finding not found"
        )

    # ==========================================
    # FIND ORIGINAL SCAN
    # ==========================================

    original_scan = (
        db.query(Scan)
        .filter(
            Scan.id == finding.scan_id
        )
        .first()
    )

    if not original_scan:
        raise ValueError(
            "Original scan not found"
        )

    # ==========================================
    # FIND ASSET
    # ==========================================

    asset = (
        db.query(Asset)
        .filter(
            Asset.id == original_scan.asset_id
        )
        .first()
    )

    if not asset:
        raise ValueError(
            "Asset not found"
        )

    # ==========================================
    # CHECK SUPPORTED ASSET TYPE
    # ==========================================

    if asset.asset_type != "filesystem":
        raise ValueError(
            "Remediation verification currently "
            "requires a filesystem asset"
        )

    # ==========================================
    # CREATE VERIFICATION SCAN
    # ==========================================

    verification_scan = Scan(
        asset_id=asset.id,
        scanner="Trivy Verification",
        status="running",
        started_at=datetime.utcnow()
    )

    db.add(verification_scan)
    db.commit()
    db.refresh(verification_scan)

    # ==========================================
    # RUN TRIVY
    # ==========================================

    try:

        results = run_trivy_scan(
            asset.target
        )

        # ======================================
        # PARSE RESULTS
        # ======================================

        parsed_findings = (
            parse_trivy_findings(
                results
            )
        )

        # ======================================
        # MATCH ORIGINAL VULNERABILITY
        # ======================================

        matching_findings = []

        for item in parsed_findings:

            vulnerability_id = (
                item.get(
                    "vulnerability_id"
                )
            )

            package_name = (
                item.get(
                    "package_name"
                )
            )

            if (
                vulnerability_id
                == finding.vulnerability_id
                and package_name
                == finding.package_name
            ):

                matching_findings.append(
                    item
                )

        # ======================================
        # COMPLETE VERIFICATION SCAN
        # ======================================

        verification_scan.status = (
            "completed"
        )

        verification_scan.completed_at = (
            datetime.utcnow()
        )

        db.commit()
        db.refresh(verification_scan)

        # ======================================
        # VULNERABILITY STILL EXISTS
        # ======================================

        if matching_findings:

            return {
                "verified": False,

                "finding_id": (
                    finding.id
                ),

                "verification_scan_id": (
                    verification_scan.id
                ),

                "vulnerability_id": (
                    finding.vulnerability_id
                ),

                "package_name": (
                    finding.package_name
                ),

                "message": (
                    "The vulnerability is still "
                    "detected after the verification scan."
                )
            }

        # ======================================
        # VULNERABILITY NO LONGER EXISTS
        # ======================================

        return {
            "verified": True,

            "finding_id": (
                finding.id
            ),

            "verification_scan_id": (
                verification_scan.id
            ),

            "vulnerability_id": (
                finding.vulnerability_id
            ),

            "package_name": (
                finding.package_name
            ),

            "message": (
                "The vulnerability is no longer "
                "detected by the verification scan."
            )
        }

    # ==========================================
    # VERIFICATION SCAN FAILED
    # ==========================================

    except Exception:

        verification_scan.status = (
            "failed"
        )

        verification_scan.completed_at = (
            datetime.utcnow()
        )

        db.commit()

        raise