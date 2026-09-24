from sqlalchemy.orm import Session

from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.asset import Asset

from backend.services.risk_engine import (
    calculate_risk_score,
    get_risk_breakdown,
    get_priority
)


def save_findings(
    db: Session,
    scan_id: int,
    findings: list[dict]
):
    """
    Save scanner findings and calculate contextual risk.

    Flow:
        Finding → Scan → Asset → Risk Engine
    """

    # ---------------------------------------------------------
    # 1. Find the scan
    # ---------------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise ValueError(
            f"Scan {scan_id} not found"
        )

    # ---------------------------------------------------------
    # 2. Find the asset connected to the scan
    # ---------------------------------------------------------

    asset = (
        db.query(Asset)
        .filter(Asset.id == scan.asset_id)
        .first()
    )

    if not asset:
        raise ValueError(
            f"Asset for scan {scan_id} not found"
        )

    # ---------------------------------------------------------
    # 3. Save findings
    # ---------------------------------------------------------

    saved_findings = []

    for item in findings:

        cvss_score = item.get("cvss_score")
        severity = item.get("severity")

        # -----------------------------------------------------
        # Calculate contextual risk
        # -----------------------------------------------------

        risk_score = calculate_risk_score(
            cvss_score=cvss_score,
            severity=severity,
            asset_criticality=asset.criticality,
            environment=asset.environment,
            internet_exposed=asset.internet_exposed
        )

        # -----------------------------------------------------
        # Generate risk explanation
        # -----------------------------------------------------

        breakdown = get_risk_breakdown(
            cvss_score=cvss_score,
            severity=severity,
            asset_criticality=asset.criticality,
            environment=asset.environment,
            internet_exposed=asset.internet_exposed
        )

        # -----------------------------------------------------
        # Determine remediation priority
        # -----------------------------------------------------

        priority = get_priority(
            risk_score
        )

        # -----------------------------------------------------
        # Create finding
        # -----------------------------------------------------

        finding = Finding(
            scan_id=scan_id,

            vulnerability_id=item.get(
                "vulnerability_id"
            ),

            package_name=item.get(
                "package_name"
            ),

            installed_version=item.get(
                "installed_version"
            ),

            fixed_version=item.get(
                "fixed_version"
            ),

            severity=severity,

            cvss_score=cvss_score,

            title=item.get(
                "title"
            ),

            description=item.get(
                "description"
            ),

            primary_url=item.get(
                "primary_url"
            ),

            target=item.get(
                "target"
            ),

            status="open",

            # -------------------------------------------------
            # Final risk information
            # -------------------------------------------------

            risk_score=risk_score,

            priority=priority,

            # -------------------------------------------------
            # Risk breakdown
            # -------------------------------------------------

            base_cvss=breakdown[
                "base_cvss"
            ],

            criticality_adjustment=breakdown[
                "criticality_adjustment"
            ],

            environment_adjustment=breakdown[
                "environment_adjustment"
            ],

            internet_exposure_adjustment=breakdown[
                "internet_exposure_adjustment"
            ]
        )

        db.add(finding)

        saved_findings.append(
            finding
        )

    # ---------------------------------------------------------
    # 4. Save everything to database
    # ---------------------------------------------------------

    db.commit()

    # ---------------------------------------------------------
    # 5. Refresh database objects
    # ---------------------------------------------------------

    for finding in saved_findings:
        db.refresh(finding)

    return saved_findings