from sqlalchemy.orm import Session

from backend.models.finding import Finding
from backend.services.risk_engine import (
    calculate_risk_score,
    get_priority
)


def save_findings(
    db: Session,
    scan_id: int,
    findings: list[dict]
):
    """
    Save parsed vulnerability findings into the database
    and calculate their risk score and priority.
    """

    saved_findings = []

    for item in findings:

        cvss_score = item.get("cvss_score")
        severity = item.get("severity")

        # Calculate Inspectra risk score
        risk_score = calculate_risk_score(
            cvss_score=cvss_score,
            severity=severity
        )

        # Convert risk score into remediation priority
        priority = get_priority(risk_score)

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

            risk_score=risk_score,

            priority=priority
        )

        db.add(finding)
        saved_findings.append(finding)

    db.commit()

    for finding in saved_findings:
        db.refresh(finding)

    return saved_findings