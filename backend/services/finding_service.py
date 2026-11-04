from sqlalchemy.orm import Session

from backend.models.finding import Finding
from backend.models.scan import Scan
from backend.models.asset import Asset

from backend.services.risk_engine import (
    calculate_risk_score,
    get_risk_breakdown,
    get_priority
)

from backend.services.nvd_service import get_cve_details


def save_findings(
    db: Session,
    scan_id: int,
    findings: list[dict]
):
    """
    Save scanner findings, enrich CVE information using NVD,
    calculate contextual risk, and store vulnerability intelligence.
    """

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise ValueError(
            f"Scan {scan_id} not found"
        )

    asset = (
        db.query(Asset)
        .filter(Asset.id == scan.asset_id)
        .first()
    )

    if not asset:
        raise ValueError(
            f"Asset for scan {scan_id} not found"
        )

    saved_findings = []

    for item in findings:

        vulnerability_id = item.get(
            "vulnerability_id"
        )

        cvss_score = item.get(
            "cvss_score"
        )

        severity = item.get(
            "severity"
        )

        title = item.get(
            "title"
        )

        description = item.get(
            "description"
        )

        primary_url = item.get(
            "primary_url"
        )

        # NVD intelligence fields
        cvss_version = None
        cvss_vector = None
        cwes = None
        published = None
        last_modified = None

        nvd_data = None

        # Fetch NVD information only for CVE identifiers
        if (
            vulnerability_id
            and vulnerability_id.upper().startswith("CVE-")
        ):
            try:
                nvd_data = get_cve_details(
                    vulnerability_id
                )

            except Exception as error:
                print(
                    f"NVD enrichment failed for "
                    f"{vulnerability_id}: {error}"
                )

        # Apply NVD intelligence
        if nvd_data:

            if nvd_data.get("cvss_score") is not None:
                cvss_score = nvd_data.get(
                    "cvss_score"
                )

            if nvd_data.get("severity"):
                severity = nvd_data.get(
                    "severity"
                )

            if nvd_data.get("description"):
                description = nvd_data.get(
                    "description"
                )

            cvss_version = nvd_data.get(
                "cvss_version"
            )

            cvss_vector = nvd_data.get(
                "cvss_vector"
            )

            cwe_list = nvd_data.get(
                "cwes",
                []
            )

            if cwe_list:
                cwes = ", ".join(cwe_list)

            published = nvd_data.get(
                "published"
            )

            last_modified = nvd_data.get(
                "last_modified"
            )

            references = nvd_data.get(
                "references",
                []
            )

            if references and not primary_url:
                primary_url = references[0]

        # Calculate contextual risk
        risk_score = calculate_risk_score(
            cvss_score=cvss_score,
            severity=severity,
            asset_criticality=asset.criticality,
            environment=asset.environment,
            internet_exposed=asset.internet_exposed
        )

        # Get detailed risk breakdown
        breakdown = get_risk_breakdown(
            cvss_score=cvss_score,
            severity=severity,
            asset_criticality=asset.criticality,
            environment=asset.environment,
            internet_exposed=asset.internet_exposed
        )

        # Convert risk score into remediation priority
        priority = get_priority(
            risk_score
        )

        # Create database finding
        finding = Finding(
            scan_id=scan_id,

            vulnerability_id=vulnerability_id,

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

            cvss_version=cvss_version,

            cvss_vector=cvss_vector,

            cwes=cwes,

            published=published,

            last_modified=last_modified,

            title=title,

            description=description,

            primary_url=primary_url,

            target=item.get(
                "target"
            ),

            status="open",

            risk_score=risk_score,

            priority=priority,

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

    db.commit()

    for finding in saved_findings:
        db.refresh(finding)

    return saved_findings