
import math


def extract_cvss_score(vulnerability: dict):
    """
    Extract the highest valid CVSS score from Trivy data.

    Supports CVSS 4.0, 3.x and 2.0.
    """

    cvss_data = vulnerability.get("CVSS") or {}

    scores = []

    for source_data in cvss_data.values():
        if not isinstance(source_data, dict):
            continue

        # Prefer the newest CVSS version available from this source.
        score = (
            source_data.get("V4Score")
            or source_data.get("V3Score")
            or source_data.get("V2Score")
        )

        if score is None:
            continue

        try:
            score = float(score)

            if math.isfinite(score) and 0.0 <= score <= 10.0:
                scores.append(score)

        except (TypeError, ValueError):
            continue

    return max(scores) if scores else None


def parse_trivy_findings(scan_results: dict):
    """
    Convert Trivy JSON results into Inspectra findings.
    """

    findings = []

    for result in scan_results.get("Results", []):

        target = result.get("Target", "")

        vulnerabilities = result.get("Vulnerabilities") or []

        for vulnerability in vulnerabilities:

            finding = {
                "vulnerability_id": vulnerability.get(
                    "VulnerabilityID"
                ),

                "package_name": vulnerability.get(
                    "PkgName"
                ),

                "installed_version": vulnerability.get(
                    "InstalledVersion"
                ),

                "fixed_version": vulnerability.get(
                    "FixedVersion"
                ),

                "severity": vulnerability.get(
                    "Severity"
                ),

                "cvss_score": extract_cvss_score(
                    vulnerability
                ),

                "title": vulnerability.get(
                    "Title"
                ),

                "description": vulnerability.get(
                    "Description"
                ),

                "primary_url": vulnerability.get(
                    "PrimaryURL"
                ),

                "target": target
            }

            findings.append(finding)

    return findings
