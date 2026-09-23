def extract_cvss_score(vulnerability: dict):
    """
    Extract the CVSS score from Trivy vulnerability data.
    Trivy can provide CVSS information from different sources.
    """

    cvss_data = vulnerability.get("CVSS") or {}

    scores = []

    for source_data in cvss_data.values():
        if not isinstance(source_data, dict):
            continue

        score = source_data.get("V3Score")

        if score is None:
            score = source_data.get("V2Score")

        if score is not None:
            try:
                scores.append(float(score))
            except (TypeError, ValueError):
                pass

    if scores:
        return max(scores)

    return None


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