import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_cve_details(cve_id: str):
    """
    Fetch vulnerability intelligence for a CVE from the
    National Vulnerability Database (NVD).
    """

    if not cve_id:
        return None

    response = requests.get(
        NVD_API_URL,
        params={
            "cveId": cve_id
        },
        timeout=15
    )

    response.raise_for_status()

    data = response.json()

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get(
        "cve",
        {}
    )

    # ---------------------------------------------------------
    # Description
    # ---------------------------------------------------------

    description = None

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value")
            break

    # ---------------------------------------------------------
    # CVSS information
    # ---------------------------------------------------------

    cvss_score = None
    cvss_version = None
    cvss_vector = None
    severity = None

    metrics = cve.get("metrics", {})

    # Prefer CVSS v3.1
    if metrics.get("cvssMetricV31"):
        metric = metrics["cvssMetricV31"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_version = "3.1"

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # Fall back to CVSS v3.0
    elif metrics.get("cvssMetricV30"):
        metric = metrics["cvssMetricV30"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_version = "3.0"

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # Fall back to CVSS v4
    elif metrics.get("cvssMetricV40"):
        metric = metrics["cvssMetricV40"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        cvss_version = "4.0"

        cvss_vector = cvss_data.get(
            "vectorString"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

    # ---------------------------------------------------------
    # CWE information
    # ---------------------------------------------------------

    cwes = []

    for weakness in cve.get(
        "weaknesses",
        []
    ):
        for description_item in weakness.get(
            "description",
            []
        ):
            value = description_item.get(
                "value"
            )

            if value and value not in cwes:
                cwes.append(value)

    # ---------------------------------------------------------
    # References
    # ---------------------------------------------------------

    references = []

    for reference in cve.get(
        "references",
        []
    ):
        url = reference.get("url")

        if url:
            references.append(url)

    # ---------------------------------------------------------
    # Return normalized intelligence
    # ---------------------------------------------------------

    return {
        "cve_id": cve.get(
            "id",
            cve_id
        ),
        "description": description,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwes": cwes,
        "references": references,
        "published": cve.get(
            "published"
        ),
        "last_modified": cve.get(
            "lastModified"
        )
    }