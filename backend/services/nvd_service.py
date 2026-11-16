
import logging
import time

import requests


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_RETRIES = 3
BASE_RETRY_DELAY = 2

logger = logging.getLogger(__name__)


def _fetch_nvd_response(cve_id: str):
    """Fetch NVD data with retries for temporary API failures."""

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                timeout=15
            )

            if response.status_code == 200:
                return response

            retryable = (
                response.status_code in (403, 429)
                or response.status_code >= 500
            )

            if not retryable:
                logger.warning(
                    "NVD returned HTTP %s for %s",
                    response.status_code,
                    cve_id
                )
                return None

            if attempt == MAX_RETRIES - 1:
                logger.error(
                    "NVD request failed after %s attempts for %s (HTTP %s)",
                    MAX_RETRIES,
                    cve_id,
                    response.status_code
                )
                return None

            retry_after = response.headers.get("Retry-After")

            try:
                delay = float(retry_after)
            except (TypeError, ValueError):
                delay = BASE_RETRY_DELAY * (2 ** attempt)

            delay = max(0, min(delay, 30))

            logger.warning(
                "NVD returned HTTP %s. Retrying in %s seconds.",
                response.status_code,
                delay
            )

            time.sleep(delay)

        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt == MAX_RETRIES - 1:
                logger.error(
                    "NVD connection failed for %s: %s",
                    cve_id,
                    exc
                )
                return None

            delay = BASE_RETRY_DELAY * (2 ** attempt)

            logger.warning(
                "NVD connection error. Retrying in %s seconds.",
                delay
            )

            time.sleep(delay)

        except requests.RequestException as exc:
            logger.error(
                "NVD request error for %s: %s",
                cve_id,
                exc
            )
            return None

    return None


def get_cve_details(cve_id: str):
    """
    Fetch vulnerability intelligence from NVD.

    Returns normalized CVE information or None when
    the information is unavailable.
    """

    if not cve_id or not isinstance(cve_id, str):
        return None

    response = _fetch_nvd_response(cve_id.strip())

    if response is None:
        return None

    try:
        data = response.json()
    except ValueError:
        logger.error("NVD returned invalid JSON for %s", cve_id)
        return None

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve", {})

    # Description
    description = None

    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value")
            break

    # CVSS information
    cvss_score = None
    cvss_version = None
    cvss_vector = None
    severity = None

    metrics = cve.get("metrics", {})

    metric_versions = [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV40", "4.0")
    ]

    for metric_name, version in metric_versions:
        metric_list = metrics.get(metric_name, [])

        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData", {})

        cvss_score = cvss_data.get("baseScore")
        cvss_version = version
        cvss_vector = cvss_data.get("vectorString")
        severity = (
            cvss_data.get("baseSeverity")
            or metric.get("baseSeverity")
        )

        break

    # CWE information
    cwes = []

    for weakness in cve.get("weaknesses", []):
        for description_item in weakness.get("description", []):
            value = description_item.get("value")

            if value and value not in cwes:
                cwes.append(value)

    # References
    references = []

    for reference in cve.get("references", []):
        url = reference.get("url")

        if url:
            references.append(url)

    # Normalized intelligence
    return {
        "cve_id": cve.get("id", cve_id),
        "description": description,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwes": cwes,
        "references": references,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified")
    }
