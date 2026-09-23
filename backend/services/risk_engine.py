def calculate_risk_score(
    cvss_score: float | None,
    severity: str | None
):
    """
    Calculate Inspectra's initial risk score.

    The score is based on CVSS when available.
    Severity is used as a fallback.
    """

    if cvss_score is not None:
        score = float(cvss_score)

    else:
        severity_scores = {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "UNKNOWN": 0.0
        }

        score = severity_scores.get(
            (severity or "UNKNOWN").upper(),
            0.0
        )

    # Keep the score within 0–10
    score = max(0.0, min(score, 10.0))

    return round(score, 2)


def get_priority(risk_score: float):
    """
    Convert the risk score into a remediation priority.
    """

    if risk_score >= 9.0:
        return "P0"

    if risk_score >= 7.0:
        return "P1"

    if risk_score >= 4.0:
        return "P2"

    if risk_score > 0:
        return "P3"

    return "P4"