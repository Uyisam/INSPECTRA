def calculate_risk_score(
    cvss_score: float | None,
    severity: str | None,
    asset_criticality: str = "medium",
    environment: str = "development",
    internet_exposed: bool = False
):
    """
    Calculate a contextual vulnerability risk score.

    The score considers:
    - CVSS / severity
    - Asset criticality
    - Environment
    - Internet exposure
    """

    # ---------------------------------------------------------
    # 1. Determine the base score
    # ---------------------------------------------------------

    if cvss_score is not None:
        base_score = float(cvss_score)
    else:
        severity_scores = {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "UNKNOWN": 0.0
        }

        base_score = severity_scores.get(
            (severity or "UNKNOWN").upper(),
            0.0
        )

    base_score = max(0.0, min(base_score, 10.0))

    # ---------------------------------------------------------
    # 2. Asset criticality adjustment
    # ---------------------------------------------------------

    criticality_adjustments = {
        "critical": 1.0,
        "high": 0.6,
        "medium": 0.3,
        "low": 0.0
    }

    criticality_adjustment = criticality_adjustments.get(
        (asset_criticality or "medium").lower(),
        0.3
    )

    # ---------------------------------------------------------
    # 3. Environment adjustment
    # ---------------------------------------------------------

    environment_adjustments = {
        "production": 0.8,
        "staging": 0.4,
        "development": 0.0,
        "testing": 0.0
    }

    environment_adjustment = environment_adjustments.get(
        (environment or "development").lower(),
        0.0
    )

    # ---------------------------------------------------------
    # 4. Internet exposure adjustment
    # ---------------------------------------------------------

    exposure_adjustment = 1.0 if internet_exposed else 0.0

    # ---------------------------------------------------------
    # 5. Calculate final score
    # ---------------------------------------------------------

    risk_score = (
        base_score
        + criticality_adjustment
        + environment_adjustment
        + exposure_adjustment
    )

    risk_score = max(
        0.0,
        min(risk_score, 10.0)
    )

    return round(risk_score, 2)

def get_risk_breakdown(
    cvss_score: float | None,
    severity: str | None,
    asset_criticality: str = "medium",
    environment: str = "development",
    internet_exposed: bool = False
):
    """
    Return the individual factors used to calculate risk.
    """

    if cvss_score is not None:
        base_score = float(cvss_score)
    else:
        severity_scores = {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "UNKNOWN": 0.0
        }

        base_score = severity_scores.get(
            (severity or "UNKNOWN").upper(),
            0.0
        )

    base_score = max(0.0, min(base_score, 10.0))

    criticality_adjustments = {
        "critical": 1.0,
        "high": 0.6,
        "medium": 0.3,
        "low": 0.0
    }

    criticality_adjustment = criticality_adjustments.get(
        (asset_criticality or "medium").lower(),
        0.3
    )

    environment_adjustments = {
        "production": 0.8,
        "staging": 0.4,
        "development": 0.0,
        "testing": 0.0
    }

    environment_adjustment = environment_adjustments.get(
        (environment or "development").lower(),
        0.0
    )

    exposure_adjustment = 1.0 if internet_exposed else 0.0

    raw_score = (
        base_score
        + criticality_adjustment
        + environment_adjustment
        + exposure_adjustment
    )

    final_score = max(
        0.0,
        min(raw_score, 10.0)
    )

    return {
        "base_cvss": round(base_score, 2),
        "criticality_adjustment": criticality_adjustment,
        "environment_adjustment": environment_adjustment,
        "internet_exposure_adjustment": exposure_adjustment,
        "raw_score": round(raw_score, 2),
        "final_score": round(final_score, 2)
    }


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