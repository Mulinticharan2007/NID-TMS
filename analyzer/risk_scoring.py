def calculate_risk_score(
    severity: str,
    alert_type: str,
    description: str,
) -> int:
    """Calculate an explainable individual alert risk score."""

    severity_value = str(severity or "").upper()
    type_value = str(alert_type or "").upper()
    description_value = str(description or "").lower()

    # Known test alerts are not treated as real threats.
    if type_value == "TEST" or "test" in description_value:
        return 0

    base_scores = {
        "LOW": 25,
        "MEDIUM": 50,
        "HIGH": 75,
        "CRITICAL": 90,
    }

    score = base_scores.get(severity_value, 20)

    if "port scan" in description_value or "port scan" in type_value.lower():
        score += 10

    if (
        "syn" in description_value
        and any(word in description_value for word in ("attempt", "flood", "anomaly"))
    ):
        score += 10

    if "brute force" in description_value:
        score += 15

    if "malware" in description_value:
        score += 15

    return min(score, 100)
