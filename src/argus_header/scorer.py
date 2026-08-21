"""Security scoring engine for Argus Header.

Converts analyzer findings into a 0-100 security score, letter grade,
risk level and severity breakdown. The analyzer remains the single
source of truth for detection; this module only applies penalties.
"""


PENALTIES = {
    "Missing Content-Security-Policy": 20,
    "Missing Strict-Transport-Security": 20,
    "Missing X-Frame-Options": 15,
    "Missing X-Content-Type-Options": 10,
    "CORS Access-Control-Allow-Origin is '*'": 12,
    "Missing Cache-Control Header": 3,
}

PENALTY_PREFIXES = [
    ("X-Powered-By Leaked:", 8),
    ("Server Header Leaked:", 5),
]

PENALTY_SUBSTRINGS = [
    ("missing Secure flag", 10),
    ("missing HttpOnly flag", 10),
    ("missing SameSite attribute", 5),
]


def calculate_score(findings: list[dict]) -> dict:
    """Calculate a 0-100 security score from analyzer findings."""

    penalty = 0
    breakdown = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        issue = finding.get("issue", "")
        severity = finding.get("severity", "LOW")

        penalty_value = _lookup_penalty(issue)

        penalty += penalty_value

        if severity in breakdown:
            breakdown[severity] += penalty_value

    score = max(0, 100 - penalty)

    grade = calculate_grade(score)
    risk_level = calculate_risk_level(findings)

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "total_findings": len(findings),
        "penalty": penalty,
        "breakdown": breakdown,
    }


def calculate_grade(score: int) -> str:
    """Convert a security score into a letter grade."""

    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_risk_level(findings: list[dict]) -> str:
    """Determine overall risk from finding severities."""

    severities = {finding.get("severity") for finding in findings}

    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def _lookup_penalty(issue: str) -> int:
    """Resolve the penalty for an issue string.

    Matching order: exact key, then known prefix (dynamic leak values),
    then substring (cookie findings embed the cookie name).
    """

    if issue in PENALTIES:
        return PENALTIES[issue]

    for prefix, penalty in PENALTY_PREFIXES:
        if issue.startswith(prefix):
            return penalty

    for fragment, penalty in PENALTY_SUBSTRINGS:
        if fragment in issue:
            return penalty

    return 0
