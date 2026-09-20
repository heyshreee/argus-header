"""Security Score Engine 2.0 for Argus Header.

In contrast to the v0.7 scorer (a flat penalty table), this module
produces a weighted, category-aware score:

    Overall       78/100   [B]
    Content       18/25
    Transport     20/20
    Browser       16/25
    Isolation     10/15
    Cookies        8/15

Each finding is classified into a security category with a fixed point
budget (the weight). Severity-based deductions are applied within each
category. The overall score is the sum of the surviving category scores,
and a grade from A+ down to F is derived from that total.

The v0.7 penalty-based scoring remains available through the legacy
functions at :mod:`argus_header.scorer` for backward compatibility.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from argus_header.models.report import CATEGORIES, ScoreData

# Fixed per-category point budgets. These act as the category weights and
# always sum to 100.
CATEGORY_MAX = {
    "Content": 25,
    "Transport": 20,
    "Browser": 25,
    "Isolation": 15,
    "Cookies": 15,
}

# Severity -> per-finding points deducted from the category budget.
SEVERITY_DEDUCTION = {
    "CRITICAL": 9,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}

# Order used for prioritised severity triage.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Risk/gate thresholds used by CI/CD mode.
SEVERITY_THRESHOLD = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

# Grade thresholds, A+ through F.
GRADE_THRESHOLDS = [
    (98, "A+"),
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


def classify_finding(finding: Mapping[str, Any]) -> str:
    """Map a finding onto one of the five scoring categories.

    Classification is based on the stable rule ``id`` when available and
    falls back to inspecting the title/category text.
    """
    fid = str(finding.get("id", "")).upper()
    title = (
        str(finding.get("title", "")) + " " + str(finding.get("issue", ""))
    ).lower()
    category = str(finding.get("category", "")).lower()

    if (
        fid.startswith("ARGUS-CSP")
        or "content-security-policy" in title
        or "csp" in category
    ):
        return "Content"
    if fid.startswith("ARGUS-HSTS") or "hsts" in title or "strict-transport" in title:
        return "Transport"
    if fid.startswith("ARGUS-CORS") or "cors" in category or "access-control" in title:
        return "Content"
    if fid.startswith("ARGUS-COOKIE") or "cookie" in category or "cookie" in title:
        return "Cookies"
    if fid.startswith(("ARGUS-COOP", "ARGUS-CORP", "ARGUS-COEP")):
        return "Isolation"
    if fid.startswith("ARGUS-XFO") or "frame" in title or "clickjack" in title:
        return "Browser"
    if fid.startswith("ARGUS-REFERRER") or "referrer" in title:
        return "Browser"
    if fid.startswith("ARGUS-PERMISSIONS") or "permissions" in title:
        return "Browser"
    if fid.startswith("ARGUS-XCTO") or "content-type" in title or "mime" in title:
        return "Browser"
    if fid.startswith("ARGUS-CACHE") or "cache" in title:
        return "Content"
    if "server leak" in title or "powered-by" in title or "leak" in category:
        return "Isolation"

    # Legacy v0.7 style categories that appear in existing findings.
    if category == "security":
        return "Content"
    if category == "cookie":
        return "Cookies"
    if category == "cors":
        return "Content"
    if category == "leakage":
        return "Isolation"
    if category == "performance":
        return "Content"

    return "Content"


def _normalize_severity(severity: str) -> str:
    severity = str(severity).upper()
    if severity not in SEVERITY_ORDER:
        return "LOW"
    return severity


def _severity_of(finding: Mapping[str, Any]) -> str:
    return _normalize_severity(finding.get("severity", "LOW"))


def _deduction_points(severity: str) -> int:
    return SEVERITY_DEDUCTION.get(
        _normalize_severity(severity), SEVERITY_DEDUCTION["LOW"]
    )


def calculate_score_2(findings: list[dict[str, Any]]) -> ScoreData:
    """Compute a category-aware, weighted score from structured findings.

    Accepts finding dictionaries produced by :mod:`argus_header.engine`
    analyzers (or any mapping with ``severity`` present). Returns a
    :class:`~argus_header.models.report.ScoreData` carrying the aggregate
    score, category breakdown and severity deduction summary.
    """
    deductions: dict[str, int] = {category: 0 for category in CATEGORIES}
    counts: dict[str, int] = {
        severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    max_severity = "LOW"

    for finding in findings:
        severity = _severity_of(finding)
        counts[severity] = counts.get(severity, 0) + 1
        if SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(max_severity):
            max_severity = severity

        category = classify_finding(finding)
        deductions[category] += _deduction_points(severity)

    category_scores: dict[str, int] = {}
    total = 0
    for category in CATEGORIES:
        budget = CATEGORY_MAX[category]
        cat_score = max(0, budget - deductions[category])
        category_scores[category] = cat_score
        total += cat_score

    grade = calculate_grade_extended(total)
    risk = calculate_risk_level_from_counts(counts)

    return ScoreData(
        score=total,
        grade=grade,
        risk_level=risk,
        penalty=total_deduction(deductions),
        total_findings=len(findings),
        categories=category_scores,
        max_per_category=max(CATEGORY_MAX.values()),
        breakdown=counts,
        weights=dict(CATEGORY_MAX),
    )


def total_deduction(deductions: Mapping[str, int]) -> int:
    """Return the aggregate point penalty across all categories."""
    return sum(deductions.values())


def calculate_grade_extended(score: int) -> str:
    """Convert a security score into a letter grade from A+ down to F."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def calculate_risk_level_from_counts(
    counts: Mapping[str, int],
) -> str:
    """Determine overall risk from a severity counts mapping."""
    for severity in SEVERITY_ORDER:
        if counts.get(severity, 0):
            return severity
    return "LOW"


def max_severity(findings: list[dict[str, Any]]) -> str:
    """Return the most severe finding level present, or LOW when empty."""
    worst = "LOW"
    for finding in findings:
        sev = _severity_of(finding)
        if SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(worst):
            worst = sev
    return worst
