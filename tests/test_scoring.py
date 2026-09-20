"""Tests for Security Score Engine 2.0."""

from argus_header.engine.scoring import (
    calculate_grade_extended,
    calculate_score_2,
    classify_finding,
    max_severity,
)
from argus_header.models.report import ScoreData


def test_clean_scan_scores_100_aplus():
    result = calculate_score_2([])

    assert result.score == 100
    assert result.grade == "A+"
    assert result.risk_level == "LOW"
    assert result.total_findings == 0
    assert result.categories == {
        "Content": 25,
        "Transport": 20,
        "Browser": 25,
        "Isolation": 15,
        "Cookies": 15,
    }
    assert result.breakdown == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_category_scores_are_weighted():
    findings = [
        {"id": "ARGUS-CSP-001", "severity": "HIGH", "title": "x"},
        {"id": "ARGUS-COOKIE-001", "severity": "MEDIUM", "title": "y"},
    ]

    result = calculate_score_2(findings)

    # HIGH in Content deducts 7; MEDIUM in Cookies deducts 4.
    assert result.categories["Content"] == 25 - 7
    assert result.categories["Cookies"] == 15 - 4


def test_overall_is_sum_of_category_scores():
    findings = [
        {"id": "ARGUS-CSP-001", "severity": "HIGH", "title": "csp"},
        {"id": "ARGUS-HSTS-001", "severity": "HIGH", "title": "hsts"},
    ]

    result = calculate_score_2(findings)

    assert result.score == sum(result.categories.values())


def test_classification_high_csp_to_content():
    assert (
        classify_finding({"id": "ARGUS-CSP-001", "title": "Missing CSP"}) == "Content"
    )


def test_classification_cookie_to_cookies():
    assert classify_finding({"id": "ARGUS-COOKIE-001"}) == "Cookies"


def test_grade_extended_includes_aplus():
    assert calculate_grade_extended(100) == "A+"
    assert calculate_grade_extended(98) == "A+"
    assert calculate_grade_extended(97) == "A"
    assert calculate_grade_extended(90) == "A"
    assert calculate_grade_extended(80) == "B"
    assert calculate_grade_extended(70) == "C"
    assert calculate_grade_extended(60) == "D"
    assert calculate_grade_extended(0) == "F"


def test_breakdown_counts_severities():
    findings = [
        {"id": "a", "severity": "HIGH", "title": "h"},
        {"id": "b", "severity": "HIGH", "title": "h2"},
        {"id": "c", "severity": "MEDIUM", "title": "m"},
        {"id": "d", "severity": "LOW", "title": "l"},
    ]

    result = calculate_score_2(findings)

    assert result.breakdown["HIGH"] == 2
    assert result.breakdown["MEDIUM"] == 1
    assert result.breakdown["LOW"] == 1


def test_risk_level_from_count_findings():
    findings = [{"id": "x", "severity": "CRITICAL", "title": "c"}]
    result = calculate_score_2(findings)
    assert result.risk_level == "CRITICAL"


def test_max_severity():
    assert max_severity([]) == "LOW"
    assert max_severity([{"severity": "MEDIUM"}]) == "MEDIUM"
    assert max_severity([{"severity": "LOW"}, {"severity": "HIGH"}]) == "HIGH"


def test_unknown_severity_treated_as_low():
    result = calculate_score_2([{"id": "x", "severity": "WEIRD", "title": "w"}])
    assert result.breakdown["LOW"] == 1


def test_score_data_dict_roundtrip():
    data = ScoreData(
        score=88, grade="B", risk_level="MEDIUM", penalty=12, total_findings=3
    )
    restored = ScoreData.from_dict(data.to_dict())
    assert restored.score == 88
    assert restored.grade == "B"
