from argus_header.scorer import (
    calculate_grade,
    calculate_risk_level,
    calculate_score,
)


def make_finding(issue, severity):
    return {"category": "Security", "issue": issue, "severity": severity}


def test_clean_site_scores_100():
    result = calculate_score([])

    assert result["score"] == 100
    assert result["grade"] == "A"
    assert result["risk_level"] == "LOW"
    assert result["penalty"] == 0
    assert result["total_findings"] == 0
    assert result["breakdown"] == {"HIGH": 0, "MEDIUM": 0, "LOW": 0}


def test_documented_example_scores_45():
    findings = [
        make_finding("Missing Content-Security-Policy", "HIGH"),
        make_finding("Missing Strict-Transport-Security", "HIGH"),
        make_finding("Missing X-Content-Type-Options", "MEDIUM"),
        make_finding("Server Header Leaked: cloudflare", "LOW"),
    ]

    result = calculate_score(findings)

    assert result["score"] == 45
    assert result["grade"] == "F"
    assert result["risk_level"] == "HIGH"
    assert result["penalty"] == 55
    assert result["breakdown"] == {"HIGH": 40, "MEDIUM": 10, "LOW": 5}
    assert result["total_findings"] == 4


def test_all_known_rules_total_penalty_is_93():
    findings = [
        make_finding("Missing Content-Security-Policy", "HIGH"),
        make_finding("Missing Strict-Transport-Security", "HIGH"),
        make_finding("Missing X-Frame-Options", "HIGH"),
        make_finding("Missing X-Content-Type-Options", "MEDIUM"),
        make_finding("X-Powered-By Leaked: Express", "MEDIUM"),
        make_finding("CORS Access-Control-Allow-Origin is '*'", "MEDIUM"),
        make_finding("Server Header Leaked: nginx/1.18.0", "LOW"),
        make_finding("Missing Cache-Control Header", "LOW"),
    ]

    result = calculate_score(findings)

    assert result["penalty"] == 93
    assert result["score"] == max(0, 100 - 93) == 7
    assert result["grade"] == "F"
    assert result["risk_level"] == "HIGH"
    assert result["breakdown"]["HIGH"] == 55
    assert result["breakdown"]["MEDIUM"] == 30
    assert result["breakdown"]["LOW"] == 8


def test_dynamic_leak_values_still_penalized():
    findings = [
        make_finding("X-Powered-By Leaked: PHP/8.2.1", "MEDIUM"),
        make_finding("Server Header Leaked: Apache/2.4.41", "LOW"),
    ]

    result = calculate_score(findings)

    assert result["penalty"] == 13
    assert result["score"] == 87


def test_unknown_issue_adds_no_penalty():
    findings = [make_finding("Some Future Finding", "LOW")]

    result = calculate_score(findings)

    assert result["penalty"] == 0
    assert result["score"] == 100


def test_penalty_floor_at_zero():
    findings = [make_finding("Missing Content-Security-Policy", "HIGH")] * 6

    result = calculate_score(findings)

    assert result["penalty"] == 120
    assert result["score"] == 0


def test_grade_boundaries():
    assert calculate_grade(100) == "A"
    assert calculate_grade(90) == "A"
    assert calculate_grade(89) == "B"
    assert calculate_grade(80) == "B"
    assert calculate_grade(79) == "C"
    assert calculate_grade(70) == "C"
    assert calculate_grade(69) == "D"
    assert calculate_grade(60) == "D"
    assert calculate_grade(59) == "F"
    assert calculate_grade(0) == "F"


def test_cookie_penalties_scored():
    findings = [
        {"category": "Cookie", "issue": "Cookie 'session' missing Secure flag", "severity": "MEDIUM"},
        {"category": "Cookie", "issue": "Cookie 'session' missing HttpOnly flag", "severity": "MEDIUM"},
        {"category": "Cookie", "issue": "Cookie 'auth' missing SameSite attribute", "severity": "LOW"},
    ]

    result = calculate_score(findings)

    assert result["penalty"] == 25
    assert result["score"] == 75
    assert result["grade"] == "C"
    assert result["risk_level"] == "MEDIUM"
    assert result["breakdown"] == {"HIGH": 0, "MEDIUM": 20, "LOW": 5}


def test_risk_levels():
    high = [{"issue": "x", "severity": "HIGH"}]
    medium = [{"issue": "x", "severity": "MEDIUM"}]
    low = [{"issue": "x", "severity": "LOW"}]

    assert calculate_risk_level(high) == "HIGH"
    assert calculate_risk_level(medium) == "MEDIUM"
    assert calculate_risk_level(low) == "LOW"
    assert calculate_risk_level([]) == "LOW"


def test_medium_only_site_keeps_high_score():
    findings = [
        make_finding("Missing X-Content-Type-Options", "MEDIUM"),
        make_finding("X-Powered-By Leaked: Next.js", "MEDIUM"),
    ]

    result = calculate_score(findings)

    assert result["score"] == 82
    assert result["grade"] == "B"
    assert result["risk_level"] == "MEDIUM"
