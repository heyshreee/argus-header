"""Tests for the deep HSTS analyzer."""

from argus_header.analyzers.hsts import analyze_hsts


def test_no_hsts_high_finding():
    findings = analyze_hsts({})

    assert len(findings) == 1
    assert findings[0]["id"] == "ARGUS-HSTS-001"
    assert findings[0]["severity"] == "HIGH"


def test_missing_max_age_high_finding():
    findings = analyze_hsts({"strict-transport-security": "includeSubDomains"})

    assert any(
        f["id"] == "ARGUS-HSTS-002" and f["severity"] == "HIGH" for f in findings
    )


def test_short_max_age_flagged():
    findings = analyze_hsts({"strict-transport-security": "max-age=60"})

    assert any(f["id"] == "ARGUS-HSTS-003" for f in findings)


def test_missing_include_subdomains_flagged():
    findings = analyze_hsts({"strict-transport-security": "max-age=63072000"})

    assert any(f["id"] == "ARGUS-HSTS-004" for f in findings)


def test_full_hsts_no_findings():
    findings = analyze_hsts(
        {"strict-transport-security": "max-age=63072000; includeSubDomains; preload"}
    )

    assert findings == []


def test_case_insensitive_directive_parsing():
    findings = analyze_hsts({"strict-transport-security": "MAX-AGE=100"})

    assert any(f["id"] == "ARGUS-HSTS-003" for f in findings)
