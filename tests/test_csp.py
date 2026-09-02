"""Tests for the deep Content-Security-Policy analyzer."""

from argus_header.analyzers.csp import _directives, analyze_csp


def test_missing_csp_is_high_finding():
    findings = analyze_csp({})

    assert len(findings) == 1
    f = findings[0]
    assert f["id"] == "ARGUS-CSP-001"
    assert f["severity"] == "HIGH"
    assert "Content Security Policy" in f["title"]


def test_weak_csp_wildcard_default_src():
    findings = analyze_csp({"content-security-policy": "default-src *"})

    ids = [f["id"] for f in findings]

    assert "ARGUS-CSP-102" in ids  # wildcard in default-src


def test_weak_csp_unsafe_inline():
    findings = analyze_csp(
        {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"}
    )

    ids = [f["id"] for f in findings]

    assert "ARGUS-CSP-004" in ids  # unsafe-inline in script-src


def test_missing_default_src_flagged():
    findings = analyze_csp({"content-security-policy": "script-src 'self'"})

    assert any(f["id"] == "ARGUS-CSP-101" for f in findings)


def test_directives_parsing():
    policy = "default-src 'self'; script-src 'self' https://cdn.example.com"

    directives = _directives(policy)

    assert directives["default-src"] == "'self'"
    assert directives["script-src"] == "'self' https://cdn.example.com"


def test_strict_csp_produces_no_warnings():
    policy = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )

    findings = analyze_csp({"content-security-policy": policy})

    # No dangerous-source or missing-frame-ancestors findings.
    assert all(
        f["id"] not in {"ARGUS-CSP-102", "ARGUS-CSP-003", "ARGUS-CSP-201"}
        for f in findings
    )


def test_report_only_policy_is_considered():
    findings = analyze_csp(
        {"content-security-policy-report-only": "default-src 'self'"}
    )

    assert findings  # a weak report-only policy still gets analysed


def test_evidence_included_in_findings():
    findings = analyze_csp({"content-security-policy": "default-src *"})

    assert any("default-src *" in f.get("evidence", "") for f in findings)
