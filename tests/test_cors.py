"""Tests for the deep CORS analyzer."""

from argus_header.analyzers.cors import analyze_cors


def test_no_cors_headers_no_findings():
    findings = analyze_cors({})
    assert findings == []


def test_wildcard_origin_flagged():
    findings = analyze_cors({"access-control-allow-origin": "*"})
    assert any(f["id"] == "ARGUS-CORS-001" for f in findings)


def test_wildcard_with_credentials_is_high():
    findings = analyze_cors(
        {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
    )
    cors = [f for f in findings if f["id"] == "ARGUS-CORS-001"]
    assert cors and cors[0]["severity"] == "HIGH"


def test_wildcard_without_credentials_is_medium():
    findings = analyze_cors({"access-control-allow-origin": "*"})
    cors = [f for f in findings if f["id"] == "ARGUS-CORS-001"]
    assert cors and cors[0]["severity"] == "MEDIUM"


def test_credentials_with_explicit_origin_flagged():
    findings = analyze_cors(
        {
            "access-control-allow-origin": "https://evil.example",
            "access-control-allow-credentials": "true",
        }
    )
    assert any(f["id"] == "ARGUS-CORS-002" for f in findings)


def test_null_origin_blocked():
    findings = analyze_cors({"access-control-allow-origin": "null"})
    assert any(f["id"] == "ARGUS-CORS-004" for f in findings)


def test_trace_method_flagged():
    findings = analyze_cors(
        {
            "access-control-allow-origin": "https://trusted.example",
            "access-control-allow-methods": "GET, POST, TRACE",
        }
    )
    assert any(f["id"] == "ARGUS-CORS-005" for f in findings)


def test_references_present():
    findings = analyze_cors({"access-control-allow-origin": "*"})
    assert findings[0]["references"]
