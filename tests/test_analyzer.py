from argus_header.analyzer import analyze_headers


def test_analyzer_missing_security_headers():
    response_data = {
        "success": True,
        "headers": {},
        "status_code": 200,
        "url": "https://example.com",
    }

    findings = analyze_headers(response_data)

    # Must detect missing CSP
    assert any(f["issue"] == "Missing Content-Security-Policy" for f in findings)

    # Must detect missing HSTS
    assert any(f["issue"] == "Missing Strict-Transport-Security" for f in findings)


def test_analyzer_detects_server_leak():
    response_data = {
        "success": True,
        "headers": {"Server": "nginx/1.18.0"},
        "status_code": 200,
        "url": "https://example.com",
    }

    findings = analyze_headers(response_data)

    assert any("Server Header Leaked" in f["issue"] for f in findings)


def test_findings_have_stable_ids():
    response_data = {
        "success": True,
        "headers": {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "Express",
            "Access-Control-Allow-Origin": "*",
        },
        "status_code": 200,
        "url": "https://example.com",
    }

    findings = analyze_headers(response_data)

    ids = {f["id"] for f in findings}

    assert {
        "SEC-001",
        "SEC-002",
        "SEC-003",
        "SEC-004",
        "LEAK-001",
        "LEAK-002",
        "CORS-001",
        "PERF-001",
    } <= ids
