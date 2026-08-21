from argus_header.analyzer import analyze_headers

def test_analyzer_missing_security_headers():
    response_data = {
        "success": True,
        "headers": {},
        "status_code": 200,
        "url": "https://example.com"
    }

    findings = analyze_headers(response_data)

    # Must detect missing CSP
    assert any(f["issue"] == "Missing Content-Security-Policy" for f in findings)

    # Must detect missing HSTS
    assert any(f["issue"] == "Missing Strict-Transport-Security" for f in findings)


def test_analyzer_detects_server_leak():
    response_data = {
        "success": True,
        "headers": {
            "Server": "nginx/1.18.0"
        },
        "status_code": 200,
        "url": "https://example.com"
    }

    findings = analyze_headers(response_data)

    assert any("Server Header Leaked" in f["issue"] for f in findings)
