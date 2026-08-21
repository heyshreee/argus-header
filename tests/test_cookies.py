from argus_header.cookies import analyze_cookies


def test_secure_cookie():
    headers = {
        "Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Lax"
    }

    findings = analyze_cookies(headers)

    assert findings == []


def test_missing_secure():
    headers = {
        "Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax"
    }

    findings = analyze_cookies(headers)

    assert len(findings) == 1
    assert "Secure" in findings[0]["issue"]
    assert findings[0]["severity"] == "MEDIUM"


def test_missing_httponly():
    headers = {
        "Set-Cookie": "session=abc123; Secure; SameSite=Lax"
    }

    findings = analyze_cookies(headers)

    assert len(findings) == 1
    assert "HttpOnly" in findings[0]["issue"]
    assert findings[0]["severity"] == "MEDIUM"


def test_missing_samesite():
    headers = {
        "Set-Cookie": "session=abc123; Secure; HttpOnly"
    }

    findings = analyze_cookies(headers)

    assert len(findings) == 1
    assert "SameSite" in findings[0]["issue"]
    assert findings[0]["severity"] == "LOW"


def test_missing_all_attributes():
    headers = {
        "Set-Cookie": "session=abc123"
    }

    findings = analyze_cookies(headers)

    assert len(findings) == 3


def test_no_cookie():
    headers = {
        "Content-Type": "text/html"
    }

    findings = analyze_cookies(headers)

    assert findings == []


def test_multiple_cookies_each_analyzed():
    headers = {
        "set-cookie": "a=1; Secure; HttpOnly",
        "SET-COOKIE": "b=2; SameSite=Strict",
    }

    findings = analyze_cookies(headers)

    issues = [f["issue"] for f in findings]

    assert any("'a' missing SameSite" in i for i in issues)
    assert any("'b' missing Secure" in i for i in issues)
    assert any("'b' missing HttpOnly" in i for i in issues)


def test_cookie_findings_use_stable_ids():
    headers = {"Set-Cookie": "session=abc123"}

    findings = analyze_cookies(headers)

    ids = sorted(f["id"] for f in findings)

    assert ids == ["COOKIE-001", "COOKIE-002", "COOKIE-003"]
