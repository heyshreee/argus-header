"""Tests for the deep cookie security analyzer."""

from argus_header.analyzers.cookies import analyze_cookies


def test_secure_cookie_no_findings():
    headers = {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Strict"}

    findings = analyze_cookies(headers)

    assert findings == []


def test_missing_secure_flagged():
    findings = analyze_cookies({"Set-Cookie": "session=abc"})

    assert any(f["id"] == "ARGUS-COOKIE-001" for f in findings)


def test_missing_httponly_flagged():
    findings = analyze_cookies({"Set-Cookie": "session=abc"})

    assert any(f["id"] == "ARGUS-COOKIE-002" for f in findings)


def test_session_cookie_missing_samesite_is_medium():
    findings = analyze_cookies({"Set-Cookie": "session=abc"})

    same = [f for f in findings if f["id"] == "ARGUS-COOKIE-003"]
    assert same and same[0]["severity"] == "MEDIUM"


def test_non_session_cookie_missing_samesite_is_low():
    findings = analyze_cookies({"Set-Cookie": "prefs=dark"})

    same = [f for f in findings if f["id"] == "ARGUS-COOKIE-004"]
    assert same and same[0]["severity"] == "LOW"


def test_host_prefix_with_domain_flagged():
    headers = {"Set-Cookie": "__Host-session=1; Domain=example.com; Path=/; Secure"}

    findings = analyze_cookies(headers)

    assert any(f["id"] == "ARGUS-COOKIE-007" for f in findings)


def test_samesite_none_without_secure_is_high():
    headers = {"Set-Cookie": "session=abc; SameSite=None"}

    findings = analyze_cookies(headers)

    assert any(
        f["id"] == "ARGUS-COOKIE-006" and f["severity"] == "HIGH" for f in findings
    )


def test_multiple_cookies_analyzed_independently():
    headers = {"set-cookie": "a=1; Secure; HttpOnly", "SET-COOKIE": "b=2"}

    findings = analyze_cookies(headers)

    names = {f.get("issue", "").split("'")[1] for f in findings}

    assert {"a", "b"} <= names


def test_strict_policy_accepted():
    headers = {
        "Set-Cookie": "sid=xyz; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600"
    }

    findings = analyze_cookies(headers)

    assert findings == []
