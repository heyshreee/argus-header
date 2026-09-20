"""Tests for cache, cross-origin, referrer, permissions and base-header
analyzers."""

from argus_header.analyzers.base_headers import analyze_base_headers
from argus_header.analyzers.cache import analyze_cache
from argus_header.analyzers.cross_origin import analyze_cross_origin
from argus_header.analyzers.permissions import analyze_permissions
from argus_header.analyzers.referrer import analyze_referrer


def test_missing_cache_control_flagged():
    findings = analyze_cache({})
    assert any(f["id"] == "ARGUS-CACHE-001" for f in findings)


def test_no_store_clean():
    findings = analyze_cache({"cache-control": "no-store, max-age=0"})
    assert "ARGUS-CACHE-002" not in [f["id"] for f in findings]


def test_public_without_safety_flagged():
    findings = analyze_cache({"cache-control": "public, max-age=31536000"})
    assert any(f["id"] == "ARGUS-CACHE-003" for f in findings)


def test_missing_coop_flagged():
    findings = analyze_cross_origin({})
    ids = {f["id"] for f in findings}
    assert {"ARGUS-COOP-001", "ARGUS-COEP-001", "ARGUS-CORP-001"} <= ids


def test_weak_coop_value_flagged():
    findings = analyze_cross_origin({"cross-origin-opener-policy": "unsafe-none"})
    assert any(f["id"] == "ARGUS-COOP-002" for f in findings)


def test_full_isolation_clean():
    headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-origin",
    }
    findings = analyze_cross_origin(headers)
    assert findings == []


def test_missing_referrer_flagged():
    findings = analyze_referrer({})
    assert any(f["id"] == "ARGUS-REFERRER-001" for f in findings)


def test_leaky_referrer_policy_flagged():
    findings = analyze_referrer({"referrer-policy": "unsafe-url"})
    assert any(f["id"] == "ARGUS-REFERRER-003" for f in findings)


def test_secure_referrer_policy_clean():
    findings = analyze_referrer({"referrer-policy": "strict-origin-when-cross-origin"})
    assert findings == []


def test_missing_permissions_flagged():
    findings = analyze_permissions({})
    assert any(f["id"] == "ARGUS-PERMISSIONS-001" for f in findings)


def test_permissive_permissions_flagged():
    findings = analyze_permissions(
        {"permissions-policy": "geolocation=*, camera=*, microphone=*, payment=*"}
    )
    assert any(f["id"] == "ARGUS-PERMISSIONS-003" for f in findings)


def test_missing_xcto_flagged():
    findings = analyze_base_headers({})
    ids = {f["id"] for f in findings}
    assert "ARGUS-XCTO-001" in ids


def test_server_leak_detected():
    findings = analyze_base_headers({"server": "nginx/1.18"})
    assert any(f["id"] == "ARGUS-SERVER-001" for f in findings)


def test_proper_xfo_clean():
    findings = analyze_base_headers(
        {"x-frame-options": "DENY", "x-content-type-options": "nosniff"}
    )
    assert "ARGUS-XFO-001" not in [f["id"] for f in findings]
    assert "ARGUS-XCTO-001" not in [f["id"] for f in findings]
