"""Security reference database for Argus Header findings.

References are tied to specific rule categories rather than dumped
generically, so each finding points toward authoritative documentation
about the exact misconfiguration it describes.
"""

from __future__ import annotations

REFERENCES: dict[str, list[str]] = {
    "csp": [
        "https://owasp.org/www-community/controls/Content_Security_Policy",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        "https://csp.withgoogle.com/",
    ],
    "hsts": [
        "https://owasp.org/www-project-secure-headers/#div-strict-transport-security",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ],
    "xfo": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "https://owasp.org/www-project-secure-headers/#div-x-frame-options",
    ],
    "xcto": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        "https://owasp.org/www-project-secure-headers/#div-x-content-type-options",
    ],
    "cors": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "https://owasp.org/www-project-secure-headers/#div-cross-origin-resource-sharing-cors",
    ],
    "cookies": [
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
    ],
    "cache": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_for_HTTP_Methods",
    ],
    "referrer": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ],
    "permissions": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ],
    "cross_origin": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
    ],
    "server_leak": [
        "https://owasp.org/www-project-secure-headers/#div-server-header",
    ],
    "x_powered_by": [
        "https://owasp.org/www-community/attacks/Information_exposure_through_query_strings_in_url",
    ],
}


def references_for(category: str) -> list[str]:
    """Return the reference URLs that apply to a finding category."""
    alias = {
        "security": "csp",
        "cookie": "cookies",
        "leakage": "server_leak",
        "performance": "cache",
    }
    resolved = alias.get(category.lower(), category.lower())
    return list(REFERENCES.get(resolved, []))
