"""Cookie security analyzer.

Analyzes every Set-Cookie header and its attributes (Secure, HttpOnly,
SameSite, Domain, Path, Expires, Max-Age, __Host- and __Secure- prefixes)
for security-relevant weaknesses.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from argus_header.engine.findings import make_finding
from argus_header.engine.references import references_for

# Match the cookie name up to the first '=' (or the whole token if no '=').
_NAME_RE = re.compile(r"^\s*([^=;]+)")

SESSION_COOKIE_NAMES = (
    "session",
    "sessionid",
    "sid",
    "phpsessid",
    "auth",
    "token",
    "jwt",
)


def _parse_cookie_header(header_value: str) -> tuple[str, dict[str, str]]:
    """Split a Set-Cookie value into its name and attribute mapping."""
    if ";" in header_value:
        first, _, rest = header_value.partition(";")
    else:
        first, rest = header_value, ""

    name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
    attributes: dict[str, str] = {}
    for part in rest.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            key, _, value = part.partition("=")
            attributes[key.strip().lower()] = value.strip()
        else:
            attributes[part.lower()] = ""
    return name, attributes


def analyze_cookies(headers: Mapping[str, str]) -> list[dict]:
    """Analyze all Set-Cookie headers and return finding dicts."""
    findings: list[dict] = []

    cookie_headers = [(k, v) for k, v in headers.items() if k.lower() == "set-cookie"]

    for key, value in cookie_headers:
        name, attrs = _parse_cookie_header(value)
        findings.extend(_analyze_single(name, attrs, value))

    return findings


def _analyze_single(name: str, attrs: dict[str, str], raw: str) -> list[dict]:
    findings: list[dict] = []
    is_session = _is_session_cookie(name)

    if "secure" not in attrs:
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-001",
                "Cookie missing Secure attribute",
                name,
                "MEDIUM",
                "The cookie is transmitted over plaintext HTTP as well as HTTPS.",
                "Add the Secure attribute so the cookie is only sent over HTTPS.",
            )
        )

    if "httponly" not in attrs:
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-002",
                "Cookie missing HttpOnly attribute",
                name,
                "MEDIUM",
                "Client-side JavaScript can read the cookie, amplifying XSS.",
                "Add the HttpOnly attribute to block script access.",
            )
        )

    if is_session and "samesite" not in attrs:
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-003",
                "Session cookie missing SameSite attribute",
                name,
                "MEDIUM",
                "Session cookies are sent on cross-site requests by default.",
                "Set SameSite=Lax or SameSite=Strict on session cookies.",
            )
        )
    elif "samesite" not in attrs:
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-004",
                "Cookie missing SameSite attribute",
                name,
                "LOW",
                "Cross-site requests are not restricted by SameSite.",
                "Set an explicit SameSite policy to mitigate CSRF.",
            )
        )
    elif attrs.get("samesite", "").lower() not in ("lax", "strict"):
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-005",
                "Cookie SameSite policy is weak",
                name,
                "LOW",
                "SameSite=None permits cross-site usage with third-party cookies.",
                "Use SameSite=Lax or SameSite=Strict unless third-party access is required.",
            )
        )

    if (
        "samesite" in attrs
        and attrs.get("samesite", "").lower() == "none"
        and "secure" not in attrs
    ):
        findings.append(
            cookie_finding(
                "ARGUS-COOKIE-006",
                "SameSite=None without Secure attribute",
                name,
                "HIGH",
                "SameSite=None cookies are rejected over HTTPS unless Secure is set.",
                "Add the Secure attribute when using SameSite=None.",
            )
        )

    if _has_host_prefix(name):
        if "domain" in attrs:
            findings.append(
                cookie_finding(
                    "ARGUS-COOKIE-007",
                    "__Host- prefixed cookie sets Domain",
                    name,
                    "HIGH",
                    "__Host- cookies must not include a Domain attribute.",
                    "Remove the Domain attribute from __Host- prefixed cookies.",
                )
            )
        if "path" in attrs and attrs.get("path") != "/":
            findings.append(
                cookie_finding(
                    "ARGUS-COOKIE-008",
                    "__Host- prefixed cookie has non-root Path",
                    name,
                    "HIGH",
                    "__Host- cookies must use Path=/.",
                    "Set Path=/ on __Host- prefixed cookies.",
                )
            )

    return findings


def _is_session_cookie(name: str) -> bool:
    return name.lower() in SESSION_COOKIE_NAMES or "session" in name.lower()


def _has_host_prefix(name: str) -> bool:
    return name.lower().startswith("__host-")


def cookie_finding(
    rule_id: str,
    title: str,
    name: str,
    severity: str,
    impact: str,
    recommendation: str,
) -> dict:
    """Build a cookie finding dict referencing the cookie name."""
    label = f"'{name}' cookie" if name else "cookie"
    display_title = f"{title} for {label}"
    return make_finding(
        id=rule_id,
        category="Cookies",
        severity=severity,
        title=display_title,
        description=f"{label}: {impact}",
        evidence=f"Set-Cookie for {label}",
        impact=impact,
        recommendation=recommendation,
        risk=impact,
        references=references_for("cookies"),
    ).to_dict()
