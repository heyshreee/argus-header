"""Cookie security analysis for Argus Header."""


def analyze_cookies(headers: dict[str, str]) -> list[dict]:
    """Analyze Set-Cookie headers for security attributes."""

    findings: list[dict] = []

    cookies = []

    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookies.append(value)

    if not cookies:
        return findings

    for cookie in cookies:
        parts = [part.strip() for part in cookie.split(";")]

        cookie_name = parts[0].split("=", 1)[0].strip()

        attributes = {part.split("=", 1)[0].strip().lower() for part in parts[1:]}

        if "secure" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-001",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing Secure flag",
                    "severity": "MEDIUM",
                    "risk": (
                        "The cookie may be transmitted over an unencrypted "
                        "HTTP connection."
                    ),
                    "fix": (
                        f"Add the Secure attribute to the '{cookie_name}' " "cookie."
                    ),
                }
            )

        if "httponly" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-002",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing HttpOnly flag",
                    "severity": "MEDIUM",
                    "risk": (
                        "Client-side JavaScript may access the cookie, "
                        "increasing the impact of XSS attacks."
                    ),
                    "fix": (
                        f"Add the HttpOnly attribute to the '{cookie_name}' " "cookie."
                    ),
                }
            )

        if "samesite" not in attributes:
            findings.append(
                {
                    "id": "COOKIE-003",
                    "category": "Cookie",
                    "issue": f"Cookie '{cookie_name}' missing SameSite attribute",
                    "severity": "LOW",
                    "risk": (
                        "The cookie has no explicit cross-site request " "policy."
                    ),
                    "fix": (
                        f"Add SameSite=Lax, SameSite=Strict, or an "
                        f"appropriate SameSite policy to '{cookie_name}'."
                    ),
                }
            )

    return findings
