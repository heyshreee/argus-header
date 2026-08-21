from .cookies import analyze_cookies


def analyze_headers(headers_data):
    """
    Analyzes the raw headers and returns a list of findings.
    """
    if not headers_data.get("success"):
        return []

    headers = {k.lower(): v for k, v in headers_data["headers"].items()}
    findings = []

    # --- 1. Security Headers Analysis ---
    
    # Content-Security-Policy
    if "content-security-policy" not in headers:
        findings.append({
            "id": "SEC-001",
            "category": "Security",
            "issue": "Missing Content-Security-Policy",
            "severity": "HIGH",
            "risk": "XSS (Cross-Site Scripting) attacks are easier to exploit.",
            "fix": "Add a 'Content-Security-Policy' header defining allowed content sources."
        })

    # Strict-Transport-Security (HSTS)
    if "strict-transport-security" not in headers:
        findings.append({
            "id": "SEC-002",
            "category": "Security",
            "issue": "Missing Strict-Transport-Security",
            "severity": "HIGH",
            "risk": "Susceptible to Man-in-the-Middle (MITM) protocol downgrade attacks.",
            "fix": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'."
        })

    # X-Frame-Options
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append({
            "id": "SEC-003",
            "category": "Security",
            "issue": "Missing X-Frame-Options",
            "severity": "HIGH",
            "risk": "Vulnerable to Clickjacking attacks.",
            "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        })

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append({
            "id": "SEC-004",
            "category": "Security",
            "issue": "Missing X-Content-Type-Options",
            "severity": "MEDIUM",
            "risk": "Browsers may MIME-sniff the response body, leading to XSS.",
            "fix": "Add 'X-Content-Type-Options: nosniff'."
        })

    # --- 2. Information Leakage ---

    # Server Header
    if "server" in headers:
        findings.append({
            "id": "LEAK-001",
            "category": "Leakage",
            "issue": f"Server Header Leaked: {headers['server']}",
            "severity": "LOW",
            "risk": "Reveals server technology, helping attackers verify CVEs.",
            "fix": "Configure server to suppress or obfuscate the 'Server' header."
        })

    # X-Powered-By
    if "x-powered-by" in headers:
        findings.append({
            "id": "LEAK-002",
            "category": "Leakage",
            "issue": f"X-Powered-By Leaked: {headers['x-powered-by']}",
            "severity": "MEDIUM",
            "risk": "Reveals specific framework/version info.",
            "fix": "Remove the 'X-Powered-By' header in server config."
        })

    # --- 3. CORS Misconfiguration ---
    
    if "access-control-allow-origin" in headers:
        if headers["access-control-allow-origin"] == "*":
            findings.append({
                "id": "CORS-001",
                "category": "CORS",
                "issue": "CORS Access-Control-Allow-Origin is '*'",
                "severity": "MEDIUM",
                "risk": "Allows any domain to access resources (dangerous if auth is used).",
                "fix": "Restrict to specific trusted domains."
            })

    # --- 4. Performance ---
    
    # Cache-Control
    if "cache-control" not in headers:
        findings.append({
            "id": "PERF-001",
            "category": "Performance",
            "issue": "Missing Cache-Control Header",
            "severity": "LOW",
            "risk": "Browser may not cache resources efficiently, slowing load times.",
            "fix": "Add 'Cache-Control' header (e.g., max-age=3600)."
        })

    # --- 5. Cookie Security ---

    findings.extend(analyze_cookies(headers))

    return findings