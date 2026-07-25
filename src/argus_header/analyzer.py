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
            "category": "Security",
            "issue": "Missing Content-Security-Policy",
            "severity": "HIGH",
            "risk": "XSS (Cross-Site Scripting) attacks are easier to exploit.",
            "fix": "Add a 'Content-Security-Policy' header defining allowed content sources."
        })

    # Strict-Transport-Security (HSTS)
    if "strict-transport-security" not in headers:
        findings.append({
            "category": "Security",
            "issue": "Missing Strict-Transport-Security",
            "severity": "HIGH",
            "risk": "Susceptible to Man-in-the-Middle (MITM) protocol downgrade attacks.",
            "fix": "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'."
        })

    # X-Frame-Options
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append({
            "category": "Security",
            "issue": "Missing X-Frame-Options",
            "severity": "HIGH",
            "risk": "Vulnerable to Clickjacking attacks.",
            "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        })

    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append({
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
            "category": "Leakage",
            "issue": f"Server Header Leaked: {headers['server']}",
            "severity": "LOW",
            "risk": "Reveals server technology, helping attackers verify CVEs.",
            "fix": "Configure server to suppress or obfuscate the 'Server' header."
        })

    # X-Powered-By
    if "x-powered-by" in headers:
        findings.append({
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
            "category": "Performance",
            "issue": "Missing Cache-Control Header",
            "severity": "LOW",
            "risk": "Browser may not cache resources efficiently, slowing load times.",
            "fix": "Add 'Cache-Control' header (e.g., max-age=3600)."
        })

    return findings



# print(analyze_headers({'success': True, 'url': 'https://example.com/', 'status_code': 200, 'headers': {'Accept-Ranges': 'bytes', 'Content-Type': 'text/html', 'ETag': '"bc2473a18e003bdb249eba5ce893033f:1760028122.592274"', 'Last-Modified': 'Thu, 09 Oct 2025 16:42:02 GMT', 'Vary': 'Accept-Encoding', 'Content-Encoding': 'gzip', 'Content-Length': '363', 'Cache-Control': 'max-age=86000', 'Date': 'Tue, 09 Dec 2025 14:19:11 GMT', 'Connection': 'keep-alive', 'Alt-Svc': 'h3=":443"; ma=93600'}, 'http_version': 11}))