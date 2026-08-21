import sys
import os
import json
from urllib.parse import urlparse

# Import your existing modules
from argus_header.requester import fetch_headers
from argus_header.analyzer import analyze_headers
from argus_header.reporter import print_report


def save_json_report(response_data, findings, target_url):
    """Save the final report into report/<hostname>.json"""

    parsed = urlparse(target_url)
    hostname = parsed.netloc or parsed.path  # handles "example.com" and "https://example.com"

    # Create report folder if missing
    os.makedirs("report", exist_ok=True)

    filepath = f"report/{hostname}.json"

    output = {
        "target": response_data.get("url"),
        "status": response_data.get("status_code"),
        "headers": response_data.get("headers"),
        "findings": findings
    }

    with open(filepath, "w") as f:
        json.dump(output, f, indent=4)

    print(f"\n[✔] JSON report saved to: {filepath}")


def main():
    # No URL passed
    if len(sys.argv) < 2:
        print("Usage: python main.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]

    # Step 1 — Fetch Headers
    response_data = fetch_headers(target_url)

    # Step 2 — Analyze
    findings = analyze_headers(response_data)

    # Step 3 — Print Report
    print_report(response_data, findings)

    # Step 4 — Save JSON
    save_json_report(response_data, findings, target_url)


if __name__ == "__main__":
    main()
