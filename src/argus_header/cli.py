import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from .requester import fetch_headers
from .analyzer import analyze_headers
from .reporter import print_report, save_json

def scan_target(url, args):
    """Helper to process a single URL."""
    # 1. Fetch
    response_data = fetch_headers(
        url, 
        method=args.method, 
        follow_redirects=not args.no_redirect, 
        timeout=args.timeout
    )

    # 2. Analyze
    findings = analyze_headers(response_data)

    # 3. Report
    print_report(response_data, findings)
    
    # 4. JSON Export (only if 1 URL is passed, or we'd need complex logic)
    if args.json and len(args.url) == 1:
        save_json(response_data, findings, args.json)

def main():
    parser = argparse.ArgumentParser(description="HTTP Headers Analysis Tool")
    
    parser.add_argument("url", nargs="+", help="Target URL(s)")
    parser.add_argument("--method", choices=["GET", "HEAD"], default="GET", help="HTTP method")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--json", help="Save report to JSON file (Single URL only)")
    parser.add_argument("--parallel", action="store_true", help="Scan multiple targets in parallel")
    
    args = parser.parse_args()

    if args.parallel and len(args.url) > 1:
        print(f"Scanning {len(args.url)} targets in parallel...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(lambda u: scan_target(u, args), args.url)
    else:
        for url in args.url:
            scan_target(url, args)
            print("-" * 50)

if __name__ == "__main__":
    main()