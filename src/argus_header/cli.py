import argparse
import sys
import time
import uuid

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console

from argus_header import __version__
from .requester import fetch_headers
from .analyzer import analyze_headers
from .reporter import print_report, save_json
from .verbose import print_verbose

console = Console()

BANNER = r"""
   ___                             
  / _ | _______ _____ _____ _____  
 / __ |/ __/ _ `/ // (_-</(_-<(_-<  
/_/ |_/_/  \_, /\_,_/___/___/___/  
            /_/                    

 Argus Header
 HTTP Header Security Analyzer
"""

def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[bold]Version:[/bold] {__version__}\n")

def scan_target(url: str, args):
    response_data = fetch_headers(
        url,
        method=args.method,
        follow_redirects=not args.no_redirect,
        timeout=args.timeout,
    )
    started = datetime.now()
    start_time = time.perf_counter()

    findings = analyze_headers(response_data)

    end_time = time.perf_counter()
    finished = datetime.now()

    scan = {
        "scan_id": uuid.uuid4().hex[:8],
        "started": started,
        "finished": finished,
        "duration": end_time - start_time,
        "response": response_data,
        "findings": findings,
        "url": url,
        "args": args,
    }

    print_report(response_data, findings)

    if args.verbose:
        print_verbose(scan)

    if args.json and len(args.url) == 1:
        save_json(response_data, findings, args.json)

def main():
    parser = argparse.ArgumentParser(
        prog="argus-header",
        description="Argus Header - HTTP Header Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  argus-header https://example.com
  argus-header https://example.com --method HEAD
  argus-header https://example.com --json report.json
  argus-header https://google.com https://github.com --parallel
  argus-header --version
""",
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"Argus Header {__version__}",
    )

    parser.add_argument(
        "url",
        nargs="+",
        help="One or more target URLs to analyze.",
    )

    parser.add_argument(
        "--method",
        choices=["GET", "HEAD"],
        default="GET",
        help="HTTP request method (default: GET).",
    )

    parser.add_argument(
        "--no-redirect",
        action="store_true",
        help="Disable HTTP redirect following.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10).",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Save the report to a JSON file.",
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Scan multiple URLs concurrently.",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed scan information."
    )

    args = parser.parse_args()

    print_banner()

    try:
        if args.parallel and len(args.url) > 1:
            console.print(
                f"[bold green][*][/bold green] Scanning {len(args.url)} targets in parallel...\n"
            )

            with ThreadPoolExecutor(max_workers=5) as executor:
                list(executor.map(lambda u: scan_target(u, args), args.url))
        else:
            for url in args.url:
                scan_target(url, args)
                console.rule()

        sys.exit(0)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan cancelled by user.[/bold yellow]")
        sys.exit(130)

    except Exception as exc:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
