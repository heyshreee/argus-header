import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.panel import Panel

from argus_header import __version__

from .config_loader import load_config
from .engine.policy import evaluate_gate
from .models.report import ScoreData
from .output.html_report import save_html
from .output.json_report import load_report, render_json, save_report
from .output.sarif import build_sarif, save_sarif
from .output.terminal import (
    print_ci_result,
    print_diff_result,
    print_findings_professional,
    print_score_breakdown,
)
from .scanner import scan_target

console = Console()

BANNER = r"""
   ___
  / _ | _______ _____ _____ _____
 / __ |/ __/ _ `/ // (_-</(_-<(_-<
/_/ |_/_/  \_, /\_,_/___/___/___/
            /_/

 ARGUS-HEADER v0.8.0
 DEEP SECURITY ANALYSIS
"""


def print_banner():
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[bold]Version:[/bold] {__version__}\n")


def build_scan_parser():
    parser = argparse.ArgumentParser(
        prog="argus-header",
        description="Argus Header - Deep HTTP Security Header Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  argus-header https://example.com
  argus-header https://example.com --score
  argus-header https://example.com --fail-on high
  argus-header https://example.com --min-score 80
  argus-header https://example.com --json report.json
  argus-header https://example.com --json            (stdout)
  argus-header https://example.com --sarif report.sarif
  argus-header https://example.com --report report.html
  argus-header https://example.com --config .argus.yml
  argus-header diff before.json after.json
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
        default=None,
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
        default=None,
        help="Request timeout in seconds (default: 10).",
    )

    parser.add_argument(
        "--config",
        metavar="FILE",
        help="Path to a .argus.yml configuration file.",
    )

    parser.add_argument(
        "--score",
        action="store_true",
        help="Display the security score breakdown (Score 2.0).",
    )

    parser.add_argument(
        "--json",
        nargs="?",
        const="-",
        metavar="FILE",
        help="Write a JSON report (to FILE, or stdout when omitted).",
    )

    parser.add_argument(
        "--sarif",
        metavar="FILE",
        help="Write a SARIF 2.1.0 report.",
    )

    parser.add_argument(
        "--report",
        metavar="FILE",
        help="Write a cyberpunk-style HTML security report.",
    )

    parser.add_argument(
        "--markdown",
        metavar="FILE",
        help="Save a Markdown security report.",
    )

    parser.add_argument(
        "--html",
        metavar="FILE",
        help="Save a legacy HTML security report.",
    )

    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Scan multiple URLs concurrently.",
    )

    parser.add_argument(
        "--verbose", action="store_true", help="Show detailed scan information."
    )

    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="CI mode: fail the build when a finding at this severity (or worse) exists.",
    )

    parser.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="CI mode: fail the build when the score is below this value.",
    )

    return parser


def scan_targets(args) -> int:
    """Run the v0.8 scan pipeline. Returns the process exit code."""
    config = load_config(args.config)

    method = args.method or (config.method if config else "GET") or "GET"
    timeout = args.timeout or (config.timeout if config else 10) or 10
    follow_redirects = not args.no_redirect
    if config is not None and not args.no_redirect:
        follow_redirects = config.redirects

    fail_on = args.fail_on or (config.policy.fail_on if config else None) or "none"
    min_score = (
        args.min_score
        if args.min_score is not None
        else (config.policy.minimum_score if config else 80)
    )

    ci_mode = (
        args.fail_on is not None
        or args.min_score is not None
        or (config is not None and (config.policy.fail_on != "none"))
    )

    reports = _collect_reports(args, method, timeout, follow_redirects, config)

    exit_code = 0
    for report in reports:
        target = report["scan"]["target"]
        if report.get("error"):
            console.print(
                f"[bold red]Error scanning {target}: {report['error']}[/bold red]"
            )
            exit_code = exit_code or 1
            continue

        _present_report(report)
        _handle_outputs(report, args)

        if ci_mode:
            result = evaluate_gate(
                report["score"],
                report["findings"],
                fail_on=fail_on,
                minimum_score=min_score,
            )
            print_ci_result(
                ScoreData.from_dict(report["score"]),
                target,
                None if result.passed else result.reason,
            )
            if not result.passed:
                exit_code = exit_code or 1

    return exit_code


def _collect_reports(args, method, timeout, follow_redirects, config):
    urls = args.url

    def run(url):
        return scan_target(
            url,
            method=method,
            follow_redirects=follow_redirects,
            timeout=timeout,
            config=config,
        )

    if args.parallel and len(urls) > 1:
        console.print(
            f"[bold green][*][/bold green] Scanning {len(urls)} targets in parallel...\n"
        )
        with ThreadPoolExecutor(max_workers=5) as executor:
            return list(executor.map(run, urls))

    return [run(url) for url in urls]


def _present_report(report) -> None:
    console.print(
        Panel(
            f"[bold green]Target:[/bold green] {report['scan']['target']}\n"
            f"[bold blue]Status:[/bold blue] {report['scan'].get('status', 'N/A')}\n"
            f"[bold]Headers Found:[/bold] {len(report.get('headers', {}))}",
            title="Scan Summary",
            expand=False,
        )
    )

    findings = report.get("findings", [])
    if findings:
        print_findings_professional(findings)
    else:
        console.print(
            "[bold green]✓ No security misconfigurations detected.[/bold green]"
        )

    print_score_breakdown(ScoreData.from_dict(report["score"]))


def _handle_outputs(report, args) -> None:
    if args.json:
        if args.json == "-":
            console.print(render_json(report))
        else:
            save_report(report, args.json)

    if args.sarif:
        sarif = build_sarif(report["findings"], report["scan"]["target"])
        save_sarif(sarif, args.sarif)

    if args.report:
        save_html(report, args.report)

    if args.html:
        from .html_report import save_html as save_legacy_html

        save_legacy_html(report, args.html)

    if args.markdown:
        from .markdown import save_markdown

        save_markdown(report, args.markdown)


def run_diff(argv) -> int:
    parser = argparse.ArgumentParser(
        prog="argus-header diff",
        description="Compare two Argus Header JSON reports.",
    )
    parser.add_argument("before", help="Path to the before.json report.")
    parser.add_argument("after", help="Path to the after.json report.")
    args = parser.parse_args(argv)

    from .diff.scanner_diff import scan_diff

    try:
        before = load_report(args.before)
        after = load_report(args.after)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]Diff error:[/bold red] {exc}")
        return 1

    result = scan_diff(before, after)
    print_diff_result(result)
    return 0


def main():
    argv = sys.argv[1:]

    if argv and argv[0] == "diff":
        print_banner()
        sys.exit(run_diff(argv[1:]))

    parser = build_scan_parser()

    if not argv:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args(argv)

    print_banner()

    try:
        sys.exit(scan_targets(args))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan cancelled by user.[/bold yellow]")
        sys.exit(130)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
