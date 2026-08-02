from datetime import datetime
import platform
import sys
from urllib.parse import urlparse
from rich.console import Console

from argus_header import __version__

console = Console()


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]

def print_scan_information(scan):
    """Print scan metadata."""

    console.rule("[bold cyan]Scan Information[/bold cyan]")

    started = scan.get("started")
    finished = scan.get("finished")
    duration = scan.get("duration")

    console.print(
        f"[bold]Scan ID[/bold]          : {scan.get('scan_id', 'N/A')}"
    )

    console.print(
        f"[bold]Started[/bold]         : "
        f"{started.strftime('%Y-%m-%d %H:%M:%S') if isinstance(started, datetime) else started or 'N/A'}"
    )

    console.print(
        f"[bold]Finished[/bold]        : "
        f"{finished.strftime('%Y-%m-%d %H:%M:%S') if isinstance(finished, datetime) else finished or 'N/A'}"
    )

    console.print(
        f"[bold]Duration[/bold]        : "
        f"{duration:.3f} sec" if isinstance(duration, (int, float)) else f"[bold]Duration[/bold]        : N/A"
    )

    console.print(f"[bold]Argus Version[/bold]  : {__version__}")
    console.print(
        f"[bold]Python Version[/bold] : {sys.version.split()[0]}"
    )
    console.print(
        f"[bold]Operating System[/bold]: {platform.system()} {platform.release()}"
    )

def print_target_information(scan):
    """Print information about the scanned target."""

    console.rule("[bold cyan]Target Information[/bold cyan]")

    response = scan["response"]

    parsed = urlparse(response["url"])

    protocol = parsed.scheme.upper()
    hostname = parsed.hostname or "Unknown"

    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme == "https" else 80

    console.print(f"[bold]Original URL[/bold] : {scan['url']}")
    console.print(f"[bold]Final URL[/bold]    : {response['url']}")
    console.print(f"[bold]Hostname[/bold]     : {hostname}")
    console.print(f"[bold]Port[/bold]         : {port}")
    console.print(f"[bold]Protocol[/bold]     : {protocol}")
    console.print(f"[bold]Method[/bold]       : {scan['args'].method}")   

def print_request_configuration(scan):
    """Print the request configuration used for the scan."""

    console.rule("[bold cyan]Request Configuration[/bold cyan]")

    args = scan["args"]

    console.print(f"[bold]HTTP Method[/bold]   : {args.method}")
    console.print(f"[bold]Timeout[/bold]       : {args.timeout} sec")
    console.print(
        f"[bold]Follow Redirects[/bold]: {'Yes' if not args.no_redirect else 'No'}"
    )
    console.print(
        f"[bold]Parallel Scan[/bold]  : {'Enabled' if args.parallel else 'Disabled'}"
    )
    console.print(
        f"[bold]JSON Export[/bold]    : {args.json if args.json else 'Disabled'}"
    )
    console.print(f"[bold]Verbose Mode[/bold]  : Enabled")
    console.print(f"[bold]Argus Version[/bold]  : {__version__}")

def print_connection_information(scan):
    """Print connection information."""

    console.rule("[bold cyan]Connection Information[/bold cyan]")

    response = scan["response"]

    http_versions = {
        9: "HTTP/0.9",
        10: "HTTP/1.0",
        11: "HTTP/1.1",
        20: "HTTP/2",
        30: "HTTP/3",
    }

    http_version = http_versions.get(
        response.get("http_version"),
        "Unknown"
    )

    console.print(f"[bold]HTTP Version[/bold] : {http_version}")

    if "response_time" in scan:
        console.print(
            f"[bold]Response Time[/bold]: {scan['response_time']:.3f} sec"
        )

def print_http_response(scan):
    """Print HTTP response information."""

    console.rule("[bold cyan]HTTP Response[/bold cyan]")

    response = scan["response"]
    headers = response["headers"]

    console.print(f"[bold]Status Code[/bold]      : {response['status_code']}")
    console.print(
        f"[bold]Content-Type[/bold]     : {headers.get('Content-Type', 'N/A')}"
    )
    console.print(
        f"[bold]Content-Length[/bold]   : {headers.get('Content-Length', 'Unknown')}"
    )
    console.print(
        f"[bold]Content-Encoding[/bold] : {headers.get('Content-Encoding', 'None')}"
    )
    console.print(
        f"[bold]Server[/bold]           : {headers.get('Server', 'Unknown')}"
    )
    console.print(
        f"[bold]Date[/bold]             : {headers.get('Date', 'Unknown')}"
    )

def print_redirect_information(scan):
    """Print redirect information."""

    console.rule("[bold cyan]Redirect Information[/bold cyan]")

    original_url = scan["url"]
    final_url = scan["response"]["url"]

    if original_url.rstrip("/") == final_url.rstrip("/"):
        console.print("[bold]Redirect Status[/bold] : No redirects detected.")
    else:
        console.print("[bold]Redirect Status[/bold] : Redirect detected")
        console.print(f"[bold]Original URL[/bold]    : {original_url}")
        console.print(f"[bold]Final URL[/bold]       : {final_url}")

def print_response_headers(scan):
    """Print all HTTP response headers."""

    console.rule("[bold cyan]Response Headers[/bold cyan]")

    headers = scan["response"]["headers"]

    for header, value in headers.items():
        console.print(f"[bold]{header}[/bold]")
        console.print(f"    {value}\n")

def print_security_headers(scan):
    """Display important HTTP security headers."""

    console.rule("[bold cyan]Security Headers[/bold cyan]")

    headers = scan["response"]["headers"]

    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ]

    for header in security_headers:
        value = headers.get(header)

        if value:
            console.print(f"[green]✔ {header}[/green]")
            console.print(f"    {value}\n")
        else:
            console.print(f"[red]✘ {header}[/red]")
            console.print("    Missing\n")

def print_missing_security_headers(scan):
    """Print missing security headers."""

    console.rule("[bold red]Missing Security Headers[/bold red]")

    headers = scan["response"]["headers"]

    missing = []

    for header in SECURITY_HEADERS:
        if header not in headers:
            missing.append(header)

    if not missing:
        console.print("[green]No missing security headers detected.[/green]")
        return

    for header in missing:
        console.print(f"[red]✘ {header}[/red]")

def print_present_security_headers(scan):
    """Print present security headers."""

    console.rule("[bold green]Present Security Headers[/bold green]")

    headers = scan["response"]["headers"]

    present = []

    for header in SECURITY_HEADERS:
        if header in headers:
            present.append((header, headers[header]))

    if not present:
        console.print("[yellow]No security headers were found.[/yellow]")
        return

    for header, value in present:
        console.print(f"[green]✔ {header}[/green]")
        console.print(f"    {value}\n")

def print_information_leakage(scan):
    """Display information leakage headers."""

    console.rule("[bold cyan]Information Leakage[/bold cyan]")

    headers = scan["response"]["headers"]

    leakage_headers = [
        "Server",
        "X-Powered-By",
        "Via",
        "X-AspNet-Version",
        "X-Runtime",
    ]

    for header in leakage_headers:
        value = headers.get(header)

        if value:
            console.print(f"[yellow]{header}[/yellow]")
            console.print(f"    {value}\n")
        else:
            console.print(f"[green]{header}[/green]")
            console.print("    Not Present\n")

def print_response_statistics(scan):
    """Display response statistics."""

    console.rule("[bold cyan]Response Statistics[/bold cyan]")

    headers = scan["response"]["headers"]

    total_headers = len(headers)

    security_present = sum(
        1 for h in SECURITY_HEADERS if h in headers
    )

    security_missing = len(SECURITY_HEADERS) - security_present

    console.print(f"[bold]Headers Received[/bold]          : {total_headers}")
    console.print(f"[bold]Security Headers Present[/bold] : {security_present}")
    console.print(f"[bold]Security Headers Missing[/bold] : {security_missing}")

    if "response_time" in scan:
        console.print(
            f"[bold]Response Time[/bold]            : {scan['response_time']:.3f} sec"
        )

def print_findings_summary(scan):
    """Display findings summary."""

    console.rule("[bold cyan]Findings Summary[/bold cyan]")

    findings = scan["findings"]

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")

    console.print(f"[red]HIGH[/red]     : {high}")
    console.print(f"[yellow]MEDIUM[/yellow]   : {medium}")
    console.print(f"[blue]LOW[/blue]      : {low}")
    console.print(f"[bold]Total[/bold]    : {len(findings)}")

def print_overall_assessment(scan):
    """Display overall assessment."""

    console.rule("[bold cyan]Overall Assessment[/bold cyan]")

    findings = scan["findings"]

    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")

    if high:
        risk = "[red]HIGH[/red]"
    elif medium:
        risk = "[yellow]MEDIUM[/yellow]"
    else:
        risk = "[green]LOW[/green]"

    console.print(f"[bold]Overall Risk[/bold] : {risk}")
    console.print(f"[bold]Findings[/bold]     : {len(findings)}")

    console.print(
        "\nReview the findings above and implement the recommended fixes."
    )

def print_end_of_scan(scan):
    """Print end-of-scan message."""

    console.rule("[bold green]End of Scan[/bold green]")

    console.print("[green]✔ Scan completed successfully.[/green]")

    if "duration" in scan:
        console.print(
            f"[bold]Duration[/bold] : {scan['duration']:.3f} sec"
        )

    console.print(f"[bold]Argus Version[/bold]  : {__version__}")


def print_verbose(scan):
    print_scan_information(scan)
    print_target_information(scan)
    print_request_configuration(scan)
    print_connection_information(scan)
    print_http_response(scan)
    print_redirect_information(scan)
    print_response_headers(scan)
    print_security_headers(scan)
    print_missing_security_headers(scan)
    print_present_security_headers(scan)
    print_information_leakage(scan)
    print_response_statistics(scan)
    print_findings_summary(scan)
    print_overall_assessment(scan)
    print_end_of_scan(scan)