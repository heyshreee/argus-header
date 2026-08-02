from datetime import datetime
import platform
import sys
from rich.console import Console

from argus_header import __version__

console = Console()

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

def print_target_information():
    pass    

def print_request_configuration():
    pass

def print_connection_information():
    pass

def print_http_response():
    pass

def print_redirect_information():
    pass

def print_response_headers():
    pass

def print_security_headers():
    pass

def print_missing_security_headers():
    pass

def print_present_security_headers():
    pass

def print_information_leakage():
    pass

def print_response_statistics():
    pass

def print_findings_summary():
    pass

def print_overall_assessment():
    pass

def print_end_of_scan():
    pass


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