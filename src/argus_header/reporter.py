import json
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from argus_header import APP_NAME, __version__

console = Console()

SCHEMA_VERSION = "0.7"


def build_json_report(
    response_data,
    findings,
    score_data,
    scan_id,
    target,
    method="GET",
    duration=0.0,
):
    """Build the canonical v0.7 report dictionary.

    Single source of truth consumed by JSON export, the API and the
    future Markdown/HTML renderers.
    """
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings if f.get("severity") == "LOW")

    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": APP_NAME,
            "version": __version__,
        },
        "scan": {
            "id": scan_id,
            "target": target,
            "final_url": response_data.get("url"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 4),
            "method": method,
            "status": response_data.get("status_code"),
        },
        "score": {
            "value": score_data["score"],
            "grade": score_data["grade"],
            "risk_level": score_data["risk_level"],
            "penalty": score_data["penalty"],
        },
        "summary": {
            "total_findings": len(findings),
            "high": high,
            "medium": medium,
            "low": low,
        },
        "headers": response_data.get("headers", {}),
        "findings": findings,
    }

def print_report(response_data, findings, verbose=False):
    """Prints a pretty CLI report."""
    
    # 1. Status Section
    if not response_data["success"]:
        console.print(f"[bold red]Error connecting to {response_data['url']}: {response_data.get('error')}[/bold red]")
        return

    console.print(Panel(
        f"[bold green]Target:[/bold green] {response_data['url']}\n"
        f"[bold blue]Status:[/bold blue] {response_data['status_code']}\n"
        f"[bold]Headers Found:[/bold] {len(response_data['headers'])}",
        title="Scan Summary",
        expand=False
    ))

    # 2. Findings Table
    if findings:
        table = Table(title="Analysis Findings", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Issue", style="cyan")
        table.add_column("Risk")
        table.add_column("Recommendation", style="green")

        # Sort findings: HIGH -> MEDIUM -> LOW
        severity_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(findings, key=lambda x: severity_map.get(x["severity"], 3))

        for f in sorted_findings:
            severity_color = "red" if f["severity"] == "HIGH" else "yellow" if f["severity"] == "MEDIUM" else "blue"
            
            table.add_row(
                f"[{severity_color}]{f['severity']}[/{severity_color}]",
                f["issue"],
                f["risk"],
                f["fix"]
            )
        
        console.print(table)
    else:
        console.print("[bold green]No significant issues found![/bold green]")

    # 3. Raw Headers (Optional or summarized)
    if not verbose:
        console.print(
            "\n[dim]Tip: Run with --verbose to view detailed scan information.[/dim]"
        )


def save_json(report, filepath):
    """Saves the canonical report dictionary to a JSON file."""
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=4)
        console.print(f"[bold green]✔ Report saved to {filepath}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save JSON:[/bold red] {e}")