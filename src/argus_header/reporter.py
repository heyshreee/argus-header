import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

def print_report(response_data, findings):
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
    console.print("\n[dim]Run with --verbose to see full header dump (not implemented in basic guide).[/dim]")


def save_json(response_data, findings, filepath):
    """Saves the report to a JSON file."""
    output = {
        "target": response_data.get("url"),
        "status": response_data.get("status_code"),
        "scan_time": "Now", # You can use datetime here
        "headers": response_data.get("headers"),
        "findings": findings
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=4)
        console.print(f"[bold green]✔ Report saved to {filepath}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to save JSON:[/bold red] {e}")