from rich.console import Console

console = Console()

def print_verbose(url, response, findings, args):
    console.rule("[bold cyan]Verbose Report[/bold cyan]")

    console.print(f"URL: {url}")
    console.print(f"Method: {args.method}")
    console.print(f"Status: {response['status_code']}")
    console.print(f"Headers: {len(response['headers'])}")
    console.print(f"HTTP Ver. : {response['http_version']}")