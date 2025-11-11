"""
Main CLI application using Typer
"""

import asyncio
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from burp_cli.api.client import BurpClient
from burp_cli.api.models import ScanStatus
from burp_cli.utils.config import get_settings
from burp_cli.utils.logger import setup_logger

app = typer.Typer(
    name="burp-cli",
    help="AI-Assisted Burp Suite CLI for automated security testing",
    add_completion=False
)
console = Console()
settings = get_settings()
logger = setup_logger(level=settings.log_level, log_file=settings.log_file)


def get_client() -> BurpClient:
    """Get Burp API client instance"""
    return BurpClient(
        api_url=settings.burp_api_url,
        api_key=settings.burp_api_key,
        timeout=settings.request_timeout
    )


@app.command()
def health() -> None:
    """Check Burp Suite API connection"""
    async def _check() -> None:
        async with get_client() as client:
            if await client.health_check():
                version = await client.get_version()
                console.print(f"[green]✓[/green] Connected to {version.product} v{version.version}")
            else:
                console.print("[red]✗[/red] Cannot connect to Burp Suite API")
                console.print(f"API URL: {settings.burp_api_url}")
                raise typer.Exit(1)

    asyncio.run(_check())


@app.command()
def scan(
    urls: List[str] = typer.Argument(..., help="Target URLs to scan"),
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Scan name"),
    wait: bool = typer.Option(False, "--wait", "-w", help="Wait for scan to complete"),
    show_issues: bool = typer.Option(False, "--issues", "-i", help="Show issues after completion")
) -> None:
    """Start a security scan on target URLs"""

    async def _scan() -> None:
        async with get_client() as client:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                # Start scan
                task = progress.add_task("Starting scan...", total=None)
                scan = await client.start_scan(urls=urls, name=name)

                progress.update(task, description=f"Scan started: {scan.scan_id}")
                console.print(f"\n[green]✓[/green] Scan ID: [bold]{scan.scan_id}[/bold]")
                console.print(f"Target URLs: {', '.join(urls)}")

                if wait:
                    # Wait for completion
                    progress.update(task, description="Waiting for scan to complete...")

                    def status_callback(details):
                        status_text = f"Status: {details.status.value}"
                        if details.issue_counts:
                            status_text += f" | Issues: {sum(details.issue_counts.values())}"
                        progress.update(task, description=status_text)

                    details = await client.wait_for_scan(
                        scan.scan_id,
                        poll_interval=settings.scan_poll_interval,
                        callback=status_callback
                    )

                    console.print(f"\n[green]✓[/green] Scan completed: {details.status.value}")

                    if show_issues and details.status == ScanStatus.SUCCEEDED:
                        # Show issues
                        issues = await client.get_scan_issues(scan.scan_id)
                        _display_issues(issues.issues)
                else:
                    console.print(f"\nUse 'burp-cli status {scan.scan_id}' to check progress")

    asyncio.run(_scan())


@app.command()
def status(scan_id: str = typer.Argument(..., help="Scan ID")) -> None:
    """Get scan status and details"""

    async def _status() -> None:
        async with get_client() as client:
            details = await client.get_scan_status(scan_id)

            console.print(f"\n[bold]Scan ID:[/bold] {details.scan_id}")
            console.print(f"[bold]Status:[/bold] {details.status.value}")

            if details.issue_counts:
                console.print("\n[bold]Issues by Severity:[/bold]")
                for severity, count in details.issue_counts.items():
                    console.print(f"  {severity}: {count}")

    asyncio.run(_status())


@app.command()
def issues(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity")
) -> None:
    """Get issues from a scan"""

    async def _issues() -> None:
        async with get_client() as client:
            scan_issues = await client.get_scan_issues(scan_id, severity=severity)

            console.print(f"\n[bold]Total Issues:[/bold] {scan_issues.total_count}")
            _display_issues(scan_issues.issues)

    asyncio.run(_issues())


@app.command()
def list() -> None:
    """List all scans"""

    async def _list() -> None:
        async with get_client() as client:
            scans = await client.list_scans()

            if not scans:
                console.print("No scans found")
                return

            table = Table(title="Burp Scans")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Status", style="green")

            for scan in scans:
                table.add_row(scan.scan_id, scan.status.value)

            console.print(table)

    asyncio.run(_list())


@app.command()
def stop(scan_id: str = typer.Argument(..., help="Scan ID to stop")) -> None:
    """Stop a running scan"""

    async def _stop() -> None:
        async with get_client() as client:
            success = await client.stop_scan(scan_id)

            if success:
                console.print(f"[green]✓[/green] Scan {scan_id} stopped")
            else:
                console.print(f"[red]✗[/red] Failed to stop scan {scan_id}")
                raise typer.Exit(1)

    asyncio.run(_stop())


@app.command()
def proxy(
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum items to retrieve"),
    filter_url: Optional[str] = typer.Option(None, "--filter", "-f", help="URL filter")
) -> None:
    """Get proxy history"""

    async def _proxy() -> None:
        async with get_client() as client:
            history = await client.get_proxy_history(limit=limit, filter_url=filter_url)

            table = Table(title="Proxy History")
            table.add_column("ID", style="cyan")
            table.add_column("Method", style="yellow")
            table.add_column("URL", style="blue")
            table.add_column("Status", style="green")

            for item in history:
                table.add_row(
                    str(item.id),
                    item.method,
                    item.url,
                    str(item.status_code or "-")
                )

            console.print(table)

    asyncio.run(_proxy())


@app.command()
def config() -> None:
    """Show current configuration"""
    console.print("\n[bold]Burp CLI Configuration:[/bold]")
    console.print(f"API URL: {settings.burp_api_url}")
    console.print(f"API Key: {'*' * 10}{settings.burp_api_key[-4:] if settings.burp_api_key else 'NOT SET'}")
    console.print(f"Log Level: {settings.log_level}")
    console.print(f"Report Output: {settings.report_output_dir}")
    console.print(f"AI Validation: {'Enabled' if settings.enable_ai_validation else 'Disabled'}")
    console.print(f"SQLMap Validation: {'Enabled' if settings.enable_sqlmap_validation else 'Disabled'}")


def _display_issues(issues: list) -> None:
    """Display issues in a table"""
    if not issues:
        console.print("No issues found")
        return

    table = Table(title="Security Issues")
    table.add_column("Name", style="cyan", no_wrap=False)
    table.add_column("Severity", style="red")
    table.add_column("Confidence", style="yellow")
    table.add_column("Path", style="blue", no_wrap=False)

    for issue in issues:
        # Color code severity
        severity_color = {
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white"
        }.get(issue.severity.value, "white")

        table.add_row(
            issue.name,
            f"[{severity_color}]{issue.severity.value}[/{severity_color}]",
            issue.confidence.value,
            issue.path
        )

    console.print("\n")
    console.print(table)


if __name__ == "__main__":
    app()
