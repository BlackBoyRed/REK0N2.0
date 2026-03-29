"""
main.py — Entry point for sec-recon-ai
───────────────────────────────────────
Usage:
    python main.py -d example.com
    python main.py -d example.com --mode stealth
    python main.py -d example.com --mode aggressive --save
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from config import DEFAULT_MODE, ScanMode, REPORTS_DIR
from collectors.passive import run_all_passive
from collectors.active import run_all_active
from collectors.aggregator import aggregate

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def print_banner():
    console.print(Panel.fit(
        "[bold cyan]sec-recon-ai[/bold cyan]\n"
        "[dim]AI-Powered Attack Surface Recon[/dim]\n"
        "[red]Only use against targets you own or have written permission to test.[/red]",
        border_style="cyan"
    ))


def print_summary(result):
    table = Table(title=f"Recon Summary — {result.domain}", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right", style="green")

    for k, v in result.summary.items():
        label = k.replace("_", " ").title()
        style = "red bold" if (k == "cves_found" and v > 0) or (k == "total_leaks" and v > 0) else "green"
        table.add_row(label, f"[{style}]{v}[/{style}]")

    console.print(table)

    if result.leaks:
        console.print("\n[bold red]GitHub Leaks Found:[/bold red]")
        for leak in result.leaks[:5]:
            console.print(f"  [red]•[/red] {leak.repo} → {leak.file}  ({leak.url})")

    if result.missing_headers:
        console.print(f"\n[bold yellow]Missing Security Headers:[/bold yellow] {', '.join(result.missing_headers)}")

    if result.hosts:
        console.print(f"\n[bold]Top Hosts:[/bold]")
        for host in result.hosts[:5]:
            ports = ", ".join(str(p.port) for p in host.ports[:8])
            cves  = f" [red]CVEs: {', '.join(host.vulns[:3])}[/red]" if host.vulns else ""
            console.print(f"  {host.ip} ({host.hostname or 'no hostname'}) — ports: {ports}{cves}")


async def run(domain: str, mode: str, save: bool):
    print_banner()
    console.print(f"\n[bold]Target:[/bold] {domain}  |  [bold]Mode:[/bold] {mode}\n")

    with console.status("[bold cyan]Running passive collectors...[/bold cyan]"):
        passive_results = await run_all_passive(domain)
    console.print("[green]✓[/green] Passive collection complete")

    active_results = []
    if mode != ScanMode.STEALTH:
        with console.status("[bold cyan]Running active collectors...[/bold cyan]"):
            active_results = await run_all_active(domain, mode)
        console.print("[green]✓[/green] Active collection complete")

    with console.status("[bold cyan]Aggregating results...[/bold cyan]"):
        result = aggregate(domain, mode, passive_results + active_results)
    console.print("[green]✓[/green] Aggregation complete\n")

    print_summary(result)

    if save:
        path = result.save()
        console.print(f"\n[dim]Raw data saved to {path}[/dim]")

    return result


def main():
    parser = argparse.ArgumentParser(description="AI-powered recon tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--mode", choices=["stealth", "normal", "aggressive"], default=DEFAULT_MODE)
    parser.add_argument("--save", action="store_true", help="Save raw JSON to data/raw/")
    args = parser.parse_args()

    result = asyncio.run(run(args.domain, args.mode, args.save))
    return result


if __name__ == "__main__":
    main()
