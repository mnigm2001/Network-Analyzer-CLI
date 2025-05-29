import csv
from rich.console import Console
from analyzer.protocols import summarize_protocols

console = Console()


def export_csv(records, csv_path="data/report.csv"):  # noqa: D103
    if not records:
        console.print("[yellow][!] No records to export.[/yellow]")
        return
    keys = records[0].keys()
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(records)
    console.print(f"[green][+] Exported {len(records)} records to {csv_path}[/green]")


def report_summary(records, protocols=None):
    """
    Report overall and protocol-specific summaries.
    """
    console.print(f"\n[cyan]Total Packets Processed:[/cyan] {len(records)}")
    if protocols:
        summarize_protocols(records)