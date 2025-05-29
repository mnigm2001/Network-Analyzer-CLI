from collections import Counter
from rich.console import Console

console = Console()

SUPPORTED_PROTOCOLS = {"ospf", "bgp"}


def detect_protocol(pkt):
    """
    Return protocol name if packet matches supported routing protocols.
    """
    # Using pyshark layers
    try:
        if hasattr(pkt, 'ospf'):
            return 'ospf'
        if hasattr(pkt, 'bgp'):
            return 'bgp'
    except Exception:
        pass
    return None


def summarize_protocols(records):
    """
    Print a summary count of supported protocols from records.
    """
    counts = Counter(rec['proto'].lower() for rec in records if rec['proto'].lower() in SUPPORTED_PROTOCOLS)
    if not counts:
        console.print("[yellow]No supported routing/signaling protocols detected.[/yellow]")
        return

    console.print("\n[cyan]Routing/Signaling Protocol Summary:[/cyan]")
    for proto, count in counts.items():
        console.print(f"[green]{proto.upper()}[/green]: {count} packets")