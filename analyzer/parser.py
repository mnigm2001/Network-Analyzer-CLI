# analyzer/parser.py

import pyshark
from rich.console import Console

console = Console()

def parse_pcap(file_path):
    """
    Simple printout of TCP/IP packet info, in real time as we iterate.
    """
    console.print(f"\n[cyan]Parsing {file_path}…[/cyan]\n")
    cap = pyshark.FileCapture(file_path)
    for pkt in cap:
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            proto = pkt.transport_layer
            console.print(f"[white]{src} → {dst}[/white]  |  [blue]{proto}[/blue]")
        except AttributeError:
            continue
    cap.close()
