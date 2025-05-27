# analyzer/capture.py

import subprocess
from scapy.all import sniff, wrpcap
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

def capture_with_tshark(count=50, output_file="data/capture.pcap", iface="eth0", bpf_filter=None):
    """
    Capture packets using tshark with optional BPF filter,
    and display packet summaries in real time.
    """
    cmd = ["tshark", "-i", iface, "-c", str(count), "-w", output_file, "-l"]  # -l = line buffering
    if bpf_filter:
        cmd += ["-f", bpf_filter]

    console.print(f"[cyan]Starting TShark capture ({count} pkts) on interface '{iface}'[/cyan]")
    console.print("[grey50]Press Ctrl+C to abort early.[/grey50]\n")

    # Launch in a way that we can echo tshark's stdout
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        task = progress.add_task("[yellow]Capturing packets...", total=None)
        # Forward tshark's own packet-by-packet summaries to our console
        for line in process.stdout:
            console.print(line.rstrip())
        process.wait()
        progress.stop()

    if process.returncode == 0:
        console.print(f"\n[green]✅ TShark capture complete. Saved to {output_file}[/green]")
    else:
        console.print(f"\n[red]❌ TShark exited with code {process.returncode}[/red]")


def capture_packets(interface="eth0", count=50, output_file="data/capture.pcap", bpf_filter=None):
    """
    Capture packets using Scapy with optional BPF filter,
    printing a dot for each packet received.
    """
    console.print(f"[cyan]Starting Scapy capture ({count} pkts) on interface '{interface}'[/cyan]")
    console.print("[grey50]Press Ctrl+C to abort early.[/grey50]\n")

    def on_packet(pkt):
        # this callback is called for each packet
        console.print(".", end="", style="bold green")

    # sniff will call on_packet for each received packet
    packets = sniff(
        iface=interface,
        count=count,
        filter=bpf_filter,
        prn=on_packet,
        store=True
    )
    console.print()  # newline after dots
    wrpcap(output_file, packets)
    console.print(f"[green]✅ Scapy capture complete. Saved to {output_file}[/green]")
