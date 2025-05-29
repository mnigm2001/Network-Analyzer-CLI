import pyshark
from rich.console import Console
from analyzer.protocols import detect_protocol

console = Console()


def parse_pcap(file_path, protocols=None):
    """
    Parse and print packet info. If 'protocols' list provided, filters to those.
    Returns list of record dicts.
    """
    console.print(f"\n[cyan]Parsing {file_path}…[/cyan]\n")
    cap = pyshark.FileCapture(file_path)
    records = []
    for pkt in cap:
        try:
            src = pkt.ip.src
            dst = pkt.ip.dst
            # choose transport layer or highest
            proto = pkt.transport_layer or pkt.highest_layer
        except AttributeError:
            continue

        # protocol-level detection
        proto_lower = proto.lower() if proto else ''
        extra_proto = detect_protocol(pkt)

        # filter if needed
        if protocols:
            allowed = [p.lower() for p in protocols]
            if proto_lower not in allowed and extra_proto not in allowed:
                continue

        # print line
        if extra_proto:
            console.print(f"[{extra_proto.upper()}] {src} → {dst} | {extra_proto.upper()} message")
            proto_to_record = extra_proto
        else:
            console.print(f"[white]{src} → {dst}[/white]  |  [blue]{proto}[/blue]")
            proto_to_record = proto

        records.append({
            'src': src,
            'dst': dst,
            'proto': proto_to_record,
            'length': int(pkt.length)
        })

    cap.close()
    return records