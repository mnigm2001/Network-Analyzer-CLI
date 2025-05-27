import argparse
from analyzer.capture import capture_with_tshark, capture_packets
from analyzer.parser import parse_pcap, extract_records
from analyzer.report import export_csv


def main():
    parser = argparse.ArgumentParser(
        description="Network Analyzer CLI: capture and parse network traffic."
    )
    parser.add_argument(
        "-i", "--iface", default="eth0",
        help="Network interface to capture on"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=20,
        help="Number of packets to capture"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help="BPF filter string (e.g. 'tcp port 80')"
    )
    parser.add_argument(
        "--method", choices=["tshark", "scapy"], default="tshark",
        help="Capture backend to use"
    )
    parser.add_argument(
        "-o", "--output", default="data/capture.pcap",
        help="Output pcap file path"
    )
    parser.add_argument(
        "--csv", action="store_true",
        help="Export parsed results to CSV"
    )
    args = parser.parse_args()

    # Capture
    if args.method == "tshark":
        capture_with_tshark(
            count=args.count,
            iface=args.iface,
            output_file=args.output,
            bpf_filter=args.filter
        )
    else:
        capture_packets(
            interface=args.iface,
            count=args.count,
            output_file=args.output,
            bpf_filter=args.filter
        )

    # Parse
    parse_pcap(args.output)

    # Optionally export CSV
    if args.csv:
        records = extract_records(args.output)
        export_csv(records)


if __name__ == "__main__":
    main()