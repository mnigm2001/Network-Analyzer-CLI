import argparse
from analyzer.capture import capture_with_tshark, capture_packets
from analyzer.parser import parse_pcap
from analyzer.report import report_summary, export_csv


def main():
    parser = argparse.ArgumentParser(
        description="Network Analyzer CLI: live capture, parse & report."
    )
    parser.add_argument("-i", "--iface", default="eth0",
                        help="Interface to capture on")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="Number of packets to capture")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("--method", choices=["tshark", "scapy"], default="tshark",
                        help="Capture backend")
    parser.add_argument("-o", "--output", default="data/capture.pcap",
                        help="PCAP output path")
    parser.add_argument("--csv", action="store_true",
                        help="Export parsed results to CSV")
    parser.add_argument("--protocols", type=lambda s: s.split(','), default=None,
                        help="Comma-separated list of protocols to parse/report (ospf,bgp)")
    args = parser.parse_args()

    # Capture
    if args.method == "tshark":
        capture_with_tshark(
            count=args.count,
            output_file=args.output,
            iface=args.iface,
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
    records = parse_pcap(args.output, protocols=args.protocols)

    # Optional CSV
    if args.csv:
        export_csv(records)

    # Summary
    report_summary(records, protocols=args.protocols)


if __name__ == "__main__":
    main()