# cli/main.py

import argparse
from analyzer.capture import capture_with_tshark, capture_packets
from analyzer.parser import parse_pcap

def main():
    parser = argparse.ArgumentParser(
        description="Network Analyzer CLI: live capture & parse."
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
    args = parser.parse_args()

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

    parse_pcap(args.output)


if __name__ == "__main__":
    main()
