from analyzer.capture import capture_packets, capture_with_tshark
from analyzer.parser import parse_pcap

def main():
    # capture_packets(count=20)
    capture_with_tshark(count=20)
    parse_pcap("data/capture.pcap")

if __name__ == "__main__":
    main()
