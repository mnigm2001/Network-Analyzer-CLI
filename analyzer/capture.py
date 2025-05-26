from scapy.all import sniff, wrpcap

def capture_packets(interface="eth0", count=50, output_file="data/capture.pcap"):
    packets = sniff(count=count, iface=interface)
    wrpcap(output_file, packets)
    print(f"[+] Captured {count} packets and saved to {output_file}")
