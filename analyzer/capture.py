from scapy.all import sniff, wrpcap

def capture_packets(interface="eth0", count=50, output_file="data/capture.pcap"):
    packets = sniff(count=count, iface=interface)
    wrpcap(output_file, packets)
    print(f"[+] Captured {count} packets and saved to {output_file}")

import subprocess

def capture_with_tshark(iface="eth0", count=50, output_file="data/capture.pcap"):
    cmd = ["tshark", "-i", iface, "-c", str(count), "-w", output_file]
    subprocess.run(cmd, check=True)
    print(f"[+] Captured {count} packets via tshark to {output_file}")
