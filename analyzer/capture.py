from scapy.all import sniff, wrpcap
import subprocess
def capture_with_tshark(count=50, output_file="data/capture.pcap", iface="eth0", bpf_filter=None):
    """
    Capture packets using tshark with optional BPF filter.
    """
    cmd = ["tshark", "-i", iface, "-c", str(count)]
    if bpf_filter:
        cmd += ["-f", bpf_filter]
    cmd += ["-w", output_file]
    subprocess.run(cmd, check=True)
    print(f"[+] Captured {count} packets on {iface} "
          f"{'(filter: '+bpf_filter+')' if bpf_filter else ''} "
          f"to {output_file}")


def capture_packets(interface="eth0", count=50, output_file="data/capture.pcap", bpf_filter=None):
    """
    Capture packets using scapy with optional BPF filter.
    """
    packets = sniff(count=count, iface=interface, filter=bpf_filter)
    wrpcap(output_file, packets)
    print(f"[+] Captured {count} packets on {interface} "
          f"{'(filter: '+bpf_filter+')' if bpf_filter else ''} "
          f"to {output_file}")