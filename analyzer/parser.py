import pyshark

def parse_pcap(file_path):
    cap = pyshark.FileCapture(file_path)
    for pkt in cap:
        try:
            ip = pkt.ip
            print(f"{ip.src} → {ip.dst} | Protocol: {pkt.transport_layer}")
        except AttributeError:
            continue
    cap.close()
