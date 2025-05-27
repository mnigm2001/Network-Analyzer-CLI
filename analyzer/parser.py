import pyshark

def parse_pcap(file_path):
    """
    Simple printout of TCP/IP packet info.
    """
    cap = pyshark.FileCapture(file_path)
    for pkt in cap:
        try:
            ip = pkt.ip
            print(f"{ip.src} → {ip.dst} | Protocol: {pkt.transport_layer}")
        except AttributeError:
            continue
    cap.close()


def extract_records(file_path):
    """
    Parse pcap and return list of dicts with packet fields.
    """
    cap = pyshark.FileCapture(file_path)
    records = []
    for pkt in cap:
        try:
            records.append({
                "src": pkt.ip.src,
                "dst": pkt.ip.dst,
                "proto": pkt.transport_layer,
                "length": int(pkt.length)
            })
        except AttributeError:
            continue
    cap.close()
    return records