import pytest
from analyzer.protocols import detect_protocol, summarize_protocols, SUPPORTED_PROTOCOLS
from scapy.all import IP, TCP, wrpcap
import pyshark

class DummyPkt:
    pass


def test_detect_protocol_ospf(tmp_path, monkeypatch):
    # Create dummy pyshark packet with ospf attribute
    class Pkt:
        ospf = True
    assert detect_protocol(Pkt()) == 'ospf'

    class Pkt2:
        bgp = True
    assert detect_protocol(Pkt2()) == 'bgp'

    class Pkt3:
        pass
    assert detect_protocol(Pkt3()) is None


def test_summarize_protocols(capsys):
    records = [
        {'src':'1','dst':'2','proto':'ospf','length':100},
        {'src':'3','dst':'4','proto':'ospf','length':100},
        {'src':'5','dst':'6','proto':'tcp','length':60},
    ]
    summarize_protocols(records)
    captured = capsys.readouterr()
    assert 'OSPF' in captured.out
    assert '2 packets' in captured.out

    # No matching
    summarize_protocols([{'proto':'tcp'}])
    captured2 = capsys.readouterr()
    assert 'No supported routing/signaling protocols detected' in captured2.out