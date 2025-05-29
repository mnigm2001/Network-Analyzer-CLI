import pytest
from scapy.all import IP, TCP, wrpcap
from analyzer.parser import parse_pcap

@pytest.fixture

def sample_pcap(tmp_path):
    """
    Create a small PCAP with two IP/TCP packets.
    """
    p1 = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(dport=80)
    p2 = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(dport=443)
    pcap_file = tmp_path / "sample.pcap"
    wrpcap(str(pcap_file), [p1, p2])
    return str(pcap_file)


def test_parse_pcap_outputs_expected(capsys, sample_pcap):
    # Should print packet info lines containing src → dst
    parse_pcap(sample_pcap)
    captured = capsys.readouterr()
    # Expect two arrows in output
    assert "10.0.0.1 → 10.0.0.2" in captured.out
    assert "10.0.0.2 → 10.0.0.1" in captured.out


def test_parse_pcap_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_pcap("nonexistent.pcap")