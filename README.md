# Network Analyzer & Packet Testing Suite

A Python-based network protocol analyzer and testing suite to demonstrate hands-on experience with **packet capture**, **protocol parsing**, and **network diagnostics**, tailored to the skills required in infrastructure and embedded networking roles.

---

## Project Purpose

This project was created to showcase my qualifications for roles that require:

- Packet-level protocol analysis (TCP/IP)
- Familiarity with tools like **Wireshark**, **TShark**, and **iPerf**
- Understanding of **routing protocols** and **legacy serial interfaces**
- Strong scripting abilities using **Python**

It is intentionally modular and extensible, and serves as both a network diagnostic tool and a demonstration of engineering best practices.

---

## Features

- ✅ **Live Packet Capture** using `scapy`
- ✅ **PCAP File Parsing** using `pyshark` and `tshark`
- ✅ **TCP/IP Header Extraction** (source/destination IP, ports, protocols)
- **Extensible Design** for:
  - IPerf test automation
  - Serial interface simulation (RS232/RS485)
  - Packet logging/reporting
  - Filtering by protocol (TCP/UDP/ICMP/OSPF)

---

## Project Structure
network-analyzer/
├── analyzer/ # Core logic (capture, parsing, reporting)
├── cli/ # Command-line interface
├── data/ # PCAP captures and logs
├── tests/ # Unit tests
├── setup.sh # Full setup script for Linux/WSL
├── requirements.txt
└── README.md


## Getting Started

### Prerequisites
- Python 3
- WSL or Linux
- `tshark` (Wireshark command-line utility)

### Setup
```bash
git clone https://github.com/yourusername/network-analyzer.git
cd network-analyzer
chmod +x setup.sh
./setup.sh
