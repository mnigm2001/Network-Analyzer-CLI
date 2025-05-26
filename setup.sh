#!/bin/bash

# Setup script for network-analyzer project

echo "[+] Updating package list..."
sudo apt update

echo "[+] Installing system dependencies..."
sudo apt install -y python3 python3-venv python3-pip tshark git

echo "[+] Creating Python virtual environment..."
python3 -m venv venv

echo "[+] Activating virtual environment..."
source venv/bin/activate

echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

pip install -e .

echo "[+] Adding user to wireshark group to allow packet capture..."
sudo usermod -aG wireshark $USER
echo "    -> You may need to log out and log back in for this to take effect."

# Find the real path to the python3 binary in your venv:
PYTHON_BIN=$(realpath $(which python3))

# Grant it CAP_NET_RAW & CAP_NET_ADMIN so it can open raw sockets:
sudo setcap cap_net_raw,cap_net_admin+eip $PYTHON_BIN

echo "[+] Setup complete."
