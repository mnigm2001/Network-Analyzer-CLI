# setup.py
from setuptools import setup, find_packages

setup(
    name="network_analyzer",
    version="0.1.0",
    packages=find_packages(),             # picks up analyzer/ and cli/
    install_requires=[                    # sync with requirements.txt
        "scapy",
        "pyshark",
    ],
    entry_points={
        "console_scripts": [
            "net-analyzer=cli.main:main"  # get a real CLI command
        ]
    },
)
