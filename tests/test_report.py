import os
import csv
import pytest
from analyzer.report import export_csv

@pytest.fixture
def sample_records():
    return [
        {"src": "1.1.1.1", "dst": "2.2.2.2", "proto": "UDP", "length": 128},
        {"src": "3.3.3.3", "dst": "4.4.4.4", "proto": "ICMP", "length": 64},
    ]


def test_export_csv_creates_file(tmp_path, sample_records):
    csv_path = tmp_path / "out.csv"
    export_csv(sample_records, csv_path=str(csv_path))

    # File should exist
    assert csv_path.exists()

    # Contents should match sample_records
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == len(sample_records)
        for input_rec, out_rec in zip(sample_records, rows):
            for key in input_rec:
                assert str(input_rec[key]) == out_rec[key]


def test_export_csv_empty_records(tmp_path, capsys):
    csv_path = tmp_path / "empty.csv"
    export_csv([], csv_path=str(csv_path))
    captured = capsys.readouterr()
    assert "[!] No records to export." in captured.out
    assert not csv_path.exists()