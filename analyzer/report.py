import csv


def export_csv(records, csv_path="data/report.csv"):  # noqa: D103
    if not records:
        print("[!] No records to export.")
        return
    keys = records[0].keys()
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(records)
    print(f"[+] Exported {len(records)} records to {csv_path}")