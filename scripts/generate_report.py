import json
import csv
from datetime import datetime

# Load enriched IOCs and parsed logs
with open("enriched_iocs.json", "r") as f:
    enriched_data = json.load(f)

with open("parsed_log.json", "r") as f:
    parsed_log = json.load(f)

# Merge data by IP
def merge_data(parsed_log, enriched_data):
    reports = []
    for log in parsed_log:
        ip = log.get("ip")
        if not ip:
            continue
        enriched_entry = next((entry for entry in enriched_data if entry["ip"] == ip), None)
        if enriched_entry:
            report = {
                "timestamp": log["timestamp"],
                "username": log["username"],
                "ip": ip,
                "workstation": log["workstation"],
                "vt_malicious_count": enriched_entry["malicious"]
            }
            reports.append(report)
    return reports

# Save as CSV
def save_to_csv(reports, filename="alerts.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=reports[0].keys())
        writer.writeheader()
        writer.writerows(reports)

# Save as JSON
def save_to_json(reports, filename="alerts.json"):
    with open(filename, "w") as f:
        json.dump(reports, f, indent=2)

if __name__ == "__main__":
    reports = merge_data(parsed_log, enriched_data)
    
    if reports:
        save_to_csv(reports)
        save_to_json(reports)
        print(f"✅ Generated {len(reports)} alerts.")
    else:
        print("⚠️ No alerts to report.")