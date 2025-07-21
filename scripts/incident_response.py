import re
import json
import os
import requests
import csv
from pprint import pprint
from datetime import datetime
from dotenv import load_dotenv

# ----------------------------
# PART 1: LOG PARSING SECTION
# ----------------------------

def read_file_with_fallback(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(filepath, 'r', encoding='utf-16') as f:
                return f.read()
        except UnicodeDecodeError:
            with open(filepath, 'r', encoding='cp1252') as f:
                return f.read()

def parse_failed_logins(log_file):
    log_data = read_file_with_fallback(log_file)
    events = re.split(r'Event\[\d+\]:', log_data)[1:]

    parsed_logs = []
    for event in events:
        log_entry = {}

        timestamp_match = re.search(r'Date: (.+?)Z', event)
        if timestamp_match:
            timestamp = timestamp_match.group(1).replace('T', ' ')
            log_entry["timestamp"] = timestamp.split('.')[0]

        username_match = re.search(r'Account For Which Logon Failed:\s+.*?Account Name:\s+(.+?)\n', event, re.DOTALL)
        if username_match:
            log_entry["username"] = username_match.group(1).strip()

        ip_match = re.search(r'Source Network Address:\s+(.+?)\s*$', event, re.MULTILINE)
        if ip_match:
            ip = ip_match.group(1).strip()
            log_entry["ip"] = ip if ip and ip != '-' else None
        else:
            log_entry["ip"] = None

        workstation_match = re.search(r'Computer: (.+?)\n', event)
        if workstation_match:
            log_entry["workstation"] = workstation_match.group(1).strip()

        parsed_logs.append(log_entry)

    return parsed_logs

def extract_ips(logs):
    return [log["ip"] for log in logs if log["ip"]]

# ----------------------------
# PART 2: VIRUSTOTAL ENRICHMENT
# ----------------------------

def check_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error checking {ip}: {e}")
        return None

def enrich_iocs(ips, api_key):
    enriched_data = []
    for ip in ips:
        result = check_virustotal(ip, api_key)
        if not result:
            continue
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        enriched_data.append({
            "ip": ip,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        })
    return enriched_data

# ----------------------------
# PART 3: REPORT GENERATION
# ----------------------------

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
                "vt_malicious_count": enriched_entry["malicious"],
                "vt_suspicious_count": enriched_entry["suspicious"],
                "vt_harmless_count": enriched_entry["harmless"],
            }
            reports.append(report)
    return reports

def save_to_csv(reports, filename="alerts.csv"):
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=reports[0].keys())
        writer.writeheader()
        writer.writerows(reports)

def save_to_json(reports, filename="alerts.json"):
    with open(filename, "w") as f:
        json.dump(reports, f, indent=2)

# ----------------------------
# PART 4: SLACK ALERTS
# ----------------------------

def send_slack_alert(message, webhook_url):
    slack_data = {
        "text": message
    }
    try:
        response = requests.post(
            webhook_url, json=slack_data,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"❌ Slack alert failed: {e}")

# ----------------------------
# MAIN EXECUTION
# ----------------------------

if __name__ == "__main__":
    load_dotenv()
    API_KEY = os.getenv("VT_API_KEY")
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

    log_file = input("Enter the log file name (e.g., failed_logins.txt): ").strip()

    try:
        print("\n🔍 Parsing logs...")
        parsed_logs = parse_failed_logins(log_file)
        with open("parsed_log.json", "w") as f:
            json.dump(parsed_logs, f, indent=2)
        pprint(parsed_logs)
        print("✅ Parsed logs saved to parsed_log.json")

        print("\n🔍 Extracting IPs...")
        ips = extract_ips(parsed_logs)
        with open("extracted_ips.json", "w") as f:
            json.dump(ips, f, indent=2)
        print("✅ Extracted IPs saved to extracted_ips.json")

        if not API_KEY:
            print("❌ VirusTotal API key not found in .env file.")
            exit()

        print("\n🦠 Querying VirusTotal...")
        enriched = enrich_iocs(ips, API_KEY)
        with open("enriched_iocs.json", "w") as f:
            json.dump(enriched, f, indent=2)
        print("✅ Enriched IOC data saved to enriched_iocs.json")

        print("\n📊 Generating report...")
        report_data = merge_data(parsed_logs, enriched)

        if report_data:
            # Send Slack alerts if Slack webhook URL is set
            alert_messages = []
            for alert in report_data:
                # Only alert if malicious count > 0
                if alert['vt_malicious_count'] > 0 or alert['vt_suspicious_count'] > 0:
                    alert_messages.append(
                        f"⚠️ *Incident Alert:*\n"
                        f"• Time: {alert['timestamp']}\n"
                        f"• User: {alert['username']}\n"
                        f"• IP: {alert['ip']}\n"
                        f"• Workstation: {alert['workstation']}\n"
                        f"• VirusTotal Malicious: {alert['vt_malicious_count']}\n"
                        f"• VirusTotal Suspicious: {alert['vt_suspicious_count']}"
                    )
            if alert_messages:
                full_message = "\n\n".join(alert_messages)
                if SLACK_WEBHOOK_URL:
                    send_slack_alert(full_message, SLACK_WEBHOOK_URL)
                    print("✅ Slack alert sent.")
                else:
                    print("⚠️ Slack webhook URL not set in .env")

            save_to_csv(report_data)
            save_to_json(report_data)
            print(f"✅ {len(report_data)} alerts saved to alerts.csv and alerts.json")
        else:
            print("⚠️ No alerts to report.")

    except FileNotFoundError:
        print(f"❌ Error: The file '{log_file}' was not found.")
    except Exception as e:
        print(f"❌ An error occurred: {e}")
