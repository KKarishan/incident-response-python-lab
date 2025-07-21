import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def load_parsed_logs():
    with open("parsed_log.json") as f:
        return json.load(f)

def load_enriched_iocs():
    with open("enriched_iocs.json") as f:
        return json.load(f)

def send_slack_alert(message, webhook_url):
    payload = {
        "text": message
    }
    try:
        response = requests.post(webhook_url, json=payload)
        if response.status_code == 200:
            print("✅ Slack message sent!")
        else:
            print(f"❌ Slack error: {response.status_code} - {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Slack request failed: {e}")

def generate_alerts(parsed_logs, enriched_iocs):
    alerts = []
    for log in parsed_logs:
        ip = log.get("ip")
        match = next((e for e in enriched_iocs if e["ip"] == ip), None)
        if match and match.get("malicious", 0) > 0:
            alerts.append({
                "timestamp": log.get("timestamp"),
                "ip": ip,
                "user": log.get("username"),
                "workstation": log.get("workstation"),
                "malicious_count": match["malicious"]
            })
    return alerts

def main():
    if not SLACK_WEBHOOK_URL:
        print("❌ Slack webhook URL missing in .env")
        return

    parsed_logs = load_parsed_logs()
    enriched_iocs = load_enriched_iocs()

    alerts = generate_alerts(parsed_logs, enriched_iocs)

    if not alerts:
        print("⚠️ No malicious alerts found.")
        return

    for alert in alerts:
        message = (
            f"🚨 *Malicious Login Attempt Detected!*\n"
            f"• User: `{alert['user']}`\n"
            f"• IP: `{alert['ip']}` (Malicious: {alert['malicious_count']})\n"
            f"• Time: {alert['timestamp']}\n"
            f"• Host: {alert['workstation']}"
        )
        print("📤 Sending Slack alert...")
        send_slack_alert(message, SLACK_WEBHOOK_URL)

if __name__ == "__main__":
    main()
