import json
import os
import requests
from dotenv import load_dotenv
from parse_logs import parse_failed_logins, extract_ips

# Load API key from .env
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

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

if __name__ == "__main__":
    log_file = input("Enter the log file to parse (e.g., failed_logins.txt): ").strip()
    logs = parse_failed_logins(log_file)
    ips = extract_ips(logs)
    print("Extracted IPs:", ips)

    if not API_KEY:
        print("API key not found in .env")
        exit()

    enriched = enrich_iocs(ips, API_KEY)
    with open("enriched_iocs.json", "w") as f:
        json.dump(enriched, f, indent=2)

    print("Enriched IOC data saved to enriched_iocs.json")
