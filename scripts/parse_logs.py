import re
import json
from pprint import pprint

def read_file_with_fallback(filepath):
    try:
        # Try UTF-8 first
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            # Try UTF-16 (common for Windows Event Log exports)
            with open(filepath, 'r', encoding='utf-16') as f:
                return f.read()
        except UnicodeDecodeError:
            # Try Windows encoding
            with open(filepath, 'r', encoding='cp1252') as f:
                return f.read()

def parse_failed_logins(log_file):
    log_data = read_file_with_fallback(log_file)

    # Split logs into individual events
    events = re.split(r'Event\[\d+\]:', log_data)[1:]  # Skip first empty split

    parsed_logs = []

    for event in events:
        log_entry = {}

        # Extract timestamp
        timestamp_match = re.search(r'Date: (.+?)Z', event)
        if timestamp_match:
            timestamp = timestamp_match.group(1).replace('T', ' ')
            log_entry["timestamp"] = timestamp.split('.')[0]  # remove microseconds

        # Extract username
        username_match = re.search(r'Account For Which Logon Failed:\s+.*?Account Name:\s+(.+?)\n', event, re.DOTALL)
        if username_match:
            log_entry["username"] = username_match.group(1).strip()

        # Extract IP address
        ip_match = re.search(r'Source Network Address:\s+(.+?)\s*$', event, re.MULTILINE)
        if ip_match:
            ip = ip_match.group(1).strip()
            log_entry["ip"] = ip if ip and ip != '-' else None
        else:
            log_entry["ip"] = None

        # Extract workstation name
        workstation_match = re.search(r'Computer: (.+?)\n', event)
        if workstation_match:
            log_entry["workstation"] = workstation_match.group(1).strip()

        parsed_logs.append(log_entry)

    return parsed_logs

# NEW FUNCTION: Extract IPs from parsed logs
def extract_ips(logs):
    return [log["ip"] for log in logs if log["ip"]]

if __name__ == "__main__":
    log_file = input("Enter the log file name (e.g., failed_logins.txt): ").strip()

    try:
        logs = parse_failed_logins(log_file)
        pprint(logs)

        # Save parsed logs
        with open("parsed_log.json", "w") as f:
            json.dump(logs, f, indent=2)
        print("Parsed log saved to parsed_log.json")

        # Extract and display IPs
        ips = extract_ips(logs)
        print("\nExtracted IPs:", ips)

        # Save IPs to file
        with open("extracted_ips.json", "w") as f:
            json.dump(ips, f, indent=2)
        print("Extracted IPs saved to extracted_ips.json")

    except FileNotFoundError:
        print(f"Error: The file '{log_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
