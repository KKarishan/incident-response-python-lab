# Day 2: Log Parsing with Python

## 🎯 **Objective**

Parse Windows `Event ID 4625` logs (`failed_logins.txt`) using Python to extract:

* 🕒 Timestamps
* 👤 Usernames
* 🖥️ Workstation names
* 🌐 IP addresses

Store results in a structured JSON format for further analysis.

---

## 📋 **Prerequisites**

✅ Completed [**Day 1: Windows Log Collection**](../guide/day1_windows-log-collection.md)
✅ `failed_logins.txt` file exists in your working directory
✅ Python **3.10+** installed
✅ Familiarity with **regular expressions**

---

## 📝 **Step-by-Step Guide**

### 1️⃣ Understand the Log Structure

A sample log from `failed_logins.txt` looks like:

```
Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Event ID: 4625
  Level: Information
  ...
  Time Created: 2025-07-03T14:32:00.123456Z
  ...
  Computer: DESKTOP-01
  ...
    Account For Which Logon Failed:
      Account Name: admin
    ...
    Network Information:
      Source Network Address: 192.168.1.10
```

### 🔍 Key Fields to Extract:

| Field           | Example                    | Regex Pattern                       |
| --------------- | -------------------------- | ----------------------------------- |
| **Timestamp**   | `2025-07-03T14:32:00.123Z` | `Time Created: (.+?)Z`              |
| **Username**    | `admin`                    | `Account Name:\s+(.+?)\n`           |
| **IP Address**  | `192.168.1.10`             | `Source Network Address:\s+(.+?)\n` |
| **Workstation** | `DESKTOP-01`               | `Computer:\s+(.+?)\n`               |

---

### 2️⃣ Create `parse_logs.py` Script

📁 **Location:** `incident-response-python-lab/scripts/parse_logs.py`

```python
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
```

---

### 3️⃣ Run the Script

```bash
cd incident-response-python-lab/scripts
python3 parse_logs.py
```

#### ✅ Expected Output:

```json
[
  {
    "timestamp": "2025-07-03 14:32:00",
    "username": "admin",
    "ip": "192.168.1.10",
    "workstation": "DESKTOP-01"
  }
]
```

Also generates:

* `parsed_log.json`
* `extracted_ips.json`

---

### 4️⃣ Validate & Debug

#### 🛠️ Issue: Log file not found

* Make sure it's in the correct folder
* Or specify the full path manually in the code

#### 🧪 Issue: Regex mismatch

* Use `print("Raw Event:", event)` to debug
* Validate your regex with [regex101.com](https://regex101.com)

---

## 🔗 References

* [Python `re` Documentation](https://docs.python.org/3/library/re.html)
* [Regex Tester](https://regex101.com)
* [Windows Event ID 4625 Details](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
