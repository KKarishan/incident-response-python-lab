# 🛡️ Incident Response Automation Lab using Python & Kali Linux


`incident-response-python-lab` readme file includes project overview, structure, setup instructions, lab guide references, and screenshots.

---

````markdown
# 🛡️ Incident Response Automation Lab with Python

Welcome to the **Incident Response Python Lab** — a 5-day student-friendly hands-on lab designed to teach you how to automate the incident response lifecycle using Python. You'll work with real log files, parse suspicious data, enrich with VirusTotal, generate actionable reports, and even integrate with Slack for real-time alerts.

---

## 📚 Project Overview

This lab guides students through:

1. **Windows Event Log Collection**
2. **Log Parsing with Python**
3. **IOC (Indicator of Compromise) Enrichment using VirusTotal**
4. **Alert Report Generation**
5. **Slack Notification Integration**

Each day focuses on one core part of the incident response pipeline and includes practical scripts, JSON/CSV outputs, and step-by-step guides.

---

## 📁 Project Structure

```plaintext
incident-response-python-lab/
├── README.md
├── guide/
│   ├── day1_windows-log-collection.md
│   ├── day2_log-parsing.md
│   ├── day3_ioc-enrichment.md
│   ├── day4_report-generation.md
│   └── day5_slack-integration.md
├── scripts/
│   ├── parse_logs.py
│   ├── virustotal_enrich.py
│   ├── generate_report.py
│   └── incident_response.py  # Day 5 combined pipeline
├── logs/
│   ├── failed_logins.txt
│   ├── parsed_log.json
│   ├── enriched_iocs.json
│   └── extracted_ips.json
├── reports/
│   ├── alerts.csv
│   └── alerts.json
├── .env.sample
├── .gitignore
└── assets/
    └── screenshots/
        ├── day_01/day01_scp_fix.png
        ├── day_03/day03_virustotal_run.png
        ├── day_04/day04_alert_csv_excel.png
        └── day_05/day05_report_script_run.png
````
---

## 📚 Background & Key Concepts

Understand **why** this lab matters and how it connects to **real-world cybersecurity work**.


### ❓ What is an IOC?

> **IOC (Indicator of Compromise)** is any data or artifact that suggests a system may have been breached. Common IOCs include suspicious IP addresses, domain names, file hashes, unusual process behavior, or login anomalies.


---

### ❓ Why / What is the benefit of an IOC?

> **The benefit of IOCs** is that they help security teams **detect and respond to threats faster**. By identifying known indicators, SOC (Security Operations Center) analysts can:
>
> * Block malicious IPs or domains
> * Trace back the origin of an attack
> * Understand the scope and impact
> * Prevent similar attacks in the future


---

### ❓ How can we use IOCs?

> IOCs are used in various security tools and workflows:
>
> * **SIEMs** (like Splunk or Elastic) to match against logs.
> * **Threat intelligence platforms** to enrich and verify indicators.
> * **Incident response scripts or automation**, like this lab, to correlate IOCs with log files and trigger alerts.


---

### ❓ How does this help in the daily life of a SOC Analyst?

> SOC analysts deal with massive amounts of log data. Automation using IOCs:
>
> * **Reduces manual effort**
> * **Flags only relevant activity**
> * **Helps prioritize alerts**
> * **Improves Mean Time to Detect (MTTD)** and **Respond (MTTR)**
>
> This lab simulates the exact process analysts follow — from collecting logs to raising alerts.


---

### ❓ What are the benefits of doing this lab?

> This hands-on lab builds **real-world incident response skills**, including:
>
> * Collecting and parsing logs from compromised machines
> * Enriching IPs using threat intelligence (VirusTotal)
> * Automating alert generation
> * Sending real-time notifications to Slack
>
> It gives students a chance to simulate what a SOC analyst does on a daily basis using open tools and Python.


---

### ❓ What are the findings from the automation?

> Depending on your test data, the script may find:
>
> * IP addresses linked to failed login attempts
> * VirusTotal results showing whether any IPs are malicious
> * Alerts generated for any detected threats
>
> 🛠️ *In a real environment*, these results would help an analyst quickly pinpoint where action is needed (blocking IPs, initiating further investigation, etc.).

---

## 🚀 Getting Started

### ✅ Prerequisites

* Python 3.9+
* Access to a Kali Linux VM & Windows 10/11 VM (for Day 1)
* VirusTotal API Key
* Slack workspace (for Day 5)

### 📦 Install Dependencies

First, clone this repo:

```bash
git clone https://github.com/yourusername/incident-response-python-lab.git
cd incident-response-python-lab
```

Then install Python dependencies:

```bash
pip install -r requirements.txt
```

Contents of `requirements.txt`:

```txt
pandas==2.0.3
requests==2.31.0
python-dotenv==1.0.0
```

### 🔐 Setup Environment Variables

Create a `.env` file based on the `.env.sample` template:

```bash
cp .env.sample .env
```

Update `.env` with your keys:

```env
VT_API_KEY=your_virustotal_api_key_here
SLACK_WEBHOOK_URL=your_slack_webhook_url_here
```

---

## 📘 Lab Guide (Daily Breakdown)

| Day | Topic                          | Guide Link                                          |
| --- | ------------------------------ | --------------------------------------------------- |
| 1️⃣ | Windows Log Collection         | [Day 1 Guide](/guide/day1_windows_log_collection.md) |
| 2️⃣ | Log Parsing with Python        | [Day 2 Guide](/guide/day2_log_parsing.md)            |
| 3️⃣ | IOC Enrichment with VirusTotal | [Day 3 Guide](/guide/day3_ioc_enrichment.md)         |
| 4️⃣ | Report Generation              | [Day 4 Guide](/guide/day4_report_generation.md)      |
| 5️⃣ | Slack Alerts Integration       | [Day 5 Guide](/guide/day5_integrate_slack.md)      |

---

## 🖼️ Screenshots

All screenshots are stored in the `assets/screenshots/day_0*` folder. Use them while going through each guide.

Example:

```markdown
![VirusTotal Script Run](/incident-response-python-lab/assets/screenshots/day_03/day03_script_running_enrichment.png)
```
![VirusTotal Script Run](/incident-response-python-lab/assets/screenshots/day_03/day03_script_running_enrichment.png)

| Screenshot                   | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `day1_scp_fix.png`           | Shows SCP troubleshooting on Kali             |
| `day2_parsing_output.png`    | Terminal output of parsed logs                |
| `day3_virustotal_run.png`    | VirusTotal enrichment confirmation            |
| `day4_alert_csv_excel.png`   | Alerts report opened in Excel                 |
| `day4_report_script_run.png` | CLI output after running `generate_report.py` |

---

## ⚠️ Testing Without Real Malicious Data

> **Note**
> Since this project is being tested in a home lab environment, it's possible that no **malicious IP addresses** will be detected from VirusTotal.
>
> To manually test Slack alert functionality:
>
> * Add a fake malicious IP entry manually to the `parsed_log.json` or `enriched_iocs.json`.
> * Run the `test_slack_alert.py` script.
>
> This will trigger a sample alert and help verify your Slack integration is working correctly.

---

## 📌 .gitignore Usage

Your `.gitignore` file ensures that sensitive and unnecessary files are **not committed** to Git.

### ✅ Common entries:

```gitignore
.env
__pycache__/
*.pyc
*.log
venv/
reports/*.csv
reports/*.json
.DS_Store
```

---

## 🧠 Learn More

* [VirusTotal API Docs](https://developers.virustotal.com/reference/overview)
* [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
* [pandas Documentation](https://pandas.pydata.org/docs/)
* [Python Dotenv](https://pypi.org/project/python-dotenv/)

---

## 🧑‍💻 Contributors

Created and maintained by students and instructors for cybersecurity automation training.
