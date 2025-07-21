# **Day 5 Add-on: Integrate Slack Alerts for Incident Response**

## 🎯 **Objective**

* Send real-time incident alerts to a Slack channel whenever malicious IPs are detected in your incident response pipeline.
* Automate notification to your security team for faster response.

---

## 📝 **Step-by-Step Guide**

### **1️⃣ Create a Slack App & Incoming Webhook**

1. Go to [Slack API Apps page](https://api.slack.com/apps) and click **Create New App**.
2. Choose **From scratch**, name your app (e.g., `IncidentResponseBot`), and select your Slack workspace.
3. Under **Features**, click **Incoming Webhooks**.
4. Toggle **Activate Incoming Webhooks** to ON.
5. Scroll down and click **Add New Webhook to Workspace**.
6. Select the channel where you want alerts posted (e.g., `#security-alerts`) and click **Allow**.
7. Copy the **Webhook URL** generated. It will look like:

   ```
   https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
   ```

![day05_slack_create_app](../assets/screenshots/day_05/day05_slack_create_app.png)

---

### **2️⃣ Add Slack Webhook URL to `.env`**

* Open your `.env` file and add a new variable:

```ini
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
```

* If you don’t have `.env` yet, create `.env.sample` with this placeholder for others:

```ini
VT_API_KEY=your_virustotal_api_key_here
SLACK_WEBHOOK_URL=your_slack_webhook_url_here
```

![day03_env_api_key_setup](../assets/screenshots/day_03/day03_env_api_key_setup.png)

---

### **3️⃣ Update Your `incident_response.py` Script**

Add a new function to send messages to Slack:

```python
import requests

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
```

---

### **4️⃣ Integrate Slack Alert in Report Generation**

Inside your `__main__` section or right after generating the report (where you know malicious IPs are found), send a Slack alert.

Example modification (after `merge_data` and before saving reports):

```python
if report_data:
    # Send Slack alerts if Slack webhook URL is set
    alert_messages = []
    for alert in report_data:
        # Only alert if malicious count > 0
        if alert['vt_malicious_count'] > 0 or alert['vt_suspicious_count']> 0:
            alert_messages.append(
                f"⚠️ *Incident Alert:*\n"
                f"• Time: {alert['timestamp']}\n"
                f"• User: {alert['username']}\n"
                f"• IP: {alert['ip']}\n"
                f"• Workstation: {alert['workstation']}\n"
                f"• VirusTotal Malicious: {ale['vt_malicious_count']}\n"
                f"• VirusTotal Suspicious: {ale['vt_suspicious_count']}"
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
    print(f"✅ {len(report_data)} alerts saved to alerts.csv analerts.json")
else:
    print("⚠️ No alerts to report.")
```

---

### **5️⃣ Install Dependencies**

If you don't have `requests` installed, make sure your `requirements.txt` includes it:

```
requests==2.31.0
python-dotenv==1.0.0
pandas==2.0.3
```

Then install:

```bash
pip install -r requirements.txt
```

---

### **6️⃣ Test Your Slack Alerts**

1. Run your incident response script with sample logs containing malicious IPs.
2. Check your Slack channel for alert messages.
3. If no message appears, verify your webhook URL and internet connection.

---

## 🔍 **Summary**

| Step | Action                                               |
| ---- | ---------------------------------------------------- |
| 1    | Create Slack App & get webhook URL                   |
| 2    | Add `SLACK_WEBHOOK_URL` in `.env`                    |
| 3    | Add `send_slack_alert()` function                    |
| 4    | Send alerts to Slack when malicious IPs are detected |
| 5    | Update `requirements.txt` and install dependencies   |
| 6    | Run and verify alerts in Slack channel               |

---

## Optional: Example Slack Alert Message

```
⚠️ Alert:
Time: 2025-07-03 14:32:00
User: admin
IP: 192.168.1.10
Workstation: DESKTOP-01
VirusTotal Malicious Count: 5
```
![day05_sample_slack_alert](../assets/screenshots/day_05/day05_sample_slack_alert.png)
---

> **⚠️ Note:**  
> Since this project is being tested in a home lab environment, it's possible that no **malicious IP addresses** will be detected from VirusTotal. As a result, no alerts may appear in your Slack channel by default.  
>
> To manually test Slack alert functionality:
>
> - Add a fake malicious IP entry manually to the `parsed_log.json` and `enriched_iocs.json` data within the script.
> - Run the provided script: `test_slack_alert.py`  
>
> This will trigger a sample alert and help verify that your Slack integration is working correctly.


### parsed_log.json:
```json
  {
    "timestamp": "2025-07-10 14:00:00",
    "username": "testuser",
    "ip": "45.134.20.53",
    "workstation": "SLACK-HOME-PC"
  }
```
### enriched_iocs.json
```json
  {
    "ip": "45.134.20.53",
    "malicious": 5,
    "suspicious": 1,
    "harmless": 0
  }
```
![day05_test_parsed_iocs](../assets/screenshots/day_05/day05_test_parsed_iocs.png)

  