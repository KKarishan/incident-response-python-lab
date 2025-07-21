# ❗ Troubleshooting: SCP File Transfer Issues

### ❌ **Error:** Cannot Copy File via SCP

**Command Used:**

```bash
scp C:\failed_logins.txt kali@192.168.0.194:/home/kali/logs/
```

**Error Message:**

```
ssh: connect to host 192.168.0.194 port 22: Connection refused
scp: Connection closed
```

---

### 🛠️ **Cause:**

The SSH server on the Kali machine is either **not installed** or **not running**, so SCP cannot connect via port 22.

---

### ✅ **Solution Steps:**

1. **Install SSH server on Kali:**

   ```bash
   sudo apt update
   sudo apt install openssh-server -y
   ```

2. **Start and enable SSH:**

   ```bash
   sudo systemctl enable ssh
   sudo systemctl start ssh
   ```

3. **(Optional) Allow SSH through firewall:**

   ```bash
   sudo ufw allow ssh
   ```

4. **Ensure destination folder exists:**

   ```bash
   mkdir -p /home/kali/logs
   ```

5. **Retry SCP transfer:**

   ```bash
   scp C:\failed_logins.txt kali@192.168.0.194:/home/kali/logs/
   ```
