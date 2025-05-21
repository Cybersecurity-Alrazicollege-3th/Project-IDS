#Project-IDS

# 🛡️ Bash Intrusion Detection System (Simple IDS)

## 🔍 Overview

This is a **lightweight, host-based intrusion detection system (HIDS)** written in Bash.  
It provides basic monitoring for:

- Critical file existence
- Suspicious process names
- Logging and terminal alerts

⚠️ This script is **not a full replacement** for advanced IDS solutions. It is mainly for learning, small systems, or initial detection needs.

---

## 📁 Project Structure

- `bash_ids.sh` → Main IDS script
- `ids_config.sh` → Configuration file (to be created by the user)
- `bash_ids.log` → Default log file (location configurable)

---

## ⚙️ How It Works

- Monitors if **sensitive files** (e.g., `/etc/shadow`) exist.
- Scans running processes for **suspicious names** (e.g., `ncat`, `netcat`, `reverse`).
- Logs every alert with a timestamp, alert type, source, and message.
- Runs in a loop with a configurable scan interval.

---

## 🛠️ Setup

1. **Clone or copy the script** to your system:

```bash
git clone https://github.com/your-username/bash-ids.git
cd bash-ids
chmod +x bash_ids.sh

# ids_config.sh

# Log file path
LOG_FILE="/var/log/bash_ids.log"

# Scan interval in seconds
CHECK_INTERVAL=30

# List of sensitive files to monitor
SENSITIVE_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/usr/bin/sudo"
)

# Suspicious process names to monitor (case-insensitive)
SUSPICIOUS_PROCS=(
    "ncat"
    "netcat"
    "reverse"
    "msfconsole"
)

sudo ./bash_ids.sh

2025-05-21 14:12:00 - [SYSTEM_INFO] - [BashIDS] - Log file: /var/log/bash_ids.log
2025-05-21 14:12:30 - [HIDS_ALERT] - [FileMonitor] - Sensitive file not found: /etc/shadow
2025-05-21 14:12:31 - [HIDS_ALERT] - [ProcessMonitor] - Suspicious process found: PID:1234, User:root, Cmd: ncat -lvnp 4444 (match: ncat)

🚨 Features
✅ Modular structure with logging

✅ File and process monitoring

✅ Real-time alerting to console and log

❌ No network traffic monitoring

❌ No historical state tracking (e.g., PID persistence)

❌ No GUI or alerting integrations (email, Slack, etc.)

⚠️ Warnings
This script does not support advanced behavioral analysis.

Does not persist state across reboots or scans.

For production environments, consider tools like OSSEC, Wazuh, or Snort.

📄 License
MIT License — use it freely, but at your own risk.

🙏 Acknowledgements
This tool is inspired by the need for basic, auditable security monitoring using minimal Bash scripting — especially for minimal or embedded Linux systems.


---

Let me know if you'd like a translated Arabic version or want to include setup instructions for cron or systemd service.
