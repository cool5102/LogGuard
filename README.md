# 🛡️ LogGuard v2 – AutoBan Edition

**Advanced Log Analysis & Intrusion Prevention Tool**  
Detects brute-force login attempts from system logs and automatically blocks suspicious IPs using the firewall.

**Author:** Dilshad – [GitHub](https://github.com/cool5102) | [LinkedIn](https://linkedin.com/in/dilshad-tech)

---

## 🚀 Overview

**LogGuard** is a Python-based **security automation tool** designed to protect systems from **remote login brute-force attacks**.  
It scans authentication logs (SSH, RDP, FTP, etc.), identifies repeated failed login attempts, and optionally **auto-blocks** the attacking IPs using the system’s built-in firewall (`ufw`, `iptables`, or `netsh`).

It’s a practical mini version of tools like **Fail2Ban**, built entirely with Python’s standard library.

---

## 🔒 What LogGuard Protects

| System | Log File | Common Target | Example |
|:-------|:----------|:---------------|:---------|
| **Linux (Ubuntu/Debian)** | `/var/log/auth.log` | SSH brute-force attacks | `Failed password for root from 45.83.123.9` |
| **Linux (CentOS/RHEL)** | `/var/log/secure` | SSH, FTP, su, sudo | same pattern |
| **Windows** | Exported `Security` logs (TXT/CSV) | RDP, SMB, local logins | “failed logon attempt” |
| **macOS** | `/var/log/system.log` | SSH logins | same pattern |

**In short:** LogGuard monitors remote login systems (SSH/RDP) to detect and block unauthorized access attempts before they succeed.

---

## ⚙️ Features

- 🔍 Detects repeated failed login attempts (brute-force pattern)
- 🧠 Configurable threshold & time window
- 💾 Exports suspicious IPs to CSV report
- 🔥 Auto-ban attackers via OS firewall
- 🧰 Works on Linux, Windows, and macOS
- 🪶 Lightweight — no external dependencies
- 🧑‍💻 Perfect for Python + cybersecurity portfolios

---

## 🧩 Requirements

- **Python 3.7+**
- Administrator/root privileges (for auto-ban)
- Log files with failed login events

No external modules needed — everything uses Python’s standard library.

---

## 📦 Installation

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-tk -y

git clone https://github.com/cool5102/LogGuard.git
cd LogGuard
python3 -m venv venv
source venv/bin/activate



LogGuard — Simple user guide

Make it easy for anyone to run LogGuard v2 (AutoBan), test it with a sample log, and understand what happens. Below are short, clear step-by-step instructions for Windows (PowerShell) and Linux/macOS (bash).


# 1) Go to your LogGuard folder (change path if needed)
cd E:\PythonLab\py-Files\LogGuard

# 2) Create a sample auth log (paste exactly)
@"
Jan 12 13:05:23 server sshd[1332]: Failed password for root from 192.168.1.44 port 55874 ssh2
Jan 12 13:05:25 server sshd[1332]: Failed password for root from 192.168.1.44 port 55875 ssh2
Jan 12 13:05:27 server sshd[1332]: Failed password for root from 192.168.1.44 port 55876 ssh2
Jan 12 13:06:15 server sshd[1222]: Failed password for invalid user admin from 45.83.123.9 port 55890 ssh2
Jan 12 13:06:17 server sshd[1222]: Failed password for invalid user admin from 45.83.123.9 port 55891 ssh2
Jan 12 13:06:20 server sshd[1222]: Failed password for invalid user admin from 45.83.123.9 port 55892 ssh2
"@ > .\sample_auth.log

# 3) Run detection-only (no firewall changes)
python logguard_autoban.py .\sample_auth.log

# 4) OPTIONAL - to enable auto-blocking (requires Admin PowerShell)
# Open PowerShell as Administrator, then run:
# python logguard_autoban.py .\sample_auth.log --autoban

# 5) See generated reports
dir .\results
Get-Content .\results\logguard_autoban_*.csv

# 6) If you used --autoban and want to remove a Windows firewall rule manually:
# (run in Admin PowerShell)
# netsh advfirewall firewall delete rule name="LogGuardBlock_192.168.1.44"

