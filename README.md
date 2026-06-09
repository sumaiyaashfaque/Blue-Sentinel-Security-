# 🛡️ BlueSentinel — Blue Team Security Suite

> A unified cybersecurity monitoring tool combining File Integrity Monitoring, 
> Intrusion Detection, and Firewall Auditing into one professional dashboard.

---

## 📌 Overview

BlueSentinel is a Python-based Blue Team security suite built for learning, 
portfolio demonstration, and real-world defensive security practice.

It simulates tools used by SOC Analysts and Security Engineers in real companies 
like IBM QRadar, Splunk, and OSSEC.

---

## 🗂️ Project Structure

```
Blue_Team_Suite/
│
├── core/
│   ├── file_monitor.py       # File integrity engine (SHA-256 hashing)
│   ├── ids_engine.py         # Network intrusion detection (Scapy)
│   └── firewall_checker.py   # Firewall rule auditor (iptables)
│
├── dashboard/
│   └── app.py                # Main CLI dashboard (entry point)
│
├── reports/
│   ├── alert_log.txt         # Auto-generated threat alerts
│   └── firewall_audit_report.txt  # Firewall audit reports
│
├── config/
│   └── settings.json         # All configuration in one place
│
└── README.md
```

---

## ⚙️ Features

### 🔥 File Integrity Monitor
- Creates SHA-256 hash baseline of any directory
- Detects modified, deleted, or newly added files
- Supports real-time continuous monitoring
- Logs all changes with timestamps

### 🚨 Intrusion Detection System (IDS)
- Captures live network packets using Scapy
- Detects connections to suspicious ports (Metasploit, Telnet, RDP, etc.)
- Identifies port scanning activity
- Detects ICMP flood attacks
- Includes simulation mode (no root required)

### 🧱 Firewall Rule Checker
- Audits iptables rules for misconfigurations
- Assigns severity levels (CRITICAL / HIGH / MEDIUM)
- Calculates overall firewall risk score (0–100)
- Generates professional audit reports
- Works on Linux (live) or any OS (simulation mode)

---

## 🚀 Getting Started

### Requirements
- Python 3.8+
- Linux (recommended) or Windows with WSL
- Kali Linux (for full IDS functionality)

### Install Dependencies
```bash
pip install scapy
```

### Run the Dashboard
```bash
cd Blue_Team_Suite
python dashboard/app.py
```

### Run Individual Modules
```bash
# File Monitor only
python core/file_monitor.py

# IDS Engine only  
python core/ids_engine.py

# Firewall Checker only
python core/firewall_checker.py
```

---

## 🧪 Testing Without Root

All three modules support **simulation mode** — no root, no network access needed.
Perfect for testing, demos, and portfolio presentations.

---

## 📊 Alert Levels

| Icon | Level    | Meaning                          |
|------|----------|----------------------------------|
| 🔴   | CRITICAL | Immediate threat detected        |
| 🟠   | HIGH     | Serious misconfiguration/risk    |
| 🟡   | WARNING  | Suspicious activity              |
| 🟢   | SAFE     | No issues found                  |
| 🔵   | INFO     | System status update             |

---

## 🎯 Skills Demonstrated

- Python scripting for security automation
- Network packet analysis (Scapy)
- Cryptographic hashing (SHA-256)
- Firewall configuration auditing
- Log analysis and alert generation
- Modular software architecture
- SOC analyst workflow simulation

---

## ⚠️ Disclaimer

This tool is built **for educational purposes only**.  
Only use on systems and networks you **own or have explicit permission** to test.  
Unauthorized use is illegal and unethical.

---

## 👤 Author
**Sumaiya**  
Cybersecurity Student | Aspiring SOC Analyst  
[https://www.linkedin.com/in/sumaiya-ashfaque-429732387?utm_source=share_via&utm_content=profile&utm_medium=member_android  ](#) | [GitHub](#)

---

## 📄 License

MIT License — free to use and modify for personal learning.
