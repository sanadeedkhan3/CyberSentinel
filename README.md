# 🛡 CyberSentinel
### AI-Powered Behavioral Network Threat Detector with LLM Explainability

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=flat&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat)

> **The first open-source network security tool that combines behavioral AI anomaly detection with real-time LLM-generated plain-English threat explanations.**

Most security tools tell you what happened. CyberSentinel tells you what it means and what to do — in language anyone can understand.

---

## What Makes This Different

| Traditional Tools | CyberSentinel |
|---|---|
| Detect known threats using signature databases | Detects unknown threats by learning behavioral baselines |
| Output cryptic alerts: anomaly_score: 0.87 | Output plain English: "Device sent 3,400 packets in 8 seconds — 10x its normal rate. Pattern matches data exfiltration." |
| Cost $50,000+/year (Darktrace, Vectra AI) | Free and open-source |
| Require security expertise to interpret | Understandable by anyone |

---

## Features

### AI Detection Engine
- Isolation Forest machine learning — detects anomalies without needing examples of attacks
- Behavioral baseline profiling — learns what normal looks like per device over time
- 9-feature analysis per 30-second traffic window
- Detects: Port Scans, Data Exfiltration, DDoS, ICMP Floods, Lateral Movement, C2 Communication

### LLM Explainability (Unique Feature)
- Every alert explained in plain English by Claude AI
- Tells you what happened, why it is suspicious, and what to do
- Works with or without API key (rule-based fallback included)

### Live Dashboard
- Real-time packet capture stats and traffic charts
- Full alert feed with search, filter by severity/type/time, and sort
- IP Inspector — click any IP to see its full activity history
- Threat heatmap showing attack patterns by hour and day

### Security and Access Control
- Login system with PBKDF2-SHA256 password hashing (260,000 iterations)
- Brute force protection — lockout after 5 failed attempts
- Session management with 8-hour auto-expiry
- Full login audit log with IP address tracking
- User management — add, disable, delete users

### Active Response
- Block suspicious IPs directly from the dashboard
- Applies real Windows Firewall / iptables rules
- One-click unblock from the Blocked IPs page

### Alerting and Reporting
- Email alerts for High/Critical threats (Gmail SMTP)
- Professional PDF security reports (24h or 7-day)
- Desktop popup notifications
- CSV export of filtered alerts

---

## Architecture

```
Network Traffic
      |
      v
Layer 1: Packet Capture Engine      Scapy + SQLite
      |
      v
Layer 2: Feature Engineering        30-second windows, 9 features per device
      |
      v
Layer 3: Behavioral Baseline        Per-device learning, mean + std deviation
      |
      v
Layer 4: Isolation Forest AI        scikit-learn, scores 0.0 to 1.0
      |
      v
Layer 5: LLM Explainability         Claude API, plain-English explanations
      |
      v
Layer 6: Live Dashboard             Flask + Chart.js + email + PDF
```

---

## Quick Start

### Requirements
- Python 3.11+
- Windows (with Npcap), Linux, or macOS
- Administrator/root privileges for packet capture

### Installation

```bash
git clone https://github.com/SanadeedKhan/cybersentinel
cd cybersentinel
pip install -r requirements.txt
cp .env.example .env
# Edit .env and add your API key and email settings
python main.py
# Visit http://127.0.0.1:5000
# Default login: admin / CyberSentinel2024!
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet capture | Scapy 2.5 |
| Database | SQLite |
| Machine learning | scikit-learn Isolation Forest |
| AI explanations | Anthropic Claude API |
| Web framework | Flask 3.0 |
| Charts | Chart.js 4.4 |
| PDF generation | ReportLab |
| Authentication | Custom PBKDF2-SHA256 |

---

## Ethical Notice

CyberSentinel is designed for use on networks you own or have explicit permission to monitor. Unauthorized network monitoring is illegal. This tool is intended for home network security, authorized corporate security, and educational purposes only.

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

Built by Sanadeed Khan as a cybersecurity portfolio project demonstrating behavioral AI security concepts used by enterprise tools like Darktrace and Vectra AI.