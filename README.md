# 🛡️ Enterprise Honeypot Platform v2.0
### Cloud-Native Threat Intelligence & Detection System
**Author:** Loki | **Platform:** AWS eu-central-1 | **Version:** T-Pot 24.04.1

---

## 📊 Live Statistics
- 🍯 **38 Active Honeypots** running simultaneously
- 🌍 **Global Attack Coverage** across all protocols
- 🤖 **Automated Threat Intelligence** pipeline
- 📱 **Real-time Telegram Alerts** for critical threats
- 📄 **Daily PDF Reports** generated automatically

---

## 🏗️ Architecture
```
Internet (Attackers)
        │
        ▼
┌─────────────────────────────────┐
│         AWS EC2 (DMZ)           │
│  ┌─────────────────────────┐   │
│  │     T-Pot v24.04.1      │   │
│  │  38 Honeypot Containers │   │
│  │  Cowrie │ Dionaea │ ... │   │
│  └──────────┬──────────────┘   │
│             │                   │
│  ┌──────────▼──────────────┐   │
│  │    Suricata IDS/IPS     │   │
│  └──────────┬──────────────┘   │
│             │                   │
│  ┌──────────▼──────────────┐   │
│  │  Logstash → Elasticsearch│  │
│  │     Kibana Dashboard     │   │
│  └──────────┬──────────────┘   │
│             │                   │
│  ┌──────────▼──────────────┐   │
│  │  Intelligence Pipeline  │   │
│  │  VirusTotal │ AbuseIPDB │   │
│  │  MITRE ATT&CK Tagger    │   │
│  │  PDF Report Generator   │   │
│  │  Telegram Alerting      │   │
│  └─────────────────────────┘   │
└─────────────────────────────────┘
```

---

## 🍯 Honeypot Services

| Service | Protocol | Purpose |
|---------|----------|---------|
| Cowrie | SSH/Telnet | Credential capture & command logging |
| Dionaea | SMB/HTTP/FTP | Malware capture |
| Elasticpot | HTTP/9200 | Fake Elasticsearch |
| Redishoneypot | Redis/6379 | Redis attack capture |
| Wordpot | HTTP | Fake WordPress |
| Mailoney | SMTP | Email attack capture |
| Medpot | DICOM | Medical device simulation |
| CiscoASA | HTTPS | Fake Cisco firewall |
| Conpot | ICS/SCADA | Industrial control systems |
| Heralding | Multi | Credential capture |
| Honeytrap | Any | Unknown protocol capture |
| +27 more | Various | Full protocol coverage |

---

## 🧠 Intelligence Pipeline

### 1. Attacker Enrichment (`enrichment.py`)
- Queries **VirusTotal API** for malware detections
- Queries **AbuseIPDB API** for abuse history
- Calculates **threat score 0-100**
- Classifies as LOW / MEDIUM / HIGH / CRITICAL
- Stores profiles in Elasticsearch

### 2. MITRE ATT&CK Tagger (`mitre_tagger.py`)
- Maps every attack event to MITRE ATT&CK framework
- Covers 20+ techniques across all tactics
- Enables heatmap visualization of attack patterns
- Framework version: ATT&CK v14

### 3. Real-time Alerting (`alerting.py`)
- Telegram alerts for HIGH and CRITICAL threats
- Hourly attack summary reports
- TOR exit node detection
- ISP and geolocation context

### 4. PDF Report Generator (`report_generator.py`)
- Professional threat intelligence reports
- Generated automatically every 24 hours
- Delivered via Telegram
- Covers: threat actors, MITRE tactics, geographic distribution

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Cloud | AWS EC2 |
| OS | Ubuntu Server 22.04 |
| Honeypot Platform | T-Pot 24.04.1 |
| IDS | Suricata 7.x |
| SIEM | Elasticsearch 9.x + Kibana |
| Log Pipeline | Logstash + Filebeat |
| Threat Intel | VirusTotal + AbuseIPDB APIs |
| Framework | MITRE ATT&CK v14 |
| Automation | Python 3.x + systemd |
| Alerting | Telegram Bot API |
| Reporting | ReportLab PDF |
| IaC | Terraform |

---

## 📁 Project Structure
```
├── scripts/
│   ├── enrichment.py        # Attacker profiling pipeline
│   ├── alerting.py          # Telegram alert system  
│   ├── mitre_tagger.py      # MITRE ATT&CK auto-tagger
│   └── report_generator.py  # PDF report generator
├── docs/
│   └── architecture.md      # Detailed architecture docs
├── systemd/
│   ├── tpot-enrichment.service
│   ├── tpot-alerting.service
│   ├── tpot-mitre.service
│   └── tpot-reports.service
└── README.md
```

---

## 🚀 Deployment

### Prerequisites
- AWS Account
- Ubuntu Server 22.04
- 8GB RAM minimum
- VirusTotal API key (free)
- AbuseIPDB API key (free)
- Telegram Bot token (free)

### Quick Start
```bash
# Clone T-Pot
git clone https://github.com/telekom-security/tpotce
cd tpotce
sudo ./install.sh

# Clone this repo
git clone https://github.com/YOUR_USERNAME/enterprise-honeypot
cd enterprise-honeypot

# Configure API keys
cp .env.example .env
nano .env

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Deploy services
sudo systemctl enable tpot-enrichment tpot-alerting tpot-mitre tpot-reports
sudo systemctl start tpot-enrichment tpot-alerting tpot-mitre tpot-reports
```

---

## 📊 Sample Findings

Based on 24-hour deployment data:
- **Top attacking countries:** United States, China, Russia, Netherlands
- **Most targeted service:** SSH (Cowrie) — 60%+ of all attacks
- **Dominant MITRE tactic:** Credential Access (T1110)
- **Average threat score:** 45/100
- **Critical threats detected:** Multiple known botnet IPs

---

## ⚠️ Legal & Ethical Notice

This platform is deployed for **defensive security research only**.
All data collected is used solely for threat intelligence and academic purposes.
Honeypot deployment complies with AWS acceptable use policy.

---

## 📬 Contact

- **LinkedIn:** linkedin.com/in/hsen-reslan-ba4284314/
- **Portfolio:** hsenr.github.io
- **GitHub:** github.com/hsenr
