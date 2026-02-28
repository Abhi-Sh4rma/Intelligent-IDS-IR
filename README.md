🛡️ Intelligent IDS-IR (SOC Alert Dashboard)

A SOC-style Intrusion Detection and Incident Response (IDS-IR) pipeline built using Python, Windows Security Logs, PowerShell, and Flask.

This project monitors live Windows authentication logs inside a VM, detects brute-force attacks in real time, correlates suspicious behavior, and displays prioritized alerts in a web-based dashboard.

🚀 Project Overview

This system simulates a Security Operations Center (SOC) authentication monitoring workflow:

Collects Windows Security Event Logs

Normalizes authentication events

Detects brute-force patterns

Correlates failed + successful logins

Assigns dynamic risk scores

Displays prioritized alerts in a live dashboard

It focuses specifically on:

Event ID 4625 → Failed Logon

Event ID 4624 → Successful Logon

🏗️ Architecture
Windows VM
   ↓
PowerShell Log Extraction
   ↓
Python Log Parser & Normalizer
   ↓
Detection Engine (Brute Force + Correlation)
   ↓
Risk Scoring Engine
   ↓
Flask Web Dashboard (Auto Refresh)
🔍 Detection Logic
1️⃣ Brute-Force Detection (Time-Window Based)

Tracks multiple failed logons (Event ID 4625)

Uses configurable time windows

Detects threshold-based suspicious activity

Maintains stateful alert persistence

Example logic:

≥ X failed attempts within Y minutes → Trigger Alert

2️⃣ Success-After-Failure Correlation

If:

Multiple failed attempts occur
AND

A successful login (4624) follows

Then:

Escalate severity

Enrich alert with correlation details

This simulates real SOC attack-chain analysis.

3️⃣ Dynamic Risk Scoring

Each alert receives a risk score based on:

Number of failed attempts

Time window density

Whether login succeeded

Account type (if configured)

Repeated offender history

Risk score determines:

🟢 Low

🟡 Medium

🔴 High

🚨 Critical

📊 SOC Alert Dashboard

Built using Flask, the dashboard includes:

Real-time alert updates (auto-refresh)

Severity classification

Risk score display

Event correlation summary

Alert persistence

This mimics a lightweight SIEM-style monitoring panel.

🛠️ Tech Stack

Python 3.x

Windows Security Logs

PowerShell (Log Extraction)

Flask (Web Framework)

JSON/Structured Logs

📁 Project Structure
Intelligent-IDS-IR/
│
├── monitor.py              # Log collector & processor
├── detection_engine.py     # Brute-force + correlation logic
├── risk_scoring.py         # Dynamic scoring model
├── dashboard.py            # Flask app
├── templates/
│   └── index.html          # Web UI
└── logs/
    └── structured_logs.json
⚙️ Setup & Installation
1️⃣ Clone the Repository
git clone https://github.com/yourusername/intelligent-ids-ir.git
cd intelligent-ids-ir
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Run the Monitor
python monitor.py
4️⃣ Start Dashboard
python dashboard.py

Then open:

http://127.0.0.1:5000
🧪 Testing Scenario

To simulate brute-force:

Attempt multiple failed logins on the VM.

Observe Event ID 4625 entries.

Optionally log in successfully afterward.

Monitor real-time alert generation in dashboard.

🎯 Key Learning Outcomes

Windows Security Log Analysis

SOC-style Detection Engineering

Stateful Detection Pipelines

Correlation Logic Design

Risk Scoring Models

Flask-based Security Dashboards

Blue Team Attack Pattern Analysis

🔮 Future Improvements

Add email/SMS alerting

Integrate with ELK stack

Add IP reputation lookup

MITRE ATT&CK mapping

Multi-host log aggregation

Machine learning anomaly detection

🧠 Why This Project Matters

This project demonstrates practical skills required for:

SOC Analyst (Tier 1 / Tier 2)

Blue Team Engineer

Detection Engineer

SIEM Analyst

It replicates real-world authentication attack detection workflows used in enterprise environments.

📌 License

This project is for educational and research purposes
