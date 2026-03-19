🚀 SkynetOps — Azure VM Monitoring

SkynetOps is an SRE automation tool that monitors Azure VMs, detects issues, generates AI-based incident reports, and creates alerts via Email + ServiceNow.
SkynetOps is an advanced SRE automation tool that monitors Azure Virtual Machines in real-time, detects anomalies, generates AI-powered incident reports, and integrates with Email Alerts + ServiceNow for full incident lifecycle management.
Features
	•	Monitor CPU, Memory, Disk
	•	Auto alerts on threshold breach
	•	AI-powered incident analysis
	•	Email notifications (Azure-style)
	•	ServiceNow ticket automation
	•	Recovery detection (adds work notes)
	•	Forecasting & anomaly detection
🏗️ Architecture Overview
Azure Monitor → SkynetOps Engine → AI Analysis
        ↓                     ↓
   Metrics Fetch        Forecast Engine
        ↓                     ↓
   Threshold Check → Incident Creation
        ↓                     ↓
   Email Alerts      ServiceNow Tickets

Setup
	1.	Install dependencies:
        pip install -r requirements.txt
    2.	Configure secrets in Azure Key Vault:
		. Subscription, VM, Email, SMTP
		. CPU / Memory / Disk thresholds
	3.	(Optional) Add vms.json for multiple VMs + SSH

Run:
    python skynetops.py
Parallel mode:
    python skynetops.py --parallel

Alerts
	•	High CPU / Memory / Disk → Incident created
	•	VM Down → P1
	•	Telemetry Missing → P2
	•	Recovery → Email + note (no auto close)

📎 Attachments Generated
	•	📄 CSV (metrics + context)
	•	📈 Charts (CPU, Memory, Disk)
	•	🤖 AI analysis report
	•	🔍 Top processes (via SSH)

🧠 AI Incident Report Example
SRE Incident Report

Summary:
- CPU Current: 92%
- CPU Avg: 75%
- Disk Activity: High

Root Cause:
- High load due to background jobs
- Disk contention

Immediate Actions:
1. Restart high CPU process
2. Check cron jobs
3. Scale VM if needed
