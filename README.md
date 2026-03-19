🚀 SkynetOps — Azure VM Monitoring

SkynetOps is an SRE automation tool that monitors Azure VMs, detects issues, generates AI-based incident reports, and creates alerts via Email + ServiceNow.

Features
	•	Monitor CPU, Memory, Disk
	•	Auto alerts on threshold breach
	•	AI-powered incident analysis
	•	Email notifications (Azure-style)
	•	ServiceNow ticket automation
	•	Recovery detection (adds work notes)
	•	Forecasting & anomaly detection

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
