🚀 **SkynetOps — Azure VM Monitoring**

**SkynetOps** is an advanced SRE automation tool that monitors Azure Virtual Machines in real-time, detects anomalies, generates AI-powered incident reports, and integrates with Email Alerts + ServiceNow for full incident lifecycle management.

**Features**

	•	Monitor CPU, Memory, Disk
	•	Auto alerts on threshold breach
	•	AI-powered incident analysis
	•	Email notifications (Azure-style)
	•	ServiceNow ticket automation
	•	Recovery detection (adds work notes)
	•	Forecasting & anomaly detection
	
**Architecture Overview**

	Azure Monitor → SkynetOps Engine → AI Analysis
	        ↓                     ↓
	   Metrics Fetch        Forecast Engine
	        ↓                     ↓
	   Threshold Check → Incident Creation
	        ↓                     ↓
	   Email Alerts      ServiceNow Tickets

**Setup:**

	1.	Install dependencies:
        pip install -r requirements.txt
    2.	Configure secrets in Azure Key Vault:
		. Subscription, VM, Email, SMTP
		. CPU / Memory / Disk thresholds
	3.	(Optional) Add vms.json for multiple VMs + SSH

**Run:**

    python skynetops.py

**Parallel mode:**

    python skynetops.py --parallel

**Alerts**

	•	High CPU / Memory / Disk → Incident created
	•	VM Down → P1
	•	Telemetry Missing → P2
	•	Recovery → Email + note (no auto close)

**Attachments Generated**

	•	CSV (metrics + context)
	•	Charts (CPU, Memory, Disk)
	•	AI analysis report
	•	Top processes (via SSH)

**AI Incident Report Example:**

	**AI Analysis (Unified SRE Incident Report) **

	**Summary:**  
	- CPU Current: 90.48%  
	- CPU Min/Max/Avg: 19.16%/90.48%/67.58%  
	- Disk Read (avg bytes/interval): 6734 MB
	- Disk Write (avg bytes/interval): 2803 MB 
	- CPU Anomalies: 1 
	- Disk Anomalies: 0  
	
	**Forecast:**  
	- CPU 15m: 92.38%  
	- CPU 30m: 96.80%  
	- CPU 60m: 98.09%  
	
	**Status:**  
	- VM: Critical (Current CPU 90.48%, memory used 88%)  
	- Disk: Highly active (sustained high read/write spikes visible in telemetry)  
	
	**Root Cause:**  
	- CPU-intensive `stress-ng-cpu` processes (PID 75951, 75952) consuming ~179.1% combined CPU, driving load to 90.48%.   
	- Disk I/O surged at 14:48 (read: ~273 MB, write: ~127 MB), possibly due to process activity or swap usage.  
	
	**Immediate Actions (Runbook):**  
	1. Terminate `stress-ng-cpu` processes: `sudo kill -9 75951 75952`.  
	2. Check for memory pressure and swap usage: `free -h; swapon -s`.  
	3. Identify disk I/O source: `sudo iotop -o` or `pidstat -d`.  
	4. Monitor system stability after killing stress processes.  
	5. Escalate to VM operator if high CPU persists post-cleanup.  
	
	**Diagnostics to Run (Linux):**  
	1. `top -b -n 1 | head -20` (current CPU/memory snapshot).  
	2. `ps auxf | grep -E &amp;quot;(stress|defunct)&amp;quot;` (identify stress processes and zombies).  
	3. `vmstat 1 10` (system-wide CPU, memory, I/O).  
	4. `sudo lsof -p ` for any suspect process (e.g., PID 75949).  
	5. `dmesg -T | tail -30` (check kernel logs for OOM or I/O errors).  
	
	**Mitigations:**  
	1. Implement process monitoring/alerting for `stress-ng` or unauthorized CPU-heavy binaries.  
	2. Set up cgroups/limits for user processes to cap CPU/memory usage.  
	3. Schedule regular log reviews for unexpected process execution.  
	
	**Follow-up / Prevention:**  
	1. Review VM’s security posture: investigate how `stress-ng` was launched (cron, user session, etc.).  
	2. Consider implementing workload isolation (containers) for critical services.  
	3. Add automated anomaly detection on process launches and sustained high CPU.

