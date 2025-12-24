
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SkynetOps — VM Health + Disk Analytics + Email Alerts + AI Analysis
(Updated: CPU Load Average in email description, Light theme email)
"""

import os
import sys
import time
import csv
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any

from dotenv import load_dotenv

# Azure AI Agent models (optional)
from azure.ai.agents.models import MessageTextContent, MessageRole  # for AI message parsing

# data & analytics
try:
    import pandas as pd
    import numpy as np
    import matplotlib.pyplot as plt
except Exception:
    print("Missing packages (pandas, numpy, matplotlib). Install them: pip install pandas numpy matplotlib")
    raise

# Azure SDK
from azure.identity import DefaultAzureCredential
from azure.monitor.query import MetricsQueryClient, MetricAggregationType
from azure.ai.agents import AgentsClient
from azure.ai.agents.models import (
    MessageRole,
    MessageTextContent,
)

# email attachments handling
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage  # For CID inline images

load_dotenv()

# ---------------- CONFIG ----------------
PROJECT_ENDPOINT = os.getenv("PROJECT_ENDPOINT")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT_NAME")

SUBSCRIPTION_ID = os.getenv("SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
VM_NAME = os.getenv("VM_NAME")

OUTPUT_DIR = Path("outputs_advanced")
OUTPUT_DIR.mkdir(exist_ok=True)

# Email config (from .env)
EMAIL_TO = os.getenv("EMAIL_ALERT_TO")
EMAIL_FROM = os.getenv("EMAIL_ALERT_FROM")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USERNAME")
SMTP_PASS = os.getenv("SMTP_PASSWORD")
COMPANY_LOGO_PATH = os.getenv("COMPANY_LOGO_PATH")

# thresholds
CPU_THRESHOLD = float(os.getenv("CPU_THRESHOLD", 0.1))  # percentage
MEM_FREE_PCT_THRESHOLD = float(os.getenv("MEM_FREE_PCT_THRESHOLD", 20.0))  # % free mem threshold
DISK_THRESHOLD = float(os.getenv("DISK_THRESHOLD", 0.0))  # optional if you compute Disk %
MEMORY_THRESHOLD = float(os.getenv("MEMORY_THRESHOLD", 0.0))  # % usage threshold

# severity margins (absolute points above threshold)
SEVERITY_MARGIN_P1 = float(os.getenv("SEVERITY_MARGIN_P1", 20))
SEVERITY_MARGIN_P2 = float(os.getenv("SEVERITY_MARGIN_P2", 10))
SEVERITY_MARGIN_P3 = float(os.getenv("SEVERITY_MARGIN_P3", 0))

FAST_LOOKBACK_MIN = int(os.getenv("FAST_LOOKBACK_MIN", 5))
ALERT_CSV_LOOKBACK_MIN = int(os.getenv("ALERT_CSV_LOOKBACK_MIN", 60))

TOTAL_MEMORY_BYTES = int(os.getenv("TOTAL_MEMORY_BYTES") or 0)

USE_EMOJI = str(os.getenv("USE_EMOJI", "1")).strip() in ("1", "true", "yes")
INLINE_CHARTS = str(os.getenv("INLINE_CHARTS", "0")).strip() in ("1", "true", "yes")

# credential
_credential = DefaultAzureCredential(exclude_cli_credential=False)

# ---------------- SSH CONFIG ----------------
VM_SSH_HOST = os.getenv("VM_SSH_HOST")
VM_SSH_PORT = int(os.getenv("VM_SSH_PORT", 22))
VM_SSH_USERNAME = os.getenv("VM_SSH_USERNAME")
VM_SSH_PASSWORD = os.getenv("VM_SSH_PASSWORD")  # optional
VM_SSH_KEY_PATH = os.getenv("VM_SSH_KEY_PATH")  # optional
VM_SSH_USE_SUDO = str(os.getenv("VM_SSH_USE_SUDO", "false")).lower() in ("1", "true", "yes")

# Try paramiko import
try:
    import paramiko
except Exception:
    print("Missing package 'paramiko'. Install it: pip install paramiko")
    paramiko = None

# ---------------- Helpers ----------------
def human_bytes(num: float, suffix: str = "B") -> str:
    if num is None:
        return "N/A"
    try:
        num = float(num)
    except Exception:
        return "N/A"
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:0.2f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:0.2f} P{suffix}"

def html_escape(s: str) -> str:
    if s is None:
        return ""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

def build_metrics_client() -> MetricsQueryClient:
    return MetricsQueryClient(_credential)

def build_agents_client() -> AgentsClient:
    if not PROJECT_ENDPOINT:
        raise ValueError("PROJECT_ENDPOINT is required for agent features")
    return AgentsClient(endpoint=PROJECT_ENDPOINT, credential=_credential)

# ---------------- Metrics fetching ----------------
def query_recent_metrics(minutes_back: int) -> List[List]:
    if not all([SUBSCRIPTION_ID, RESOURCE_GROUP, VM_NAME]):
        raise ValueError("Azure subscription/resource/VM not configured in .env")

    client = build_metrics_client()
    vm_res = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/{VM_NAME}"

    metric_names = [
        "Percentage CPU",
        "Available Memory Bytes",
        "Disk Read Bytes",
        "Disk Write Bytes",
    ]

    kwargs = dict(
        metric_names=metric_names,
        timespan=timedelta(minutes=minutes_back),
        granularity=timedelta(minutes=1),
        aggregations=[MetricAggregationType.AVERAGE],
    )

    try:
        resp = client.query_resource(resource_uri=vm_res, **kwargs)
    except TypeError:
        resp = client.query_resource(resource_id=vm_res, **kwargs)

    rows = []
    for metric in getattr(resp, "metrics", []):
        name_obj = getattr(metric, "name", metric)
        name_label = getattr(name_obj, "value", name_obj)
        for ts in getattr(metric, "timeseries", []):
            for point in getattr(ts, "data", []):
                ts_time = getattr(point, "timestamp", None) or getattr(point, "time_stamp", None)
                ts_iso = ts_time.isoformat() if ts_time else datetime.utcnow().isoformat()
                val = getattr(point, "average", None) or 0
                rows.append([ts_iso, name_label, float(val)])
    return rows

# ---------------- Dataframe ----------------
def rows_to_df(rows: List[List]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=["timestamp", "metric", "value"])
    df = pd.DataFrame(rows, columns=["timestamp", "metric", "value"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

# ---------------- Analytics ----------------
def compute_summary_stats(df: pd.DataFrame, metric_name: str, drop_zeros: bool = False) -> dict:
    s = df.loc[df["metric"] == metric_name, "value"].astype(float)
    if drop_zeros:
        s = s.replace(0.0, np.nan)
    s = s.dropna()
    if s.empty:
        return {"min": None, "max": None, "avg": None, "median": None, "std": None}
    return {
        "min": float(s.min()),
        "max": float(s.max()),
        "avg": float(s.mean()),
        "median": float(s.median()),
        "std": float(s.std()),
    }

def moving_average(series: pd.Series, window: int = 5) -> pd.Series:
    return series.rolling(window=window, min_periods=1).mean()

def detect_anomalies_zscore(series: pd.Series, thresh: float = 2.5) -> pd.Series:
    if series.empty:
        return pd.Series(dtype=bool)
    mu = series.mean()
    sigma = series.std(ddof=0) if series.std(ddof=0) != 0 else 1.0
    z = (series - mu) / sigma
    return z.abs() > thresh

def simple_linear_forecast(series: pd.Series, steps: int = 3) -> List[float]:
    if series.empty:
        return [0.0] * steps
    x = np.arange(len(series))
    y = series.values
    A = np.vstack([x, np.ones(len(x))]).T
    m, c = np.linalg.lstsq(A, y, rcond=None)[0]
    preds = [float(m * (len(x) + i) + c) for i in range(steps)]
    return preds

# ---------------- Charts ----------------
def generate_line_chart(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    dfm = df[df["metric"] == metric_name].sort_values("timestamp")
    out = OUTPUT_DIR / out_name
    if dfm.empty:
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, "No data", ha="center", va="center")
        plt.axis("off")
        plt.savefig(out, bbox_inches="tight", dpi=120)
        plt.close()
        return out
    plt.figure(figsize=(8, 3.5))
    plt.plot(dfm["timestamp"], dfm["value"], marker="o", linewidth=1, label=metric_name)
    ma = moving_average(dfm["value"], window=max(2, int(len(dfm) / 6)))
    plt.plot(dfm["timestamp"], ma, linestyle="--", label="Moving Avg")
    plt.fill_between(dfm["timestamp"], dfm["value"], ma, alpha=0.08)
    plt.title(f"{metric_name} — last {dfm['timestamp'].max() - dfm['timestamp'].min()}")
    plt.xlabel("Time")
    plt.ylabel(metric_name)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out, dpi=120)
    plt.close()
    return out

def generate_pie_chart(cpu_value: float, out_name: str) -> Path:
    used = float(cpu_value) if cpu_value is not None else 0.0
    used = max(0.0, min(100.0, used))
    free = 100.0 - used
    labels = ["Used CPU %", "Free CPU %"]
    values = [used, free]
    out = OUTPUT_DIR / out_name
    plt.figure(figsize=(4, 4))
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title("CPU Usage (latest)")
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    return out

# ---------------- CSV ----------------
def save_csv(rows: List[List], filename: str) -> Path:
    p = OUTPUT_DIR / filename
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "metric", "value"])
        w.writerows(rows)
    return p

def build_failed_csv(cpu: Optional[float], mem_pct_free: Optional[float]) -> Path:
    rows = []
    ts = datetime.utcnow().isoformat()
    if cpu is not None and cpu > CPU_THRESHOLD:
        rows.append([ts, "Percentage CPU", cpu, CPU_THRESHOLD])
    if mem_pct_free is not None and mem_pct_free < MEM_FREE_PCT_THRESHOLD:
        rows.append([ts, "Available Memory % Free", mem_pct_free, MEM_FREE_PCT_THRESHOLD])
    p = OUTPUT_DIR / f"alert_failed_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "metric", "value", "threshold"])
        w.writerows(rows)
    return p

# ---------------- Email (robust CID handling) ----------------
def _attach_cid_image(msg: MIMEMultipart, cid: str, file_path: Optional[Path]) -> None:
    """
    Attach as inline CID image with extra Gmail/Outlook-friendly headers.
    """
    if not file_path or not os.path.isfile(str(file_path)):
        return
    try:
        with open(file_path, "rb") as imgf:
            img = MIMEImage(imgf.read())
            img.add_header("Content-ID", f"<{cid}>")
            img.add_header("Content-Disposition", "inline", filename=os.path.basename(str(file_path)))
            img.add_header("X-Attachment-Id", cid)
            msg.attach(img)
    except Exception as e:
        print(f"Failed to attach inline image {cid}: {e}")

def send_email_with_html(subject: str, html_body: str, attachments: List[Path], inline_cids: Dict[str, Path] = None) -> bool:
    """
    Sends HTML email with optional attachments and inline CID images.
    For best compatibility: root multipart/related, HTML part as MIMEText (text/html),
    then CID images attached directly to the same 'related' container.
    """
    if not (EMAIL_TO and EMAIL_FROM and SMTP_USER and SMTP_PASS and SMTP_SERVER):
        print("Email not sent - SMTP config missing in .env")
        return False
    try:
        msg = MIMEMultipart("related")
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject

        # HTML body
        msg.attach(MIMEText(html_body, "html"))

        # Inline images (logo + optional charts)
        if inline_cids:
            for cid, path in inline_cids.items():
                _attach_cid_image(msg, cid, Path(path) if path else None)

        # Regular attachments
        for file_path in attachments or []:
            try:
                with open(file_path, "rb") as fp:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(fp.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
                    msg.attach(part)
            except Exception as e:
                print("Failed to attach", file_path, e)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)

        print("📧 Email sent:", subject)
        return True
    except Exception as e:
        print("❌ Email send error:", e)
        return False

# ---------------- Health / Severity / Alerts ----------------
def compute_status_and_severity(value: Optional[float], threshold: float) -> Tuple[str, Optional[str]]:
    if value is None or np.isnan(value):
        return ("Unknown", None)
    diff = value - threshold
    if diff >= SEVERITY_MARGIN_P1:
        return ("Critical", "P1")
    elif diff >= SEVERITY_MARGIN_P2:
        return ("Critical", "P2")
    elif diff >= SEVERITY_MARGIN_P3:
        return ("Warning", "P3")
    else:
        return ("Healthy", None)

def aggregate_overall(cpu_status: str, mem_status: str, disk_status: str) -> str:
    statuses = [cpu_status, mem_status, disk_status]
    if "Critical" in statuses:
        return "Critical"
    if "Warning" in statuses:
        return "Warning"
    if all(s in ("Healthy", "Unknown") for s in statuses):
        return "Healthy"
    return "Unknown"

def build_triggered_alerts(metrics: Dict[str, Any],
                           thresholds: Dict[str, float],
                           anomaly_counts: Dict[str, int]) -> List[Dict[str, str]]:
    alerts = []
    now = datetime.utcnow().isoformat(timespec="seconds")
    # CPU
    cpu_v = metrics.get("cpu_percent")
    if cpu_v is not None and not np.isnan(cpu_v) and cpu_v > thresholds.get("cpu", 0.0):
        _, sev = compute_status_and_severity(cpu_v, thresholds["cpu"])
        alerts.append({"when": now, "metric": "CPU Usage", "value": f"{cpu_v:.2f}%", "threshold": f"{thresholds['cpu']:.2f}%", "severity": sev or "-", "note": "High CPU usage"})
    # Memory (usage)
    mem_v = metrics.get("memory_percent")
    if mem_v is not None and not np.isnan(mem_v) and mem_v > thresholds.get("mem", 0.0):
        _, sev = compute_status_and_severity(mem_v, thresholds["mem"])
        alerts.append({"when": now, "metric": "Memory Usage", "value": f"{mem_v:.2f}%", "threshold": f"{thresholds['mem']:.2f}%", "severity": sev or "-", "note": "High memory usage"})
    # Disk (usage)
    disk_v = metrics.get("disk_percent")
    if disk_v is not None and not np.isnan(disk_v) and disk_v > thresholds.get("disk", 0.0):
        _, sev = compute_status_and_severity(disk_v, thresholds["disk"])
        alerts.append({"when": now, "metric": "Disk Usage", "value": f"{disk_v:.2f}%", "threshold": f"{thresholds['disk']:.2f}%", "severity": sev or "-", "note": "High disk usage"})
    # Anomalies
    if anomaly_counts.get("disk_read", 0) > 0:
        alerts.append({"when": now, "metric": "Disk Read", "value": f"anomalies={anomaly_counts['disk_read']}", "threshold": "-", "severity": "-", "note": "Read throughput anomalies detected"})
    if anomaly_counts.get("disk_write", 0) > 0:
        alerts.append({"when": now, "metric": "Disk Write", "value": f"anomalies={anomaly_counts['disk_write']}", "threshold": "-", "severity": "-", "note": "Write throughput anomalies detected"})
    return alerts

def render_alerts_html(alerts: List[Dict[str, str]]) -> str:
    if not alerts:
        return '<div style="color:#6b7280; font-size:13px;">No active alerts at this time.</div>'
    rows = []
    for a in alerts:
        rows.append(
            "<tr>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(a['when'])}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(a['metric'])}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(a['value'])}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(a['threshold'])}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#b91c1c;'>{html_escape(a['severity'])}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#374151;'>{html_escape(a['note'])}</td>"
            "</tr>"
        )
    return (
        "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
        "<thead>"
        "<tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Time (UTC)</th>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Metric</th>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Value</th>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Threshold</th>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Severity</th>"
        "<th align='left' style='padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;'>Note</th>"
        "</tr>"
        "</thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )

# ---------------- Agent-run helper ----------------
def run_agent_analysis_direct(agent_client: AgentsClient, df: pd.DataFrame) -> str:
    cpu_df = df[df["metric"] == "Percentage CPU"].sort_values("timestamp")
    cpu_df = cpu_df[cpu_df["value"].astype(float) > 0.0]
    disk_read_df = df[df["metric"] == "Disk Read Bytes"].sort_values("timestamp")
    disk_write_df = df[df["metric"] == "Disk Write Bytes"].sort_values("timestamp")

    cpu_data = [{"timestamp": str(row.timestamp), "value": float(row.value)} for row in cpu_df.itertuples()]
    disk_read_data = [{"timestamp": str(row.timestamp), "value": float(row.value)} for row in disk_read_df.itertuples()]
    disk_write_data = [{"timestamp": str(row.timestamp), "value": float(row.value)} for row in disk_write_df.itertuples()]

    ssh_cpu_now = None
    ssh_total = None
    ssh_available = None
    ssh_mem_free_pct = None
    ssh_top = None
    try:
        ssh_cpu_now = ssh_get_overall_cpu()
    except Exception:
        ssh_cpu_now = None
    try:
        ssh_total, ssh_available = ssh_get_memory_info()
        if ssh_total and ssh_available:
            ssh_mem_free_pct = (ssh_available / ssh_total) * 100.0
    except Exception:
        ssh_total, ssh_available, ssh_mem_free_pct = None, None, None
    try:
        ssh_top = ssh_get_top_processes(max_rows=5)
    except Exception:
        ssh_top = None

    if ssh_cpu_now is not None:
        cpu_data.append({"timestamp": datetime.utcnow().isoformat(), "value": float(ssh_cpu_now)})

    instructions = (
        "You are the SkynetOps SRE Incident Response Agent.\n"
        "You will receive VM telemetry as JSON with time series arrays for CPU and Disk I/O, "
        "and an SSH snapshot with current CPU/memory and top processes.\n\n"
        "JSON INPUT SCHEMA:\n"
        "{\n"
        "  'cpu': [ { 'timestamp': 'YYYY-MM-DDTHH:MM:SS', 'value': <percent_float> }, ... ],\n"
        "  'disk_read': [ { 'timestamp': 'YYYY-MM-DDTHH:MM:SS', 'value': <bytes_float> }, ... ],\n"
        "  'disk_write': [ { 'timestamp': 'YYYY-MM-DDTHH:MM:SS', 'value': <bytes_float> }, ... ],\n"
        "  'ssh': {\n"
        "    'cpu_current_pct': <float or null>,\n"
        "    'mem_total_bytes': <int or null>,\n"
        "    'mem_available_bytes': <int or null>,\n"
        "    'mem_free_pct': <float or null>,\n"
        "    'top': {\n"
        "       'cpu': [ {'pid': str, 'command': str, 'cpu_pct': str}, ... ],\n"
        "       'memory': [ {'pid': str, 'command': str, 'mem_pct': str, 'rss_kb': str}, ... ],\n"
        "       'disk': [ {'pid': str, 'command': str, 'kb_rd_s': str, 'kb_wr_s': str}, ... ]\n"
        "    }\n"
        "  }\n"
        "}\n\n"
        "SRE TASKS:\n"
        "1) Compute latest levels (current CPU %, current disk read/write bytes per interval).\n"
        "2) Compute Min/Max/Avg for CPU, disk read, disk write (ignore empty series).\n"
        "3) Detect anomalies using z-score > 2.5 on CPU and on each disk series; report counts.\n"
        "4) Forecast CPU for 15m/30m/60m using a simple linear trend over the provided series.\n"
        "5) Determine health:\n"
        "   - VM: Healthy | Warning | Critical (based on sustained CPU and anomaly presence).\n"
        "   - Disk: Normal | Saturated | Highly active (based on sustained write/read volume and anomalies).\n"
        "6) Produce SRE runbook-style guidance:\n"
        "   - Immediate Actions (step-by-step triage a responder can perform now).\n"
        "   - Diagnostics to Run (concrete Linux commands; prefer safe, read-only checks).\n"
        "   - Mitigations (short-term controls to reduce impact, e.g., throttle, restart safe services, scale out).\n"
        "   - Follow-up / Prevention (longer-term fixes, monitoring, SLO/SLA alignment).\n"
        "7) Use SSH snapshot for current CPU/memory context and top offenders; align recommendations to observed top processes.\n"
        "8) Be concise, action-oriented, and avoid speculation beyond the data. If data is missing (e.g., memory), call it out explicitly and provide general steps.\n\n"
        "OUTPUT FORMAT (STRICT):\n"
        "SRE Incident Report\n"
        "Summary:\n"
        "- CPU Current: <value>%\n"
        "- CPU Min/Max/Avg: <min>/<max>/<avg>%\n"
        "- Disk Read (avg bytes/interval): <value>\n"
        "- Disk Write (avg bytes/interval): <value>\n"
        "- CPU Anomalies: <count>\n"
        "- Disk Anomalies: <count>\n\n"
        "Forecast:\n"
        "- CPU 15m: <value>%\n"
        "- CPU 30m: <value>%\n"
        "- CPU 60m: <value>%\n\n"
        "Status:\n"
        "- VM: <Healthy | Warning | Critical>\n"
        "- Disk: <Normal | Saturated | Highly active>\n\n"
        "Top Findings:\n"
        "- <concise finding 1>\n"
        "- <concise finding 2>\n"
        "- <concise finding 3>\n\n"
        "Immediate Actions (Runbook):\n"
        "1. <action>\n"
        "2. <action>\n"
        "3. <action>\n"
        "4. <action>\n"
        "5. <action>\n\n"
        "Diagnostics to Run (Linux):\n"
        "- <command 1>\n"
        "- <command 2>\n"
        "- <command 3>\n"
        "- <command 4>\n"
        "- <command 5>\n\n"
        "Mitigations:\n"
        "- <mitigation 1>\n"
        "- <mitigation 2>\n"
        "- <mitigation 3>\n\n"
        "Follow-up / Prevention:\n"
        "- <follow-up 1>\n"
        "- <follow-up 2>\n"
        "- <follow-up 3>\n"
    )

    agent = agent_client.create_agent(
        model=MODEL_DEPLOYMENT,
        name=f"skynetops-agent-{int(time.time())}",
        instructions=instructions,
        tools=[],
    )

    thread = agent_client.threads.create()
    payload = {
        "cpu": cpu_data,
        "disk_read": disk_read_data,
        "disk_write": disk_write_data,
        "ssh": {
            "cpu_current_pct": float(ssh_cpu_now) if ssh_cpu_now is not None else None,
            "mem_total_bytes": int(ssh_total) if ssh_total is not None else None,
            "mem_available_bytes": int(ssh_available) if ssh_available is not None else None,
            "mem_free_pct": float(ssh_mem_free_pct) if ssh_mem_free_pct is not None else None,
            "top": ssh_top,
        },
    }

    agent_client.messages.create(
        thread_id=thread.id,
        role="user",
        content=f"Here is the VM telemetry JSON:\n{payload}\n\nProvide the SRE Incident Report.",
    )

    agent_client.runs.create_and_process(thread_id=thread.id, agent_id=agent.id)

    summary = ""
    try:
        messages = agent_client.messages.list(thread_id=thread.id, order="asc")
        for message in messages:
            if message.role == MessageRole.AGENT:
                if getattr(message, "text_messages", None):
                    for text_msg in message.text_messages:
                        summary += text_msg.text.value + "\n"
                elif getattr(message, "content", None):
                    for content_block in message.content:
                        if isinstance(content_block, MessageTextContent):
                            summary += content_block.text.value + "\n"
                        elif getattr(content_block, "type", None) == "text":
                            text_obj = getattr(content_block, "text", None)
                            if text_obj is not None and hasattr(text_obj, "value"):
                                summary += text_obj.value + "\n"
                            elif text_obj is not None:
                                summary += str(text_obj) + "\n"
    except Exception as e:
        print(f"Error parsing messages: {e}")
        summary = f"⚠ Error retrieving agent analysis: {e}"

    try:
        agent_client.agents.delete_agent(agent.id)
    except Exception:
        pass

    if not summary.strip():
        summary = "⚠ Agent returned no analysis."
    return summary.strip()

# ---------------- SSH ----------------
def _ssh_connect() -> Optional['paramiko.SSHClient']:
    if paramiko is None:
        print("SSH not available: paramiko not installed.")
        return None
    if not (VM_SSH_HOST and VM_SSH_USERNAME and (VM_SSH_KEY_PATH or VM_SSH_PASSWORD)):
        print("SSH not configured: set VM_SSH_HOST, VM_SSH_USERNAME, and either VM_SSH_KEY_PATH or VM_SSH_PASSWORD.")
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if VM_SSH_KEY_PATH:
            pkey = None
            try:
                pkey = paramiko.RSAKey.from_private_key_file(VM_SSH_KEY_PATH)
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(VM_SSH_KEY_PATH)
                except Exception:
                    pkey = None
            client.connect(VM_SSH_HOST, port=VM_SSH_PORT, username=VM_SSH_USERNAME,
                           pkey=pkey, timeout=20, compress=True, allow_agent=True, look_for_keys=True)
        else:
            client.connect(VM_SSH_HOST, port=VM_SSH_PORT, username=VM_SSH_USERNAME,
                           password=VM_SSH_PASSWORD, timeout=20, compress=True, allow_agent=True, look_for_keys=True)
        return client
    except Exception as e:
        print("SSH connection error:", e)
        return None

def _ssh_exec(client: 'paramiko.SSHClient', command: str) -> str:
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        if err and not out:
            return err
        return out or err or ""
    except Exception as e:
        return f"ERROR: {e}"

def _parse_ps_table(text: str, expect_cols: int) -> List[List[str]]:
    lines = [l.strip() for l in text.strip().splitlines() if l.strip()]
    rows = []
    for i, line in enumerate(lines):
        if i == 0:
            continue
        parts = line.split(None, expect_cols - 1)
        if len(parts) >= expect_cols:
            rows.append(parts[:expect_cols])
    return rows

def ssh_get_overall_cpu() -> Optional[float]:
    client = _ssh_connect()
    if client is None:
        return None
    try:
        cmd = (
            "bash -lc '"
            "if command -v mpstat >/dev/null 2>&1; then "
            "  mpstat 1 1 | awk \"/Average/ {print 100 - \\$NF}\"; "
            "elif command -v top >/dev/null 2>&1; then "
            "  top -bn1 | grep \"Cpu(s)\" | awk -F\"id,\" \"{ split(\\$1, cpu, \\\" \\\" ); print 100 - cpu[length(cpu)] }\"; "
            "else echo NA; fi'"
        )
        out = _ssh_exec(client, cmd).strip()
        try:
            val = float(out)
            return max(0.0, min(100.0, val))
        except Exception:
            return None
    finally:
        try:
            client.close()
        except Exception:
            pass

def ssh_get_memory_info() -> Tuple[Optional[int], Optional[int]]:
    client = _ssh_connect()
    if client is None:
        return None, None
    try:
        cmd = "bash -lc 'cat /proc/meminfo | egrep \"^(MemTotal|MemAvailable):\"'"
        out = _ssh_exec(client, cmd)
        mem_total_kb = None
        mem_available_kb = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2:
                    try: mem_total_kb = float(parts[1])
                    except Exception: pass
            elif line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2:
                    try: mem_available_kb = float(parts[1])
                    except Exception: pass
        mem_total_bytes = int(mem_total_kb * 1024) if mem_total_kb is not None else None
        mem_available_bytes = int(mem_available_kb * 1024) if mem_available_kb is not None else None
        return mem_total_bytes, mem_available_bytes
    finally:
        try:
            client.close()
        except Exception:
            pass

# ---------------- NEW: CPU Load Averages (additive) ----------------
def ssh_get_load_averages() -> Optional[dict]:
    """
    Returns a dict:
      {
        "l1": float, "l5": float, "l15": float,
        "running": int, "total": int,
        "uptime": str
      }
    or None if SSH is unavailable.
    """
    client = _ssh_connect()
    if client is None:
        return None
    try:
        # Read loadavg (1/5/15 min + running/total processes) and human uptime
        cmd = "bash -lc 'cat /proc/loadavg; uptime -p'"
        out_lines = _ssh_exec(client, cmd).strip().splitlines()
        if not out_lines:
            return None

        # /proc/loadavg format: "0.21 1.08 1.08 1/230 12345"
        la_parts = out_lines[0].split()
        if len(la_parts) < 4:
            return None

        l1 = float(la_parts[0])
        l5 = float(la_parts[1])
        l15 = float(la_parts[2])

        # "1/230" => running / total processes
        running, total = 0, 0
        try:
            running, total = [int(x) for x in la_parts[3].split("/", 1)]
        except Exception:
            pass

        # uptime -p prints: "up 23 days, 3 hours, 49 minutes"
        uptime_line = out_lines[1].strip() if len(out_lines) > 1 else ""
        uptime = uptime_line.replace("up ", "") if uptime_line.startswith("up ") else uptime_line

        return {
            "l1": l1, "l5": l5, "l15": l15,
            "running": running, "total": total,
            "uptime": uptime or ""
        }
    finally:
        try:
            client.close()
        except Exception:
            pass

def ssh_get_top_processes(max_rows: int = 5) -> dict:
    result = {"cpu": [], "memory": [], "disk": []}
    client = _ssh_connect()
    if client is None:
        return {
            "cpu": [],
            "memory": [],
            "disk": [{"pid": "", "command": "SSH not configured or unavailable", "kb_rd_s": "", "kb_wr_s": ""}],
        }
    try:
        cmd_cpu = f"bash -lc \"ps -eo pid,comm,pcpu --sort=-pcpu | awk 'NR==1 || NR<={max_rows+1}'\""
        out_cpu = _ssh_exec(client, cmd_cpu)
        rows_cpu = _parse_ps_table(out_cpu, expect_cols=3)
        for r in rows_cpu[:max_rows]:
            pid, comm, pcpu = r
            result["cpu"].append({"pid": pid, "command": comm, "cpu_pct": pcpu})

        cmd_mem = f"bash -lc \"ps -eo pid,comm,pmem,rss --sort=-pmem | awk 'NR==1 || NR<={max_rows+1}'\""
        out_mem = _ssh_exec(client, cmd_mem)
        rows_mem = _parse_ps_table(out_mem, expect_cols=4)
        for r in rows_mem[:max_rows]:
            pid, comm, pmem, rss = r
            result["memory"].append({"pid": pid, "command": comm, "mem_pct": pmem, "rss_kb": rss})

        sudo_prefix = "sudo -n " if VM_SSH_USE_SUDO else ""
        cmd_disk = (
            "bash -lc '"
            "if command -v pidstat >/dev/null 2>&1; then "
            "  pidstat -d 1 1 | awk \"NR<=20\"; "
            "elif command -v iotop >/dev/null 2>&1; then "
            f"  {sudo_prefix}iotop -b -n 1 -o | awk \"NR<=10\"; "
            "else echo \"pidstat/iotop not available\"; fi'"
        )
        out_disk = _ssh_exec(client, cmd_disk)
        disk_rows = []
        if "pidstat" in out_disk or "UID" in out_disk or "Command" in out_disk:
            for line in out_disk.splitlines():
                line = line.strip()
                if not line or line.startswith(("Linux", "Time")): continue
                if line.lower().startswith(("pid", "average")): continue
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit():
                    pid = parts[0]
                    try:
                        kb_rd_s = parts[1].replace(",", "")
                        kb_wr_s = parts[2].replace(",", "")
                    except Exception:
                        kb_rd_s, kb_wr_s = "", ""
                    command = " ".join(parts[3:])
                    disk_rows.append({"pid": pid, "command": command, "kb_rd_s": kb_rd_s, "kb_wr_s": kb_wr_s})
            disk_rows = disk_rows[:max_rows]
        elif "iotop" in out_disk or "Total DISK" in out_disk or "K/s" in out_disk:
            for line in out_disk.splitlines():
                line = line.strip()
                if not line or "Total DISK" in line or line.startswith(("PID", "TID")): continue
                parts = line.split()
                if parts and parts[0].isdigit():
                    pid = parts[0]
                    command = line
                    kb_rd_s, kb_wr_s = "", ""
                    try:
                        tokens = [p for p in parts if p.endswith("K/s") or p.endswith("M/s")]
                        if len(tokens) >= 2:
                            kb_rd_s, kb_wr_s = tokens[0], tokens[1]
                    except Exception:
                        pass
                    disk_rows.append({"pid": pid, "command": command, "kb_rd_s": kb_rd_s, "kb_wr_s": kb_wr_s})
            disk_rows = disk_rows[:max_rows]
        else:
            disk_rows = [{"pid": "", "command": "pidstat/iotop not available", "kb_rd_s": "", "kb_wr_s": ""}]
        result["disk"] = disk_rows or [{"pid": "", "command": "No disk data", "kb_rd_s": "", "kb_wr_s": ""}]
    except Exception as e:
        result["disk"] = [{"pid": "", "command": f"SSH error: {e}", "kb_rd_s": "", "kb_wr_s": ""}]
    finally:
        try:
            client.close()
        except Exception:
            pass
    return result

def build_top_processes_html(top: dict) -> str:
    def render_cpu():
        rows = top.get("cpu", [])
        if not rows:
            return "<p style='color:#6b7280;'>No CPU process data</p>"
        out = []
        out.append(
            "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
            "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>PID</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>Command</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>CPU %</th>"
            "</tr></thead><tbody>"
        )
        for r in rows:
            out.append(
                "<tr>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('pid',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('command',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(str(r.get('cpu_pct','')))}</td>"
                "</tr>"
            )
        out.append("</tbody></table>")
        return "".join(out)

    def render_mem():
        rows = top.get("memory", [])
        if not rows:
            return "<p style='color:#6b7280;'>No Memory process data</p>"
        out = []
        out.append(
            "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
            "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>PID</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>Command</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>Mem %</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>RSS</th>"
            "</tr></thead><tbody>"
        )
        for r in rows:
            rss_kb = r.get("rss_kb")
            rss_str = human_bytes(float(rss_kb) * 1024) if rss_kb and str(rss_kb).isdigit() else str(rss_kb or "")
            out.append(
                "<tr>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('pid',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('command',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(str(r.get('mem_pct','')))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(rss_str)}</td>"
                "</tr>"
            )
        out.append("</tbody></table>")
        return "".join(out)

    def render_disk():
        rows = top.get("disk", [])
        if not rows:
            return "<p style='color:#6b7280;'>No Disk I/O process data</p>"
        out = []
        out.append(
            "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
            "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>PID</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>Command</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>kB read/s</th>"
            "<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>kB write/s</th>"
            "</tr></thead><tbody>"
        )
        for r in rows:
            out.append(
                "<tr>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('pid',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(r.get('command',''))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(str(r.get('kb_rd_s','')))}</td>"
                f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(str(r.get('kb_wr_s','')))}</td>"
                "</tr>"
            )
        out.append("</tbody></table>")
        return "".join(out)

    return (
        "<div style='margin:10px 0;'>"
        "<h4 style='margin:0 0 8px; color:#1f2937;'>Top Processes on VM (via SSH)</h4>"
        "<h5 style='margin:10px 0 6px; color:#374151;'>CPU</h5>" + render_cpu() +
        "<h5 style='margin:14px 0 6px; color:#374151;'>Memory</h5>" + render_mem() +
        "<h5 style='margin:14px 0 6px; color:#374151;'>Disk I/O</h5>" + render_disk() +
        "</div>"
    )

# ---------------- AI Analysis renderer (Styled Cards) ----------------
def render_ai_analysis_html(summary_text: str) -> str:
    """
    Converts Agent's plain text SRE Incident Report into light-themed HTML cards with headings + bullet lists.
    """
    if not summary_text:
        return "<div style='color:#6b7280;'>No AI analysis available.</div>"

    lines = [l.rstrip() for l in summary_text.splitlines()]
    sections = {}
    current = None
    buffer: List[str] = []

    def flush():
        nonlocal current, buffer
        if current:
            sections[current] = buffer[:]
        buffer.clear()

    # detect known headings
    headings = {
        "Summary:": "Summary",
        "Forecast:": "Forecast",
        "Status:": "Status",
        "Top Findings:": "Top Findings",
        "Immediate Actions (Runbook):": "Immediate Actions",
        "Diagnostics to Run (Linux):": "Diagnostics",
        "Mitigations:": "Mitigations",
        "Follow-up / Prevention:": "Follow-up / Prevention",
    }

    for raw in lines:
        if raw.strip() in headings.keys():
            flush()
            current = headings[raw.strip()]
        else:
            buffer.append(raw)
    flush()

    def render_list(items: List[str]) -> str:
        lis = []
        for x in items:
            x = x.strip()
            if not x:
                continue
            if x.startswith(("-", "•")):
                x = x.lstrip("-• ").strip()
            lis.append(f"<li style='margin:6px 0; color:#111827;'>{html_escape(x)}</li>")
        return "<ul style='margin:8px 0 0 18px; padding:0;'>{}</ul>".format("".join(lis)) if lis else "<div class='muted' style='color:#6b7280;'>No data.</div>"

    def card(title: str, items: List[str]) -> str:
        return (
            "<div style='margin:10px 0; background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:12px;' bgcolor='#ffffff'>"
            f"<div style='font-weight:600; color:#1f2937; margin-bottom:6px;'>{html_escape(title)}</div>"
            f"{render_list(items)}"
            "</div>"
        )

    html = ["<div>"]
    for t in ["Summary", "Forecast", "Status", "Top Findings", "Immediate Actions", "Diagnostics", "Mitigations", "Follow-up / Prevention"]:
        if t in sections:
            html.append(card(t, sections[t]))
    html.append("</div>")
    return "".join(html)

# ---------------- Testing helpers ----------------
def create_dummy_csv() -> Path:
    p = Path("dummy_metrics.csv")
    rows = [
        ["timestamp", "metric", "value"],
        ["2025-12-02T10:00:00", "Percentage CPU", 0.5],
        ["2025-12-02T10:01:00", "Percentage CPU", 0.7],
        ["2025-12-02T10:02:00", "Percentage CPU", 0.6],
        ["2025-12-02T10:03:00", "Percentage CPU", 0.65],
        ["2025-12-02T10:00:00", "Available Memory Bytes", 2450000000],
        ["2025-12-02T10:01:00", "Available Memory Bytes", 2400000000],
        ["2025-12-02T10:00:00", "Disk Read Bytes", 0],
        ["2025-12-02T10:01:00", "Disk Read Bytes", 0],
        ["2025-12-02T10:00:00", "Disk Write Bytes", 1248035],
        ["2025-12-02T10:01:00", "Disk Write Bytes", 1248035],
    ]
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerows(rows)
    return p

def load_dummy_rows_from_csv(path: Path) -> List[List]:
    df = pd.read_csv(path)
    rows = []
    for _, r in df.iterrows():
        rows.append([r["timestamp"], r["metric"], float(r["value"])])
    return rows

# ---------------- Main alert workflow ----------------
def process_cycle(rows: List[List], agent_client: Optional[AgentsClient] = None) -> bool:
    print("\n==============================")
    print("➡ Starting alert processing...")
    print("==============================")

    df = rows_to_df(rows)

    print("➡ Extracting latest CPU, Memory, Disk values...")
    cpu_latest = None
    if not df.empty and "Percentage CPU" in df["metric"].unique():
        cpu_latest = float(
            df.loc[df["metric"] == "Percentage CPU"].sort_values("timestamp")["value"].iloc[-1]
        )

    ssh_cpu = ssh_get_overall_cpu()
    if ssh_cpu is not None:
        print(f"   (SSH) VM CPU current = {ssh_cpu}%")
        cpu_latest = ssh_cpu

    mem_pct_free = None
    mem_total_bytes = TOTAL_MEMORY_BYTES if TOTAL_MEMORY_BYTES > 0 else None
    mem_available_bytes_latest = None

    if ("Available Memory Bytes" in df["metric"].unique()) and (mem_total_bytes is not None):
        mem_bytes = float(
            df.loc[df["metric"] == "Available Memory Bytes"]
            .sort_values("timestamp")["value"]
            .iloc[-1]
        )
        mem_available_bytes_latest = mem_bytes
        mem_pct_free = (mem_bytes / mem_total_bytes) * 100.0
    else:
        ssh_total, ssh_available = ssh_get_memory_info()
        if ssh_total is not None and ssh_available is not None:
            mem_total_bytes = ssh_total
            mem_available_bytes_latest = ssh_available
            mem_pct_free = (ssh_available / ssh_total) * 100.0

    disk_read_latest = None
    disk_write_latest = None
    if "Disk Read Bytes" in df["metric"].unique():
        disk_read_latest = float(
            df.loc[df["metric"] == "Disk Read Bytes"]
            .sort_values("timestamp")["value"]
            .iloc[-1]
        )
    if "Disk Write Bytes" in df["metric"].unique():
        disk_write_latest = float(
            df.loc[df["metric"] == "Disk Write Bytes"]
            .sort_values("timestamp")["value"]
            .iloc[-1]
        )

    print(f"   CPU latest = {cpu_latest}")
    print(f"   Memory free % = {mem_pct_free}")
    print(f"   Disk Read Bytes latest = {disk_read_latest}")
    print(f"   Disk Write Bytes latest = {disk_write_latest}")

    print("➡ Running analytics (min/max/avg/anomaly/forecast)...")
    stats_cpu = compute_summary_stats(df, "Percentage CPU", drop_zeros=True)
    stats_mem = compute_summary_stats(df, "Available Memory Bytes")
    stats_disk_read = compute_summary_stats(df, "Disk Read Bytes")
    stats_disk_write = compute_summary_stats(df, "Disk Write Bytes")

    cpu_series = (
        df.loc[df["metric"] == "Percentage CPU"]
        .sort_values("timestamp")["value"]
        .astype(float)
        .replace(0.0, np.nan)
        .dropna()
    )
    disk_read_series = df.loc[df["metric"] == "Disk Read Bytes"].sort_values("timestamp")["value"]
    disk_write_series = df.loc[df["metric"] == "Disk Write Bytes"].sort_values("timestamp")["value"]

    cpu_anomalies = detect_anomalies_zscore(cpu_series)
    disk_read_anomalies = detect_anomalies_zscore(disk_read_series)
    disk_write_anomalies = detect_anomalies_zscore(disk_write_series)

    forecasts = simple_linear_forecast(cpu_series, steps=3)
    print("   ✔ Analytics completed")

    print("➡ Building CSV files...")
    ctx_csv_name = f"alert_ctx_{int(time.time())}.csv"
    ctx_path = save_csv(rows, ctx_csv_name)
    failed_csv = build_failed_csv(cpu_latest, mem_pct_free)
    print("   ✔ CSV files created")

    print("➡ Generating charts...")
    cpu_line = generate_line_chart(df, "Percentage CPU", f"cpu_line_{int(time.time())}.png")
    mem_line = generate_line_chart(df, "Available Memory Bytes", f"mem_line_{int(time.time())}.png")
    disk_read_line = generate_line_chart(df, "Disk Read Bytes", f"disk_read_{int(time.time())}.png")
    disk_write_line = generate_line_chart(df, "Disk Write Bytes", f"disk_write_{int(time.time())}.png")
    pie = generate_pie_chart(cpu_latest or 0.0, f"cpu_pie_{int(time.time())}.png")
    print("   ✔ Charts created")

    summary_text = ""
    if agent_client and PROJECT_ENDPOINT and MODEL_DEPLOYMENT:
        print("➡ Running Azure AI Agent (may take time)...")
        try:
            summary_text = run_agent_analysis_direct(agent_client, df)
            print("   ✔ Agent analysis finished")
        except Exception as e:
            print("   ⚠ Agent error:", e)
            summary_text = f"⚠ Agent analysis failed: {e}"
    else:
        print("➡ AI Agent disabled (no endpoint/model in .env)")
        summary_text = "AI Agent disabled (missing PROJECT_ENDPOINT or MODEL_DEPLOYMENT)."

    print("➡ Collecting top processes via SSH (CPU/Mem/Disk)...")
    try:
        top = ssh_get_top_processes(max_rows=5)
        top_html_block = build_top_processes_html(top)
        print("   ✔ Top processes collected")
    except Exception as e:
        print("   ⚠ SSH top processes error:", e)
        top_html_block = f"<p>⚠ SSH top processes error: {html_escape(str(e))}</p>"

    # --- NEW: CPU Load Average description (light theme card) ---
    loadavg = None
    try:
        loadavg = ssh_get_load_averages()
    except Exception:
        loadavg = None

    if loadavg:
        load_desc_html = (
            f"<div style='font-size:13px; color:#374151;'>"
            f"<strong>Load average:</strong> {loadavg['l1']:.2f} {loadavg['l5']:.2f} {loadavg['l15']:.2f} "
            f"&nbsp;|&nbsp; <strong>Uptime:</strong> {html_escape(loadavg['uptime'])} "
            f"&nbsp;|&nbsp; <strong>Tasks:</strong> {loadavg['running']}/{loadavg['total']} running"
            f"</div>"
        )
    else:
        load_desc_html = (
            "<div style='font-size:13px; color:#6b7280;'>"
            "<strong>Load average:</strong> N/A (SSH not configured or unavailable)"
            "</div>"
        )

    # Human-readable stats
    cpu_min_str = f"{stats_cpu['min']:0.2f} %" if stats_cpu["min"] is not None else "N/A"
    cpu_max_str = f"{stats_cpu['max']:0.2f} %" if stats_cpu["max"] is not None else "N/A"
    cpu_avg_str = f"{stats_cpu['avg']:0.2f} %" if stats_cpu['avg'] is not None else "N/A"
    mem_min_str = human_bytes(stats_mem["min"]) if stats_mem["min"] is not None else "N/A"
    mem_max_str = human_bytes(stats_mem["max"]) if stats_mem["max"] is not None else "N/A"
    mem_avg_str = human_bytes(stats_mem["avg"]) if stats_mem["avg"] is not None else "N/A"
    disk_read_min_str = human_bytes(stats_disk_read["min"]) if stats_disk_read["min"] is not None else "N/A"
    disk_read_max_str = human_bytes(stats_disk_read["max"]) if stats_disk_read["max"] is not None else "N/A"
    disk_read_avg_str = human_bytes(stats_disk_read["avg"]) if stats_disk_read["avg"] is not None else "N/A"
    disk_write_min_str = human_bytes(stats_disk_write["min"]) if stats_disk_write["min"] is not None else "N/A"
    disk_write_max_str = human_bytes(stats_disk_write["max"]) if stats_disk_write["max"] is not None else "N/A"
    disk_write_avg_str = human_bytes(stats_disk_write["avg"]) if stats_disk_write["avg"] is not None else "N/A"

    cpu_forecast_15m = f"{forecasts[0]:0.2f}" if len(forecasts) > 0 else "0.00"
    cpu_forecast_30m = f"{forecasts[1]:0.2f}" if len(forecasts) > 1 else "0.00"
    cpu_forecast_60m = f"{forecasts[2]:0.2f}" if len(forecasts) > 2 else "0.00"

    # Summary metrics (usage)
    memory_percent = None
    if mem_pct_free is not None:
        memory_percent = 100.0 - mem_pct_free
    metrics = {
        "cpu_percent": float(cpu_latest) if cpu_latest is not None else float("nan"),
        "memory_percent": float(memory_percent) if memory_percent is not None else float("nan"),
        "disk_percent": float("nan"),  # populate if you have disk capacity %
    }
    cpu_threshold = CPU_THRESHOLD
    mem_threshold = MEMORY_THRESHOLD if MEMORY_THRESHOLD > 0 else (100.0 - MEM_FREE_PCT_THRESHOLD)
    disk_threshold = DISK_THRESHOLD

    cpu_status, cpu_sev = compute_status_and_severity(metrics["cpu_percent"], cpu_threshold)
    mem_status, mem_sev = compute_status_and_severity(metrics["memory_percent"], mem_threshold) if not np.isnan(metrics["memory_percent"]) else ("Unknown", None)
    disk_status, disk_sev = compute_status_and_severity(metrics["disk_percent"], disk_threshold) if not np.isnan(metrics["disk_percent"]) else ("Unknown", None)
    health = {"cpu_status": cpu_status, "memory_status": mem_status, "disk_status": disk_status}
    overall = aggregate_overall(cpu_status, mem_status, disk_status)

    anomaly_counts = {
        "cpu": int(cpu_anomalies.sum()) if hasattr(cpu_anomalies, "sum") else 0,
        "disk_read": int(disk_read_anomalies.sum()) if hasattr(disk_read_anomalies, "sum") else 0,
        "disk_write": int(disk_write_anomalies.sum()) if hasattr(disk_write_anomalies, "sum") else 0,
    }
    thresholds = {"cpu": cpu_threshold, "mem": mem_threshold, "disk": disk_threshold}
    triggered_alerts = build_triggered_alerts(metrics, thresholds, anomaly_counts)
    alerts_html = render_alerts_html(triggered_alerts)

    # Styled AI analysis
    ai_html = render_ai_analysis_html(summary_text)

    # ---------- Light Theme HTML ----------
    now = datetime.utcnow().isoformat(timespec="seconds")
    subject = f"SkynetOps Alert on {VM_NAME or 'VM'} — {overall}"
    emoji_prefix = "🚨 " if USE_EMOJI else ""
    header_brand_tag = f"<span>SkynetOps • {html_escape(VM_NAME or 'VM')}</span>"

    cpu_current_str = f"{metrics['cpu_percent']:.2f}%" if not np.isnan(metrics['cpu_percent']) else "N/A"
    mem_current_str = f"{metrics['memory_percent']:.2f}%" if not np.isnan(metrics.get('memory_percent', float('nan'))) else "N/A"
    disk_current_str = f"{metrics['disk_percent']:.2f}%" if not np.isnan(metrics.get('disk_percent', float('nan'))) else "N/A"
    cpu_threshold_str = f"{cpu_threshold:.2f}%"
    mem_threshold_str = f"{mem_threshold:.2f}%"
    disk_threshold_str = f"{disk_threshold:.2f}%"

    # Inline charts (optional) CIDs
    inline_cids: Dict[str, Path] = {}
    if COMPANY_LOGO_PATH:
        inline_cids["company_logo"] = Path(COMPANY_LOGO_PATH)
    if INLINE_CHARTS:
        inline_cids["chart_cpu_line"] = cpu_line
        inline_cids["chart_mem_line"] = mem_line
        inline_cids["chart_disk_read_line"] = disk_read_line
        inline_cids["chart_disk_write_line"] = disk_write_line
        inline_cids["chart_cpu_pie"] = pie

    body_html = f"""\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="x-ua-compatible" content="ie=edge" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>SkynetOps Alert</title>
  </head>
  <body style="margin:0; padding:0; background:#f8fafc; color:#111827;" bgcolor="#f8fafc">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;" bgcolor="#f8fafc">
      <tr>
        <td align="center" style="padding:24px 12px;" bgcolor="#f8fafc">
          <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px; max-width:640px; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;" bgcolor="#ffffff">
            <!-- Header -->
            <tr>
              <td style="padding:20px 30px; border-bottom:1px solid #e5e7eb; background:#f9fafb;" bgcolor="#f9fafb">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
                  <tr>
                    <td align="left" style="font-size:18px; font-weight:600; color:#1f2937;">
                      {header_brand_tag}
                    </td>
                    <td align="right" style="font-size:13px; color:#374151;">
                      System Health Alert — {overall}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Title -->
            <tr>
              <td style="padding:25px 30px;" bgcolor="#ffffff">
                <h2 style="margin:0; font-size:22px; line-height:1.3; color:#dc2626;">
                  {emoji_prefix}Alert Detected
                </h2>
                <p style="margin:10px 0 0; color:#111827;">One or more system metrics have exceeded configured thresholds.</p>
                <p style="margin-top:6px; font-size:13px; color:#374151;">
                  <strong>Timestamp (UTC):</strong> {now}
                </p>
              </td>
            </tr>

            <!-- CPU Load Average (description) -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <div style="background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:12px;" bgcolor="#ffffff">
                  {load_desc_html}
                </div>
              </td>
            </tr>

            <!-- Summary Table -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">Alert Summary</h3>
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;" bgcolor="#ffffff">
                  <thead>
                    <tr style="background:#f3f4f6;" bgcolor="#f3f4f6">
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Metric</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Current</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Threshold</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Status</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">CPU Usage</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{cpu_current_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{cpu_threshold_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{health['cpu_status']}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#b91c1c;">{cpu_sev or '-'}</td>
                    </tr>
                    <tr>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">Disk Usage</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{disk_current_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{disk_threshold_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{health['disk_status']}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#b91c1c;">{disk_sev or '-'}</td>
                    </tr>
                    <tr>
                      <td style="padding:10px 12px; color:#111827;">Memory Usage</td>
                      <td style="padding:10px 12px; color:#111827;">{mem_current_str}</td>
                      <td style="padding:10px 12px; color:#111827;">{mem_threshold_str}</td>
                      <td style="padding:10px 12px; color:#111827;">{health['memory_status']}</td>
                      <td style="padding:10px 12px; color:#b91c1c;">{mem_sev or '-'}</td>
                    </tr>
                  </tbody>
                </table>
              </td>
            </tr>

            <!-- Triggered Alerts -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">Triggered Alerts</h3>
                <div style="background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:12px;" bgcolor="#ffffff">
                  {alerts_html}
                </div>
              </td>
            </tr>

            <!-- Analytics -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">Analytics</h3>
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;" bgcolor="#ffffff">
                  <thead>
                    <tr style="background:#f3f4f6;" bgcolor="#f3f4f6">
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Series</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Min</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Max</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Avg</th>
                      <th align="left" style="padding:10px 12px; font-size:13px; color:#111827; border-bottom:1px solid #e5e7eb;">Anomalies</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">CPU (%)</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{cpu_min_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{cpu_max_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{cpu_avg_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{anomaly_counts['cpu']}</td>
                    </tr>
                    <tr>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">Disk Read (bytes)</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{disk_read_min_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{disk_read_max_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{disk_read_avg_str}</td>
                      <td style="padding:10px 12px; border-bottom:1px solid #e5e7eb; color:#111827;">{anomaly_counts['disk_read']}</td>
                    </tr>
                    <tr>
                      <td style="padding:10px 12px; color:#111827;">Disk Write (bytes)</td>
                      <td style="padding:10px 12px; color:#111827;">{disk_write_min_str}</td>
                      <td style="padding:10px 12px; color:#111827;">{disk_write_max_str}</td>
                      <td style="padding:10px 12px; color:#111827;">{disk_write_avg_str}</td>
                      <td style="padding:10px 12px; color:#111827;">{anomaly_counts['disk_write']}</td>
                    </tr>
                  </tbody>
                </table>
                <div style="margin-top:10px; background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:12px; color:#111827;" bgcolor="#ffffff">
                  <div style="font-size:13px;"><strong>CPU Forecasts:</strong></div>
                  <div style="font-size:13px; color:#374151; margin-top:6px;">
                    15m: {cpu_forecast_15m}% &nbsp;|&nbsp; 30m: {cpu_forecast_30m}% &nbsp;|&nbsp; 60m: {cpu_forecast_60m}%
                  </div>
                </div>
              </td>
            </tr>

            <!-- Inline Charts (optional) -->
            {"" if not INLINE_CHARTS else f'''
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">Charts</h3>
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;" bgcolor="#ffffff">
                  <tr>
                    <td align="center" style="padding:8px;" bgcolor="#ffffff">
                      <id:chart_cpu_line
                    </td>
                  </tr>
                  <tr>
                    <td align="center" style="padding:8px;" bgcolor="#ffffff">
                      <img src="cid:chart_mem_line" alt="Memory trend" style="max-width:600px; width:100%; border:1px solid           <td align="center" style="padding:8px;" bgcolor="#ffffff">
                      cid:chart_disk_read_line
                    </td>
                  </tr>
                  <tr>
                    <td align="center" style="padding:8px;" bgcolor="#ffffff">
                      cid:chart_disk_write_line
                    </td>
                  </tr>
                  <tr>
                    <td align="center" style="padding:8px;" bgcolor="#ffffff">
                      <img src="cid:chart_cpu_pie           </td>
                  </tr>
                </table>
              </td>
            </tr>
            '''}

            <!-- Top Processes (SSH) -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">Top Processes (SSH)</h3>
                <div style="background:#ffffff; border:1px solid #e5e7eb; border-radius:8px; padding:12px;" bgcolor="#ffffff">
                  {top_html_block}
                </div>
              </td>
            </tr>

            <!-- AI Analysis (Styled) -->
            <tr>
              <td style="padding:0 30px 22px;" bgcolor="#ffffff">
                <h3 style="margin:0 0 10px; font-size:18px; color:#1f2937;">AI Analysis</h3>
                {ai_html}
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:14px 30px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px;" bgcolor="#f9fafb">
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
                  <tr>
                    <td align="left" style="color:#374151; font-size:12px; line-height:1.5;">
                      This alert was automatically generated by
                      <strong style="color:#111827;">SkynetOps Monitoring Platform</strong>.<br/>
                      Attachments include CSV reports and process details (if applicable).
                    </td>
                    <td align="right" style="padding-left:10px;">
                      {"<img src=\"cid:company_logo\" alt=\"Logo\" style=\"height:24px;\">"
                         if COMPANY_LOGO_PATH else "EY GDS"}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

    attachments = [failed_csv, ctx_path]
    # keep original PNGs as attachments too
    attachments += [cpu_line, mem_line, disk_read_line, disk_write_line, pie]

    print("➡ Sending email...")
    sent = send_email_with_html(subject, body_html, attachments, inline_cids=inline_cids)

    if sent:
        print("✅ EMAIL SENT SUCCESSFULLY!")
    else:
        print("❌ Email failed!")

    print("==============================")
    print("➡ Alert cycle completed.")
    print("==============================\n")
    return sent

# ---------------- CLI / Main ----------------
def test_email_only() -> bool:
    # Quick smoke test for light theme + CID logo
    html = """<!DOCTYPE html><html><body style="background:#f8fafc; color:#111827; padding:20px;" bgcolor="#f8fafc">
      <table width="600" style="background:#ffffff; border:1px solid #e5e7eb;" bgcolor="#ffffff" cellpadding="0" cellspacing="0">
        <tr><td style="padding:16px; color:#111827;" bgcolor="#ffffff">
          <h3 style="margin:0; color:#dc2626;">Light Theme Test</h3>
          <p>Logo below should render via CID:</p>
          <img src="cid:company_logo" alt="Logo" style="height:24pxbody></html>"""
    inline = {}
    if COMPANY_LOGO_PATH:
        inline["company_logo"] = Path(COMPANY_LOGO_PATH)
    return send_email_with_html("[SkynetOps TEST] SMTP + CID", html, [], inline_cids=inline)

def test_dummy_once() -> bool:
    p = create_dummy_csv()
    rows = load_dummy_rows_from_csv(p)
    agent_client: Optional[AgentsClient] = None
    try:
        agent_client = build_agents_client() if PROJECT_ENDPOINT else None
    except Exception as e:
        print("Agent client not available:", e)
        agent_client = None
    return process_cycle(rows, agent_client)

def continuous_loop() -> None:
    agent_client: Optional[AgentsClient] = None
    try:
        agent_client = build_agents_client() if PROJECT_ENDPOINT else None
    except Exception as e:
        print("Agent client not available:", e)
        agent_client = None

    print("Starting continuous monitoring loop. Press Ctrl+C to stop.")
    while True:
        try:
            rows = query_recent_metrics(FAST_LOOKBACK_MIN)
            cpu_latest = None
            mem_pct_free = None

            if rows:
                df = rows_to_df(rows)
                if "Percentage CPU" in df["metric"].unique():
                    cpu_latest = float(
                        df.loc[df["metric"] == "Percentage CPU"]
                        .sort_values("timestamp")["value"]
                        .iloc[-1]
                    )

                ssh_cpu = ssh_get_overall_cpu()
                if ssh_cpu is not None:
                    cpu_latest = ssh_cpu

                mem_total_bytes = TOTAL_MEMORY_BYTES if TOTAL_MEMORY_BYTES > 0 else None
                if ("Available Memory Bytes" in df["metric"].unique()) and (mem_total_bytes is not None):
                    mem_bytes = float(
                        df.loc[df["metric"] == "Available Memory Bytes"]
                        .sort_values("timestamp")["value"]
                        .iloc[-1]
                    )
                    mem_pct_free = (mem_bytes / mem_total_bytes) * 100.0
                else:
                    ssh_total, ssh_available = ssh_get_memory_info()
                    if ssh_total is not None and ssh_available is not None:
                        mem_pct_free = (ssh_available / ssh_total) * 100.0

                alert_reasons = []
                if cpu_latest is not None and cpu_latest > CPU_THRESHOLD:
                    alert_reasons.append("High CPU")
                if mem_pct_free is not None and mem_pct_free < MEM_FREE_PCT_THRESHOLD:
                    alert_reasons.append("Low memory")

                if alert_reasons:
                    print("ALERT detected:", alert_reasons)
                    process_cycle(rows, agent_client)
                else:
                    print(f"No alert: CPU={cpu_latest} Mem%Free={mem_pct_free}")
            else:
                print("No metrics returned this cycle.")

            time.sleep(30)
        except KeyboardInterrupt:
            print("Exiting by user request.")
            break
        except Exception as e:
            print("Loop error:", e)
            time.sleep(10)

if __name__ == "__main__":
    if "--test-email" in sys.argv:
        ok = test_email_only()
        print("Test email result:", ok)
    elif "--test-dummy" in sys.argv:
        ok = test_dummy_once()
        print("Dummy test run result:", ok)
    else:
        continuous_loop()
