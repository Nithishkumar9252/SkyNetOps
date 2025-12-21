#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SkynetOps — VM Health + Disk Analytics + Email Alerts + AI Analysis
"""

import os
import sys
import time
import csv
import smtplib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv

from azure.ai.agents.models import MessageTextContent, MessageRole  # for AI message parsing[web:16][web:24]

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
    FilePurpose,
    CodeInterpreterTool,
    MessageRole,
    MessageTextContent,
)

# email attachments handling
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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

# thresholds
CPU_THRESHOLD = float(os.getenv("CPU_THRESHOLD", 0.1))
MEM_FREE_PCT_THRESHOLD = float(os.getenv("MEM_FREE_PCT_THRESHOLD", 20.0))


FAST_LOOKBACK_MIN = int(os.getenv("FAST_LOOKBACK_MIN", 5))
ALERT_CSV_LOOKBACK_MIN = int(os.getenv("ALERT_CSV_LOOKBACK_MIN", 60))

TOTAL_MEMORY_BYTES = int(os.getenv("TOTAL_MEMORY_BYTES") or 0)

# credential
_credential = DefaultAzureCredential(exclude_cli_credential=False)


# ---------------- Helpers ----------------
def human_bytes(num: float, suffix: str = "B") -> str:
    """
    Convert a byte value into a human-readable string (KB, MB, GB, TB).
    """
    if num is None:
        return "N/A"
    num = float(num)
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:0.2f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:0.2f} P{suffix}"


def build_metrics_client() -> MetricsQueryClient:
    return MetricsQueryClient(_credential)


def build_agents_client() -> AgentsClient:
    if not PROJECT_ENDPOINT:
        raise ValueError("PROJECT_ENDPOINT is required for agent features")
    return AgentsClient(endpoint=PROJECT_ENDPOINT, credential=_credential)


# ---------------- Metrics fetching (CPU, memory, disk) ----------------
def query_recent_metrics(minutes_back: int) -> List[List]:
    """
    Returns rows: [timestamp_iso, metric, value]
    Includes CPU, memory, and disk I/O metrics.[web:69][web:68]
    """
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


# ---------------- Utilities: data -> dataframe ----------------
def rows_to_df(rows: List[List]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=["timestamp", "metric", "value"])
    df = pd.DataFrame(rows, columns=["timestamp", "metric", "value"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ---------------- Advanced analytics ----------------
def compute_summary_stats(df: pd.DataFrame, metric_name: str) -> dict:
    s = df.loc[df["metric"] == metric_name, "value"]
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


# ---------------- Chart generation ----------------
def generate_line_chart(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    dfm = df[df["metric"] == metric_name].sort_values("timestamp")
    if dfm.empty:
        out = OUTPUT_DIR / out_name
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, "No data", horizontalalignment="center", verticalalignment="center")
        plt.axis("off")
        plt.savefig(out, bbox_inches="tight")
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
    out = OUTPUT_DIR / out_name
    plt.savefig(out, dpi=120)
    plt.close()
    return out


def generate_pie_chart(cpu_value: float, out_name: str) -> Path:
    used = float(cpu_value) if cpu_value is not None else 0.0
    used = max(0.0, min(100.0, used))
    free = max(0.0, 100.0 - used)
    labels = ["Used CPU %", "Free CPU %"]
    values = [used, free]
    plt.figure(figsize=(4, 4))
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title("CPU Usage (latest)")
    out = OUTPUT_DIR / out_name
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    return out


def generate_histogram(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    s = df.loc[df["metric"] == metric_name, "value"]
    plt.figure(figsize=(6, 3))
    if s.empty:
        plt.text(0.5, 0.5, "No data", horizontalalignment="center", verticalalignment="center")
        plt.axis("off")
    else:
        plt.hist(s, bins=min(20, max(3, len(s) // 2)), alpha=0.8)
        plt.title(f"{metric_name} distribution")
        plt.xlabel(metric_name)
    out = OUTPUT_DIR / out_name
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    return out


# ---------------- CSV builders ----------------
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


# ---------------- Email ----------------
def send_email_with_html(subject: str, html_body: str, attachments: List[Path]) -> bool:
    if not (EMAIL_TO and EMAIL_FROM and SMTP_USER and SMTP_PASS and SMTP_SERVER):
        print("Email not sent - SMTP config missing in .env")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

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


# ---------------- Agent-run helper ----------------
def run_agent_analysis_direct(agent_client: AgentsClient, df: pd.DataFrame) -> str:
    """
    Sends VM CPU + disk metrics directly to Agent as JSON.
    """

    cpu_df = df[df["metric"] == "Percentage CPU"].sort_values("timestamp")
    disk_read_df = df[df["metric"] == "Disk Read Bytes"].sort_values("timestamp")
    disk_write_df = df[df["metric"] == "Disk Write Bytes"].sort_values("timestamp")

    if cpu_df.empty and disk_read_df.empty and disk_write_df.empty:
        return "⚠ No CPU or disk metrics found for analysis."

    cpu_data = [
        {"timestamp": str(row.timestamp), "value": float(row.value)}
        for row in cpu_df.itertuples()
    ]
    disk_read_data = [
        {"timestamp": str(row.timestamp), "value": float(row.value)}
        for row in disk_read_df.itertuples()
    ]
    disk_write_data = [
        {"timestamp": str(row.timestamp), "value": float(row.value)}
        for row in disk_write_df.itertuples()
    ]

    instructions = (
        "You are the SkynetOps VM Health Analysis Agent.\n"
        "You will receive JSON with VM CPU and disk metrics.\n\n"
        "JSON FORMAT:\n"
        "{\n"
        "  'cpu': [ { 'timestamp': '2025-12-09T10:00:00', 'value': 74.2 }, ... ],\n"
        "  'disk_read': [ { 'timestamp': '2025-12-09T10:00:00', 'value': 123456 }, ... ],\n"
        "  'disk_write': [ { 'timestamp': '2025-12-09T10:00:00', 'value': 789012 }, ... ]\n"
        "}\n\n"
        "Tasks:\n"
        "- Compute latest CPU and disk read/write levels.\n"
        "- Min/Max/Avg for CPU, disk read, disk write.\n"
        "- Detect anomalies (z-score > 2.5) on CPU and disk.\n"
        "- Forecast CPU for 15m/30m/60m.\n"
        "- Overall VM health status (Healthy / Warning / Critical).\n"
        "- Disk health status (Normal / Saturated / Highly active).\n"
        "- Recommendations.\n\n"
        "OUTPUT FORMAT STRICT:\n"
        "VM Health Summary:\n"
        "- CPU Current: <value>%\n"
        "- CPU Min/Max/Avg: <min>/<max>/<avg>%\n"
        "- Disk Read (avg bytes/min): <value>\n"
        "- Disk Write (avg bytes/min): <value>\n"
        "- CPU Anomalies: <count>\n"
        "- Disk Anomalies: <count>\n\n"
        "Forecast:\n"
        "- CPU 15m: <value>%\n"
        "- CPU 30m: <value>%\n"
        "- CPU 60m: <value>%\n\n"
        "Status:\n"
        "- VM: <Healthy | Warning | Critical>\n"
        "- Disk: <Normal | Saturated | Highly active>\n\n"
        "Recommendations:\n"
        "- <action 1>\n"
        "- <action 2>\n"
        "- <action 3>\n"
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
    }

    agent_client.messages.create(
        thread_id=thread.id,
        role="user",
        content=f"Here is the VM CPU and disk data in JSON:\n{payload}\n\nProvide the VM Health Summary.",
    )

    run = agent_client.runs.create_and_process(
        thread_id=thread.id,
        agent_id=agent.id,
    )

    summary = ""
    try:
        messages = agent_client.messages.list(
            thread_id=thread.id,
            order="asc",
        )

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


# ---------------- Testing helpers ----------------
def create_dummy_csv() -> Path:
    p = Path("dummy_metrics.csv")
    rows = [
        ["timestamp", "metric", "value"],
        ["2025-12-02T10:00:00", "Percentage CPU", 95],
        ["2025-12-02T10:01:00", "Percentage CPU", 92],
        ["2025-12-02T10:02:00", "Percentage CPU", 88],
        ["2025-12-02T10:03:00", "Percentage CPU", 85],
        ["2025-12-02T10:00:00", "Available Memory Bytes", 2450000000],
        ["2025-12-02T10:01:00", "Available Memory Bytes", 2400000000],
        ["2025-12-02T10:00:00", "Disk Read Bytes", 123456],
        ["2025-12-02T10:01:00", "Disk Read Bytes", 150000],
        ["2025-12-02T10:00:00", "Disk Write Bytes", 789012],
        ["2025-12-02T10:01:00", "Disk Write Bytes", 800000],
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

    mem_pct_free = None
    if TOTAL_MEMORY_BYTES and "Available Memory Bytes" in df["metric"].unique():
        mem_bytes = float(
            df.loc[df["metric"] == "Available Memory Bytes"]
            .sort_values("timestamp")["value"]
            .iloc[-1]
        )
        mem_pct_free = (mem_bytes / TOTAL_MEMORY_BYTES) * 100.0

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
    stats_cpu = compute_summary_stats(df, "Percentage CPU")
    stats_mem = compute_summary_stats(df, "Available Memory Bytes")
    stats_disk_read = compute_summary_stats(df, "Disk Read Bytes")
    stats_disk_write = compute_summary_stats(df, "Disk Write Bytes")

    cpu_series = (
        df.loc[df["metric"] == "Percentage CPU"]
        .sort_values("timestamp")["value"]
    )
    disk_read_series = (
        df.loc[df["metric"] == "Disk Read Bytes"]
        .sort_values("timestamp")["value"]
    )
    disk_write_series = (
        df.loc[df["metric"] == "Disk Write Bytes"]
        .sort_values("timestamp")["value"]
    )

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
    # cpu_hist = generate_histogram(df, "Percentage CPU", f"cpu_hist_{int(time.time())}.png")
    pie = generate_pie_chart(cpu_latest or 0.0, f"cpu_pie_{int(time.time())}.png")
    print("   ✔ Charts created")

    summary = ""
    if agent_client and PROJECT_ENDPOINT and MODEL_DEPLOYMENT:
        print("➡ Running Azure AI Agent (may take time)...")
        try:
            summary = run_agent_analysis_direct(agent_client, df)
            print("   ✔ Agent analysis finished")
        except Exception as e:
            print("   ⚠ Agent error:", e)
            summary = f"⚠ Agent analysis failed: {e}"
    else:
        print("➡ AI Agent disabled (no endpoint/model in .env)")
        summary = "AI Agent disabled (missing PROJECT_ENDPOINT or MODEL_DEPLOYMENT)."

    # ---------- Human-readable formatting ----------
    cpu_latest_str = f"{cpu_latest:0.2f} %" if cpu_latest is not None else "N/A"
    mem_free_str = f"{mem_pct_free:0.2f} %" if mem_pct_free is not None else "N/A"

    disk_read_latest_str = human_bytes(disk_read_latest) if disk_read_latest is not None else "N/A"
    disk_write_latest_str = human_bytes(disk_write_latest) if disk_write_latest is not None else "N/A"

    cpu_min_str = f"{stats_cpu['min']:0.2f} %" if stats_cpu["min"] is not None else "N/A"
    cpu_max_str = f"{stats_cpu['max']:0.2f} %" if stats_cpu["max"] is not None else "N/A"
    cpu_avg_str = f"{stats_cpu['avg']:0.2f} %" if stats_cpu["avg"] is not None else "N/A"

    mem_min_str = human_bytes(stats_mem["min"]) if stats_mem["min"] is not None else "N/A"
    mem_max_str = human_bytes(stats_mem["max"]) if stats_mem["max"] is not None else "N/A"
    mem_avg_str = human_bytes(stats_mem["avg"]) if stats_mem["avg"] is not None else "N/A"

    disk_read_min_str = human_bytes(stats_disk_read["min"]) if stats_disk_read["min"] is not None else "N/A"
    disk_read_max_str = human_bytes(stats_disk_read["max"]) if stats_disk_read["max"] is not None else "N/A"
    disk_read_avg_str = human_bytes(stats_disk_read["avg"]) if stats_disk_read["avg"] is not None else "N/A"

    disk_write_min_str = human_bytes(stats_disk_write["min"]) if stats_disk_write["min"] is not None else "N/A"
    disk_write_max_str = human_bytes(stats_disk_write["max"]) if stats_disk_write["max"] is not None else "N/A"
    disk_write_avg_str = human_bytes(stats_disk_write["avg"]) if stats_disk_write["avg"] is not None else "N/A"

    cpu_forecast_str = ", ".join([f"{v:0.2f} %" for v in forecasts])

    print("➡ Building HTML email body...")
    now = datetime.utcnow().isoformat()
    subject = f"🚨 SkynetOps Alert on {VM_NAME or 'VM'}"

    body_html = f"""
    <html>
      <body style="font-family: Arial, sans-serif; color: #222;">
        <h2>🚨 SkynetOps Alert — {VM_NAME or 'VM'}</h2>
        <p><strong>Time (UTC):</strong> {now}</p>

        <h3>Alert summary</h3>
        <ul>
          <li><strong>CPU (latest):</strong> {cpu_latest_str}</li>
          <li><strong>Memory free (latest):</strong> {mem_free_str}</li>
          <li><strong>Disk Read (latest):</strong> {disk_read_latest_str}</li>
          <li><strong>Disk Write (latest):</strong> {disk_write_latest_str}</li>
        </ul>

        <h3>Advanced analytics</h3>
        <ul>
          <li>CPU — min: {cpu_min_str}, max: {cpu_max_str}, avg: {cpu_avg_str}</li>
          <li>Memory — min: {mem_min_str}, max: {mem_max_str}, avg: {mem_avg_str}</li>
          <li>Disk Read — min: {disk_read_min_str}, max: {disk_read_max_str}, avg: {disk_read_avg_str}</li>
          <li>Disk Write — min: {disk_write_min_str}, max: {disk_write_max_str}, avg: {disk_write_avg_str}</li>
          <li>CPU anomalies: {int(cpu_anomalies.sum())}</li>
          <li>Disk read anomalies: {int(disk_read_anomalies.sum())}, Disk write anomalies: {int(disk_write_anomalies.sum())}</li>
          <li>CPU forecast (next 3): {cpu_forecast_str}</li>
        </ul>

        <h3>AI Analysis</h3>
        <pre style="background:#f0f0f0; padding:10px; border-radius:5px;">{summary}</pre>

        <p>Attachments: failed-metrics CSV, context CSV, and charts (CPU, memory, disk).</p>
      </body>
    </html>
    """

    print("   ✔ HTML generated")

    attachments = [
        failed_csv,
        ctx_path,
        cpu_line,
        mem_line,
        disk_read_line,
        disk_write_line,
        # cpu_hist,
        pie,
    ]

    print("➡ Sending email...")
    sent = send_email_with_html(subject, body_html, attachments)

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
    html = "<html><body><p>SkynetOps TEST email</p></body></html>"
    return send_email_with_html("[SkynetOps TEST] SMTP Check", html, [])


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
                if TOTAL_MEMORY_BYTES and "Available Memory Bytes" in df["metric"].unique():
                    mem_bytes = float(
                        df.loc[df["metric"] == "Available Memory Bytes"]
                        .sort_values("timestamp")["value"]
                        .iloc[-1]
                    )
                    mem_pct_free = (mem_bytes / TOTAL_MEMORY_BYTES) * 100.0

                alert_reasons = []
                if cpu_latest is not None and cpu_latest > CPU_THRESHOLD:
                    alert_reasons.append("High CPU")
                if mem_pct_free is not None and mem_pct_free < MEM_FREE_PCT_THRESHOLD:
                    alert_reasons.append("Low memory")

                if alert_reasons:
                    print("ALERT detected:", alert_reasons)
                    process_cycle(rows, agent_client)
                else:
                    print(f"No alert: CPU={cpu_latest} Mem%={mem_pct_free}")
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
