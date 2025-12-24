
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SkynetOps — Hybrid Monitoring (Azure VM via SSH)
- Data source: Direct-from-VM (Linux) over SSH (CPU, Memory, Disk capacity, Disk I/O)
- Severity levels (P1/P2/P3), dynamic subjects, CID logo, dark-mode email, inline charts (base64)
- Top-5 Processes (CPU / Memory / Disk I/O) direct from VM — all in table form (summary style)
- Docker containers summary (if Docker CLI available on VM) + Top 5 containers by CPU and Memory
- Cloud AI Analysis via Azure AI Agents (optional but attempted)
- CSV attachments retained for alert details / top processes / docker summary
"""

# ---------------- Stdlib imports ----------------
import os
import sys
import time
import csv
import json
import base64
import smtplib
import html
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from email.mime.image import MIMEImage
import mimetypes

# ---------------- Third-party env loader ----------------
from dotenv import load_dotenv

# ---------------- Charts ----------------
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ---------------- Data & analytics ----------------
try:
    import pandas as pd
    import numpy as np
except Exception:
    print("Missing packages (pandas, numpy, matplotlib). Install: pip install pandas numpy matplotlib paramiko python-dotenv azure-identity azure-ai-agents")
    raise

# ---------------- SSH (remote Azure VM) ----------------
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except Exception:
    PARAMIKO_AVAILABLE = False
    print("⚠️ paramiko not available. Install: pip install paramiko")

# ---------------- Azure AI (optional) ----------------
try:
    from azure.identity import DefaultAzureCredential
    from azure.ai.agents import AgentsClient
    from azure.ai.agents.models import MessageTextContent, MessageRole
    AZURE_AI_AVAILABLE = True
except Exception:
    AZURE_AI_AVAILABLE = False
    print("⚠️ Azure AI SDK not available. To enable AI: pip install azure-identity azure-ai-agents")

# ---------------- Email attachments handling ----------------
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# ---------------- ENV/CONFIG ----------------
load_dotenv()
os.environ["PYTHONIOENCODING"] = "utf-8"

# Azure AI
PROJECT_ENDPOINT = os.getenv("PROJECT_ENDPOINT")
MODEL_DEPLOYMENT = os.getenv("MODEL_DEPLOYMENT_NAME")
AI_DEADLINE_SEC = float(os.getenv("AI_DEADLINE_SEC", 20.0))
AI_POLL_EVERY_SEC = float(os.getenv("AI_POLL_EVERY_SEC", 0.7))
USE_API_KEY = os.getenv("USE_API_KEY", "false").lower() in ("1", "true", "yes")
AZURE_API_KEY = os.getenv("AZURE_API_KEY")

# SSH to Azure VM
VM_HOST = os.getenv("VM_HOST")
VM_PORT = int(os.getenv("VM_PORT", 22))
VM_USER = os.getenv("VM_USER")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH")
SSH_PASSWORD = os.getenv("SSH_PASSWORD")

# Output
OUTPUT_DIR = Path("outputs_skynetops_ssh")
OUTPUT_DIR.mkdir(exist_ok=True)

# Email config
EMAIL_TO = os.getenv("EMAIL_ALERT_TO")
EMAIL_FROM = os.getenv("EMAIL_ALERT_FROM")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.office365.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USERNAME")
SMTP_PASS = os.getenv("SMTP_PASSWORD")

# Threshold defaults (can be overridden by user at runtime)
CPU_THRESHOLD_DEFAULT = float(os.getenv("CPU_THRESHOLD", 80.0))
DISK_THRESHOLD_DEFAULT = float(os.getenv("DISK_THRESHOLD", 85.0))  # % capacity used
MEMORY_THRESHOLD_DEFAULT = float(os.getenv("MEMORY_THRESHOLD", 85.0))  # % used

# Sampling settings
FAST_SAMPLES = int(os.getenv("FAST_SAMPLES", 5))     # micro-series length
SAMPLE_SEC   = float(os.getenv("SAMPLE_SEC", 0.2))   # per sample spacing
FAST_LOOKBACK_MIN = int(os.getenv("FAST_LOOKBACK_MIN", 5))  # for label only

# Emoji control
USE_EMOJI = os.getenv("USE_EMOJI", "1") == "1"

# Branding & behavior
COMPANY_LOGO_PATH = os.getenv("COMPANY_LOGO_PATH")  # e.g., assets/EY-Logo-web.png or absolute path
INLINE_CHARTS = os.getenv("INLINE_CHARTS", "1") == "1"

# Disk mount path (Linux VM)
MOUNT_PATH = os.getenv("MOUNT_PATH", "/")

# Severity margins
SEVERITY_MARGIN_P1 = int(os.getenv("SEVERITY_MARGIN_P1", 20))
SEVERITY_MARGIN_P2 = int(os.getenv("SEVERITY_MARGIN_P2", 10))
SEVERITY_MARGIN_P3 = int(os.getenv("SEVERITY_MARGIN_P3", 0))

# ---------------- Console safety ----------------
def _init_console_encoding() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
_init_console_encoding()

def _icon(unicode_icon: str, fallback: str) -> str:
    if not USE_EMOJI:
        return fallback
    try:
        (sys.stdout.encoding or "utf-8")
        unicode_icon.encode(sys.stdout.encoding or "utf-8", errors="strict")
        return unicode_icon
    except Exception:
        return fallback

ICONS = {
    "gear": _icon("⚙️", "[Process]"),
    "alert": _icon("🚨", "[Alert]"),
    "ok": _icon("✅", "[OK]"),
    "safe": _icon("✅", "[Safe]"),
    "warning": _icon("⚠️", "[Warn]"),
    "cpu": _icon("🧮", "[CPU]"),
    "disk": _icon("💾", "[Disk]"),
    "mem": _icon("🧠", "[Mem]"),
}

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

def utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def resolve_logo_path(env_value: Optional[str]) -> Optional[Path]:
    if not env_value:
        return None

    # Expand env vars & ~
    env_value = os.path.expandvars(os.path.expanduser(env_value))

    # Try absolute
    p = Path(env_value)
    if p.is_absolute() and p.exists():
        return p

    # Try relative to script file
    script_dir = Path(__file__).resolve().parent
    p2 = script_dir / env_value
    if p2.exists():
        return p2.resolve()

    # Try current working dir
    p3 = Path.cwd() / env_value
    if p3.exists():
        return p3.resolve()

    return None


# ---------------- Severity + Subject helpers ----------------
def classify_severity(value: float, threshold: float) -> Optional[str]:
    if value is None or threshold is None:
        return None
    diff = float(value) - float(threshold)
    if diff < SEVERITY_MARGIN_P3:
        return None
    if diff >= SEVERITY_MARGIN_P1:
        return "P1"
    if diff >= SEVERITY_MARGIN_P2:
        return "P2"
    return "P3"

def overall_severity(cpu_s: Optional[str], disk_s: Optional[str], mem_s: Optional[str]) -> Optional[str]:
    order = {"P1": 3, "P2": 2, "P3": 1, None: 0}
    return max([cpu_s, disk_s, mem_s], key=lambda s: order.get(s, 0)) or None

def build_alert_subject(metrics: dict, cpu_thr: float, disk_thr: float, mem_thr: float) -> str:
    cpu_s = classify_severity(metrics.get("cpu_percent"), cpu_thr)
    disk_s = classify_severity(metrics.get("disk_percent"), disk_thr)
    mem_s = classify_severity(metrics.get("memory_percent"), mem_thr)
    overall = overall_severity(cpu_s, disk_s, mem_s) or "Info"

    items = []
    if cpu_s:
        items.append(f"CPU {metrics['cpu_percent']:.1f}% ({cpu_s})")
    if disk_s and metrics.get('disk_percent') is not None:
        items.append(f"Disk {metrics['disk_percent']:.1f}% ({disk_s})")
    if mem_s and metrics.get('memory_percent') is not None:
        items.append(f"Memory {metrics['memory_percent']:.1f}% ({mem_s})")

    prefix = f"🔴 [{overall}] " if (USE_EMOJI and overall != "Info") else f"[{overall}] "
    if len(items) == 1:
        subject = f"{prefix}SkynetOps Alert — {items[0]}"
    elif len(items) > 1:
        subject = f"{prefix}SkynetOps Alert — " + ", ".join(items)
    else:
        subject = f"{ICONS['ok']} SkynetOps — System Healthy" if USE_EMOJI else "SkynetOps — System Healthy"
    return subject

def file_to_base64_datauri(image_path: Optional[Path]) -> Optional[str]:
    if not image_path:
        return None
    try:
        with open(image_path, "rb") as fp:
            b64 = base64.b64encode(fp.read()).decode("ascii")
        ext = image_path.suffix.lower()
        if ext in (".png", ""): mime = "image/png"
        elif ext in (".jpg", ".jpeg"): mime = "image/jpeg"
        elif ext == ".svg": mime = "image/svg+xml"
        else: mime = "application/octet-stream"
        return f"data:{mime};base64,{b64}"
    except Exception:
        return None

# ---------------- SSH Session ----------------
class SSHSession:
    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None

    def __enter__(self):
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko not installed.")
        if not VM_HOST or not VM_USER or (not SSH_KEY_PATH and not SSH_PASSWORD):
            raise ValueError("REMOTE mode requires VM_HOST, VM_USER and SSH_KEY_PATH or SSH_PASSWORD")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if SSH_KEY_PATH and Path(SSH_KEY_PATH).exists():
            pkey = None
            try:
                pkey = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH)
            except Exception:
                pkey = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH)
            client.connect(VM_HOST, port=VM_PORT, username=VM_USER, pkey=pkey, timeout=20, allow_agent=True, look_for_keys=True)
        else:
            client.connect(VM_HOST, port=VM_PORT, username=VM_USER, password=SSH_PASSWORD, timeout=20, allow_agent=True, look_for_keys=True)
        self.client = client
        return self

    def run(self, cmd: str) -> Tuple[str, str, int]:
        assert self.client is not None
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=25)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

# ---------------- Remote Sampling ----------------
def sample_cpu_remote(sess: SSHSession, step: float = SAMPLE_SEC) -> float:
    out1, _, _ = sess.run("cat /proc/stat | head -n 1")
    time.sleep(step)
    out2, _, _ = sess.run("cat /proc/stat | head -n 1")
    def parse(line: str) -> Tuple[int, int]:
        parts = line.strip().split()
        if not parts or parts[0] != "cpu":
            return 0, 0
        vals = list(map(int, parts[1:]))
        idle = vals[3] + vals[4]  # idle + iowait
        total = sum(vals)
        return idle, total
    i1, t1 = parse(out1); i2, t2 = parse(out2)
    dt = t2 - t1; di = i2 - i1
    return 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / dt)) * 100.0))

def mem_used_pct_remote(sess: SSHSession) -> Optional[float]:
    out, _, _ = sess.run("cat /proc/meminfo")
    mt = ma = None
    for line in out.splitlines():
        if line.startswith("MemTotal:"):
            mt = int(line.split()[1]) * 1024
        if line.startswith("MemAvailable:"):
            ma = int(line.split()[1]) * 1024
    if mt and ma:
        used_pct = (1.0 - (ma / mt)) * 100.0
        return max(0.0, min(100.0, used_pct))
    return None

def disk_capacity_used_remote(sess: SSHSession, mount: str = MOUNT_PATH) -> Optional[float]:
    mount = mount if mount.startswith("/") else "/"
    out, _, rc = sess.run(f"df -P {mount} | tail -n 1 | awk '{{print $5}}'")
    if rc == 0 and out.strip():
        try:
            val = float(out.strip().replace('%', '').strip())
            return max(0.0, min(100.0, val))
        except Exception:
            return None
    return None

def disk_bps_remote(sess: SSHSession, step: float = SAMPLE_SEC) -> Tuple[float, float]:
    out1, _, _ = sess.run("cat /proc/diskstats"); t1 = time.time()
    time.sleep(step)
    out2, _, _ = sess.run("cat /proc/diskstats"); t2 = time.time()
    def rdwr(out: str) -> Tuple[int, int]:
        r = w = 0
        for ln in out.splitlines():
            p = ln.split()
            if len(p) >= 14:
                try:
                    r += int(p[5]) * 512
                    w += int(p[9]) * 512
                except Exception:
                    pass
        return r, w
    r1, w1 = rdwr(out1); r2, w2 = rdwr(out2)
    dt = max(0.001, t2 - t1)
    return max(0.0, (r2 - r1) / dt), max(0.0, (w2 - w1) / dt)

def top5_cpu_remote(sess: SSHSession) -> List[Dict[str, Any]]:
    out, _, _ = sess.run(r"ps -eo pid,user,pcpu,pmem,rss,comm --sort=-pcpu | head -n 6")
    rows = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) >= 6:
            pid, user, pcpu, pmem, rss, comm = parts[:6]
            rows.append({"Computer": VM_HOST or "VM", "PID": int(pid), "Process": comm, "User": user, "CPUPercent": float(pcpu), "RSSBytes": int(rss) * 1024})
    return rows[:5]

def top5_memory_remote(sess: SSHSession) -> List[Dict[str, Any]]:
    out, _, _ = sess.run(r"ps -eo pid,user,pcpu,pmem,rss,comm --sort=-rss | head -n 6")
    rows = []
    for line in out.strip().splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) >= 6:
            pid, user, pcpu, pmem, rss, comm = parts[:6]
            rows.append({"Computer": VM_HOST or "VM", "PID": int(pid), "Process": comm, "User": user, "CPUPercent": float(pcpu), "RSSBytes": int(rss) * 1024})
    return rows[:5]

def top5_disk_remote(sess: SSHSession, step: float = SAMPLE_SEC) -> List[Dict[str, Any]]:
    out, _, _ = sess.run(r"ps -eo pid --sort=-pcpu | head -n 31")
    pids = [int(x.strip()) for x in out.strip().splitlines()[1:] if x.strip().isdigit()]
    def read_io(pid: int) -> Tuple[int, int]:
        o, _, _ = sess.run(f"cat /proc/{pid}/io 2>/dev/null || true")
        rb = wb = 0
        for ln in o.splitlines():
            if ln.startswith("read_bytes:"):
                rb = int(ln.split()[1])
            if ln.startswith("write_bytes:"):
                wb = int(ln.split()[1])
        return rb, wb
    io1 = {pid: read_io(pid) for pid in pids}
    time.sleep(step)
    rows = []
    for pid in pids:
        rb2, wb2 = read_io(pid); rb1, wb1 = io1.get(pid, (rb2, wb2))
        rows.append({"Computer": VM_HOST or "VM", "PID": pid, "Process": "", "ReadBps": max(0.0, (rb2 - rb1) / step), "WriteBps": max(0.0, (wb2 - wb1) / step)})
    if pids:
        ps_o, _, _ = sess.run("ps -o pid,comm -p " + ",".join(map(str, pids)))
        names = {}
        for ln in ps_o.splitlines()[1:]:
            parts = ln.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                names[int(parts[0])] = parts[1]
        for r in rows:
            r["Process"] = names.get(r["PID"], str(r["PID"]))
    rows.sort(key=lambda x: x.get("ReadBps", 0.0) + x.get("WriteBps", 0.0), reverse=True)
    for r in rows:
        r["TotalBps"] = r["ReadBps"] + r["WriteBps"]
    return rows[:5]

# ---------------- Docker helpers (REMOTE via CLI) ----------------
def docker_available_remote(sess: SSHSession) -> bool:
    out, _, rc = sess.run("command -v docker >/dev/null 2>&1 && echo OK || echo NO")
    return (rc == 0 and "OK" in out)

def _pct_to_float(s: str) -> float:
    try:
        return float(str(s).strip().replace("%", ""))
    except Exception:
        return 0.0

def _parse_mem_usage(s: str) -> Tuple[float, float]:
    """
    Parse strings like '10.24MiB / 1GiB' into (used_bytes, limit_bytes).
    """
    try:
        parts = [p.strip() for p in s.split("/")]
        used = parts[0]; limit = parts[1]
        def to_bytes(x: str) -> float:
            m = re.match(r"([0-9]*\.?[0-9]+)\s*([KMGTP]?i?B)", x, re.I)
            if not m:
                return float(x) if x.replace(".", "", 1).isdigit() else 0.0
            val = float(m.group(1)); unit = m.group(2).lower()
            mult = {"b":1, "kib":1024, "kb":1000, "mib":1024**2, "mb":1000**2,
                    "gib":1024**3, "gb":1000**3, "tib":1024**4, "tb":1000**4,
                    "pib":1024**5, "pb":1000**5}.get(unit,1)
            return val * mult
        return to_bytes(used), to_bytes(limit)
    except Exception:
        return 0.0, 0.0

def docker_summary_remote(sess: SSHSession) -> List[Dict[str, Any]]:
    if not docker_available_remote(sess):
        return []
    fmt_ps = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
    out_ps, _, _ = sess.run(f"docker ps --format '{fmt_ps}'")
    ps_rows = {}
    for ln in out_ps.strip().splitlines():
        parts = ln.split("\t")
        if len(parts) >= 4:
            cid, name, img, status = parts[:4]
            ps_rows[cid] = {"ID": cid, "Name": name, "Image": img, "Status": status}

    fmt_st = "{{.Container}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}"
    out_st, _, _ = sess.run(f"docker stats --no-stream --format '{fmt_st}'")
    rows: List[Dict[str, Any]] = []
    for ln in out_st.strip().splitlines():
        parts = ln.split("\t")
        if len(parts) >= 7:
            cid, name, cpu_s, mem_usage, mem_pct_s, net_io, block_io = parts[:7]
            used_b, lim_b = _parse_mem_usage(mem_usage)
            row = {
                "ID": cid, "Name": name, "Image": ps_rows.get(cid, {}).get("Image", ""),
                "Status": ps_rows.get(cid, {}).get("Status", ""),
                "CPUPercent": _pct_to_float(cpu_s),
                "MemPercent": _pct_to_float(mem_pct_s),
                "MemUsageBytes": used_b, "MemLimitBytes": lim_b,
                "NetIO": net_io, "BlockIO": block_io
            }
            rows.append(row)
    if not rows and ps_rows:
        rows = [{"ID": cid, **ps_rows[cid],
                 "CPUPercent": 0.0, "MemPercent": 0.0,
                 "MemUsageBytes": 0.0, "MemLimitBytes": 0.0, "NetIO":"", "BlockIO":""}
                for cid in ps_rows.keys()]
    return rows

def render_docker_html(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<h3>Docker Summary</h3><p>No Docker data (CLI unavailable or daemon not running).</p>"

    def row_html(r: Dict[str, Any]) -> str:
        return (
            "<tr>"
            f"<td>{html.escape(r.get('ID',''))}</td>"
            f"<td>{html.escape(r.get('Name',''))}</td>"
            f"<td>{html.escape(r.get('Image',''))}</td>"
            f"<td>{html.escape(r.get('Status',''))}</td>"
            f"<td style='text-align:right'>{float(r.get('CPUPercent',0.0)):.2f}%</td>"
            f"<td style='text-align:right'>{float(r.get('MemPercent',0.0)):.2f}%</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('MemUsageBytes',0.0)))}</td>"
            f"<td>{html.escape(r.get('NetIO',''))}</td>"
            f"<td>{html.escape(r.get('BlockIO',''))}</td>"
            "</tr>"
        )

    # Top 5 by CPU and Memory
    top_cpu = sorted(rows, key=lambda r: float(r.get("CPUPercent",0.0)), reverse=True)[:5]
    top_mem = sorted(rows, key=lambda r: float(r.get("MemUsageBytes",0.0)), reverse=True)[:5]

    def simple_list_html(title: str, data: List[Dict[str,Any]], cols: List[str]) -> str:
        header = "<tr>" + "".join([f"<th>{c}</th>" for c in cols]) + "</tr>"
        body = ""
        for r in data:
            cells = []
            for c in cols:
                v = r.get(c)
                if c == "CPUPercent":
                    v = f"{float(v or 0.0):.2f}%"
                elif c == "MemUsageBytes":
                    v = human_bytes(float(v or 0.0))
                cells.append(f"<td>{html.escape(str(v)) if v is not None else ''}</td>")
            body += "<tr>" + "".join(cells) + "</tr>"
        return (
            f"<h4>{title}</h4>"
            "<table class='summary' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
            f"<thead>{header}</thead><tbody>{body or '<tr><td colspan=99>No data</td></tr>'}</tbody></table>"
        )

    full_table = (
        "<h3>Docker Summary</h3>"
        "<table class='summary' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
        "<thead><tr>"
        "<th>ID</th><th>Name</th><th>Image</th><th>Status</th>"
        "<th>CPU %</th><th>Mem %</th><th>Mem Used</th><th>Net I/O</th><th>Block I/O</th>"
        "</tr></thead>"
        "<tbody>"
        + "".join([row_html(r) for r in rows])
        + "</tbody></table>"
    )

    top_cpu_table = simple_list_html("Top 5 Containers — CPU", top_cpu, ["Name","ID","Image","CPUPercent"])
    top_mem_table = simple_list_html("Top 5 Containers — Memory", top_mem, ["Name","ID","Image","MemUsageBytes"])
    return full_table + top_cpu_table + top_mem_table

def save_docker_csv(rows: List[Dict[str,Any]]) -> Optional[Path]:
    if not rows:
        return None
    p = OUTPUT_DIR / f"docker_summary_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ID","Name","Image","Status","CPUPercent","MemPercent","MemUsageBytes","MemLimitBytes","NetIO","BlockIO"])
        for r in rows:
            w.writerow([
                r.get("ID",""), r.get("Name",""), r.get("Image",""), r.get("Status",""),
                r.get("CPUPercent",0.0), r.get("MemPercent",0.0),
                r.get("MemUsageBytes",0.0), r.get("MemLimitBytes",0.0),
                r.get("NetIO",""), r.get("BlockIO","")
            ])
    return p

# ---------------- Dataframe utilities ----------------
def rows_to_df(rows: List[List]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame(columns=["timestamp", "metric", "value"])
    df = pd.DataFrame(rows, columns=["timestamp", "metric", "value"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df

# ---------------- Charts ----------------
def generate_line_chart(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    dfm = df[df["metric"] == metric_name].sort_values("timestamp")
    out = OUTPUT_DIR / out_name
    if dfm.empty:
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, "No data", ha="center", va="center")
        plt.axis("off")
        plt.savefig(out, bbox_inches="tight", dpi=100)
        plt.close()
        return out
    plt.figure(figsize=(8, 3.5))
    plt.plot(dfm["timestamp"], dfm["value"], marker="o", linewidth=1.5, label=metric_name, color="#2196F3")
    if len(dfm) > 2:
        ma = dfm["value"].rolling(window=max(2, int(len(dfm) / 2)), min_periods=1).mean()
        plt.plot(dfm["timestamp"], ma, linestyle="--", label="Moving Avg", color="#FF9800", linewidth=1)
        plt.fill_between(dfm["timestamp"], dfm["value"], ma, alpha=0.1)
    plt.title(f"{metric_name}", fontsize=12, fontweight="bold")
    plt.xlabel("Time", fontsize=10)
    plt.ylabel(metric_name, fontsize=10)
    plt.legend(fontsize=9)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(out, dpi=120, bbox_inches="tight")
    plt.close()
    return out

def generate_pie_chart(cpu_value: float, disk_value: Optional[float], mem_value: Optional[float], out_name: str) -> Path:
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.5))
    # CPU
    cpu_used = max(0.0, min(100.0, float(cpu_value or 0)))
    cpu_free = 100.0 - cpu_used
    axes[0].pie([cpu_used, cpu_free], labels=["Used", "Free"], autopct="%1.1f%%", colors=["#FF6B6B", "#4ECDC4"], startangle=90)
    axes[0].set_title(f"CPU ({cpu_used:.1f}%)", fontweight="bold")
    # Disk
    if disk_value is not None:
        disk_used = max(0.0, min(100.0, float(disk_value or 0)))
        disk_free = 100.0 - disk_used
        axes[1].pie([disk_used, disk_free], labels=["Used", "Free"], autopct="%1.1f%%", colors=["#FF6B6B", "#4ECDC4"], startangle=90)
        axes[1].set_title(f"Disk ({disk_used:.1f}%)", fontweight="bold")
    else:
        axes[1].axis("off")
        axes[1].text(0.5, 0.5, "Disk % N/A", ha="center", va="center")
    # Memory
    if mem_value is not None:
        mem_used = max(0.0, min(100.0, float(mem_value or 0)))
        mem_free = 100.0 - mem_used
        axes[2].pie([mem_used, mem_free], labels=["Used", "Free"], autopct="%1.1f%%", colors=["#FF6B6B", "#4ECDC4"], startangle=90)
        axes[2].set_title(f"Memory ({mem_used:.1f}%)", fontweight="bold")
    else:
        axes[2].axis("off")
        axes[2].text(0.5, 0.5, "Memory % N/A", ha="center", va="center")
    plt.tight_layout()
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

def build_alert_csv(metrics: dict, health: dict, cpu_threshold: float, disk_threshold: float, mem_threshold: float) -> Path:
    p = OUTPUT_DIR / f"alert_report_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "metric", "value", "threshold", "status"])
        w.writerow([metrics["timestamp"], "CPU %", metrics.get("cpu_percent"), cpu_threshold, health["cpu_status"]])
        w.writerow([metrics["timestamp"], "Disk %", metrics.get("disk_percent"), disk_threshold, health["disk_status"]])
        w.writerow([metrics["timestamp"], "Memory %", metrics.get("memory_percent"), mem_threshold, health["memory_status"]])
    return p

def save_top_csv(name: str, rows: List[Dict[str,Any]], cols: List[str]) -> Path:
    p = OUTPUT_DIR / f"{name}_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c) for c in cols])
    return p

# ---------------- Email ----------------
def send_email_with_html(subject: str, html_body: str, attachments: List[Path], cid_images: List[Tuple[str, Path]] = None) -> bool:
    if not (EMAIL_TO and EMAIL_FROM and SMTP_USER and SMTP_PASS and SMTP_SERVER):
        print(f"{ICONS['warning']} Email not sent - SMTP config missing in .env")
        return False
    try:
        msg = MIMEMultipart("mixed")
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO
        msg["Subject"] = subject

        related = MIMEMultipart("related")
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(html_body, "html"))
        related.attach(alt)
        msg.attach(related)

        

        # CID images
        for cid, img_path in (cid_images or []):
            try:
                with open(img_path, "rb") as fp:
                    img_data = fp.read()

                mime_type, _ = mimetypes.guess_type(img_path)
                subtype = mime_type.split("/")[-1] if mime_type else "png"

                img = MIMEImage(img_data, _subtype=subtype)
                img.add_header("Content-ID", f"<{cid}>")
                img.add_header("Content-Disposition", "inline", filename=img_path.name)

                related.attach(img)
                print(f"✔ CID image attached: {img_path}")

            except Exception as e:
                print("❌ Failed CID attach:", img_path, e)




        # Attachments
        for file_path in attachments or []:
            try:
                if not file_path or not Path(file_path).exists():
                    continue
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

        print("Email sent:", subject)
        return True
    except Exception as e:
        print("Email send error:", e)
        return False

# ---------------- Cloud AI (optional but attempted) ----------------
def _extract_text_from_block(block) -> Optional[str]:
    try:
        if isinstance(block, MessageTextContent):
            txt_obj = getattr(block, "text", None)
            return getattr(txt_obj, "value", None) or (str(txt_obj) if txt_obj is not None else None)
    except Exception:
        pass
    if isinstance(block, dict):
        if block.get("type") == "text":
            t = block.get("text")
            if isinstance(t, dict):
                return t.get("value") or t.get("text") or ""
            return str(t) if t is not None else ""
        for key in ("value", "text"):
            v = block.get(key)
            if isinstance(v, dict):
                return v.get("value") or v.get("text") or ""
            if v:
                return str(v)
    t = getattr(block, "text", None)
    if isinstance(t, dict):
        return t.get("value") or t.get("text") or ""
    return (getattr(t, "value", None) or (str(t) if t is not None else None))

def _normalize_vm_health_text(text: str) -> str:
    if not text:
        return text
    lines = [ln.rstrip() for ln in text.splitlines()]
    def _humanize_bytes(val: float) -> str:
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        while val >= 1024.0 and i < len(units)-1:
            val /= 1024.0
            i += 1
        return f"{val:0.2f} {units[i]}"
    disk_patterns = [
        (re.compile(r"^-?\s*Disk Read\s*\(.*?\):\s*([0-9]*\.?[0-9]+)"), "Disk Read"),
        (re.compile(r"^-?\s*Disk Write\s*\(.*?\):\s*([0-9]*\.?[0-9]+)"), "Disk Write"),
    ]
    for idx, ln in enumerate(lines):
        for pat, label in disk_patterns:
            m = pat.match(ln.strip())
            if m:
                try:
                    val = float(m.group(1))
                except Exception:
                    continue
                lines[idx] = f"- {label} (avg): {_humanize_bytes(val)}"
                break
    def _map_forecast_label(ln: str) -> str:
        m = re.match(r"^-\s*CPU\s*(\d+)\s*m:\s*(.+)$", ln.strip())
        if not m:
            return ln
        mins = int(m.group(1)); val = m.group(2).strip()
        plus = {15: "+1", 30: "+2", 60: "+3"}.get(mins)
        return f"- CPU {plus}: {val}" if plus else ln
    lines = [(_map_forecast_label(ln)) for ln in lines]
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip().lower().startswith("recommendations:"))
        recs = []
        for j in range(start+1, len(lines)):
            s = lines[j].strip()
            if not s or (not s.startswith("- ") and ":" in s and s.split(":")[0].istitle()):
                break
            if s.startswith("- "):
                val = s[2:].strip()
                if val and val not in recs:
                    recs.append(val)
        recs = recs[:5]
        new_block = ["Recommendations:"] + [f"- {r}" for r in recs]
        k = start + 1
        while k < len(lines) and lines[k].strip().startswith("- "):
            k += 1
        lines = lines[:start] + new_block + lines[k:]
    except StopIteration:
        pass
    return "\n".join(lines).strip()

def run_cloud_ai_mandatory(df: pd.DataFrame) -> str:
    if not AZURE_AI_AVAILABLE:
        return "❌ Cloud AI error: SDK missing."
    try:
        if USE_API_KEY and AZURE_API_KEY:
            agent_client = AgentsClient(endpoint=PROJECT_ENDPOINT, api_key=AZURE_API_KEY)  # type: ignore
        else:
            _credential = DefaultAzureCredential(exclude_cli_credential=False)
            agent_client = AgentsClient(endpoint=PROJECT_ENDPOINT, credential=_credential)

        cpu_df        = df[df["metric"] == "Percentage CPU"].sort_values("timestamp")
        disk_read_df  = df[df["metric"] == "Disk Read Bytes"].sort_values("timestamp")
        disk_write_df = df[df["metric"] == "Disk Write Bytes"].sort_values("timestamp")
        if cpu_df.empty and disk_read_df.empty and disk_write_df.empty:
            return "⚠ Cloud AI: no metrics to analyze."
        def to_series_list(dff: pd.DataFrame) -> List[Dict[str, Any]]:
            return [{"timestamp": str(r.timestamp), "value": float(r.value)} for r in dff.itertuples()]

        payload = {
            "cpu": to_series_list(cpu_df),
            "disk_read": to_series_list(disk_read_df),
            "disk_write": to_series_list(disk_write_df),
        }

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
            "- Disk health status (Normal | Saturated | Highly active).\n"
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
            "BOTTLENECKS:\n"
            "- <issue>\n"
            "- <issue>\n"
            "- <issue>\n"
            "Recommendations:\n"
            "- <action 1>\n"
            "- <action 2>\n"
            "- <action 3>\n"
            "- <action 4>\n"
            "- <action 5>\n"
            "- <action 6>\n"
        )

        agent = agent_client.create_agent(
            model=MODEL_DEPLOYMENT,
            name=f"skynetops-agent-{int(time.time())}",
            instructions=instructions,
            tools=[],
        )
        thread = agent_client.threads.create()
        agent_client.messages.create(
            thread_id=thread.id,
            role="user",
            content=f"Here is the VM CPU and disk data in JSON:\n{payload}\n\nProvide the VM Health Summary.",
        )
        run = agent_client.runs.create(thread_id=thread.id, agent_id=agent.id)

        deadline = time.time() + AI_DEADLINE_SEC
        status = getattr(run, "status", None)
        while status not in ("completed", "failed", "cancelled", "expired") and time.time() < deadline:
            time.sleep(AI_POLL_EVERY_SEC)
            run = agent_client.runs.get(thread_id=thread.id, run_id=run.id)
            status = getattr(run, "status", None)

        if status != "completed":
            try:
                agent_client.agents.delete_agent(agent.id)
            except Exception:
                pass

        try:
            messages = agent_client.messages.list(thread_id=thread.id, order="asc")
            summary_parts: List[str] = []
            for msg in messages:
                role_val = getattr(msg, "role", None)
                if role_val == MessageRole.AGENT or str(role_val).lower() == "assistant":
                    if getattr(msg, "text_messages", None):
                        for text_msg in msg.text_messages:
                            try:
                                summary_parts.append(text_msg.text.value)
                            except Exception:
                                if hasattr(text_msg, "text"):
                                    summary_parts.append(str(text_msg.text))
                        continue
                    content = getattr(msg, "content", None)
                    if content:
                        for block in content:
                            text_val = _extract_text_from_block(block)
                            if text_val:
                                summary_parts.append(text_val)
            try:
                agent_client.agents.delete_agent(agent.id)
            except Exception:
                pass
            summary = "\n".join([s for s in summary_parts if s]).strip()
            if not summary:
                return "⚠ Agent returned no analysis."
            return _normalize_vm_health_text(summary)
        except Exception as e:
            try:
                agent_client.agents.delete_agent(agent.id)
            except Exception:
                pass
            return f"⚠ Error parsing agent messages: {e}"
    except Exception as e:
        return f"❌ Cloud AI error: {e}"

# ---------------- Health check & HTML sections ----------------
def check_remote_health(metrics: dict, cpu_threshold: float, disk_threshold: float, mem_threshold: float) -> dict:
    alerts = []
    cpu_status = f"{ICONS['safe']} Safe"
    disk_status = f"{ICONS['safe']} Safe"
    mem_status = f"{ICONS['safe']} Safe"

    if metrics.get("cpu_percent") is not None and metrics["cpu_percent"] > cpu_threshold:
        cpu_status = f"{ICONS['alert']} HIGH ({metrics['cpu_percent']:.2f}%)"
        alerts.append(f"HIGH CPU usage >{cpu_threshold}%: {metrics['cpu_percent']:.2f}%")
    else:
        cpu_status = f"{ICONS['safe']} Safe ({metrics.get('cpu_percent', 0.0):.2f}%)"

    if metrics.get("disk_percent") is not None:
        if metrics["disk_percent"] > disk_threshold:
            disk_status = f"{ICONS['alert']} HIGH ({metrics['disk_percent']:.2f}%)"
            alerts.append(f"HIGH Disk capacity used >{disk_threshold}%: {metrics['disk_percent']:.2f}%")
        else:
            disk_status = f"{ICONS['safe']} Safe ({metrics['disk_percent']:.2f}%)"
    else:
        disk_status = f"{ICONS['warning']} N/A (capacity metric unavailable)"

    if metrics.get("memory_percent") is not None:
        if metrics["memory_percent"] > mem_threshold:
            mem_status = f"{ICONS['alert']} HIGH ({metrics['memory_percent']:.2f}%)"
            alerts.append(f"HIGH Memory usage >{mem_threshold}%: {metrics['memory_percent']:.2f}%")
        else:
            mem_status = f"{ICONS['safe']} Safe ({metrics['memory_percent']:.2f}%)"
    else:
        mem_status = f"{ICONS['warning']} N/A (metric unavailable)"

    return {
        "is_healthy": len(alerts) == 0,
        "cpu_status": cpu_status,
        "disk_status": disk_status,
        "memory_status": mem_status,
        "alerts": alerts,
    }

def html_table_top_cpu(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<p>No process data available.</p>"
    tr = []
    for r in rows:
        tr.append(
            "<tr>"
            f"<td>{r.get('PID','')}</td>"
            f"<td>{html.escape(str(r.get('Process','')))}</td>"
            f"<td>{html.escape(str(r.get('User','')))}</td>"
            f"<td style='text-align:right'>{float(r.get('CPUPercent',0.0)):.1f}%</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('RSSBytes',0.0)))}</td>"
            "</tr>"
        )
    return (
        "<table class='summary' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
        "<thead><tr>"
        "<th>PID</th><th>Name</th><th>User</th><th>CPU %</th><th>RSS</th>"
        "</tr></thead><tbody>" + "".join(tr) + "</tbody></table>"
    )

def html_table_top_mem(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<p>No process data available.</p>"
    tr = []
    for r in rows:
        tr.append(
            "<tr>"
            f"<td>{r.get('PID','')}</td>"
            f"<td>{html.escape(str(r.get('Process','')))}</td>"
            f"<td>{html.escape(str(r.get('User','')))}</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('RSSBytes',0.0)))}</td>"
            f"<td style='text-align:right'>{float(r.get('CPUPercent',0.0)):.1f}%</td>"
            "</tr>"
        )
    return (
        "<table class='summary' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
        "<thead><tr>"
        "<th>PID</th><th>Name</th><th>User</th><th>RSS</th><th>CPU %</th>"
        "</tr></thead><tbody>" + "".join(tr) + "</tbody></table>"
    )

def html_table_top_io(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "<p>No process data available.</p>"
    tr = []
    for r in rows:
        tr.append(
            "<tr>"
            f"<td>{r.get('PID','')}</td>"
            f"<td>{html.escape(str(r.get('Process','')))}</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('ReadBps',0.0)))}/s</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('WriteBps',0.0)))}/s</td>"
            f"<td style='text-align:right'>{human_bytes(float(r.get('TotalBps',0.0)))}/s</td>"
            "</tr>"
        )
    return (
        "<table class='summary' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
        "<thead><tr>"
        "<th>PID</th><th>Name</th><th>Read</th><th>Write</th><th>Total</th>"
        "</tr></thead><tbody>" + "".join(tr) + "</tbody></table>"
    )

# ---------------- Main alert workflow ----------------
def process_health_alert(
    metrics: dict,
    health: dict,
    cpu_threshold: float,
    disk_threshold: float,
    mem_threshold: float,
    df_micro: pd.DataFrame,
    cpu_line_chart: Optional[Path],
    docker_rows: Optional[List[Dict[str,Any]]] = None
) -> bool:
    print("=" * 70)
    print(f"{ICONS['gear']} Processing system health alert (Remote SSH)...")
    print("=" * 70)

    # Charts
    charts: List[Path] = []
    pie_chart = generate_pie_chart(metrics.get("cpu_percent", 0.0), metrics.get("disk_percent"), metrics.get("memory_percent"), f"health_pies_{int(time.time())}.png")
    charts.append(pie_chart)
    if cpu_line_chart:
        charts.append(cpu_line_chart)

    # Inline base64
    pie_data_uri = file_to_base64_datauri(pie_chart) if INLINE_CHARTS else None
    cpu_data_uri = file_to_base64_datauri(cpu_line_chart) if (INLINE_CHARTS and cpu_line_chart) else None

    # AI Analysis (Cloud)
    ai_analysis = run_cloud_ai_mandatory(df_micro)

    # Severity classification
    cpu_alert = metrics.get("cpu_percent") is not None and metrics["cpu_percent"] > cpu_threshold
    disk_alert = metrics.get("disk_percent") is not None and metrics["disk_percent"] > disk_threshold
    mem_alert  = metrics.get("memory_percent") is not None and metrics["memory_percent"] > mem_threshold

    cpu_sev = classify_severity(metrics.get("cpu_percent", 0.0), cpu_threshold) if cpu_alert else None
    disk_sev = classify_severity(metrics.get("disk_percent", 0.0), disk_threshold) if disk_alert else None
    mem_sev  = classify_severity(metrics.get("memory_percent", 0.0), mem_threshold)  if mem_alert  else None
    overall  = overall_severity(cpu_sev, disk_sev, mem_sev) or "Info"

    # Top processes from VM
    top_cpu = metrics.get("top_cpu", []) if cpu_alert else []
    top_mem = metrics.get("top_mem", []) if mem_alert else []
    top_io  = metrics.get("top_io", [])  if disk_alert else []

    # Docker HTML
    docker_html = render_docker_html(docker_rows or [])

    # Build CSVs
    alert_csv = build_alert_csv(metrics, health, cpu_threshold, disk_threshold, mem_threshold)
    proc_csvs: List[Path] = []
    if top_cpu: proc_csvs.append(save_top_csv("top_cpu", top_cpu, ["Computer","PID","Process","User","CPUPercent","RSSBytes"]))
    if top_mem: proc_csvs.append(save_top_csv("top_mem", top_mem, ["Computer","PID","Process","User","RSSBytes","CPUPercent"]))
    if top_io:  proc_csvs.append(save_top_csv("top_disk_io", top_io, ["Computer","PID","Process","ReadBps","WriteBps","TotalBps"]))
    docker_csv = save_docker_csv(docker_rows or [])
    if docker_csv: proc_csvs.append(docker_csv)

    # Process tables (HTML)
    cpu_section = "<h3>Top 5 CPU Processes</h3>" + html_table_top_cpu(top_cpu) if cpu_alert else ""
    mem_section = "<h3>Top 5 Memory Processes</h3>" + html_table_top_mem(top_mem) if mem_alert else ""
    disk_section = (
        "<h3>Top 5 Disk I/O Processes</h3>"
        f"<p style='color:#555'>Sorted by total bytes/sec (read+write). Sampling window ~{SAMPLE_SEC:.1f}s.</p>"
        + html_table_top_io(top_io)
    ) if disk_alert else ""

    # Alerts list
    if health["alerts"]:
        alerts_html = "<ul>" + "".join(f"<li style='color:#D32F2F'><strong>{html.escape(a)}</strong></li>" for a in health["alerts"]) + "</ul>"
    else:
        alerts_html = "<p style='color:#388E3C'>No alerts</p>"

    print("➡ Building HTML email body...")
    now = utc_iso_now()
    subject = build_alert_subject(metrics, cpu_threshold, disk_threshold, mem_threshold)

    # CID logo setup
    

# ---------------- Branding (CID Logo) ----------------


# ---------------- Branding (CID Logo) ----------------
    cid_images: list[tuple[str, Path]] = []
    logo_cid = "company_logo"

    # Header: keep text fallback only (no logo in header)
    header_brand_tag = '<span style="font-weight:600">SkynetOps Monitoring</span>'

    # Footer: start empty; fill only if logo is resolved
    footer_logo_tag = ""

    logo_path = resolve_logo_path(COMPANY_LOGO_PATH)
    if logo_path and logo_path.exists():
        cid_images.append((logo_cid, logo_path))
        # ✅ Footer logo image tag (CID)
        footer_logo_tag = (
            f'<img src="cid:{logo_cid}" alt="Company Logo" '
            f'style="height:28px; vertical-align:middle; display:inline-block;" />'
        )


    body_html = f"""
<html>
<head>
<meta charset="utf-8" />
<style>
  body {{
    margin:0; padding:0; background-color:#f4f6f8;
    font-family:Segoe UI, Arial, sans-serif; color:#1f2933;
  }}
  .card {{
    background:#ffffff; border-radius:8px;
    box-shadow:0 2px 10px rgba(0,0,0,0.08);
  }}
  .muted {{ color:#6b7280; }}
  .danger {{ color:#b91c1c; }}
  table.summary th, table.summary td {{
    border:1px solid #e5e7eb; font-size:14px; padding:8px;
  }}
  table.summary thead tr {{ background:#f9fafb; }}
  pre.block {{
    background:#f9fafb; border:1px solid #e5e7eb;
    padding:14px; border-radius:6px; font-size:13px; white-space:pre-wrap;
  }}
  @media (prefers-color-scheme: dark) {{
    body {{ background-color:#0b0f14; color:#e5e7eb; }}
    .card {{ background:#111827; box-shadow:none; }}
    .muted {{ color:#9aa4b2; }}
    .danger {{ color:#f87171; }}
    table.summary th, table.summary td {{ border-color:#334155; }}
    table.summary thead tr {{ background:#1f2937; }}
    pre.block {{ background:#1f2937; border-color:#334155; }}
  }}
</style>
</head>
<body>

<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:24px 0;">

<table width="900" cellpadding="0" cellspacing="0" class="card">


<!-- Header -->
<tr><td style="padding:20px 30px; border-bottom:1px solid #e5e7eb;">
  <table width="100%"><tr>
    <td align="left" style="font-size:18px; font-weight:600; color:#111827;">
      {header_brand_tag}
    </td>
    <td align="right" class="muted" style="font-size:13px;">
      System Health Alert — {overall}
    </td>
  </tr></table>
</td></tr>


<!-- Title -->
<tr><td style="padding:25px 30px;">
  <h2 class="danger" style="margin:0;">{'🚨 ' if USE_EMOJI else ''}Alert Detected</h2>
  <p style="margin:8px 0 0;">One or more system metrics have exceeded configured thresholds.</p>
  <p class="muted" style="margin-top:6px; font-size:13px;">
    <strong>Timestamp (UTC):</strong> {now}
  </p>
</td></tr>

<!-- Summary Table -->
<tr><td style="padding:0 30px 20px;">
  <h3 style="margin-bottom:10px;">Alert Summary</h3>

  <table class="summary" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
    <thead>
      <tr>
        <th align="left">Metric</th>
        <th align="left">Current</th>
        <th align="left">Threshold</th>
        <th align="left">Status</th>
        <th align="left">Severity</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>CPU Usage</td>
        <td>{metrics.get('cpu_percent', 0.0):.2f}%</td>
        <td>{cpu_threshold}%</td>
        <td>{health['cpu_status']}</td>
        <td>{cpu_sev or '-'}</td>
      </tr>
      <tr>
        <td>Disk Usage</td>
        <td>{f"{metrics['disk_percent']:.2f}%" if metrics.get('disk_percent') is not None else "N/A"}</td>
        <td>{disk_threshold}%</td>
        <td>{health['disk_status']}</td>
        <td>{disk_sev or '-'}</td>
      </tr>
      <tr>
        <td>Memory Usage</td>
        <td>{metrics.get('memory_percent', float('nan')):.2f}%</td>
        <td>{mem_threshold}%</td>
        <td>{health['memory_status']}</td>
        <td>{mem_sev or '-'}</td>
      </tr>
    </tbody>
  </table>
</td></tr>

<!-- Visuals (stacked one-by-one) -->
<tr><td style="padding:0 30px 10px;">
  <h3>Visuals</h3>

  <div style="border:1px solid #e5e7eb; border-radius:6px; padding:8px; margin-bottom:12px;">
    <div class="muted" style="margin-bottom:6px;">Current Health (Pie)</div>
    {('<img alt="health_pie" src="' + (pie_data_uri or '') + '" style="max-width:100%; border-radius:4px;" />') if pie_data_uri else '<p class="muted">No chart</p>'}
  </div>

  <div style="border:1px solid #e5e7eb; border-radius:6px; padding:8px; margin-bottom:12px;">
    <div class="muted" style="margin-bottom:6px;">Azure VM CPU (Last {FAST_LOOKBACK_MIN}m)</div>
    {('<img alt="azure_cpu" src="' + (cpu_data_uri or '') + '" style="max-width:100%; border-radius:4px;" />') if cpu_data_uri else '<p class="muted">No Azure CPU data</p>'}
  </div>
</td></tr>

<!-- Alerts -->
<tr><td style="padding:0 30px 20px;">
  <h3>Triggered Alerts</h3>
  {alerts_html}
</td></tr>

<!-- Docker Summary -->
<tr><td style="padding:0 30px 20px;">
  {docker_html}
</td></tr>

<!-- Top Processes -->
<tr><td style="padding:0 30px 20px;">
  {cpu_section}
  {mem_section}
  {disk_section}
</td></tr>

<!-- AI Analysis -->
<tr><td style="padding:0 30px 30px;">
  <h3>AI-Driven Analysis & Recommendations</h3>
  <pre class="block">{html.escape(ai_analysis)}</pre>
</td></tr>


<!-- Footer -->
<tr>
  <td style="padding:14px 30px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px;" class="muted">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
      <tr>
        <!-- Left: footer text -->
        <td align="left" style="color:#6b7280; font-size:12px; line-height:1.4;">
          This alert was automatically generated by
          <strong>SkynetOps Monitoring Platform</strong>.<br/>
          Attachments include CSV reports and process details (if applicable).
        </td>

        <!-- Right: company logo (CID), bottom-right -->
        <td align="right" style="padding-left:10px;">
          <!-- CID logo (Outlook/Gmail safe) -->
          <img
            src="cid:company_logo"
            alt="Company Logo"
            width="auto"
            height="28"
            style="
              height:28px;
              max-height:28px;
              display:inline-block;
              vertical-align:middle;
              border:0;
              outline:none;
              text-decoration:none;
            "
          />
        </td>
      </tr>
    </table>
  </td>
</tr>
</table>


</body>
</html>
"""

    attachments = [alert_csv] + proc_csvs  # charts are inline (base64)
    print("➡ Sending email...")
    sent = send_email_with_html(subject, body_html, attachments, cid_images=cid_images)
    if sent:
        print(f"{ICONS['ok']} EMAIL SENT SUCCESSFULLY!")
    else:
        print("❌ Email failed!")
    print("=" * 70)
    return sent

# ---------------- Threshold input ----------------
def get_thresholds_from_user() -> Tuple[float, float, float]:
    print("=" * 60)
    print(" SkynetOps — Threshold Configuration (Remote SSH to Azure VM)")
    print("=" * 60)
    try:
        cpu_threshold = float((input(f"Enter CPU Threshold (%)[default {CPU_THRESHOLD_DEFAULT}]: ").strip() or str(CPU_THRESHOLD_DEFAULT)))
        disk_threshold = float((input(f"Enter Disk Threshold (%)[default {DISK_THRESHOLD_DEFAULT}]: ").strip() or str(DISK_THRESHOLD_DEFAULT)))
        mem_threshold = float((input(f"Enter Memory Threshold (%)[default {MEMORY_THRESHOLD_DEFAULT}]: ").strip() or str(MEMORY_THRESHOLD_DEFAULT)))
        cpu_threshold = max(1, min(100, cpu_threshold))
        disk_threshold = max(1, min(100, disk_threshold))
        mem_threshold = max(1, min(100, mem_threshold))
        print(f"{ICONS['ok']} Thresholds configured:")
        print(f"   CPU   : {cpu_threshold}%")
        print(f"   Disk  : {disk_threshold}%")
        print(f"   Memory: {mem_threshold}%")
        return cpu_threshold, disk_threshold, mem_threshold
    except ValueError:
        print(f"Invalid input. Using defaults CPU={CPU_THRESHOLD_DEFAULT}%, Disk={DISK_THRESHOLD_DEFAULT}%, Memory={MEMORY_THRESHOLD_DEFAULT}%")
        return CPU_THRESHOLD_DEFAULT, DISK_THRESHOLD_DEFAULT, MEMORY_THRESHOLD_DEFAULT

# ---------------- One-time cycle ----------------
def one_time_check(cpu_t: float, disk_t: float, mem_t: float) -> None:
    if not VM_HOST:
        print("❌ VM_HOST not set in .env. Please configure SSH to Azure VM.")
        return
    with SSHSession() as sess:
        # Collect snapshot
        cpu_now = sample_cpu_remote(sess, SAMPLE_SEC)
        mem_used = mem_used_pct_remote(sess)
        disk_used = disk_capacity_used_remote(sess, MOUNT_PATH)

        # Micro-series
        rows: List[List] = []
        for _ in range(max(1, FAST_SAMPLES)):
            t = utc_iso_now()
            c = sample_cpu_remote(sess, SAMPLE_SEC)
            r, w = disk_bps_remote(sess, SAMPLE_SEC)
            rows += [[t, "Percentage CPU", c], [t, "Disk Read Bytes", r], [t, "Disk Write Bytes", w]]
        df = rows_to_df(rows)
        cpu_line = generate_line_chart(df, "Percentage CPU", f"vm_cpu_{int(time.time())}.png")

        # Top-5
        top_cpu = top5_cpu_remote(sess)
        top_mem = top5_memory_remote(sess)
        top_io  = top5_disk_remote(sess, SAMPLE_SEC)

        # Docker
        docker_rows = docker_summary_remote(sess)

        # Metrics
        metrics = {
            "timestamp": utc_iso_now(),
            "cpu_percent": cpu_now,
            "disk_percent": disk_used,
            "memory_percent": mem_used,
            "disk_read_bytes": None,
            "disk_write_bytes": None,
            "cpu_count": None,
            "memory_available_bytes": None,
            "disk_free_bytes": None,
            "top_cpu": top_cpu,
            "top_mem": top_mem,
            "top_io": top_io,
        }

        health = check_remote_health(metrics, cpu_t, disk_t, mem_t)

        print("=" * 70)
        print(" SkynetOps — Remote VM Health (SSH)")
        print("=" * 70)
        print(f"Host           : {VM_HOST}")
        print(f"Timestamp (UTC): {metrics['timestamp']}")
        print(f"CPU            : {metrics.get('cpu_percent', 0.0):.2f}%")
        print(f"Memory Used    : {(metrics.get('memory_percent') if metrics.get('memory_percent') is not None else float('nan')):.2f}%")
        print(f"Disk Used      : {(metrics.get('disk_percent') if metrics.get('disk_percent') is not None else float('nan')):.2f}%")
        print(f"Status         : {'HEALTHY' if health['is_healthy'] else 'ALERT'}")
        if health["alerts"]:
            print("Alerts:")
            for i, a in enumerate(health["alerts"], 1):
                print(f"  {i}. {a}")
        print("=" * 70)

        # Send alert if needed
        if not health["is_healthy"]:
            process_health_alert(metrics, health, cpu_t, disk_t, mem_t, df, cpu_line, docker_rows)
        else:
            print(f"{ICONS['ok']} System is healthy - no alert sent.")

# ---------------- Continuous loop ----------------
def continuous_loop(cpu_t: float, disk_t: float, mem_t: float) -> None:
    if not VM_HOST:
        print("❌ VM_HOST not set in .env. Please configure SSH to Azure VM.")
        return

    print("Starting continuous monitoring loop (Remote Azure VM via SSH). Press Ctrl+C to stop.")
    while True:
        try:
            with SSHSession() as sess:
                cpu_now = sample_cpu_remote(sess, SAMPLE_SEC)
                mem_used = mem_used_pct_remote(sess)
                disk_used = disk_capacity_used_remote(sess, MOUNT_PATH)

                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cpu_sev = classify_severity(cpu_now, cpu_t) if cpu_now > cpu_t else None
                disk_sev = classify_severity(disk_used or 0.0, disk_t) if (disk_used is not None and disk_used > disk_t) else None
                mem_sev  = classify_severity(mem_used or 0.0, mem_t) if (mem_used is not None and mem_used > mem_t) else None
                overall  = overall_severity(cpu_sev, disk_sev, mem_sev) or ""
                icon = f"[Alert {overall}]" if overall else "[OK]"
                print(
                    f"[{ts}] {icon} CPU={cpu_now:.1f}% "
                    f"Disk={(disk_used if disk_used is not None else float('nan')):.1f}% "
                    f"Mem={(mem_used if mem_used is not None else float('nan')):.1f}%"
                )

                health = check_remote_health(
                    {"cpu_percent": cpu_now, "disk_percent": disk_used, "memory_percent": mem_used},
                    cpu_t, disk_t, mem_t
                )

                if not health["is_healthy"]:
                    print("ALERT detected:", health["alerts"])
                    # Micro-series
                    rows: List[List] = []
                    for _ in range(max(1, FAST_SAMPLES)):
                        t = utc_iso_now()
                        c = sample_cpu_remote(sess, SAMPLE_SEC)
                        r, w = disk_bps_remote(sess, SAMPLE_SEC)
                        rows += [[t, "Percentage CPU", c], [t, "Disk Read Bytes", r], [t, "Disk Write Bytes", w]]
                    df = rows_to_df(rows)
                    cpu_line = generate_line_chart(df, "Percentage CPU", f"vm_cpu_{int(time.time())}.png")

                    # Top-5 + Docker
                    top_cpu = top5_cpu_remote(sess)
                    top_mem = top5_memory_remote(sess)
                    top_io  = top5_disk_remote(sess, SAMPLE_SEC)
                    docker_rows = docker_summary_remote(sess)

                    metrics_full = {
                        "timestamp": utc_iso_now(),
                        "cpu_percent": cpu_now,
                        "disk_percent": disk_used,
                        "memory_percent": mem_used,
                        "disk_read_bytes": None,
                        "disk_write_bytes": None,
                        "cpu_count": None,
                        "memory_available_bytes": None,
                        "disk_free_bytes": None,
                        "top_cpu": top_cpu,
                        "top_mem": top_mem,
                        "top_io": top_io,
                    }
                    process_health_alert(metrics_full, health, cpu_t, disk_t, mem_t, df, cpu_line, docker_rows)

            time.sleep(30)
        except KeyboardInterrupt:
            print("Exiting by user request.")
            break
        except Exception as e:
            print("Loop error:", e)
            time.sleep(10)

# ---------------- CLI / Main ----------------
if __name__ == "__main__":
    if "--test-email" in sys.argv:
        ok = send_email_with_html("[SkynetOps TEST] SMTP Check", "<html><body><p>SkynetOps TEST email</p></body></html>", [], cid_images=[])
        print("Test email result:", ok)
        sys.exit(0)

    cpu_thr, disk_thr, mem_thr = get_thresholds_from_user()

    if "--check" in sys.argv:
        one_time_check(cpu_thr, disk_thr, mem_thr)
    else:
        continuous_loop(cpu_thr, disk_thr, mem_thr)
