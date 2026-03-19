
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SkynetOps — Azure VM Monitoring → Email + ServiceNow
Unified SRE Incident Report (Full AI) + Advanced Forecasts

UPDATES (2026-01-23 per Naveen):
- ADDED: Recovery workflow (emails + concise work notes) for CPU/Memory/Disk, VM Crash (VM up), Telemetry.
- NO AUTO-RESOLUTION on recovery. Only short, values-only work-notes are added to existing incidents.
- CHANGED: All ServiceNow work-note updates during continued breach now append only a concise values line
           (no repeated steps / AI text). Initial incident description on create remains rich.

Original features retained:
- Accurate Azure Monitor capture with UTC 'Z' timestamps.
- Advanced forecasting (HW/ARIMA/Linear).
- Unified AI SRE Incident Report.
- Per-VM SSH diagnostics.
- No duplicate tickets per VM/issue, dedupe via sn_state.json.
- Create NEW incident when old one is Resolved/Closed.
- Ticket numbers shown & clickable in emails.
- Key Vault-driven thresholds; Crash=P1, Telemetry=P2.
"""

# -------------------- Standard library --------------------
import os
import sys
import csv
import time
import json
import smtplib
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple, Dict, Any

# -------------------- External HTTP (ServiceNow) --------------------
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------- Azure SDKs --------------------
from azure.identity import (
    DefaultAzureCredential,
    AzureCliCredential,
    ManagedIdentityCredential,
)
from azure.keyvault.secrets import SecretClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resourcehealth import ResourceHealthMgmtClient
from azure.storage.blob import BlobClient
from azure.monitor.query import LogsQueryClient

# -------------------- Azure AI Agents (optional) --------------------
HAS_AGENTS = True
try:
    from azure.ai.agents import AgentsClient
    from azure.ai.agents.models import MessageRole, MessageTextContent
except Exception:
    HAS_AGENTS = False
    AgentsClient = None
    MessageRole = None
    MessageTextContent = None

# -------------------- Data / viz --------------------
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# -------------------- SSH (optional, per-VM via vms.json) --------------------
HAS_SSH = True
try:
    import paramiko
except Exception:
    HAS_SSH = False
    paramiko = None

# -------------------- Advanced Forecasting libs (optional) --------------------
HAS_STATSMODELS = True
try:
    from statsmodels.tsa.holtwinters import ExponentialSmoothing
    from statsmodels.tsa.arima.model import ARIMA
except Exception:
    HAS_STATSMODELS = False
    ExponentialSmoothing = None
    ARIMA = None

# ==================== Constants ====================
KEYVAULT_URL = "https://skynetops-secure.vault.azure.net/"
OUTPUT_DIR = Path("outputs_skynetops")
OUTPUT_DIR.mkdir(exist_ok=True)

# ==================== ServiceNow ====================
# ⚠ Move these to Key Vault or environment variables for production.
SN_INSTANCE_URL = "https://dev281446.service-now.com"
SN_USERNAME = "admin"
SN_PASSWORD = "n/K*cwNC95Gr"
SN_ATTACH_ON_UPDATE = 1  # 1 to attach CSVs/images on create/update
SN_VERIFY = False        # SSL verification (False in dev)
SN_STATE_FILE = OUTPUT_DIR / "sn_state.json"

# Optional caller and assignment group config
SN_ASSIGNMENT_GROUP_NAME = "Incident Management"
SN_CALLER_EMAIL = None
SN_CALLER_USERNAME = None

# ACK behavior: In Progress only (no SLA pause, no On Hold)
SN_SLA_PAUSE_ON_ACK = False
SN_SLA_PAUSE_METHOD = "state"  # kept for compatibility; not used when pause is off

# ==================== Globals ====================
SUBSCRIPTION_ID = None
RESOURCE_GROUP = None
VM_NAME = None

# ==================== Behavior toggles ====================
AI_FULL_ANALYSIS_ONLY = True  # True → use unified SRE Incident Report everywhere

# ==================== vms.json (per-VM config for SSH etc.) ====================
VMS_JSON_PATH = os.getenv("VMS_JSON_PATH", "vms.json")

def _load_vms_from_file(path: str) -> List[Dict[str, Any]]:
    try:
        p = Path(path)
        if p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            else:
                print("⚠ vms.json must be a JSON array of VM objects.")
        else:
            print(f"⚠ vms.json not found at {p.resolve()}; falling back to KV config.")
    except Exception as e:
        print(f"⚠ Failed to load vms.json: {e}")
    return []

def get_vm_ssh_cfg(vm: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ssh = vm.get("ssh")
    if not ssh or ssh is False:
        return None
    if ssh.get("enabled", True) is False:
        return None
    host = ssh.get("host")
    user = ssh.get("username")
    if not host or not user:
        return None
    return {
        "ssh_host": host,
        "ssh_port": int(ssh.get("port", 22) or 22),
        "ssh_user": user,
        "ssh_pass": ssh.get("password"),
        "ssh_key_path": ssh.get("key_path"),
        "ssh_use_sudo": bool(ssh.get("use_sudo", False)),
    }

# ==================== ServiceNow helpers ====================
def _sn_load_state() -> Dict[str, Any]:
    if SN_STATE_FILE.is_file():
        try:
            return json.load(open(SN_STATE_FILE, "r"))
        except Exception:
            return {}
    return {}

def _sn_save_state(state: Dict[str, Any]) -> None:
    try:
        json.dump(state, open(SN_STATE_FILE, "w"), indent=2)
    except Exception as e:
        print("ServiceNow state save failed:", e)

def _sn_session() -> requests.Session:
    s = requests.Session()
    s.auth = (SN_USERNAME, SN_PASSWORD)
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    s.verify = SN_VERIFY
    return s

def resp_status_bad(code: int) -> bool:
    return code >= 300

def sn_lookup_group_sys_id(name: str) -> Optional[str]:
    try:
        s = _sn_session()
        params = {"sysparm_query": f"name={name}", "sysparm_fields": "sys_id", "sysparm_limit": "1"}
        r = s.get(f"{SN_INSTANCE_URL}/api/now/table/sys_user_group", params=params)
        if resp_status_bad(r.status_code):
            return None
        rows = (r.json() or {}).get("result") or []
        return rows[0].get("sys_id") if rows else None
    except Exception:
        return None

def sn_lookup_user_sys_id(email: Optional[str] = None, username: Optional[str] = None) -> Optional[str]:
    try:
        s = _sn_session()
        if email:
            q = f"email={email}"
        elif username:
            q = f"user_name={username}"
        else:
            return None
        params = {"sysparm_query": q, "sysparm_fields": "sys_id", "sysparm_limit": "1"}
        r = s.get(f"{SN_INSTANCE_URL}/api/now/table/sys_user", params=params)
        if resp_status_bad(r.status_code):
            return None
        rows = (r.json() or {}).get("result") or []
        return rows[0].get("sys_id") if rows else None
    except Exception:
        return None

def sn_incident_link(sys_id: Optional[str]) -> str:
    if not sys_id:
        return ""
    return f"{SN_INSTANCE_URL}/nav_to.do?uri=incident.do%3Fsys_id%3D{sys_id}"

def sn_create_incident(short_description: str,
                       description: str,
                       urgency: int = 2,
                       impact: int = 2,
                       priority: Optional[int] = None,
                       assignment_group: Optional[str] = None,
                       caller_id: Optional[str] = None) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    try:
        s = _sn_session()
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            "impact": impact,
            "state": 1,     # New
            "category": "inquiry"
        }
        if priority is not None:
            payload["priority"] = priority
        if assignment_group:
            if len(assignment_group) < 32 or "-" in assignment_group:
                ag_id = sn_lookup_group_sys_id(assignment_group)
                if ag_id:
                    payload["assignment_group"] = ag_id
            else:
                payload["assignment_group"] = assignment_group
        if caller_id:
            payload["caller_id"] = caller_id
        resp = s.post(f"{SN_INSTANCE_URL}/api/now/table/incident", json=payload)
        if resp_status_bad(resp.status_code):
            return None, None, f"Create incident failed: {resp.status_code} {resp.text}"
        data = resp.json().get("result", {})
        return data.get("sys_id"), data.get("number"), None
    except Exception as e:
        return None, None, str(e)

def sn_update_incident(sys_id: str, fields: Dict[str, Any]) -> Optional[str]:
    try:
        s = _sn_session()
        resp = s.patch(f"{SN_INSTANCE_URL}/api/now/table/incident/{sys_id}", json=fields)
        if resp_status_bad(resp.status_code):
            return f"Update incident failed: {resp.status_code} {resp.text}"
        return None
    except Exception as e:
        return str(e)

def sn_add_work_notes(sys_id: str, notes: str) -> Optional[str]:
    return sn_update_incident(sys_id, {"work_notes": notes})

def sn_get_incident_fields(sys_id: str, fields: List[str]) -> Dict[str, Any]:
    try:
        s = _sn_session()
        params = {"sysparm_fields": ",".join(fields)}
        resp = s.get(f"{SN_INSTANCE_URL}/api/now/table/incident/{sys_id}", params=params)
        if resp_status_bad(resp.status_code):
            return {}
        return resp.json().get("result", {}) or {}
    except Exception:
        return {}

def sn_is_resolved_or_closed(sys_id: Optional[str]) -> bool:
    if not sys_id:
        return False
    data = sn_get_incident_fields(sys_id, ["state"])
    try:
        state = int(data.get("state", 0))
        return state >= 6
    except Exception:
        return False

def sev_to_urgency(sev: Optional[str]) -> int:
    s = (sev or "").upper()
    if s == "P1": return 1
    if s == "P2": return 2
    return 3

def sev_to_priority(sev: Optional[str]) -> int:
    s = (sev or "").upper()
    if s == "P1": return 1
    if s == "P2": return 2
    if s == "P3": return 3
    return 4

def sn_ack_incident(sys_id: str, ack_text: str = "Acknowledged automatically by SkynetOps") -> Optional[str]:
    try:
        err = sn_update_incident(sys_id, {"state": 2})  # In Progress
        if err:
            return err
        return sn_add_work_notes(sys_id, ack_text)
    except Exception as e:
        return str(e)

def sn_attach_file(sys_id: str, file_path: Path) -> Optional[str]:
    try:
        if not file_path or not Path(file_path).is_file():
            return None
        s = _sn_session()
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            params = {"table_name": "incident", "table_sys_id": sys_id, "file_name": file_path.name}
            resp = s.post(f"{SN_INSTANCE_URL}/api/now/attachment/file", params=params, files=files)
        if resp_status_bad(resp.status_code):
            return f"Attach failed {file_path.name}: {resp.status_code} {resp.text}"
        return None
    except Exception as e:
        return str(e)

def _sn_get_vm_issue_state(sn_state: Dict[str, Any], vm_key: str) -> Dict[str, Any]:
    vm_entry = sn_state.get(vm_key, {})
    if "open" not in vm_entry:
        open_map = {"CPU": {}, "Memory": {}, "Disk": {}, "Crash": {}, "Telemetry": {}}
        vm_entry = {"open": open_map}
        sn_state[vm_key] = vm_entry
    else:
        for k in ("CPU", "Memory", "Disk", "Crash", "Telemetry"):
            vm_entry["open"].setdefault(k, {})
    return vm_entry

# ==================== Auth helpers ====================
def get_token_credential():
    mode = (os.getenv("SKYNETOPS_AUTH") or "").lower()
    if mode == "cli":
        return AzureCliCredential()
    if mode == "mi":
        client_id = os.getenv("AZURE_CLIENT_ID")
        return ManagedIdentityCredential(client_id=client_id) if client_id else ManagedIdentityCredential()
    if shutil.which("az"):
        try:
            subprocess.run(["az", "account", "show"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return AzureCliCredential()
        except Exception:
            pass
    return DefaultAzureCredential(
        exclude_environment_credential=True,
        exclude_workload_identity_credential=True,
        exclude_managed_identity_credential=True,
        exclude_visual_studio_code_credential=True,
        exclude_shared_token_cache_credential=True,
        exclude_powershell_credential=True,
        exclude_developer_cli_credential=True,
        exclude_interactive_browser_credential=False
    )

# ==================== Key Vault loader ====================
def kv_client() -> SecretClient:
    cred = get_token_credential()
    return SecretClient(vault_url=KEYVAULT_URL, credential=cred)

def _kv_get(client: SecretClient, name: str, required: bool = False, default: Optional[str] = None) -> Optional[str]:
    try:
        s = client.get_secret(name)
        return s.value if s and s.value is not None else default
    except Exception:
        if required and default is None:
            raise
        return default

def load_config_from_kv() -> Dict[str, Any]:
    c = kv_client()
    subscription_id = _kv_get(c, "SUBSCRIPTION-ID", required=True)
    resource_group = _kv_get(c, "RESOURCE-GROUP", required=True)
    vm_name = _kv_get(c, "VM-NAME", required=True)
    email_to = _kv_get(c, "EMAIL-ALERT-TO", required=True)
    email_from = _kv_get(c, "EMAIL-ALERT-FROM", required=True)
    smtp_server = _kv_get(c, "SMTP-SERVER", required=True)
    smtp_port = int(_kv_get(c, "SMTP-PORT", default="587") or "587")
    smtp_user = _kv_get(c, "SMTP-USERNAME", required=True)
    smtp_pass = _kv_get(c, "SMTP-PASSWORD", required=True)
    company_logo_path = _kv_get(c, "COMPANY-LOGO-PATH", default=None)

    def _f(name: str, default: float) -> float:
        v = _kv_get(c, name, required=False)
        try: return float(v) if v is not None else default
        except Exception: return default

    cpu_threshold = _f("CPU-THRESHOLD", 70.0)               # %
    mem_free_pct_thr = _f("MEM-FREE-PCT-THRESHOLD", 30.0)   # %
    disk_threshold = _f("DISK-THRESHOLD", 70.0)             # % (usage)
    memory_threshold = _f("MEMORY-THRESHOLD", 90.0)         # % used

    sev_margin_p1 = _f("SEVERITY-MARGIN-P1", 20.0)
    sev_margin_p2 = _f("SEVERITY-MARGIN-P2", 10.0)
    sev_margin_p3 = _f("SEVERITY-MARGIN-P3", 0.0)

    fast_lookback_min = int(_kv_get(c, "FAST-LOOKBACK-MIN", default="15") or "15")
    use_emoji = str(_kv_get(c, "USE-EMOJI", default="true")).strip().lower() in ("1","true","yes")
    inline_charts = str(_kv_get(c, "INLINE-CHARTS", default="false")).strip().lower() in ("1","true","yes")

    total_memory_bytes = _kv_get(c, "TOTAL-MEMORY-BYTES", default=None)
    total_memory_bytes = int(total_memory_bytes) if (total_memory_bytes and str(total_memory_bytes).isdigit()) else 0

    crash_lookback_min = int(_kv_get(c, "CRASH-LOOKBACK-MIN", default="180") or "180")
    crash_watch_sec = int(_kv_get(c, "CRASH-WATCH-SEC", default="60") or "60")

    vms_config_json = _kv_get(c, "VMS-CONFIG-JSON", default=None)
    project_endpoint = _kv_get(c, "PROJECT-ENDPOINT", required=False)
    model_deployment = _kv_get(c, "MODEL-DEPLOYMENT-NAME", required=False)
    workspace_id = _kv_get(c, "LOG-ANALYTICS-WORKSPACE-ID", default=None)

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "vm_name": vm_name,
        "email_to": email_to,
        "email_from": email_from,
        "smtp_server": smtp_server,
        "smtp_port": smtp_port,
        "smtp_user": smtp_user,
        "smtp_pass": smtp_pass,
        "company_logo_path": company_logo_path,
        "cpu_threshold": cpu_threshold,
        "mem_free_pct_threshold": mem_free_pct_thr,
        "disk_threshold": disk_threshold,
        "memory_threshold": memory_threshold,
        "sev_margin_p1": sev_margin_p1,
        "sev_margin_p2": sev_margin_p2,
        "sev_margin_p3": sev_margin_p3,
        "fast_lookback_min": fast_lookback_min,
        "use_emoji": use_emoji,
        "inline_charts": inline_charts,
        "total_memory_bytes": total_memory_bytes,
        "crash_lookback_min": crash_lookback_min,
        "crash_watch_sec": crash_watch_sec,
        "vms_config_json": vms_config_json,
        "project_endpoint": project_endpoint,
        "model_deployment": model_deployment,
        "workspace_id": workspace_id,
    }

def parse_vms(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    vms = _load_vms_from_file(VMS_JSON_PATH)
    if vms:
        return vms
    vms_kv = []
    if cfg.get("vms_config_json"):
        try:
            vms_kv = json.loads(cfg["vms_config_json"])
            if not isinstance(vms_kv, list):
                print("⚠ VMS-CONFIG-JSON must be a JSON array; falling back to single VM from KV.")
                vms_kv = []
        except Exception as e:
            print("⚠ Failed to parse VMS-CONFIG-JSON:", e)
    if vms_kv:
        return vms_kv
    return [{
        "name": cfg["vm_name"],
        "resource_group": cfg["resource_group"],
        "subscription_id": cfg["subscription_id"],
        "email_to": cfg["email_to"],
    }]

# ==================== Clients ====================
def build_monitor_client(sub_id: str) -> MonitorManagementClient:
    cred = get_token_credential()
    return MonitorManagementClient(cred, sub_id)

def build_compute_client(sub_id: str) -> ComputeManagementClient:
    cred = get_token_credential()
    return ComputeManagementClient(cred, sub_id)

def build_resource_health_client(sub_id: str) -> ResourceHealthMgmtClient:
    cred = get_token_credential()
    return ResourceHealthMgmtClient(cred, sub_id)

def build_logs_client() -> LogsQueryClient:
    cred = get_token_credential()
    return LogsQueryClient(credential=cred)

def build_agents_client(cfg: Dict[str, Any]) -> Optional[AgentsClient]:
    if not HAS_AGENTS:
        return None
    if cfg.get("project_endpoint") and cfg.get("model_deployment"):
        return AgentsClient(endpoint=cfg["project_endpoint"], credential=get_token_credential())
    return None

# ==================== Helpers ====================
def vm_resource_id(sub_id: str, rg: str, name: str) -> str:
    return f"/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"

def html_escape(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

def human_bytes(num: float, suffix: str = "B") -> str:
    try:
        num = float(num)
    except Exception:
        return "N/A"
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(num) < 1024.0:
            return f"{num:0.2f} {unit}{suffix}"
        num /= 1024.0
    return f"{num:0.2f} P{suffix}"

def _as_text(x) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    return getattr(x, "localized_value", None) or getattr(x, "value", None) or str(x)

def normalize_power_state(state: Optional[str]) -> str:
    if not state:
        return "Unknown"
    s = state.strip().lower()
    if "running" in s: return "Running"
    if "deallocated" in s: return "Deallocated"
    if "stopped" in s or "deallocating" in s: return "Stopped"
    if "starting" in s: return "Starting"
    return "Unknown"

def _to_utc_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ==================== Boot diagnostics ====================
def download_blob_text_via_sas(sas_url: Optional[str], tail_bytes: int = 400000) -> Optional[str]:
    if not sas_url:
        return None
    try:
        bc = BlobClient.from_blob_url(sas_url)
        props = bc.get_blob_properties()
        size = int(props.size or 0)
        if size <= 0:
            data = bc.download_blob().readall()
            return data.decode(errors="ignore")
        start = max(0, size - tail_bytes)
        data = bc.download_blob(offset=start, length=(size - start)).readall()
        return data.decode(errors="ignore")
    except Exception:
        return None

# ==================== Metrics (Azure Monitor) ====================
def query_metrics_for_vm(sub_id: str, rg: str, name: str, minutes_back: int = 15) -> pd.DataFrame:
    client = build_monitor_client(sub_id)
    rid = vm_resource_id(sub_id, rg, name)
    metric_names = [
        "Percentage CPU",
        "Disk Read Bytes",
        "Disk Write Bytes",
        "Available Memory Percentage",
        "Available Memory Bytes",
    ]
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=minutes_back)
    timespan = f"{_to_utc_z(start_dt)}/{_to_utc_z(end_dt)}"
    result = client.metrics.list(
        resource_uri=rid,
        timespan=timespan,
        interval="PT1M",
        metricnames=",".join(metric_names),
        aggregation="Average,Total,Minimum,Maximum",
    )
    rows: List[List] = []
    for metric in getattr(result, "value", []) or []:
        name_label = _as_text(getattr(metric, "name", None))
        for ts in getattr(metric, "timeseries", []) or []:
            for dp in getattr(ts, "data", []) or []:
                ts_time = getattr(dp, "time_stamp", None) or getattr(dp, "timestamp", None)
                stamp = (_to_utc_z(ts_time) if ts_time else _to_utc_z(end_dt))
                for agg_attr, agg_label in (
                    ("average", "Average"),
                    ("total", "Total"),
                    ("minimum", "Minimum"),
                    ("maximum", "Maximum"),
                ):
                    val = getattr(dp, agg_attr, None)
                    if val is not None:
                        rows.append([stamp, name_label, agg_label, float(val)])
    df = pd.DataFrame(rows, columns=["timestamp", "metric", "aggregation", "value"])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df

def query_metrics_last_days(sub_id: str, rg: str, name: str, days_back: int = 5, granularity: str = "PT30M") -> pd.DataFrame:
    client = build_monitor_client(sub_id)
    rid = vm_resource_id(sub_id, rg, name)
    metric_names = ["Percentage CPU", "Available Memory Bytes", "Disk Read Bytes", "Disk Write Bytes"]
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=days_back)
    timespan = f"{_to_utc_z(start_dt)}/{_to_utc_z(end_dt)}"
    result = client.metrics.list(
        resource_uri=rid,
        timespan=timespan,
        interval=granularity,
        metricnames=",".join(metric_names),
        aggregation="Average,Total,Minimum,Maximum",
    )
    rows: List[List] = []
    for metric in getattr(result, "value", []) or []:
        name_label = _as_text(getattr(metric, "name", None))
        for ts in getattr(metric, "timeseries", []) or []:
            for dp in getattr(ts, "data", []) or []:
                ts_time = getattr(dp, "time_stamp", None) or getattr(dp, "timestamp", None)
                stamp = (_to_utc_z(ts_time) if ts_time else _to_utc_z(end_dt))
                for agg_attr, agg_label in (
                    ("average", "Average"),
                    ("total", "Total"),
                    ("minimum", "Minimum"),
                    ("maximum", "Maximum"),
                ):
                    val = getattr(dp, agg_attr, None)
                    if val is not None:
                        rows.append([stamp, name_label, agg_label, float(val)])
    df = pd.DataFrame(rows, columns=["timestamp", "metric", "aggregation", "value"])
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df

def get_metric_series(df: pd.DataFrame, metric: str, aggregation: str) -> pd.Series:
    if df.empty:
        return pd.Series(dtype=float)
    dfa = df[(df["metric"] == metric) & (df["aggregation"] == aggregation)].sort_values("timestamp")
    if dfa.empty:
        return pd.Series(dtype=float)
    return dfa["value"].astype(float)

def get_metric_series_with_ts(df: pd.DataFrame, metric: str, aggregations_pref: List[str]) -> pd.Series:
    if df.empty:
        return pd.Series(dtype=float)
    dfx = df[df["metric"] == metric]
    for agg in aggregations_pref:
        dfa = dfx[dfx["aggregation"] == agg].sort_values("timestamp")
        if not dfa.empty:
            return pd.Series(dfa["value"].astype(float).values, index=pd.to_datetime(dfa["timestamp"], utc=True))
    if not dfx.empty:
        dfa = dfx.sort_values("timestamp")
        return pd.Series(dfa["value"].astype(float).values, index=pd.to_datetime(dfa["timestamp"], utc=True))
    return pd.Series(dtype=float)

def series_stats(series: pd.Series) -> Dict[str, Optional[float]]:
    if series.empty:
        return {"latest": None, "min": None, "max": None, "avg": None}
    s = series.astype(float).dropna()
    if s.empty:
        return {"latest": None, "min": None, "max": None, "avg": None}
    return {"latest": float(s.iloc[-1]), "min": float(s.min()), "max": float(s.max()), "avg": float(s.mean())}

# ==================== SSH helpers (per-VM via vms.json) ====================
def _ssh_connect_vm(vm: Dict[str, Any]) -> Optional['paramiko.SSHClient']:
    if not HAS_SSH:
        print("SSH not available: paramiko not installed.")
        return None
    ssh_cfg = get_vm_ssh_cfg(vm)
    if not ssh_cfg:
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if ssh_cfg.get("ssh_key_path"):
            pkey = None
            try:
                pkey = paramiko.RSAKey.from_private_key_file(ssh_cfg["ssh_key_path"])
            except Exception:
                try:
                    pkey = paramiko.Ed25519Key.from_private_key_file(ssh_cfg["ssh_key_path"])
                except Exception:
                    pkey = None
            client.connect(
                ssh_cfg["ssh_host"],
                port=ssh_cfg["ssh_port"],
                username=ssh_cfg["ssh_user"],
                pkey=pkey,
                timeout=20, compress=True, allow_agent=True, look_for_keys=True
            )
        else:
            client.connect(
                ssh_cfg["ssh_host"],
                port=ssh_cfg["ssh_port"],
                username=ssh_cfg["ssh_user"],
                password=ssh_cfg.get("ssh_pass"),
                timeout=20, compress=True, allow_agent=True, look_for_keys=True
            )
        return client
    except Exception as e:
        print("SSH connection error:", e)
        return None

def _ssh_exec(client: 'paramiko.SSHClient', command: str) -> str:
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=60)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        if err and not out:
            return err
        return out or err or ""
    except Exception as e:
        return f"ERROR: {e}"

def _parse_ps_table(text: str, expect_cols: int) -> List[List[str]]:
    lines = [l.rstrip() for l in text.strip().splitlines() if l.strip()]
    rows = []
    for i, line in enumerate(lines):
        if i == 0:
            continue
        parts = line.split(None, expect_cols - 1)
        if len(parts) >= expect_cols:
            rows.append(parts[:expect_cols])
    return rows

def ssh_get_load_averages_vm(vm: Dict[str, Any]) -> Optional[dict]:
    client = _ssh_connect_vm(vm)
    if client is None:
        return None
    try:
        cmd = 'bash -lc "LC_ALL=C cat /proc/loadavg; uptime -p"'
        out_lines = _ssh_exec(client, cmd).strip().splitlines()
        if not out_lines:
            return None
        la = out_lines[0].split()
        if len(la) < 4:
            return None
        l1 = float(la[0]); l5 = float(la[1]); l15 = float(la[2])
        running, total = 0, 0
        try:
            a, b = la[3].split("/", 1)
            running, total = int(a), int(b)
        except Exception:
            pass
        uptime_line = out_lines[1].strip() if len(out_lines) > 1 else ""
        uptime = uptime_line.replace("up ", "") if uptime_line.startswith("up ") else uptime_line
        return {"l1": l1, "l5": l5, "l15": l15, "running": running, "total": total, "uptime": uptime or ""}
    finally:
        try:
            client.close()
        except Exception:
            pass

def ssh_get_disk_usage_percent_vm(vm: Dict[str, Any]) -> Optional[float]:
    """
    Aggregate disk usage % across real filesystems via `df`, excluding ephemeral FS:
      tmpfs, devtmpfs, overlay, squashfs, loop, blobfuse, fuse.portal, ramfs.

    Formula:
      usage_pct = (Σ used_kb / Σ size_kb) * 100
    """
    client = _ssh_connect_vm(vm)
    if client is None:
        return None
    try:
        # PRIMARY: df --output=fstype,size,used, then sum with awk.
        # Important: escape $N as \$N inside the double-quoted awk program
        cmd_primary = """bash -lc '
LC_ALL=C df -PT -k --output=fstype,size,used 2>/dev/null |
awk "NR>1 && \\$1 !~ /^(tmpfs|devtmpfs|overlay|squashfs|loop|blobfuse|fuse\\.portal|ramfs)$/ && \\$2 ~ /^[0-9]+$/ && \\$3 ~ /^[0-9]+$/ {size+=\\$2; used+=\\$3}
END { if (size>0) printf(\\"%.2f\\", (used*100.0)/size); }"
'"""
        out = _ssh_exec(client, cmd_primary).strip()

        # FALLBACK: use table form and compute used/size locally if primary didn't yield a numeric percentage
        if not out or not any(ch.isdigit() for ch in out):
            cmd_fallback = """bash -lc '
LC_ALL=C df -PT -k 2>/dev/null |
awk "NR>1 && \\$2 !~ /^(tmpfs|devtmpfs|overlay|squashfs|loop|blobfuse|fuse\\.portal|ramfs)$/ && \\$3 ~ /^[0-9]+$/ && \\$4 ~ /^[0-9]+$/ {size+=\\$3; used+=\\$4}
END { if (size>0) printf(\\"%d %d\\", used, size); }"
'"""
            pair = _ssh_exec(client, cmd_fallback).strip()
            toks = pair.split()
            if len(toks) >= 2 and toks[0].isdigit() and toks[1].isdigit():
                used = float(toks[0]); size = float(toks[1])
                out = f"{(used*100.0/size):.2f}"

        # Normalize decimal separator; clamp to [0, 100]
        out = out.replace(",", ".").strip()
        try:
            val = float(out)
            return max(0.0, min(100.0, val))
        except Exception:
            print("[ssh_get_disk_usage_percent_vm] Could not parse df result:", repr(out))
            return None
    finally:
        try:
            client.close()
        except Exception:
            pass
def ssh_get_top_processes_vm(vm: Dict[str, Any], max_rows: int = 5) -> dict:
    result = {"cpu": [], "memory": [], "disk": []}
    client = _ssh_connect_vm(vm)
    if client is None:
        return {
            "cpu": [],
            "memory": [],
            "disk": [{"pid": "", "command": "SSH not configured or disabled for this VM", "kb_rd_s": "", "kb_wr_s": ""}],
        }
    try:
        cmd_cpu = f'bash -lc "LC_ALL=C ps -eo pid,comm,pcpu --sort=-pcpu | awk \'NR==1 || NR<={max_rows+1}\'"'
        out_cpu = _ssh_exec(client, cmd_cpu)
        rows_cpu = _parse_ps_table(out_cpu, expect_cols=3)
        for r in rows_cpu[:max_rows]:
            pid, comm, pcpu = r
            result["cpu"].append({"pid": pid, "command": comm, "cpu_pct": pcpu})

        cmd_mem = f'bash -lc "LC_ALL=C ps -eo pid,comm,pmem,rss --sort=-pmem | awk \'NR==1 || NR<={max_rows+1}\'"'
        out_mem = _ssh_exec(client, cmd_mem)
        rows_mem = _parse_ps_table(out_mem, expect_cols=4)
        for r in rows_mem[:max_rows]:
            pid, comm, pmem, rss = r
            result["memory"].append({"pid": pid, "command": comm, "mem_pct": pmem, "rss_kb": rss})

        ssh_cfg = get_vm_ssh_cfg(vm) or {}
        sudo_prefix = "sudo -n " if ssh_cfg.get("ssh_use_sudo") else ""
        cmd_disk = (
            "bash -lc '"
            "if command -v pidstat >/dev/null 2>&1; then "
            ' pidstat -d -p ALL 1 1 | awk "NR<=50"; '
            "elif command -v iotop >/dev/null 2>&1; then "
            f' {sudo_prefix}iotop -b -n 1 -o | awk "NR<=20"; '
            "else echo \"pidstat/iotop not available\"; fi'"
        )
        out_disk = _ssh_exec(client, cmd_disk)
        disk_rows = []
        if "pidstat" in out_disk or "UID" in out_disk or "Command" in out_disk:
            for line in out_disk.splitlines():
                line = line.strip()
                if not line or line.startswith(("Linux","Time")): continue
                if line.lower().startswith(("pid","average")): continue
                parts = line.split()
                if len(parts) >= 4 and parts[0].isdigit():
                    pid = parts[0]
                    kb_rd_s, kb_wr_s = "", ""
                    try:
                        kb_rd_s = parts[1].replace(",", "")
                        kb_wr_s = parts[2].replace(",", "")
                    except Exception:
                        pass
                    command = " ".join(parts[3:])
                    disk_rows.append({"pid": pid, "command": command, "kb_rd_s": kb_rd_s, "kb_wr_s": kb_wr_s})
            disk_rows = disk_rows[:max_rows]
        elif "iotop" in out_disk or "Total DISK" in out_disk or "K/s" in out_disk:
            for line in out_disk.splitlines():
                line = line.strip()
                if not line or "Total DISK" in line or line.startswith(("PID","TID")): continue
                parts = line.split()
                if parts and parts[0].isdigit():
                    pid = parts[0]; command = line
                    kb_rd_s, kb_wr_s = "", ""
                    try:
                        tokens = [p for p in parts if p.endswith("K/s") or p.endswith("M/s")]
                        if len(tokens) >= 2:
                            kb_rd_s, kb_wr_s = tokens[0], tokens[1]
                    except Exception:
                        pass
                    disk_rows.append({"pid": pid, "command": command, "kb_rd_s": kb_rd_s, "kb_wr_s": ""})
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

# ==================== Resource Health & Activity Logs ====================
def build_resource_health_client_safe(sub_id: str) -> Optional[ResourceHealthMgmtClient]:
    try:
        return build_resource_health_client(sub_id)
    except Exception:
        return None

def get_resource_health(sub_id: str, rg: str, name: str, minutes_back: int) -> dict:
    rhc = build_resource_health_client_safe(sub_id)
    rid = vm_resource_id(sub_id, rg, name)
    out = {"availability": None, "recent_events": []}
    if rhc is None:
        out["availability"] = {"availability_state": "Unknown", "summary": "ResourceHealth client not available"}
        return out
    try:
        avail = list(rhc.availability_statuses.list_by_resource(rid))
        if avail:
            latest = avail[0]
            out["availability"] = {
                "availability_state": getattr(latest, "availability_state", None),
                "summary": getattr(latest, "summary", None),
                "reason_type": getattr(latest, "reason_type", None),
                "occurred_time": str(getattr(latest, "occurred_time", "")),
            }
        try:
            for ev in rhc.event.list_by_resource(rid):
                out["recent_events"].append({
                    "title": getattr(ev, "title", None),
                    "summary": getattr(ev, "summary", None),
                    "type": getattr(ev, "type", None),
                    "impact": getattr(ev, "impact", None),
                    "start_time": str(getattr(ev, "start_time", "")),
                })
        except Exception:
            pass
    except Exception as e:
        out["availability"] = {"availability_state": "Unknown", "summary": f"ResourceHealth error: {e}"}
    return out

def list_activity_logs_for_vm(sub_id: str, rg: str, name: str, minutes_back: int) -> list:
    client = build_monitor_client(sub_id)
    rid = vm_resource_id(sub_id, rg, name)
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(minutes=minutes_back)
    end = _to_utc_z(end_dt)
    start = _to_utc_z(start_dt)
    filter_str = f"eventTimestamp ge {start} and eventTimestamp le {end} and resourceUri eq '{rid}'"
    select = ",".join(["eventTimestamp", "operationName", "resourceGroupName", "status", "caller", "category"])
    events = []
    try:
        for e in client.activity_logs.list(filter=filter_str, select=select):
            cat = _as_text(getattr(e, "category", None))
            op = _as_text(getattr(e, "operation_name", None))
            status = _as_text(getattr(e, "result_type", None))
            caller = getattr(e, "caller", None)
            ts = getattr(e, "event_timestamp", None)
            events.append({
                "timestamp": str(ts) if ts else "",
                "category": cat,
                "operation": op,
                "status": status,
                "caller": caller or "",
            })
    except Exception as ex:
        events.append({
            "timestamp": _to_utc_z(datetime.now(timezone.utc)),
            "category": "ERROR",
            "operation": "activity_logs.list",
            "status": "Exception",
            "caller": str(ex),
        })
    return events

# ==================== Forecast & stats helpers ====================
def _resample_minutely(s: pd.Series) -> pd.Series:
    if s.empty:
        return s
    s = s.sort_index()
    s = s.asfreq('min')
    s = s.interpolate(method='time').ffill().bfill()
    return s

def _infer_seasonal_period(s: pd.Series, max_period: int = 120) -> Optional[int]:
    s = s.dropna()
    n = len(s)
    if n < 20:
        return None
    max_lag = min(max_period, n // 2)
    if max_lag < 6:
        return None
    acfs = []
    lags = list(range(2, max_lag + 1))
    for lag in lags:
        try:
            acf = float(s.autocorr(lag))
        except Exception:
            acf = np.nan
        acfs.append(acf)
    if not acfs or all(np.isnan(acfs)):
        return None
    best_idx = int(np.nanargmax(acfs))
    best_val = acfs[best_idx]
    best_lag = lags[best_idx]
    return best_lag if (np.isfinite(best_val) and best_val > 0.3) else None

def _fit_best_arima(y: pd.Series, p_range=(0, 2), d_range=(0, 2), q_range=(0, 2)):
    if not HAS_STATSMODELS or y.empty:
        return None, None
    best_aic = np.inf
    best_fit, best_order = None, None
    for p in range(p_range[0], p_range[1] + 1):
        for d in range(d_range[0], d_range[1] + 1):
            for q in range(q_range[0], q_range[1] + 1):
                order = (p, d, q)
                try:
                    fit = ARIMA(y.values, order=order).fit()
                    aic = float(fit.aic) if getattr(fit, "aic", None) is not None else np.inf
                    if aic < best_aic:
                        best_aic = aic
                        best_fit = fit
                        best_order = order
                except Exception:
                    continue
    return best_fit, best_order

def _clamp_array(arr: np.ndarray, low: float = None, high: float = None) -> np.ndarray:
    if low is not None:
        arr = np.maximum(arr, low)
    if high is not None:
        arr = np.minimum(arr, high)
    return arr

def advanced_forecast_series(series: pd.Series,
                             horizons_minutes: List[int],
                             clamp_low: Optional[float] = None,
                             clamp_high: Optional[float] = None,
                             prefer_seasonal: bool = True) -> Dict[str, Any]:
    out = {"points": {}, "intervals": {}, "model": "Linear", "order": None}
    if series is None or series.empty:
        for h in horizons_minutes:
            out["points"][str(h)] = 0.0
            out["intervals"][str(h)] = None
        return out
    y = _resample_minutely(series.astype(float))
    max_h = int(max(horizons_minutes))
    seasonal_period = _infer_seasonal_period(y) if prefer_seasonal else None
    if HAS_STATSMODELS:
        if seasonal_period and len(y) >= (seasonal_period * 2):
            try:
                hw = ExponentialSmoothing(
                    y.values, trend='add', damped_trend=True,
                    seasonal=('add' if y.min() >= 0 else None), seasonal_periods=seasonal_period
                ).fit(optimized=True, use_brute=True)
                fc = hw.forecast(steps=max_h)
                fc = np.asarray(fc, dtype=float)
                fc = _clamp_array(fc, clamp_low, clamp_high)
                for h in horizons_minutes:
                    out["points"][str(h)] = float(fc[h - 1])
                    out["intervals"][str(h)] = None
                out["model"] = "HW"
                return out
            except Exception:
                pass
        try:
            fit, order = _fit_best_arima(y)
            if fit is not None:
                fr = fit.get_forecast(steps=max_h)
                fc = np.asarray(fr.predicted_mean, dtype=float)
                ci = fr.conf_int(alpha=0.20)
                fc = _clamp_array(fc, clamp_low, clamp_high)
                for h in horizons_minutes:
                    idx = h - 1
                    out["points"][str(h)] = float(fc[idx])
                    try:
                        low = float(ci.iloc[idx, 0]); high = float(ci.iloc[idx, 1])
                        low = float(_clamp_array(np.array([low]), clamp_low, clamp_high)[0])
                        high = float(_clamp_array(np.array([high]), clamp_low, clamp_high)[0])
                        out["intervals"][str(h)] = (low, high)
                    except Exception:
                        out["intervals"][str(h)] = None
                out["model"] = "ARIMA"
                out["order"] = order
                return out
        except Exception:
            pass
    try:
        steps = max_h
        x = np.arange(len(y))
        A = np.vstack([x, np.ones(len(x))]).T
        m, c = np.linalg.lstsq(A, y.values, rcond=None)[0]
        fc = [float(m * (len(x) + i) + c) for i in range(steps)]
        fc = np.array(fc, dtype=float)
        fc = _clamp_array(fc, clamp_low, clamp_high)
        for h in horizons_minutes:
            out["points"][str(h)] = float(fc[h - 1])
            out["intervals"][str(h)] = None
        out["model"] = "Linear"
        return out
    except Exception:
        for h in horizons_minutes:
            out["points"][str(h)] = float(y.iloc[-1]) if not y.empty else 0.0
            out["intervals"][str(h)] = None
        out["model"] = "Linear"
        return out

# ==================== Charts & CSV ====================
def moving_average(values, window: int = 3):
    s = pd.Series(values, dtype=float)
    return s.rolling(window=window, min_periods=1).mean().values

def generate_line_chart(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    dfm = df[df["metric"] == metric_name].sort_values("timestamp")
    out = OUTPUT_DIR / out_name
    if dfm.empty:
        plt.figure(figsize=(6, 3))
        plt.text(0.5, 0.5, "No data", ha="center", va="center")
        plt.axis("off")
        plt.savefig(out, bbox_inches="tight")
        plt.close()
        return out
    plt.figure(figsize=(8, 3.5))
    plt.plot(dfm["timestamp"], dfm["value"], marker="o", linewidth=1, label=metric_name)
    ma = moving_average(dfm["value"], window=max(2, int(len(dfm) / 6)))
    plt.plot(dfm["timestamp"], ma, linestyle="--", label="Moving Avg")
    try:
        plt.fill_between(dfm["timestamp"], dfm["value"], ma, alpha=0.08)
    except Exception:
        pass
    span = (dfm['timestamp'].max() - dfm['timestamp'].min())
    plt.title(f"{metric_name} — last {span}")
    plt.xlabel("Time"); plt.ylabel(metric_name); plt.legend(); plt.tight_layout()
    plt.savefig(out, dpi=120); plt.close()
    return out

def generate_pie_chart(cpu_value: float, out_name: str) -> Path:
    used = float(cpu_value) if cpu_value is not None else 0.0
    used = max(0.0, min(100.0, used))
    free = max(0.0, 100.0 - used)
    labels = ["Used CPU %", "Free CPU %"]; values = [used, free]
    plt.figure(figsize=(4, 4))
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90)
    plt.title("CPU Usage (latest)")
    out = OUTPUT_DIR / out_name
    plt.savefig(out, dpi=120, bbox_inches="tight"); plt.close()
    return out

def generate_histogram(df: pd.DataFrame, metric_name: str, out_name: str) -> Path:
    s = df.loc[df["metric"] == metric_name, "value"]
    out = OUTPUT_DIR / out_name
    plt.figure(figsize=(6, 3))
    if s.empty:
        plt.text(0.5, 0.5, "No data", ha="center", va="center")
        plt.axis("off")
    else:
        plt.hist(s, bins=min(20, max(3, len(s) // 2)), alpha=0.8)
        plt.title(f"{metric_name} distribution"); plt.xlabel(metric_name)
    plt.savefig(out, dpi=120, bbox_inches="tight"); plt.close()
    return out

def save_csv(rows: List[List], filename: str) -> Path:
    p = OUTPUT_DIR / filename
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "metric", "value"])
        w.writerows(rows)
    return p

def build_failed_csv(cpu_latest: Optional[float], mem_free_pct: Optional[float], cfg: Dict[str, Any]) -> Path:
    ts = _to_utc_z(datetime.now(timezone.utc))
    rows = []
    if cpu_latest is not None and cpu_latest > cfg["cpu_threshold"]:
        rows.append([ts, "Percentage CPU", f"{cpu_latest:.2f}", f"{cfg['cpu_threshold']:.2f}"])
    if mem_free_pct is not None and mem_free_pct < cfg["mem_free_pct_threshold"]:
        rows.append([ts, "Available Memory % Free", f"{mem_free_pct:.2f}", f"{cfg['mem_free_pct_threshold']:.2f}"])
    p = OUTPUT_DIR / f"alert_failed_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "metric", "value", "threshold"])
        w.writerows(rows)
    return p

def build_alert_ctx_csv(context: Dict[str, Any]) -> Path:
    p = OUTPUT_DIR / f"alert_ctx_{int(time.time())}.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["key", "value"])
        for k, v in context.items():
            w.writerow([k, v])
    return p

# ==================== Triggered Alerts helpers ====================
def compute_status_and_severity(value: float, threshold: float, cfg: Dict[str, Any] = None) -> Tuple[str, Optional[str]]:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return ("Unknown", None)
    if cfg is None:
        p1 = 20.0; p2 = 10.0; p3 = 0.0
    else:
        p1 = cfg.get("sev_margin_p1", 20.0)
        p2 = cfg.get("sev_margin_p2", 10.0)
        p3 = cfg.get("sev_margin_p3", 0.0)
    diff = float(value) - float(threshold)
    if diff >= p1: return ("Critical", "P1")
    if diff >= p2: return ("Critical", "P2")
    if diff >= p3: return ("Warning", "P3")
    return ("Healthy", None)

def build_triggered_alerts(metrics: Dict[str, float], thresholds: Dict[str, float], now_iso: str, cfg: Dict[str, Any]) -> List[Dict[str, str]]:
    alerts: List[Dict[str, str]] = []
    cpu_v = metrics.get("cpu_percent")
    if cpu_v is not None and not np.isnan(cpu_v) and cpu_v >= thresholds.get("cpu", 0.0):
        _, sev = compute_status_and_severity(cpu_v, thresholds["cpu"], cfg)
        alerts.append({"when": now_iso, "metric": "CPU Usage", "value": f"{cpu_v:.2f}%", "threshold": f"{thresholds['cpu']:.2f}%", "severity": sev or "-", "note": "High CPU usage"})
    mem_v = metrics.get("memory_percent")
    if mem_v is not None and not np.isnan(mem_v) and mem_v >= thresholds.get("mem", 0.0):
        _, sev = compute_status_and_severity(mem_v, thresholds["mem"], cfg)
        alerts.append({"when": now_iso, "metric": "Memory Usage", "value": f"{mem_v:.2f}%", "threshold": f"{thresholds['mem']:.2f}%", "severity": sev or "-", "note": "High memory usage"})
    disk_v = metrics.get("disk_percent")
    if disk_v is not None and not np.isnan(disk_v) and disk_v >= thresholds.get("disk", 0.0):
        _, sev = compute_status_and_severity(disk_v, thresholds["disk"], cfg)
        alerts.append({"when": now_iso, "metric": "Disk Usage", "value": f"{disk_v:.2f}%", "threshold": f"{thresholds['disk']:.2f}%", "severity": sev or "-", "note": "High disk usage"})
    return alerts

def render_alerts_html(alerts: List[Dict[str, str]]) -> str:
    if not alerts:
        return "<p style='color:#6b7280;'>No triggered alerts in this cycle.</p>"
    head = (
        "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
        "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
        "<th align='left' style='padding:8px;'>Time (UTC)</th>"
        "<th align='left' style='padding:8px;'>Metric</th>"
        "<th align='left' style='padding:8px;'>Value</th>"
        "<th align='left' style='padding:8px;'>Threshold</th>"
        "<th align='left' style='padding:8px;'>Severity</th>"
        "<th align='left' style='padding:8px;'>Note</th>"
        "</tr></thead><tbody>"
    )
    rows = []
    for a in alerts:
        rows.append(
            "<tr>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(a.get('when',''))}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(a.get('metric',''))}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(a.get('value',''))}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(a.get('threshold',''))}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#b91c1c;'>{html_escape(a.get('severity','-'))}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(a.get('note',''))}</td>"
            "</tr>"
        )
    tail = "</tbody></table>"
    return head + "".join(rows) + tail

# ==================== Email builders ====================
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

def azure_severity_badge(sev: str) -> str:
    sev = (sev or "Unknown").strip().capitalize()
    color_map = {"Critical": "#D13438", "Warning": "#FF8C00", "Healthy": "#107C10", "Unknown": "#605E5C"}
    color = color_map.get(sev, "#605E5C")
    return (
        f"<span style='display:inline-block; padding:2px 8px; border-radius:12px; "
        f"background:{color}; color:#ffffff; font-size:12px;'>{html_escape(sev)}</span>"
    )

def build_metrics_details_html(details: Dict[str, Any]) -> str:
    def fmt_pct(x):
        return "N/A" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:0.2f}%"
    def fmt_bytes(x):
        return "N/A" if x is None else human_bytes(x)
    rows = []
    rows.append(
        "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
        "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
        "<th align='left' style='padding:8px 10px; font-size:13px;'>Metric</th>"
        "<th align='left' style='padding:8px 10px; font-size:13px;'>Latest</th>"
        "<th align='left' style='padding:8px 10px; font-size:13px;'>Min</th>"
        "<th align='left' style='padding:8px 10px; font-size:13px;'>Max</th>"
        "<th align='left' style='padding:8px 10px; font-size:13px;'>Avg</th>"
        "</tr></thead><tbody>"
    )
    cpu = details["cpu"]
    rows.append(
        "<tr>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>CPU Usage</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_pct(cpu.get('latest'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_pct(cpu.get('min'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_pct(cpu.get('max'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_pct(cpu.get('avg'))}</td>"
        "</tr>"
    )
    rows.append(
        "<tr>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>Memory Used %</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_pct(details.get('mem_used_pct'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        "</tr>"
    )
    rows.append(
        "<tr>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>Available Memory</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_bytes(details.get('mem_avail_bytes'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        "</tr>"
    )
    dr = details["disk_read_bytes"]; dw = details["disk_write_bytes"]
    rows.append(
        "<tr>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>Disk Read Bytes (latest/avg)</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_bytes(dr.get('latest'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_bytes(dr.get('avg'))}</td>"
        "</tr>"
    )
    rows.append(
        "<tr>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>Disk Write Bytes (latest/avg)</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_bytes(dw.get('latest'))}</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>—</td>"
        f"<td style='padding:8px 10px; border-top:1px solid #e5e7eb;'>{fmt_bytes(dw.get('avg'))}</td>"
        "</tr>"
    )
    rows.append("</tbody></table>")
    return "".join(rows)

def _attach_cid_image(msg: MIMEMultipart, cid: str, file_path: Optional[Path]) -> None:
    if not file_path or not Path(file_path).is_file():
        return
    try:
        with open(file_path, "rb") as imgf:
            img = MIMEImage(imgf.read())
            img.add_header("Content-ID", f"<{cid}>")
            img.add_header("Content-Disposition", "inline", filename=Path(file_path).name)
            img.add_header("X-Attachment-Id", cid)
            msg.attach(img)
    except Exception as e:
        print(f"Failed to attach inline image {cid}: {e}")

def send_email(cfg: Dict[str, Any], subject: str, html_body: str, attachments: List[Path], inline_cids: Dict[str, Path] = None) -> bool:
    email_to = cfg["email_to"]; email_from = cfg["email_from"]
    server = cfg["smtp_server"]; port = cfg["smtp_port"]
    user = cfg["smtp_user"];   pwd = cfg["smtp_pass"]
    if not all([email_to, email_from, server, port, user, pwd]):
        print("Email not sent - SMTP config incomplete (check KV secrets).")
        return False
    try:
        msg = MIMEMultipart("related")
        msg["From"] = email_from
        msg["To"] = email_to
        msg["Subject"] = subject
        alt = MIMEMultipart("alternative")
        msg.attach(alt)
        alt.attach(MIMEText(html_body, "html"))
        if inline_cids:
            for cid, path in inline_cids.items():
                _attach_cid_image(msg, cid, Path(path) if path else None)
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
        with smtplib.SMTP(server, port, timeout=45) as s:
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
        print("📧 Email sent:", subject)
        return True
    except Exception as e:
        print("❌ Email send error:", e)
        return False

# -------------------- Existing alert email templates --------------------
def build_azure_metric_alert_email(vm_name: str, now_iso: str, severity_text: str, essentials: Dict[str, str],
                                   load_desc_html: str, alert_summary_table_html: str, metrics_details_html: str,
                                   charts_block_html: str, top_html_block: str, ai_analysis_html_block: str,
                                   company_logo_path: Optional[str] = None, ticket_header_html: str = "") -> str:
    banner_bg = "#0078D4"
    logo_img = f'cid:company_logo' if company_logo_path else ""
    sev_badge = azure_severity_badge(severity_text)
    ess_rows = []
    def ess_row(k,v):
        ess_rows.append(
            "<tr>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>{html_escape(k)}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(v)}</td>"
            "</tr>"
        )
    for k in ["Fired time (UTC)", "Severity", "Monitor condition", "Alert rule", "Signal type",
              "Resource", "Resource group", "Subscription"]:
        if k in essentials:
            v = essentials.get(k, "")
            ess_row(k, v)
    return f"""\
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="utf-8" />
  <title>Azure Monitor-style Alert</title>
 </head>
 <body style="margin:0; padding:0; background:#f8fafc; color:#111827;" bgcolor="#f8fafc">
 <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;" bgcolor="#f8fafc">
  <tr>
   <td align="center" style="padding:24px 12px;" bgcolor="#f8fafc">
    <table role="presentation" width="800" cellpadding="0" cellspacing="0" border="0" style="width:800px; max-width:800px; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;" bgcolor="#ffffff">
     <tr>
      <td style="padding:16px 20px; background:{banner_bg}; color:#ffffff; font-size:16px; font-weight:600;" bgcolor="{banner_bg}">
       Azure Monitor Alert • SkynetOps
       <span style="float:right;">{logo_img}</span>
      </td>
     </tr>
     <tr>
      <td style="padding:18px 20px;">
       <div style="display:flex; align-items:center; gap:12px;">
        <div style="font-size:20px; font-weight:600; color:#1f2937;">{html_escape(vm_name or 'VM')}</div>
        {sev_badge}
       </div>
       <div style="font-size:12px; color:#6b7280; margin-top:4px;">Fired: {html_escape(now_iso)} (UTC)</div>
       {ticket_header_html}
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Essentials</h3>
       <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; border:1px solid #e5e7eb;" bgcolor="#ffffff">
        <tbody>
         {''.join(ess_rows)}
        </tbody>
       </table>
      </td>
     </tr>
     <tr><td style="padding:0 20px 18px;">{load_desc_html}</td></tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Alert Summary</h3>
       {alert_summary_table_html}
      </td>
     </tr>
     {charts_block_html}
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Metrics Details</h3>
       {metrics_details_html}
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Top Processes (SSH)</h3>
       {top_html_block}
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">AI Analysis (Unified SRE Incident Report)</h3>
       {ai_analysis_html_block}
      </td>
     </tr>
     <tr>
      <td style="padding:14px 20px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; color:#374151;" bgcolor="#f9fafb">
       This alert was automatically generated by <strong>SkynetOps Monitoring Platform</strong>.
      </td>
     </tr>
    </table>
   </td>
  </tr>
 </table>
 </body>
</html>
"""

def build_azure_crash_status_email(vm_label: str, now_iso: str, severity_text: str, essentials: Dict[str, str],
                                   activity_logs_html: str, ai_text_block: str,
                                   company_logo_path: Optional[str] = None, ticket_header_html: str = "") -> str:
    banner_bg = "#0078D4"
    logo_img = f'cid:company_logo' if company_logo_path else ""
    sev_badge = azure_severity_badge(severity_text)
    ess_rows = []
    def ess_row(k,v):
        ess_rows.append(
            "<tr>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>{html_escape(k)}</td>"
            f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(v)}</td>"
            "</tr>"
        )
    for k in ["Fired time (UTC)", "Severity", "Monitor condition", "Signal type",
              "Power state", "Availability", "Resource", "Resource group", "Subscription", "Note"]:
        if k in essentials:
            ess_row(k, essentials.get(k, ""))
    return f"""\
<!DOCTYPE html>
<html lang="en">
 <head>
  <meta charset="utf-8" />
  <title>Azure Monitor-style Crash/Status</title>
 </head>
 <body style="margin:0; padding:0; background:#f8fafc; color:#111827;" bgcolor="#f8fafc">
 <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;" bgcolor="#f8fafc">
  <tr>
   <td align="center" style="padding:24px 12px;" bgcolor="#f8fafc">
    <table role="presentation" width="800" cellpadding="0" cellspacing="0" border="0" style="width:800px; max-width:800px; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;" bgcolor="#ffffff">
     <tr>
      <td style="padding:16px 20px; background:{banner_bg}; color:#ffffff; font-size:16px; font-weight:600;" bgcolor="{banner_bg}">
       Azure Monitor Alert • SkynetOps
       <span style="float:right;">{logo_img}</span>
      </td>
     </tr>
     <tr>
      <td style="padding:18px 20px;">
       <div style="display:flex; align-items:center; gap:12px;">
        <div style="font-size:20px; font-weight:600; color:#1f2937;">{html_escape(vm_label)}</div>
        {sev_badge}
       </div>
       <div style="font-size:12px; color:#6b7280; margin-top:4px;">Fired: {html_escape(now_iso)} (UTC)</div>
       {ticket_header_html}
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Essentials</h3>
       <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; border:1px solid #e5e7eb;" bgcolor="#ffffff">
        <tbody>{''.join(ess_rows)}</tbody></table>
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">Activity Logs (recent)</h3>
       {activity_logs_html}
      </td>
     </tr>
     <tr>
      <td style="padding:0 20px 18px;">
       <h3 style="margin:0 0 8px;">AI Analysis (Unified SRE Incident Report)</h3>
       {ai_text_block}
      </td>
     </tr>
     <tr>
      <td style="padding:14px 20px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; color:#374151;" bgcolor="#f9fafb">
       This alert was automatically generated by <strong>SkynetOps Monitoring Platform</strong>.
      </td>
     </tr>
    </table>
   </td>
  </tr>
 </table>
 </body>
</html>
"""

# ==================== AI: Unified SRE Incident Report ====================
def _count_z_anomalies(s: pd.Series, z: float = 3.0) -> int:
    s = s.dropna().astype(float)
    if len(s) < 10:
        return 0
    mu = float(s.mean())
    sd = float(s.std(ddof=1)) or 0.0
    if sd == 0.0:
        return 0
    z_scores = np.abs((s.values - mu) / sd)
    return int(np.sum(z_scores >= z))

def run_ai_full_incident_analysis(cfg: Dict[str, Any], context: Dict[str, Any]) -> str:
    is_crash = str(context.get("note", "")).strip().lower() == "crash"
    if is_crash:
        instructions = (
            "You are the SkynetOps SRE Incident Response Agent.\n"
            "You will receive VM crash/status context (power state, resource health, recent activity logs, and serial console tail).\n"
            "Be concise and prescriptive; if data is missing, call it out explicitly.\n\n"
            "OUTPUT FORMAT (STRICT):\n"
            "Crash Incident Report\n"
            "Summary:\n"
            "- Power State: <value>\n"
            "- Availability: <value> (<reason>)\n"
            "- Key Activity (last): <event>\n"
            "- Serial Findings: <items>\n\n"
            "Most Likely Root Cause(s):\n"
            "- <cause 1>\n"
            "- <cause 2>\n\n"
            "Immediate Remediation Steps:\n"
            "1. <step>\n"
            "2. <step>\n"
            "3. <step>\n\n"
            "Diagnostics to Run:\n"
            "- <command 1>\n"
            "- <command 2>\n"
            "- <command 3>\n\n"
            "Prevention / Follow-up:\n"
            "- <item 1>\n"
            "- <item 2>\n"
            "- <item 3>\n"
        )
    else:
        instructions = (
            "You are the SkynetOps SRE Incident Response Agent.\n"
            "You will receive VM telemetry as JSON with time series arrays for CPU and Disk I/O, "
            "and an SSH snapshot with current CPU/memory and top processes.\n\n"
            "OUTPUT FORMAT (STRICT):\n"
            "SRE Incident Report\n"
            "Summary:\n- CPU Current: <value>%\n- CPU Min/Max/Avg: <min>/<max>/<avg>%\n"
            "- Disk Read (avg bytes/interval): <value>\n- Disk Write (avg bytes/interval): <value>\n"
            "- CPU Anomalies: <count>\n- Disk Anomalies: <count>\n\n"
            "Forecast:\n- CPU 15m: <value>%\n- CPU 30m: <value>%\n- CPU 60m: <value>%\n\n"
            "Status:\n- VM: <Healthy | Warning | Critical>\n- Disk: <Normal | Saturated | Highly active>\n\n"
            "Root Cause:\n- <Root Cause 1>\n- <Root Cause 2>\n- <Root Cause 3>\n\n"
            "Immediate Actions (Runbook):\n1. <action>\n2. <action>\n3. <action>\n4. <action>\n5. <action>\n\n"
            "Diagnostics to Run (Linux):\n- <cmd1>\n- <cmd2>\n- <cmd3>\n- <cmd4>\n- <cmd5>\n\n"
            "Mitigations:\n- <m1>\n- <m2>\n- <m3>\n\n"
            "Follow-up / Prevention:\n- <f1>\n- <f2>\n- <f3>\n"
        )
    if not HAS_AGENTS or not (cfg.get("project_endpoint") and cfg.get("model_deployment")):
        return ("SRE Incident Report\n\nSummary:\n- AI Agent disabled or not configured.\n\n"
                "Forecast:\n- N/A\n\nStatus:\n- N/A\n\nRoot Cause:\n- Insufficient evidence\n\n"
                "Immediate Actions (Runbook):\n- N/A\n\nDiagnostics to Run (Linux):\n- N/A\n\n"
                "Mitigations:\n- N/A\n\nFollow-up / Prevention:\n- N/A")
    agent_client = build_agents_client(cfg)
    if not agent_client:
        return "SRE Incident Report\n\nSummary:\n- AI Agent client not available.\n\nRoot Cause:\n- Insufficient evidence"
    agent = None
    thread = None
    try:
        agent = agent_client.create_agent(
            model=cfg["model_deployment"],
            name=f"skynetops-sre-{int(time.time())}",
            instructions=instructions,
            tools=[],
        )
        thread = agent_client.threads.create()
        agent_client.messages.create(
            thread_id=thread.id,
            role="user",
            content=f"Telemetry/Context JSON:\n{json.dumps(context, default=str)}\n\nProduce the report now."
        )
        agent_client.runs.create_and_process(thread_id=thread.id, agent_id=agent.id)
        out = ""
        messages = agent_client.messages.list(thread_id=thread.id, order="asc")
        for m in messages:
            if m.role == MessageRole.AGENT:
                if getattr(m, "text_messages", None):
                    for t in m.text_messages:
                        out += t.text.value + "\n"
                elif getattr(m, "content", None):
                    for c in m.content:
                        if isinstance(c, MessageTextContent):
                            out += c.text.value + "\n"
                        elif getattr(c, "type", None) == "text":
                            text_obj = getattr(c, "text", None)
                            out += getattr(text_obj, "value", str(text_obj)) + "\n"
        out = out.strip()
        return out if out else "SRE Incident Report\n\nRoot Cause:\n- Insufficient evidence"
    except Exception as e:
        return f"SRE Incident Report\n\n⚠ Agent error: {e}\n\nRoot Cause:\n- Insufficient evidence"
    finally:
        try:
            if agent is not None and getattr(agent, "id", None):
                agent_client.agents.delete_agent(agent.id)
        except Exception:
            pass
        try:
            if thread is not None and getattr(thread, "id", None):
                if hasattr(agent_client.threads, "delete_thread"):
                    agent_client.threads.delete_thread(thread.id)
        except Exception:
            pass

# ==================== Helper: Top processes HTML & Ticket link ====================
def build_top_processes_html_ssh(top: dict) -> str:
    def render_table(title, headers, rows):
        head = (
            "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; background:#ffffff; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
            "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
            + "".join([f"<th style='padding:8px 10px; color:#111827; font-size:13px; border-bottom:1px solid #e5e7eb;' align='left'>{html_escape(h)}</th>" for h in headers])
            + "</tr></thead><tbody>"
        )
        body = []
        for r in rows:
            body.append(
                "<tr>"
                + "".join([f"<td style='padding:8px 10px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(str(col))}</td>" for col in r])
                + "</tr>"
            )
        tail = "</tbody></table>"
        return f"<h5 style='margin:10px 0 6px; color:#374151;'>{html_escape(title)}</h5>" + head + "".join(body) + tail
    sections = []
    cpu_rows = [[x.get("pid",""), x.get("command",""), x.get("cpu_pct","")] for x in (top.get("cpu", []) or [])]
    mem_rows = [[x.get("pid",""), x.get("command",""), x.get("mem_pct",""), x.get("rss_kb","")] for x in (top.get("memory", []) or [])]
    disk_rows= [[x.get("pid",""), x.get("command",""), x.get("kb_rd_s",""), x.get("kb_wr_s","")] for x in (top.get("disk", []) or [])]
    sections.append(render_table("CPU", ["PID","Command","CPU %"], cpu_rows) if cpu_rows else "<p style='color:#6b7280;'>No CPU process data</p>")
    sections.append(render_table("Memory", ["PID","Command","Mem %","RSS"], mem_rows) if mem_rows else "<p style='color:#6b7280;'>No Memory process data</p>")
    sections.append(render_table("Disk I/O", ["PID","Command","kB read/s","kB write/s"], disk_rows) if disk_rows else "<p style='color:#6b7280;'>No Disk I/O process data</p>")
    return "<div style='margin:10px 0;'><h4 style='margin:0 0 8px; color:#1f2937;'>Top Processes on VM (via SSH)</h4>" + "".join(sections) + "</div>"

def render_ticket_link(number: Optional[str], link: Optional[str]) -> str:
    if not number or number == "-" or not link:
        return "-"
    # Return a clickable number as an anchor (matches your previous email rendering style)
    return f'<a href="{link}">{html_escape(number)}</a>'

# ==================== NEW: Recovery helpers (concise note-only, no resolution) ====================
def sn_add_recovery_note(sys_id: str, note: str) -> Optional[str]:
    try:
        text = f"Recovery detected at {_to_utc_z(datetime.now(timezone.utc))}\n{note}"
        return sn_add_work_notes(sys_id, text)
    except Exception as e:
        return str(e)

def _ticket_inline(number: Optional[str], link: Optional[str]) -> str:
    if not number or number == "-" or not link:
        return ""
    return f"<div style='margin-top:6px; font-size:13px;'>Ticket: {render_ticket_link(number, link)}</div>"

def build_metric_recovery_email_html(vm_name: str, now_iso: str, metric_name: str, current_str: str,
                                     threshold_str: str, company_logo_path: Optional[str] = None,
                                     ticket_header_html: str = "") -> str:
    banner_bg = "#0078D4"
    logo_img = 'cid:company_logo' if company_logo_path else ""
    badge = azure_severity_badge("Healthy")
    essentials = (
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Recovered time (UTC)</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(now_iso)}</td>"
        "</tr>"
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Metric</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(metric_name)}</td>"
        "</tr>"
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Current</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(current_str)}</td>"
        "</tr>"
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Threshold</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(threshold_str)}</td>"
        "</tr>"
    )
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><title>Azure Monitor-style Recovery</title></head>
<body style="margin:0; padding:0; background:#f8fafc; color:#111827;" bgcolor="#f8fafc">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;" bgcolor="#f8fafc">
<tr><td align="center" style="padding:24px 12px;" bgcolor="#f8fafc">
  <table role="presentation" width="800" cellpadding="0" cellspacing="0" border="0" style="width:800px; max-width:800px; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;" bgcolor="#ffffff">
    <tr><td style="padding:16px 20px; background:{banner_bg}; color:#ffffff; font-size:16px; font-weight:600;" bgcolor="{banner_bg}">
      Azure Monitor Recovery • SkynetOps
      <span style="float:right;">{logo_img}</span>
    </td></tr>
    <tr><td style="padding:18px 20px;">
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="font-size:20px; font-weight:600; color:#1f2937;">{html_escape(vm_name or 'VM')}</div>
        {badge}
      </div>
      {ticket_header_html}
    </td></tr>
    <tr><td style="padding:0 20px 18px;">
      <h3 style="margin:0 0 8px;">Essentials</h3>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; border:1px solid #e5e7eb;" bgcolor="#ffffff">
        <tbody>{essentials}</tbody>
      </table>
    </td></tr>
    <tr><td style="padding:14px 20px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; color:#374151;" bgcolor="#f9fafb">
      This recovery was automatically detected by <strong>SkynetOps Monitoring Platform</strong>.
    </td></tr>
  </table>
</td></tr></table>
</body>
</html>"""

def build_vm_up_recovery_email_html(vm_label: str, now_iso: str, company_logo_path: Optional[str] = None,
                                    ticket_header_html: str = "") -> str:
    banner_bg = "#0078D4"
    logo_img = 'cid:company_logo' if company_logo_path else ""
    badge = azure_severity_badge("Healthy")
    essentials = (
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Recovered time (UTC)</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>{html_escape(now_iso)}</td>"
        "</tr>"
        "<tr>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; font-weight:600; color:#111827;'>Power state</td>"
        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#111827;'>Running</td>"
        "</tr>"
    )
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"/><title>Azure Monitor-style VM Up (Recovered)</title></head>
<body style="margin:0; padding:0; background:#f8fafc; color:#111827;" bgcolor="#f8fafc">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f8fafc;" bgcolor="#f8fafc">
<tr><td align="center" style="padding:24px 12px;" bgcolor="#f8fafc">
  <table role="presentation" width="800" cellpadding="0" cellspacing="0" border="0" style="width:800px; max-width:800px; background:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #e5e7eb;" bgcolor="#ffffff">
    <tr><td style="padding:16px 20px; background:{banner_bg}; color:#ffffff; font-size:16px; font-weight:600;" bgcolor="{banner_bg}">
      Azure Monitor Recovery • SkynetOps
      <span style="float:right;">{logo_img}</span>
    </td></tr>
    <tr><td style="padding:18px 20px;">
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="font-size:20px; font-weight:600; color:#1f2937;">{html_escape(vm_label)}</div>
        {badge}
      </div>
      {ticket_header_html}
    </td></tr>
    <tr><td style="padding:0 20px 18px;">
      <h3 style="margin:0 0 8px;">Essentials</h3>
      <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; border:1px solid #e5e7eb;" bgcolor="#ffffff">
        <tbody>{essentials}</tbody>
      </table>
    </td></tr>
    <tr><td style="padding:14px 20px; background:#f9fafb; border-top:1px solid #e5e7eb; font-size:12px; color:#374151;" bgcolor="#f9fafb">
      This recovery was automatically detected by <strong>SkynetOps Monitoring Platform</strong>.
    </td></tr>
  </table>
</td></tr></table>
</body>
</html>"""

def _metric_breached(cfg: Dict[str, Any], cur_value: Optional[float], thr_key: str) -> bool:
    if cur_value is None or (isinstance(cur_value, float) and np.isnan(cur_value)):
        return False
    key_to_cfg = {"cpu": "cpu_threshold", "mem": "memory_threshold", "disk": "disk_threshold"}
    return float(cur_value) >= float(cfg[key_to_cfg[thr_key]])

def handle_recoveries_add_note_only(cfg: Dict[str, Any],
                                    vm: Dict[str, Any],
                                    sub_id: str, rg: str, name: str,
                                    power_state: str, df: pd.DataFrame,
                                    cpu_latest: Optional[float],
                                    memory_used_pct: Optional[float],
                                    disk_percent: Optional[float]) -> None:
    """
    NOTE-ONLY recovery handler:
    - If Crash ticket exists and VM is Running -> send VM-up email + add concise note.
    - If Telemetry ticket exists and metrics are present -> send telemetry recovery email + add concise note.
    - If CPU/Memory/Disk incidents are open and value is below threshold -> send metric recovery email + add concise note.
    """
    vm_label = f"{name} / {rg}"
    sn_state = _sn_load_state()
    vm_key = f"{sub_id}\n{rg}\n{name}"
    vm_issue_state = _sn_get_vm_issue_state(sn_state, vm_key)
    open_map = vm_issue_state.get("open", {})

    now_iso = _to_utc_z(datetime.now(timezone.utc))
    is_running = (power_state == "Running")
    metrics_missing = df.empty

    # Crash → Running
    if open_map.get("Crash", {}).get("sys_id") and is_running:
        b = open_map["Crash"]
        sys_id = b.get("sys_id"); number = b.get("number"); link = sn_incident_link(sys_id)
        sent = send_email(
            dict(cfg, **({"email_to": vm["email_to"]} if vm.get("email_to") else {})),
            subject=f"[Recovery] {vm_label} — VM is Running",
            html_body=build_vm_up_recovery_email_html(vm_label, now_iso, cfg.get("company_logo_path"), _ticket_inline(number, link)),
            attachments=[], inline_cids={"company_logo": Path(cfg["company_logo_path"])} if cfg.get("company_logo_path") else None
        )
        err = sn_add_recovery_note(sys_id, "Recovered: PowerState=Running.")
        if err: print(f"[{vm_label}] ⚠ SN recovery-note (Crash) failed: {err}")
        else:   print(f"[{vm_label}] ✅ Crash recovery noted (email_sent={sent})")

    # Telemetry → back
    if open_map.get("Telemetry", {}).get("sys_id") and is_running and not metrics_missing:
        b = open_map["Telemetry"]
        sys_id = b.get("sys_id"); number = b.get("number"); link = sn_incident_link(sys_id)
        sent = send_email(
            dict(cfg, **({"email_to": vm["email_to"]} if vm.get("email_to") else {})),
            subject=f"[Recovery] {vm_label} — Telemetry pipeline is healthy",
            html_body=build_metric_recovery_email_html(vm.get("name") or cfg["vm_name"], now_iso, "Telemetry", "Metrics received", "N/A",
                                                       cfg.get("company_logo_path"), _ticket_inline(number, link)),
            attachments=[], inline_cids={"company_logo": Path(cfg["company_logo_path"])} if cfg.get("company_logo_path") else None
        )
        err = sn_add_recovery_note(sys_id, "Recovered: Metrics pipeline healthy.")
        if err: print(f"[{vm_label}] ⚠ SN recovery-note (Telemetry) failed: {err}")
        else:   print(f"[{vm_label}] ✅ Telemetry recovery noted (email_sent={sent})")

    # Skip metric recoveries if VM not running or metrics missing
    if not is_running or metrics_missing:
        return

    # Metric recoveries (CPU / Memory / Disk)
    if open_map.get("CPU", {}).get("sys_id") and (cpu_latest is not None) and not _metric_breached(cfg, cpu_latest, "cpu"):
        b = open_map["CPU"]; sys_id = b.get("sys_id"); number = b.get("number"); link = sn_incident_link(sys_id)
        sent = send_email(
            dict(cfg, **({"email_to": vm["email_to"]} if vm.get("email_to") else {})),
            subject=f"[Recovery] {vm.get('name') or 'VM'} — CPU back to normal",
            html_body=build_metric_recovery_email_html(vm.get("name") or cfg["vm_name"], now_iso, "CPU",
                                                       f"{cpu_latest:.2f}%", f"{cfg['cpu_threshold']:.2f}%",
                                                       cfg.get("company_logo_path"), _ticket_inline(number, link)),
            attachments=[], inline_cids={"company_logo": Path(cfg["company_logo_path"])} if cfg.get("company_logo_path") else None
        )
        err = sn_add_recovery_note(sys_id, f"Recovered: CPU={cpu_latest:.2f}% < threshold {cfg['cpu_threshold']:.2f}%.")
        if err: print(f"[{vm_label}] ⚠ SN recovery-note (CPU) failed: {err}")
        else:   print(f"[{vm_label}] ✅ CPU recovery noted (email_sent={sent})")

    if open_map.get("Memory", {}).get("sys_id") and (memory_used_pct is not None) and not _metric_breached(cfg, memory_used_pct, "mem"):
        b = open_map["Memory"]; sys_id = b.get("sys_id"); number = b.get("number"); link = sn_incident_link(sys_id)
        sent = send_email(
            dict(cfg, **({"email_to": vm["email_to"]} if vm.get("email_to") else {})),
            subject=f"[Recovery] {vm.get('name') or 'VM'} — Memory back to normal",
            html_body=build_metric_recovery_email_html(vm.get("name") or cfg["vm_name"], now_iso, "Memory",
                                                       f"{memory_used_pct:.2f}%", f"{cfg['memory_threshold']:.2f}%",
                                                       cfg.get("company_logo_path"), _ticket_inline(number, link)),
            attachments=[], inline_cids={"company_logo": Path(cfg["company_logo_path"])} if cfg.get("company_logo_path") else None
        )
        err = sn_add_recovery_note(sys_id, f"Recovered: MemoryUsed={memory_used_pct:.2f}% < threshold {cfg['memory_threshold']:.2f}%.")
        if err: print(f"[{vm_label}] ⚠ SN recovery-note (Memory) failed: {err}")
        else:   print(f"[{vm_label}] ✅ Memory recovery noted (email_sent={sent})")

    if open_map.get("Disk", {}).get("sys_id") and (disk_percent is not None) and not _metric_breached(cfg, disk_percent, "disk"):
        b = open_map["Disk"]; sys_id = b.get("sys_id"); number = b.get("number"); link = sn_incident_link(sys_id)
        sent = send_email(
            dict(cfg, **({"email_to": vm["email_to"]} if vm.get("email_to") else {})),
            subject=f"[Recovery] {vm.get('name') or 'VM'} — Disk back to normal",
            html_body=build_metric_recovery_email_html(vm.get("name") or cfg["vm_name"], now_iso, "Disk",
                                                       f"{disk_percent:.2f}%", f"{cfg['disk_threshold']:.2f}%",
                                                       cfg.get("company_logo_path"), _ticket_inline(number, link)),
            attachments=[], inline_cids={"company_logo": Path(cfg["company_logo_path"])} if cfg.get("company_logo_path") else None
        )
        err = sn_add_recovery_note(sys_id, f"Recovered: DiskUsage={disk_percent:.2f}% < threshold {cfg['disk_threshold']:.2f}%.")
        if err: print(f"[{vm_label}] ⚠ SN recovery-note (Disk) failed: {err}")
        else:   print(f"[{vm_label}] ✅ Disk recovery noted (email_sent={sent})")


# ==================== Orchestrator (per VM) ====================
def run_once_for_vm(cfg: Dict[str, Any], vm: Dict[str, Any]) -> Tuple[str, bool, Optional[str]]:
    try:
        sub_id = vm.get("subscription_id") or cfg["subscription_id"]
        rg = vm.get("resource_group") or cfg["resource_group"]
        name = vm.get("name") or cfg["vm_name"]
        vm_label = f"{name} / {rg}"

        sn_state = _sn_load_state()
        vm_key = f"{sub_id}\n{rg}\n{name}"
        vm_issue_state = _sn_get_vm_issue_state(sn_state, vm_key)
        open_map = vm_issue_state["open"]

        compute = build_compute_client(sub_id)
        iv = compute.virtual_machines.instance_view(resource_group_name=rg, vm_name=name)
        power_code = next((s.code for s in (iv.statuses or []) if s and str(s.code).lower().startswith("powerstate/")), "PowerState/unknown")
        power_state = normalize_power_state(power_code)

        df = query_metrics_for_vm(sub_id, rg, name, cfg["fast_lookback_min"])

        cpu_series_max = get_metric_series(df, "Percentage CPU", "Maximum")
        cpu_series_avg = get_metric_series(df, "Percentage CPU", "Average")
        cpu_series_for_stats = cpu_series_avg if not cpu_series_avg.empty else cpu_series_max
        cpu_stat = series_stats(cpu_series_for_stats)
        cpu_latest = (cpu_series_max.iloc[-1] if not cpu_series_max.empty else (cpu_series_avg.iloc[-1] if not cpu_series_avg.empty else None))
        if cpu_latest is not None:
            cpu_latest = float(cpu_latest)

        mem_pct_avail_min_series = get_metric_series(df, "Available Memory Percentage", "Minimum")
        mem_avail_bytes_min_series = get_metric_series(df, "Available Memory Bytes", "Minimum")
        memory_used_pct: Optional[float] = None
        mem_free_pct: Optional[float] = None
        if not mem_pct_avail_min_series.empty:
            mem_free_pct = float(mem_pct_avail_min_series.iloc[-1])
            memory_used_pct = max(0.0, min(100.0, 100.0 - float(mem_pct_avail_min_series.iloc[-1])))
        elif not mem_avail_bytes_min_series.empty and cfg["total_memory_bytes"] > 0:
            mem_free_pct = (float(mem_avail_bytes_min_series.iloc[-1]) / cfg["total_memory_bytes"]) * 100.0
            mem_free_pct = max(0.0, min(100.0, mem_free_pct))
            memory_used_pct = 100.0 - mem_free_pct

        dr_total = get_metric_series(df, "Disk Read Bytes", "Total")
        if dr_total.empty: dr_total = get_metric_series(df, "Disk Read Bytes", "Average")
        dw_total = get_metric_series(df, "Disk Write Bytes", "Total")
        if dw_total.empty: dw_total = get_metric_series(df, "Disk Write Bytes", "Average")
        dr_stat = {"latest": (float(dr_total.iloc[-1]) if not dr_total.empty else None),
                   "avg": (float(dr_total.mean()) if not dr_total.empty else None)}
        dw_stat = {"latest": (float(dw_total.iloc[-1]) if not dw_total.empty else None),
                   "avg": (float(dw_total.mean()) if not dw_total.empty else None)}

        disk_percent = ssh_get_disk_usage_percent_vm(vm)

        cpu_ts = get_metric_series_with_ts(df, "Percentage CPU", ["Maximum", "Average"])
        dr_ts = get_metric_series_with_ts(df, "Disk Read Bytes", ["Total", "Average"])
        dw_ts = get_metric_series_with_ts(df, "Disk Write Bytes", ["Total", "Average"])
        cpu_fc = advanced_forecast_series(cpu_ts, horizons_minutes=[15, 30, 60], clamp_low=0.0, clamp_high=100.0)
        dr_fc = advanced_forecast_series(dr_ts, horizons_minutes=[15, 30, 60], clamp_low=0.0, clamp_high=None)
        dw_fc = advanced_forecast_series(dw_ts, horizons_minutes=[15, 30, 60], clamp_low=0.0, clamp_high=None)

        cpu_crossed  = (cpu_latest is not None) and (cpu_latest >= cfg["cpu_threshold"])
        mem_crossed  = (memory_used_pct is not None) and (memory_used_pct >= cfg["memory_threshold"])
        disk_crossed = (disk_percent is not None) and (disk_percent >= cfg["disk_threshold"])
        thresholds_crossed = cpu_crossed or mem_crossed or disk_crossed

        is_running = (power_state == "Running")
        metrics_missing = df.empty

        ts_now = int(time.time())
        attachments: List[Path] = []
        alert_failed_csv = build_failed_csv(cpu_latest, mem_free_pct, cfg)
        attachments.append(alert_failed_csv)
        alert_ctx = {
            "vm": vm_label,
            "fired_utc": _to_utc_z(datetime.now(timezone.utc)),
            "power_state": power_state,
            "cpu_latest": f"{cpu_latest:.2f}" if cpu_latest is not None else "N/A",
            "cpu_threshold": f"{cfg['cpu_threshold']:.2f}",
            "memory_used_pct": f"{memory_used_pct:.2f}" if memory_used_pct is not None else "N/A",
            "memory_threshold": f"{cfg['memory_threshold']:.2f}",
            "disk_usage_pct": f"{disk_percent:.2f}" if disk_percent is not None else "N/A",
            "disk_threshold": f"{cfg['disk_threshold']:.2f}",
            "dr_latest": dr_stat["latest"],
            "dr_avg": dr_stat["avg"],
            "dw_latest": dw_stat["latest"],
            "dw_avg": dw_stat["avg"],
        }
        alert_ctx_csv = build_alert_ctx_csv(alert_ctx)
        attachments.append(alert_ctx_csv)

        # --------------- CONDITION 1: Threshold breach ---------------
        if is_running and thresholds_crossed:
            print(f"[{vm_label}] Condition 1: running + thresholds crossed. Building Azure-style metric alert email.")
            top = ssh_get_top_processes_vm(vm, max_rows=5)
            loadavg = ssh_get_load_averages_vm(vm)
            if loadavg:
                load_desc_html = (
                    f"<div style='font-size:13px; color:#374151;'>"
                    f"<strong>Load average:</strong> {loadavg['l1']:.2f} {loadavg['l5']:.2f} {loadavg['l15']:.2f} "
                    f"&nbsp;<strong>Uptime:</strong> {html_escape(loadavg['uptime'])} "
                    f"&nbsp;<strong>Tasks:</strong> {loadavg['running']}/{loadavg['total']} running"
                    f"</div>"
                )
            else:
                load_desc_html = "<div style='font-size:13px; color:#6b7280;'><strong>Load average:</strong> N/A (SSH not available/disabled)</div>"

            cpu_status, cpu_sev = compute_status_and_severity(cpu_latest, cfg["cpu_threshold"], cfg)
            mem_status, mem_sev = compute_status_and_severity(memory_used_pct, cfg["memory_threshold"], cfg) if memory_used_pct is not None else ("Unknown", None)
            disk_status, disk_sev = compute_status_and_severity(disk_percent, cfg["disk_threshold"], cfg) if disk_percent is not None else ("Unknown", None)

            def aggregate_overall(cpu_status: str, mem_status: str, disk_status: str) -> str:
                statuses = [cpu_status, mem_status, disk_status]
                if "Critical" in statuses: return "Critical"
                if "Warning" in statuses: return "Warning"
                if all(s in ("Healthy", "Unknown") for s in statuses): return "Healthy"
                return "Unknown"

            overall = aggregate_overall(cpu_status, mem_status, disk_status)
            metrics_details = {
                "cpu": cpu_stat,
                "mem_used_pct": (float(memory_used_pct) if memory_used_pct is not None else None),
                "mem_avail_bytes": (float(mem_avail_bytes_min_series.iloc[-1]) if not mem_avail_bytes_min_series.empty else None),
                "disk_usage_pct": (float(disk_percent) if disk_percent is not None else None),
                "disk_read_bytes": dr_stat,
                "disk_write_bytes": dw_stat,
            }
            metrics_details_html = build_metrics_details_html(metrics_details)

            cpu_current_str = f"{cpu_latest:.2f}%" if cpu_latest is not None else "N/A"
            mem_current_str = f"{(memory_used_pct or 0):.2f}%" if memory_used_pct is not None else "N/A"
            disk_current_str = f"{(disk_percent or 0):.2f}%" if disk_percent is not None else "N/A"
            cpu_threshold_str = f"{cfg['cpu_threshold']:.2f}%"
            mem_threshold_str = f"{cfg['memory_threshold']:.2f}%"
            disk_threshold_str = f"{cfg['disk_threshold']:.2f}%"

            cpu_anoms = _count_z_anomalies(cpu_ts) if not cpu_ts.empty else 0
            dr_anoms = _count_z_anomalies(dr_ts) if not dr_ts.empty else 0
            dw_anoms = _count_z_anomalies(dw_ts) if not dw_ts.empty else 0
            mem_ctx = {
                "used_pct": float(memory_used_pct) if memory_used_pct is not None else None,
                "avail_bytes": float(mem_avail_bytes_min_series.iloc[-1]) if not mem_avail_bytes_min_series.empty else None,
                "free_pct": float(mem_free_pct) if mem_free_pct is not None else None,
            }
            disk_ctx = {
                "usage_pct": float(disk_percent) if disk_percent is not None else None,
                "read_ts": [{"timestamp": str(t), "value": float(v)} for t, v in (dr_ts.items() if hasattr(dr_ts, "items") else [])],
                "write_ts": [{"timestamp": str(t), "value": float(v)} for t, v in (dw_ts.items() if hasattr(dw_ts, "items") else [])],
            }
            cpu_ts_json = [{"timestamp": str(t), "value": float(v)} for t, v in (cpu_ts.items() if hasattr(cpu_ts, "items") else [])]
            unified_context = {
                "vm": {"name": name, "resource_group": rg, "subscription": sub_id},
                "power_state": power_state,
                "cpu": cpu_ts_json,
                "memory": mem_ctx,
                "disk": disk_ctx,
                "ssh": {"top": top, "notes": ("pidstat/iotop not available" if (top and top.get("disk") and "not available" in str(top["disk"][0].get("command","")).lower()) else "")},
                "forecasts": {"cpu": cpu_fc, "disk_read": dr_fc, "disk_write": dw_fc},
                "anomalies": {"cpu_count": cpu_anoms, "disk_read_count": dr_anoms, "disk_write_count": dw_anoms},
                "thresholds": {"cpu": cfg["cpu_threshold"], "mem": cfg["memory_threshold"], "disk": cfg["disk_threshold"]},
            }
            full_ai_text = run_ai_full_incident_analysis(cfg, unified_context)

            ai_txt_path = OUTPUT_DIR / f"ai_analysis_{name}_{int(time.time())}.txt"
            try:
                with open(ai_txt_path, "w", encoding="utf-8") as f:
                    f.write(full_ai_text)
                attachments.append(ai_txt_path)
            except Exception as e:
                print("AI report attachment creation failed:", e)

            def row(metric, cur, thr, status, sev, ticket_num, ticket_link):
                sev_out = sev or "-"
                ticket_html = render_ticket_link(ticket_num, ticket_link) if ticket_num and ticket_link else "-"
                return (
                    "<tr>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(metric)}</td>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(cur)}</td>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(thr)}</td>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(status)}</td>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb; color:#b91c1c;'>{html_escape(sev_out)}</td>"
                    f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{ticket_html}</td>"
                    "</tr>"
                )

            thresholds_dict = {"cpu": float(cfg["cpu_threshold"]), "mem": float(cfg["memory_threshold"]), "disk": float(cfg["disk_threshold"])}
            now_iso = _to_utc_z(datetime.now(timezone.utc))
            metrics_dict = {
                "cpu_percent": float(cpu_latest) if cpu_latest is not None else float("nan"),
                "memory_percent": float(memory_used_pct) if memory_used_pct is not None else float("nan"),
                "disk_percent": float(disk_percent) if disk_percent is not None else float("nan"),
            }
            triggered_alerts = build_triggered_alerts(metrics_dict, thresholds_dict, now_iso, cfg)
            alerts_html = render_alerts_html(triggered_alerts)
            charts_block_html = (
                "<tr><td style='padding:0 20px 18px;' bgcolor='#ffffff'>"
                "<h3 style='margin:0 0 8px;'>Triggered Alerts</h3>"
                f"{alerts_html}"
                "</td></tr>"
            )

            inline_cids: Dict[str, Path] = {}
            if cfg.get("company_logo_path"):
                inline_cids["company_logo"] = Path(cfg["company_logo_path"])

            # Recent charts
            try:
                df_avg = df[df["aggregation"] == "Average"].copy()
                df_total = df[df["aggregation"] == "Total"].copy()
                df_max = df[df["aggregation"] == "Maximum"].copy()
                cpu_line_recent = generate_line_chart(df_max, "Percentage CPU", f"cpu_line_{ts_now}.png")
                mem_line_recent = generate_line_chart(df_avg, "Available Memory Bytes", f"mem_line_{ts_now}.png")
                dr_line_recent  = generate_line_chart(df_total if not df_total.empty else df_avg, "Disk Read Bytes",  f"disk_read_{ts_now}.png")
                dw_line_recent  = generate_line_chart(df_total if not df_total.empty else df_avg, "Disk Write Bytes", f"disk_write_{ts_now}.png")
                cpu_hist_recent = generate_histogram(df_max, "Percentage CPU", f"cpu_hist_{ts_now}.png")
                cpu_pie_recent  = generate_pie_chart(cpu_latest if cpu_latest is not None else 0.0, f"cpu_pie_{ts_now}.png")
                attachments += [cpu_line_recent, mem_line_recent, dr_line_recent, dw_line_recent, cpu_hist_recent, cpu_pie_recent]
            except Exception as e:
                print("Recent chart build error:", e)

            # 5-day charts
            try:
                df_5d = query_metrics_last_days(sub_id, rg, name, days_back=5, granularity="PT30M")
                df5d_avg = df_5d[df_5d["aggregation"] == "Average"].copy()
                df5d_tot = df_5d[df_5d["aggregation"] == "Total"].copy()
                df5d_max = df_5d[df_5d["aggregation"] == "Maximum"].copy()
                cpu_line_5d = generate_line_chart(df5d_max, "Percentage CPU", f"cpu_line_5d_{ts_now}.png")
                mem_line_5d = generate_line_chart(df5d_avg, "Available Memory Bytes", f"mem_line_5d_{ts_now}.png")
                dr_line_5d  = generate_line_chart(df5d_tot if not df5d_tot.empty else df5d_avg, "Disk Read Bytes",  f"disk_read_5d_{ts_now}.png")
                dw_line_5d  = generate_line_chart(df5d_tot if not df5d_tot.empty else df5d_avg, "Disk Write Bytes", f"disk_write_5d_{ts_now}.png")
                attachments += [cpu_line_5d, mem_line_5d, dr_line_5d, dw_line_5d]
            except Exception as e:
                print("5-day chart build error:", e)

            ai_text_block = f"<pre style='background:#ffffff; border:1px solid #e5e7eb; padding:12px; white-space:pre-wrap;'>{html_escape(full_ai_text or 'Insufficient evidence')}</pre>"
            now_iso2 = _to_utc_z(datetime.now(timezone.utc))
            essentials = {
                "Fired time (UTC)": now_iso2,
                "Severity": overall,
                "Monitor condition": "Fired",
                "Alert rule": "SkynetOps Threshold Alert",
                "Signal type": "Metric",
                "Resource": name or "VM",
                "Resource group": rg,
                "Subscription": sub_id,
            }

            # Ticket header block
            items_inline = []
            for k in ("CPU", "Memory", "Disk"):
                bucket = (open_map.get(k, {}) or {})
                num = bucket.get("number"); sys_id = bucket.get("sys_id")
                lnk = sn_incident_link(sys_id) if sys_id else ""
                if num:
                    items_inline.append(f"{html_escape(k)}: {render_ticket_link(num, lnk)}")
            ticket_header_html = "<div style='margin-top:6px; font-size:13px;'>Tickets: " + " • ".join(items_inline) + "</div>" if items_inline else ""

            alert_summary_table_html = (
                "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
                "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
                "<th align='left' style='padding:8px;'>Metric</th>"
                "<th align='left' style='padding:8px;'>Current</th>"
                "<th align='left' style='padding:8px;'>Threshold</th>"
                "<th align='left' style='padding:8px;'>Status</th>"
                "<th align='left' style='padding:8px;'>Severity</th>"
                "<th align='left' style='padding:8px;'>Ticket #</th>"
                "</tr></thead><tbody>"
                + row("CPU Usage",    cpu_current_str,  cpu_threshold_str,  cpu_status,  cpu_sev, (open_map.get("CPU", {}) or {}).get("number"),    sn_incident_link((open_map.get("CPU", {}) or {}).get("sys_id")))
                + row("Disk Usage",   disk_current_str, disk_threshold_str, disk_status, disk_sev, (open_map.get("Disk", {}) or {}).get("number"),   sn_incident_link((open_map.get("Disk", {}) or {}).get("sys_id")))
                + row("Memory Usage", mem_current_str,  mem_threshold_str,  mem_status,  mem_sev, (open_map.get("Memory", {}) or {}).get("number"), sn_incident_link((open_map.get("Memory", {}) or {}).get("sys_id")))
                + "</tbody></table>"
            )

            body_html = build_azure_metric_alert_email(
                vm_name=name or 'VM',
                now_iso=now_iso2,
                severity_text=overall,
                essentials=essentials,
                load_desc_html=load_desc_html,
                alert_summary_table_html=alert_summary_table_html,
                metrics_details_html=metrics_details_html,
                charts_block_html=charts_block_html,
                top_html_block=build_top_processes_html_ssh(top),
                ai_analysis_html_block=ai_text_block,
                company_logo_path=cfg.get("company_logo_path"),
                ticket_header_html=ticket_header_html
            )

            try:
                if not df.empty:
                    csv_path = OUTPUT_DIR / f"metrics_{name}_{int(time.time())}.csv"
                    df.to_csv(csv_path, index=False)
                    attachments.append(csv_path)
                tp_rows = []
                for r in top.get("cpu", []):    tp_rows.append({"type": "cpu", **r})
                for r in top.get("memory", []): tp_rows.append({"type": "memory", **r})
                for r in top.get("disk", []):   tp_rows.append({"type": "disk", **r})
                if tp_rows:
                    tp_csv = OUTPUT_DIR / f"top_processes_{name}_{int(time.time())}.csv"
                    pd.DataFrame(tp_rows).to_csv(tp_csv, index=False)
                    attachments.append(tp_csv)
            except Exception as e:
                print("Attachment build failed:", e)

            subject = f"[Azure Monitor Alert] {name or 'VM'} — {overall}"
            cfg_local = dict(cfg)
            if vm.get("email_to"): cfg_local["email_to"] = vm["email_to"]
            sent = send_email(cfg_local, subject, body_html, attachments, inline_cids=inline_cids if inline_cids else None)

            # SN create/update (values-only notes on updates)
            try:
                caller_sys_id = sn_lookup_user_sys_id(email=SN_CALLER_EMAIL, username=SN_CALLER_USERNAME) if (SN_CALLER_EMAIL or SN_CALLER_USERNAME) else None
                ag_sys_or_name = SN_ASSIGNMENT_GROUP_NAME
                issues = []
                if cpu_latest is not None:
                    _s, _sev = compute_status_and_severity(cpu_latest, cfg["cpu_threshold"], cfg)
                    issues.append({"key": "CPU", "breached": cpu_crossed, "sev": _sev, "priority": sev_to_priority(_sev),
                                   "latest_str": f"{cpu_latest:.2f}%", "threshold_str": f"{cfg['cpu_threshold']:.2f}%"})
                if memory_used_pct is not None:
                    _s, _sev = compute_status_and_severity(memory_used_pct, cfg["memory_threshold"], cfg)
                    issues.append({"key": "Memory", "breached": mem_crossed, "sev": _sev, "priority": sev_to_priority(_sev),
                                   "latest_str": f"{memory_used_pct:.2f}%", "threshold_str": f"{cfg['memory_threshold']:.2f}%"})
                if disk_percent is not None:
                    _s, _sev = compute_status_and_severity(disk_percent, cfg["disk_threshold"], cfg)
                    issues.append({"key": "Disk", "breached": disk_crossed, "sev": _sev, "priority": sev_to_priority(_sev),
                                   "latest_str": f"{disk_percent:.2f}%", "threshold_str": f"{cfg['disk_threshold']:.2f}%"})
                for issue in issues:
                    bucket = open_map.get(issue["key"], {})
                    sys_id_existing = bucket.get("sys_id")
                    if sys_id_existing and sn_is_resolved_or_closed(sys_id_existing):
                        sys_id_existing = None
                        bucket = {}
                    short_desc = f"SkynetOps Alert: High {issue['key']} on {vm_label} ({issue['latest_str']} ≥ {issue['threshold_str']})"
                    description = (
                        "Incident raised automatically by SkynetOps.\n\n"
                        "Metric Threshold Breach:\n"
                        f"- {issue['key']}: {issue['latest_str']} (threshold {issue['threshold_str']}) [Severity={issue['sev'] or '-'}]\n\n"
                        "AI Analysis (Full):\n"
                        f"{full_ai_text}\n\n"
                        "Attachments:\n"
                        "- CSV: alert context & telemetry snapshots.\n"
                        "- Charts: recent and 5-day trends (if available).\n"
                        "- AI Report: full analysis text file.\n"
                    )
                    if issue["breached"]:
                        if not sys_id_existing:
                            urgency = sev_to_urgency(issue["sev"])
                            sys_id, number, err = sn_create_incident(
                                short_desc, description,
                                urgency=urgency, impact=urgency, priority=issue["priority"],
                                assignment_group=ag_sys_or_name, caller_id=caller_sys_id
                            )
                            if err:
                                print(f"[{vm_label}] ServiceNow create failed ({issue['key']}): {err}")
                            else:
                                print(f"[{vm_label}] ServiceNow incident created ({issue['key']}): {number}")
                                open_map[issue["key"]] = {"sys_id": sys_id, "number": number, "opened_due_to": issue["key"]}
                                _sn_save_state(sn_state)
                                err_ack = sn_ack_incident(sys_id)
                                if err_ack:
                                    print(f"[{vm_label}] ServiceNow ack failed ({issue['key']}): {err_ack}")
                        else:
                            # concise values-only update (no AI/runbook repeats)
                            now_iso3 = _to_utc_z(datetime.now(timezone.utc))
                            upd_notes = f"[{now_iso3}] {issue['key']} update: current={issue['latest_str']} threshold={issue['threshold_str']}"
                            err_upd = sn_add_work_notes(bucket.get("sys_id"), upd_notes)
                            if err_upd:
                                print(f"[{vm_label}] ServiceNow update failed ({issue['key']}): {err_upd}")
                vm_issue_state["open"] = open_map
                sn_state[vm_key] = vm_issue_state
                _sn_save_state(sn_state)
            except Exception as e:
                print(f"[{vm_label}] ServiceNow per-issue op error (post-email): {e}")

            # Attach files to incidents
            if SN_ATTACH_ON_UPDATE == 1:
                try:
                    for issue_key in ("CPU", "Memory", "Disk"):
                        bucket = open_map.get(issue_key, {})
                        sys_id_existing = bucket.get("sys_id")
                        if sys_id_existing:
                            for att in attachments or []:
                                e_attach = sn_attach_file(sys_id_existing, Path(att))
                                if e_attach:
                                    print(f"[{vm_label}] Attach error ({issue_key}) {att}: {e_attach}")
                except Exception as e:
                    print(f"[{vm_label}] ServiceNow attachment error: {e}")

            # >>> Recovery (concise note-only)
            try:
                handle_recoveries_add_note_only(cfg, vm, sub_id, rg, name, power_state, df, cpu_latest, memory_used_pct, disk_percent)
            except Exception as e:
                print(f"[{vm_label}] ⚠ recovery handler error: {e}")

            return (vm_label, sent, None)

        # --------------- CONDITION 2: Crash / VM not running ---------------
        elif not is_running:
            print(f"[{vm_label}] Condition 2: VM not running. Azure-style crash/status email (no charts).")
            rh = get_resource_health(sub_id, rg, name, cfg["crash_lookback_min"])
            acts = list_activity_logs_for_vm(sub_id, rg, name, cfg["crash_lookback_min"])

            serial_sas = None
            try:
                bd = iv.boot_diagnostics
                serial_sas = getattr(bd, "serial_console_log_blob_uri", None)
            except Exception:
                serial_sas = None
            serial_tail = download_blob_text_via_sas(serial_sas) or ""
            serial_tail = serial_tail[-4000:] if serial_tail else ""

            crash_bucket = open_map.get("Crash", {})
            crash_sys_id = crash_bucket.get("sys_id")
            if crash_sys_id and sn_is_resolved_or_closed(crash_sys_id):
                crash_sys_id = None
                crash_bucket = {}

            now_iso = _to_utc_z(datetime.now(timezone.utc))
            availability = rh.get("availability", {}) or {}

            unified_context = {
                "vm": {"name": name, "resource_group": rg, "subscription": sub_id},
                "power_state": power_state,
                "resource_health": rh,
                "activity_logs": acts,
                "serial_tail": serial_tail,
                "cpu": [],
                "disk": {"usage_pct": None, "read_ts": [], "write_ts": []},
                "memory": {"used_pct": None, "avail_bytes": None, "free_pct": None},
                "ssh": {"top": {}, "notes": ""},
                "forecasts": {"cpu": None, "disk_read": None, "disk_write": None},
                "anomalies": {"cpu_count": 0, "disk_read_count": 0, "disk_write_count": 0},
                "note": "Crash",
            }
            full_ai_text = run_ai_full_incident_analysis(cfg, unified_context)
            ai_text_block = f"<pre style='background:#ffffff; border:1px solid #e5e7eb; padding:12px; white-space:pre-wrap;'>{html_escape(full_ai_text or '')}</pre>"

            ai_txt_path = OUTPUT_DIR / f"ai_analysis_{name}_{int(time.time())}.txt"
            try:
                with open(ai_txt_path, "w", encoding="utf-8") as f:
                    f.write(full_ai_text)
            except Exception as e:
                print("AI report attachment creation failed:", e)

            crash_short = f"SkynetOps Alert: VM not running — {vm_label} (PowerState={power_state})"
            crash_desc = (
                f"VM not in Running state.\n"
                f"- Fired: {now_iso}\n"
                f"- Power State: {power_state}\n"
                f"- Availability: {availability.get('availability_state','Unknown')} ({availability.get('summary','')})\n"
                f"- Serial console tail captured.\n\n"
                "AI Analysis (Full):\n"
                f"{full_ai_text}\n"
            )

            ticket_num_crash = "-"
            ticket_link_crash = ""
            try:
                if not crash_sys_id:
                    sys_id, number, err = sn_create_incident(
                        crash_short, crash_desc, urgency=1, impact=1, priority=1,
                        assignment_group=SN_ASSIGNMENT_GROUP_NAME,
                        caller_id=sn_lookup_user_sys_id(email=SN_CALLER_EMAIL, username=SN_CALLER_USERNAME) if (SN_CALLER_EMAIL or SN_CALLER_USERNAME) else None
                    )
                    if err:
                        print(f"[{vm_label}] ServiceNow crash create failed: {err}")
                    else:
                        open_map["Crash"] = {"sys_id": sys_id, "number": number, "opened_due_to": "Crash"}
                        _sn_save_state(sn_state)
                        sn_ack_incident(sys_id)
                        ticket_num_crash = number or "-"
                        ticket_link_crash = sn_incident_link(sys_id)
                else:
                    ticket_num_crash = crash_bucket.get("number") or "-"
                    ticket_link_crash = sn_incident_link(crash_bucket.get("sys_id"))
                    # concise status-only note
                    sn_add_work_notes(crash_bucket.get("sys_id"), f"[{now_iso}] Still not running. PowerState={power_state}")
            except Exception as e:
                print(f"[{vm_label}] ServiceNow Crash incident error: {e}")

            if SN_ATTACH_ON_UPDATE == 1 and open_map.get("Crash", {}).get("sys_id"):
                try:
                    for att in [ai_txt_path] if ai_txt_path.exists() else []:
                        e_attach = sn_attach_file(open_map["Crash"]["sys_id"], Path(att))
                        if e_attach:
                            print(f"[{vm_label}] Attach error (Crash) {att}: {e_attach}")
                except Exception as e:
                    print(f"[{vm_label}] ServiceNow crash attachment error: {e}")

            # Recovery (note-only)
            try:
                handle_recoveries_add_note_only(cfg, vm, sub_id, rg, name, power_state, df, cpu_latest, memory_used_pct, disk_percent)
            except Exception as e:
                print(f"[{vm_label}] ⚠ recovery handler error: {e}")

            subject = f"[Azure Monitor Alert] {vm_label} — {power_state}"
            cfg_local = dict(cfg)
            if vm.get("email_to"): cfg_local["email_to"] = vm["email_to"]

            # Build minimal Activity Logs table (optional for brevity here)
            if acts:
                rows = []
                rows.append(
                    "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
                    "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
                    "<th align='left' style='padding:8px;'>Time</th>"
                    "<th align='left' style='padding:8px;'>Category</th>"
                    "<th align='left' style='padding:8px;'>Operation</th>"
                    "<th align='left' style='padding:8px;'>Status</th>"
                    "<th align='left' style='padding:8px;'>Caller</th>"
                    "</tr></thead><tbody>"
                )
                for e in acts[:15]:
                    rows.append(
                        "<tr>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('timestamp',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('category',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('operation',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('status',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('caller',''))}</td>"
                        "</tr>"
                    )
                rows.append("</tbody></table>")
                activity_logs_html = "".join(rows)
            else:
                activity_logs_html = "<p style='color:#6b7280;'>No recent Activity Log entries.</p>"

            essentials = {
                "Fired time (UTC)": now_iso,
                "Severity": "Critical",
                "Monitor condition": "Fired",
                "Signal type": "ResourceHealth/ActivityLog",
                "Power state": power_state,
                "Availability": f"{availability.get('availability_state','Unknown')} ({availability.get('summary','')})",
                "Resource": name or "VM",
                "Resource group": rg,
                "Subscription": sub_id,
            }
            ticket_header_html = f"<div style='margin-top:6px; font-size:13px;'>Ticket: {render_ticket_link(ticket_num_crash, ticket_link_crash)}</div>" if (ticket_link_crash and ticket_num_crash and ticket_num_crash != "-") else ""
            body_html = build_azure_crash_status_email(vm_label, now_iso, "Critical", essentials, activity_logs_html, ai_text_block, cfg.get("company_logo_path"), ticket_header_html)
            sent = send_email(cfg_local, subject, body_html, attachments=[], inline_cids=None)
            return (vm_label, sent, None)

        # --------------- CONDITION 3: Telemetry gap ---------------
        elif is_running and metrics_missing:
            print(f"[{vm_label}] Condition 3: Running but no metrics. Azure-style crash/status (telemetry gap).")
            rh = get_resource_health(sub_id, rg, name, cfg["crash_lookback_min"])
            acts = list_activity_logs_for_vm(sub_id, rg, name, cfg["crash_lookback_min"])

            serial_sas = None
            try:
                bd = iv.boot_diagnostics
                serial_sas = getattr(bd, "serial_console_log_blob_uri", None)
            except Exception:
                serial_sas = None
            serial_tail = download_blob_text_via_sas(serial_sas) or ""
            serial_tail = serial_tail[-4000:] if serial_tail else ""

            telemetry_bucket = open_map.get("Telemetry", {})
            telemetry_sys_id = telemetry_bucket.get("sys_id")
            if telemetry_sys_id and sn_is_resolved_or_closed(telemetry_sys_id):
                telemetry_sys_id = None
                telemetry_bucket = {}

            now_iso = _to_utc_z(datetime.now(timezone.utc))
            unified_context = {
                "vm": {"name": name, "resource_group": rg, "subscription": sub_id},
                "power_state": power_state,
                "resource_health": rh,
                "activity_logs": acts,
                "serial_tail": serial_tail,
                "cpu": [],
                "disk": {"usage_pct": None, "read_ts": [], "write_ts": []},
                "memory": {"used_pct": None, "avail_bytes": None, "free_pct": None},
                "ssh": {"top": {}, "notes": ""},
                "forecasts": {"cpu": None, "disk_read": None, "disk_write": None},
                "anomalies": {"cpu_count": 0, "disk_read_count": 0, "disk_write_count": 0},
                "note": f"No metrics found in last {cfg['fast_lookback_min']} minutes.",
            }
            full_ai_text = run_ai_full_incident_analysis(cfg, unified_context)
            ai_text_block = f"<pre style='background:#ffffff; border:1px solid #e5e7eb; padding:12px; white-space:pre-wrap;'>{html_escape(full_ai_text or '')}</pre>"

            telemetry_short = f"SkynetOps Alert: Telemetry gap — {vm_label}"
            telemetry_desc = (
                f"VM is Running but metrics are missing in the last {cfg['fast_lookback_min']} minutes.\n"
                f"- Fired: {now_iso}\n"
                f"- Power State: {power_state}\n"
                f"- Check agent/extension health, network, and Azure Monitor pipeline.\n"
            )

            ticket_num_tel = "-"
            ticket_link_tel = ""
            try:
                if not telemetry_sys_id:
                    sys_id, number, err = sn_create_incident(
                        telemetry_short, telemetry_desc, urgency=2, impact=2, priority=2,
                        assignment_group=SN_ASSIGNMENT_GROUP_NAME,
                        caller_id=sn_lookup_user_sys_id(email=SN_CALLER_EMAIL, username=SN_CALLER_USERNAME) if (SN_CALLER_EMAIL or SN_CALLER_USERNAME) else None
                    )
                    if err:
                        print(f"[{vm_label}] ServiceNow telemetry create failed: {err}")
                    else:
                        open_map["Telemetry"] = {"sys_id": sys_id, "number": number, "opened_due_to": "Telemetry"}
                        _sn_save_state(sn_state)
                        sn_ack_incident(sys_id)
                        ticket_num_tel = number or "-"
                        ticket_link_tel = sn_incident_link(sys_id)
                else:
                    ticket_num_tel = telemetry_bucket.get("number") or "-"
                    ticket_link_tel = sn_incident_link(telemetry_bucket.get("sys_id"))
                    sn_add_work_notes(telemetry_bucket.get("sys_id"), f"[{now_iso}] Telemetry still missing for last {cfg['fast_lookback_min']} min.")
            except Exception as e:
                print(f"[{vm_label}] ServiceNow Telemetry incident error: {e}")

            # Recovery (note-only)
            try:
                handle_recoveries_add_note_only(cfg, vm, sub_id, rg, name, power_state, df, cpu_latest, memory_used_pct, disk_percent)
            except Exception as e:
                print(f"[{vm_label}] ⚠ recovery handler error: {e}")

            # Build/broadcast email
            if acts:
                rows = []
                rows.append(
                    "<table width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse; border:1px solid #e5e7eb;' bgcolor='#ffffff'>"
                    "<thead><tr style='background:#f3f4f6;' bgcolor='#f3f4f6'>"
                    "<th align='left' style='padding:8px;'>Time</th>"
                    "<th align='left' style='padding:8px;'>Category</th>"
                    "<th align='left' style='padding:8px;'>Operation</th>"
                    "<th align='left' style='padding:8px;'>Status</th>"
                    "<th align='left' style='padding:8px;'>Caller</th>"
                    "</tr></thead><tbody>"
                )
                for e in acts[:15]:
                    rows.append(
                        "<tr>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('timestamp',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('category',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('operation',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('status',''))}</td>"
                        f"<td style='padding:8px; border-bottom:1px solid #e5e7eb;'>{html_escape(e.get('caller',''))}</td>"
                        "</tr>"
                    )
                rows.append("</tbody></table>")
                activity_logs_html = "".join(rows)
            else:
                activity_logs_html = "<p style='color:#6b7280;'>No recent Activity Log entries.</p>"

            essentials = {
                "Fired time (UTC)": now_iso,
                "Severity": "Warning",
                "Monitor condition": "Fired",
                "Signal type": "Metric/Telemetry gap",
                "Power state": power_state,
                "Availability": (rh.get("availability", {}) or {}).get("availability_state", "Unknown"),
                "Resource": name or "VM",
                "Resource group": rg,
                "Subscription": sub_id,
                "Note": f"No metrics found in last {cfg['fast_lookback_min']} minutes.",
            }

            ticket_header_html = f"<div style='margin-top:6px; font-size:13px;'>Ticket: {render_ticket_link(ticket_num_tel, ticket_link_tel)}</div>" if (ticket_link_tel and ticket_num_tel and ticket_num_tel != "-") else ""
            body_html = build_azure_crash_status_email(vm_label, now_iso, "Warning", essentials, activity_logs_html, ai_text_block, cfg.get("company_logo_path"), ticket_header_html)
            subject = f"[Azure Monitor Alert] {vm_label} — Running (telemetry gap)"
            cfg_local = dict(cfg)
            if vm.get("email_to"): cfg_local["email_to"] = vm["email_to"]
            sent = send_email(cfg_local, subject, body_html, attachments=[], inline_cids=None)
            return (vm_label, sent, None)

        # --------------- HEALTHY (no alerts) ---------------
        else:
            print(f"[{vm_label}] No alert this cycle (running & thresholds NOT crossed). CPU={cpu_latest}, MemUsed%={memory_used_pct}, Disk%={disk_percent}")
            try:
                handle_recoveries_add_note_only(cfg, vm, sub_id, rg, name, power_state, df, cpu_latest, memory_used_pct, disk_percent)
            except Exception as e:
                print(f"[{vm_label}] ⚠ recovery handler error: {e}")
            return (vm_label, False, None)

    except Exception as e:
        return (vm.get("name") or "vm", False, str(e))


# ==================== Loops ====================
def continuous_loop(cfg: Dict[str, Any], vms: List[Dict[str, Any]]) -> None:
    while True:
        try:
            for vm in vms:
                label, sent, err = run_once_for_vm(cfg, vm)
                if err:
                    print(f"[{label}] ❌ {err}")
                elif sent:
                    print(f"[{label}] ✅ email sent")
                else:
                    print(f"[{label}] ℹ cycle completed (no email)")
            time.sleep(60)
        except KeyboardInterrupt:
            print("Exiting.")
            break
        except Exception as e:
            print("Loop error:", e)
            time.sleep(10)

def continuous_loop_parallel(cfg: Dict[str, Any], vms: List[Dict[str, Any]]) -> None:
    from concurrent.futures import ProcessPoolExecutor, as_completed
    max_workers = min(len(vms), (os.cpu_count() or 4))
    while True:
        try:
            start_ts = time.time()
            with ProcessPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(run_once_for_vm, cfg, vm) for vm in vms]
                for fut in as_completed(futures):
                    try:
                        label, sent, err = fut.result()
                    except Exception as child_ex:
                        print(f"[parallel] ❌ child error: {child_ex}")
                        continue
                    if err:
                        print(f"[{label}] ❌ {err}")
                    elif sent:
                        print(f"[{label}] ✅ email sent")
                    else:
                        print(f"[{label}] ℹ cycle completed (no email)")
            elapsed = time.time() - start_ts
            time.sleep(max(5, 60 - int(elapsed)))
        except KeyboardInterrupt:
            print("Exiting.")
            break
        except Exception as e:
            print("Loop error (parent):", e)
            time.sleep(10)

# ==================== Entry ====================
if __name__ == "__main__":
    cfg = load_config_from_kv()
    vms = parse_vms(cfg)

    if "--show-config" in sys.argv:
        print("Key Vault URL:", KEYVAULT_URL)
        print("Subscription ID:", cfg["subscription_id"])
        print("Default RG/VM:", cfg["resource_group"], "/", cfg["vm_name"])
        print("Email To:", cfg["email_to"])
        print("SMTP:", cfg["smtp_server"], cfg["smtp_port"])
        print("Thresholds: CPU/MEM/DISK =", cfg["cpu_threshold"], cfg["memory_threshold"], cfg["disk_threshold"])
        print("Severity margins (P1/P2/P3):", cfg["sev_margin_p1"], cfg["sev_margin_p2"], cfg["sev_margin_p3"])
        print("FAST-LOOKBACK-MIN:", cfg["fast_lookback_min"])
        print("TOTAL-MEMORY-BYTES:", cfg["total_memory_bytes"])
        print("Crash lookback/watch:", cfg["crash_lookback_min"], "/", cfg["crash_watch_sec"])
        print("Inline charts:", cfg["inline_charts"])
        print("Using VMS-CONFIG-JSON:", bool(cfg["vms_config_json"]))
        print("AI endpoint/model present:", bool(cfg.get("project_endpoint")), bool(cfg.get("model_deployment")))
        print("Log Analytics Workspace ID:", cfg.get("workspace_id"))
        print("VM Source:", f"vms.json @ {Path(VMS_JSON_PATH).resolve()}" if Path(VMS_JSON_PATH).is_file() else "KV / fallback")
        print("SSH mode:", "Per-VM from vms.json (no global SSH)")
        print("ServiceNow:", SN_INSTANCE_URL, "attach_on_update:", SN_ATTACH_ON_UPDATE, "verify_ssl:", SN_VERIFY)
        print("ACK behavior:", "In Progress only (no On Hold, no SLA pause)")
        print("AI_FULL_ANALYSIS_ONLY:", AI_FULL_ANALYSIS_ONLY)
        sys.exit(0)

    if "--parallel" in sys.argv:
        continuous_loop_parallel(cfg, vms)
    else:
        continuous_loop(cfg, vms)
