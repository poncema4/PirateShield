"""

PirateShield - Network Anomaly Detection Model
================================================
Rule-based risk scoring engine implementing rules M01-M08.
Produces composite risk scores on a 0-100 scale.

Rules
-----
  M01  Excessive Outbound Traffic       (+40 max)  14-day rolling baseline
  M02  VPN / Proxy Destination          (+25 max)
  M03  Abnormal Connection Burst        (+35 max)  14-day rolling baseline
  M04  High-Risk Port Access            (+30 max)  14-day rolling baseline
  M05  Suspicious Protocol              (+20 max)
  M06  Unknown Device                   (+15 max)
  M07  C2 Beaconing Detection           (+40 max)  inter-arrival time variance
  M08  Threat Event Classification      (+40 max)

Composite
---------
  composite = min(100, M01 + M02 + M03 + M04 + M05 + M06 + M07 + M08)

Alert Thresholds
----------------
  composite >= 60  OR  any single rule raw score >= 80% of its max
  => write alert to the alerts table in pirateshield.db

Severity
--------
  0-14   None
  15-34  Low
  35-59  Medium
  60-84  High
  85-100 Critical

"""

import json
import sys
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

import numpy as np
import pandas as pd

BASE_DIR     = Path(__file__).resolve().parents[2]
DATA_FILE    = BASE_DIR / "data" / "synthetic_events" / "synthetic_network_events.json"
MODEL_OUTPUT = BASE_DIR / "data" / "risk_scores" / "network" / "network_risk_scores.json"
DB_PATH      = BASE_DIR / "pirateshield.db"

BASELINE_WINDOW_DAYS = 14

HIGH_RISK_PORTS   = {22, 23, 3389, 4444, 5900, 6667, 1337}
VPN_PROXY_PORTS   = {1080, 1194, 8080, 9050, 9150, 4145, 1081}
SUSPICIOUS_DEST   = {"185.220.101.1", "198.51.100.77", "203.0.113.45"}

HIGH_RISK_TYPES   = {"port_scan", "brute_force", "data_exfil", "malware",
                     "lateral_movement", "c2_beacon"}
MEDIUM_RISK_TYPES = {"unusual_login", "vpn_connection"}

PROTOCOL_MAP      = {"TCP": 0, "UDP": 1, "ICMP": 2, "RAW": 3}

RULE_MAX = {
    "M01": 40, "M02": 25, "M03": 35, "M04": 30,
    "M05": 20, "M06": 15, "M07": 40, "M08": 40,
}

SEVERITY_THRESHOLDS = [
    (85, "critical"),
    (60, "high"),
    (35, "medium"),
    (15, "low"),
]

FEATURE_COLS = [
    "bytes_sent", "bytes_received", "byte_volume",
    "protocol_code", "port_risk", "event_type_risk",
    "dest_ip_risk", "unknown_device", "hour",
]

def load_events(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)

def get_severity(score: int) -> str | None:
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return None

def severity_label(score: int) -> str:
    s = get_severity(score)
    return s.upper() if s else "NONE"

def events_to_dataframe(events: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(events)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["bytes_sent"]     = df["bytes_sent"].fillna(0).astype(float)
    df["bytes_received"] = df["bytes_received"].fillna(0).astype(float)
    df["byte_volume"]    = df["bytes_sent"] + df["bytes_received"]
    df["destination_port"] = df["destination_port"].fillna(0).astype(int)

    df["protocol_code"] = df["protocol"].map(PROTOCOL_MAP).fillna(0).astype(int)

    df["port_risk"] = df["destination_port"].apply(
        lambda p: 1.0 if p in HIGH_RISK_PORTS else 0.0
    )

    def event_risk(et):
        if et in HIGH_RISK_TYPES:
            return 1.0
        if et in MEDIUM_RISK_TYPES:
            return 0.5
        return 0.0

    df["event_type_risk"] = df["event_type"].apply(event_risk)

    df["dest_ip_risk"] = df["destination_ip"].apply(
        lambda ip: 1.0 if ip in SUSPICIOUS_DEST else 0.0
    )

    def unknown_device(row):
        known = row.get("user_known_devices")
        dev   = row.get("device_id")
        if not known or not dev:
            return 0.5
        if isinstance(known, str):
            try:
                known = json.loads(known)
            except (json.JSONDecodeError, TypeError):
                return 0.5
        return 0.0 if dev in known else 1.0

    df["unknown_device"] = df.apply(unknown_device, axis=1)
    df["hour"] = df["timestamp"].dt.hour

    return df

class RollingBaseline:
    """Compute per-device rolling statistics over a configurable window."""

    def __init__(self, df: pd.DataFrame, window_days: int = BASELINE_WINDOW_DAYS):
        self.window = timedelta(days=window_days)
        self.df = df

        self._bytes_by_device: dict[str, list[float]] = defaultdict(list)
        self._ports_by_device: dict[str, list[int]]   = defaultdict(list)
        self._conn_counts:     dict[str, list[int]]    = defaultdict(list)

        self._precompute()

    def _precompute(self):
        if self.df.empty:
            return
        for device_id, group in self.df.groupby("device_id"):
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].values
            bytes_sent = group["bytes_sent"].values
            ports      = group["destination_port"].values
            dest_ips   = group["destination_ip"].values

            for i in range(len(group)):
                current_ts = timestamps[i]
                window_start = current_ts - np.timedelta64(int(self.window.total_seconds()), 's')
                mask = (timestamps[:i] >= window_start)
                historical = bytes_sent[:i][mask]

                self._bytes_by_device[device_id].append(
                    (float(np.mean(historical)) if len(historical) > 0 else 0.0,
                     float(np.std(historical))  if len(historical) > 1 else 1.0)
                )

                hist_ports = ports[:i][mask]
                hr_count = sum(1 for p in hist_ports if p in HIGH_RISK_PORTS)
                total = len(hist_ports) if len(hist_ports) > 0 else 1
                self._ports_by_device[device_id].append(
                    (hr_count / total, total)
                )

                hist_ips = dest_ips[:i][mask]
                unique_count = len(set(hist_ips)) if len(hist_ips) > 0 else 0
                self._conn_counts[device_id].append(
                    (unique_count, len(hist_ips) if len(hist_ips) > 0 else 1)
                )

        self._device_indices: dict[str, int] = defaultdict(int)

    def get_bytes_baseline(self, device_id: str) -> tuple[float, float]:
        idx = self._device_indices.get(device_id, 0)
        data = self._bytes_by_device.get(device_id, [])
        if idx < len(data):
            self._device_indices[device_id] = idx + 1
            return data[idx]
        global_mean = float(self.df["bytes_sent"].mean()) if not self.df.empty else 0.0
        global_std  = float(self.df["bytes_sent"].std())  if not self.df.empty else 1.0
        return (global_mean, max(global_std, 1.0))

    def get_port_baseline(self, device_id: str) -> tuple[float, int]:
        idx = self._device_indices.get(device_id, 0) - 1
        data = self._ports_by_device.get(device_id, [])
        if 0 <= idx < len(data):
            return data[idx]
        return (0.0, 1)

    def get_conn_baseline(self, device_id: str) -> tuple[int, int]:
        idx = self._device_indices.get(device_id, 0) - 1
        data = self._conn_counts.get(device_id, [])
        if 0 <= idx < len(data):
            return data[idx]
        return (0, 1)

class BeaconingDetector:
    """Detect periodic callback patterns via inter-arrival time variance."""

    def __init__(self, df: pd.DataFrame):
        self.scores: dict[tuple[str, str], float] = {}
        self._compute(df)

    def _compute(self, df: pd.DataFrame):
        if df.empty:
            return

        groups: dict[tuple[str, str], list[float]] = defaultdict(list)
        for _, row in df.iterrows():
            src = row.get("source_ip", "")
            dst = row.get("destination_ip", "")
            if src and dst:
                ts = row["timestamp"].timestamp() if hasattr(row["timestamp"], "timestamp") else 0
                groups[(src, dst)].append(ts)

        for key, timestamps in groups.items():
            if len(timestamps) < 3:
                self.scores[key] = 0.0
                continue

            timestamps.sort()
            deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            deltas = [d for d in deltas if d > 0]

            if len(deltas) < 2:
                self.scores[key] = 0.0
                continue

            mean_delta = np.mean(deltas)
            std_delta  = np.std(deltas)

            if mean_delta == 0:
                self.scores[key] = 0.0
                continue

            cv = std_delta / mean_delta

            if cv < 0.1:
                self.scores[key] = 1.0
            elif cv < 0.3:
                self.scores[key] = 0.85
            elif cv < 0.5:
                self.scores[key] = 0.6
            elif cv < 0.8:
                self.scores[key] = 0.3
            else:
                self.scores[key] = 0.0

    def get_score(self, source_ip: str, destination_ip: str) -> float:
        return self.scores.get((source_ip, destination_ip), 0.0)

def rule_m01_excessive_outbound(row: pd.Series, baseline: RollingBaseline) -> int:
    """M01: Excessive Outbound Traffic -- 14-day rolling baseline deviation."""
    bytes_sent = float(row.get("bytes_sent", 0))
    device_id  = row.get("device_id", "unknown")
    mean, std  = baseline.get_bytes_baseline(device_id)
    std = max(std, 1.0)

    if bytes_sent > 5_000_000:
        return 40
    if bytes_sent > 1_000_000:
        return 25

    if mean > 0:
        z_score = (bytes_sent - mean) / std
        if z_score > 3.0:
            return 40
        if z_score > 2.0:
            return 25
        if z_score > 1.5:
            return 15
    return 0

def rule_m02_vpn_proxy(row: pd.Series) -> int:
    """M02: VPN / Proxy Destination Detection."""
    score = 0
    dst_ip   = row.get("destination_ip", "")
    dst_port = int(row.get("destination_port", 0))

    if dst_ip in SUSPICIOUS_DEST:
        score += 15

    if dst_port in VPN_PROXY_PORTS:
        score += 15

    event_type = str(row.get("event_type", "")).lower()
    if event_type == "vpn_connection":
        score += 10

    return min(score, 25)

def rule_m03_abnormal_connections(row: pd.Series, baseline: RollingBaseline,
                                  dest_counts: dict) -> int:
    """M03: Abnormal Connection Burst -- unique destinations per source in window."""
    source_ip = row.get("source_ip", "")
    count = dest_counts.get(source_ip, 0)

    if count > 100:
        return 35
    if count > 50:
        return 25
    if count > 20:
        return 15

    device_id = row.get("device_id", "unknown")
    hist_unique, hist_total = baseline.get_conn_baseline(device_id)
    if hist_total > 5 and count > hist_unique * 3:
        return 20

    return 0

def rule_m04_high_risk_port(row: pd.Series, baseline: RollingBaseline) -> int:
    """M04: High-Risk Port Access -- with baseline frequency check."""
    port = int(row.get("destination_port", 0))
    if port not in HIGH_RISK_PORTS:
        return 0

    device_id = row.get("device_id", "unknown")
    hist_rate, hist_total = baseline.get_port_baseline(device_id)

    if port in {4444, 1337, 6667}:
        return 30
    if port in {22, 23, 3389, 5900}:
        if hist_rate > 0.3 and hist_total > 10:
            return 10
        return 25
    return 20

def rule_m05_suspicious_protocol(row: pd.Series) -> int:
    """M05: Suspicious Protocol Usage."""
    protocol = str(row.get("protocol", "")).upper()
    if protocol == "RAW":
        return 20
    if protocol == "ICMP":
        return 10
    return 0

def rule_m06_unknown_device(row: pd.Series) -> int:
    """M06: Unknown Device Connection."""
    known = row.get("user_known_devices")
    dev   = row.get("device_id")

    if not known or not dev:
        return 0

    if isinstance(known, str):
        try:
            known = json.loads(known)
        except (json.JSONDecodeError, TypeError):
            return 0

    if isinstance(known, list) and dev not in known:
        return 15
    return 0

def rule_m07_beaconing(row: pd.Series, detector: BeaconingDetector) -> int:
    """M07: C2 Beaconing Detection -- inter-arrival time variance analysis."""
    src = row.get("source_ip", "")
    dst = row.get("destination_ip", "")
    beacon_score = detector.get_score(src, dst)

    if beacon_score <= 0:
        return 0

    raw = int(beacon_score * 40)

    if dst in SUSPICIOUS_DEST:
        raw = min(40, raw + 10)

    event_type = str(row.get("event_type", "")).lower()
    if event_type == "c2_beacon":
        raw = min(40, raw + 10)

    return raw

def rule_m08_threat_classification(row: pd.Series) -> int:
    """M08: Threat Event Classification -- direct type-based scoring."""
    event_type = str(row.get("event_type", "")).lower()

    if event_type in {"c2_beacon", "malware"}:
        return 40
    if event_type in {"data_exfil", "brute_force", "lateral_movement"}:
        return 35
    if event_type == "port_scan":
        return 20
    if event_type in MEDIUM_RISK_TYPES:
        return 15
    return 0

def compute_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Apply all M01-M08 rules and compute composite risk scores."""
    if df.empty:
        return df

    baseline = RollingBaseline(df)
    detector = BeaconingDetector(df)

    dest_counts: dict[str, int] = {}
    for src, group in df.groupby("source_ip"):
        dest_counts[src] = group["destination_ip"].nunique()

    m01_scores = []
    m02_scores = []
    m03_scores = []
    m04_scores = []
    m05_scores = []
    m06_scores = []
    m07_scores = []
    m08_scores = []
    composites = []
    labels     = []
    actions    = []

    for _, row in df.iterrows():
        m01 = rule_m01_excessive_outbound(row, baseline)
        m02 = rule_m02_vpn_proxy(row)
        m03 = rule_m03_abnormal_connections(row, baseline, dest_counts)
        m04 = rule_m04_high_risk_port(row, baseline)
        m05 = rule_m05_suspicious_protocol(row)
        m06 = rule_m06_unknown_device(row)
        m07 = rule_m07_beaconing(row, detector)
        m08 = rule_m08_threat_classification(row)

        composite = min(100, m01 + m02 + m03 + m04 + m05 + m06 + m07 + m08)

        sev = severity_label(composite)
        if composite >= 85:
            action = "Immediate security alert"
        elif composite >= 60:
            action = "Log anomaly alert"
        elif composite >= 35:
            action = "Monitor traffic"
        elif composite >= 15:
            action = "Low-priority review"
        else:
            action = "No action"

        m01_scores.append(m01)
        m02_scores.append(m02)
        m03_scores.append(m03)
        m04_scores.append(m04)
        m05_scores.append(m05)
        m06_scores.append(m06)
        m07_scores.append(m07)
        m08_scores.append(m08)
        composites.append(composite)
        labels.append(sev)
        actions.append(action)

    df = df.copy()
    df["m01_score"]    = m01_scores
    df["m02_score"]    = m02_scores
    df["m03_score"]    = m03_scores
    df["m04_score"]    = m04_scores
    df["m05_score"]    = m05_scores
    df["m06_score"]    = m06_scores
    df["m07_score"]    = m07_scores
    df["m08_score"]    = m08_scores
    df["risk_score"]   = composites
    df["risk_label"]   = labels
    df["risk_action"]  = actions

    return df

def should_alert(row: pd.Series) -> bool:
    """Alert if composite >= 60 OR any single rule raw >= 80% of its max."""
    if row["risk_score"] >= 60:
        return True
    for rule, maximum in RULE_MAX.items():
        col = f"{rule.lower()}_score"
        if col in row and row[col] >= maximum * 0.8:
            return True
    return False

def classify_risk(score: float) -> tuple[str, str]:
    """Map a 0-100 score to (label, action)."""
    if score >= 85:
        return "CRITICAL", "Immediate security alert"
    if score >= 60:
        return "HIGH", "Log anomaly alert"
    if score >= 35:
        return "MEDIUM", "Monitor traffic"
    if score >= 15:
        return "LOW", "Low-priority review"
    return "NONE", "No action"

def generate_alert(row: pd.Series) -> str:
    rules_fired = []
    rule_names = {
        "m01": "M01 Excessive Outbound Traffic",
        "m02": "M02 VPN/Proxy Destination",
        "m03": "M03 Abnormal Connection Burst",
        "m04": "M04 High-Risk Port Access",
        "m05": "M05 Suspicious Protocol",
        "m06": "M06 Unknown Device",
        "m07": "M07 C2 Beaconing",
        "m08": "M08 Threat Classification",
    }
    for key, name in rule_names.items():
        col = f"{key}_score"
        if col in row and row[col] > 0:
            rules_fired.append(f"{name}: +{row[col]}")

    alert = (
        f"PirateShield Network Security Alert\n"
        f"{'=' * 50}\n"
        f"Event ID:     {row['event_id']}\n"
        f"Timestamp:    {row['timestamp']}\n"
        f"Source IP:    {row.get('source_ip', 'N/A')}\n"
        f"Dest IP:      {row.get('destination_ip', 'N/A')}\n"
        f"Dest Port:    {row.get('destination_port', 'N/A')}\n"
        f"Protocol:     {row.get('protocol', 'N/A')}\n"
        f"Event Type:   {row.get('event_type', 'N/A')}\n"
        f"\n"
        f"Rule Breakdown:\n"
    )
    for r in rules_fired:
        alert += f"  {r}\n"
    if not rules_fired:
        alert += "  All rules within normal range\n"

    alert += (
        f"\n"
        f"Composite Risk Score: {row['risk_score']}\n"
        f"Severity:             {row['risk_label']}\n"
        f"Action:               {row['risk_action']}\n"
    )
    return alert

def build_output_records(df: pd.DataFrame) -> list[dict]:
    records = []
    for _, row in df.iterrows():
        records.append({
            "event_id":         row["event_id"],
            "user_id":          row.get("user_id"),
            "device_id":        row.get("device_id"),
            "timestamp":        str(row["timestamp"]),
            "source_ip":        row.get("source_ip"),
            "destination_ip":   row.get("destination_ip"),
            "destination_port": int(row.get("destination_port", 0)),
            "protocol":         row.get("protocol"),
            "event_type":       row.get("event_type"),
            "bytes_sent":       int(row.get("bytes_sent", 0)),
            "bytes_received":   int(row.get("bytes_received", 0)),
            "m01_score":        int(row["m01_score"]),
            "m02_score":        int(row["m02_score"]),
            "m03_score":        int(row["m03_score"]),
            "m04_score":        int(row["m04_score"]),
            "m05_score":        int(row["m05_score"]),
            "m06_score":        int(row["m06_score"]),
            "m07_score":        int(row["m07_score"]),
            "m08_score":        int(row["m08_score"]),
            "risk_score":       int(row["risk_score"]),
            "risk_label":       row["risk_label"],
            "risk_action":      row["risk_action"],
            "alert":            bool(should_alert(row)),
        })
    return records

def write_alerts_to_db(df: pd.DataFrame, db_path: Path):
    """Write alerts to the pirateshield.db alerts table."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT,
            user_id TEXT,
            device_id TEXT,
            severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
            reason TEXT NOT NULL,
            risk_score REAL NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    existing = set()
    for r in cursor.execute("SELECT event_id FROM alerts WHERE event_id IS NOT NULL").fetchall():
        existing.add(r[0])

    alert_count = 0
    for _, row in df.iterrows():
        if not should_alert(row):
            continue

        if row.get("event_id") in existing:
            continue

        sev = get_severity(int(row["risk_score"]))
        if not sev:
            continue

        rules_fired = []
        rule_names = {
            "m01": "M01-ExcessiveOutbound",
            "m02": "M02-VPN/Proxy",
            "m03": "M03-AbnormalConnections",
            "m04": "M04-HighRiskPort",
            "m05": "M05-SuspiciousProtocol",
            "m06": "M06-UnknownDevice",
            "m07": "M07-Beaconing",
            "m08": "M08-ThreatType",
        }
        for key, name in rule_names.items():
            col = f"{key}_score"
            if col in row and row[col] > 0:
                rules_fired.append(f"{name}(+{row[col]})")

        reason = "; ".join(rules_fired) if rules_fired else "Risk threshold exceeded"

        cursor.execute("""
            INSERT INTO alerts (event_id, user_id, device_id, severity, reason, risk_score)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            row.get("event_id"),
            row.get("user_id"),
            row.get("device_id"),
            sev,
            reason,
            int(row["risk_score"]),
        ))
        alert_count += 1

    conn.commit()
    conn.close()
    return alert_count

def write_network_scores_to_db(df: pd.DataFrame, db_path: Path):
    """Write scored network events to the network_events table."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute("""
            INSERT OR REPLACE INTO network_events
                (event_id, user_id, timestamp, source_ip, destination_ip,
                 destination_port, protocol, bytes_sent, bytes_received,
                 device_id, event_type, payload, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row.get("event_id"),
            row.get("user_id"),
            str(row.get("timestamp")),
            row.get("source_ip"),
            row.get("destination_ip"),
            int(row.get("destination_port", 0)),
            row.get("protocol"),
            int(row.get("bytes_sent", 0)),
            int(row.get("bytes_received", 0)),
            row.get("device_id"),
            row.get("event_type"),
            json.dumps({
                "m01": int(row["m01_score"]), "m02": int(row["m02_score"]),
                "m03": int(row["m03_score"]), "m04": int(row["m04_score"]),
                "m05": int(row["m05_score"]), "m06": int(row["m06_score"]),
                "m07": int(row["m07_score"]), "m08": int(row["m08_score"]),
            }),
            int(row["risk_score"]),
        ))

    conn.commit()
    conn.close()

def print_results(df: pd.DataFrame):
    header = (
        f"{'Event Type':<20} {'Src IP':<14} {'Dst IP':<16} "
        f"{'M01':>4} {'M02':>4} {'M03':>4} {'M04':>4} "
        f"{'M05':>4} {'M06':>4} {'M07':>4} {'M08':>4} "
        f"{'Score':>6}  {'Severity'}"
    )
    print(header)
    print("-" * len(header))

    for _, row in df.iterrows():
        print(
            f"{str(row.get('event_type','')):<20} "
            f"{str(row.get('source_ip','')):<14} "
            f"{str(row.get('destination_ip','')):<16} "
            f"{int(row['m01_score']):>4} {int(row['m02_score']):>4} "
            f"{int(row['m03_score']):>4} {int(row['m04_score']):>4} "
            f"{int(row['m05_score']):>4} {int(row['m06_score']):>4} "
            f"{int(row['m07_score']):>4} {int(row['m08_score']):>4} "
            f"{int(row['risk_score']):>6}  {row['risk_label']}"
        )

    flagged = df[df.apply(should_alert, axis=1)]
    if len(flagged) > 0:
        print(f"\n{'=' * 60}")
        print(f"  ALERTS GENERATED: {len(flagged)} / {len(df)}")
        print(f"{'=' * 60}\n")
        for _, row in flagged.iterrows():
            print(generate_alert(row))
            print()
    else:
        print("\nNo events exceeded alert thresholds.")

    print("-" * 50)
    print("Risk Distribution:")
    for label in ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        count = len(df[df["risk_label"] == label])
        pct = count / len(df) * 100 if len(df) > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"  {label:<10} {count:>3} ({pct:5.1f}%) {bar}")

def main():
    parser = argparse.ArgumentParser(description="PirateShield Network Anomaly Detection Model")
    parser.add_argument("--input", type=str, default=None,
                        help="Path to network events JSON file")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON to stdout")
    parser.add_argument("--db", action="store_true",
                        help="Write results and alerts to pirateshield.db")
    parser.add_argument("--output", type=str, default=None,
                        help="Path to write scored results JSON")
    args = parser.parse_args()

    input_path = Path(args.input) if args.input else DATA_FILE
    output_path = Path(args.output) if args.output else MODEL_OUTPUT

    if not input_path.exists():
        print(f"Error: data file not found at {input_path}", file=sys.stderr)
        sys.exit(1)

    events = load_events(input_path)
    if not args.json:
        print(f"PirateShield Network Anomaly Detection Model")
        print(f"{'=' * 50}")
        print(f"Rules: M01-M08 | Scale: 0-100 | Alert: >= 60 or raw >= 80%")
        print(f"Loaded {len(events)} network events from {input_path.name}\n")

    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    output = build_output_records(df)

    if args.json:
        print(json.dumps(output))
        if args.db and DB_PATH.exists():
            write_alerts_to_db(df, DB_PATH)
        sys.exit(0)

    print_results(df)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nRisk scores written to {output_path}")

    if args.db:
        if DB_PATH.exists():
            alert_count = write_alerts_to_db(df, DB_PATH)
            print(f"Database updated: {alert_count} alerts written to {DB_PATH.name}")
        else:
            print(f"Warning: database not found at {DB_PATH}")

    total_alerts = len(df[df.apply(should_alert, axis=1)])
    critical = len(df[df["risk_label"] == "CRITICAL"])
    print(f"\nSummary: {len(events)} events scored, {total_alerts} alerts, {critical} critical")

if __name__ == "__main__":
    main()