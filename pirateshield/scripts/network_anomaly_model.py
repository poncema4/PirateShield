"""
PirateShield – Network Anomaly Detection Model
================================================
Hybrid anomaly detection combining:
  Layer 1: SARIMA traffic forecasting   (weight 0.40)
  Layer 2: DBSCAN behavioral clustering (weight 0.35)
  Layer 3: PCA reconstruction detection (weight 0.25)

Composite risk score: 0.00–1.00
  Normal     0.00–0.30
  Suspicious 0.30–0.55
  High Risk  0.55–0.75
  Critical   0.75–1.00

Based on docs/network/in/network_model.md
"""

import json
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from statsmodels.tsa.statespace.sarimax import SARIMAX

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parents[1]
DATA_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_network_events.json"
MODEL_OUTPUT = BASE_DIR / "data" / "risk_scores" / "network_risk_scores.json"

# ---------------------------------------------------------------------------
# Risk thresholds (from network_model.md)
# ---------------------------------------------------------------------------
THRESHOLDS = [
    (0.30, "Normal",     "No action"),
    (0.55, "Suspicious", "Monitor traffic"),
    (0.75, "High Risk",  "Log anomaly alert"),
    (1.00, "Critical",   "Immediate security alert"),
]

# Composite weights (from network_model.md)
W_TRAFFIC = 0.40
W_BEHAVIOR = 0.35
W_RECONSTRUCTION = 0.25

# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------
# Protocol one-hot mapping
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "RAW": 3}

# High-risk ports (from network_rules_v1.md and risk_scoring.ts)
HIGH_RISK_PORTS = {22, 23, 3389, 4444, 5900, 6667, 1337}

# High-risk event types
HIGH_RISK_TYPES = {"port_scan", "brute_force", "data_exfil", "malware",
                   "lateral_movement", "c2_beacon"}
MEDIUM_RISK_TYPES = {"unusual_login", "vpn_connection"}

# Known suspicious destination IPs
SUSPICIOUS_DEST_IPS = {"185.220.101.1", "198.51.100.77", "203.0.113.45"}


def load_events(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def events_to_dataframe(events: list[dict]) -> pd.DataFrame:
    """Convert raw JSON events into a feature DataFrame."""
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # ---- Numeric features ----
    df["bytes_sent"] = df["bytes_sent"].fillna(0).astype(float)
    df["bytes_received"] = df["bytes_received"].fillna(0).astype(float)
    df["byte_volume"] = df["bytes_sent"] + df["bytes_received"]
    df["destination_port"] = df["destination_port"].fillna(0).astype(int)

    # Protocol encoding
    df["protocol_code"] = df["protocol"].map(PROTOCOL_MAP).fillna(0).astype(int)

    # Port risk flag
    df["port_risk"] = df["destination_port"].apply(
        lambda p: 1.0 if p in HIGH_RISK_PORTS else 0.0
    )

    # Event type risk encoding
    def event_risk(et):
        if et in HIGH_RISK_TYPES:
            return 1.0
        if et in MEDIUM_RISK_TYPES:
            return 0.5
        return 0.0

    df["event_type_risk"] = df["event_type"].apply(event_risk)

    # Suspicious destination IP
    df["dest_ip_risk"] = df["destination_ip"].apply(
        lambda ip: 1.0 if ip in SUSPICIOUS_DEST_IPS else 0.0
    )

    # Unknown device flag
    def unknown_device(row):
        known = row.get("user_known_devices")
        dev = row.get("device_id")
        if not known or not dev:
            return 0.5  # missing info → slight risk
        return 0.0 if dev in known else 1.0

    df["unknown_device"] = df.apply(unknown_device, axis=1)

    # Hour of day (network activity at odd hours is riskier)
    df["hour"] = df["timestamp"].dt.hour

    return df


# ---------------------------------------------------------------------------
# Feature columns used by DBSCAN and reconstruction
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "bytes_sent", "bytes_received", "byte_volume",
    "protocol_code", "port_risk", "event_type_risk",
    "dest_ip_risk", "unknown_device", "hour",
]


# ===========================================================================
# Layer 1 – SARIMA Traffic Forecasting  →  TrafficScore
# ===========================================================================
def compute_traffic_scores(df: pd.DataFrame) -> np.ndarray:
    """
    SARIMA predicts expected byte_volume per time step.
    TrafficScore = |actual − predicted| / σ(residuals), clamped to [0, 1].
    """
    series = df["byte_volume"].values.astype(float)
    n = len(series)

    if n < 6:
        # Too few observations for SARIMA → fall back to z-score of volume
        mean_vol = series.mean()
        std_vol = series.std() if series.std() > 0 else 1.0
        raw = np.abs(series - mean_vol) / std_vol
        return np.clip(raw / raw.max() if raw.max() > 0 else raw, 0, 1)

    # Fit SARIMA(1,1,1) – simple order suitable for small samples
    try:
        model = SARIMAX(series, order=(1, 1, 1), enforce_stationarity=False,
                        enforce_invertibility=False)
        result = model.fit(disp=False, maxiter=200)
        predicted = result.fittedvalues
    except Exception:
        # Fallback: rolling mean as "forecast"
        predicted = pd.Series(series).rolling(window=3, min_periods=1).mean().values

    residuals = np.abs(series - predicted)
    sigma = residuals.std()
    if sigma == 0:
        return np.zeros(n)

    # Normalize: TrafficScore = residual / σ, clamped 0–1
    traffic_scores = residuals / sigma
    # Use a sigmoid-style soft clamp so extreme values map close to 1
    traffic_scores = 1 - np.exp(-traffic_scores)
    return np.clip(traffic_scores, 0, 1)


# ===========================================================================
# Layer 2 – DBSCAN Behavioral Clustering  →  BehaviorScore
# ===========================================================================
def compute_behavior_scores(df: pd.DataFrame) -> np.ndarray:
    """
    DBSCAN clusters normal behaviours.
    Noise points → BehaviorScore = 1.
    Cluster-edge points → distance_to_center / max_cluster_distance.
    Core points → ≈ 0.
    """
    features = df[FEATURE_COLS].values
    scaler = StandardScaler()
    X = scaler.fit_transform(features)
    n = len(X)

    # eps/min_samples tuned for small K-12 school datasets
    db = DBSCAN(eps=1.5, min_samples=2)
    labels = db.fit_predict(X)

    scores = np.zeros(n)
    for i in range(n):
        if labels[i] == -1:
            # Noise → anomaly
            scores[i] = 1.0
        else:
            # Distance to cluster center
            cluster_mask = labels == labels[i]
            center = X[cluster_mask].mean(axis=0)
            dists = np.linalg.norm(X[cluster_mask] - center, axis=1)
            max_dist = dists.max() if dists.max() > 0 else 1.0
            scores[i] = np.linalg.norm(X[i] - center) / max_dist

    return np.clip(scores, 0, 1)


# ===========================================================================
# Layer 3 – Reconstruction Anomaly (PCA-based autoencoder)  →  ReconstructionScore
# ===========================================================================
def compute_reconstruction_scores(df: pd.DataFrame) -> np.ndarray:
    """
    PCA learns a low-dimensional representation of normal traffic.
    ReconstructionError = ‖input − reconstructed‖.
    ReconstructionScore = error / max_expected_error, clamped 0–1.
    """
    features = df[FEATURE_COLS].values
    scaler = StandardScaler()
    X = scaler.fit_transform(features)

    # Keep fewer components to force lossy reconstruction
    n_components = max(1, min(3, X.shape[1] - 1, X.shape[0] - 1))
    pca = PCA(n_components=n_components)
    compressed = pca.fit_transform(X)
    reconstructed = pca.inverse_transform(compressed)

    errors = np.linalg.norm(X - reconstructed, axis=1)
    max_err = errors.max() if errors.max() > 0 else 1.0

    return np.clip(errors / max_err, 0, 1)


# ===========================================================================
# Composite Risk Score
# ===========================================================================
def classify_risk(score: float) -> tuple[str, str]:
    for threshold, label, action in THRESHOLDS:
        if score <= threshold:
            return label, action
    return "Critical", "Immediate security alert"


def compute_risk_scores(df: pd.DataFrame) -> pd.DataFrame:
    """Run all 3 layers and compute the composite risk score."""
    traffic_scores = compute_traffic_scores(df)
    behavior_scores = compute_behavior_scores(df)
    reconstruction_scores = compute_reconstruction_scores(df)

    composite = (
        W_TRAFFIC * traffic_scores
        + W_BEHAVIOR * behavior_scores
        + W_RECONSTRUCTION * reconstruction_scores
    )
    composite = np.clip(composite, 0, 1)

    df = df.copy()
    df["traffic_score"] = np.round(traffic_scores, 4)
    df["behavior_score"] = np.round(behavior_scores, 4)
    df["reconstruction_score"] = np.round(reconstruction_scores, 4)
    df["risk_score"] = np.round(composite, 4)
    df["risk_label"], df["risk_action"] = zip(
        *[classify_risk(s) for s in composite]
    )

    return df


# ===========================================================================
# Alert generation (mirrors network_model.md example)
# ===========================================================================
def generate_alert(row: pd.Series) -> str:
    details = []
    if row["traffic_score"] > 0.3:
        details.append("Traffic volume exceeded predicted baseline")
    if row["behavior_score"] > 0.3:
        details.append("Connection pattern does not match known behavior clusters")
    if row["reconstruction_score"] > 0.3:
        details.append("Reconstruction anomaly detected")

    if not details:
        details.append("All detection layers within normal range")

    alert = (
        f"PirateShield Security Alert\n"
        f"{'─' * 40}\n"
        f"Event ID:   {row['event_id']}\n"
        f"Timestamp:  {row['timestamp']}\n"
        f"Source IP:  {row.get('source_ip', 'N/A')}\n"
        f"Dest IP:    {row.get('destination_ip', 'N/A')}\n"
        f"Event Type: {row.get('event_type', 'N/A')}\n"
        f"\n"
        f"Layer Scores:\n"
        f"  Traffic (SARIMA):        {row['traffic_score']:.4f}\n"
        f"  Behavior (DBSCAN):       {row['behavior_score']:.4f}\n"
        f"  Reconstruction (PCA):    {row['reconstruction_score']:.4f}\n"
        f"\n"
        f"Details:\n"
    )
    for d in details:
        alert += f"  • {d}\n"

    alert += (
        f"\n"
        f"Risk Score: {row['risk_score']:.4f}\n"
        f"Severity:   {row['risk_label']}\n"
        f"Action:     {row['risk_action']}\n"
    )
    return alert


# ===========================================================================
# JSON output for integration with the TypeScript backend
# ===========================================================================
def build_output_records(df: pd.DataFrame) -> list[dict]:
    records = []
    for _, row in df.iterrows():
        records.append({
            "event_id":             row["event_id"],
            "user_id":              row.get("user_id"),
            "device_id":            row.get("device_id"),
            "timestamp":            str(row["timestamp"]),
            "source_ip":            row.get("source_ip"),
            "destination_ip":       row.get("destination_ip"),
            "destination_port":     int(row.get("destination_port", 0)),
            "protocol":             row.get("protocol"),
            "event_type":           row.get("event_type"),
            "bytes_sent":           int(row.get("bytes_sent", 0)),
            "bytes_received":       int(row.get("bytes_received", 0)),
            "traffic_score":        float(row["traffic_score"]),
            "behavior_score":       float(row["behavior_score"]),
            "reconstruction_score": float(row["reconstruction_score"]),
            "risk_score":           float(row["risk_score"]),
            "risk_label":           row["risk_label"],
            "risk_action":          row["risk_action"],
        })
    return records


# ===========================================================================
# Main
# ===========================================================================
def main():
    if not DATA_FILE.exists():
        print(f"Error: data file not found at {DATA_FILE}")
        print("Run  python scripts/generate_network_events.py  first.")
        sys.exit(1)

    events = load_events(DATA_FILE)
    print(f"Loaded {len(events)} network events from {DATA_FILE.name}\n")

    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    # ---- Print summary table ----
    print(f"{'Event Type':<22} {'Src IP':<14} {'Dest IP':<16} "
          f"{'Traffic':>8} {'Behavior':>9} {'Recon':>7} {'Risk':>7}  {'Label'}")
    print("─" * 110)
    for _, row in df.iterrows():
        print(
            f"{row['event_type']:<22} {str(row.get('source_ip','')):<14} "
            f"{str(row.get('destination_ip','')):<16} "
            f"{row['traffic_score']:>8.4f} {row['behavior_score']:>9.4f} "
            f"{row['reconstruction_score']:>7.4f} {row['risk_score']:>7.4f}  "
            f"{row['risk_label']}"
        )

    # ---- Print alerts for non-normal events ----
    flagged = df[df["risk_label"] != "Normal"]
    if len(flagged) > 0:
        print(f"\n{'═' * 60}")
        print(f"  FLAGGED EVENTS: {len(flagged)} / {len(df)}")
        print(f"{'═' * 60}\n")
        for _, row in flagged.iterrows():
            print(generate_alert(row))
            print()
    else:
        print("\nNo events exceeded the Normal threshold.")

    # ---- Score distribution summary ----
    print("─" * 60)
    print("Risk Distribution:")
    for label in ["Normal", "Suspicious", "High Risk", "Critical"]:
        count = len(df[df["risk_label"] == label])
        pct = count / len(df) * 100 if len(df) > 0 else 0
        bar = "█" * int(pct / 2)
        print(f"  {label:<12} {count:>3} ({pct:5.1f}%) {bar}")

    # ---- Save JSON output ----
    output = build_output_records(df)
    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_OUTPUT, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nRisk scores written to {MODEL_OUTPUT}")


if __name__ == "__main__":
    main()
