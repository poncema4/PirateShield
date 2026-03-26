"""

PirateShield - Network Model Test Suite
========================================
Validates the mathematical calculations and algorithms in the
network anomaly detection model against known expected outputs

"""

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from network_anomaly_model import (
    FEATURE_COLS,
    W_BEHAVIOR,
    W_RECONSTRUCTION,
    W_TRAFFIC,
    classify_risk,
    compute_behavior_scores,
    compute_reconstruction_scores,
    compute_risk_scores,
    compute_traffic_scores,
    events_to_dataframe,
    generate_alert,
    load_events,
)

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_FILE = BASE_DIR / "data" / "synthetic_events" /"synthetic_network_events.json"

PASSED = 0
FAILED = 0

def check(name: str, condition: bool, detail: str = ""):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED += 1
        print(f"  FAIL  {name}  {detail}")

# ===========================================================================
# Test 1: Composite weight formula
# ===========================================================================
def test_weights():
    print("\n[Test 1] Composite weights sum to 1.0")
    total = W_TRAFFIC + W_BEHAVIOR + W_RECONSTRUCTION
    check("weights sum", abs(total - 1.0) < 1e-9, f"got {total}")
    check("W_TRAFFIC = 0.40", W_TRAFFIC == 0.40)
    check("W_BEHAVIOR = 0.35", W_BEHAVIOR == 0.35)
    check("W_RECONSTRUCTION = 0.25", W_RECONSTRUCTION == 0.25)

# ===========================================================================
# Test 2: Risk classification thresholds
# ===========================================================================
def test_thresholds():
    print("\n[Test 2] Risk classification thresholds")
    check("0.00 → Normal",     classify_risk(0.00)[0] == "Normal")
    check("0.15 → Normal",     classify_risk(0.15)[0] == "Normal")
    check("0.30 → Normal",     classify_risk(0.30)[0] == "Normal")
    check("0.31 → Suspicious", classify_risk(0.31)[0] == "Suspicious")
    check("0.55 → Suspicious", classify_risk(0.55)[0] == "Suspicious")
    check("0.56 → High Risk",  classify_risk(0.56)[0] == "High Risk")
    check("0.75 → High Risk",  classify_risk(0.75)[0] == "High Risk")
    check("0.76 → Critical",   classify_risk(0.76)[0] == "Critical")
    check("1.00 → Critical",   classify_risk(1.00)[0] == "Critical")

# ===========================================================================
# Test 3: Manual composite calculation (from network_model.md example)
# ===========================================================================
def test_manual_composite():
    print("\n[Test 3] Manual composite calculation (network_model.md example)")
    traffic = 0.7
    behavior = 0.8
    recon = 0.5
    expected = (0.40 * traffic) + (0.35 * behavior) + (0.25 * recon)
    check(f"0.40*0.7 + 0.35*0.8 + 0.25*0.5 = {expected:.2f}",
          abs(expected - 0.69) < 0.01, f"got {expected}")
    label, _ = classify_risk(expected)
    check("0.69 → High Risk", label == "High Risk", f"got {label}")

# ===========================================================================
# Test 4: Score ranges [0, 1]
# ===========================================================================
def test_score_ranges():
    print("\n[Test 4] All scores in [0, 1] range")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    for col in ["traffic_score", "behavior_score", "reconstruction_score", "risk_score"]:
        vals = df[col].values
        check(f"{col} min >= 0", vals.min() >= 0, f"min={vals.min()}")
        check(f"{col} max <= 1", vals.max() <= 1, f"max={vals.max()}")

# ===========================================================================
# Test 5: High-risk events get higher scores
# ===========================================================================
def test_high_risk_detection():
    print("\n[Test 5] High-risk events score higher than normal")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    high_risk_types = {"data_exfil", "malware", "c2_beacon", "brute_force"}
    normal_types = {"network_connection", "dns_lookup"}

    hr_scores = df[df["event_type"].isin(high_risk_types)]["risk_score"]
    nm_scores = df[df["event_type"].isin(normal_types)]["risk_score"]

    if len(hr_scores) > 0 and len(nm_scores) > 0:
        check("high-risk mean > normal mean",
              hr_scores.mean() > nm_scores.mean(),
              f"HR={hr_scores.mean():.4f} vs NM={nm_scores.mean():.4f}")
    else:
        check("high-risk mean > normal mean", True, "skipped – not enough data")

# ===========================================================================
# Test 6: Layer independence (each score computed separately)
# ===========================================================================
def test_layer_independence():
    print("\n[Test 6] Layer scores are independently computed")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)

    t_scores = compute_traffic_scores(df)
    b_scores = compute_behavior_scores(df)
    r_scores = compute_reconstruction_scores(df)

    composite = W_TRAFFIC * t_scores + W_BEHAVIOR * b_scores + W_RECONSTRUCTION * r_scores
    composite = np.clip(composite, 0, 1)

    df2 = compute_risk_scores(df)
    diff = np.abs(composite - df2["risk_score"].values)
    check("composite matches formula", diff.max() < 1e-3,
          f"max diff={diff.max():.6f}")

# ===========================================================================
# Test 7: Data exfil events should be Critical or High Risk
# ===========================================================================
def test_data_exfil_severity():
    print("\n[Test 7] data_exfil events flagged as high severity")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    exfil = df[df["event_type"] == "data_exfil"]
    for _, row in exfil.iterrows():
        label = row["risk_label"]
        check(f"data_exfil {row['event_id'][:8]}… → {label}",
              label in ("High Risk", "Critical"),
              f"got {label} (score={row['risk_score']:.4f})")

# ===========================================================================
# Test 8: Alert generation
# ===========================================================================
def test_alert_generation():
    print("\n[Test 8] Alert generation")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    flagged = df[df["risk_label"] != "Normal"]
    if len(flagged) > 0:
        row = flagged.iloc[0]
        alert = generate_alert(row)
        check("alert contains Risk Score", "Risk Score:" in alert)
        check("alert contains Severity", "Severity:" in alert)
        check("alert contains Event ID", "Event ID:" in alert)
    else:
        check("alert generation", True, "skipped - no flagged events")

# ===========================================================================
# Test 9: Feature extraction completeness
# ===========================================================================
def test_feature_extraction():
    print("\n[Test 9] Feature extraction produces all required columns")
    events = load_events(DATA_FILE)
    df = events_to_dataframe(events)
    for col in FEATURE_COLS:
        check(f"column '{col}' exists", col in df.columns)
    check("no NaN in features", not df[FEATURE_COLS].isnull().any().any())

# ===========================================================================
# Test 10: Custom event scoring
# ===========================================================================
def test_custom_event():
    print("\n[Test 10] Score a single custom event")
    custom = [{
        "event_id": "test-001",
        "timestamp": "2026-03-26T12:00:00Z",
        "user_id": "student1",
        "device_id": "unknown-device-99",
        "source_ip": "10.0.0.5",
        "destination_ip": "185.220.101.1",
        "destination_port": 4444,
        "protocol": "RAW",
        "event_type": "c2_beacon",
        "bytes_sent": 50000000,
        "bytes_received": 500,
        "user_known_devices": ["host-A", "host-B"],
        "lat": 0.0,
        "long": 0.0,
    }]
    normal = [{
        "event_id": f"normal-{i}",
        "timestamp": f"2026-03-26T11:{i:02d}:00Z",
        "user_id": "student1",
        "device_id": "host-A",
        "source_ip": "10.0.0.5",
        "destination_ip": "8.8.8.8",
        "destination_port": 443,
        "protocol": "TCP",
        "event_type": "network_connection",
        "bytes_sent": 1000 + i * 100,
        "bytes_received": 2000,
        "user_known_devices": ["host-A", "host-B"],
        "lat": 0.0,
        "long": 0.0,
    } for i in range(10)]

    events = normal + custom
    df = events_to_dataframe(events)
    df = compute_risk_scores(df)

    c2_row = df[df["event_id"] == "test-001"].iloc[0]
    check(f"c2_beacon risk_score > 0.55 (got {c2_row['risk_score']:.4f})",
          c2_row["risk_score"] > 0.55)
    check(f"c2_beacon label = High Risk or Critical (got {c2_row['risk_label']})",
          c2_row["risk_label"] in ("High Risk", "Critical"))

    normal_scores = df[df["event_id"].str.startswith("normal")]["risk_score"]
    check(f"normal events avg < c2_beacon score",
          normal_scores.mean() < c2_row["risk_score"],
          f"normal avg={normal_scores.mean():.4f}")

# ===========================================================================
# Main
# ===========================================================================
def main():
    print("=" * 60)
    print("PirateShield Network Model – Test Suite")
    print("=" * 60)

    test_weights()
    test_thresholds()
    test_manual_composite()
    test_score_ranges()
    test_high_risk_detection()
    test_layer_independence()
    test_data_exfil_severity()
    test_alert_generation()
    test_feature_extraction()
    test_custom_event()

    print("\n" + "=" * 60)
    print(f"Results: {PASSED} passed, {FAILED} failed, {PASSED + FAILED} total")
    print("=" * 60)
    sys.exit(0 if FAILED == 0 else 1)

if __name__ == "__main__":
    main()