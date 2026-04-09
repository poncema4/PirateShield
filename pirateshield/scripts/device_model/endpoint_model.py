# Scoring system for endpoints/devices
# Currently implements Layer 1 (rule-based) and Layer 3 (chain detection).
# Layer 2 (autoencoder anomaly scoring) is a placeholder until i do it 
# Defaults to running script using json file made with generate_device_events.py

# Composite score: DeviceRisk = min(S_rules + AnomalyPoints + ChainPoints, 100)
# Layer 3 math: C_chain(t, d) = SUM( s_i * e^(-decay * (t - t_i)) ) for events on
#   device d where (t - t_i) <= window  (Zheng, Eq. 6)
# Chain score is normalized and capped at 15 points max contribution.

# HOW TO run this script with the deliberate attacks:
# run 'generate_attack_scenarios.py'
# Then run from rpeo root using --input OR CD into the script directory and use path:
# cd pirateshield/scripts/device_model
# python endpoint_model.py --input ../../data/synthetic_events/synthetic_deviceAttack_scenarios.json

import json
import math
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_INPUT_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_device_events.json"
OUTPUT_FILE = BASE_DIR / "data" / "risk_scores" / "endpoint" / "endpoint_risk_scores.json"

DECAY_RATE = 0.005    # controls how fast old events fade (per second)
WINDOW_SECONDS = 600   # only look at events within this window (10 minutes)
C_MAX = 25.0        # normalization ceiling (calibrated from expected max)
CHAIN_CAP = 15      # max points Layer 3 can contribute

SUSPICIOUS_PROCESSES = [  # can probably add to this but maybe not needed for this testing version
    "wireguard", "openvpn", "tor", "proxychains", "nmap", "netcat",
    "nc", "mimikatz", "metasploit", "msfconsole", "ngrok", "sshuttle",
    "cracktool", "bypass_tool", "tun2socks"
]
CPU_SPIKE_RATIO = 2.5
CPU_LONG_DURATION = 600


# LAYER 1: RULE-BASED SCORING ----------------------------------

def score_rules(event):
    """
    Apply Layer 1 rules to a single device event. Returns (score, reasons)
    Same as 'risk_scoring.ts'
    """
    score = 0
    reasons = []

    suspicious = event.get("suspicious", False)
    proc = (event.get("process_name") or "").lower()
    event_type = event.get("event_type", "")

    # R1: suspicious flag set by endpoint agent
    if suspicious:
        score += 40
        reasons.append(f"Suspicious process flag: {proc or 'unknown'}")

    # R2: known-bad process name (only if R1 did not already fire to avoid double-counting)
    if proc in SUSPICIOUS_PROCESSES and not suspicious:
        score += 35
        reasons.append(f"Known-bad process: {proc}")

    # R3: USB-launched executable
    if event_type == "usb_event" and event.get("new_executable_started"):
        score += 45
        reasons.append(f"USB triggered executable: {event.get('exe_path', 'unknown')}")

    # R4 / R5: CPU spike (sustained vs brief)
    cpu = event.get("cpu_percent", 0)
    baseline = event.get("baseline_cpu", 1) or 1
    duration = event.get("duration_seconds", 0)
    ratio = cpu / baseline if baseline > 0 else 0

    if ratio >= CPU_SPIKE_RATIO and duration >= CPU_LONG_DURATION:
        score += 30
        reasons.append(f"Sustained CPU spike: {cpu:.1f}% ({ratio:.1f}x baseline) for {duration}s")
    elif ratio >= CPU_SPIKE_RATIO:
        score += 10
        reasons.append(f"Brief CPU spike: {cpu:.1f}% ({ratio:.1f}x baseline)")

    # R6: security component disabled
    if event_type == "security_change" and event.get("new_status") == "disabled":
        score += 50
        reasons.append(f"Security component disabled: {event.get('component', 'unknown')}")

    return score, reasons


# LAYER 2: AUTOENCODER ANOMALY SCORING (placeholder) ----------------

def score_anomaly(event):
    """Layer 2 placeholder. Returns anomaly points once autoencoder is trained."""
    # (load trained autoencoder)
    return 0


# LAYER 3: HAWKES-INSPIRED CHAIN DETECTION ------------------
def parse_timestamp(ts_str):
    """Convert timestamp string to seconds."""
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def compute_chain_scores(events):
    """Score every event with all three layers and return results list."""

    events_sorted = sorted(events, key=lambda e: parse_timestamp(e.get("timestamp", "")))

    # pre-compute Layer 1 and Layer 2 scores for every event
    for event in events_sorted:
        rule_score, rule_reasons = score_rules(event)
        event["_rule_score"] = rule_score
        event["_rule_reasons"] = rule_reasons
        event["_anomaly_score"] = score_anomaly(event)
        # suspicion signal used by chain intensity - take the higher of the two layers
        event["_suspicion"] = max(rule_score, event["_anomaly_score"])

    # group events by device for chain lookback
    by_device = {}
    for event in events_sorted:
        device = event.get("device_id", "unknown")
        by_device.setdefault(device, []).append(event)

    results = []

    for device_id, device_events in by_device.items():
        for i, current in enumerate(device_events):
            t_current = parse_timestamp(current.get("timestamp", ""))
            chain_intensity = 0.0
            contributing_events = 0

            # sum decayed suspicion scores from all prior events on this device within the window
            for j in range(i):
                prior = device_events[j]
                t_prior = parse_timestamp(prior.get("timestamp", ""))
                age = t_current - t_prior

                if age > WINDOW_SECONDS or age < 0:
                    continue

                s_i = prior["_suspicion"]
                if s_i <= 0:
                    continue

                decay_factor = math.exp(-DECAY_RATE * age)
                chain_intensity += s_i * decay_factor
                contributing_events += 1

            # include the current event's own suspicion in chain intensity (no decay)
            if current["_suspicion"] > 0:
                chain_intensity += current["_suspicion"] * 1.0
                contributing_events += 1

            chain_norm = min(chain_intensity / C_MAX, 1.0) if C_MAX > 0 else 0.0
            chain_points = min(chain_norm * CHAIN_CAP, CHAIN_CAP)

            rule_score = current["_rule_score"]
            anomaly_points = current["_anomaly_score"]
            composite = min(rule_score + anomaly_points + chain_points, 100)

            if composite >= 85:
                severity = "CRITICAL"
            elif composite >= 60:
                severity = "HIGH"
            elif composite >= 35:
                severity = "MEDIUM"
            elif composite >= 15:
                severity = "LOW"
            else:
                severity = "NONE"

            results.append({
                "event_id": current.get("event_id"),
                "device_id": device_id,
                "user_id": current.get("user") or current.get("user_id"),
                "event_type": current.get("event_type"),
                "timestamp": current.get("timestamp"),
                "process_name": current.get("process_name"),
                "scenario": current.get("scenario"),           # present in attack scenarios, None otherwise
                "scenario_step": current.get("scenario_step"),
                "layer1_rule_score": rule_score,
                "layer2_anomaly_score": anomaly_points,
                "layer3_chain_intensity": round(chain_intensity, 4),
                "layer3_chain_norm": round(chain_norm, 4),
                "layer3_chain_points": round(chain_points, 2),
                "chain_contributing_events": contributing_events,
                "composite_score": round(composite, 2),
                "severity": severity,
                "rule_reasons": current["_rule_reasons"],
            })

    return results


# MAIN ---

def main():
    parser = argparse.ArgumentParser(description="PirateShield endpoint risk model")
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_FILE,
        help="Path to device events JSON file (default: synthetic_device_events.json)"
    )
    args = parser.parse_args()

    input_file = args.input

    if not input_file.exists():
        print(f"No device events found at {input_file}")
        if input_file == DEFAULT_INPUT_FILE:
            print("Run generate_device_events.py first to create synthetic data.")
        sys.exit(1)

    with open(input_file, "r") as f:
        events = json.load(f)

    print(f"Loaded {len(events)} device events from {input_file}")

    results = compute_chain_scores(events)

    total = len(results)
    flagged = [r for r in results if r["composite_score"] >= 15]
    chains = [r for r in results if r["layer3_chain_points"] > 0]
    # Boosted means; event was originally below threshold, but this formula brought it into an alert range.
    boosted = [r for r in results if r["layer3_chain_points"] > 0 and r["layer1_rule_score"] < 35 and r["composite_score"] >= 35]

    print(f"\nResults: {total} events scored")
    print(f"  Flagged (score >= 15): {len(flagged)}")
    print(f"  Events with chain contribution: {len(chains)}")
    print(f"  Events boosted into alert range by chain: {len(boosted)}")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        count = len([r for r in results if r["severity"] == sev])
        if count > 0:
            print(f"  {sev}: {count}")

    top = sorted(results, key=lambda r: r["composite_score"], reverse=True)[:5]
    if top:
        print(f"\nTop 5 highest scoring events:")
        for r in top:
            label = f" [scenario={r['scenario']} step={r['scenario_step']}]" if r.get("scenario") else ""
            print(f"  Score: {r['composite_score']:6.2f} | "
                  f"L1: {r['layer1_rule_score']:3d} | "
                  f"L3: {r['layer3_chain_points']:5.2f} | "
                  f"{r['event_type']:18s} | "
                  f"{r['device_id']:20s} | "
                  f"{', '.join(r['rule_reasons']) if r['rule_reasons'] else 'no rules fired'}"
                  f"{label}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nScores written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()