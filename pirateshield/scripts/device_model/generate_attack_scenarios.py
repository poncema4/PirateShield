# Attack Scenario Generator
# Generates deliberate multi-step attack chains to specifically test Layer 3 chain detection.
# Each scenario places high-signal events on the same device within the
# 10-minute window, which should produce visible chain score contributions.
# Output: data/synthetic_events/synthetic_deviceAttack_scenarios.json

"""
standalone test file for chain detection scenarios.
run this separately from generate_device_events.py.
pass the output to endpoint_model.py with --input to score it.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_deviceAttack_scenarios.json"

EST = timezone(timedelta(hours=-5))


# SCENARIOS --------------------------------------------

def scenario_suspicious_then_cpu_then_security(device_id, user, base_ts):
    """Suspicious process, then sustained CPU spike, then firewall disabled - all within 8 minutes."""
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=3)
    t2 = base_ts + timedelta(minutes=8)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "ngrok",
            "process_path": "/usr/bin/ngrok",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "chain_attack_A",
            "scenario_step": 1,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 94.0,
            "baseline_cpu": 8.0,
            "duration_seconds": 650,   # sustained - triggers +30 rule
            "risk_score": 30,
            "scenario": "chain_attack_A",
            "scenario_step": 2,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "firewall",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "chain_attack_A",
            "scenario_step": 3,
        },
    ]


def scenario_usb_then_suspicious_process(device_id, user, base_ts):
    """USB drops an executable, then a known-bad process launches 2 minutes later."""
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=2)


    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school chromebook",
            "user": user,
            "event_type": "usb_event",
            "usb_id": "USB-8821",
            "action": "connected",
            "new_executable_started": True,
            "exe_path": "E:/patcher.exe",
            "risk_score": 40,
            "scenario": "chain_attack_B",
            "scenario_step": 1,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school chromebook",
            "user": user,
            "event_type": "process_start",
            "process_name": "mimikatz",
            "process_path": "/tmp/mimikatz",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "chain_attack_B",
            "scenario_step": 2,
        },
    ]


def scenario_security_disabled_then_known_bad(device_id, user, base_ts):
    """Antivirus disabled, then a known-bad process appears 5 minutes later."""
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=5)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "security_change",
            "component": "antivirus",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "chain_attack_C",
            "scenario_step": 1,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "process_start",
            "process_name": "metasploit",
            "process_path": "/opt/metasploit/msfconsole",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "chain_attack_C",
            "scenario_step": 2,
        },
    ]


def scenario_rapid_multi_event(device_id, user, base_ts):
    """Four events in under 4 minutes - designed to max out chain intensity."""
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=1)
    t2 = base_ts + timedelta(minutes=2, seconds=30)
    t3 = base_ts + timedelta(minutes=3, seconds=45)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "tor",
            "process_path": "/usr/bin/tor",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "chain_attack_D",
            "scenario_step": 1,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "usb_event",
            "usb_id": "USB-3347",
            "action": "connected",
            "new_executable_started": True,
            "exe_path": "E:/setup.exe",
            "risk_score": 40,
            "scenario": "chain_attack_D",
            "scenario_step": 2,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 88.5,
            "baseline_cpu": 7.0,
            "duration_seconds": 700,
            "risk_score": 30,
            "scenario": "chain_attack_D",
            "scenario_step": 3,
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "EDR_agent",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "chain_attack_D",
            "scenario_step": 4,
        },
    ]


# MAIN -------------------------------------

SCENARIOS = [
    ("device-01", "student003", scenario_suspicious_then_cpu_then_security),
    ("device-02", "student007", scenario_usb_then_suspicious_process),
    ("device-03", "student011", scenario_security_disabled_then_known_bad),
    ("device-04", "student015", scenario_rapid_multi_event),
]


def main():
    """Build all attack scenarios and write them to a single JSON file."""
    base_ts = datetime.now(EST)
    all_events = []

    for i, (device_id, user, builder) in enumerate(SCENARIOS):
        # stagger scenario start times by 15 minutes so chains don't bleed into each other
        scenario_base = base_ts + timedelta(minutes=i * 15)
        events = builder(device_id, user, scenario_base)
        all_events.extend(events)
        print(f"Scenario {i + 1} ({builder.__name__}): {len(events)} events on {device_id}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2)

    print(f"\nWrote {len(all_events)} attack scenario events to:")
    print(OUTPUT_FILE)
    print("\nRun endpoint_model.py against this file to verify chain scores.")


if __name__ == "__main__":
    main()