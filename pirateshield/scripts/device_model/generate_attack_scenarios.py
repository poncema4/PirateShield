# Attack Scenario Generator
# Generates deliberate multi-step attack chains to test all three detection layers.
# Each event carries a real syscall trace sampled from ADFA-LD attack data so
# Layer 2 (autoencoder) produces genuine reconstruction errors on attack behavior.
# Output: data/synthetic_events/synthetic_deviceAttack_scenarios.json
#
# Usage:
#   python generate_attack_scenarios.py --adfa-dir /path/to/ADFA-LD

import json
import uuid
import random
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_deviceAttack_scenarios.json"

EST = timezone(timedelta(hours=-5))
RANDOM_SEED = 42


# DATA LOADING ----------------------------------------

def _load_traces(directory: Path, recurse: bool) -> list:
    """Load all trace files from directory into lists of integer syscall IDs."""
    traces = []
    pattern = "**/*" if recurse else "*"
    for filepath in sorted(directory.glob(pattern)):
        if not filepath.is_file():
            continue
        raw = filepath.read_text(errors="ignore").strip()
        if not raw:
            continue
        try:
            syscalls = list(map(int, raw.split()))
            if syscalls:
                traces.append(syscalls)
        except ValueError:
            continue
    return traces


def load_attack_traces(adfa_dir: Path) -> list:
    """Load all attack traces from ADFA-LD Attack_Data_Master."""
    attack_dir = adfa_dir / "Attack_Data_Master"
    if not attack_dir.exists():
        print(f"[WARNING] Attack_Data_Master not found at {attack_dir}")
        print("[WARNING] Events will be generated without syscall_trace - Layer 2 will score 0")
        return []
    traces = _load_traces(attack_dir, recurse=True)
    print(f"Loaded {len(traces)} attack traces from ADFA-LD")
    return traces


def sample_trace(traces: list) -> list:
    """Return a random trace from the pool, or empty list if pool is empty."""
    if not traces:
        return []
    return random.choice(traces)


# SCENARIOS ----------------------------------------
# Each scenario function returns a list of events representing one attack chain.
# Scenarios A-D test high-L1 chains (chain detection contribution).
# Scenario E tests L2-only detection (stealth events, no L1 triggers).
# Scenario F tests L1+L2 tipping point (low L1 that L2 pushes into alert range).

def scenario_suspicious_then_cpu_then_security(device_id, user, base_ts, attack_traces):
    """Suspicious process, sustained CPU spike, firewall disabled - all within 8 minutes."""
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
            "syscall_trace": sample_trace(attack_traces),
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
            "duration_seconds": 650,
            "risk_score": 30,
            "scenario": "chain_attack_A",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_usb_then_suspicious_process(device_id, user, base_ts, attack_traces):
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
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_security_disabled_then_known_bad(device_id, user, base_ts, attack_traces):
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
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_rapid_multi_event(device_id, user, base_ts, attack_traces):
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
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
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
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_stealth_process_injection(device_id, user, base_ts, attack_traces):
    """Three benign-looking processes with attack syscall traces.

    No L1 rules fire - process names are safe, no USB, no security change.
    Only Layer 2 (autoencoder) can detect the attack syscall patterns.
    Demonstrates L2 catching what L1 completely misses.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=2, seconds=30)
    t2 = base_ts + timedelta(minutes=5, seconds=15)
    t3 = base_ts + timedelta(minutes=7, seconds=45)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "chrome",
            "process_path": "/usr/bin/chrome",
            "suspicious": False,
            "risk_score": 0,
            "scenario": "stealth_injection",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "python",
            "process_path": "/usr/bin/python3",
            "suspicious": False,
            "risk_score": 0,
            "scenario": "stealth_injection",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "edge",
            "process_path": "/usr/bin/edge",
            "suspicious": False,
            "risk_score": 0,
            "scenario": "stealth_injection",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 28.0,
            "baseline_cpu": 15.0,
            "duration_seconds": 120,
            "risk_score": 0,
            "scenario": "stealth_injection",
            "scenario_step": 4,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_mixed_signals(device_id, user, base_ts, attack_traces):
    """Low L1 borderline events that only reach alert range with L2 and L3 combined.

    Each event scores 10 or less on L1 alone - below every meaningful threshold.
    Attack syscall traces push L2 scores to 15-20 per event.
    Chain detection compounds them. Demonstrates all three layers working together.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=3)
    t2 = base_ts + timedelta(minutes=5, seconds=30)
    t3 = base_ts + timedelta(minutes=8)

    return [
        {
            # Brief CPU spike - L1 = +10 (R5: ratio >= 2.5, not sustained)
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 42.0,
            "baseline_cpu": 14.0,
            "duration_seconds": 180,
            "risk_score": 10,
            "scenario": "mixed_signals",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            # Safe-looking process - L1 = 0
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "process_start",
            "process_name": "zoom",
            "process_path": "/usr/bin/zoom",
            "suspicious": False,
            "risk_score": 0,
            "scenario": "mixed_signals",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            # Another brief CPU spike - L1 = +10
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 38.0,
            "baseline_cpu": 12.0,
            "duration_seconds": 200,
            "risk_score": 10,
            "scenario": "mixed_signals",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            # Another safe process - L1 = 0
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "process_start",
            "process_name": "svchost",
            "process_path": "/usr/bin/svchost",
            "suspicious": False,
            "risk_score": 0,
            "scenario": "mixed_signals",
            "scenario_step": 4,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_ransomware_prep(device_id, user, base_ts, attack_traces):
    """Ransomware preparation - security disabled, suspicious process, rapid CPU spike.

    Models initial ransomware staging: attacker disables AV, runs encryption tool,
    CPU spikes as files are scanned. All within 6 minutes.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=2)
    t2 = base_ts + timedelta(minutes=4, seconds=30)
    t3 = base_ts + timedelta(minutes=6)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "antivirus",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "ransomware_prep",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "cracktool",
            "process_path": "/tmp/cracktool",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "ransomware_prep",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 97.0,
            "baseline_cpu": 9.0,
            "duration_seconds": 720,
            "risk_score": 30,
            "scenario": "ransomware_prep",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "firewall",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "ransomware_prep",
            "scenario_step": 4,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_data_exfiltration(device_id, user, base_ts, attack_traces):
    """Data exfiltration - VPN tool launched, sustained CPU for compression, USB removal.

    Models a student copying and compressing files then removing a USB drive.
    Sustained CPU spike suggests large file operation before exfiltration.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=1, seconds=30)
    t2 = base_ts + timedelta(minutes=4)
    t3 = base_ts + timedelta(minutes=7, seconds=15)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "process_start",
            "process_name": "openvpn",
            "process_path": "/usr/sbin/openvpn",
            "suspicious": False,
            "risk_score": 35,
            "scenario": "data_exfiltration",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 85.0,
            "baseline_cpu": 10.0,
            "duration_seconds": 680,
            "risk_score": 30,
            "scenario": "data_exfiltration",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "usb_event",
            "usb_id": "USB-7734",
            "action": "connected",
            "new_executable_started": True,
            "exe_path": "E:/sync.exe",
            "risk_score": 40,
            "scenario": "data_exfiltration",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "laptop",
            "user": user,
            "event_type": "usb_event",
            "usb_id": "USB-7734",
            "action": "removed",
            "new_executable_started": False,
            "exe_path": None,
            "risk_score": 0,
            "scenario": "data_exfiltration",
            "scenario_step": 4,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_lateral_movement(device_id, user, base_ts, attack_traces):
    """Lateral movement - network tunnel tool, then known-bad process on a second device.

    Models an attacker pivoting from one compromised device to another using a proxy.
    Two events on the same device within the chain window.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=3)
    t2 = base_ts + timedelta(minutes=5, seconds=45)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "proxychains",
            "process_path": "/usr/bin/proxychains",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "lateral_movement",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "nmap",
            "process_path": "/usr/bin/nmap",
            "suspicious": False,
            "risk_score": 35,
            "scenario": "lateral_movement",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "EDR_agent",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "lateral_movement",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


def scenario_credential_harvesting(device_id, user, base_ts, attack_traces):
    """Credential harvesting - mimikatz variant with USB drop and CPU spike.

    Models credential theft: USB delivers payload, known-bad process extracts hashes,
    sustained CPU indicates large-scale hash cracking attempt.
    """
    t0 = base_ts
    t1 = base_ts + timedelta(minutes=1)
    t2 = base_ts + timedelta(minutes=3, seconds=15)
    t3 = base_ts + timedelta(minutes=5, seconds=30)

    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t0.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "usb_event",
            "usb_id": "USB-9912",
            "action": "connected",
            "new_executable_started": True,
            "exe_path": "E:/update.exe",
            "risk_score": 40,
            "scenario": "credential_harvesting",
            "scenario_step": 1,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t1.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "process_start",
            "process_name": "msfconsole",
            "process_path": "/opt/metasploit/msfconsole",
            "suspicious": True,
            "risk_score": 50,
            "scenario": "credential_harvesting",
            "scenario_step": 2,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t2.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": 99.0,
            "baseline_cpu": 8.0,
            "duration_seconds": 650,
            "risk_score": 30,
            "scenario": "credential_harvesting",
            "scenario_step": 3,
            "syscall_trace": sample_trace(attack_traces),
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": t3.isoformat(),
            "device_id": device_id,
            "device_type": "school computer",
            "user": user,
            "event_type": "security_change",
            "component": "Windows_Defender",
            "new_status": "disabled",
            "risk_score": 25,
            "scenario": "credential_harvesting",
            "scenario_step": 4,
            "syscall_trace": sample_trace(attack_traces),
        },
    ]


# MAIN ----------------------------------------

SCENARIOS = [
    ("device-01", "student003", scenario_suspicious_then_cpu_then_security),
    ("device-02", "student007", scenario_usb_then_suspicious_process),
    ("device-03", "student011", scenario_security_disabled_then_known_bad),
    ("device-04", "student015", scenario_rapid_multi_event),
    ("device-05", "student019", scenario_stealth_process_injection),
    ("device-06", "student020", scenario_mixed_signals),
    ("device-07", "student008", scenario_ransomware_prep),
    ("device-08", "student012", scenario_data_exfiltration),
    ("device-09", "student016", scenario_lateral_movement),
    ("device-10", "student004", scenario_credential_harvesting),
]


def main():
    parser = argparse.ArgumentParser(description="Generate attack scenario events with ADFA-LD syscall traces")
    parser.add_argument(
        "--adfa-dir",
        type=Path,
        default=Path("C:/Users/alexg/datasets/ADFA-LD/ADFA-LD"),
        help="Path to ADFA-LD dataset root (default: C:/Users/alexg/datasets/ADFA-LD/ADFA-LD)",
    )
    args = parser.parse_args()

    random.seed(RANDOM_SEED)
    attack_traces = load_attack_traces(args.adfa_dir)

    base_ts = datetime.now(EST)
    all_events = []

    for i, (device_id, user, builder) in enumerate(SCENARIOS):
        scenario_base = base_ts + timedelta(minutes=i * 20)
        events = builder(device_id, user, scenario_base, attack_traces)
        all_events.extend(events)
        print(f"Scenario {i + 1} ({builder.__name__}): {len(events)} events on {device_id}")

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2)

    print(f"\nWrote {len(all_events)} attack scenario events to {OUTPUT_FILE}")
    print("Run evaluate_layers.py to score all layer combinations.")


if __name__ == "__main__":
    main()
