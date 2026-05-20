"""
program that pretends to be a computer or Chromebook
and reports fake device activity, so PirateShield can be tested
without installing anything on real student devices.
Each event carries a real syscall trace sampled from ADFA-LD so
Layer 2 (autoencoder) produces genuine scores on normal behavior.
output: data/synthetic_events/synthetic_device_events.json

Usage:
    python generate_device_events.py [count]
    python generate_device_events.py [count] --adfa-dir /path/to/ADFA-LD
"""
import sys
import json
import random
import uuid
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_device_events.json"

EST = timezone(timedelta(hours=-5))
RANDOM_SEED = 42

DEVICE_TYPE = ["school computer", "school chromebook", "laptop", "phone", "tablet"]
USERS = [f"student{n:03d}" for n in range(1, 21)]

SAFE_PROCESS = [
    "chrome", "explorer", "system", "svchost", "python", "zoom", "teams", "edge"
]

SUSPICIOUS_PROCESS = ["openvpn", "wireguard", "proxychains", "ngrok", "sshuttle",
    "cracktool", "bypass_tool", "tun2socks"]

FIREWALL_ODD = 0.9


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


def load_adfa_traces(adfa_dir: Path):
    """Load normal and attack traces from ADFA-LD. Returns (normal_traces, attack_traces)."""
    normal_dir = adfa_dir / "Training_Data_Master"
    val_dir = adfa_dir / "Validation_Data_Master"
    attack_dir = adfa_dir / "Attack_Data_Master"

    normal_traces = []
    attack_traces = []

    if normal_dir.exists():
        normal_traces += _load_traces(normal_dir, recurse=False)
    if val_dir.exists():
        normal_traces += _load_traces(val_dir, recurse=False)
    if attack_dir.exists():
        attack_traces = _load_traces(attack_dir, recurse=True)

    if normal_traces or attack_traces:
        print(f"Loaded {len(normal_traces)} normal traces, {len(attack_traces)} attack traces from ADFA-LD")
    else:
        print("[WARNING] No ADFA-LD traces loaded - events will have no syscall_trace field")

    return normal_traces, attack_traces


def sample_trace(traces: list) -> list:
    """Return a random trace from the pool, or empty list if pool is empty."""
    if not traces:
        return []
    return random.choice(traces)


# EVENT GENERATION ----------------------------------------

def generate_event(base_time_est, index, normal_traces, attack_traces, clean_baseline=False):
    """Generate one synthetic device event.

    clean_baseline=True forces all events to be genuinely benign:
    no suspicious processes, no USB executables, firewall always on,
    CPU spikes always below sustained threshold. Used for clean FP measurement.
    """
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    device_type = random.choice(DEVICE_TYPE)
    device_id = f"device-{random.randint(1, 10):02d}"
    user = random.choice(USERS)

    r = random.random()

    # weighted: process_start 60%, cpu_spike 20%, usb_event 15%, security_change 5%
    if r < 0.60:
        # clean baseline never generates suspicious processes
        suspicion_rate = 0.0 if clean_baseline else 0.05
        if random.random() < suspicion_rate:
            proc = random.choice(SUSPICIOUS_PROCESS)
            suspicious = True
            trace = sample_trace(attack_traces)
        else:
            proc = random.choice(SAFE_PROCESS)
            suspicious = False
            trace = sample_trace(normal_traces)

        risk = 50 if suspicious else 0

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_time_est.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "user": user,
            "event_type": "process_start",
            "process_name": proc,
            "process_path": f"/usr/bin/{proc}",
            "suspicious": suspicious,
            "risk_score": min(100, risk),
            "syscall_trace": trace,
        }

    elif r < 0.80:
        baseline = random.uniform(5.0, 15.0)
        if clean_baseline:
            # keep ratio below 2.5 so no L1 rule fires
            cpu_percent = round(random.uniform(baseline * 1.1, baseline * 2.3), 1)
            duration_seconds = random.randint(10, 400)
        else:
            cpu_percent = round(random.uniform(baseline * 1.5, baseline * 5.0), 1)
            duration_seconds = random.randint(10, 900)

        risk = 0
        if not clean_baseline and cpu_percent > baseline * 3:
            risk += 30

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_time_est.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "user": user,
            "event_type": "cpu_spike",
            "cpu_percent": cpu_percent,
            "baseline_cpu": round(baseline, 1),
            "duration_seconds": duration_seconds,
            "risk_score": min(100, risk),
            "syscall_trace": sample_trace(normal_traces),
        }

    elif r < 0.95:
        usb_id = f"USB-{random.randint(1000, 9999)}"
        action = random.choice(["connected", "removed"])
        # clean baseline never launches executables from USB
        new_exe = False if clean_baseline else (random.random() < 0.02)
        exe_path = f"E:/{uuid.uuid4().hex[:6]}.exe" if new_exe else None

        risk = 40 if new_exe else 0
        trace = sample_trace(attack_traces) if new_exe else sample_trace(normal_traces)

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_time_est.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "user": user,
            "event_type": "usb_event",
            "usb_id": usb_id,
            "action": action,
            "new_executable_started": new_exe,
            "exe_path": exe_path,
            "risk_score": min(100, risk),
            "syscall_trace": trace,
        }

    else:
        # clean baseline keeps firewall always enabled
        fw_enabled = True if clean_baseline else (random.random() < FIREWALL_ODD)
        risk = 25 if not fw_enabled else 0
        trace = sample_trace(attack_traces) if not fw_enabled else sample_trace(normal_traces)

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_time_est.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "user": user,
            "event_type": "security_change",
            "component": "firewall",
            "new_status": "enabled" if fw_enabled else "disabled",
            "risk_score": min(100, risk),
            "syscall_trace": trace,
        }


# MAIN ----------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic device events with ADFA-LD syscall traces")
    parser.add_argument("count", nargs="?", type=int, default=100,
                        help="Number of events to generate (default: 100)")
    parser.add_argument(
        "--adfa-dir",
        type=Path,
        default=Path("C:/Users/alexg/datasets/ADFA-LD/ADFA-LD"),
        help="Path to ADFA-LD dataset root",
    )
    parser.add_argument(
        "--clean-baseline",
        action="store_true",
        help="Generate purely benign events only - no suspicious processes, no USB executables, "
             "firewall always on. Use this set for false positive measurement in evaluation.",
    )
    args = parser.parse_args()

    random.seed(RANDOM_SEED)
    normal_traces, attack_traces = load_adfa_traces(args.adfa_dir)

    existing = []
    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    base_time_est = datetime.now(EST)
    new_events = [generate_event(base_time_est, i, normal_traces, attack_traces,
                                 clean_baseline=args.clean_baseline)
                  for i in range(args.count)]

    events = existing + new_events

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"Wrote {len(new_events)} new events (total {len(events)}) to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
