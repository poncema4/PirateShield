"""
program that pretends to be a computer or Chromebook 
and reports fake device activity, so PirateShield can be tested
without installing anything on real student devices
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Path for the json file 
BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_device_events.json"

# Relevant data for the generator 
EST = timezone(timedelta(hours=-5))

DEVICE_TYPE = ["school computer", "school chromebook", "laptop", "phone", "tablet"]
USERS = [f"student{n:03d}" for n in range(1, 21)]

# common safe processes you expect on student devices
SAFE_PROCESS = [
    "chrome", "explorer", "system", "svchost", "python", "zoom", "teams", "edge"
]

SUSPICIOUS_PROCESS = ["openvpn", "wireguard", "proxychains", "ngrok", "sshuttle",
    "cracktool", "bypass_tool", "tun2socks"]  # *make this a weighed pool*
FIRE_WALL_ODD = 0.9 # 90% of the time firewall is up 


def generate_event(base_time_est, index):
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    device_type = random.choice(DEVICE_TYPE)
    device_id = f"device-{uuid.uuid4().hex[:8]}"
    user = random.choice(USERS)

    # Endpoint events (processes, cpu/memory spikes, usb, security changes).
    r = random.random()

    # weighted: process_start 60%, cpu_spike 20%, usb_event 15%, security_change 5%
    if r < 0.60:
        # process_start
        suspicion_rate = 0.05
        if random.random() < suspicion_rate:
            proc = random.choice(SUSPICIOUS_PROCESS)
            suspicious = True
        else:
            proc = random.choice(SAFE_PROCESS)
            suspicious = False

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
            "risk_score": min(100, risk)
        }
    elif r < 0.80:
        # cpu_spike
        baseline = random.uniform(5.0, 15.0) # between 5 and 15%
        cpu_percent = round(random.uniform(baseline * 1.5, baseline * 5.0), 1)
        duration_seconds = random.randint(10, 900)

        risk = 0
        if cpu_percent > baseline * 3:
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
            "risk_score": min(100, risk)
        }
    elif r < 0.95:
        # usb_event
        usb_id = f"USB-{random.randint(1000,9999)}"
        action = random.choice(["connected", "removed"])
        new_exe = random.random() < 0.02  #2% of the time, usb launches exe
        exe_path = f"E:/{uuid.uuid4().hex[:6]}.exe" if new_exe else None

        risk = 40 if new_exe else 0

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
            "risk_score": min(100, risk)
        }
    else:
        # security_change (firewall toggled)
        fw_enabled = random.random() < FIRE_WALL_ODD  # 90% enabled, 10% disabled
        risk = 25 if not fw_enabled else 0

        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": event_time_est.isoformat(),
            "device_id": device_id,
            "device_type": device_type,
            "user": user,
            "event_type": "security_change",
            "component": "firewall",
            "new_status": "enabled" if fw_enabled else "disabled",
            "risk_score": min(100, risk)
        }


def main(count: int = 50):  # can change count for how many outputs
    # load existing events (if present)
    existing = []
    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    base_time_est = datetime.now(EST)
    new_events = [generate_event(base_time_est, i) for i in range(count)]

    events = existing + new_events

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    print(f"Wrote {len(new_events)} new events (total {len(events)}) to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()