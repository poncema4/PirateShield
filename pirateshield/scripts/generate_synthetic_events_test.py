import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_events.json"

EST = timezone(timedelta(hours=-5))

SOURCE_IPS = ["10.0.0.5", "10.0.0.9", "10.0.0.12"]
DESTINATION_IPS = [
    "142.250.72.14",
    "8.8.8.8",
    "185.220.101.1",
    "203.0.113.45"
]

DESTINATION_PORTS = [80, 443, 8080, 1080, 1194]
PROTOCOLS = ["TCP", "UDP"]
DEVICES = ["host-A", "host-B", "host-C"]

def generate_event(base_time_est, index):
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": event_time_est.isoformat(),
        "source_ip": random.choice(SOURCE_IPS),
        "destination_ip": random.choice(DESTINATION_IPS),
        "destination_port": random.choice(DESTINATION_PORTS),
        "protocol": random.choice(PROTOCOLS),
        "bytes_sent": random.randint(1_000, 100_000_000),
        "bytes_received": random.randint(1_000, 50_000),
        "device_id": random.choice(DEVICES),
        "event_type": "network_connection"
    }

def main():
    events = []
    base_time_est = datetime.now(EST)

    for i in range(5):
        events.append(generate_event(base_time_est, i))

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=2)

    print(f"Generated {len(events)} synthetic events in EST at:")
    print(OUTPUT_FILE)

if __name__ == "__main__":
    main()