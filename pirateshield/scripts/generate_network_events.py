import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_network_events.json"
EST = timezone(timedelta(hours=-5))

SOURCE_IPS = ["10.0.0.5", "10.0.0.9", "10.0.0.12", "10.0.0.22", "172.16.0.3"]

DESTINATION_IPS = [
    "142.250.72.14",
    "8.8.8.8",
    "185.220.101.1",
    "203.0.113.45",
    "91.108.4.1",
    "198.51.100.77",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "RAW"]
DEVICES = ["host-A", "host-B", "host-C", "host-D", "unknown-device-99"]
USERS = ["student1", "teacher2", "it_staff3"]

KNOWN_USER_DEVICES = {
    "student1":  ["host-A", "host-B"],
    "teacher2":  ["host-B", "host-C"],
    "it_staff3": ["host-C", "host-D"],
}

EVENT_PROFILES = [
    # Normal traffic (most common)
    ("network_connection", 40, [80, 443, 8080],          ["TCP"],              (1_000,    500_000)),
    ("dns_lookup",         15, [53],                     ["UDP"],              (200,      5_000)),
    ("file_transfer",      10, [21, 443, 8080],          ["TCP"],              (100_000,  10_000_000)),

    # Suspicious / medium risk
    ("port_scan",           8, [22, 23, 3389, 445, 139], ["TCP"],              (100,      1_000)),
    ("unusual_login",       7, [22, 3389],               ["TCP"],              (500,      10_000)),
    ("vpn_connection",      5, [1194, 1080, 443],        ["UDP", "TCP"],       (10_000,   500_000)),

    # High risk / attack traffic
    ("brute_force",         5, [22, 3389, 21],           ["TCP"],              (5_000,    50_000)),
    ("data_exfil",          4, [443, 80, 4444],          ["TCP"],              (5_000_000, 80_000_000)),
    ("lateral_movement",    3, [445, 139, 3389],         ["TCP"],              (10_000,   200_000)),
    ("malware",             2, [4444, 6667, 1337],       ["TCP", "RAW"],       (50_000,   5_000_000)),
    ("c2_beacon",           1, [80, 443, 8080],          ["TCP"],              (500,      5_000)),
]

EVENT_POOL = []
for profile in EVENT_PROFILES:
    EVENT_POOL.extend([profile] * profile[1])

def generate_event(base_time_est: datetime, index: int) -> dict:
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    user = random.choice(USERS)
    known_devices = KNOWN_USER_DEVICES[user]

    if random.random() < 0.8:
        device_id = random.choice(known_devices)
    else:
        device_id = random.choice(DEVICES)

    event_type, _, ports, protocols, bytes_range = random.choice(EVENT_POOL)

    destination_ip = random.choice(DESTINATION_IPS)

    if event_type in ("malware", "c2_beacon", "data_exfil"):
        destination_ip = random.choice(["185.220.101.1", "198.51.100.77", "203.0.113.45"])

    return {
        "user_id":            user,
        "event_id":           str(uuid.uuid4()),
        "timestamp":          event_time_est.isoformat(),
        "source_ip":          random.choice(SOURCE_IPS),
        "destination_ip":     destination_ip,
        "destination_port":   random.choice(ports),
        "lat":                round(random.uniform(-90.0, 90.0), 6),
        "long":               round(random.uniform(-180.0, 180.0), 6),
        "protocol":           random.choice(protocols),
        "bytes_sent":         random.randint(*bytes_range),
        "bytes_received":     random.randint(1_000, 50_000),
        "device_id":          device_id,
        "user_known_devices": known_devices,
        "event_type":         event_type,
    }

def main():
    existing_events = []
    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE, "r") as f:
                existing_events = json.load(f)
        except json.JSONDecodeError:
            existing_events = []

    new_events = []
    base_time_est = datetime.now(EST)
    for i in range(5):
        new_events.append(generate_event(base_time_est, i))

    print("Generated events:")
    for e in new_events:
        print(f"  [{e['event_type']:20s}] port={e['destination_port']:5d}  bytes_sent={e['bytes_sent']:>12,}  device={e['device_id']}")

    events = existing_events + new_events
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=2)

    print(f"\n{len(events)} total events written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()