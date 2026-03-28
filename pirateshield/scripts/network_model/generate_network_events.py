import json
import random
import uuid
import sys
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import BytesIO

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_events" / "synthetic_network_events.json"
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

def generate_chart(events: list[dict]) -> str | None:
    """Generate a matplotlib chart of event distribution and return base64 PNG."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as ticker
    except ImportError:
        return None

    type_counts: dict[str, int] = {}
    for e in events:
        t = e.get("event_type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    color_map = {
        "network_connection": "#3fb950",
        "dns_lookup": "#3fb950",
        "file_transfer": "#58a6ff",
        "port_scan": "#d29922",
        "unusual_login": "#d29922",
        "vpn_connection": "#d29922",
        "brute_force": "#f85149",
        "data_exfil": "#da3633",
        "lateral_movement": "#f85149",
        "malware": "#da3633",
        "c2_beacon": "#da3633",
    }

    labels = sorted(type_counts.keys(), key=lambda k: type_counts[k], reverse=True)
    counts = [type_counts[l] for l in labels]
    colors = [color_map.get(l, "#8b949e") for l in labels]

    fig, ax = plt.subplots(figsize=(10, 5))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#161b22")

    bars = ax.barh(labels, counts, color=colors, edgecolor="#30363d", linewidth=0.5)
    ax.set_xlabel("Count", color="#c9d1d9", fontsize=11)
    ax.set_title("Network Event Distribution", color="#f0f6fc", fontsize=14, fontweight="bold")
    ax.tick_params(colors="#8b949e")
    ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    for spine in ax.spines.values():
        spine.set_color("#30363d")

    for bar, count in zip(bars, counts):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                str(count), va="center", color="#c9d1d9", fontsize=10)

    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format="png", dpi=120, facecolor="#0d1117", bbox_inches="tight")
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

def generate_event_fixed_type(base_time_est: datetime, index: int, event_type: str) -> dict:
    """Generate an event with a specific event_type instead of random selection."""
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    user = random.choice(USERS)
    known_devices = KNOWN_USER_DEVICES[user]

    if random.random() < 0.8:
        device_id = random.choice(known_devices)
    else:
        device_id = random.choice(DEVICES)

    # Find the matching profile for the given event_type
    profile = None
    for p in EVENT_PROFILES:
        if p[0] == event_type:
            profile = p
            break

    if profile is None:
        # Fallback to network_connection if unknown type
        profile = EVENT_PROFILES[0]
        event_type = profile[0]

    _, _, ports, protocols, bytes_range = profile

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

    # Parse --count and --event-type from args
    count = 5
    forced_event_type = None
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg == "--count" and i + 1 < len(args):
            count = int(args[i + 1])
        if arg == "--event-type" and i + 1 < len(args):
            forced_event_type = args[i + 1]

    new_events = []
    base_time_est = datetime.now(EST)
    for i in range(count):
        if forced_event_type:
            new_events.append(generate_event_fixed_type(base_time_est, i, forced_event_type))
        else:
            new_events.append(generate_event(base_time_est, i))

    print("Generated events:")
    for e in new_events:
        print(f"  [{e['event_type']:20s}] port={e['destination_port']:5d}  bytes_sent={e['bytes_sent']:>12,}  device={e['device_id']}")

    events = existing_events + new_events
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(events, f, indent=2)

    print(f"\n{len(events)} total events written to {OUTPUT_FILE}")

    if "--chart" in sys.argv:
        chart_b64 = generate_chart(events)
        if chart_b64:
            print(f"\nCHART_BASE64:{chart_b64}")
        else:
            print("\n(matplotlib not available for chart generation)")

if __name__ == "__main__":
    main()