## Overview

All network events ingested by PirateShield follow a single standardized schema 
to ensure consistent processing and analysis

---

## Event Format (JSON)

```json
{
  "event_id": "uuid",
  "timestamp": "2026-02-05T14:32:10",
  "source_ip": "192.168.1.10",
  "destination_ip": "8.8.8.8",
  "destination_port": 443,
  "protocol": "TCP",
  "bytes_sent": 523412,
  "bytes_received": 12034,
  "device_id": "host-123",
  "event_type": "network_connection"
}
```

---

## Field Definitions:

event_id -> unique identifier for the event
timestamp -> EST timestamp based on timezone
source_ip -> originating IP address
destination_ip -> destination IP address
destination_port -> destination port number
protocol -> network protocol (TCP/UDP)
bytes_sent -> bytes sent from the source
bytes_received -> bytes received by the source
device_id -> identifier of the reporting device
event_type -> type of network event

---

## Schema Design Rationale

- Supports time-based correlation
- Enables traffic volume analysis
- Allows destination reputation checks
- Easy to extend with new fields