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

| Field | Description |
|------|------------|
| `event_id` | Unique identifier for the event |
| `timestamp` | ISO 8601 UTC timestamp |
| `source_ip` | Originating IP address |
| `destination_ip` | Destination IP address |
| `destination_port` | Destination port number |
| `protocol` | Network protocol (TCP or UDP) |
| `bytes_sent` | Bytes sent from the source |
| `bytes_received` | Bytes received by the source |
| `device_id` | Identifier of the reporting device |
| `event_type` | Type of network event |

---

## Schema Design Rationale

- Supports time-based correlation
- Enables traffic volume analysis
- Allows destination reputation checks
- Easy to extend with new fields