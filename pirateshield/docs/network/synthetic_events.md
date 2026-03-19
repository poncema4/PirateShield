## Overview

Synthetic network events are used to test anomaly detection rules and validate risk scoring behavior

---

## Normal Traffic Example

```json
{
  "event_id": "1",
  "timestamp": "2026-02-05T14:30:00",
  "source_ip": "10.0.0.5",
  "destination_ip": "142.250.72.14",
  "destination_port": 443,
  "protocol": "TCP",
  "bytes_sent": 15000,
  "bytes_received": 32000,
  "device_id": "host-A",
  "event_type": "network_connection"
}
```

---

## VPN or Proxy Traffic Example

```json
{
  "event_id": "2",
  "timestamp": "2026-02-05T14:31:10",
  "source_ip": "10.0.0.5",
  "destination_ip": "185.220.101.1",
  "destination_port": 1194,
  "protocol": "UDP",
  "bytes_sent": 90000000,
  "bytes_received": 12000,
  "device_id": "host-A",
  "event_type": "network_connection"
}
```

---

## High Connection Volume Example

```json
{
  "event_id": "3",
  "timestamp": "2026-02-05T14:31:40",
  "source_ip": "10.0.0.9",
  "destination_ip": "203.0.113.45",
  "destination_port": 80,
  "protocol": "TCP",
  "bytes_sent": 5000,
  "bytes_received": 2000,
  "device_id": "host-B",
  "event_type": "network_connection"
}
```