## Overview

This defines the initial set of network anomaly detection rules used by PirateShield to calculate risk scores

---

## Rule 1: Excessive Outbound Traffic

**Description**  
Detects devices sending unusually large amounts of outbound data in a short time window

**Detection Logic**
```
SUM(bytes_sent) per device over 5 minutes > 500 MB
```

**Risk Score Impact**
- +40 points

**Rationale**  
May indicate data exfiltration or malware activity

---

## Rule 2: VPN or Proxy Destination Detection

**Description**  
Detects traffic sent to known VPN, proxy, or anonymization services

**Indicators**
- Destination IP matches a known VPN or proxy list
- Destination port associated with tunneling or proxy services

**Common Ports**
- 1080 (SOCKS)
- 1194 (OpenVPN)
- 8080 (HTTP Proxy)

**Risk Score Impact**
- +25 points

**Rationale**  
VPN or proxy usage may be used to bypass monitoring controls

---

## Rule 3: Abnormal Connection Patterns

**Description**  
Detects unusually high numbers of outbound connections to multiple destinations in a short time period

**Detection Logic**
```
COUNT(unique destination_ip) > 100 within 1 minute
```

**Risk Score Impact**
- +35 points

**Rationale**  
May indicate scanning, botnet behavior, or command-and-control activity