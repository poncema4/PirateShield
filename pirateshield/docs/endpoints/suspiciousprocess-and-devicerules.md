# Endpoint Security Design

## 1. Suspicious Process List

### VPN and Tunneling Tools
- tor.exe
- psiphon.exe
- openvpn.exe
- shadowsocks.exe
- any executable associated with mobile VPN apps
- processes using unauthorized VPN endpoints

### Portable Hacking and Scanning Tools
- angryipscanner.exe
- wireshark-portable.exe
- nmap.exe
- password cracking utilities
- tools running directly from Downloads, AppData, Desktop, or USB paths

### Remote Access / Control Tools
- anydesk.exe
- teamviewer.exe
- agent64.exe (RAT example)
- unknown background remote-control processes

### Cryptomining and Resource Abuse
- miner.exe
- processes connecting to mining pools (port 3333, 4444)
- executables with sustained high CPU/GPU usage without user activity

### Ransomware Indicators
- known ransomware process names (ex. lockbit.exe)
- unknown executables modifying files at high frequency

(can be expanded)
---


## 2. Device Anomaly Rules

### Suspicious Process Execution

- Process name matches suspicious_process_list
- Process runs from non-standard location (Downloads, AppData, USB)
- App not found in installed applications list
- Background-only execution without visible window
- Remote-control process detected outside school hours

### Abnormal CPU / Memory Behavior

- CPU usage > 3* baseline for more than 10 minutes
- cpu_percent > 90% with no active user interaction
- Sudden spike in file modifications across directories
- High disk write rate from unknown process
- Device temperature significantly above baseline

### Privilege Escalation Indicators

- Unexpected UAC trigger from untrusted parent process
- token_type changes from standard to admin without workflow
- Scheduled task created with highest privileges
- Service creation or modification by non-admin user
- Registry edits targeting system-level keys from non-elevated context

### Security Control Tampering

- antivirus_status transitions from running to stopped
- EDR service disabled or unresponsive
- Firewall turned off outside maintenance window
- New firewall rule created unexpectedly
- DNS or proxy settings modified by untrusted process

### BYOD and Device Switching Anomalies

- Same user_id signs in from multiple device_ids in short window
- Same account active from two networks simultaneously
- Many new device_ids associated with one account
- Unmanaged device showing repeated outbound beacon-like behavior

---
