# 3. Identity Related Events

## Objectives

- Gain a deeper understanding of atomic identity events.
- Identify what identity data must be observed and logged.

Identity events are categorized into:

1. Authentication events
2. Temporal events
3. Location & network events
4. Device & session events
5. Identity context events
6. Post-login activity signals

---

## 3.1 Authentication Events

- Login success
- Login failure
- MFA sent
- MFA accepted or rejected
- MFA enrollment
- MFA removal
- Password reset
- Legacy protocol login (IMAP/POP/SMTP)
- OAuth consent granted

---

## 3.2 Temporal Events

- Login timestamp
- Time since last login
- Login during school hours, after hours, weekends, holidays, or breaks
- Burst frequency
- Time between login attempts
- Time between geolocation changes

---

## 3.3 Location & Network Events

- Source IP
- ASN
- Residential vs. datacenter IP
- VPN flag
- Geolocation (country, state, city)
- Impossible travel indicators
- Guest vs. internal network

---

## 3.4 Device & Session Events

- Device ID
- Device type
- Managed vs. unmanaged
- Device trust state
- Device reported lost
- Session ID
- Session age
- Concurrent sessions
- Token reuse
- Cookie/session continuation after IP change

---

## 3.5 Identity Context Events

- User ID
- Role
- Privilege level
- Account status (active, dormant, terminated)
- MFA enforcement state
- Assigned substitute flag
- Working day flag
- Permission grants and revocations

---

## 3.6 Post-Login Activity Signals

- Action sequence
- Resources accessed
- Volume accessed
- Export/download events
- Privilege escalation attempts
- Audit log tampering
- Lateral app access via SSO
