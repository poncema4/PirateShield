# 4. Identity Anomaly Rules

## Objective

- Detect when identity behavior becomes suspicious.
- Develop a structured rule library.

Identity anomalies fall into the following categories:

1. Authentication failure
2. Location & travel
3. Time-based
4. Device & session
5. MFA & authentication control bypass
6. Identity lifecycle violations
7. Post-login behavioral anomalies
8. Social engineering–driven identity compromise

---

## 4.1 Authentication Failure Anomalies

- Burst of failed logins
- Failed logins across many accounts
- Failures from rotating IPs
- Failures followed by success
- Same password hash across accounts
- High failure noise masking success

---

## 4.2 Location & Travel Anomalies

- Impossible travel
- New country login
- Login from unusual region
- Geolocation change mid-session
- Login from foreign IP shortly after phishing
- VPN use when user historically does not use VPN

---

## 4.3 Time-Based Anomalies

- Login outside normal hours
- Login during vacation
- Login on non-working day
- Login followed by sensitive action at abnormal hours
- Repeated after-hours admin access

---

## 4.4 Device & Session Anomalies

- New device login
- Unmanaged device accessing sensitive data
- Session continues after device change
- Token reuse on unknown device
- Long-lived sessions without re-authentication
- Concurrent sessions from different locations

---

## 4.5 MFA & Authentication Control Bypass

- MFA not used for privileged role
- Legacy protocol login with MFA disabled
- MFA push bombing
- MFA approval after multiple denials
- MFA enrollment from unusual IP location
- Legitimate MFA device removed unexpectedly

---

## 4.6 Identity Lifecycle Violations

- Dormant account reactivation
- Login after termination
- Substitute account used outside assignment
- Temporary privileges not revoked
- Old trusted device still authenticating

---

## 4.7 Post-Login Behavioral Anomalies (Identity Abuse)

- Access outside role norms
- Large data exports
- Sudden privilege escalation
- Lateral movement across SSO apps
- Low-and-slow data exfiltration
- Grade changes without authorization
- Bulk actions inconsistent with role

---

## 4.8 Social Engineering–Driven Identity Compromise

- Login shortly after phishing interaction
- Login after helpdesk reset
- Credential submission events
- Email sender spoofing plus login correlation
- Impersonation of authority figures
- Internal account suddenly acting suspicious or phishing others
