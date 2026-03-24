# 1. Login Behaviors

## Objectives

- Study normal login behaviors of school faculty and students.
- Study malicious login behaviors from outsiders and insiders.
- Identify structural risks in lifecycle and trust-based login behaviors.
- Understand who logs in, when they log in, how they authenticate, and what deviations look like.

---

## 1.1 Normal Login Behaviors

### Typical Student Login Patterns

- High-frequency logins during school hours through LMS platforms (Canvas, Google Classroom, Schoology, etc.).
- Primarily school-managed devices (Chromebooks, MacBooks).
- Shared IP ranges (school networks, classrooms, labs).
- Occasional account sharing (friends or siblings).
- Repeated device or LMS logins due to sleep or session expiration.
- Mix of school and home networks (especially middle and high school students).

---

### Typical Teacher Login Patterns

- Predictable weekday patterns (typically 7:00 AM – 4:00 PM).
- Multiple applications via SSO (Google Workspace, Canvas, SIS, etc.).
- Mix of school and home networks.
- Limited geographic variance.
- Low tolerance for failed login attempts.

---

### Typical Admin or Staff Login Patterns

- Fewer logins but higher privilege levels.
- Access to sensitive systems.
- Rare after-hours activity (sometimes legitimate in emergencies).
- MFA consistently used (assumption).

---

## 1.2 Malicious Login Behaviors

### Outsider Threats

Outsiders typically use automated authentication attacks or stealth authentication techniques.

#### Automated Authentication Attacks

- Credential stuffing
- Password spraying
- Brute-force attempts
- Use of botnets, residential proxies, or rotating IPs
- Rapid switching between accounts
- Noise-based attacks to hide successful logins

#### Stealth Authentication Attacks

- SSO token reuse
- Session hijacking
- Saved browser profile abuse
- Cached credentials on unmanaged devices
- OAuth token abuse
- MFA fatigue or push bombing

---

### Insider Threats (K-12 Specific)

Often overlooked but common in school environments:

- Shared student accounts
- Students logging into teacher accounts
- Use of substitute accounts
- Login from personal devices
- Login during exams or after hours
- Borrowed or stolen Chromebooks
- Reuse of remembered sessions
- Impersonation of staff to IT helpdesk

## 1.3 Lifecycle and Trust-Based Login Behaviors

We must consider long-term structural risks such as student graduation or staff termination. These lifecycle events introduce potential weaknesses if not properly managed.

### Structural Risks

- Dormant accounts reactivated
- Former students still logging in
- Temporary privileges persisting
- Devices trusted beyond their lifecycle
- MFA enrollment hijacking
- Legacy protocols bypassing MFA