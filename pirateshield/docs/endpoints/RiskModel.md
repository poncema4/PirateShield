# Endpoint Device Risk Scoring Model

## Overview

PirateShield's endpoint layer detects suspicious device activity using a **hybrid rule-and-anomaly scoring model** built from multiple detection techniques. The model combines static rule-based scoring, UHAC-inspired command anomaly analysis, and RAPID-inspired event chain detection to produce a **single explainable risk score (0-100)**.

This approach allows PirateShield to:

* Flag known-bad process and device behavior immediately
* Detect unusual or never-before-seen commands on the device fleet
* Identify suspicious clusters of events happening in a short time window
* Produce explainable alerts with human-readable reason strings
* Operate in real-time without heavy ML infrastructure

The system integrates ideas from the following techniques:

1. **Weighted rule-based scoring** (static, deterministic detection)
2. **UHAC-inspired command anomaly scoring** (frequency-based anomaly signal)
3. **RAPID-inspired chain detection** (event clustering signal)

---

## System Architecture

PirateShield processes device events through a **three-layer detection pipeline**

```
Device Event (JSON)
      │
      ▼
Field Normalization
(user_id, device_id, event_type, timestamp)
      │
      ├──────────────────┬──────────────────┐
      ▼                  ▼                  ▼
Layer 1:           Layer 2:           Layer 3:
Rule-Based         UHAC: Command      RAPID: Chain
Scoring            Anomaly            Detection
      │                  │                  │
      └──────────────────┴──────────────────┘
                         │
                         ▼
                  Score Combination
                         │
                         ▼
                  Clamp to 0-100
                         │
                         ▼
              Alert Generation + Reasons
```

Each layer produces a **partial score**, which is combined into a final **DeviceRisk** score.

---

## Data Collected From Device Events

PirateShield extracts the following fields from each endpoint event:

| Feature               | Description                                      |
| --------------------- | ------------------------------------------------ |
| event_type            | process_start, cpu_spike, usb_event, security_change |
| device_id             | Unique identifier for the device                 |
| user_id               | Student or staff identifier                      |
| timestamp             | Event timestamp (ISO 8601)                       |
| process_name          | Name of the process that triggered the event     |
| process_path          | File path of the process binary                  |
| suspicious            | Boolean flag from endpoint agent                 |
| cpu_percent           | Current CPU usage percentage                     |
| baseline_cpu          | Historical average CPU for this device           |
| duration_seconds      | How long the CPU spike lasted                    |
| usb_id                | Identifier for inserted USB device               |
| usb_action            | connected / removed                              |
| new_executable_started| Whether a USB insertion triggered an .exe launch |
| exe_path              | File path of the launched executable             |
| component             | Security component affected (e.g., firewall)     |
| new_status            | New status of the component (enabled / disabled) |

**Planned / future fields:**
- `cmdline` (full command-line string)
- `mem_percent`, `baseline_mem` (memory metrics)
- `previous_device_id`, `switch_gap_minutes` (device switching)

These features are used across all three detection layers.

---

# Detection Layer 1: Rule-Based Scoring

## Purpose

Detect known-bad or high-confidence suspicious endpoint activity using deterministic rules.

This is the **primary driver** of the risk score. It produces the most points and is the most explainable - you can always point to exactly why the score went up.

---

## How It Works

Each device event is evaluated against a set of predefined rules. Each rule is a binary indicator function: either the event matches the rule, or it does not. If it matches, a fixed number of points is added to the score.

Formally, the rule-based score for a single event is:

```
S_rules = Σ (w_i × 𝟙[R_i(e)])
```

Where:
- `e` is the device event being scored
- `R_i` is the i-th detection rule (returns true or false)
- `𝟙[R_i(e)]` is the indicator function (1 if the rule triggers, 0 otherwise)
- `w_i` is the fixed severity weight assigned to rule i

We assign severity weights based on the assessed risk of each event type in a K-12 endpoint context. <!-- TODO: consider finding a citation for rule-based weighted scoring in IDS literature -->

---

## Rule Definitions and Weights

| Rule | Condition | Points (w_i) |
| ---- | --------- | ------------- |
| R1: Suspicious process flag | `suspicious == true` | +40 |
| R2: Known-bad process name | `process_name` is in suspicious process list | +35 |
| R3: USB launched executable | `usb_event` AND `new_executable_started == true` | +45 |
| R4: Sustained CPU spike | `cpu_percent / baseline_cpu ≥ 2.5` AND `duration ≥ 600s` | +30 |
| R5: Brief CPU spike | `cpu_percent / baseline_cpu ≥ 2.5` (not sustained) | +10 |
| R6: Security component disabled | `security_change` AND `new_status == disabled` | +50 |

**Suspicious process list** (examples): `wireguard`, `openvpn`, `tor`, `proxychains`, `nmap`, `netcat`, `mimikatz`, `metasploit`

**Note:** R1 and R2 have overlap protection. If both trigger for the same process, only the higher-scoring one counts.

---

## Rule Score Range

The theoretical maximum of `S_rules` (if every rule triggered simultaneously) is approximately 160 before clamping. In practice, most single events trigger 1-2 rules. The fact that rules can push past 100 before clamping is intentional - it means a single severe event (like a USB-launched executable on a device with its firewall disabled) can immediately reach critical severity on its own, without needing the anomaly layers.

---

# Detection Layer 2: UHAC-Inspired Command Anomaly Scoring

## Purpose

Detect unusual or never-before-seen processes and commands on the device fleet.

This layer is inspired by the UHAC method (Kayhan et al., 2023), which demonstrated that ranking endpoint commands by rarity effectively surfaces suspicious activity. UHAC uses autoencoders to detect anomalous commands via reconstruction error. PirateShield adapts this core insight - rare commands are more suspicious - into a lightweight frequency-based approach suitable for real-time K-12 deployment without ML training infrastructure.

---

## How It Works

The mathematical foundation comes from Zhang et al. (2021), who formalized TF-IDF feature extraction for host-based intrusion detection on system-level audit data.

**Term Frequency (TF)** measures how prominent a process is within a single device's recent activity:

```
tf(s, T_d) = count of process s in device trace T_d
             ─────────────────────────────────────────
             total number of process events in T_d
```

Where:
- `s` is a process name (e.g., `ngrok`, `chrome`, `svchost`)
- `T_d` is the set of recent process events on device `d` (e.g., last 24 hours)

**Inverse Document Frequency (IDF)** measures how rare a process is across the entire device fleet:

```
idf(s, T) = log( N_T / (count of devices where s appears + 1) )
```

Where:
- `N_T` is the total number of devices (or device-day traces) in the fleet
- The `+1` in the denominator prevents division by zero for completely new processes

**TF-IDF Rarity Weight:**

```
tfidf(s, T_d, T) = tf(s, T_d) × idf(s, T)
```

A process that appears on only 1 out of 200 devices gets a high IDF. A process that runs on every device (like `chrome`) gets a low IDF. This is the mathematical formalization of "rare across the fleet ⇒ more suspicious."

(Zhang et al., Eq. 3-4)

---

## Command Rarity Score

To convert the raw TF-IDF weight into a bounded anomaly score, we normalize against the maximum observed TF-IDF value across the fleet:

```
A_cmd(s) = tfidf(s, T_d, T) / max_tfidf
```

Where `max_tfidf` is the highest TF-IDF value observed in the current fleet window.

This produces a value in the range [0, 1], where:
- 0 → process is completely ordinary
- 1 → process is the rarest observed in the fleet

---

## Contribution to Final Score

The command rarity score is scaled and **capped at a maximum of 20 points**:

```
RarityPoints = min(A_cmd × 20, 20)
```

**Why cap at 20?** Rule-based signals are directly interpretable ("the firewall was disabled"). A rarity signal only says "this process is unusual" - it does not confirm malice. Capping prevents a rare-but-benign process (like a newly installed educational app) from dominating the score. The cap ensures that rarity acts as a **nudge**, not a conviction.

---

# Detection Layer 3: RAPID-Inspired Chain Detection

## Purpose

Detect when multiple suspicious events cluster together in a short time window on the same device.

This layer is inspired by the RAPID framework (Amaru et al., 2025), which demonstrated that analyzing sequences of system events - rather than isolated events - significantly improves detection of multi-step attacks. RAPID uses provenance graphs and deep learning. PirateShield adapts this core insight - event chains matter more than individual events - into a lightweight temporal scoring approach.

---

## How It Works

The mathematical foundation comes from the Hawkes process framework, as formalized by Zheng, Yuan & Wu (2021) for insider threat detection on security event streams.

The Hawkes process models event intensity (how "active" suspicious behavior is right now) as a function of recent event history. The conditional intensity at time `t` is:

```
λ*(t) = λ_0 + Σ γ(t, t_i)
```

Where:
- `λ_0` is a baseline intensity (background rate of events)
- `t_i` are the timestamps of previous events on this device
- `γ(t, t_i)` is a triggering kernel - a function that decays as events get older

(Zheng, Yuan & Wu, Eq. 6)

The key idea: **each recent suspicious event increases the current intensity, and that contribution fades over time.** Three suspicious events in 5 minutes produce a much higher intensity than three events spread over 3 hours.

---

## PirateShield Adaptation

PirateShield uses a simplified form of the Hawkes intensity, where the triggering kernel is an exponential decay bounded within a fixed time window `W`:

```
C_chain(t, d) = Σ s_i × e^(-λ(t - t_i))    for all events i on device d
                                                where (t - t_i) ≤ W
```

Where:
- `t` is the current time
- `d` is the device being scored
- `s_i` is the rule-based score of event `i` (from Layer 1)
- `t_i` is the timestamp of event `i`
- `λ` is the decay rate (controls how fast old events lose influence)
- `W` is the window size (e.g., 10 minutes)

Events outside the window (`t - t_i > W`) contribute zero. Within the window, recent events contribute more than older events because of the exponential decay.

This is a special case of the general Hawkes intensity where `γ(t, t_i)` is nonzero only when `t - t_i ≤ W` (Zheng, Yuan & Wu, 2021).

---

## Chain Score

The raw chain value `C_chain` is normalized by dividing by a maximum expected value to produce a score in [0, 1]:

```
ChainNorm = C_chain(t, d) / C_max
```

Where `C_max` is the theoretical maximum chain intensity (e.g., the value produced if several high-severity events all occurred simultaneously). This can be calibrated from training data or set analytically.

---

## Contribution to Final Score

The chain detection score is scaled and **capped at a maximum of 15 points**:

```
ChainPoints = min(ChainNorm × 15, 15)
```

**Why cap at 15?** The chain signal is a pattern indicator, not a direct detection. A cluster of 3 mild events in 10 minutes might warrant investigation, but it should never score higher than a single confirmed rule trigger like "firewall disabled" (+50). The cap ensures chains boost the score without overpowering concrete evidence.

---

# Composite Risk Scoring

## Score Combination

PirateShield combines all three layers into a single risk score:

```
DeviceRisk = min(S_rules + RarityPoints + ChainPoints, 100)
```

Where:
- `S_rules` = sum of all triggered rule weights (Layer 1)
- `RarityPoints` = min(A_cmd × 20, 20) (Layer 2)
- `ChainPoints` = min(ChainNorm × 15, 15) (Layer 3)

---

## Why This Structure?

| Layer              | Max Contribution | Role                                         |
| ------------------ | ---------------- | -------------------------------------------- |
| Rule-based scoring | ~160 (before clamp) | Main driver - deterministic, explainable  |
| UHAC: command anomaly | +20           | nudge for unusual commands                   |
| RAPID: chain detection | +15          | nudge for clustered suspicious events        |

Rule-based scoring is intentionally the heaviest driver. The anomaly layers (rarity + chain) act as confidence nudges on top. A concrete rule trigger like "firewall disabled" (+50) always outweighs a borderline anomaly signal on its own. But when base rules produce a low score and both anomaly layers fire, they can push a borderline event into alert range - which is exactly the behavior we want.

---

## Risk Score Interpretation

| Risk Score  | Severity | Action                    |
| ----------- | -------- | ------------------------- |
| 0 - 14      | None     | No action                 |
| 15 - 34     | Low      | Log for review            |
| 35 - 59     | Medium   | Monitor device            |
| 60 - 84     | High     | Flag for investigation    |
| 85 - 100    | Critical | Immediate security alert  |

---

# Worked Example

## Scenario

A student on device `lab-01` triggers three events within 10 minutes:

| Event | Timestamp | What happened |
| ----- | --------- | ------------- |
| 1     | 10:00:00  | Unknown process `ngrok` launched - not on the suspicious process list |
| 2     | 10:03:00  | A second unfamiliar process `tun2socks` starts |
| 3     | 10:08:00  | Brief CPU spike - 3.1x baseline, not sustained |

---

## Layer 1: Rule-Based Scoring

| Event | Rule triggered | Points |
| ----- | ------------- | ------ |
| 1     | `ngrok` not on suspicious list, `suspicious` flag = false | +0 |
| 2     | `tun2socks` not on suspicious list, `suspicious` flag = false | +0 |
| 3     | Brief CPU spike (ratio ≥ 2.5, not sustained) → R5 | +10 |
| **Total** | | **S_rules = 10** |

Base rules alone: score of **10** - below every alert threshold.

---

## Layer 2: Command Rarity Scoring

`ngrok` appears on only 2 out of 200 devices in the fleet.
`tun2socks` has **never been seen** on any device before.

For the highest-rarity process (`tun2socks`):

```
tf(tun2socks, T_lab01) = 1/3 = 0.333
idf(tun2socks, T) = log(200 / (0 + 1)) = log(200) ≈ 2.301
tfidf = 0.333 × 2.301 = 0.766
```

Assuming max_tfidf across the fleet is currently 0.850:

```
A_cmd = 0.766 / 0.850 = 0.901
RarityPoints = min(0.901 × 20, 20) = 18.0
```

The rarity layer contributes **+18 points**.

---

## Layer 3: Chain Detection

Three events within a 10-minute window on the same device. Using `λ = 0.005` (per second) and `W = 600s`:

At the time of event 3 (t = 10:08:00):

```
Event 1 contribution: 0 × e^(-0.005 × 480) = 0       (s_i = 0, no rule triggered)
Event 2 contribution: 0 × e^(-0.005 × 300) = 0       (s_i = 0, no rule triggered)
Event 3 contribution: 10 × e^(-0.005 × 0) = 10.0     (s_i = 10 from CPU spike)
```

Wait - events 1 and 2 had `S_rules = 0`, so they contribute nothing to the chain intensity in this simple form.

But we also want chains to account for **rarity-flagged** events, not just rule-triggered ones. So we use a modified event score:

```
s_i = max(S_rules_i, RarityPoints_i)
```

Re-computing:

```
Event 1 (ngrok):     s_1 = max(0, ~14) = 14,  age = 480s → 14 × e^(-0.005 × 480) = 14 × 0.091 = 1.27
Event 2 (tun2socks): s_2 = max(0, ~18) = 18,  age = 300s → 18 × e^(-0.005 × 300) = 18 × 0.223 = 4.01
Event 3 (cpu spike):  s_3 = max(10, 0) = 10,   age = 0s   → 10 × e^(0)            = 10.0

C_chain = 1.27 + 4.01 + 10.0 = 15.28
```

Assuming `C_max = 25` (calibrated from fleet data):

```
ChainNorm = 15.28 / 25 = 0.611
ChainPoints = min(0.611 × 15, 15) = 9.2
```

The chain layer contributes **+9 points**.

---

## Final Score

```
DeviceRisk = min(10 + 18 + 9, 100) = 37
```

**Result: Medium severity - Monitor device**

---

## Why This Matters

Pure rule-based scoring would have produced a score of **10** - below every alert threshold, nothing happens. The rarity layer flagged that `tun2socks` was unlike anything seen across the fleet, and the chain layer recognized that multiple unusual events clustered in a short window. Together they surfaced something worth a human looking at.

**Alert reason string:**
> Brief CPU spike · Unusual process commands detected (tun2socks: never seen on fleet) · Multiple suspicious events in short window (3 events in 10 min)

---

# Alert Generation

PirateShield produces human-readable alerts:

```
PirateShield Security Alert

Type: Endpoint Device Anomaly

Details:
• Brief CPU spike: 3.1x baseline
• Unusual process detected: tun2socks (rarity score: 0.90)
• Multiple events clustered in 10-minute window

Risk Score: 37
Severity: Medium
Device: lab-01
User: student_lab_01
```

---

# Sources

- **UHAC (conceptual inspiration for Layer 2):** Kayhan, V.O., Agrawal, M., & Shivendu, S. (2023). *Cyber threat detection: Unsupervised hunting of anomalous commands (UHAC).* Decision Support Systems, 168, 113928. doi: 10.1016/j.dss.2023.113928

- **RAPID (conceptual inspiration for Layer 3):** Amaru, Y., Wudali, P.N., Elovici, Y., & Shabtai, A. (2025). *RAPID: Robust APT detection and investigation using context-aware deep learning.* Computer Networks, 273, 111744. doi: 10.1016/j.comnet.2025.111744

- **TF-IDF formulas for host-based anomaly detection (Layer 2 equations):** Zhang, L., Cushing, R., de Laat, C., & Grosso, P. (2021). *A real-time intrusion detection system based on OC-SVM for containerized applications.* Proc. IEEE 24th Int. Conf. on Computational Science and Engineering (CSE 2021), pp. 138-145. doi: 10.1109/CSE53436.2021.00029

- **Hawkes process temporal intensity for security event streams (Layer 3 equations):** Zheng, P., Yuan, S., & Wu, X. (2021). *Using Dirichlet Marked Hawkes Processes for Insider Threat Detection.* Digital Threats: Research and Practice, 3(1), Article 5. doi: 10.1145/3457908

---

# Future Improvements

Future PirateShield endpoint versions may incorporate:

* `cmdline` field for full command-line TF-IDF (character n-gram features as in UHAC)
* Memory usage anomaly detection (`mem_percent` / `baseline_mem`)
* Device-switching correlation (rapid switching between devices as a suspicion signal)
* Adaptive decay rate `λ` tuned via threshold optimization
* Per-device fleet baselines that update on a rolling 30-day window
