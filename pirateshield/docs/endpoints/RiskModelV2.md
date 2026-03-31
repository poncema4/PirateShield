# Endpoint Device Risk Scoring Model

## Overview

PirateShield's endpoint layer detects suspicious device activity using a **hybrid detection model** that combines deterministic rule-based scoring, autoencoder-based command anomaly detection, and temporal event chain analysis to produce a **single explainable risk score (0-100)**.

This approach allows PirateShield to:

* Flag known-bad process and device behavior immediately
* Detect anomalous command patterns that deviate from learned normal behavior
* Identify suspicious clusters of events happening in a short time window
* Produce explainable alerts with human-readable reason strings
* Operate in real-time with modest compute resources

The system integrates ideas from the following techniques:

1. **Weighted rule-based scoring** (deterministic detection of known threats)
2. **Autoencoder reconstruction anomaly detection** (inspired by UHAC, Kayhan et al. 2023)
3. **Temporal chain detection using Hawkes process** (RAPID, Amaru et al. 2025)

---

## System Architecture

PirateShield processes device events through a **three-layer detection pipeline**

```
Device Event (JSON)
      |
      v
Field Normalization
(user_id, device_id, event_type, timestamp)
      |
      +------------------+------------------+
      v                  v                  v
Layer 1:           Layer 2:           Layer 3:
Rule-Based         UHAC: Command      RAPID: Chain
Scoring            Anomaly            Detection
      |                  |                  |
      +------------------+------------------+
                         |
                         v
                  Score Combination
                         |
                         v
                  Clamp to 0-100
                         |
                         v
              Alert Generation + Reasons
```

Each layer produces a **partial score**, which is combined into a final **DeviceRisk** score.

---

## Data Collected From Device Events

PirateShield extracts the following fields from each endpoint event:

| Feature                | Description                                           |
| ---------------------- | ----------------------------------------------------- |
| event_type             | process_start, cpu_spike, usb_event, security_change  |
| device_id              | Unique identifier for the device                      |
| user_id                | Student or staff identifier                           |
| timestamp              | Event timestamp (ISO 8601)                            |
| process_name           | Name of the process that triggered the event          |
| process_path           | File path of the process binary                       |
| suspicious             | Boolean flag from endpoint agent                      |
| cpu_percent            | Current CPU usage percentage                          |
| baseline_cpu           | Historical average CPU for this device                |
| duration_seconds       | How long the CPU spike lasted                         |
| usb_id                 | Identifier for inserted USB device                    |
| usb_action             | connected / removed                                   |
| new_executable_started | Whether a USB insertion triggered an .exe launch      |
| exe_path               | File path of the launched executable                  |
| component              | Security component affected (e.g., firewall)          |
| new_status             | New status of the component (enabled / disabled)      |

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

```
S_rules = SUM( w_i * 1[R_i(e)] )
```

Where:
- `e` is the device event being scored
- `R_i` is the i-th detection rule (returns true or false)
- `1[R_i(e)]` is the indicator function (1 if the rule triggers, 0 otherwise)
- `w_i` is the fixed severity weight assigned to rule i

We assign severity weights based on the assessed risk of each event type in a K-12 endpoint context. <!-- TODO: consider finding a citation for rule-based weighted scoring in IDS literature -->

---

## Rule Definitions and Weights

| Rule | Condition | Points (w_i) |
| ---- | --------- | ------------- |
| R1: Suspicious process flag | `suspicious == true` | +40 |
| R2: Known-bad process name | `process_name` is in suspicious process list | +35 |
| R3: USB launched executable | `usb_event` AND `new_executable_started == true` | +45 |
| R4: Sustained CPU spike | `cpu_percent / baseline_cpu >= 2.5` AND `duration >= 600s` | +30 |
| R5: Brief CPU spike | `cpu_percent / baseline_cpu >= 2.5` (not sustained) | +10 |
| R6: Security component disabled | `security_change` AND `new_status == disabled` | +50 |

**Suspicious process list** (examples): `wireguard`, `openvpn`, `tor`, `proxychains`, `nmap`, `netcat`, `mimikatz`, `metasploit`

**Note:** R1 and R2 have overlap protection. If both trigger for the same process, only the higher-scoring one counts.

---

## Rule Score Range

The theoretical maximum of `S_rules` (if every rule triggered simultaneously) is approximately 160 before clamping. In practice, most single events trigger 1-2 rules. The fact that rules can push past 100 before clamping is intentional - it means a single severe event (like a USB-launched executable on a device with its firewall disabled) can immediately reach critical severity on its own, without needing the anomaly layers.

---

# Detection Layer 2: UHAC-Inspired Command Anomaly Detection (Autoencoder)

## Purpose

Detect anomalous process behavior by learning what normal endpoint activity looks like and flagging events that deviate from that learned baseline.

This layer is inspired by the UHAC method (Kayhan et al., 2023), which demonstrated that autoencoders trained on normal command patterns can effectively surface suspicious endpoint activity through reconstruction error. PirateShield implements a similar autoencoder-based approach for process-level anomaly detection on endpoint devices.

---

## Feature Extraction

Before the autoencoder can process endpoint events, raw system call traces must be converted into fixed-length numeric feature vectors. Following the approach in Zhang et al. (2021), who formalized feature extraction methods for host-based intrusion detection, PirateShield uses **term frequency (TF)** to represent each trace segment as a vector.

The system call stream is divided into fixed-length segments of size `L_s`. For each segment, the term frequency of each system call symbol is computed as:

```
tf(S, T_s) = count of symbol S in T_s / count of system calls in T_s
```

(Zhang et al. 2021, Eq. 3)

Where:
- `S` is a system call symbol (e.g., read, write, open, execve)
- `T_s` is one segment of the system call trace

This produces a fixed-length feature vector for each segment, where each dimension represents the relative frequency of one system call type within that segment.

**Why TF over TF-IDF?** Zhang et al. (2021) evaluated both TF and TF-IDF as feature extraction methods for host-based anomaly detection and found that TF provides nearly identical detection performance to TF-IDF while requiring significantly less computation time. They also observed that the IDF factor extracted from only training data introduces distortion when applied to test data, leading to degraded performance. Based on these findings, we adopt TF as our feature extraction method.

---

## Autoencoder Architecture

An autoencoder is a neural network trained to reconstruct its own input. It consists of:

- **Encoder**: compresses the input feature vector into a lower-dimensional latent representation
- **Decoder**: reconstructs the original feature vector from the latent representation

The autoencoder is trained exclusively on **normal** (non-attack) system call trace segments. During training, it learns a compressed representation of what normal endpoint behavior looks like. After training, when a new trace segment is fed through the autoencoder, the reconstruction error measures how different the segment is from learned normal patterns.

```
ReconstructionError = || Input - ReconstructedOutput ||
```

Normal traces produce low reconstruction error because the autoencoder has learned their patterns. Anomalous traces produce high reconstruction error because the autoencoder has never seen behavior like them and cannot reconstruct it accurately.

This principle is the core insight from UHAC (Kayhan et al., 2023): commands that the model cannot reconstruct well are strong candidates for threat investigation.

---

## Command Anomaly Score

The reconstruction error is normalized to produce a score in the range [0, 1]:

```
AnomalyScore = ReconstructionError / MaxExpectedError
```

Where `MaxExpectedError` is calibrated from the training data (e.g., the maximum reconstruction error observed on the normal validation set, or a chosen percentile threshold).

Range:
- 0 - normal behavior, well-reconstructed
- 1 - highly anomalous, poorly reconstructed

---

## Contribution to Final Score

The anomaly score is scaled and **capped at a maximum of 20 points**:

```
AnomalyPoints = min(AnomalyScore * 20, 20)
```

**Why cap at 20?** Rule-based signals are directly interpretable ("the firewall was disabled"). An autoencoder anomaly signal says "this behavior deviates from learned normal patterns" - it does not confirm malice. Capping prevents a rare-but-benign trace (like a software update changing system call patterns) from dominating the score. The cap ensures that the autoencoder acts as a **triage nudge**, not a conviction.

---

## Evaluation Dataset: ADFA-LD

The autoencoder is trained and evaluated using the **ADFA-LD** (Australian Defence Force Academy Linux Dataset), a widely-used benchmark for host-based intrusion detection systems.

ADFA-LD contains:
- **Normal traces**: thousands of system call traces collected from a Linux host during normal operation (web browsing, document editing, routine server tasks)
- **Attack traces**: system call traces from six attack types including Hydra-FTP, Hydra-SSH, Adduser, Java-Meterpreter, Meterpreter, and Webshell

The dataset is specifically designed for evaluating system-call-based HIDS and has been used in dozens of published papers (Creech & Hu, 2013; Xie et al., 2014; Zhang et al., 2021).

**Training procedure**: The autoencoder is trained on normal traces only, using K-fold cross-validation (K=10) following the evaluation methodology established by Zhang et al. (2021). Attack traces are used exclusively for testing. Detection performance is measured using TPR, FPR, and AUC.

---

# Detection Layer 3: RAPID-Inspired Chain Detection (Hawkes Process)

## Purpose

Detect when multiple suspicious events cluster together in a short time window on the same device, because chains of events are more suspicious than isolated events.

This layer is inspired by the RAPID framework (Amaru et al., 2025), which demonstrated that analyzing sequences of system events - rather than isolated events - significantly improves detection of multi-step attacks on endpoints. PirateShield adapts this insight into a lightweight temporal scoring approach using the Hawkes process framework.

---

## How It Works

The mathematical foundation comes from Zheng, Yuan & Wu (2021), who formalized the Hawkes process for insider threat detection on security event streams.

The Hawkes process is a self-exciting temporal point process where the occurrence of past events increases the likelihood of future events. Its conditional intensity function is defined as:

```
lambda*(t) = lambda_0 + SUM( gamma(t, t_i) )
```

(Zheng, Yuan & Wu 2021, Eq. 6)

Where:
- `lambda_0 > 0` is the base intensity, independent of event history
- `gamma(t, t_i)` is a triggering kernel - a monotonically decreasing function so that recent events have more influence on the upcoming event's intensity
- The sum is over all previous events `t_i` in the history

The key idea: **each recent suspicious event increases the current intensity, and that contribution fades over time.** Three suspicious events in 5 minutes produce a much higher intensity than three events spread over 3 hours. Zheng et al. describe this as the "self-excitation" property where "the occurrence likelihood of an upcoming event increases due to previous events which have just occurred."

---

## PirateShield Adaptation

PirateShield uses a simplified form of the Hawkes intensity with an exponential decay kernel bounded within a fixed time window `W`:

```
C_chain(t, d) = SUM( s_i * e^(-lambda * (t - t_i)) )
               for all events i on device d where (t - t_i) <= W
```

Where:
- `t` is the current time
- `d` is the device being scored
- `s_i` is the suspicion score of event `i` (from Layer 1 or Layer 2, whichever is higher)
- `t_i` is the timestamp of event `i`
- `lambda` is the decay rate (controls how fast old events lose influence)
- `W` is the window size (e.g., 600 seconds / 10 minutes)

Events outside the window (`t - t_i > W`) contribute zero. Within the window, recent events contribute more than older events due to the exponential decay.

This is a special case of the Hawkes intensity (Zheng et al. 2021, Eq. 6) where the triggering kernel `gamma(t, t_i)` is nonzero only within the window and takes an exponential decay form. The exponential kernel is a standard choice in the Hawkes process literature for modeling temporal self-excitation with monotonic decay.

**What feeds into the chain:** Each event's suspicion score is determined by:
```
s_i = max(S_rules_i, AnomalyPoints_i)
```
This means events flagged by either rules or the autoencoder contribute to the chain intensity. An event that scored zero on both layers contributes nothing.

---

## Chain Score

The raw chain value is normalized to produce a score in [0, 1]:

```
ChainNorm = C_chain(t, d) / C_max
```

Where `C_max` is the maximum expected chain intensity, calibrated from fleet data or set analytically.

---

## Contribution to Final Score

The chain detection score is scaled and **capped at a maximum of 15 points**:

```
ChainPoints = min(ChainNorm * 15, 15)
```

**Why cap at 15?** The chain signal is a pattern indicator, not a direct detection. A cluster of 3 mild events in 10 minutes might warrant investigation, but it should never score higher than a single confirmed rule trigger like "firewall disabled" (+50). The cap ensures chains boost the score without overpowering concrete evidence.

---

# Composite Risk Scoring

## Score Combination

PirateShield combines all three layers into a single risk score:

```
DeviceRisk = min(S_rules + AnomalyPoints + ChainPoints, 100)
```

Where:
- `S_rules` = sum of all triggered rule weights (Layer 1)
- `AnomalyPoints` = min(AnomalyScore * 20, 20) (Layer 2)
- `ChainPoints` = min(ChainNorm * 15, 15) (Layer 3)

---

## Why This Structure?

| Layer                      | Max Contribution    | Role                                          |
| -------------------------- | ------------------- | --------------------------------------------- |
| Rule-based scoring         | ~160 (before clamp) | Main driver - deterministic, explainable       |
| UHAC: command anomaly      | +20                 | Triage nudge for anomalous command patterns    |
| RAPID: chain detection     | +15                 | Triage nudge for clustered suspicious events   |

Rule-based scoring is intentionally the heaviest driver. The anomaly layers act as confidence nudges on top. A concrete rule trigger like "firewall disabled" (+50) always outweighs a borderline anomaly signal on its own. But when base rules produce a low score and both anomaly layers fire, they can push a borderline event into alert range - which is exactly the behavior we want.

Each layer covers a different blind spot:
- **Layer 1** catches known threats instantly but is blind to anything not on the rule list
- **Layer 2** catches unknown/novel threats through learned behavior deviation but looks at events in isolation
- **Layer 3** catches coordinated multi-step behavior that looks innocuous in isolation but is suspicious as a sequence

---

## Risk Score Interpretation

| Risk Score | Severity | Action                   |
| ---------- | -------- | ------------------------ |
| 0 - 14     | None     | No action                |
| 15 - 34    | Low      | Log for review           |
| 35 - 59    | Medium   | Monitor device           |
| 60 - 84    | High     | Flag for investigation   |
| 85 - 100   | Critical | Immediate security alert |

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
| ----- | -------------- | ------ |
| 1     | `ngrok` not on suspicious list, `suspicious` flag = false | +0 |
| 2     | `tun2socks` not on suspicious list, `suspicious` flag = false | +0 |
| 3     | Brief CPU spike (ratio >= 2.5, not sustained) - R5 | +10 |
| **Total** | | **S_rules = 10** |

Base rules alone: score of **10** - below every alert threshold.

---

## Layer 2: Command Anomaly Detection

The autoencoder was trained on normal ADFA-LD traces. The trace segment containing `ngrok` and `tun2socks` system calls is fed through the autoencoder.

```
ReconstructionError = 0.73 (out of MaxExpectedError = 0.85)
AnomalyScore = 0.73 / 0.85 = 0.859
AnomalyPoints = min(0.859 * 20, 20) = 17.2
```

The autoencoder contributes **+17 points** because the system call patterns from these processes look nothing like the normal behavior it was trained on.

---

## Layer 3: Chain Detection

Three events within a 10-minute window on the same device. Using `lambda = 0.005` (per second) and `W = 600s`:

Each event's suspicion score:
```
Event 1 (ngrok):     s_1 = max(0, 17.2) = 17.2
Event 2 (tun2socks): s_2 = max(0, 17.2) = 17.2
Event 3 (cpu spike):  s_3 = max(10, 0) = 10
```

At the time of event 3 (t = 10:08:00):
```
Event 1: 17.2 * e^(-0.005 * 480) = 17.2 * 0.091 = 1.57
Event 2: 17.2 * e^(-0.005 * 300) = 17.2 * 0.223 = 3.84
Event 3: 10.0 * e^(-0.005 * 0)   = 10.0 * 1.000 = 10.00

C_chain = 1.57 + 3.84 + 10.00 = 15.41
```

Assuming `C_max = 25` (calibrated from fleet data):
```
ChainNorm = 15.41 / 25 = 0.616
ChainPoints = min(0.616 * 15, 15) = 9.2
```

The chain layer contributes **+9 points**.

---

## Final Score

```
DeviceRisk = min(10 + 17 + 9, 100) = 36
```

**Result: Medium severity - Monitor device**

---

## Why This Matters

Pure rule-based scoring would have produced a score of **10** - below every alert threshold, nothing happens. The autoencoder flagged that the system call patterns from `ngrok` and `tun2socks` were unlike anything in the learned normal baseline, and the chain layer recognized that multiple suspicious events clustered in a short window. Together they surfaced something worth a human looking at.

**Alert reason string:**
> Brief CPU spike - Anomalous command patterns detected (reconstruction error: 0.86) - Multiple suspicious events in short window (3 events in 10 min)

---

# Alert Generation

PirateShield produces human-readable alerts:

```
PirateShield Security Alert

Type: Endpoint Device Anomaly

Details:
- Brief CPU spike: 3.1x baseline
- Anomalous process behavior detected (reconstruction error: 0.86)
- Multiple events clustered in 10-minute window

Risk Score: 36
Severity: Medium
Device: lab-01
User: student_lab_01
```

---

# Evaluation Plan

## Dataset

ADFA-LD (Australian Defence Force Academy Linux Dataset)
- Source: https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/IFTZPF
- Labeled version: github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset
- Normal traces: system call sequences from routine Linux host operation
- Attack traces: six attack categories (Hydra-FTP, Hydra-SSH, Adduser, Java-Meterpreter, Meterpreter, Webshell)

## Methodology

1. Convert raw system call traces into TF feature vectors using segmentation (Zhang et al. 2021)
2. Train autoencoder on normal traces using 10-fold cross-validation
3. Run trained model against attack traces and compute reconstruction errors
4. Apply Layer 1 rules, Layer 2 autoencoder scores, and Layer 3 chain detection
5. Report composite DeviceRisk scores for both normal and attack traces

## Metrics

- True Positive Rate (TPR): proportion of attack traces correctly flagged
- False Positive Rate (FPR): proportion of normal traces incorrectly flagged
- Area Under ROC Curve (AUC): overall detection capability
- Comparison: composite model (all 3 layers) vs Layer 1 only, to demonstrate that Layers 2 and 3 improve detection

---

# Sources

- **UHAC (conceptual inspiration for Layer 2):** Kayhan, V.O., Agrawal, M., & Shivendu, S. (2023). *Cyber threat detection: Unsupervised hunting of anomalous commands (UHAC).* Decision Support Systems, 168, 113928. doi: 10.1016/j.dss.2023.113928

- **RAPID (conceptual inspiration for Layer 3):** Amaru, Y., Wudali, P.N., Elovici, Y., & Shabtai, A. (2025). *RAPID: Robust APT detection and investigation using context-aware deep learning.* Computer Networks, 273, 111744. doi: 10.1016/j.comnet.2025.111744

- **TF feature extraction for host-based anomaly detection (Layer 2 feature extraction, Eq. 3):** Zhang, L., Cushing, R., de Laat, C., & Grosso, P. (2021). *A real-time intrusion detection system based on OC-SVM for containerized applications.* Proc. IEEE 24th Int. Conf. on Computational Science and Engineering (CSE 2021), pp. 138-145. doi: 10.1109/CSE53436.2021.00029

- **Hawkes process for security event streams (Layer 3 temporal intensity, Eq. 6):** Zheng, P., Yuan, S., & Wu, X. (2021). *Using Dirichlet Marked Hawkes Processes for Insider Threat Detection.* Digital Threats: Research and Practice, 3(1), Article 5. doi: 10.1145/3457908

- **ADFA-LD benchmark dataset:** Creech, G. & Hu, J. (2013). *A Semantic Approach to Host-Based Intrusion Detection Systems Using Contiguous and Discontiguous System Call Patterns.* IEEE Transactions on Computers, 63, 807-819.

---

# Future Improvements

Future PirateShield endpoint versions may incorporate:

* `cmdline` field for full command-line feature extraction (character n-gram features as in UHAC)
* Memory usage anomaly detection (`mem_percent` / `baseline_mem`)
* Device-switching correlation (rapid switching between devices as a suspicion signal)
* Adaptive decay rate `lambda` tuned via threshold optimization
* Per-device fleet baselines that update on a rolling 30-day window
* Full provenance graph analysis following RAPID's methodology (contingent on expanded audit log collection from endpoint devices)
