# Network Anomaly Detection Model

## Overview

PirateShield’s network layer detects anomalous traffic using a **hybrid anomaly detection model** by multiple network anomaly detection articles presented. The model combines statistical forecasting, behavioral clustering, and reconstruction-based anomaly detection to produce a **single interpretable risk score**.

This approach allows PirateShield to:

* Detect traffic spikes and drops
* Identify unknown behavioral patterns
* Detect subtle traffic anomalies
* Produce explainable alerts
* Operate in real-time with modest compute resources

The system integrates ideas from the following techniques:

1. **SARIMA time-series forecasting**
2. **CNN + RNN feature extraction with DBSCAN clustering**
3. **Autoencoder reconstruction anomaly detection**
4. **Multimodal reasoning concepts from LLM anomaly detection research**

---

## System Architecture

PirateShield processes traffic through a **four stage detection pipeline**

```
Network Traffic
      │
      ▼
Feature Extraction
      │
      ▼
Baseline Modeling (SARIMA)
      │
      ▼
Behavior Analysis (DBSCAN)
      │
      ▼
Reconstruction Detection
      │
      ▼
Risk Scoring Engine
      │
      ▼
Alert Generation
```

Each stage produces a **partial anomaly score**, which is combined into a final **riskscore**

---

## Data Collected From Network Traffic

PirateShield extracts features from each network flow

| Feature         | Description             |
| --------------- | ----------------------- |
| src_ip          | Source IP address       |
| dest_ip         | Destination IP address  |
| src_port        | Source port number      |
| dest_port       | Destination port        |
| protocol        | TCP / UDP / ICMP        |
| packet_count    | Packets per connection  |
| byte_volume     | Total bytes transferred |
| duration        | Connection duration     |
| timestamp       | Flow timestamp          |
| connection_rate | Connections per minute  |

These features are used by all anomaly detection layers

---

# Detection Layer 1: Traffic Forecasting (SARIMA)

## Purpose

Detect abnormal traffic spikes or drops compared to historical baseline traffic

This is particularly useful for detecting:

* DDoS traffic spikes
* sudden traffic outages
* unexpected usage bursts

---

## How It Works

A **SARIMA model** predicts expected traffic volume at time t

Expected traffic:

```
ExpectedTraffic(t) = SARIMA forecast
```

Actual observed traffic:

```
ActualTraffic(t)
```

Residual error:

```
Residual(t) = |ActualTraffic(t) − ExpectedTraffic(t)|
```

If the residual exceeds a threshold, the event may represent an anomaly

---

## Traffic Anomaly Score

The residual is normalized using the historical standard deviation of residuals

```
TrafficScore = Residual(t) / σ
```

Where

```
σ = standard deviation of residual errors
```

Normalized range:

```
0 → normal traffic
1 → extremely abnormal traffic
```

---

# Detection Layer 2: Behavioral Clustering (DBSCAN)

## Purpose

Identify **rare or unknown behavior patterns** in network activity

This helps detect:

* port scanning
* unusual connection patterns
* lateral movement behavior

---

## How It Works

Traffic features are clustered using **DBSCAN**

Clusters represent **normal network behaviors**

Points outside clusters are classified as **noise**

```
Cluster → normal behavior
Noise point → anomaly
```

---

## Behavior Score

If the data point is classified as noise:

```
BehaviorScore = 1
```

If the point lies near a cluster boundary:

```
BehaviorScore = distance_to_cluster_center / max_cluster_distance
```

Otherwise:

```
BehaviorScore ≈ 0
```

---

# Detection Layer 3: Reconstruction Anomaly Detection

## Purpose

Detect traffic patterns that differ from known normal patterns

Inspired by **autoencoder anomaly detection models**

---

## How It Works

A model is trained to reconstruct normal network traffic patterns

For each observation:

```
ReconstructionError = |Input − ReconstructedOutput|
```

Large reconstruction errors indicate unusual behavior

---

## Reconstruction Score

Normalized reconstruction anomaly score:

```
ReconstructionScore = ReconstructionError / MaxExpectedError
```

Range:

```
0 → normal
1 → highly anomalous
```

---

## Composite Risk Scoring System

PirateShield combines all anomaly scores into a **single risk score**

```
RiskScore =
    (0.40 × TrafficScore)
  + (0.35 × BehaviorScore)
  + (0.25 × ReconstructionScore)
```

---

## Why These Weights?

| Component           | Weight | Reason                                             |
| ------------------- | ------ | -------------------------------------------------- |
| TrafficScore        | 0.40   | Traffic anomalies are strong indicators of attacks |
| BehaviorScore       | 0.35   | Behavioral anomalies detect unknown threats        |
| ReconstructionScore | 0.25   | Captures subtle anomalies missed by other models   |

The weighted scoring system balances detection accuracy and stability

---

## Risk Score Interpretation

| Risk Score  | Meaning    | Action                   |
| ----------- | ---------- | ------------------------ |
| 0.00 – 0.30 | Normal     | No action                |
| 0.30 – 0.55 | Suspicious | Monitor traffic          |
| 0.55 – 0.75 | High Risk  | Log anomaly alert        |
| 0.75 – 1.00 | Critical   | Immediate security alert |

---

## Example Detection

Example network observation:

```
TrafficScore = 0.7
BehaviorScore = 0.8
ReconstructionScore = 0.5
```

Risk score calculation:

```
RiskScore =
(0.40 × 0.7) +
(0.35 × 0.8) +
(0.25 × 0.5)

RiskScore = 0.69
```

Result:

```
High Risk Network Activity
```

---

# Alert Generation

PirateShield produces human readable alerts

Example alert:

```
PirateShield Security Alert

Type: Network Behavior Anomaly

Details:
• Traffic volume exceeded predicted baseline
• Connection pattern does not match known behavior clusters
• Moderate reconstruction anomaly detected

Risk Score: 0.69
Severity: High
```

---

# Network Graph Model

PirateShield can represent network activity as a **risk graph**

Nodes represent:

```
Devices
IP addresses
Users
Services
```

Edges represent:

```
Network connections
```

Each edge stores a risk score

Example:

```
LaptopA ─── (RiskScore 0.72) ─── ExternalServer
```

High risk edges can form **attack paths** across the network

---

# Advantages of This Hybrid Model

### Strong Detection Coverage

Combines:

* statistical anomaly detection
* behavioral anomaly detection
* reconstruction anomaly detection

---

### Reduced False Positives

SARIMA baseline modeling reduces random traffic fluctuations

DBSCAN clustering prevents rare but normal behaviors from triggering alerts

---

### Explainable Alerts

Each anomaly score component can be shown to users to explain why traffic was flagged

---

# Future Improvements

Future PirateShield versions may incorporate:

* multimodal anomaly detection
* LLM-based correlation of logs and network behavior
* automated threat classification
* adaptive scoring models