# What and How: Approaches to Network Anomaly Detection

## Overview

The five articles each answer the question of *how* to detect network anomalies 
differently. Together, they represent a spectrum of approaches, from 
statistical models to deep learning to large language models, each with 
distinct strengths and tradeoffs relevant to PirateShield's network layer.

---

## Approach 1: Statistical Time-Series Forecasting (SARIMA)
**From:** Real-time SARIMA-based Anomaly Detection in Operator Networks

### What It Does
SARIMA models the expected pattern of network traffic over time using 
historical data. It forecasts what traffic *should* look like at any given 
moment, then flags moments where the real traffic deviates beyond a threshold.

### How It Works
1. Apply a Box-Cox transformation to stabilize traffic variance
2. Fit a SARIMA model using daily/weekly seasonal periods
3. At each time step, compare predicted vs. actual traffic
4. Normalize the residual and compare to a threshold
5. Use pruning logic to eliminate mirror and consecutive false positives
6. Run via Kalman filter for real-time efficiency (400x faster than ARIMA)

### Strengths for PirateShield
- Explainable: you can see exactly why something was flagged
- Effective for catching **traffic spikes and sudden drops**
- Reduces false positives significantly with pruning
- Runs in real-time with low computational cost

### Limitations
- Works best for **volume-based anomalies** (not behavior or identity)
- Requires historical baseline data to be accurate
- May miss slow, gradual attacks that stay below the threshold

---

## Approach 2: Deep Learning Feature Extraction + Clustering (CNN + RNN + DBSCAN)
**From:** Network Anomaly Detection Algorithm Based on Deep Learning and Data Mining

### What It Does
Uses deep learning to extract high-level features from raw traffic, then 
uses density-based clustering (DBSCAN) to separate normal behavior clusters 
from outlier anomalies.

### How It Works
1. Collect raw traffic data (IP, ports, protocols, packet sizes, timestamps)
2. Use CNN to extract spatial patterns across packet sequences
3. Use RNN to model time-series behavior across connections
4. Feed extracted features into DBSCAN
5. DBSCAN identifies core clusters (normal behavior) and noise points (anomalies)
6. Analyze noise points for context and proximity to clusters

### Strengths for PirateShield
- Does not require labeled anomaly data to train
- Automatically discovers behavioral clusters without specifying number of groups
- Handles noisy, real-world traffic well
- Good at detecting **unknown attack patterns**

### Limitations
- DBSCAN performance depends heavily on choosing good parameters (ε and MinPts)
- Computationally heavier than statistical methods
- May flag rare-but-legitimate behaviors (e.g., late-night maintenance) as anomalies

---

## Approach 3: Deep Q-Network + Autoencoder (Reinforcement Learning)
**From:** Network Traffic Anomaly Detection and Malicious Behavior Simulation

### What It Does
Combines a Deep Q-Network (reinforcement learning) for adaptive traffic 
control with an autoencoder for anomaly detection. Builds a multi-level 
detection matrix that flexibly responds to changing attack conditions.

### How It Works
1. Reduce dimensionality of raw traffic data using T-SNE
2. Build a multi-level detection matrix using a BiGAN framework
3. Use the Deep Q-Network to adaptively navigate the traffic state space
4. Use the autoencoder to identify traffic that cannot be well-reconstructed 
   (i.e., anomalous)
5. Lock in abnormal traffic and simulate malicious behavior for validation

### Strengths for PirateShield
- Adaptive: the model updates its behavior as traffic patterns change
- Works well in **malicious attack simulation scenarios** (DDoS, Trojans)
- F1 value of 0.8 is stable across 7 different traffic cycles

### Limitations
- Complex to implement and tune
- Designed more for enterprise/ISP scale; may be over-engineered for a school pilot
- Requires significant compute resources

---

## Approach 4: Transformer GAN (T-GAN)
**From:** T-GAN: Transformer-based Generative Adversarial Network

### What It Does
Trains a GAN entirely on normal traffic. The generator learns what normal 
traffic looks like, and the discriminator learns to score how "normal" any 
given traffic is. High anomaly scores flag suspicious traffic.

### How It Works
1. Pre-process KDD CUP 99 traffic data using sliding windows
2. Pre-train: align synthetic (generated) traffic features with real normal traffic
3. Adversarial training: generator tries to fool discriminator; 
   discriminator gets better at spotting fakes and real anomalies
4. At detection time: run traffic through the discriminator's anomaly scoring head
5. High anomaly score = flag the traffic

### Strengths for PirateShield
- Does not need labeled anomaly examples, only normal traffic to train on
- Multi-head attention captures **long-range dependencies** (slow attacks, 
  distributed behavior)
- Near-perfect recall (99.99%) and misses almost nothing
- Naturally handles the class imbalance problem

### Limitations
- Requires significant training data of normal traffic first
- High false positive rate without careful tuning
- Computationally heavy (Transformer + GAN training)
- Harder to explain to non-expert users why something was flagged

---

## Approach 5: Large Language Model for Multimodal Anomaly Detection (NS-LLM)
**From:** Anomalous Network Access Detection with Large Language Model

### What It Does
Converts network traffic, user behavior logs, and system logs into natural 
language, then uses a fine-tuned LLM to reason about whether access behavior 
is anomalous. The LLM uses cross-domain reasoning to connect patterns across 
multiple data sources.

### How It Works
1. Collect multimodal data: traffic logs (F), user behavior (A), system logs (L)
2. Convert structured data into natural language using description templates
3. Fuse all three sources into a unified prompt using prompt learning
4. Pass the prompt to NS-LLM (fine-tuned on cybersecurity corpus)
5. The model outputs: normal or anomalous, plus the type of anomaly

### Strengths for PirateShield
- Best at detecting **complex, multi-step, cross-layer anomalies** 
  (exactly what PirateShield's Month 4 correlation engine needs)
- Outputs human-readable explanations, aligns with PirateShield's goal 
  of clear alert descriptions
- High accuracy (85.8%) and strong cross-domain reasoning

### Limitations
- Requires significant compute for LLM inference
- Needs a large high-quality training corpus (this paper used 430,000 items)
- Not yet practical for real-time deployment at the school level
- Black-box reasoning can be hard to audit

---

## Summary Comparison Table

| Approach       | Best For                        | Real-Time? | Explainable? | False Positive Risk |
|----------------|---------------------------------|------------|--------------|---------------------|
| SARIMA         | Traffic volume spikes/drops     | Yes        | High         | Low (with pruning)  |
| CNN+RNN+DBSCAN | Unknown behavioral patterns     | Moderate   | Medium       | Medium              |
| DQN+Autoencoder| Adaptive attack simulation      | Moderate   | Low          | Low                 |
| T-GAN          | Long-range temporal threats     | No         | Low          | Medium-High         |
| NS-LLM         | Multi-layer correlated anomalies| No         | Very High    | Low                 |

---

## What This Means for PirateShield's Network Layer

For PirateShield's Month 1-2 foundation work, the **SARIMA and DBSCAN 
approaches** are the most practical, they are explainable, implementable 
with synthetic data, and directly address traffic spike and behavioral 
baseline detection.

For Month 3-4 when correlation and multi-layer detection become the focus, 
the **NS-LLM multimodal fusion idea** provides the strongest conceptual 
framework for combining identity, device, and network signals into 
unified, human-readable alerts.

The **T-GAN recall rate** (99.99%) is the benchmark PirateShield should 
aim for in terms of not missing real threats, while the **SARIMA pruning 
strategy** is the model for keeping false positives under control.