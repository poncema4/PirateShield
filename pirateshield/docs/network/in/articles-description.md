# Articles Description

## 1. Anomalous Network Access Detection with Large Language Model
**Authors:** Lei Zhang, Jiaxuan Wu, et al. | **Published:** 2025 | **Source:** ACM CNSSE 2025 | [View PDF](./articles/Anomalous_network_access_detection_with_LLM.pdf)

This paper proposes using a Large Language Model (LLM) to detect abnormal 
network access behavior. It combines three data types like network traffic logs, 
user behavior data, and system logs, converting them into natural language 
so the LLM can reason about them. The model (called NS-LLM) is fine-tuned on 
cybersecurity data and outperforms traditional models with an 85.8% accuracy 
and 84.5% F1-score.

**Key Idea:** Fuse multimodal data (traffic + behavior + logs) into natural 
language → feed into a domain-specific LLM → detect complex anomalies.

---

## 2. Network Anomaly Detection Algorithm Based on Deep Learning and Data Mining
**Author:** Yiting Li | **Published:** 2024 | **Source:** ACM CNSCT 2024 | [View PDF](./articles/Anomaly_detection_algorithm_based_on_deep_learning_and_data_mining.pdf)

This paper combines CNN and RNN deep learning models with the DBSCAN clustering 
algorithm to detect network threats. CNNs capture spatial patterns in traffic 
packets, RNNs model sequential/time-series behavior, and DBSCAN identifies 
outlier "noise points" as potential anomalies. Evaluated on the KDD Cup 99 
dataset, it outperforms traditional machine learning and autoencoder methods 
in both precision and recall stability.

**Key Idea:** Extract features with CNN + RNN → cluster with DBSCAN → 
flag outlier points as anomalies.

---

## 3. Network Traffic Anomaly Detection and Malicious Behavior Simulation 
**Authors:** Yongda Lu, Shan Xu | **Published:** 2024 | **Source:** ACM CNSCT 2024 | [View PDF](./articles/Network_traffic_anomaly_detection_and_malicious_behavior_simulation_analysis.pdf)

This paper designs a multi-level anomaly detection system that combines a 
Deep Q-Network (DQN) for reinforcement-learning-based traffic control and 
an autoencoder for pattern recognition. It reduces traffic data dimensionality 
using T-SNE and builds a multi-level detection matrix using a BiGAN framework. 
Tested across 7 traffic cycles, the final F1 value consistently reaches 0.8, 
even under simulated DDoS and Trojan attack conditions.

**Key Idea:** Dimensionality reduction → multi-level detection matrix (BiGAN) 
→ Deep Q-Network + autoencoder → detect and simulate malicious behavior.

---

## 4. Real-time SARIMA-based Anomaly Detection in Operator Networks
**Authors:** Pablo Fondo-Ferreiro, et al. | **Published:** 2026 | **Source:** Computer Networks (Elsevier) | [View PDF](./articles/Real-time_SARIMA-based_anomaly_detection_in_operator_networks.pdf)

This paper proposes a statistical time-series approach using SARIMA (Seasonal 
AutoRegressive Integrated Moving Average) to detect traffic volume anomalies 
in real-time operator networks. It introduces a "SARIMA-pruned" version that 
significantly reduces false positives by ignoring mirror and consecutive 
anomaly artifacts. Deployed via Kalman filters for real-time efficiency, the 
system is 400x faster than standard ARIMA and was validated on real nationwide 
operator traffic data.

**Key Idea:** Forecast expected traffic with SARIMA → compare residuals against 
threshold → prune false positives → detect real anomalies in real-time.

---

## 5. T-GAN: Transformer-based Generative Adversarial Network for Network 
Traffic Anomaly Detection
**Authors:** Weimin Yin, Chao Wang, Yifan Qin | **Published:** 2025 | **Source:** ACM CNCC 2025 | [View PDF](./articles/T-GAN_for_network_traffic_anomaly_detection.pdf)

This paper proposes T-GAN, a GAN model where both the generator and 
discriminator use Transformer architecture with multi-head self-attention. 
The generator learns the distribution of normal traffic, and deviations from 
that distribution flag anomalies. This design solves two major problems: 
long-range temporal dependency in traffic sequences and class imbalance 
(very few labeled anomaly samples). On KDD CUP 99, T-GAN achieves 99.99% 
recall and 95.68% accuracy, outperforming MAD-GAN and E-GAN.

**Key Idea:** Train GAN on normal traffic using Transformers → use reconstruction error and discriminator score to detect anomalies → near-perfect recall.