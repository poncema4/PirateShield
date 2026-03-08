# Articles Description

## 1. UHAC: Unsupervised Host-based Anomaly Detection for Process Auditing

**Authors:** Kayhan et al. | **Published:** 2023 | **Source:** Decision Support Systems (Elsevier) | [View](https://www.sciencedirect.com/science/article/abs/pii/S0167923623000039)

This paper presents an unsupervised anomaly detection approach for identifying suspicious command and process activity in system audit logs collected from endpoint devices. The method converts command-line and process execution data into feature vectors using token-level features and character n-grams, allowing the system to capture unusual or obfuscated commands that may indicate malicious behavior. An autoencoder model is trained on normal system activity and used to reconstruct expected command patterns. The difference between the observed command and the reconstructed command (reconstruction error) is used as an anomaly score.

The authors show that this method can effectively prioritize suspicious events for investigation. By ranking commands by anomaly score, security analysts can review only the highest-scoring events and still identify the majority of abnormal behavior.

**Key Idea:** Convert process and command logs into feature vectors → train an autoencoder on normal behavior → use reconstruction error to rank suspicious endpoint activity.

---

## 2. RAPID: Provenance-based Adaptive Intrusion Detection for Endpoint Systems

**Authors:** Amaru et al. | **Published:** 2025 | **Source:** Computer Networks (Elsevier) | [View](https://www.sciencedirect.com/science/article/abs/pii/S1389128625007108)

This paper introduces RAPID, a provenance-based intrusion detection system designed to analyze system audit logs and identify complex attack behavior on endpoint devices. Instead of examining events independently, RAPID constructs provenance graphs that represent relationships between processes, files, and network connections. These graphs capture how system activity unfolds over time and allow the detection system to identify suspicious sequences of events rather than isolated anomalies.

By analyzing these relationships, RAPID can detect multi-step attack behaviors that may appear normal when individual events are viewed separately. The system also provides contextual information that helps analysts understand how an attack progressed through the system, improving both detection accuracy and investigation efficiency.

**Key Idea:** Build provenance graphs from endpoint logs → detect anomalous chains of system activity → trace attack paths to explain suspicious behavior.
