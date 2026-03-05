# Research Paper Summaries

1. **MITRE ATT&CK-Driven Threat Analysis for Edge-IoT and a Quantitative Risk Scoring Model**
**Authors:** Yun & Min | **Published:** 2025 | **Source:** CMES 145(2) | View PDF
This paper proposes a quantitative risk scoring model for Edge-IoT environments by mapping MITRE ATT&CK threat categories to CVSS vulnerability scores. It combines four weighted components — impact, frequency, detection difficulty, and kill chain stage — into a single normalized risk score. Frequency scoring uses Laplace smoothing with log transformation, detection uses a DNN classifier trained with focal loss, and difficulty maps nonlinearly to Cyber Kill Chain stages. Validated on the Edge-IIoTset dataset (14 attack types, 1.9M records) with Spearman's ρ ≥ 0.9.

**Key Idea:** Normalize CVSS impact + Laplace-smoothed frequency + DNN detection score + Kill Chain difficulty → weighted additive risk score → rank and prioritize threats.

2. **Model-Based Structural and Behavioral Cybersecurity Risk Assessment in System Designs**
**Authors**: Jungebloud et al. | Published: 2025 | Source: Computers & Security 157 | View PDF
This paper proposes a formal risk assessment methodology using UML system models transformed into attack graphs, then simulated using Deterministic and Stochastic Petri Nets (DSPN). Static metrics like number of attack paths and path length are computed from graph traversal, while dynamic metrics like Mean Time to Compromise (MTTC) are derived from Petri net simulation across three attacker profiles (Layman, Proficient, Expert). Validated on a BMW in-vehicle network case study, the model quantifies how patching and IDPS deployment reduce overall risk scores.

**Key Idea:** UML model → graph transformation → BFS/DFS attack path extraction → DSPN simulation with attacker profiles → MTTC and probabilistic risk scores.

3. **A Cyber Risk Economics Model for Organization-Wide Risk Management (CYREM-ORM)**
**Authors**: Tong Xin, Ying He, Efpraxia D. Zamani, Mark Evans, Cunjin Luo | **Published:** 2026 | **Source:** Computers & Security 165 | View PDF
This paper proposes CYREM-ORM, a model that translates Cyber Threat Intelligence (CTI) into financial loss estimates by mapping STIX-formatted threat data to the FAIR risk framework. Threat actor relevance is scored across capability, motivation, goals, location, and sector using Noisy-OR aggregation. Loss magnitude is modeled using PERT distributions for both primary losses (incident response, business interruption) and secondary losses (regulatory fines, reputational damage), then propagated through 100,000-iteration Monte Carlo simulation to produce annual loss distributions. Validated across three case studies including the 2017 Equifax breach and an SME education consulting company.

**Key Idea:** STIX CTI → FAIR factor mapping → TEF and LEF estimation → PERT loss distributions → Monte Carlo simulation → monetized annual risk output.

4. **Policy-Driven Contextual Risk Evaluation in OAuth 2.0 Authentication Frameworks for AI Chatbot-Based RPA Systems**
**Authors:** Soonhong Kwon, Wooyoung Son, Jong-Hyouk Lee | **Published:** 2025 | **Source:** Computers and Electrical Engineering 128 | View PDF
This paper proposes a context-aware risk scoring framework integrated into an OAuth 2.0 authentication flow for AI chatbot-RPA systems. Risk is calculated by combining context importance weights (location, connection type, time zone, activity sensitivity) with a sigmoid-based sensitivity response function φ(x) = 1/(1+e^(-k(x-μ))), where k controls slope steepness and μ sets the risk inflection point. The resulting score is compared against a policy threshold to issue Full Access, Limited Access, or Access Denied tokens. Validated through high-risk and normal scenario experiments and STRIDE threat simulations with average latency of 9.22ms.

**Key Idea:** Collect contextual signals → apply sigmoid sensitivity function per context → multiply by access control matrix → compare against threshold → issue tiered access token.

5. **Anomaly detection in heterogeneous cybersecurity data**
**Authors:** S.A. Okolie, C.A. Amadi, J.N. Odii, E.C. Nwokorie, U․C Onyemauche | **Published:** 2025 | **Source:** Franklin Open 13 | [View PDF](./research-papers/Anomaly_detection_in_heterogeneous_cybersecurity_data.pdf)

This paper explores the application of anomaly detection techniques in heterogeneous cybersecurity data, encompassing network traffic logs, endpoint telemetry, user activity, and external threat intelligence. It examines the role of machine learning, deep learning, and statistical models in processing and correlating these diverse datasets to identify threats with improved accuracy and speed. The discussion includes challenges such as managing data diversity, scalability, and balancing sensitivity with specificity in detection. Through a review of case studies and recent advancements, the paper highlights successful implementations of anomaly detection, including hybrid approaches combining unsupervised learning with domain expertise. This
work underscores the importance of anomaly detection in safeguarding digital ecosystems against increasingly sophisticated cyber threats.