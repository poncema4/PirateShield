# Problem Statement

## The Core Problem: Detecting Network Anomalies in Complex Environments

Network anomaly detection is the challenge of identifying unusual or 
suspicious behavior in network traffic that deviates from what is considered 
normal. This is a critical problem in cybersecurity because attackers, 
unauthorized users, and misuse often reveal themselves through abnormal 
network patterns, but these patterns are hard to catch automatically.

---

## Why This Is Hard?

### 1. Traditional Rule-Based Methods Are Not Enough
Rule-based systems like Snort rely on manually written rules to match known 
attack signatures. As shown in the T-GAN and LLM papers, these methods 
**cannot detect zero-day attacks or unknown/evolving threats** because they 
only recognize what they have already seen.

### 2. Network Traffic Is High-Dimensional and Non-Stationary
Traffic data contains dozens of features (IP addresses, ports, packet sizes, 
timestamps, etc.) and changes constantly over time. The Deep Q-Network paper 
highlights that **traditional methods cannot handle this high dimensionality** 
efficiently, and the T-GAN paper notes that traffic is **non-stationary**, 
making static models unreliable.

### 3. Anomalies Are Extremely Rare
The T-GAN paper reports that anomalous traffic samples typically make up only 
**0.1% to 1%** of all network data. This severe class imbalance causes 
supervised models to overfit to normal behavior and miss real attacks. 
Unsupervised methods, on the other hand, tend to produce too many 
false positives.

### 4. Long-Range Temporal Dependencies Are Difficult to Capture
Network attacks often unfold across time, a series of small actions that 
together indicate a threat. The T-GAN and LLM papers both note that CNN and 
basic RNN models **struggle to model long-range dependencies** in sequential 
traffic data, meaning they miss slow or distributed attacks.

### 5. False Positives Are a Real Operational Problem
The SARIMA paper demonstrates that even good detection systems produce too 
many false alarms, which overwhelm security staff and reduce trust in the 
system. **Reducing false positives without sacrificing recall** is one of the 
hardest challenges in anomaly detection.

### 6. Real-Time Detection Is Required
Operator networks and school networks need **live monitoring**, not 
post-analysis. The SARIMA paper's use of Kalman filters addresses this, 
achieving 400x speed improvements, but real-time accuracy remains 
a challenge across all approaches.

---

## The Problem in the Context of PirateShield

PirateShield faces all of these same challenges in a K-12 school environment:

- **School network traffic is complex and high-volume**, mixing normal student 
  activity (video streaming, Google Classroom, Canvas) with potential misuse 
  (VPN usage, tunneling tools, unauthorized downloads).

- **Anomalies are rare and hard to label**, most students behave normally 
  most of the time, making it difficult to define what "suspicious" looks like 
  without causing excessive false alerts.

- **Behavior changes over time**, school hours, weekdays vs. weekends, and 
  exam periods all create different "normal" baselines. A static rule cannot 
  capture this.

- **Real-time detection is essential**, threats need to be identified while 
  they are happening, not days later in a log review.

The core problem PirateShield must solve is: *How do we accurately detect 
abnormal network behavior in a dynamic school environment, in real time, 
without flooding IT staff with false alarms?*