# Problem Statement
## The Core Problem: 
Many K-12 schools over-rely on third-party technology such as Canvas, Google Classroom, Infinite Campus, PowerSchool, etc. (EdTech). This is a problem, as researchers found that 89% of the technologies they studied violated students' privacy through surveillance and sharing data with third parties for advertising purposes. Adding onto this, the US Government Accountability Office (GAO) found that there were 99 student data breaches, affecting hundreds of school districts, within a 4-year time span. [*1*] 
To combat this issue, our  goal is to release  PirateShield, a multi-layer cybersecurity system for K-12 schools that observes identity, device, network, and access-behavior overtime.


##  Introduction to Role Context - Mitigating Privilege Misuse in Access Control through Anomaly Detection (Mehri et al. 2023) [*2*]


Access control systems serve as the first line of defense for protecting sensitive data and resources. In PirateShield, role-based policies form this foundation, as they enforce predefined access rules to flag when users act outside their expected permissions. That said, role-based access control has a well-known limitation. As Mehri et al. point out, once permissions are assigned, there is nothing stopping a user from misusing them. This applies to both **insider threats** (legitimate users abusing their access) and **external attackers** (who steal credentials to impersonate someone). PirateShield will take this into account by layering behavioral monitoring on top of role policies, giving it the ability to flag anomalies when a user's actions deviate from what's expected of their role.

Examples of Role-Based Permissions in a SIS: -  
**Students** – View course info, contact advisors/teachers - 
 **Parents** – Edit/view student info, contact advisors/teachers, view course info 
 **Teachers** – Edit/view student grades, contact students/parents, view limited student info 
 **Principals** – Contact teachers, create global announcements, view student course info and disciplinary records -  
 **IT** – Access to all metadata (user password modification, login info, network traffic, global announcements)

## Role Access Table - Design and Implementation of Student InformationManagement System Based On Java (Zhou Xiaofang) [*3*]

To determine if an action is allowed according to policy, we can create a role-access table. This approach is supported by existing foundations, such as Chen et al. proposing to use a structured function table to organize role-based access across different student information systems, mapping user roles (students, teachers, administrators) to permitted actions within each system. PirateShield adopts a similar structure, defining allowed and restricted actions per role across each EdTech system:

| Role | System | Allowed Actions | Restricted Actions |
|------|--------|----------------|-------------------|
| Student | SIS | View own grades, submit assignments | Edit grades, access other student records |
| Student | Google Classroom | Submit work, view course materials | Modify course settings |
| Parent | SIS | Edit/view student info, contact advisors, view course info| Edit grades, access other student records|
| Teacher | SIS | View/edit grades for assigned classes | Modify admin settings |
| Teacher | Google Drive | Upload/download course materials | Access administrative files |
| Administrator | SIS | Manage student records | N/A |
| IT Admin | All Systems | System maintenance, account management | N/A |

While tables like this make it easy to visually identify potential access anomalies, a more formal or mathematical framework may be preferable for administrators using PirateShield. This approach is discussed in a separate document.

## Overview of Access Risk Scoring 

PirateShield evaluates access events through a structured, rule-based risk scoring model. When a user performs an action that violates expecated role permissions, the system assigns risk points according to predefined **Access Rules**. These points are added up to form a Base Access Risk **(BAR)** score, which is then adjusted at the end to account for system sensitivity to produce a Final Access Risk score **(FAR)**

This methodology is grounded in established cybersecurity risk procedures mentioned in section **Application of Grounded Methodology**.


## Formal Risk Score Equation (Prototype)

#### Base Access Risk

The Base Access Risk **(BAR)** is calculated as the sum of all triggered rule scores for a given access event:

$$BAR = \sum (Rule_i \times Triggered_i)$$

**Where:**

$Rule_i$ = Fixed \# of risk points assigned to rule $i$

$Triggered_i$ = 1 if the rule condition is met, 0 otherwise

#### Sensitivity Adjustment
After the **BAR** is calculated, the system adjusts the score based on the sensitivity level of the system being accessed. This adjustment reflects the fact that misuse of more sensitive systems poses a greater security risk.

$$\text{FAR} = BAR \times \text{SensitivityMultiplier}$$

After combining both steps, the complete equation is:
$$
\text{FAR} = \left[ \sum_{i=1}^{n} (Rule_i \times Triggered_i) \right] \times \text{Sensitivity\_Multiplier}
$$
| System Sensitivity | Multiplier |Risk Adjustment| 
|------------------|-------------|--------------|
| Low | 0.8| Reduces score - lower risk context|
|Medium| 1.0| No change - baseline risk|
|High| 1.2| Increases score - critical system accessed|

## Access Rules

Each triggered rule corresponds to a specific policy violation and contributes a fixed number of risk points. Rules are evaluated independently and additively.
| Rule | Condition | Risk Points|
|------|---------|------------|
|Rule 1 - Role Violation | User attempts to access a system outside their permitted role (e.g. student accessing Admin Portal) | +40|
|Rule 2 - Bulk Download | More than 50 files downloaded within a 10-minute window | +30 |
|Rule 3 - Off-Hours Sensitivie Access | A high-sensitivity system is accessed outisde school hours (school_hour_flag = 0) | +20 |
|Rule 4 - Repeated Failure Attempts | 5 or more failed access attempts to a restricted system | +25 |

 **NOTE:** Rules themselves do not immediately trigger alerts. Instead, they accumulate risk points that contribute to the **FAR** score, which is then evaluated against alert thresholds.

## Application of Grounded Methodology
PirateShield's Access Risk calculation is consistent with approaches found in recent cybersecurity risk quantification articles. The following sections describe how each element of the scoring model relates to published research articles. 

### Additive Rule Scoring - CyRiPred (Kia et al. 2024) [*4*]
CyRiPred (Expert Systems with Applications, 2024) computes cyber risk scores by multiplying topic occurrence (frequency) by baseScore (impact severity), element-wise, per **CVE** (Common Vulnerabilities and Exposures)  topic per time period:

$$\text{CyRiPred Risk Score} = \text{Occurrence} \times \text{baseScore}$$

PirateShield adopts this same additive structure. The binary Triggered_i flag encodes occurence (did the event happen?) while the fixed Rule_i points encode impact severity, making the BAR equation a direct contextual adaptation of this model:

$$
BAR = \sum_{i=1}^{n} (Rule_i \times Triggered_i) \iff \text{Risk} = \sum_{i=1}^{n} (Occurrence_i \times baseScore_i)
$$

### Sensitivity Multiplier - Cybersecurity Risk Quantification and Classification Framework (Zadeh et al., 2023) [*5*]
Zadeh et al. (ScienceDirect, 2023) propose a Breach Level Index (BLI) scoring model in which weighted contextual factors - including data type, source, number of records, and harm potential - are applied as multipliers to scale a base risk score. Each factor reflects how the context of a breach amplifies or reduces its overall severity:

$$
BLI = \text{BaseScore} \times w(\text{data type}) \times w(\text{source}) \times w(\text{records}) \times w(\text{harm potential})
$$

PirateShield's Sensitivity Multiplier applies this same principle. The BAR score is scaled by the sensitivity level of the accessed system, reflecting that the same violation poses proportionally greater risk on a more sensitive system, directly mirroring the contextual weighting approach of the BLI model. 

### Alert ThresHold Classification - BLI Risk Classification Matrix (Zadeh et al., 2023) [*5*]

Zadeh et al. classify continuous BLI scores into 5 discrete severity levels: minimal (1-2.9), moderate (3-4.9), critical (5-6.9), severe (7-8.9), and catastrophic (9-10). PirateShield applies the same principle, mapping the **FAR** scores into graded alerts for administrators to easily interpret:
| FAR Score | Risk Level |Action | 
|------------------|-------------|--------------|
| < 40| Low | Log only|
|40-79| Medium| Notifiy administrator|
| >= 80| High| Real-time immediate alert|



## Access-Related Alerts

The calculation of the **Access Risk score** is performed internally and is not visible to end users. Once computed, the score is sent to the backend system, where it is evaluated against the predefined alert thresholds mentioned in the table prior. If the risk score exceeds certain thresholds, PirateShield generates an **access-related alert** that is presented to system administrators in a clear and actionable format.

Below are examples of access-related alerts that may be generated:

**Access Failure – Insufficient Role Privileges**  
**Severity: High**  
A user attempted to access a system or resource that is not permitted for their assigned role.

**Bulk Data Download Detected**  
**Severity: Medium–High**  
A large number of files were downloaded within a short period of time, which may indicate potential data exfiltration or misuse.

**After-Hours Access Detected**  
**Severity: Medium**  
A user accessed a system outside of normal school operating hours.

**Repeated Failed Access Attempts**  
**Severity: Medium–High**  
Multiple failed attempts were made to access a restricted system, which may indicate unauthorized access attempts.

Administrators can review these alerts through the PirateShield interface to investigate suspicious activity and determine whether further action is required.

## Worked Example
### Access Event
| user_id | Role | Time | System | Action | # of files | Data Size | Success? | School Hour Flag | Sensitivity |
|---------|------|------|--------|--------|------------|-----------|----------|------------------|-------------|
| 95653 | Student | 2:30 AM | Admin Portal | Download | 60 | 120 MB | Yes | 0 | High|
### Policy Rules Triggered
| Rule | Triggered? | Points|
|-------|-----------|--------|
|Rule 1 - Role Violation (Student -> Admin Portal)| Yes | +40|
|Rule 2 - Bulk Download (60 files)|Yes|+30|
|Rule 3 - Off-Hours Sensitive Access| Yes | +20|
|Rule 4 - Repeated Failed Attempts | No | +25 |

### Access Risk Score Calculation
$$
\begin{aligned}
BAR &= (40 \times 1) + (30 \times 1) + (20 \times 1) + (25 \times 1) \\
BAR &= 115 \\
\text{Sensitivity} &= 1.2\times \ (\text{High}) \\
FAR &= 115 \times 1.2 = 138 \\
\text{Classification} &= \text{Critical} \ (\geq 80)
\end{aligned}
$$


### Generated Alert  (WIP)
  
**ALERT: Unauthorized Access Attempt Detected**  
  
Severity: Critical  
Risk Score: 138
  
User: 95653  
Role: Student  
System: Admin Portal  
Action: Download  
Files Accessed: 60  
Timestamp: 2:30 AM  
  
**Reason for Alert:**  
- Role violation detected  
- Bulk data download detected  
- Access occurred outside school hours  
  
**Recommended Action:**  
- Review the user's recent activity  
- Verify whether the account has been compromised  
- Temporarily restrict access if necessary


## Conclusion

Through the use of role-based policies and predefined access rules, PirateShield is able to systematically evaluate access events and assign a corresponding **AccessRisk score**. By examining factors such as user role, system accessed, performed action, time of access, and system sensitivity, the system can detect policy violations and potentially suspicious activity in a structured and deterministic way.

Rather than immediately triggering alerts for every irregular event, PirateShield accumulates risk through rule evaluation and sensitivity adjustments. This approach allows the system to produce meaningful risk scores that can later be interpreted by the backend to generate appropriate alerts for administrators.

By combining clearly defined role permissions with rule-based risk scoring, PirateShield provides a transparent and explainable method for identifying potential access misuse. This policy-based approach serves as an important layer within the broader PirateShield architecture, where it can later be combined with other signals such as identity behavior and device risk to create a more comprehensive security monitoring system.


## References


•[1] J. Chanenson et al., "Uncovering Privacy and Security Challenges in K-12 Schools," CHI 2023.

•[2] Gelareh Hasel Mehri et al., "Mitigating Privilege Misuse in Access Control through Anomaly Detection" ARES 2023.

•[3] Zhou Xiaofang, "Design and Implementation of Student InformationManagement System Based On Java," ICISS 2018.

• [4] A. N. Kia, B. Sheehan, F. Murphy, and D. Shannon, “A Cyber Risk Prediction Model Using Common Vulnerabilities and Exposures,” Expert Systems with Applications, vol. 238, 2024. 

• [5] A. Zadeh, B. Lavine, H. Zolbanin et al., “A Cybersecurity Risk Quantification and Classification Framework for Informed Risk Mitigation Decisions,” Decision Analytics Journal, vol. 9, 2023.

	

