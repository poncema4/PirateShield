# Problem Statement
## The Core Problem: 
Many K-12 schools over-rely on third-party technology such as Canvas, Google Classroom, Infinite Campus, PowerSchool, etc. (EdTech). This is a problem, as "researchers found that 89% of the technologies they studied violated students' privacy through surveillance and sharing data with third parties for advertising purposes." [1] Adding onto this, the "US Government Accountability Office (GAO) found that there were 99 student data breaches, affecting hundreds of school districts, within a 4-year time span." [2] To combat this issue, our  goal is to release  PirateShield, a multi-layer cybersecurity system for K-12 schools that observes identity, device, network, and access-behavior overtime.


## An Introduction to Role Context Through Access Behavior

Role-based policies serve as the first layer of defense in PirateShield, by enforcing predefined access rules. These policies enable deterministic evaluation of access events to identify potential misuse when user actions violate expected role permissions. 
Examples of Role-Based Permissions in a SIS:

• Students – View course info, contact advisors/teachers

• Parents – Edit/view student info, contact advisors/teachers, view course info

• Teachers – Edit/view student grades, contact students/parents, view limited student info

• Principals – Contact teachers, create global announcements, view student course info and disciplinary records

• IT – Access to all metadata (user password modification, login info, network traffic, global announcements)

## Role Context - Role Access Table (WIP, use references justifying table usage from doc)

To determine if an action is allowed according to policy, we can create a role-access table. An example table is as follows:
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

## What are Access Rules?


Access Rules define how risk points are assigned when a user performs actions that violate expected role permissions defined in the Role Access Table. These rules allow PirateShield to evaluate access events and calculate a **Base Access Risk score** based on the severity of the violation.

Each rule corresponds to a specific type of policy violation and contributes a fixed number of risk points. The sum of these rule scores forms the **Base Access Risk** for a given access event. **NOTE: This is just a demo.**

### Example Rules

**Rule 1 – Role Violation**  
If a student attempts to access the Admin Portal  
**+40 risk points**

**Rule 2 – Bulk Download**  
If more than 50 files are downloaded within a 10-minute period  
**+30 risk points**

**Rule 3 – Off-Hours Sensitive Access**  
If a high-sensitivity system is accessed outside of school hours  
(`school_hour_flag = 0`)  
**+20 risk points**

**Rule 4 – Repeated Failed Access Attempts**  
If a user makes 5 or more failed attempts to access a restricted system  
**+25 risk points**

Each triggered rule contributes to the total risk score. Rules themselves do **not immediately generate alerts**; instead, they accumulate risk points that contribute to the overall risk assessment.

----------

## Sensitivity Adjustment

After the **Base Access Risk** is calculated, the system adjusts the score based on the sensitivity level of the system being accessed. This adjustment reflects the fact that misuse of more sensitive systems poses a greater security risk. **Note: This is just a demo.**

Example sensitivity adjustments:
| System Sensitivity | Risk Adjustment|
|------------------|-------------|
| Low | **BAR** x 0.8|
|Medium| **BAR** x 1.0|
|High| **BAR** x 1.2|

This adjusted value represents the **Final Access Risk score** for the event and can be used by PirateShield to determine whether administrative alerts should be generated.



## AccessRisk Score & Access-Related Alerts

The calculation of the **AccessRisk score** is performed internally and is not visible to end users. Once computed, the score is sent to the backend system, where it is evaluated against predefined alert thresholds. If the risk score exceeds certain thresholds, PirateShield generates an **access-related alert** that is presented to system administrators in a clear and actionable format.

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

## An Example
### Access Event
| user_id | Role | Time | System | Action | # of files | Data Size | Success? | School Hour Flag | Sensitivity |
|---------|------|------|--------|--------|------------|-----------|----------|------------------|-------------|
| 95653 | Student | 2:30 AM | Admin Portal | Download | 60 | 120 MB | Yes | 0 | High|
### Policy Rules Applied 
Rule 1 – Role Violation  
Student attempting to access Admin Portal  
+40 points  
  
Rule 2 – Bulk Download  
More than 50 files downloaded within a short time period  
+30 points  
  
Rule 3 – Off-Hours Sensitive Access  
High sensitivity system accessed outside school hours  
+20 points
### Base Risk Calculation
Base AccessRisk = 40 + 30 + 20  
Base AccessRisk = 90
### Sensitivity Adjustment
Admin Portal = High Sensitivity
Final AccessRisk = 90 × 1.2  
Final AccessRisk = 108

### Generated Alert  
  
**ALERT: Unauthorized Access Attempt Detected**  
  
Severity: Critical  
Risk Score: 108  
  
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

•[2] J. Chanenson et al., "Uncovering Privacy and Security Challenges in K-12 Schools," CHI 2023.
	

