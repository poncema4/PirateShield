## Problem Statement
K-12 school districts experience a large number of daily login events across student account, creating challenges for IT administrators to determine whether a login attempt represents a normal student behavior or a potential identity compromise. Many existing monitoring systems prioritize identifying known attacks rather than detecting deviations in individual user behavior patterns. As a result, this creates detection inaccuracies such as false positives, false negatives, and even go unnoticed since there exists abnormal login activities that differs from a student's normal login patterns. 
These detection inaccuracies can interfere with timely cyber risk assessment and strategic level decisions on cyber risk mitigations and investment strategies, which often leads to delays, budget issues that limits effective responses to cybersecurity incidents [1].

**User Story:** As a school district IT security administrator, I want a system that evaluates whether a student login deviates from their normal behavior patterns, so that I can identify potential account compromise without generating excessive false alerts.

## Proposed Solution
Use existing data from each student (i.e. last 30 days), such as login information to calculate and store the following:
    1. Average login time (mean)
    2. Standard deviation of login time
    3. Average number of logins per day
    4. Whether it is weekday or weekend
    5. Whether it is school hours or off-hours
Because every student behaves differently on weekdays vs weekends, and during school hours vs at night. So we must compare correctly.

With this, we identify the student's normal behavior pattern such that when an abnormal activity occurs, we can detect if it's suspcious via a contextual risk scoring model.

