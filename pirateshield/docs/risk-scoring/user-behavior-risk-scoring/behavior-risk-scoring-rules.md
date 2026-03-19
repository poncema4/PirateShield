## Rule Category 1: Login Time Detection
These rules evaluate how far a student's current login time deviates from their personal baseline.

1. Off-Peak Hour Login 
If a student logs in outside their personal peak login window (defined as μ_time ± 2σ_time), apply time deviation scoring. The further outside the window, the higher the risk contribution. A student who always logs in between 7am and 4pm logging in at 11pm is a strong signal. A student with highly variable login times logging in at 11pm is a weak signal. The z-score self-calibrates this automatically.

2. Late Night / Early Morning Flag
If login occurs between 10pm and 5am, apply a fixed contextual bonus to the risk score regardless of the student's baseline. No K-12 student should have a legitimate school-related reason to access district systems at 3am. This is a hard contextual rule that applies to all students equally, not a baseline-relative rule.

10pm–12am: +0.10 bonus to S
12am–5am: +0.20 bonus to S

3. Outside School Hours
If login occurs outside defined school hours (typically 6am–6pm on school days), apply a moderate contextual flag. This is weaker than Rule 2 because evening homework access is legitimate, but it contributes to the composite score.

6pm–10pm on school days: +0.05 bonus to S
Before 6am on school days: +0.10 bonus to S

4. Personal Time Anomaly
Compute Z_time = (current_hour − μ_time) / σ_time. Apply sigmoid transformation φ(Z_time) with k=2, μ=2.0, meaning risk starts rising meaningfully at z=2 and hits maximum around z=4. This captures the student-specific deviation on top of the absolute time rules above.

## Rule Category 2: Login Frequency Deviation
These rules evaluate whether a student is logging in at an unusual rate compared to their own history.

1. Daily Frequency Spike
Compute Z_freq = (today_count − μ_freq) / σ_freq. A student who normally logs in twice a day suddenly logging in 15 times is a strong compromise signal — credential stuffing or automated access often produces high-frequency login patterns. Apply sigmoid with k=1.5, μ=2.5, giving more tolerance for natural variation before risk rises steeply.

2. Rapid Successive Logins
If a student logs in more than 3 times within any 10-minute window, apply a hard spike bonus of +0.25 to S. This catches automated login attempts regardless of the student's daily baseline. Normal human students don't log in 4 times in 10 minutes.

3. Unusual Login Silence Followed by Burst
If a student has zero logins for 3 or more consecutive school days (within their normal active period) followed by a sudden burst of logins, apply a +0.15 bonus. Account dormancy followed by sudden activity is a known pattern in compromised credential use — attackers often sit on credentials before using them.

4. Single Session Multiple Platform Access
If within the same login session a student accesses an unusual number of different applications or resources compared to their baseline, escalate the frequency risk tier. This extends frequency scoring beyond raw login count to session behavior breadth.

## Rule Category 3: Day-of-Week Pattern Deviation
These rules evaluate whether the current login day matches the student's historical day-of-week patterns.

1. Weekend Login for Non-Weekend User
Compute the student's historical weekend login rate (weekend_logins / total_logins over 30 days). If this rate is below 0.10 (student almost never logs in on weekends) and the current login is on a Saturday or Sunday, apply a +0.20 bonus to S. If the rate is below 0.05, apply +0.30. If the rate is above 0.25 (student regularly logs in on weekends), apply no bonus.

2. Holiday and Break Login
Maintain a district calendar of non-school days. If a login occurs on a day the district calendar marks as a break or holiday, apply a +0.15 bonus regardless of the student's baseline. Cross-reference with the student's historical holiday login rate — if they have a history of logging in during breaks, reduce the bonus to +0.05.

3. Day-of-Week Z-Score
For each day of the week, compute the student's historical login probability. If the current day has a historical login probability below 0.10 for that student, apply a small contextual flag. This captures students who, for example, never log in on Mondays suddenly doing so.