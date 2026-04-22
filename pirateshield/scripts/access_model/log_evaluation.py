import access_table as at
from datetime import datetime

# Purpose: Determines if the given role, system, and action is allowed
def is_allowed(role, system, action):
    for entry in at.role_access_table:
        if entry["role"] == role and entry["system"] == system:
            return action in entry["allowed"]
    return False

# Purpose: Fetches a rule from policy_rules by rule_id
def get_rule(rule_id):
    for rule in at.policy_rules:
        if rule["rule_id"] == rule_id:
            return rule
    return None

# Purpose: Checks if the time of access is outside normal hours for a given role
# Normal hours are defined per role since teachers/admins may work later than students
ROLE_HOURS = {
    "student":        (8, 15),   # 8am - 3pm
    "teacher":        (7, 18),   # 7am - 6pm
    "principal":      (7, 18),
    "counselor":      (7, 17),
    "front office":   (7, 16),
    "it":       (6, 20),   # broader window for maintenance
    "administrator":  (7, 18),
}

def is_off_hours(role, hour):
    if role not in ROLE_HOURS:
        return False
    start, end = ROLE_HOURS[role]
    return not (start <= hour < end)

# Purpose: Computes access velocity score based on action frequency vs baseline
# Velocity = actions taken in current window / expected baseline rate
# Returns a point value if velocity exceeds threshold, 0 otherwise
def compute_velocity_score(context):
    if context.baseline_rate is None or context.baseline_rate == 0:
        return 0
    
    # calculate how many actions were taken in the last time window
    now = datetime.now()
    recent_actions = [
        t for t in context.action_timestamps
        if (now - t).seconds <= context.velocity_window
    ]
    
    current_rate = len(recent_actions) / context.velocity_window
    velocity_ratio = current_rate / context.baseline_rate

    if velocity_ratio >= 3.0:       # 3x baseline - critical
        return 35
    elif velocity_ratio >= 2.0:     # 2x baseline - high
        return 25
    elif velocity_ratio >= 1.5:     # 1.5x baseline - moderate
        return 15
    return 0

# Purpose: Evaluates an incoming event against RBAC, behavioral, and velocity layers
def evaluate_event(role, system, action, context):
    score = 0
    triggered = []

    # Stage 1: RBAC check
    if not is_allowed(role, system, action):
        rule = get_rule(1)  # Role Violation
        score += rule["points"]
        triggered.append(rule)

    # Stage 2: Behavioral rules
    if context.files_downloaded > 50:
        rule = get_rule(2)  # Bulk Download
        score += rule["points"]
        triggered.append(rule)

    # Stage 3: Time of access anomaly per role
    current_hour = 10 # for testing, use datetime.now().hour normally
    if is_off_hours(role, current_hour):
        rule = get_rule(3)  # Off-Hours Sensitive Access
        score += rule["points"]
        triggered.append(rule)

    # Stage 4: Repeated failed attempts
    if context.failed_attempts >= 5:
        rule = get_rule(4)  # Repeated Failed Attempts
        score += rule["points"]
        triggered.append(rule)

    # Stage 5: Access velocity scoring
    velocity_points = compute_velocity_score(context)
    if velocity_points > 0:
        rule = get_rule(5)  # High Access Velocity
        rule_copy = rule.copy()
        rule_copy["points"] = velocity_points  # override with computed value
        score += velocity_points
        triggered.append(rule_copy)

    # Stage 6: Concurrent session anomaly
    if context.concurrent_sessions > 1:
        rule = get_rule(11)  # Concurrent Session Anomaly
        score += rule["points"]
        triggered.append(rule)

    return {
        "score": score,
        "triggered": triggered,
        "alert_level": classify_score(score)
    }

# Purpose: Classifies the final risk score into an alert level
def classify_score(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    return "NONE"