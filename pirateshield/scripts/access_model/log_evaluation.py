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
    "it":             (6, 20),   # broader window for maintenance
    "administrator":  (7, 18),
    "nurse":          (7, 16),
}

def is_off_hours(role, hour):
    if role not in ROLE_HOURS:
        return False
    start, end = ROLE_HOURS[role]
    return not (start <= hour < end)


# Behavioral Context Scoring
# Weighted additive formula — each signal
# contributes a normalized intensity (0.0–1.0)
# multiplied by its assigned weight.
# Total scaled to the behavioral rule's max points.
#
# Weights represent relative contribution of each
# signal to overall behavioral risk. Must sum to 1.0.


BEHAVIORAL_WEIGHTS = {
    "off_hours":           0.25,
    "bulk_download":       0.20,
    "failed_attempts":     0.20,
    "geo_anomaly":         0.15,
    "concurrent_session":  0.10,
    "minor_data_exposure": 0.10,
}

BULK_DOWNLOAD_THRESHOLD   = 50    # files in a session
FAILED_ATTEMPTS_THRESHOLD = 5     # matches original threshold

def compute_behavioral_score(context, hour):
    """
    Returns (score, triggered_rule_names).

    Each signal produces a 0.0–1.0 intensity value.
    Partial credit applies where the signal is approaching
    but has not fully crossed a threshold.
    Final score is scaled to 0–50 range.
    """
    signals = {}
    triggered = []

    # Off-hours
    if is_off_hours(context.role, hour):
        signals["off_hours"] = 1.0
        triggered.append(get_rule(3))
    else:
        signals["off_hours"] = 0.0

    # Bulk download — partial credit
    files = context.files_downloaded
    if files >= BULK_DOWNLOAD_THRESHOLD:
        signals["bulk_download"] = 1.0
        triggered.append(get_rule(2))
    elif files > 0:
        signals["bulk_download"] = files / BULK_DOWNLOAD_THRESHOLD
    else:
        signals["bulk_download"] = 0.0

    # Failed attempts — partial credit
    attempts = context.failed_attempts
    if attempts >= FAILED_ATTEMPTS_THRESHOLD:
        signals["failed_attempts"] = 1.0
        triggered.append(get_rule(4))
    elif attempts > 0:
        signals["failed_attempts"] = attempts / FAILED_ATTEMPTS_THRESHOLD
    else:
        signals["failed_attempts"] = 0.0

    # Geographic anomaly
    if not context.known_location:
        signals["geo_anomaly"] = 1.0
        triggered.append(get_rule(10))
    else:
        signals["geo_anomaly"] = 0.0

    # Concurrent session
    if context.concurrent_sessions > 1:
        signals["concurrent_session"] = min(1.0, (context.concurrent_sessions - 1) / 3)
        triggered.append(get_rule(11))
    else:
        signals["concurrent_session"] = 0.0

    # Minor data exposure (COPPA)
    if context.accessed_minor_data:
        signals["minor_data_exposure"] = 1.0
        triggered.append(get_rule(9))
    else:
        signals["minor_data_exposure"] = 0.0

    # Weighted sum → scale to 0–50
    raw = sum(BEHAVIORAL_WEIGHTS[k] * signals[k] for k in BEHAVIORAL_WEIGHTS)
    score = round(raw * 50, 2)
    return score, triggered


# Access Velocity Scoring
# Exponential decay model:
#   V = Σ exp(-λ * Δt) for each past event
#   Recent events weigh near 1.0; older decay toward 0.
#   Normalized to 0–50 range.


def compute_velocity_score(context):
    """
    Returns (score, triggered_rule_names).

    Uses BehavioralContext.compute_velocity() for the
    exponential decay calculation, then scales to 0–50.
    Rapid role switching adds a flat bonus if detected.
    """
    triggered = []

    velocity_normalized = context.compute_velocity()   # 0.0–1.0
    score = round(velocity_normalized * 50, 2)

    if score > 25:
        triggered.append(get_rule(5))   # High Access Velocity

    if context.rapid_role_switch_detected():
        triggered.append(get_rule(6))   # Rapid Role Switching
        score = min(50.0, score + 10.0)

    return round(score, 2), triggered

# Main Event Evaluator

def evaluate_event(role, system, action, context, hour=None):
    """
    Evaluates an incoming event across three layers:
      1. RBAC check       — is this action permitted for this role?
      2. Behavioral score — weighted formula across contextual signals
      3. Velocity score   — exponential decay over action timestamps

    Final risk score capped at 100.
    """
    if hour is None:
        hour = datetime.now().hour

    score = 0
    triggered = []

    # Layer 1 — RBAC
    if not is_allowed(role, system, action):
        rule = get_rule(1)  # Role Violation
        score += rule["points"]
        triggered.append(rule)

    # Layer 2 — Behavioral context (weighted formula)
    behavioral_score, behavioral_rules = compute_behavioral_score(context, hour)
    score += behavioral_score
    triggered.extend(behavioral_rules)

    # Layer 3 — Access velocity (exponential decay)
    velocity_score, velocity_rules = compute_velocity_score(context)
    score += velocity_score
    triggered.extend(velocity_rules)

    # Cap at 100
    score = round(min(100.0, score), 2)

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