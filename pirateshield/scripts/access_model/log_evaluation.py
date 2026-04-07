import access_table as at

# Purpose: Determines if the given role, system, and action is allowed
def is_allowed(role, system, action):
    for entry in at.role_access_table:
        if entry["role"] == role and entry["system"] == system:
            return action in entry["allowed"]
    return False




def evaluate_event(role, system, action, context):
    score = 0
    triggered = []

    # Stage 1: RBAC check
    if not is_allowed(role, system, action):
        rule = get_rule(1)  # Role Violation
        score += rule["points"]
        triggered.append(rule)

    # Stage 2: Behavioral rules
    if context["files_downloaded"] > 50:
        rule = get_rule(2)  # Bulk Download
        score += rule["points"]
        triggered.append(rule)

    if context["off_hours"]:
        rule = get_rule(3)  # Off-Hours Access
        score += rule["points"]
        triggered.append(rule)

    return {"score": score, "triggered": triggered}
    