
role_access_table = [
    {
        "role": "student",
        "system": "SIS",
        "allowed": ["view own grades", "submit assignments", "email"],
        "restricted": ["edit grades", "access other student records", "make announcements"]
    },
    {

        "role": "teacher",
        "system": "SIS",
        "allowed": ["view/edit grades for assigned classes"],
        "restricted": ["modify admin settings", "make announcements"]
    },
    {
        "role": "principal", 
        "system": "SIS",
        "allowed": ["view student course information", "make announcements", "view/download records for students"],
        "restricted": ["access payroll", "health records"]

    },
    {
        "role": "it",
        "system": "SIS",
        "allowed": ["make announcements", "edit system configuration", "view student course information",
                    "edit user accounts", "view system logs", "perform data backups"],
        "restricted": ["edit audit log metadata", "view student/staff records", "view/download records for students",
                       ""]
    },
    {
        "role": "nurse",
        "system": "SIS",
        "allowed": ["view/edit student health records"],
        "restricted": ["access academic records", "access disciplinary files"]
    }
]

policy_rules = [
    {
        "rule_id": 1,
        "name": "Role Violation",
        "description": "Access attempt outside permitted role (e.g. student -> Admin Portal)",
        "points": 40
    },
    {
        "rule_id": 2,
        "name": "Bulk Download",
        "description": "Downloading above threshold (e.g. 60+ files)",
        "points": 30
    },
    {
        "rule_id": 3,
        "name": "Off-Hours Sensitive Access",
        "description": "Accessing sensitive resources outside normal hours",
        "points": 20
    },
    {
        "rule_id": 4,
        "name": "Repeated Failed Attempts",
        "description": "Multiple failed login or access attempts",
        "points": 25
    },
    # velocity based
    {
        "rule_id": 5,
        "name": "High Access Velocity",
        "description": "User performing actions at abnormally high rate vs baseline",
        "points": 25
    },
    {
        "rule_id": 6,
        "name": "Rapid Role Switching",
        "description": "Multiple role-based access attempts across different systems in short window",
        "points": 30
    },
    # FERPA
    {
        "rule_id": 7,
        "name": "Unauthorized Student Record Access",
        "description": "User accessing student records outside their assigned scope (FERPA violation)",
        "points": 40
    },
    {
        "rule_id": 8,
        "name": "Mass Student Record Export",
        "description": "Bulk export of student PII records beyond authorized threshold",
        "points": 45
    },
    # COPPA
    {
        "rule_id": 9,
        "name": "Minor Data Exposure Risk",
        "description": "Access or export of personal data belonging to users under 13",
        "points": 45
    },
    # Behavioral
    {
        "rule_id": 10,
        "name": "Unusual Geographic Access",
        "description": "Login or access attempt from unexpected location",
        "points": 30
    },
    {
        "rule_id": 11,
        "name": "Concurrent Session Anomaly",
        "description": "Same account active from multiple devices or IPs simultaneously",
        "points": 35
    },
    {
        "rule_id": 12,
        "name": "Audit Log Tampering",
        "description": "Attempt to modify or delete system audit logs",
        "points": 50
    },
    {
        "rule_id": 13,
        "name": "Privilege Escalation Attempt",
        "description": "User attempting to access resources beyond their assigned role level",
        "points": 40
    },
]
