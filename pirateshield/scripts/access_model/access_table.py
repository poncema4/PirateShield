

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
        "role": "IT",
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
]