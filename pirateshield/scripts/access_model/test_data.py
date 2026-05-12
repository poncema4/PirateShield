from behavioral_context import BehavioralContext
from log_evaluation import evaluate_event
from datetime import datetime
import time

def run_test(label, role, system, action, setup_fn, hour=10):
    print(f"\n{'='*55}")
    print(f"TEST: {label}")
    print(f"Role: {role} | System: {system} | Action: {action}")
    ctx = BehavioralContext(f"{role}_01", role, system)
    setup_fn(ctx)
    result = evaluate_event(role, system, action, ctx, hour=hour)
    print(f"Score: {result['score']}")
    print(f"Alert Level: {result['alert_level']}")
    print(f"Triggered Rules:")
    for rule in result['triggered']:
        if rule:
            print(f"  - [{rule['rule_id']}] {rule['name']} (+{rule['points']} pts)")
    print(f"{'='*55}")

# Normal student behavior 
def test1_setup(ctx):
    ctx.files_downloaded = 2
    ctx.failed_attempts = 0
    for _ in range(3):
        ctx.log_action("view own grades")

run_test(
    label="Normal Student - Viewing Grades",
    role="student", system="SIS", action="view own grades",
    setup_fn=test1_setup, hour=10
)

# Student attempting role violation 
def test2_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0

run_test(
    label="Student Attempting to Edit Grades (Role Violation)",
    role="student", system="SIS", action="edit grades",
    setup_fn=test2_setup, hour=10
)

# Bulk download 
def test3_setup(ctx):
    ctx.files_downloaded = 65
    ctx.failed_attempts = 0
    for _ in range(5):
        ctx.log_action("view/edit grades for assigned classes")

run_test(
    label="Teacher Bulk Downloading Files",
    role="teacher", system="SIS",
    action="view/edit grades for assigned classes",
    setup_fn=test3_setup, hour=10
)

# Repeated failed attempts
def test4_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 6

run_test(
    label="Unknown User - Repeated Failed Attempts",
    role="student", system="SIS", action="view own grades",
    setup_fn=test4_setup, hour=10
)

# High velocity 
def test5_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0
    for _ in range(30):
        ctx.log_action("view own grades")

run_test(
    label="Student High Access Velocity",
    role="student", system="SIS", action="view own grades",
    setup_fn=test5_setup, hour=10
)

# Concurrent sessions 
def test6_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0
    ctx.concurrent_sessions = 3

run_test(
    label="Teacher Concurrent Sessions",
    role="teacher", system="SIS",
    action="view/edit grades for assigned classes",
    setup_fn=test6_setup, hour=10
)

# Everything at once (worst case)
def test7_setup(ctx):
    ctx.files_downloaded = 80
    ctx.failed_attempts = 7
    ctx.concurrent_sessions = 2
    ctx.known_location = False
    for _ in range(30):
        ctx.log_action("edit grades")
    ctx.log_system_access("SIS")
    ctx.log_system_access("HR")
    ctx.log_system_access("Payroll")

run_test(
    label="Student - Multiple Violations Simultaneously",
    role="student", system="SIS", action="edit grades",
    setup_fn=test7_setup, hour=2   # 2 AM
)

# IT accessing student records 
def test8_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0

run_test(
    label="IT Attempting to View Student Records",
    role="it", system="SIS",
    action="view/download records for students",
    setup_fn=test8_setup, hour=10
)

# Normal IT behavior 
def test9_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0

run_test(
    label="IT Normal - System Maintenance",
    role="it", system="SIS", action="edit system configuration",
    setup_fn=test9_setup, hour=10
)

# Nurse accessing wrong records 
def test10_setup(ctx):
    ctx.files_downloaded = 0
    ctx.failed_attempts = 0

run_test(
    label="Nurse Attempting to Access Academic Records",
    role="nurse", system="SIS", action="access academic records",
    setup_fn=test10_setup, hour=10
)