import math
from datetime import datetime


class BehavioralContext:
    def __init__(self, user_id, role, system):
        self.user_id = user_id
        self.role = role
        self.system = system

        # session tracking
        self.session_start = datetime.now()
        self.action_timestamps = []         # list of datetime objects, one per action
        self.files_downloaded = 0
        self.failed_attempts = 0
        self.concurrent_sessions = 1
        self.known_location = True          # False = unrecognized IP/location
        self.accessed_minor_data = False    # COPPA signal

        # role switching — list of dicts: {"timestamp": datetime, "system": str}
        self.role_switch_events = []

        # velocity — exponential decay model
        # lambda controls how fast older events lose influence
        # higher = shorter memory window
        self.decay_lambda = 0.05            # per second
        self.velocity_cap = 20.0            # raw decay sum that maps to max velocity score
        self.velocity_window = 60           # seconds (kept for reference/legacy)

    def log_action(self, action):
        self.action_timestamps.append(datetime.now())

    def log_system_access(self, system):
        """Call this when a user accesses a different system (for role switching detection)."""
        self.role_switch_events.append({
            "timestamp": datetime.now(),
            "system": system
        })

    def session_duration(self):
        return (datetime.now() - self.session_start).seconds

    def compute_velocity(self):
        """
        Exponential decay velocity score (0.0 – 1.0 normalized).

        V = Σ exp(-λ * Δt) for each past action timestamp.
        Recent events contribute near 1.0; older events decay toward 0.
        Normalized against velocity_cap so output is 0.0–1.0.
        """
        now = datetime.now()
        raw = sum(
            math.exp(-self.decay_lambda * (now - t).total_seconds())
            for t in self.action_timestamps
        )
        return min(1.0, raw / self.velocity_cap)

    def rapid_role_switch_detected(self, window_seconds=300, threshold=3):
        """
        Returns True if user accessed >= threshold distinct systems
        within the last window_seconds.
        """
        now = datetime.now()
        recent_systems = set(
            e["system"] for e in self.role_switch_events
            if (now - e["timestamp"]).total_seconds() <= window_seconds
        )
        return len(recent_systems) >= threshold