from datetime import datetime

class BehavioralContext:
    def __init__(self, user_id, role, system):
        self.user_id = user_id
        self.role = role
        self.system = system
        
        # session tracking
        self.session_start = datetime.now()
        self.action_timestamps = []     # list of datetime objects, one per action
        self.files_downloaded = 0
        self.failed_attempts = 0
        self.concurrent_sessions = 1
        
        # velocity
        self.baseline_rate = None       # actions per second, learned over time
        self.velocity_window = 60       # look back 60 seconds for velocity calc
        
    # Purpose: Logs a new action and its timestamp
    def log_action(self, action):
        self.action_timestamps.append(datetime.now())

    # Purpose: Updates the baseline rate from historical average
    def set_baseline(self, avg_actions_per_second):
        self.baseline_rate = avg_actions_per_second

    # Purpose: Returns how long the session has been active in seconds
    def session_duration(self):
        return (datetime.now() - self.session_start).seconds