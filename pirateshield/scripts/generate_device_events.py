"""
program that pretends to be a computer or Chromebook 
and reports fake device activity, so PirateShield can be tested
without installing anything on real student devices
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Path for the json file 
BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_FILE = BASE_DIR / "data" / "synthetic_device_events.json"

# Relevant data for the generator 
EST = timezone(timedelta(hours=-5))

DEVICE_TYPE = ["school computer", "school chromebook", "laptop", "phone", "tablet"]
USERS = [f"student{n:03d}" for n in range(1, 21)]
SAFE_PROCESS = ["", "", "", "",]
SUSPICIOUS_PROCESS = ["", "",]  # *make this a weighed pool*
FIRE_WALL_STATUS = random.random() < 0.9 # 90% of the time firewall is up 

# IPS
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(2, 64)] # school LAN pool
EXTERNAL_IPS = ["8.8.8.8", "1.1.1.1", "45.76.34.12", "93.184.216.34"]
HIGH_RISK_IPS = ["203.0.113.45", "198.51.100.23"] # suspicious, raise a flag, *consider making it a set*

# *do ports, add more 

def generate_event(base_time_est, index):
    event_time_est = base_time_est + timedelta(seconds=index * 5)

    return {
        #"event_id": str(uuid.uuid4()), 
        "timestamp": event_time_est.isoformat(),
        
        "event_type": "device_connection"
    }