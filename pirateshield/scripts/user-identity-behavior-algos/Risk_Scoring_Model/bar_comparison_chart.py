import sys
import os
import matplotlib.pyplot as plt
import numpy as np

# Walk up from visuals/ to the project root
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from models.existing_model import RiskScoreModel
from models.hybrid_model import HybridScoreModel


# Data
event = {
    "student_id": "student_darin271",
    "timestamp": "03-14-2026 11:10:23",
    "day_of_the_week": "Saturday",
    "hour": 11,
    "is_school_hours": False,
    "is_weekend": True,
    "login_count_today": 3,
    "device_id": "THINKPAD_13",
    "ip_subnet": "1.1.1.x",
    "failed_attempts": 1
   # "hour_bins": [0,0,0,0,0,0,0,2,8,12,7,3,0,0,0,0,1,0,0,0,0,0,0,0]
}

profile = {
    "average_hour": 8.4,
    "deviation_hour": 1.2,
    "average_freq": 2.1,
    "deviation_freq": 0.8,
    "off_hours_rate": 0.04,
    "weekend_rate": 0.03,
    "known_devices": ["THINKPAD_13", "iPhone_DARIN"],
    "known_subnets": ["192.168.10.x", "1.1.1.x"],
    "historical_days": 30
   # "average_hour_bins": [0,0,0,0,0,0,0,2,8,12,7,3,0,0,0,0,1,0,0,0,0,0,0,0]
}

hour_bins = [0,0,0,0,0,0,0,2,8,12,7,3,0,0,0,0,1,0,0,0,0,0,0,0]

# Existing model calculations
risk_model = RiskScoreModel()

z_score_hour = risk_model.z_score(event["hour"], profile["average_hour"], profile["deviation_hour"])
z_score_freq = risk_model.z_score(event["login_count_today"], profile["average_freq"], profile["deviation_freq"])
z_score_off_hours = risk_model.z_score_bernoulli(not event["is_school_hours"], profile["off_hours_rate"])
z_score_weekend = risk_model.z_score_bernoulli(event["is_weekend"], profile["weekend_rate"])

sigmoid_hour = risk_model.sigmoid(z_score_hour)
sigmoid_freq = risk_model.sigmoid(z_score_freq)
sigmoid_off_hours = risk_model.sigmoid(z_score_off_hours)
sigmoid_weekend = risk_model.sigmoid(z_score_weekend)

risk_score = risk_model.weighted_composite_score(sigmoid_off_hours, sigmoid_hour, sigmoid_freq, sigmoid_weekend)

# Hybrid model calculations
hybrid_model = HybridScoreModel()
hybrid_score = hybrid_model.compute_hybrid_score(event["hour"], hour_bins, event["is_weekend"])

# Plot
models = ['Existing Model', 'Hybrid Model']
scores = [risk_score, hybrid_score]

x = np.arange(len(models))
plt.bar(x, scores, color=['blue', 'orange'])
plt.xticks(x, models)
plt.ylabel('Risk Score')
plt.title('Comparison of Risk Scores from Existing and Hybrid Models')
plt.ylim(0, 1)
plt.show()