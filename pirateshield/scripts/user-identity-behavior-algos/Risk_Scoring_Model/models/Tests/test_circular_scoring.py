import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from weighted_circular_distance import weighted_circular_distance, hybrid_scoring

login_hour = 11
hour_bins = [0,0,0,0,0,0,0,2,8,12,7,3,0,0,0,0,1,0,0,0,0,0,0,0]
weekend_flag = False

print("Weighted Circular Distance:", weighted_circular_distance(login_hour, hour_bins, weekend_flag))
print("Hybrid Scoring:", hybrid_scoring(login_hour, hour_bins, weekend_flag))