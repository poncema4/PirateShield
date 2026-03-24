import json
from datetime import datetime
import math
from pathlib import Path

# Load data file relative to this script's location so tests/workers
# can run from different working directories.
DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_network_events.json"
with open(DATA_FILE, "r") as file:
    networkEvents = json.load(file)

def getLastTwoLogins(events: list[dict], userID: str):
    userEvents = [event for event in events if event["user_id"] == userID]
    userEvents.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    if len(userEvents) >= 2:
        return userEvents[-2], userEvents[-1]
    
    return None

# Using the Haversine formula to compute distance between two lat/long points
def computeDistance(prevLogin: dict, currLogin: dict) -> int:    
    latDistance = (currLogin["lat"] - prevLogin["lat"]) * math.pi / 180.0
    longDistance = (currLogin["long"] - prevLogin["long"]) * math.pi / 180.0

    lat1 = currLogin["lat"] * math.pi / 180.0 
    lat2 = prevLogin["lat"] * math.pi / 180.0

    a = pow(math.sin(latDistance/2), 2) + math.cos(lat1) * math.cos(lat2) * pow(math.sin(longDistance/2), 2)
    radius = 6371
    c = 2 * math.asin(math.sqrt(a))
    return radius*c
    
def detectImpossibleTravel(userID: str, speedThreshold=1000) -> bool:
    logins = getLastTwoLogins(networkEvents, userID)

    if not logins:
        return False
    
    prevLogin, currLogin = logins

    distance = computeDistance(prevLogin, currLogin)

    time1 = datetime.fromisoformat(prevLogin["timestamp"])
    time2 = datetime.fromisoformat(currLogin["timestamp"])

    timeDiffHours = (time2 - time1).total_seconds() / 3600

    if timeDiffHours == 0:
        return True
    
    speed = distance / timeDiffHours

    print(f"Distance: {distance:.2f} km")
    print(f"Time: {timeDiffHours:.4f} hours")
    print(f"Speed: {speed:.2f} km/h")

    return speed > speedThreshold

# Tests

def test_getLastTwoLogins() -> None:
    prevLogin1, currLogin1 = getLastTwoLogins(networkEvents, "teacher2")
    assert prevLogin1 is not None
    assert currLogin1 is not None
    assert prevLogin1["user_id"] == "teacher2"
    assert currLogin1["user_id"] == "teacher2"

def test_computeDistance() -> None:
    prevLogin = {"lat": 40.7128, "long": -74.0060}  # New York
    currLogin = {"lat": 34.0522, "long": -118.2437} # Los Angeles
    distance = computeDistance(prevLogin, currLogin)
    assert distance > 3900 and distance < 4000  # Approximate distance in km
    assert abs(distance - 3936) < 10  # Approximate distance in km

def test_detectImpossibleTravel() -> None:
    assert detectImpossibleTravel("teacher2")
    assert detectImpossibleTravel("student1")
    
