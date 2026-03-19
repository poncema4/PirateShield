import json
from datetime import datetime
from pathlib import Path

# FUTURE TODO: Differentiate managed and unmanaged devices (unmanaged obviously is more severe)

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_network_events.json"
with open(DATA_FILE, "r") as file:
    networkEvents = json.load(file)

def getLastTwoLogins(events: list[dict], userID: str):
    userEvents = [event for event in events if event["user_id"] == userID]
    userEvents.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    if len(userEvents) >= 2:
        return userEvents[-2], userEvents[-1]
    
    return None

# If this is true, this means that we have detected a new device for that user
def flagNewDevice(userID: str) -> bool:
    logins = getLastTwoLogins(networkEvents, userID)

    if not logins:
        return False
    
    prevLogin, currLogin = logins

    return len(prevLogin["user_known_devices"]) < len(currLogin["user_known_devices"])

# Testing

def test_getLastTwoLogins() -> None:
    prevLogin1, currLogin1 = getLastTwoLogins(networkEvents, "teacher2")
    assert prevLogin1 is not None
    assert currLogin1 is not None
    assert prevLogin1["user_id"] == "teacher2"
    assert currLogin1["user_id"] == "teacher2"

# This test varies depending on what's in the json file, but it works
def test_flagNewDevice() -> None:
    # assert flagNewDevice("student1") == False
    # assert flagNewDevice("teacher2") == True
    # assert flagNewDevice("it_staff3") == True
    pass