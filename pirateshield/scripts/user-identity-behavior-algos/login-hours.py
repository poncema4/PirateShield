import json
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_network_events.json"
with open(DATA_FILE, "r") as file:
    networkEvents = json.load(file)

def getLastTwoLogins(events: json, userID: str):
    userEvents = [event for event in events if event["user_id"] == userID]
    userEvents.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    if len(userEvents) < 1:
        return None
    
    return userEvents[-1]
    
def detectLoginHours(userID: str, startHour: int, endHour: int) -> bool:
    login = getLastTwoLogins(networkEvents, userID)

    if not login:
        return False
    
    time = datetime.fromisoformat(login["timestamp"])

    if time.hour < startHour or time.hour >= endHour:
        print(f"Login hour: {time.hour}")
        return True

    return False

# Tests
def test_getLastLogin() -> None:
    login1 = getLastTwoLogins(networkEvents, "teacher2")
    assert login1 != None
    assert login1["user_id"] == "teacher2"

def test_detectLoginHours() -> None:
    assert detectLoginHours("teacher2", 6, 20) == False
    assert detectLoginHours("teacher2", 7, 19) == False