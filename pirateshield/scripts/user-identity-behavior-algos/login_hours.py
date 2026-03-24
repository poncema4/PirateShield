import json
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_network_events.json"
with open(DATA_FILE, "r") as file:
    networkEvents = json.load(file)

def getLastLogin(events: list[dict], userID: str):
    userEvents = [event for event in events if event["user_id"] == userID]
    userEvents.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    if len(userEvents) < 1:
        return None
    
    return userEvents[-1]
    
def detectLoginHours(userID: str, startHour=6, endHour=22) -> bool:
    login = getLastLogin(networkEvents, userID)

    if not login:
        return False
    
    time = datetime.fromisoformat(login["timestamp"])

    if time.hour < startHour or time.hour >= endHour:
        print(f"Login hour: {time.hour}")
        return True

    return False

# Tests
def test_getLastLogin() -> None:
    login1 = getLastLogin(networkEvents, "teacher2")
    assert login1 is not None
    assert login1["user_id"] == "teacher2"

def test_detectLoginHours() -> None:
    assert detectLoginHours("teacher2", 6, 20) == False
    assert detectLoginHours("teacher2", 7, 19) == False