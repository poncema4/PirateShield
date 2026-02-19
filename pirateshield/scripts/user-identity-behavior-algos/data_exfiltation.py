import json
from datetime import datetime
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[2] / "data" / "synthetic_network_events.json"
with open(DATA_FILE, "r") as file:
    networkEvents = json.load(file)

def getUserRecords(events: list[dict], userID: str) -> list[dict]:
    userEvents = [event for event in events if event["user_id"] == userID]
    userEvents.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]))

    if len(userEvents) < 2:
        return None
    
    return userEvents

def getAverageBytes(userID: str) -> int:
    userEvents = getUserRecords(networkEvents, userID)

    return sum(userEvents[:-1]) // len(userEvents)-1

def detectDataExfiltration(userID: str) -> bool:
    records = getUserRecords(networkEvents, userID)

    if records is None:
        return False
    
    lastLogin = records[-1]

    return lastLogin["bytes_sent"] > 5 * getAverageBytes(userID)

# testing
def test_getUserRecords():
    pass

def test_getAverageBytes():
    pass

def test_detectDataExfiltration():
    pass