import data_exfiltation, impossible_travel, login_hours, new_device_detection

def basicRiskScoring(events: list[dict], userID: str, threshold=70) -> bool:
    riskScore = 0

    user_events = [e for e in events if e["user_id"] == userID]

    if data_exfiltation.detectDataExfiltration(userID):
        riskScore += 30
    if impossible_travel.detectImpossibleTravel(userID):
        riskScore += 50
    if login_hours.detectLoginHours(userID):
        riskScore += 10
    if new_device_detection.flagNewDevice(userID):
        riskScore += 20
    
    return riskScore >= threshold

def alert(userID: str) -> str:
    if basicRiskScoring(userID):
        return f"[Alert]: Suspicious user {userID}"
    return ""

    
# TODO: Finish debugging and write tests