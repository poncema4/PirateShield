# PirateShield Contextual Risk Score Calculation

For every login, we compute the contextual risk score (abbreviated as CRS) between 0 and 1. This number reflects how anomalous the specific login is relative to the student's historical data. We then compare the CRS against known attack signature profiles to identify not just that something is wrong but what kind of attack it likely is.

## Step 1. Input Data
```
event = {
    student_id: "student_darin271",
    timestamp: "03-14-2026 11:10:23",
    day_of_the_week: "Saturday",
    hour: 2,
    is_school_hours: False,
    is_weekend: True,
    login_count_today: 3,
    device_id: "THINKPAD_13",
    ip_subnet: "1.1.1.x",
    failed_attempts: 1

}

profile = {
    average_hour: 8.4,
    deviation_hour: 1.2,
    average_freq: 2.1,
    deviation_freq: 0.8,
    off_hours_rate: 0.04,
    weekend_rate: 0.03,
    known_devices: ["THINKPAD_13", "iPhone_DARIN"]
    known_subnets: ["192.168.10.x", "1.1.1.x"],
    historical_days: 30
}
```

## Step 2. Compute the Z-Scores
Using the formula from S.A. Okolie et al.

$${Z} = \frac{x - \mu}{\sigma}$$
