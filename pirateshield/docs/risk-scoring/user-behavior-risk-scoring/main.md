# PirateShield Contextual Risk Score Calculation

For every login, we compute the contextual risk score (abbreviated as CRS) between 0 and 1. This number reflects how anomalous the specific login is relative to the student's historical data. We then compare the CRS against known attack signature profiles to identify not just that something is wrong but what kind of attack it likely is.

## Step 1. Input Data
Fereidouni et al. 

```
event = {
    student_id: "student_darin271",
    timestamp: "03-14-2026 11:10:23",
    day_of_the_week: "Saturday",
    hour: 11,
    is_school_hours: False,
    is_weekend: True,
    login_count_today: 3,
    device_id: "THINKPAD_13",
    ip_subnet: "1.1.1.x",
    failed_attempts: 1
    hour_bins: [...]

}

Note: Additional features can include User Agent (UA), Timezone & Language, Connection Type, RTT, Successful Login?, and Benign IP?

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
    average_hour_bins: [...]
}
```

## Step 2. Compute Z-Scores
Using the Z-Score formula from Okolie et al.

$${Z} = \frac{x - \mu}{\sigma}$$

- Z_hour = (11 - 8.4) / 1.2 = 2.6 / 1.2 = 2.167

- Z_freq = (3 - 2.1) / 0.8 = 0.9 / 0.8 = 1.125

**Note**: Z_off and Z_weekend rates are probabilities and we can only decide using True/False so we apply Bernoulli's Distribution to get the Z-Score.

$${Z} = \frac{1 - r}{\sqrt{r * (1 - r)}}$$

- Z_off = (1 - 0.04) / $\sqrt{0.04 * 0.96}$ = 0.96 / 0.192 = 5

- Z_weekend = (1 - 0.03) / $\sqrt{0.03 * 0.97}$ = 0.97 / 0.168 = 5.774


[TODO]: Plan weighted circular distance after first solution
Using the weighted circular distance from Hamidreza Fereidouni et al. 

$$S_{\text{cyclic}}(x) = \frac{1}{2} \left( \frac{\sum_{i=1}^{n} w_i \cdot \cos(\theta_x - \theta_i)}{\sum_{i=1}^{n} w_i} + 1 \right)$$

Where:
- $$x$$ is the current login hour
- $$n$$ is the number of bins (24 for hour of day, 7 for day of week)
- $$w_i$$ is weight (historical visit count) of bin $$i$$
- $$\Theta{_x} = \frac{2\pi{x}}{period}$$ is the angular position of the current value
- $$\Theta{_i} = \frac{2\pi{i}}{n}$$ is the angular position of bin $$i$$

For the hours example:

Let's say if our $$w_i$$ were 

$$\Theta{_11} = \frac{2\pi{11}}{period}$$ 
$$\Theta{_i} = \frac{2\pi{i}}{24}$$
$$S_{\text{cyclic}}(x) = \frac{1}{2} \left( \frac{\sum_{i=1}^{n} w_i \cdot \cos(\theta_x - \theta_i)}{\sum_{i=1}^{n} w_i} + 1 \right)$$

## Step 3. Apply the Sigmoid Transformation
Using the sigmoid formula from Kwon et al. 

$$\phi{(Z)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$

We set $$k = 1$$ and $$\mu = 2$$ as our baseline parameters, following the two-sigma anomaly convention standard in statistical anomaly detection.

$$\phi{(Z_{hour})} = \frac{1}{1 + e^{-1(2.167 - 2)}} = 0.5416$$
$$\phi{(Z_{freq})} = \frac{1}{1 + e^{-1(1.125 - 2)}} = 0.2942$$
$$\phi{(Z_{off})} = \frac{1}{1 + e^{-1(5 - 2)}} = 0.9525$$
$$\phi{(Z_{weekend})} = \frac{1}{1 + e^{-1(5.774 - 2)}} = 0.9775$$

## Step 4. Compute Weighted Composite Score
Using the weighted composite score formula from Okolie et al. combined with Yun et al.

$$S_{raw} = w_1\phi(Z_{off}) + w_2\phi(Z_{hour}) + w_3\phi(Z_{freq}) + w_4\phi(Z_{weekend})$$

Where:
- $$w_1 = 0.35$$
- $$w_2 = 0.25$$
- $$w_3 = 0.20$$
- $$w_4 = 0.20$$

$$S_{raw} = 0.35(0.9525) + 0.25(0.5416) + 0.20(0.2942) + 0.20(0.9775)$$
$$S_{raw} = 0.7231$$

## Step 5. Apply Contextual Bonuses (Optional)
```
n failed attempts = +n*0.05
unknown device = +0.20
unknown ip = +0.20
login (12am-5am EST) = +0.20
etc.
```
$$S_{raw} = 0.7231 + 0.20 + 0.05$$
$$S_{raw} = 0.9731$$

## Step 6. Assess Risk Score
Using the idea from Baseri et al.

Based on $$S_{raw}$$:

If $$0.0 <= S_{raw} <= 0.4$$:
- Low risk -> Simple authentication (standard login proceeds)

Else if $$0.4 < S_{raw} <= 0.7$$:
- Medium risk -> More steps (additional verification)

Else if $$0.7 < S_{raw} < 0.9$$:
- High risk -> Advanced authentication (block or escalate)

Else (meaning $$0.9 <= S_{raw} <= 1$$):
- Critical risk -> Immediate escalation 

## Edge Cases and Questions

1. What if the student's data was skewed? (addressed by Okolie et al.)
For example, a student logs in 10 times on Monday and once every other day.

According to the paper, it states that the Z-score thresholds assume normally distributed data and offers an alternative:
- Setting a threshold at 1.5 times the interquartile range

2. How can we handle a case where if the student is new or doesn't have the historical data? (Cold-start phase addressed by Baseri et al.)
- No data -> no risk scoring

According to the paper, instead of flagging new users with no history as high-risk, assign to peer cluster and use cluster aggregate baseline until individual baseline is established.

3. Student's behavior can change legitimately over time, but how can we distinguish this from a malicious user who follows the same procedure? Follow up: how can decrease false positives for this if it's legitimate?

And more to think about


