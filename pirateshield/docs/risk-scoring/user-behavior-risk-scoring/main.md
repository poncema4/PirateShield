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


[TODO]: Fill in example for sigmoid transformation
## Step 3. Apply the Sigmoid Transformation
Using the sigmoid formula from Kwon et al. 

$$\phi{(Z)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$

$$\phi{(Z_hour)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$
$$\phi{(Z_freq)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$
$$\phi{(Z_off)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$
$$\phi{(Z_weekend)} = \frac{1}{1 + e^{-k(Z - \mu)}}$$


[TODO]: Fill in example for weighted composite score
## Step 4. Compute Weighted Composite Score
Using the weighted composite score formula from Okolie et al.

$$S_raw = w_1\phi(Z_hour) + w_2\phi(Z_freq) + w_3\phi(Z_off) + w_4\phi(Z_weekend)$$

$$S_raw = ...$$
